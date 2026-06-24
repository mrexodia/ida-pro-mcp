"""Unit tests for the pure-logic autopilot helpers in trace.py.

summarize_records (server-side rollup over probe records) and diff_buffers
(the crypto pre/post byte-diff primitive) are both pure: they take plain dicts
/ hex strings and return plain dicts, so they run headless with no IDA process.
"""

import pytest

from ida_pro_mcp.ida_mcp.trace import diff_buffers, summarize_records
from ida_pro_mcp.ida_mcp.api_probes import (
    AUTOPILOT_FORBIDDEN_ACTIONS,
    AUTOPILOT_SAFE_ACTIONS,
    plan_autopilot,
    validate_autopilot_step,
)


def _rec(probe_id="p", caller=None, tid=None, ea=None, captured=None, **extra):
    record = {"probe_id": probe_id}
    if tid is not None:
        record["tid"] = tid
    if ea is not None:
        record["ea"] = ea
    cap = dict(captured or {})
    if caller is not None:
        cap.setdefault("caller", caller)
    record["captured"] = cap
    record.update(extra)
    return record


# --------------------------------------------------------------------------
# summarize_records
# --------------------------------------------------------------------------


def test_summarize_rejects_bad_group_by():
    with pytest.raises(ValueError):
        summarize_records([], group_by="sideways")


def test_summarize_empty():
    out = summarize_records([], group_by="probe_id")
    assert out["total_records"] == 0
    assert out["distinct_groups"] == 0
    assert out["groups"] == []
    assert out["group_by"] == "probe_id"


def test_summarize_count_by_probe_id():
    recs = [_rec(probe_id="a"), _rec(probe_id="a"), _rec(probe_id="b")]
    out = summarize_records(recs, group_by="probe_id")
    assert out["total_records"] == 3
    assert out["distinct_groups"] == 2
    # Sorted by count descending: "a" (2) before "b" (1).
    assert out["groups"][0]["key"] == "a"
    assert out["groups"][0]["count"] == 2
    assert out["groups"][1]["key"] == "b"
    assert out["groups"][1]["count"] == 1


def test_summarize_distinct_callers_call_tree():
    recs = [
        _rec(probe_id="a", caller="0x401000"),
        _rec(probe_id="a", caller="0x401000"),
        _rec(probe_id="a", caller="0x402000"),
    ]
    out = summarize_records(recs, group_by="probe_id")
    grp = out["groups"][0]
    assert grp["distinct_callers"] == 2
    assert grp["callers"] == ["0x401000", "0x402000"]


def test_summarize_group_by_caller():
    recs = [
        _rec(caller="0x401000"),
        _rec(caller="0x401000"),
        _rec(caller="0x402000"),
    ]
    out = summarize_records(recs, group_by="caller")
    by_key = {g["key"]: g for g in out["groups"]}
    assert by_key["0x401000"]["count"] == 2
    assert by_key["0x402000"]["count"] == 1


def test_summarize_group_by_tid():
    recs = [_rec(tid=1), _rec(tid=1), _rec(tid=2)]
    out = summarize_records(recs, group_by="tid")
    by_key = {g["key"]: g for g in out["groups"]}
    assert by_key[1]["count"] == 2
    assert by_key[2]["count"] == 1


def test_summarize_group_by_func_uses_ea():
    recs = [_rec(ea="0x401000"), _rec(ea="0x401000"), _rec(ea="0x405000")]
    out = summarize_records(recs, group_by="func")
    by_key = {g["key"]: g for g in out["groups"]}
    assert by_key["0x401000"]["count"] == 2
    assert by_key["0x405000"]["count"] == 1


def test_summarize_group_by_pc_from_captured():
    recs = [
        _rec(captured={"eip": "0x401010"}),
        _rec(captured={"eip": "0x401010"}),
        _rec(captured={"rip": "0x7ff000"}),
    ]
    out = summarize_records(recs, group_by="pc")
    by_key = {g["key"]: g for g in out["groups"]}
    assert by_key["0x401010"]["count"] == 2
    assert by_key["0x7ff000"]["count"] == 1


def test_summarize_missing_key_buckets_under_none():
    recs = [_rec(probe_id="a"), {"captured": {}}]
    out = summarize_records(recs, group_by="tid")
    keys = {g["key"] for g in out["groups"]}
    assert None in keys


def test_summarize_skips_non_dict_records():
    recs = [_rec(probe_id="a"), "not a dict", 42, None]
    out = summarize_records(recs, group_by="probe_id")
    assert out["total_records"] == 4  # total counts the raw list
    assert out["distinct_groups"] == 1
    assert out["groups"][0]["count"] == 1


def test_summarize_numeric_field_min_max_last():
    recs = [
        _rec(probe_id="a", captured={"arg2": "0x10"}),
        _rec(probe_id="a", captured={"arg2": "0x100"}),
        _rec(probe_id="a", captured={"arg2": "0x40"}),
    ]
    out = summarize_records(recs, group_by="probe_id", numeric_field="arg2")
    grp = out["groups"][0]
    assert grp["numeric_field"] == "arg2"
    assert grp["min"] == float(0x10)
    assert grp["max"] == float(0x100)
    assert grp["last"] == float(0x40)


def test_summarize_numeric_field_top_level():
    recs = [_rec(probe_id="a", hit=1), _rec(probe_id="a", hit=5)]
    out = summarize_records(recs, group_by="probe_id", numeric_field="hit")
    grp = out["groups"][0]
    assert grp["min"] == 1.0
    assert grp["max"] == 5.0


def test_summarize_numeric_field_all_unparseable_yields_none():
    recs = [
        _rec(probe_id="a", captured={"x": {"addr": "0x1", "hex": "ab"}}),
        _rec(probe_id="a", captured={"x": "notanumber"}),
    ]
    out = summarize_records(recs, group_by="probe_id", numeric_field="x")
    grp = out["groups"][0]
    assert grp["min"] is None
    assert grp["max"] is None
    assert grp["last"] is None


def test_summarize_numeric_field_decimal_and_int():
    recs = [_rec(probe_id="a", captured={"n": 7}), _rec(probe_id="a", captured={"n": "9"})]
    out = summarize_records(recs, group_by="probe_id", numeric_field="n")
    grp = out["groups"][0]
    assert grp["min"] == 7.0
    assert grp["max"] == 9.0


# --------------------------------------------------------------------------
# diff_buffers
# --------------------------------------------------------------------------


def test_diff_equal_buffers():
    out = diff_buffers("deadbeef", "deadbeef")
    assert out["equal"] is True
    assert out["changed_offsets"] == []
    assert out["first_diff"] is None
    assert out["len_a"] == 4
    assert out["len_b"] == 4


def test_diff_single_byte_change():
    out = diff_buffers("deadbeef", "deadbe00")
    assert out["equal"] is False
    assert out["changed_offsets"] == [3]
    assert out["first_diff"] == 3


def test_diff_multiple_changes():
    out = diff_buffers("00112233", "00ff2244")
    assert out["changed_offsets"] == [1, 3]
    assert out["first_diff"] == 1
    assert out["equal"] is False


def test_diff_length_mismatch_extends_changed():
    out = diff_buffers("0011", "00112233")
    assert out["len_a"] == 2
    assert out["len_b"] == 4
    # offset 0,1 equal; 2,3 only present in b -> changed.
    assert out["changed_offsets"] == [2, 3]
    assert out["first_diff"] == 2
    assert out["equal"] is False


def test_diff_length_mismatch_with_inner_change():
    out = diff_buffers("ff11", "00112233")
    assert out["changed_offsets"] == [0, 2, 3]
    assert out["first_diff"] == 0


def test_diff_empty_buffers_equal():
    out = diff_buffers("", "")
    assert out["equal"] is True
    assert out["len_a"] == 0
    assert out["len_b"] == 0
    assert out["changed_offsets"] == []


def test_diff_accepts_0x_prefix_and_spaces():
    out = diff_buffers("0xdead beef", "de ad be ef")
    assert out["equal"] is True
    assert out["len_a"] == 4


def test_diff_accepts_bytes():
    out = diff_buffers(b"\x01\x02", b"\x01\x03")
    assert out["changed_offsets"] == [1]
    assert out["equal"] is False


def test_diff_odd_length_hex_is_error():
    out = diff_buffers("abc", "abcd")
    assert out["equal"] is False
    assert "error" in out
    assert out["len_a"] is None
    assert out["len_b"] == 2


def test_diff_non_hex_is_error():
    out = diff_buffers("zzzz", "0011")
    assert out["equal"] is False
    assert "error" in out
    assert out["len_a"] is None


def test_diff_none_input_is_error():
    out = diff_buffers(None, "0011")
    assert out["equal"] is False
    assert "error" in out
    assert out["len_a"] is None
    assert out["len_b"] == 2


def test_diff_crypto_pre_post_roundtrip():
    pre = "48656c6c6f"  # "Hello"
    post = "ffffffffff"
    out = diff_buffers(pre, post)
    assert out["changed_offsets"] == [0, 1, 2, 3, 4]
    assert out["first_diff"] == 0
    assert out["equal"] is False


# --------------------------------------------------------------------------
# validate_autopilot_step (pure whitelist guard)
# --------------------------------------------------------------------------


def test_validate_step_accepts_safe_actions():
    for action in AUTOPILOT_SAFE_ACTIONS:
        out = validate_autopilot_step({"action": action})
        assert out.get("error") is None, action
        assert out["action"] == action
        assert out["params"] == {}


def test_validate_step_normalizes_case_and_whitespace():
    out = validate_autopilot_step({"action": "  Continue "})
    assert out["action"] == "continue"
    assert "error" not in out


def test_validate_step_carries_params():
    out = validate_autopilot_step({"action": "run_until", "target_ea": "0x401000", "timeout_ms": 5000})
    assert out["action"] == "run_until"
    assert out["params"] == {"target_ea": "0x401000", "timeout_ms": 5000}


def test_validate_step_rejects_non_dict():
    out = validate_autopilot_step("continue")
    assert "error" in out


def test_validate_step_rejects_missing_action():
    out = validate_autopilot_step({"timeout_ms": 1000})
    assert "error" in out


@pytest.mark.parametrize("forbidden", sorted(AUTOPILOT_FORBIDDEN_ACTIONS))
def test_validate_step_rejects_forbidden_actions(forbidden):
    out = validate_autopilot_step({"action": forbidden})
    assert "error" in out
    assert out["action"] == forbidden
    assert "forbidden" in out["error"]


def test_validate_step_appcall_is_forbidden_explicitly():
    out = validate_autopilot_step({"action": "appcall", "ea": "0x401000"})
    assert "error" in out
    assert "appcall" in out["error"]


def test_validate_step_patch_is_forbidden_explicitly():
    out = validate_autopilot_step({"action": "patch", "ea": "0x401000"})
    assert "error" in out
    assert "patch" in out["error"]


def test_validate_step_rejects_unknown_action():
    out = validate_autopilot_step({"action": "teleport"})
    assert "error" in out
    assert "not a safe autopilot primitive" in out["error"]


def test_safe_and_forbidden_sets_are_disjoint():
    assert AUTOPILOT_SAFE_ACTIONS.isdisjoint(AUTOPILOT_FORBIDDEN_ACTIONS)


# --------------------------------------------------------------------------
# plan_autopilot (budget + whole-list validation)
# --------------------------------------------------------------------------


def test_plan_valid_sequence():
    steps = [
        {"action": "read_regs"},
        {"action": "continue", "timeout_ms": 2000},
        {"action": "probe_drain"},
    ]
    out = plan_autopilot(steps, step_budget=64)
    assert "error" not in out
    assert out["budget"] == 64
    assert [s["action"] for s in out["steps"]] == ["read_regs", "continue", "probe_drain"]


def test_plan_rejects_empty():
    out = plan_autopilot([], step_budget=64)
    assert "error" in out


def test_plan_rejects_non_list():
    out = plan_autopilot({"action": "continue"}, step_budget=64)
    assert "error" in out


def test_plan_rejects_over_budget():
    steps = [{"action": "read_regs"}] * 5
    out = plan_autopilot(steps, step_budget=4)
    assert "error" in out
    assert "exceeds step_budget" in out["error"]


def test_plan_rejects_bad_budget():
    assert "error" in plan_autopilot([{"action": "read_regs"}], step_budget=0)
    assert "error" in plan_autopilot([{"action": "read_regs"}], step_budget="x")


def test_plan_pinpoints_first_forbidden_step():
    steps = [
        {"action": "read_regs"},
        {"action": "appcall", "ea": "0x401000"},
        {"action": "continue"},
    ]
    out = plan_autopilot(steps, step_budget=64)
    assert "error" in out
    assert out["index"] == 1
    assert "appcall" in out["error"]


def test_plan_pinpoints_first_unknown_step():
    steps = [{"action": "continue"}, {"action": "frobnicate"}]
    out = plan_autopilot(steps, step_budget=64)
    assert out["index"] == 1
    assert "not a safe autopilot primitive" in out["error"]


def test_plan_forbids_patch_install_in_loop():
    steps = [{"action": "patch_asm", "ea": "0x401000", "asm": "nop"}]
    out = plan_autopilot(steps, step_budget=64)
    assert "error" in out
    assert out["index"] == 0
