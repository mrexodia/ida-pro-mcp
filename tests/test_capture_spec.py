"""Unit tests for api_probes.parse_capture_spec and build_probe_record.

Both are pure (no IDA, no live process) by design.
"""

from ida_pro_mcp.ida_mcp.api_probes import (
    build_probe_record,
    parse_capture_spec,
)


# --------------------------------------------------------------------------
# parse_capture_spec
# --------------------------------------------------------------------------


def test_parse_register_token():
    plan = parse_capture_spec(["eax"])
    assert plan == [{"raw": "eax", "kind": "reg", "name": "eax"}]


def test_parse_register_is_case_insensitive():
    plan = parse_capture_spec(["EAX", "Rdi"])
    assert plan[0] == {"raw": "EAX", "kind": "reg", "name": "eax"}
    assert plan[1] == {"raw": "Rdi", "kind": "reg", "name": "rdi"}


def test_parse_arg_token():
    plan = parse_capture_spec(["arg0", "arg3"])
    assert plan[0] == {"raw": "arg0", "kind": "arg", "name": "0"}
    assert plan[1] == {"raw": "arg3", "kind": "arg", "name": "3"}


def test_parse_ret_maps_to_eax():
    plan = parse_capture_spec(["ret"])
    assert plan == [{"raw": "ret", "kind": "ret", "name": "eax"}]


def test_parse_caller_token():
    plan = parse_capture_spec(["caller"])
    assert plan == [{"raw": "caller", "kind": "caller", "name": "caller"}]


def test_parse_mem_token():
    plan = parse_capture_spec(["mem(ecx+0x10, 16)"])
    assert plan == [{"raw": "mem(ecx+0x10, 16)", "kind": "mem", "name": "ecx+0x10", "size": 16}]


def test_parse_mem_token_is_case_insensitive():
    plan = parse_capture_spec(["MEM(eax, 4)"])
    assert plan[0]["kind"] == "mem"
    assert plan[0]["name"] == "eax"
    assert plan[0]["size"] == 4


def test_parse_mem_size_out_of_range():
    plan = parse_capture_spec(["mem(eax, 999999)"])
    assert plan[0]["kind"] == "mem"
    assert "error" in plan[0]
    assert plan[0]["error"] == "size out of range"


def test_parse_unknown_token_carries_error_not_raise():
    plan = parse_capture_spec(["bogus_token"])
    assert plan == [
        {"raw": "bogus_token", "kind": "unknown", "error": "unrecognized capture token"}
    ]


def test_parse_partly_valid_spec_keeps_valid_tokens():
    plan = parse_capture_spec(["eax", "nope", "arg1"])
    kinds = [t["kind"] for t in plan]
    assert kinds == ["reg", "unknown", "arg"]
    assert "error" in plan[1]


def test_parse_skips_empty_and_whitespace_tokens():
    plan = parse_capture_spec(["", "  ", "eax"])
    assert plan == [{"raw": "eax", "kind": "reg", "name": "eax"}]


def test_parse_none_returns_empty():
    assert parse_capture_spec(None) == []


def test_parse_accepts_bare_string():
    plan = parse_capture_spec("eax")
    assert plan == [{"raw": "eax", "kind": "reg", "name": "eax"}]


def test_parse_strips_surrounding_whitespace_on_token():
    plan = parse_capture_spec(["  edx  "])
    assert plan[0]["kind"] == "reg"
    assert plan[0]["name"] == "edx"
    assert plan[0]["raw"] == "edx"


# --------------------------------------------------------------------------
# build_probe_record
# --------------------------------------------------------------------------


def test_build_record_minimal():
    rec = build_probe_record("p1", "entry", 0x401000, {"eax": "0x1"})
    assert rec["probe_id"] == "p1"
    assert rec["kind"] == "entry"
    assert rec["ea"] == "0x401000"  # int ea is hex-stringified
    assert rec["captured"] == {"eax": "0x1"}
    # Optional fields absent unless supplied.
    assert "hit" not in rec
    assert "tid" not in rec


def test_build_record_ea_none_passthrough():
    rec = build_probe_record("p1", "entry", None, {})
    assert rec["ea"] is None
    assert rec["captured"] == {}


def test_build_record_ea_non_int_passthrough():
    rec = build_probe_record("p1", "entry", "symbolic", {})
    assert rec["ea"] == "symbolic"


def test_build_record_with_hit_and_tid():
    rec = build_probe_record("p1", "ret", 0x10, {}, hit=3, tid=42)
    assert rec["hit"] == 3
    assert rec["tid"] == 42


def test_build_record_hit_zero_is_included():
    rec = build_probe_record("p1", "ret", 0x10, {}, hit=0)
    assert rec["hit"] == 0  # 0 is not None -> included


def test_build_record_extra_setdefault_does_not_clobber():
    rec = build_probe_record(
        "p1", "entry", 0x10, {"a": 1}, extra={"probe_id": "OTHER", "note": "n"}
    )
    # extra uses setdefault: existing canonical keys win.
    assert rec["probe_id"] == "p1"
    assert rec["note"] == "n"


def test_build_record_copies_captured_dict():
    cap = {"eax": "1"}
    rec = build_probe_record("p1", "entry", 0x10, cap)
    cap["eax"] = "999"
    assert rec["captured"]["eax"] == "1"


def test_build_record_does_not_stamp_seq_or_meta():
    rec = build_probe_record("p1", "entry", 0x10, {})
    # _seq / _meta / ts are stamped later by record_probe_event, not here.
    assert "_seq" not in rec
    assert "_meta" not in rec
    assert "ts" not in rec
