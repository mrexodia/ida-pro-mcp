"""Unit tests for the NEW pure-logic helpers added to trace.py / api_probes.py.

These cover the three areas the task calls out:

  * wildcard byte-pattern parsing  -> trace.pattern_to_mask (the IDA-style
    (bytes, mask) rendering of a parse_byte_pattern result)
  * range merge                    -> trace.total_range_bytes (coalesced span
    total, built on merge_ranges)
  * probe_stats aggregation shape  -> trace.aggregate_probe_stats (the pure
    rollup the probe_stats tool now delegates to), plus the tool's result shape

All pure: the helpers take plain lists / dicts and return plain values, so they
run headless against the conftest IDA stubs with NO live debugger / process.
"""

import pytest

from ida_pro_mcp.ida_mcp.trace import (
    aggregate_probe_stats,
    parse_byte_pattern,
    pattern_to_mask,
    total_range_bytes,
)
from ida_pro_mcp.ida_mcp import api_probes


# --------------------------------------------------------------------------
# pattern_to_mask  (wildcard byte-pattern parsing -> (bytes, mask))
# --------------------------------------------------------------------------


def test_mask_all_concrete():
    raw, mask = pattern_to_mask([0x8B, 0x56, 0xFF])
    assert raw == b"\x8b\x56\xff"
    assert mask == "xxx"


def test_mask_with_wildcards():
    raw, mask = pattern_to_mask([0x8B, None, 0xFF])
    # wildcard slot is zeroed in the bytes, '?' in the mask
    assert raw == b"\x8b\x00\xff"
    assert mask == "x?x"


def test_mask_all_wildcards():
    raw, mask = pattern_to_mask([None, None, None])
    assert raw == b"\x00\x00\x00"
    assert mask == "???"


def test_mask_single_byte():
    raw, mask = pattern_to_mask([0x00])
    assert raw == b"\x00"
    assert mask == "x"


def test_mask_round_trips_parse_byte_pattern():
    # the canonical pipeline: parse a hex string, then render the mask
    raw, mask = pattern_to_mask(parse_byte_pattern("8b ?? 56 ff"))
    assert raw == b"\x8b\x00\x56\xff"
    assert mask == "x?xx"
    assert len(raw) == len(mask) == 4


def test_mask_length_matches_pattern_length():
    pat = parse_byte_pattern("aa bb cc dd ee")
    raw, mask = pattern_to_mask(pat)
    assert len(raw) == len(mask) == len(pat) == 5


def test_mask_empty_raises():
    with pytest.raises(ValueError):
        pattern_to_mask([])
    with pytest.raises(ValueError):
        pattern_to_mask(None)


def test_mask_out_of_range_byte_raises():
    with pytest.raises(ValueError):
        pattern_to_mask([0x100])
    with pytest.raises(ValueError):
        pattern_to_mask([-1])


def test_mask_non_int_slot_raises():
    with pytest.raises(ValueError):
        pattern_to_mask([0x8B, "ff"])


def test_mask_rejects_bool_slot():
    # bool is an int subclass; it must NOT silently render as a byte
    with pytest.raises(ValueError):
        pattern_to_mask([True])


# --------------------------------------------------------------------------
# total_range_bytes  (range merge -> coalesced byte total)
# --------------------------------------------------------------------------


def test_total_disjoint_sums_each():
    assert total_range_bytes([(0, 10), (20, 25)]) == 15


def test_total_overlap_counted_once():
    # (0,10) and (5,15) coalesce to (0,15) -> 15 bytes, not 20
    assert total_range_bytes([(0, 10), (5, 15)]) == 15


def test_total_adjacent_merged():
    assert total_range_bytes([(0, 10), (10, 20)]) == 20


def test_total_contained_counted_once():
    assert total_range_bytes([(0, 100), (10, 20)]) == 100


def test_total_unsorted_input():
    assert total_range_bytes([(20, 25), (0, 10)]) == 15


def test_total_empty_is_zero():
    assert total_range_bytes([]) == 0
    assert total_range_bytes(None) == 0


def test_total_skips_invalid_entries():
    # (10,10) zero-width and (5,1) inverted are dropped; only (0,4) counts
    assert total_range_bytes([(10, 10), (5, 1), (0, 4)]) == 4


def test_total_chain_merge():
    assert total_range_bytes([(0, 5), (5, 10), (10, 15), (20, 25)]) == 20


# --------------------------------------------------------------------------
# aggregate_probe_stats  (probe_stats aggregation shape)
# --------------------------------------------------------------------------


def _ring(cap=4096, size=0, dropped=0):
    return {"cap": cap, "buffer_mode": "circular", "size": size,
            "next_cursor": size, "dropped": dropped, "full": False}


def test_aggregate_empty_shape():
    out = aggregate_probe_stats([], _ring())
    assert out["total_probes"] == 0
    assert out["armed_probes"] == 0
    assert out["per_probe"] == []
    assert out["dropped"] == 0
    assert out["fill_pct"] == 0.0
    assert out["ring"]["cap"] == 4096


def test_aggregate_counts_armed():
    probes = [
        {"probe_id": "a", "ea": "0x1", "kind": "probe", "hits": 1, "max_hits": 10, "armed": True},
        {"probe_id": "b", "ea": "0x2", "kind": "probe", "hits": 2, "max_hits": 10, "armed": False},
        {"probe_id": "c", "ea": "0x3", "kind": "watch", "hits": 0, "max_hits": 5, "armed": True},
    ]
    out = aggregate_probe_stats(probes, _ring())
    assert out["total_probes"] == 3
    assert out["armed_probes"] == 2


def test_aggregate_sorts_per_probe_by_hits_desc():
    probes = [
        {"probe_id": "low", "hits": 3, "armed": True},
        {"probe_id": "high", "hits": 99, "armed": True},
        {"probe_id": "mid", "hits": 50, "armed": True},
    ]
    out = aggregate_probe_stats(probes, _ring())
    assert [p["probe_id"] for p in out["per_probe"]] == ["high", "mid", "low"]


def test_aggregate_per_probe_field_shape():
    probes = [{"probe_id": "a", "ea": "0x401000", "kind": "probe",
               "hits": 7, "max_hits": 100, "armed": True}]
    out = aggregate_probe_stats(probes, _ring())
    p = out["per_probe"][0]
    assert set(p) == {"probe_id", "ea", "kind", "hits", "max_hits", "armed"}
    assert p["ea"] == "0x401000"
    assert p["hits"] == 7
    assert p["armed"] is True


def test_aggregate_fill_pct():
    out = aggregate_probe_stats([], _ring(cap=100, size=25))
    assert out["fill_pct"] == 25.0


def test_aggregate_fill_pct_zero_cap_is_safe():
    out = aggregate_probe_stats([], {"cap": 0, "size": 0})
    assert out["fill_pct"] == 0.0


def test_aggregate_dropped_surfaced():
    out = aggregate_probe_stats([], _ring(dropped=12))
    assert out["dropped"] == 12


def test_aggregate_missing_hits_defaults_zero():
    probes = [{"probe_id": "a", "armed": False}]
    out = aggregate_probe_stats(probes, _ring())
    assert out["per_probe"][0]["hits"] == 0
    assert out["per_probe"][0]["armed"] is False


def test_aggregate_skips_non_dict_probes():
    probes = [{"probe_id": "a", "hits": 1, "armed": True}, "junk", 42, None]
    out = aggregate_probe_stats(probes, _ring())
    assert out["total_probes"] == 1
    assert out["per_probe"][0]["probe_id"] == "a"


def test_aggregate_handles_none_ring_stats():
    out = aggregate_probe_stats([], None)
    assert out["ring"] == {}
    assert out["fill_pct"] == 0.0
    assert out["dropped"] == 0


# --------------------------------------------------------------------------
# probe_stats tool delegates to aggregate_probe_stats (same shape)
# --------------------------------------------------------------------------


def test_probe_stats_tool_shape_matches_helper():
    from ida_pro_mcp.ida_mcp import trace as _trace
    _trace.clear_probes()
    try:
        d = _trace.register_probe("only", ea="0x1000", kind="probe", armed=True)
        d["hits"] = 5
        out = api_probes.probe_stats()
        expected = _trace.aggregate_probe_stats(
            _trace.list_probes(), _trace.get_probe_ring().stats()
        )
        assert out["total_probes"] == expected["total_probes"] == 1
        assert out["armed_probes"] == 1
        assert out["per_probe"][0]["probe_id"] == "only"
        assert out["per_probe"][0]["hits"] == 5
        assert set(out) == {"armed_probes", "total_probes", "ring",
                            "fill_pct", "dropped", "per_probe"}
    finally:
        _trace.clear_probes()


# --------------------------------------------------------------------------
# memory_scan surfaces the parsed mask (still debugger-guarded)
# --------------------------------------------------------------------------


def test_memory_scan_still_requires_debugger():
    out = api_probes.memory_scan("8b ?? ff")
    assert "error" in out
    assert "debugger" in out["error"].lower()


def test_new_helpers_exported_from_trace_all():
    from ida_pro_mcp.ida_mcp import trace as _trace
    for name in ("pattern_to_mask", "total_range_bytes", "aggregate_probe_stats"):
        assert name in _trace.__all__, name
