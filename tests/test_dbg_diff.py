"""Headless unit tests for ``diff_snapshots`` in
``ida_pro_mcp.ida_mcp.dbg_common``.

A snapshot is {"regs": {name: value}, "ranges": [{"addr": <int|hex-str>,
"hex": <hexstr>}]}. ``diff_snapshots(before, after)`` reports changed registers
and, per watched range, the individual bytes whose hex differs. Pure -- the
snapshots are synthetic dicts.
"""

import pytest

from ida_pro_mcp.ida_mcp.dbg_common import diff_snapshots


def test_diff_identical_snapshots_is_empty():
    snap = {
        "regs": {"rax": 1, "rbx": 2},
        "ranges": [{"addr": 0x1000, "hex": "deadbeef"}],
    }
    res = diff_snapshots(snap, snap)
    assert res == {"regs": [], "ranges": []}


def test_diff_reports_changed_registers_only():
    before = {"regs": {"rax": 0x10, "rbx": 0x20, "rcx": 0x30}, "ranges": []}
    after = {"regs": {"rax": 0x10, "rbx": 0x99, "rcx": 0x30}, "ranges": []}
    res = diff_snapshots(before, after)
    assert res["regs"] == [{"name": "rbx", "old": 0x20, "new": 0x99}]
    assert res["ranges"] == []


def test_diff_reports_per_byte_range_changes():
    # Bytes at offsets 1 and 3 differ (de->de same, ad->ff, be->be, ef->00).
    before = {"regs": {}, "ranges": [{"addr": 0x2000, "hex": "deadbeef"}]}
    after = {"regs": {}, "ranges": [{"addr": 0x2000, "hex": "deffbe00"}]}
    res = diff_snapshots(before, after)
    assert res["regs"] == []
    assert res["ranges"] == [
        {"addr": 0x2001, "offset": 1, "old": "ad", "new": "ff"},
        {"addr": 0x2003, "offset": 3, "old": "ef", "new": "00"},
    ]


def test_diff_pairs_ranges_by_addr_not_position():
    before = {
        "regs": {},
        "ranges": [
            {"addr": 0x1000, "hex": "0000"},
            {"addr": 0x2000, "hex": "aabb"},
        ],
    }
    # Reversed order in `after`; pairing must follow addr, not list index.
    after = {
        "regs": {},
        "ranges": [
            {"addr": 0x2000, "hex": "aacc"},
            {"addr": 0x1000, "hex": "0000"},
        ],
    }
    res = diff_snapshots(before, after)
    assert res["ranges"] == [{"addr": 0x2001, "offset": 1, "old": "bb", "new": "cc"}]


def test_diff_addr_accepts_hex_string_keys():
    before = {"regs": {}, "ranges": [{"addr": "0x3000", "hex": "1234"}]}
    after = {"regs": {}, "ranges": [{"addr": "0x3000", "hex": "12ff"}]}
    res = diff_snapshots(before, after)
    assert res["ranges"] == [{"addr": 0x3001, "offset": 1, "old": "34", "new": "ff"}]


def test_diff_ignores_register_present_in_only_one_snapshot():
    before = {"regs": {"rax": 1, "rdx": 7}, "ranges": []}
    after = {"regs": {"rax": 2}, "ranges": []}
    res = diff_snapshots(before, after)
    # rdx exists only in BEFORE -> skipped; only rax (in both, changed) reported.
    assert res["regs"] == [{"name": "rax", "old": 1, "new": 2}]


def test_diff_ignores_range_addr_in_only_one_snapshot():
    before = {"regs": {}, "ranges": [{"addr": 0x4000, "hex": "00"}]}
    after = {"regs": {}, "ranges": [{"addr": 0x5000, "hex": "11"}]}
    res = diff_snapshots(before, after)
    assert res["ranges"] == []


def test_diff_skips_mismatched_length_hex():
    before = {"regs": {}, "ranges": [{"addr": 0x6000, "hex": "aabb"}]}
    after = {"regs": {}, "ranges": [{"addr": 0x6000, "hex": "aabbcc"}]}
    res = diff_snapshots(before, after)
    assert res["ranges"] == []


def test_diff_handles_empty_or_missing_keys():
    assert diff_snapshots({}, {}) == {"regs": [], "ranges": []}
    assert diff_snapshots(None, None) == {"regs": [], "ranges": []}
