"""Headless unit tests for the ``CallPairing`` structure in
``ida_pro_mcp.ida_mcp.dbg_common``.

``CallPairing`` matches a function-entry event to its later return by
(tid, sp_at_entry): the stack pointer at entry uniquely identifies an in-flight
frame on a thread until the epilogue restores it. Pure -- plain data structure,
no IDA, no live process.
"""

import pytest

from ida_pro_mcp.ida_mcp.dbg_common import CallPairing


def test_entry_then_matching_return_joins_records():
    cp = CallPairing()
    cp.record_entry(tid=7, sp_at_entry=0x1000, payload={"args": [1, 2]})
    assert cp.pending_count() == 1

    joined = cp.match_return(tid=7, sp_at_return=0x1000, payload={"ret": 0x42})
    assert joined == {
        "tid": 7,
        "sp": 0x1000,
        "entry": {"args": [1, 2]},
        "return": {"ret": 0x42},
    }
    # Consumed on match.
    assert cp.pending_count() == 0


def test_unmatched_return_is_ignored():
    cp = CallPairing()
    cp.record_entry(tid=1, sp_at_entry=0x2000, payload={"a": 1})
    # Return with a non-matching SP -> no pairing, pending entry untouched.
    assert cp.match_return(tid=1, sp_at_return=0x9999, payload={}) is None
    assert cp.pending_count() == 1


def test_return_with_different_tid_does_not_match():
    cp = CallPairing()
    cp.record_entry(tid=1, sp_at_entry=0x3000, payload={"a": 1})
    # Same SP, different thread -> different key -> no match.
    assert cp.match_return(tid=2, sp_at_return=0x3000, payload={}) is None
    assert cp.pending_count() == 1


def test_return_without_any_entry_is_ignored():
    cp = CallPairing()
    assert cp.match_return(tid=5, sp_at_return=0x4000, payload={"ret": 0}) is None
    assert cp.pending_count() == 0


def test_match_consumes_so_second_return_misses():
    cp = CallPairing()
    cp.record_entry(tid=3, sp_at_entry=0x5000, payload={"x": 1})
    assert cp.match_return(tid=3, sp_at_return=0x5000, payload={}) is not None
    # The entry was popped; a duplicate return finds nothing.
    assert cp.match_return(tid=3, sp_at_return=0x5000, payload={}) is None


def test_multiple_frames_match_independently_by_sp():
    cp = CallPairing()
    cp.record_entry(tid=1, sp_at_entry=0x1000, payload={"frame": "outer"})
    cp.record_entry(tid=1, sp_at_entry=0x0F00, payload={"frame": "inner"})
    assert cp.pending_count() == 2

    inner = cp.match_return(tid=1, sp_at_return=0x0F00, payload={"ret": "i"})
    assert inner["entry"] == {"frame": "inner"}
    assert cp.pending_count() == 1

    outer = cp.match_return(tid=1, sp_at_return=0x1000, payload={"ret": "o"})
    assert outer["entry"] == {"frame": "outer"}
    assert cp.pending_count() == 0


def test_record_entry_returns_key_and_last_in_wins_on_collision():
    cp = CallPairing()
    key = cp.record_entry(tid=9, sp_at_entry=0x6000, payload={"v": 1})
    assert key == (9, 0x6000)
    # Same key again (e.g. a missed return) overwrites -- last-in wins.
    cp.record_entry(tid=9, sp_at_entry=0x6000, payload={"v": 2})
    assert cp.pending_count() == 1
    joined = cp.match_return(tid=9, sp_at_return=0x6000, payload={})
    assert joined["entry"] == {"v": 2}


def test_drop_removes_pending_entry():
    cp = CallPairing()
    cp.record_entry(tid=4, sp_at_entry=0x7000, payload={"a": 1})
    assert cp.drop(tid=4, sp_at_entry=0x7000) is True
    assert cp.pending_count() == 0
    # Dropping a non-existent entry returns False.
    assert cp.drop(tid=4, sp_at_entry=0x7000) is False


def test_payload_is_copied_not_aliased():
    cp = CallPairing()
    payload = {"args": [1]}
    cp.record_entry(tid=1, sp_at_entry=0x8000, payload=payload)
    # Mutating the original after recording must not affect the stored entry.
    payload["args"].append(2)
    payload["extra"] = "x"
    joined = cp.match_return(tid=1, sp_at_return=0x8000, payload={})
    assert joined["entry"] == {"args": [1, 2]}  # shallow copy: nested list shared
    assert "extra" not in joined["entry"]  # top-level key added later not seen
