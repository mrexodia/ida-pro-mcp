"""Unit tests for trace.ProbeRing (pure-logic, no IDA process).

Covers capacity, circular eviction + dropped counter, the monotonic seq
cursor used by drain(since_cursor=...), filtering, limit, and the
linear-vs-circular buffer_mode contract.
"""

from ida_pro_mcp.ida_mcp.trace import ProbeRing


def test_basic_append_and_seq_cursor():
    ring = ProbeRing(cap=8)
    seq0 = ring.append({"x": 1})
    seq1 = ring.append({"x": 2})
    assert seq0 == 0
    assert seq1 == 1
    drained = ring.drain()
    assert [r["x"] for r in drained] == [1, 2]
    assert [r["_seq"] for r in drained] == [0, 1]


def test_stats_shape():
    ring = ProbeRing(cap=4, buffer_mode="circular")
    ring.append({"a": 1})
    st = ring.stats()
    assert st["cap"] == 4
    assert st["buffer_mode"] == "circular"
    assert st["size"] == 1
    assert st["next_cursor"] == 1
    assert st["dropped"] == 0
    assert st["full"] is False


def test_cap_clamped_to_at_least_one():
    ring = ProbeRing(cap=0)
    assert ring.cap == 1
    ring.append({"a": 1})
    ring.append({"a": 2})
    assert ring.stats()["size"] == 1


def test_cap_clamped_to_hard_max():
    from ida_pro_mcp.ida_mcp.trace import _PROBE_RING_HARD_MAX

    ring = ProbeRing(cap=_PROBE_RING_HARD_MAX * 10)
    assert ring.cap == _PROBE_RING_HARD_MAX


def test_invalid_buffer_mode_raises():
    import pytest

    with pytest.raises(ValueError):
        ProbeRing(cap=4, buffer_mode="sideways")


def test_circular_eviction_and_dropped_counter():
    ring = ProbeRing(cap=3, buffer_mode="circular")
    for i in range(5):
        seq = ring.append({"i": i})
        assert seq == i  # seq is monotonic across the whole lifetime
    st = ring.stats()
    assert st["size"] == 3
    assert st["dropped"] == 2  # two oldest evicted
    assert st["full"] is True
    assert st["next_cursor"] == 5
    # Only the last three survive, oldest-first.
    survivors = [r["i"] for r in ring.drain()]
    assert survivors == [2, 3, 4]


def test_circular_seq_stable_after_eviction():
    """drain(since_cursor=...) stays correct even after old records evicted."""
    ring = ProbeRing(cap=2, buffer_mode="circular")
    for i in range(5):
        ring.append({"i": i})
    # Records with _seq >= 3 are i==3 and i==4.
    got = ring.drain(since_cursor=3)
    assert [r["i"] for r in got] == [3, 4]
    # since_cursor past everything yields nothing.
    assert ring.drain(since_cursor=99) == []


def test_linear_stops_at_capacity_and_returns_none():
    ring = ProbeRing(cap=3, buffer_mode="linear")
    seqs = [ring.append({"i": i}) for i in range(5)]
    # First three accepted (seq 0,1,2); last two dropped (None).
    assert seqs == [0, 1, 2, None, None]
    st = ring.stats()
    assert st["size"] == 3
    assert st["dropped"] == 2
    assert st["full"] is True
    assert st["next_cursor"] == 3  # cursor did NOT advance on dropped records
    assert [r["i"] for r in ring.drain()] == [0, 1, 2]


def test_drain_filter():
    ring = ProbeRing(cap=10)
    for i in range(6):
        ring.append({"i": i, "even": i % 2 == 0})
    evens = ring.drain(filter=lambda r: r["even"])
    assert [r["i"] for r in evens] == [0, 2, 4]


def test_drain_limit():
    ring = ProbeRing(cap=10)
    for i in range(6):
        ring.append({"i": i})
    first_two = ring.drain(limit=2)
    assert [r["i"] for r in first_two] == [0, 1]


def test_drain_since_cursor_and_filter_combined():
    ring = ProbeRing(cap=10)
    for i in range(6):
        ring.append({"i": i})
    got = ring.drain(since_cursor=2, filter=lambda r: r["i"] % 2 == 0, limit=1)
    assert [r["i"] for r in got] == [2]


def test_drain_does_not_consume():
    ring = ProbeRing(cap=4)
    ring.append({"i": 1})
    assert len(ring.drain()) == 1
    assert len(ring.drain()) == 1  # still there
    assert ring.stats()["size"] == 1


def test_append_copies_record():
    ring = ProbeRing(cap=4)
    src = {"i": 1}
    ring.append(src)
    src["i"] = 999  # mutate the caller's dict
    assert ring.drain()[0]["i"] == 1  # ring kept its own copy


def test_clear_resets_counters_but_not_cursor():
    ring = ProbeRing(cap=3, buffer_mode="circular")
    for i in range(5):
        ring.append({"i": i})
    cursor_before = ring.stats()["next_cursor"]
    ring.clear()
    st = ring.stats()
    assert st["size"] == 0
    assert st["dropped"] == 0
    assert st["full"] is False
    # New appends keep counting up from where the seq was.
    ring.append({"i": 99})
    assert ring.stats()["next_cursor"] == cursor_before + 1
