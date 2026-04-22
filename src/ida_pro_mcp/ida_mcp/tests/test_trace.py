"""Tests for the tools/call trace middleware (file backend and IDB backend)."""

import json
import tempfile
from pathlib import Path

from ..framework import test, skip_test
from ..rpc import MCP_SERVER
from .. import trace


def _read_lines(path: Path) -> list[dict]:
    return [json.loads(ln) for ln in path.read_text().splitlines() if ln.strip()]


def _call_through_registry(name: str, arguments: dict | None = None) -> dict:
    return MCP_SERVER.registry.methods["tools/call"](name, arguments)


def _reset_idb_state() -> None:
    """Kill any residual trace netnode from prior tests."""
    try:
        import ida_netnode
    except Exception:
        return
    n = ida_netnode.netnode(trace.IDB_NETNODE_NAME, 0, False)
    if n != ida_netnode.BADNODE:
        n.kill()


# ============================================================================
# File backend
# ============================================================================


@test()
def test_trace_writes_one_record_per_tool_call():
    """configure() + one tools/call should produce one JSONL line."""
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "trace.jsonl"
        trace.configure(str(path))
        try:
            _call_through_registry("server_health", {})
        finally:
            trace.shutdown()

        lines = _read_lines(path)
        assert len(lines) == 1, f"expected 1 record, got {len(lines)}"
        rec = lines[0]
        assert rec["tool"] == "server_health"
        assert rec["arguments"] == {}
        assert "ts" in rec and "duration_ms" in rec
        assert "isError" in rec
        assert "structuredContent" in rec


@test()
def test_trace_redacts_unsafe_tool_arguments_by_default():
    """py_eval arguments should be '<redacted>' when --trace-verbose is off."""
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "trace.jsonl"
        trace.configure(str(path))
        try:
            _call_through_registry("py_eval", {"code": "2+2"})
        finally:
            trace.shutdown()
        rec = _read_lines(path)[0]
        assert rec["tool"] == "py_eval"
        assert rec["arguments"] == "<redacted>"


@test()
def test_trace_verbose_keeps_unsafe_tool_arguments():
    """verbose=True should pass @unsafe arguments through."""
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "trace.jsonl"
        trace.configure(str(path), verbose=True)
        try:
            _call_through_registry("py_eval", {"code": "2+2"})
        finally:
            trace.shutdown()
        rec = _read_lines(path)[0]
        assert rec["arguments"] == {"code": "2+2"}


@test()
def test_trace_disabled_by_default_writes_nothing():
    """Without configure(), no tracing should happen."""
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "should-not-exist.jsonl"
        _call_through_registry("server_health", {})
        assert not path.exists(), "unexpected trace file created"


@test()
def test_trace_records_duration_and_timestamp_shape():
    """Each record has a numeric duration_ms and an ISO-8601 UTC timestamp."""
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "trace.jsonl"
        trace.configure(str(path))
        try:
            _call_through_registry("server_health", {})
        finally:
            trace.shutdown()
        rec = _read_lines(path)[0]
        assert isinstance(rec["duration_ms"], (int, float))
        assert rec["duration_ms"] >= 0
        assert rec["ts"].endswith("Z")
        assert "T" in rec["ts"]


# ============================================================================
# IDB backend
# ============================================================================


@test()
def test_trace_idb_round_trip():
    """configure_idb + one call + flush → iter_records yields the record."""
    _reset_idb_state()
    trace.configure_idb(batch_records=1)
    try:
        _call_through_registry("server_health", {})
        records = list(trace.iter_idb_records())
        assert len(records) == 1, f"expected 1 record, got {len(records)}"
        assert records[0]["tool"] == "server_health"
        assert records[0]["arguments"] == {}
    finally:
        trace.clear_idb()
        trace.shutdown()


@test()
def test_trace_idb_multiple_segments_preserve_order():
    """Per-record flushing creates multiple segments; iteration preserves order."""
    _reset_idb_state()
    trace.configure_idb(batch_records=1)
    try:
        for _ in range(5):
            _call_through_registry("server_health", {})
        records = list(trace.iter_idb_records())
        assert len(records) == 5
        stats = trace.idb_stats()
        assert stats["segments"] == 5
        assert stats["total_records"] == 5
    finally:
        trace.clear_idb()
        trace.shutdown()


@test()
def test_trace_idb_large_batch_spans_multiple_supvals():
    """A batch whose gzipped size exceeds one supval (>1024 B) round-trips."""
    _reset_idb_state()
    # 200 records batched into one segment; gzipped JSONL comfortably exceeds 1 KB.
    trace.configure_idb(batch_records=200, batch_bytes=10 * 1024 * 1024)
    try:
        for _ in range(200):
            _call_through_registry("server_health", {})
        trace.flush_idb()
        stats = trace.idb_stats()
        assert stats["segments"] == 1, f"expected 1 segment, got {stats['segments']}"
        records = list(trace.iter_idb_records())
        assert len(records) == 200
        for r in records:
            assert r["tool"] == "server_health"
    finally:
        trace.clear_idb()
        trace.shutdown()


@test()
def test_trace_idb_gap_trick_adjacent_segments_intact():
    """Two segments stored with the +1 gap both decode to their own payloads."""
    _reset_idb_state()
    trace.configure_idb(batch_records=1)
    try:
        _call_through_registry("server_health", {})
        _call_through_registry("server_health", {"arg": "second"})
        stats = trace.idb_stats()
        assert stats["segments"] == 2
        records = list(trace.iter_idb_records())
        assert len(records) == 2
        assert records[0]["arguments"] == {}
        assert records[1]["arguments"] == {"arg": "second"}
    finally:
        trace.clear_idb()
        trace.shutdown()


@test()
def test_trace_idb_clear_wipes_node_and_resets_meta():
    """clear_idb removes every segment and zeroes meta counters."""
    _reset_idb_state()
    trace.configure_idb(batch_records=1)
    try:
        for _ in range(3):
            _call_through_registry("server_health", {})
        assert trace.idb_stats()["total_records"] == 3
        trace.clear_idb()
        stats = trace.idb_stats()
        assert stats["segments"] == 0
        assert stats["total_records"] == 0
        assert stats["next_chunk_start"] == 0
        assert list(trace.iter_idb_records()) == []
    finally:
        trace.shutdown()


@test()
def test_trace_idb_batching_defers_writes_until_threshold():
    """Appends below threshold stay buffered; crossing it flushes one segment."""
    _reset_idb_state()
    trace.configure_idb(batch_records=3)
    try:
        _call_through_registry("server_health", {})
        _call_through_registry("server_health", {})
        assert trace.idb_stats()["segments"] == 0
        _call_through_registry("server_health", {})
        assert trace.idb_stats()["segments"] == 1
        assert trace.idb_stats()["total_records"] == 3
        _call_through_registry("server_health", {})
        assert trace.idb_stats()["segments"] == 1
        trace.flush_idb()
        assert trace.idb_stats()["segments"] == 2
        assert trace.idb_stats()["total_records"] == 4
    finally:
        trace.clear_idb()
        trace.shutdown()


@test()
def test_trace_idb_redaction_applies():
    """@unsafe tool arguments are redacted in the IDB backend too."""
    _reset_idb_state()
    trace.configure_idb(batch_records=1)
    try:
        _call_through_registry("py_eval", {"code": "2+2"})
        records = list(trace.iter_idb_records())
        assert records[0]["tool"] == "py_eval"
        assert records[0]["arguments"] == "<redacted>"
    finally:
        trace.clear_idb()
        trace.shutdown()


@test()
def test_trace_idb_meta_version_and_counters():
    """meta exposes version + monotonically increasing counters."""
    _reset_idb_state()
    trace.configure_idb(batch_records=1)
    try:
        _call_through_registry("server_health", {})
        _call_through_registry("server_health", {})
        stats = trace.idb_stats()
        assert stats["version"] >= 1
        assert stats["segments"] == 2
        assert stats["total_records"] == 2
        assert stats["next_segment_id"] == 2
        assert stats["next_chunk_start"] > 0
    finally:
        trace.clear_idb()
        trace.shutdown()


@test()
def test_trace_both_backends_receive_same_records():
    """File + IDB backends configured together both capture every call."""
    _reset_idb_state()
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "trace.jsonl"
        trace.configure(str(path))
        trace.configure_idb(batch_records=1)
        try:
            _call_through_registry("server_health", {"x": 1})
            _call_through_registry("server_health", {"x": 2})
            file_records = _read_lines(path)
            idb_records = list(trace.iter_idb_records())
            assert len(file_records) == 2
            assert len(idb_records) == 2
            assert [r["arguments"] for r in file_records] == [{"x": 1}, {"x": 2}]
            assert [r["arguments"] for r in idb_records] == [{"x": 1}, {"x": 2}]
        finally:
            trace.clear_idb()
            trace.shutdown()


@test()
def test_trace_clear_tool_wipes_idb_segments():
    """`trace_clear` wipes the IDB backend. The call itself is traced after
    the wipe, so exactly one record (the clear call) remains."""
    _reset_idb_state()
    trace.configure_idb(batch_records=1)
    try:
        _call_through_registry("server_health", {})
        _call_through_registry("server_health", {})
        assert trace.idb_stats()["total_records"] == 2
        resp = _call_through_registry("trace_clear", {})
        sc = resp.get("structuredContent") or {}
        assert sc.get("ok") is True, f"unexpected response: {resp}"
        records = list(trace.iter_idb_records())
        assert len(records) == 1, f"expected 1 residual record, got {len(records)}"
        assert records[0]["tool"] == "trace_clear"
    finally:
        trace.clear_idb()
        trace.shutdown()


@test()
def test_trace_idb_shutdown_flushes_pending_buffer():
    """Shutdown must drain the in-memory buffer to a final segment."""
    _reset_idb_state()
    trace.configure_idb(batch_records=100)
    try:
        _call_through_registry("server_health", {})
        _call_through_registry("server_health", {})
        assert trace.idb_stats()["segments"] == 0
        trace.shutdown()
        records = list(trace.iter_idb_records())
        assert len(records) == 2, f"expected 2 flushed records, got {len(records)}"
    finally:
        _reset_idb_state()
