# Tests for the IDB tools/call trace middleware.

from ..framework import test
from ..rpc import MCP_SERVER
from .. import trace


def _call_through_registry(name: str, arguments: dict | None = None) -> dict:
    return MCP_SERVER.registry.methods["tools/call"](name, arguments)


def _kill_trace_node() -> None:
    """Wipe the trace netnode."""
    import ida_netnode
    n = ida_netnode.netnode(trace.IDB_NETNODE_NAME, 0, False)
    if n != ida_netnode.BADNODE:
        n.kill()


def _reset_trace(*, batch_records: int = 1, batch_bytes: int | None = None) -> None:
    """Drain the prior backend, wipe the netnode, configure fresh."""
    # Shutdown before kill so buffered records don't leak into the new netnode.
    trace.shutdown()
    _kill_trace_node()
    if batch_bytes is None:
        trace.configure_idb(batch_records=batch_records)
    else:
        trace.configure_idb(batch_records=batch_records, batch_bytes=batch_bytes)


def _teardown_trace() -> None:
    """Drain pending records, then wipe the netnode."""
    trace.shutdown()
    _kill_trace_node()


def _read_stats() -> dict[str, int]:
    """Read counters directly from the trace netnode."""
    import ida_netnode
    node = ida_netnode.netnode(trace.IDB_NETNODE_NAME, 0, False)
    if node == ida_netnode.BADNODE:
        return {
            "version": 0,
            "segments": 0,
            "next_chunk_start": 0,
            "next_segment_id": 0,
            "total_records": 0,
        }
    segments = 0
    i = node.altfirst(trace._TAG_INDEX)
    while i != ida_netnode.BADNODE:
        segments += 1
        i = node.altnext(i, trace._TAG_INDEX)
    return {
        "version": node.altval(trace._META_VERSION, trace._TAG_META),
        "segments": segments,
        "next_chunk_start": node.altval(trace._META_NEXT_CHUNK, trace._TAG_META),
        "next_segment_id": node.altval(trace._META_NEXT_SEG_ID, trace._TAG_META),
        "total_records": node.altval(trace._META_TOTAL_RECORDS, trace._TAG_META),
    }


def _flush() -> None:
    backend = trace._state["idb_backend"]
    if backend is not None:
        backend.flush()


@test()
def test_trace_idb_round_trip():
    """configure_idb + one call + flush -> iter_records yields the record."""
    _reset_trace(batch_records=1)
    try:
        _call_through_registry("server_health", {})
        records = list(trace.iter_idb_records())
        assert len(records) == 1, f"expected 1 record, got {len(records)}"
        assert records[0]["tool"] == "server_health"
        assert records[0]["arguments"] == {}
    finally:
        _teardown_trace()


@test()
def test_trace_idb_multiple_segments_preserve_order():
    """Per-record flushing creates multiple segments; iteration preserves order."""
    _reset_trace(batch_records=1)
    try:
        for _ in range(5):
            _call_through_registry("server_health", {})
        records = list(trace.iter_idb_records())
        assert len(records) == 5
        stats = _read_stats()
        assert stats["segments"] == 5
        assert stats["total_records"] == 5
    finally:
        _teardown_trace()


@test()
def test_trace_idb_large_batch_spans_multiple_supvals():
    """A batch whose gzipped size exceeds one supval (>1024 B) round-trips."""
    _reset_trace(batch_records=200, batch_bytes=10 * 1024 * 1024)
    try:
        for _ in range(200):
            _call_through_registry("server_health", {})
        _flush()
        stats = _read_stats()
        assert stats["segments"] == 1, f"expected 1 segment, got {stats['segments']}"
        records = list(trace.iter_idb_records())
        assert len(records) == 200
        for r in records:
            assert r["tool"] == "server_health"
    finally:
        _teardown_trace()


@test()
def test_trace_idb_gap_trick_adjacent_segments_intact():
    """Two segments stored with the +1 gap both decode to their own payloads."""
    _reset_trace(batch_records=1)
    try:
        _call_through_registry("server_health", {})
        _call_through_registry("server_health", {"arg": "second"})
        stats = _read_stats()
        assert stats["segments"] == 2
        records = list(trace.iter_idb_records())
        assert len(records) == 2
        assert records[0]["arguments"] == {}
        assert records[1]["arguments"] == {"arg": "second"}
    finally:
        _teardown_trace()


@test()
def test_trace_idb_batching_defers_writes_until_threshold():
    """Appends below threshold stay buffered; crossing it flushes one segment."""
    _reset_trace(batch_records=3)
    try:
        _call_through_registry("server_health", {})
        _call_through_registry("server_health", {})
        assert _read_stats()["segments"] == 0
        _call_through_registry("server_health", {})
        assert _read_stats()["segments"] == 1
        assert _read_stats()["total_records"] == 3
        _call_through_registry("server_health", {})
        assert _read_stats()["segments"] == 1
        _flush()
        assert _read_stats()["segments"] == 2
        assert _read_stats()["total_records"] == 4
    finally:
        _teardown_trace()


@test()
def test_trace_idb_unsafe_arguments_logged_verbatim():
    """@unsafe tool arguments are stored as-is (no redaction)."""
    _reset_trace(batch_records=1)
    try:
        _call_through_registry("py_eval", {"code": "2+2"})
        records = list(trace.iter_idb_records())
        assert records[0]["tool"] == "py_eval"
        assert records[0]["arguments"] == {"code": "2+2"}
    finally:
        _teardown_trace()


@test()
def test_trace_idb_meta_version_and_counters():
    """meta exposes version + monotonically increasing counters."""
    _reset_trace(batch_records=1)
    try:
        _call_through_registry("server_health", {})
        _call_through_registry("server_health", {})
        stats = _read_stats()
        assert stats["version"] >= 1
        assert stats["segments"] == 2
        assert stats["total_records"] == 2
        assert stats["next_segment_id"] == 2
        assert stats["next_chunk_start"] > 0
    finally:
        _teardown_trace()


@test()
def test_trace_idb_shutdown_flushes_pending_buffer():
    """Shutdown must drain the in-memory buffer to a final segment."""
    _reset_trace(batch_records=100)
    try:
        _call_through_registry("server_health", {})
        _call_through_registry("server_health", {})
        assert _read_stats()["segments"] == 0
        trace.shutdown()
        records = list(trace.iter_idb_records())
        assert len(records) == 2, f"expected 2 flushed records, got {len(records)}"
    finally:
        _teardown_trace()


@test()
def test_trace_idb_records_duration_and_timestamp_shape():
    """Each record has numeric duration_ms and ISO-8601 UTC timestamp."""
    _reset_trace(batch_records=1)
    try:
        _call_through_registry("server_health", {})
        rec = list(trace.iter_idb_records())[0]
        assert isinstance(rec["duration_ms"], (int, float))
        assert rec["duration_ms"] >= 0
        assert rec["ts"].endswith("Z")
        assert "T" in rec["ts"]
    finally:
        _teardown_trace()


@test()
def test_trace_install_tracer_idempotent():
    """Calling install_tracer() twice does not double-wrap tools/call."""
    _reset_trace(batch_records=1)
    try:
        from ..rpc import MCP_SERVER
        first = MCP_SERVER.registry.methods["tools/call"]
        trace.install_tracer()
        assert MCP_SERVER.registry.methods["tools/call"] is first

        _call_through_registry("server_health", {})
        records = list(trace.iter_idb_records())
        assert len(records) == 1
    finally:
        _teardown_trace()


@test()
def test_trace_install_tracer_lifts_to_outermost():
    """install_tracer() lifts the tracer above a later non-tracer wrapper."""
    _reset_trace(batch_records=1)
    try:
        from ..rpc import MCP_SERVER

        observed: list[str] = []
        prior_tracer = MCP_SERVER.registry.methods["tools/call"]
        assert getattr(prior_tracer, "_ida_mcp_tracer", False)

        def outer(name, arguments=None, _meta=None):
            observed.append(name)
            return prior_tracer(name, arguments, _meta)

        MCP_SERVER.registry.methods["tools/call"] = outer
        try:
            # `outer` is now the outermost layer; the tracer is inner.
            # install_tracer() should re-wrap so the tracer is outermost
            # while `outer` remains on the call path between tracer and
            # the original method.
            trace.install_tracer()
            top = MCP_SERVER.registry.methods["tools/call"]
            assert getattr(top, "_ida_mcp_tracer", False)
            assert top is not prior_tracer

            _call_through_registry("server_health", {})
            # `outer` is still in the chain, so it observed the call once.
            assert observed == ["server_health"]
            # The new outermost tracer recorded the call.
            records = list(trace.iter_idb_records())
            assert any(r["tool"] == "server_health" for r in records)
        finally:
            MCP_SERVER.registry.methods["tools/call"] = prior_tracer
    finally:
        _teardown_trace()
