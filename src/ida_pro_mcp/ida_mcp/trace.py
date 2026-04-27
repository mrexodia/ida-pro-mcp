"""Tool-call tracing.

Always-on. The trace lives in the IDB under netnode `$ ida_mcp.trace` as
append-only gzipped batches. Tags:
  META  (version, next_chunk, next_seg_id, total_records),
  INDEX (seg_id -> start),
  DATA  (blobs).
One empty supval sits between blobs so getblob() self-terminates. All netnode
writes run on the IDA main thread via @idasync.

Use the `ida-mcp-trace-dump` script to export an IDB's trace as JSONL.
"""

import atexit
import gzip
import json
import threading
import time
from datetime import datetime, timezone
from typing import Any, Iterator

from .rpc import MCP_SERVER
from .sync import idasync


IDB_NETNODE_NAME = "$ ida_mcp.trace"
_TAG_META = ord("M")
_TAG_INDEX = ord("I")
_TAG_DATA = ord("D")
_CHUNK = 1024  # MAXSPECSIZE: one netnode supval
_FORMAT_VERSION = 1

_META_VERSION = 0
_META_NEXT_CHUNK = 1
_META_NEXT_SEG_ID = 2
_META_TOTAL_RECORDS = 3

_DEFAULT_BATCH_RECORDS = 256
_DEFAULT_BATCH_BYTES = 64 * 1024


_state_lock = threading.Lock()
_state: dict[str, Any] = {
    "idb_backend": None,
    "atexit_registered": False,
    "idb_hook": None,
}


@idasync
def _netnode_flush_segment(payload: bytes, record_count: int) -> None:
    """Write one segment and bump meta counters atomically on the IDA main thread."""
    import ida_netnode

    node = ida_netnode.netnode(IDB_NETNODE_NAME, 0, True)

    if node.altval(_META_VERSION, _TAG_META) == 0:
        node.altset(_META_VERSION, _FORMAT_VERSION, _TAG_META)

    start = node.altval(_META_NEXT_CHUNK, _TAG_META)
    seg_id = node.altval(_META_NEXT_SEG_ID, _TAG_META)

    if not node.setblob(payload, start, _TAG_DATA):
        raise RuntimeError(f"setblob failed at index {start}")

    node.altset(seg_id, start, _TAG_INDEX)

    used_chunks = (len(payload) + _CHUNK - 1) // _CHUNK
    new_start = start + used_chunks + 1  # +1: empty supval that terminates getblob
    new_seg_id = seg_id + 1

    node.altset(_META_NEXT_CHUNK, new_start, _TAG_META)
    node.altset(_META_NEXT_SEG_ID, new_seg_id, _TAG_META)

    cur_total = node.altval(_META_TOTAL_RECORDS, _TAG_META)
    node.altset(_META_TOTAL_RECORDS, cur_total + record_count, _TAG_META)


@idasync
def _netnode_iter_blobs() -> list[bytes]:
    """Return every segment's compressed blob in segment-id order."""
    import ida_netnode
    node = ida_netnode.netnode(IDB_NETNODE_NAME, 0, False)
    if node == ida_netnode.BADNODE:
        return []
    pairs: list[tuple[int, int]] = []
    i = node.altfirst(_TAG_INDEX)
    while i != ida_netnode.BADNODE:
        pairs.append((i, node.altval(i, _TAG_INDEX)))
        i = node.altnext(i, _TAG_INDEX)
    pairs.sort()
    blobs: list[bytes] = []
    for _, start in pairs:
        blob = node.getblob(start, _TAG_DATA)
        if isinstance(blob, tuple):
            blob = blob[0]
        if blob:
            blobs.append(bytes(blob))
    return blobs


class NetnodeBackend:
    """Append-only compressed-segment log in an IDA netnode."""

    def __init__(self, *, batch_records: int, batch_bytes: int):
        self.batch_records = max(1, batch_records)
        self.batch_bytes = max(1024, batch_bytes)
        self._lock = threading.Lock()
        self._flush_lock = threading.Lock()
        self._buffer: list[bytes] = []
        self._buffered_bytes = 0
        self._closed = False

    def append(self, record: dict) -> None:
        line = json.dumps(record, separators=(",", ":"), default=str).encode("utf-8")
        flush_now = False
        with self._lock:
            if self._closed:
                return
            self._buffer.append(line)
            self._buffered_bytes += len(line) + 1
            if (
                len(self._buffer) >= self.batch_records
                or self._buffered_bytes >= self.batch_bytes
            ):
                flush_now = True
        if flush_now:
            self.flush()

    def flush(self) -> None:
        with self._flush_lock:
            with self._lock:
                if not self._buffer:
                    return
                to_flush = self._buffer
                self._buffer = []
                self._buffered_bytes = 0
            payload = b"\n".join(to_flush) + b"\n"
            compressed = gzip.compress(payload, mtime=0)
            try:
                _netnode_flush_segment(compressed, len(to_flush))
            except Exception:
                # Re-prepend the failed batch so retries keep wall-clock order.
                with self._lock:
                    self._buffer[:0] = to_flush
                    self._buffered_bytes = sum(len(l) + 1 for l in self._buffer)
                return

    def close(self) -> None:
        with self._lock:
            self._closed = True
        self.flush()

    def iter_records(self) -> Iterator[dict]:
        self.flush()
        for blob in _netnode_iter_blobs():
            try:
                raw = gzip.decompress(blob)
            except OSError:
                continue
            for line in raw.splitlines():
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue


def _ensure_atexit() -> None:
    with _state_lock:
        if _state["atexit_registered"]:
            return
        _state["atexit_registered"] = True
    atexit.register(shutdown)


def _install_idb_hook() -> None:
    """Flush pending records when the IDB is saved or closed."""
    with _state_lock:
        if _state["idb_hook"] is not None:
            return
    try:
        import ida_idp
    except Exception:
        return

    backend_ref = _state

    class _TraceFlushHook(ida_idp.IDB_Hooks):
        def savebase(self, *args):
            b = backend_ref.get("idb_backend")
            if b is not None:
                try:
                    b.flush()
                except Exception:
                    pass
            return 0

        def closebase(self, *args):
            b = backend_ref.get("idb_backend")
            if b is not None:
                try:
                    b.flush()
                except Exception:
                    pass
            return 0

    hook = _TraceFlushHook()
    if hook.hook():
        with _state_lock:
            _state["idb_hook"] = hook


def configure_idb(
    *,
    batch_records: int = _DEFAULT_BATCH_RECORDS,
    batch_bytes: int = _DEFAULT_BATCH_BYTES,
) -> None:
    """Enable IDB tracing. Batches writes before committing to the netnode."""
    new_backend = NetnodeBackend(
        batch_records=batch_records, batch_bytes=batch_bytes
    )
    with _state_lock:
        old = _state["idb_backend"]
        _state["idb_backend"] = new_backend
    if old is not None:
        old.close()
    install_tracer()
    _ensure_atexit()
    _install_idb_hook()


def shutdown() -> None:
    """Flush and close the backend, unhook the IDB listener."""
    with _state_lock:
        idb_b = _state["idb_backend"]
        hook = _state["idb_hook"]
        _state["idb_backend"] = None
        _state["idb_hook"] = None
    if hook is not None:
        try:
            hook.unhook()
        except Exception:
            pass
    if idb_b is not None:
        try:
            idb_b.close()
        except Exception:
            pass


def iter_idb_records() -> Iterator[dict]:
    """Iterate every trace record stored in the IDB. Flushes pending writes first."""
    with _state_lock:
        backend = _state["idb_backend"]
    if backend is None:
        for blob in _netnode_iter_blobs():
            try:
                raw = gzip.decompress(blob)
            except OSError:
                continue
            for line in raw.splitlines():
                if line:
                    try:
                        yield json.loads(line)
                    except json.JSONDecodeError:
                        continue
        return
    yield from backend.iter_records()


def _now_iso() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def _dispatch(record: dict) -> None:
    with _state_lock:
        idb_b = _state["idb_backend"]
    if idb_b is not None:
        try:
            idb_b.append(record)
        except Exception:
            pass


def install_tracer() -> None:
    """Wrap tools/call. Idempotent; lifts the tracer to outermost if already wrapped."""
    inner = MCP_SERVER.registry.methods["tools/call"]
    if getattr(inner, "_ida_mcp_tracer", False):
        return
    original = inner

    def traced(name, arguments=None, _meta=None):
        start = time.monotonic()
        record: dict[str, Any] = {
            "ts": _now_iso(),
            "tool": name,
            "arguments": arguments or {},
        }
        try:
            response = original(name, arguments, _meta)
        except Exception as e:
            record["duration_ms"] = round((time.monotonic() - start) * 1000, 2)
            record["error"] = f"{type(e).__name__}: {e}"
            _dispatch(record)
            raise

        record["duration_ms"] = round((time.monotonic() - start) * 1000, 2)
        record["isError"] = bool(response.get("isError"))
        record["structuredContent"] = response.get("structuredContent")

        meta = (response.get("_meta") or {}).get("ida_mcp") or {}
        if meta.get("output_truncated"):
            record["full_result_size"] = meta.get("total_chars")
            record["truncated"] = True
            record["output_id"] = meta.get("output_id")

        _dispatch(record)
        return response

    traced._ida_mcp_tracer = True
    MCP_SERVER.registry.methods["tools/call"] = traced


__all__ = [
    "configure_idb",
    "install_tracer",
    "shutdown",
    "iter_idb_records",
    "IDB_NETNODE_NAME",
]
