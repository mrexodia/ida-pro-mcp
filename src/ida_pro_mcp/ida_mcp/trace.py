"""Tool-call tracing.

Two opt-in backends:

  File backend:  one JSON record per tools/call to a JSONL file.
                 trace.configure(path) or IDA_MCP_TRACE_FILE=<path>.

  IDB backend:   append-only gzipped batches in netnode `$ ida_mcp.trace`.
                 trace.configure_idb() or IDA_MCP_TRACE_IDB=1.
                 Tags: META (version, next_chunk, next_seg_id, total_records),
                 INDEX (seg_id -> start), DATA (blobs). One empty supval sits
                 between blobs so getblob() self-terminates. All netnode ops
                 run on the IDA main thread via @idasync.
"""

import atexit
import gzip
import json
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from .rpc import MCP_SERVER, MCP_UNSAFE, tool
from .sync import idasync


# ----------------------------------------------------------------------------
# Constants
# ----------------------------------------------------------------------------

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


# ----------------------------------------------------------------------------
# Shared state
# ----------------------------------------------------------------------------

_state_lock = threading.Lock()
_state: dict[str, Any] = {
    "verbose": False,
    "patched": False,
    "file_backend": None,
    "idb_backend": None,
    "atexit_registered": False,
}


# ----------------------------------------------------------------------------
# File backend
# ----------------------------------------------------------------------------


class FileBackend:
    """One JSON line per call, flushed after every write."""

    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.Lock()
        self._file = open(path, "a", encoding="utf-8")

    def append(self, record: dict) -> None:
        line = json.dumps(record, separators=(",", ":"), default=str)
        with self._lock:
            if self._file is None:
                return
            self._file.write(line)
            self._file.write("\n")
            self._file.flush()

    def flush(self) -> None:
        with self._lock:
            if self._file is not None:
                self._file.flush()

    def close(self) -> None:
        with self._lock:
            if self._file is not None:
                try:
                    self._file.flush()
                    self._file.close()
                finally:
                    self._file = None


# ----------------------------------------------------------------------------
# Netnode backend
# ----------------------------------------------------------------------------


@idasync
def _netnode_flush_segment(payload: bytes, record_count: int) -> None:
    """Write one segment and advance all meta counters in a single main-thread hop.

    Keeping data + index + meta writes inside one @idasync job prevents a
    concurrent kill from slipping between partial updates.
    """
    import ida_netnode

    node = ida_netnode.netnode(IDB_NETNODE_NAME, 0, True)

    if node.altval(_META_VERSION, _TAG_META) == 0:
        node.altset(_META_VERSION, _FORMAT_VERSION, _TAG_META)

    start = node.altval(_META_NEXT_CHUNK, _TAG_META)
    seg_id = node.altval(_META_NEXT_SEG_ID, _TAG_META)

    if not node.setblob(payload, start, _TAG_DATA):
        # Leave meta untouched so the caller keeps the buffered batch for retry.
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
def _netnode_read_stats() -> dict[str, int]:
    import ida_netnode
    node = ida_netnode.netnode(IDB_NETNODE_NAME, 0, False)
    if node == ida_netnode.BADNODE:
        return {
            "version": 0,
            "segments": 0,
            "next_chunk_start": 0,
            "next_segment_id": 0,
            "total_records": 0,
        }
    segments = 0
    i = node.altfirst(_TAG_INDEX)
    while i != ida_netnode.BADNODE:
        segments += 1
        i = node.altnext(i, _TAG_INDEX)
    return {
        "version": node.altval(_META_VERSION, _TAG_META),
        "segments": segments,
        "next_chunk_start": node.altval(_META_NEXT_CHUNK, _TAG_META),
        "next_segment_id": node.altval(_META_NEXT_SEG_ID, _TAG_META),
        "total_records": node.altval(_META_TOTAL_RECORDS, _TAG_META),
    }


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


@idasync
def _netnode_kill() -> None:
    import ida_netnode
    node = ida_netnode.netnode(IDB_NETNODE_NAME, 0, False)
    if node != ida_netnode.BADNODE:
        node.kill()


class NetnodeBackend:
    """Append-only compressed-segment log in an IDA netnode."""

    def __init__(self, *, batch_records: int, batch_bytes: int):
        self.batch_records = max(1, batch_records)
        self.batch_bytes = max(1024, batch_bytes)
        self._lock = threading.Lock()        # buffer + closed flag
        self._flush_lock = threading.Lock()  # serializes flushes and clears
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

    def clear(self) -> dict:
        # Flush lock drains any in-flight write before we kill the node, so a
        # pending @idasync meta-bump cannot resurrect the node after kill().
        with self._flush_lock:
            with self._lock:
                self._buffer.clear()
                self._buffered_bytes = 0
            _netnode_kill()
        return {"ok": True}

    def close(self) -> None:
        # Set closed before draining so concurrent appends drop instead of
        # racing into a buffer we're about to flush.
        with self._lock:
            self._closed = True
        self.flush()

    def stats(self) -> dict[str, int]:
        return _netnode_read_stats()

    def iter_records(self) -> Iterator[dict]:
        self.flush()
        for blob in _netnode_iter_blobs():
            try:
                raw = gzip.decompress(blob)
            except OSError:
                continue  # tolerate a truncated tail segment
            for line in raw.splitlines():
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue


# ----------------------------------------------------------------------------
# Public configure / shutdown
# ----------------------------------------------------------------------------


def _ensure_patched() -> None:
    with _state_lock:
        if _state["patched"]:
            return
        _state["patched"] = True
    _install_trace_patch()
    with _state_lock:
        if not _state["atexit_registered"]:
            atexit.register(shutdown)
            _state["atexit_registered"] = True


def configure(path: str, *, verbose: bool = False) -> None:
    """Enable the file backend. Appends to `path` (creates parents)."""
    resolved = Path(path).expanduser().resolve()
    resolved.parent.mkdir(parents=True, exist_ok=True)
    new_backend = FileBackend(resolved)
    with _state_lock:
        old = _state["file_backend"]
        _state["file_backend"] = new_backend
        if verbose:
            _state["verbose"] = True
    if old is not None:
        old.close()
    _ensure_patched()


def configure_idb(
    *,
    verbose: bool = False,
    batch_records: int = _DEFAULT_BATCH_RECORDS,
    batch_bytes: int = _DEFAULT_BATCH_BYTES,
) -> None:
    """Enable the IDB backend. Batches writes before committing to the netnode."""
    new_backend = NetnodeBackend(
        batch_records=batch_records, batch_bytes=batch_bytes
    )
    with _state_lock:
        old = _state["idb_backend"]
        _state["idb_backend"] = new_backend
        if verbose:
            _state["verbose"] = True
    if old is not None:
        old.close()
    _ensure_patched()


def configure_from_env() -> None:
    path = os.environ.get("IDA_MCP_TRACE_FILE", "").strip()
    verbose = os.environ.get("IDA_MCP_TRACE_VERBOSE", "").strip() not in ("", "0", "false", "no")
    idb = os.environ.get("IDA_MCP_TRACE_IDB", "").strip() not in ("", "0", "false", "no")
    if path:
        configure(path, verbose=verbose)
    if idb:
        configure_idb(verbose=verbose)


def shutdown() -> None:
    """Close both backends (flushing any pending IDB segment)."""
    with _state_lock:
        file_b = _state["file_backend"]
        idb_b = _state["idb_backend"]
        _state["file_backend"] = None
        _state["idb_backend"] = None
    if idb_b is not None:
        try:
            idb_b.close()
        except Exception:
            pass
    if file_b is not None:
        try:
            file_b.close()
        except Exception:
            pass


# ----------------------------------------------------------------------------
# Introspection helpers used by the test suite and future tooling
# ----------------------------------------------------------------------------


def flush_idb() -> None:
    """Force the IDB backend to flush any buffered records."""
    with _state_lock:
        backend = _state["idb_backend"]
    if backend is not None:
        backend.flush()


def clear_idb() -> dict:
    """Wipe every segment from the IDB trace netnode (preserves configuration)."""
    with _state_lock:
        backend = _state["idb_backend"]
    if backend is None:
        try:
            _netnode_kill()
            return {"ok": True, "note": "no backend active; wiped node directly"}
        except Exception as e:
            return {"ok": False, "error": str(e)}
    return backend.clear()


def idb_stats() -> dict[str, int]:
    """Return counters from the IDB trace netnode (zero dict if none exists)."""
    return _netnode_read_stats()


def iter_idb_records() -> Iterator[dict]:
    """Iterate every trace record stored in the IDB (flushes pending first)."""
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


# ----------------------------------------------------------------------------
# Middleware
# ----------------------------------------------------------------------------


def _redact_args(tool_name: str, arguments: Any) -> Any:
    if _state["verbose"]:
        return arguments
    if tool_name in MCP_UNSAFE:
        return "<redacted>"
    return arguments


def _now_iso() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def _dispatch(record: dict) -> None:
    with _state_lock:
        file_b = _state["file_backend"]
        idb_b = _state["idb_backend"]
    if file_b is not None:
        try:
            file_b.append(record)
        except Exception:
            pass
    if idb_b is not None:
        try:
            idb_b.append(record)
        except Exception:
            pass


def _install_trace_patch() -> None:
    original = MCP_SERVER.registry.methods["tools/call"]

    def traced(name, arguments=None, _meta=None):
        start = time.monotonic()
        record: dict[str, Any] = {
            "ts": _now_iso(),
            "tool": name,
            "arguments": _redact_args(name, arguments or {}),
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

    MCP_SERVER.registry.methods["tools/call"] = traced


# ----------------------------------------------------------------------------
# MCP tool
# ----------------------------------------------------------------------------


@tool
def trace_clear() -> dict:
    """Wipe the IDB trace log (netnode `$ ida_mcp.trace`). File backend unaffected."""
    return clear_idb()


__all__ = [
    "configure",
    "configure_idb",
    "configure_from_env",
    "shutdown",
    "flush_idb",
    "clear_idb",
    "idb_stats",
    "iter_idb_records",
    "trace_clear",
    "IDB_NETNODE_NAME",
]
