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
import os
import re
import tempfile
import threading
import time
from collections import deque
from datetime import datetime, timezone
from typing import Any, Callable, Iterator, Optional

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

# Per-record cap for what gets persisted into the IDB netnode. The tracer used
# to write the FULL arguments + structuredContent of every tool call verbatim
# (e.g. a whole py_exec_file source blob, or a megabyte of decompiled text)
# into the database, which grows the IDB permanently and unbounded. We redact
# each record to a sane size before it ever reaches the backend: long strings
# are clipped and deep/wide containers are summarized, mirroring the rpc output
# truncation idea (rpc.OUTPUT_LIMIT_PREVIEW_STR_LEN / OUTPUT_LIMIT_PREVIEW_ITEMS).
_TRACE_MAX_STR = 1024  # max chars kept for any single string value
_TRACE_MAX_ITEMS = 64  # max elements kept from any single list
_TRACE_MAX_DEPTH = 6  # max container nesting descended before summarizing


def _redact_for_trace(value: Any, depth: int = 0) -> Any:
    """Cap/redact one traced value so the IDB netnode cannot grow unbounded.

    Clips long strings to _TRACE_MAX_STR chars (appending a "... [N chars
    total]" marker), truncates long lists to _TRACE_MAX_ITEMS, and stops
    descending past _TRACE_MAX_DEPTH (summarizing the remaining subtree). Bytes
    are summarized by length. Pure: no IDA, no live process.
    """
    if isinstance(value, str):
        if len(value) > _TRACE_MAX_STR:
            return value[:_TRACE_MAX_STR] + f"... [{len(value)} chars total]"
        return value
    if isinstance(value, (bytes, bytearray)):
        return f"<{len(value)} bytes>"
    if depth >= _TRACE_MAX_DEPTH:
        if isinstance(value, list):
            return f"[... {len(value)} items, depth-truncated]"
        if isinstance(value, dict):
            return f"{{... {len(value)} keys, depth-truncated}}"
        return value
    if isinstance(value, list):
        clipped = [_redact_for_trace(v, depth + 1) for v in value[:_TRACE_MAX_ITEMS]]
        if len(value) > _TRACE_MAX_ITEMS:
            clipped.append(f"... [{len(value)} items total]")
        return clipped
    if isinstance(value, dict):
        return {k: _redact_for_trace(v, depth + 1) for k, v in value.items()}
    return value

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
            # Cap/redact before the record is committed so a single huge
            # arguments/structuredContent blob cannot bloat the IDB netnode.
            idb_b.append(_redact_for_trace(record))
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


# ============================================================================
# Probe infrastructure (Phase 0 plumbing for the probe toolkit)
#
# Pure-Python ring buffer + registry + JSONL persistence. ProbeRing and the
# registry import without idaapi; only the per-record sha-stamp touches idc and
# is guarded so the module stays importable outside IDA.
# ============================================================================

_PROBE_RING_DEFAULT_CAP = 4096
_PROBE_RING_HARD_MAX = 65536


class ProbeRing:
    """Bounded ring of probe-event records with a monotonic seq cursor.

    buffer_mode "circular" evicts the oldest record on overflow (bumping the
    dropped counter); "linear" stops appending once full and raises the `full`
    flag. The seq cursor is monotonic across the whole lifetime of the ring,
    so drain(since_cursor=...) is stable even after eviction.
    """

    def __init__(self, cap: int = _PROBE_RING_DEFAULT_CAP, *, buffer_mode: str = "circular"):
        cap = int(cap)
        if cap < 1:
            cap = 1
        if cap > _PROBE_RING_HARD_MAX:
            cap = _PROBE_RING_HARD_MAX
        if buffer_mode not in ("circular", "linear"):
            raise ValueError(f"buffer_mode must be 'circular' or 'linear', got {buffer_mode!r}")
        self.cap = cap
        self.buffer_mode = buffer_mode
        self._lock = threading.Lock()
        self._buf: deque = deque(maxlen=cap)
        self._seq = 0
        self.dropped = 0
        self.full = False

    def append(self, record: dict) -> Optional[int]:
        """Append a record, stamping it with the next seq. Returns the seq, or
        None if a "linear" ring is full and the record was dropped."""
        with self._lock:
            if self.buffer_mode == "linear" and len(self._buf) >= self.cap:
                self.full = True
                self.dropped += 1
                return None
            if self.buffer_mode == "circular" and len(self._buf) >= self.cap:
                self.dropped += 1
            seq = self._seq
            self._seq += 1
            entry = dict(record)
            entry["_seq"] = seq
            self._buf.append(entry)
            if len(self._buf) >= self.cap:
                self.full = True
            return seq

    def drain(
        self,
        since_cursor: int = 0,
        filter: Optional[Callable[[dict], bool]] = None,
        limit: Optional[int] = None,
    ) -> list[dict]:
        """Return records with _seq >= since_cursor (optionally filtered),
        oldest first, up to limit. Does not remove anything from the ring."""
        with self._lock:
            snapshot = list(self._buf)
        out: list[dict] = []
        for entry in snapshot:
            if entry.get("_seq", 0) < since_cursor:
                continue
            if filter is not None and not filter(entry):
                continue
            out.append(entry)
            if limit is not None and len(out) >= limit:
                break
        return out

    def stats(self) -> dict:
        with self._lock:
            return {
                "cap": self.cap,
                "buffer_mode": self.buffer_mode,
                "size": len(self._buf),
                "next_cursor": self._seq,
                "dropped": self.dropped,
                "full": self.full,
            }

    def clear(self) -> None:
        with self._lock:
            self._buf.clear()
            self.dropped = 0
            self.full = False


# ----------------------------------------------------------------------------
# Probe registry: probe_id -> probe descriptor
# ----------------------------------------------------------------------------

_probe_registry: dict[str, dict] = {}
_probe_registry_lock = threading.Lock()


def register_probe(
    probe_id: str,
    *,
    ea: Any,
    kind: str,
    condition: Any = None,
    max_hits: Optional[int] = None,
    armed: bool = True,
    capture: Any = None,
) -> dict:
    """Register (or replace) a probe. Returns the stored descriptor."""
    descriptor = {
        "probe_id": probe_id,
        "ea": ea,
        "kind": kind,
        "condition": condition,
        "hits": 0,
        "max_hits": max_hits,
        "armed": bool(armed),
        "capture": capture,
    }
    with _probe_registry_lock:
        _probe_registry[probe_id] = descriptor
    return descriptor


def get_probe(probe_id: str) -> Optional[dict]:
    with _probe_registry_lock:
        return _probe_registry.get(probe_id)


def list_probes() -> list[dict]:
    with _probe_registry_lock:
        return list(_probe_registry.values())


def remove_probe(probe_id: str) -> bool:
    with _probe_registry_lock:
        return _probe_registry.pop(probe_id, None) is not None


def clear_probes() -> None:
    with _probe_registry_lock:
        _probe_registry.clear()


# ----------------------------------------------------------------------------
# Probe event persistence (ring + JSONL file, sha-stamped _meta)
# ----------------------------------------------------------------------------

_probe_ring = ProbeRing()
_probe_persist_lock = threading.Lock()
_probe_state: dict[str, Any] = {
    "ring": _probe_ring,
    "session_id": None,
    "file_path": None,
}


def get_probe_ring() -> ProbeRing:
    return _probe_state["ring"]


def probe_dir() -> str:
    """Directory probe JSONL files are written to. Override with
    IDA_MCP_PROBE_DIR; defaults to <tempdir>/ida_mcp_probes."""
    return os.environ.get(
        "IDA_MCP_PROBE_DIR",
        os.path.join(tempfile.gettempdir(), "ida_mcp_probes"),
    )


def _input_file_sha256() -> Optional[str]:
    """Best-effort IDB input-file SHA-256; None outside IDA."""
    try:
        import idc
    except Exception:
        return None
    try:
        sha = idc.retrieve_input_file_sha256()
        if sha:
            return sha.hex() if isinstance(sha, (bytes, bytearray)) else str(sha)
    except Exception:
        pass
    try:
        path = idc.get_input_file_path()
        if path and os.path.isfile(path):
            import hashlib
            h = hashlib.sha256()
            with open(path, "rb") as fh:
                for block in iter(lambda: fh.read(65536), b""):
                    h.update(block)
            return h.hexdigest()
    except Exception:
        pass
    return None


def _probe_meta() -> dict:
    return {"sha256": _input_file_sha256(), "dirty": True}


def configure_probes(session_id: str, *, cap: Optional[int] = None, buffer_mode: Optional[str] = None) -> dict:
    """Set the session id (used for the JSONL filename) and optionally re-create
    the ring with a new cap / buffer_mode. Returns {session_id, file_path}."""
    with _probe_persist_lock:
        if cap is not None or buffer_mode is not None:
            ring = ProbeRing(
                cap if cap is not None else _probe_state["ring"].cap,
                buffer_mode=buffer_mode if buffer_mode is not None else _probe_state["ring"].buffer_mode,
            )
            _probe_state["ring"] = ring
        directory = probe_dir()
        try:
            os.makedirs(directory, exist_ok=True)
        except Exception:
            pass
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        safe_session = "".join(c if c.isalnum() or c in "-_." else "_" for c in str(session_id))
        file_path = os.path.join(directory, f"probes_{stamp}_{safe_session}.jsonl")
        _probe_state["session_id"] = session_id
        _probe_state["file_path"] = file_path
        return {"session_id": session_id, "file_path": file_path}


def record_probe_event(event: dict) -> dict:
    """Append an event to the probe ring AND persist it to the session JSONL
    file. Stamps each persisted record with _meta (IDB sha + dirty=true).
    Returns the appended record (with _seq, _meta)."""
    record = dict(event)
    record["_meta"] = _probe_meta()
    record.setdefault("ts", _now_iso())
    with _probe_persist_lock:
        ring = _probe_state["ring"]
        file_path = _probe_state["file_path"]
    seq = ring.append(record)
    if seq is not None:
        record["_seq"] = seq
    if file_path is not None:
        line = json.dumps(record, separators=(",", ":"), default=str)
        try:
            with open(file_path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except Exception:
            pass
    return record


# ============================================================================
# PURE-LOGIC AUTOPILOT ANALYSIS over ProbeRing records (no idaapi)
#
# These helpers roll up / diff already-captured probe records so an agent can
# reason over 10^5 hits in a single response instead of streaming every record.
# They take plain dicts / hex strings and are fully unit-testable headless.
# ============================================================================

_SUMMARY_GROUP_FIELDS = ("probe_id", "func", "caller", "tid", "pc")


def _record_group_key(record: dict, group_by: str) -> Any:
    """Extract the grouping key for one record.

    Top-level fields (probe_id, tid) are read directly; the call-tree fields
    (func, caller, pc) live inside the captured dict under common token names
    and are read from there, falling back to the top level. Missing keys group
    under the literal None bucket so nothing is silently dropped.
    """
    if group_by in ("probe_id", "tid"):
        return record.get(group_by)
    captured = record.get("captured") or {}
    if group_by == "caller":
        return captured.get("caller", record.get("caller"))
    if group_by == "func":
        return record.get("func", record.get("ea"))
    if group_by == "pc":
        for token in ("eip", "rip", "pc"):
            if token in captured:
                return captured.get(token)
        return record.get("pc", record.get("ea"))
    return None


def _coerce_number(value: Any) -> Optional[float]:
    """Best-effort numeric coercion of a captured value.

    Accepts ints/floats directly and hex/dec strings ("0x10", "42"). Captured
    mem/error dicts and anything unparseable yield None (excluded from min/max).
    """
    if isinstance(value, bool):
        return float(value)
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return None
        try:
            return float(int(s, 0))
        except ValueError:
            pass
        try:
            return float(s)
        except ValueError:
            return None
    return None


def _record_numeric(record: dict, field: Optional[str]) -> Optional[float]:
    """Pull the numeric value of `field` from a record (top level or captured)."""
    if not field:
        return None
    if field in record:
        return _coerce_number(record.get(field))
    captured = record.get("captured") or {}
    if field in captured:
        return _coerce_number(captured.get(field))
    return None


def summarize_records(
    records: Any,
    group_by: str = "probe_id",
    *,
    numeric_field: Optional[str] = None,
) -> dict:
    """Server-side rollup of probe records grouped by one dimension.

    group_by must be one of {"probe_id","func","caller","tid","pc"}. Returns a
    dict with the overall total plus a per-group breakdown: count, the set of
    distinct callers (the call-tree edge), and, when numeric_field is given, the
    min/max/last of that field coerced across the group. Pure: takes a list of
    record dicts (as produced by build_probe_record / drained from the ring) and
    returns a plain dict; no IDA, no live process.
    """
    if group_by not in _SUMMARY_GROUP_FIELDS:
        raise ValueError(
            f"group_by must be one of {_SUMMARY_GROUP_FIELDS}, got {group_by!r}"
        )

    rows = list(records or [])
    groups: dict[Any, dict] = {}
    order: list[Any] = []

    for record in rows:
        if not isinstance(record, dict):
            continue
        key = _record_group_key(record, group_by)
        bucket = groups.get(key)
        if bucket is None:
            bucket = {
                "key": key,
                "count": 0,
                "_callers": set(),
                "_nums": [],
            }
            groups[key] = bucket
            order.append(key)
        bucket["count"] += 1

        captured = record.get("captured") or {}
        caller = captured.get("caller", record.get("caller"))
        if caller is not None:
            bucket["_callers"].add(caller)

        if numeric_field is not None:
            n = _record_numeric(record, numeric_field)
            if n is not None:
                bucket["_nums"].append(n)

    out_groups: list[dict] = []
    for key in order:
        bucket = groups[key]
        nums = bucket["_nums"]
        entry: dict = {
            "key": bucket["key"],
            "count": bucket["count"],
            "distinct_callers": len(bucket["_callers"]),
            "callers": sorted(str(c) for c in bucket["_callers"]),
        }
        if numeric_field is not None:
            entry["numeric_field"] = numeric_field
            if nums:
                entry["min"] = min(nums)
                entry["max"] = max(nums)
                entry["last"] = nums[-1]
            else:
                entry["min"] = None
                entry["max"] = None
                entry["last"] = None
        out_groups.append(entry)

    out_groups.sort(key=lambda g: g["count"], reverse=True)

    return {
        "group_by": group_by,
        "numeric_field": numeric_field,
        "total_records": len(rows),
        "distinct_groups": len(out_groups),
        "groups": out_groups,
    }


def _decode_hex(value: Any) -> Optional[bytes]:
    """Decode a hex string (optionally 0x-prefixed / whitespace-laced) to bytes.

    Returns None for anything that is not a clean even-length hex string so a
    caller passing a captured mem-dict / error gets a graceful diff result.
    """
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if not isinstance(value, str):
        return None
    s = value.strip().replace(" ", "")
    if s[:2].lower() == "0x":
        s = s[2:]
    if not s:
        return b""
    if len(s) % 2 != 0:
        return None
    try:
        return bytes.fromhex(s)
    except ValueError:
        return None


def diff_buffers(a_hex: Any, b_hex: Any) -> dict:
    """Byte-diff two captured hex buffers (the crypto pre/post primitive).

    Returns {len_a, len_b, changed_offsets, first_diff, equal}. Offsets beyond
    the shorter buffer are reported as changed (a length mismatch is a diff).
    `equal` is True only when both decode and are byte-identical. If either side
    is not a clean hex string the result carries an `error` and equal=False.
    Pure: no IDA, no live process.
    """
    a = _decode_hex(a_hex)
    b = _decode_hex(b_hex)
    if a is None or b is None:
        return {
            "len_a": None if a is None else len(a),
            "len_b": None if b is None else len(b),
            "changed_offsets": [],
            "first_diff": None,
            "equal": False,
            "error": "one or both buffers are not valid hex",
        }

    len_a = len(a)
    len_b = len(b)
    common = min(len_a, len_b)
    changed: list[int] = []
    for i in range(common):
        if a[i] != b[i]:
            changed.append(i)
    if len_a != len_b:
        changed.extend(range(common, max(len_a, len_b)))

    first_diff = changed[0] if changed else None
    return {
        "len_a": len_a,
        "len_b": len_b,
        "changed_offsets": changed,
        "first_diff": first_diff,
        "equal": (len_a == len_b and not changed),
    }


# ============================================================================
# PURE-LOGIC BYTE-PATTERN + RANGE helpers (no idaapi)
#
# Used by the live memory_scan tool, but kept pure so the wildcard parsing and
# the mapped-range coalescing are unit-testable headless.
# ============================================================================


def parse_byte_pattern(pattern_hex: Any) -> list[Optional[int]]:
    """Parse a hex byte pattern with wildcards into a list of int|None.

    Accepts space- or comma-separated tokens, an unspaced hex run, or an
    "0x"-prefixed run. A byte is a 2-hex-digit value 00..ff. A wildcard is "??"
    or "?" (a single "?" matches one whole byte) and parses to None. A token of
    one hex nibble is rejected (ambiguous). Pure: no IDA, no live process.

    Raises ValueError for an empty / malformed pattern so the caller reports a
    clean error instead of installing a never-matching scan.
    """
    if pattern_hex is None:
        raise ValueError("empty byte pattern")
    s = str(pattern_hex).strip()
    if not s:
        raise ValueError("empty byte pattern")

    # Tokenize. If there is any whitespace or comma, split on it; otherwise treat
    # the string as a contiguous run of byte/?? pairs.
    if any(ch.isspace() for ch in s) or "," in s:
        raw_tokens = [t for t in re.split(r"[\s,]+", s) if t]
    else:
        if s[:2].lower() == "0x":
            s = s[2:]
        raw_tokens = []
        i = 0
        n = len(s)
        while i < n:
            ch = s[i]
            if ch == "?":
                # consume one or two consecutive '?' as a single wildcard byte
                if i + 1 < n and s[i + 1] == "?":
                    raw_tokens.append("??")
                    i += 2
                else:
                    raw_tokens.append("?")
                    i += 1
            else:
                raw_tokens.append(s[i:i + 2])
                i += 2

    if not raw_tokens:
        raise ValueError("empty byte pattern")

    pattern: list[Optional[int]] = []
    for tok in raw_tokens:
        low = tok.lower()
        if low in ("??", "?", "*", ".."):
            pattern.append(None)
            continue
        if low.startswith("0x"):
            low = low[2:]
        if len(low) != 2 or any(c not in "0123456789abcdef" for c in low):
            raise ValueError(f"bad pattern token {tok!r} (want a hex byte or '??')")
        pattern.append(int(low, 16))
    return pattern


def find_pattern_in_buffer(
    buf: bytes,
    pattern: list[Optional[int]],
    base: int = 0,
    limit: Optional[int] = None,
) -> list[int]:
    """Return absolute addresses where `pattern` matches inside `buf`.

    `pattern` is a list of int|None (None == wildcard byte, as produced by
    parse_byte_pattern). A returned address is base + match_offset. Stops once
    `limit` hits are collected (None == unbounded). Pure: a straight byte scan
    over the buffer, no IDA, no live process.
    """
    if not pattern:
        return []
    data = bytes(buf or b"")
    plen = len(pattern)
    dlen = len(data)
    hits: list[int] = []
    if plen > dlen:
        return hits
    # Anchor on the first concrete (non-wildcard) byte to skip cheaply.
    anchor_idx = next((i for i, b in enumerate(pattern) if b is not None), None)
    last_start = dlen - plen
    i = 0
    while i <= last_start:
        if anchor_idx is not None:
            a = data[i + anchor_idx]
            if a != pattern[anchor_idx]:
                i += 1
                continue
        matched = True
        for j in range(plen):
            pb = pattern[j]
            if pb is not None and data[i + j] != pb:
                matched = False
                break
        if matched:
            hits.append(base + i)
            if limit is not None and len(hits) >= limit:
                break
        i += 1
    return hits


def merge_ranges(ranges: Any) -> list[tuple[int, int]]:
    """Coalesce a list of (start, end) half-open ranges into sorted, disjoint
    ranges. Adjacent or overlapping ranges are merged. Invalid entries (end <=
    start, non-numeric) are skipped. Pure: no IDA, no live process.
    """
    cleaned: list[tuple[int, int]] = []
    for entry in (ranges or []):
        try:
            start, end = int(entry[0]), int(entry[1])
        except (TypeError, ValueError, IndexError):
            continue
        if end <= start:
            continue
        cleaned.append((start, end))
    if not cleaned:
        return []
    cleaned.sort()
    merged: list[tuple[int, int]] = [cleaned[0]]
    for start, end in cleaned[1:]:
        last_start, last_end = merged[-1]
        if start <= last_end:  # overlap or adjacency
            if end > last_end:
                merged[-1] = (last_start, end)
        else:
            merged.append((start, end))
    return merged


def largest_aligned_slot(addr: int, size: int, max_slot: int = 8) -> int:
    """Pick the largest hardware-watchpoint slot (8/4/2/1) that is <= size, <=
    max_slot, and naturally aligned to `addr`. Always returns at least 1.

    Hardware data breakpoints watch a naturally-aligned power-of-two window. For
    a range we arm the biggest such window that fits. Pure: no IDA.
    """
    try:
        a = int(addr)
        sz = int(size)
        cap = int(max_slot)
    except (TypeError, ValueError):
        return 1
    if sz < 1:
        return 1
    for slot in (8, 4, 2, 1):
        if slot > cap:
            continue
        if slot <= sz and (a % slot) == 0:
            return slot
    return 1


def clamp_scan_window(
    seg_start: int,
    seg_end: int,
    want_start: Optional[int],
    want_end: Optional[int],
) -> Optional[tuple[int, int]]:
    """Intersect a segment [seg_start,seg_end) with a requested [want_start,
    want_end) window. Returns the clamped (start, end) or None when there is no
    overlap. None bounds mean "unbounded on that side". Pure helper for
    memory_scan's range walk.
    """
    lo = seg_start if want_start is None else max(seg_start, int(want_start))
    hi = seg_end if want_end is None else min(seg_end, int(want_end))
    if hi <= lo:
        return None
    return (lo, hi)


def pattern_to_mask(pattern: Any) -> tuple[bytes, str]:
    """Render a parsed byte pattern (list of int|None) as an IDA-style
    (bytes, mask) pair.

    `pattern` is the int|None list produced by parse_byte_pattern. The returned
    `bytes` value carries 0x00 in every wildcard slot and the concrete byte
    elsewhere; the `mask` string carries "x" for a concrete byte and "?" for a
    wildcard, one char per byte. This is the canonical form an IDA byte-search
    consumes. Pure: no IDA, no live process.

    Raises ValueError for an empty pattern or a slot that is neither None nor a
    0..255 int, so a malformed pattern fails loudly instead of producing a
    silently-wrong mask.
    """
    items = list(pattern or [])
    if not items:
        raise ValueError("empty pattern")
    raw = bytearray()
    mask_chars: list[str] = []
    for i, item in enumerate(items):
        if item is None:
            raw.append(0)
            mask_chars.append("?")
            continue
        if isinstance(item, bool) or not isinstance(item, int):
            raise ValueError(f"pattern slot {i} is not an int or wildcard: {item!r}")
        if item < 0 or item > 0xFF:
            raise ValueError(f"pattern slot {i} out of byte range: {item}")
        raw.append(item)
        mask_chars.append("x")
    return bytes(raw), "".join(mask_chars)


def total_range_bytes(ranges: Any) -> int:
    """Total number of bytes covered by a list of (start, end) half-open ranges,
    counting overlaps ONCE.

    Coalesces via merge_ranges first (so overlapping / adjacent / unsorted /
    invalid entries are handled exactly as the scan walk sees them), then sums
    the disjoint spans. Pure: no IDA, no live process.
    """
    return sum(end - start for start, end in merge_ranges(ranges))


def aggregate_probe_stats(probes: Any, ring_stats: Any) -> dict:
    """Roll up the probe registry + ring stats into the probe_stats result shape.

    `probes` is a list of probe descriptor dicts (as list_probes returns);
    `ring_stats` is the dict from ProbeRing.stats(). Returns
    {armed_probes,total_probes,ring,fill_pct,dropped,per_probe} where per_probe
    is the (id,ea,kind,hits,max_hits,armed) breakdown sorted by hit count
    descending. fill_pct is size/cap as a 0..100 percentage (0.0 when cap is
    missing/zero). Pure: takes plain dicts and returns a plain dict so the
    aggregation shape is unit-testable headless; the live tool only supplies the
    inputs.
    """
    rows = [p for p in (probes or []) if isinstance(p, dict)]
    armed = sum(1 for p in rows if p.get("armed"))
    stats = dict(ring_stats or {})
    cap = stats.get("cap") or 0
    size = stats.get("size") or 0
    fill = round((size / cap) * 100.0, 2) if cap else 0.0

    per_probe = [
        {
            "probe_id": p.get("probe_id"),
            "ea": p.get("ea"),
            "kind": p.get("kind"),
            "hits": p.get("hits", 0),
            "max_hits": p.get("max_hits"),
            "armed": bool(p.get("armed")),
        }
        for p in rows
    ]
    per_probe.sort(key=lambda d: d.get("hits", 0) or 0, reverse=True)

    return {
        "armed_probes": armed,
        "total_probes": len(rows),
        "ring": stats,
        "fill_pct": fill,
        "dropped": stats.get("dropped", 0),
        "per_probe": per_probe,
    }


__all__ = [
    "configure_idb",
    "install_tracer",
    "shutdown",
    "iter_idb_records",
    "IDB_NETNODE_NAME",
    # Probe infrastructure
    "ProbeRing",
    "register_probe",
    "get_probe",
    "list_probes",
    "remove_probe",
    "clear_probes",
    "get_probe_ring",
    "probe_dir",
    "configure_probes",
    "record_probe_event",
    # Pure-logic autopilot analysis
    "summarize_records",
    "diff_buffers",
    # Pure-logic byte-pattern + range helpers
    "parse_byte_pattern",
    "find_pattern_in_buffer",
    "merge_ranges",
    "largest_aligned_slot",
    "clamp_scan_window",
    "pattern_to_mask",
    "total_range_bytes",
    "aggregate_probe_stats",
]
