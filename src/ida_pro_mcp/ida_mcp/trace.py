"""Tool call tracing (#189).

Appends one JSON record per tools/call to a file. Opt-in via CLI flag
(--trace-file PATH) or env var IDA_MCP_TRACE_FILE. Arguments for
@unsafe tools (py_eval, py_exec_file, ...) are redacted unless
--trace-verbose / IDA_MCP_TRACE_VERBOSE=1.
"""

import atexit
import json
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .rpc import MCP_SERVER, MCP_UNSAFE


_state: dict[str, Any] = {
    "enabled": False,
    "verbose": False,
    "path": None,
    "file": None,
    "lock": threading.Lock(),
}


def configure(path: str, *, verbose: bool = False) -> None:
    """Enable tracing; opens `path` in append mode and installs middleware."""
    resolved = Path(path).expanduser().resolve()
    resolved.parent.mkdir(parents=True, exist_ok=True)
    with _state["lock"]:
        if _state["file"] is not None:
            _state["file"].close()
        _state["file"] = open(resolved, "a", encoding="utf-8")
        _state["path"] = resolved
        _state["verbose"] = verbose
        already = _state["enabled"]
        _state["enabled"] = True
    if not already:
        _install_trace_patch()
        atexit.register(shutdown)


def configure_from_env() -> None:
    path = os.environ.get("IDA_MCP_TRACE_FILE", "").strip()
    if not path:
        return
    verbose = os.environ.get("IDA_MCP_TRACE_VERBOSE", "").strip() not in ("", "0", "false", "no")
    configure(path, verbose=verbose)


def shutdown() -> None:
    with _state["lock"]:
        f = _state["file"]
        if f is not None:
            try:
                f.flush()
                f.close()
            except Exception:
                pass
        _state["file"] = None


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


def _emit(record: dict) -> None:
    line = json.dumps(record, separators=(",", ":"), default=str)
    with _state["lock"]:
        f = _state["file"]
        if f is None:
            return
        f.write(line)
        f.write("\n")
        f.flush()


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
            _emit(record)
            raise

        record["duration_ms"] = round((time.monotonic() - start) * 1000, 2)
        record["isError"] = bool(response.get("isError"))
        record["structuredContent"] = response.get("structuredContent")

        meta = (response.get("_meta") or {}).get("ida_mcp") or {}
        if meta.get("output_truncated"):
            record["full_result_size"] = meta.get("total_chars")
            record["truncated"] = True
            record["output_id"] = meta.get("output_id")

        _emit(record)
        return response

    MCP_SERVER.registry.methods["tools/call"] = traced


__all__ = ["configure", "configure_from_env", "shutdown"]
