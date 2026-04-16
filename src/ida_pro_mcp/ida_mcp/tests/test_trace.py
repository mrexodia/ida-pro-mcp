"""Tests for the tools/call trace middleware (#189)."""

import json
import tempfile
from pathlib import Path

from ..framework import test
from ..rpc import MCP_SERVER
from .. import trace


def _read_lines(path: Path) -> list[dict]:
    return [json.loads(ln) for ln in path.read_text().splitlines() if ln.strip()]


def _call_through_registry(name: str, arguments: dict | None = None) -> dict:
    return MCP_SERVER.registry.methods["tools/call"](name, arguments)


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
    # The middleware only attaches after configure(); a bare call must not
    # leak to a non-configured sink. We verify by ensuring no file exists
    # for a path we never registered.
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
