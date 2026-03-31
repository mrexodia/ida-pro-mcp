"""Tests for idalib_server integration helpers."""

import os
import sys

from ..framework import test

try:
    from ida_pro_mcp import idalib_server
except ImportError:
    _parent = os.path.join(os.path.dirname(__file__), "..", "..")
    sys.path.insert(0, _parent)
    try:
        import idalib_server  # type: ignore
    finally:
        sys.path.remove(_parent)


@test()
def test_idalib_health_treats_successful_server_health_as_ready():
    """idalib_health should report ready when server_health returns a healthy payload."""
    original_get_session_manager = idalib_server.get_session_manager
    original_resolve_context = idalib_server._resolve_effective_context_id
    original_context_fields = idalib_server._context_response_fields
    original_server_health = idalib_server.server_health

    class _FakeSession:
        def to_dict(self):
            return {"session_id": "sess-1", "input_path": "dummy.bin"}

    class _FakeManager:
        def get_context_session(self, context_id):
            return _FakeSession()

        def activate_context(self, context_id):
            self.activated = context_id

    idalib_server.get_session_manager = lambda: _FakeManager()
    idalib_server._resolve_effective_context_id = lambda: "ctx-1"
    idalib_server._context_response_fields = lambda context_id: {
        "context_id": context_id,
        "transport_context_id": None,
        "isolated_contexts": False,
    }
    idalib_server.server_health = lambda: {
        "uptime_sec": 1.0,
        "module": "dummy.bin",
        "imagebase": "0x0",
        "strings_cache_ready": True,
        "hexrays_ready": False,
    }
    try:
        result = idalib_server.idalib_health()
        assert result["error"] is None
        assert result["health"]["module"] == "dummy.bin"
        assert result["ready"] is True
    finally:
        idalib_server.get_session_manager = original_get_session_manager
        idalib_server._resolve_effective_context_id = original_resolve_context
        idalib_server._context_response_fields = original_context_fields
        idalib_server.server_health = original_server_health
