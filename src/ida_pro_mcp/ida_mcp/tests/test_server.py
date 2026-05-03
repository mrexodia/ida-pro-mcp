"""Tests for the top-level stdio proxy server (server.py) and unsafe tool gating."""

import argparse
import contextlib
import json
import os
import sys

from ..framework import test
from ..rpc import MCP_SERVER, MCP_UNSAFE

try:
    from ida_pro_mcp import server
except ImportError:
    _parent = os.path.join(os.path.dirname(__file__), "..", "..")
    sys.path.insert(0, _parent)
    try:
        import server  # type: ignore
    finally:
        sys.path.remove(_parent)


class _FakeHttpResponse:
    status = 200
    reason = "OK"

    def __init__(self, body=b'{"jsonrpc":"2.0","result":{}}'):
        self._body = body

    def read(self):
        return self._body


class _RecordingConnection:
    calls = []

    def __init__(self, host, port, timeout=None):
        self.host = host
        self.port = port
        self.timeout = timeout

    def request(self, method, path, body=None, headers=None):
        self.__class__.calls.append(
            {
                "host": self.host,
                "port": self.port,
                "timeout": self.timeout,
                "method": method,
                "path": path,
                "body": body,
                "headers": headers or {},
            }
        )

    def getresponse(self):
        return _FakeHttpResponse()

    def close(self):
        pass


@contextlib.contextmanager
def _saved_target():
    """Preserve the currently selected IDA target across assertions."""
    old_host = server.IDA_HOST
    old_port = server.IDA_PORT
    old_session = getattr(server.mcp._transport_session_id, "data", None)
    old_exts = getattr(server.mcp._enabled_extensions, "data", set())
    old_targets = server._session_proxy_targets.copy()
    old_target_last_seen = server._session_proxy_last_seen.copy()
    try:
        yield
    finally:
        server.IDA_HOST = old_host
        server.IDA_PORT = old_port
        server._session_proxy_targets.clear()
        server._session_proxy_targets.update(old_targets)
        server._session_proxy_last_seen.clear()
        server._session_proxy_last_seen.update(old_target_last_seen)
        server.mcp._transport_session_id.data = old_session
        server.mcp._enabled_extensions.data = old_exts


@test()
def test_tools_list_keeps_discovery_tools_when_ida_unreachable():
    """tools/list should still expose local discovery tools when IDA is down."""
    with _saved_target():
        server.IDA_HOST = "127.0.0.1"
        server.IDA_PORT = 1  # unreachable
        req = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
        result = server.dispatch_proxy(req)
        assert "result" in result, f"Expected successful tools/list response, got: {result}"
        tool_names = {tool["name"] for tool in result["result"].get("tools", [])}
        assert "select_instance" in tool_names
        assert "list_instances" in tool_names
        assert "open_file" not in tool_names


@test()
def test_streamable_http_initialize_returns_session_id():
    """Streamable HTTP initialize should issue a session id for per-client state."""
    test_mcp = server.McpServer("session-test")
    test_mcp.serve("127.0.0.1", 0, request_handler=server.McpHttpRequestHandler)
    port = test_mcp._http_server.server_address[1]
    conn = server.http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        payload = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "test", "version": "1.0"},
                },
            }
        )
        conn.request("POST", "/mcp", payload, {"Content-Type": "application/json"})
        response = conn.getresponse()
        response.read()
        session_id = response.getheader("Mcp-Session-Id")
        assert response.status == 200
        assert session_id, "Expected initialize response to include Mcp-Session-Id"
        assert test_mcp.has_http_session(session_id)
    finally:
        conn.close()
        test_mcp.stop()


@test()
def test_select_instance_is_scoped_to_transport_session():
    """Each MCP transport session should keep its own selected proxy target."""
    with _saved_target():
        original_probe = server.probe_instance
        server.probe_instance = lambda host, port: True
        try:
            server.mcp._transport_session_id.data = "http:session-a"
            result_a = server.select_instance(port=11111, host="127.0.0.1")
            assert result_a["success"] is True

            server.mcp._transport_session_id.data = "http:session-b"
            result_b = server.select_instance(port=22222, host="127.0.0.1")
            assert result_b["success"] is True

            server.mcp._transport_session_id.data = "http:session-a"
            assert server._get_active_ida_target() == ("127.0.0.1", 11111)

            server.mcp._transport_session_id.data = "http:session-b"
            assert server._get_active_ida_target() == ("127.0.0.1", 22222)
        finally:
            server.probe_instance = original_probe


@test()
def test_select_instance_does_not_change_process_default_for_session():
    """Session-scoped selection must not overwrite the default target for other clients."""
    with _saved_target():
        original_probe = server.probe_instance
        server.probe_instance = lambda host, port: True
        server.IDA_HOST = "127.0.0.1"
        server.IDA_PORT = 13337
        try:
            server.mcp._transport_session_id.data = "http:session-a"
            result = server.select_instance(port=14444, host="127.0.0.1")
            assert result["success"] is True
            assert (server.IDA_HOST, server.IDA_PORT) == ("127.0.0.1", 13337)

            server.mcp._transport_session_id.data = "http:session-b"
            assert server._get_active_ida_target() == ("127.0.0.1", 13337)
        finally:
            server.probe_instance = original_probe


@test()
def test_server_proxy_to_instance_forwards_session_and_extensions():
    """Top-level proxy requests should preserve MCP session and enabled extensions."""
    with _saved_target():
        original_conn = server.http.client.HTTPConnection
        _RecordingConnection.calls = []
        server.http.client.HTTPConnection = _RecordingConnection
        server.mcp._transport_session_id.data = "http:session-456"
        server.mcp._enabled_extensions.data = {"dbg"}
        try:
            server._proxy_to_instance("127.0.0.1", 13337, b"{}")
            assert len(_RecordingConnection.calls) == 1
            call = _RecordingConnection.calls[0]
            assert call["path"] == "/mcp?ext=dbg"
            assert call["headers"].get("Mcp-Session-Id") == "session-456"
        finally:
            server.http.client.HTTPConnection = original_conn


@test()
def test_resolve_ida_rpc_preserves_ext_query_param():
    """--ida-rpc http://host:port/mcp?ext=dbg should seed enabled extensions."""
    with _saved_target():
        args = argparse.Namespace(ida_rpc="http://10.0.0.1:9999/mcp?ext=dbg")
        server._resolve_ida_rpc(args)
        assert server.IDA_HOST == "10.0.0.1"
        assert server.IDA_PORT == 9999
        exts = getattr(server.mcp._enabled_extensions, "data", set())
        assert "dbg" in exts, f"Expected 'dbg' in enabled extensions, got: {exts}"


@test()
def test_resolve_ida_rpc_preserves_multiple_ext_query_params():
    """--ida-rpc with ext=dbg,extra should seed both extensions."""
    with _saved_target():
        args = argparse.Namespace(ida_rpc="http://10.0.0.1:9999/mcp?ext=dbg,extra")
        server._resolve_ida_rpc(args)
        exts = getattr(server.mcp._enabled_extensions, "data", set())
        assert "dbg" in exts, f"Expected 'dbg' in extensions, got: {exts}"
        assert "extra" in exts, f"Expected 'extra' in extensions, got: {exts}"


@test()
def test_resolve_ida_rpc_no_ext_leaves_extensions_empty():
    """--ida-rpc without ext param should not add spurious extensions."""
    with _saved_target():
        server.mcp._enabled_extensions.data = set()
        args = argparse.Namespace(ida_rpc="http://10.0.0.1:9999")
        server._resolve_ida_rpc(args)
        exts = getattr(server.mcp._enabled_extensions, "data", set())
        assert len(exts) == 0, f"Expected no extensions, got: {exts}"


@test()
def test_ida_rpc_ext_flows_through_to_proxy_path():
    """Extensions from --ida-rpc should appear in proxied request path."""
    with _saved_target():
        original_conn = server.http.client.HTTPConnection
        _RecordingConnection.calls = []
        server.http.client.HTTPConnection = _RecordingConnection
        try:
            args = argparse.Namespace(ida_rpc="http://10.0.0.1:9999/mcp?ext=dbg")
            server._resolve_ida_rpc(args)
            server._proxy_to_instance("10.0.0.1", 9999, b"{}")
            assert len(_RecordingConnection.calls) == 1
            assert _RecordingConnection.calls[0]["path"] == "/mcp?ext=dbg"
        finally:
            server.http.client.HTTPConnection = original_conn


# ---------------------------------------------------------------------------
# Unsafe tool gating (idalib registry-removal approach, mirrors idalib_server)
# ---------------------------------------------------------------------------


@contextlib.contextmanager
def _saved_tools():
    """Save and restore the tools registry so removal tests are non-destructive."""
    original = MCP_SERVER.tools.methods.copy()
    try:
        yield
    finally:
        MCP_SERVER.tools.methods = original


@test()
def test_unsafe_tools_registered():
    """@unsafe decorator should populate MCP_UNSAFE with known tool names."""
    assert len(MCP_UNSAFE) > 0, "MCP_UNSAFE is empty — no tools marked @unsafe"
    assert "py_eval" in MCP_UNSAFE, "py_eval should be marked @unsafe"
    assert "py_exec_file" in MCP_UNSAFE, "py_exec_file should be marked @unsafe"


@test()
def test_unsafe_tools_present_by_default():
    """Unsafe tools should be in the registry by default (plugin behavior)."""
    tool_names = set(MCP_SERVER.tools.methods)
    for name in ("py_eval", "py_exec_file"):
        assert name in tool_names, f"{name} should be present by default"


@test()
def test_unsafe_tools_hidden_after_removal():
    """tools/list should exclude tools removed from the registry (idalib --unsafe behavior)."""
    with _saved_tools():
        for name in MCP_UNSAFE:
            MCP_SERVER.tools.methods.pop(name, None)
        result = MCP_SERVER._mcp_tools_list()
        tool_names = {t["name"] for t in result.get("tools", [])}
        leaked = MCP_UNSAFE & tool_names
        assert not leaked, f"Removed unsafe tools still listed: {leaked}"


@test()
def test_unsafe_tool_call_rejected_after_removal():
    """tools/call for a removed tool should return an error."""
    with _saved_tools():
        for name in MCP_UNSAFE:
            MCP_SERVER.tools.methods.pop(name, None)
        result = MCP_SERVER._mcp_tools_call("py_eval", {"code": "pass"})
        assert result.get("isError"), f"Expected error for removed tool, got: {result}"


@test()
def test_safe_tools_unaffected_by_unsafe_removal():
    """Non-unsafe tools should remain callable after unsafe removal."""
    with _saved_tools():
        for name in MCP_UNSAFE:
            MCP_SERVER.tools.methods.pop(name, None)
        assert "decompile" not in MCP_UNSAFE, "decompile should not be unsafe"
        assert "decompile" in MCP_SERVER.tools.methods, "decompile should survive removal"
