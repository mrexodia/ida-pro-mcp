"""Tests for the top-level stdio proxy server (server.py)."""

import contextlib
import os
import sys

from ..framework import test

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
    try:
        yield
    finally:
        server.IDA_HOST = old_host
        server.IDA_PORT = old_port
        server.mcp._transport_session_id.data = old_session
        server.mcp._enabled_extensions.data = old_exts


@test()
def test_tools_list_keeps_discovery_and_launch_tools_when_ida_unreachable():
    """tools/list should still expose local discovery/recovery tools when IDA is down."""
    with _saved_target():
        server.IDA_HOST = "127.0.0.1"
        server.IDA_PORT = 1  # unreachable
        req = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
        result = server.dispatch_proxy(req)
        assert "result" in result, f"Expected successful tools/list response, got: {result}"
        tool_names = {tool["name"] for tool in result["result"].get("tools", [])}
        assert "select_instance" in tool_names
        assert "list_instances" in tool_names
        assert "open_file" in tool_names


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
