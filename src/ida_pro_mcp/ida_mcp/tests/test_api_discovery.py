"""Tests for the discovery API module (api_discovery.py).

Tests dispatch routing decisions, loop prevention, select_instance state
machine, tools/list merge logic, and IDB file discovery.
"""

import json
import os
import tempfile

from ..framework import test
from .. import api_discovery


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _SavedState:
    """Context manager that snapshots and restores api_discovery globals."""
    def __enter__(self):
        self._host = api_discovery._redirect_host
        self._port = api_discovery._redirect_port
        self._targets = api_discovery._redirect_targets.copy()
        self._lhost = api_discovery._LOCAL_HOST
        self._lport = api_discovery._LOCAL_PORT
        self._proxied = api_discovery.is_request_proxied()
        self._session = getattr(api_discovery.MCP_SERVER._transport_session_id, "data", None)
        return self
    def __exit__(self, *exc):
        api_discovery._redirect_host = self._host
        api_discovery._redirect_port = self._port
        api_discovery._redirect_targets.clear()
        api_discovery._redirect_targets.update(self._targets)
        api_discovery._LOCAL_HOST = self._lhost
        api_discovery._LOCAL_PORT = self._lport
        api_discovery.set_request_proxied(self._proxied)
        api_discovery.MCP_SERVER._transport_session_id.data = self._session


def _make_jsonrpc(method, params=None, id=1):
    """Build a minimal JSON-RPC 2.0 request dict."""
    req = {"jsonrpc": "2.0", "method": method, "id": id}
    if params is not None:
        req["params"] = params
    return req


def _is_local_registry_response(result):
    """True if this looks like a response from the local JSON-RPC registry.

    Local registry errors use standard JSON-RPC codes (-32601 method not found,
    -32602 invalid params, etc.). Proxy errors use -32000. A successful result
    has a "result" key. This lets us distinguish "went local" from "went proxy."
    """
    if result is None:
        return False  # notification
    if "result" in result:
        return True
    err = result.get("error", {})
    # Standard JSON-RPC error codes from the local registry
    return err.get("code", 0) in (-32600, -32601, -32602, -32603, -32700)


def _is_proxy_error(result):
    """True if this is a proxy failure response (code -32000)."""
    if result is None:
        return False
    return result.get("error", {}).get("code") == -32000


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


# ---------------------------------------------------------------------------
# IDB file discovery
# ---------------------------------------------------------------------------


@test()
def test_find_existing_idb_prefers_i64_over_idb():
    """_find_existing_idb prefers .i64 over .idb when both exist."""
    with tempfile.TemporaryDirectory() as tmp:
        base = os.path.join(tmp, "sample")
        binary = base + ".exe"
        i64 = base + ".i64"
        idb = base + ".idb"
        for path in (binary, i64, idb):
            with open(path, "w") as f:
                f.write("")
        assert api_discovery._find_existing_idb(binary) == i64


@test()
def test_find_existing_idb_returns_none_when_missing():
    """_find_existing_idb returns None when no IDB exists."""
    with tempfile.TemporaryDirectory() as tmp:
        binary = os.path.join(tmp, "sample.exe")
        with open(binary, "w") as f:
            f.write("")
        assert api_discovery._find_existing_idb(binary) is None


# ---------------------------------------------------------------------------
# select_instance state machine
# ---------------------------------------------------------------------------


@test()
def test_select_instance_port_zero_resets_redirect():
    """select_instance(port=0) clears redirect and returns success."""
    with _SavedState():
        api_discovery._redirect_host = "10.0.0.1"
        api_discovery._redirect_port = 9999
        result = api_discovery.select_instance(port=0)
        assert result["success"] is True
        assert api_discovery.get_redirect_target() is None


@test()
def test_select_instance_local_port_clears_redirect():
    """Selecting the local instance's own port clears redirect."""
    with _SavedState():
        api_discovery.set_local_instance("127.0.0.1", 13337)
        api_discovery._redirect_host = "10.0.0.1"
        api_discovery._redirect_port = 9999
        result = api_discovery.select_instance(port=13337, host="127.0.0.1")
        assert result["success"] is True
        assert "local" in result.get("message", "").lower()
        assert api_discovery.get_redirect_target() is None


@test()
def test_select_instance_unreachable_returns_error():
    """Selecting an unreachable port returns success=False without changing state."""
    with _SavedState():
        api_discovery._redirect_host = None
        api_discovery._redirect_port = None
        result = api_discovery.select_instance(port=1, host="127.0.0.1")
        assert result["success"] is False
        assert "not reachable" in result.get("error", "")
        assert api_discovery.get_redirect_target() is None


@test()
def test_select_instance_redirect_is_scoped_to_transport_session():
    """Each MCP transport session should keep its own selected redirect target."""
    with _SavedState():
        original_probe = api_discovery.probe_instance
        api_discovery.probe_instance = lambda host, port: True
        try:
            api_discovery.MCP_SERVER._transport_session_id.data = "http:session-a"
            result_a = api_discovery.select_instance(port=11111, host="127.0.0.1")
            assert result_a["success"] is True

            api_discovery.MCP_SERVER._transport_session_id.data = "http:session-b"
            result_b = api_discovery.select_instance(port=22222, host="127.0.0.1")
            assert result_b["success"] is True

            api_discovery.MCP_SERVER._transport_session_id.data = "http:session-a"
            assert api_discovery.get_redirect_target() == ("127.0.0.1", 11111)

            api_discovery.MCP_SERVER._transport_session_id.data = "http:session-b"
            assert api_discovery.get_redirect_target() == ("127.0.0.1", 22222)
        finally:
            api_discovery.probe_instance = original_probe


# ---------------------------------------------------------------------------
# Dispatch routing — _redirecting_dispatch
#
# Strategy: the local JSON-RPC registry returns standard error codes
# (-32601 method not found, -32602 invalid params). The proxy error path
# returns -32000. We use this to distinguish which path was taken.
# Redirect targets point at unreachable addresses so proxy attempts fail
# fast rather than hang.
# ---------------------------------------------------------------------------


@test()
def test_dispatch_no_redirect_goes_local():
    """When no redirect is active, tools/call dispatches to the local registry."""
    with _SavedState():
        api_discovery._redirect_host = None
        api_discovery._redirect_port = None
        req = _make_jsonrpc("tools/call", {"name": "decompile", "arguments": {}})
        result = api_discovery._redirecting_dispatch(req)
        # Local registry returns -32602 (missing required 'addr' param),
        # NOT -32000 (proxy error).
        assert _is_local_registry_response(result), f"Expected local response, got: {result}"


@test()
def test_dispatch_initialize_always_local():
    """initialize is always handled locally even when redirect is active."""
    with _SavedState():
        api_discovery._redirect_host = "10.0.0.99"
        api_discovery._redirect_port = 1
        req = _make_jsonrpc("initialize", {"capabilities": {}})
        result = api_discovery._redirecting_dispatch(req)
        # initialize hits the local registry (returns error for missing params,
        # but it's a registry error, not a proxy error).
        assert _is_local_registry_response(result), f"Expected local response, got: {result}"


@test()
def test_dispatch_notification_always_local():
    """notifications/* are handled locally even when redirect is active.

    Notifications have no id and return None from the registry. The key
    assertion is that no ConnectionRefusedError is raised — the request
    never touches the network.
    """
    with _SavedState():
        api_discovery._redirect_host = "10.0.0.99"
        api_discovery._redirect_port = 1
        req = _make_jsonrpc("notifications/initialized")
        req.pop("id")  # notifications have no id
        result = api_discovery._redirecting_dispatch(req)
        # Registry returns None for notifications (no response expected).
        # If it had tried to proxy to 10.0.0.99:1, it would have raised.
        assert result is None


@test()
def test_dispatch_local_tool_stays_local_when_redirecting():
    """tools/call for list_instances dispatches locally even when redirect is active."""
    with _SavedState():
        api_discovery._redirect_host = "10.0.0.99"
        api_discovery._redirect_port = 1
        req = _make_jsonrpc("tools/call", {"name": "list_instances", "arguments": {}})
        result = api_discovery._redirecting_dispatch(req)
        # list_instances is a registered tool, so local dispatch succeeds.
        assert "result" in result, f"Expected success result, got: {result}"
        assert not _is_proxy_error(result)


@test()
def test_dispatch_non_local_tool_proxied_when_redirecting():
    """tools/call for a non-local tool attempts to proxy when redirect is active."""
    with _SavedState():
        api_discovery._redirect_host = "127.0.0.1"
        api_discovery._redirect_port = 1  # unreachable
        req = _make_jsonrpc("tools/call", {"name": "decompile", "arguments": {"addr": "0x1000"}})
        result = api_discovery._redirecting_dispatch(req)
        # Proxy fails → -32000 error, not a local registry error
        assert _is_proxy_error(result), f"Expected proxy error, got: {result}"
        assert result["id"] == 1


@test()
def test_dispatch_loop_prevention_proxied_request_goes_local():
    """When is_request_proxied() is True, dispatch goes local even with redirect active.

    This prevents A->B->A proxy loops: if instance B receives a proxied request
    from A, it must not follow its own redirect back to A.
    """
    with _SavedState():
        api_discovery._redirect_host = "10.0.0.99"
        api_discovery._redirect_port = 1
        api_discovery.set_request_proxied(True)
        req = _make_jsonrpc("tools/call", {"name": "decompile", "arguments": {}})
        result = api_discovery._redirecting_dispatch(req)
        assert _is_local_registry_response(result), f"Expected local response, got: {result}"
        assert not _is_proxy_error(result)


@test()
def test_dispatch_proxy_error_preserves_request_id():
    """When proxy fails, the JSON-RPC error response preserves the request id."""
    with _SavedState():
        api_discovery._redirect_host = "127.0.0.1"
        api_discovery._redirect_port = 1
        req = _make_jsonrpc("tools/call", {"name": "rename", "arguments": {}}, id=42)
        result = api_discovery._redirecting_dispatch(req)
        assert result["id"] == 42
        assert _is_proxy_error(result)


@test()
def test_api_discovery_proxy_to_instance_forwards_session_and_extensions():
    """Forwarded proxy requests should preserve MCP session and enabled extensions."""
    with _SavedState():
        original_conn = api_discovery.http.client.HTTPConnection
        _RecordingConnection.calls = []
        api_discovery.http.client.HTTPConnection = _RecordingConnection
        api_discovery.MCP_SERVER._transport_session_id.data = "http:session-123"
        api_discovery.MCP_SERVER._enabled_extensions.data = {"dbg"}
        try:
            api_discovery.proxy_to_instance("127.0.0.1", 13337, b"{}")
            assert len(_RecordingConnection.calls) == 1
            call = _RecordingConnection.calls[0]
            assert call["path"] == "/mcp?ext=dbg"
            assert call["headers"].get(api_discovery.PROXY_HEADER) == "1"
            assert call["headers"].get("Mcp-Session-Id") == "session-123"
        finally:
            api_discovery.http.client.HTTPConnection = original_conn
            api_discovery.MCP_SERVER._enabled_extensions.data = set()


@test()
def test_dispatch_proxy_notification_error_returns_none():
    """When a proxied tools/call has no id (notification-style), proxy error returns None."""
    with _SavedState():
        api_discovery._redirect_host = "127.0.0.1"
        api_discovery._redirect_port = 1
        req = _make_jsonrpc("tools/call", {"name": "rename", "arguments": {}})
        del req["id"]
        result = api_discovery._redirecting_dispatch(req)
        assert result is None


@test()
def test_dispatch_unknown_method_proxied_with_fallback():
    """Non-tool methods (e.g. resources/list) proxy first; on failure, fall back to local."""
    with _SavedState():
        api_discovery._redirect_host = "127.0.0.1"
        api_discovery._redirect_port = 1
        req = _make_jsonrpc("resources/list", {})
        result = api_discovery._redirecting_dispatch(req)
        # Proxy to port 1 fails; fallback gives us a local registry response
        assert _is_local_registry_response(result), f"Expected local fallback, got: {result}"
        assert not _is_proxy_error(result)


# ---------------------------------------------------------------------------
# tools/list merge — deduplication of local tool names
# ---------------------------------------------------------------------------


@test()
def test_dispatch_tools_list_returns_local_tools_when_redirect_unreachable():
    """tools/list still returns local discovery tools when the redirect target is down."""
    with _SavedState():
        api_discovery._redirect_host = "127.0.0.1"
        api_discovery._redirect_port = 1  # unreachable
        req = _make_jsonrpc("tools/list", {})
        result = api_discovery._redirecting_dispatch(req)
        # Should still get a successful response with local tools
        assert "result" in result, f"Expected result, got: {result}"
        tools = result["result"].get("tools", [])
        tool_names = {t["name"] for t in tools}
        # The local discovery tools should always be present
        assert "list_instances" in tool_names
        assert "select_instance" in tool_names
        assert "open_file" in tool_names


@test()
def test_dispatch_tools_list_without_redirect_returns_all_tools():
    """tools/list without redirect returns the full local tool catalog."""
    with _SavedState():
        api_discovery._redirect_host = None
        api_discovery._redirect_port = None
        req = _make_jsonrpc("tools/list", {})
        result = api_discovery._redirecting_dispatch(req)
        assert "result" in result
        tools = result["result"].get("tools", [])
        tool_names = {t["name"] for t in tools}
        # Should have all registered IDA tools + discovery tools
        assert "list_instances" in tool_names
        assert "decompile" in tool_names
