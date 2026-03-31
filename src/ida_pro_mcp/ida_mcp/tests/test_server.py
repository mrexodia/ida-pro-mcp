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


@contextlib.contextmanager
def _saved_target():
    """Preserve the currently selected IDA target across assertions."""
    old_host = server.IDA_HOST
    old_port = server.IDA_PORT
    try:
        yield
    finally:
        server.IDA_HOST = old_host
        server.IDA_PORT = old_port


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
