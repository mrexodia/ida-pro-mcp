"""Tests for installer config generation changes.

Verifies that stdio configs no longer hardcode --ida-rpc (enabling auto-discovery)
while HTTP/SSE configs still embed the RPC address.
"""

import os
import sys

from ..framework import test

try:
    from ida_pro_mcp.installer import generate_mcp_config, SERVER_SCRIPT, IDA_HOST, IDA_PORT
except ImportError:
    _parent = os.path.join(os.path.dirname(__file__), "..", "..")
    sys.path.insert(0, _parent)
    try:
        from installer import generate_mcp_config, SERVER_SCRIPT, IDA_HOST, IDA_PORT
    finally:
        sys.path.remove(_parent)


@test()
def test_stdio_config_has_no_ida_rpc_arg():
    """stdio config omits --ida-rpc so the server can auto-discover instances."""
    config = generate_mcp_config(client_name="Generic", transport="stdio")
    args = config.get("args", [])
    combined = " ".join(str(a) for a in ([config.get("command", "")] + args))
    assert "--ida-rpc" not in combined


@test()
def test_stdio_config_contains_server_script():
    """stdio config includes the server script path."""
    config = generate_mcp_config(client_name="Generic", transport="stdio")
    args = config.get("args", [])
    assert SERVER_SCRIPT in args


@test()
def test_streamable_http_config_contains_url():
    """streamable-http config generates a URL with the current host:port."""
    config = generate_mcp_config(client_name="Generic", transport="streamable-http")
    assert "url" in config
    assert f"{IDA_HOST}:{IDA_PORT}" in config["url"]


@test()
def test_sse_config_claude_preserves_sse_path():
    """Claude SSE config preserves /sse path; Generic forces /mcp."""
    claude_config = generate_mcp_config(client_name="Claude", transport="sse")
    assert claude_config["url"].endswith("/sse")
    assert claude_config["type"] == "sse"
    generic_config = generate_mcp_config(client_name="Generic", transport="sse")
    assert generic_config["url"].endswith("/mcp")


@test()
def test_opencode_stdio_uses_command_list():
    """Opencode stdio config uses a command list (no separate args key)."""
    config = generate_mcp_config(client_name="Opencode", transport="stdio")
    assert "command" in config
    assert isinstance(config["command"], list)
    assert SERVER_SCRIPT in config["command"]
    combined = " ".join(str(a) for a in config["command"])
    assert "--ida-rpc" not in combined


@test()
def test_claude_http_config_has_type_field():
    """Claude client HTTP config includes the 'type' field."""
    config = generate_mcp_config(client_name="Claude", transport="streamable-http")
    assert config.get("type") == "http"
    assert "url" in config
