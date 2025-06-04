"""Utilities for launching and interacting with the offline MCP core."""

from __future__ import annotations

import sys
import json
import http.client

jsonrpc_request_id = 1
ida_host = "127.0.0.1"
ida_port = 13337


def make_jsonrpc_request(method: str, *params):
    global jsonrpc_request_id, ida_host, ida_port
    conn = http.client.HTTPConnection(ida_host, ida_port)
    request = {
        "jsonrpc": "2.0",
        "method": method,
        "params": list(params),
        "id": jsonrpc_request_id,
    }
    jsonrpc_request_id += 1
    try:
        conn.request("POST", "/mcp", json.dumps(request), {"Content-Type": "application/json"})
        response = conn.getresponse()
        data = json.loads(response.read().decode())
        if "error" in data:
            error = data["error"]
            code = error["code"]
            message = error["message"]
            pretty = f"JSON-RPC error {code}: {message}"
            if "data" in error:
                pretty += "\n" + error["data"]
            raise Exception(pretty)
        result = data["result"]
        if result is None:
            result = "success"
        return result
    finally:
        conn.close()


def check_connection() -> str:
    """Check if the IDA plugin is running."""
    try:
        metadata = make_jsonrpc_request("get_metadata")
        return f"Successfully connected to IDA Pro (open file: {metadata['module']})"
    except Exception:
        if sys.platform == "darwin":
            shortcut = "Ctrl+Option+M"
        else:
            shortcut = "Ctrl+Alt+M"
        return f"Failed to connect to IDA Pro! Did you run Edit -> Plugins -> MCP ({shortcut}) to start the server?"
