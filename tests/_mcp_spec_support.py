"""Shared helpers and MCP-spec JSON Schemas for the regression tests."""

import http.server  # Preload stdlib http before adding local ida_mcp paths.
import importlib.util
import json
import pathlib
import socket
import sys
import threading
import time
import types
import urllib.error
import urllib.request
from typing import Any

from jsonschema import Draft202012Validator


_ZEROMCP_SRC = pathlib.Path(__file__).resolve().parents[1] / "src" / "ida_pro_mcp" / "ida_mcp"
sys.path.insert(0, str(_ZEROMCP_SRC))
try:
    from zeromcp.mcp import McpServer  # noqa: E402
finally:
    sys.path.remove(str(_ZEROMCP_SRC))


# ---------------------------------------------------------------------------
# MCP spec JSON Schemas (what strict Zod-style clients enforce on the wire)
# ---------------------------------------------------------------------------

TOOL_NAME_PATTERN = r"^[a-zA-Z_][a-zA-Z0-9_.-]*$"

TOOL_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "properties": {
        "name": {"type": "string", "pattern": TOOL_NAME_PATTERN, "minLength": 1},
        "description": {"type": "string"},
        "inputSchema": {
            "type": "object",
            "properties": {"type": {"const": "object"}},
            "required": ["type"],
        },
        "outputSchema": {
            "type": "object",
            "properties": {"type": {"const": "object"}},
            "required": ["type"],
        },
    },
    "required": ["name", "inputSchema"],
}

TOOLS_LIST_RESULT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {"tools": {"type": "array", "items": TOOL_SCHEMA}},
    "required": ["tools"],
}

PROMPT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "name": {"type": "string", "minLength": 1},
        "description": {"type": "string"},
        "arguments": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "minLength": 1},
                    "description": {"type": "string"},
                    "required": {"type": "boolean"},
                },
                "required": ["name"],
            },
        },
    },
    "required": ["name"],
}

PROMPTS_LIST_RESULT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {"prompts": {"type": "array", "items": PROMPT_SCHEMA}},
    "required": ["prompts"],
}

RESOURCE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "uri": {"type": "string", "minLength": 1},
        "name": {"type": "string"},
        "description": {"type": "string"},
        "mimeType": {"type": "string"},
    },
    "required": ["uri"],
}

RESOURCES_LIST_RESULT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {"resources": {"type": "array", "items": RESOURCE_SCHEMA}},
    "required": ["resources"],
}

RESOURCE_TEMPLATE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "uriTemplate": {"type": "string", "minLength": 1},
        "name": {"type": "string"},
        "description": {"type": "string"},
        "mimeType": {"type": "string"},
    },
    "required": ["uriTemplate"],
}

RESOURCE_TEMPLATES_LIST_RESULT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {"resourceTemplates": {"type": "array", "items": RESOURCE_TEMPLATE_SCHEMA}},
    "required": ["resourceTemplates"],
}

INITIALIZE_RESULT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "protocolVersion": {"type": "string", "minLength": 1},
        "capabilities": {"type": "object"},
        "serverInfo": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "minLength": 1},
                "version": {"type": "string", "minLength": 1},
            },
            "required": ["name", "version"],
        },
    },
    "required": ["protocolVersion", "capabilities", "serverInfo"],
}

CALL_TOOL_RESULT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "content": {"type": "array"},
        "structuredContent": {"type": "object"},
        "isError": {"type": "boolean"},
        "_meta": {"type": "object"},
    },
    "required": ["content"],
}

JSONRPC_RESPONSE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "jsonrpc": {"const": "2.0"},
        "id": {"type": ["string", "number", "null"]},
        "result": {},
        "error": {
            "type": "object",
            "properties": {
                "code": {"type": "integer"},
                "message": {"type": "string"},
                "data": {},
            },
            "required": ["code", "message"],
        },
    },
    "required": ["jsonrpc", "id"],
    "oneOf": [
        {"required": ["result"], "not": {"required": ["error"]}},
        {"required": ["error"], "not": {"required": ["result"]}},
    ],
}


# ---------------------------------------------------------------------------
# Validator helper
# ---------------------------------------------------------------------------

def assert_schema(instance: Any, schema: dict[str, Any], message: str = "") -> None:
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(instance), key=lambda e: list(e.path))
    if errors:
        lines = [f"{message}: " if message else ""]
        for e in errors:
            path = "/".join(str(p) for p in e.absolute_path) or "<root>"
            lines.append(f"  at {path}: {e.message}")
        raise AssertionError("\n".join(lines))


# ---------------------------------------------------------------------------
# Real HTTP server harness
# ---------------------------------------------------------------------------

class McpHttpTestServer:
    """Boot an McpServer on a random local port for wire-level tests."""

    def __init__(self, server: McpServer):
        self.server = server
        self.host = "127.0.0.1"
        self.port = _pick_free_port(self.host)
        self.base_url = f"http://{self.host}:{self.port}"

    def __enter__(self) -> "McpHttpTestServer":
        self.server.serve(self.host, self.port, background=True)
        _wait_until_ready(self.base_url + "/mcp")
        return self

    def __exit__(self, *exc_info: Any) -> None:
        self.server.stop()

    def post_jsonrpc(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        *,
        request_id: Any = 1,
        extra_headers: dict[str, str] | None = None,
        notification: bool = False,
    ) -> tuple[int, dict[str, str], dict[str, Any] | None]:
        payload: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if not notification:
            payload["id"] = request_id
        if params is not None:
            payload["params"] = params

        body = json.dumps(payload).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if extra_headers:
            headers.update(extra_headers)

        req = urllib.request.Request(
            self.base_url + "/mcp", data=body, headers=headers, method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                raw = resp.read()
                status = resp.status
                hdrs = {k: v for k, v in resp.headers.items()}
        except urllib.error.HTTPError as e:
            raw = e.read()
            status = e.code
            hdrs = {k: v for k, v in e.headers.items()}

        parsed: dict[str, Any] | None = None
        if raw:
            try:
                parsed = json.loads(raw.decode("utf-8"))
            except json.JSONDecodeError:
                parsed = None
        return status, hdrs, parsed


def _pick_free_port(host: str) -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _wait_until_ready(url: str, timeout: float = 2.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            req = urllib.request.Request(url, method="OPTIONS")
            with urllib.request.urlopen(req, timeout=0.2):
                return
        except urllib.error.HTTPError:
            return
        except (urllib.error.URLError, ConnectionRefusedError, socket.timeout):
            time.sleep(0.02)
    raise RuntimeError(f"server at {url} not ready within {timeout}s")


# ---------------------------------------------------------------------------
# In-process helpers
# ---------------------------------------------------------------------------

def call_rpc(server: McpServer, method: str, **params: Any) -> Any:
    handler = server.registry.methods[method]
    return handler(**params) if params else handler()


def load_ida_rpc_module() -> types.ModuleType:
    """Load rpc.py without triggering the ida_mcp package __init__ (needs IDA)."""
    pkg_root = pathlib.Path(__file__).resolve().parents[1] / "src" / "ida_pro_mcp" / "ida_mcp"

    pkg_name = "_test_stub_ida_mcp"
    if pkg_name + ".rpc" in sys.modules:
        return sys.modules[pkg_name + ".rpc"]

    stub = types.ModuleType(pkg_name)
    stub.__path__ = [str(pkg_root)]
    sys.modules[pkg_name] = stub

    zero_name = pkg_name + ".zeromcp"
    zero_spec = importlib.util.spec_from_file_location(
        zero_name,
        pkg_root / "zeromcp" / "__init__.py",
        submodule_search_locations=[str(pkg_root / "zeromcp")],
    )
    zero_mod = importlib.util.module_from_spec(zero_spec)
    sys.modules[zero_name] = zero_mod
    zero_spec.loader.exec_module(zero_mod)

    rpc_name = pkg_name + ".rpc"
    rpc_spec = importlib.util.spec_from_file_location(rpc_name, pkg_root / "rpc.py")
    rpc_mod = importlib.util.module_from_spec(rpc_spec)
    sys.modules[rpc_name] = rpc_mod
    rpc_spec.loader.exec_module(rpc_mod)
    return rpc_mod


__all__ = [
    "McpServer",
    "McpHttpTestServer",
    "Draft202012Validator",
    "assert_schema",
    "call_rpc",
    "load_ida_rpc_module",
    "TOOL_NAME_PATTERN",
    "TOOL_SCHEMA",
    "TOOLS_LIST_RESULT_SCHEMA",
    "PROMPT_SCHEMA",
    "PROMPTS_LIST_RESULT_SCHEMA",
    "RESOURCE_SCHEMA",
    "RESOURCES_LIST_RESULT_SCHEMA",
    "RESOURCE_TEMPLATE_SCHEMA",
    "RESOURCE_TEMPLATES_LIST_RESULT_SCHEMA",
    "INITIALIZE_RESULT_SCHEMA",
    "CALL_TOOL_RESULT_SCHEMA",
    "JSONRPC_RESPONSE_SCHEMA",
]
