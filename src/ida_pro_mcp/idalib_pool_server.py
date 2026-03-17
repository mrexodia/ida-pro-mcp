"""idalib Pool Proxy — MCP server that manages a pool of idalib instances.

This process does NOT import ``idapro``.  It speaks MCP over HTTP to clients
and forwards IDA tool calls to backend idalib_server sub-processes connected
via Unix domain sockets.

Usage::

    uv run idalib-pool --port 8750 /path/to/binary          # single binary
    uv run idalib-pool --max-instances 3 --port 8750         # limited pool
    uv run idalib-pool --max-instances 0 --port 8750         # unlimited
"""

from __future__ import annotations

import argparse
import copy
import json
import logging
import os
import signal
import sys
import traceback
from pathlib import Path
from typing import Any

# Import zeromcp directly from the vendored package path without triggering
# ida_mcp/__init__.py (which imports idapro-dependent modules).
import importlib.util

def _import_zeromcp_module(name: str, subpath: str):
    """Import a zeromcp module by file path, bypassing ida_mcp.__init__."""
    zeromcp_dir = os.path.join(os.path.dirname(__file__), "ida_mcp", "zeromcp")
    spec = importlib.util.spec_from_file_location(name, os.path.join(zeromcp_dir, subpath))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod

_jsonrpc_mod = _import_zeromcp_module(
    "ida_pro_mcp.ida_mcp.zeromcp.jsonrpc", "jsonrpc.py"
)
_mcp_mod = _import_zeromcp_module(
    "ida_pro_mcp.ida_mcp.zeromcp.mcp", "mcp.py"
)
McpServer = _mcp_mod.McpServer
JsonRpcResponse = _jsonrpc_mod.JsonRpcResponse

from ida_pro_mcp.idalib_pool_manager import PoolManager  # noqa: E402

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------
# Management tool names that the proxy intercepts
# --------------------------------------------------------------------------

IDALIB_MANAGEMENT_TOOLS = {
    "idalib_open",
    "idalib_close",
    "idalib_switch",
    "idalib_unbind",
    "idalib_list",
    "idalib_current",
    "idalib_save",
    "idalib_health",
    "idalib_warmup",
}

# --------------------------------------------------------------------------
# Tool schema injection
# --------------------------------------------------------------------------

_SESSION_ID_SCHEMA: dict = {
    "type": "string",
    "description": (
        "Session ID to route this call to. "
        "If omitted, uses the default session."
    ),
}


def _inject_session_id(tools: list[dict]) -> list[dict]:
    """Add an optional ``session_id`` parameter to every tool's input schema."""
    result = []
    for tool in tools:
        tool = copy.deepcopy(tool)
        schema = tool.setdefault("inputSchema", {})
        props = schema.setdefault("properties", {})
        if "session_id" not in props:
            props["session_id"] = _SESSION_ID_SCHEMA
        # session_id is always optional — never add to "required"
        tool["inputSchema"] = schema
        result.append(tool)
    return result


def _filter_management_tools(tools: list[dict]) -> list[dict]:
    """Remove idalib_* management tools that the proxy handles itself."""
    return [t for t in tools if t.get("name") not in IDALIB_MANAGEMENT_TOOLS]


# --------------------------------------------------------------------------
# Proxy dispatch
# --------------------------------------------------------------------------

def build_dispatch(mcp: McpServer, pool: PoolManager):
    """Patch ``mcp.registry.dispatch`` with pool-aware routing."""

    dispatch_original = mcp.registry.dispatch
    _tools_cache: list[dict] | None = None

    def _ensure_tools_cache() -> list[dict]:
        nonlocal _tools_cache
        if _tools_cache is None:
            raw = pool.forward_tools_list()
            raw = _filter_management_tools(raw)
            _tools_cache = _inject_session_id(raw)
        return _tools_cache

    def _error_response(request_id: Any, code: int, message: str) -> JsonRpcResponse:
        if request_id is None:
            return None  # type: ignore[return-value]
        return {
            "jsonrpc": "2.0",
            "error": {"code": code, "message": message},
            "id": request_id,
        }

    # --- Management tool handlers ---

    def _handle_idalib_open(arguments: dict) -> dict:
        input_path = arguments.get("input_path", "")
        session_id = arguments.get("session_id")
        run_auto = arguments.get("run_auto_analysis", True)
        return pool.open_session(input_path, session_id=session_id, run_auto_analysis=run_auto)

    def _handle_idalib_close(arguments: dict) -> dict:
        sid = arguments.get("session_id", "")
        return pool.close_session(sid)

    def _handle_idalib_switch(arguments: dict) -> dict:
        sid = arguments.get("session_id", "")
        with pool._lock:
            if sid not in pool.sessions:
                return {"success": False, "error": f"Session not found: {sid}"}
            pool.default_session_id = sid
            sess = pool.sessions[sid]
            sess.last_accessed = __import__("time").monotonic()
            return {
                "success": True,
                "session": sess.to_dict(),
                "message": f"Default session set to: {sid}",
            }

    def _handle_idalib_list(_arguments: dict) -> dict:
        return pool.list_sessions()

    def _handle_idalib_current(_arguments: dict) -> dict:
        return pool.get_current_session()

    def _handle_idalib_save(arguments: dict) -> dict:
        sid = arguments.pop("session_id", None) or pool.default_session_id
        if sid is None:
            return {"error": "No session to save. Use idalib_open first."}
        try:
            _sess, inst = pool.resolve_session_instance(sid)
        except (KeyError, RuntimeError) as e:
            return {"error": str(e)}
        return pool.forward_tool_call(inst, "idalib_save", arguments)

    _mgmt_handlers: dict[str, Any] = {
        "idalib_open": _handle_idalib_open,
        "idalib_close": _handle_idalib_close,
        "idalib_switch": _handle_idalib_switch,
        "idalib_list": _handle_idalib_list,
        "idalib_current": _handle_idalib_current,
        "idalib_save": _handle_idalib_save,
    }

    # --- tools/call handler ---

    def _handle_tools_call(request_obj: dict) -> JsonRpcResponse | None:
        params = request_obj.get("params", {})
        tool_name = params.get("name", "")
        arguments = params.get("arguments") or {}
        request_id = request_obj.get("id")

        # 1. Management tools — handle locally
        handler = _mgmt_handlers.get(tool_name)
        if handler is not None:
            try:
                result = handler(dict(arguments))
            except Exception as e:
                return _error_response(request_id, -32000, str(e))
            return {
                "jsonrpc": "2.0",
                "result": {
                    "content": [{"type": "text", "text": json.dumps(result, indent=2)}],
                    "structuredContent": result if isinstance(result, dict) else {"result": result},
                    "isError": bool(isinstance(result, dict) and result.get("error")),
                },
                "id": request_id,
            }

        # 2. Other management tools — forward to default session's instance
        if tool_name in IDALIB_MANAGEMENT_TOOLS:
            sid = pool.default_session_id
            if sid is None:
                return _error_response(
                    request_id, -32001,
                    f"No active session for tool '{tool_name}'. Use idalib_open first.",
                )
            try:
                _sess, inst = pool.resolve_session_instance(sid)
            except (KeyError, RuntimeError) as e:
                return _error_response(request_id, -32001, str(e))
            return pool.forward_raw(inst, request_obj)

        # 3. IDA tools — route by session_id
        session_id = arguments.pop("session_id", None) or pool.default_session_id
        if session_id is None:
            return _error_response(
                request_id, -32001,
                "No active session. Use idalib_open to create one, or pass session_id.",
            )

        try:
            _sess, inst = pool.resolve_session_instance(session_id)
        except (KeyError, RuntimeError) as e:
            return _error_response(request_id, -32001, str(e))

        # Rebuild request without session_id in arguments
        forwarded = copy.deepcopy(request_obj)
        fwd_args = forwarded.get("params", {}).get("arguments", {})
        fwd_args.pop("session_id", None)

        return pool.forward_raw(inst, forwarded)

    # --- tools/list handler ---

    def _handle_tools_list(request_obj: dict) -> JsonRpcResponse:
        # Get local tools (initialize etc) from original dispatch
        local_resp = dispatch_original(request_obj)
        local_tools = (local_resp or {}).get("result", {}).get("tools", [])

        # Get IDA tools from cache
        ida_tools = _ensure_tools_cache()

        return {
            "jsonrpc": "2.0",
            "result": {"tools": local_tools + ida_tools},
            "id": request_obj.get("id"),
        }

    # --- Main dispatch ---

    def dispatch_proxy(request: dict | str | bytes | bytearray) -> JsonRpcResponse | None:
        if not isinstance(request, dict):
            request_obj: dict = json.loads(request)
        else:
            request_obj = request

        method = request_obj.get("method", "")
        request_id = request_obj.get("id")

        # Protocol methods handled locally
        if method == "initialize":
            return dispatch_original(request)
        if method.startswith("notifications/"):
            return dispatch_original(request)

        # tools/list — merge local + cached IDA tools
        if method == "tools/list":
            return _handle_tools_list(request_obj)

        # tools/call — route
        if method == "tools/call":
            try:
                return _handle_tools_call(request_obj)
            except Exception as e:
                tb = traceback.format_exc()
                return _error_response(request_id, -32000, f"{e}\n{tb}")

        # Everything else — forward to default session's instance
        sid = pool.default_session_id
        if sid is None:
            return _error_response(
                request_id, -32001,
                f"No active session for method '{method}'. Use idalib_open first.",
            )
        try:
            _sess, inst = pool.resolve_session_instance(sid)
        except (KeyError, RuntimeError) as e:
            return _error_response(request_id, -32001, str(e))
        return pool.forward_raw(inst, request_obj)

    mcp.registry.dispatch = dispatch_proxy


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="MCP proxy server managing a pool of idalib instances"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Show debug messages"
    )
    parser.add_argument(
        "--host", type=str, default="127.0.0.1",
        help="Host to listen on (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port", type=int, default=8750,
        help="Port to listen on (default: 8750)",
    )
    parser.add_argument(
        "--max-instances", type=int, default=1,
        help="Max idalib instances (0 = unlimited, default: 1)",
    )
    parser.add_argument(
        "--socket-dir", type=str, default=None,
        help="Directory for instance Unix sockets (default: auto temp dir)",
    )
    parser.add_argument(
        "--unsafe", action="store_true",
        help="Pass --unsafe to idalib instances",
    )
    parser.add_argument(
        "--auth-token", type=str,
        default=os.environ.get("IDA_MCP_AUTH_TOKEN"),
        help="Bearer token for HTTP authentication (or set IDA_MCP_AUTH_TOKEN)",
    )
    parser.add_argument(
        "input_path", type=Path, nargs="?",
        help="Optional binary to open on startup.",
    )
    args = parser.parse_args()

    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level)

    idalib_args: list[str] = []
    if args.verbose:
        idalib_args.append("--verbose")
    if args.unsafe:
        idalib_args.append("--unsafe")

    pool = PoolManager(
        max_instances=args.max_instances,
        socket_dir=args.socket_dir,
        idalib_args=idalib_args,
    )

    mcp = McpServer("ida-pro-mcp")
    if args.auth_token:
        mcp.auth_token = args.auth_token

    # We need at least one instance running to get the tool schemas
    logger.info("Spawning initial instance for tool discovery...")
    pool.spawn_instance()

    build_dispatch(mcp, pool)

    # Open initial binary if provided
    if args.input_path is not None:
        if not args.input_path.exists():
            print(f"Error: Input file not found: {args.input_path}", file=sys.stderr)
            sys.exit(1)
        logger.info("Opening initial binary: %s", args.input_path)
        result = pool.open_session(str(args.input_path))
        if isinstance(result, dict) and result.get("error"):
            print(f"Error opening binary: {result['error']}", file=sys.stderr)
            sys.exit(1)
        logger.info("Initial session: %s", result.get("session", {}).get("session_id"))

    def cleanup(signum, frame):
        logger.info("Shutting down pool...")
        pool.shutdown_all()
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    mcp.serve(host=args.host, port=args.port, background=False)


if __name__ == "__main__":
    main()
