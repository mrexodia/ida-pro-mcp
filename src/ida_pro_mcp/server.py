import argparse
import http.client
import json
import os
import sys
import traceback
from typing import Annotated, TYPE_CHECKING
from urllib.parse import urlparse

if TYPE_CHECKING:
    from ida_pro_mcp.ida_mcp.zeromcp import McpServer
    from ida_pro_mcp.ida_mcp.zeromcp.jsonrpc import JsonRpcRequest, JsonRpcResponse
    from ida_pro_mcp.ida_mcp.discovery import InstanceInfo
else:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "ida_mcp"))
    from zeromcp import McpServer
    from zeromcp.jsonrpc import JsonRpcRequest, JsonRpcResponse

    sys.path.pop(0)

try:
    from .installer import list_available_clients, print_mcp_config, run_install_command, set_ida_rpc
except ImportError:
    from installer import list_available_clients, print_mcp_config, run_install_command, set_ida_rpc

try:
    from .ida_mcp.discovery import discover_instances, probe_instance
except ImportError:
    try:
        from ida_mcp.discovery import discover_instances, probe_instance
    except ImportError:
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "ida_mcp"))
        from discovery import discover_instances, probe_instance

        sys.path.pop(0)

IDA_HOST = "127.0.0.1"
IDA_PORT = 13337

mcp = McpServer("ida-pro-mcp")
dispatch_original = mcp.registry.dispatch

LOCAL_TOOLS = {"select_instance"}


def _proxy_to_ida(payload: bytes | str | dict) -> dict:
    """Send a JSON-RPC request to the active IDA instance and return the response."""
    if isinstance(payload, dict):
        payload = json.dumps(payload)
    elif isinstance(payload, str):
        payload = payload.encode("utf-8")

    conn = http.client.HTTPConnection(IDA_HOST, IDA_PORT, timeout=30)
    try:
        conn.request(
            "POST",
            "/mcp",
            payload,
            {"Content-Type": "application/json"},
        )
        response = conn.getresponse()
        raw_data = response.read().decode()
        if response.status >= 400:
            raise RuntimeError(
                f"HTTP {response.status} {response.reason}: {raw_data}"
            )
        return json.loads(raw_data)
    finally:
        conn.close()



def dispatch_proxy(request: dict | str | bytes | bytearray) -> JsonRpcResponse | None:
    """Dispatch JSON-RPC requests to the MCP server registry."""
    if not isinstance(request, dict):
        request_obj: JsonRpcRequest = json.loads(request)
    else:
        request_obj: JsonRpcRequest = request  # type: ignore

    if request_obj["method"] == "initialize":
        return dispatch_original(request)
    if request_obj["method"].startswith("notifications/"):
        return dispatch_original(request)

    # Handle local tools (instance discovery) without proxying to IDA
    if request_obj["method"] == "tools/call":
        params = request_obj.get("params", {})
        tool_name = params.get("name", "")
        if tool_name in LOCAL_TOOLS:
            return dispatch_original(request)

    # Handle tools/list locally: always include local tools, merge IDA tools when available
    if request_obj["method"] == "tools/list":
        # Get local tools (always available)
        local_result = dispatch_original(request)
        local_tool_names = {t["name"] for t in local_result.get("result", {}).get("tools", [])} if local_result else set()
        # Try to get IDA tools and merge them in
        try:
            ida_result = _proxy_to_ida(request)
            if ida_result and "result" in ida_result:
                # Filter out IDA tools that duplicate local tools (e.g. select_instance)
                ida_tools = [t for t in ida_result["result"].get("tools", [])
                             if t.get("name") not in local_tool_names]
                if local_result and "result" in local_result:
                    local_result["result"]["tools"] = ida_tools + local_result["result"].get("tools", [])
        except Exception:
            pass  # IDA unreachable — local tools still work
        return local_result

    try:
        return _proxy_to_ida(request)
    except Exception as e:
        full_info = traceback.format_exc()
        request_id = request_obj.get("id")
        if request_id is None:
            return None  # Notification, no response needed

        shortcut = "Ctrl+Option+M" if sys.platform == "darwin" else "Ctrl+Alt+M"
        return JsonRpcResponse(
            {
                "jsonrpc": "2.0",
                "error": {
                    "code": -32000,
                    "message": (
                        "Failed to complete request to IDA Pro. "
                        f"Did you run Edit -> Plugins -> MCP ({shortcut}) to start the server?\n"
                        "The request was not retried automatically. "
                        "If this was a mutating operation, verify IDA state before retrying.\n"
                        f"{full_info}"
                    ),
                    "data": str(e),
                },
                "id": request_id,
            }
        )


mcp.registry.dispatch = dispatch_proxy


# ============================================================================
# Local tools (handled by the proxy, not forwarded to IDA)
# ============================================================================


@mcp.tool
def select_instance(
    port: Annotated[int, "Port number of the IDA instance to connect to"],
    host: Annotated[str, "Host address of the IDA instance"] = "127.0.0.1",
) -> dict:
    """Switch this MCP server to proxy requests to a different IDA Pro instance.

    Use list_instances first to see available instances, then select one by port.
    All subsequent tool calls will be routed to the selected instance.
    """
    global IDA_HOST, IDA_PORT
    if not probe_instance(host, port):
        return {"success": False, "error": f"Instance at {host}:{port} is not reachable"}
    IDA_HOST = host
    IDA_PORT = port
    set_ida_rpc(IDA_HOST, IDA_PORT)
    return {"success": True, "host": host, "port": port}


# ============================================================================

DEFAULT_IDA_RPC = f"http://{IDA_HOST}:{IDA_PORT}"


def _resolve_ida_rpc(args) -> None:
    """Resolve the IDA RPC target: explicit --ida-rpc, or auto-discovery."""
    global IDA_HOST, IDA_PORT

    if args.ida_rpc is not None:
        # Explicit --ida-rpc: use directly (backwards compatible)
        ida_rpc = urlparse(args.ida_rpc)
        if ida_rpc.hostname is None or ida_rpc.port is None:
            raise Exception(f"Invalid IDA RPC server: {args.ida_rpc}")
        IDA_HOST = ida_rpc.hostname
        IDA_PORT = ida_rpc.port
        set_ida_rpc(IDA_HOST, IDA_PORT)
        return

    # Auto-discover running IDA instances
    instances = discover_instances()
    if len(instances) == 0:
        print(f"[MCP] No IDA instances discovered, using default {IDA_HOST}:{IDA_PORT}", file=sys.stderr)
    elif len(instances) == 1:
        inst = instances[0]
        IDA_HOST = inst["host"]
        IDA_PORT = inst["port"]
        print(f"[MCP] Auto-connected to: {inst['binary']} at {IDA_HOST}:{IDA_PORT}", file=sys.stderr)
    else:
        print(f"[MCP] Found {len(instances)} IDA instances:", file=sys.stderr)
        for i, inst in enumerate(instances):
            print(f"  [{i}] {inst['binary']} at {inst['host']}:{inst['port']}", file=sys.stderr)
        inst = instances[0]
        IDA_HOST = inst["host"]
        IDA_PORT = inst["port"]
        print(f"[MCP] Auto-selected: {inst['binary']}. Use select_instance tool to switch.", file=sys.stderr)

    set_ida_rpc(IDA_HOST, IDA_PORT)


def main():
    global IDA_HOST, IDA_PORT

    parser = argparse.ArgumentParser(description="IDA Pro MCP Server")
    parser.add_argument(
        "--install",
        nargs="?",
        const="",
        default=None,
        metavar="TARGETS",
        help="Install the MCP Server and IDA plugin. "
        "The IDA plugin is installed immediately. "
        "Optionally specify comma-separated client targets (e.g., 'claude,cursor'). "
        "Without targets, an interactive selector is shown.",
    )
    parser.add_argument(
        "--uninstall",
        nargs="?",
        const="",
        default=None,
        metavar="TARGETS",
        help="Uninstall the MCP Server and IDA plugin. "
        "The IDA plugin is uninstalled immediately. "
        "Optionally specify comma-separated client targets. "
        "Without targets, an interactive selector is shown.",
    )
    parser.add_argument(
        "--allow-ida-free",
        action="store_true",
        help="Allow installation despite IDA Free being installed",
    )
    parser.add_argument(
        "--transport",
        type=str,
        default=None,
        help="MCP transport for install: 'streamable-http' (default), 'stdio', or 'sse'. "
        "For running: use stdio (default) or pass a URL (e.g., http://127.0.0.1:8744[/mcp|/sse])",
    )
    parser.add_argument(
        "--scope",
        type=str,
        choices=["global", "project"],
        default=None,
        help="Installation scope: 'project' (current directory, default) or 'global' (user-level)",
    )
    parser.add_argument(
        "--ida-rpc",
        type=str,
        default=None,
        help=f"IDA RPC server (default: auto-discover, fallback: {DEFAULT_IDA_RPC})",
    )
    parser.add_argument(
        "--config", action="store_true", help="Generate MCP config JSON"
    )
    parser.add_argument(
        "--list-clients",
        action="store_true",
        help="List all available MCP client targets",
    )
    args = parser.parse_args()

    # Handle --list-clients independently
    if args.list_clients:
        list_available_clients()
        return

    # Resolve IDA RPC target (explicit or auto-discovery)
    _resolve_ida_rpc(args)

    is_install = args.install is not None
    is_uninstall = args.uninstall is not None

    # Validate flag combinations
    if args.scope and not (is_install or is_uninstall):
        print("--scope requires --install or --uninstall")
        return

    if is_install and is_uninstall:
        print("Cannot install and uninstall at the same time")
        return

    if is_install or is_uninstall:
        run_install_command(
            uninstall=is_uninstall,
            targets_str=args.install if is_install else args.uninstall,
            args=args,
        )
        return

    if args.config:
        print_mcp_config()
        return

    try:
        transport = args.transport or "stdio"
        if transport == "stdio":
            mcp.stdio()
        else:
            url = urlparse(transport)
            if url.hostname is None or url.port is None:
                raise Exception(f"Invalid transport URL: {args.transport}")
            # NOTE: npx -y @modelcontextprotocol/inspector for debugging
            mcp.serve(url.hostname, url.port)
            input("Server is running, press Enter or Ctrl+C to stop.")
    except (KeyboardInterrupt, EOFError):
        pass


if __name__ == "__main__":
    main()
