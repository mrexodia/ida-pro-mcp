import argparse
import http.client
import json
import os
import re
import sys
import threading
import time
import traceback
from collections import OrderedDict
from typing import Annotated, TYPE_CHECKING, TypedDict
from urllib.parse import parse_qs, urlparse

if TYPE_CHECKING:
    from ida_pro_mcp.ida_mcp.zeromcp import (
        EXTERNAL_BASE_HEADER,
        McpHttpRequestHandler,
        McpServer,
        get_current_request_external_base_url,
    )
    from ida_pro_mcp.ida_mcp.zeromcp.jsonrpc import JsonRpcRequest, JsonRpcResponse
else:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "ida_mcp"))
    from zeromcp import (
        EXTERNAL_BASE_HEADER,
        McpHttpRequestHandler,
        McpServer,
        get_current_request_external_base_url,
    )
    from zeromcp.jsonrpc import JsonRpcRequest, JsonRpcResponse

    sys.path.pop(0)

try:
    from .installer import (
        list_available_clients,
        print_mcp_config,
        run_install_command,
        set_ida_rpc,
    )
except ImportError:
    from installer import (
        list_available_clients,
        print_mcp_config,
        run_install_command,
        set_ida_rpc,
    )

try:
    from .ida_mcp.discovery import discover_instances, probe_instance
except ImportError:
    try:
        from ida_mcp.discovery import discover_instances, probe_instance
    except ImportError:
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "ida_mcp"))
        from discovery import discover_instances, probe_instance

        sys.path.pop(0)

class ProxyInstanceInfo(TypedDict, total=False):
    host: str
    port: int
    pid: int
    binary: str
    idb_path: str
    started_at: str
    reachable: bool
    active: bool


class ProxySelectResult(TypedDict, total=False):
    success: bool
    host: str
    port: int
    message: str
    error: str


DEFAULT_IDA_HOST = "127.0.0.1"
DEFAULT_IDA_PORT = 13337
IDA_HOST = DEFAULT_IDA_HOST
IDA_PORT = DEFAULT_IDA_PORT

mcp = McpServer("ida-pro-mcp")
dispatch_original = mcp.registry.dispatch

LOCAL_TOOLS = {"list_instances", "select_instance"}
OUTPUT_PROXY_CACHE_MAX_SIZE = 100
_OUTPUT_PATH_RE = re.compile(r"^/output/([a-f0-9-]+)\.(\w+)$")
_output_proxy_targets: OrderedDict[str, tuple[str, int]] = OrderedDict()
_output_proxy_lock = threading.Lock()
SESSION_PROXY_TARGET_TTL_SEC = 24 * 60 * 60
SESSION_PROXY_TARGET_MAX_SIZE = 4096
_session_proxy_targets: OrderedDict[str, tuple[str, int]] = OrderedDict()
_session_proxy_last_seen: dict[str, float] = {}
_session_proxy_lock = threading.Lock()


def _get_proxy_session_key() -> str | None:
    """Return the active MCP transport session id, if one is available."""
    return mcp.get_current_transport_session_id()


def _prune_session_proxy_targets_locked(now: float | None = None) -> None:
    """Remove expired or excess per-session IDA target selections."""
    now = time.monotonic() if now is None else now

    # Tests and older callers may mutate _session_proxy_targets directly. Treat
    # entries without metadata as live, then include them in normal pruning.
    for session_key in list(_session_proxy_targets):
        _session_proxy_last_seen.setdefault(session_key, now)

    if SESSION_PROXY_TARGET_TTL_SEC > 0:
        cutoff = now - SESSION_PROXY_TARGET_TTL_SEC
        for session_key, last_seen in list(_session_proxy_last_seen.items()):
            if last_seen < cutoff:
                _session_proxy_targets.pop(session_key, None)
                _session_proxy_last_seen.pop(session_key, None)

    for session_key in list(_session_proxy_last_seen):
        if session_key not in _session_proxy_targets:
            _session_proxy_last_seen.pop(session_key, None)

    if SESSION_PROXY_TARGET_MAX_SIZE > 0:
        while len(_session_proxy_targets) > SESSION_PROXY_TARGET_MAX_SIZE:
            session_key, _ = _session_proxy_targets.popitem(last=False)
            _session_proxy_last_seen.pop(session_key, None)


def _get_active_ida_target() -> tuple[str, int]:
    """Return the IDA target selected for this MCP transport session."""
    session_key = _get_proxy_session_key()
    if session_key is not None:
        now = time.monotonic()
        with _session_proxy_lock:
            _prune_session_proxy_targets_locked(now)
            target = _session_proxy_targets.get(session_key)
            if target is not None:
                _session_proxy_targets.move_to_end(session_key)
                _session_proxy_last_seen[session_key] = now
                return target
    return IDA_HOST, IDA_PORT


def _set_active_ida_target(host: str, port: int) -> None:
    """Select an IDA target for the current session, falling back to process-wide state."""
    global IDA_HOST, IDA_PORT
    session_key = _get_proxy_session_key()
    if session_key is not None:
        now = time.monotonic()
        with _session_proxy_lock:
            _session_proxy_targets.pop(session_key, None)
            _session_proxy_targets[session_key] = (host, port)
            _session_proxy_last_seen[session_key] = now
            _prune_session_proxy_targets_locked(now)
        return
    IDA_HOST = host
    IDA_PORT = port
    set_ida_rpc(IDA_HOST, IDA_PORT)


def _clear_active_ida_target() -> tuple[str, int]:
    """Clear the current session's target selection and return the default target."""
    global IDA_HOST, IDA_PORT
    session_key = _get_proxy_session_key()
    if session_key is not None:
        with _session_proxy_lock:
            _session_proxy_targets.pop(session_key, None)
            _session_proxy_last_seen.pop(session_key, None)
        return IDA_HOST, IDA_PORT
    IDA_HOST = DEFAULT_IDA_HOST
    IDA_PORT = DEFAULT_IDA_PORT
    set_ida_rpc(IDA_HOST, IDA_PORT)
    return IDA_HOST, IDA_PORT


def _extract_output_id(response: dict) -> str | None:
    result = response.get("result")
    if not isinstance(result, dict):
        return None
    meta = result.get("_meta")
    if not isinstance(meta, dict):
        return None
    ida_meta = meta.get("ida_mcp")
    if not isinstance(ida_meta, dict):
        return None
    output_id = ida_meta.get("output_id")
    return output_id if isinstance(output_id, str) else None


def _remember_output_proxy_target(output_id: str, host: str, port: int) -> None:
    with _output_proxy_lock:
        _output_proxy_targets.pop(output_id, None)
        _output_proxy_targets[output_id] = (host, port)
        while len(_output_proxy_targets) > OUTPUT_PROXY_CACHE_MAX_SIZE:
            _output_proxy_targets.popitem(last=False)


def _get_output_proxy_target(output_id: str) -> tuple[str, int] | None:
    with _output_proxy_lock:
        target = _output_proxy_targets.get(output_id)
        if target is None:
            return None
        _output_proxy_targets.move_to_end(output_id)
        return target


def _remember_output_proxy_target_from_response(host: str, port: int, response: dict) -> None:
    output_id = _extract_output_id(response)
    if output_id:
        _remember_output_proxy_target(output_id, host, port)


def _get_proxy_request_path() -> str:
    """Build the proxied MCP path, preserving enabled extensions."""
    enabled = sorted(getattr(mcp._enabled_extensions, "data", set()))
    if enabled:
        return f"/mcp?ext={','.join(enabled)}"
    return "/mcp"


def _get_proxy_request_headers() -> dict[str, str]:
    """Build proxy request headers, preserving HTTP MCP session identity."""
    headers = {"Content-Type": "application/json"}
    transport_session_id = mcp.get_current_transport_session_id()
    if transport_session_id and transport_session_id.startswith("http:"):
        session_id = transport_session_id.split(":", 1)[1]
        if session_id and session_id != "anonymous":
            headers["Mcp-Session-Id"] = session_id
    external_base_url = get_current_request_external_base_url()
    if external_base_url:
        headers[EXTERNAL_BASE_HEADER] = external_base_url
    return headers


def _proxy_to_instance(host: str, port: int, payload: bytes | str | dict) -> dict:
    """Send a JSON-RPC request to a specific IDA instance and return the response."""
    if isinstance(payload, dict):
        payload = json.dumps(payload)
    elif isinstance(payload, str):
        payload = payload.encode("utf-8")

    conn = http.client.HTTPConnection(host, port, timeout=30)
    try:
        conn.request(
            "POST",
            _get_proxy_request_path(),
            payload,
            _get_proxy_request_headers(),
        )
        response = conn.getresponse()
        raw_data = response.read().decode()
        if response.status >= 400:
            raise RuntimeError(
                f"HTTP {response.status} {response.reason}: {raw_data}"
            )
        parsed = json.loads(raw_data)
        _remember_output_proxy_target_from_response(host, port, parsed)
        return parsed
    finally:
        conn.close()


def _proxy_output_download(host: str, port: int, path: str) -> tuple[int, str, list[tuple[str, str]], bytes]:
    """Proxy a raw output download from a specific IDA instance."""
    conn = http.client.HTTPConnection(host, port, timeout=30)
    try:
        conn.request("GET", path)
        response = conn.getresponse()
        return response.status, response.reason, response.getheaders(), response.read()
    finally:
        conn.close()


def _proxy_to_ida(payload: bytes | str | dict) -> dict:
    """Send a JSON-RPC request to the active IDA instance and return the response."""
    host, port = _get_active_ida_target()
    return _proxy_to_instance(host, port, payload)


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
        local_tool_names = (
            {t["name"] for t in local_result.get("result", {}).get("tools", [])}
            if local_result
            else set()
        )
        # Try to get IDA tools and merge them in
        try:
            ida_result = _proxy_to_ida(request)
            if ida_result and "result" in ida_result:
                # Filter out IDA tools that duplicate local tools (e.g. select_instance)
                ida_tools = [
                    t
                    for t in ida_result["result"].get("tools", [])
                    if t.get("name") not in local_tool_names
                ]
                if local_result and "result" in local_result:
                    local_result["result"]["tools"] = (
                        ida_tools + local_result["result"].get("tools", [])
                    )
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


class ProxyHttpRequestHandler(McpHttpRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        output_match = _OUTPUT_PATH_RE.match(parsed.path)
        if output_match:
            if not self._check_api_request():
                return
            output_id = output_match.group(1)
            target = _get_output_proxy_target(output_id)
            if target is None:
                self.send_error(404, "Output not found or expired")
                return
            try:
                status, _, response_headers, body = _proxy_output_download(
                    target[0], target[1], parsed.path
                )
            except Exception as e:
                self.send_error(502, f"Failed to proxy output download: {e}")
                return

            self.send_response(status)
            for header, value in response_headers:
                if header.lower() == "transfer-encoding":
                    continue
                self.send_header(header, value)
            self.send_cors_headers()
            self.end_headers()
            self.wfile.write(body)
            return
        super().do_GET()


# ============================================================================
# Local tools (handled by the proxy, not forwarded to IDA)
# ============================================================================


@mcp.tool
def list_instances() -> list[ProxyInstanceInfo]:
    """List discovered IDA Pro instances and indicate which one is active."""
    active_host, active_port = _get_active_ida_target()
    result = []
    for inst in discover_instances():
        reachable = probe_instance(inst["host"], inst["port"])
        result.append(
            {
                **inst,
                "reachable": reachable,
                "active": inst["host"] == active_host and inst["port"] == active_port,
            }
        )
    return result


@mcp.tool
def select_instance(
    port: Annotated[int, "Port number of the IDA instance to connect to"],
    host: Annotated[str, "Host address of the IDA instance"] = "127.0.0.1",
) -> ProxySelectResult:
    """Switch this MCP server to proxy requests to a different IDA Pro instance.

    Use list_instances first to see available instances, then select one by port.
    All subsequent tool calls will be routed to the selected instance.
    """
    if port == 0:
        default_host, default_port = _clear_active_ida_target()
        return {
            "success": True,
            "host": default_host,
            "port": default_port,
            "message": "Reset to default IDA target",
        }
    if not probe_instance(host, port):
        return {"success": False, "error": f"Instance at {host}:{port} is not reachable"}
    _set_active_ida_target(host, port)
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

        # Preserve ?ext= query param so proxy requests include the extensions
        ext_value = parse_qs(ida_rpc.query).get("ext", [""])[0]
        if ext_value:
            mcp._enabled_extensions.data = set(ext_value.split(","))

        set_ida_rpc(IDA_HOST, IDA_PORT)
        return

    # Auto-discover running IDA instances
    instances = discover_instances()
    if len(instances) == 0:
        print(
            f"[MCP] No IDA instances discovered, using default {IDA_HOST}:{IDA_PORT}",
            file=sys.stderr,
        )
    elif len(instances) == 1:
        inst = instances[0]
        IDA_HOST = inst["host"]
        IDA_PORT = inst["port"]
        print(
            f"[MCP] Auto-connected to: {inst['binary']} at {IDA_HOST}:{IDA_PORT}",
            file=sys.stderr,
        )
    else:
        print(f"[MCP] Found {len(instances)} IDA instances:", file=sys.stderr)
        for i, inst in enumerate(instances):
            print(f"  [{i}] {inst['binary']} at {inst['host']}:{inst['port']}", file=sys.stderr)
        inst = instances[0]
        IDA_HOST = inst["host"]
        IDA_PORT = inst["port"]
        print(
            f"[MCP] Auto-selected: {inst['binary']}. "
            "Use select_instance tool to switch.",
            file=sys.stderr,
        )

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
            mcp.serve(url.hostname, url.port, request_handler=ProxyHttpRequestHandler)
            input("Server is running, press Enter or Ctrl+C to stop.")
    except (KeyboardInterrupt, EOFError):
        pass


if __name__ == "__main__":
    main()
