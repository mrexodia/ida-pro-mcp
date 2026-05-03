"""Discovery API - list and switch between IDA instances.

When running in streamable-http mode (client connects directly to IDA),
select_instance makes this IDA instance proxy tool calls to the target.
This lets a single MCP endpoint reach any running IDA instance.
"""

import http.client
import json
import threading
from collections import OrderedDict
from typing import Annotated, NotRequired, TypedDict

from .rpc import tool, MCP_SERVER
from .zeromcp import EXTERNAL_BASE_HEADER, get_current_request_external_base_url
from .discovery import discover_instances, probe_instance


class InstanceSelectionResult(TypedDict, total=False):
    success: bool
    host: str
    port: int
    message: str
    error: str


class InstanceListItem(TypedDict, total=False):
    host: str
    port: int
    pid: int
    binary: str
    idb_path: str
    started_at: str
    reachable: bool
    active: bool


# Track which instance this server is (filled in by the plugin loader)
_LOCAL_PORT: int | None = None
_LOCAL_HOST: str = "127.0.0.1"

# Thread-local: set by HTTP handler when request is a proxied forward
_request_context = threading.local()

# Redirect target: when set, tool calls are proxied to this instance
_redirect_host: str | None = None
_redirect_port: int | None = None
_redirect_targets: dict[str, tuple[str, int]] = {}
_redirect_lock = threading.Lock()

# Tools that are always handled locally, never proxied
_LOCAL_TOOL_NAMES = {"list_instances", "select_instance"}


def set_local_instance(host: str, port: int):
    """Called by the plugin loader after server starts."""
    global _LOCAL_HOST, _LOCAL_PORT
    _LOCAL_HOST = host
    _LOCAL_PORT = port


def _get_redirect_session_key() -> str | None:
    """Return the current MCP transport session id, if any."""
    return MCP_SERVER.get_current_transport_session_id()


def get_redirect_target() -> tuple[str, int] | None:
    """Returns (host, port) if requests should be proxied, else None."""
    session_key = _get_redirect_session_key()
    if session_key is not None:
        with _redirect_lock:
            return _redirect_targets.get(session_key)
    if _redirect_host is not None and _redirect_port is not None:
        return (_redirect_host, _redirect_port)
    return None


def _set_redirect_target(host: str, port: int):
    """Set the redirect target for the current MCP transport session."""
    global _redirect_host, _redirect_port
    session_key = _get_redirect_session_key()
    if session_key is not None:
        with _redirect_lock:
            _redirect_targets[session_key] = (host, port)
        return
    _redirect_host = host
    _redirect_port = port


def _clear_redirect_target():
    """Clear the redirect target for the current MCP transport session."""
    global _redirect_host, _redirect_port
    session_key = _get_redirect_session_key()
    if session_key is not None:
        with _redirect_lock:
            _redirect_targets.pop(session_key, None)
        return
    _redirect_host = None
    _redirect_port = None


def set_request_proxied(proxied: bool):
    """Called by HTTP handler to mark the current request as proxied."""
    _request_context.proxied = proxied


def is_request_proxied() -> bool:
    """Check if the current request was forwarded from another instance."""
    return getattr(_request_context, "proxied", False)


def is_local_tool(name: str) -> bool:
    """Check if a tool should be handled locally even when redirecting."""
    return name in _LOCAL_TOOL_NAMES


PROXY_HEADER = "X-MCP-Proxied"
OUTPUT_PROXY_CACHE_MAX_SIZE = 100
_output_proxy_targets: OrderedDict[str, tuple[str, int]] = OrderedDict()
_output_proxy_lock = threading.Lock()


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


def get_output_proxy_target(output_id: str) -> tuple[str, int] | None:
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
    enabled = sorted(getattr(MCP_SERVER._enabled_extensions, "data", set()))
    if enabled:
        return f"/mcp?ext={','.join(enabled)}"
    return "/mcp"


def _get_proxy_request_headers() -> dict[str, str]:
    """Build proxy request headers, preserving MCP session identity."""
    headers = {
        "Content-Type": "application/json",
        PROXY_HEADER: "1",
    }
    transport_session_id = MCP_SERVER.get_current_transport_session_id()
    if transport_session_id and transport_session_id.startswith("http:"):
        session_id = transport_session_id.split(":", 1)[1]
        if session_id and session_id != "anonymous":
            headers["Mcp-Session-Id"] = session_id
    external_base_url = get_current_request_external_base_url()
    if external_base_url:
        headers[EXTERNAL_BASE_HEADER] = external_base_url
    return headers


def proxy_to_instance(host: str, port: int, payload: bytes) -> dict:
    """Forward a JSON-RPC request to another IDA instance.

    Sets X-MCP-Proxied header so the target knows this is a forwarded request
    and won't follow its own redirect (preventing A→B→A loops).
    """
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
            raise RuntimeError(f"HTTP {response.status} {response.reason}: {raw_data}")
        parsed = json.loads(raw_data)
        _remember_output_proxy_target_from_response(host, port, parsed)
        return parsed
    finally:
        conn.close()


def proxy_output_to_instance(
    host: str, port: int, path: str
) -> tuple[int, str, list[tuple[str, str]], bytes]:
    """Forward an output download request to another IDA instance."""
    conn = http.client.HTTPConnection(host, port, timeout=30)
    try:
        conn.request("GET", path, headers={PROXY_HEADER: "1"})
        response = conn.getresponse()
        return response.status, response.reason, response.getheaders(), response.read()
    finally:
        conn.close()


# ============================================================================
# Dispatch interception: proxy tools/call and tools/list when redirecting
# ============================================================================

_original_dispatch = MCP_SERVER.registry.dispatch


def _redirecting_dispatch(request):
    """Intercept dispatch to proxy tool calls when redirect is active."""
    redirect = get_redirect_target()
    if redirect is None or is_request_proxied():
        # No redirect, or this request was already proxied here — handle locally
        return _original_dispatch(request)

    # Parse the request
    if not isinstance(request, dict):
        request_obj = json.loads(request)
    else:
        request_obj = request

    method = request_obj.get("method", "")

    # Always handle locally: initialize, notifications, non-tool methods
    if method == "initialize" or method.startswith("notifications/"):
        return _original_dispatch(request)

    # tools/call: proxy unless it's a local tool
    if method == "tools/call":
        params = request_obj.get("params", {})
        tool_name = params.get("name", "")
        if is_local_tool(tool_name):
            return _original_dispatch(request)
        # Proxy to redirect target (with loop detection)
        try:
            payload = (
                json.dumps(request_obj).encode("utf-8")
                if isinstance(request, dict)
                else request
            )
            if isinstance(payload, str):
                payload = payload.encode("utf-8")
            return proxy_to_instance(redirect[0], redirect[1], payload)
        except Exception as e:
            request_id = request_obj.get("id")
            if request_id is None:
                return None
            return {
                "jsonrpc": "2.0",
                "error": {
                    "code": -32000,
                    "message": f"Failed to proxy to {redirect[0]}:{redirect[1]}: {e}",
                },
                "id": request_id,
            }

    # tools/list: merge local discovery tools with redirect target's tools
    if method == "tools/list":
        local_result = _original_dispatch(request)
        try:
            payload = (
                json.dumps(request_obj).encode("utf-8")
                if isinstance(request, dict)
                else request
            )
            if isinstance(payload, str):
                payload = payload.encode("utf-8")
            remote_result = proxy_to_instance(redirect[0], redirect[1], payload)
            if remote_result and "result" in remote_result:
                remote_tools = remote_result["result"].get("tools", [])
                # Filter out remote list_instances/select_instance to avoid duplicates
                remote_tools = [
                    t for t in remote_tools if t.get("name") not in _LOCAL_TOOL_NAMES
                ]
                if local_result and "result" in local_result:
                    local_tools = local_result["result"].get("tools", [])
                    local_result["result"]["tools"] = remote_tools + local_tools
        except Exception:
            pass  # Remote unreachable, show local tools only
        return local_result

    # Everything else (resources/list, etc.): proxy
    try:
        payload = (
            json.dumps(request_obj).encode("utf-8")
            if isinstance(request, dict)
            else request
        )
        if isinstance(payload, str):
            payload = payload.encode("utf-8")
        return proxy_to_instance(redirect[0], redirect[1], payload)
    except Exception:
        return _original_dispatch(request)


MCP_SERVER.registry.dispatch = _redirecting_dispatch


# ============================================================================
# Tools
# ============================================================================


@tool
def list_instances() -> list[InstanceListItem]:
    """List all discovered IDA Pro instances with their binary name, port, and reachability status.

    Use this to see which IDA databases are currently open and available for analysis.
    The 'active' field indicates which instance is currently handling your tool calls.
    """
    instances = discover_instances()
    result = []
    redirect = get_redirect_target()
    for inst in instances:
        reachable = probe_instance(inst["host"], inst["port"])
        if redirect:
            active = inst["host"] == redirect[0] and inst["port"] == redirect[1]
        else:
            active = inst["host"] == _LOCAL_HOST and inst["port"] == _LOCAL_PORT
        result.append({
            **inst,
            "reachable": reachable,
            "active": active,
        })
    return result


@tool
def select_instance(
    port: Annotated[int, "Port number of the IDA instance to connect to"],
    host: Annotated[str, "Host address of the IDA instance"] = "127.0.0.1",
) -> InstanceSelectionResult:
    """Switch to a different IDA Pro instance. All subsequent tool calls will be
    routed to the selected instance. Use list_instances to see available instances.

    To switch back to this instance, call select_instance with this instance's port,
    or call select_instance with port=0 to reset.
    """
    # Reset redirect
    if port == 0:
        _clear_redirect_target()
        return {
            "success": True,
            "message": f"Reset to local instance at {_LOCAL_HOST}:{_LOCAL_PORT}",
        }

    # Selecting the local instance clears redirect
    if host == _LOCAL_HOST and port == _LOCAL_PORT:
        _clear_redirect_target()
        return {"success": True, "host": host, "port": port, "message": "Selected local instance"}

    if not probe_instance(host, port):
        return {"success": False, "error": f"Instance at {host}:{port} is not reachable"}

    _set_redirect_target(host, port)
    return {"success": True, "host": host, "port": port}


