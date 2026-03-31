"""Discovery API - list and switch between IDA instances.

When running in streamable-http mode (client connects directly to IDA),
select_instance makes this IDA instance proxy tool calls to the target.
This lets a single MCP endpoint reach any running IDA instance.
"""

import http.client
import json
import os
import subprocess
import sys
import threading
import time
from typing import Annotated, NotRequired, TypedDict

from .rpc import tool, MCP_SERVER
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


class OpenFileResult(TypedDict, total=False):
    success: bool
    host: str
    port: int
    binary: str
    pid: int
    switched: bool
    message: str
    error: str


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
_LOCAL_TOOL_NAMES = {"list_instances", "select_instance", "open_file"}


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
        return json.loads(raw_data)
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


def _find_existing_idb(file_path: str) -> str | None:
    """Check if an IDB already exists for the given binary.

    IDA creates .idb (32-bit) or .i64 (64-bit) files next to the binary.
    Opening the IDB directly skips the packed/unpacked dialog.
    """
    base = os.path.splitext(file_path)[0]
    # Prefer .i64 (64-bit) over .idb (32-bit)
    for ext in (".i64", ".idb"):
        idb_path = base + ext
        if os.path.isfile(idb_path):
            return idb_path
    return None


@tool
def open_file(
    file_path: Annotated[
        str, "Absolute path to the binary file to open in a new IDA instance"
    ],
    switch: Annotated[
        bool, "Automatically switch to the new instance once it starts"
    ] = True,
    autonomous: Annotated[
        bool, "Run in autonomous mode (-A flag), suppressing all dialogs"
    ] = False,
    new_database: Annotated[
        bool, "Force creating a new database even if one exists"
    ] = False,
    timeout: Annotated[
        int, "Seconds to wait for the new instance to register (0 = don't wait)"
    ] = 30,
) -> OpenFileResult:
    """Open a file in a new IDA Pro instance.

    Launches a new IDA process for the given binary. If an existing IDB/i64 database
    is found, opens that directly (skips the packed/unpacked dialog). Use new_database=True
    to force a fresh analysis. Use autonomous=True to suppress all IDA dialogs.

    If switch=True (default), automatically routes subsequent tool calls to the new instance.
    """
    if not os.path.isfile(file_path):
        return {"success": False, "error": f"File not found: {file_path}"}

    # Get the IDA executable from the currently running instance
    ida_exe = sys.executable
    if not os.path.isfile(ida_exe):
        return {"success": False, "error": f"Cannot find IDA executable: {ida_exe}"}

    # Determine what to open: existing IDB or raw binary
    target = file_path
    if not new_database:
        existing_idb = _find_existing_idb(file_path)
        if existing_idb:
            target = existing_idb

    args = [ida_exe]
    if autonomous:
        args.append("-A")
    if new_database:
        args.append("-c")  # Force new database
    args.append(target)

    # Snapshot current instances before launch
    before = {(i["host"], i["port"]) for i in discover_instances()}

    try:
        subprocess.Popen(
            args,
            creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
            if sys.platform == "win32" else 0,
        )
    except Exception as e:
        return {"success": False, "error": f"Failed to launch IDA: {e}"}

    if timeout == 0:
        return {"success": True, "message": "IDA launched, not waiting for registration"}

    # Poll for the new instance to register
    deadline = time.monotonic() + timeout
    new_instance = None
    while time.monotonic() < deadline:
        time.sleep(1)
        current = discover_instances()
        for inst in current:
            key = (inst["host"], inst["port"])
            if key not in before:
                new_instance = inst
                break
        if new_instance:
            break

    if not new_instance:
        return {
            "success": True,
            "message": (
                f"IDA launched but did not register within {timeout}s. "
                "Use list_instances to check later."
            ),
        }

    result = {
        "success": True,
        "host": new_instance["host"],
        "port": new_instance["port"],
        "binary": new_instance["binary"],
        "pid": new_instance["pid"],
    }

    if switch:
        _set_redirect_target(new_instance["host"], new_instance["port"])
        result["switched"] = True

    return result
