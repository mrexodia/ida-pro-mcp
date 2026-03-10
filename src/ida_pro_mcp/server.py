import os
import sys
import json
import shutil
import argparse
import http.client
import tempfile
import traceback
import tomllib
import tomli_w
from typing import TYPE_CHECKING
from urllib.parse import urlparse, urlunparse
import glob

if TYPE_CHECKING:
    from ida_pro_mcp.ida_mcp.zeromcp import McpServer
    from ida_pro_mcp.ida_mcp.zeromcp.jsonrpc import JsonRpcResponse, JsonRpcRequest
else:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "ida_mcp"))
    from zeromcp import McpServer
    from zeromcp.jsonrpc import JsonRpcResponse, JsonRpcRequest

    sys.path.pop(0)  # Clean up

IDA_HOST = "127.0.0.1"
IDA_PORT = 13337
IDA_PORT_RANGE = 100  # scan 13337..13436

mcp = McpServer("ida-pro-mcp")
dispatch_original = mcp.registry.dispatch


# ============================================================================
# Multi-Instance Management
# ============================================================================


class IDAInstance:
    """A discovered IDA Pro instance."""

    __slots__ = ("host", "port", "binary_name", "binary_path", "base", "size",
                 "processor", "bits", "analysis_complete")

    def __init__(self, host: str, port: int, metadata: dict | None = None):
        self.host = host
        self.port = port
        md = metadata or {}
        self.binary_name: str = md.get("module", "")
        self.binary_path: str = md.get("path", "")
        self.base: str = md.get("base", "")
        self.size: str = md.get("size", "")
        self.processor: str = md.get("processor", "")
        self.bits: int = md.get("bits", 0)
        self.analysis_complete: bool = md.get("analysis_complete", False)

    def to_dict(self) -> dict:
        d: dict = {
            "port": self.port,
            "binary_name": self.binary_name,
            "analysis_complete": self.analysis_complete,
        }
        if self.binary_path:
            d["binary_path"] = self.binary_path
        if self.processor:
            d["processor"] = self.processor
        if self.bits:
            d["bits"] = self.bits
        if self.base:
            d["base"] = self.base
        if self.size:
            d["size"] = self.size
        return d


def _probe_instance(host: str, port: int, timeout: float = 0.5) -> IDAInstance | None:
    """Try to connect to an IDA MCP plugin and fetch its metadata."""
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        # Use resources/read to fetch IDB metadata
        rpc_request = json.dumps({
            "jsonrpc": "2.0",
            "method": "resources/read",
            "params": {"uri": "ida://idb/metadata"},
            "id": 1,
        })
        conn.request("POST", "/mcp", rpc_request, {"Content-Type": "application/json"})
        resp = conn.getresponse()
        if resp.status != 200:
            return None
        data = json.loads(resp.read().decode())
        # Extract metadata from resources/read response
        result = data.get("result", {})
        contents = result.get("contents", [])
        if contents and "text" in contents[0]:
            metadata = json.loads(contents[0]["text"])
            return IDAInstance(host, port, metadata)
        # Connected but no metadata (maybe no binary loaded yet)
        return IDAInstance(host, port)
    except Exception:
        return None
    finally:
        conn.close()


class InstanceManager:
    """Manages discovery and routing for multiple IDA Pro instances."""

    def __init__(self, host: str, base_port: int, port_range: int):
        self.host = host
        self.base_port = base_port
        self.port_range = port_range
        self.instances: dict[int, IDAInstance] = {}  # port -> instance
        self.active_port: int | None = None

    def discover(self) -> list[IDAInstance]:
        """Scan the port range for active IDA instances."""
        import concurrent.futures

        found: dict[int, IDAInstance] = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
            futures = {
                pool.submit(_probe_instance, self.host, port): port
                for port in range(self.base_port, self.base_port + self.port_range)
            }
            for future in concurrent.futures.as_completed(futures):
                inst = future.result()
                if inst is not None:
                    found[inst.port] = inst

        self.instances = found

        # Auto-select if we have no active or active is gone
        if self.active_port not in self.instances:
            if self.instances:
                self.active_port = min(self.instances.keys())
            else:
                self.active_port = None

        return list(self.instances.values())

    def get_active(self) -> IDAInstance | None:
        if self.active_port is not None and self.active_port in self.instances:
            return self.instances[self.active_port]
        return None

    def switch(self, port: int | None = None, name: str | None = None) -> IDAInstance:
        """Switch active instance by port or binary name substring."""
        if port is not None:
            if port not in self.instances:
                raise ValueError(f"No instance on port {port}. Run list_instances to refresh.")
            self.active_port = port
            return self.instances[port]

        if name is not None:
            name_lower = name.lower()
            matches = [
                inst for inst in self.instances.values()
                if name_lower in inst.binary_name.lower()
                or name_lower in inst.binary_path.lower()
            ]
            if len(matches) == 0:
                available = ", ".join(
                    f"{i.binary_name} (:{i.port})" for i in self.instances.values()
                )
                raise ValueError(
                    f"No instance matching '{name}'. Available: {available}"
                )
            if len(matches) > 1:
                dupes = ", ".join(
                    f"{m.binary_name} (:{m.port})" for m in matches
                )
                raise ValueError(
                    f"Multiple instances match '{name}': {dupes}. Use port number instead."
                )
            self.active_port = matches[0].port
            return matches[0]

        raise ValueError("Provide either port or name")


instance_manager = InstanceManager(IDA_HOST, IDA_PORT, IDA_PORT_RANGE)


# ============================================================================
# MCP Tools for instance management
# ============================================================================


@mcp.tool
def list_instances() -> dict:
    """Discover and list all running IDA Pro instances. Scans the port range for active MCP plugins."""
    found = instance_manager.discover()
    active = instance_manager.active_port
    return {
        "instances": [
            {**inst.to_dict(), "active": inst.port == active}
            for inst in sorted(found, key=lambda i: i.port)
        ],
        "count": len(found),
    }


@mcp.tool
def switch_instance(
    port: int | None = None,
    name: str | None = None,
) -> dict:
    """Switch active IDA instance by port number or binary name substring.

    Provide either port (e.g. 13337) or name (e.g. 'firmware' matches 'firmware_v2.bin').
    """
    # Re-discover first so we have fresh data
    instance_manager.discover()
    inst = instance_manager.switch(port=port, name=name)
    return {"switched_to": inst.to_dict()}


@mcp.tool
def get_active_instance() -> dict:
    """Get info about the currently active IDA instance."""
    inst = instance_manager.get_active()
    if inst is None:
        return {"active": None, "hint": "No active instance. Run list_instances to discover."}
    return {"active": inst.to_dict()}


# ============================================================================
# Dispatch proxy - routes to active IDA instance
# ============================================================================

MCP_INSTRUCTIONS = """This is a multi-instance IDA Pro MCP server. You may be connected to multiple IDA instances simultaneously, each with a different binary loaded.

MULTI-INSTANCE WORKFLOW:
- Use list_instances to discover all running IDA instances and which binary each has open.
- Use switch_instance to change which instance your tool calls are routed to.
- Every tool response includes an [instance: <binary> @ port <N>] tag. ALWAYS check this tag to verify you are querying the correct binary. If the tag shows an unexpected binary, you called the wrong instance -- switch first and retry.
- Before analyzing a different binary, always switch_instance first. Do not assume which instance is active.

EFFECTIVE USE OF IDA:
- IDA has already performed deep analysis of the binary (functions, xrefs, types, strings, decompilation). Use IDA's tools instead of reimplementing analysis with capstone, manual parsing, or brute-force scripts.
- Decompilation, xref queries, string searches, struct analysis, and rename/retype operations are all available as tools -- use them.
- For understanding code, decompile functions rather than reading raw bytes. For finding references, use xref tools rather than scanning memory.
- The string cache is pre-built on plugin start. Use find_regex for fast string searches instead of scanning memory manually.
- Only fall back to raw memory reads or external tools for truly low-level tasks that IDA's analysis cannot cover.
- list_instances reports analysis_complete for each instance. If analysis is still running, results may be incomplete -- wait or re-check later.

WHEN TO ASK THE USER TO LOAD A BINARY:
- If you need to analyze a binary that is not currently open in any IDA instance, ask the user to open it in IDA and start the MCP plugin (Ctrl+Alt+M). Then use list_instances to discover it.
- Do not try to reverse-engineer binaries manually with capstone, struct.unpack, or byte-level parsing when IDA can do it better. Opening the binary in IDA and using MCP tools gives far superior results (full disassembly, decompilation, type recovery, xrefs, string analysis) with less effort.
- For non-trivial analysis tasks, IDA + MCP is almost always the fastest path to high-quality results. Only use manual approaches for quick one-off checks on small data.
"""

# Tools handled locally by the MCP server (not forwarded to IDA plugin)
_LOCAL_TOOLS = {"list_instances", "switch_instance", "get_active_instance"}


def dispatch_proxy(request: dict | str | bytes | bytearray) -> JsonRpcResponse | None:
    """Dispatch JSON-RPC requests, routing to the active IDA instance."""
    if not isinstance(request, dict):
        request_obj: JsonRpcRequest = json.loads(request)
    else:
        request_obj: JsonRpcRequest = request  # type: ignore

    method = request_obj["method"]

    # Protocol methods handled locally
    if method == "initialize":
        response = dispatch_original(request)
        if response and "result" in response:
            response["result"]["instructions"] = MCP_INSTRUCTIONS
        return response
    if method.startswith("notifications/"):
        return dispatch_original(request)

    # tools/list and tools/call for local tools need special handling
    if method == "tools/list":
        # Forward to IDA for its tools, then merge our local tools
        return _dispatch_tools_list(request_obj, request)
    if method == "tools/call":
        tool_name = request_obj.get("params", {}).get("name", "")
        if tool_name in _LOCAL_TOOLS:
            return dispatch_original(request)

    # Everything else goes to the active IDA instance
    active = instance_manager.get_active()
    if active is None:
        # Auto-discover on first use
        instance_manager.discover()
        active = instance_manager.get_active()

    if active is None:
        id = request_obj.get("id")
        if id is None:
            return None
        if sys.platform == "darwin":
            shortcut = "Ctrl+Option+M"
        else:
            shortcut = "Ctrl+Alt+M"
        return JsonRpcResponse(
            {
                "jsonrpc": "2.0",
                "error": {
                    "code": -32000,
                    "message": (
                        "No IDA Pro instances found! "
                        f"Open IDA and run Edit -> Plugins -> MCP ({shortcut}) to start the server, "
                        "then call list_instances to discover it."
                    ),
                },
                "id": id,
            }
        )

    response = _forward_to_ida(active.host, active.port, request_obj, request)

    # Tag tool call responses when multiple instances are active
    if method == "tools/call" and len(instance_manager.instances) > 1 and response and "result" in response:
        result = response["result"]
        content = result.get("content")
        if isinstance(content, list):
            instance_tag = f"[instance: {active.binary_name or 'unknown'} @ port {active.port}]"
            content.insert(0, {"type": "text", "text": instance_tag})

    return response


def _forward_to_ida(
    host: str, port: int, request_obj: dict, raw_request: dict | str | bytes | bytearray
) -> JsonRpcResponse | None:
    """Forward a JSON-RPC request to an IDA instance."""
    conn = http.client.HTTPConnection(host, port, timeout=30)
    try:
        if isinstance(raw_request, dict):
            body = json.dumps(raw_request)
        elif isinstance(raw_request, str):
            body = raw_request.encode("utf-8")
        else:
            body = raw_request
        conn.request("POST", "/mcp", body, {"Content-Type": "application/json"})
        response = conn.getresponse()
        data = response.read().decode()
        return json.loads(data)
    except Exception as e:
        full_info = traceback.format_exc()
        id = request_obj.get("id")
        if id is None:
            return None
        return JsonRpcResponse(
            {
                "jsonrpc": "2.0",
                "error": {
                    "code": -32000,
                    "message": f"Failed to connect to IDA Pro on port {port}: {e}\n{full_info}",
                    "data": str(e),
                },
                "id": id,
            }
        )
    finally:
        conn.close()


def _dispatch_tools_list(request_obj: dict, raw_request) -> JsonRpcResponse | None:
    """Merge local tools into the IDA instance's tools/list response."""
    # Get local tools (list_instances, switch_instance, get_active_instance)
    local_response = dispatch_original(raw_request)
    local_tools = []
    if local_response and "result" in local_response:
        local_tools = local_response["result"].get("tools", [])

    # Try to get IDA instance tools
    active = instance_manager.get_active()
    if active is None:
        instance_manager.discover()
        active = instance_manager.get_active()

    if active is not None:
        ida_response = _forward_to_ida(active.host, active.port, request_obj, raw_request)
        if ida_response and "result" in ida_response:
            ida_tools = ida_response["result"].get("tools", [])
            # Merge: IDA tools + local tools
            merged = ida_tools + local_tools
            ida_response["result"]["tools"] = merged
            return ida_response

    # No IDA instance - return just local tools
    return local_response


mcp.registry.dispatch = dispatch_proxy


SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
IDA_PLUGIN_PKG = os.path.join(SCRIPT_DIR, "ida_mcp")
IDA_PLUGIN_LOADER = os.path.join(SCRIPT_DIR, "ida_mcp.py")

# NOTE: This is in the global scope on purpose
if not os.path.exists(IDA_PLUGIN_PKG):
    raise RuntimeError(
        f"IDA plugin package not found at {IDA_PLUGIN_PKG} (did you move it?)"
    )
if not os.path.exists(IDA_PLUGIN_LOADER):
    raise RuntimeError(
        f"IDA plugin loader not found at {IDA_PLUGIN_LOADER} (did you move it?)"
    )

# Client name aliases: lowercase alias -> exact name in configs dict
CLIENT_ALIASES: dict[str, str] = {
    "vscode": "VS Code",
    "vs-code": "VS Code",
    "vscode-insiders": "VS Code Insiders",
    "vs-code-insiders": "VS Code Insiders",
    "vs2022": "Visual Studio 2022",
    "visual-studio": "Visual Studio 2022",
    "claude-desktop": "Claude",
    "claude-app": "Claude",
    "claude-code": "Claude Code",
    "roo": "Roo Code",
    "roocode": "Roo Code",
    "kilo": "Kilo Code",
    "kilocode": "Kilo Code",
    "gemini": "Gemini CLI",
    "qwen": "Qwen Coder",
    "copilot": "Copilot CLI",
    "amazonq": "Amazon Q",
    "amazon-q": "Amazon Q",
    "lmstudio": "LM Studio",
    "lm-studio": "LM Studio",
    "augment": "Augment Code",
    "qodo": "Qodo Gen",
    "antigravity": "Antigravity IDE",
    "boltai": "BoltAI",
    "bolt": "BoltAI",
}

# Project-level config definitions: name -> (subdirectory, config_file)
# Empty subdirectory means config file is in project root
PROJECT_LEVEL_CONFIGS: dict[str, tuple[str, str]] = {
    "Claude Code": ("", ".mcp.json"),
    "Cursor": (".cursor", "mcp.json"),
    "VS Code": (".vscode", "mcp.json"),
    "VS Code Insiders": (".vscode", "mcp.json"),
    "Windsurf": (".windsurf", "mcp.json"),
    "Zed": (".zed", "settings.json"),
}

# Special JSON structures for project-level configs
# VS Code project-level .vscode/mcp.json uses {"servers": {...}} at top level
PROJECT_SPECIAL_JSON_STRUCTURES: dict[str, tuple[str | None, str]] = {
    "VS Code": (None, "servers"),
    "VS Code Insiders": (None, "servers"),
}


def get_python_executable():
    """Get the path to the Python executable"""
    venv = os.environ.get("VIRTUAL_ENV")
    if venv:
        if sys.platform == "win32":
            python = os.path.join(venv, "Scripts", "python.exe")
        else:
            python = os.path.join(venv, "bin", "python3")
        if os.path.exists(python):
            return python

    for path in sys.path:
        if sys.platform == "win32":
            path = path.replace("/", "\\")

        split = path.split(os.sep)
        if split[-1].endswith(".zip"):
            path = os.path.dirname(path)
            if sys.platform == "win32":
                python_executable = os.path.join(path, "python.exe")
            else:
                python_executable = os.path.join(path, "..", "bin", "python3")
            python_executable = os.path.abspath(python_executable)

            if os.path.exists(python_executable):
                return python_executable
    return sys.executable


def copy_python_env(env: dict[str, str]):
    # Reference: https://docs.python.org/3/using/cmdline.html#environment-variables
    python_vars = [
        "PYTHONHOME",
        "PYTHONPATH",
        "PYTHONSAFEPATH",
        "PYTHONPLATLIBDIR",
        "PYTHONPYCACHEPREFIX",
        "PYTHONNOUSERSITE",
        "PYTHONUSERBASE",
    ]
    # MCP servers are run without inheriting the environment, so we need to forward
    # the environment variables that affect Python's dependency resolution by hand.
    # Issue: https://github.com/mrexodia/ida-pro-mcp/issues/111
    result = False
    for var in python_vars:
        value = os.environ.get(var)
        if value:
            result = True
            env[var] = value
    return result


def normalize_transport_url(transport: str) -> str:
    url = urlparse(transport)
    if url.hostname is None or url.port is None:
        raise Exception(f"Invalid transport URL: {transport}")
    path = url.path
    if path in ("", "/"):
        path = "/mcp"
    return urlunparse((url.scheme, f"{url.hostname}:{url.port}", path, "", "", ""))


def force_mcp_path(transport_url: str) -> str:
    url = urlparse(transport_url)
    return urlunparse((url.scheme, f"{url.hostname}:{url.port}", "/mcp", "", "", ""))


def infer_http_transport_type(transport_url: str) -> str:
    path = urlparse(transport_url).path.rstrip("/")
    if path == "/sse":
        return "sse"
    return "http"


def generate_mcp_config(*, client_name: str, transport: str = "stdio"):
    if transport == "stdio":
        mcp_config = {
            "command": get_python_executable(),
            "args": [
                __file__,
                "--ida-rpc",
                f"http://{IDA_HOST}:{IDA_PORT}",
            ],
        }
        env = {}
        if copy_python_env(env):
            print("[WARNING] Custom Python environment variables detected")
            mcp_config["env"] = env
        return mcp_config

    if transport == "streamable-http":
        transport = f"http://{IDA_HOST}:{IDA_PORT}/mcp"
    elif transport == "sse":
        transport = f"http://{IDA_HOST}:{IDA_PORT}/sse"

    transport_url = normalize_transport_url(transport)

    # Codex uses streamable HTTP URL-only config.
    if client_name == "Codex":
        return {"url": force_mcp_path(transport_url)}

    # Claude/Claude Code support explicit transport type in JSON config.
    if client_name in ("Claude", "Claude Code"):
        return {"type": infer_http_transport_type(transport_url), "url": transport_url}

    # Keep all other clients on streamable HTTP /mcp for compatibility.
    return {"type": "http", "url": force_mcp_path(transport_url)}


def print_mcp_config():
    print("[STDIO MCP CONFIGURATION]")
    print(
        json.dumps(
            {
                "mcpServers": {
                    mcp.name: generate_mcp_config(
                        client_name="Generic",
                        transport="stdio",
                    )
                }
            },
            indent=2,
        )
    )
    print("\n[STREAMABLE HTTP MCP CONFIGURATION]")
    print(
        json.dumps(
            {
                "mcpServers": {
                    mcp.name: generate_mcp_config(
                        client_name="Generic",
                        transport=f"http://{IDA_HOST}:{IDA_PORT}/mcp",
                    )
                }
            },
            indent=2,
        )
    )
    print("\n[SSE MCP CONFIGURATION]")
    print(
        json.dumps(
            {
                "mcpServers": {
                    mcp.name: generate_mcp_config(
                        client_name="Generic",
                        transport=f"http://{IDA_HOST}:{IDA_PORT}/sse",
                    )
                }
            },
            indent=2,
        )
    )


def resolve_client_name(input_name: str, available_clients: list[str]) -> str | None:
    """Resolve user input to an exact client name from available_clients.

    Priority: exact match (case-insensitive) -> alias -> unique substring match.
    """
    lower_input = input_name.strip().lower()

    # Exact match (case-insensitive)
    for client in available_clients:
        if client.lower() == lower_input:
            return client

    # Alias match
    if lower_input in CLIENT_ALIASES:
        alias_target = CLIENT_ALIASES[lower_input]
        if alias_target in available_clients:
            return alias_target

    # Unique substring match
    matches = [c for c in available_clients if lower_input in c.lower()]
    if len(matches) == 1:
        return matches[0]

    return None


# Global special JSON structures for user-level configs
GLOBAL_SPECIAL_JSON_STRUCTURES: dict[str, tuple[str | None, str]] = {
    "VS Code": ("mcp", "servers"),
    "VS Code Insiders": ("mcp", "servers"),
    "Visual Studio 2022": (None, "servers"),  # servers at top level
}


def get_global_configs() -> dict[str, tuple[str, str]]:
    """Return platform-specific global (user-level) MCP client config paths."""
    if sys.platform == "win32":
        return {
            "Cline": (
                os.path.join(
                    os.getenv("APPDATA", ""),
                    "Code",
                    "User",
                    "globalStorage",
                    "saoudrizwan.claude-dev",
                    "settings",
                ),
                "cline_mcp_settings.json",
            ),
            "Roo Code": (
                os.path.join(
                    os.getenv("APPDATA", ""),
                    "Code",
                    "User",
                    "globalStorage",
                    "rooveterinaryinc.roo-cline",
                    "settings",
                ),
                "mcp_settings.json",
            ),
            "Kilo Code": (
                os.path.join(
                    os.getenv("APPDATA", ""),
                    "Code",
                    "User",
                    "globalStorage",
                    "kilocode.kilo-code",
                    "settings",
                ),
                "mcp_settings.json",
            ),
            "Claude": (
                os.path.join(os.getenv("APPDATA", ""), "Claude"),
                "claude_desktop_config.json",
            ),
            "Cursor": (os.path.join(os.path.expanduser("~"), ".cursor"), "mcp.json"),
            "Windsurf": (
                os.path.join(os.path.expanduser("~"), ".codeium", "windsurf"),
                "mcp_config.json",
            ),
            "Claude Code": (os.path.join(os.path.expanduser("~")), ".claude.json"),
            "LM Studio": (
                os.path.join(os.path.expanduser("~"), ".lmstudio"),
                "mcp.json",
            ),
            "Codex": (os.path.join(os.path.expanduser("~"), ".codex"), "config.toml"),
            "Zed": (
                os.path.join(os.getenv("APPDATA", ""), "Zed"),
                "settings.json",
            ),
            "Gemini CLI": (
                os.path.join(os.path.expanduser("~"), ".gemini"),
                "settings.json",
            ),
            "Qwen Coder": (
                os.path.join(os.path.expanduser("~"), ".qwen"),
                "settings.json",
            ),
            "Copilot CLI": (
                os.path.join(os.path.expanduser("~"), ".copilot"),
                "mcp-config.json",
            ),
            "Crush": (
                os.path.join(os.path.expanduser("~")),
                "crush.json",
            ),
            "Augment Code": (
                os.path.join(
                    os.getenv("APPDATA", ""),
                    "Code",
                    "User",
                ),
                "settings.json",
            ),
            "Qodo Gen": (
                os.path.join(
                    os.getenv("APPDATA", ""),
                    "Code",
                    "User",
                ),
                "settings.json",
            ),
            "Antigravity IDE": (
                os.path.join(os.path.expanduser("~"), ".gemini", "antigravity"),
                "mcp_config.json",
            ),
            "Warp": (
                os.path.join(os.path.expanduser("~"), ".warp"),
                "mcp_config.json",
            ),
            "Amazon Q": (
                os.path.join(os.path.expanduser("~"), ".aws", "amazonq"),
                "mcp_config.json",
            ),
            "Opencode": (
                os.path.join(os.path.expanduser("~"), ".opencode"),
                "mcp_config.json",
            ),
            "Kiro": (
                os.path.join(os.path.expanduser("~"), ".kiro"),
                "mcp_config.json",
            ),
            "Trae": (
                os.path.join(os.path.expanduser("~"), ".trae"),
                "mcp_config.json",
            ),
            "VS Code": (
                os.path.join(
                    os.getenv("APPDATA", ""),
                    "Code",
                    "User",
                ),
                "settings.json",
            ),
            "VS Code Insiders": (
                os.path.join(
                    os.getenv("APPDATA", ""),
                    "Code - Insiders",
                    "User",
                ),
                "settings.json",
            ),
        }
    elif sys.platform == "darwin":
        return {
            "Cline": (
                os.path.join(
                    os.path.expanduser("~"),
                    "Library",
                    "Application Support",
                    "Code",
                    "User",
                    "globalStorage",
                    "saoudrizwan.claude-dev",
                    "settings",
                ),
                "cline_mcp_settings.json",
            ),
            "Roo Code": (
                os.path.join(
                    os.path.expanduser("~"),
                    "Library",
                    "Application Support",
                    "Code",
                    "User",
                    "globalStorage",
                    "rooveterinaryinc.roo-cline",
                    "settings",
                ),
                "mcp_settings.json",
            ),
            "Kilo Code": (
                os.path.join(
                    os.path.expanduser("~"),
                    "Library",
                    "Application Support",
                    "Code",
                    "User",
                    "globalStorage",
                    "kilocode.kilo-code",
                    "settings",
                ),
                "mcp_settings.json",
            ),
            "Claude": (
                os.path.join(
                    os.path.expanduser("~"), "Library", "Application Support", "Claude"
                ),
                "claude_desktop_config.json",
            ),
            "Cursor": (os.path.join(os.path.expanduser("~"), ".cursor"), "mcp.json"),
            "Windsurf": (
                os.path.join(os.path.expanduser("~"), ".codeium", "windsurf"),
                "mcp_config.json",
            ),
            "Claude Code": (os.path.join(os.path.expanduser("~")), ".claude.json"),
            "LM Studio": (
                os.path.join(os.path.expanduser("~"), ".lmstudio"),
                "mcp.json",
            ),
            "Codex": (os.path.join(os.path.expanduser("~"), ".codex"), "config.toml"),
            "Antigravity IDE": (
                os.path.join(os.path.expanduser("~"), ".gemini", "antigravity"),
                "mcp_config.json",
            ),
            "Zed": (
                os.path.join(
                    os.path.expanduser("~"), "Library", "Application Support", "Zed"
                ),
                "settings.json",
            ),
            "Gemini CLI": (
                os.path.join(os.path.expanduser("~"), ".gemini"),
                "settings.json",
            ),
            "Qwen Coder": (
                os.path.join(os.path.expanduser("~"), ".qwen"),
                "settings.json",
            ),
            "Copilot CLI": (
                os.path.join(os.path.expanduser("~"), ".copilot"),
                "mcp-config.json",
            ),
            "Crush": (
                os.path.join(os.path.expanduser("~")),
                "crush.json",
            ),
            "Augment Code": (
                os.path.join(
                    os.path.expanduser("~"),
                    "Library",
                    "Application Support",
                    "Code",
                    "User",
                ),
                "settings.json",
            ),
            "Qodo Gen": (
                os.path.join(
                    os.path.expanduser("~"),
                    "Library",
                    "Application Support",
                    "Code",
                    "User",
                ),
                "settings.json",
            ),
            "BoltAI": (
                os.path.join(
                    os.path.expanduser("~"),
                    "Library",
                    "Application Support",
                    "BoltAI",
                ),
                "config.json",
            ),
            "Perplexity": (
                os.path.join(
                    os.path.expanduser("~"),
                    "Library",
                    "Application Support",
                    "Perplexity",
                ),
                "mcp_config.json",
            ),
            "Warp": (
                os.path.join(os.path.expanduser("~"), ".warp"),
                "mcp_config.json",
            ),
            "Amazon Q": (
                os.path.join(os.path.expanduser("~"), ".aws", "amazonq"),
                "mcp_config.json",
            ),
            "Opencode": (
                os.path.join(os.path.expanduser("~"), ".opencode"),
                "mcp_config.json",
            ),
            "Kiro": (
                os.path.join(os.path.expanduser("~"), ".kiro"),
                "mcp_config.json",
            ),
            "Trae": (
                os.path.join(os.path.expanduser("~"), ".trae"),
                "mcp_config.json",
            ),
            "VS Code": (
                os.path.join(
                    os.path.expanduser("~"),
                    "Library",
                    "Application Support",
                    "Code",
                    "User",
                ),
                "settings.json",
            ),
            "VS Code Insiders": (
                os.path.join(
                    os.path.expanduser("~"),
                    "Library",
                    "Application Support",
                    "Code - Insiders",
                    "User",
                ),
                "settings.json",
            ),
        }
    elif sys.platform == "linux":
        return {
            "Cline": (
                os.path.join(
                    os.path.expanduser("~"),
                    ".config",
                    "Code",
                    "User",
                    "globalStorage",
                    "saoudrizwan.claude-dev",
                    "settings",
                ),
                "cline_mcp_settings.json",
            ),
            "Roo Code": (
                os.path.join(
                    os.path.expanduser("~"),
                    ".config",
                    "Code",
                    "User",
                    "globalStorage",
                    "rooveterinaryinc.roo-cline",
                    "settings",
                ),
                "mcp_settings.json",
            ),
            "Kilo Code": (
                os.path.join(
                    os.path.expanduser("~"),
                    ".config",
                    "Code",
                    "User",
                    "globalStorage",
                    "kilocode.kilo-code",
                    "settings",
                ),
                "mcp_settings.json",
            ),
            # Claude not supported on Linux
            "Cursor": (os.path.join(os.path.expanduser("~"), ".cursor"), "mcp.json"),
            "Windsurf": (
                os.path.join(os.path.expanduser("~"), ".codeium", "windsurf"),
                "mcp_config.json",
            ),
            "Claude Code": (os.path.join(os.path.expanduser("~")), ".claude.json"),
            "LM Studio": (
                os.path.join(os.path.expanduser("~"), ".lmstudio"),
                "mcp.json",
            ),
            "Codex": (os.path.join(os.path.expanduser("~"), ".codex"), "config.toml"),
            "Antigravity IDE": (
                os.path.join(os.path.expanduser("~"), ".gemini", "antigravity"),
                "mcp_config.json",
            ),
            "Zed": (
                os.path.join(os.path.expanduser("~"), ".config", "zed"),
                "settings.json",
            ),
            "Gemini CLI": (
                os.path.join(os.path.expanduser("~"), ".gemini"),
                "settings.json",
            ),
            "Qwen Coder": (
                os.path.join(os.path.expanduser("~"), ".qwen"),
                "settings.json",
            ),
            "Copilot CLI": (
                os.path.join(os.path.expanduser("~"), ".copilot"),
                "mcp-config.json",
            ),
            "Crush": (
                os.path.join(os.path.expanduser("~")),
                "crush.json",
            ),
            "Augment Code": (
                os.path.join(
                    os.path.expanduser("~"),
                    ".config",
                    "Code",
                    "User",
                ),
                "settings.json",
            ),
            "Qodo Gen": (
                os.path.join(
                    os.path.expanduser("~"),
                    ".config",
                    "Code",
                    "User",
                ),
                "settings.json",
            ),
            "Warp": (
                os.path.join(os.path.expanduser("~"), ".warp"),
                "mcp_config.json",
            ),
            "Amazon Q": (
                os.path.join(os.path.expanduser("~"), ".aws", "amazonq"),
                "mcp_config.json",
            ),
            "Opencode": (
                os.path.join(os.path.expanduser("~"), ".opencode"),
                "mcp_config.json",
            ),
            "Kiro": (
                os.path.join(os.path.expanduser("~"), ".kiro"),
                "mcp_config.json",
            ),
            "Trae": (
                os.path.join(os.path.expanduser("~"), ".trae"),
                "mcp_config.json",
            ),
            "VS Code": (
                os.path.join(
                    os.path.expanduser("~"),
                    ".config",
                    "Code",
                    "User",
                ),
                "settings.json",
            ),
            "VS Code Insiders": (
                os.path.join(
                    os.path.expanduser("~"),
                    ".config",
                    "Code - Insiders",
                    "User",
                ),
                "settings.json",
            ),
        }
    else:
        return {}


def get_project_configs(project_dir: str) -> dict[str, tuple[str, str]]:
    """Return project-level MCP client config paths for the given directory."""
    result = {}
    for name, (subdir, config_file) in PROJECT_LEVEL_CONFIGS.items():
        if subdir:
            config_dir = os.path.join(project_dir, subdir)
        else:
            config_dir = project_dir
        result[name] = (config_dir, config_file)
    return result


def is_client_installed(
    name: str, config_dir: str, config_file: str, *, project: bool = False
) -> bool:
    """Check if the MCP server is already installed for a given client."""
    config_path = os.path.join(config_dir, config_file)
    if not os.path.exists(config_path):
        return False

    is_toml = config_file.endswith(".toml")
    try:
        if is_toml:
            with open(config_path, "rb") as f:
                data = f.read()
                config = tomllib.loads(data.decode("utf-8")) if data else {}
        else:
            with open(config_path, "r", encoding="utf-8") as f:
                data = f.read().strip()
                config = json.loads(data) if data else {}
    except (json.JSONDecodeError, tomllib.TOMLDecodeError, OSError):
        return False

    special = (
        PROJECT_SPECIAL_JSON_STRUCTURES if project else GLOBAL_SPECIAL_JSON_STRUCTURES
    )
    if is_toml:
        mcp_servers = config.get("mcp_servers", {})
    elif name in special:
        top_key, nested_key = special[name]
        if top_key is None:
            mcp_servers = config.get(nested_key, {})
        else:
            mcp_servers = config.get(top_key, {}).get(nested_key, {})
    else:
        mcp_servers = config.get("mcpServers", {})

    return mcp.name in mcp_servers


def is_ida_plugin_installed() -> bool:
    """Check if the IDA plugin is currently installed."""
    if sys.platform == "win32":
        ida_folder = os.path.join(os.environ["APPDATA"], "Hex-Rays", "IDA Pro")
    else:
        ida_folder = os.path.join(os.path.expanduser("~"), ".idapro")
    loader = os.path.join(ida_folder, "plugins", "ida_mcp.py")
    return os.path.lexists(loader)


def _make_read_key():
    """Create a platform-specific key reader function, or None if not a TTY."""
    if not sys.stdin.isatty():
        return None
    try:
        if sys.platform == "win32":
            import msvcrt

            def read_key():
                ch = msvcrt.getwch()
                if ch in ("\x00", "\xe0"):
                    ch2 = msvcrt.getwch()
                    if ch2 == "H":
                        return "up"
                    elif ch2 == "P":
                        return "down"
                    return None
                elif ch == " ":
                    return "space"
                elif ch == "\r":
                    return "enter"
                elif ch == "\x1b":
                    return "esc"
                elif ch == "a":
                    return "a"
                return None
        else:
            import tty
            import termios

            def read_key():
                fd = sys.stdin.fileno()
                old = termios.tcgetattr(fd)
                try:
                    tty.setraw(fd)
                    ch = sys.stdin.read(1)
                    if ch == "\x1b":
                        ch2 = sys.stdin.read(1)
                        if ch2 == "[":
                            ch3 = sys.stdin.read(1)
                            if ch3 == "A":
                                return "up"
                            elif ch3 == "B":
                                return "down"
                        return "esc"
                    elif ch == " ":
                        return "space"
                    elif ch in ("\r", "\n"):
                        return "enter"
                    elif ch == "a":
                        return "a"
                    elif ch == "\x03":
                        return "esc"
                    return None
                finally:
                    termios.tcsetattr(fd, termios.TCSADRAIN, old)

        return read_key
    except ImportError:
        return None


def _tui_loop(read_key, render, on_key) -> bool:
    """Generic TUI render loop. Returns True if completed, False if cancelled."""
    sys.stdout.write("\033[?25l")  # Hide cursor
    output = render()
    sys.stdout.write(output + "\n")
    sys.stdout.flush()
    # Number of lines to move up = number of visual lines
    total_lines = output.count("\n") + 1

    def clear():
        sys.stdout.write(f"\033[{total_lines}A\033[J")
        sys.stdout.flush()

    try:
        while True:
            key = read_key()
            result = on_key(key)
            if result == "confirm":
                clear()
                return True
            elif result == "cancel":
                clear()
                return False
            elif result == "noop":
                continue

            # Redraw
            clear()
            output = render()
            sys.stdout.write(output + "\n")
            sys.stdout.flush()
            total_lines = output.count("\n") + 1
    finally:
        sys.stdout.write("\033[?25h")  # Restore cursor
        sys.stdout.flush()


def interactive_choose(items: list[str], title: str, default: int = 0) -> str | None:
    """Show an interactive single-choice selector.

    Returns the selected item name, or None if cancelled.
    """
    read_key = _make_read_key()
    if read_key is None:
        return None

    cursor = default

    def render():
        lines = [f"\033[1m{title}\033[0m"]
        lines.append("  (up/down: move, enter: confirm, esc: cancel)")
        lines.append("")
        for i, name in enumerate(items):
            pointer = "\033[36m>\033[0m" if i == cursor else " "
            lines.append(f"  {pointer} {name}")
        return "\n".join(lines)

    def on_key(key):
        nonlocal cursor
        if key == "up":
            cursor = (cursor - 1) % len(items)
        elif key == "down":
            cursor = (cursor + 1) % len(items)
        elif key in ("enter", "space"):
            return "confirm"
        elif key == "esc":
            return "cancel"
        else:
            return "noop"
        return "redraw"

    if _tui_loop(read_key, render, on_key):
        result = items[cursor]
        print(f"\033[1m{title}\033[0m {result}")
        return result
    return None


def interactive_select(items: list[tuple[str, bool]], title: str) -> list[str] | None:
    """Show an interactive checkbox selector.

    Args:
        items: List of (name, pre_checked) tuples.

    Returns:
        List of selected item names, or None if cancelled.
    """
    read_key = _make_read_key()
    if read_key is None:
        return None

    selected = [checked for _, checked in items]
    cursor = 0

    def render():
        lines = [f"\033[1m{title}\033[0m"]
        lines.append("  (space: toggle, a: toggle all, enter: confirm, esc: cancel)")
        lines.append("")
        for i, (name, _) in enumerate(items):
            check = "\033[32m[x]\033[0m" if selected[i] else "[ ]"
            pointer = "\033[36m>\033[0m" if i == cursor else " "
            lines.append(f"  {pointer} {check} {name}")
        return "\n".join(lines)

    def on_key(key):
        nonlocal cursor, selected
        if key == "up":
            cursor = (cursor - 1) % len(items)
        elif key == "down":
            cursor = (cursor + 1) % len(items)
        elif key == "space":
            selected[cursor] = not selected[cursor]
        elif key == "a":
            all_selected = all(selected)
            selected = [not all_selected] * len(items)
        elif key == "enter":
            return "confirm"
        elif key == "esc":
            return "cancel"
        else:
            return "noop"
        return "redraw"

    if _tui_loop(read_key, render, on_key):
        result = [name for (name, _), sel in zip(items, selected) if sel]
        if result:
            print(f"\033[1m{title}\033[0m {', '.join(result)}")
        else:
            print(f"\033[1m{title}\033[0m (none)")
        return result
    return None


def list_available_clients():
    """List all available installation targets."""
    configs = get_global_configs()
    if not configs:
        print(f"Unsupported platform: {sys.platform}")
        return

    print("Available installation targets:\n")
    print(f"  {'ida-plugin':<25} IDA Pro plugin (user-level only)")
    print()
    print("  MCP Clients:")
    for name in configs:
        supports_project = name in PROJECT_LEVEL_CONFIGS
        project_marker = " [supports --project]" if supports_project else ""
        config_dir, config_file = configs[name]
        exists = os.path.exists(config_dir)
        status = "found" if exists else "not found"
        print(f"    {name:<25} ({status}){project_marker}")

    print()
    print("Usage examples:")
    print(
        "  ida-pro-mcp --install                                    # Interactive selector"
    )
    print(
        "  ida-pro-mcp --install claude,cursor,ida-plugin            # Specific targets"
    )
    print(
        "  ida-pro-mcp --install vscode --scope project              # Project-level config"
    )
    print(
        "  ida-pro-mcp --install cursor --transport streamable-http  # Streamable HTTP config"
    )
    print(
        "  ida-pro-mcp --uninstall cursor                            # Uninstall specific target"
    )


def install_mcp_servers(
    *,
    transport: str = "stdio",
    uninstall: bool = False,
    quiet: bool = False,
    only: list[str] | None = None,
    project: bool = False,
):
    # Select config source and special JSON structures based on project flag
    if project:
        configs = get_project_configs(os.getcwd())
        special_json_structures = PROJECT_SPECIAL_JSON_STRUCTURES
    else:
        configs = get_global_configs()
        special_json_structures = GLOBAL_SPECIAL_JSON_STRUCTURES

    if not configs:
        print(f"Unsupported platform: {sys.platform}")
        return

    # Filter configs by --only targets
    if only is not None:
        available = list(configs.keys())
        filtered_configs: dict[str, tuple[str, str]] = {}
        for target_name in only:
            resolved = resolve_client_name(target_name, available)
            if resolved is None:
                print(
                    f"Unknown client: '{target_name}'. Use --list-clients to see available targets."
                )
            elif resolved not in filtered_configs:
                filtered_configs[resolved] = configs[resolved]
        configs = filtered_configs
        if not configs:
            return

    installed = 0
    for name, (config_dir, config_file) in configs.items():
        config_path = os.path.join(config_dir, config_file)
        is_toml = config_file.endswith(".toml")

        if not os.path.exists(config_dir):
            if project and not uninstall:
                os.makedirs(config_dir, exist_ok=True)
            else:
                action = "uninstall" if uninstall else "installation"
                if not quiet:
                    print(
                        f"Skipping {name} {action}\n  Config: {config_path} (not found)"
                    )
                continue

        # Read existing config
        if not os.path.exists(config_path):
            config = {}
        else:
            with open(
                config_path,
                "rb" if is_toml else "r",
                encoding=None if is_toml else "utf-8",
            ) as f:
                if is_toml:
                    data = f.read()
                    if len(data) == 0:
                        config = {}
                    else:
                        try:
                            config = tomllib.loads(data.decode("utf-8"))
                        except tomllib.TOMLDecodeError:
                            if not quiet:
                                print(
                                    f"Skipping {name} uninstall\n  Config: {config_path} (invalid TOML)"
                                )
                            continue
                else:
                    data = f.read().strip()
                    if len(data) == 0:
                        config = {}
                    else:
                        try:
                            config = json.loads(data)
                        except json.decoder.JSONDecodeError:
                            if not quiet:
                                print(
                                    f"Skipping {name} uninstall\n  Config: {config_path} (invalid JSON)"
                                )
                            continue

        # Handle TOML vs JSON structure
        if is_toml:
            if "mcp_servers" not in config:
                config["mcp_servers"] = {}
            mcp_servers = config["mcp_servers"]
        else:
            # Check if this client uses a special JSON structure
            if name in special_json_structures:
                top_key, nested_key = special_json_structures[name]
                if top_key is None:
                    # servers at top level (e.g., Visual Studio 2022)
                    if nested_key not in config:
                        config[nested_key] = {}
                    mcp_servers = config[nested_key]
                else:
                    # nested structure (e.g., VS Code uses mcp.servers)
                    if top_key not in config:
                        config[top_key] = {}
                    if nested_key not in config[top_key]:
                        config[top_key][nested_key] = {}
                    mcp_servers = config[top_key][nested_key]
            else:
                # Default: mcpServers at top level
                if "mcpServers" not in config:
                    config["mcpServers"] = {}
                mcp_servers = config["mcpServers"]

        # Migrate old name
        old_name = "github.com/mrexodia/ida-pro-mcp"
        if old_name in mcp_servers:
            mcp_servers[mcp.name] = mcp_servers[old_name]
            del mcp_servers[old_name]

        if uninstall:
            if mcp.name not in mcp_servers:
                if not quiet:
                    print(
                        f"Skipping {name} uninstall\n  Config: {config_path} (not installed)"
                    )
                continue
            del mcp_servers[mcp.name]
        else:
            mcp_servers[mcp.name] = generate_mcp_config(
                client_name=name,
                transport=transport,
            )

        # Atomic write: temp file + rename
        suffix = ".toml" if is_toml else ".json"
        fd, temp_path = tempfile.mkstemp(
            dir=config_dir, prefix=".tmp_", suffix=suffix, text=True
        )
        try:
            with os.fdopen(
                fd, "wb" if is_toml else "w", encoding=None if is_toml else "utf-8"
            ) as f:
                if is_toml:
                    f.write(tomli_w.dumps(config).encode("utf-8"))
                else:
                    json.dump(config, f, indent=2)
            os.replace(temp_path, config_path)
        except Exception:
            os.unlink(temp_path)
            raise

        if not quiet:
            action = "Uninstalled" if uninstall else "Installed"
            print(
                f"{action} {name} MCP server (restart required)\n  Config: {config_path}"
            )
        installed += 1
    if not uninstall and installed == 0:
        print(
            "No MCP servers installed. For unsupported MCP clients, use the following config:\n"
        )
        print_mcp_config()


def install_ida_plugin(
    *, uninstall: bool = False, quiet: bool = False, allow_ida_free: bool = False
):
    if sys.platform == "win32":
        ida_folder = os.path.join(os.environ["APPDATA"], "Hex-Rays", "IDA Pro")
    else:
        ida_folder = os.path.join(os.path.expanduser("~"), ".idapro")
    if not allow_ida_free:
        free_licenses = glob.glob(os.path.join(ida_folder, "idafree_*.hexlic"))
        if len(free_licenses) > 0:
            print(
                "IDA Free does not support plugins and cannot be used. Purchase and install IDA Pro instead."
            )
            sys.exit(1)
    ida_plugin_folder = os.path.join(ida_folder, "plugins")

    # Install both the loader file and package directory
    loader_source = IDA_PLUGIN_LOADER
    loader_destination = os.path.join(ida_plugin_folder, "ida_mcp.py")

    pkg_source = IDA_PLUGIN_PKG
    pkg_destination = os.path.join(ida_plugin_folder, "ida_mcp")

    # Clean up old plugin if it exists
    old_plugin = os.path.join(ida_plugin_folder, "mcp-plugin.py")

    if uninstall:
        # Remove loader
        if os.path.lexists(loader_destination):
            os.remove(loader_destination)
            if not quiet:
                print(f"Uninstalled IDA plugin loader\n  Path: {loader_destination}")

        # Remove package
        if os.path.exists(pkg_destination):
            if os.path.isdir(pkg_destination) and not os.path.islink(pkg_destination):
                shutil.rmtree(pkg_destination)
            else:
                os.remove(pkg_destination)
            if not quiet:
                print(f"Uninstalled IDA plugin package\n  Path: {pkg_destination}")

        # Remove old plugin if it exists
        if os.path.lexists(old_plugin):
            os.remove(old_plugin)
            if not quiet:
                print(f"Removed old plugin\n  Path: {old_plugin}")
    else:
        # Create IDA plugins folder
        if not os.path.exists(ida_plugin_folder):
            os.makedirs(ida_plugin_folder)

        # Remove old plugin if it exists
        if os.path.lexists(old_plugin):
            os.remove(old_plugin)
            if not quiet:
                print(f"Removed old plugin file\n  Path: {old_plugin}")

        installed_items = []

        # Install loader file
        loader_realpath = (
            os.path.realpath(loader_destination)
            if os.path.lexists(loader_destination)
            else None
        )
        if loader_realpath != loader_source:
            if os.path.lexists(loader_destination):
                os.remove(loader_destination)

            try:
                os.symlink(loader_source, loader_destination)
                installed_items.append(f"loader: {loader_destination}")
            except OSError:
                shutil.copy(loader_source, loader_destination)
                installed_items.append(f"loader: {loader_destination}")

        # Install package directory
        pkg_realpath = (
            os.path.realpath(pkg_destination)
            if os.path.lexists(pkg_destination)
            else None
        )
        if pkg_realpath != pkg_source:
            if os.path.lexists(pkg_destination):
                if os.path.isdir(pkg_destination) and not os.path.islink(
                    pkg_destination
                ):
                    shutil.rmtree(pkg_destination)
                else:
                    os.remove(pkg_destination)

            try:
                os.symlink(pkg_source, pkg_destination)
                installed_items.append(f"package: {pkg_destination}")
            except OSError:
                shutil.copytree(pkg_source, pkg_destination)
                installed_items.append(f"package: {pkg_destination}")

        if not quiet:
            if installed_items:
                print("Installed IDA Pro plugin (IDA restart required)")
                for item in installed_items:
                    print(f"  {item}")
            else:
                print("Skipping IDA plugin installation (already up to date)")


def _resolve_transport(value: str) -> str:
    """Normalize a --transport value to 'stdio', 'streamable-http', or 'sse'."""
    v = value.strip().lower()
    if v == "stdio":
        return "stdio"
    elif v in ("sse",):
        return "sse"
    elif v in ("http", "streamable-http", "streamable"):
        return "streamable-http"
    # URL passed (e.g., http://...) — treat as streamable-http for install config
    return "streamable-http"


def _interactive_install(*, uninstall: bool, args):
    """Full interactive install/uninstall flow with transport and scope selection."""
    action = "uninstall" if uninstall else "install"

    # Step 1: Transport selection (skip for uninstall, or if --transport was explicitly set)
    if not uninstall and args.transport is None:
        choice = interactive_choose(
            ["Streamable HTTP (recommended)", "stdio", "SSE"],
            "Select transport mode:",
        )
        if choice is None:
            print("Cancelled.")
            return
        if choice.startswith("stdio"):
            transport = "stdio"
        elif choice.startswith("Streamable"):
            transport = "streamable-http"
        else:
            transport = "sse"
    elif not uninstall:
        transport = _resolve_transport(args.transport or "streamable-http")
    else:
        transport = "stdio"  # doesn't matter for uninstall

    # Step 2: Scope selection (skip if --scope was explicitly set)
    if args.scope:
        scope_value = args.scope
    else:
        scope = interactive_choose(
            ["Project (current directory)", "Global (user-level)"],
            "Select installation scope:",
        )
        if scope is None:
            print("Cancelled.")
            return
        if scope.startswith("Project"):
            scope_value = "project"
        else:
            scope_value = "global"

    do_global = scope_value == "global"
    do_project = scope_value == "project"

    # Step 3: Target selection per scope
    if do_global:
        global_configs = get_global_configs()
        if global_configs:
            items: list[tuple[str, bool]] = []
            items.append(("IDA Plugin", is_ida_plugin_installed()))
            for name, (config_dir, config_file) in global_configs.items():
                installed = is_client_installed(name, config_dir, config_file)
                items.append((name, installed))

            selected = interactive_select(items, f"Select global targets to {action}:")
            if selected is None:
                print("Cancelled.")
                return

            if "IDA Plugin" in selected:
                install_ida_plugin(
                    uninstall=uninstall, allow_ida_free=args.allow_ida_free
                )
            client_names = [s for s in selected if s != "IDA Plugin"]
            if client_names:
                install_mcp_servers(
                    transport=transport,
                    uninstall=uninstall,
                    only=client_names,
                )
        else:
            print(f"Unsupported platform: {sys.platform}")

    if do_project:
        project_configs = get_project_configs(os.getcwd())
        if project_configs:
            items = []
            for name, (config_dir, config_file) in project_configs.items():
                installed = is_client_installed(
                    name, config_dir, config_file, project=True
                )
                items.append((name, installed))

            selected = interactive_select(items, f"Select project targets to {action}:")
            if selected is None:
                print("Cancelled.")
                return

            if selected:
                install_mcp_servers(
                    transport=transport,
                    uninstall=uninstall,
                    only=selected,
                    project=True,
                )


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
        "Optionally specify comma-separated targets (e.g., 'ida-plugin,claude,cursor'). "
        "Without targets, an interactive selector is shown.",
    )
    parser.add_argument(
        "--uninstall",
        nargs="?",
        const="",
        default=None,
        metavar="TARGETS",
        help="Uninstall the MCP Server and IDA plugin. "
        "Optionally specify comma-separated targets. "
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
        default=f"http://{IDA_HOST}:{IDA_PORT}",
        help=f"IDA RPC server to use (default: http://{IDA_HOST}:{IDA_PORT})",
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

    # Parse IDA RPC server argument
    ida_rpc = urlparse(args.ida_rpc)
    if ida_rpc.hostname is None or ida_rpc.port is None:
        raise Exception(f"Invalid IDA RPC server: {args.ida_rpc}")
    IDA_HOST = ida_rpc.hostname
    IDA_PORT = ida_rpc.port

    # Update instance manager with CLI-provided host/port
    instance_manager.host = IDA_HOST
    instance_manager.base_port = IDA_PORT

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
        targets_str = args.install if is_install else args.uninstall
        uninstall = is_uninstall

        if targets_str:
            # Explicit targets: --install claude,cursor,ida-plugin
            # Use CLI flags for transport/scope (no interactive prompts)
            transport = _resolve_transport(args.transport or "streamable-http")
            scope = args.scope or "project"

            targets = [t.strip() for t in targets_str.split(",") if t.strip()]
            install_ida = False
            client_targets = []
            for target in targets:
                if target.lower() == "ida-plugin":
                    install_ida = True
                else:
                    client_targets.append(target)

            if install_ida:
                install_ida_plugin(
                    uninstall=uninstall, allow_ida_free=args.allow_ida_free
                )
            if client_targets:
                do_global = scope == "global"
                do_project = scope == "project"
                if do_global:
                    install_mcp_servers(
                        transport=transport,
                        uninstall=uninstall,
                        only=client_targets,
                    )
                if do_project:
                    install_mcp_servers(
                        transport=transport,
                        uninstall=uninstall,
                        only=client_targets,
                        project=True,
                    )
        else:
            # No targets: full interactive flow
            _interactive_install(uninstall=uninstall, args=args)
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
