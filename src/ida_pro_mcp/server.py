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

mcp = McpServer("ida-pro-mcp")
dispatch_original = mcp.registry.dispatch


def dispatch_proxy(request: dict | str | bytes | bytearray) -> JsonRpcResponse | None:
    """Dispatch JSON-RPC requests to the MCP server registry"""
    if not isinstance(request, dict):
        request_obj: JsonRpcRequest = json.loads(request)
    else:
        request_obj: JsonRpcRequest = request  # type: ignore

    if request_obj["method"] == "initialize":
        return dispatch_original(request)
    elif request_obj["method"].startswith("notifications/"):
        return dispatch_original(request)

    payload: bytes | str | dict = request
    if isinstance(payload, dict):
        payload = json.dumps(payload)
    elif isinstance(payload, str):
        payload = payload.encode("utf-8")

    try:
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
    except Exception as e:
        full_info = traceback.format_exc()
        id = request_obj.get("id")
        if id is None:
            return None  # Notification, no response needed

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
                        "Failed to complete request to IDA Pro. "
                        f"Did you run Edit -> Plugins -> MCP ({shortcut}) to start the server?\n"
                        "The request was not retried automatically. "
                        "If this was a mutating operation, verify IDA state before retrying.\n"
                        f"{full_info}"
                    ),
                    "data": str(e),
                },
                "id": id,
            }
        )


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
    "Opencode": (".config/opencode", "opencode.json"),
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
        if client_name == "Opencode":
            mcp_config = {
                "type": "local",
                "command": [
                    get_python_executable(),
                    __file__,
                    "--ida-rpc",
                    f"http://{IDA_HOST}:{IDA_PORT}",
                ],
            }
        else:
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
    if client_name in ("Claude", "Claude Code", "Opencode"):
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
    "Opencode": (None, "mcp"),  # mcp at top level
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
                os.path.join(os.path.expanduser("~"), ".config", "opencode"),
                "opencode.json",
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
                os.path.join(os.path.expanduser("~"), ".config", "opencode"),
                "opencode.json",
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
                os.path.join(os.path.expanduser("~"), ".config", "opencode"),
                "opencode.json",
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
        "  ida-pro-mcp --install claude,cursor                       # Specific client targets"
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
            for name, (config_dir, config_file) in global_configs.items():
                installed = is_client_installed(name, config_dir, config_file)
                items.append((name, installed))

            selected = interactive_select(items, f"Select global targets to {action}:")
            if selected is None:
                print("Cancelled.")
                return

            if selected:
                install_mcp_servers(
                    transport=transport,
                    uninstall=uninstall,
                    only=selected,
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

        install_ida_plugin(
            uninstall=uninstall, allow_ida_free=args.allow_ida_free
        )

        if targets_str:
            # Explicit targets: --install claude,cursor
            # Use CLI flags for transport/scope (no interactive prompts)
            transport = _resolve_transport(args.transport or "streamable-http")
            scope = args.scope or "project"

            client_targets = [
                t.strip()
                for t in targets_str.split(",")
                if t.strip() and t.strip().lower() != "ida-plugin"
            ]
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
            # No targets: interactive client selection when a TTY is available.
            if sys.stdin.isatty():
                _interactive_install(uninstall=uninstall, args=args)
            else:
                action = "installed" if is_install else "uninstalled"
                print(
                    f"IDA plugin {action}. No TTY available for interactive client selection; "
                    "pass explicit client targets to configure MCP clients."
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
