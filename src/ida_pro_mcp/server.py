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
from urllib.parse import urlparse
import glob

# Terminal raw mode support (Unix only)
if sys.platform != "win32":
    import tty
    import termios
else:
    import msvcrt

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

    conn = http.client.HTTPConnection(IDA_HOST, IDA_PORT, timeout=30)
    try:
        if isinstance(request, dict):
            request = json.dumps(request)
        elif isinstance(request, str):
            request = request.encode("utf-8")
        conn.request("POST", "/mcp", request, {"Content-Type": "application/json"})
        response = conn.getresponse()
        data = response.read().decode()
        return json.loads(data)
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
                    "message": f"Failed to connect to IDA Pro! Did you run Edit -> Plugins -> MCP ({shortcut}) to start the server?\n{full_info}",
                    "data": str(e),
                },
                "id": id,
            }
        )
    finally:
        conn.close()


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


def generate_mcp_config(*, stdio: bool):
    if stdio:
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
    else:
        return {"type": "http", "url": f"http://{IDA_HOST}:{IDA_PORT}/mcp"}


def print_mcp_config():
    print("[HTTP MCP CONFIGURATION]")
    print(
        json.dumps(
            {"mcpServers": {mcp.name: generate_mcp_config(stdio=False)}}, indent=2
        )
    )
    print("\n[STDIO MCP CONFIGURATION]")
    print(
        json.dumps(
            {"mcpServers": {mcp.name: generate_mcp_config(stdio=True)}}, indent=2
        )
    )


# Map client names to their JSON key paths for clients that don't use "mcpServers"
# Format: client_name -> (top_level_key, nested_key)
# None means use default "mcpServers" at top level
SPECIAL_JSON_STRUCTURES = {
    "VS Code": ("mcp", "servers"),
    "Visual Studio 2022": (None, "servers"),  # servers at top level
}


def get_mcp_client_configs() -> dict[str, tuple[str, str]]:
    """Get the MCP client configurations for the current platform.
    
    Returns a dict mapping client name to (config_dir, config_file).
    """
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
        }
    else:
        return {}


def read_config_file(config_path: str, is_toml: bool) -> dict | None:
    """Read a config file (JSON or TOML). Returns None if invalid."""
    if not os.path.exists(config_path):
        return {}
    
    with open(
        config_path,
        "rb" if is_toml else "r",
        encoding=None if is_toml else "utf-8",
    ) as f:
        if is_toml:
            data = f.read()
            if len(data) == 0:
                return {}
            try:
                return tomllib.loads(data.decode("utf-8"))
            except tomllib.TOMLDecodeError:
                return None
        else:
            data = f.read().strip()
            if len(data) == 0:
                return {}
            try:
                return json.loads(data)
            except json.decoder.JSONDecodeError:
                return None


def get_mcp_servers_dict(config: dict, client_name: str, is_toml: bool) -> dict:
    """Get the mcp_servers dict from a config, creating nested structure if needed."""
    if is_toml:
        if "mcp_servers" not in config:
            config["mcp_servers"] = {}
        return config["mcp_servers"]
    
    # Check if this client uses a special JSON structure
    if client_name in SPECIAL_JSON_STRUCTURES:
        top_key, nested_key = SPECIAL_JSON_STRUCTURES[client_name]
        if top_key is None:
            # servers at top level (e.g., Visual Studio 2022)
            if nested_key not in config:
                config[nested_key] = {}
            return config[nested_key]
        else:
            # nested structure (e.g., VS Code uses mcp.servers)
            if top_key not in config:
                config[top_key] = {}
            if nested_key not in config[top_key]:
                config[top_key][nested_key] = {}
            return config[top_key][nested_key]
    else:
        # Default: mcpServers at top level
        if "mcpServers" not in config:
            config["mcpServers"] = {}
        return config["mcpServers"]


def check_client_status(name: str, config_dir: str, config_file: str) -> tuple[bool, bool]:
    """Check if a client is available and if the MCP server is installed.
    
    Returns (available, installed).
    """
    config_path = os.path.join(config_dir, config_file)
    is_toml = config_file.endswith(".toml")
    
    # Check if client is available (config dir exists)
    if not os.path.exists(config_dir):
        return False, False
    
    # Read config file
    config = read_config_file(config_path, is_toml)
    if config is None:
        return True, False  # Available but invalid config
    
    # Get mcp_servers dict
    mcp_servers = get_mcp_servers_dict(config, name, is_toml)
    
    # Check for old name migration
    old_name = "github.com/mrexodia/ida-pro-mcp"
    installed = mcp.name in mcp_servers or old_name in mcp_servers
    
    return True, installed


def get_available_clients() -> list[tuple[str, bool]]:
    """Get list of available MCP clients and their installation status.
    
    Returns list of (client_name, is_installed).
    """
    configs = get_mcp_client_configs()
    result = []
    
    for name, (config_dir, config_file) in configs.items():
        available, installed = check_client_status(name, config_dir, config_file)
        if available:
            result.append((name, installed))
    
    return result


def is_interactive_terminal() -> bool:
    """Check if we're running in an interactive terminal."""
    return sys.stdin.isatty() and sys.stdout.isatty()


def getch() -> str:
    """Read a single character from stdin without echoing."""
    if sys.platform == "win32":
        ch = msvcrt.getwch()
        # Handle special keys on Windows
        if ch in ('\x00', '\xe0'):  # Special key prefix
            ch2 = msvcrt.getwch()
            if ch2 == 'H':  # Up arrow
                return '\x1b[A'
            elif ch2 == 'P':  # Down arrow
                return '\x1b[B'
        return ch
    else:
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            ch = sys.stdin.read(1)
            # Handle escape sequences (arrow keys)
            if ch == '\x1b':
                ch += sys.stdin.read(2)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        return ch


def interactive_checkbox_selection(
    items: list[tuple[str, bool]], 
    title: str = "Select items"
) -> list[str] | None:
    """Display an interactive checkbox selection UI.
    
    Args:
        items: List of (item_name, initially_checked) tuples
        title: Title to display above the list
        
    Returns:
        List of selected item names, or None if cancelled (Ctrl+C/Escape)
    """
    if not items:
        return []
    
    selected = [checked for _, checked in items]
    cursor = 0
    
    def render():
        # Clear screen and move cursor to top
        sys.stdout.write("\033[2J\033[H")
        print(f"{title}\n")
        print("Use ↑/↓ to navigate, Space to toggle, Enter to confirm, Ctrl+C to cancel\n")
        
        for i, (name, _) in enumerate(items):
            checkbox = "[x]" if selected[i] else "[ ]"
            prefix = ">" if i == cursor else " "
            print(f" {prefix} {checkbox} {name}")
        
        print()
        sys.stdout.flush()
    
    render()
    
    while True:
        try:
            ch = getch()
            
            if ch == '\x03':  # Ctrl+C
                return None
            elif ch == '\x1b':  # Escape (single escape, not part of sequence)
                return None
            elif ch == '\x1b[A':  # Up arrow
                cursor = (cursor - 1) % len(items)
            elif ch == '\x1b[B':  # Down arrow
                cursor = (cursor + 1) % len(items)
            elif ch == ' ':  # Space - toggle
                selected[cursor] = not selected[cursor]
            elif ch in ('\r', '\n'):  # Enter - confirm
                return [name for (name, _), sel in zip(items, selected) if sel]
            elif ch == 'k':  # vim-style up
                cursor = (cursor - 1) % len(items)
            elif ch == 'j':  # vim-style down
                cursor = (cursor + 1) % len(items)
            
            render()
        except (KeyboardInterrupt, EOFError):
            return None


def interactive_option_selection(
    options: list[str],
    title: str = "Select an option",
    default: int = 0
) -> str | None:
    """Display an interactive single-choice selection UI.
    
    Args:
        options: List of option strings
        title: Title to display above the list
        default: Index of default selected option
        
    Returns:
        Selected option string, or None if cancelled (Ctrl+C/Escape)
    """
    if not options:
        return None
    
    cursor = default
    
    def render():
        # Clear screen and move cursor to top
        sys.stdout.write("\033[2J\033[H")
        print(f"{title}\n")
        print("Use ↑/↓ to navigate, Enter to confirm, Ctrl+C to cancel\n")
        
        for i, option in enumerate(options):
            prefix = ">" if i == cursor else " "
            print(f" {prefix} {option}")
        
        print()
        sys.stdout.flush()
    
    render()
    
    while True:
        try:
            ch = getch()
            
            if ch == '\x03':  # Ctrl+C
                return None
            elif ch == '\x1b':  # Escape (single escape, not part of sequence)
                return None
            elif ch == '\x1b[A':  # Up arrow
                cursor = (cursor - 1) % len(options)
            elif ch == '\x1b[B':  # Down arrow
                cursor = (cursor + 1) % len(options)
            elif ch in ('\r', '\n'):  # Enter - confirm
                return options[cursor]
            elif ch == 'k':  # vim-style up
                cursor = (cursor - 1) % len(options)
            elif ch == 'j':  # vim-style down
                cursor = (cursor + 1) % len(options)
            
            render()
        except (KeyboardInterrupt, EOFError):
            return None


def install_local_mcp_config(
    *,
    stdio: bool = False,
    uninstall: bool = False,
    quiet: bool = False,
    directory: str | None = None
):
    """Install or uninstall MCP server configuration locally in a project directory.
    
    Creates/updates .mcp.json in the specified directory (or current directory).
    
    Args:
        stdio: Use stdio transport (vs HTTP)
        uninstall: Uninstall instead of install
        quiet: Suppress output
        directory: Directory to install in (default: current working directory)
    """
    if directory is None:
        directory = os.getcwd()
    
    config_path = os.path.join(directory, ".mcp.json")
    
    # Read existing config
    config = read_config_file(config_path, is_toml=False)
    if config is None:
        if not quiet:
            print(f"Skipping local installation\n  Config: {config_path} (invalid JSON)")
        return
    
    # Get mcp_servers dict (local configs use standard mcpServers)
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
                print(f"Skipping local uninstall\n  Config: {config_path} (not installed)")
            return
        del mcp_servers[mcp.name]
        
        # Remove file if empty
        if not mcp_servers:
            if os.path.exists(config_path):
                os.remove(config_path)
                if not quiet:
                    print(f"Removed local MCP config\n  Config: {config_path}")
            return
    else:
        mcp_servers[mcp.name] = generate_mcp_config(stdio=stdio)
    
    # Atomic write: temp file + rename
    fd, temp_path = tempfile.mkstemp(
        dir=directory, prefix=".tmp_", suffix=".json", text=True
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)
        os.replace(temp_path, config_path)
    except:
        os.unlink(temp_path)
        raise
    
    if not quiet:
        action = "Uninstalled" if uninstall else "Installed"
        print(f"{action} local MCP server config\n  Config: {config_path}")


def install_mcp_servers(
    *, 
    stdio: bool = False, 
    uninstall: bool = False, 
    quiet: bool = False,
    clients: list[str] | None = None
):
    """Install or uninstall MCP server configuration for MCP clients.
    
    Args:
        stdio: Use stdio transport (vs HTTP)
        uninstall: Uninstall instead of install
        quiet: Suppress output
        clients: List of specific client names to install/uninstall (None = all available)
    """
    configs = get_mcp_client_configs()
    if not configs:
        print(f"Unsupported platform: {sys.platform}")
        return

    # Normalize client filter to lowercase for case-insensitive matching
    client_filter = None
    if clients is not None:
        client_filter = {c.lower() for c in clients}

    installed = 0
    for name, (config_dir, config_file) in configs.items():
        # Filter by client names if specified
        if client_filter is not None and name.lower() not in client_filter:
            continue

        config_path = os.path.join(config_dir, config_file)
        is_toml = config_file.endswith(".toml")

        if not os.path.exists(config_dir):
            action = "uninstall" if uninstall else "installation"
            if not quiet:
                print(f"Skipping {name} {action}\n  Config: {config_path} (not found)")
            continue

        # Read existing config
        config = read_config_file(config_path, is_toml)
        if config is None:
            if not quiet:
                file_type = "TOML" if is_toml else "JSON"
                print(f"Skipping {name}\n  Config: {config_path} (invalid {file_type})")
            continue

        # Get mcp_servers dict
        mcp_servers = get_mcp_servers_dict(config, name, is_toml)

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
            mcp_servers[mcp.name] = generate_mcp_config(stdio=stdio)

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
        except:
            os.unlink(temp_path)
            raise

        if not quiet:
            action = "Uninstalled" if uninstall else "Installed"
            print(
                f"{action} {name} MCP server (restart required)\n  Config: {config_path}"
            )
        installed += 1
    
    if not uninstall and installed == 0:
        if client_filter:
            print(f"No matching MCP clients found for: {', '.join(clients or [])}")
        else:
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


def run_interactive_installer(*, uninstall: bool = False, stdio: bool = True):
    """Run the interactive installer with checkbox selection.
    
    Note: IDA plugin should be installed/uninstalled by caller before this.
    
    Args:
        uninstall: If True, uninstall selected clients instead of installing
        stdio: Use stdio transport (vs HTTP)
    """
    # Ask about installation scope (global vs local)
    scope_title = "Select installation scope:"
    scope_options = [
        "Global (user-wide, applies to all projects)",
        "Local (current directory only, creates .mcp.json)",
    ]
    scope = interactive_option_selection(scope_options, scope_title)
    
    if scope is None:
        print("\nInstallation cancelled.")
        return
    
    is_local = scope.startswith("Local")
    
    if is_local:
        # Local installation - just create .mcp.json in current directory
        sys.stdout.write("\033[2J\033[H")
        install_local_mcp_config(stdio=stdio, uninstall=uninstall)
        return
    
    # Global installation - show client selection
    available_clients = get_available_clients()
    
    if not available_clients:
        sys.stdout.write("\033[2J\033[H")
        print("No MCP clients detected on this system.")
        print("For manual configuration, use the following config:\n")
        print_mcp_config()
        return
    
    # For interactive selection, pre-check clients that are already installed
    title = "Select MCP clients to uninstall:" if uninstall else "Select MCP clients to install:"
    selected = interactive_checkbox_selection(available_clients, title)
    
    if selected is None:
        # User cancelled
        print("\nInstallation cancelled.")
        return
    
    if not selected:
        print("\nNo clients selected.")
        return
    
    # Clear screen and show results
    sys.stdout.write("\033[2J\033[H")
    
    # Install/uninstall selected clients
    install_mcp_servers(
        stdio=stdio,
        uninstall=uninstall,
        clients=selected
    )


def main():
    global IDA_HOST, IDA_PORT
    parser = argparse.ArgumentParser(description="IDA Pro MCP Server")
    parser.add_argument(
        "--install",
        nargs="*",
        metavar="CLIENT",
        help="Install the MCP Server and IDA plugin. Optionally specify client names (e.g., 'claude-code', 'cursor'). "
             "Without arguments: interactive mode if terminal, IDA plugin only otherwise.",
    )
    parser.add_argument(
        "--uninstall",
        nargs="*",
        metavar="CLIENT",
        help="Uninstall the MCP Server and IDA plugin. Optionally specify client names. "
             "Without arguments: interactive mode if terminal, IDA plugin only otherwise.",
    )
    parser.add_argument(
        "--local",
        action="store_true",
        help="Install/uninstall to local .mcp.json in current directory instead of global config",
    )
    parser.add_argument(
        "--allow-ida-free",
        action="store_true",
        help="Allow installation despite IDA Free being installed",
    )
    parser.add_argument(
        "--transport",
        type=str,
        default="stdio",
        help="MCP transport protocol to use (stdio or http://127.0.0.1:8744)",
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
    args = parser.parse_args()

    # Parse IDA RPC server argument
    ida_rpc = urlparse(args.ida_rpc)
    if ida_rpc.hostname is None or ida_rpc.port is None:
        raise Exception(f"Invalid IDA RPC server: {args.ida_rpc}")
    IDA_HOST = ida_rpc.hostname
    IDA_PORT = ida_rpc.port

    if args.install is not None and args.uninstall is not None:
        print("Cannot install and uninstall at the same time")
        return

    stdio = args.transport == "stdio"

    if args.install is not None:
        # Always install IDA plugin first
        install_ida_plugin(allow_ida_free=args.allow_ida_free)
        
        if args.local:
            # Local installation to .mcp.json
            install_local_mcp_config(stdio=stdio)
        elif len(args.install) > 0:
            # Specific clients specified: install those clients globally
            install_mcp_servers(stdio=stdio, clients=args.install)
        elif is_interactive_terminal():
            # No clients specified, interactive terminal: show interactive UI
            run_interactive_installer(
                uninstall=False,
                stdio=stdio
            )
        # else: non-interactive without clients - IDA plugin already installed above
        return

    if args.uninstall is not None:
        # Always uninstall IDA plugin first
        install_ida_plugin(uninstall=True, allow_ida_free=args.allow_ida_free)
        
        if args.local:
            # Local uninstallation from .mcp.json
            install_local_mcp_config(uninstall=True)
        elif len(args.uninstall) > 0:
            # Specific clients specified: uninstall those clients globally
            install_mcp_servers(uninstall=True, clients=args.uninstall)
        elif is_interactive_terminal():
            # No clients specified, interactive terminal: show interactive UI
            run_interactive_installer(
                uninstall=True,
                stdio=stdio
            )
        # else: non-interactive without clients - IDA plugin already uninstalled above
        return

    if args.config:
        print_mcp_config()
        return

    try:
        if args.transport == "stdio":
            mcp.stdio()
        else:
            url = urlparse(args.transport)
            if url.hostname is None or url.port is None:
                raise Exception(f"Invalid transport URL: {args.transport}")
            # NOTE: npx -y @modelcontextprotocol/inspector for debugging
            mcp.serve(url.hostname, url.port)
            input("Server is running, press Enter or Ctrl+C to stop.")
    except (KeyboardInterrupt, EOFError):
        pass


if __name__ == "__main__":
    main()
