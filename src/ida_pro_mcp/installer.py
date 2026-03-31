import glob
import json
import os
import shutil
import sys
import tempfile
import tomllib
import tomli_w
from urllib.parse import urlparse, urlunparse

try:
    from .installer_data import (
        GLOBAL_SPECIAL_JSON_STRUCTURES,
        PROJECT_LEVEL_CONFIGS,
        PROJECT_SPECIAL_JSON_STRUCTURES,
        get_global_configs,
        get_project_configs,
        resolve_client_name,
    )
    from .installer_tui import interactive_choose, interactive_select
except ImportError:
    from installer_data import (
        GLOBAL_SPECIAL_JSON_STRUCTURES,
        PROJECT_LEVEL_CONFIGS,
        PROJECT_SPECIAL_JSON_STRUCTURES,
        get_global_configs,
        get_project_configs,
        resolve_client_name,
    )
    from installer_tui import interactive_choose, interactive_select

MCP_SERVER_NAME = "ida-pro-mcp"
SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
SERVER_SCRIPT = os.path.join(SCRIPT_DIR, "server.py")
IDA_PLUGIN_PKG = os.path.join(SCRIPT_DIR, "ida_mcp")
IDA_PLUGIN_LOADER = os.path.join(SCRIPT_DIR, "ida_mcp.py")
IDA_HOST = "127.0.0.1"
IDA_PORT = 13337

# NOTE: This is in the global scope on purpose
if not os.path.exists(IDA_PLUGIN_PKG):
    raise RuntimeError(
        f"IDA plugin package not found at {IDA_PLUGIN_PKG} (did you move it?)"
    )
if not os.path.exists(IDA_PLUGIN_LOADER):
    raise RuntimeError(
        f"IDA plugin loader not found at {IDA_PLUGIN_LOADER} (did you move it?)"
    )


def set_ida_rpc(host: str, port: int) -> None:
    global IDA_HOST, IDA_PORT
    IDA_HOST = host
    IDA_PORT = port


def get_python_executable():
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
    # MCP servers are run without inheriting the environment, so we need to forward
    # the environment variables that affect Python's dependency resolution by hand.
    # Issue: https://github.com/mrexodia/ida-pro-mcp/issues/111
    python_vars = [
        "PYTHONHOME",
        "PYTHONPATH",
        "PYTHONSAFEPATH",
        "PYTHONPLATLIBDIR",
        "PYTHONPYCACHEPREFIX",
        "PYTHONNOUSERSITE",
        "PYTHONUSERBASE",
    ]
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
    path = url.path or "/mcp"
    if path == "/":
        path = "/mcp"
    return urlunparse((url.scheme, f"{url.hostname}:{url.port}", path, "", "", ""))


def force_mcp_path(transport_url: str) -> str:
    url = urlparse(transport_url)
    return urlunparse((url.scheme, f"{url.hostname}:{url.port}", "/mcp", "", "", ""))


def infer_http_transport_type(transport_url: str) -> str:
    return "sse" if urlparse(transport_url).path.rstrip("/") == "/sse" else "http"


def generate_mcp_config(*, client_name: str, transport: str = "stdio"):
    if transport == "stdio":
        # No --ida-rpc: server auto-discovers running IDA instances
        if client_name == "Opencode":
            mcp_config = {
                "type": "local",
                "command": [
                    get_python_executable(),
                    SERVER_SCRIPT,
                ],
            }
        else:
            mcp_config = {
                "command": get_python_executable(),
                "args": [
                    SERVER_SCRIPT,
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
    if client_name == "Opencode":
        return {"type": "remote", "url": transport_url}
    if client_name == "Codex":
        return {"url": force_mcp_path(transport_url)}
    if client_name in ("Claude", "Claude Code"):
        return {"type": infer_http_transport_type(transport_url), "url": transport_url}
    return {"type": "http", "url": force_mcp_path(transport_url)}


def print_mcp_config():
    print("[STDIO MCP CONFIGURATION]")
    print(
        json.dumps(
            {
                "mcpServers": {
                    MCP_SERVER_NAME: generate_mcp_config(
                        client_name="Generic", transport="stdio"
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
                    MCP_SERVER_NAME: generate_mcp_config(
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
                    MCP_SERVER_NAME: generate_mcp_config(
                        client_name="Generic",
                        transport=f"http://{IDA_HOST}:{IDA_PORT}/sse",
                    )
                }
            },
            indent=2,
        )
    )


def _get_scope_config_spec(
    *, project: bool, project_dir: str | None = None
) -> tuple[dict[str, tuple[str, str]], dict[str, tuple[str | None, str]]]:
    if project:
        return (
            get_project_configs(project_dir or os.getcwd()),
            PROJECT_SPECIAL_JSON_STRUCTURES,
        )
    return get_global_configs(), GLOBAL_SPECIAL_JSON_STRUCTURES


def _read_config_file(config_path: str, *, is_toml: bool) -> dict | None:
    try:
        if is_toml:
            with open(config_path, "rb") as f:
                data = f.read()
                return tomllib.loads(data.decode("utf-8")) if data else {}
        with open(config_path, "r", encoding="utf-8") as f:
            data = f.read().strip()
            return json.loads(data) if data else {}
    except (json.JSONDecodeError, tomllib.TOMLDecodeError, OSError):
        return None


def _write_config_file(config_path: str, config: dict, *, is_toml: bool) -> None:
    config_dir = os.path.dirname(config_path)
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


def _get_mcp_servers_view(
    config: dict,
    *,
    client_name: str,
    is_toml: bool,
    special_json_structures: dict[str, tuple[str | None, str]],
) -> dict:
    if is_toml:
        return config.setdefault("mcp_servers", {})
    if client_name in special_json_structures:
        top_key, nested_key = special_json_structures[client_name]
        if top_key is None:
            return config.setdefault(nested_key, {})
        return config.setdefault(top_key, {}).setdefault(nested_key, {})
    return config.setdefault("mcpServers", {})


def _resolve_client_targets(
    configs: dict[str, tuple[str, str]], only: list[str] | None
) -> dict[str, tuple[str, str]]:
    if only is None:
        return configs

    available = list(configs.keys())
    filtered: dict[str, tuple[str, str]] = {}
    for target_name in only:
        resolved = resolve_client_name(target_name, available)
        if resolved is None:
            print(
                f"Unknown client: '{target_name}'. Use --list-clients to see available targets."
            )
        elif resolved not in filtered:
            filtered[resolved] = configs[resolved]
    return filtered


def is_client_installed(
    name: str, config_dir: str, config_file: str, *, project: bool = False
) -> bool:
    config_path = os.path.join(config_dir, config_file)
    if not os.path.exists(config_path):
        return False

    is_toml = config_file.endswith(".toml")
    config = _read_config_file(config_path, is_toml=is_toml)
    if config is None:
        return False

    _, special_json_structures = _get_scope_config_spec(project=project)
    mcp_servers = _get_mcp_servers_view(
        config,
        client_name=name,
        is_toml=is_toml,
        special_json_structures=special_json_structures,
    )
    return MCP_SERVER_NAME in mcp_servers


def list_available_clients():
    configs = get_global_configs()
    if not configs:
        print(f"Unsupported platform: {sys.platform}")
        return

    print("Available installation targets:\n")
    print("  MCP Clients:")
    for name, (config_dir, _) in configs.items():
        supports_project = name in PROJECT_LEVEL_CONFIGS
        project_marker = " [supports --project]" if supports_project else ""
        status = "found" if os.path.exists(config_dir) else "not found"
        print(f"    {name:<25} ({status}){project_marker}")

    print()
    print("Usage examples:")
    print("  ida-pro-mcp --install                                    # Interactive selector")
    print("  ida-pro-mcp --install claude,cursor                       # Specific client targets")
    print("  ida-pro-mcp --install vscode --scope project              # Project-level config")
    print("  ida-pro-mcp --install cursor --transport streamable-http  # Streamable HTTP config")
    print("  ida-pro-mcp --uninstall cursor                            # Uninstall specific target")


def install_mcp_servers(
    *,
    transport: str = "stdio",
    uninstall: bool = False,
    quiet: bool = False,
    only: list[str] | None = None,
    project: bool = False,
):
    configs, special_json_structures = _get_scope_config_spec(project=project)
    if not configs:
        print(f"Unsupported platform: {sys.platform}")
        return

    configs = _resolve_client_targets(configs, only)
    if not configs:
        return

    changed = 0
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

        config = {}
        if os.path.exists(config_path):
            config = _read_config_file(config_path, is_toml=is_toml)
            if config is None:
                if not quiet:
                    kind = "TOML" if is_toml else "JSON"
                    action = "uninstall" if uninstall else "installation"
                    print(
                        f"Skipping {name} {action}\n"
                        f"  Config: {config_path} (invalid {kind})"
                    )
                continue

        mcp_servers = _get_mcp_servers_view(
            config,
            client_name=name,
            is_toml=is_toml,
            special_json_structures=special_json_structures,
        )
        old_name = "github.com/mrexodia/ida-pro-mcp"
        if old_name in mcp_servers:
            mcp_servers[MCP_SERVER_NAME] = mcp_servers[old_name]
            del mcp_servers[old_name]

        if uninstall:
            if MCP_SERVER_NAME not in mcp_servers:
                if not quiet:
                    print(
                        f"Skipping {name} uninstall\n  Config: {config_path} (not installed)"
                    )
                continue
            del mcp_servers[MCP_SERVER_NAME]
        else:
            mcp_servers[MCP_SERVER_NAME] = generate_mcp_config(
                client_name=name,
                transport=transport,
            )

        _write_config_file(config_path, config, is_toml=is_toml)
        if not quiet:
            action = "Uninstalled" if uninstall else "Installed"
            print(
                f"{action} {name} MCP server (restart required)\n  Config: {config_path}"
            )
        changed += 1

    if not uninstall and changed == 0:
        print(
            "No MCP servers installed. For unsupported MCP clients, use the following config:\n"
        )
        print_mcp_config()


def _get_ida_user_dir() -> str:
    if sys.platform == "win32":
        return os.path.join(os.environ["APPDATA"], "Hex-Rays", "IDA Pro")
    return os.path.join(os.path.expanduser("~"), ".idapro")


def _remove_path(path: str) -> None:
    if not os.path.lexists(path):
        return
    if os.path.isdir(path) and not os.path.islink(path):
        shutil.rmtree(path)
    else:
        os.remove(path)


def _install_link_or_copy(source: str, destination: str) -> bool:
    existing_realpath = (
        os.path.realpath(destination) if os.path.lexists(destination) else None
    )
    if existing_realpath == source:
        return False

    _remove_path(destination)
    try:
        os.symlink(source, destination)
    except OSError:
        if os.path.isdir(source):
            shutil.copytree(source, destination)
        else:
            shutil.copy(source, destination)
    return True


def is_ida_plugin_installed() -> bool:
    return os.path.lexists(os.path.join(_get_ida_user_dir(), "plugins", "ida_mcp.py"))


def install_ida_plugin(
    *, uninstall: bool = False, quiet: bool = False, allow_ida_free: bool = False
):
    ida_folder = _get_ida_user_dir()
    if not allow_ida_free:
        free_licenses = glob.glob(os.path.join(ida_folder, "idafree_*.hexlic"))
        if free_licenses:
            print(
                "IDA Free does not support plugins and cannot be used. Purchase and install IDA Pro instead."
            )
            sys.exit(1)

    ida_plugin_folder = os.path.join(ida_folder, "plugins")
    loader_destination = os.path.join(ida_plugin_folder, "ida_mcp.py")
    pkg_destination = os.path.join(ida_plugin_folder, "ida_mcp")
    old_plugin = os.path.join(ida_plugin_folder, "mcp-plugin.py")

    if uninstall:
        removed_items: list[str] = []
        for label, path in (
            ("loader", loader_destination),
            ("package", pkg_destination),
            ("old plugin", old_plugin),
        ):
            if os.path.lexists(path):
                _remove_path(path)
                removed_items.append(f"{label}: {path}")

        if not quiet:
            if removed_items:
                print("Uninstalled IDA Pro plugin")
                for item in removed_items:
                    print(f"  {item}")
            else:
                print("Skipping IDA plugin uninstall (not installed)")
        return

    os.makedirs(ida_plugin_folder, exist_ok=True)
    removed_old_plugin = False
    if os.path.lexists(old_plugin):
        _remove_path(old_plugin)
        removed_old_plugin = True

    installed_items: list[str] = []
    if _install_link_or_copy(IDA_PLUGIN_LOADER, loader_destination):
        installed_items.append(f"loader: {loader_destination}")
    if _install_link_or_copy(IDA_PLUGIN_PKG, pkg_destination):
        installed_items.append(f"package: {pkg_destination}")

    if not quiet:
        if installed_items or removed_old_plugin:
            print("Installed IDA Pro plugin (IDA restart required)")
            if removed_old_plugin:
                print(f"  removed old plugin: {old_plugin}")
            for item in installed_items:
                print(f"  {item}")
        else:
            print("Skipping IDA plugin installation (already up to date)")


def _resolve_transport(value: str) -> str:
    v = value.strip().lower()
    if v == "stdio":
        return "stdio"
    if v == "sse":
        return "sse"
    if v in ("http", "streamable-http", "streamable"):
        return "streamable-http"
    return "streamable-http"


def _get_install_transport(*, uninstall: bool, args, interactive: bool) -> str | None:
    if uninstall:
        return "stdio"
    if args.transport is not None:
        return _resolve_transport(args.transport)
    if not interactive:
        return "streamable-http"

    choice = interactive_choose(
        ["Streamable HTTP (recommended)", "stdio", "SSE"],
        "Select transport mode:",
    )
    if choice is None:
        return None
    if choice.startswith("stdio"):
        return "stdio"
    if choice.startswith("Streamable"):
        return "streamable-http"
    return "sse"


def _get_install_scope(args, *, interactive: bool) -> str | None:
    if args.scope:
        return args.scope
    if not interactive:
        return "project"

    choice = interactive_choose(
        ["Project (current directory)", "Global (user-level)"],
        "Select installation scope:",
    )
    if choice is None:
        return None
    if choice.startswith("Project"):
        return "project"
    return "global"


def _get_scope_selection_items(*, project: bool) -> list[tuple[str, bool]]:
    configs, _ = _get_scope_config_spec(project=project)
    return [
        (
            name,
            is_client_installed(name, config_dir, config_file, project=project),
        )
        for name, (config_dir, config_file) in configs.items()
    ]


def _apply_client_install(
    *,
    scope: str,
    transport: str,
    uninstall: bool,
    client_targets: list[str],
) -> None:
    if client_targets:
        install_mcp_servers(
            transport=transport,
            uninstall=uninstall,
            only=client_targets,
            project=(scope == "project"),
        )


def _parse_client_targets(targets_str: str) -> list[str]:
    return [
        target.strip()
        for target in targets_str.split(",")
        if target.strip() and target.strip().lower() != "ida-plugin"
    ]


def _interactive_install(*, uninstall: bool, args):
    action = "uninstall" if uninstall else "install"
    transport = _get_install_transport(uninstall=uninstall, args=args, interactive=True)
    if transport is None:
        print("Cancelled.")
        return

    scope = _get_install_scope(args, interactive=True)
    if scope is None:
        print("Cancelled.")
        return

    items = _get_scope_selection_items(project=(scope == "project"))
    if not items:
        print(f"Unsupported platform: {sys.platform}")
        return

    selected = interactive_select(items, f"Select {scope} targets to {action}:")
    if selected is None:
        print("Cancelled.")
        return

    _apply_client_install(
        scope=scope,
        transport=transport,
        uninstall=uninstall,
        client_targets=selected,
    )


def run_install_command(*, uninstall: bool, targets_str: str, args) -> None:
    install_ida_plugin(uninstall=uninstall, allow_ida_free=args.allow_ida_free)

    if targets_str:
        _apply_client_install(
            scope=_get_install_scope(args, interactive=False),
            transport=_get_install_transport(
                uninstall=uninstall, args=args, interactive=False
            ),
            uninstall=uninstall,
            client_targets=_parse_client_targets(targets_str),
        )
        return

    if sys.stdin.isatty():
        _interactive_install(uninstall=uninstall, args=args)
        return

    action = "installed" if not uninstall else "uninstalled"
    print(
        f"IDA plugin {action}. No TTY available for interactive client selection; "
        "pass explicit client targets to configure MCP clients."
    )
