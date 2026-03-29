"""IDA Pro MCP Plugin Loader

This file serves as the entry point for IDA Pro's plugin system.
It loads the actual implementation from the ida_mcp package.
"""

import sys
import idaapi
import ida_kernwin
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from . import ida_mcp

# Import config helpers (same netnode system you already use for "unrestricted")
from ida_mcp.http import config_json_get, config_json_set


def unload_package(package_name: str):
    """Remove every module that belongs to the package from sys.modules."""
    to_remove = [
        mod_name
        for mod_name in sys.modules
        if mod_name == package_name or mod_name.startswith(package_name + ".")
    ]
    for mod_name in to_remove:
        del sys.modules[mod_name]


CONFIG_ACTION_ID = "mcp:configure"
CONFIG_ACTION_LABEL = "MCP Configuration"


class MCPConfigForm(idaapi.Form):
    """Form to configure MCP server host and port."""

    def __init__(self, host: str, port: int):
        form_str = r"""STARTITEM 0
MCP Server Configuration

<Host:{host}>
<Port:{port}>
"""
        super().__init__(
            form_str,
            {
                "host": idaapi.Form.StringInput(value=host),
                "port": idaapi.Form.NumericInput(value=port, tp=idaapi.Form.FT_DEC),
            },
        )


class MCPConfigHandler(idaapi.action_handler_t):
    def __init__(self, plugin: "MCP"):
        idaapi.action_handler_t.__init__(self)
        self.plugin = plugin

    def activate(self, ctx):
        old_host = self.plugin.host
        old_port = self.plugin.port

        form = MCPConfigForm(self.plugin.host, self.plugin.port)
        form.Compile()
        ok = form.Execute()
        if ok != 1:
            form.Free()
            return 0

        host = form.host.value
        port = form.port.value
        form.Free()

        if port < 1 or port > 65535:
            print(f"[MCP] Invalid port: {port}")
            return 0

        if host == old_host and port == old_port:
            print(f"[MCP] Configuration unchanged: {host}:{port}")
            return 1

        # Persist the new bind IP/port (same mechanism as unrestricted)
        config_json_set("bind_host", host)
        config_json_set("bind_port", port)

        self.plugin.host = host
        self.plugin.port = port
        print(f"[MCP] Configuration updated: {host}:{port}")

        # Apply immediately if server is already running
        if self.plugin.mcp is not None:
            print("[MCP] Applying configuration change without manual restart...")
            self.plugin.run(0)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class MCPUIHooks(ida_kernwin.UI_Hooks):
    """Defers menu attachment until the UI is fully ready."""

    def ready_to_run(self):
        ida_kernwin.attach_action_to_menu(
            "Edit/Plugins/", CONFIG_ACTION_ID, idaapi.SETMENU_APP
        )
        self.unhook()


class MCP(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "MCP Plugin"
    help = "MCP"
    wanted_name = "MCP"
    wanted_hotkey = "Ctrl-Alt-M"

    DEFAULT_HOST = "0.0.0.0"   # \u2190 CHANGED: LAN by default
                            
    DEFAULT_PORT = 13337

    def init(self):
        hotkey = MCP.wanted_hotkey.replace("-", "+")
        if __import__("sys").platform == "darwin":
            hotkey = hotkey.replace("Alt", "Option")

        print(
            f"[MCP] Plugin loaded, use Edit -> Plugins -> MCP ({hotkey}) to start the server"
        )
        self.mcp: "ida_mcp.rpc.McpServer | None" = None
                                     
                                     

        # Load persisted bind IP/port (or default to 0.0.0.0)
        self.host = config_json_get("bind_host", self.DEFAULT_HOST)
        self.port = config_json_get("bind_port", self.DEFAULT_PORT)

        # Register menu item for host/port config
        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                CONFIG_ACTION_ID,
                CONFIG_ACTION_LABEL,
                MCPConfigHandler(self),
            )
        )
        # Defer menu attachment until the UI is fully initialized
        self._ui_hooks = MCPUIHooks()
        self._ui_hooks.hook()

        print(f"[MCP] Binding to: {self.host}:{self.port} (change via MCP Configuration menu)")

        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        if self.mcp:
            self.mcp.stop()
            self.mcp = None

        # HACK: ensure fresh load of ida_mcp package
        unload_package("ida_mcp")
        if TYPE_CHECKING:
            from .ida_mcp import MCP_SERVER, IdaMcpHttpRequestHandler, init_caches
        else:
            from ida_mcp import MCP_SERVER, IdaMcpHttpRequestHandler, init_caches

        try:
            init_caches()
        except Exception as e:
            print(f"[MCP] Cache init failed: {e}")

        port = self.port
        max_port = port + 100
        while port < max_port:
            try:
                MCP_SERVER.serve(
                    self.host, port, request_handler=IdaMcpHttpRequestHandler
                )
                print(f"  Config: http://{self.host}:{port}/config.html")
                self.mcp = MCP_SERVER
                return
            except OSError as e:
                if e.errno in (48, 98, 10048):  # Address already in use
                    port += 1
                else:
                    raise
        print(f"[MCP] Error: No available port in range {self.port}-{max_port - 1}")

    def term(self):
        if hasattr(self, "_ui_hooks"):
            self._ui_hooks.unhook()
        ida_kernwin.unregister_action(CONFIG_ACTION_ID)
        if self.mcp:
            self.mcp.stop()


def PLUGIN_ENTRY():
    return MCP()