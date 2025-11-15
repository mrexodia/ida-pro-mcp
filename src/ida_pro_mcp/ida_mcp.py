"""IDA Pro MCP Plugin Loader

This file serves as the entry point for IDA Pro's plugin system.
It loads the actual implementation from the ida_mcp package.
"""

import idaapi
import traceback

# Try to import the package implementation
try:
    from ida_mcp import MCPServer
    _IMPORTS_OK = True
    _IMPORT_ERROR = None
except Exception as e:
    _IMPORTS_OK = False
    _IMPORT_ERROR = e
    traceback.print_exc()

    # Create dummy server
    class MCPServer:
        def __init__(self):
            pass
        def start(self):
            print("[MCP] Cannot start: import failed")
        def stop(self):
            pass


# ============================================================================
# IDA Plugin Class
# ============================================================================


class MCP(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "MCP Plugin"
    help = "MCP"
    wanted_name = "MCP"
    wanted_hotkey = "Ctrl-Alt-M"

    def init(self):
        global _IMPORTS_OK, _IMPORT_ERROR
        self.mcp_server = MCPServer()
        hotkey = MCP.wanted_hotkey.replace("-", "+")
        if __import__('sys').platform == "darwin":
            hotkey = hotkey.replace("Alt", "Option")

        if _IMPORTS_OK:
            print(
                f"[MCP] Plugin loaded, use Edit -> Plugins -> MCP ({hotkey}) to start the server"
            )
        else:
            print(
                f"[MCP] Plugin loaded WITH ERRORS - check console above"
            )
            print(f"[MCP] Error: {_IMPORT_ERROR}")
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        self.mcp_server.start()

    def term(self):
        self.mcp_server.stop()


def PLUGIN_ENTRY():
    return MCP()


# IDA plugin flags
PLUGIN_FLAGS = idaapi.PLUGIN_HIDE | idaapi.PLUGIN_FIX
