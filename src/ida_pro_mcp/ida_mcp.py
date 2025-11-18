"""IDA Pro MCP Plugin Loader

This file serves as the entry point for IDA Pro's plugin system.
It loads the actual implementation from the ida_mcp package.
"""

import idaapi
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .ida_mcp import MCP_SERVER
else:
    from ida_mcp import MCP_SERVER


class MCP(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "MCP Plugin"
    help = "MCP"
    wanted_name = "MCP"
    wanted_hotkey = "Ctrl-Alt-M"

    # TODO: make these configurable
    HOST = "127.0.0.1"
    BASE_PORT = 13337
    MAX_PORT_TRIES = 10

    def init(self):
        hotkey = MCP.wanted_hotkey.replace("-", "+")
        if __import__("sys").platform == "darwin":
            hotkey = hotkey.replace("Alt", "Option")

        print(
            f"[MCP] Plugin loaded, use Edit -> Plugins -> MCP ({hotkey}) to start the server"
        )
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        for i in range(self.MAX_PORT_TRIES):
            port = self.BASE_PORT + i
            try:
                MCP_SERVER.serve(self.HOST, port)
                break
            except OSError as e:
                if e.errno in (98, 10048):  # Address already in use
                    if i == self.MAX_PORT_TRIES - 1:
                        print(
                            f"[MCP] Error: Could not find available port in range {self.BASE_PORT}-{self.BASE_PORT + self.MAX_PORT_TRIES - 1}"
                        )
                        self.running = False
                        return
                    continue
                raise

    def term(self):
        MCP_SERVER.stop()


def PLUGIN_ENTRY():
    return MCP()


# IDA plugin flags
PLUGIN_FLAGS = idaapi.PLUGIN_HIDE | idaapi.PLUGIN_FIX
