"""IDA Pro MCP Plugin - Entry point that loads the modular package

This file serves as the IDA plugin entry point and delegates to the ida_mcp package.
"""

# Import and expose the plugin entry point from the package
from ida_mcp import PLUGIN_ENTRY, PLUGIN_FLAGS

__all__ = ["PLUGIN_ENTRY", "PLUGIN_FLAGS"]
