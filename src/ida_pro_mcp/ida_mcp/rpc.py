from .zeromcp import McpServer, McpToolError

MCP_SERVER = McpServer("ida-pro-mcp")
MCP_UNSAFE: set[str] = set()

jsonrpc = MCP_SERVER.tool
resource = MCP_SERVER.resource


def unsafe(func):
    MCP_UNSAFE.add(func.__name__)
    return func


__all__ = [
    "McpServer",
    "McpToolError",
    "MCP_SERVER",
    "MCP_UNSAFE",
    "jsonrpc",
    "unsafe",
    "resource",
]
