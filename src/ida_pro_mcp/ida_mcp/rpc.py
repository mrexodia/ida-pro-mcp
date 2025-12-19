from .zeromcp import McpRpcRegistry, McpServer, McpToolError, McpHttpRequestHandler

MCP_SERVER = McpServer("ida-pro-mcp")
MCP_UNSAFE: set[str] = set()


def tool(func):
    return MCP_SERVER.tool(func)


def resource(uri):
    return MCP_SERVER.resource(uri)


def unsafe(func):
    MCP_UNSAFE.add(func.__name__)
    return func


__all__ = [
    "McpRpcRegistry",
    "McpServer",
    "McpToolError",
    "McpHttpRequestHandler",
    "MCP_SERVER",
    "MCP_UNSAFE",
    "tool",
    "unsafe",
    "resource",
]
