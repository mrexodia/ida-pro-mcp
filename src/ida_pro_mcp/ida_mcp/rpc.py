from .zeromcp import McpRpcRegistry, McpServer, McpToolError, McpHttpRequestHandler

MCP_UNSAFE: set[str] = set()
MCP_EXTENSIONS: dict[str, set[str]] = {}  # group -> set of function names
MCP_SERVER = McpServer("ida-pro-mcp", extensions=MCP_EXTENSIONS)


def tool(func):
   return MCP_SERVER.tool(func)


def resource(uri):
   return MCP_SERVER.resource(uri)


def unsafe(func):
   MCP_UNSAFE.add(func.__name__)
   return func


def ext(group: str):
   """Mark a tool as belonging to an extension group.

   Tools in extension groups are hidden by default. Enable via ?ext=group query param.
   Example: @ext("dbg") marks debugger tools that require ?ext=dbg to be visible.
   """
   def decorator(func):
      if group not in MCP_EXTENSIONS:
         MCP_EXTENSIONS[group] = set()
      MCP_EXTENSIONS[group].add(func.__name__)
      return func
   return decorator


__all__ = [
   "McpRpcRegistry",
   "McpServer",
   "McpToolError",
   "McpHttpRequestHandler",
   "MCP_SERVER",
   "MCP_UNSAFE",
   "MCP_EXTENSIONS",
   "tool",
   "unsafe",
   "ext",
   "resource",
]
