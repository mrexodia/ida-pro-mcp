import sys

if sys.version_info < (3, 11):
    raise RuntimeError("Python 3.11 or higher is required for the MCP plugin")

from typing import Callable
from .jsonrpc import JsonRpcRegistry, JsonRpcError


class JSONRPCError(Exception):
    """IDA-specific JSON-RPC error (kept for backwards compatibility)"""
    def __init__(self, code: int, message: str, data = None):
        self.code = code
        self.message = message
        self.data = data


class RPCRegistry(JsonRpcRegistry):
    """IDA-specific RPC registry that extends JsonRpcRegistry with unsafe tracking"""
    def __init__(self):
        super().__init__()
        self.unsafe: set[str] = set()
        self.resources: dict[str, Callable] = {}

    def register(self, func: Callable) -> Callable:
        """Register a function (alias for method())"""
        return self.method(func)

    def mark_unsafe(self, func: Callable) -> Callable:
        """Mark a function as unsafe (requires --unsafe flag)"""
        self.unsafe.add(func.__name__)
        return func

    def register_resource(self, uri: str, func: Callable) -> Callable:
        """Register a function as a resource with URI pattern

        Resources are registered in TWO places:
        1. rpc_registry.resources - for URI pattern matching and resource listing
        2. rpc_registry.methods - so resources/read can dispatch to them via JSON-RPC

        Note: Resources are filtered out of tools/list via __resource_uri__ attribute check
        """
        func.__resource_uri__ = uri
        self.resources[func.__name__] = func
        # Also register as JSON-RPC method (but won't appear in tools/list)
        self.method(func)
        return func

    def map_exception(self, e: Exception) -> JsonRpcError:
        """Map IDA-specific exceptions to JSON-RPC errors"""
        # Import here to avoid circular dependency
        from .sync import IDAError

        if isinstance(e, IDAError):
            return {
                "code": -32000,
                "message": e.message,
            }
        if isinstance(e, JSONRPCError):
            error: JsonRpcError = {
                "code": e.code,
                "message": e.message,
            }
            if e.data is not None:
                error["data"] = e.data
            return error
        return super().map_exception(e)


# Global registry instance
rpc_registry = RPCRegistry()


def jsonrpc(func: Callable) -> Callable:
    """Decorator to register a function as a JSON-RPC method"""
    return rpc_registry.register(func)


def unsafe(func: Callable) -> Callable:
    """Decorator to mark a function as unsafe (requires --unsafe flag)"""
    return rpc_registry.mark_unsafe(func)


def resource(uri: str) -> Callable[[Callable], Callable]:
    """Decorator to register a function as an MCP resource with URI pattern"""
    def decorator(func: Callable) -> Callable:
        return rpc_registry.register_resource(uri, func)
    return decorator
