import sys

if sys.version_info < (3, 11):
    raise RuntimeError("Python 3.11 or higher is required for the MCP plugin")

from typing import Callable
from .jsonrpc import JsonRpcRegistry, JsonRpcException, JsonRpcError


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

    def register(self, func: Callable) -> Callable:
        """Register a function (alias for method())"""
        return self.method(func)

    def mark_unsafe(self, func: Callable) -> Callable:
        """Mark a function as unsafe (requires --unsafe flag)"""
        self.unsafe.add(func.__name__)
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
