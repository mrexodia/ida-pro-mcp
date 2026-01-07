import json
import inspect
import os
import threading
import time
import traceback
from typing import Any, Callable, get_type_hints, get_origin, get_args, Union, TypedDict, TypeAlias, NotRequired, is_typeddict
from types import UnionType

JsonRpcId: TypeAlias = str | int | float | None

# Thread-local storage for current request context (ID + cancel event)
_current_request = threading.local()

# Global pending requests for cancellation
_pending_requests_lock = threading.Lock()
_pending_requests: dict[int | str, threading.Event] = {}


def get_current_request_id() -> JsonRpcId:
    """Get the JSON-RPC request ID of the currently executing request."""
    return getattr(_current_request, "id", None)


def get_current_cancel_event() -> threading.Event | None:
    """Get the cancel event for the currently executing request."""
    return getattr(_current_request, "cancel_event", None)


def register_pending_request(request_id: int | str) -> threading.Event:
    """Register a request as pending and return its cancel event."""
    event = threading.Event()
    with _pending_requests_lock:
        _pending_requests[request_id] = event
    _current_request.cancel_event = event
    return event


def unregister_pending_request(request_id: int | str) -> None:
    """Unregister a pending request."""
    with _pending_requests_lock:
        _pending_requests.pop(request_id, None)
    _current_request.cancel_event = None


def cancel_request(request_id: int | str) -> bool:
    """Signal cancellation for a pending request. Returns True if request was found."""
    with _pending_requests_lock:
        event = _pending_requests.get(request_id)
        if event:
            event.set()
            return True
    return False


def _parse_bool_env(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    value = value.strip().lower()
    if value in ("1", "true", "yes", "on"):
        return True
    if value in ("0", "false", "no", "off"):
        return False
    return default


_LOG_REQUESTS = _parse_bool_env("IDA_MCP_LOG_REQUESTS", True)
_LOG_SKIP_METHODS = {
    m.strip()
    for m in os.getenv("IDA_MCP_LOG_SKIP_METHODS", "tools/call").split(",")
    if m.strip()
}
JsonRpcParams: TypeAlias = dict[str, Any] | list[Any] | None

class JsonRpcRequest(TypedDict):
    jsonrpc: str
    method: str
    params: NotRequired[JsonRpcParams]
    id: NotRequired[JsonRpcId]

class JsonRpcError(TypedDict):
    code: int
    message: str
    data: NotRequired[Any]

class JsonRpcResponse(TypedDict):
    jsonrpc: str
    result: NotRequired[Any]
    error: NotRequired[JsonRpcError]
    id: JsonRpcId

class JsonRpcException(Exception):
    def __init__(self, code: int, message: str, data: Any = None):
        self.code = code
        self.message = message
        self.data = data


class RequestCancelledError(Exception):
    """Base class for request cancellation errors (LSP error code -32800)."""
    pass

class JsonRpcRegistry:
    def __init__(self):
        self.methods: dict[str, Callable] = {}
        self._cache: dict[Callable, tuple[inspect.Signature, dict, list[str]]] = {}
        self.redact_exceptions = False

    def method(self, func: Callable, name: str | None = None) -> Callable:
        self.methods[name or func.__name__] = func # type: ignore
        return func

    def dispatch(self, request: dict | str | bytes | bytearray) -> JsonRpcResponse | None:
        try:
            if not isinstance(request, dict):
                request = json.loads(request)
            if not isinstance(request, dict):
                return self._error(None, -32600, "Invalid request: must be a JSON object")
        except Exception as e:
            return self._error(None, -32700, "JSON parse error", str(e))

        if request.get("jsonrpc") != "2.0":
            return self._error(None, -32600, "Invalid request: 'jsonrpc' must be '2.0'")

        method = request.get("method")
        if method is None:
            return self._error(None, -32600, "Invalid request: 'method' is required")
        if not isinstance(method, str):
            return self._error(None, -32600, "Invalid request: 'method' must be a string")

        request_id: JsonRpcId = request.get("id")
        is_notification = "id" not in request
        params: JsonRpcParams = request.get("params")

        log_method = _LOG_REQUESTS and method not in _LOG_SKIP_METHODS
        if log_method:
            params_str = json.dumps(params, default=str)
            if len(params_str) > 200:
                params_str = params_str[:200] + "..."
            print(f"[MCP] >> {method}({params_str})")

        # Set current request ID in thread-local for cancellation tracking
        _current_request.id = request_id
        start_time = time.perf_counter()
        try:
            result = self._call(method, params)
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            if log_method:
                result_str = json.dumps(result, default=str)
                if len(result_str) > 200:
                    result_str = result_str[:200] + "..."
                print(f"[MCP] << {method} ({elapsed_ms:.1f}ms) {result_str}")
            if is_notification:
                return None
            return {
                "jsonrpc": "2.0",
                "result": result,
                "id": request_id,
            }
        except JsonRpcException as e:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            if log_method:
                print(f"[MCP] << {method} ({elapsed_ms:.1f}ms) ERROR: {e.message}")
            if is_notification:
                return None
            return self._error(request_id, e.code, e.message, e.data)
        except RequestCancelledError as e:
            # LSP error code -32800: Request cancelled
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            if log_method:
                print(f"[MCP] << {method} ({elapsed_ms:.1f}ms) CANCELLED")
            if is_notification:
                return None
            return self._error(request_id, -32800, str(e) or "Request cancelled")
        except Exception as e:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            if log_method:
                print(f"[MCP] << {method} ({elapsed_ms:.1f}ms) EXCEPTION: {e}")
            if is_notification:
                return None
            error = self.map_exception(e)
            return self._error(request_id, error["code"], error["message"], error.get("data"))
        finally:
            _current_request.id = None

    def map_exception(self, e: Exception) -> JsonRpcError:
        if self.redact_exceptions:
            return {
                "code": -32603,
                "message": f"Internal Error: {str(e)}",
            }
        return {
            "code": -32603,
            "message": "\n".join(traceback.format_exception(e)).strip() + "\n\nPlease report a bug!",
        }

    def _call(self, method: str, params: Any) -> Any:
        if method not in self.methods:
            raise JsonRpcException(-32601, f"Method '{method}' not found")

        func = self.methods[method]

        # Check for cached reflection data
        if func not in self._cache:
            sig = inspect.signature(func)
            hints = get_type_hints(func)
            hints.pop("return", None)

            # Determine required vs optional parameters
            required_params = []
            for param_name, param in sig.parameters.items():
                if param.default is inspect.Parameter.empty:
                    required_params.append(param_name)

            self._cache[func] = (sig, hints, required_params)

        sig, hints, required_params = self._cache[func]

        # Handle None params
        if params is None:
            if len(required_params) == 0:
                return func()
            else:
                raise JsonRpcException(-32602, "Missing required params")

        # Convert list params to dict by parameter names
        if isinstance(params, list):
            if len(params) < len(required_params):
                raise JsonRpcException(
                    -32602,
                    f"Invalid params: expected at least {len(required_params)} arguments, got {len(params)}"
                )
            if len(params) > len(sig.parameters):
                raise JsonRpcException(
                    -32602,
                    f"Invalid params: expected at most {len(sig.parameters)} arguments, got {len(params)}"
                )
            params = dict(zip(sig.parameters.keys(), params))

        # Validate dict params
        if isinstance(params, dict):
            # Check all required params are present
            missing = set(required_params) - set(params.keys())
            if missing:
                raise JsonRpcException(
                    -32602,
                    f"Invalid params: missing required parameters: {list(missing)}"
                )

            # Check no extra params
            extra = set(params.keys()) - set(sig.parameters.keys())
            if extra:
                raise JsonRpcException(
                    -32602,
                    f"Invalid params: unexpected parameters: {list(extra)}"
                )

            validated_params = {}
            for param_name, value in params.items():
                # If no type hint, pass through without validation
                if param_name not in hints:
                    validated_params[param_name] = value
                    continue

                # Has type hint, validate
                expected_type = hints[param_name]

                # Inline type validation
                origin = get_origin(expected_type)
                args = get_args(expected_type)

                # Handle None/null
                if value is None:
                    if expected_type is not type(None):
                        # Check if None is allowed in a Union
                        if not (origin in (Union, UnionType) and type(None) in args):
                            raise JsonRpcException(-32602, f"Invalid params: {param_name} cannot be null")
                    validated_params[param_name] = None
                    continue

                # Handle Union types (int | str, Optional[int], etc.)
                if origin in (Union, UnionType):
                    type_matched = False

                    # HACK: Try to parse str as JSON for non-str unions
                    # 
                    # When JSON schema says one field is "object", Claude Code
                    # (and maybe other MCP clients) can't (or won't) detect
                    # that the field is actually a dict/list. Instead, they
                    # treat the field as a string containing JSON object.
                    #
                    # To work around this, if the expected type is a Union
                    # that does not include str, and the provided value is
                    # a str, we try to parse it as JSON first.
                    if type(str) not in args and isinstance(value, str):
                        try:
                            value = json.loads(value)
                        except json.JSONDecodeError:
                            pass

                    for arg_type in args:
                        if arg_type is type(None):
                            continue

                        arg_origin = get_origin(arg_type)
                        check_type = arg_origin if arg_origin is not None else arg_type

                        # TypedDict cannot be used with isinstance - check for dict instead
                        if is_typeddict(arg_type):
                            check_type = dict

                        if isinstance(value, check_type):
                            type_matched = True
                            break

                    if not type_matched:
                        raise JsonRpcException(-32602, "Invalid params: expected {} for {}, got {}".format(
                            " | ".join(
                                t.__name__ if isinstance(t, type) else str(t)
                                for t in args
                            ),
                            param_name,
                            type(value).__name__
                        ))
                    validated_params[param_name] = value
                    continue

                # Handle generic types (list[X], dict[K,V])
                if origin is not None:
                    if not isinstance(value, origin):
                        raise JsonRpcException(
                            -32602,
                            f"Invalid params: {param_name} expected {origin.__name__}, got {type(value).__name__}"
                        )
                    validated_params[param_name] = value
                    continue

                # Handle TypedDict (must check before basic types)
                if is_typeddict(expected_type):
                    if not isinstance(value, dict):
                        raise JsonRpcException(
                            -32602,
                            f"Invalid params: {param_name} expected dict, got {type(value).__name__}"
                        )
                    validated_params[param_name] = value
                    continue

                # Handle Any
                if expected_type is Any:
                    validated_params[param_name] = value
                    continue

                # Handle basic types
                if isinstance(expected_type, type):
                    # Allow int -> float conversion
                    if expected_type is float and isinstance(value, int):
                        validated_params[param_name] = float(value)
                        continue
                    if not isinstance(value, expected_type):
                        raise JsonRpcException(
                            -32602,
                            f"Invalid params: {param_name} expected {expected_type.__name__}, got {type(value).__name__}"
                        )
                    validated_params[param_name] = value
                    continue

            return func(**validated_params)

        else:
            raise JsonRpcException(-32602, "Invalid params: must be array or object")

    def _error(self, request_id: JsonRpcId, code: int, message: str, data: Any = None) -> JsonRpcResponse | None:
        error: JsonRpcError = {
            "code": code,
            "message": message,
        }
        if data is not None:
            error["data"] = data
        return {
            "jsonrpc": "2.0",
            "error": error,
            "id": request_id,
        }
