import sys

if sys.version_info < (3, 11):
    raise RuntimeError("Python 3.11 or higher is required for the MCP plugin")

from typing import (
    Any,
    Callable,
    get_type_hints,
    Annotated,
    Union,
    get_origin,
    get_args,
)
import types


class JSONRPCError(Exception):
    def __init__(self, code: int, message: str, data: Any = None):
        self.code = code
        self.message = message
        self.data = data


def _check_type(value: Any, expected_type: Any) -> bool:
    """Check if a value matches the expected type, handling unions and generics."""
    # Handle Annotated types
    if hasattr(expected_type, "__origin__") and expected_type.__origin__ is Annotated:
        expected_type = get_args(expected_type)[0]

    # Handle Any
    if expected_type is Any:
        return True

    # Handle Union types (str | int or Union[str, int])
    origin = get_origin(expected_type)
    if origin is Union or isinstance(expected_type, types.UnionType):
        if isinstance(expected_type, types.UnionType):
            # Python 3.10+ union syntax (str | int)
            args = expected_type.__args__
        else:
            # typing.Union syntax
            args = get_args(expected_type)
        return any(_check_type(value, arg) for arg in args)

    # Handle parameterized generics (list[str], dict[str, int], etc.)
    if origin is not None:
        # For generics like list[str], we check the origin (list) and optionally the args
        if origin is list:
            if not isinstance(value, list):
                return False
            args = get_args(expected_type)
            if args:  # If list[str], check each element
                return all(_check_type(item, args[0]) for item in value)
            return True
        elif origin is dict:
            if not isinstance(value, dict):
                return False
            args = get_args(expected_type)
            if args:  # If dict[str, int], check keys and values
                key_type, value_type = args[0], args[1]
                return all(
                    _check_type(k, key_type) and _check_type(v, value_type)
                    for k, v in value.items()
                )
            return True
        elif origin is tuple:
            if not isinstance(value, tuple):
                return False
            args = get_args(expected_type)
            if args and args[-1] is not Ellipsis:  # Fixed-size tuple
                if len(value) != len(args):
                    return False
                return all(_check_type(v, t) for v, t in zip(value, args))
            elif args:  # Variable-size tuple like tuple[int, ...]
                elem_type = args[0]
                return all(_check_type(v, elem_type) for v in value)
            return True
        elif origin is set:
            if not isinstance(value, set):
                return False
            args = get_args(expected_type)
            if args:
                return all(_check_type(item, args[0]) for item in value)
            return True

    # Handle Optional (Union[T, None])
    if expected_type is type(None) or expected_type is None:
        return value is None

    # Handle regular types
    try:
        return isinstance(value, expected_type)
    except TypeError:
        # If isinstance fails (e.g., with parameterized generics), try direct comparison
        return type(value) is expected_type


def _get_type_name(expected_type: Any) -> str:
    """Get a string representation of a type for error messages."""
    # Handle Annotated types
    if hasattr(expected_type, "__origin__") and expected_type.__origin__ is Annotated:
        expected_type = get_args(expected_type)[0]

    # Handle Any
    if expected_type is Any:
        return "any"

    # Handle Union types
    origin = get_origin(expected_type)
    if origin is Union or isinstance(expected_type, types.UnionType):
        if isinstance(expected_type, types.UnionType):
            args = expected_type.__args__
        else:
            args = get_args(expected_type)
        # Filter out None for Optional
        non_none_args = [
            arg for arg in args if arg is not type(None) and arg is not None
        ]
        if len(non_none_args) == 1 and len(args) == 2:
            return f"optional {_get_type_name(non_none_args[0])}"
        return " | ".join(_get_type_name(arg) for arg in args)

    # Handle parameterized generics
    if origin is not None:
        args = get_args(expected_type)
        if origin is list:
            if args:
                return f"list[{_get_type_name(args[0])}]"
            return "list"
        elif origin is dict:
            if args:
                return f"dict[{_get_type_name(args[0])}, {_get_type_name(args[1])}]"
            return "dict"
        elif origin is tuple:
            if args:
                if args[-1] is Ellipsis:
                    return f"tuple[{_get_type_name(args[0])}, ...]"
                return f"tuple[{', '.join(_get_type_name(a) for a in args)}]"
            return "tuple"
        elif origin is set:
            if args:
                return f"set[{_get_type_name(args[0])}]"
            return "set"
        else:
            # Other generic types
            if args:
                return (
                    f"{origin.__name__}[{', '.join(_get_type_name(a) for a in args)}]"
                )
            return origin.__name__

    # Handle regular types
    if hasattr(expected_type, "__name__"):
        return expected_type.__name__
    elif hasattr(expected_type, "__qualname__"):
        return expected_type.__qualname__
    else:
        return str(expected_type)


class RPCRegistry:
    def __init__(self):
        self.methods: dict[str, Callable] = {}
        self.unsafe: set[str] = set()

    def register(self, func: Callable) -> Callable:
        self.methods[func.__name__] = func
        return func

    def mark_unsafe(self, func: Callable) -> Callable:
        self.unsafe.add(func.__name__)
        return func

    def dispatch(self, method: str, params: Any) -> Any:
        if method not in self.methods:
            raise JSONRPCError(-32601, f"Method '{method}' not found")

        func = self.methods[method]
        hints = get_type_hints(func)
        hints.pop("return", None)

        if isinstance(params, list):
            if len(params) != len(hints):
                raise JSONRPCError(
                    -32602,
                    f"Invalid params: expected {len(hints)} arguments, got {len(params)}",
                )

            converted_params = []
            for value, (param_name, expected_type) in zip(params, hints.items()):
                try:
                    if not _check_type(value, expected_type):
                        # Try to convert if it's a simple type (not a union or generic)
                        origin = get_origin(expected_type)
                        is_union = (
                            isinstance(expected_type, types.UnionType)
                            or origin is Union
                        )

                        if not is_union and origin is None:
                            # Handle Annotated types
                            actual_type = expected_type
                            if (
                                hasattr(expected_type, "__origin__")
                                and expected_type.__origin__ is Annotated
                            ):
                                actual_type = get_args(expected_type)[0]
                            if actual_type is not Any:
                                value = actual_type(value)
                    converted_params.append(value)
                except (ValueError, TypeError):
                    raise JSONRPCError(
                        -32602,
                        f"Invalid type for parameter '{param_name}': expected {_get_type_name(expected_type)}",
                    )

            return func(*converted_params)
        elif isinstance(params, dict):
            if set(params.keys()) != set(hints.keys()):
                raise JSONRPCError(
                    -32602, f"Invalid params: expected {list(hints.keys())}"
                )

            converted_params = {}
            for param_name, expected_type in hints.items():
                value = params.get(param_name)
                try:
                    if not _check_type(value, expected_type):
                        # Try to convert if it's a simple type (not a union or generic)
                        origin = get_origin(expected_type)
                        is_union = (
                            isinstance(expected_type, types.UnionType)
                            or origin is Union
                        )

                        if not is_union and origin is None:
                            # Handle Annotated types
                            actual_type = expected_type
                            if (
                                hasattr(expected_type, "__origin__")
                                and expected_type.__origin__ is Annotated
                            ):
                                actual_type = get_args(expected_type)[0]
                            if actual_type is not Any:
                                value = actual_type(value)
                    converted_params[param_name] = value
                except (ValueError, TypeError):
                    raise JSONRPCError(
                        -32602,
                        f"Invalid type for parameter '{param_name}': expected {_get_type_name(expected_type)}",
                    )

            return func(**converted_params)
        else:
            raise JSONRPCError(
                -32600, "Invalid Request: params must be array or object"
            )


rpc_registry = RPCRegistry()


def jsonrpc(func: Callable) -> Callable:
    """Decorator to register a function as a JSON-RPC method"""
    global rpc_registry
    return rpc_registry.register(func)


def unsafe(func: Callable) -> Callable:
    """Decorator to register mark a function as unsafe"""
    return rpc_registry.mark_unsafe(func)
