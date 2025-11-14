import os
import sys

if sys.version_info < (3, 11):
    raise RuntimeError("Python 3.11 or higher is required for the MCP plugin")

import json
import re
import struct
import threading
import socket
import time
import uuid
from urllib.parse import urlparse, parse_qs
from typing import (
    Any,
    Callable,
    get_type_hints,
    TypedDict,
    Optional,
    Annotated,
    TypeVar,
    Generic,
    NotRequired,
    overload,
    Literal,
    Union,
    get_origin,
    get_args,
)
import types
import logging
import queue
import traceback
import functools
from enum import IntEnum
import ida_hexrays
import ida_kernwin
import ida_funcs
import ida_lines
import ida_idaapi
import idc
import idaapi
import idautils
import ida_nalt
import ida_bytes
import ida_typeinf
import ida_xref
import ida_entry
import ida_idd
import ida_dbg
import ida_name
import ida_ida
import ida_frame
import ida_segment
import ida_search


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


# ============================================================================
# MCP Streamable HTTP Implementation
# ============================================================================


class SessionState:
    """Manages state for a Streamable HTTP session"""

    def __init__(self, session_id: str):
        self.session_id = session_id
        self.created_at = time.time()
        self.last_activity = time.time()
        self.initialized = False

    def update_activity(self):
        """Update last activity timestamp"""
        self.last_activity = time.time()

    def mark_initialized(self):
        """Mark the session as initialized"""
        self.initialized = True
        self.update_activity()


# ============================================================================
# MCP Server-Sent Events (SSE) Implementation
# ============================================================================


class SSEConnection:
    """Manages a single SSE client connection"""

    def __init__(self, client_socket, client_address, session_id: str | None = None):
        self.socket = client_socket
        self.address = client_address
        self.session_id = session_id or str(uuid.uuid4())
        self.alive = True
        self.initialized = False

    def send_event(self, event_type: str, data):
        """Send an SSE event to the client

        Args:
            event_type: Type of event (e.g., 'endpoint', 'message', 'ping')
            data: Event data - can be string (sent as-is) or dict (JSON-encoded)
        """
        if not self.alive:
            return False

        try:
            event_str = f"event: {event_type}\n"
            if isinstance(data, str):
                data_str = f"data: {data}\n\n"
            else:
                data_str = f"data: {json.dumps(data)}\n\n"
            message = (event_str + data_str).encode("utf-8")
            self.socket.sendall(message)
            return True
        except (BrokenPipeError, OSError):
            self.alive = False
            return False

    def send_message(self, message: dict):
        """Send an MCP JSON-RPC message"""
        return self.send_event("message", message)

    def close(self):
        """Close the connection"""
        self.alive = False
        try:
            self.socket.close()
        except Exception:
            pass


class MCPProtocolHandler:
    """Handles MCP protocol messages and generates tool schemas"""

    def __init__(self, registry: "RPCRegistry"):
        self.registry = registry
        self.server_info = {"name": "ida-pro-mcp", "version": "1.0.0"}
        self.capabilities = {"tools": {"listChanged": True}}

    def generate_tool_schema(self, func_name: str, func: Callable) -> dict:
        """Generate MCP tool schema from a function"""
        hints = get_type_hints(func)
        hints.pop("return", None)

        properties = {}
        required = []

        for param_name, param_type in hints.items():
            description = ""
            actual_type = param_type

            if hasattr(param_type, "__origin__"):
                if param_type.__origin__ is Annotated:
                    args = param_type.__metadata__
                    if args:
                        description = args[0]
                    actual_type = param_type.__args__[0]

            json_type = "string"
            if actual_type is int:
                json_type = "integer"
            elif actual_type is float:
                json_type = "number"
            elif actual_type is bool:
                json_type = "boolean"
            elif actual_type is str:
                json_type = "string"

            properties[param_name] = {"type": json_type, "description": description}
            required.append(param_name)

        description = func.__doc__ or f"Call {func_name}"
        if description:
            description = description.strip()

        return {
            "name": func_name,
            "description": description,
            "inputSchema": {
                "type": "object",
                "properties": properties,
                "required": required,
            },
        }

    def get_tools_list(self) -> list[dict]:
        """Generate list of all available tools"""
        tools = []
        for func_name, func in self.registry.methods.items():
            tool_schema = self.generate_tool_schema(func_name, func)
            tools.append(tool_schema)
        return tools

    def handle_initialize(self, params: dict) -> dict:
        """Handle MCP initialize request"""
        return {
            "protocolVersion": "2024-11-05",
            "capabilities": self.capabilities,
            "serverInfo": self.server_info,
        }

    def handle_tools_list(self, params: dict) -> dict:
        """Handle tools/list request"""
        return {"tools": self.get_tools_list()}

    def handle_tools_call(self, params: dict) -> dict:
        """Handle tools/call request"""
        tool_name = params.get("name")
        arguments = params.get("arguments", {})

        if not tool_name:
            raise JSONRPCError(-32602, "Missing tool name")

        result = self.registry.dispatch(tool_name, arguments)

        return {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(result)
                    if not isinstance(result, str)
                    else result,
                }
            ]
        }


class MCPServer:
    """MCP server using Streamable HTTP transport"""

    HOST = "127.0.0.1"
    BASE_PORT = 13337
    MAX_PORT_TRIES = 10

    def __init__(self):
        self.server_socket = None
        self.server_thread = None
        self.running = False
        self.port = None
        self.sessions: dict[str, SessionState] = {}
        self.connections: list[SSEConnection] = []
        self.mcp_handler = MCPProtocolHandler(rpc_registry)

    def start(self):
        """Start the MCP server"""
        if self.running:
            print("[MCP] Server is already running")
            return

        self.server_thread = threading.Thread(target=self._run_server, daemon=True)
        self.running = True
        self.server_thread.start()

    def stop(self):
        """Stop the MCP server"""
        if not self.running:
            return

        self.running = False

        for conn in self.connections[:]:
            conn.close()
        self.connections.clear()

        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass
            self.server_socket = None

        if self.server_thread:
            self.server_thread.join(timeout=2)

        print("[MCP] Server stopped")

    def _parse_http_request(self, data: bytes) -> tuple[str, str, dict, bytes]:
        """Parse raw HTTP request. Returns (method, path, headers, body)"""
        try:
            header_end = data.find(b"\r\n\r\n")
            if header_end == -1:
                raise ValueError("Invalid HTTP request: no header terminator")

            header_data = data[:header_end].decode("utf-8", errors="replace")
            body = data[header_end + 4 :]

            lines = header_data.split("\r\n")
            request_line = lines[0]

            parts = request_line.split(" ")
            if len(parts) < 2:
                raise ValueError("Invalid HTTP request line")

            method = parts[0]
            path = parts[1]

            headers = {}
            for line in lines[1:]:
                if ":" in line:
                    key, value = line.split(":", 1)
                    headers[key.strip().lower()] = value.strip()

            if headers.get("transfer-encoding") == "chunked":
                body = self._decode_chunked_body(body)

            return method, path, headers, body
        except Exception as e:
            raise ValueError(f"Failed to parse HTTP request: {e}")

    def _decode_chunked_body(self, chunked_data: bytes) -> bytes:
        """Decode HTTP chunked transfer encoding"""
        body = b""
        pos = 0

        while pos < len(chunked_data):
            line_end = chunked_data.find(b"\r\n", pos)
            if line_end == -1:
                break

            chunk_size_str = chunked_data[pos:line_end].decode("ascii").strip()
            if ";" in chunk_size_str:
                chunk_size_str = chunk_size_str.split(";", 1)[0]

            try:
                chunk_size = int(chunk_size_str, 16)
            except ValueError:
                break

            if chunk_size == 0:
                break

            chunk_start = line_end + 2
            chunk_end = chunk_start + chunk_size
            if chunk_end > len(chunked_data):
                break

            body += chunked_data[chunk_start:chunk_end]
            pos = chunk_end + 2

        return body

    def _is_chunked_body_complete(self, chunked_data: bytes) -> bool:
        """Return True when we have received the full chunked body (including trailer)"""
        pos = 0

        while True:
            line_end = chunked_data.find(b"\r\n", pos)
            if line_end == -1:
                return False

            size_line = chunked_data[pos:line_end].strip()
            if b";" in size_line:
                size_line = size_line.split(b";", 1)[0]

            if not size_line:
                return False

            try:
                chunk_size = int(size_line, 16)
            except ValueError:
                return False

            pos = line_end + 2
            if len(chunked_data) < pos + chunk_size + 2:
                return False

            pos += chunk_size
            if chunked_data[pos : pos + 2] != b"\r\n":
                return False
            pos += 2

            if chunk_size == 0:
                if len(chunked_data) == pos:
                    return True
                trailer_end = chunked_data.find(b"\r\n\r\n", pos)
                return trailer_end != -1 and trailer_end + 4 <= len(chunked_data)

    def _send_http_response(
        self, sock: socket.socket, status: int, headers: dict, body: bytes = b""
    ):
        """Send raw HTTP response"""
        status_text = {
            200: "OK",
            400: "Bad Request",
            404: "Not Found",
            500: "Internal Server Error",
        }.get(status, "Unknown")

        response = f"HTTP/1.1 {status} {status_text}\r\n"
        for key, value in headers.items():
            response += f"{key}: {value}\r\n"
        response += "\r\n"

        sock.sendall(response.encode("utf-8") + body)

    def _handle_streamable_post(
        self, client_socket: socket.socket, body: bytes, headers: dict
    ):
        """Handle POST /mcp (Streamable HTTP with Mcp-Session-Id header)"""
        try:
            session_id = headers.get("mcp-session-id")
            if not session_id:
                session_id = str(uuid.uuid4())

            session_state = self.sessions.get(session_id)
            if session_state is None:
                session_state = SessionState(session_id)
                self.sessions[session_id] = session_state
            else:
                session_state.update_activity()

            request = json.loads(body.decode("utf-8"))

            if request.get("jsonrpc") != "2.0":
                raise JSONRPCError(-32600, "Invalid JSON-RPC version")

            method = request.get("method")
            params = request.get("params", {})
            request_id = request.get("id")
            is_notification = request_id is None

            def send_notification_ack(status: int = 204):
                ack_headers = {
                    "Mcp-Session-Id": session_id,
                    "Access-Control-Allow-Origin": "*",
                    "Content-Length": "0",
                }
                self._send_http_response(client_socket, status, ack_headers, b"")

            if method == "notifications/initialized":
                session_state.mark_initialized()
                send_notification_ack()
                return
            if method and method.startswith("notifications/") and is_notification:
                send_notification_ack()
                return

            response = {"jsonrpc": "2.0", "id": request_id}

            try:
                if method == "initialize":
                    result = self.mcp_handler.handle_initialize(params)
                elif method == "tools/list":
                    result = self.mcp_handler.handle_tools_list(params)
                elif method == "tools/call":
                    result = self.mcp_handler.handle_tools_call(params)
                else:
                    raise JSONRPCError(-32601, f"Method not found: {method}")

                response["result"] = result

            except JSONRPCError as e:
                response["error"] = {"code": e.code, "message": e.message}
                if e.data:
                    response["error"]["data"] = e.data
            except IDAError as e:
                response["error"] = {"code": -32000, "message": e.message}
            except Exception as e:
                traceback.print_exc()
                response["error"] = {
                    "code": -32603,
                    "message": "Internal error",
                    "data": str(e),
                }

            response_body = json.dumps(response).encode("utf-8")
            response_headers = {
                "Content-Type": "application/json",
                "Content-Length": str(len(response_body)),
                "Mcp-Session-Id": session_id,
                "Access-Control-Allow-Origin": "*",
            }
            self._send_http_response(
                client_socket, 200, response_headers, response_body
            )

        except Exception as e:
            traceback.print_exc()
            error_response = {
                "jsonrpc": "2.0",
                "error": {"code": -32700, "message": "Parse error", "data": str(e)},
                "id": None,
            }
            response_body = json.dumps(error_response).encode("utf-8")
            error_headers = {
                "Content-Type": "application/json",
                "Content-Length": str(len(response_body)),
            }
            self._send_http_response(client_socket, 400, error_headers, response_body)

    def _handle_sse_connection(
        self, client_socket: socket.socket, client_address, headers: dict
    ):
        """Handle SSE connection (GET /sse)"""
        requested_session_id = headers.get("mcp-session-id")
        if requested_session_id:
            session_id = requested_session_id
            session_state = self.sessions.get(session_id)
            if session_state is None:
                self._send_http_response(
                    client_socket,
                    404,
                    {"Content-Type": "text/plain"},
                    b"Unknown MCP session (initialize first)",
                )
                client_socket.close()
                return
            session_state.update_activity()
        else:
            session_id = str(uuid.uuid4())
            self.sessions[session_id] = SessionState(session_id)

        conn = SSEConnection(client_socket, client_address, session_id)
        self.connections.append(conn)

        try:
            headers = {
                "Content-Type": "text/event-stream",
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "Access-Control-Allow-Origin": "*",
            }
            self._send_http_response(client_socket, 200, headers)

            conn.send_event(
                "endpoint",
                {
                    "url": f"/sse?session={conn.session_id}",
                    "headers": {"Mcp-Session-Id": conn.session_id},
                },
            )

            last_ping = time.time()
            while conn.alive and self.running:
                now = time.time()
                if now - last_ping > 30:
                    if not conn.send_event("ping", {}):
                        break
                    last_ping = now
                time.sleep(1)

        finally:
            conn.close()
            if conn in self.connections:
                self.connections.remove(conn)

    def _handle_message_post(
        self,
        client_socket: socket.socket,
        body: bytes,
        client_address,
        path: str,
        headers: dict,
    ):
        """Handle POST /sse (MCP JSON-RPC request) - SSE mode"""
        try:
            parsed = urlparse(path)
            query_params = parse_qs(parsed.query)
            session_id = query_params.get("session", [None])[0]
            if session_id is None:
                session_id = headers.get("mcp-session-id")

            if session_id is None:
                self._send_http_response(
                    client_socket,
                    400,
                    {"Content-Type": "text/plain", "Access-Control-Allow-Origin": "*"},
                    b"Missing Mcp-Session-Id for SSE POST",
                )
                return

            request = json.loads(body.decode("utf-8"))

            if request.get("jsonrpc") != "2.0":
                raise JSONRPCError(-32600, "Invalid JSON-RPC version")

            method = request.get("method")
            params = request.get("params", {})
            request_id = request.get("id")
            is_notification = request_id is None

            def send_notification_ack():
                headers = {
                    "Content-Type": "text/plain",
                    "Access-Control-Allow-Origin": "*",
                }
                if session_id:
                    headers["Mcp-Session-Id"] = session_id
                self._send_http_response(client_socket, 202, headers, b"Accepted")

            if method == "notifications/initialized":
                if session_id:
                    for conn in self.connections:
                        if conn.session_id == session_id:
                            conn.initialized = True
                            break
                send_notification_ack()
                return
            if method and method.startswith("notifications/") and is_notification:
                send_notification_ack()
                return

            response = {"jsonrpc": "2.0", "id": request_id}

            try:
                if method == "initialize":
                    result = self.mcp_handler.handle_initialize(params)
                elif method == "tools/list":
                    result = self.mcp_handler.handle_tools_list(params)
                elif method == "tools/call":
                    result = self.mcp_handler.handle_tools_call(params)
                else:
                    raise JSONRPCError(-32601, f"Method not found: {method}")

                response["result"] = result

            except JSONRPCError as e:
                response["error"] = {"code": e.code, "message": e.message}
                if e.data:
                    response["error"]["data"] = e.data
            except IDAError as e:
                response["error"] = {"code": -32000, "message": e.message}
            except Exception as e:
                traceback.print_exc()
                response["error"] = {
                    "code": -32603,
                    "message": "Internal error",
                    "data": str(e),
                }

            sse_conn = None
            if session_id:
                for conn in self.connections:
                    if conn.session_id == session_id and conn.alive:
                        sse_conn = conn
                        break

            if not sse_conn:
                error_msg = f"No active SSE connection found for session {session_id}"
                print(f"[MCP SSE ERROR] {error_msg}")
                self._send_http_response(
                    client_socket,
                    400,
                    {"Content-Type": "text/plain"},
                    error_msg.encode("utf-8"),
                )
                return

            sse_conn.send_event("message", response)

            self._send_http_response(
                client_socket,
                202,
                {"Content-Type": "text/plain", "Access-Control-Allow-Origin": "*"},
                b"Accepted",
            )

        except Exception as e:
            traceback.print_exc()
            error_response = {
                "jsonrpc": "2.0",
                "error": {"code": -32700, "message": "Parse error", "data": str(e)},
                "id": None,
            }
            response_body = json.dumps(error_response).encode("utf-8")
            headers = {
                "Content-Type": "application/json",
                "Content-Length": str(len(response_body)),
            }
            self._send_http_response(client_socket, 400, headers, response_body)

    def _handle_options_request(self, client_socket: socket.socket):
        """Handle OPTIONS request for CORS"""
        headers = {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type",
            "Access-Control-Max-Age": "86400",
        }
        self._send_http_response(client_socket, 200, headers)

    def _handle_jsonrpc_post(self, client_socket: socket.socket, body: bytes):
        """Handle POST /mcp (legacy JSON-RPC)"""
        try:
            request = json.loads(body.decode("utf-8"))
        except json.JSONDecodeError:
            error_response = {
                "jsonrpc": "2.0",
                "error": {"code": -32700, "message": "Parse error: invalid JSON"},
            }
            response_body = json.dumps(error_response).encode("utf-8")
            self._send_http_response(
                client_socket,
                200,
                {
                    "Content-Type": "application/json",
                    "Content-Length": str(len(response_body)),
                },
                response_body,
            )
            return

        response: dict[str, Any] = {"jsonrpc": "2.0"}
        if request.get("id") is not None:
            response["id"] = request.get("id")

        try:
            if not isinstance(request, dict):
                raise JSONRPCError(-32600, "Invalid Request")
            if request.get("jsonrpc") != "2.0":
                raise JSONRPCError(-32600, "Invalid JSON-RPC version")
            if "method" not in request:
                raise JSONRPCError(-32600, "Method not specified")

            result = rpc_registry.dispatch(request["method"], request.get("params", []))
            response["result"] = result

        except JSONRPCError as e:
            response["error"] = {"code": e.code, "message": e.message}
            if e.data is not None:
                response["error"]["data"] = e.data
        except IDAError as e:
            response["error"] = {
                "code": -32000,
                "message": e.message,
            }
        except Exception:
            traceback.print_exc()
            response["error"] = {
                "code": -32603,
                "message": "Internal error (please report a bug)",
                "data": traceback.format_exc(),
            }

        try:
            response_body = json.dumps(response).encode("utf-8")
        except Exception:
            traceback.print_exc()
            response_body = json.dumps(
                {
                    "error": {
                        "code": -32603,
                        "message": "Internal error (please report a bug)",
                        "data": traceback.format_exc(),
                    }
                }
            ).encode("utf-8")

        self._send_http_response(
            client_socket,
            200,
            {
                "Content-Type": "application/json",
                "Content-Length": str(len(response_body)),
            },
            response_body,
        )

    def _handle_client(self, client_socket: socket.socket, client_address):
        """Handle a client connection"""
        try:
            client_socket.settimeout(5.0)
            data = b""
            content_length = None
            is_chunked = False
            header_end_pos = None

            while True:
                chunk = client_socket.recv(4096)
                if not chunk:
                    break
                data += chunk

                if b"\r\n\r\n" in data and header_end_pos is None:
                    header_end_pos = data.find(b"\r\n\r\n")

                    if data.startswith(b"GET"):
                        break

                    headers_str = data[:header_end_pos].decode(
                        "utf-8", errors="replace"
                    )
                    for line in headers_str.split("\r\n"):
                        line_lower = line.lower()
                        if line_lower.startswith("content-length:"):
                            content_length = int(line.split(":", 1)[1].strip())
                        elif (
                            line_lower.startswith("transfer-encoding:")
                            and "chunked" in line_lower
                        ):
                            is_chunked = True

                if header_end_pos is not None:
                    body_offset = header_end_pos + 4
                    body_view = data[body_offset:]

                    if content_length is not None:
                        if len(body_view) >= content_length:
                            break
                    elif is_chunked:
                        if self._is_chunked_body_complete(body_view):
                            break
                    elif not data.startswith(b"GET"):
                        break

            if not data:
                client_socket.close()
                return

            method, path, headers, body = self._parse_http_request(data)

            base_path = path.split("?")[0]

            if method == "OPTIONS":
                self._handle_options_request(client_socket)
                client_socket.close()
            elif method == "GET" and base_path == "/sse":
                self._handle_sse_connection(client_socket, client_address, headers)
            elif method == "POST" and base_path == "/sse":
                self._handle_message_post(
                    client_socket, body, client_address, path, headers
                )
                client_socket.close()
            elif method == "POST" and base_path == "/mcp":
                self._handle_streamable_post(client_socket, body, headers)
                client_socket.close()
            else:
                self._send_http_response(
                    client_socket, 404, {"Content-Type": "text/plain"}, b"Not Found"
                )
                client_socket.close()

        except Exception as e:
            traceback.print_exc()
            try:
                self._send_http_response(
                    client_socket,
                    500,
                    {"Content-Type": "text/plain"},
                    str(e).encode("utf-8"),
                )
            except Exception:
                pass
            try:
                client_socket.close()
            except Exception:
                pass

    def _run_server(self):
        """Run the SSE server main loop"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            for i in range(self.MAX_PORT_TRIES):
                port = self.BASE_PORT + i
                try:
                    self.server_socket.bind((self.HOST, port))
                    self.port = port
                    break
                except OSError as e:
                    if e.errno in (98, 10048):
                        if i == self.MAX_PORT_TRIES - 1:
                            raise OSError(
                                f"Could not find available port in range {self.BASE_PORT}-{self.BASE_PORT + self.MAX_PORT_TRIES - 1}"
                            )
                        continue
                    raise

            self.server_socket.listen(5)
            self.server_socket.settimeout(1.0)

            print("[MCP] Server started:")
            print(f"  Streamable HTTP: http://{self.HOST}:{self.port}/mcp")
            print(f"  SSE: http://{self.HOST}:{self.port}/sse")

            while self.running:
                try:
                    client_socket, client_address = self.server_socket.accept()
                    client_thread = threading.Thread(
                        target=self._handle_client,
                        args=(client_socket, client_address),
                        daemon=True,
                    )
                    client_thread.start()
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        print(f"[MCP] Error accepting connection: {e}")

        except OSError as e:
            if e.errno == 98 or e.errno == 10048:
                print(f"[MCP] Error: Port {self.port} is already in use")
            else:
                print(f"[MCP] Server error: {e}")
            self.running = False
        except Exception as e:
            print(f"[MCP] Server error: {e}")
            traceback.print_exc()
        finally:
            self.running = False
            if self.server_socket:
                try:
                    self.server_socket.close()
                except Exception:
                    pass


# ============================================================================
# IDA Synchronization & Error Handling
# ============================================================================

ida_major, ida_minor = map(int, idaapi.get_kernel_version().split("."))


class IDAError(Exception):
    def __init__(self, message: str):
        super().__init__(message)

    @property
    def message(self) -> str:
        return self.args[0]


class IDASyncError(Exception):
    pass


logger = logging.getLogger(__name__)


class IDASafety(IntEnum):
    SAFE_NONE = ida_kernwin.MFF_FAST
    SAFE_READ = ida_kernwin.MFF_READ
    SAFE_WRITE = ida_kernwin.MFF_WRITE


call_stack = queue.LifoQueue()


def sync_wrapper(ff, safety_mode: IDASafety):
    """Call a function ff with a specific IDA safety_mode."""
    if safety_mode not in [IDASafety.SAFE_READ, IDASafety.SAFE_WRITE]:
        error_str = f"Invalid safety mode {safety_mode} over function {ff.__name__}"
        logger.error(error_str)
        raise IDASyncError(error_str)

    res_container = queue.Queue()

    def runned():
        if not call_stack.empty():
            last_func_name = call_stack.get()
            error_str = f"Call stack is not empty while calling the function {ff.__name__} from {last_func_name}"
            raise IDASyncError(error_str)

        call_stack.put((ff.__name__))
        try:
            res_container.put(ff())
        except Exception as x:
            res_container.put(x)
        finally:
            call_stack.get()

    idaapi.execute_sync(runned, safety_mode)
    res = res_container.get()
    if isinstance(res, Exception):
        raise res
    return res


def idawrite(f):
    """Decorator for marking a function as modifying the IDB."""

    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        ff = functools.partial(f, *args, **kwargs)
        ff.__name__ = f.__name__
        return sync_wrapper(ff, idaapi.MFF_WRITE)

    return wrapper


def idaread(f):
    """Decorator for marking a function as reading from the IDB."""

    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        ff = functools.partial(f, *args, **kwargs)
        ff.__name__ = f.__name__
        return sync_wrapper(ff, idaapi.MFF_READ)

    return wrapper


def is_window_active():
    """Returns whether IDA is currently active"""
    try:
        from PyQt5.QtWidgets import QApplication
    except (ImportError, SystemError):
        return False

    app = QApplication.instance()
    if app is None:
        return False

    for widget in app.topLevelWidgets():
        if widget.isActiveWindow():
            return True
    return False


# ============================================================================
# Helper Functions
# ============================================================================


class Metadata(TypedDict):
    path: str
    module: str
    base: str
    size: str
    md5: str
    sha256: str
    crc32: str
    filesize: str


def get_image_size() -> int:
    try:
        info = idaapi.get_inf_structure()
        omin_ea = info.omin_ea
        omax_ea = info.omax_ea
    except AttributeError:
        import ida_ida

        omin_ea = ida_ida.inf_get_omin_ea()
        omax_ea = ida_ida.inf_get_omax_ea()
    image_size = omax_ea - omin_ea
    header = idautils.peutils_t().header()
    if header and header[:4] == b"PE\0\0":
        image_size = struct.unpack("<I", header[0x50:0x54])[0]
    return image_size


def parse_address(addr: str | int) -> int:
    if isinstance(addr, int):
        return addr
    try:
        return int(addr, 0)
    except ValueError:
        for ch in addr:
            if ch not in "0123456789abcdefABCDEF":
                raise IDAError(f"Failed to parse address: {addr}")
        raise IDAError(f"Failed to parse address (missing 0x prefix): {addr}")


def normalize_list_input(value: list | str) -> list:
    """Normalize input to list - accepts list or comma-separated string"""
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    return [value]


def normalize_dict_list(value: list[dict] | dict) -> list[dict]:
    """Normalize input to list[dict] - accepts list[dict] or single dict"""
    if isinstance(value, dict):
        return [value]
    elif isinstance(value, list):
        return value
    else:
        raise JSONRPCError(
            -32602,
            f"Invalid type: expected list[dict] or dict, got {type(value).__name__}",
        )


def looks_like_address(s: str) -> bool:
    """Check if string looks like an address (0x prefix or all hex chars)"""
    if s.startswith("0x") or s.startswith("0X"):
        return True
    # All hex chars and at least 4 chars → likely address
    if len(s) >= 4 and all(c in "0123456789abcdefABCDEF" for c in s):
        return True
    return False


class Function(TypedDict):
    ea: str
    name: str
    size: str


@overload
def get_function(addr: int, *, raise_error: Literal[True]) -> Function: ...


@overload
def get_function(addr: int) -> Function: ...


@overload
def get_function(addr: int, *, raise_error: Literal[False]) -> Optional[Function]: ...


def get_function(addr, *, raise_error=True):
    fn = idaapi.get_func(addr)
    if fn is None:
        if raise_error:
            raise IDAError(f"No function found at address {hex(addr)}")
        return None

    try:
        name = fn.get_name()
    except AttributeError:
        name = ida_funcs.get_func_name(fn.start_ea)

    return Function(ea=hex(addr), name=name, size=hex(fn.end_ea - fn.start_ea))


def get_prototype(fn: ida_funcs.func_t) -> Optional[str]:
    try:
        prototype: ida_typeinf.tinfo_t = fn.get_prototype()
        if prototype is not None:
            return str(prototype)
        else:
            return None
    except AttributeError:
        try:
            return idc.get_type(fn.start_ea)
        except Exception:
            tif = ida_typeinf.tinfo_t()
            if ida_nalt.get_tinfo(tif, fn.start_ea):
                return str(tif)
            return None
    except Exception as e:
        print(f"Error getting function prototype: {e}")
        return None


DEMANGLED_TO_EA = {}


def create_demangled_to_ea_map():
    for ea in idautils.Functions():
        demangled = idaapi.demangle_name(idc.get_name(ea, 0), idaapi.MNG_NODEFINIT)
        if demangled:
            DEMANGLED_TO_EA[demangled] = ea


def get_type_by_name(type_name: str) -> ida_typeinf.tinfo_t:
    # 8-bit integers
    if type_name in ("int8", "__int8", "int8_t", "char", "signed char"):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_INT8)
    elif type_name in ("uint8", "__uint8", "uint8_t", "unsigned char", "byte", "BYTE"):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_UINT8)
    # 16-bit integers
    elif type_name in (
        "int16",
        "__int16",
        "int16_t",
        "short",
        "short int",
        "signed short",
        "signed short int",
    ):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_INT16)
    elif type_name in (
        "uint16",
        "__uint16",
        "uint16_t",
        "unsigned short",
        "unsigned short int",
        "word",
        "WORD",
    ):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_UINT16)
    # 32-bit integers
    elif type_name in (
        "int32",
        "__int32",
        "int32_t",
        "int",
        "signed int",
        "long",
        "long int",
        "signed long",
        "signed long int",
    ):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_INT32)
    elif type_name in (
        "uint32",
        "__uint32",
        "uint32_t",
        "unsigned int",
        "unsigned long",
        "unsigned long int",
        "dword",
        "DWORD",
    ):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_UINT32)
    # 64-bit integers
    elif type_name in (
        "int64",
        "__int64",
        "int64_t",
        "long long",
        "long long int",
        "signed long long",
        "signed long long int",
    ):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_INT64)
    elif type_name in (
        "uint64",
        "__uint64",
        "uint64_t",
        "unsigned int64",
        "unsigned long long",
        "unsigned long long int",
        "qword",
        "QWORD",
    ):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_UINT64)
    # 128-bit integers
    elif type_name in ("int128", "__int128", "int128_t", "__int128_t"):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_INT128)
    elif type_name in (
        "uint128",
        "__uint128",
        "uint128_t",
        "__uint128_t",
        "unsigned int128",
    ):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_UINT128)
    # Floating point types
    elif type_name in ("float",):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_FLOAT)
    elif type_name in ("double",):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_DOUBLE)
    elif type_name in ("long double", "ldouble"):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_LDOUBLE)
    # Boolean type
    elif type_name in ("bool", "_Bool", "boolean"):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_BOOL)
    # Void type
    elif type_name in ("void",):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_VOID)
    # Named types
    tif = ida_typeinf.tinfo_t()
    if tif.get_named_type(None, type_name, ida_typeinf.BTF_STRUCT):
        return tif
    if tif.get_named_type(None, type_name, ida_typeinf.BTF_TYPEDEF):
        return tif
    if tif.get_named_type(None, type_name, ida_typeinf.BTF_ENUM):
        return tif
    if tif.get_named_type(None, type_name, ida_typeinf.BTF_UNION):
        return tif
    if tif := ida_typeinf.tinfo_t(type_name):
        return tif

    raise IDAError(f"Unable to retrieve {type_name} type info object")


T = TypeVar("T")


class Page(TypedDict, Generic[T]):
    data: list[T]
    next_offset: Optional[int]


def paginate(data: list[T], offset: int, count: int) -> Page[T]:
    if count == 0:
        count = len(data)
    next_offset = offset + count
    if next_offset >= len(data):
        next_offset = None
    return {
        "data": data[offset : offset + count],
        "next_offset": next_offset,
    }


def pattern_filter(data: list[T], pattern: str, key: str) -> list[T]:
    if not pattern:
        return data

    regex = None

    if pattern.startswith("/") and pattern.count("/") >= 2:
        last_slash = pattern.rfind("/")
        body = pattern[1:last_slash]
        flag_str = pattern[last_slash + 1 :]

        flags = 0
        for ch in flag_str:
            if ch == "i":
                flags |= re.IGNORECASE
            elif ch == "m":
                flags |= re.MULTILINE
            elif ch == "s":
                flags |= re.DOTALL

        try:
            regex = re.compile(body, flags or re.IGNORECASE)
        except re.error:
            regex = None

    def get_value(item) -> str:
        try:
            v = item[key]
        except Exception:
            v = getattr(item, key, "")
        return "" if v is None else str(v)

    def matches(item) -> bool:
        text = get_value(item)
        if regex is not None:
            return bool(regex.search(text))
        return pattern.lower() in text.lower()

    return [item for item in data if matches(item)]


def refresh_decompiler_widget():
    widget = ida_kernwin.get_current_widget()
    if widget is not None:
        vu = ida_hexrays.get_widget_vdui(widget)
        if vu is not None:
            vu.refresh_ctext()


def refresh_decompiler_ctext(fn_addr: int):
    error = ida_hexrays.hexrays_failure_t()
    cfunc: ida_hexrays.cfunc_t = ida_hexrays.decompile_func(
        fn_addr, error, ida_hexrays.DECOMP_WARNINGS
    )
    if cfunc:
        cfunc.refresh_func_ctext()


class my_modifier_t(ida_hexrays.user_lvar_modifier_t):
    def __init__(self, var_name: str, new_type: ida_typeinf.tinfo_t):
        ida_hexrays.user_lvar_modifier_t.__init__(self)
        self.var_name = var_name
        self.new_type = new_type

    def modify_lvars(self, lvinf):
        for lvar_saved in lvinf.lvvec:
            lvar_saved: ida_hexrays.lvar_saved_info_t
            if lvar_saved.name == self.var_name:
                lvar_saved.type = self.new_type
                return True
        return False


def parse_decls_ctypes(decls: str, hti_flags: int) -> tuple[int, list[str]]:
    if sys.platform == "win32":
        import ctypes

        assert isinstance(decls, str), "decls must be a string"
        assert isinstance(hti_flags, int), "hti_flags must be an int"
        c_decls = decls.encode("utf-8")
        c_til = None
        ida_dll = ctypes.CDLL("ida")
        ida_dll.parse_decls.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_void_p,
            ctypes.c_int,
        ]
        ida_dll.parse_decls.restype = ctypes.c_int

        messages: list[str] = []

        @ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_char_p, ctypes.c_char_p)
        def magic_printer(fmt: bytes, arg1: bytes):
            if fmt.count(b"%") == 1 and b"%s" in fmt:
                formatted = fmt.replace(b"%s", arg1)
                messages.append(formatted.decode("utf-8"))
                return len(formatted) + 1
            else:
                messages.append(f"unsupported magic_printer fmt: {repr(fmt)}")
                return 0

        errors = ida_dll.parse_decls(c_til, c_decls, magic_printer, hti_flags)
    else:
        errors = ida_typeinf.parse_decls(None, decls, False, hti_flags)
        messages = []
    return errors, messages


# ============================================================================
# Core API Functions
# ============================================================================


@jsonrpc
@idaread
def meta() -> Metadata:
    """Get IDB metadata"""

    def hash(f):
        try:
            return f().hex()
        except Exception:
            return ""

    return Metadata(
        path=idaapi.get_input_file_path(),
        module=idaapi.get_root_filename(),
        base=hex(idaapi.get_imagebase()),
        size=hex(get_image_size()),
        md5=hash(ida_nalt.retrieve_input_file_md5),
        sha256=hash(ida_nalt.retrieve_input_file_sha256),
        crc32=hex(ida_nalt.retrieve_input_file_crc32()),
        filesize=hex(ida_nalt.retrieve_input_file_size()),
    )


@jsonrpc
@idaread
def fn(queries: Annotated[list[str] | str, "Address(es) or name(s)"]) -> list[dict]:
    """Get functions by address or name (auto-detects)"""
    queries = normalize_list_input(queries)

    if len(DEMANGLED_TO_EA) == 0:
        create_demangled_to_ea_map()

    results = []
    for query in queries:
        try:
            ea = idaapi.BADADDR

            # Try as address first if it looks like one
            if looks_like_address(query):
                try:
                    ea = parse_address(query)
                except Exception:
                    ea = idaapi.BADADDR

            # Fall back to name lookup
            if ea == idaapi.BADADDR:
                ea = idaapi.get_name_ea(idaapi.BADADDR, query)
                if ea == idaapi.BADADDR and query in DEMANGLED_TO_EA:
                    ea = DEMANGLED_TO_EA[query]

            if ea != idaapi.BADADDR:
                func = get_function(ea, raise_error=False)
                if func:
                    results.append({"query": query, "fn": func, "error": None})
                else:
                    results.append({"query": query, "fn": None, "error": "Not a function"})
            else:
                results.append({"query": query, "fn": None, "error": "Not found"})
        except Exception as e:
            results.append({"query": query, "fn": None, "error": str(e)})

    return results


@jsonrpc
@idaread
def cur_ea() -> str:
    """Get current address"""
    return hex(idaapi.get_screen_ea())


@jsonrpc
@idaread
def cur_fn() -> Optional[Function]:
    """Get current function"""
    return get_function(idaapi.get_screen_ea())


class ConvertedNumber(TypedDict):
    decimal: str
    hexadecimal: str
    bytes: str
    ascii: Optional[str]
    binary: str


@jsonrpc
def conv_num(
    inputs: Annotated[list[dict] | dict, "[{text, size}, ...] or {text, size}"],
) -> list[dict]:
    """Convert numbers to different formats"""
    if isinstance(inputs, dict):
        inputs = [inputs]

    results = []
    for item in inputs:
        text = item.get("text", "")
        size = item.get("size")

        try:
            value = int(text, 0)
        except ValueError:
            results.append(
                {"input": text, "result": None, "error": f"Invalid number: {text}"}
            )
            continue

        if not size:
            size = 0
            n = abs(value)
            while n:
                size += 1
                n >>= 1
            size += 7
            size //= 8

        try:
            bytes_data = value.to_bytes(size, "little", signed=True)
        except OverflowError:
            results.append(
                {
                    "input": text,
                    "result": None,
                    "error": f"Number {text} is too big for {size} bytes",
                }
            )
            continue

        ascii_str = ""
        for byte in bytes_data.rstrip(b"\x00"):
            if byte >= 32 and byte <= 126:
                ascii_str += chr(byte)
            else:
                ascii_str = None
                break

        results.append(
            {
                "input": text,
                "result": ConvertedNumber(
                    decimal=str(value),
                    hexadecimal=hex(value),
                    bytes=bytes_data.hex(" "),
                    ascii=ascii_str,
                    binary=bin(value),
                ),
                "error": None,
            }
        )

    return results


@jsonrpc
@idaread
def fns(
    queries: Annotated[
        list[dict] | dict, "[{offset, count, filter}, ...] or {offset, count, filter}"
    ],
) -> list[Page[Function]]:
    """List functions"""
    if isinstance(queries, dict):
        queries = [queries]
    elif not isinstance(queries, list):
        raise JSONRPCError(
            -32602,
            f"Invalid type for 'queries': expected list[dict] or dict, got {type(queries).__name__}",
        )

    all_functions = [get_function(addr) for addr in idautils.Functions()]

    results = []
    for query in queries:
        offset = query.get("offset", 0)
        count = query.get("count", 100)
        filter_pattern = query.get("filter", "")

        filtered = pattern_filter(all_functions, filter_pattern, "name")
        results.append(paginate(filtered, offset, count))

    return results


class Global(TypedDict):
    ea: str
    name: str


@jsonrpc
@idaread
def globs(
    queries: Annotated[
        list[dict] | dict, "[{offset, count, filter}, ...] or {offset, count, filter}"
    ],
) -> list[Page[Global]]:
    """List globals"""
    if isinstance(queries, dict):
        queries = [queries]
    elif not isinstance(queries, list):
        raise JSONRPCError(
            -32602,
            f"Invalid type for 'queries': expected list[dict] or dict, got {type(queries).__name__}",
        )

    all_globals: list[Global] = []
    for addr, name in idautils.Names():
        if not idaapi.get_func(addr) and name is not None:
            all_globals.append(Global(ea=hex(addr), name=name))

    results = []
    for query in queries:
        offset = query.get("offset", 0)
        count = query.get("count", 100)
        filter_pattern = query.get("filter", "")

        filtered = pattern_filter(all_globals, filter_pattern, "name")
        results.append(paginate(filtered, offset, count))

    return results


class Import(TypedDict):
    ea: str
    imported_name: str
    module: str


@jsonrpc
@idaread
def imports(
    offset: Annotated[int, "Offset"],
    count: Annotated[int, "Count (0=all)"],
) -> Page[Import]:
    """List imports"""
    nimps = ida_nalt.get_import_module_qty()

    rv = []
    for i in range(nimps):
        module_name = ida_nalt.get_import_module_name(i)
        if not module_name:
            module_name = "<unnamed>"

        def imp_cb(ea, symbol_name, ordinal, acc):
            if not symbol_name:
                symbol_name = f"#{ordinal}"
            acc += [Import(ea=hex(ea), imported_name=symbol_name, module=module_name)]
            return True

        def imp_cb_w_context(ea, symbol_name, ordinal):
            return imp_cb(ea, symbol_name, ordinal, rv)
        ida_nalt.enum_import_names(i, imp_cb_w_context)

    return paginate(rv, offset, count)


class String(TypedDict):
    ea: str
    length: int
    string: str


@jsonrpc
@idaread
def strings(
    queries: Annotated[
        list[dict] | dict, "[{offset, count, filter}, ...] or {offset, count, filter}"
    ],
) -> list[Page[String]]:
    """List strings"""
    if isinstance(queries, dict):
        queries = [queries]
    elif not isinstance(queries, list):
        raise JSONRPCError(
            -32602,
            f"Invalid type for 'queries': expected list[dict] or dict, got {type(queries).__name__}",
        )
    all_strings: list[String] = []
    for item in idautils.Strings():
        if item is None:
            continue
        try:
            string = str(item)
            if string:
                all_strings.append(
                    String(ea=hex(item.ea), length=item.length, string=string)
                )
        except Exception:
            continue

    results = []
    for query in queries:
        offset = query.get("offset", 0)
        count = query.get("count", 100)
        filter_pattern = query.get("filter", "")

        filtered = pattern_filter(all_strings, filter_pattern, "string")
        results.append(paginate(filtered, offset, count))

    return results


class Segment(TypedDict):
    name: str
    start: str
    end: str
    size: str
    permissions: str


def ida_segment_perm2str(perm: int) -> str:
    perms = []
    if perm & ida_segment.SEGPERM_READ:
        perms.append("r")
    else:
        perms.append("-")
    if perm & ida_segment.SEGPERM_WRITE:
        perms.append("w")
    else:
        perms.append("-")
    if perm & ida_segment.SEGPERM_EXEC:
        perms.append("x")
    else:
        perms.append("-")
    return "".join(perms)


@jsonrpc
@idaread
def segments() -> list[Segment]:
    """List all segments"""
    segments = []
    for i in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(i)
        if not seg:
            continue
        seg_name = ida_segment.get_segm_name(seg)
        segments.append(
            Segment(
                name=seg_name,
                start=hex(seg.start_ea),
                end=hex(seg.end_ea),
                size=hex(seg.end_ea - seg.start_ea),
                permissions=ida_segment_perm2str(seg.perm),
            )
        )
    return segments


@jsonrpc
@idaread
def local_types():
    """List local types"""
    error = ida_hexrays.hexrays_failure_t()
    locals = []
    idati = ida_typeinf.get_idati()
    type_count = ida_typeinf.get_ordinal_limit(idati)
    for ordinal in range(1, type_count):
        try:
            tif = ida_typeinf.tinfo_t()
            if tif.get_numbered_type(idati, ordinal):
                type_name = tif.get_type_name()
                if not type_name:
                    type_name = f"<Anonymous Type #{ordinal}>"
                locals.append(f"\nType #{ordinal}: {type_name}")
                if tif.is_udt():
                    c_decl_flags = (
                        ida_typeinf.PRTYPE_MULTI
                        | ida_typeinf.PRTYPE_TYPE
                        | ida_typeinf.PRTYPE_SEMI
                        | ida_typeinf.PRTYPE_DEF
                        | ida_typeinf.PRTYPE_METHODS
                        | ida_typeinf.PRTYPE_OFFSETS
                    )
                    c_decl_output = tif._print(None, c_decl_flags)
                    if c_decl_output:
                        locals.append(f"  C declaration:\n{c_decl_output}")
                else:
                    simple_decl = tif._print(
                        None,
                        ida_typeinf.PRTYPE_1LINE
                        | ida_typeinf.PRTYPE_TYPE
                        | ida_typeinf.PRTYPE_SEMI,
                    )
                    if simple_decl:
                        locals.append(f"  Simple declaration:\n{simple_decl}")
            else:
                message = f"\nType #{ordinal}: Failed to retrieve information."
                if error.str:
                    message += f": {error.str}"
                if error.errea != idaapi.BADADDR:
                    message += f"from (address: {hex(error.errea)})"
                raise IDAError(message)
        except Exception:
            continue
    return locals


def decompile_checked(addr: int) -> ida_hexrays.cfunc_t:
    if not ida_hexrays.init_hexrays_plugin():
        raise IDAError("Hex-Rays decompiler is not available")
    error = ida_hexrays.hexrays_failure_t()
    cfunc = ida_hexrays.decompile_func(addr, error, ida_hexrays.DECOMP_WARNINGS)
    if not cfunc:
        if error.code == ida_hexrays.MERR_LICENSE:
            raise IDAError(
                "Decompiler license is not available. Use `disassemble_function` to get the assembly code instead."
            )

        message = f"Decompilation failed at {hex(addr)}"
        if error.str:
            message += f": {error.str}"
        if error.errea != idaapi.BADADDR:
            message += f" (address: {hex(error.errea)})"
        raise IDAError(message)
    return cfunc


@jsonrpc
@idaread
def decomp(
    addrs: Annotated[list[str] | str, "Address(es)"],
) -> list[dict]:
    """Decompile functions"""
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            start = parse_address(addr)
            cfunc = decompile_checked(start)
            if is_window_active():
                ida_hexrays.open_pseudocode(start, ida_hexrays.OPF_REUSE)
            sv = cfunc.get_pseudocode()
            code = ""
            for i, sl in enumerate(sv):
                sl: ida_kernwin.simpleline_t
                item = ida_hexrays.ctree_item_t()
                ea = None if i > 0 else cfunc.entry_ea
                if cfunc.get_line_item(sl.line, 0, False, None, item, None):
                    dstr: str | None = item.dstr()
                    if dstr:
                        ds = dstr.split(": ")
                        if len(ds) == 2:
                            try:
                                ea = int(ds[0], 16)
                            except ValueError:
                                pass
                line = ida_lines.tag_remove(sl.line)
                if len(code) > 0:
                    code += "\n"
                if not ea:
                    code += f"/* line: {i} */ {line}"
                else:
                    code += f"/* line: {i}, address: {hex(ea)} */ {line}"

            results.append({"ea": addr, "code": code})
        except Exception as e:
            results.append({"ea": addr, "code": None, "error": str(e)})

    return results


class DisassemblyLine(TypedDict):
    segment: NotRequired[str]
    ea: str
    label: NotRequired[str]
    instruction: str
    comments: NotRequired[list[str]]


class Argument(TypedDict):
    name: str
    type: str


class StackFrameVariable(TypedDict):
    name: str
    offset: str
    size: str
    type: str


class DisassemblyFunction(TypedDict):
    name: str
    start_ea: str
    return_type: NotRequired[str]
    arguments: NotRequired[list[Argument]]
    stack_frame: list[StackFrameVariable]
    lines: list[DisassemblyLine]


@jsonrpc
@idaread
def disasm(
    addrs: Annotated[list[str] | str, "Address(es)"],
) -> list[dict]:
    """Disassemble functions"""
    addrs = normalize_list_input(addrs)
    results = []

    for start_addr in addrs:
        try:
            start = parse_address(start_addr)
            func = idaapi.get_func(start)
            if not func:
                results.append(
                    {"ea": start_addr, "asm": None, "error": "No function found"}
                )
                continue
            if is_window_active():
                ida_kernwin.jumpto(start)

            func_name: str = ida_funcs.get_func_name(func.start_ea) or "<unnamed>"

            lines: list[DisassemblyLine] = []
            for ea in idautils.FuncItems(func.start_ea):
                if ea == idaapi.BADADDR:
                    continue

                seg = idaapi.getseg(ea)
                segment: str | None = idaapi.get_segm_name(seg) if seg else None

                label: str | None = idc.get_name(ea, 0)
                if not label or (label == func_name and ea == func.start_ea):
                    label = None

                comments: list[str] = []
                c: str | None = idaapi.get_cmt(ea, False)
                if c:
                    comments.append(c)
                c = idaapi.get_cmt(ea, True)
                if c:
                    comments.append(c)

                mnem: str = idc.print_insn_mnem(ea) or ""
                ops: list[str] = []
                for n in range(8):
                    if idc.get_operand_type(ea, n) == idaapi.o_void:
                        break
                    ops.append(idc.print_operand(ea, n) or "")
                instruction = f"{mnem} {', '.join(ops)}".rstrip()

                line: DisassemblyLine = {"ea": hex(ea), "instruction": instruction}
                if segment:
                    line["segment"] = segment
                if label:
                    line["label"] = label
                if comments:
                    line["comments"] = comments
                lines.append(line)

            rettype = None
            args: Optional[list[Argument]] = None
            tif = ida_typeinf.tinfo_t()
            if ida_nalt.get_tinfo(tif, func.start_ea) and tif.is_func():
                ftd = ida_typeinf.func_type_data_t()
                if tif.get_func_details(ftd):
                    rettype = str(ftd.rettype)
                    args = [
                        Argument(name=(a.name or f"arg{i}"), type=str(a.type))
                        for i, a in enumerate(ftd)
                    ]

            out: DisassemblyFunction = {
                "name": func_name,
                "start_ea": hex(func.start_ea),
                "stack_frame": get_stack_frame_variables_internal(func.start_ea, False),
                "lines": lines,
            }
            if rettype:
                out["return_type"] = rettype
            if args is not None:
                out["arguments"] = args

            results.append({"ea": start_addr, "asm": out})
        except Exception as e:
            results.append({"ea": start_addr, "asm": None, "error": str(e)})

    return results


class Xref(TypedDict):
    ea: str
    type: str
    fn: Optional[Function]


@jsonrpc
@idaread
def xrefs_to(
    addrs: Annotated[list[str] | str, "Address(es)"],
) -> list[dict]:
    """Get xrefs to addresses"""
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            xrefs = []
            xref: ida_xref.xrefblk_t
            for xref in idautils.XrefsTo(parse_address(addr)):
                xrefs += [
                    Xref(
                        ea=hex(xref.frm),
                        type="code" if xref.iscode else "data",
                        fn=get_function(xref.frm, raise_error=False),
                    )
                ]
            results.append({"ea": addr, "xrefs": xrefs})
        except Exception as e:
            results.append({"ea": addr, "xrefs": None, "error": str(e)})

    return results


@jsonrpc
@idaread
def xrefs_to_field(
    queries: Annotated[list[dict] | dict, "[{struct, field}, ...] or {struct, field}"],
) -> list[dict]:
    """Get xrefs to struct fields"""
    if isinstance(queries, dict):
        queries = [queries]

    results = []
    til = ida_typeinf.get_idati()
    if not til:
        return [
            {
                "struct": q.get("struct"),
                "field": q.get("field"),
                "xrefs": [],
                "error": "Failed to retrieve type library",
            }
            for q in queries
        ]

    for query in queries:
        struct_name = query.get("struct", "")
        field_name = query.get("field", "")

        try:
            tif = ida_typeinf.tinfo_t()
            if not tif.get_named_type(
                til, struct_name, ida_typeinf.BTF_STRUCT, True, False
            ):
                results.append(
                    {
                        "struct": struct_name,
                        "field": field_name,
                        "xrefs": [],
                        "error": f"Struct '{struct_name}' not found",
                    }
                )
                continue

            idx = ida_typeinf.get_udm_by_fullname(None, struct_name + "." + field_name)
            if idx == -1:
                results.append(
                    {
                        "struct": struct_name,
                        "field": field_name,
                        "xrefs": [],
                        "error": f"Field '{field_name}' not found in '{struct_name}'",
                    }
                )
                continue

            tid = tif.get_udm_tid(idx)
            if tid == ida_idaapi.BADADDR:
                results.append(
                    {
                        "struct": struct_name,
                        "field": field_name,
                        "xrefs": [],
                        "error": "Unable to get tid",
                    }
                )
                continue

            xrefs = []
            xref: ida_xref.xrefblk_t
            for xref in idautils.XrefsTo(tid):
                xrefs += [
                    Xref(
                        ea=hex(xref.frm),
                        type="code" if xref.iscode else "data",
                        fn=get_function(xref.frm, raise_error=False),
                    )
                ]
            results.append({"struct": struct_name, "field": field_name, "xrefs": xrefs})
        except Exception as e:
            results.append(
                {
                    "struct": struct_name,
                    "field": field_name,
                    "xrefs": [],
                    "error": str(e),
                }
            )

    return results


@jsonrpc
@idaread
def callees(
    addrs: Annotated[list[str] | str, "Address(es)"],
) -> list[dict]:
    """Get function callees"""
    addrs = normalize_list_input(addrs)
    results = []

    for fn_addr in addrs:
        try:
            func_start = parse_address(fn_addr)
            func = idaapi.get_func(func_start)
            if not func:
                results.append(
                    {"ea": fn_addr, "callees": None, "error": "No function found"}
                )
                continue
            func_end = idc.find_func_end(func_start)
            callees: list[dict[str, str]] = []
            current_ea = func_start
            while current_ea < func_end:
                insn = idaapi.insn_t()
                idaapi.decode_insn(insn, current_ea)
                if insn.itype in [idaapi.NN_call, idaapi.NN_callfi, idaapi.NN_callni]:
                    target = idc.get_operand_value(current_ea, 0)
                    target_type = idc.get_operand_type(current_ea, 0)
                    if target_type in [idaapi.o_mem, idaapi.o_near, idaapi.o_far]:
                        func_type = (
                            "internal"
                            if idaapi.get_func(target) is not None
                            else "external"
                        )
                        func_name = idc.get_name(target)
                        if func_name is not None:
                            callees.append(
                                {
                                    "ea": hex(target),
                                    "name": func_name,
                                    "type": func_type,
                                }
                            )
                current_ea = idc.next_head(current_ea, func_end)

            unique_callee_tuples = {tuple(callee.items()) for callee in callees}
            unique_callees = [dict(callee) for callee in unique_callee_tuples]
            results.append({"ea": fn_addr, "callees": unique_callees})
        except Exception as e:
            results.append({"ea": fn_addr, "callees": None, "error": str(e)})

    return results


@jsonrpc
@idaread
def callers(
    addrs: Annotated[list[str] | str, "Address(es)"],
) -> list[dict]:
    """Get function callers"""
    addrs = normalize_list_input(addrs)
    results = []

    for fn_addr in addrs:
        try:
            callers = {}
            for caller_addr in idautils.CodeRefsTo(parse_address(fn_addr), 0):
                func = get_function(caller_addr, raise_error=False)
                if not func:
                    continue
                insn = idaapi.insn_t()
                idaapi.decode_insn(insn, caller_addr)
                if insn.itype not in [
                    idaapi.NN_call,
                    idaapi.NN_callfi,
                    idaapi.NN_callni,
                ]:
                    continue
                callers[func["ea"]] = func

            results.append({"ea": fn_addr, "callers": list(callers.values())})
        except Exception as e:
            results.append({"ea": fn_addr, "callers": None, "error": str(e)})

    return results


@jsonrpc
@idaread
def entrypoints() -> list[Function]:
    """Get entry points"""
    result = []
    for i in range(ida_entry.get_entry_qty()):
        ordinal = ida_entry.get_entry_ordinal(i)
        addr = ida_entry.get_entry(ordinal)
        func = get_function(addr, raise_error=False)
        if func is not None:
            result.append(func)
    return result


# ============================================================================
# Modification Operations (Comments, Renaming, Types)
# ============================================================================


@jsonrpc
@idawrite
def set_cmt(
    items: Annotated[list[dict] | dict, "[{addr, comment}, ...] or {addr, comment}"],
):
    """Set comments"""
    if isinstance(items, dict):
        items = [items]

    results = []
    for item in items:
        addr_str = item.get("ea", "")
        comment = item.get("comment", "")

        try:
            ea = parse_address(addr_str)

            if not idaapi.set_cmt(ea, comment, False):
                results.append(
                    {
                        "ea": addr_str,
                        "error": f"Failed to set disassembly comment at {hex(ea)}",
                    }
                )
                continue

            if not ida_hexrays.init_hexrays_plugin():
                results.append({"ea": addr_str, "ok": True})
                continue

            try:
                cfunc = decompile_checked(ea)
            except IDAError:
                results.append({"ea": addr_str, "ok": True})
                continue

            if ea == cfunc.entry_ea:
                idc.set_func_cmt(ea, comment, True)
                cfunc.refresh_func_ctext()
                results.append({"ea": addr_str, "ok": True})
                continue

            eamap = cfunc.get_eamap()
            if ea not in eamap:
                results.append(
                    {
                        "ea": addr_str,
                        "ok": True,
                        "error": f"Failed to set decompiler comment at {hex(ea)}",
                    }
                )
                continue
            nearest_ea = eamap[ea][0].ea

            if cfunc.has_orphan_cmts():
                cfunc.del_orphan_cmts()
                cfunc.save_user_cmts()

            tl = idaapi.treeloc_t()
            tl.ea = nearest_ea
            for itp in range(idaapi.ITP_SEMI, idaapi.ITP_COLON):
                tl.itp = itp
                cfunc.set_user_cmt(tl, comment)
                cfunc.save_user_cmts()
                cfunc.refresh_func_ctext()
                if not cfunc.has_orphan_cmts():
                    results.append({"ea": addr_str, "ok": True})
                    break
                cfunc.del_orphan_cmts()
                cfunc.save_user_cmts()
            else:
                results.append(
                    {
                        "ea": addr_str,
                        "ok": True,
                        "error": f"Failed to set decompiler comment at {hex(ea)}",
                    }
                )
        except Exception as e:
            results.append({"ea": addr_str, "error": str(e)})

    return results


@jsonrpc
@idawrite
def patch_asm(
    items: Annotated[list[dict] | dict, "[{addr, asm}, ...] or {addr, asm}"],
) -> list[dict]:
    """Patch assembly"""
    if isinstance(items, dict):
        items = [items]

    results = []
    for item in items:
        addr_str = item.get("ea", "")
        instructions = item.get("asm", "")

        try:
            ea = parse_address(addr_str)
            assembles = instructions.split(";")
            for assemble in assembles:
                assemble = assemble.strip()
                try:
                    (check_assemble, bytes_to_patch) = idautils.Assemble(ea, assemble)
                    if not check_assemble:
                        results.append(
                            {"ea": addr_str, "error": f"Failed to assemble: {assemble}"}
                        )
                        break
                    ida_bytes.patch_bytes(ea, bytes_to_patch)
                    ea += len(bytes_to_patch)
                except Exception as e:
                    results.append(
                        {"ea": addr_str, "error": f"Failed at {hex(ea)}: {e}"}
                    )
                    break
            else:
                results.append({"ea": addr_str, "ok": True})
        except Exception as e:
            results.append({"ea": addr_str, "error": str(e)})

    return results


def get_global_variable_value_internal(ea: int) -> str:
    tif = ida_typeinf.tinfo_t()
    if not ida_nalt.get_tinfo(tif, ea):
        if not ida_bytes.has_any_name(ea):
            raise IDAError(f"Failed to get type information for variable at {ea:#x}")

        size = ida_bytes.get_item_size(ea)
        if size == 0:
            raise IDAError(f"Failed to get type information for variable at {ea:#x}")
    else:
        size = tif.get_size()

    if size == 0 and tif.is_array() and tif.get_array_element().is_decl_char():
        return_string = idaapi.get_strlit_contents(ea, -1, 0).decode("utf-8").strip()
        return f'"{return_string}"'
    elif size == 1:
        return hex(ida_bytes.get_byte(ea))
    elif size == 2:
        return hex(ida_bytes.get_word(ea))
    elif size == 4:
        return hex(ida_bytes.get_dword(ea))
    elif size == 8:
        return hex(ida_bytes.get_qword(ea))
    else:
        return " ".join(hex(x) for x in ida_bytes.get_bytes(ea, size))


@jsonrpc
@idaread
def gvar_value(queries: Annotated[list[str] | str, "Address(es) or name(s)"]) -> list[dict]:
    """Read global var values by address or name (auto-detects)"""
    queries = normalize_list_input(queries)
    results = []

    for query in queries:
        try:
            ea = idaapi.BADADDR

            # Try as address first if it looks like one
            if looks_like_address(query):
                try:
                    ea = parse_address(query)
                except Exception:
                    ea = idaapi.BADADDR

            # Fall back to name lookup
            if ea == idaapi.BADADDR:
                ea = idaapi.get_name_ea(idaapi.BADADDR, query)

            if ea == idaapi.BADADDR:
                results.append({"query": query, "value": None, "error": "Not found"})
                continue

            value = get_global_variable_value_internal(ea)
            results.append({"query": query, "value": value, "error": None})
        except Exception as e:
            results.append({"query": query, "value": None, "error": str(e)})

    return results


@jsonrpc
@idawrite
def declare_type(decls: Annotated[list[str] | str, "C decl(s)"]) -> list[dict]:
    """Declare types"""
    decls = normalize_list_input(decls)
    results = []

    for decl in decls:
        try:
            flags = ida_typeinf.PT_SIL | ida_typeinf.PT_EMPTY | ida_typeinf.PT_TYP
            errors, messages = parse_decls_ctypes(decl, flags)

            pretty_messages = "\n".join(messages)
            if errors > 0:
                results.append(
                    {"decl": decl, "error": f"Failed to parse:\n{pretty_messages}"}
                )
            else:
                results.append({"decl": decl, "ok": True})
        except Exception as e:
            results.append({"decl": decl, "error": str(e)})

    return results


# ============================================================================
# Memory Reading Operations
# ============================================================================


@jsonrpc
@idaread
def get_bytes(
    addrs: Annotated[list[dict] | dict, "[{addr, size}, ...] or {addr, size}"],
) -> list[dict]:
    """Read bytes"""
    if isinstance(addrs, dict):
        addrs = [addrs]

    results = []
    for item in addrs:
        addr = item.get("ea", "")
        size = item.get("size", 0)

        try:
            ea = parse_address(addr)
            data = " ".join(f"{x:#02x}" for x in ida_bytes.get_bytes(ea, size))
            results.append({"ea": addr, "data": data})
        except Exception as e:
            results.append({"ea": addr, "data": None, "error": str(e)})

    return results


@jsonrpc
@idaread
def get_u8(addrs: Annotated[list[str] | str, "Address(es)"]) -> list[dict]:
    """Read uint8"""
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)
            value = ida_bytes.get_wide_byte(ea)
            results.append({"ea": addr, "value": value})
        except Exception as e:
            results.append({"ea": addr, "value": None, "error": str(e)})

    return results


@jsonrpc
@idaread
def get_u16(addrs: Annotated[list[str] | str, "Address(es)"]) -> list[dict]:
    """Read uint16"""
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)
            value = ida_bytes.get_wide_word(ea)
            results.append({"ea": addr, "value": value})
        except Exception as e:
            results.append({"ea": addr, "value": None, "error": str(e)})

    return results


@jsonrpc
@idaread
def get_u32(addrs: Annotated[list[str] | str, "Address(es)"]) -> list[dict]:
    """Read uint32"""
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)
            value = ida_bytes.get_wide_dword(ea)
            results.append({"ea": addr, "value": value})
        except Exception as e:
            results.append({"ea": addr, "value": None, "error": str(e)})

    return results


@jsonrpc
@idaread
def get_u64(addrs: Annotated[list[str] | str, "Address(es)"]) -> list[dict]:
    """Read uint64"""
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)
            value = ida_bytes.get_qword(ea)
            results.append({"ea": addr, "value": value})
        except Exception as e:
            results.append({"ea": addr, "value": None, "error": str(e)})

    return results


@jsonrpc
@idaread
def get_string(addrs: Annotated[list[str] | str, "Address(es)"]) -> list[dict]:
    """Read strings"""
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)
            value = idaapi.get_strlit_contents(ea, -1, 0).decode("utf-8")
            results.append({"ea": addr, "value": value})
        except Exception as e:
            results.append({"ea": addr, "value": None, "error": str(e)})

    return results


# ============================================================================
# Stack Frame Operations
# ============================================================================


def get_stack_frame_variables_internal(
    fn_addr: int, raise_error: bool
) -> list[StackFrameVariable]:
    if ida_major < 9:
        return []

    func = idaapi.get_func(fn_addr)
    if not func:
        if raise_error:
            raise IDAError(f"No function found at address {fn_addr}")
        return []

    tif = ida_typeinf.tinfo_t()
    if not tif.get_type_by_tid(func.frame) or not tif.is_udt():
        return []

    members: list[StackFrameVariable] = []
    udt = ida_typeinf.udt_type_data_t()
    tif.get_udt_details(udt)
    for udm in udt:
        if not udm.is_gap():
            name = udm.name
            offset = udm.offset // 8
            size = udm.size // 8
            type = str(udm.type)
            members.append(
                StackFrameVariable(
                    name=name, offset=hex(offset), size=hex(size), type=type
                )
            )
    return members


@jsonrpc
@idaread
def stack_vars(addrs: Annotated[list[str] | str, "Address(es)"]) -> list[dict]:
    """Get stack vars"""
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)
            vars = get_stack_frame_variables_internal(ea, True)
            results.append({"ea": addr, "vars": vars})
        except Exception as e:
            results.append({"ea": addr, "vars": None, "error": str(e)})

    return results


@jsonrpc
@idawrite
def create_stkvar(
    items: Annotated[
        list[dict] | dict, "[{ea, offset, name, type}, ...] or {ea, offset, name, type}"
    ],
):
    """Create stack vars"""
    if isinstance(items, dict):
        items = [items]

    results = []
    for item in items:
        fn_addr = item.get("ea", "")
        offset = item.get("offset", "")
        var_name = item.get("name", "")
        type_name = item.get("type", "")

        try:
            func = idaapi.get_func(parse_address(fn_addr))
            if not func:
                results.append(
                    {"ea": fn_addr, "name": var_name, "error": "No function found"}
                )
                continue

            ea = parse_address(offset)

            frame_tif = ida_typeinf.tinfo_t()
            if not ida_frame.get_func_frame(frame_tif, func):
                results.append(
                    {"ea": fn_addr, "name": var_name, "error": "No frame returned"}
                )
                continue

            tif = get_type_by_name(type_name)
            if not ida_frame.define_stkvar(func, var_name, ea, tif):
                results.append(
                    {"ea": fn_addr, "name": var_name, "error": "Failed to define"}
                )
                continue

            results.append({"ea": fn_addr, "name": var_name, "ok": True})
        except Exception as e:
            results.append({"ea": fn_addr, "name": var_name, "error": str(e)})

    return results


@jsonrpc
@idawrite
def delete_stkvar(
    items: Annotated[list[dict] | dict, "[{ea, name}, ...] or {ea, name}"],
):
    """Delete stack vars"""
    if isinstance(items, dict):
        items = [items]

    results = []
    for item in items:
        fn_addr = item.get("ea", "")
        var_name = item.get("name", "")

        try:
            func = idaapi.get_func(parse_address(fn_addr))
            if not func:
                results.append(
                    {"ea": fn_addr, "name": var_name, "error": "No function found"}
                )
                continue

            frame_tif = ida_typeinf.tinfo_t()
            if not ida_frame.get_func_frame(frame_tif, func):
                results.append(
                    {"ea": fn_addr, "name": var_name, "error": "No frame returned"}
                )
                continue

            idx, udm = frame_tif.get_udm(var_name)
            if not udm:
                results.append(
                    {"ea": fn_addr, "name": var_name, "error": f"{var_name} not found"}
                )
                continue

            tid = frame_tif.get_udm_tid(idx)
            if ida_frame.is_special_frame_member(tid):
                results.append(
                    {
                        "ea": fn_addr,
                        "name": var_name,
                        "error": f"{var_name} is special frame member",
                    }
                )
                continue

            udm = ida_typeinf.udm_t()
            frame_tif.get_udm_by_tid(udm, tid)
            offset = udm.offset // 8
            size = udm.size // 8
            if ida_frame.is_funcarg_off(func, offset):
                results.append(
                    {
                        "ea": fn_addr,
                        "name": var_name,
                        "error": f"{var_name} is argument member",
                    }
                )
                continue

            if not ida_frame.delete_frame_members(func, offset, offset + size):
                results.append(
                    {"ea": fn_addr, "name": var_name, "error": "Failed to delete"}
                )
                continue

            results.append({"ea": fn_addr, "name": var_name, "ok": True})
        except Exception as e:
            results.append({"ea": fn_addr, "name": var_name, "error": str(e)})

    return results


# ============================================================================
# Structure Operations
# ============================================================================


class StructureMember(TypedDict):
    name: str
    offset: str
    size: str
    type: str


class StructureDefinition(TypedDict):
    name: str
    size: str
    members: list[StructureMember]


@jsonrpc
@idaread
def structs() -> list[StructureDefinition]:
    """List all structures"""
    rv = []
    limit = ida_typeinf.get_ordinal_limit()
    for ordinal in range(1, limit):
        tif = ida_typeinf.tinfo_t()
        tif.get_numbered_type(None, ordinal)
        if tif.is_udt():
            udt = ida_typeinf.udt_type_data_t()
            members = []
            if tif.get_udt_details(udt):
                members = [
                    StructureMember(
                        name=x.name,
                        offset=hex(x.offset // 8),
                        size=hex(x.size // 8),
                        type=str(x.type),
                    )
                    for _, x in enumerate(udt)
                ]

            rv += [
                StructureDefinition(
                    name=tif.get_type_name(), size=hex(tif.get_size()), members=members
                )
            ]

    return rv


@jsonrpc
@idaread
def struct_info(names: Annotated[list[str] | str, "Struct name(s)"]) -> list[dict]:
    """Get struct info"""
    names = normalize_list_input(names)
    results = []

    for name in names:
        try:
            tif = ida_typeinf.tinfo_t()
            if not tif.get_named_type(None, name):
                results.append({"name": name, "error": f"Struct '{name}' not found"})
                continue

            result = {
                "name": name,
                "type": str(tif._print()),
                "size": tif.get_size(),
                "is_udt": tif.is_udt(),
            }

            if not tif.is_udt():
                result["error"] = "Not a user-defined type"
                results.append({"name": name, "info": result})
                continue

            udt_data = ida_typeinf.udt_type_data_t()
            if not tif.get_udt_details(udt_data):
                result["error"] = "Failed to get struct details"
                results.append({"name": name, "info": result})
                continue

            result["cardinality"] = udt_data.size()
            result["is_union"] = udt_data.is_union
            result["udt_type"] = "Union" if udt_data.is_union else "Struct"

            members = []
            for i, member in enumerate(udt_data):
                offset = member.begin() // 8
                size = member.size // 8 if member.size > 0 else member.type.get_size()
                member_type = member.type._print()
                member_name = member.name

                member_info = {
                    "index": i,
                    "offset": f"0x{offset:08X}",
                    "size": size,
                    "type": member_type,
                    "name": member_name,
                    "is_nested_udt": member.type.is_udt(),
                }

                if member.type.is_udt():
                    member_info["nested_size"] = member.type.get_size()

                members.append(member_info)

            result["members"] = members
            result["total_size"] = tif.get_size()

            results.append({"name": name, "info": result})
        except Exception as e:
            results.append({"name": name, "error": str(e)})

    return results


@jsonrpc
@idaread
def struct_at(
    queries: Annotated[list[dict] | dict, "[{addr, struct}, ...] or {addr, struct}"],
) -> list[dict]:
    """Read struct fields"""
    if isinstance(queries, dict):
        queries = [queries]

    results = []
    for query in queries:
        addr_str = query.get("ea", "")
        struct_name = query.get("struct", "")

        try:
            addr = parse_address(addr_str)

            tif = ida_typeinf.tinfo_t()
            if not tif.get_named_type(None, struct_name):
                results.append(
                    {
                        "ea": addr_str,
                        "struct": struct_name,
                        "members": None,
                        "error": f"Struct '{struct_name}' not found",
                    }
                )
                continue

            udt_data = ida_typeinf.udt_type_data_t()
            if not tif.get_udt_details(udt_data):
                results.append(
                    {
                        "ea": addr_str,
                        "struct": struct_name,
                        "members": None,
                        "error": "Failed to get struct details",
                    }
                )
                continue

            members = []
            for member in udt_data:
                offset = member.begin() // 8
                member_addr = addr + offset
                member_type = member.type._print()
                member_name = member.name
                member_size = member.type.get_size()

                try:
                    if member.type.is_ptr():
                        is_64bit = (
                            ida_ida.inf_is_64bit()
                            if ida_major >= 9
                            else idaapi.get_inf_structure().is_64bit()
                        )
                        if is_64bit:
                            value = idaapi.get_qword(member_addr)
                            value_str = f"0x{value:016X}"
                        else:
                            value = idaapi.get_dword(member_addr)
                            value_str = f"0x{value:08X}"
                    elif member_size == 1:
                        value = idaapi.get_byte(member_addr)
                        value_str = f"0x{value:02X} ({value})"
                    elif member_size == 2:
                        value = idaapi.get_word(member_addr)
                        value_str = f"0x{value:04X} ({value})"
                    elif member_size == 4:
                        value = idaapi.get_dword(member_addr)
                        value_str = f"0x{value:08X} ({value})"
                    elif member_size == 8:
                        value = idaapi.get_qword(member_addr)
                        value_str = f"0x{value:016X} ({value})"
                    else:
                        bytes_data = []
                        for i in range(min(member_size, 16)):
                            try:
                                byte_val = idaapi.get_byte(member_addr + i)
                                bytes_data.append(f"{byte_val:02X}")
                            except Exception:
                                break
                        value_str = f"[{' '.join(bytes_data)}{'...' if member_size > 16 else ''}]"
                except Exception:
                    value_str = "<failed to read>"

                member_info = {
                    "offset": f"0x{offset:08X}",
                    "type": member_type,
                    "name": member_name,
                    "value": value_str,
                }

                members.append(member_info)

            results.append({"ea": addr_str, "struct": struct_name, "members": members})
        except Exception as e:
            results.append(
                {
                    "ea": addr_str,
                    "struct": struct_name,
                    "members": None,
                    "error": str(e),
                }
            )

    return results


@jsonrpc
@idaread
def struct_get(names: Annotated[list[str] | str, "Struct name(s)"]) -> list[dict]:
    """Get struct info"""
    names = normalize_list_input(names)
    results = []

    for name in names:
        try:
            tif = ida_typeinf.tinfo_t()
            if not tif.get_named_type(None, name):
                results.append({"name": name, "error": f"Struct '{name}' not found"})
                continue

            info = {
                "name": name,
                "type": tif._print(),
                "size": tif.get_size(),
                "is_udt": tif.is_udt(),
            }

            if tif.is_udt():
                udt_data = ida_typeinf.udt_type_data_t()
                if tif.get_udt_details(udt_data):
                    info["cardinality"] = udt_data.size()
                    info["is_union"] = udt_data.is_union

                    members = []
                    for member in udt_data:
                        members.append(
                            {
                                "name": member.name,
                                "type": member.type._print(),
                                "offset": member.begin() // 8,
                                "size": member.type.get_size(),
                            }
                        )
                    info["members"] = members

            results.append({"name": name, "info": info})
        except Exception as e:
            results.append({"name": name, "error": str(e)})

    return results


@jsonrpc
@idaread
def search_structs(filter: Annotated[str, "Filter pattern"]) -> list[dict]:
    """Search structs"""
    results = []
    limit = ida_typeinf.get_ordinal_limit()

    for ordinal in range(1, limit):
        tif = ida_typeinf.tinfo_t()
        if tif.get_numbered_type(None, ordinal):
            type_name: str = tif.get_type_name()
            if type_name and filter.lower() in type_name.lower():
                if tif.is_udt():
                    udt_data = ida_typeinf.udt_type_data_t()
                    cardinality = 0
                    if tif.get_udt_details(udt_data):
                        cardinality = udt_data.size()

                    results.append(
                        {
                            "name": type_name,
                            "size": tif.get_size(),
                            "cardinality": cardinality,
                            "is_union": udt_data.is_union
                            if tif.get_udt_details(udt_data)
                            else False,
                            "ordinal": ordinal,
                        }
                    )

    return results


# ============================================================================
# Debugger Operations
# ============================================================================


class RegisterValue(TypedDict):
    name: str
    value: str


class ThreadRegisters(TypedDict):
    thread_id: int
    registers: list[RegisterValue]


GENERAL_PURPOSE_REGISTERS = {
    "EAX",
    "EBX",
    "ECX",
    "EDX",
    "ESI",
    "EDI",
    "EBP",
    "ESP",
    "EIP",
    "RAX",
    "RBX",
    "RCX",
    "RDX",
    "RSI",
    "RDI",
    "RBP",
    "RSP",
    "RIP",
    "R8",
    "R9",
    "R10",
    "R11",
    "R12",
    "R13",
    "R14",
    "R15",
}


def dbg_ensure_running() -> "ida_idd.debugger_t":
    dbg = ida_idd.get_dbg()
    if not dbg:
        raise IDAError("Debugger not running")
    if ida_dbg.get_ip_val() is None:
        raise IDAError("Debugger not running")
    return dbg


def _get_registers_for_thread(dbg: "ida_idd.debugger_t", tid: int) -> ThreadRegisters:
    """Helper to get registers for a specific thread."""
    regs = []
    regvals: ida_idd.regvals_t = ida_dbg.get_reg_vals(tid)
    for reg_index, rv in enumerate(regvals):
        rv: ida_idd.regval_t
        reg_info = dbg.regs(reg_index)

        try:
            reg_value = rv.pyval(reg_info.dtype)
        except ValueError:
            reg_value = ida_idaapi.BADADDR

        if isinstance(reg_value, int):
            reg_value = hex(reg_value)
        if isinstance(reg_value, bytes):
            reg_value = reg_value.hex(" ")
        else:
            reg_value = str(reg_value)
        regs.append(
            RegisterValue(
                name=reg_info.name,
                value=reg_value,
            )
        )
    return ThreadRegisters(
        thread_id=tid,
        registers=regs,
    )


def _get_registers_general_for_thread(
    dbg: "ida_idd.debugger_t", tid: int
) -> ThreadRegisters:
    """Helper to get general-purpose registers for a specific thread."""
    all_registers = _get_registers_for_thread(dbg, tid)
    general_registers = [
        reg
        for reg in all_registers["registers"]
        if reg["name"] in GENERAL_PURPOSE_REGISTERS
    ]
    return ThreadRegisters(
        thread_id=tid,
        registers=general_registers,
    )


def _get_registers_specific_for_thread(
    dbg: "ida_idd.debugger_t", tid: int, register_names: list[str]
) -> ThreadRegisters:
    """Helper to get specific registers for a given thread."""
    all_registers = _get_registers_for_thread(dbg, tid)
    specific_registers = [
        reg for reg in all_registers["registers"] if reg["name"] in register_names
    ]
    return ThreadRegisters(
        thread_id=tid,
        registers=specific_registers,
    )


@jsonrpc
@idaread
@unsafe
def dbg_regs() -> list[ThreadRegisters]:
    """Get all registers"""
    result: list[ThreadRegisters] = []
    dbg = dbg_ensure_running()
    for thread_index in range(ida_dbg.get_thread_qty()):
        tid = ida_dbg.getn_thread(thread_index)
        result.append(_get_registers_for_thread(dbg, tid))
    return result


@jsonrpc
@idaread
@unsafe
def dbg_regs_thread(tids: Annotated[list[int] | int, "Thread ID(s)"]) -> list[dict]:
    """Get thread registers"""
    if isinstance(tids, int):
        tids = [tids]

    dbg = dbg_ensure_running()
    available_tids = [ida_dbg.getn_thread(i) for i in range(ida_dbg.get_thread_qty())]
    results = []

    for tid in tids:
        try:
            if tid not in available_tids:
                results.append(
                    {"tid": tid, "regs": None, "error": f"Thread {tid} not found"}
                )
                continue
            regs = _get_registers_for_thread(dbg, tid)
            results.append({"tid": tid, "regs": regs})
        except Exception as e:
            results.append({"tid": tid, "regs": None, "error": str(e)})

    return results


@jsonrpc
@idaread
@unsafe
def dbg_regs_cur() -> ThreadRegisters:
    """Get current thread registers"""
    dbg = dbg_ensure_running()
    tid = ida_dbg.get_current_thread()
    return _get_registers_for_thread(dbg, tid)


@jsonrpc
@idaread
@unsafe
def dbg_gpregs_thread(tids: Annotated[list[int] | int, "Thread ID(s)"]) -> list[dict]:
    """Get GP registers for threads"""
    if isinstance(tids, int):
        tids = [tids]

    dbg = dbg_ensure_running()
    available_tids = [ida_dbg.getn_thread(i) for i in range(ida_dbg.get_thread_qty())]
    results = []

    for tid in tids:
        try:
            if tid not in available_tids:
                results.append(
                    {"tid": tid, "regs": None, "error": f"Thread {tid} not found"}
                )
                continue
            regs = _get_registers_general_for_thread(dbg, tid)
            results.append({"tid": tid, "regs": regs})
        except Exception as e:
            results.append({"tid": tid, "regs": None, "error": str(e)})

    return results


@jsonrpc
@idaread
@unsafe
def dbg_gpregs_cur() -> ThreadRegisters:
    """Get current thread GP registers"""
    dbg = dbg_ensure_running()
    tid = ida_dbg.get_current_thread()
    return _get_registers_general_for_thread(dbg, tid)


@jsonrpc
@idaread
@unsafe
def dbg_regs_for_thread(
    thread_id: Annotated[int, "Thread ID"],
    register_names: Annotated[str, "Reg names (comma-sep)"],
) -> ThreadRegisters:
    """Get specific thread registers"""
    dbg = dbg_ensure_running()
    if thread_id not in [
        ida_dbg.getn_thread(i) for i in range(ida_dbg.get_thread_qty())
    ]:
        raise IDAError(f"Thread with ID {thread_id} not found")
    names = [name.strip() for name in register_names.split(",")]
    return _get_registers_specific_for_thread(dbg, thread_id, names)


@jsonrpc
@idaread
@unsafe
def dbg_regs_for_cur(
    register_names: Annotated[str, "Reg names (comma-sep)"],
) -> ThreadRegisters:
    """Get specific current thread registers"""
    dbg = dbg_ensure_running()
    tid = ida_dbg.get_current_thread()
    names = [name.strip() for name in register_names.split(",")]
    return _get_registers_specific_for_thread(dbg, tid, names)


@jsonrpc
@idaread
@unsafe
def dbg_callstack() -> list[dict[str, str]]:
    """Get call stack"""
    callstack = []
    try:
        tid = ida_dbg.get_current_thread()
        trace = ida_idd.call_stack_t()

        if not ida_dbg.collect_stack_trace(tid, trace):
            return []
        for frame in trace:
            frame_info = {
                "ea": hex(frame.callea),
            }
            try:
                module_info = ida_idd.modinfo_t()
                if ida_dbg.get_module_info(frame.callea, module_info):
                    frame_info["module"] = os.path.basename(module_info.name)
                else:
                    frame_info["module"] = "<unknown>"

                name = (
                    ida_name.get_nice_colored_name(
                        frame.callea,
                        ida_name.GNCN_NOCOLOR
                        | ida_name.GNCN_NOLABEL
                        | ida_name.GNCN_NOSEG
                        | ida_name.GNCN_PREFDBG,
                    )
                    or "<unnamed>"
                )
                frame_info["symbol"] = name

            except Exception as e:
                frame_info["module"] = "<error>"
                frame_info["symbol"] = str(e)

            callstack.append(frame_info)

    except Exception:
        pass
    return callstack


class Breakpoint(TypedDict):
    ea: str
    enabled: bool
    condition: Optional[str]


def list_breakpoints():
    breakpoints: list[Breakpoint] = []
    for i in range(ida_dbg.get_bpt_qty()):
        bpt = ida_dbg.bpt_t()
        if ida_dbg.getn_bpt(i, bpt):
            breakpoints.append(
                Breakpoint(
                    ea=hex(bpt.ea),
                    enabled=bpt.flags & ida_dbg.BPT_ENABLED,
                    condition=str(bpt.condition) if bpt.condition else None,
                )
            )
    return breakpoints


@jsonrpc
@idaread
@unsafe
def dbg_breakpoints():
    """List breakpoints"""
    return list_breakpoints()


@jsonrpc
@idaread
@unsafe
def dbg_start():
    """Start debugger"""
    if len(list_breakpoints()) == 0:
        for i in range(ida_entry.get_entry_qty()):
            ordinal = ida_entry.get_entry_ordinal(i)
            addr = ida_entry.get_entry(ordinal)
            if addr != ida_idaapi.BADADDR:
                ida_dbg.add_bpt(addr, 0, idaapi.BPT_SOFT)

    if idaapi.start_process("", "", "") == 1:
        ip = ida_dbg.get_ip_val()
        if ip is not None:
            return hex(ip)
    raise IDAError("Failed to start debugger")


@jsonrpc
@idaread
@unsafe
def dbg_exit():
    """Exit debugger"""
    dbg_ensure_running()
    if idaapi.exit_process():
        return
    raise IDAError("Failed to exit debugger")


@jsonrpc
@idaread
@unsafe
def dbg_continue() -> str:
    """Continue debugger"""
    dbg_ensure_running()
    if idaapi.continue_process():
        ip = ida_dbg.get_ip_val()
        if ip is not None:
            return hex(ip)
    raise IDAError("Failed to continue debugger")


@jsonrpc
@idaread
@unsafe
def dbg_run_to(
    addr: Annotated[str, "Address"],
):
    """Run to address"""
    dbg_ensure_running()
    ea = parse_address(addr)
    if idaapi.run_to(ea):
        ip = ida_dbg.get_ip_val()
        if ip is not None:
            return hex(ip)
    raise IDAError(f"Failed to run to address {hex(ea)}")


@jsonrpc
@idaread
@unsafe
def dbg_bp_add(addrs: Annotated[list[str] | str, "Address(es)"]) -> list[dict]:
    """Add breakpoints"""
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)
            if idaapi.add_bpt(ea, 0, idaapi.BPT_SOFT):
                results.append({"ea": addr, "ok": True})
            else:
                breakpoints = list_breakpoints()
                for bpt in breakpoints:
                    if bpt["ea"] == hex(ea):
                        results.append({"ea": addr, "ok": True})
                        break
                else:
                    results.append({"ea": addr, "error": "Failed to set breakpoint"})
        except Exception as e:
            results.append({"ea": addr, "error": str(e)})

    return results


@jsonrpc
@idaread
@unsafe
def dbg_stepi():
    """Step into"""
    dbg_ensure_running()
    if idaapi.step_into():
        ip = ida_dbg.get_ip_val()
        if ip is not None:
            return hex(ip)
    raise IDAError("Failed to step into")


@jsonrpc
@idaread
@unsafe
def dbg_step():
    """Step over"""
    dbg_ensure_running()
    if idaapi.step_over():
        ip = ida_dbg.get_ip_val()
        if ip is not None:
            return hex(ip)
    raise IDAError("Failed to step over")


@jsonrpc
@idaread
@unsafe
def dbg_bp_del(addrs: Annotated[list[str] | str, "Address(es)"]) -> list[dict]:
    """Delete breakpoints"""
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)
            if idaapi.del_bpt(ea):
                results.append({"ea": addr, "ok": True})
            else:
                results.append({"ea": addr, "error": "Failed to delete breakpoint"})
        except Exception as e:
            results.append({"ea": addr, "error": str(e)})

    return results


@jsonrpc
@idaread
@unsafe
def dbg_bp_enable(
    items: Annotated[list[dict] | dict, "[{addr, enabled}, ...] or {addr, enabled}"],
) -> list[dict]:
    """Enable/disable breakpoints"""
    if isinstance(items, dict):
        items = [items]

    results = []
    for item in items:
        addr = item.get("ea", "")
        enable = item.get("enabled", True)

        try:
            ea = parse_address(addr)
            if idaapi.enable_bpt(ea, enable):
                results.append({"ea": addr, "ok": True})
            else:
                results.append(
                    {
                        "ea": addr,
                        "error": f"Failed to {'enable' if enable else 'disable'} breakpoint",
                    }
                )
        except Exception as e:
            results.append({"ea": addr, "error": str(e)})

    return results


# ============================================================================
# Advanced Analysis Operations
# ============================================================================


@jsonrpc
@unsafe
def py_eval(
    code: Annotated[str, "Python code"],
) -> str:
    """Execute Python code in IDA context. Returns string result. Has access to all IDA API modules. Supports Jupyter-style evaluation."""
    try:
        # Create execution context with IDA modules (lazy import to avoid errors)
        def lazy_import(module_name):
            try:
                return __import__(module_name)
            except Exception:
                return None

        exec_globals = {
            "__builtins__": __builtins__,
            "idaapi": idaapi,
            "idc": idc,
            "idautils": lazy_import("idautils"),
            "ida_allins": lazy_import("ida_allins"),
            "ida_auto": lazy_import("ida_auto"),
            "ida_bitrange": lazy_import("ida_bitrange"),
            "ida_bytes": ida_bytes,
            "ida_dbg": ida_dbg,
            "ida_dirtree": lazy_import("ida_dirtree"),
            "ida_diskio": lazy_import("ida_diskio"),
            "ida_entry": ida_entry,
            "ida_expr": lazy_import("ida_expr"),
            "ida_fixup": lazy_import("ida_fixup"),
            "ida_fpro": lazy_import("ida_fpro"),
            "ida_frame": ida_frame,
            "ida_funcs": ida_funcs,
            "ida_gdl": lazy_import("ida_gdl"),
            "ida_graph": lazy_import("ida_graph"),
            "ida_hexrays": ida_hexrays,
            "ida_ida": ida_ida,
            "ida_idd": lazy_import("ida_idd"),
            "ida_idp": lazy_import("ida_idp"),
            "ida_ieee": lazy_import("ida_ieee"),
            "ida_kernwin": ida_kernwin,
            "ida_libfuncs": lazy_import("ida_libfuncs"),
            "ida_lines": ida_lines,
            "ida_loader": lazy_import("ida_loader"),
            "ida_merge": lazy_import("ida_merge"),
            "ida_mergemod": lazy_import("ida_mergemod"),
            "ida_moves": lazy_import("ida_moves"),
            "ida_nalt": ida_nalt,
            "ida_name": ida_name,
            "ida_netnode": lazy_import("ida_netnode"),
            "ida_offset": lazy_import("ida_offset"),
            "ida_pro": lazy_import("ida_pro"),
            "ida_problems": lazy_import("ida_problems"),
            "ida_range": lazy_import("ida_range"),
            "ida_regfinder": lazy_import("ida_regfinder"),
            "ida_registry": lazy_import("ida_registry"),
            "ida_search": lazy_import("ida_search"),
            "ida_segment": ida_segment,
            "ida_segregs": lazy_import("ida_segregs"),
            "ida_srclang": lazy_import("ida_srclang"),
            "ida_strlist": lazy_import("ida_strlist"),
            "ida_struct": lazy_import("ida_struct"),
            "ida_tryblks": lazy_import("ida_tryblks"),
            "ida_typeinf": ida_typeinf,
            "ida_ua": lazy_import("ida_ua"),
            "ida_undo": lazy_import("ida_undo"),
            "ida_xref": ida_xref,
            "ida_enum": lazy_import("ida_enum"),
            "parse_address": parse_address,
            "get_function": get_function,
        }

        # Try evaluation first (for simple expressions)
        try:
            result = eval(code, exec_globals)
            return str(result)
        except Exception:
            pass

        # Execute as statements
        exec_locals = {}
        exec(code, exec_globals, exec_locals)

        # Merge locals into globals for multi-statement blocks
        exec_globals.update(exec_locals)

        # Try to eval the last line as an expression (Jupyter-style)
        lines = code.strip().split("\n")
        if lines:
            last_line = lines[-1].strip()
            if last_line and not last_line.startswith(
                (
                    "#",
                    "import ",
                    "from ",
                    "def ",
                    "class ",
                    "if ",
                    "for ",
                    "while ",
                    "with ",
                    "try:",
                )
            ):
                try:
                    result = eval(last_line, exec_globals)
                    return str(result)
                except Exception:
                    pass

        # Return 'result' variable if explicitly set
        if "result" in exec_locals:
            return str(exec_locals["result"])

        # Return last assigned variable
        if exec_locals:
            last_key = list(exec_locals.keys())[-1]
            return str(exec_locals[last_key])

        return "Code executed successfully (no return value)"
    except Exception:
        import traceback

        return f"Error executing Python code:\n{traceback.format_exc()}"


# ============================================================================
# Batch Analysis Operations
# ============================================================================


class FunctionAnalysis(TypedDict):
    ea: str
    name: Optional[str]
    code: Optional[str]
    asm: Optional[list]
    xto: list[Xref]
    xfrom: list[Xref]
    callees: list[dict]
    callers: list[Function]
    strings: list[String]
    constants: list[dict]
    blocks: list[dict]
    error: Optional[str]


def get_callees(addr: str) -> list[dict]:
    """Get callees for a single function address"""
    try:
        func_start = parse_address(addr)
        func = idaapi.get_func(func_start)
        if not func:
            return []
        func_end = idc.find_func_end(func_start)
        callees: list[dict[str, str]] = []
        current_ea = func_start
        while current_ea < func_end:
            insn = idaapi.insn_t()
            idaapi.decode_insn(insn, current_ea)
            if insn.itype in [idaapi.NN_call, idaapi.NN_callfi, idaapi.NN_callni]:
                target = idc.get_operand_value(current_ea, 0)
                target_type = idc.get_operand_type(current_ea, 0)
                if target_type in [idaapi.o_mem, idaapi.o_near, idaapi.o_far]:
                    func_type = (
                        "internal"
                        if idaapi.get_func(target) is not None
                        else "external"
                    )
                    func_name = idc.get_name(target)
                    if func_name is not None:
                        callees.append(
                            {
                                "ea": hex(target),
                                "name": func_name,
                                "type": func_type,
                            }
                        )
            current_ea = idc.next_head(current_ea, func_end)

        unique_callee_tuples = {tuple(callee.items()) for callee in callees}
        unique_callees = [dict(callee) for callee in unique_callee_tuples]
        return unique_callees
    except Exception:
        return []


def get_callers(addr: str) -> list[Function]:
    """Get callers for a single function address"""
    try:
        callers = {}
        for caller_addr in idautils.CodeRefsTo(parse_address(addr), 0):
            func = get_function(caller_addr, raise_error=False)
            if not func:
                continue
            insn = idaapi.insn_t()
            idaapi.decode_insn(insn, caller_addr)
            if insn.itype not in [
                idaapi.NN_call,
                idaapi.NN_callfi,
                idaapi.NN_callni,
            ]:
                continue
            callers[func["ea"]] = func

        return list(callers.values())
    except Exception:
        return []


def get_xrefs_from_internal(ea: int) -> list[Xref]:
    """Get all xrefs from an address"""
    xrefs = []
    for xref in idautils.XrefsFrom(ea, 0):
        xrefs.append(
            Xref(
                ea=hex(xref.to),
                type="code" if xref.iscode else "data",
                fn=get_function(xref.to, raise_error=False),
            )
        )
    return xrefs


def extract_function_strings(ea: int) -> list[String]:
    """Extract string references from a function"""
    func = idaapi.get_func(ea)
    if not func:
        return []

    strings = []
    for item_ea in idautils.FuncItems(func.start_ea):
        for xref in idautils.XrefsFrom(item_ea, 0):
            if not xref.iscode:
                # Check if target is a string
                str_type = ida_nalt.get_str_type(xref.to)
                if str_type != ida_nalt.STRTYPE_C:
                    continue
                try:
                    str_content = idc.get_strlit_contents(xref.to)
                    if str_content:
                        strings.append(
                            String(
                                ea=hex(xref.to),
                                length=len(str_content),
                                string=str_content.decode("utf-8", errors="replace"),
                            )
                        )
                except Exception:
                    pass
    return strings


def extract_function_constants(ea: int) -> list[dict]:
    """Extract immediate constants from a function"""
    func = idaapi.get_func(ea)
    if not func:
        return []

    constants = []
    for item_ea in idautils.FuncItems(func.start_ea):
        insn = idaapi.insn_t()
        if idaapi.decode_insn(insn, item_ea) > 0:
            for op in insn.ops:
                if op.type == idaapi.o_imm:
                    constants.append(
                        {
                            "ea": hex(item_ea),
                            "value": hex(op.value),
                            "decimal": op.value,
                        }
                    )
    return constants


def decompile_function_safe(ea: int) -> Optional[str]:
    """Safely decompile a function, returning None on failure"""
    try:
        if not ida_hexrays.init_hexrays_plugin():
            return None
        error = ida_hexrays.hexrays_failure_t()
        cfunc = ida_hexrays.decompile_func(ea, error, ida_hexrays.DECOMP_WARNINGS)
        if not cfunc:
            return None
        sv = cfunc.get_pseudocode()
        return "\n".join(ida_lines.tag_remove(sl.line) for sl in sv)
    except Exception:
        return None


def get_assembly_lines(ea: int) -> list[dict]:
    """Get assembly lines for a function"""
    func = idaapi.get_func(ea)
    if not func:
        return []

    lines = []
    for item_ea in idautils.FuncItems(func.start_ea):
        mnem = idc.print_insn_mnem(item_ea) or ""
        ops = []
        for n in range(8):
            if idc.get_operand_type(item_ea, n) == idaapi.o_void:
                break
            ops.append(idc.print_operand(item_ea, n) or "")
        lines.append(
            {"ea": hex(item_ea), "instruction": f"{mnem} {', '.join(ops)}".rstrip()}
        )
    return lines


def get_all_xrefs(ea: int) -> dict:
    """Get all xrefs to and from an address"""
    return {
        "to": [
            {"ea": hex(x.frm), "type": "code" if x.iscode else "data"}
            for x in idautils.XrefsTo(ea, 0)
        ],
        "from": [
            {"ea": hex(x.to), "type": "code" if x.iscode else "data"}
            for x in idautils.XrefsFrom(ea, 0)
        ],
    }


def get_all_comments(ea: int) -> dict:
    """Get all comments for an address"""
    func = idaapi.get_func(ea)
    if not func:
        return {}

    comments = {}
    for item_ea in idautils.FuncItems(func.start_ea):
        cmt = idaapi.get_cmt(item_ea, False)
        if cmt:
            comments[hex(item_ea)] = {"regular": cmt}
        cmt = idaapi.get_cmt(item_ea, True)
        if cmt:
            if hex(item_ea) not in comments:
                comments[hex(item_ea)] = {}
            comments[hex(item_ea)]["repeatable"] = cmt
    return comments


@jsonrpc
@idaread
def analyze_fns(addrs: Annotated[list[str], "Address(es)"]) -> list[FunctionAnalysis]:
    """Analyze functions: decomp, xrefs, callees, strings"""
    results = []
    for addr in addrs:
        try:
            ea = parse_address(addr)
            func = idaapi.get_func(ea)

            if not func:
                results.append(
                    FunctionAnalysis(
                        ea=addr,
                        name=None,
                        code=None,
                        asm=None,
                        xto=[],
                        xfrom=[],
                        callees=[],
                        callers=[],
                        strings=[],
                        constants=[],
                        blocks=[],
                        error="Function not found",
                    )
                )
                continue

            # Get basic blocks
            flowchart = idaapi.FlowChart(func)
            blocks = []
            for block in flowchart:
                blocks.append(
                    {
                        "start": hex(block.start_ea),
                        "end": hex(block.end_ea),
                        "type": block.type,
                    }
                )

            result = FunctionAnalysis(
                ea=addr,
                name=ida_funcs.get_func_name(func.start_ea),
                code=decompile_function_safe(ea),
                asm=get_assembly_lines(ea),
                xto=[
                    Xref(
                        ea=hex(x.frm),
                        type="code" if x.iscode else "data",
                        fn=get_function(x.frm, raise_error=False),
                    )
                    for x in idautils.XrefsTo(ea, 0)
                ],
                xfrom=get_xrefs_from_internal(ea),
                callees=get_callees(addr),
                callers=get_callers(addr),
                strings=extract_function_strings(ea),
                constants=extract_function_constants(ea),
                blocks=blocks,
                error=None,
            )
            results.append(result)
        except Exception as e:
            results.append(
                FunctionAnalysis(
                    ea=addr,
                    name=None,
                    code=None,
                    asm=None,
                    xto=[],
                    xfrom=[],
                    callees=[],
                    callers=[],
                    strings=[],
                    constants=[],
                    blocks=[],
                    error=str(e),
                )
            )
    return results


# ============================================================================
# Pattern Matching & Signature Tools
# ============================================================================


class PatternMatch(TypedDict):
    pattern: str
    matches: list[str]
    count: int


@jsonrpc
@idaread
def find_bytes(
    patterns: Annotated[list[str], "Byte patterns (e.g. '48 8B ?? ??')"],
) -> list[PatternMatch]:
    """Find byte patterns"""
    results = []
    for pattern in patterns:
        matches = []
        try:
            # Parse the pattern
            compiled = ida_bytes.compiled_binpat_vec_t()
            err = ida_bytes.parse_binpat_str(
                compiled, ida_ida.inf_get_min_ea(), pattern, 16
            )
            if err:
                results.append(PatternMatch(pattern=pattern, matches=[], count=0))
                continue

            # Search for matches
            ea = ida_ida.inf_get_min_ea()
            while ea != idaapi.BADADDR:
                ea = ida_bytes.bin_search(
                    ea, ida_ida.inf_get_max_ea(), compiled, ida_bytes.BIN_SEARCH_FORWARD
                )
                if ea != idaapi.BADADDR:
                    matches.append(hex(ea))
                    ea += 1
        except Exception:
            pass

        results.append(
            PatternMatch(pattern=pattern, matches=matches, count=len(matches))
        )
    return results


class CodePattern(TypedDict):
    mnemonic: str
    operands: NotRequired[list[str]]


@jsonrpc
@idaread
def find_insns(
    sequences: Annotated[list[list[str]], "Instruction sequences"],
) -> list[dict]:
    """Find instruction sequences"""
    results = []

    for sequence in sequences:
        if not sequence:
            results.append({"sequence": sequence, "matches": [], "count": 0})
            continue

        matches = []
        # Scan all code segments
        for seg_ea in idautils.Segments():
            seg = idaapi.getseg(seg_ea)
            if not seg or not (seg.perm & idaapi.SEGPERM_EXEC):
                continue

            ea = seg.start_ea
            while ea < seg.end_ea:
                # Try to match sequence starting at ea
                match_ea = ea
                matched = True

                for expected_mnem in sequence:
                    insn = idaapi.insn_t()
                    if idaapi.decode_insn(insn, match_ea) == 0:
                        matched = False
                        break

                    actual_mnem = idc.print_insn_mnem(match_ea)
                    if actual_mnem != expected_mnem:
                        matched = False
                        break

                    match_ea = idc.next_head(match_ea, seg.end_ea)
                    if match_ea == idaapi.BADADDR:
                        matched = False
                        break

                if matched:
                    matches.append(hex(ea))

                ea = idc.next_head(ea, seg.end_ea)
                if ea == idaapi.BADADDR:
                    break

        results.append(
            {"sequence": sequence, "matches": matches, "count": len(matches)}
        )

    return results


# ============================================================================
# Control Flow Analysis
# ============================================================================


class BasicBlock(TypedDict):
    start: str
    end: str
    size: int
    type: int
    successors: list[str]
    predecessors: list[str]


@jsonrpc
@idaread
def basic_blocks(addrs: Annotated[list[str], "Address(es)"]) -> list[dict]:
    """Get basic blocks"""
    results = []
    for fn_addr in addrs:
        try:
            ea = parse_address(fn_addr)
            func = idaapi.get_func(ea)
            if not func:
                results.append(
                    {"ea": fn_addr, "error": "Function not found", "blocks": []}
                )
                continue

            flowchart = idaapi.FlowChart(func)
            blocks = []
            for block in flowchart:
                blocks.append(
                    BasicBlock(
                        start=hex(block.start_ea),
                        end=hex(block.end_ea),
                        size=block.end_ea - block.start_ea,
                        type=block.type,
                        successors=[hex(succ.start_ea) for succ in block.succs()],
                        predecessors=[hex(pred.start_ea) for pred in block.preds()],
                    )
                )

            results.append(
                {"ea": fn_addr, "blocks": blocks, "count": len(blocks), "error": None}
            )
        except Exception as e:
            results.append({"ea": fn_addr, "error": str(e), "blocks": []})
    return results


@jsonrpc
@idaread
def find_paths(
    queries: Annotated[
        list[dict] | dict, "Source/target pairs or single {source, target}"
    ],
) -> list[dict]:
    """Find execution paths"""
    queries = normalize_dict_list(queries)
    results = []

    for query in queries:
        source = parse_address(query["source"])
        target = parse_address(query["target"])

        # Get containing function
        func = idaapi.get_func(source)
        if not func:
            results.append(
                {
                    "source": query["source"],
                    "target": query["target"],
                    "paths": [],
                    "reachable": False,
                    "error": "Source not in a function",
                }
            )
            continue

        # Build flow graph
        flowchart = idaapi.FlowChart(func)

        # Find source and target blocks
        source_block = None
        target_block = None
        for block in flowchart:
            if block.start_ea <= source < block.end_ea:
                source_block = block
            if block.start_ea <= target < block.end_ea:
                target_block = block

        if not source_block or not target_block:
            results.append(
                {
                    "source": query["source"],
                    "target": query["target"],
                    "paths": [],
                    "reachable": False,
                    "error": "Could not find basic blocks",
                }
            )
            continue

        # Simple BFS to find paths
        paths = []
        queue = [([source_block], {source_block.id})]

        while queue and len(paths) < 10:  # Limit paths
            path, visited = queue.pop(0)
            current = path[-1]

            if current.id == target_block.id:
                paths.append([hex(b.start_ea) for b in path])
                continue

            for succ in current.succs():
                if succ.id not in visited and len(path) < 20:  # Limit depth
                    queue.append((path + [succ], visited | {succ.id}))

        results.append(
            {
                "source": query["source"],
                "target": query["target"],
                "paths": paths,
                "reachable": len(paths) > 0,
                "error": None,
            }
        )

    return results


# ============================================================================
# Type Inference & Application
# ============================================================================


@jsonrpc
@idawrite
def apply_types(
    applications: Annotated[
        list[dict] | dict,
        "[{kind, ea, type, ...}, ...] or {kind, ea, type, ...}. kind: function|global|local|stkvar",
    ],
) -> list[dict]:
    """Apply types (function/global/local/stkvar)"""
    applications = normalize_dict_list(applications)
    results = []

    for app in applications:
        try:
            kind = app["kind"]

            if kind == "function":
                func = idaapi.get_func(parse_address(app["ea"]))
                if not func:
                    results.append({"edit": app, "error": "Function not found"})
                    continue

                tif = ida_typeinf.tinfo_t(app["signature"], None, ida_typeinf.PT_SIL)
                if not tif.is_func():
                    results.append({"edit": app, "error": "Not a function type"})
                    continue

                success = ida_typeinf.apply_tinfo(
                    func.start_ea, tif, ida_typeinf.PT_SIL
                )
                results.append(
                    {
                        "edit": app,
                        "ok": success,
                        "error": None if success else "Failed to apply type",
                    }
                )

            elif kind == "global":
                ea = idaapi.get_name_ea(idaapi.BADADDR, app.get("name", ""))
                if ea == idaapi.BADADDR:
                    ea = parse_address(app["ea"])

                tif = get_type_by_name(app["type"])
                success = ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.PT_SIL)
                results.append(
                    {
                        "edit": app,
                        "ok": success,
                        "error": None if success else "Failed to apply type",
                    }
                )

            elif kind == "local":
                func = idaapi.get_func(parse_address(app["ea"]))
                if not func:
                    results.append({"edit": app, "error": "Function not found"})
                    continue

                new_tif = ida_typeinf.tinfo_t(app["type"], None, ida_typeinf.PT_SIL)
                modifier = my_modifier_t(app["variable"], new_tif)
                success = ida_hexrays.modify_user_lvars(func.start_ea, modifier)
                results.append(
                    {
                        "edit": app,
                        "ok": success,
                        "error": None if success else "Failed to apply type",
                    }
                )

            elif kind == "stkvar":
                func = idaapi.get_func(parse_address(app["ea"]))
                if not func:
                    results.append({"edit": app, "error": "No function found"})
                    continue

                frame_tif = ida_typeinf.tinfo_t()
                if not ida_frame.get_func_frame(frame_tif, func):
                    results.append({"edit": app, "error": "No frame"})
                    continue

                idx, udm = frame_tif.get_udm(app["name"])
                if not udm:
                    results.append({"edit": app, "error": f"{app['name']} not found"})
                    continue

                tid = frame_tif.get_udm_tid(idx)
                udm = ida_typeinf.udm_t()
                frame_tif.get_udm_by_tid(udm, tid)
                offset = udm.offset // 8

                tif = get_type_by_name(app["type"])
                success = ida_frame.set_frame_member_type(func, offset, tif)
                results.append(
                    {
                        "edit": app,
                        "ok": success,
                        "error": None if success else "Failed to set type",
                    }
                )

            else:
                results.append({"edit": app, "error": f"Unknown kind: {kind}"})

        except Exception as e:
            results.append({"edit": app, "error": str(e)})

    return results


@jsonrpc
@idaread
def infer_types(addrs: Annotated[list[str], "Address(es)"]) -> list[dict]:
    """Infer types"""
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)
            tif = ida_typeinf.tinfo_t()

            # Try Hex-Rays inference
            if ida_hexrays.init_hexrays_plugin() and ida_hexrays.guess_tinfo(tif, ea):
                results.append(
                    {
                        "ea": addr,
                        "inferred_type": str(tif),
                        "method": "hexrays",
                        "confidence": "high",
                    }
                )
                continue

            # Try getting existing type info
            if ida_nalt.get_tinfo(tif, ea):
                results.append(
                    {
                        "ea": addr,
                        "inferred_type": str(tif),
                        "method": "existing",
                        "confidence": "high",
                    }
                )
                continue

            # Try to guess from size
            size = ida_bytes.get_item_size(ea)
            if size > 0:
                type_guess = {
                    1: "uint8_t",
                    2: "uint16_t",
                    4: "uint32_t",
                    8: "uint64_t",
                }.get(size, f"uint8_t[{size}]")

                results.append(
                    {
                        "ea": addr,
                        "inferred_type": type_guess,
                        "method": "size_based",
                        "confidence": "low",
                    }
                )
                continue

            results.append(
                {
                    "ea": addr,
                    "inferred_type": None,
                    "method": None,
                    "confidence": "none",
                }
            )

        except Exception as e:
            results.append(
                {
                    "ea": addr,
                    "inferred_type": None,
                    "method": None,
                    "confidence": "none",
                    "error": str(e),
                }
            )

    return results


# ============================================================================
# Advanced Search Operations
# ============================================================================


@jsonrpc
@idaread
def search(
    queries: Annotated[list[dict] | dict, "[{type, ...}, ...] or {type, ...}"],
) -> list[dict]:
    """Search (type: 'immediate'|'string'|'data_ref'|'code_ref')"""
    queries = normalize_dict_list(queries)
    results = []

    for query in queries:
        try:
            query_type = query.get("type")
            matches = []

            if query_type == "immediate":
                # Search for immediate values
                value = query.get("value", 0)
                start_ea = parse_address(
                    query.get("start", hex(ida_ida.inf_get_min_ea()))
                )

                ea = start_ea
                while ea != idaapi.BADADDR:
                    ea = ida_search.find_imm(ea, ida_search.SEARCH_DOWN, value)
                    if ea != idaapi.BADADDR:
                        matches.append(hex(ea))
                        ea = idc.next_head(ea, ida_ida.inf_get_max_ea())

            elif query_type == "string":
                # Search for strings containing pattern
                pattern = query.get("pattern", "")
                for s in idautils.Strings():
                    if pattern.lower() in str(s).lower():
                        matches.append(hex(s.ea))

            elif query_type == "data_ref":
                # Find all data references to a target
                target_str = query.get("target")
                if target_str is None:
                    continue
                target = parse_address(target_str)
                for xref in idautils.DataRefsTo(target):
                    matches.append(hex(xref))

            elif query_type == "code_ref":
                # Find all code references to a target
                target_str = query.get("target")
                if target_str is None:
                    continue
                target = parse_address(target_str)
                for xref in idautils.CodeRefsTo(target, 0):
                    matches.append(hex(xref))

            results.append(
                {
                    "query": query,
                    "matches": matches,
                    "count": len(matches),
                    "error": None,
                }
            )

        except Exception as e:
            results.append({"query": query, "matches": [], "count": 0, "error": str(e)})

    return results


# ============================================================================
# Export Operations
# ============================================================================


@jsonrpc
@idaread
def export_fns(
    addrs: Annotated[list[str], "Address(es)"],
    format: Annotated[str, "Format: json|c_header|prototypes"] = "json",
) -> dict:
    """Export functions"""
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)
            func = idaapi.get_func(ea)
            if not func:
                results.append({"ea": addr, "error": "Function not found"})
                continue

            func_data = {
                "ea": addr,
                "name": ida_funcs.get_func_name(func.start_ea),
                "prototype": get_prototype(func),
                "size": hex(func.end_ea - func.start_ea),
                "comments": get_all_comments(ea),
            }

            if format == "json":
                func_data["asm"] = get_assembly_lines(ea)
                func_data["code"] = decompile_function_safe(ea)
                func_data["xrefs"] = get_all_xrefs(ea)

            results.append(func_data)

        except Exception as e:
            results.append({"ea": addr, "error": str(e)})

    if format == "c_header":
        # Generate C header file
        lines = ["// Auto-generated by IDA Pro MCP", ""]
        for func in results:
            if "prototype" in func and func["prototype"]:
                lines.append(f"{func['prototype']};")
        return {"format": "c_header", "content": "\n".join(lines)}

    elif format == "prototypes":
        # Just prototypes
        prototypes = []
        for func in results:
            if "prototype" in func and func["prototype"]:
                prototypes.append(
                    {"name": func.get("name"), "prototype": func["prototype"]}
                )
        return {"format": "prototypes", "functions": prototypes}

    return {"format": "json", "functions": results}


# ============================================================================
# Graph Operations
# ============================================================================


@jsonrpc
@idaread
def callgraph(
    roots: Annotated[list[str], "Root addresses"],
    max_depth: Annotated[int, "Max depth"] = 5,
) -> list[dict]:
    """Get call graph"""
    results = []

    for root in roots:
        try:
            ea = parse_address(root)
            func = idaapi.get_func(ea)
            if not func:
                results.append(
                    {
                        "root": root,
                        "error": "Function not found",
                        "nodes": [],
                        "edges": [],
                    }
                )
                continue

            nodes = {}
            edges = []
            visited = set()

            def traverse(addr, depth):
                if depth > max_depth or addr in visited:
                    return
                visited.add(addr)

                f = idaapi.get_func(addr)
                if not f:
                    return

                func_name = ida_funcs.get_func_name(f.start_ea)
                nodes[hex(addr)] = {"ea": hex(addr), "name": func_name, "depth": depth}

                # Get callees
                for item_ea in idautils.FuncItems(f.start_ea):
                    for xref in idautils.CodeRefsFrom(item_ea, 0):
                        callee_func = idaapi.get_func(xref)
                        if callee_func:
                            edges.append(
                                {
                                    "from": hex(addr),
                                    "to": hex(callee_func.start_ea),
                                    "type": "call",
                                }
                            )
                            traverse(callee_func.start_ea, depth + 1)

            traverse(ea, 0)

            results.append(
                {
                    "root": root,
                    "nodes": list(nodes.values()),
                    "edges": edges,
                    "max_depth": max_depth,
                    "error": None,
                }
            )

        except Exception as e:
            results.append({"root": root, "error": str(e), "nodes": [], "edges": []})

    return results


# ============================================================================
# Batch Renaming
# ============================================================================


@jsonrpc
@idawrite
def rename_all(
    renamings: Annotated[
        list[dict] | dict,
        "[{type, ea, old, new}, ...] or {type, ea, old, new}. type: function|global|local|stkvar",
    ],
) -> list[dict]:
    """Rename anything (function/global/local/stkvar)"""
    renamings = normalize_dict_list(renamings)
    results = []

    for item in renamings:
        try:
            item_type = item["type"]
            success = False

            if item_type == "function":
                ea = parse_address(item["ea"])
                success = idaapi.set_name(ea, item["new"], idaapi.SN_CHECK)
                if success:
                    func = idaapi.get_func(ea)
                    if func:
                        refresh_decompiler_ctext(func.start_ea)

            elif item_type == "global":
                ea = idaapi.get_name_ea(idaapi.BADADDR, item["old"])
                if ea != idaapi.BADADDR:
                    success = idaapi.set_name(ea, item["new"], idaapi.SN_CHECK)

            elif item_type == "local":
                func = idaapi.get_func(parse_address(item["ea"]))
                if func:
                    success = ida_hexrays.rename_lvar(
                        func.start_ea, item["old"], item["new"]
                    )
                    if success:
                        refresh_decompiler_ctext(func.start_ea)

            elif item_type == "stkvar":
                func = idaapi.get_func(parse_address(item["ea"]))
                if not func:
                    results.append({"item": item, "error": "No function found"})
                    continue

                frame_tif = ida_typeinf.tinfo_t()
                if not ida_frame.get_func_frame(frame_tif, func):
                    results.append({"item": item, "error": "No frame"})
                    continue

                idx, udm = frame_tif.get_udm(item["old"])
                if not udm:
                    results.append({"item": item, "error": f"{item['old']} not found"})
                    continue

                tid = frame_tif.get_udm_tid(idx)
                if ida_frame.is_special_frame_member(tid):
                    results.append({"item": item, "error": "Special frame member"})
                    continue

                udm = ida_typeinf.udm_t()
                frame_tif.get_udm_by_tid(udm, tid)
                offset = udm.offset // 8
                if ida_frame.is_funcarg_off(func, offset):
                    results.append({"item": item, "error": "Argument member"})
                    continue

                sval = ida_frame.soff_to_fpoff(func, offset)
                success = ida_frame.define_stkvar(func, item["new"], sval, udm.type)

            results.append(
                {
                    "item": item,
                    "ok": success,
                    "error": None if success else "Rename failed",
                }
            )

        except Exception as e:
            results.append({"item": item, "error": str(e)})

    return results


# ============================================================================
# Memory Operations (Debugging)
# ============================================================================


@jsonrpc
@idaread
@unsafe
def dbg_read_mem(
    regions: Annotated[list[dict] | dict, "[{ea, size}, ...] or {ea, size}"],
) -> list[dict]:
    """Read debug memory"""
    regions = normalize_dict_list(regions)
    dbg_ensure_running()
    results = []

    for region in regions:
        try:
            addr = parse_address(region["ea"])
            size = region["size"]

            data = idaapi.dbg_read_memory(addr, size)
            if data:
                results.append(
                    {
                        "ea": region["ea"],
                        "size": len(data),
                        "data": data.hex(),
                        "error": None,
                    }
                )
            else:
                results.append(
                    {
                        "ea": region["ea"],
                        "size": 0,
                        "data": None,
                        "error": "Failed to read memory",
                    }
                )

        except Exception as e:
            results.append(
                {"ea": region.get("ea"), "size": 0, "data": None, "error": str(e)}
            )

    return results


@jsonrpc
@idaread
@unsafe
def dbg_write_mem(
    regions: Annotated[
        list[dict] | dict, "[{ea, data (hex)}, ...] or {ea, data (hex)}"
    ],
) -> list[dict]:
    """Write debug memory"""
    regions = normalize_dict_list(regions)
    dbg_ensure_running()
    results = []

    for region in regions:
        try:
            addr = parse_address(region["ea"])
            data = bytes.fromhex(region["data"])

            success = idaapi.dbg_write_memory(addr, data)
            results.append(
                {
                    "ea": region["ea"],
                    "size": len(data) if success else 0,
                    "ok": success,
                    "error": None if success else "Write failed",
                }
            )

        except Exception as e:
            results.append({"ea": region.get("ea"), "size": 0, "error": str(e)})

    return results


# ============================================================================
# Batch Data Operations
# ============================================================================


@jsonrpc
@idawrite
def put_bytes(
    patches: Annotated[
        list[dict] | dict, "[{ea, data (hex)}, ...] or {ea, data (hex)}"
    ],
) -> list[dict]:
    """Patch bytes"""
    patches = normalize_dict_list(patches)
    results = []

    for patch in patches:
        try:
            ea = parse_address(patch["ea"])
            data = bytes.fromhex(patch["data"])

            ida_bytes.patch_bytes(ea, data)
            results.append(
                {"ea": patch["ea"], "size": len(data), "ok": True, "error": None}
            )

        except Exception as e:
            results.append({"ea": patch.get("ea"), "size": 0, "error": str(e)})

    return results


# ============================================================================
# Cross-Reference Analysis
# ============================================================================


@jsonrpc
@idaread
def xref_matrix(entities: Annotated[list[str], "Address(es)"]) -> dict:
    """Build xref matrix"""
    matrix = {}

    for source in entities:
        try:
            source_ea = parse_address(source)
            matrix[source] = {}

            for target in entities:
                if source == target:
                    continue

                target_ea = parse_address(target)

                # Count references from source to target
                count = 0
                for xref in idautils.XrefsFrom(source_ea, 0):
                    if xref.to == target_ea:
                        count += 1

                if count > 0:
                    matrix[source][target] = count

        except Exception:
            matrix[source] = {"error": "Failed to process"}

    return {"matrix": matrix, "entities": entities}


# ============================================================================
# String Analysis
# ============================================================================


@jsonrpc
@idaread
def analyze_strings(
    filters: Annotated[
        list[dict] | dict,
        "[{pattern, min_length, ...}, ...] or {pattern, min_length, ...}",
    ],
) -> list[dict]:
    """Analyze strings"""
    filters = normalize_dict_list(filters)
    all_strings = []

    # Collect all strings once
    for s in idautils.Strings():
        try:
            all_strings.append(
                {
                    "ea": hex(s.ea),
                    "length": s.length,
                    "string": str(s),
                    "type": s.strtype,
                }
            )
        except Exception:
            pass

    results = []
    for filt in filters:
        pattern = filt.get("pattern", "").lower()
        min_length = filt.get("min_length", 0)

        matches = []
        for s in all_strings:
            if len(s["string"]) < min_length:
                continue
            if pattern and pattern not in s["string"].lower():
                continue

            # Add xref info
            s_ea = parse_address(s["ea"])
            xrefs = [hex(x.frm) for x in idautils.XrefsTo(s_ea, 0)]

            matches.append({**s, "xrefs": xrefs, "xref_count": len(xrefs)})

        results.append({"filter": filt, "matches": matches, "count": len(matches)})

    return results


class MCP(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "MCP Plugin"
    help = "MCP"
    wanted_name = "MCP"
    wanted_hotkey = "Ctrl-Alt-M"

    def init(self):
        self.mcp_server = MCPServer()
        hotkey = MCP.wanted_hotkey.replace("-", "+")
        if sys.platform == "darwin":
            hotkey = hotkey.replace("Alt", "Option")
        print(
            f"[MCP] Plugin loaded, use Edit -> Plugins -> MCP ({hotkey}) to start the server"
        )
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        self.mcp_server.start()

    def term(self):
        self.mcp_server.stop()


def PLUGIN_ENTRY():
    return MCP()
