"""MCP Server Implementation with Streamable HTTP and SSE support"""

import json
import socket
import threading
import time
import traceback
import uuid
from typing import Any, Callable
from typing import get_type_hints
from typing import Annotated
from urllib.parse import urlparse, parse_qs

from .rpc import rpc_registry, JSONRPCError
from .sync import IDAError
from .utils import handle_large_output


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

        # Handle large outputs for disasm and decompile
        if tool_name in ("disasm", "decompile"):
            result = handle_large_output(result)

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
