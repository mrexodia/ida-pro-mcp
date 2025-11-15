import time
import uuid
import json
import threading
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, get_type_hints, Annotated
from urllib.parse import urlparse, parse_qs

from jsonrpc import JsonRpcException, JsonRpcRegistry

class IDAError(Exception):
    def __init__(self, message: str):
        super().__init__(message)

    @property
    def message(self) -> str:
        return self.args[0]

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
    def __init__(self, wfile, client_address, session_id: str | None = None):
        self.wfile = wfile  # File-like object for writing to client
        self.address = client_address
        self.session_id = session_id or str(uuid.uuid4())
        self.alive = True
        self.initialized = False

    def send_event(self, event_type: str, data):
        """Send an SSE event to the client

        Args:
            event_type: Type of event (e.g., "endpoint", "message", "ping")
            data: Event data - can be string (sent as-is) or dict (JSON-encoded)
        """
        if not self.alive:
            return False

        try:
            # SSE format: "event: type\ndata: content\n\n"
            event_str = f"event: {event_type}\n"
            if isinstance(data, str):
                data_str = f"data: {data}\n\n"
            else:
                data_str = f"data: {json.dumps(data)}\n\n"
            message = (event_str + data_str).encode("utf-8")
            self.wfile.write(message)
            self.wfile.flush()  # Ensure data is sent immediately
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
        # Note: wfile will be closed by the request handler

class MCPProtocolHandler:
    """Handles MCP protocol messages and generates tool schemas"""

    def __init__(self, registry: JsonRpcRegistry):
        self.registry = registry

    def generate_tool_schema(self, func_name: str, func: Callable) -> dict:
        """Generate MCP tool schema from a function"""
        hints = get_type_hints(func)
        hints.pop("return", None)

        # Build parameter schema
        properties = {}
        required = []

        for param_name, param_type in hints.items():
            # Handle Annotated types to extract descriptions
            description = ""
            actual_type = param_type

            if hasattr(param_type, "__origin__"):
                if param_type.__origin__ is Annotated:
                    args = param_type.__metadata__
                    if args:
                        description = args[0]
                    actual_type = param_type.__args__[0]

            # Map Python types to JSON schema types
            json_type = "string"  # default
            if actual_type == int:
                json_type = "integer"
            elif actual_type == float:
                json_type = "number"
            elif actual_type == bool:
                json_type = "boolean"
            elif actual_type == str:
                json_type = "string"

            properties[param_name] = {
                "type": json_type,
                "description": description
            }
            required.append(param_name)

        # Get docstring as description
        description = func.__doc__ or f"Call {func_name}"
        if description:
            description = description.strip()

        return {
            "name": func_name,
            "description": description,
            "inputSchema": {
                "type": "object",
                "properties": properties,
                "required": required
            }
        }

    def get_tools_list(self) -> list[dict]:
        """Generate list of all available tools"""
        tools = []
        for func_name, func in self.registry.methods.items():
            tool_schema = self.generate_tool_schema(func_name, func)
            tools.append(tool_schema)
        return tools

    def handle_initialize(self, params: dict, protocol_version) -> dict:
        """Handle MCP initialize request"""
        return {
            "protocolVersion": protocol_version,
            "capabilities": {
            "tools": {}
            },
            "serverInfo": {
                "name": "ida-pro-mcp",
                "version": "1.0.0"
            },
        }

    def handle_tools_list(self, params: dict) -> dict:
        """Handle tools/list request"""
        return {
            "tools": self.get_tools_list()
        }

    def handle_tools_call(self, params: dict) -> dict:
        """Handle tools/call request"""
        tool_name = params.get("name")
        arguments = params.get("arguments", {})

        if not tool_name:
            raise JsonRpcException(-32602, "Missing tool name")

        # Call the function via registry
        result = self.registry.dispatch(tool_name, arguments)

        return {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(result) if not isinstance(result, str) else result
                }
            ]
        }

class MCPHTTPRequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for MCP server using stdlib http.server"""

    # Class-level reference to server instance (set when server starts)
    mcp_server: "MCPServer"  # Will be set to MCPServer instance

    def log_message(self, format, *args):
        """Override to suppress default logging or customize"""
        # Suppress default logging for now
        pass

    def handle(self):
        """Override to add error handling for connection errors"""
        try:
            super().handle()
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            # Client disconnected - normal, suppress traceback
            pass
        finally:
            # Cleanup session on disconnect
            session_id = self.headers.get("Mcp-Session-Id") if hasattr(self, "headers") else None
            if session_id and session_id in self.mcp_server.sessions:
                del self.mcp_server.sessions[session_id]

    def do_GET(self):
        """Handle GET requests"""
        parsed_path = urlparse(self.path)
        base_path = parsed_path.path

        if base_path == "/mcp":
            # /mcp only supports POST - return 405 Method Not Allowed
            self.send_error(405, "Method Not Allowed")
        elif base_path == "/sse":
            # SSE connection - handle long-lived connection
            self._handle_sse_connection()
        else:
            self.send_error(404, "Not Found")

    def do_POST(self):
        """Handle POST requests"""
        # Read request body
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""

        parsed_path = urlparse(self.path)
        base_path = parsed_path.path

        if base_path == "/mcp":
            # Streamable HTTP transport
            self._handle_streamable_post(body)
        elif base_path == "/sse":
            # SSE message post
            self._handle_sse_post(body)
        else:
            self.send_error(404, "Not Found")

    def do_OPTIONS(self):
        """Handle OPTIONS requests (CORS)"""
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Accept, X-Requested-With, Mcp-Session-Id, Mcp-Protocol-Version")
        self.send_header("Access-Control-Max-Age", "86400")
        self.end_headers()

    def _send_json_response(self, data: dict, status=200, extra_headers=None):
        """Helper to send JSON response"""
        body = json.dumps(data).encode("utf-8")

        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Mcp-Session-Id, Mcp-Protocol-Version")

        if extra_headers:
            for key, value in extra_headers.items():
                self.send_header(key, value)

        self.end_headers()
        self.wfile.write(body)

    def _handle_streamable_post(self, body: bytes):
        """Handle Streamable HTTP POST request (POST /mcp)"""
        try:
            # Parse JSON-RPC request
            request = json.loads(body.decode("utf-8"))

            # Validate JSON-RPC 2.0
            if request.get("jsonrpc") != "2.0":
                raise JsonRpcException(-32600, "Invalid JSON-RPC version")

            method = request.get("method")
            params = request.get("params", {})
            request_id = request.get("id")

            # Check if this is a notification (no id field)
            if request_id is None:
                # Return 202 Accepted to acknowledge POST
                self.send_response(202)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Content-Length", "8")
                self.end_headers()
                self.wfile.write(b"Accepted")
                return

            # Regular request - prepare response
            response = {
                "jsonrpc": "2.0",
                "id": request_id
            }

            try:
                # Handle MCP protocol methods
                if method == "initialize":
                    result = self.mcp_server.mcp_handler.handle_initialize(params, "2025-06-18")
                elif method == "tools/list":
                    result = self.mcp_server.mcp_handler.handle_tools_list(params)
                elif method == "tools/call":
                    result = self.mcp_server.mcp_handler.handle_tools_call(params)
                else:
                    raise JsonRpcException(-32601, f"Method not found: {method}")

                response["result"] = result

            except JsonRpcException as e:
                response["error"] = {
                    "code": e.code,
                    "message": e.message
                }
                if e.data:
                    response["error"]["data"] = e.data
            except IDAError as e:
                response["error"] = {
                    "code": -32000,
                    "message": e.message
                }
            except Exception as e:
                traceback.print_exc()
                response["error"] = {
                    "code": -32603,
                    "message": "Internal error",
                    "data": str(e)
                }

            # Send response
            self._send_json_response(response)

        except Exception as e:
            traceback.print_exc()
            error_response = {
                "jsonrpc": "2.0",
                "error": {
                    "code": -32700,
                    "message": "Parse error",
                    "data": str(e)
                },
                "id": None
            }
            self._send_json_response(error_response, status=400)

    def _handle_sse_connection(self):
        """Handle SSE GET connection"""
        # Extract session ID from headers
        session_id = str(uuid.uuid4())
        self.mcp_server.sessions[session_id] = SessionState(session_id)

        # Create SSE connection wrapper (now using wfile)
        conn = SSEConnection(self.wfile, self.client_address, session_id)
        self.mcp_server.connections.append(conn)

        try:
            # Send SSE headers
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()

            # Send endpoint event with session ID for routing
            conn.send_event("endpoint", f"/sse?session={conn.session_id}")

            # Keep connection alive with periodic pings
            last_ping = time.time()
            while conn.alive and self.mcp_server.running:
                now = time.time()
                if now - last_ping > 30:  # Ping every 30 seconds
                    if not conn.send_event("ping", {}):
                        break
                    last_ping = now
                time.sleep(1)

        finally:
            conn.close()
            if conn in self.mcp_server.connections:
                self.mcp_server.connections.remove(conn)

    def _handle_sse_post(self, body: bytes):
        """Handle POST /sse (MCP JSON-RPC request) - SSE mode"""
        try:
            # Extract session ID from query parameters
            parsed = urlparse(self.path)
            query_params = parse_qs(parsed.query)
            session_id = query_params.get("session", [None])[0]
            if session_id is None:
                self.send_error(400, "Missing ?session for SSE POST")
                return

            # Parse JSON-RPC request
            request = json.loads(body.decode("utf-8"))

            # Validate JSON-RPC 2.0
            if request.get("jsonrpc") != "2.0":
                raise JsonRpcException(-32600, "Invalid JSON-RPC version")

            method = request.get("method")
            params = request.get("params", {})
            request_id = request.get("id")

            # Check if this is a notification (no id field)
            if request_id is None:
                # Return 202 Accepted to acknowledge POST (no SSE event sent)
                self.send_response(202)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Content-Length", "8")
                self.end_headers()
                self.wfile.write(b"Accepted")
                return

            # Regular request - prepare response
            response = {
                "jsonrpc": "2.0",
                "id": request_id
            }

            try:
                # Handle MCP protocol methods
                if method == "initialize":
                    result = self.mcp_server.mcp_handler.handle_initialize(params, protocol_version="2024-11-05")
                elif method == "tools/list":
                    result = self.mcp_server.mcp_handler.handle_tools_list(params)
                elif method == "tools/call":
                    result = self.mcp_server.mcp_handler.handle_tools_call(params)
                else:
                    raise JsonRpcException(-32601, f"Method not found: {method}")

                response["result"] = result

            except JsonRpcException as e:
                response["error"] = {
                    "code": e.code,
                    "message": e.message
                }
                if e.data:
                    response["error"]["data"] = e.data
            except IDAError as e:
                response["error"] = {
                    "code": -32000,
                    "message": e.message
                }
            except Exception as e:
                traceback.print_exc()
                response["error"] = {
                    "code": -32603,
                    "message": "Internal error",
                    "data": str(e)
                }

            # Find active SSE connection for this client (match by session ID)
            sse_conn = None
            if session_id:
                for conn in self.mcp_server.connections:
                    if conn.session_id == session_id and conn.alive:
                        sse_conn = conn
                        break

            if not sse_conn:
                # No SSE connection found
                error_msg = f"No active SSE connection found for session {session_id}"
                print(f"[MCP SSE ERROR] {error_msg}")
                self.send_error(400, error_msg)
                return

            # Send response via SSE event stream
            sse_conn.send_event("message", response)

            # Return 202 Accepted to acknowledge POST
            self.send_response(202)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Content-Length", "8")
            self.end_headers()
            self.wfile.write(b"Accepted")

        except Exception as e:
            traceback.print_exc()
            error_response = {
                "jsonrpc": "2.0",
                "error": {
                    "code": -32700,
                    "message": "Parse error",
                    "data": str(e)
                },
                "id": None
            }
            self._send_json_response(error_response, status=400)

class MCPServer:
    """MCP server using stdlib http.server with ThreadingHTTPServer"""

    HOST = "127.0.0.1"
    BASE_PORT = 13337
    MAX_PORT_TRIES = 10

    def __init__(self):
        self.http_server = None
        self.server_thread = None
        self.running = False
        self.port = None  # Will be set when server starts
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

        # Close all SSE connections
        for conn in self.connections[:]:
            conn.close()
        self.connections.clear()

        # Shutdown the HTTP server
        if self.http_server:
            # shutdown() must be called from a different thread
            # than the one running serve_forever()
            self.http_server.shutdown()
            self.http_server.server_close()
            self.http_server = None

        if self.server_thread:
            self.server_thread.join(timeout=2)

        print("[MCP] Server stopped")

    def _run_server(self):
        """Run the HTTP server main loop using ThreadingHTTPServer"""
        # Set the MCPServer instance on the handler class
        MCPHTTPRequestHandler.mcp_server = self

        # Try to bind to a port starting from BASE_PORT
        for i in range(self.MAX_PORT_TRIES):
            port = self.BASE_PORT + i
            try:
                # Create HTTP server with threading support
                self.http_server = ThreadingHTTPServer(
                    (self.HOST, port),
                    MCPHTTPRequestHandler
                )
                self.port = port
                break
            except OSError as e:
                if e.errno in (98, 10048):  # Address already in use
                    if i == self.MAX_PORT_TRIES - 1:
                        print(f"[MCP] Error: Could not find available port in range {self.BASE_PORT}-{self.BASE_PORT + self.MAX_PORT_TRIES - 1}")
                        self.running = False
                        return
                    continue
                else:
                    print(f"[MCP] Server error: {e}")
                    self.running = False
                    return

        if not self.http_server:
            print(f"[MCP] Error: Failed to create HTTP server")
            self.running = False
            return

        print("[MCP] Server started:")
        print(f"  Streamable HTTP: http://{self.HOST}:{self.port}/mcp")
        print(f"  SSE: http://{self.HOST}:{self.port}/sse")

        try:
            # Serve forever (until shutdown() is called)
            self.http_server.serve_forever()
        except Exception as e:
            print(f"[MCP] Server error: {e}")
            traceback.print_exc()
        finally:
            self.running = False