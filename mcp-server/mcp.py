import time
import uuid
import json
import threading
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, get_type_hints, Annotated
from urllib.parse import urlparse, parse_qs

from jsonrpc import JsonRpcRegistry, JsonRpcError

class McpToolError(Exception):
    def __init__(self, message: str):
        super().__init__(message)

    @property
    def message(self) -> str:
        return self.args[0]

class McpToolRegistry(JsonRpcRegistry):
    """JSON-RPC registry with custom error handling for MCP tools"""
    def map_exception(self, e: Exception) -> JsonRpcError:
        if isinstance(e, McpToolError):
            return {
                "code": -32000,
                "message": e.args[0] or "MCP Tool Error",
            }
        return super().map_exception(e)

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
            if isinstance(data, str):
                data_str = f"data: {data}\n\n"
            else:
                data_str = f"data: {json.dumps(data)}\n\n"
            message = f"event: {event_type}\n{data_str}".encode("utf-8")
            self.wfile.write(message)
            self.wfile.flush()  # Ensure data is sent immediately
            return True
        except (BrokenPipeError, OSError):
            self.alive = False
            return False

class MCPProtocolHandler:
    """Handles MCP protocol messages and generates tool schemas"""

    def __init__(self, tool_registry: McpToolRegistry):
        self.tool_registry = tool_registry
        self.mcp_registry = JsonRpcRegistry()

        # Register MCP protocol methods with correct names
        self.mcp_registry.methods["initialize"] = self._mcp_initialize
        self.mcp_registry.methods["tools/list"] = self._mcp_tools_list
        self.mcp_registry.methods["tools/call"] = self._mcp_tools_call

    def _type_to_json_schema(self, py_type: Any) -> dict:
        """Convert Python type hint to JSON schema object"""
        from typing import get_origin, get_args, Union

        # Handle Annotated[Type, "description"]
        if get_origin(py_type) is Annotated:
            args = get_args(py_type)
            actual_type = args[0]
            description = args[1] if len(args) > 1 else None
            schema = self._type_to_json_schema(actual_type)
            if description:
                schema["description"] = description
            return schema

        # Handle Union/Optional types
        if get_origin(py_type) is Union:
            union_args = get_args(py_type)
            non_none = [t for t in union_args if t is not type(None)]
            if len(non_none) == 1:
                return self._type_to_json_schema(non_none[0])
            # Multiple types -> anyOf
            return {"anyOf": [self._type_to_json_schema(t) for t in non_none]}

        # Primitives
        if py_type == int:
            return {"type": "integer"}
        if py_type == float:
            return {"type": "number"}
        if py_type == str:
            return {"type": "string"}
        if py_type == bool:
            return {"type": "boolean"}

        # Handle list types
        if py_type == list or get_origin(py_type) is list:
            args = get_args(py_type)
            schema: dict[str, Any] = {"type": "array"}
            if args:
                schema["items"] = self._type_to_json_schema(args[0])
            return schema

        # Handle dict types
        if py_type == dict or get_origin(py_type) is dict:
            return {"type": "object"}

        # TypedDict detection
        if hasattr(py_type, "__annotations__"):
            if hasattr(py_type, "__required_keys__") or hasattr(py_type, "__optional_keys__"):
                return self._typed_dict_to_schema(py_type)

        # Fallback
        return {"type": "object"}

    def _typed_dict_to_schema(self, typed_dict_class) -> dict:
        """Convert TypedDict to JSON schema"""
        try:
            from typing_extensions import NotRequired
        except ImportError:
            from typing import NotRequired

        from typing import get_origin, get_args

        hints = get_type_hints(typed_dict_class, include_extras=True)
        properties = {}
        required = []

        for field_name, field_type in hints.items():
            # Check if field is NotRequired
            is_not_required = get_origin(field_type) is NotRequired
            if is_not_required:
                field_type = get_args(field_type)[0]

            properties[field_name] = self._type_to_json_schema(field_type)

            # Add to required if not NotRequired
            if not is_not_required:
                # Also check __required_keys__ if available
                if hasattr(typed_dict_class, "__required_keys__"):
                    if field_name in typed_dict_class.__required_keys__:
                        if field_name not in required:
                            required.append(field_name)
                else:
                    # Default to required if no __required_keys__
                    required.append(field_name)

        schema = {
            "type": "object",
            "properties": properties
        }
        if required:
            schema["required"] = required

        return schema

    def generate_tool_schema(self, func_name: str, func: Callable) -> dict:
        """Generate MCP tool schema from a function"""
        import inspect

        hints = get_type_hints(func, include_extras=True)
        return_type = hints.pop("return", None)
        sig = inspect.signature(func)

        # Build parameter schema
        properties = {}
        required = []

        for param_name, param_type in hints.items():
            # Check if parameter has default value
            param = sig.parameters.get(param_name)
            has_default = param and param.default is not inspect.Parameter.empty

            # Use _type_to_json_schema to handle all type conversions including Union
            properties[param_name] = self._type_to_json_schema(param_type)

            # Only add to required if no default value
            if not has_default:
                required.append(param_name)

        # Get docstring as description
        description = func.__doc__ or f"Call {func_name}"
        if description:
            description = description.strip()

        schema: dict[str, Any] = {
            "name": func_name,
            "description": description,
            "inputSchema": {
                "type": "object",
                "properties": properties,
                "required": required
            }
        }

        # Add outputSchema if return type exists and is not None
        if return_type and return_type is not type(None):
            return_schema = self._type_to_json_schema(return_type)
            # MCP spec requires outputSchema to always be type: object
            # Wrap primitives in an object with a "value" property
            if return_schema.get("type") != "object":
                schema["outputSchema"] = {
                    "type": "object",
                    "properties": {
                        "value": return_schema
                    },
                    "required": ["value"]
                }
            else:
                schema["outputSchema"] = return_schema

        return schema

    def _mcp_initialize(self, protocolVersion: str, capabilities: dict, clientInfo: dict, _meta: dict | None = None) -> dict:
        """MCP initialize method"""
        return {
            "protocolVersion": protocolVersion,
            "capabilities": {
                "tools": {}
            },
            "serverInfo": {
                "name": "ida-pro-mcp",
                "version": "1.0.0"
            },
        }

    def _mcp_tools_list(self, _meta: dict | None = None) -> dict:
        """MCP tools/list method"""
        return {
            "tools": [
                self.generate_tool_schema(func_name, func)
                for func_name, func in self.tool_registry.methods.items()
            ]
        }

    def _mcp_tools_call(self, name: str, arguments: dict | None = None, _meta: dict | None = None) -> dict:
        """MCP tools/call method"""
        # Wrap tool call in JSON-RPC request
        tool_response = self.tool_registry.dispatch({
            "jsonrpc": "2.0",
            "method": name,
            "params": arguments,
            "id": None,
        })

        # Check for error response
        if tool_response and "error" in tool_response:
            error = tool_response["error"]
            return {
                "content": [{"type": "text", "text": error.get("message", "Unknown error")}],
                "isError": True
            }

        result = tool_response.get("result") if tool_response else None
        return {
            "content": [{"type": "text", "text": json.dumps(result, indent=2)}],
            "structuredContent": result if isinstance(result, dict) else {"value": result},
            "isError": False
        }

class MCPHTTPRequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for MCP server using stdlib http.server"""

    # Class-level reference to server instance (set when server starts)
    mcp_server: "MCPServer"  # Will be set to MCPServer instance

    def log_message(self, format, *args):
        """Override to suppress default logging or customize"""
        pass

    def handle(self):
        """Override to add error handling for connection errors"""
        try:
            super().handle()
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            # Client disconnected - normal, suppress traceback
            pass

    def do_GET(self):
        match urlparse(self.path).path:
            case "/mcp":
                self.send_error(405, "Method Not Allowed")
            case "/sse":
                self._handle_sse_get()
            case _:
                self.send_error(404, "Not Found")

    def do_POST(self):
        # Read request body (TODO: do we need to handle chunked encoding and what about no Content-Length?)
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""

        match urlparse(self.path).path:
            case "/mcp":
                self._handle_mcp_post(body)
            case "/sse":
                self._handle_sse_post(body)
            case _:
                self.send_error(404, "Not Found")

    def do_OPTIONS(self):
        """Handle CORS preflight requests"""
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Accept, X-Requested-With, Mcp-Session-Id, Mcp-Protocol-Version")
        self.send_header("Access-Control-Max-Age", "86400")
        self.end_headers()

    def _handle_mcp_post(self, body: bytes):
        # Dispatch to MCP registry
        response = self.mcp_server.mcp_handler.mcp_registry.dispatch(body)

        # Check if notification (returns None)
        if response is None:
            # Return 202 Accepted for notifications
            self.send_response(202)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Content-Length", "8")
            self.end_headers()
            self.wfile.write(b"Accepted")
            return

        # Send JSON-RPC response
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Mcp-Session-Id, Mcp-Protocol-Version")
        self.end_headers()
        self.wfile.write(json.dumps(response).encode("utf-8"))

    def _handle_sse_get(self):
        # Create SSE connection wrapper
        conn = SSEConnection(self.wfile, self.client_address, str(uuid.uuid4()))
        self.mcp_server.sse_connections[conn.session_id] = conn

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
            conn.alive = False
            if conn.session_id in self.mcp_server.sse_connections:
                del self.mcp_server.sse_connections[conn.session_id]

    def _handle_sse_post(self, body: bytes):
        query_params = parse_qs(urlparse(self.path).query)
        session_id = query_params.get("session", [None])[0]
        if session_id is None:
            self.send_error(400, "Missing ?session for SSE POST")
            return

        # Dispatch to MCP registry
        response = self.mcp_server.mcp_handler.mcp_registry.dispatch(body)

        # Check if notification (returns None)
        if response is None:
            # Return 202 Accepted for notifications (no SSE event sent)
            self.send_response(202)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Content-Length", "8")
            self.end_headers()
            self.wfile.write(b"Accepted")
            return

        # Find active SSE connection for this client
        sse_conn = self.mcp_server.sse_connections.get(session_id)
        if sse_conn is None or not sse_conn.alive:
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

class MCPServer:
    """MCP server using stdlib http.server with ThreadingHTTPServer"""

    HOST = "127.0.0.1"
    BASE_PORT = 13337
    MAX_PORT_TRIES = 10

    def __init__(self, tool_registry: McpToolRegistry):
        self.http_server = None
        self.server_thread = None
        self.running = False
        self.port = None  # Will be set when server starts
        self.sse_connections: dict[str, SSEConnection] = {}
        self.mcp_handler = MCPProtocolHandler(tool_registry)

    def start(self):
        if self.running:
            print("[MCP] Server is already running")
            return

        self.server_thread = threading.Thread(target=self._run_server, daemon=True)
        self.running = True
        self.server_thread.start()

        # Wait for port to be assigned
        import time
        timeout = 2.0
        start_time = time.time()
        while self.port is None and time.time() - start_time < timeout:
            time.sleep(0.01)

    def stop(self):
        if not self.running:
            return

        self.running = False

        # Close all SSE connections
        for conn in self.sse_connections.values():
            conn.alive = False
        self.sse_connections.clear()

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
                # Create HTTP server with threading support and exclusive binding
                class ExclusiveThreadingHTTPServer(ThreadingHTTPServer):
                    allow_reuse_address = False

                self.http_server = ExclusiveThreadingHTTPServer(
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
