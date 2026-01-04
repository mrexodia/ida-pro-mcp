import re
import sys
import time
import uuid
import json
import inspect
import threading
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer, HTTPServer
from typing import Any, Callable, Union, Annotated, BinaryIO, NotRequired, get_origin, get_args, get_type_hints, is_typeddict
from types import UnionType
from urllib.parse import urlparse, parse_qs
from io import BufferedIOBase

from .jsonrpc import JsonRpcRegistry, JsonRpcError, JsonRpcException, get_current_request_id, register_pending_request, unregister_pending_request, cancel_request

class McpToolError(Exception):
    def __init__(self, message: str):
        super().__init__(message)

class McpRpcRegistry(JsonRpcRegistry):
    """JSON-RPC registry with custom error handling for MCP tools"""
    def map_exception(self, e: Exception) -> JsonRpcError:
        if isinstance(e, McpToolError):
            return {
                "code": -32000,
                "message": e.args[0] or "MCP Tool Error",
            }
        return super().map_exception(e)

class _McpSseConnection:
    """Manages a single SSE client connection"""
    def __init__(self, wfile):
        self.wfile: BufferedIOBase = wfile
        self.session_id = str(uuid.uuid4())
        self.alive = True

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

class McpHttpRequestHandler(BaseHTTPRequestHandler):
    server_version = "zeromcp/1.3.0"
    error_message_format = "%(code)d - %(message)s"
    error_content_type = "text/plain"

    def __init__(self, request, client_address, server):
        self.mcp_server: "McpServer" = getattr(server, "mcp_server")
        super().__init__(request, client_address, server)

    def _parse_extensions(self, path: str) -> set[str]:
        """Parse ?ext=dbg,foo query param into set of enabled extensions"""
        query = parse_qs(urlparse(path).query)
        ext_param = query.get("ext", [""])[0]
        if not ext_param:
            return set()
        return {e.strip() for e in ext_param.split(",") if e.strip()}

    def log_message(self, format, *args):
        """Override to suppress default logging or customize"""
        pass

    def send_cors_headers(self, *, preflight = False):
        origin = self.headers.get("Origin", "")
        if not origin:
            return
        def is_allowed():
            allowed = self.mcp_server.cors_allowed_origins
            if allowed is None:
                return False
            if callable(allowed):
                return allowed(origin)
            if isinstance(allowed, str):
                allowed = [allowed]
            assert isinstance(allowed, list)
            return "*" in allowed or origin in allowed
        if not is_allowed():
            return
        self.send_header("Access-Control-Allow-Origin", origin)
        if preflight:
            self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, Accept, X-Requested-With, Mcp-Session-Id, Mcp-Protocol-Version")
            if self.headers.get("Access-Control-Request-Private-Network") == "true":
                self.send_header("Access-Control-Allow-Private-Network", "true")

    def send_error(self, code, message=None, explain=None):
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_cors_headers()
        self.end_headers()
        self.wfile.write(f"{message}\n".encode("utf-8"))

    def handle(self):
        """Override to add error handling for connection errors"""
        try:
            super().handle()
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            # Client disconnected - normal, suppress traceback
            pass

    def do_GET(self):
        match urlparse(self.path).path:
            case "/sse":
                self._handle_sse_get()
            case "/mcp":
                self.send_error(405, "Method Not Allowed")
            case _:
                self.send_error(404, "Not Found")

    def do_POST(self):
        # Read request body
        content_length = int(self.headers.get("Content-Length", 0))

        if content_length > self.mcp_server.post_body_limit:
            self.send_error(413, f"Payload Too Large: exceeds {self.mcp_server.post_body_limit} bytes")
            return

        body = self.rfile.read(content_length) if content_length > 0 else b""

        match urlparse(self.path).path:
            case "/sse":
                self._handle_sse_post(body)
            case "/mcp":
                self._handle_mcp_post(body)
            case _:
                self.send_error(404, "Not Found")

    def do_OPTIONS(self):
        """Handle CORS preflight requests"""
        self.send_response(200)
        self.send_cors_headers(preflight=True)
        self.end_headers()

    def _handle_sse_get(self):
        # Create SSE connection wrapper
        conn = _McpSseConnection(self.wfile)
        self.mcp_server._sse_connections[conn.session_id] = conn

        try:
            # Send SSE headers
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.send_cors_headers()
            self.end_headers()

            # Send endpoint event with session ID for routing
            conn.send_event("endpoint", f"/sse?session={conn.session_id}")

            # Keep connection alive with periodic pings
            last_ping = time.time()
            while conn.alive and self.mcp_server._running:
                now = time.time()
                if now - last_ping > 30:  # Ping every 30 seconds
                    if not conn.send_event("ping", {}):
                        break
                    last_ping = now
                time.sleep(1)

        finally:
            conn.alive = False
            if conn.session_id in self.mcp_server._sse_connections:
                del self.mcp_server._sse_connections[conn.session_id]

    def _handle_sse_post(self, body: bytes):
        query_params = parse_qs(urlparse(self.path).query)
        session_id = query_params.get("session", [None])[0]
        if session_id is None:
            self.send_error(400, "Missing ?session for SSE POST")
            return

        # Parse extensions from query params and store in thread-local
        extensions = self._parse_extensions(self.path)
        setattr(self.mcp_server._enabled_extensions, "data", extensions)

        # Dispatch to MCP registry
        setattr(self.mcp_server._protocol_version, "data", "2024-11-05")
        response = self.mcp_server.registry.dispatch(body)

        # Send SSE response if necessary
        if response is not None:
            sse_conn = self.mcp_server._sse_connections.get(session_id)
            if sse_conn is None or not sse_conn.alive:
                # No SSE connection found
                self.send_error(400, f"No active SSE connection found for session {session_id}")
                return

            # Send response via SSE event stream
            sse_conn.send_event("message", response)

        # Return 202 Accepted to acknowledge POST
        self.send_response(202)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_cors_headers()
        self.end_headers()
        self.wfile.write(body)

    def _handle_mcp_post(self, body: bytes):
        # Parse extensions from query params and store in thread-local
        extensions = self._parse_extensions(self.path)
        setattr(self.mcp_server._enabled_extensions, "data", extensions)

        # Dispatch to MCP registry
        setattr(self.mcp_server._protocol_version, "data", "2025-06-18")
        response = self.mcp_server.registry.dispatch(body)

        def send_response(status: int, body: bytes):
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_cors_headers()
            self.end_headers()
            self.wfile.write(body)

        # Check if notification (returns None)
        if response is None:
            send_response(202, b"Accepted")
        else:
            send_response(200, json.dumps(response).encode("utf-8"))

class McpServer:
    def __init__(self, name: str, version = "1.0.0", *, extensions: dict[str, set[str]] | None = None):
        self.name = name
        self.version = version
        self.cors_allowed_origins: Callable[[str], bool] | list[str] | str | None = self.cors_localhost
        self.post_body_limit = 10 * 1024 * 1024  # 10MB
        self.tools = McpRpcRegistry()
        self.resources = McpRpcRegistry()
        self.prompts = McpRpcRegistry()

        self._http_server: HTTPServer | None = None
        self._server_thread: threading.Thread | None = None
        self._running = False
        self._sse_connections: dict[str, _McpSseConnection] = {}
        self._protocol_version = threading.local()
        self._enabled_extensions = threading.local()  # set[str] per request
        self._extensions_registry = extensions if extensions is not None else {}  # group -> set of tool names

        # Register MCP protocol methods with correct names
        self.registry = JsonRpcRegistry()
        self.registry.methods["ping"] = self._mcp_ping
        self.registry.methods["initialize"] = self._mcp_initialize
        self.registry.methods["tools/list"] = self._mcp_tools_list
        self.registry.methods["tools/call"] = self._mcp_tools_call
        self.registry.methods["resources/list"] = self._mcp_resources_list
        self.registry.methods["resources/templates/list"] = self._mcp_resource_templates_list
        self.registry.methods["resources/read"] = self._mcp_resources_read
        self.registry.methods["prompts/list"] = self._mcp_prompts_list
        self.registry.methods["prompts/get"] = self._mcp_prompts_get
        self.registry.methods["notifications/cancelled"] = self._mcp_notifications_cancelled

    def tool(self, func: Callable) -> Callable:
        return self.tools.method(func)

    def resource(self, uri: str) -> Callable[[Callable], Callable]:
        def decorator(func: Callable) -> Callable:
            setattr(func, "__resource_uri__", uri)
            return self.resources.method(func)
        return decorator

    def prompt(self, func: Callable) -> Callable:
        return self.prompts.method(func)

    def serve(self, host: str, port: int, *, background = True, request_handler = McpHttpRequestHandler):
        if self._running:
            print("[MCP] Server is already running")
            return

        # Create server with deferred binding
        assert issubclass(request_handler, McpHttpRequestHandler)
        self._http_server = (ThreadingHTTPServer if background else HTTPServer)(
            (host, port),
            request_handler,
            bind_and_activate=False
        )
        self._http_server.allow_reuse_address = True
        if hasattr(self._http_server, "allow_reuse_port"):
            self._http_server.allow_reuse_port = True

        # Set the MCPServer instance on the handler class
        setattr(self._http_server, "mcp_server", self)

        try:
            # Bind and activate in main thread - errors propagate synchronously
            self._http_server.server_bind()
            self._http_server.server_activate()
        except OSError:
            # Cleanup on binding failure
            self._http_server.server_close()
            self._http_server = None
            raise

        # Only start thread after successful bind
        self._running = True

        print("[MCP] Server started:")
        print(f"  Streamable HTTP: http://{host}:{port}/mcp")
        print(f"  SSE: http://{host}:{port}/sse")

        def serve_forever():
            try:
                self._http_server.serve_forever() # type: ignore
            except Exception as e:
                print(f"[MCP] Server error: {e}")
                traceback.print_exc()
            finally:
                self._running = False

        if background:
            self._server_thread = threading.Thread(target=serve_forever, daemon=True)
            self._server_thread.start()
        else:
            serve_forever()

    def stop(self):
        if not self._running:
            return

        self._running = False

        # Close all SSE connections
        for conn in self._sse_connections.values():
            conn.alive = False
        self._sse_connections.clear()

        # Shutdown the HTTP server
        if self._http_server:
            # shutdown() must be called from a different thread
            # than the one running serve_forever()
            self._http_server.shutdown()
            self._http_server.server_close()
            self._http_server = None

        if self._server_thread:
            self._server_thread.join()
            self._server_thread = None

        print("[MCP] Server stopped")

    def stdio(self, stdin: BinaryIO | None = None, stdout: BinaryIO | None = None):
        stdin = stdin or sys.stdin.buffer
        stdout = stdout or sys.stdout.buffer
        while True:
            try:
                request = stdin.readline()
                if not request: # EOF
                    break

                # Strip whitespace (trailing newline) before parsing
                request = request.strip()
                if not request:
                    continue

                response = self.registry.dispatch(request)
                if response is not None:
                    stdout.write(json.dumps(response).encode("utf-8") + b"\n")
                    stdout.flush()
            except (BrokenPipeError, KeyboardInterrupt): # Client disconnected
                break

    def cors_localhost(self, origin: str) -> bool:
        """Allow CORS requests from localhost on ANY port."""
        return urlparse(origin).hostname in ("localhost", "127.0.0.1", "::1")

    def _mcp_ping(self, _meta: dict | None = None) -> dict:
        """MCP ping method"""
        return {}

    def _mcp_initialize(self, protocolVersion: str, capabilities: dict, clientInfo: dict, _meta: dict | None = None) -> dict:
        """MCP initialize method"""
        return {
            "protocolVersion": getattr(self._protocol_version, "data", protocolVersion),
            "capabilities": {
                "tools": {},
                "resources": {
                    "subscribe": False,
                    "listChanged": False,
                },
                "prompts": {},
            },
            "serverInfo": {
                "name": self.name,
                "version": self.version,
            },
        }

    def _mcp_tools_list(self, _meta: dict | None = None) -> dict:
        """MCP tools/list method"""
        enabled = getattr(self._enabled_extensions, "data", set())
        tools = []
        for func_name, func in self.tools.methods.items():
            # Check if tool belongs to an extension group
            tool_group = self._get_tool_extension(func_name)
            if tool_group and tool_group not in enabled:
                continue  # Skip tools from disabled extension groups
            tools.append(self._generate_tool_schema(func_name, func))
        return {"tools": tools}

    def _get_tool_extension(self, func_name: str) -> str | None:
        """Return extension group name if tool belongs to one, else None"""
        for group, tools in self._extensions_registry.items():
            if func_name in tools:
                return group
        return None

    def _mcp_tools_call(self, name: str, arguments: dict | None = None, _meta: dict | None = None) -> dict:
        """MCP tools/call method"""
        # Check if tool requires an extension that isn't enabled
        enabled = getattr(self._enabled_extensions, "data", set())
        tool_group = self._get_tool_extension(name)
        if tool_group and tool_group not in enabled:
            return {
                "content": [{"type": "text", "text": f"Tool '{name}' requires extension '{tool_group}'. Enable with ?ext={tool_group}"}],
                "isError": True,
            }

        # Register request for cancellation tracking
        request_id = get_current_request_id()
        if request_id is not None:
            register_pending_request(request_id)

        try:
            # Wrap tool call in JSON-RPC request
            tool_response = self.tools.dispatch({
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
                    "isError": True,
                }

            result = tool_response.get("result") if tool_response else None
            return {
                "content": [{"type": "text", "text": json.dumps(result, indent=2)}],
                "structuredContent": result if isinstance(result, dict) else {"result": result},
                "isError": False,
            }
        finally:
            if request_id is not None:
                unregister_pending_request(request_id)

    def _mcp_notifications_cancelled(self, requestId: int | str, reason: str | None = None) -> None:
        """MCP notifications/cancelled - cancel an in-flight request"""
        if cancel_request(requestId):
            print(f"[MCP] Cancelled request {requestId}: {reason or 'no reason'}")
        # Notifications don't return a response

    def _mcp_resources_list(self, _meta: dict | None = None) -> dict:
        """MCP resources/list method - returns static resources only (no URI parameters)"""
        resources = []
        for func_name, func in self.resources.methods.items():
            uri: str = getattr(func, "__resource_uri__")

            # Skip templates (resources with parameters like {addr})
            if "{" in uri:
                continue

            resources.append({
                "uri": uri,
                "name": func_name,
                "description": (func.__doc__ or f"Read {uri}").strip(),
                "mimeType": "application/json",
            })

        return {"resources": resources}

    def _mcp_resource_templates_list(self, _meta: dict | None = None) -> dict:
        """MCP resources/templates/list method - returns parameterized resource templates"""
        templates = []
        for func_name, func in self.resources.methods.items():
            uri: str = getattr(func, "__resource_uri__")

            # Only include templates (resources with parameters like {addr})
            if "{" not in uri:
                continue

            templates.append({
                "uriTemplate": uri,
                "name": func_name,
                "description": (func.__doc__ or f"Read {uri}").strip(),
                "mimeType": "application/json",
            })

        return {"resourceTemplates": templates}

    def _mcp_resources_read(self, uri: str, _meta: dict | None = None) -> dict:
        """MCP resources/read method"""

        # Try to match URI against all registered resource patterns
        for func_name, func in self.resources.methods.items():
            pattern: str = getattr(func, "__resource_uri__")

            # Convert pattern to regex, replacing {param} with named capture groups
            regex_pattern = re.sub(r"\{(\w+)\}", r"(?P<\1>[^/]+)", pattern)
            regex_pattern = f"^{regex_pattern}$"

            match = re.match(regex_pattern, uri)
            if match:
                # Found matching resource - call it via JSON-RPC
                params = list(match.groupdict().values())

                tool_response = self.resources.dispatch({
                    "jsonrpc": "2.0",
                    "method": func_name,
                    "params": params,
                    "id": None,
                })

                if tool_response and "error" in tool_response:
                    error = tool_response["error"]
                    return {
                        "contents": [{
                            "uri": uri,
                            "mimeType": "application/json",
                            "text": json.dumps({"error": error.get("message", "Unknown error")}, indent=2),
                        }],
                        "isError": True,
                    }

                result = tool_response.get("result") if tool_response else None
                return {
                    "contents": [{
                        "uri": uri,
                        "mimeType": "application/json",
                        "text": json.dumps(result, indent=2),
                    }]
                }

        # No matching resource found
        available: list[str] = [getattr(f, "__resource_uri__") for f in self.resources.methods.values()]
        return {
            "contents": [{
                "uri": uri,
                "mimeType": "application/json",
                "text": json.dumps({
                    "error": f"Resource not found: {uri}",
                    "available_patterns": available,
                }, indent=2),
            }],
            "isError": True,
        }

    def _mcp_prompts_list(self, _meta: dict | None = None) -> dict:
        """MCP prompts/list method"""
        return {
            "prompts": [
                self._generate_prompt_schema(func_name, func)
                for func_name, func in self.prompts.methods.items()
            ],
        }

    def _mcp_prompts_get(
        self, name: str, arguments: dict | None = None, _meta: dict | None = None
    ) -> dict:
        """MCP prompts/get method"""
        # Dispatch to prompts registry
        prompt_response = self.prompts.dispatch(
            {
                "jsonrpc": "2.0",
                "method": name,
                "params": arguments,
                "id": None,
            }
        )
        assert prompt_response is not None, "Only notification requests return None"

        # Check for error response
        if "error" in prompt_response:
            error = prompt_response["error"]
            raise JsonRpcException(error["code"], error["message"], error.get("data"))

        result = prompt_response.get("result")

        # Pass through list of messages directly
        if isinstance(result, list):
            return {"messages": result}

        # Convert non-string results to JSON
        if not isinstance(result, str):
            result = json.dumps(result, indent=2)
        return {
            "messages": [
                {
                    "role": "user",
                    "content": {"type": "text", "text": result},
                },
            ],
        }

    def _generate_prompt_schema(self, func_name: str, func: Callable) -> dict:
        """Generate MCP prompt schema from a function"""
        hints = get_type_hints(func, include_extras=True)
        hints.pop("return", None)
        sig = inspect.signature(func)

        # Build arguments list (PromptArgument format)
        arguments = []
        for param_name, param_type in hints.items():
            arg: dict[str, Any] = {"name": param_name}

            # Extract description from Annotated
            origin = get_origin(param_type)
            if origin is Annotated:
                args = get_args(param_type)
                arg["description"] = str(args[-1])

            # Check if required (no default value)
            param = sig.parameters.get(param_name)
            if not param or param.default is inspect.Parameter.empty:
                arg["required"] = True

            arguments.append(arg)

        schema: dict[str, Any] = {
            "name": func_name,
            "description": (func.__doc__ or f"Prompt {func_name}").strip(),
        }

        if arguments:
            schema["arguments"] = arguments

        return schema

    def _type_to_json_schema(self, py_type: Any) -> dict:
        """Convert Python type hint to JSON schema object"""
        origin = get_origin(py_type)
        # Annotated[T, "description"]
        if origin is Annotated:
            args = get_args(py_type)
            return {
                **self._type_to_json_schema(args[0]),
                "description": str(args[-1]),
            }

        # NotRequired[T]
        if origin is NotRequired:
            return self._type_to_json_schema(get_args(py_type)[0])

        # Union[Ts..], Optional[T] and T1 | T2
        if origin in (Union, UnionType):
            return {"anyOf": [self._type_to_json_schema(t) for t in get_args(py_type)]}

        # list[T]
        if origin is list:
            return {
                "type": "array",
                "items": self._type_to_json_schema(get_args(py_type)[0]),
            }

        # dict[str, T]
        if origin is dict:
            return {
                "type": "object",
                "additionalProperties": self._type_to_json_schema(get_args(py_type)[1]),
            }

        # TypedDict
        if is_typeddict(py_type):
            return self._typed_dict_to_schema(py_type)

        # Primitives
        return {
            "type": {
                int: "integer",
                float: "number",
                str: "string",
                bool: "boolean",
                list: "array",
                dict: "object",
                type(None): "null",
            }.get(py_type, "object"),
        }

    def _typed_dict_to_schema(self, typed_dict_class) -> dict:
        """Convert TypedDict to JSON schema"""
        hints = get_type_hints(typed_dict_class, include_extras=True)
        required_keys = getattr(typed_dict_class, '__required_keys__', set(hints.keys()))

        return {
            "type": "object",
            "properties": {
                field_name: self._type_to_json_schema(field_type)
                for field_name, field_type in hints.items()
            },
            "required": [key for key in hints.keys() if key in required_keys],
            "additionalProperties": False
        }

    def _generate_tool_schema(self, func_name: str, func: Callable) -> dict:
        """Generate MCP tool schema from a function"""
        hints = get_type_hints(func, include_extras=True)
        return_type = hints.pop("return", None)
        sig = inspect.signature(func)

        # Build parameter schema
        properties = {}
        required = []

        for param_name, param_type in hints.items():
            properties[param_name] = self._type_to_json_schema(param_type)

            # Add to required if no default value
            param = sig.parameters.get(param_name)
            if not param or param.default is inspect.Parameter.empty:
                required.append(param_name)

        schema: dict[str, Any] = {
            "name": func_name,
            "description": (func.__doc__ or f"Call {func_name}").strip(),
            "inputSchema": {
                "type": "object",
                "properties": properties,
                "required": required,
            }
        }

        # Add outputSchema if return type exists and is not None
        if return_type and return_type is not type(None):
            return_schema = self._type_to_json_schema(return_type)

            # Wrap non-object returns in a "result" property
            if return_schema.get("type") != "object":
                return_schema = {
                    "type": "object",
                    "properties": {"result": return_schema},
                    "required": ["result"],
                }

            schema["outputSchema"] = return_schema

        return schema
