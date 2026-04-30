import re
import select
import socket
import sys
import time
import uuid
import json
import gzip
import zlib
import ipaddress
import inspect
import logging
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer, HTTPServer
from typing import Any, Callable, Union, Annotated, BinaryIO, NotRequired, get_origin, get_args, get_type_hints, is_typeddict
from types import UnionType
from urllib.parse import urlparse, parse_qs, urlunparse
from io import BufferedIOBase

from .jsonrpc import JsonRpcRegistry, JsonRpcError, JsonRpcException, get_current_request_id, register_pending_request, unregister_pending_request, cancel_request

EXTERNAL_BASE_HEADER = "X-IDA-MCP-External-Base"

logger = logging.getLogger(__name__)

_request_context = threading.local()

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


def _origin_allowed_by_policy(
    allowed: Callable[[str], bool] | list[str] | str | None,
    origin: str,
) -> bool:
    if not origin or allowed is None:
        return False
    if callable(allowed):
        return allowed(origin)
    if isinstance(allowed, str):
        allowed = [allowed]
    return "*" in allowed or origin in allowed


def _parse_host_header(host_header: str | None) -> str | None:
    if not host_header:
        return None

    host_header = host_header.strip()
    if not host_header:
        return None

    if host_header.startswith("["):
        end = host_header.find("]")
        if end == -1:
            return None
        return host_header[1:end]

    if host_header.count(":") == 1:
        return host_header.rsplit(":", 1)[0]

    return host_header


def _is_loopback_host(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host.lower() == "localhost"


def _host_header_allowed_for_bind(bound_host: str, host_header: str | None) -> bool:
    """Reject DNS-rebinding style Host headers when the server is loopback-bound."""
    if host_header is None:
        return True

    host_name = _parse_host_header(host_header)
    if host_name is None:
        return False

    if not _is_loopback_host(bound_host):
        return True

    return _is_loopback_host(host_name)


def set_current_request_external_base_url(url: str | None) -> None:
    setattr(_request_context, "external_base_url", url.rstrip("/") if url else None)


def get_current_request_external_base_url() -> str | None:
    return getattr(_request_context, "external_base_url", None)


def _strip_optional_quotes(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] == '"':
        return value[1:-1]
    return value


def _first_header_value(value: str | None) -> str | None:
    if not value:
        return None
    first = value.split(",", 1)[0].strip()
    return first or None


def _normalize_external_base_url(url: str | None) -> str | None:
    if not url:
        return None
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return None
    path = parsed.path.rstrip("/")
    return urlunparse((parsed.scheme, parsed.netloc, path, "", "", ""))


def _normalize_forwarded_prefix(prefix: str | None) -> str:
    if not prefix:
        return ""
    prefix = _strip_optional_quotes(prefix).strip()
    if not prefix or prefix == "/":
        return ""
    if not prefix.startswith("/"):
        prefix = f"/{prefix}"
    return prefix.rstrip("/")


def _append_forwarded_port(authority: str, port: str | None) -> str:
    if not port:
        return authority
    try:
        parsed = urlparse(f"//{authority}")
        if parsed.hostname is not None and parsed.port is None:
            return f"{authority}:{port}"
    except ValueError:
        pass
    return authority


def _parse_forwarded_header(forwarded: str | None) -> dict[str, str]:
    if not forwarded:
        return {}
    result: dict[str, str] = {}
    first_entry = forwarded.split(",", 1)[0]
    for item in first_entry.split(";"):
        if "=" not in item:
            continue
        key, value = item.split("=", 1)
        key = key.strip().lower()
        value = _strip_optional_quotes(value)
        if key and value:
            result[key] = value
    return result


def _derive_external_base_url(
    headers: dict | Any,
    *,
    bound_host: str | None = None,
    bound_port: int | None = None,
) -> str | None:
    propagated = _normalize_external_base_url(headers.get(EXTERNAL_BASE_HEADER))
    if propagated:
        return propagated

    forwarded = _parse_forwarded_header(headers.get("Forwarded"))
    authority = forwarded.get("host") or _first_header_value(headers.get("X-Forwarded-Host"))
    authority = authority or headers.get("Host")
    if authority:
        authority = authority.strip()

    forwarded_port = _first_header_value(headers.get("X-Forwarded-Port"))
    if authority:
        authority = _append_forwarded_port(authority, forwarded_port)
    elif bound_host is not None and bound_port is not None:
        authority = f"{bound_host}:{bound_port}"

    if not authority:
        return None

    scheme = (
        forwarded.get("proto")
        or _first_header_value(headers.get("X-Forwarded-Proto"))
        or "http"
    ).strip().lower()
    prefix = _normalize_forwarded_prefix(_first_header_value(headers.get("X-Forwarded-Prefix")))
    return _normalize_external_base_url(f"{scheme}://{authority}{prefix}")

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
        if not _origin_allowed_by_policy(self.mcp_server.cors_allowed_origins, origin):
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

    def _check_api_request(self) -> bool:
        """Block browser traffic that violates the configured origin policy.

        Browsers can bypass passive CORS-only defenses during DNS rebinding
        because same-origin requests do not need CORS. Rejecting unexpected Host
        and Origin headers closes that gap while keeping direct clients working.
        """
        bound_host = self.server.server_address[0]
        if not _host_header_allowed_for_bind(bound_host, self.headers.get("Host")):
            self.send_error(403, "Invalid Host")
            return False

        origin = self.headers.get("Origin", "")
        if origin and not _origin_allowed_by_policy(
            self.mcp_server.cors_allowed_origins, origin
        ):
            self.send_error(403, "Invalid Origin")
            return False

        return True

    def do_GET(self):
        if not self._check_api_request():
            return
        match urlparse(self.path).path:
            case "/sse":
                self._handle_sse_get()
            case "/mcp":
                self.send_error(405, "Method Not Allowed")
            case _:
                self.send_error(404, "Not Found")

    def do_POST(self):
        if not self._check_api_request():
            return
        body = self._read_body()
        if body is None:
            return

        match urlparse(self.path).path:
            case "/sse":
                self._handle_sse_post(body)
            case "/mcp":
                self._handle_mcp_post(body)
            case _:
                self.send_error(404, "Not Found")

    def do_OPTIONS(self):
        """Handle CORS preflight requests"""
        if not self._check_api_request():
            return
        self.send_response(200)
        self.send_cors_headers(preflight=True)
        self.end_headers()

    def _read_body(self) -> bytes | None:
        if "chunked" in self.headers.get("Transfer-Encoding", "").lower():
            raw = self._read_chunked()
        else:
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length > self.mcp_server.post_body_limit:
                self.send_error(413, f"Payload Too Large: exceeds {self.mcp_server.post_body_limit} bytes")
                return None
            raw = self.rfile.read(content_length) if content_length > 0 else b""

        if len(raw) > self.mcp_server.post_body_limit:
            self.send_error(413, f"Payload Too Large: exceeds {self.mcp_server.post_body_limit} bytes")
            return None

        return self._decompress_body(raw)

    def _read_chunked(self) -> bytes:
        body = b""
        limit = self.mcp_server.post_body_limit
        while True:
            line = self.rfile.readline().split(b";")[0].strip()
            chunk_size = int(line, 16)
            if chunk_size == 0:
                # Consume trailer fields until blank line
                while self.rfile.readline().strip():
                    pass
                break
            body += self.rfile.read(min(chunk_size, limit + 1 - len(body)))
            if len(body) > limit:
                return body
            self.rfile.readline()
        return body

    def _decompress_body(self, data: bytes) -> bytes:
        encoding = self.headers.get("Content-Encoding", "").lower().strip()
        if encoding in ("gzip", "x-gzip"):
            return gzip.decompress(data)
        elif encoding == "deflate":
            if data[:1] == b'\x78':
                return zlib.decompress(data)
            else:
                return zlib.decompress(data, -15)
        return data

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

            # TCP disconnect: kernel gets FIN/RST immediately, but Python only sees it when we
            # read (EOF) or write (BrokenPipeError). We only write every 30s, so we never "see"
            # the disconnect until then. Fix: use select() to wait for socket readable; when
            # client closes, socket becomes readable and recv() returns 0 (EOF).
            sock = self.connection
            if sock and hasattr(sock, "settimeout"):
                try:
                    sock.settimeout(1.0)
                except OSError:
                    pass

            last_ping = time.time()
            while conn.alive and self.mcp_server._running:
                now = time.time()
                # Detect disconnect without writing: select() says when socket is readable
                if sock:
                    try:
                        r, _, _ = select.select([sock], [], [], 1.0)
                        if r:
                            # Readable: peer closed (EOF) or sent data. SSE client sends nothing.
                            if sock.recv(1, socket.MSG_PEEK) == b"":
                                break
                    except (OSError, socket.error, ConnectionResetError, BrokenPipeError):
                        break
                else:
                    time.sleep(1)

                if now - last_ping > 30:  # Ping every 30 seconds
                    if not conn.send_event("ping", {}):
                        break
                    last_ping = now

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

        sse_conn = self.mcp_server._sse_connections.get(session_id)
        if sse_conn is None or not sse_conn.alive:
            self.send_error(400, f"No active SSE connection found for session {session_id}")
            return

        # Parse extensions from query params and store in thread-local
        extensions = self._parse_extensions(self.path)
        setattr(self.mcp_server._enabled_extensions, "data", extensions)
        setattr(self.mcp_server._transport_session_id, "data", f"sse:{session_id}")
        set_current_request_external_base_url(
            _derive_external_base_url(
                self.headers,
                bound_host=self.server.server_address[0],
                bound_port=self.server.server_address[1],
            )
        )

        try:
            # Dispatch to MCP registry
            setattr(self.mcp_server._protocol_version, "data", "2024-11-05")
            response = self.mcp_server.registry.dispatch(body)
        finally:
            setattr(self.mcp_server._enabled_extensions, "data", set())
            setattr(self.mcp_server._protocol_version, "data", None)
            setattr(self.mcp_server._transport_session_id, "data", None)
            set_current_request_external_base_url(None)

        # Send SSE response if necessary
        if response is not None:
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
        request_method: str | None = None
        try:
            parsed = json.loads(body)
            if isinstance(parsed, dict):
                method = parsed.get("method")
                if isinstance(method, str):
                    request_method = method
        except Exception:
            pass

        mcp_session_id = self.headers.get("Mcp-Session-Id")
        if request_method == "initialize":
            if mcp_session_id is None:
                mcp_session_id = str(uuid.uuid4())
            self.mcp_server.register_http_session(mcp_session_id)
        elif self.mcp_server.require_streamable_http_session:
            if mcp_session_id is None:
                self.send_error(
                    400,
                    "Missing Mcp-Session-Id header. Call initialize first and "
                    "reuse the returned Mcp-Session-Id.",
                )
                return
            if not self.mcp_server.has_http_session(mcp_session_id):
                logger.info(
                    "[MCP] Re-registering HTTP session %s after reconnect",
                    mcp_session_id,
                )
                self.mcp_server.register_http_session(mcp_session_id)

        # Parse extensions from query params and store in thread-local
        extensions = self._parse_extensions(self.path)
        setattr(self.mcp_server._enabled_extensions, "data", extensions)
        setattr(
            self.mcp_server._transport_session_id,
            "data",
            f"http:{mcp_session_id}" if mcp_session_id else "http:anonymous",
        )
        set_current_request_external_base_url(
            _derive_external_base_url(
                self.headers,
                bound_host=self.server.server_address[0],
                bound_port=self.server.server_address[1],
            )
        )

        # Dispatch to MCP registry
        setattr(self.mcp_server._protocol_version, "data", "2025-06-18")
        try:
            response = self.mcp_server.registry.dispatch(body)
        finally:
            setattr(self.mcp_server._enabled_extensions, "data", set())
            setattr(self.mcp_server._protocol_version, "data", None)
            setattr(self.mcp_server._transport_session_id, "data", None)
            set_current_request_external_base_url(None)

        def send_response(status: int, body: bytes):
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            if mcp_session_id is not None:
                self.send_header("Mcp-Session-Id", mcp_session_id)
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
        self._http_sessions: dict[str, float] = {}
        self._http_sessions_lock = threading.Lock()
        self.http_session_ttl_sec = 24 * 60 * 60
        self.http_session_max_count = 4096
        self._protocol_version = threading.local()
        self._transport_session_id = threading.local()
        self._enabled_extensions = threading.local()  # set[str] per request
        self._extensions_registry = extensions if extensions is not None else {}  # group -> set of tool names
        self.require_streamable_http_session = False

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
        self.registry.methods["notifications/initialized"] = self._mcp_notifications_initialized
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
            logger.info("[MCP] Server is already running")
            return

        # Create server with deferred binding
        assert issubclass(request_handler, McpHttpRequestHandler)
        self._http_server = (ThreadingHTTPServer if background else HTTPServer)(
            (host, port),
            request_handler,
            bind_and_activate=False
        )
        # Fast restarts: skip TCP TIME_WAIT so a port can be reused immediately
        # after the server stops. On Windows, SO_REUSEADDR is dangerous (allows
        # multiple processes to bind the same port silently), so we use
        # SO_EXCLUSIVEADDRUSE instead, which still allows TIME_WAIT reuse but
        # prevents port hijacking. On Unix, SO_REUSEADDR is the correct option.
        import sys
        if sys.platform == "win32":
            import socket
            self._http_server.allow_reuse_address = False
            self._http_server.socket.setsockopt(
                socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1  # type: ignore[attr-defined]
            )
        else:
            self._http_server.allow_reuse_address = True

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

        logger.info("[MCP] Server started")
        logger.info("  Streamable HTTP: http://%s:%s/mcp", host, port)
        logger.info("  SSE: http://%s:%s/sse", host, port)

        def serve_forever():
            try:
                self._http_server.serve_forever() # type: ignore
            except Exception:
                logger.exception("[MCP] Server error")
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

        logger.info("[MCP] Server stopped")

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

                setattr(self._transport_session_id, "data", "stdio:default")
                try:
                    response = self.registry.dispatch(request)
                finally:
                    setattr(self._transport_session_id, "data", None)
                if response is not None:
                    stdout.write(json.dumps(response).encode("utf-8") + b"\n")
                    stdout.flush()
            except (BrokenPipeError, KeyboardInterrupt): # Client disconnected
                break

    def get_current_transport_session_id(self) -> str | None:
        return getattr(self._transport_session_id, "data", None)

    def _prune_http_sessions_locked(self, now: float) -> None:
        if self.http_session_ttl_sec > 0:
            cutoff = now - self.http_session_ttl_sec
            expired = [
                session_id
                for session_id, last_seen in self._http_sessions.items()
                if last_seen < cutoff
            ]
            for session_id in expired:
                self._http_sessions.pop(session_id, None)

        if self.http_session_max_count > 0:
            while len(self._http_sessions) > self.http_session_max_count:
                oldest = next(iter(self._http_sessions))
                self._http_sessions.pop(oldest, None)

    def register_http_session(self, session_id: str) -> None:
        now = time.monotonic()
        with self._http_sessions_lock:
            # Refresh existing IDs by moving them to the insertion-order tail.
            self._http_sessions.pop(session_id, None)
            self._http_sessions[session_id] = now
            self._prune_http_sessions_locked(now)

    def has_http_session(self, session_id: str) -> bool:
        now = time.monotonic()
        with self._http_sessions_lock:
            self._prune_http_sessions_locked(now)
            if session_id not in self._http_sessions:
                return False
            self._http_sessions.pop(session_id, None)
            self._http_sessions[session_id] = now
            return True

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
                "content": [{"type": "text", "text": json.dumps(result, separators=(",", ":"))}],
                "structuredContent": result if isinstance(result, dict) else {"result": result},
                "isError": False,
            }
        finally:
            if request_id is not None:
                unregister_pending_request(request_id)

    def _mcp_notifications_initialized(self) -> None:
        """MCP notifications/initialized - client signals initialization complete"""
        # Notifications don't return a response

    def _mcp_notifications_cancelled(self, requestId: int | str, reason: str | None = None) -> None:
        """MCP notifications/cancelled - cancel an in-flight request"""
        if cancel_request(requestId):
            logger.info(
                "[MCP] Cancelled request %s: %s",
                requestId,
                reason or "no reason",
            )
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
                            "text": json.dumps({"error": error.get("message", "Unknown error")}, separators=(",", ":")),
                        }],
                        "isError": True,
                    }

                result = tool_response.get("result") if tool_response else None
                return {
                    "contents": [{
                        "uri": uri,
                        "mimeType": "application/json",
                        "text": json.dumps(result, separators=(",", ":")),
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
                }, separators=(",", ":")),
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
            result = json.dumps(result, separators=(",", ":"))
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

    def _schema_is_object_like(self, schema: dict) -> bool:
        """Check if a JSON schema always describes a dict at runtime.

        Handles plain objects and anyOf unions where every variant is an object,
        which matches the unwrapped pass-through in _mcp_tools_call.
        """
        if schema.get("type") == "object":
            return True
        if "anyOf" in schema:
            return all(self._schema_is_object_like(s) for s in schema["anyOf"])
        return False

    def _type_to_json_schema(self, py_type: Any) -> dict:
        """Convert Python type hint to JSON schema object"""
        if py_type is Any:
            return {}

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

            # Wrap non-object returns in a "result" property.
            # _mcp_tools_call passes dicts through unwrapped, so union-of-objects
            # (anyOf where every variant is an object) must not be wrapped either.
            if not self._schema_is_object_like(return_schema):
                return_schema = {
                    "type": "object",
                    "properties": {"result": return_schema},
                    "required": ["result"],
                }
            elif return_schema.get("type") != "object":
                # anyOf-of-objects: MCP spec requires outputSchema root to be
                # type:"object". Hoist it so validators (e.g. MCP Inspector)
                # accept the schema while anyOf still constrains the variants.
                return_schema = {"type": "object", **return_schema}

            schema["outputSchema"] = return_schema

        return schema
