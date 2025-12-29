"""
IDA Pro MCP Server with Session Management

This MCP server provides tools for:
1. Opening and managing multiple binary analysis sessions (via idalib)
2. Routing IDA tool calls to the active session
3. Full MCP protocol support (stdio and HTTP/SSE)

Usage:
    # Start the session-aware MCP server
    uv run idalib-session-mcp

    # With SSE transport
    uv run idalib-session-mcp --transport http://127.0.0.1:8744/sse

    # Generate tools cache (run once to enable all tools on startup)
    uv run idalib-session-mcp --generate-tools-cache /path/to/any/binary
"""

import os
import sys
import json
import time
import uuid
import signal
import socket
import logging
import argparse
import threading
import subprocess
import http.client
import traceback
from pathlib import Path
from typing import Optional, Any, Annotated
from dataclasses import dataclass, asdict
from urllib.parse import urlparse

# Import zeromcp from ida_mcp package
if os.path.exists(os.path.join(os.path.dirname(__file__), "ida_mcp")):
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "ida_mcp"))
    from zeromcp import McpServer
    from zeromcp.jsonrpc import JsonRpcResponse, JsonRpcRequest

    sys.path.pop(0)
else:
    from ida_pro_mcp.ida_mcp.zeromcp import McpServer
    from ida_pro_mcp.ida_mcp.zeromcp.jsonrpc import JsonRpcResponse, JsonRpcRequest

logger = logging.getLogger(__name__)

# Port range for idalib sessions
SESSION_PORT_START = 13400
SESSION_PORT_END = 13500

# Tools cache file location
TOOLS_CACHE_FILE = os.path.join(os.path.dirname(__file__), "ida_tools_cache.json")


def load_cached_tools() -> Optional[list[dict]]:
    """Load cached IDA tools from file"""
    if os.path.exists(TOOLS_CACHE_FILE):
        try:
            with open(TOOLS_CACHE_FILE, "r") as f:
                tools = json.load(f)
                logger.info(f"Loaded {len(tools)} cached IDA tools from {TOOLS_CACHE_FILE}")
                return tools
        except Exception as e:
            logger.warning(f"Failed to load tools cache: {e}")
    return None


def save_cached_tools(tools: list[dict]) -> None:
    """Save IDA tools to cache file"""
    try:
        with open(TOOLS_CACHE_FILE, "w") as f:
            json.dump(tools, f, indent=2)
        logger.info(f"Saved {len(tools)} IDA tools to {TOOLS_CACHE_FILE}")
    except Exception as e:
        logger.warning(f"Failed to save tools cache: {e}")


@dataclass
class Session:
    """Represents an active IDA session"""

    session_id: str
    binary_path: str
    port: int
    pid: int
    status: str  # "starting", "analyzing", "ready", "error", "closed"
    created_at: float
    error_message: Optional[str] = None
    analysis_time: Optional[float] = None  # Time taken for analysis in seconds

    def to_dict(self) -> dict:
        return asdict(self)


class SessionMcpServer:
    """MCP Server with integrated session management"""

    def __init__(self, unsafe: bool = False, verbose: bool = False):
        self.mcp = McpServer("ida-pro-mcp-session")
        self.sessions: dict[str, Session] = {}
        self.processes: dict[str, subprocess.Popen] = {}
        self.active_session_id: Optional[str] = None
        self.unsafe = unsafe
        self.verbose = verbose
        self._lock = threading.Lock()
        self._port_counter = SESSION_PORT_START

        # Load cached IDA tools from file (for startup without session)
        self._cached_ida_tools: Optional[list[dict]] = load_cached_tools()

        # Register session management tools
        self._register_session_tools()

        # Patch the dispatch to route IDA tools to active session
        self._patch_dispatch()

    def _register_session_tools(self):
        """Register session management MCP tools"""

        @self.mcp.tool
        def session_open(
            binary_path: Annotated[str, "Path to the binary file to analyze"],
        ) -> dict:
            """Open a new IDA analysis session for a binary file.

            Creates a new idalib session that analyzes the binary.
            The session becomes the active session automatically.
            Returns session info including session_id and port.
            """
            try:
                session = self._create_session(binary_path)
                self.active_session_id = session.session_id
                return {
                    "success": True,
                    "session": session.to_dict(),
                    "message": f"Session {session.session_id} created and activated",
                }
            except Exception as e:
                return {
                    "success": False,
                    "error": str(e),
                }

        @self.mcp.tool
        def session_list() -> dict:
            """List all active IDA analysis sessions.

            Returns information about all sessions including their
            session_id, binary_path, port, status, and whether active.
            """
            with self._lock:
                sessions = []
                for s in self.sessions.values():
                    info = s.to_dict()
                    info["is_active"] = s.session_id == self.active_session_id
                    sessions.append(info)
                return {
                    "sessions": sessions,
                    "active_session_id": self.active_session_id,
                    "total_count": len(sessions),
                }

        @self.mcp.tool
        def session_switch(
            session_id: Annotated[str, "ID of the session to switch to"],
        ) -> dict:
            """Switch to a different IDA analysis session.

            Makes the specified session the active session.
            All subsequent IDA tool calls will be routed to this session.
            """
            with self._lock:
                if session_id not in self.sessions:
                    return {
                        "success": False,
                        "error": f"Session {session_id} not found",
                    }

                session = self.sessions[session_id]
                if session.status != "ready":
                    return {
                        "success": False,
                        "error": f"Session {session_id} is not ready (status: {session.status})",
                    }

                self.active_session_id = session_id
                return {
                    "success": True,
                    "session": session.to_dict(),
                    "message": f"Switched to session {session_id}",
                }

        @self.mcp.tool
        def session_close(
            session_id: Annotated[str, "ID of the session to close"],
        ) -> dict:
            """Close an IDA analysis session.

            Terminates the idalib process and removes the session.
            If the closed session was active, no session will be active.
            """
            success = self._destroy_session(session_id)
            if success:
                return {
                    "success": True,
                    "message": f"Session {session_id} closed",
                }
            else:
                return {
                    "success": False,
                    "error": f"Session {session_id} not found",
                }

        @self.mcp.tool
        def session_info(
            session_id: Annotated[str, "ID of the session to get info for"] = None,
        ) -> dict:
            """Get detailed information about a session.

            If session_id is not provided, returns info about the active session.
            """
            with self._lock:
                if session_id is None:
                    session_id = self.active_session_id

                if session_id is None:
                    return {
                        "error": "No active session. Use session_open to create one.",
                    }

                if session_id not in self.sessions:
                    return {
                        "error": f"Session {session_id} not found",
                    }

                session = self.sessions[session_id]
                info = session.to_dict()
                info["is_active"] = session_id == self.active_session_id
                return info

    def _patch_dispatch(self):
        """Patch MCP dispatch to route IDA tool calls to active session"""
        original_dispatch = self.mcp.registry.dispatch

        def patched_dispatch(
            request: dict | str | bytes | bytearray,
        ) -> JsonRpcResponse | None:
            # Parse request if needed
            if not isinstance(request, dict):
                request_obj: JsonRpcRequest = json.loads(request)
            else:
                request_obj: JsonRpcRequest = request

            method = request_obj.get("method", "")

            # Handle session management and protocol methods locally
            local_methods = [
                "initialize",
                "ping",
                "tools/list",
                "tools/call",
                "resources/list",
                "resources/templates/list",
                "resources/read",
                "prompts/list",
                "prompts/get",
            ]

            # Check if this is a session tool or protocol method
            if method in local_methods:
                # For tools/call, check if it's a session tool
                if method == "tools/call":
                    tool_name = request_obj.get("params", {}).get("name", "")
                    if tool_name.startswith("session_"):
                        return original_dispatch(request)

                    # Route to active session
                    return self._route_to_session(request_obj)

                # For tools/list, merge session tools with IDA tools
                if method == "tools/list":
                    return self._merge_tools_list(original_dispatch(request))

                return original_dispatch(request)

            # Notifications
            if method.startswith("notifications/"):
                return original_dispatch(request)

            # Unknown method - try routing to session
            return self._route_to_session(request_obj)

        self.mcp.registry.dispatch = patched_dispatch

    def _route_to_session(self, request: JsonRpcRequest) -> JsonRpcResponse | None:
        """Route a request to the active IDA session"""
        with self._lock:
            if self.active_session_id is None:
                return self._error_response(
                    request.get("id"),
                    -32001,
                    "No active session. Use session_open to create one.",
                )

            session = self.sessions.get(self.active_session_id)
            if session is None or session.status != "ready":
                return self._error_response(
                    request.get("id"),
                    -32001,
                    "Active session is not ready.",
                )

            port = session.port

        # Forward request to session's MCP server
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=120)
            body = json.dumps(request)
            conn.request("POST", "/mcp", body, {"Content-Type": "application/json"})
            response = conn.getresponse()
            data = response.read().decode()
            return json.loads(data)
        except Exception as e:
            full_info = traceback.format_exc()
            return self._error_response(
                request.get("id"),
                -32000,
                f"Failed to connect to IDA session: {e}\n{full_info}",
            )
        finally:
            conn.close()

    def _merge_tools_list(self, local_response: JsonRpcResponse) -> JsonRpcResponse:
        """Merge local session tools with IDA tools from active session"""
        if local_response is None:
            return None

        # Start with local tools
        local_tools = local_response.get("result", {}).get("tools", [])

        # If we have cached IDA tools, use them
        if self._cached_ida_tools is not None:
            all_tools = local_tools + self._cached_ida_tools
            return {
                "jsonrpc": "2.0",
                "result": {"tools": all_tools},
                "id": local_response.get("id"),
            }

        # Try to get tools from any ready session (not just active)
        port = None
        with self._lock:
            for session in self.sessions.values():
                if session.status == "ready":
                    port = session.port
                    break

        if port is None:
            return local_response

        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            request = {"jsonrpc": "2.0", "method": "tools/list", "id": 1}
            conn.request(
                "POST", "/mcp", json.dumps(request), {"Content-Type": "application/json"}
            )
            response = conn.getresponse()
            data = json.loads(response.read().decode())
            session_tools = data.get("result", {}).get("tools", [])

            # Cache the IDA tools for future use (both in memory and to file)
            self._cached_ida_tools = session_tools
            save_cached_tools(session_tools)
            logger.info(f"Cached {len(session_tools)} IDA tools")

            # Merge tools (local first, then session)
            all_tools = local_tools + session_tools
            return {
                "jsonrpc": "2.0",
                "result": {"tools": all_tools},
                "id": local_response.get("id"),
            }
        except Exception as e:
            logger.warning(f"Failed to get tools from session: {e}")
            return local_response
        finally:
            conn.close()

    def _error_response(
        self, id: Any, code: int, message: str
    ) -> JsonRpcResponse:
        """Create a JSON-RPC error response"""
        if id is None:
            return None
        return {
            "jsonrpc": "2.0",
            "error": {"code": code, "message": message},
            "id": id,
        }

    def _find_available_port(self) -> int:
        """Find an available port for a new session"""
        for port in range(self._port_counter, SESSION_PORT_END):
            in_use = any(s.port == port for s in self.sessions.values())
            if not in_use:
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.bind(("127.0.0.1", port))
                        self._port_counter = port + 1
                        return port
                except OSError:
                    continue

        self._port_counter = SESSION_PORT_START
        raise RuntimeError("No available ports for new session")

    def _create_session(self, binary_path: str) -> Session:
        """Create a new IDA session for a binary"""
        binary_path = os.path.abspath(binary_path)

        if not os.path.exists(binary_path):
            raise FileNotFoundError(f"Binary not found: {binary_path}")

        session_id = str(uuid.uuid4())[:8]
        port = self._find_available_port()

        # Start idalib subprocess
        cmd = [
            sys.executable,
            "-m",
            "ida_pro_mcp.idalib_server",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--session-id",
            session_id,
            binary_path,
        ]

        if self.unsafe:
            cmd.append("--unsafe")
        if self.verbose:
            cmd.append("--verbose")

        logger.info(f"Starting session {session_id}: {' '.join(cmd)}")

        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
        except Exception as e:
            raise RuntimeError(f"Failed to start idalib: {e}")

        session = Session(
            session_id=session_id,
            binary_path=binary_path,
            port=port,
            pid=process.pid,
            status="starting",
            created_at=time.time(),
        )

        with self._lock:
            self.sessions[session_id] = session
            self.processes[session_id] = process

        # Start monitor thread
        thread = threading.Thread(
            target=self._monitor_session, args=(session_id,), daemon=True
        )
        thread.start()

        # Wait for ready
        self._wait_for_session_ready(session_id, timeout=120)

        return self.sessions[session_id]

    def _wait_for_session_ready(self, session_id: str, timeout: float = 120):
        """Wait for session to become ready"""
        start_time = time.time()
        port = self.sessions[session_id].port

        while time.time() - start_time < timeout:
            with self._lock:
                if session_id not in self.sessions:
                    raise RuntimeError("Session was closed")

                session = self.sessions[session_id]
                if session.status == "error":
                    raise RuntimeError(
                        session.error_message or "Session failed to start"
                    )

            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)
                    s.connect(("127.0.0.1", port))
                    with self._lock:
                        if session_id in self.sessions:
                            self.sessions[session_id].status = "ready"
                    return
            except (socket.error, socket.timeout):
                pass

            time.sleep(0.5)

        raise TimeoutError(f"Session {session_id} did not become ready in {timeout}s")

    def _monitor_session(self, session_id: str):
        """Monitor a session subprocess and parse output"""
        with self._lock:
            if session_id not in self.processes:
                return
            process = self.processes[session_id]

        output_lines = []
        try:
            for line in process.stdout:
                line = line.rstrip()
                output_lines.append(line)
                if self.verbose:
                    logger.debug(f"[{session_id}] {line}")

                # Parse [SESSION_READY] marker to extract analysis time
                if line.startswith("[SESSION_READY]"):
                    # Parse: [SESSION_READY] session_id=xxx port=xxx analysis_time=xxx
                    try:
                        parts = line.split()
                        for part in parts[1:]:
                            if part.startswith("analysis_time="):
                                analysis_time_str = part.split("=")[1]
                                if analysis_time_str != "None":
                                    with self._lock:
                                        if session_id in self.sessions:
                                            self.sessions[session_id].analysis_time = float(analysis_time_str)
                                            logger.info(f"Session {session_id} analysis completed in {analysis_time_str}s")
                    except Exception as e:
                        logger.warning(f"Failed to parse SESSION_READY: {e}")
        except:
            pass

        return_code = process.wait()

        with self._lock:
            if session_id in self.sessions:
                if return_code != 0:
                    self.sessions[session_id].status = "error"
                    self.sessions[session_id].error_message = (
                        f"Process exited with code {return_code}: "
                        + "\n".join(output_lines[-10:])
                    )
                else:
                    self.sessions[session_id].status = "closed"

    def _destroy_session(self, session_id: str) -> bool:
        """Destroy a session, saving the IDB before termination"""
        with self._lock:
            if session_id not in self.sessions:
                return False

            process = self.processes.get(session_id)

            if process and process.poll() is None:
                try:
                    # Send SIGTERM to trigger graceful shutdown with IDB save
                    logger.info(f"Sending SIGTERM to session {session_id} for graceful shutdown with IDB save...")
                    process.terminate()
                    # Wait longer for IDB save to complete (up to 30 seconds)
                    process.wait(timeout=30)
                    logger.info(f"Session {session_id} terminated gracefully with IDB saved")
                except subprocess.TimeoutExpired:
                    logger.warning(f"Session {session_id} did not terminate in time, force killing...")
                    process.kill()
                    process.wait()

            if session_id in self.processes:
                del self.processes[session_id]
            del self.sessions[session_id]

            if self.active_session_id == session_id:
                self.active_session_id = None

            logger.info(f"Destroyed session {session_id}")
            return True

    def cleanup(self):
        """Clean up all sessions, saving IDBs before termination"""
        session_ids = list(self.sessions.keys())
        if session_ids:
            logger.info(f"Saving and closing {len(session_ids)} session(s)...")
        for session_id in session_ids:
            self._destroy_session(session_id)

    def serve(self, host: str, port: int, *, background: bool = True):
        """Start the MCP server"""
        self.mcp.serve(host, port, background=background)

    def stop(self):
        """Stop the MCP server"""
        self.mcp.stop()

    def stdio(self):
        """Run in stdio mode"""
        self.mcp.stdio()


def generate_tools_cache(binary_path: str, unsafe: bool = False, verbose: bool = False):
    """Generate tools cache by opening a temporary session"""
    print(f"Generating tools cache using binary: {binary_path}")

    server = SessionMcpServer(unsafe=unsafe, verbose=verbose)

    try:
        # Open a session to get tools
        session = server._create_session(binary_path)
        print(f"Session created: {session.session_id}")

        # Get tools from session
        port = session.port
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
        request = {"jsonrpc": "2.0", "method": "tools/list", "id": 1}
        conn.request("POST", "/mcp", json.dumps(request), {"Content-Type": "application/json"})
        response = conn.getresponse()
        data = json.loads(response.read().decode())
        tools = data.get("result", {}).get("tools", [])
        conn.close()

        # Save to cache
        save_cached_tools(tools)
        print(f"Cached {len(tools)} tools to {TOOLS_CACHE_FILE}")

    finally:
        server.cleanup()


def main():
    parser = argparse.ArgumentParser(
        description="IDA Pro MCP Server with Session Management"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Show debug messages"
    )
    parser.add_argument(
        "--transport",
        type=str,
        default="stdio",
        help="MCP transport: stdio (default) or http://host:port/sse",
    )
    parser.add_argument(
        "--unsafe", action="store_true", help="Enable unsafe functions (DANGEROUS)"
    )
    parser.add_argument(
        "--generate-tools-cache",
        type=str,
        metavar="BINARY",
        help="Generate tools cache using the specified binary, then exit",
    )
    args = parser.parse_args()

    if args.verbose:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO

    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # Handle --generate-tools-cache
    if args.generate_tools_cache:
        generate_tools_cache(args.generate_tools_cache, args.unsafe, args.verbose)
        return

    server = SessionMcpServer(unsafe=args.unsafe, verbose=args.verbose)

    def signal_handler(signum, frame):
        logger.info("Shutting down, saving all IDBs...")
        server.cleanup()
        server.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        if args.transport == "stdio":
            server.stdio()
        else:
            url = urlparse(args.transport)
            if url.hostname is None or url.port is None:
                raise Exception(f"Invalid transport URL: {args.transport}")
            server.serve(url.hostname, url.port, background=False)
    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        server.cleanup()


if __name__ == "__main__":
    main()
