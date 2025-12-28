"""
IDA Pro MCP Session Manager

A headless daemon that manages multiple IDA idalib sessions.
Each session runs in its own subprocess with idalib, allowing LLMs to:
1. Open binary files dynamically
2. Manage multiple binaries simultaneously
3. Route commands to specific sessions

Communication: Unix socket (primary) or TCP (fallback for Windows)
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
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Optional

logger = logging.getLogger(__name__)

# Default paths
DEFAULT_SOCKET_PATH = "/tmp/ida-mcp-session.sock"
DEFAULT_TCP_HOST = "127.0.0.1"
DEFAULT_TCP_PORT = 13380

# Port range for idalib sessions
SESSION_PORT_START = 13400
SESSION_PORT_END = 13500


@dataclass
class Session:
    """Represents an active IDA session"""

    session_id: str
    binary_path: str
    port: int
    pid: int
    status: str  # "starting", "ready", "error", "closed"
    created_at: float
    error_message: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)


class SessionManager:
    """Manages multiple IDA idalib sessions"""

    def __init__(self, unsafe: bool = False, verbose: bool = False):
        self.sessions: dict[str, Session] = {}
        self.processes: dict[str, subprocess.Popen] = {}
        self.active_session_id: Optional[str] = None
        self.unsafe = unsafe
        self.verbose = verbose
        self._lock = threading.Lock()
        self._port_counter = SESSION_PORT_START
        self._running = False

    def _find_available_port(self) -> int:
        """Find an available port for a new session"""
        with self._lock:
            # Try ports in range
            for port in range(self._port_counter, SESSION_PORT_END):
                # Check if port is in use by any session
                in_use = any(s.port == port for s in self.sessions.values())
                if not in_use:
                    # Quick socket check
                    try:
                        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                            s.bind(("127.0.0.1", port))
                            self._port_counter = port + 1
                            return port
                    except OSError:
                        continue

            # Wrap around
            self._port_counter = SESSION_PORT_START
            raise RuntimeError("No available ports for new session")

    def create_session(self, binary_path: str) -> Session:
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

        # Start a thread to monitor the process
        thread = threading.Thread(
            target=self._monitor_session, args=(session_id,), daemon=True
        )
        thread.start()

        # Wait for the session to be ready (or fail)
        self._wait_for_session_ready(session_id, timeout=60)

        return self.sessions[session_id]

    def _wait_for_session_ready(self, session_id: str, timeout: float = 60):
        """Wait for session to become ready or fail"""
        start_time = time.time()
        port = self.sessions[session_id].port

        while time.time() - start_time < timeout:
            # Check if process is still running
            with self._lock:
                if session_id not in self.sessions:
                    raise RuntimeError("Session was closed")

                session = self.sessions[session_id]
                if session.status == "error":
                    raise RuntimeError(
                        session.error_message or "Session failed to start"
                    )

            # Try to connect to the session
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)
                    s.connect(("127.0.0.1", port))
                    # Connection succeeded - session is ready
                    with self._lock:
                        if session_id in self.sessions:
                            self.sessions[session_id].status = "ready"
                    return
            except (socket.error, socket.timeout):
                pass

            time.sleep(0.5)

        raise TimeoutError(f"Session {session_id} did not become ready in {timeout}s")

    def _monitor_session(self, session_id: str):
        """Monitor a session's subprocess"""
        with self._lock:
            if session_id not in self.processes:
                return
            process = self.processes[session_id]

        # Read stdout/stderr
        output_lines = []
        try:
            for line in process.stdout:
                output_lines.append(line.rstrip())
                if self.verbose:
                    logger.debug(f"[{session_id}] {line.rstrip()}")
        except:
            pass

        # Wait for process to exit
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

    def list_sessions(self) -> list[dict]:
        """List all sessions"""
        with self._lock:
            return [s.to_dict() for s in self.sessions.values()]

    def get_session(self, session_id: str) -> Optional[Session]:
        """Get a session by ID"""
        with self._lock:
            return self.sessions.get(session_id)

    def destroy_session(self, session_id: str) -> bool:
        """Destroy a session"""
        with self._lock:
            if session_id not in self.sessions:
                return False

            session = self.sessions[session_id]
            process = self.processes.get(session_id)

            if process and process.poll() is None:
                # Terminate the process
                try:
                    process.terminate()
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()

            # Clean up
            if session_id in self.processes:
                del self.processes[session_id]
            del self.sessions[session_id]

            if self.active_session_id == session_id:
                self.active_session_id = None

            logger.info(f"Destroyed session {session_id}")
            return True

    def set_active_session(self, session_id: str) -> bool:
        """Set the active session for routing"""
        with self._lock:
            if session_id not in self.sessions:
                return False
            self.active_session_id = session_id
            return True

    def get_active_session(self) -> Optional[Session]:
        """Get the active session"""
        with self._lock:
            if self.active_session_id:
                return self.sessions.get(self.active_session_id)
            return None

    def cleanup(self):
        """Clean up all sessions"""
        session_ids = list(self.sessions.keys())
        for session_id in session_ids:
            self.destroy_session(session_id)


class SessionManagerServer:
    """Server that exposes SessionManager over Unix socket or TCP"""

    def __init__(self, manager: SessionManager, socket_path: str = None, tcp_port: int = None):
        self.manager = manager
        self.socket_path = socket_path
        self.tcp_port = tcp_port
        self._server_socket: Optional[socket.socket] = None
        self._running = False

    def _handle_client(self, client_socket: socket.socket):
        """Handle a client connection"""
        try:
            data = b""
            while True:
                chunk = client_socket.recv(4096)
                if not chunk:
                    break
                data += chunk
                # Try to parse JSON
                try:
                    request = json.loads(data.decode("utf-8"))
                    break
                except json.JSONDecodeError:
                    continue

            if not data:
                return

            response = self._handle_request(request)
            client_socket.sendall(json.dumps(response).encode("utf-8"))

        except Exception as e:
            logger.error(f"Client handler error: {e}")
            try:
                error_response = {"error": str(e)}
                client_socket.sendall(json.dumps(error_response).encode("utf-8"))
            except:
                pass
        finally:
            client_socket.close()

    def _handle_request(self, request: dict) -> dict:
        """Handle a JSON-RPC-like request"""
        method = request.get("method", "")
        params = request.get("params", {})

        try:
            if method == "create_session":
                session = self.manager.create_session(params["binary_path"])
                return {"result": session.to_dict()}

            elif method == "list_sessions":
                sessions = self.manager.list_sessions()
                return {"result": sessions}

            elif method == "get_session":
                session = self.manager.get_session(params["session_id"])
                if session:
                    return {"result": session.to_dict()}
                return {"error": "Session not found"}

            elif method == "destroy_session":
                success = self.manager.destroy_session(params["session_id"])
                return {"result": success}

            elif method == "set_active_session":
                success = self.manager.set_active_session(params["session_id"])
                return {"result": success}

            elif method == "get_active_session":
                session = self.manager.get_active_session()
                if session:
                    return {"result": session.to_dict()}
                return {"result": None}

            elif method == "ping":
                return {"result": "pong"}

            else:
                return {"error": f"Unknown method: {method}"}

        except Exception as e:
            logger.exception(f"Request handler error: {e}")
            return {"error": str(e)}

    def serve(self):
        """Start the server"""
        self._running = True

        if self.socket_path and sys.platform != "win32":
            # Unix socket
            if os.path.exists(self.socket_path):
                os.unlink(self.socket_path)

            self._server_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self._server_socket.bind(self.socket_path)
            os.chmod(self.socket_path, 0o600)  # Restrict permissions
            logger.info(f"Session manager listening on unix://{self.socket_path}")
        else:
            # TCP fallback
            port = self.tcp_port or DEFAULT_TCP_PORT
            self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server_socket.bind((DEFAULT_TCP_HOST, port))
            logger.info(f"Session manager listening on tcp://{DEFAULT_TCP_HOST}:{port}")

        self._server_socket.listen(5)
        self._server_socket.settimeout(1)  # Allow periodic shutdown checks

        while self._running:
            try:
                client_socket, _ = self._server_socket.accept()
                thread = threading.Thread(
                    target=self._handle_client, args=(client_socket,), daemon=True
                )
                thread.start()
            except socket.timeout:
                continue
            except Exception as e:
                if self._running:
                    logger.error(f"Accept error: {e}")

    def stop(self):
        """Stop the server"""
        self._running = False
        if self._server_socket:
            self._server_socket.close()
        if self.socket_path and os.path.exists(self.socket_path):
            os.unlink(self.socket_path)


class SessionManagerClient:
    """Client for communicating with the session manager daemon"""

    def __init__(self, socket_path: str = None, tcp_host: str = None, tcp_port: int = None):
        self.socket_path = socket_path or DEFAULT_SOCKET_PATH
        self.tcp_host = tcp_host or DEFAULT_TCP_HOST
        self.tcp_port = tcp_port or DEFAULT_TCP_PORT

    def _connect(self) -> socket.socket:
        """Connect to the session manager"""
        # Try Unix socket first
        if sys.platform != "win32" and os.path.exists(self.socket_path):
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.connect(self.socket_path)
            return sock

        # Fall back to TCP
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.tcp_host, self.tcp_port))
        return sock

    def _request(self, method: str, **params) -> dict:
        """Send a request to the session manager"""
        sock = self._connect()
        try:
            request = {"method": method, "params": params}
            sock.sendall(json.dumps(request).encode("utf-8"))
            sock.shutdown(socket.SHUT_WR)

            data = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk

            response = json.loads(data.decode("utf-8"))
            if "error" in response:
                raise RuntimeError(response["error"])
            return response.get("result")
        finally:
            sock.close()

    def ping(self) -> bool:
        """Check if session manager is running"""
        try:
            result = self._request("ping")
            return result == "pong"
        except:
            return False

    def create_session(self, binary_path: str) -> dict:
        """Create a new session"""
        return self._request("create_session", binary_path=binary_path)

    def list_sessions(self) -> list[dict]:
        """List all sessions"""
        return self._request("list_sessions")

    def get_session(self, session_id: str) -> Optional[dict]:
        """Get a session by ID"""
        return self._request("get_session", session_id=session_id)

    def destroy_session(self, session_id: str) -> bool:
        """Destroy a session"""
        return self._request("destroy_session", session_id=session_id)

    def set_active_session(self, session_id: str) -> bool:
        """Set the active session"""
        return self._request("set_active_session", session_id=session_id)

    def get_active_session(self) -> Optional[dict]:
        """Get the active session"""
        return self._request("get_active_session")


def main():
    parser = argparse.ArgumentParser(
        description="IDA Pro MCP Session Manager - manages multiple IDA idalib sessions"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Show debug messages"
    )
    parser.add_argument(
        "--socket",
        type=str,
        default=DEFAULT_SOCKET_PATH,
        help=f"Unix socket path (default: {DEFAULT_SOCKET_PATH})",
    )
    parser.add_argument(
        "--tcp-port",
        type=int,
        default=DEFAULT_TCP_PORT,
        help=f"TCP port for Windows/fallback (default: {DEFAULT_TCP_PORT})",
    )
    parser.add_argument(
        "--unsafe", action="store_true", help="Enable unsafe functions in sessions"
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

    manager = SessionManager(unsafe=args.unsafe, verbose=args.verbose)
    server = SessionManagerServer(
        manager, socket_path=args.socket, tcp_port=args.tcp_port
    )

    def signal_handler(signum, frame):
        logger.info("Shutting down...")
        server.stop()
        manager.cleanup()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    server.serve()


if __name__ == "__main__":
    main()
