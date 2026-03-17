"""idalib Pool Manager — manages a pool of idalib_server subprocess instances.

Each instance is an independent idalib_server process communicating over a
Unix domain socket.  The pool enforces a 1-instance-per-session model: every
instance holds at most one active IDB at a time.  When the pool is full a new
``open`` evicts the least-recently-used session.

Key invariants
--------------
* ``_open_paths`` prevents the same binary from being opened by two instances
  concurrently (IDA creates working files alongside the IDB).
* ``max_instances == 0`` means *unlimited*: a fresh instance is spawned for
  every ``open`` and destroyed on ``close``.
"""

from __future__ import annotations

import http.client
import json
import logging
import os
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class SessionInfo:
    session_id: str
    binary_path: str
    instance_index: int
    last_accessed: float = field(default_factory=time.monotonic)

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "input_path": self.binary_path,
            "filename": os.path.basename(self.binary_path),
            "is_active": True,
            "last_accessed": self.last_accessed,
            "instance_index": self.instance_index,
        }


@dataclass
class InstanceInfo:
    index: int
    socket_path: str
    process: subprocess.Popen
    session_id: str | None = None  # None ⇒ idle


# ---------------------------------------------------------------------------
# Pool Manager
# ---------------------------------------------------------------------------

class PoolManager:
    def __init__(
        self,
        max_instances: int = 1,
        socket_dir: str | None = None,
        idalib_args: list[str] | None = None,
    ):
        self.max_instances = max_instances  # 0 = unlimited
        self.socket_dir = socket_dir or tempfile.mkdtemp(prefix="idalib-pool-")
        self.idalib_args = idalib_args or []  # extra args forwarded to idalib_server

        self.instances: list[InstanceInfo] = []
        self.sessions: dict[str, SessionInfo] = {}
        self.default_session_id: str | None = None

        # resolved-path → session_id   (prevents concurrent access to same IDB)
        self._open_paths: dict[str, str] = {}
        self._lock = threading.Lock()
        self._next_index = 0

        os.makedirs(self.socket_dir, exist_ok=True)

    # ------------------------------------------------------------------
    # Instance lifecycle
    # ------------------------------------------------------------------

    def _next_socket_path(self) -> str:
        idx = self._next_index
        self._next_index += 1
        return os.path.join(self.socket_dir, f"{idx}.sock")

    def spawn_instance(self) -> InstanceInfo:
        sock_path = self._next_socket_path()
        cmd = [
            sys.executable, "-m", "ida_pro_mcp.idalib_server",
            "--unix-socket", sock_path,
            *self.idalib_args,
        ]
        logger.info("Spawning instance: %s", " ".join(cmd))
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        inst = InstanceInfo(
            index=self._next_index - 1,
            socket_path=sock_path,
            process=proc,
        )
        self.instances.append(inst)
        self._wait_for_ready(inst)
        return inst

    def _wait_for_ready(self, inst: InstanceInfo, timeout: float = 120) -> None:
        """Poll the instance socket until it accepts connections."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if inst.process.poll() is not None:
                raise RuntimeError(
                    f"Instance {inst.index} exited prematurely "
                    f"(code {inst.process.returncode})"
                )
            if os.path.exists(inst.socket_path):
                try:
                    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    sock.connect(inst.socket_path)
                    sock.close()
                    logger.info("Instance %d ready at %s", inst.index, inst.socket_path)
                    return
                except (ConnectionRefusedError, OSError):
                    pass
            time.sleep(0.2)
        raise TimeoutError(
            f"Instance {inst.index} did not become ready within {timeout}s"
        )

    def kill_instance(self, inst: InstanceInfo) -> None:
        logger.info("Killing instance %d (pid %d)", inst.index, inst.process.pid)
        try:
            inst.process.send_signal(signal.SIGTERM)
            inst.process.wait(timeout=10)
        except Exception:
            inst.process.kill()
            inst.process.wait(timeout=5)
        if inst in self.instances:
            self.instances.remove(inst)

    def shutdown_all(self) -> None:
        with self._lock:
            for inst in list(self.instances):
                # Try to save before killing
                if inst.session_id:
                    try:
                        self.forward_tool_call(inst, "idalib_save", {})
                    except Exception:
                        pass
                self.kill_instance(inst)
            self.instances.clear()
            self.sessions.clear()
            self._open_paths.clear()

    # ------------------------------------------------------------------
    # Session operations
    # ------------------------------------------------------------------

    def open_session(
        self,
        binary_path: str,
        session_id: str | None = None,
        run_auto_analysis: bool = True,
    ) -> dict:
        """Open a binary.  Returns an idalib_open-compatible response dict."""
        resolved = str(Path(binary_path).resolve())

        with self._lock:
            # --- path dedup / conflict ---
            if resolved in self._open_paths:
                existing_sid = self._open_paths[resolved]
                if session_id is not None and session_id != existing_sid:
                    return {
                        "error": (
                            f"Binary already open as session '{existing_sid}'. "
                            f"Cannot open with different session_id '{session_id}'."
                        )
                    }
                # Cooperative: return existing session
                sess = self.sessions[existing_sid]
                sess.last_accessed = time.monotonic()
                self.default_session_id = existing_sid
                return {
                    "success": True,
                    "session": sess.to_dict(),
                    "message": f"Returning existing session: {existing_sid}",
                }

            # --- allocate instance ---
            inst = self._allocate_instance_locked()

            # --- generate session id ---
            if session_id is None:
                session_id = str(uuid.uuid4())[:8]

        # --- forward open to instance (outside lock — may be slow) ---
        resp = self.forward_tool_call(inst, "idalib_open", {
            "input_path": resolved,
            "run_auto_analysis": run_auto_analysis,
            "session_id": session_id,
        })

        if isinstance(resp, dict) and resp.get("error"):
            # Open failed — instance stays idle
            return resp

        with self._lock:
            sess = SessionInfo(
                session_id=session_id,
                binary_path=resolved,
                instance_index=inst.index,
            )
            self.sessions[session_id] = sess
            self._open_paths[resolved] = session_id
            inst.session_id = session_id
            self.default_session_id = session_id

        return {
            "success": True,
            "session": sess.to_dict(),
            "message": f"Session created: {session_id}",
        }

    def close_session(self, session_id: str) -> dict:
        with self._lock:
            sess = self.sessions.get(session_id)
            if sess is None:
                return {"success": False, "error": f"Session not found: {session_id}"}

            inst = self._find_instance_locked(sess.instance_index)
            if inst is None:
                # Instance already gone — just clean up
                self._cleanup_session_locked(session_id)
                return {"success": True, "message": f"Session cleaned up: {session_id}"}

        # Forward close (outside lock)
        self.forward_tool_call(inst, "idalib_close", {"session_id": session_id})

        with self._lock:
            self._cleanup_session_locked(session_id)
            inst.session_id = None

            # In unlimited mode, destroy the now-idle instance
            if self.max_instances == 0:
                self.kill_instance(inst)

        return {"success": True, "message": f"Session closed: {session_id}"}

    def _cleanup_session_locked(self, session_id: str) -> None:
        sess = self.sessions.pop(session_id, None)
        if sess:
            self._open_paths.pop(sess.binary_path, None)
        if self.default_session_id == session_id:
            # Pick another session as default, if any
            self.default_session_id = next(iter(self.sessions), None)

    # ------------------------------------------------------------------
    # Instance allocation & LRU
    # ------------------------------------------------------------------

    def _allocate_instance_locked(self) -> InstanceInfo:
        """Find or create an idle instance.  Caller holds ``_lock``."""
        # 1. Find an existing idle instance
        for inst in self.instances:
            if inst.session_id is None:
                return inst

        # 2. Can we spawn a new one?
        if self.max_instances == 0 or len(self.instances) < self.max_instances:
            # Release lock briefly for spawn (I/O heavy)
            self._lock.release()
            try:
                return self.spawn_instance()
            finally:
                self._lock.acquire()

        # 3. Pool full — evict LRU
        return self._evict_lru_locked()

    def _evict_lru_locked(self) -> InstanceInfo:
        """Close the least-recently-used session and return its (now idle) instance."""
        if not self.sessions:
            raise RuntimeError("Pool is full but has no sessions to evict")

        lru_sid = min(self.sessions, key=lambda s: self.sessions[s].last_accessed)
        lru_sess = self.sessions[lru_sid]
        inst = self._find_instance_locked(lru_sess.instance_index)
        if inst is None:
            raise RuntimeError(f"Instance for LRU session {lru_sid} not found")

        logger.info("Evicting LRU session %s from instance %d", lru_sid, inst.index)

        # Release lock for I/O
        self._lock.release()
        try:
            try:
                self.forward_tool_call(inst, "idalib_save", {})
            except Exception:
                pass
            self.forward_tool_call(inst, "idalib_close", {"session_id": lru_sid})
        finally:
            self._lock.acquire()

        self._cleanup_session_locked(lru_sid)
        inst.session_id = None
        return inst

    def _find_instance_locked(self, index: int) -> InstanceInfo | None:
        for inst in self.instances:
            if inst.index == index:
                return inst
        return None

    # ------------------------------------------------------------------
    # Routing
    # ------------------------------------------------------------------

    def resolve_session_instance(self, session_id: str) -> tuple[SessionInfo, InstanceInfo]:
        """Return (session, instance) for a session_id, or raise."""
        with self._lock:
            sess = self.sessions.get(session_id)
            if sess is None:
                raise KeyError(
                    f"Session '{session_id}' not found. "
                    f"Use idalib_open to create a session first."
                )
            sess.last_accessed = time.monotonic()
            inst = self._find_instance_locked(sess.instance_index)
            if inst is None:
                raise RuntimeError(
                    f"Instance for session '{session_id}' is gone. "
                    f"The session may have been evicted."
                )
            return sess, inst

    # ------------------------------------------------------------------
    # Listing
    # ------------------------------------------------------------------

    def list_sessions(self) -> dict:
        with self._lock:
            sessions = [s.to_dict() for s in self.sessions.values()]
            return {
                "sessions": sessions,
                "count": len(sessions),
                "default_session_id": self.default_session_id,
            }

    def get_current_session(self) -> dict:
        with self._lock:
            if self.default_session_id is None:
                return {
                    "error": "No default session. Use idalib_open to create one.",
                }
            sess = self.sessions.get(self.default_session_id)
            if sess is None:
                return {"error": f"Default session '{self.default_session_id}' not found."}
            return sess.to_dict()

    # ------------------------------------------------------------------
    # HTTP forwarding
    # ------------------------------------------------------------------

    def forward_tool_call(
        self, inst: InstanceInfo, tool_name: str, arguments: dict
    ) -> Any:
        """Call a single tool on an instance via its MCP endpoint."""
        request = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": arguments},
            "id": 1,
        }
        resp = self.forward_raw(inst, request)
        # Unwrap structured result
        result = resp.get("result", resp)
        sc = result.get("structuredContent") if isinstance(result, dict) else None
        return sc if sc is not None else result

    def forward_raw(self, inst: InstanceInfo, request: dict) -> dict:
        """Send a raw JSON-RPC request to an instance and return the response."""
        conn = http.client.HTTPConnection("localhost", timeout=300)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(inst.socket_path)
        conn.sock = sock
        try:
            body = json.dumps(request)
            conn.request("POST", "/mcp", body, {"Content-Type": "application/json"})
            resp = conn.getresponse()
            data = resp.read().decode()
            if resp.status >= 400:
                raise RuntimeError(f"HTTP {resp.status}: {data}")
            return json.loads(data)
        finally:
            conn.close()

    def forward_tools_list(self) -> list[dict]:
        """Get tools/list from the first available instance."""
        with self._lock:
            candidates = [i for i in self.instances if i.process.poll() is None]
        if not candidates:
            return []
        inst = candidates[0]
        request = {"jsonrpc": "2.0", "method": "tools/list", "id": 1}
        resp = self.forward_raw(inst, request)
        return resp.get("result", {}).get("tools", [])
