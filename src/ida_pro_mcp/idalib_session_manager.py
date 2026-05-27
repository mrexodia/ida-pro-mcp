"""IDALib Session Manager - Multi-binary state for the headless MCP worker.

Each session represents a binary opened in this idalib process. Callers must
name the session they want to operate on explicitly via `activate_session`;
there is no implicit "current session" or transport-context binding.
"""

import uuid
import threading
import logging
from pathlib import Path
from typing import Dict, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime

import idapro
import ida_auto

logger = logging.getLogger(__name__)


@dataclass
class IDASession:
    """Represents a single IDA database session"""

    session_id: str
    input_path: Path
    created_at: datetime = field(default_factory=datetime.now)
    last_accessed: datetime = field(default_factory=datetime.now)
    is_analyzing: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert session to dictionary format"""
        return {
            "session_id": self.session_id,
            "input_path": str(self.input_path),
            "filename": self.input_path.name,
            "created_at": self.created_at.isoformat(),
            "last_accessed": self.last_accessed.isoformat(),
            "is_analyzing": self.is_analyzing,
            "metadata": self.metadata,
        }


class IDASessionManager:
    """Manages multiple IDA database sessions for idalib mode.

    `_sessions` stores all known session metadata. `_active_session_id` tracks
    the database currently opened in the idalib process. Callers select which
    session a request applies to by passing its session_id explicitly.
    """

    def __init__(self):
        self._sessions: Dict[str, IDASession] = {}
        self._active_session_id: Optional[str] = None
        self._lock = threading.RLock()
        logger.info("IDASessionManager initialized")

    def open_binary(
        self,
        input_path: Path | str,
        run_auto_analysis: bool = True,
        session_id: Optional[str] = None,
    ) -> str:
        """Open a binary file, activate it, and return its session ID."""
        input_path = Path(input_path)

        if not input_path.exists():
            raise FileNotFoundError(f"Input file not found: {input_path}")

        with self._lock:
            for sid, session in self._sessions.items():
                if session.input_path.resolve() == input_path.resolve():
                    logger.info(f"Binary already open in session: {sid}")
                    session.last_accessed = datetime.now()
                    return sid

            if session_id is None:
                session_id = str(uuid.uuid4())[:8]
            elif session_id in self._sessions:
                raise ValueError(f"Session already exists: {session_id}")

            logger.info(f"Opening database: {input_path} (session: {session_id})")
            self._activate_database_path(str(input_path), run_auto_analysis)

            session = IDASession(
                session_id=session_id,
                input_path=input_path,
                is_analyzing=run_auto_analysis,
            )

            self._sessions[session_id] = session
            self._active_session_id = session_id

            if run_auto_analysis:
                logger.debug(
                    f"Waiting for auto-analysis to complete (session: {session_id})"
                )
                ida_auto.auto_wait()
                session.is_analyzing = False
                logger.info(f"Auto-analysis completed (session: {session_id})")

            logger.info(f"Session created: {session_id} for {input_path.name}")
            return session_id

    def close_session(self, session_id: str) -> bool:
        """Close a specific session and its database."""
        with self._lock:
            if session_id not in self._sessions:
                logger.warning(f"Session not found: {session_id}")
                return False

            session = self._sessions[session_id]
            logger.info(f"Closing session: {session_id} ({session.input_path.name})")

            if self._active_session_id == session_id:
                idapro.close_database()
                self._active_session_id = None

            del self._sessions[session_id]
            logger.info(f"Session closed: {session_id}")
            return True

    def activate_session(self, session_id: str) -> IDASession:
        """Make `session_id` the active database for the current request."""
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                raise ValueError(f"Session not found: {session_id}")
            self._activate_session_locked(session_id)
            session.last_accessed = datetime.now()
            return session

    def list_sessions(self) -> list[dict]:
        """List all open sessions with activation metadata."""
        with self._lock:
            return [
                {
                    **session.to_dict(),
                    "is_active": session.session_id == self._active_session_id,
                }
                for session in self._sessions.values()
            ]

    def get_session(self, session_id: str) -> Optional[IDASession]:
        """Get a specific session by ID."""
        with self._lock:
            return self._sessions.get(session_id)

    def close_all_sessions(self):
        """Close all sessions and databases."""
        with self._lock:
            logger.info(f"Closing all {len(self._sessions)} sessions")

            if self._active_session_id is not None:
                idapro.close_database()
                self._active_session_id = None

            self._sessions.clear()
            logger.info("All sessions closed")

    def _activate_session_locked(self, session_id: str) -> None:
        if self._active_session_id == session_id:
            return
        session = self._sessions.get(session_id)
        if session is None:
            raise ValueError(f"Session not found: {session_id}")
        self._activate_database_path(str(session.input_path), run_auto_analysis=False)
        self._active_session_id = session_id
        logger.info("Activated session %s (%s)", session_id, session.input_path.name)

    def _activate_database_path(self, input_path: str, run_auto_analysis: bool) -> None:
        if self._active_session_id is not None:
            logger.debug("Closing active database before opening %s", input_path)
            idapro.close_database()
            self._active_session_id = None

        if idapro.open_database(input_path, run_auto_analysis=run_auto_analysis):
            raise RuntimeError(f"Failed to open database: {input_path}")


_session_manager: Optional[IDASessionManager] = None


def get_session_manager() -> IDASessionManager:
    """Get the global session manager instance."""
    global _session_manager
    if _session_manager is None:
        _session_manager = IDASessionManager()
    return _session_manager
