"""IDALib Session Manager - Multi-binary management for headless MCP server

This module provides session management for multiple IDA databases in idalib mode.
Each session represents an opened binary with its own IDA database instance.
"""

import os
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
    """Manages multiple IDA database sessions for idalib mode"""
    
    def __init__(self):
        self._sessions: Dict[str, IDASession] = {}
        self._current_session_id: Optional[str] = None
        self._lock = threading.RLock()
        logger.info("IDASessionManager initialized")
    
    def open_binary(
        self, 
        input_path: Path | str, 
        run_auto_analysis: bool = True,
        session_id: Optional[str] = None
    ) -> str:
        """Open a binary file and create a new session
        
        Args:
            input_path: Path to the binary file
            run_auto_analysis: Whether to run auto-analysis
            session_id: Optional custom session ID (auto-generated if not provided)
            
        Returns:
            Session ID for the opened binary
            
        Raises:
            FileNotFoundError: If the input file doesn't exist
            RuntimeError: If failed to open the database
        """
        input_path = Path(input_path)
        
        if not input_path.exists():
            raise FileNotFoundError(f"Input file not found: {input_path}")
        
        with self._lock:
            # Check if this file is already open
            for sid, session in self._sessions.items():
                if session.input_path.resolve() == input_path.resolve():
                    logger.info(f"Binary already open in session: {sid}")
                    self._current_session_id = sid
                    session.last_accessed = datetime.now()
                    return sid
            
            # Close current database if any (Do we need to close the database first?)
            if self._current_session_id is not None:
                logger.debug("Closing current database before opening new one")
                idapro.close_database()
            
            # Generate session ID
            if session_id is None:
                session_id = str(uuid.uuid4())[:8]
            
            # Open the database
            logger.info(f"Opening database: {input_path} (session: {session_id})")
            
            if idapro.open_database(str(input_path), run_auto_analysis=run_auto_analysis):
                raise RuntimeError(f"Failed to open database: {input_path}")
            
            # Create session object
            session = IDASession(
                session_id=session_id,
                input_path=input_path,
                is_analyzing=run_auto_analysis,
            )
            
            self._sessions[session_id] = session
            self._current_session_id = session_id
            
            # Wait for analysis if requested
            if run_auto_analysis:
                logger.debug(f"Waiting for auto-analysis to complete (session: {session_id})")
                ida_auto.auto_wait()
                session.is_analyzing = False
                logger.info(f"Auto-analysis completed (session: {session_id})")
            
            logger.info(f"Session created: {session_id} for {input_path.name}")
            return session_id
    
    def close_session(self, session_id: str) -> bool:
        """Close a specific session and its database
        
        Args:
            session_id: Session ID to close
            
        Returns:
            True if closed successfully, False if session not found
        """
        with self._lock:
            if session_id not in self._sessions:
                logger.warning(f"Session not found: {session_id}")
                return False
            
            session = self._sessions[session_id]
            logger.info(f"Closing session: {session_id} ({session.input_path.name})")
            
            # If this is the current session, close the database
            if self._current_session_id == session_id:
                idapro.close_database()
                self._current_session_id = None
            
            # Remove session
            del self._sessions[session_id]
            logger.info(f"Session closed: {session_id}")
            return True
    
    def switch_session(self, session_id: str) -> bool:
        """Switch to a different session
        
        Args:
            session_id: Session ID to switch to
            
        Returns:
            True if switched successfully
            
        Raises:
            ValueError: If session not found
        """
        with self._lock:
            if session_id not in self._sessions:
                raise ValueError(f"Session not found: {session_id}")
            
            if self._current_session_id == session_id:
                logger.debug(f"Already on session: {session_id}")
                return True
            
            session = self._sessions[session_id]
            
            # Close current database
            if self._current_session_id is not None:
                logger.debug(f"Closing current session: {self._current_session_id}")
                idapro.close_database()
            
            # Open the target session's database
            logger.info(f"Switching to session: {session_id} ({session.input_path.name})")
            
            if idapro.open_database(str(session.input_path), run_auto_analysis=False):
                raise RuntimeError(f"Failed to switch to session: {session_id}")
            
            self._current_session_id = session_id
            session.last_accessed = datetime.now()
            
            logger.info(f"Switched to session: {session_id}")
            return True
    
    def get_current_session(self) -> Optional[IDASession]:
        """Get the current active session
        
        Returns:
            Current session or None if no active session
        """
        with self._lock:
            if self._current_session_id is None:
                return None
            return self._sessions.get(self._current_session_id)
    
    def list_sessions(self) -> list[dict]:
        """List all open sessions
        
        Returns:
            List of session dictionaries with metadata
        """
        with self._lock:
            return [
                {
                    **session.to_dict(),
                    "is_current": session.session_id == self._current_session_id,
                }
                for session in self._sessions.values()
            ]
    
    def get_session(self, session_id: str) -> Optional[IDASession]:
        """Get a specific session by ID
        
        Args:
            session_id: Session ID to retrieve
            
        Returns:
            Session object or None if not found
        """
        with self._lock:
            return self._sessions.get(session_id)
    
    def close_all_sessions(self):
        """Close all sessions and databases"""
        with self._lock:
            logger.info(f"Closing all {len(self._sessions)} sessions")
            
            if self._current_session_id is not None:
                idapro.close_database()
                self._current_session_id = None
            
            self._sessions.clear()
            logger.info("All sessions closed")


# Global session manager instance
_session_manager: Optional[IDASessionManager] = None


def get_session_manager() -> IDASessionManager:
    """Get the global session manager instance
    
    Returns:
        Global IDASessionManager instance
    """
    global _session_manager
    if _session_manager is None:
        _session_manager = IDASessionManager()
    return _session_manager
