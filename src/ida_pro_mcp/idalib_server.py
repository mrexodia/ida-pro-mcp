import sys
import signal
import logging
import argparse
from pathlib import Path

# idapro must go first to initialize idalib
import idapro
import ida_auto

from ida_pro_mcp.ida_mcp import MCP_SERVER
"""IDALib-specific MCP tools for managing multiple binary sessions
"""
from typing import Annotated, Optional
from ida_pro_mcp.ida_mcp.rpc import tool
from ida_pro_mcp.idalib_session_manager import get_session_manager

@tool
def idalib_open(
    input_path: Annotated[str, "Path to the binary file to analyze"],
    run_auto_analysis: Annotated[bool, "Run automatic analysis on the binary"] = True,
    session_id: Annotated[Optional[str], "Custom session ID (auto-generated if not provided)"] = None,
) -> dict:
    """Open a binary file and create a new IDA session (idalib mode only)
    
    Opens a binary file for analysis and creates a new session. The binary will be
    analyzed in IDA's headless mode. If the file is already open, returns the existing
    session ID.
    
    Args:
        input_path: Path to the binary file to analyze
        run_auto_analysis: Whether to run IDA's automatic analysis (default: True)
        session_id: Optional custom session ID (default: auto-generated)
        
    Returns:
        Dictionary with session information:
        - session_id: Unique identifier for this session
        - input_path: Path to the binary file
        - filename: Name of the binary file
        - created_at: Session creation timestamp
        - is_analyzing: Whether analysis is currently running
        
    Example:
        ```json
        {
            "session_id": "a3f4c8b2",
            "input_path": "/path/to/binary.exe",
            "filename": "binary.exe",
            "created_at": "2025-12-25T10:30:00",
            "is_analyzing": false
        }
        ```
    """
    
    try:
        manager = get_session_manager()
        session_id_result = manager.open_binary(
            Path(input_path),
            run_auto_analysis=run_auto_analysis,
            session_id=session_id
        )
        
        session = manager.get_session(session_id_result)
        if session is None:
            return {"error": f"Failed to retrieve session after opening: {session_id_result}"}
        
        return {
            "success": True,
            "session": session.to_dict(),
            "message": f"Binary opened successfully: {session.input_path.name}"
        }
    except FileNotFoundError as e:
        return {"error": str(e)}
    except RuntimeError as e:
        return {"error": f"Failed to open binary: {e}"}
    except Exception as e:
        return {"error": f"Unexpected error: {e}"}


@tool
def idalib_close(
    session_id: Annotated[str, "Session ID to close"]
) -> dict:
    """Close an IDA session and its associated database (idalib mode only)
    
    Closes the specified session and releases all associated resources. If this is
    the currently active session, the database will be closed.
    
    Args:
        session_id: Unique identifier of the session to close
        
    Returns:
        Dictionary with operation result:
        - success: Whether the operation succeeded
        - message: Descriptive message
        
    Example:
        ```json
        {
            "success": true,
            "message": "Session closed: a3f4c8b2"
        }
        ```
    """
    
    try:
        manager = get_session_manager()
        
        if manager.close_session(session_id):
            return {
                "success": True,
                "message": f"Session closed: {session_id}"
            }
        else:
            return {
                "success": False,
                "error": f"Session not found: {session_id}"
            }
    except Exception as e:
        return {"error": f"Failed to close session: {e}"}


@tool
def idalib_switch(
    session_id: Annotated[str, "Session ID to switch to"]
) -> dict:
    """Switch to a different IDA session (idalib mode only)
    
    Switches the active session to the specified session. This closes the current
    database and opens the target session's database. All subsequent MCP tool calls
    will operate on the switched session.
    
    Args:
        session_id: Unique identifier of the session to switch to
        
    Returns:
        Dictionary with session information after switching:
        - success: Whether the switch succeeded
        - session: Current session details
        - message: Descriptive message
        
    Example:
        ```json
        {
            "success": true,
            "session": {
                "session_id": "a3f4c8b2",
                "filename": "binary.exe",
                "is_current": true
            },
            "message": "Switched to session: a3f4c8b2"
        }
        ```
    """
    
    try:
        manager = get_session_manager()
        
        if manager.switch_session(session_id):
            session = manager.get_current_session()
            if session is None:
                return {"error": "Failed to retrieve current session after switching"}
            
            return {
                "success": True,
                "session": session.to_dict(),
                "message": f"Switched to session: {session_id} ({session.input_path.name})"
            }
    except ValueError as e:
        return {"error": str(e)}
    except RuntimeError as e:
        return {"error": f"Failed to switch session: {e}"}
    except Exception as e:
        return {"error": f"Unexpected error: {e}"}


@tool
def idalib_list() -> dict:
    """List all open IDA sessions (idalib mode only)
    
    Returns a list of all currently open sessions with their metadata. The current
    active session is marked with is_current=true.
    
    Returns:
        Dictionary with sessions list:
        - sessions: List of session dictionaries
        - count: Total number of sessions
        - current_session_id: ID of the currently active session
        
    Example:
        ```json
        {
            "sessions": [
                {
                    "session_id": "a3f4c8b2",
                    "filename": "binary1.exe",
                    "input_path": "/path/to/binary1.exe",
                    "created_at": "2025-12-25T10:30:00",
                    "last_accessed": "2025-12-25T10:35:00",
                    "is_current": true,
                    "is_analyzing": false
                },
                {
                    "session_id": "b7e2d9f1",
                    "filename": "binary2.dll",
                    "input_path": "/path/to/binary2.dll",
                    "created_at": "2025-12-25T10:31:00",
                    "last_accessed": "2025-12-25T10:31:00",
                    "is_current": false,
                    "is_analyzing": false
                }
            ],
            "count": 2,
            "current_session_id": "a3f4c8b2"
        }
        ```
    """
    
    try:
        manager = get_session_manager()
        sessions = manager.list_sessions()
        current_session = manager.get_current_session()
        
        return {
            "sessions": sessions,
            "count": len(sessions),
            "current_session_id": current_session.session_id if current_session else None
        }
    except Exception as e:
        return {"error": f"Failed to list sessions: {e}"}


@tool
def idalib_current() -> dict:
    """Get information about the current active IDA session (idalib mode only)
    
    Returns detailed information about the currently active session, or an error
    if no session is active.
    
    Returns:
        Dictionary with current session information:
        - session_id: Unique identifier
        - filename: Binary file name
        - input_path: Full path to the binary
        - created_at: Session creation timestamp
        - last_accessed: Last access timestamp
        - is_analyzing: Whether analysis is running
        - metadata: Additional session metadata
        
    Example:
        ```json
        {
            "session_id": "a3f4c8b2",
            "filename": "binary.exe",
            "input_path": "/path/to/binary.exe",
            "created_at": "2025-12-25T10:30:00",
            "last_accessed": "2025-12-25T10:35:00",
            "is_analyzing": false,
            "metadata": {}
        }
        ```
    """
    
    try:
        manager = get_session_manager()
        session = manager.get_current_session()
        
        if session is None:
            return {
                "error": "No active session. Use idalib_open() to open a binary first."
            }
        
        return session.to_dict()
    except Exception as e:
        return {"error": f"Failed to get current session: {e}"}



logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(description="MCP server for IDA Pro via idalib")
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Show debug messages"
    )
    parser.add_argument(
        "--host",
        type=str,
        default="127.0.0.1",
        help="Host to listen on, default: 127.0.0.1",
    )
    parser.add_argument(
        "--port", type=int, default=8745, help="Port to listen on, default: 8745"
    )
    parser.add_argument(
        "--unsafe", action="store_true", help="Enable unsafe functions (DANGEROUS)"
    )
    parser.add_argument(
        "input_path", 
        type=Path, 
        nargs="?",  # Make input_path optional
        help="Path to the input file to analyze (optional, can be loaded dynamically via MCP tools)."
    )
    args = parser.parse_args()

    if args.verbose:
        log_level = logging.DEBUG
        idapro.enable_console_messages(True)
    else:
        log_level = logging.INFO
        idapro.enable_console_messages(False)

    logging.basicConfig(level=log_level)

    # reset logging levels that might be initialized in idapythonrc.py
    # which is evaluated during import of idalib.
    logging.getLogger().setLevel(log_level)

    # Initialize session manager for dynamic binary loading
    from ida_pro_mcp.idalib_session_manager import get_session_manager
    session_manager = get_session_manager()

    # Open initial binary if provided
    if args.input_path is not None:
        if not args.input_path.exists():
            raise FileNotFoundError(f"Input file not found: {args.input_path}")

        logger.info("opening initial database: %s", args.input_path)
        session_id = session_manager.open_binary(args.input_path, run_auto_analysis=True)
        logger.info(f"Initial session created: {session_id}")
    else:
        logger.info("No initial binary specified. Use idalib_open() to load binaries dynamically.")

    # Setup signal handlers to ensure IDA database is properly closed on shutdown.
    # When a signal arrives, our handlers execute first, allowing us to close the
    # IDA database cleanly before the process terminates.
    def cleanup_and_exit(signum, frame):
        logger.info("Shutting down...")
        logger.info("Closing all IDA sessions...")
        session_manager.close_all_sessions()
        logger.info("All sessions closed.")
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup_and_exit)
    signal.signal(signal.SIGTERM, cleanup_and_exit)

    # NOTE: npx -y @modelcontextprotocol/inspector for debugging
    # TODO: with background=True the main thread (this one) does not fake any
    # work from @idasync, so we deadlock.
    MCP_SERVER.serve(host=args.host, port=args.port, background=False)


if __name__ == "__main__":
    main()
