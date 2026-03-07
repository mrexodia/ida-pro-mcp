import argparse
import json
import logging
import signal
import sys
from pathlib import Path
from typing import Annotated, Optional

# idapro must go first to initialize idalib
import idapro

from ida_pro_mcp.ida_mcp import MCP_SERVER
from ida_pro_mcp.ida_mcp.rpc import get_current_transport_session_id, tool
from ida_pro_mcp.idalib_session_manager import get_session_manager

logger = logging.getLogger(__name__)

STDIO_DEFAULT_CONTEXT_ID = "stdio:default"
SHARED_FALLBACK_CONTEXT_ID = "shared:fallback"
IDALIB_MANAGEMENT_TOOLS = {
    "idalib_open",
    "idalib_close",
    "idalib_switch",
    "idalib_unbind",
    "idalib_list",
    "idalib_current",
}

_ISOLATED_CONTEXTS_ENABLED = False


def _resolve_effective_context_id() -> str:
    """Resolve the context key used for this request.

    - Default mode: always use the shared fallback context.
    - Isolated mode: require per-transport context.
    """
    transport_context_id = get_current_transport_session_id()
    if _ISOLATED_CONTEXTS_ENABLED:
        if transport_context_id is None:
            raise RuntimeError(
                "No MCP transport context is active for this request. "
                "Use MCP initialize and send Mcp-Session-Id on /mcp requests."
            )
        return transport_context_id
    return SHARED_FALLBACK_CONTEXT_ID


def _context_response_fields(context_id: str) -> dict:
    return {
        "context_id": context_id,
        "transport_context_id": get_current_transport_session_id(),
        "isolated_contexts": _ISOLATED_CONTEXTS_ENABLED,
    }


def _install_context_activation_hooks() -> None:
    if getattr(MCP_SERVER, "_idalib_context_hooks_installed", False):
        return

    original_tools_call = MCP_SERVER.registry.methods["tools/call"]

    def tools_call_with_context(
        name: str, arguments: Optional[dict] = None, _meta: Optional[dict] = None
    ) -> dict:
        if name not in IDALIB_MANAGEMENT_TOOLS:
            try:
                manager = get_session_manager()
                context_id = _resolve_effective_context_id()
                manager.activate_context(context_id)
            except Exception as e:
                return {
                    "content": [{"type": "text", "text": str(e)}],
                    "isError": True,
                }
        return original_tools_call(name, arguments, _meta)

    MCP_SERVER.registry.methods["tools/call"] = tools_call_with_context

    original_resources_read = MCP_SERVER.registry.methods["resources/read"]

    def resources_read_with_context(uri: str, _meta: Optional[dict] = None) -> dict:
        try:
            manager = get_session_manager()
            context_id = _resolve_effective_context_id()
            manager.activate_context(context_id)
        except Exception as e:
            return {
                "contents": [
                    {
                        "uri": uri,
                        "mimeType": "application/json",
                        "text": json.dumps({"error": str(e)}, indent=2),
                    }
                ],
                "isError": True,
            }
        return original_resources_read(uri, _meta)

    MCP_SERVER.registry.methods["resources/read"] = resources_read_with_context
    setattr(MCP_SERVER, "_idalib_context_hooks_installed", True)


@tool
def idalib_open(
    input_path: Annotated[str, "Path to the binary file to analyze"],
    run_auto_analysis: Annotated[bool, "Run automatic analysis on the binary"] = True,
    session_id: Annotated[
        Optional[str], "Custom session ID (auto-generated if not provided)"
    ] = None,
) -> dict:
    """Open a binary and bind it to the active idalib context policy."""

    try:
        manager = get_session_manager()
        context_id = _resolve_effective_context_id()
        opened_session_id = manager.open_binary(
            Path(input_path), run_auto_analysis=run_auto_analysis, session_id=session_id
        )
        session = manager.bind_context(context_id, opened_session_id, activate=True)
        return {
            "success": True,
            **_context_response_fields(context_id),
            "session": session.to_dict(),
            "message": (
                f"Binary opened and bound to context: {session.input_path.name} "
                f"({opened_session_id})"
            ),
        }
    except (FileNotFoundError, RuntimeError, ValueError) as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": f"Unexpected error: {e}"}


@tool
def idalib_close(session_id: Annotated[str, "Session ID to close"]) -> dict:
    """Close an IDA session and remove all context bindings targeting it."""

    try:
        manager = get_session_manager()
        if manager.close_session(session_id):
            return {"success": True, "message": f"Session closed: {session_id}"}
        return {"success": False, "error": f"Session not found: {session_id}"}
    except Exception as e:
        return {"error": f"Failed to close session: {e}"}


@tool
def idalib_switch(
    session_id: Annotated[str, "Session ID to bind to active context"],
) -> dict:
    """Bind the active idalib context to a session and activate it."""

    try:
        manager = get_session_manager()
        context_id = _resolve_effective_context_id()
        session = manager.bind_context(context_id, session_id, activate=True)
        return {
            "success": True,
            **_context_response_fields(context_id),
            "session": session.to_dict(),
            "message": (
                f"Bound context to session: {session_id} ({session.input_path.name})"
            ),
        }
    except ValueError as e:
        return {"error": str(e)}
    except RuntimeError as e:
        return {"error": f"Failed to switch session: {e}"}
    except Exception as e:
        return {"error": f"Unexpected error: {e}"}


@tool
def idalib_unbind() -> dict:
    """Unbind the active idalib context from any session."""

    try:
        manager = get_session_manager()
        context_id = _resolve_effective_context_id()
        if manager.unbind_context(context_id):
            return {
                "success": True,
                **_context_response_fields(context_id),
                "message": "Context unbound successfully.",
            }
        return {
            "success": False,
            **_context_response_fields(context_id),
            "error": "No bound session for this context.",
        }
    except Exception as e:
        return {"error": f"Failed to unbind context: {e}"}


@tool
def idalib_list() -> dict:
    """List sessions with context-binding and active-database metadata."""

    try:
        manager = get_session_manager()
        context_id = _resolve_effective_context_id()
        sessions = manager.list_sessions(context_id=context_id)
        current_context_session_id = manager.get_context_session_id(context_id)
        return {
            "sessions": sessions,
            "count": len(sessions),
            **_context_response_fields(context_id),
            "current_context_session_id": current_context_session_id,
        }
    except Exception as e:
        return {"error": f"Failed to list sessions: {e}"}


@tool
def idalib_current() -> dict:
    """Return the session bound to the active idalib context policy."""

    try:
        manager = get_session_manager()
        context_id = _resolve_effective_context_id()
        session = manager.get_context_session(context_id)
        if session is None:
            return {
                "error": (
                    "No session bound for this context. "
                    "Use idalib_open(...) or idalib_switch(session_id) first."
                ),
                **_context_response_fields(context_id),
            }

        manager.activate_context(context_id)
        session = manager.get_context_session(context_id)
        if session is None:
            return {
                "error": "Context binding became invalid. Bind to a valid session again.",
                **_context_response_fields(context_id),
            }

        return {**session.to_dict(), **_context_response_fields(context_id)}
    except Exception as e:
        return {"error": f"Failed to get current session: {e}"}


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
        "--isolated-contexts",
        action="store_true",
        help=(
            "Enable strict many-to-many context isolation. "
            "Default mode uses shared fallback context."
        ),
    )
    parser.add_argument(
        "--unsafe", action="store_true", help="Enable unsafe functions (DANGEROUS)"
    )
    parser.add_argument(
        "input_path",
        type=Path,
        nargs="?",
        help="Path to the input file to analyze (optional).",
    )
    args = parser.parse_args()

    if args.verbose:
        log_level = logging.DEBUG
        idapro.enable_console_messages(True)
    else:
        log_level = logging.INFO
        idapro.enable_console_messages(False)

    logging.basicConfig(level=log_level)
    logging.getLogger().setLevel(log_level)

    global _ISOLATED_CONTEXTS_ENABLED
    _ISOLATED_CONTEXTS_ENABLED = args.isolated_contexts

    mode = "isolated-contexts" if _ISOLATED_CONTEXTS_ENABLED else "shared-fallback"
    logger.info("idalib session mode: %s", mode)

    session_manager = get_session_manager()

    if args.input_path is not None:
        if not args.input_path.exists():
            raise FileNotFoundError(f"Input file not found: {args.input_path}")

        logger.info("opening initial database: %s", args.input_path)
        session_id = session_manager.open_binary(
            args.input_path, run_auto_analysis=True
        )
        logger.info("Initial session created: %s", session_id)

        startup_context_id = (
            STDIO_DEFAULT_CONTEXT_ID
            if _ISOLATED_CONTEXTS_ENABLED
            else SHARED_FALLBACK_CONTEXT_ID
        )
        session_manager.bind_context(startup_context_id, session_id, activate=True)
        logger.info(
            "Bound startup session %s to context %s",
            session_id,
            startup_context_id,
        )
    else:
        logger.info(
            "No initial binary specified. Use idalib_open() to load binaries dynamically."
        )

    def cleanup_and_exit(signum, frame):
        logger.info("Shutting down...")
        logger.info("Closing all IDA sessions...")
        session_manager.close_all_sessions()
        logger.info("All sessions closed.")
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup_and_exit)
    signal.signal(signal.SIGTERM, cleanup_and_exit)

    # In isolated mode we require Streamable HTTP session semantics.
    MCP_SERVER.require_streamable_http_session = _ISOLATED_CONTEXTS_ENABLED
    _install_context_activation_hooks()

    # NOTE: npx -y @modelcontextprotocol/inspector for debugging
    # TODO: with background=True the main thread does not fake any
    # work from @idasync, so we deadlock.
    MCP_SERVER.serve(host=args.host, port=args.port, background=False)


if __name__ == "__main__":
    main()
