import argparse
import json
import logging
import signal
import sys
from pathlib import Path
from typing import Annotated, Any, Optional, TypedDict

# idapro must go first to initialize idalib
import idapro
import ida_loader

from ida_pro_mcp.ida_mcp import MCP_SERVER, MCP_UNSAFE
from ida_pro_mcp.ida_mcp.api_core import (
    ServerHealthResult,
    ServerWarmupResult,
    server_health,
    server_warmup,
)
from ida_pro_mcp.ida_mcp.rpc import get_current_transport_session_id, tool
from ida_pro_mcp.idalib_session_manager import get_session_manager

class IdalibContextFields(TypedDict):
    context_id: str
    transport_context_id: str | None
    isolated_contexts: bool


class IdalibSessionInfo(TypedDict):
    session_id: str
    input_path: str
    filename: str
    created_at: str
    last_accessed: str
    is_analyzing: bool
    metadata: dict[str, Any]


class IdalibOpenResult(IdalibContextFields, total=False):
    success: bool
    session: IdalibSessionInfo
    message: str
    error: str


class IdalibCloseResult(TypedDict, total=False):
    success: bool
    message: str
    error: str


class IdalibSwitchResult(IdalibContextFields, total=False):
    success: bool
    session: IdalibSessionInfo
    message: str
    error: str


class IdalibUnbindResult(IdalibContextFields, total=False):
    success: bool
    message: str
    error: str


class IdalibListResult(IdalibContextFields, total=False):
    sessions: list[IdalibSessionInfo]
    count: int
    current_context_session_id: str | None
    error: str


class IdalibCurrentResult(IdalibContextFields, total=False):
    session_id: str
    input_path: str
    filename: str
    created_at: str
    last_accessed: str
    is_analyzing: bool
    metadata: dict[str, Any]
    error: str


class IdalibSaveResult(IdalibContextFields, total=False):
    ok: bool
    path: str
    error: str | None


class IdalibHealthResult(IdalibContextFields, total=False):
    ready: bool
    session: IdalibSessionInfo | None
    health: ServerHealthResult | None
    error: str | None


class IdalibWarmupResult(IdalibContextFields, total=False):
    ready: bool
    session: IdalibSessionInfo | None
    warmup: ServerWarmupResult | None
    error: str | None


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
    "idalib_save",
    "idalib_health",
    "idalib_warmup",
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


def _context_response_fields(context_id: str) -> IdalibContextFields:
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
) -> IdalibOpenResult:
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
def idalib_close(
    session_id: Annotated[str, "Session ID to close"]
) -> IdalibCloseResult:
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
) -> IdalibSwitchResult:
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
def idalib_unbind() -> IdalibUnbindResult:
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
def idalib_list() -> IdalibListResult:
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
def idalib_current() -> IdalibCurrentResult:
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


@tool
def idalib_save(
    path: Annotated[str, "Optional destination path (default: current IDB path)"] = "",
    session_id: Annotated[
        Optional[str], "Optional session to activate before saving"
    ] = None,
) -> IdalibSaveResult:
    """Save the active (or requested) IDA session database to disk."""

    try:
        manager = get_session_manager()
        context_id = _resolve_effective_context_id()

        if session_id:
            manager.bind_context(context_id, session_id, activate=True)
        else:
            manager.activate_context(context_id)

        save_path = path.strip() if path else ""
        if not save_path:
            save_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
        if not save_path:
            return {
                "ok": False,
                **_context_response_fields(context_id),
                "error": "Could not resolve IDB path",
            }

        ok = bool(ida_loader.save_database(save_path, 0))
        return {
            "ok": ok,
            "path": save_path,
            **_context_response_fields(context_id),
            "error": None if ok else "save_database returned false",
        }
    except Exception as e:
        return {"ok": False, "error": str(e)}


@tool
def idalib_health(
    session_id: Annotated[
        Optional[str], "Optional session to bind/activate before probing health"
    ] = None,
) -> IdalibHealthResult:
    """Health/ready probe for idalib context + core server status."""
    try:
        manager = get_session_manager()
        context_id = _resolve_effective_context_id()

        if session_id:
            session = manager.bind_context(context_id, session_id, activate=True)
        else:
            session = manager.get_context_session(context_id)
            if session is None:
                return {
                    "ready": False,
                    **_context_response_fields(context_id),
                    "session": None,
                    "health": None,
                    "error": (
                        "No session bound for this context. "
                        "Use idalib_open(...) or idalib_switch(session_id) first."
                    ),
                }
            manager.activate_context(context_id)
            session = manager.get_context_session(context_id)

        health = server_health()
        return {
            "ready": bool(
                isinstance(health, dict)
                and health.get("status", "ok") == "ok"
                and not health.get("error")
            ),
            **_context_response_fields(context_id),
            "session": session.to_dict() if session is not None else None,
            "health": health,
            "error": None,
        }
    except Exception as e:
        return {"ready": False, "error": str(e)}


@tool
def idalib_warmup(
    session_id: Annotated[
        Optional[str], "Optional session to bind/activate before warmup"
    ] = None,
    wait_auto_analysis: Annotated[bool, "Wait for auto analysis queue"] = True,
    build_caches: Annotated[bool, "Build core caches"] = True,
    init_hexrays: Annotated[bool, "Initialize Hex-Rays plugin"] = True,
) -> IdalibWarmupResult:
    """Warm up idalib context and core subsystems."""
    try:
        manager = get_session_manager()
        context_id = _resolve_effective_context_id()

        if session_id:
            session = manager.bind_context(context_id, session_id, activate=True)
        else:
            session = manager.get_context_session(context_id)
            if session is None:
                return {
                    "ready": False,
                    **_context_response_fields(context_id),
                    "session": None,
                    "warmup": None,
                    "error": (
                        "No session bound for this context. "
                        "Use idalib_open(...) or idalib_switch(session_id) first."
                    ),
                }
            manager.activate_context(context_id)
            session = manager.get_context_session(context_id)

        warmup = server_warmup(
            wait_auto_analysis=wait_auto_analysis,
            build_caches=build_caches,
            init_hexrays=init_hexrays,
        )
        return {
            "ready": bool(warmup.get("ok")),
            **_context_response_fields(context_id),
            "session": session.to_dict() if session is not None else None,
            "warmup": warmup,
            "error": None,
        }
    except Exception as e:
        return {"ready": False, "error": str(e)}


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

    # Gate unsafe tools: remove them from the registry unless --unsafe is set.
    if not args.unsafe:
        for name in MCP_UNSAFE:
            MCP_SERVER.tools.methods.pop(name, None)
        if MCP_UNSAFE:
            logger.info("Unsafe tools disabled (start with --unsafe to enable)")

    _install_context_activation_hooks()

    # NOTE: npx -y @modelcontextprotocol/inspector for debugging
    # TODO: with background=True the main thread does not fake any
    # work from @idasync, so we deadlock.
    MCP_SERVER.serve(host=args.host, port=args.port, background=False)


if __name__ == "__main__":
    main()
