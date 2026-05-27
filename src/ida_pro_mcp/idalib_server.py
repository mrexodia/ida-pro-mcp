import argparse
import logging
import os
import signal
import time
from pathlib import Path
from typing import Annotated, Any, TypedDict

# idapro must go first to initialize idalib
import idapro

from ida_pro_mcp.ida_mcp import MCP_SERVER, MCP_UNSAFE
from ida_pro_mcp.ida_mcp.api_core import (
    ServerWarmupResult,
    server_warmup,
)
from ida_pro_mcp.ida_mcp.discovery import register_instance, unregister_instance
from ida_pro_mcp.ida_mcp.http import IdaMcpHttpRequestHandler
from ida_pro_mcp.ida_mcp.profile import apply_profile, load_profile
from ida_pro_mcp.ida_mcp.rpc import set_download_base_url, tool
from ida_pro_mcp.idalib_session_manager import get_session_manager
from ida_pro_mcp.worker_lifecycle import WorkerLifecycle


class IdalibSessionInfo(TypedDict):
    session_id: str
    input_path: str
    filename: str
    created_at: str
    last_accessed: str
    is_analyzing: bool
    metadata: dict[str, Any]


class IdalibSessionListInfo(IdalibSessionInfo, total=False):
    is_active: bool


class IdalibOpenResult(TypedDict, total=False):
    success: bool
    session: IdalibSessionInfo
    warmup: ServerWarmupResult | None
    message: str
    error: str


class IdalibListResult(TypedDict, total=False):
    sessions: list[IdalibSessionListInfo]
    count: int
    error: str


logger = logging.getLogger(__name__)

IDB_MANAGEMENT_TOOLS = {
    "idb_open",
    "idb_list",
}


_LIFECYCLE = WorkerLifecycle()
_REGISTERED_PORT: int | None = None
_BOUND_HOST: str = ""
_BOUND_PORT: int = 0


def _register_in_discovery(host: str, port: int, input_path: Path) -> None:
    global _REGISTERED_PORT
    try:
        register_instance(
            host=host,
            port=port,
            pid=os.getpid(),
            binary=input_path.name,
            idb_path=str(input_path),
            backend="worker",
        )
        _REGISTERED_PORT = port
        logger.info("Registered idalib worker in discovery (port %d)", port)
    except Exception:
        logger.exception("Failed to register worker in discovery")


def _deregister_from_discovery() -> None:
    global _REGISTERED_PORT
    if _REGISTERED_PORT is None:
        return
    try:
        unregister_instance(_REGISTERED_PORT)
    except Exception:
        logger.debug("Failed to unregister worker", exc_info=True)
    _REGISTERED_PORT = None


@tool
def idb_open(
    input_path: Annotated[str, "Path to the binary file to analyze"],
    run_auto_analysis: Annotated[bool, "Run automatic analysis on the binary"] = True,
    build_caches: Annotated[bool, "Build core caches after open"] = True,
    init_hexrays: Annotated[bool, "Initialize Hex-Rays decompiler after open"] = True,
    idle_ttl_sec: Annotated[
        int,
        "Minimum idle TTL in seconds before the headless worker self-exits.",
    ] = 600,
    preferred_session_id: Annotated[
        str,
        "Preferred session ID (auto-generated if empty). Ignored if the file is already open.",
    ] = "",
) -> IdalibOpenResult:
    """Open a binary, activate it, and warm up subsystems in one call."""

    try:
        manager = get_session_manager()
        resolved_path = Path(input_path).resolve()
        load_started_at = time.monotonic()
        opened_session_id = manager.open_binary(
            resolved_path,
            run_auto_analysis=run_auto_analysis,
            session_id=preferred_session_id or None,
        )
        session = manager.activate_session(opened_session_id)
        warmup: ServerWarmupResult | None = None
        if build_caches or init_hexrays:
            warmup = server_warmup(
                wait_auto_analysis=False,
                build_caches=build_caches,
                init_hexrays=init_hexrays,
            )
        _LIFECYCLE.set_idle_ttl(float(idle_ttl_sec), time.monotonic() - load_started_at)
        if _REGISTERED_PORT is None and _BOUND_HOST and _BOUND_PORT:
            _register_in_discovery(_BOUND_HOST, _BOUND_PORT, session.input_path)
        return {
            "success": True,
            "session": session.to_dict(),
            "warmup": warmup,
            "message": (
                f"Binary opened: {session.input_path.name} ({opened_session_id})"
            ),
        }
    except (FileNotFoundError, RuntimeError, ValueError) as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": f"Unexpected error: {e}"}


@tool
def idb_list() -> IdalibListResult:
    """List open IDA sessions."""

    try:
        manager = get_session_manager()
        sessions = manager.list_sessions()
        return {"sessions": sessions, "count": len(sessions)}
    except Exception as e:
        return {"error": f"Failed to list sessions: {e}"}


def _install_dispatch_hook() -> None:
    """Wrap the registry dispatcher so every request bumps the watchdog timer."""
    original = MCP_SERVER.registry.dispatch

    def touching_dispatch(request):
        try:
            return original(request)
        finally:
            _LIFECYCLE.touch()

    MCP_SERVER.registry.dispatch = touching_dispatch


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
        "--profile",
        type=Path,
        default=None,
        metavar="PATH",
        help=(
            "Restrict exposed tools to those listed in a profile file "
            "(one name per line, # for comments). idb_* management tools "
            "are always kept."
        ),
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

    global _BOUND_HOST, _BOUND_PORT
    _BOUND_HOST = args.host
    _BOUND_PORT = args.port

    session_manager = get_session_manager()

    if args.input_path is not None:
        if not args.input_path.exists():
            raise FileNotFoundError(f"Input file not found: {args.input_path}")

        logger.info("opening initial database: %s", args.input_path)
        resolved = args.input_path.resolve()
        session_id = session_manager.open_binary(resolved, run_auto_analysis=True)
        logger.info("Initial session created: %s", session_id)
        _register_in_discovery(args.host, args.port, resolved)
    else:
        logger.info(
            "No initial binary specified. Use idb_open() to load binaries dynamically."
        )

    def _on_lifecycle_exit(reason: str) -> None:
        logger.info("Worker lifecycle requesting shutdown: %s", reason)
        # MCP_SERVER.stop() must be called from outside the serve_forever
        # thread; our watchdog thread qualifies.
        try:
            MCP_SERVER.stop()
        except Exception:
            logger.exception("MCP_SERVER.stop() failed during lifecycle shutdown")

    _LIFECYCLE.start(on_shutdown=_on_lifecycle_exit)
    _install_dispatch_hook()

    def cleanup_and_exit(signum, frame):
        logger.info("Signal %s received; shutting down", signum)
        try:
            MCP_SERVER.stop()
        except Exception:
            logger.exception("MCP_SERVER.stop() failed in signal handler")

    signal.signal(signal.SIGINT, cleanup_and_exit)
    signal.signal(signal.SIGTERM, cleanup_and_exit)

    if not args.unsafe:
        for name in MCP_UNSAFE:
            MCP_SERVER.tools.methods.pop(name, None)
        if MCP_UNSAFE:
            logger.info("Unsafe tools disabled (start with --unsafe to enable)")

    if args.profile is not None:
        try:
            whitelist = load_profile(args.profile)
        except (OSError, UnicodeDecodeError) as e:
            raise SystemExit(f"Failed to read profile '{args.profile}': {e}")
        kept, unknown = apply_profile(
            MCP_SERVER.tools.methods,
            whitelist,
            protected=IDB_MANAGEMENT_TOOLS,
        )
        if unknown:
            logger.warning(
                "Profile references unknown tool(s) (ignored): %s", ", ".join(unknown)
            )
        logger.info(
            "Profile applied: %d whitelisted + %d management tool(s) active",
            len(kept),
            len(IDB_MANAGEMENT_TOOLS),
        )

    from ida_pro_mcp.ida_mcp import trace

    trace.install_tracer()
    logger.info("Tracing tools/call to IDB netnode %s", trace.IDB_NETNODE_NAME)

    if not "IDA_MCP_URL" in os.environ:
        set_download_base_url(f"http://{args.host}:{args.port}")

    try:
        MCP_SERVER.serve(
            host=args.host,
            port=args.port,
            background=False,
            request_handler=IdaMcpHttpRequestHandler,
        )
    finally:
        # Reached when MCP_SERVER.serve returns: either signal handler called
        # .stop(), watchdog called .stop(), or the loop errored out.
        logger.info("Server loop exited; cleaning up")
        _LIFECYCLE.stop()
        _deregister_from_discovery()
        try:
            session_manager.close_all_sessions()
        except Exception:
            logger.exception("close_all_sessions raised during cleanup")


if __name__ == "__main__":
    main()
