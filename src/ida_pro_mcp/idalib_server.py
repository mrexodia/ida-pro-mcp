import sys
import signal
import logging
import argparse
from pathlib import Path

# idapro must go first to initialize idalib
import idapro
import ida_auto

from ida_pro_mcp.ida_mcp import MCP_SERVER

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
    from ida_pro_mcp.ida_mcp.rpc import set_download_base_url

    set_download_base_url(f"http://{args.host}:{args.port}")
    MCP_SERVER.serve(host=args.host, port=args.port, background=False)


if __name__ == "__main__":
    main()
