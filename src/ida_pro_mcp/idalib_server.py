import sys
import time
import signal
import logging
import argparse
from pathlib import Path

# idapro must go first to initialize idalib
import idapro
import ida_auto

from ida_pro_mcp.ida_mcp import MCP_SERVER

logger = logging.getLogger(__name__)

# Global variable to store analysis time (accessible via MCP tool)
_analysis_info = {
    "analysis_time": None,
    "binary_path": None,
    "analysis_complete": False,
}


def get_analysis_info() -> dict:
    """Get analysis information (called by session manager)"""
    return _analysis_info.copy()


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
        "--session-id",
        type=str,
        default=None,
        help="Session ID (used by session manager)",
    )
    parser.add_argument(
        "input_path",
        type=Path,
        nargs="?",
        default=None,
        help="Path to the input file to analyze.",
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

    # If no input path provided, start in session mode (waiting for binary)
    if args.input_path is None:
        logger.info("No input file specified. Starting in session manager mode...")
        # In session mode, we just start the MCP server without opening a database
        # The session management tools will handle opening binaries
        from ida_pro_mcp.ida_mcp.rpc import set_download_base_url

        set_download_base_url(f"http://{args.host}:{args.port}")

        # Print ready marker for session manager
        print(f"[SESSION_READY] port={args.port}", flush=True)

        MCP_SERVER.serve(host=args.host, port=args.port, background=False)
        return

    if not args.input_path.exists():
        raise FileNotFoundError(f"Input file not found: {args.input_path}")

    # Track analysis time
    _analysis_info["binary_path"] = str(args.input_path)
    analysis_start = time.time()

    logger.info("opening database: %s", args.input_path)
    if idapro.open_database(str(args.input_path), run_auto_analysis=True):
        raise RuntimeError("failed to analyze input file")

    logger.debug("idalib: waiting for analysis...")
    ida_auto.auto_wait()

    # Record analysis completion
    analysis_time = time.time() - analysis_start
    _analysis_info["analysis_time"] = round(analysis_time, 2)
    _analysis_info["analysis_complete"] = True
    logger.info(f"Analysis completed in {analysis_time:.2f} seconds")

    # Setup signal handlers to ensure IDA database is properly closed on shutdown.
    # When a signal arrives, our handlers execute first, allowing us to close the
    # IDA database cleanly before the process terminates.
    def cleanup_and_exit(signum, frame):
        logger.info("Closing IDA database...")
        idapro.close_database()
        logger.info("IDA database closed.")
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup_and_exit)
    signal.signal(signal.SIGTERM, cleanup_and_exit)

    # NOTE: npx -y @modelcontextprotocol/inspector for debugging
    # TODO: with background=True the main thread (this one) does not fake any
    # work from @idasync, so we deadlock.
    from ida_pro_mcp.ida_mcp.rpc import set_download_base_url

    set_download_base_url(f"http://{args.host}:{args.port}")

    # Print ready marker for session manager (includes analysis time)
    if args.session_id:
        print(f"[SESSION_READY] session_id={args.session_id} port={args.port} analysis_time={_analysis_info['analysis_time']}", flush=True)

    MCP_SERVER.serve(host=args.host, port=args.port, background=False)


if __name__ == "__main__":
    main()
