import sys
import logging
import argparse
from pathlib import Path

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.server import Settings

# idapro must come first to initialize idalib
import idapro
import ida_auto
import ida_hexrays

from ida_pro_mcp.ida_tools import rpc_registry


logger = logging.getLogger(__name__)


def load_file(path: Path):
    if not path.exists():
        raise FileNotFoundError(f"Input file not found: {path}")

    logger.debug("opening database: %s", path)
    if idapro.open_database(str(path), run_auto_analysis=True):
        raise RuntimeError("failed to analyze input file")

    logger.debug("idalib: waiting for analysis...")
    ida_auto.auto_wait()
    


def main() -> int:
    
    parser = argparse.ArgumentParser(description="MCP server for IDA Pro via idalib")
    parser.add_argument("input_path", type=Path, help="Path to the input file to analyze.")
    parser.add_argument("--host", type=str, default=Settings.host)
    parser.add_argument("--port", type=int, default=Settings.port)
    args = parser.parse_args()
    
    from rich.console import Console
    from rich.logging import RichHandler
    logging.basicConfig(
        level=logging.DEBUG,
        handlers=[RichHandler(console=Console(stderr=True))],
    )
    # if you've set the logging level in idapythonrc.py,
    # which gets evaluated during `import idapro`,
    # override it explicitly here.
    logging.getLogger().setLevel(logging.DEBUG)
    
    # this won't work with MCP stdio since it writes to stdout
    idapro.enable_console_messages(True)
    
    # TODO: does this have to be called after load?
    if not ida_hexrays.init_hexrays_plugin():
        raise RuntimeError("failed to initialize Hex-Rays decompiler")

    load_file(args.input_path)
    
    mcp = FastMCP("github.com/mrexodia/ida-pro-mcp", log_level="INFO", host=args.host, port=args.port)
    for name, callable in rpc_registry.methods.items():
        mcp.add_tool(callable, name)

    try:
        logger.info("MCP Server (sse) availabile at: http://%s:%d", mcp.settings.host, mcp.settings.port)
        mcp.run(transport="sse")
    except KeyboardInterrupt:
        return 0
    except Exception:
        return 1
    
    return 0
    
    
if __name__ == "__main__":
    sys.exit(main())
