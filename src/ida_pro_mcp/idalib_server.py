import sys
import inspect
import logging
import argparse
import importlib
import importlib.util
from pathlib import Path
from typing import get_origin, get_args, Annotated

from mcp.server.fastmcp import FastMCP

# idapro must go first to initialize idalib
import idapro

import ida_auto
import ida_hexrays

logger = logging.getLogger(__name__)

mcp = FastMCP("github.com/mrexodia/ida-pro-mcp#idalib")

def fixup_tool_argument_descriptions(mcp: FastMCP):
    # In our tool definitions within `mcp-plugin.py`, we use `typing.Annotated` on function parameters
    # to attach documentation. For example:
    #
    #     def get_function_by_name(
    #         name: Annotated[str, "Name of the function to get"]
    #     ) -> Function:
    #         """Get a function by its name"""
    #         ...
    #
    # However, the interpretation of Annotated is left up to static analyzers and other tools.
    # FastMCP doesn't have any special handling for these comments, so we splice them into the
    # tool metadata ourselves here.
    #
    # Example, before:
    #
    #     tool.parameter={
    #       properties: {
    #         name: {
    #           title: "Name",
    #           type: "string"
    #         }
    #       },
    #       required: ["name"],
    #       title: "get_function_by_nameArguments",
    #       type: "object"
    #     }
    #
    # Example, after:
    #
    #     tool.parameter={
    #       properties: {
    #         name: {
    #           title: "Name",
    #           type: "string"
    #           description: "Name of the function to get"
    #         }
    #       },
    #       required: ["name"],
    #       title: "get_function_by_nameArguments",
    #       type: "object"
    #     }
    #
    # References:
    #   - https://docs.python.org/3/library/typing.html#typing.Annotated
    #   - https://fastapi.tiangolo.com/python-types/#type-hints-with-metadata-annotations

    # unfortunately, FastMCP.list_tools() is async, so we break with best practices and reach into `._tool_manager`
    # rather than spinning up an asyncio runtime just to fetch the (non-async) list of tools.
    for tool in mcp._tool_manager.list_tools():
        sig = inspect.signature(tool.fn)
        for name, parameter in sig.parameters.items():
            annotation = parameter.annotation
            if not annotation:
                continue

            origin = get_origin(annotation)
            if origin is not Annotated:
                continue

            args = get_args(annotation)
            if len(args) < 2:
                continue

            base_type = args[0]
            metadata = args[1]
            if base_type is not str:
                continue

            # metadata may be a string, or a pydantic Field(description='...')
            description = metadata if isinstance(metadata, str) else getattr(metadata, "description", None)
            if not isinstance(description, str) or description == "":
                continue

            logger.debug("adding parameter documentation %s(%s='%s')", tool.name, name, description)
            if "properties" in tool.parameters and name in tool.parameters["properties"]:
                tool.parameters["properties"][name]["description"] = description

def main():
    parser = argparse.ArgumentParser(description="MCP server for IDA Pro via idalib")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show debug messages")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Host to listen on, default: 127.0.0.1")
    parser.add_argument("--port", type=int, default=8745, help="Port to listen on, default: 8745")
    parser.add_argument("--unsafe", action="store_true", help="Enable unsafe functions (DANGEROUS)")
    parser.add_argument("input_path", type=Path, help="Path to the input file to analyze.")
    args = parser.parse_args()

    if args.verbose:
        log_level = logging.DEBUG
        idapro.enable_console_messages(True)
    else:
        log_level = logging.INFO
        idapro.enable_console_messages(False)

    mcp.settings.log_level = logging.getLevelName(log_level)
    mcp.settings.host = args.host
    mcp.settings.port = args.port
    logging.basicConfig(level=log_level)

    # reset logging levels that might be initialized in idapythonrc.py
    # which is evaluated during import of idalib.
    logging.getLogger().setLevel(log_level)

    if not args.input_path.exists():
        raise FileNotFoundError(f"Input file not found: {args.input_path}")

    # TODO: add a tool for specifying the idb/input file (sandboxed)
    logger.info("opening database: %s", args.input_path)
    if not idapro.open_database(str(args.input_path), run_auto_analysis=True):
        raise RuntimeError("failed to open or analyze input file")

    logger.debug("idalib: waiting for analysis...")
    ida_auto.auto_wait()

    if not ida_hexrays.init_hexrays_plugin():
        raise RuntimeError("failed to initialize Hex-Rays decompiler")

    # Import IDA plugin module with hyphen in filename via file path
    plugin_path = Path(__file__).with_name("mcp-plugin.py")
    spec = importlib.util.spec_from_file_location("ida_pro_mcp.mcp_plugin", plugin_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"failed to load plugin from {plugin_path}")
    plugin = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(plugin)
    logger.debug("adding tools...")
    for name, callable in plugin.rpc_registry.methods.items():
        if args.unsafe or name not in plugin.rpc_registry.unsafe:
            logger.debug("adding tool: %s: %s", name, callable)
            mcp.add_tool(callable, name)

    # NOTE: https://github.com/modelcontextprotocol/python-sdk/issues/466
    fixup_tool_argument_descriptions(mcp)

    # NOTE: npx @modelcontextprotocol/inspector for debugging
    logger.info("MCP Server available at: http://%s:%d/sse", mcp.settings.host, mcp.settings.port)
    try:
        mcp.run(transport="sse")
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()
