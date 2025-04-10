import sys
import inspect
import logging
import argparse
import importlib
from pathlib import Path
import typing_inspection.introspection as intro

from rich.console import Console
from rich.logging import RichHandler
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.server import Settings

# idapro must go first to initialize idalib
import idapro

import ida_auto
import ida_hexrays

logger = logging.getLogger(__name__)


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
            # this instance is a raw `typing._AnnotatedAlias` that we can't do anything with directly.
            # it renders like:
            #
            #      typing.Annotated[str, 'Name of the function to get']
            if not parameter.annotation:
                continue

            # this instance will look something like:
            #
            #     InspectedAnnotation(type=<class 'str'>, qualifiers=set(), metadata=['Name of the function to get'])
            #
            annotation = intro.inspect_annotation(
                                                  parameter.annotation,
                                                  annotation_source=intro.AnnotationSource.ANY
                                              )

            # for our use case, where we attach a single string annotation that is meant as documentation,
            # we extract that string and assign it to "description" in the tool metadata.

            if annotation.type is not str:
                continue

            if len(annotation.metadata) != 1:
                continue

            description = annotation.metadata[0]
            if not isinstance(description, str):
                continue

            logger.debug("adding parameter documentation %s(%s='%s')", tool.name, name, description)
            tool.parameters["properties"][name]["description"] = description


def main() -> int:
    parser = argparse.ArgumentParser(description="MCP server for IDA Pro via idalib")
    parser.add_argument("--verbose", action="store_true", help="Show debug messages")
    parser.add_argument("--transport", choices=["stdio", "sse"], default="stdio", help="MCP protocol to use")
    # FastMCP default host is 0.0.0.0, but we should avoid exposing the server publicly by default.
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Host to serve on when using MCP/sse")
    parser.add_argument("--port", type=int, default=Settings.model_fields["port"].default, help="Port to serve on when using MCP/sse")
    parser.add_argument("input_path", type=Path, help="Path to the input file to analyze.")
    args = parser.parse_args()

    if args.verbose:
        log_level = logging.DEBUG
        log_level_s = "DEBUG"

        # this is OK for MCP/sse, but not for MCP/stdio
        # TODO: though it *might* be ok if this is written to STDERR
        idapro.enable_console_messages(True)
    else:
        log_level = logging.INFO
        log_level_s = "INFO"
        idapro.enable_console_messages(False)

    logging.basicConfig(
        level=log_level,
        handlers=[RichHandler(console=Console(stderr=True))],
    )

    # reset logging levels that might be initialized in idapythonrc.py
    # which is evaluated during import of idalib.
    logging.getLogger().setLevel(log_level)

    if not args.input_path.exists():
        raise FileNotFoundError(f"Input file not found: {args.input_path}")

    # TODO: add a tool for specifying the idb/input file (sandboxed)
    logger.info("opening database: %s", args.input_path)
    if idapro.open_database(str(args.input_path), run_auto_analysis=True):
        raise RuntimeError("failed to analyze input file")

    logger.debug("idalib: waiting for analysis...")
    ida_auto.auto_wait()

    if not ida_hexrays.init_hexrays_plugin():
        raise RuntimeError("failed to initialize Hex-Rays decompiler")

    # for MCP/stdio, STDERR should not imply an error with MCP, but some clients are buggy today.
    # see: https://github.com/modelcontextprotocol/modelcontextprotocol/issues/177
    mcp = FastMCP("github.com/mrexodia/ida-pro-mcp", log_level=log_level_s, host=args.host, port=args.port)

    plugin = importlib.import_module("ida_pro_mcp.mcp-plugin")
    logger.debug("adding tools...")
    for name, callable in plugin.rpc_registry.methods.items():
        logger.debug("adding tool: %s: %s", name, callable)
        mcp.add_tool(callable, name)

    fixup_tool_argument_descriptions(mcp)

    try:
        if args.transport == "sse":
            logger.info("MCP Server (sse) availabile at: http://%s:%d", mcp.settings.host, mcp.settings.port)
            mcp.run(transport="sse")
        elif args.transport == "stdio":
            mcp.run(transport="stdio")
        else:
            raise ValueError("invalid transport")
    except KeyboardInterrupt:
        return 0
    except Exception:
        return 1

    return 0

if __name__ == "__main__":
    sys.exit(main())
