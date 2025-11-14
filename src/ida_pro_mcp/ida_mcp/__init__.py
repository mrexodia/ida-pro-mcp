"""IDA Pro MCP Plugin - Modular Package Version

This package provides MCP (Model Context Protocol) integration for IDA Pro,
enabling AI assistants to interact with IDA's disassembler and decompiler.

Architecture:
- rpc.py: JSON-RPC infrastructure and registry
- mcp.py: MCP protocol server (HTTP/SSE)
- sync.py: IDA synchronization decorators (@idaread/@idawrite)
- utils.py: Shared helpers and TypedDict definitions
- api_*.py: Modular API implementations (71 functions total)
"""

# Import infrastructure modules
from . import rpc
from . import sync
from . import utils
from . import mcp

# Import all API modules to register @jsonrpc functions
from . import api_core
from . import api_analysis
from . import api_memory
from . import api_types
from . import api_modify
from . import api_stack
from . import api_debug
from . import api_python

# Re-export key components for external use
from .rpc import rpc_registry, jsonrpc, unsafe, JSONRPCError
from .sync import idaread, idawrite, IDAError, IDASyncError
from .mcp import MCPServer

# Plugin metadata
__version__ = "2.0.0"
__author__ = "IDA Pro MCP Contributors"

__all__ = [
    'MCPServer',
    'rpc_registry',
    'jsonrpc',
    'unsafe',
    'JSONRPCError',
    'idaread',
    'idawrite',
    'IDAError',
    'IDASyncError',
]
