"""IDA Pro MCP Plugin - Modular Package Version

This package provides MCP (Model Context Protocol) integration for IDA Pro,
enabling AI assistants to interact with IDA's disassembler and decompiler.

Architecture:
- rpc.py: JSON-RPC infrastructure and registry
- mcp.py: MCP protocol server (HTTP/SSE)
- sync.py: IDA synchronization decorator (@idasync)
- utils.py: Shared helpers and TypedDict definitions
- api_*.py: Modular API implementations
"""

# Ignore SIGPIPE to prevent IDA from being killed when an MCP client
# disconnects while the HTTP server is writing a response. IDA's embedded
# Python may not preserve CPython's default SIG_IGN for SIGPIPE.
import signal

if hasattr(signal, "SIGPIPE"):
    signal.signal(signal.SIGPIPE, signal.SIG_IGN)

# Import infrastructure modules
from . import rpc
from . import sync
from . import utils

# Import all API modules to register @tool functions and @resource functions
from . import api_core
from . import api_analysis
from . import api_memory
from . import api_types
from . import api_modify
from . import api_stack
from . import api_debug
from . import api_python
from . import api_resources
from . import api_survey
from . import api_composite
from . import api_segments
from . import api_entries
from . import api_bookmarks
from . import api_operands
from . import api_data
from . import api_search
from . import api_auto
from . import api_fixups
from . import api_patches
from . import api_names
from . import api_segregs
from . import api_tils
from . import api_signatures
from . import api_problems
from . import api_tryblks
from . import api_graphs
from . import api_hexrays_ext
from . import api_processor
from . import api_loader
from . import api_xrefs_manage
from . import api_database
from . import api_discovery

# Re-export key components for external use
from .sync import idasync, IDAError, IDASyncError, CancelledError
from .rpc import MCP_SERVER, MCP_UNSAFE, tool, unsafe, resource
from .http import IdaMcpHttpRequestHandler
from .api_core import init_caches
from .api_discovery import set_local_instance

__all__ = [
    # Infrastructure modules
    "rpc",
    "sync",
    "utils",
    # API modules
    "api_core",
    "api_analysis",
    "api_memory",
    "api_types",
    "api_modify",
    "api_stack",
    "api_debug",
    "api_python",
    "api_resources",
    "api_survey",
    "api_composite",
    "api_segments",
    "api_entries",
    "api_bookmarks",
    "api_operands",
    "api_data",
    "api_search",
    "api_auto",
    "api_fixups",
    "api_patches",
    "api_names",
    "api_segregs",
    "api_tils",
    "api_signatures",
    "api_problems",
    "api_tryblks",
    "api_graphs",
    "api_hexrays_ext",
    "api_processor",
    "api_loader",
    "api_xrefs_manage",
    "api_database",
    "api_discovery",
    # Re-exported components
    "idasync",
    "IDAError",
    "IDASyncError",
    "CancelledError",
    "MCP_SERVER",
    "MCP_UNSAFE",
    "tool",
    "unsafe",
    "resource",
    "IdaMcpHttpRequestHandler",
    "init_caches",
    "set_local_instance",
]
