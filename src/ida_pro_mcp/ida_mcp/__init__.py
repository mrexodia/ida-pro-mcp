"""IDA Pro MCP Plugin - Modular Package Version

This package provides MCP (Model Context Protocol) integration for IDA Pro,
enabling AI assistants to interact with IDA's disassembler and decompiler.

Architecture:
- rpc.py: JSON-RPC infrastructure and registry
- mcp.py: MCP protocol server (HTTP/SSE)
- sync.py: IDA synchronization decorators (@idasync)
- utils.py: Shared helpers and TypedDict definitions
- tests.py: Test framework (@test decorator, run_tests)
- api_*.py: Modular API implementations (71 tools + 24 resources)
"""

# Import infrastructure modules
from . import rpc
from . import sync
from . import utils
from . import tests

# Import all API modules to register @tool functions, @resource functions, and @test functions
from . import api_core
from . import api_analysis
from . import api_memory
from . import api_types
from . import api_modify
from . import api_stack
from . import api_debug
from . import api_python
from . import api_resources

# Re-export key components for external use
from .sync import idasync, IDAError, IDASyncError
from .rpc import MCP_SERVER, MCP_UNSAFE, tool, unsafe, resource
from .tests import run_tests, test, set_sample_size, get_sample_size
from .http import IdaMcpHttpRequestHandler

__all__ = [
    # Infrastructure modules
    "rpc",
    "sync",
    "utils",
    "tests",
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
    # Re-exported components
    "idasync",
    "IDAError",
    "IDASyncError",
    "MCP_SERVER",
    "MCP_UNSAFE",
    "tool",
    "unsafe",
    "resource",
    "run_tests",
    "test",
    "set_sample_size",
    "get_sample_size",
    "IdaMcpHttpRequestHandler",
]
