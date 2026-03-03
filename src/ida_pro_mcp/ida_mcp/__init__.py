"""IDA Pro MCP Plugin package.

This project originally exposed a large set of fine-grained tools. To avoid
injecting dozens of tool descriptions into an LLM context, we provide a compact
toolset that only exposes a few aggregated capabilities.

Select toolset via env var:
- IDA_MCP_TOOLSET=compact (default)
- IDA_MCP_TOOLSET=full
"""

from __future__ import annotations

import os

# Infrastructure modules
from . import rpc
from . import sync
from . import utils

_TOOLSET = os.environ.get("IDA_MCP_TOOLSET", "compact").strip().lower()

# Import API modules to register @tool functions
if _TOOLSET == "full":
    from . import api_core
    from . import api_analysis
    from . import api_memory
    from . import api_types
    from . import api_modify
    from . import api_stack
    from . import api_debug
    from . import api_python
    from . import api_resources

    from .api_core import init_caches
else:
    from . import api_compact


    def init_caches() -> None:  # type: ignore[override]
        return

# Import HTTP handler after tools are registered (so config pruning is applied)
from .http import IdaMcpHttpRequestHandler

# Re-export key components for external use
from .sync import idasync, IDAError, IDASyncError, CancelledError
from .rpc import MCP_SERVER, MCP_UNSAFE, tool, unsafe, resource

__all__ = [
    "rpc",
    "sync",
    "utils",
    "IdaMcpHttpRequestHandler",
    "idasync",
    "IDAError",
    "IDASyncError",
    "CancelledError",
    "MCP_SERVER",
    "MCP_UNSAFE",
    "tool",
    "unsafe",
    "resource",
    "init_caches",
]

if _TOOLSET == "full":
    __all__ += [
        "api_core",
        "api_analysis",
        "api_memory",
        "api_types",
        "api_modify",
        "api_stack",
        "api_debug",
        "api_python",
        "api_resources",
    ]
else:
    __all__ += ["api_compact"]

