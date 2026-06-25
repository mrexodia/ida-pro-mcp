"""Structured error taxonomy for IDA MCP tools.

All errors subclass the same `McpToolError` base that `sync.IDAError` uses, so
`McpRpcRegistry.map_exception` turns any of them into a JSON-RPC error object.
On top of that base, each class here carries a distinct, JSON-RPC-ish integer
`code` so callers (and future structured-error handling in the registry) can
discriminate *why* a tool failed without string-matching the message:

  * NotFoundError           -- the requested entity does not exist (address,
                               function, type, name, ...).
  * InvalidArgumentError    -- the caller supplied a malformed / out-of-range
                               / contradictory argument.
  * VersionUnsupportedError -- the running IDA / decompiler version is too old
                               (or otherwise incompatible) for the operation.
  * FeatureUnavailableError -- a required subsystem is absent at runtime
                               (no Hex-Rays license, debugger not loaded, ...).

`IDAError` itself stays defined in `sync.py` (this module re-exports it so a
single `from .errors import IDAError, NotFoundError, ...` works), and every
class here is a `McpToolError`, so existing `except IDAError`/`except
McpToolError` handlers keep working unchanged.

Code space: the base codes mirror JSON-RPC's server-error range. -32000 is the
generic MCP tool error already used by `McpToolError` mapping; the specialised
codes below sit just under it so they remain in the implementation-defined
server-error band (-32000..-32099).
"""

from __future__ import annotations

from .rpc import McpToolError

# Re-export so consumers can import the whole error taxonomy from one module.
from .sync import IDAError  # noqa: F401  (re-exported)


class StructuredError(McpToolError):
    """Base for the structured error taxonomy.

    Subclasses set a distinct class-level ``code``. Instances expose ``.message``
    (the human-readable text) and ``.code`` so callers can branch on the cause
    without parsing the message string. Carrying ``McpToolError`` as the base
    keeps these mappable by ``McpRpcRegistry.map_exception``.
    """

    #: JSON-RPC-ish error code; overridden per subclass.
    code: int = -32000

    def __init__(self, message: str):
        super().__init__(message)

    @property
    def message(self) -> str:
        return self.args[0]


class NotFoundError(StructuredError):
    """Requested entity (address, function, name, type, ...) does not exist."""

    code = -32004


class InvalidArgumentError(StructuredError):
    """Caller supplied a malformed, out-of-range, or contradictory argument."""

    code = -32602  # JSON-RPC "Invalid params"


class VersionUnsupportedError(StructuredError):
    """Running IDA / decompiler version is too old or incompatible."""

    code = -32010


class FeatureUnavailableError(StructuredError):
    """A required runtime subsystem is unavailable (no Hex-Rays license, ...)."""

    code = -32011


__all__ = [
    "IDAError",
    "StructuredError",
    "NotFoundError",
    "InvalidArgumentError",
    "VersionUnsupportedError",
    "FeatureUnavailableError",
]
