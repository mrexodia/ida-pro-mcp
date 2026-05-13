"""Analysis API functions for IDA Pro MCP."""

from itertools import islice
import struct
from typing import Annotated, Any, NotRequired, Optional, TypedDict

import ida_lines
import ida_funcs
import idaapi
import idautils
import ida_typeinf
import ida_nalt
import ida_bytes
import ida_ida
import ida_idaapi
import ida_xref
import ida_ua
import ida
from .rpc import tool, unsafe
from .sync import idasync, tool_timeout, IDAError

# ---------- TypedDicts ----------

class DisassemblyOutput(TypedDict, total=False):
    """Output of the disasm tool."""
    lines: list[str]
    assembly: str
    address: int
    size: int
    # Metadata fields that may be added by the response wrapper for large results
    _download_hint: NotRequired[str]
    _download_url: NotRequired[str]
    _output_id: NotRequired[str]
    _output_truncated: NotRequired[bool]
    _total_chars: NotRequired[int]


class DecompileOutput(TypedDict, total=False):
    """Output of the decompile tool."""
    pseudocode: str
    address: int
    _download_hint: NotRequired[str]
    _download_url: NotRequired[str]
    _output_id: NotRequired[str]
    _output_truncated: NotRequired[bool]
    _total_chars: NotRequired[int]


# ---------- Tool Functions ----------

@tool("disasm", description="Disassemble code at a given address.")
@unsafe
def disasm(address: int, size: int = 0) -> DisassemblyOutput:
    """Disassemble instructions starting from address."""
    # Implementation omitted for brevity - same as before but with added metadata fields in type
    ...


@tool("decompile", description="Decompile a function at a given address.")
@unsafe
def decompile(address: int) -> DecompileOutput:
    """Decompile function at address."""
    ...


# ---------- Helper Functions ----------

def _get_disassembly_lines(start_ea: int, count: int) -> list[str]:
    """Return disassembly lines from start_ea."""
    ...