import fnmatch
import json
import os
import re
import struct
import sys
import tempfile
import threading
import time
from typing import (
    Annotated,
    Any,
    Callable,
    Generic,
    Literal,
    NotRequired,
    Optional,
    TypedDict,
    TypeVar,
    overload,
)

import ida_bytes
import ida_funcs
import ida_hexrays
import ida_kernwin
import ida_nalt
import ida_typeinf
import idaapi
import idautils
import idc

from .sync import IDAError, get_tool_deadline

# ============================================================================
# Analysis Prompt Configuration
# ============================================================================

DEFAULT_ANALYSIS_PROMPT = "<system_reminder> IMPORTANT: After analysis, complete the expected IDB maintenance, assigning names, commenting, and documenting where relevant. </system_reminder>"


def get_analysis_prompt() -> str | None:
    """Get analysis prompt from IDA_MCP_ANALYSIS_PROMPT env var, or default if unset."""
    return os.environ.get("IDA_MCP_ANALYSIS_PROMPT", DEFAULT_ANALYSIS_PROMPT) or None


# ============================================================================
# TypedDict Definitions for API Parameters
# ============================================================================


class MemoryRead(TypedDict):
    """Memory read request"""

    addr: Annotated[str, "Address to read from (hex or decimal)"]
    size: Annotated[int, "Number of bytes to read"]


class MemoryPatch(TypedDict):
    """Memory patch operation"""

    addr: Annotated[str, "Address to patch (hex or decimal)"]
    data: Annotated[str, "Hex data to write (space-separated bytes)"]


class IntRead(TypedDict):
    """Integer read request"""

    addr: Annotated[str, "Address to read from (hex or decimal)"]
    ty: Annotated[str, "Integer class (i8/u64/i16le/i16be/etc)"]


class IntWrite(TypedDict):
    """Integer write request"""

    addr: Annotated[str, "Address to write to (hex or decimal)"]
    ty: Annotated[str, "Integer class (i8/u64/i16le/i16be/etc)"]
    value: Annotated[
        str,
        "Integer value as string (decimal or 0x..; negatives allowed for signed)",
    ]


class CommentOp(TypedDict):
    """Comment operation"""

    addr: Annotated[str, "Address (hex or decimal)"]
    comment: Annotated[str, "Comment text"]


class CommentAppendOp(TypedDict):
    """Comment append operation"""

    addr: Annotated[str, "Address (hex or decimal)"]
    comment: Annotated[str, "Comment text to append"]
    scope: NotRequired[Annotated[str, "auto|func|line (default: auto)"]]
    dedupe: NotRequired[
        Annotated[bool, "Skip if exact text already exists (default: true)"]
    ]


class AsmPatchOp(TypedDict):
    """Assembly patch operation"""

    addr: Annotated[str, "Address (hex or decimal)"]
    asm: Annotated[str, "Assembly instruction(s), semicolon-separated"]


class FunctionRename(TypedDict):
    """Function rename operation"""

    addr: Annotated[str, "Function address (hex or decimal)"]
    name: Annotated[str, "New function name"]


class GlobalRename(TypedDict):
    """Global variable rename operation"""

    old: Annotated[str, "Current variable name"]
    new: Annotated[str, "New variable name"]


class LocalRename(TypedDict):
    """Local variable rename operation"""

    func_addr: Annotated[str, "Function address"]
    old: Annotated[str, "Current variable name"]
    new: Annotated[str, "New variable name"]


class StackRename(TypedDict):
    """Stack variable rename operation"""

    func_addr: Annotated[str, "Function address"]
    old: Annotated[str, "Current variable name"]
    new: Annotated[str, "New variable name"]


class RenameBatch(TypedDict, total=False):
    """Batch rename operations across all entity types.

    At least one of func/data/local/stack should be present.
    """

    func: Annotated[
        list[FunctionRename] | FunctionRename, "Function rename operations"
    ]
    data: Annotated[
        list[GlobalRename] | GlobalRename, "Global/data variable rename operations"
    ]
    local: Annotated[
        list[LocalRename] | LocalRename, "Local variable rename operations"
    ]
    stack: Annotated[
        list[StackRename] | StackRename, "Stack variable rename operations"
    ]
    stop_on_error: Annotated[bool, "Stop on first failure"]
    dry_run: Annotated[bool, "Validate only, no changes"]
    allow_overwrite: Annotated[bool, "Force overwrite existing names"]


class StructFieldQuery(TypedDict):
    """Struct field query for xrefs"""

    struct: Annotated[str, "Structure name"]
    field: Annotated[str, "Field name"]


class XrefQuery(TypedDict):
    """Generic cross-reference query"""

    addr: Annotated[str, "Address or name"]
    direction: NotRequired[Annotated[str, "to|from|both (default: both)"]]
    xref_type: NotRequired[Annotated[str, "any|code|data (default: any)"]]
    offset: NotRequired[Annotated[int, "Start index (default: 0)"]]
    count: NotRequired[Annotated[int, "Max results (default: 200, max: 5000)"]]
    include_fn: NotRequired[Annotated[bool, "Include function metadata"]]
    dedup: NotRequired[Annotated[bool, "Deduplicate by addr/type"]]
    sort_by: NotRequired[Annotated[str, "Sort: addr|type"]]
    descending: NotRequired[Annotated[bool, "Descending"]]


class ListQuery(TypedDict, total=False):
    """Pagination query for listing operations"""

    filter: Annotated[str, "Glob filter"]
    offset: Annotated[int, "Start index"]
    count: Annotated[int, "Max results (0=all)"]


class FunctionQuery(TypedDict, total=False):
    """Function query with richer filtering"""

    filter: Annotated[str, "Name glob/regex"]
    name_regex: Annotated[str, "Name regex"]
    min_size: Annotated[int, "Min size in bytes"]
    max_size: Annotated[int, "Max size in bytes"]
    has_type: Annotated[bool, "Require type info"]
    offset: Annotated[int, "Start index"]
    count: Annotated[int, "Max results (0=all)"]
    sort_by: Annotated[str, "Sort: addr|name|size"]
    descending: Annotated[bool, "Descending"]


class EntityQuery(TypedDict):
    """Generic IDB entity query with filtering, projection, and pagination"""

    kind: Annotated[str, "functions|globals|imports|strings|names"]
    filter: NotRequired[Annotated[str, "Glob/regex filter"]]
    regex: NotRequired[Annotated[str, "Regex on primary text field"]]
    min_addr: NotRequired[Annotated[str, "Min address bound"]]
    max_addr: NotRequired[Annotated[str, "Max address bound"]]
    segment: NotRequired[Annotated[str, "Segment filter"]]
    module: NotRequired[Annotated[str, "Import module filter"]]
    offset: NotRequired[Annotated[int, "Start index"]]
    count: NotRequired[Annotated[int, "Max results (0=all)"]]
    sort_by: NotRequired[Annotated[str, "Sort: addr|name|size|length"]]
    descending: NotRequired[Annotated[bool, "Descending"]]
    fields: NotRequired[Annotated[list[str], "Projection field list"]]


class FuncProfileQuery(TypedDict, total=False):
    """Function profiling query with pagination and optional detail lists.

    All fields are optional - omit addr to profile all functions.
    """

    addr: Annotated[str, "Function address or name (omit or '*' for all)"]
    filter: Annotated[str, "Name glob/regex"]
    offset: Annotated[int, "Start index"]
    count: Annotated[int, "Max results (0=all)"]
    sort_by: Annotated[str, "Sort: addr|name|size"]
    descending: Annotated[bool, "Descending"]
    include_lists: Annotated[bool, "Include callers/callees/strings/constants"]
    max_items: Annotated[int, "Max items per list"]
    include_prototype: Annotated[bool, "Include prototype"]


class AnalyzeBatchQuery(TypedDict):
    """Comprehensive function analysis request"""

    addr: Annotated[str, "Function address or name"]
    include_decompile: NotRequired[Annotated[bool, "Include decompiler output"]]
    include_disasm: NotRequired[Annotated[bool, "Include disassembly"]]
    include_xrefs: NotRequired[Annotated[bool, "Include xrefs-to/from"]]
    include_callers: NotRequired[Annotated[bool, "Include callers"]]
    include_callees: NotRequired[Annotated[bool, "Include callees"]]
    include_strings: NotRequired[Annotated[bool, "Include strings"]]
    include_constants: NotRequired[Annotated[bool, "Include constants"]]
    include_basic_blocks: NotRequired[Annotated[bool, "Include basic blocks"]]
    include_proto: NotRequired[Annotated[bool, "Include prototype"]]
    max_disasm_insns: NotRequired[Annotated[int, "Max disasm instructions"]]
    max_callers: NotRequired[Annotated[int, "Max callers"]]
    max_callees: NotRequired[Annotated[int, "Max callees"]]
    max_strings: NotRequired[Annotated[int, "Max strings"]]
    max_constants: NotRequired[Annotated[int, "Max constants"]]
    max_blocks: NotRequired[Annotated[int, "Max blocks"]]


class ImportQuery(TypedDict, total=False):
    """Import query with filtering and pagination"""

    filter: Annotated[str, "Name glob/regex"]
    module: Annotated[str, "Module glob/regex"]
    offset: Annotated[int, "Start index"]
    count: Annotated[int, "Max results (0=all)"]


class TypeInspectQuery(TypedDict):
    """Type inspection request"""

    name: Annotated[str, "Type name"]
    include_members: NotRequired[Annotated[bool, "Include UDT member details"]]
    max_members: NotRequired[Annotated[int, "Max members"]]


class TypeQuery(TypedDict, total=False):
    """Type catalog query with filtering, pagination, and optional relationships"""

    filter: Annotated[str, "Name glob/regex"]
    kind: Annotated[str, "any|struct|union|enum|typedef|func|ptr|udt"]
    offset: Annotated[int, "Start index"]
    count: Annotated[int, "Max results (0=all)"]
    sort_by: Annotated[str, "Sort: name|size|ordinal"]
    descending: Annotated[bool, "Descending"]
    include_decl: Annotated[bool, "Include declaration text"]
    include_members: Annotated[bool, "Include UDT member details"]
    max_members: Annotated[int, "Max members per UDT"]
    include_relationships: Annotated[bool, "Include related type names"]


class BreakpointOp(TypedDict):
    """Debugger breakpoint operation"""

    addr: Annotated[str, "Breakpoint address (hex or decimal)"]
    enabled: Annotated[bool, "Enable (true) or disable (false)"]


class BreakpointConditionBase(TypedDict):
    """Debugger breakpoint condition operation"""

    addr: Annotated[str, "Breakpoint address (hex or decimal)"]


class BreakpointConditionOp(BreakpointConditionBase, total=False):
    condition: Annotated[
        Optional[str], "Breakpoint condition expression; null/empty clears it"
    ]
    language: Annotated[
        Optional[str],
        "Condition language ('idc', 'python', or exact IDA extlang name); null preserves current/default",
    ]
    low_level: Annotated[bool, "Set a low-level/server-side condition when true"]


class InsnPattern(TypedDict, total=False):
    """Instruction pattern for operand search"""

    mnem: Annotated[str, "Mnemonic to match"]
    op0: Annotated[int, "Match first operand"]
    op1: Annotated[int, "Match second operand"]
    op2: Annotated[int, "Match third operand"]
    op_any: Annotated[int, "Match any operand"]
    func: Annotated[str, "Scope: function address"]
    segment: Annotated[str, "Scope: segment name"]
    start: Annotated[str, "Scope: start address"]
    end: Annotated[str, "Scope: end address (exclusive)"]
    offset: Annotated[int, "Start index"]
    count: Annotated[int, "Max matches (max: 5000)"]
    max_scan_insns: Annotated[int, "Max instructions to scan"]
    include_fn: Annotated[bool, "Include function metadata"]
    include_disasm: Annotated[bool, "Include disassembly text"]
    allow_broad: Annotated[bool, "Allow scopeless scan"]


class NumberConversion(TypedDict, total=False):
    """Number conversion request"""

    text: Annotated[str, "Number string to convert"]
    size: Annotated[int, "Byte size for conversion (omit for auto)"]


class StructRead(TypedDict, total=False):
    """Structure read request

    Address is required. Struct name is optional - if omitted, will attempt
    to auto-detect from type information already applied at the address.
    """

    addr: Annotated[str, "Address"]
    struct: Annotated[NotRequired[str], "Struct name (auto-detect if omitted)"]


class TypeEdit(TypedDict):
    """Type application operation"""

    addr: Annotated[str, "Address (function, global, or stack frame)"]
    ty: NotRequired[Annotated[str, "Type name or declaration"]]
    name: NotRequired[Annotated[str, "Variable/function name"]]
    kind: NotRequired[Annotated[str, "Entity kind (auto-detected)"]]
    signature: NotRequired[Annotated[str, "Function signature"]]
    variable: NotRequired[Annotated[str, "Local variable name"]]


class EnumMemberUpsert(TypedDict, total=False):
    """Enum member upsert operation"""

    name: Annotated[str, "Enum member name"]
    value: Annotated[int | str, "Enum member value"]


class EnumUpsert(TypedDict, total=False):
    """Enum create/update operation"""

    name: Annotated[str, "Enum type name"]
    members: Annotated[list[EnumMemberUpsert] | EnumMemberUpsert, "Members to upsert"]
    bitfield: Annotated[bool, "Bitfield enum"]


class TypeApplyBatch(TypedDict):
    """Batch type application configuration"""

    edits: Annotated[list[TypeEdit] | TypeEdit, "Type edits to apply"]
    stop_on_error: NotRequired[Annotated[bool, "Stop on first failure"]]


class StackVarDecl(TypedDict):
    """Stack variable declaration"""

    addr: Annotated[str, "Function address"]
    offset: Annotated[str, "Stack offset"]
    name: Annotated[str, "Variable name"]
    ty: Annotated[str, "Type name"]


class StackVarDelete(TypedDict):
    """Stack variable deletion"""

    addr: Annotated[str, "Function address"]
    name: Annotated[str, "Variable name"]


class DefineOp(TypedDict, total=False):
    """Define function/code operation"""

    addr: Annotated[
        str, "Address to define (hex or decimal). Use 'start:end' for explicit bounds."
    ]
    end: Annotated[str, "Optional end address for explicit bounds"]


class UndefineOp(TypedDict, total=False):
    """Undefine operation"""

    addr: Annotated[str, "Address to undefine (hex or decimal)"]
    end: Annotated[str, "Optional end address"]
    size: Annotated[int, "Optional size in bytes"]


# ============================================================================
# TypedDict Definitions for Results
# ============================================================================


class Metadata(TypedDict):
    path: str
    module: str
    base: str
    size: str
    md5: str
    sha256: str
    crc32: str
    filesize: str


class Function(TypedDict):
    addr: str
    name: str
    size: str


class ConvertedNumber(TypedDict):
    decimal: str
    hexadecimal: str
    bytes: str
    ascii: Optional[str]
    binary: str


class Global(TypedDict):
    addr: str
    name: str


class Import(TypedDict):
    addr: str
    imported_name: str
    module: str


class String(TypedDict):
    addr: str
    length: int
    string: str


class Segment(TypedDict):
    name: str
    start: str
    end: str
    size: str
    permissions: str


class Ref(TypedDict):
    addr: str
    name: str
    string: NotRequired[str]


class DisassemblyLine(TypedDict):
    segment: NotRequired[str]
    addr: str
    label: NotRequired[str]
    instruction: str
    comments: NotRequired[list[str]]
    refs: NotRequired[list[Ref]]


class Argument(TypedDict):
    name: str
    type: str


class StackFrameVariable(TypedDict):
    name: str
    offset: str
    size: str
    type: str


class DisassemblyFunction(TypedDict):
    name: str
    start_ea: str
    segment: NotRequired[str]
    return_type: NotRequired[str]
    arguments: NotRequired[list[Argument]]
    stack_frame: NotRequired[list[StackFrameVariable]]
    lines: list[DisassemblyLine]


class Xref(TypedDict):
    addr: str
    type: str
    fn: Optional[Function]


class StructureMember(TypedDict):
    name: str
    offset: str
    size: str
    type: str


class StructureDefinition(TypedDict):
    name: str
    size: str
    members: list[StructureMember]


class RegisterValue(TypedDict):
    name: str
    value: str


class ThreadRegisters(TypedDict):
    thread_id: int
    registers: list[RegisterValue]


class Breakpoint(TypedDict):
    addr: str
    enabled: bool
    condition: Optional[str]
    language: Optional[str]


class FunctionAnalysis(TypedDict):
    addr: str
    name: Optional[str]
    code: Optional[str]
    asm: Optional[str]
    xto: list[Xref]
    xfrom: list[Xref]
    callees: list[dict]
    callers: list[Function]
    strings: list[String]
    constants: list[dict]
    blocks: list[dict]
    error: Optional[str]
    prompt: Optional[str]


class PatternMatch(TypedDict):
    pattern: str
    matches: list[str]
    count: int


class CodePattern(TypedDict):
    mnemonic: str
    operands: NotRequired[list[str]]


class BasicBlock(TypedDict):
    start: str
    end: str
    size: int
    type: int
    successors: list[str]
    predecessors: list[str]


T = TypeVar("T")


class Page(TypedDict, Generic[T]):
    data: list[T]
    next_offset: Optional[int]


# ============================================================================
# Helper Functions
# ============================================================================


def get_image_size() -> int:
    from . import compat

    omin_ea = compat.inf_get_omin_ea()
    omax_ea = compat.inf_get_omax_ea()

    image_size = omax_ea - omin_ea
    header = idautils.peutils_t().header()
    if header and header[:4] == b"PE\0\0":
        image_size = struct.unpack("<I", header[0x50:0x54])[0]
    return image_size


def parse_address(addr: str | int) -> int:
    if isinstance(addr, int):
        return addr
    try:
        return int(addr, 0)
    except ValueError:
        # Try name-to-address resolution before failing
        try:
            import idaapi

            ea = idaapi.get_name_ea(idaapi.BADADDR, addr.strip())
            if ea != idaapi.BADADDR:
                return ea
        except ImportError:
            pass
        for ch in addr:
            if ch not in "0123456789abcdefABCDEF":
                raise IDAError(f"Not found: {addr!r}")
        raise IDAError(f"Failed to parse address (missing 0x prefix): {addr}")


def read_bytes_bss_safe(ea: int, size: int) -> bytes:
    """Read `size` bytes starting at `ea`, substituting 0 for unloaded bytes.

    Unloaded bytes in BSS-like sections are zero at runtime by every mainstream
    loader, but ida_bytes.get_byte() returns 0xFF as a sentinel for them. Patch
    that here so reads of globals in .bss return the real zero-initialized
    value instead of 0xff garbage.
    """
    if size <= 0:
        return b""
    bulk = ida_bytes.get_bytes(ea, size)
    if bulk is None or len(bulk) != size:
        # Bulk read failed/short — build byte-by-byte, zero for unloaded bytes.
        out = bytearray(size)
        for i in range(size):
            if ida_bytes.is_loaded(ea + i):
                out[i] = ida_bytes.get_byte(ea + i)
        return bytes(out)
    # idalib's get_bytes returns the 0xFF sentinel for unloaded .bss bytes
    # instead of failing, so the bulk read alone is NOT BSS-safe. The sentinel
    # is 0xFF, so only 0xFF bytes are candidates: zero any that aren't actually
    # loaded (a genuine 0xFF in initialized data stays, since it is_loaded).
    if 0xFF in bulk:
        out = bytearray(bulk)
        for i in range(size):
            if out[i] == 0xFF and not ida_bytes.is_loaded(ea + i):
                out[i] = 0
        return bytes(out)
    return bytes(bulk)


def read_int_bss_safe(ea: int, size: int) -> int:
    """Read an integer of `size` bytes at `ea`, honoring IDB endianness.

    Returns 0 if the byte at `ea` is not loaded (BSS / zero-initialized region).
    Uses IDA's native sized readers (get_byte/word/dword/qword) for loaded
    bytes so the result respects the database endianness.
    """
    if not ida_bytes.is_loaded(ea):
        return 0
    if size == 1:
        return ida_bytes.get_byte(ea)
    if size == 2:
        return ida_bytes.get_word(ea)
    if size == 4:
        return ida_bytes.get_dword(ea)
    if size == 8:
        return ida_bytes.get_qword(ea)
    raise ValueError(f"unsupported integer size: {size}")


def normalize_list_input(value: list | str) -> list:
    """Normalize input to list - accepts list or comma-separated string"""
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    return [value]


def normalize_dict_list(
    value: list[dict] | dict | str | list[str] | Any,
    string_parser: Optional[Callable[[str], dict]] = None,
) -> list[dict]:
    """Normalize input to list[dict] with optional string parsing

    Args:
        value: Input value (dict, list[dict], str, list[str], or any)
        string_parser: Optional function to convert string → dict
                      If None, strings → empty dict

    Flow:
        dict → [dict]
        str → split by ',' → list[str] → map(string_parser) → list[dict]
        list[str] → map(string_parser) → list[dict]
        list[dict] → list[dict]
        Any → [{}]
    """
    if isinstance(value, dict):
        return [value]
    elif isinstance(value, list):
        if not value:
            return [{}]
        # Check if list[str] or list[dict]
        if all(isinstance(item, dict) for item in value):
            return value
        elif all(isinstance(item, str) for item in value):
            # list[str] → map with parser
            if string_parser:
                return [string_parser(s.strip()) for s in value if s.strip()]
            return [{}]
        else:
            # Mixed types - filter dicts only
            return [item for item in value if isinstance(item, dict)] or [{}]
    elif isinstance(value, str):
        # Try JSON parse first
        try:
            parsed = json.loads(value)
            if isinstance(parsed, dict):
                return [parsed]
            elif isinstance(parsed, list):
                return parsed
        except (json.JSONDecodeError, ValueError):
            pass

        # Not JSON - split by comma and parse
        parts = [s.strip() for s in value.split(",") if s.strip()]
        if not parts:
            return [{}]

        if string_parser:
            return [string_parser(part) for part in parts]
        return [{}]
    else:
        # Any other type → empty dict
        return [{}]


def looks_like_address(s: str) -> bool:
    """Check if string looks like an address (0x prefix or all hex chars)"""
    if s.startswith("0x") or s.startswith("0X"):
        return True
    # All hex chars and at least 4 chars → likely address
    if len(s) >= 4 and all(c in "0123456789abcdefABCDEF" for c in s):
        return True
    return False


@overload
def get_function(addr: int, *, raise_error: Literal[True]) -> Function: ...


@overload
def get_function(addr: int) -> Function: ...


@overload
def get_function(addr: int, *, raise_error: Literal[False]) -> Optional[Function]: ...


def get_function(addr, *, raise_error=True):
    from . import compat

    fn = idaapi.get_func(addr)
    if fn is None:
        if raise_error:
            raise IDAError(f"No function found at address {hex(addr)}")
        return None

    name = compat.get_func_name(fn)

    return Function(addr=hex(fn.start_ea), name=name, size=hex(fn.end_ea - fn.start_ea))


def get_prototype(fn: ida_funcs.func_t) -> Optional[str]:
    from . import compat

    prototype = compat.get_func_prototype(fn)
    if prototype is not None:
        return str(prototype)

    # Fallback: try idc.get_type
    try:
        return idc.get_type(fn.start_ea)
    except Exception:
        pass

    return None


DEMANGLED_TO_EA = {}


def create_demangled_to_ea_map():
    for ea in idautils.Functions():
        demangled = idaapi.demangle_name(idc.get_name(ea, 0), idaapi.MNG_NODEFINIT)
        if demangled:
            DEMANGLED_TO_EA[demangled] = ea


def get_type_by_name(type_name: str) -> ida_typeinf.tinfo_t:
    # 8-bit integers
    if type_name in ("int8", "__int8", "int8_t", "char", "signed char"):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_INT8)
    elif type_name in ("uint8", "__uint8", "uint8_t", "unsigned char", "byte", "BYTE"):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_UINT8)
    # 16-bit integers
    elif type_name in (
            "int16",
            "__int16",
            "int16_t",
            "short",
            "short int",
            "signed short",
            "signed short int",
    ):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_INT16)
    elif type_name in (
            "uint16",
            "__uint16",
            "uint16_t",
            "unsigned short",
            "unsigned short int",
            "word",
            "WORD",
    ):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_UINT16)
    # 32-bit integers
    elif type_name in (
            "int32",
            "__int32",
            "int32_t",
            "int",
            "signed int",
            "long",
            "long int",
            "signed long",
            "signed long int",
    ):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_INT32)
    elif type_name in (
            "uint32",
            "__uint32",
            "uint32_t",
            "unsigned int",
            "unsigned long",
            "unsigned long int",
            "dword",
            "DWORD",
    ):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_UINT32)
    # 64-bit integers
    elif type_name in (
            "int64",
            "__int64",
            "int64_t",
            "signed __int64",
            "long long",
            "long long int",
            "signed long long",
            "signed long long int",
    ):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_INT64)
    elif type_name in (
            "uint64",
            "__uint64",
            "uint64_t",
            "unsigned int64",
            "unsigned __int64",
            "unsigned long long",
            "unsigned long long int",
            "qword",
            "QWORD",
    ):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_UINT64)
    # 128-bit integers
    elif type_name in ("int128", "__int128", "int128_t", "__int128_t"):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_INT128)
    elif type_name in (
            "uint128",
            "__uint128",
            "uint128_t",
            "__uint128_t",
            "unsigned int128",
    ):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_UINT128)
    # Floating point types
    elif type_name in ("float",):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_FLOAT)
    elif type_name in ("double",):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_DOUBLE)
    elif type_name in ("long double", "ldouble"):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_LDOUBLE)
    # Boolean type
    elif type_name in ("bool", "_Bool", "boolean"):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_BOOL)
    # Void type
    elif type_name in ("void",):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_VOID)
    # Named types
    tif = ida_typeinf.tinfo_t()
    if tif.get_named_type(None, type_name, ida_typeinf.BTF_STRUCT):
        return tif
    if tif.get_named_type(None, type_name, ida_typeinf.BTF_TYPEDEF):
        return tif
    if tif.get_named_type(None, type_name, ida_typeinf.BTF_ENUM):
        return tif
    if tif.get_named_type(None, type_name, ida_typeinf.BTF_UNION):
        return tif

    # Try parse_decl for arbitrary type expressions (works in IDA 9.0+)
    tif = ida_typeinf.tinfo_t()
    flags = ida_typeinf.PT_SIL | ida_typeinf.PT_TYP
    candidate = type_name if type_name.endswith(";") else type_name + ";"
    if ida_typeinf.parse_decl(tif, None, candidate, flags) is not None and not tif.empty():
        return tif

    raise IDAError(f"Unable to retrieve {type_name} type info object")


def paginate(data: list[T], offset: int, count: int) -> Page[T]:
    if count == 0:
        count = len(data)
    next_offset = offset + count
    if next_offset >= len(data):
        next_offset = None
    return {
        "data": data[offset: offset + count],
        "next_offset": next_offset,
    }


def pattern_filter(data: list[T], pattern: str, key: str) -> list[T]:
    if not pattern:
        return data

    regex = None
    use_glob = False

    # Regex pattern: /pattern/flags
    if pattern.startswith("/") and pattern.count("/") >= 2:
        last_slash = pattern.rfind("/")
        body = pattern[1:last_slash]
        flag_str = pattern[last_slash + 1:]

        flags = 0
        for ch in flag_str:
            if ch == "i":
                flags |= re.IGNORECASE
            elif ch == "m":
                flags |= re.MULTILINE
            elif ch == "s":
                flags |= re.DOTALL

        try:
            regex = re.compile(body, flags or re.IGNORECASE)
        except re.error:
            regex = None
    # Glob pattern: contains * or ?
    elif "*" in pattern or "?" in pattern:
        use_glob = True

    def get_value(item) -> str:
        try:
            v = item[key]
        except Exception:
            v = getattr(item, key, "")
        return "" if v is None else str(v)

    def matches(item) -> bool:
        text = get_value(item)
        if regex is not None:
            return bool(regex.search(text))
        if use_glob:
            return fnmatch.fnmatch(text.lower(), pattern.lower())
        return pattern.lower() in text.lower()

    return [item for item in data if matches(item)]


def refresh_decompiler_widget():
    if not ida_hexrays.init_hexrays_plugin():
        return
    widget = ida_kernwin.get_current_widget()
    if widget is not None:
        vu = ida_hexrays.get_widget_vdui(widget)
        if vu is not None:
            vu.refresh_ctext()


def refresh_decompiler_ctext(fn_addr: int):
    if not ida_hexrays.init_hexrays_plugin():
        return
    error = ida_hexrays.hexrays_failure_t()
    cfunc: ida_hexrays.cfunc_t = ida_hexrays.decompile_func(
        fn_addr, error, ida_hexrays.DECOMP_WARNINGS
    )
    if cfunc:
        cfunc.refresh_func_ctext()


class my_modifier_t(ida_hexrays.user_lvar_modifier_t):
    def __init__(self, var_name: str, new_type: ida_typeinf.tinfo_t):
        ida_hexrays.user_lvar_modifier_t.__init__(self)
        self.var_name = var_name
        self.new_type = new_type

    def modify_lvars(self, lvinf):
        for lvar_saved in lvinf.lvvec:
            lvar_saved: ida_hexrays.lvar_saved_info_t
            if lvar_saved.name == self.var_name:
                lvar_saved.type = self.new_type
                return True
        return False


def hexrays_local_var_exists(func_ea: int, var_name: str) -> bool:
    """Return True if a Hex-Rays local variable exists in the decompiled function."""
    if not ida_hexrays.init_hexrays_plugin():
        return False
    try:
        cfunc = ida_hexrays.decompile(func_ea)
        if not cfunc:
            return False
        lvars = cfunc.get_lvars()
        for i in range(lvars.size()):
            if lvars[i].name == var_name:
                return True
    except Exception:
        return False
    return False


def parse_decls_ctypes(decls: str, hti_flags: int) -> tuple[int, list[str]]:
    if sys.platform == "win32":
        import ctypes

        assert isinstance(decls, str), "decls must be a string"
        assert isinstance(hti_flags, int), "hti_flags must be an int"
        c_decls = decls.encode("utf-8")
        c_til = None
        ida_dll = ctypes.CDLL("ida")
        ida_dll.parse_decls.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_void_p,
            ctypes.c_int,
        ]
        ida_dll.parse_decls.restype = ctypes.c_int

        messages: list[str] = []

        @ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_char_p, ctypes.c_char_p)
        def magic_printer(fmt: bytes, arg1: bytes):
            if fmt.count(b"%") == 1 and b"%s" in fmt:
                formatted = fmt.replace(b"%s", arg1)
                messages.append(formatted.decode("utf-8"))
                return len(formatted) + 1
            else:
                messages.append(f"unsupported magic_printer fmt: {repr(fmt)}")
                return 0

        errors = ida_dll.parse_decls(c_til, c_decls, magic_printer, hti_flags)
    else:
        errors = ida_typeinf.parse_decls(None, decls, False, hti_flags)
        messages = []
    return errors, messages


def get_stack_frame_variables_internal(
    fn_addr: int, raise_error: bool
) -> list[StackFrameVariable]:
    from .sync import ida_major

    if ida_major < 9:
        return []

    func = idaapi.get_func(fn_addr)
    if not func:
        if raise_error:
            raise IDAError(f"No function found at address {fn_addr}")
        return []

    tif = ida_typeinf.tinfo_t()
    if not tif.get_type_by_tid(func.frame) or not tif.is_udt():
        return []

    members: list[StackFrameVariable] = []
    udt = ida_typeinf.udt_type_data_t()
    tif.get_udt_details(udt)
    for udm in udt:
        if not udm.is_gap():
            name = udm.name
            offset = udm.offset // 8
            size = udm.size // 8
            type = str(udm.type)
            members.append(
                StackFrameVariable(
                    name=name, offset=hex(offset), size=hex(size), type=type
                )
            )
    return members


_STRING_OR_SPACES_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"'  # double-quoted string
    r"|'(?:[^'\\]|\\.)*'"  # single-quoted string / char
    r"|[ \t]{2,}"  # run of 2+ whitespace (outside strings)
)


def compact_whitespace(line: str) -> str:
    """Collapse runs of 2+ spaces/tabs to a single space, preserving string literals."""
    stripped = line.lstrip(" \t")
    if not stripped:
        return line
    lead = line[: len(line) - len(stripped)]

    def _repl(m: re.Match) -> str:
        s = m.group()
        if s[0] in ('"', "'"):
            return s  # preserve string content
        return " "

    return lead + _STRING_OR_SPACES_RE.sub(_repl, stripped)


# ============================================================================
# Decompiler cfunc cache
# ============================================================================
#
# decompile() previously decompiled a function TWICE per call -- once for the
# pseudocode text and once again to collect refs. Hex-Rays decompilation is
# the single most expensive operation in the server, so we memoise the cfunc_t
# per function start_ea. Entries are invalidated explicitly when a tool mutates
# the function (rename, retype, patch, ...) via bump_decompile_dirty(); a
# module-level dirty counter lets callers cheaply detect "did anything change?"

_cfunc_cache_lock = threading.RLock()
# func_start_ea -> (cfunc_or_None, error_str_or_None)
_cfunc_cache: dict[int, tuple[object, str | None]] = {}
_decompile_dirty_counter = 0


def get_decompile_dirty() -> int:
    """Return the current decompiler dirty counter (monotonically increasing)."""
    return _decompile_dirty_counter


def bump_decompile_dirty(ea: int | None = None) -> int:
    """Invalidate cached cfunc(s) and increment the dirty counter.

    Call after any mutation that changes decompiler output (rename, set_type,
    comment, asm patch, ...). `ea=None` clears the whole cache; otherwise the
    cache entry for the *enclosing function* of `ea` is dropped. Returns the new
    counter value. Thread-safe.
    """
    global _decompile_dirty_counter
    with _cfunc_cache_lock:
        if ea is None:
            _cfunc_cache.clear()
        else:
            func = idaapi.get_func(ea)
            key = func.start_ea if func is not None else ea
            _cfunc_cache.pop(key, None)
        _decompile_dirty_counter += 1
        return _decompile_dirty_counter


def get_cached_cfunc(ea: int) -> tuple[object, str | None]:
    """Decompile the function containing `ea`, caching the cfunc_t.

    Returns (cfunc_or_None, error_str_or_None): exactly one is non-None. The
    cfunc is keyed by the enclosing function's start_ea so repeated calls within
    one logical operation (text + refs) decompile only once. Errors are cached
    too, so a function the decompiler refuses is not retried on every call until
    bump_decompile_dirty() invalidates it. Thread-safe.
    """
    func = idaapi.get_func(ea)
    key = func.start_ea if func is not None else ea
    with _cfunc_cache_lock:
        if key in _cfunc_cache:
            return _cfunc_cache[key]
    cfunc: object = None
    err: str | None = None
    try:
        cfunc = decompile_checked(key)
    except IDAError as e:
        err = str(e)
    except Exception as e:
        err = f"Decompilation failed at {hex(key)}: {e}"
    with _cfunc_cache_lock:
        _cfunc_cache[key] = (cfunc, err)
    return cfunc, err


def decompile_checked(addr: int):
    """Decompile a function and raise IDAError on failure (uncached)."""
    if not ida_hexrays.init_hexrays_plugin():
        raise IDAError("Hex-Rays decompiler is not available")
    hf = ida_hexrays.hexrays_failure_t()
    cfunc = ida_hexrays.decompile(addr, hf)
    if not cfunc:
        if hf.code == ida_hexrays.MERR_LICENSE:
            raise IDAError(
                "Decompiler license is not available. Use `disassemble_function` to get the assembly code instead."
            )

        message = f"Decompilation failed at {hex(addr)}"
        if hf.str:
            message += f": {hf.str}"
        if hf.errea != idaapi.BADADDR:
            message += f" (address: {hex(hf.errea)})"
        raise IDAError(message)
    return cfunc


def decompile_function_safe(
    ea: int, include_addresses: bool = True
) -> tuple[str | None, str | None]:
    """Safely decompile a function. Returns (code, error); exactly one is non-None.

    Routes through the per-IDB cfunc cache (get_cached_cfunc) so callers that
    also need refs/lvars reuse the same decompilation instead of paying for a
    second decompile.
    """
    import ida_lines
    import ida_kernwin

    try:
        cfunc, err = get_cached_cfunc(ea)
        if cfunc is None:
            return None, err or f"Decompilation failed at {hex(ea)}"
        sv = cfunc.get_pseudocode()
        lines = []
        for sl in sv:
            sl: ida_kernwin.simpleline_t
            _head = ida_hexrays.ctree_item_t()
            item = ida_hexrays.ctree_item_t()
            _tail = ida_hexrays.ctree_item_t()
            line_ea = None
            if include_addresses and cfunc.get_line_item(sl.line, 0, False, _head, item, _tail):
                dstr: str | None = item.dstr()
                if dstr:
                    ds = dstr.split(": ")
                    if len(ds) == 2:
                        try:
                            line_ea = int(ds[0], 16)
                        except ValueError:
                            pass
            text = compact_whitespace(ida_lines.tag_remove(sl.line))
            if line_ea is not None:
                lines.append(f"{text} /*{line_ea:#x}*/")
            else:
                lines.append(text)
        return "\n".join(lines), None
    except IDAError as e:
        return None, str(e)
    except Exception as e:
        return None, f"Decompilation failed at {hex(ea)}: {e}"


def get_assembly_lines(ea: int) -> str:
    """Get assembly lines for a function in compact string format"""
    func = idaapi.get_func(ea)
    if not func:
        return ""

    func_name: str = ida_funcs.get_func_name(func.start_ea) or "<unnamed>"

    # Get segment from first instruction
    first_seg = idaapi.getseg(func.start_ea)
    segment_name = idaapi.get_segm_name(first_seg) if first_seg else "UNKNOWN"

    # Build compact string format
    lines_str = f"{func_name} ({segment_name} @ {hex(func.start_ea)}):"

    for item_ea in idautils.FuncItems(func.start_ea):
        mnem = idc.print_insn_mnem(item_ea) or ""
        ops = []
        for n in range(8):
            if idc.get_operand_type(item_ea, n) == idaapi.o_void:
                break
            ops.append(idc.print_operand(item_ea, n) or "")
        instruction = f"{mnem} {', '.join(ops)}".rstrip()
        lines_str += f"\n{item_ea:x}  {instruction}"

    return lines_str


def get_all_xrefs(ea: int) -> dict:
    """Get all xrefs to and from an address"""
    return {
        "to": [
            {"addr": hex(x.frm), "type": "code" if x.iscode else "data"}
            for x in idautils.XrefsTo(ea, 0)
        ],
        "from": [
            {"addr": hex(x.to), "type": "code" if x.iscode else "data"}
            for x in idautils.XrefsFrom(ea, 0)
        ],
    }


def get_all_comments(ea: int) -> dict:
    """Get all comments for an address"""
    func = idaapi.get_func(ea)
    if not func:
        return {}

    comments = {}
    for item_ea in idautils.FuncItems(func.start_ea):
        cmt = idaapi.get_cmt(item_ea, False)
        if cmt:
            comments[hex(item_ea)] = {"regular": cmt}
        cmt = idaapi.get_cmt(item_ea, True)
        if cmt:
            if hex(item_ea) not in comments:
                comments[hex(item_ea)] = {}
            comments[hex(item_ea)]["repeatable"] = cmt
    return comments


# ============================================================================
# Unified call-edge classification
# ============================================================================
#
# Historically `_direct_callees` followed *all* CodeRefsFrom (including
# tail-call jmps and fallthroughs) while `_direct_callers` filtered to
# NN_call* only. The two directions were therefore NOT transposes of each
# other, which silently corrupted the recursive callee walk and `reaches`.
# The helpers below are the single source of truth both directions use.

CallEdgeKind = Literal["call", "tailcall", "jump", "fallthrough", "indirect"]

# One classified control-flow edge, returned by iter_func_call_edges, is a
# plain dict with these keys (declared functionally because 'from' is a
# reserved word and cannot be a class attribute):
#   from:        int           -- the originating instruction EA
#   to:          int | None    -- target EA (None for unresolved indirect)
#   kind:        str           -- one of CallEdgeKind
#   indirect:    bool          -- True for unresolved indirect/virtual sites
#   target_name: str | None    -- IDA name of the target, when known
CallEdge = TypedDict(
    "CallEdge",
    {
        "from": int,
        "to": Optional[int],
        "kind": str,
        "indirect": bool,
        "target_name": Optional[str],
    },
)


def _insn_at(ea: int) -> Optional[idaapi.insn_t]:
    """Decode and return the instruction at `ea`, or None if undecodable."""
    insn = idaapi.insn_t()
    if idaapi.decode_insn(insn, ea) <= 0:
        return None
    return insn


def classify_code_edge(frm_ea: int) -> CallEdgeKind:
    """Classify the control-flow edge originating at instruction `frm_ea`.

    Returns one of {"call","tailcall","jump","fallthrough","indirect"} by
    decoding the instruction:

      * call       -- a direct call instruction (is_call_insn, resolvable
                      operand 0 target).
      * indirect   -- a call/jump whose target is computed (register/memory
                      operand) and not statically resolvable to one address.
      * tailcall   -- an unconditional jump that lands on the *start* of a
                      different function (classic tail call).
      * jump       -- any other jump (conditional, or jump within the same
                      function / into a non-function-start address).
      * fallthrough-- no branch (the instruction simply continues to the next).

    Defaults to "fallthrough" when the instruction cannot be decoded.
    """
    insn = _insn_at(frm_ea)
    if insn is None:
        return "fallthrough"

    op0_type = idc.get_operand_type(frm_ea, 0)
    direct_target_op = op0_type in (idaapi.o_near, idaapi.o_far, idaapi.o_mem)

    if idaapi.is_call_insn(insn):
        # A call whose op0 is a register/computed operand is indirect; o_mem
        # (call [rip+x]) is treated as indirect too because the real callee is
        # the pointed-to value, not the memory address itself.
        if op0_type in (idaapi.o_near, idaapi.o_far):
            return "call"
        return "indirect"

    # Jump family (conditional or unconditional). itype is in the NN_j* range
    # on x86; rather than enumerate, detect via mnemonic prefix + code ref.
    mnem = (idc.print_insn_mnem(frm_ea) or "").lower()
    is_jump = mnem.startswith("j") or mnem in ("b", "bl", "br", "bx", "jmp")
    if is_jump:
        if not direct_target_op:
            return "indirect"
        target = idc.get_operand_value(frm_ea, 0)
        tfunc = idaapi.get_func(target)
        if tfunc is not None and tfunc.start_ea == target:
            src_func = idaapi.get_func(frm_ea)
            if src_func is None or src_func.start_ea != tfunc.start_ea:
                return "tailcall"
        return "jump"

    return "fallthrough"


def _iter_func_chunk_items(func_ea: int):
    """Yield every instruction head across ALL chunks of the function.

    Uses idautils.Chunks, which enumerates the main entry chunk AND every
    out-of-line tail (cold paths, shared tails) — unlike idautils.FuncItems
    (main chunk only) and unlike func_tail_iterator_t.first(), which skips the
    main chunk for a function that has no separate tails.
    """
    if idaapi.get_func(func_ea) is None:
        return
    for chunk_start, chunk_end in idautils.Chunks(func_ea):
        ea = chunk_start
        while ea < chunk_end and ea != idaapi.BADADDR:
            yield ea
            ea = idc.next_head(ea, chunk_end)


def _switch_targets(ea: int) -> list[int]:
    """Resolve jump-table / switch case targets at instruction `ea`.

    Returns the distinct case target addresses (incl. default) when `ea` is an
    indirect jump driven by a switch IDA has recognised; empty list otherwise.
    """
    try:
        si = idaapi.get_switch_info(ea)
    except Exception:
        si = None
    if si is None:
        return []
    targets: list[int] = []
    try:
        results = idaapi.calc_switch_cases(ea, si)
    except Exception:
        results = None
    if results is not None:
        try:
            for tgt in results.targets:
                targets.append(int(tgt))
        except Exception:
            pass
    if not targets:
        # Fallback: read the jump table directly.
        try:
            jtable = si.jumps
            elsize = si.get_jtable_element_size()
            ncases = int(si.get_jtable_size())
            for i in range(ncases):
                slot = jtable + i * elsize
                val = read_int_bss_safe(slot, elsize) if elsize in (1, 2, 4, 8) else 0
                if si.flags & idaapi.SWI_ELBASE:
                    val += si.elbase
                if val:
                    targets.append(val)
        except Exception:
            pass
    default = getattr(si, "defjump", idaapi.BADADDR)
    if default not in (None, idaapi.BADADDR):
        targets.append(int(default))
    return _dedup_ints(targets)


def _dedup_ints(items: list[int]) -> list[int]:
    seen: set[int] = set()
    out: list[int] = []
    for it in items:
        if it in seen:
            continue
        seen.add(it)
        out.append(it)
    return out


def iter_func_call_edges(func_ea: int, direction: str = "out") -> list[CallEdge]:
    """Chunk-aware, switch-aware call/jump edge enumeration for a function.

    This is the single source of truth that both the callee and caller
    directions build on, so they are exact transposes of one another.

    direction:
      * "out" -- edges leaving `func_ea`: every call/tailcall/indirect site in
        any of the function's chunks, plus resolved switch/jump-table targets.
        Unresolved indirect / virtual call sites are surfaced as explicit
        edges with indirect=True and to=None.
      * "in"  -- edges entering `func_ea`: every call/tailcall site (in any
        caller, across that caller's chunks) whose target is `func_ea`.

    Returns list of dicts: {"from": int, "to": int|None, "kind": str,
    "indirect": bool, "target_name": str|None}. Only call/tailcall/indirect
    edges are emitted (plain intra-function jumps and fallthroughs are not
    call-graph edges and are filtered out).
    """
    func = idaapi.get_func(func_ea)
    if func is None:
        return []
    start_ea = func.start_ea

    def _name_for(tea: Optional[int]) -> Optional[str]:
        if tea is None or tea == idaapi.BADADDR:
            return None
        nm = idc.get_name(tea)
        return nm or None

    edges: list[dict] = []
    seen: set[tuple] = set()

    def _add(frm: int, to: Optional[int], kind: str, indirect: bool):
        key = (frm, to, kind, indirect)
        if key in seen:
            return
        seen.add(key)
        edges.append(
            {
                "from": frm,
                "to": to,
                "kind": kind,
                "indirect": indirect,
                "target_name": _name_for(to),
            }
        )

    if direction == "out":
        for item_ea in _iter_func_chunk_items(start_ea):
            kind = classify_code_edge(item_ea)
            if kind == "call":
                target = idc.get_operand_value(item_ea, 0)
                _add(item_ea, int(target), "call", False)
            elif kind == "tailcall":
                target = idc.get_operand_value(item_ea, 0)
                _add(item_ea, int(target), "tailcall", False)
            elif kind == "indirect":
                # Try to resolve via a switch/jump table first.
                sw_targets = _switch_targets(item_ea)
                if sw_targets:
                    for t in sw_targets:
                        _add(item_ea, t, "jump", False)
                else:
                    _add(item_ea, None, "indirect", True)
            # plain "jump"/"fallthrough" are not call-graph edges
        return edges

    # direction == "in": find call/tailcall sites whose target is this func.
    for ref in idautils.CodeRefsTo(start_ea, 0):
        kind = classify_code_edge(ref)
        if kind not in ("call", "tailcall"):
            continue
        _add(int(ref), start_ea, kind, False)
    return edges


# ============================================================================
# Budgeted call-tree traversal primitive
# ============================================================================


class WalkNode(TypedDict):
    ea: int
    depth: int
    parent: Optional[int]
    is_leaf: bool
    is_recursive: bool
    back_edge: bool


def _call_neighbors(func_ea: int, direction: str) -> list[int]:
    """Distinct neighbour function start-EAs via iter_func_call_edges.

    "out" -> callee function starts (resolved direct/tailcall targets that land
    inside a known function); "in" -> caller function starts. Indirect edges
    with no static target are skipped here (no node to expand).
    """
    out: list[int] = []
    if direction == "in":
        for edge in iter_func_call_edges(func_ea, "in"):
            site = edge.get("from")
            caller = idaapi.get_func(site) if site is not None else None
            if caller is not None:
                out.append(caller.start_ea)
    else:
        for edge in iter_func_call_edges(func_ea, "out"):
            to = edge.get("to")
            if to is None:
                continue
            callee = idaapi.get_func(to)
            if callee is not None:
                out.append(callee.start_ea)
    return _dedup_ints(out)


def walk_call_tree(
    root_ea: int,
    *,
    depth: int,
    node_budget: int,
    direction: str = "out",
    deadline: float | None = None,
) -> list[WalkNode]:
    """Iterative BFS over the call graph with depth, node, and time budgets.

    Replaces recursive DFS (which mislabelled depth and risked RecursionError)
    with an explicit BFS queue. Cycle detection uses a visited set; a neighbour
    already visited produces a back-edge node (back_edge=True) that is recorded
    but not re-expanded, so the result still surfaces recursion without looping.

    Args:
      root_ea: function start EA to walk from (recorded at depth 0).
      depth: max levels to descend/ascend (0 = root only). Negative clamps to 0.
      node_budget: hard cap on distinct functions recorded; hitting it stops
        the walk (the node that would exceed it is not added).
      direction: "out" (callees) or "in" (callers).
      deadline: monotonic time at which to bail; defaults to
        get_tool_deadline(). The walk stops once time.monotonic() >= deadline.

    Yields/returns list of WalkNode: {ea, depth, parent, is_leaf, is_recursive,
    back_edge}. `is_recursive` flags a self-call (neighbour == node). A leaf is
    a node with no expandable neighbours (or one beyond the depth bound). The
    root has parent=None.

    The shared backbone for callgraph / callees_recursive / callers_recursive /
    reaches and future call-tree tools, so they share cycle/budget semantics.
    """
    if depth < 0:
        depth = 0
    if node_budget < 1:
        node_budget = 1
    if deadline is None:
        deadline = get_tool_deadline()
    direction = "in" if direction == "in" else "out"

    def _expired() -> bool:
        return deadline is not None and time.monotonic() >= deadline

    visited: set[int] = {root_ea}
    nodes: list[WalkNode] = []
    # frontier holds (ea, depth, parent)
    frontier: list[tuple[int, int, Optional[int]]] = [(root_ea, 0, None)]

    while frontier:
        if _expired():
            break
        next_frontier: list[tuple[int, int, Optional[int]]] = []
        for ea, d, parent in frontier:
            if _expired():
                break
            neighbors = [] if d >= depth else _call_neighbors(ea, direction)
            is_recursive = any(n == ea for n in neighbors)
            expandable = [n for n in neighbors if n != ea]
            is_leaf = len(expandable) == 0
            nodes.append(
                {
                    "ea": ea,
                    "depth": d,
                    "parent": parent,
                    "is_leaf": is_leaf,
                    "is_recursive": is_recursive,
                    "back_edge": False,
                }
            )
            if d >= depth:
                continue
            for nxt in expandable:
                if nxt in visited:
                    # Cycle / shared subtree: record a back-edge node but do
                    # not re-expand it.
                    nodes.append(
                        {
                            "ea": nxt,
                            "depth": d + 1,
                            "parent": ea,
                            "is_leaf": True,
                            "is_recursive": False,
                            "back_edge": True,
                        }
                    )
                    continue
                if len(visited) >= node_budget:
                    return nodes
                visited.add(nxt)
                next_frontier.append((nxt, d + 1, ea))
        frontier = next_frontier

    return nodes


def get_callees(addr: str) -> list[dict]:
    """Get callees for a single function address.

    Chunk- and tail-call-aware via iter_func_call_edges. RETURN CONTRACT
    (unchanged shape): list of {"addr","name","type"} dicts, deduplicated by
    target. `type` is "internal" when the target lands inside a known function,
    else "external". Unresolved indirect call sites are not included (they have
    no named target).
    """
    try:
        func_start = parse_address(addr)
        func = idaapi.get_func(func_start)
        if not func:
            return []
        callees: list[dict[str, str]] = []
        for edge in iter_func_call_edges(func_start, "out"):
            target = edge.get("to")
            if target is None:
                continue
            if edge.get("kind") not in ("call", "tailcall"):
                continue
            func_name = edge.get("target_name") or idc.get_name(target)
            if not func_name:
                continue
            func_type = (
                "internal" if idaapi.get_func(target) is not None else "external"
            )
            callees.append(
                {
                    "addr": hex(target),
                    "name": func_name,
                    "type": func_type,
                }
            )

        unique_callee_tuples = {tuple(callee.items()) for callee in callees}
        unique_callees = [dict(callee) for callee in unique_callee_tuples]
        return unique_callees
    except Exception:
        return []


def get_callers(addr: str, limit: int = 50) -> list[Function]:
    """Get callers for a single function address.

    Chunk- and tail-call-aware via iter_func_call_edges. RETURN CONTRACT
    (unchanged shape): list of Function dicts {"addr","name","size"}, one per
    distinct calling function, capped at `limit`.
    """
    try:
        target = parse_address(addr)
        callers: dict[str, Function] = {}
        for edge in iter_func_call_edges(target, "in"):
            if len(callers) >= limit:
                break
            site = edge.get("from")
            if site is None:
                continue
            func = get_function(site, raise_error=False)
            if not func:
                continue
            callers[func["addr"]] = func
        return list(callers.values())
    except Exception:
        return []


def get_xrefs_from_internal(ea: int) -> list[Xref]:
    """Get all xrefs from an address"""
    xrefs = []
    for xref in idautils.XrefsFrom(ea, 0):
        xrefs.append(
            Xref(
                addr=hex(xref.to),
                type="code" if xref.iscode else "data",
                fn=get_function(xref.to, raise_error=False),
            )
        )
    return xrefs


def extract_function_strings(ea: int) -> list[String]:
    """Extract string references from a function"""
    func = idaapi.get_func(ea)
    if not func:
        return []

    strings = []
    for item_ea in idautils.FuncItems(func.start_ea):
        for xref in idautils.XrefsFrom(item_ea, 0):
            if not xref.iscode:
                # Accept ANY string type, not just STRTYPE_C. The old
                # `!= STRTYPE_C` check silently dropped UTF-16/UTF-32 and
                # Pascal strings, which undercounts strings on Windows
                # binaries (wide literals) and is brittle anyway because
                # get_str_type packs encoding flags into the upper bytes.
                if not ida_bytes.is_strlit(ida_bytes.get_flags(xref.to)):
                    continue
                str_type = ida_nalt.get_str_type(xref.to)
                if str_type is None or str_type < 0:
                    str_type = ida_nalt.STRTYPE_C
                try:
                    # Decode per the detected string type so wide/Pascal
                    # literals are read with the right element width.
                    str_content = idc.get_strlit_contents(xref.to, -1, str_type)
                    if str_content:
                        strings.append(
                            String(
                                addr=hex(xref.to),
                                length=len(str_content),
                                string=str_content.decode("utf-8", errors="replace"),
                            )
                        )
                except Exception:
                    pass
    return strings


def extract_function_constants(ea: int) -> list[dict]:
    """Extract immediate constants from a function"""
    func = idaapi.get_func(ea)
    if not func:
        return []

    constants = []
    for item_ea in idautils.FuncItems(func.start_ea):
        insn = idaapi.insn_t()
        if idaapi.decode_insn(insn, item_ea) > 0:
            for op in insn.ops:
                if op.type == idaapi.o_imm:
                    constants.append(
                        {
                            "addr": hex(item_ea),
                            "value": hex(op.value),
                            "decimal": op.value,
                        }
                    )
    return constants


# ============================================================================
# Large Output Handling
# ============================================================================


def _prune_spill_dir(spill_dir: str, max_files: int = 32) -> None:
    """Keep at most `max_files` spill files, deleting the oldest first."""
    try:
        entries = [
            os.path.join(spill_dir, name)
            for name in os.listdir(spill_dir)
            if name.startswith("ida_mcp_") and name.endswith(".json")
        ]
    except OSError:
        return
    if len(entries) < max_files:
        return
    try:
        entries.sort(key=lambda p: os.path.getmtime(p))
    except OSError:
        return
    for stale in entries[: len(entries) - max_files + 1]:
        try:
            os.unlink(stale)
        except OSError:
            pass


def handle_large_output(result: Any, line_threshold: int = 3000) -> Any:
    """
    Handle potentially large outputs by writing to temp file if needed.

    Args:
        result: The result object to check
        line_threshold: Number of lines above which to write to file (default: 3000)

    Returns:
        Either the original result or a dict with file path if written to file
    """
    try:
        serialized = json.dumps(result, indent=2)
        line_count = serialized.count("\n") + 1

        if line_count > line_threshold:
            spill_dir = os.path.join(tempfile.gettempdir(), "ida_mcp_large_output")
            os.makedirs(spill_dir, exist_ok=True)
            _prune_spill_dir(spill_dir, max_files=32)
            fd, temp_path = tempfile.mkstemp(
                suffix=".json", prefix="ida_mcp_", dir=spill_dir, text=True
            )
            try:
                with os.fdopen(fd, "w") as f:
                    f.write(serialized)

                return {
                    "type": "file_reference",
                    "path": temp_path,
                    "line_count": line_count,
                    "message": f"Output too large ({line_count} lines), written to file",
                }
            except Exception:
                os.close(fd)
                raise

        return result

    except Exception:
        return result
