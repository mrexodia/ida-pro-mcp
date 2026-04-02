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
import ida_name
from .rpc import tool
from .sync import idasync, tool_timeout, IDAError
from .utils import (
    parse_address,
    normalize_list_input,
    normalize_dict_list,
    get_function,
    get_prototype,
    paginate,
    pattern_filter,
    get_stack_frame_variables_internal,
    decompile_function_safe,
    get_assembly_lines,
    get_all_xrefs,
    get_all_comments,
    Function,
    get_callers,
    get_callees,
    extract_function_strings,
    extract_function_constants,
    Argument,
    DisassemblyFunction,
    Xref,
    BasicBlock,
    StructFieldQuery,
    XrefQuery,
    InsnPattern,
    FuncProfileQuery,
    AnalyzeBatchQuery,
)
from . import compat


class DecompileResult(TypedDict):
    addr: str
    code: str | None
    error: NotRequired[str]


class ResultCursor(TypedDict, total=False):
    next: int
    done: bool


class DisasmResult(TypedDict, total=False):
    addr: str
    asm: DisassemblyFunction | None
    instruction_count: int
    total_instructions: int | None
    cursor: ResultCursor
    error: str


class FuncProfileItem(TypedDict, total=False):
    addr: str
    name: str
    size: str
    instruction_count: int
    basic_block_count: int
    caller_count: int
    callee_count: int
    string_ref_count: int
    constant_count: int
    has_type: bool
    prototype: str | None
    callers: list[dict[str, Any]]
    callers_truncated: bool
    callees: list[dict[str, Any]]
    callees_truncated: bool
    strings: list[dict[str, Any]]
    strings_truncated: bool
    constants: list[dict[str, Any]]
    constants_truncated: bool
    error: str | None


class FuncProfileResult(TypedDict, total=False):
    query: str
    data: list[FuncProfileItem]
    next_offset: int | None
    error: str | None


class AnalyzeBatchDisasm(TypedDict):
    lines: list[str]
    instruction_count: int
    truncated: bool


AnalyzeBatchXrefs = TypedDict(
    "AnalyzeBatchXrefs",
    {
        "to": list[dict[str, str]],
        "from": list[dict[str, str]],
        "to_truncated": bool,
        "from_truncated": bool,
        "to_count": int,
        "from_count": int,
    },
)


class AnalyzeBatchDetails(TypedDict, total=False):
    size: str
    prototype: str | None
    decompile: str | None
    decompile_error: str | None
    disasm: AnalyzeBatchDisasm | None
    xrefs: AnalyzeBatchXrefs | None
    callers: list[dict[str, Any]] | None
    caller_count: int
    callers_truncated: bool
    callees: list[dict[str, Any]] | None
    callee_count: int
    callees_truncated: bool
    strings: list[dict[str, Any]] | None
    string_ref_count: int
    strings_truncated: bool
    constants: list[dict[str, Any]] | None
    constant_count: int
    constants_truncated: bool
    basic_blocks: list[BasicBlock] | None
    basic_block_count: int
    basic_blocks_truncated: bool


class AnalyzeBatchResult(TypedDict, total=False):
    query: str
    addr: str | None
    name: str | None
    analysis: AnalyzeBatchDetails | None
    error: str | None


class XrefsToResult(TypedDict, total=False):
    addr: str
    xrefs: list[Xref] | None
    more: bool
    error: str


XrefQueryRow = TypedDict(
    "XrefQueryRow",
    {
        "direction": str,
        "addr": str,
        "from": str,
        "to": str,
        "type": str,
        "fn": Function | None,
    },
    total=False,
)


class XrefQueryResult(TypedDict, total=False):
    query: str
    resolved_addr: str | None
    direction: str
    xref_type: str
    data: list[XrefQueryRow]
    next_offset: int | None
    total: int
    error: str | None


class StructFieldXrefsResult(TypedDict, total=False):
    struct: str
    field: str
    xrefs: list[Xref]
    error: str


class CalleeResultItem(TypedDict):
    addr: str
    name: str
    type: str


class CalleesResult(TypedDict, total=False):
    addr: str
    callees: list[CalleeResultItem] | None
    more: bool
    error: str


class FindBytesResult(TypedDict, total=False):
    pattern: str
    matches: list[str]
    n: int
    cursor: ResultCursor
    error: str


class BasicBlocksResult(TypedDict, total=False):
    addr: str
    error: str
    blocks: list[BasicBlock]
    count: int
    total_blocks: int
    cursor: ResultCursor


class FindResult(TypedDict, total=False):
    query: str | int | None
    matches: list[str]
    count: int
    cursor: ResultCursor
    error: str | None


class InsnScanRange(TypedDict):
    start: str
    end: str


class InsnQuerySummary(TypedDict, total=False):
    mnem: str | None
    op0: int | str | None
    op1: int | str | None
    op2: int | str | None
    op_any: int | str | None
    func: str | None
    segment: str | None
    start: str | None
    end: str | None
    offset: int
    count: int
    max_scan_insns: int
    allow_broad: bool


class InsnQueryMatch(TypedDict, total=False):
    addr: str
    disasm: str
    fn: Function | None


class InsnQueryResult(TypedDict, total=False):
    query: InsnQuerySummary
    ranges: list[InsnScanRange]
    matches: list[InsnQueryMatch]
    count: int
    cursor: ResultCursor
    scanned: int
    truncated: bool
    next_start: str | None
    error: str | None


class ExportedFunctionJson(TypedDict, total=False):
    addr: str
    name: str | None
    prototype: str | None
    size: str
    comments: dict[str, dict[str, str]]
    asm: str
    code: str | None
    xrefs: dict[str, list[dict[str, str]]]
    error: str


class ExportedPrototype(TypedDict, total=False):
    name: str | None
    prototype: str


class ExportFuncsJsonResult(TypedDict):
    format: str
    functions: list[ExportedFunctionJson]


class ExportFuncsHeaderResult(TypedDict):
    format: str
    content: str


class ExportFuncsPrototypesResult(TypedDict):
    format: str
    functions: list[ExportedPrototype]


class CallGraphNode(TypedDict):
    addr: str
    name: str | None
    depth: int


CallGraphEdge = TypedDict(
    "CallGraphEdge",
    {"from": str, "to": str, "type": str},
)


class CallGraphResult(TypedDict, total=False):
    root: str
    nodes: list[CallGraphNode]
    edges: list[CallGraphEdge]
    max_depth: int
    truncated: bool
    limit_reason: str | None
    max_nodes: int
    max_edges: int
    max_edges_per_func: int
    per_func_capped: bool
    error: str


# ============================================================================
# Instruction Helpers
# ============================================================================

_IMM_SCAN_BACK_MAX = 15


def _raw_bin_search(
    ea: int, max_ea: int, data: bytes, mask: bytes, flags: int = 0
) -> int:
    """Search for raw bytes with mask, compatible across IDA versions.

    Returns the match address, or idaapi.BADADDR if not found.
    """
    search_flags = flags or (ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOSHOW)
    return compat.raw_bin_search(ea, max_ea, data, mask, search_flags)


def _decode_insn_at(ea: int) -> ida_ua.insn_t | None:
    insn = ida_ua.insn_t()
    if ida_ua.decode_insn(insn, ea) == 0:
        return None
    return insn


def _next_head(ea: int, end_ea: int) -> int:
    return ida_bytes.next_head(ea, end_ea)


def _operand_value(insn: ida_ua.insn_t, i: int) -> int | None:
    op = insn.ops[i]
    if op.type == ida_ua.o_void:
        return None
    if op.type in (ida_ua.o_mem, ida_ua.o_far, ida_ua.o_near):
        return op.addr
    return op.value


def _operand_type(insn: ida_ua.insn_t, i: int) -> int:
    return insn.ops[i].type


def _insn_mnem(insn: ida_ua.insn_t) -> str:
    try:
        return insn.get_canon_mnem().lower()
    except Exception:
        return ""


def _value_to_le_bytes(value: int) -> tuple[bytes, int, int] | None:
    if value < 0:
        if value >= -0x80000000:
            size = 4
            value &= 0xFFFFFFFF
        elif value >= -0x8000000000000000:
            size = 8
            value &= 0xFFFFFFFFFFFFFFFF
        else:
            return None
    else:
        if value <= 0xFFFFFFFF:
            size = 4
        elif value <= 0xFFFFFFFFFFFFFFFF:
            size = 8
        else:
            return None

    fmt = "<I" if size == 4 else "<Q"
    return struct.pack(fmt, value), size, value


def _value_candidates_for_immediate(value: int) -> list[tuple[int, int, bytes]]:
    candidates: list[tuple[int, int, bytes]] = []

    def add(size: int, signed_val: int):
        if size == 4:
            masked = signed_val & 0xFFFFFFFF
            if not (-0x80000000 <= signed_val <= 0x7FFFFFFF):
                return
            b = struct.pack("<I", masked)
        else:
            masked = signed_val & 0xFFFFFFFFFFFFFFFF
            if not (-0x8000000000000000 <= signed_val <= 0x7FFFFFFFFFFFFFFF):
                return
            b = struct.pack("<Q", masked)
        candidates.append((masked, size, b))

    add(4, value)
    add(8, value)
    return candidates


def _resolve_immediate_insn_start(
    match_ea: int,
    value: int,
    seg_start: int,
    alt_value: int | None = None,
) -> int | None:
    start_min = max(seg_start, match_ea - _IMM_SCAN_BACK_MAX)
    for start in range(match_ea, start_min - 1, -1):
        insn = _decode_insn_at(start)
        if insn is None:
            continue
        end_ea = start + insn.size
        if not (start <= match_ea < end_ea):
            continue
        for i in range(8):
            op_type = _operand_type(insn, i)
            if op_type == ida_ua.o_void:
                break
            if op_type != ida_ua.o_imm:
                continue
            op_val = _operand_value(insn, i)
            if op_val is None:
                continue
            if op_val == value or (alt_value is not None and op_val == alt_value):
                offb = getattr(insn.ops[i], "offb", 0)
                if offb and start + offb != match_ea:
                    continue
                return start
    return None


def _clamp_int(value: object, default: int, minimum: int, maximum: int) -> int:
    try:
        i = int(value)
    except Exception:
        i = default
    if i < minimum:
        return minimum
    if i > maximum:
        return maximum
    return i


def _parse_optional_int(value: object, field: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return None
        try:
            return int(s, 0)
        except Exception as e:
            raise ValueError(f"{field} must be an integer") from e
    try:
        return int(value)
    except Exception as e:
        raise ValueError(f"{field} must be an integer") from e


def _resolve_function_start(query: object) -> tuple[int | None, str | None]:
    q = str(query or "").strip()
    if not q:
        return None, "Function query is required"

    ea = idaapi.BADADDR
    try:
        ea = parse_address(q)
    except Exception:
        ea = idaapi.get_name_ea(idaapi.BADADDR, q)

    if ea == idaapi.BADADDR:
        return None, f"Failed to resolve function: {q}"

    func = idaapi.get_func(ea)
    if not func:
        return None, f"Not a function: {q}"
    return func.start_ea, None


def _limit_items(items: list, limit: int) -> tuple[list, bool]:
    if limit < 0:
        limit = 0
    if len(items) <= limit:
        return items, False
    return items[:limit], True


def _disasm_lines_limited(func: ida_funcs.func_t, max_insns: int) -> tuple[list[str], bool]:
    lines: list[str] = []
    truncated = False
    for item_ea in idautils.FuncItems(func.start_ea):
        if len(lines) >= max_insns:
            truncated = True
            break
        line = ida_lines.generate_disasm_line(item_ea, 0)
        instruction = ida_lines.tag_remove(line) if line else ""
        lines.append(f"{item_ea:x}  {instruction}")
    return lines, truncated


def _collect_basic_blocks_limited(
    func: ida_funcs.func_t, max_blocks: int
) -> tuple[list[BasicBlock], bool]:
    blocks: list[BasicBlock] = []
    truncated = False
    for block in idaapi.FlowChart(func):
        if len(blocks) >= max_blocks:
            truncated = True
            break
        blocks.append(
            BasicBlock(
                start=hex(block.start_ea),
                end=hex(block.end_ea),
                size=block.end_ea - block.start_ea,
                type=block.type,
                successors=[hex(s.start_ea) for s in block.succs()],
                predecessors=[hex(p.start_ea) for p in block.preds()],
            )
        )
    return blocks, truncated


def _collect_callees_for_function(func: ida_funcs.func_t) -> list[dict]:
    callees: dict[int, dict] = {}
    for item_ea in idautils.FuncItems(func.start_ea):
        for target in idautils.CodeRefsFrom(item_ea, 0):
            callee = idaapi.get_func(target)
            if not callee:
                continue
            callee_start = callee.start_ea
            if callee_start in callees:
                continue
            callees[callee_start] = {
                "addr": hex(callee_start),
                "name": ida_funcs.get_func_name(callee_start) or "<unnamed>",
            }
    return list(callees.values())


def _collect_callers_for_function(func: ida_funcs.func_t) -> list[dict]:
    callers: dict[int, dict] = {}
    for caller_site in idautils.CodeRefsTo(func.start_ea, 0):
        caller = idaapi.get_func(caller_site)
        if not caller:
            continue
        caller_start = caller.start_ea
        if caller_start in callers:
            continue

        insn = idaapi.insn_t()
        idaapi.decode_insn(insn, caller_site)
        if insn.itype not in [idaapi.NN_call, idaapi.NN_callfi, idaapi.NN_callni]:
            continue

        callers[caller_start] = {
            "addr": hex(caller_start),
            "name": ida_funcs.get_func_name(caller_start) or "<unnamed>",
        }
    return list(callers.values())


def _profile_function(
    start_ea: int,
    include_lists: bool,
    max_items: int,
    include_prototype: bool,
) -> FuncProfileItem:
    func = idaapi.get_func(start_ea)
    if not func:
        return {"addr": hex(start_ea), "error": "Function not found"}

    name = ida_funcs.get_func_name(func.start_ea) or "<unnamed>"
    size_int = func.end_ea - func.start_ea
    has_type = ida_nalt.get_tinfo(ida_typeinf.tinfo_t(), func.start_ea)

    instruction_count = sum(1 for _ in idautils.FuncItems(func.start_ea))
    basic_block_count = sum(1 for _ in idaapi.FlowChart(func))
    callers = _collect_callers_for_function(func)
    callees = _collect_callees_for_function(func)
    strings = extract_function_strings(func.start_ea)
    constants = extract_function_constants(func.start_ea)

    out = {
        "addr": hex(func.start_ea),
        "name": name,
        "size": hex(size_int),
        "size_int": size_int,
        "instruction_count": instruction_count,
        "basic_block_count": basic_block_count,
        "caller_count": len(callers),
        "callee_count": len(callees),
        "string_ref_count": len(strings),
        "constant_count": len(constants),
        "has_type": has_type,
        "prototype": None,
        "error": None,
    }

    if include_prototype:
        out["prototype"] = get_prototype(func)

    if include_lists:
        callers_limited, callers_truncated = _limit_items(callers, max_items)
        callees_limited, callees_truncated = _limit_items(callees, max_items)
        strings_limited, strings_truncated = _limit_items(strings, max_items)
        constants_limited, constants_truncated = _limit_items(constants, max_items)

        out["callers"] = callers_limited
        out["callers_truncated"] = callers_truncated
        out["callees"] = callees_limited
        out["callees_truncated"] = callees_truncated
        out["strings"] = strings_limited
        out["strings_truncated"] = strings_truncated
        out["constants"] = constants_limited
        out["constants_truncated"] = constants_truncated

    return out


# ============================================================================
# Code Analysis & Decompilation
# ============================================================================


@tool
@idasync
@tool_timeout(90.0)
def decompile(
    addr: Annotated[str, "Function address or name to decompile"],
) -> DecompileResult:
    """Decompile function(s) at address(es); returns pseudocode and per-item errors."""
    try:
        try:
            start = parse_address(addr)
        except IDAError:
            ea = idaapi.get_name_ea(idaapi.BADADDR, addr)
            if ea == idaapi.BADADDR:
                return {
                    "addr": addr,
                    "code": None,
                    "error": f"Function not found: {addr!r}",
                }
            start = ea
        code = decompile_function_safe(start)
        if code is None:
            return {"addr": addr, "code": None, "error": "Decompilation failed"}
        return {"addr": addr, "code": code}
    except Exception as e:
        return {"addr": addr, "code": None, "error": str(e)}


@tool
@idasync
@tool_timeout(90.0)
def disasm(
    addr: Annotated[str, "Function address or name to disassemble"],
    max_instructions: Annotated[
        int, "Max instructions per function (default: 5000, max: 50000)"
    ] = 5000,
    offset: Annotated[int, "Skip first N instructions (default: 0)"] = 0,
    include_total: Annotated[
        bool, "Compute total instruction count (default: false)"
    ] = False,
) -> DisasmResult:
    """Disassemble function with offset/max_instructions pagination and optional total count."""

    # Enforce max limit
    if max_instructions <= 0 or max_instructions > 50000:
        max_instructions = 50000
    if offset < 0:
        offset = 0

    try:
        try:
            start = parse_address(addr)
        except IDAError:
            ea = idaapi.get_name_ea(idaapi.BADADDR, addr)
            if ea == idaapi.BADADDR:
                return {
                    "addr": addr,
                    "asm": None,
                    "error": f"Function not found: {addr!r}",
                    "cursor": {"done": True},
                }
            start = ea
        func = idaapi.get_func(start)

        # Get segment info
        seg = idaapi.getseg(start)
        if not seg:
            return {
                "addr": addr,
                "asm": None,
                "error": "No segment found",
                "cursor": {"done": True},
            }

        segment_name = idaapi.get_segm_name(seg) if seg else "UNKNOWN"

        if func:
            # Function exists: disassemble function items starting from requested address
            func_name: str = ida_funcs.get_func_name(func.start_ea) or "<unnamed>"
            header_addr = start  # Use requested address, not function start
        else:
            # No function: disassemble sequentially from start address
            func_name = "<no function>"
            header_addr = start

        lines: list[dict] = []
        seen = 0
        total_count = 0
        more = False

        def _maybe_add(ea: int) -> bool:
            nonlocal seen, total_count, more
            if include_total:
                total_count += 1
            if seen < offset:
                seen += 1
                return True
            if len(lines) < max_instructions:
                line = ida_lines.generate_disasm_line(ea, 0)
                instruction = ida_lines.tag_remove(line) if line else ""
                lines.append({"addr": f"{ea:x}", "instruction": instruction})
                seen += 1
                return True
            more = True
            seen += 1
            return include_total

        if func:
            for ea in idautils.FuncItems(func.start_ea):
                if ea == idaapi.BADADDR:
                    continue
                if ea < start:
                    continue
                if not _maybe_add(ea):
                    break
        else:
            ea = start
            while ea < seg.end_ea:
                if ea == idaapi.BADADDR:
                    break
                if _decode_insn_at(ea) is None:
                    break
                if not _maybe_add(ea):
                    break
                ea = _next_head(ea, seg.end_ea)
                if ea == idaapi.BADADDR:
                    break

        if include_total and not more:
            more = total_count > offset + max_instructions

        rettype = None
        args: Optional[list[Argument]] = None
        stack_frame = None

        if func:
            tif = ida_typeinf.tinfo_t()
            if ida_nalt.get_tinfo(tif, func.start_ea) and tif.is_func():
                ftd = ida_typeinf.func_type_data_t()
                if tif.get_func_details(ftd):
                    rettype = str(ftd.rettype)
                    args = [
                        Argument(name=(a.name or f"arg{i}"), type=str(a.type))
                        for i, a in enumerate(ftd)
                    ]
            stack_frame = get_stack_frame_variables_internal(func.start_ea, False)

        out: DisassemblyFunction = {
            "name": func_name,
            "start_ea": hex(header_addr),
            "segment": segment_name,
            "lines": lines,
        }
        if stack_frame:
            out["stack_frame"] = stack_frame
        if rettype:
            out["return_type"] = rettype
        if args is not None:
            out["arguments"] = args

        return {
            "addr": addr,
            "asm": out,
            "instruction_count": len(lines),
            "total_instructions": total_count if include_total else None,
            "cursor": ({"next": offset + max_instructions} if more else {"done": True}),
        }
    except Exception as e:
        return {
            "addr": addr,
            "asm": None,
            "error": str(e),
            "cursor": {"done": True},
        }


# ============================================================================
# Batch Analysis & Profiling
# ============================================================================


@tool
@idasync
@tool_timeout(120.0)
def func_profile(
    queries: Annotated[
        list[FuncProfileQuery] | FuncProfileQuery | str,
        "Function profiling query (supports name/address filters + pagination)",
    ],
) -> list[FuncProfileResult]:
    """Profile functions with summary metrics and optional sampled details."""
    queries = normalize_dict_list(
        queries,
        lambda s: {
            "query": s,
            "offset": 0,
            "count": 50,
            "sort_by": "addr",
            "descending": False,
            "include_lists": False,
            "max_items": 25,
            "include_prototype": False,
        },
    )

    results: list[dict] = []
    for query in queries:
        q = str(query.get("query", "*") or "*").strip()
        filter_pattern = str(query.get("filter", "") or "")
        offset = _clamp_int(query.get("offset", 0), 0, 0, 2_000_000_000)
        count = _clamp_int(query.get("count", 50), 50, 0, 1000)
        sort_by = str(query.get("sort_by", "addr") or "addr")
        descending = bool(query.get("descending", False))
        include_lists = bool(query.get("include_lists", False))
        max_items = _clamp_int(query.get("max_items", 25), 25, 0, 1000)
        include_prototype = bool(query.get("include_prototype", False))

        # Resolve candidate function starts.
        candidates: list[dict] = []
        if q not in ("", "*"):
            start_ea, err = _resolve_function_start(q)
            if err is not None or start_ea is None:
                results.append(
                    {
                        "query": q,
                        "data": [],
                        "next_offset": None,
                        "error": err or "Failed to resolve function",
                    }
                )
                continue
            fn = idaapi.get_func(start_ea)
            if fn:
                candidates.append(
                    {
                        "start_ea": fn.start_ea,
                        "addr": hex(fn.start_ea),
                        "name": ida_funcs.get_func_name(fn.start_ea) or "<unnamed>",
                        "size_int": fn.end_ea - fn.start_ea,
                        "size": hex(fn.end_ea - fn.start_ea),
                    }
                )
        else:
            for start_ea in idautils.Functions():
                fn = idaapi.get_func(start_ea)
                if not fn:
                    continue
                candidates.append(
                    {
                        "start_ea": fn.start_ea,
                        "addr": hex(fn.start_ea),
                        "name": ida_funcs.get_func_name(fn.start_ea) or "<unnamed>",
                        "size_int": fn.end_ea - fn.start_ea,
                        "size": hex(fn.end_ea - fn.start_ea),
                    }
                )

        if filter_pattern:
            candidates = pattern_filter(candidates, filter_pattern, "name")

        if sort_by == "name":
            candidates.sort(key=lambda f: f["name"].lower(), reverse=descending)
        elif sort_by == "size":
            candidates.sort(key=lambda f: f["size_int"], reverse=descending)
        else:
            candidates.sort(key=lambda f: f["start_ea"], reverse=descending)

        page = paginate(candidates, offset, count)
        profiled: list[dict] = []
        for item in page["data"]:
            profiled.append(
                _profile_function(
                    int(item["start_ea"]),
                    include_lists=include_lists,
                    max_items=max_items,
                    include_prototype=include_prototype,
                )
            )

        for item in profiled:
            item.pop("size_int", None)

        results.append(
            {
                "query": q,
                "data": profiled,
                "next_offset": page["next_offset"],
                "error": None,
            }
        )

    return results


@tool
@idasync
@tool_timeout(120.0)
def analyze_batch(
    queries: Annotated[
        list[AnalyzeBatchQuery] | AnalyzeBatchQuery | str,
        "Comprehensive per-function analysis with selectable sections",
    ],
) -> list[AnalyzeBatchResult]:
    """Run comprehensive analysis over one or more target functions."""
    queries = normalize_dict_list(
        queries,
        lambda s: {
            "query": s,
            "include_decompile": True,
            "include_disasm": False,
            "include_xrefs": True,
            "include_callers": True,
            "include_callees": True,
            "include_strings": True,
            "include_constants": True,
            "include_basic_blocks": True,
            "include_proto": True,
            "max_disasm_insns": 300,
            "max_callers": 100,
            "max_callees": 100,
            "max_strings": 100,
            "max_constants": 200,
            "max_blocks": 500,
        },
    )

    results: list[dict] = []
    for query in queries:
        q = str(query.get("query", "") or query.get("addr", "") or "").strip()
        if not q:
            results.append(
                {
                    "query": q,
                    "addr": None,
                    "name": None,
                    "analysis": None,
                    "error": "Function query is required",
                }
            )
            continue

        start_ea, err = _resolve_function_start(q)
        if err is not None or start_ea is None:
            results.append(
                {
                    "query": q,
                    "addr": None,
                    "name": None,
                    "analysis": None,
                    "error": err or "Failed to resolve function",
                }
            )
            continue

        try:
            fn = idaapi.get_func(start_ea)
            if not fn:
                raise RuntimeError(f"Function not found: {q}")

            fn_name = ida_funcs.get_func_name(fn.start_ea) or "<unnamed>"
            size_int = fn.end_ea - fn.start_ea

            include_decompile = bool(query.get("include_decompile", True))
            include_disasm = bool(query.get("include_disasm", False))
            include_xrefs = bool(query.get("include_xrefs", True))
            include_callers = bool(query.get("include_callers", True))
            include_callees = bool(query.get("include_callees", True))
            include_strings = bool(query.get("include_strings", True))
            include_constants = bool(query.get("include_constants", True))
            include_basic_blocks = bool(query.get("include_basic_blocks", True))
            include_proto = bool(query.get("include_proto", True))

            max_disasm_insns = _clamp_int(
                query.get("max_disasm_insns", 300), 300, 0, 50_000
            )
            max_callers = _clamp_int(query.get("max_callers", 100), 100, 0, 5000)
            max_callees = _clamp_int(query.get("max_callees", 100), 100, 0, 5000)
            max_strings = _clamp_int(query.get("max_strings", 100), 100, 0, 5000)
            max_constants = _clamp_int(
                query.get("max_constants", 200), 200, 0, 10000
            )
            max_blocks = _clamp_int(query.get("max_blocks", 500), 500, 0, 10000)

            analysis: dict = {
                "size": hex(size_int),
                "prototype": None,
                "decompile": None,
                "decompile_error": None,
                "disasm": None,
                "xrefs": None,
                "callers": None,
                "caller_count": 0,
                "callers_truncated": False,
                "callees": None,
                "callee_count": 0,
                "callees_truncated": False,
                "strings": None,
                "string_ref_count": 0,
                "strings_truncated": False,
                "constants": None,
                "constant_count": 0,
                "constants_truncated": False,
                "basic_blocks": None,
                "basic_block_count": 0,
                "basic_blocks_truncated": False,
            }

            if include_proto:
                analysis["prototype"] = get_prototype(fn)

            if include_decompile:
                code = decompile_function_safe(fn.start_ea)
                analysis["decompile"] = code
                if code is None:
                    analysis["decompile_error"] = "Decompilation failed"

            if include_disasm:
                lines, disasm_truncated = _disasm_lines_limited(fn, max_disasm_insns)
                analysis["disasm"] = {
                    "lines": lines,
                    "instruction_count": len(lines),
                    "truncated": disasm_truncated,
                }

            if include_xrefs:
                xrefs = get_all_xrefs(fn.start_ea)
                xrefs_to = list(xrefs.get("to", []))
                xrefs_from = list(xrefs.get("from", []))
                xrefs_to, xto_trunc = _limit_items(xrefs_to, 200)
                xrefs_from, xfrom_trunc = _limit_items(xrefs_from, 200)
                analysis["xrefs"] = {
                    "to": xrefs_to,
                    "from": xrefs_from,
                    "to_truncated": xto_trunc,
                    "from_truncated": xfrom_trunc,
                    "to_count": len(xrefs.get("to", [])),
                    "from_count": len(xrefs.get("from", [])),
                }

            if include_callers:
                callers = get_callers(hex(fn.start_ea), limit=max_callers)
                analysis["caller_count"] = len(callers)
                analysis["callers"] = callers
                analysis["callers_truncated"] = (
                    max_callers > 0 and len(callers) >= max_callers
                )

            if include_callees:
                all_callees = get_callees(hex(fn.start_ea))
                limited_callees, callees_truncated = _limit_items(all_callees, max_callees)
                analysis["callee_count"] = len(all_callees)
                analysis["callees"] = limited_callees
                analysis["callees_truncated"] = callees_truncated

            if include_strings:
                all_strings = extract_function_strings(fn.start_ea)
                limited_strings, strings_truncated = _limit_items(all_strings, max_strings)
                analysis["string_ref_count"] = len(all_strings)
                analysis["strings"] = limited_strings
                analysis["strings_truncated"] = strings_truncated

            if include_constants:
                all_constants = extract_function_constants(fn.start_ea)
                limited_constants, constants_truncated = _limit_items(
                    all_constants, max_constants
                )
                analysis["constant_count"] = len(all_constants)
                analysis["constants"] = limited_constants
                analysis["constants_truncated"] = constants_truncated

            if include_basic_blocks:
                blocks, blocks_truncated = _collect_basic_blocks_limited(fn, max_blocks)
                analysis["basic_block_count"] = len(blocks)
                analysis["basic_blocks"] = blocks
                analysis["basic_blocks_truncated"] = blocks_truncated

            results.append(
                {
                    "query": q,
                    "addr": hex(fn.start_ea),
                    "name": fn_name,
                    "analysis": analysis,
                    "error": None,
                }
            )
        except Exception as e:
            results.append(
                {
                    "query": q,
                    "addr": hex(start_ea),
                    "name": None,
                    "analysis": None,
                    "error": str(e),
                }
            )

    return results


# ============================================================================
# Cross-Reference Analysis
# ============================================================================


@tool
@idasync
def xrefs_to(
    addrs: Annotated[list[str] | str, "Addresses to find cross-references to"],
    limit: Annotated[int, "Max xrefs per address (default: 100, max: 1000)"] = 100,
) -> list[XrefsToResult]:
    """Return xrefs to address(es), capped per target with truncation flag."""
    addrs = normalize_list_input(addrs)

    if limit <= 0 or limit > 1000:
        limit = 1000

    results = []

    for addr in addrs:
        try:
            xrefs = []
            more = False
            for xref in idautils.XrefsTo(parse_address(addr)):
                if len(xrefs) >= limit:
                    more = True
                    break
                xrefs.append(
                    Xref(
                        addr=hex(xref.frm),
                        type="code" if xref.iscode else "data",
                        fn=get_function(xref.frm, raise_error=False),
                    )
                )
            results.append({"addr": addr, "xrefs": xrefs, "more": more})
        except Exception as e:
            results.append({"addr": addr, "xrefs": None, "error": str(e)})

    return results


@tool
@idasync
def xref_query(
    queries: Annotated[
        list[XrefQuery] | XrefQuery | str,
        "Generic xref query with direction/type filters and pagination",
    ],
) -> list[XrefQueryResult]:
    """Query xrefs with direction/type filters and pagination."""
    queries = normalize_dict_list(
        queries,
        lambda s: {
            "query": s,
            "direction": "both",
            "xref_type": "any",
            "offset": 0,
            "count": 200,
            "include_fn": True,
            "dedup": True,
            "sort_by": "addr",
            "descending": False,
        },
    )

    results: list[dict] = []
    for query in queries:
        q = str(query.get("query", "")).strip()
        direction = str(query.get("direction", "both") or "both").lower()
        xref_type = str(query.get("xref_type", "any") or "any").lower()
        offset = _clamp_int(query.get("offset", 0), 0, 0, 2_000_000_000)
        count = _clamp_int(query.get("count", 200), 200, 0, 5000)
        include_fn = bool(query.get("include_fn", True))
        dedup = bool(query.get("dedup", True))
        sort_by = str(query.get("sort_by", "addr") or "addr")
        descending = bool(query.get("descending", False))

        if direction not in {"to", "from", "both"}:
            direction = "both"
        if xref_type not in {"any", "code", "data"}:
            xref_type = "any"

        try:
            if not q:
                raise ValueError("query is required")
            try:
                target = parse_address(q)
            except Exception:
                target = idaapi.get_name_ea(idaapi.BADADDR, q)
                if target == idaapi.BADADDR:
                    raise ValueError(f"Failed to resolve address/name: {q}")

            rows: list[dict] = []
            if direction in {"to", "both"}:
                for xr in idautils.XrefsTo(target, 0):
                    kind = "code" if xr.iscode else "data"
                    if xref_type != "any" and kind != xref_type:
                        continue
                    row = {
                        "direction": "to",
                        "addr": hex(xr.frm),
                        "from": hex(xr.frm),
                        "to": hex(target),
                        "type": kind,
                    }
                    if include_fn:
                        row["fn"] = get_function(xr.frm, raise_error=False)
                    rows.append(row)

            if direction in {"from", "both"}:
                for xr in idautils.XrefsFrom(target, 0):
                    kind = "code" if xr.iscode else "data"
                    if xref_type != "any" and kind != xref_type:
                        continue
                    row = {
                        "direction": "from",
                        "addr": hex(xr.to),
                        "from": hex(target),
                        "to": hex(xr.to),
                        "type": kind,
                    }
                    if include_fn:
                        row["fn"] = get_function(xr.to, raise_error=False)
                    rows.append(row)

            if dedup:
                seen = set()
                deduped = []
                for row in rows:
                    key = (row["direction"], row["from"], row["to"], row["type"])
                    if key in seen:
                        continue
                    seen.add(key)
                    deduped.append(row)
                rows = deduped

            if sort_by == "type":
                rows.sort(
                    key=lambda r: (str(r.get("type", "")), int(str(r["addr"]), 16)),
                    reverse=descending,
                )
            else:
                rows.sort(key=lambda r: int(str(r["addr"]), 16), reverse=descending)

            page = paginate(rows, offset, count)
            results.append(
                {
                    "query": q,
                    "resolved_addr": hex(target),
                    "direction": direction,
                    "xref_type": xref_type,
                    "data": page["data"],
                    "next_offset": page["next_offset"],
                    "total": len(rows),
                    "error": None,
                }
            )
        except Exception as e:
            results.append(
                {
                    "query": q,
                    "resolved_addr": None,
                    "direction": direction,
                    "xref_type": xref_type,
                    "data": [],
                    "next_offset": None,
                    "total": 0,
                    "error": str(e),
                }
            )

    return results


@tool
@idasync
def xrefs_to_field(
    queries: list[StructFieldQuery] | StructFieldQuery,
) -> list[StructFieldXrefsResult]:
    """Get cross-references to structure fields"""
    if isinstance(queries, dict):
        queries = [queries]

    results = []
    til = ida_typeinf.get_idati()
    if not til:
        return [
            {
                "struct": q.get("struct"),
                "field": q.get("field"),
                "xrefs": [],
                "error": "Failed to retrieve type library",
            }
            for q in queries
        ]

    for query in queries:
        struct_name = query.get("struct", "")
        field_name = query.get("field", "")

        try:
            tif = ida_typeinf.tinfo_t()
            if not tif.get_named_type(
                til, struct_name, ida_typeinf.BTF_STRUCT, True, False
            ):
                results.append(
                    {
                        "struct": struct_name,
                        "field": field_name,
                        "xrefs": [],
                        "error": f"Struct '{struct_name}' not found",
                    }
                )
                continue

            idx = ida_typeinf.get_udm_by_fullname(None, struct_name + "." + field_name)
            if idx == -1:
                results.append(
                    {
                        "struct": struct_name,
                        "field": field_name,
                        "xrefs": [],
                        "error": f"Field '{field_name}' not found in '{struct_name}'",
                    }
                )
                continue

            tid = tif.get_udm_tid(idx)
            if tid == ida_idaapi.BADADDR:
                results.append(
                    {
                        "struct": struct_name,
                        "field": field_name,
                        "xrefs": [],
                        "error": "Unable to get tid",
                    }
                )
                continue

            xrefs = []
            xref: ida_xref.xrefblk_t
            for xref in idautils.XrefsTo(tid):
                xrefs += [
                    Xref(
                        addr=hex(xref.frm),
                        type="code" if xref.iscode else "data",
                        fn=get_function(xref.frm, raise_error=False),
                    )
                ]
            results.append({"struct": struct_name, "field": field_name, "xrefs": xrefs})
        except Exception as e:
            results.append(
                {
                    "struct": struct_name,
                    "field": field_name,
                    "xrefs": [],
                    "error": str(e),
                }
            )

    return results


# ============================================================================
# Call Graph Analysis
# ============================================================================


@tool
@idasync
def callees(
    addrs: Annotated[list[str] | str, "Function addresses to get callees for"],
    limit: Annotated[int, "Max callees per function (default: 200, max: 500)"] = 200,
) -> list[CalleesResult]:
    """Return unique callees per function, capped by limit."""
    addrs = normalize_list_input(addrs)

    if limit <= 0 or limit > 500:
        limit = 500

    results = []

    for fn_addr in addrs:
        try:
            func_start = parse_address(fn_addr)
            func = idaapi.get_func(func_start)
            if not func:
                results.append(
                    {"addr": fn_addr, "callees": None, "error": "No function found"}
                )
                continue
            func_end = func.end_ea
            callees_dict = {}
            more = False
            current_ea = func_start
            while current_ea < func_end:
                if len(callees_dict) >= limit:
                    more = True
                    break
                insn = _decode_insn_at(current_ea)
                if insn is None:
                    next_ea = _next_head(current_ea, func_end)
                    if next_ea == idaapi.BADADDR:
                        break
                    current_ea = next_ea
                    continue
                if insn.itype in [idaapi.NN_call, idaapi.NN_callfi, idaapi.NN_callni]:
                    op0 = insn.ops[0]
                    if op0.type in (ida_ua.o_mem, ida_ua.o_near, ida_ua.o_far):
                        target = op0.addr
                    elif op0.type == ida_ua.o_imm:
                        target = op0.value
                    else:
                        target = None
                    if target is not None and target not in callees_dict:
                        func_type = (
                            "internal"
                            if idaapi.get_func(target) is not None
                            else "external"
                        )
                        func_name = ida_name.get_name(target)
                        if func_name is not None:
                            callees_dict[target] = {
                                "addr": hex(target),
                                "name": func_name,
                                "type": func_type,
                            }
                next_ea = _next_head(current_ea, func_end)
                if next_ea == idaapi.BADADDR:
                    break
                current_ea = next_ea

            results.append(
                {
                    "addr": fn_addr,
                    "callees": list(callees_dict.values()),
                    "more": more,
                }
            )
        except Exception as e:
            results.append({"addr": fn_addr, "callees": None, "error": str(e)})

    return results


# ============================================================================
# Pattern Matching & Signature Tools
# ============================================================================


@tool
@idasync
def find_bytes(
    patterns: Annotated[
        list[str] | str, "Byte patterns to search for (e.g. '48 8B ?? ??')"
    ],
    limit: Annotated[int, "Max matches per pattern (default: 1000, max: 10000)"] = 1000,
    offset: Annotated[int, "Skip first N matches (default: 0)"] = 0,
) -> list[FindBytesResult]:
    """Search byte patterns (supports ??) with offset/limit pagination."""
    patterns = normalize_list_input(patterns)

    # Enforce max limit
    if limit <= 0 or limit > 10000:
        limit = 10000

    # Build a reusable search closure based on available IDA API
    def _make_searcher(pattern: str):
        """Return a (searcher_fn, error_str|None) for the given pattern.

        searcher_fn(ea, max_ea) -> ea_t  (BADADDR if not found)
        """
        return compat.make_bytes_searcher(pattern)

    results = []
    for pattern in patterns:
        matches = []
        skipped = 0
        more = False
        try:
            searcher, build_err = _make_searcher(pattern)
            if build_err is not None:
                results.append(
                    {
                        "pattern": pattern,
                        "matches": [],
                        "n": 0,
                        "cursor": {"done": True},
                        "error": build_err,
                    }
                )
                continue

            # Search with early exit
            ea = ida_ida.inf_get_min_ea()
            max_ea = ida_ida.inf_get_max_ea()
            while ea != idaapi.BADADDR:
                ea = searcher(ea, max_ea)
                if ea == idaapi.BADADDR:
                    break
                if skipped < offset:
                    skipped += 1
                else:
                    matches.append(hex(ea))
                    if len(matches) >= limit:
                        # Check if there's more
                        next_ea = searcher(ea + 1, max_ea)
                        more = next_ea != idaapi.BADADDR
                        break
                ea += 1
        except Exception as e:
            results.append(
                {
                    "pattern": pattern,
                    "matches": [],
                    "n": 0,
                    "cursor": {"done": True},
                    "error": str(e),
                }
            )
            continue

        results.append(
            {
                "pattern": pattern,
                "matches": matches,
                "n": len(matches),
                "cursor": {"next": offset + limit} if more else {"done": True},
            }
        )
    return results


# ============================================================================
# Control Flow Analysis
# ============================================================================


@tool
@idasync
def basic_blocks(
    addrs: Annotated[list[str] | str, "Function addresses to get basic blocks for"],
    max_blocks: Annotated[
        int, "Max basic blocks per function (default: 1000, max: 10000)"
    ] = 1000,
    offset: Annotated[int, "Skip first N blocks (default: 0)"] = 0,
) -> list[BasicBlocksResult]:
    """Return function CFG blocks with offset/max_blocks pagination."""
    addrs = normalize_list_input(addrs)

    # Enforce max limit
    if max_blocks <= 0 or max_blocks > 10000:
        max_blocks = 10000

    results = []
    for fn_addr in addrs:
        try:
            ea = parse_address(fn_addr)
            func = idaapi.get_func(ea)
            if not func:
                results.append(
                    {
                        "addr": fn_addr,
                        "error": "Function not found",
                        "blocks": [],
                        "cursor": {"done": True},
                    }
                )
                continue

            flowchart = idaapi.FlowChart(func)
            all_blocks = []

            for block in flowchart:
                all_blocks.append(
                    BasicBlock(
                        start=hex(block.start_ea),
                        end=hex(block.end_ea),
                        size=block.end_ea - block.start_ea,
                        type=block.type,
                        successors=[hex(succ.start_ea) for succ in block.succs()],
                        predecessors=[hex(pred.start_ea) for pred in block.preds()],
                    )
                )

            # Apply pagination
            total_blocks = len(all_blocks)
            blocks = all_blocks[offset : offset + max_blocks]
            more = offset + max_blocks < total_blocks

            results.append(
                {
                    "addr": fn_addr,
                    "blocks": blocks,
                    "count": len(blocks),
                    "total_blocks": total_blocks,
                    "cursor": (
                        {"next": offset + max_blocks} if more else {"done": True}
                    ),
                }
            )
        except Exception as e:
            results.append(
                {
                    "addr": fn_addr,
                    "error": str(e),
                    "blocks": [],
                    "cursor": {"done": True},
                }
            )
    return results


# ============================================================================
# Search Operations
# ============================================================================


@tool
@idasync
def find(
    type: Annotated[
        str, "Search type: 'string', 'immediate', 'data_ref', or 'code_ref'"
    ],
    targets: Annotated[
        list[str | int] | str | int, "Search targets (strings, integers, or addresses)"
    ],
    limit: Annotated[int, "Max matches per target (default: 1000, max: 10000)"] = 1000,
    offset: Annotated[int, "Skip first N matches (default: 0)"] = 0,
) -> list[FindResult]:
    """Search strings/immediates/refs for targets with offset/limit pagination."""
    if not isinstance(targets, list):
        targets = [targets]

    # Enforce max limit to prevent token overflow
    if limit <= 0 or limit > 10000:
        limit = 10000

    results = []

    if type == "string":
        # Raw byte search for UTF-8 substrings across the binary
        for pattern in targets:
            pattern_str = str(pattern)
            pattern_bytes = pattern_str.encode("utf-8")
            if not pattern_bytes:
                results.append(
                    {
                        "query": pattern_str,
                        "matches": [],
                        "count": 0,
                        "cursor": {"done": True},
                        "error": "Empty pattern",
                    }
                )
                continue

            matches = []
            skipped = 0
            more = False
            try:
                ea = ida_ida.inf_get_min_ea()
                max_ea = ida_ida.inf_get_max_ea()
                mask = b"\xff" * len(pattern_bytes)
                while ea != idaapi.BADADDR:
                    ea = _raw_bin_search(ea, max_ea, pattern_bytes, mask)
                    if ea != idaapi.BADADDR:
                        if skipped < offset:
                            skipped += 1
                        else:
                            matches.append(hex(ea))
                            if len(matches) >= limit:
                                next_ea = _raw_bin_search(
                                    ea + 1, max_ea, pattern_bytes, mask
                                )
                                more = next_ea != idaapi.BADADDR
                                break
                        ea += 1
            except Exception:
                pass

            results.append(
                {
                    "query": pattern_str,
                    "matches": matches,
                    "count": len(matches),
                    "cursor": {"next": offset + limit} if more else {"done": True},
                    "error": None,
                }
            )

    elif type == "immediate":
        # Search for immediate values
        for value in targets:
            if isinstance(value, str):
                try:
                    value = int(value, 0)
                except ValueError:
                    value = 0

            matches = []
            skipped = 0
            more = False
            try:
                candidates = _value_candidates_for_immediate(value)
                if not candidates:
                    results.append(
                        {
                            "query": value,
                            "matches": [],
                            "count": 0,
                            "cursor": {"done": True},
                            "error": "Immediate out of range",
                        }
                    )
                    continue

                seen_insn = set()
                for seg_ea in idautils.Segments():
                    seg = idaapi.getseg(seg_ea)
                    if not seg or not (seg.perm & idaapi.SEGPERM_EXEC):
                        continue
                    for normalized, size, pattern_bytes in candidates:
                        ea = seg.start_ea
                        while ea != idaapi.BADADDR and ea < seg.end_ea:
                            ea = _raw_bin_search(
                                ea, seg.end_ea, pattern_bytes, b"\xff" * size
                            )
                            if ea == idaapi.BADADDR:
                                break

                            insn_start = _resolve_immediate_insn_start(
                                ea, value, seg.start_ea, normalized
                            )
                            if insn_start is not None and insn_start not in seen_insn:
                                seen_insn.add(insn_start)
                                if skipped < offset:
                                    skipped += 1
                                else:
                                    matches.append(hex(insn_start))
                                    if len(matches) >= limit:
                                        more = True
                                        break

                            ea += 1

                        if more:
                            break
                    if more:
                        break
            except Exception:
                pass

            results.append(
                {
                    "query": value,
                    "matches": matches,
                    "count": len(matches),
                    "cursor": {"next": offset + limit} if more else {"done": True},
                    "error": None,
                }
            )

    elif type == "data_ref":
        # Find all data references to targets
        for target_str in targets:
            try:
                target = parse_address(str(target_str))
                gen = (hex(xref) for xref in idautils.DataRefsTo(target))
                # Skip offset items, take limit+1 to check more
                matches = list(islice(islice(gen, offset, None), limit + 1))
                more = len(matches) > limit
                if more:
                    matches = matches[:limit]

                results.append(
                    {
                        "query": str(target_str),
                        "matches": matches,
                        "count": len(matches),
                        "cursor": (
                            {"next": offset + limit} if more else {"done": True}
                        ),
                        "error": None,
                    }
                )
            except Exception as e:
                results.append(
                    {
                        "query": str(target_str),
                        "matches": [],
                        "count": 0,
                        "cursor": {"done": True},
                        "error": str(e),
                    }
                )

    elif type == "code_ref":
        # Find all code references to targets
        for target_str in targets:
            try:
                target = parse_address(str(target_str))
                gen = (hex(xref) for xref in idautils.CodeRefsTo(target, 0))
                # Skip offset items, take limit+1 to check more
                matches = list(islice(islice(gen, offset, None), limit + 1))
                more = len(matches) > limit
                if more:
                    matches = matches[:limit]

                results.append(
                    {
                        "query": str(target_str),
                        "matches": matches,
                        "count": len(matches),
                        "cursor": (
                            {"next": offset + limit} if more else {"done": True}
                        ),
                        "error": None,
                    }
                )
            except Exception as e:
                results.append(
                    {
                        "query": str(target_str),
                        "matches": [],
                        "count": 0,
                        "cursor": {"done": True},
                        "error": str(e),
                    }
                )

    else:
        results.append(
            {
                "query": None,
                "matches": [],
                "count": 0,
                "cursor": {"done": True},
                "error": f"Unknown search type: {type}",
            }
        )

    return results


def _resolve_insn_scan_ranges(
    pattern: dict, allow_broad: bool
) -> tuple[list[tuple[int, int]], str | None]:
    func_addr = pattern.get("func")
    segment_name = pattern.get("segment")
    start_s = pattern.get("start")
    end_s = pattern.get("end")

    exec_segments = []
    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        if seg and (seg.perm & idaapi.SEGPERM_EXEC):
            exec_segments.append(seg)

    if func_addr is not None:
        try:
            ea = parse_address(func_addr)
            func = idaapi.get_func(ea)
            if not func:
                return [], f"Function not found at {func_addr}"
            return [(func.start_ea, func.end_ea)], None
        except Exception as e:
            return [], str(e)

    if segment_name is not None:
        for seg in exec_segments:
            if idaapi.get_segm_name(seg) == segment_name:
                return [(seg.start_ea, seg.end_ea)], None
        return [], f"Executable segment not found: {segment_name}"

    if start_s is not None or end_s is not None:
        if start_s is None:
            return [], "start is required when end is set"
        try:
            start_ea = parse_address(start_s)
            end_ea = parse_address(end_s) if end_s is not None else None
        except Exception as e:
            return [], str(e)

        if not exec_segments:
            return [], "No executable segments found"

        if end_ea is None:
            seg = idaapi.getseg(start_ea)
            if not seg or not (seg.perm & idaapi.SEGPERM_EXEC):
                return [], "start address not in executable segment"
            end_ea = seg.end_ea

        if end_ea <= start_ea:
            return [], "end must be greater than start"

        ranges = []
        for seg in exec_segments:
            seg_start = max(seg.start_ea, start_ea)
            seg_end = min(seg.end_ea, end_ea)
            if seg_end > seg_start:
                ranges.append((seg_start, seg_end))

        if not ranges:
            return [], "No executable ranges within start/end"

        return ranges, None

    if not allow_broad:
        return [], "Scope required: set func/segment/start/end or allow_broad=true"

    if not exec_segments:
        return [], "No executable segments found"

    return [(seg.start_ea, seg.end_ea) for seg in exec_segments], None


def _scan_insn_ranges(
    ranges: list[tuple[int, int]],
    mnem: str,
    op0_val: int | None,
    op1_val: int | None,
    op2_val: int | None,
    any_val: int | None,
    limit: int,
    offset: int,
    max_scan_insns: int,
) -> tuple[list[str], bool, int, bool, int | None]:
    matches: list[str] = []
    skipped = 0
    scanned = 0
    more = False
    truncated = False
    next_start: int | None = None

    for start_ea, end_ea in ranges:
        ea = start_ea
        while ea < end_ea:
            if scanned >= max_scan_insns:
                truncated = True
                next_start = ea
                break

            scanned += 1

            insn = _decode_insn_at(ea)
            if insn is None:
                ea = _next_head(ea, end_ea)
                if ea == idaapi.BADADDR:
                    break
                continue

            if mnem and _insn_mnem(insn) != mnem:
                ea = _next_head(ea, end_ea)
                if ea == idaapi.BADADDR:
                    break
                continue

            match = True
            if op0_val is not None and _operand_value(insn, 0) != op0_val:
                match = False
            if op1_val is not None and _operand_value(insn, 1) != op1_val:
                match = False
            if op2_val is not None and _operand_value(insn, 2) != op2_val:
                match = False

            if any_val is not None and match:
                found_any = False
                for i in range(8):
                    if _operand_type(insn, i) == ida_ua.o_void:
                        break
                    if _operand_value(insn, i) == any_val:
                        found_any = True
                        break
                if not found_any:
                    match = False

            if match:
                if skipped < offset:
                    skipped += 1
                else:
                    matches.append(hex(ea))
                    if len(matches) > limit:
                        more = True
                        matches = matches[:limit]
                        break

            ea = _next_head(ea, end_ea)
            if ea == idaapi.BADADDR:
                break

        if more or truncated:
            break

    return matches, more, scanned, truncated, next_start


@tool
@idasync
def insn_query(
    queries: Annotated[
        list[InsnPattern] | InsnPattern | str,
        "Instruction query with mnemonic/operand filters and scoped scan",
    ],
) -> list[InsnQueryResult]:
    """Query instructions with mnemonic/operand filters and scoped scans."""
    queries = normalize_dict_list(
        queries,
        lambda s: {
            "mnem": s,
            "offset": 0,
            "count": 100,
            "max_scan_insns": 200000,
            "allow_broad": False,
            "include_fn": False,
            "include_disasm": False,
        },
    )

    results: list[dict] = []
    for pattern in queries:
        mnem = str(pattern.get("mnem", "") or "").strip().lower()
        if mnem == "*":
            mnem = ""

        offset = _clamp_int(pattern.get("offset", 0), 0, 0, 2_000_000_000)
        count = _clamp_int(pattern.get("count", 100), 100, 0, 5000)
        max_scan_insns = _clamp_int(
            pattern.get("max_scan_insns", 200000), 200000, 1, 2_000_000
        )
        allow_broad = bool(pattern.get("allow_broad", False))
        include_fn = bool(pattern.get("include_fn", False))
        include_disasm = bool(pattern.get("include_disasm", False))

        summary = {
            "mnem": mnem or None,
            "op0": pattern.get("op0"),
            "op1": pattern.get("op1"),
            "op2": pattern.get("op2"),
            "op_any": pattern.get("op_any"),
            "func": pattern.get("func"),
            "segment": pattern.get("segment"),
            "start": pattern.get("start"),
            "end": pattern.get("end"),
            "offset": offset,
            "count": count,
            "max_scan_insns": max_scan_insns,
            "allow_broad": allow_broad,
        }

        try:
            op0_val = _parse_optional_int(pattern.get("op0"), "op0")
            op1_val = _parse_optional_int(pattern.get("op1"), "op1")
            op2_val = _parse_optional_int(pattern.get("op2"), "op2")
            any_val = _parse_optional_int(pattern.get("op_any"), "op_any")

            ranges, range_error = _resolve_insn_scan_ranges(pattern, allow_broad)
            if range_error:
                raise ValueError(range_error)

            addresses, more, scanned, truncated, next_start = _scan_insn_ranges(
                ranges,
                mnem,
                op0_val,
                op1_val,
                op2_val,
                any_val,
                count,
                offset,
                max_scan_insns,
            )

            rows = []
            for addr_s in addresses:
                ea = int(addr_s, 16)
                row = {"addr": addr_s}
                if include_disasm:
                    line = ida_lines.generate_disasm_line(ea, 0)
                    row["disasm"] = ida_lines.tag_remove(line) if line else ""
                if include_fn:
                    row["fn"] = get_function(ea, raise_error=False)
                rows.append(row)

            summary["op0"] = op0_val
            summary["op1"] = op1_val
            summary["op2"] = op2_val
            summary["op_any"] = any_val

            results.append(
                {
                    "query": summary,
                    "ranges": [
                        {"start": hex(start_ea), "end": hex(end_ea)}
                        for start_ea, end_ea in ranges
                    ],
                    "matches": rows,
                    "count": len(rows),
                    "cursor": {"next": offset + count} if more else {"done": True},
                    "scanned": scanned,
                    "truncated": truncated,
                    "next_start": hex(next_start) if next_start is not None else None,
                    "error": None,
                }
            )
        except Exception as e:
            results.append(
                {
                    "query": summary,
                    "ranges": [],
                    "matches": [],
                    "count": 0,
                    "cursor": {"done": True},
                    "scanned": 0,
                    "truncated": False,
                    "next_start": None,
                    "error": str(e),
                }
            )

    return results


# ============================================================================
# Export Operations
# ============================================================================


@tool
@idasync
def export_funcs(
    addrs: Annotated[list[str] | str, "Function addresses to export"],
    format: Annotated[
        str, "Export format: json (default), c_header, or prototypes"
    ] = "json",
) -> ExportFuncsJsonResult | ExportFuncsHeaderResult | ExportFuncsPrototypesResult:
    """Export function data for addresses in json/c_header/prototypes formats."""
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)
            func = idaapi.get_func(ea)
            if not func:
                results.append({"addr": addr, "error": "Function not found"})
                continue

            func_data = {
                "addr": addr,
                "name": ida_funcs.get_func_name(func.start_ea),
                "prototype": get_prototype(func),
                "size": hex(func.end_ea - func.start_ea),
                "comments": get_all_comments(ea),
            }

            if format == "json":
                func_data["asm"] = get_assembly_lines(ea)
                func_data["code"] = decompile_function_safe(ea)
                func_data["xrefs"] = get_all_xrefs(ea)

            results.append(func_data)

        except Exception as e:
            results.append({"addr": addr, "error": str(e)})

    if format == "c_header":
        # Generate C header file
        lines = ["// Auto-generated by IDA Pro MCP", ""]
        for func in results:
            if "prototype" in func and func["prototype"]:
                lines.append(f"{func['prototype']};")
        return {"format": "c_header", "content": "\n".join(lines)}

    elif format == "prototypes":
        # Just prototypes
        prototypes = []
        for func in results:
            if "prototype" in func and func["prototype"]:
                prototypes.append(
                    {"name": func.get("name"), "prototype": func["prototype"]}
                )
        return {"format": "prototypes", "functions": prototypes}

    return {"format": "json", "functions": results}


# ============================================================================
# Graph Operations
# ============================================================================


@tool
@idasync
def callgraph(
    roots: Annotated[
        list[str] | str, "Root function addresses to start call graph traversal from"
    ],
    max_depth: Annotated[int, "Maximum depth for call graph traversal"] = 5,
    max_nodes: Annotated[
        int, "Max nodes across the graph (default: 1000, max: 100000)"
    ] = 1000,
    max_edges: Annotated[
        int, "Max edges across the graph (default: 5000, max: 200000)"
    ] = 5000,
    max_edges_per_func: Annotated[
        int, "Max edges per function (default: 200, max: 5000)"
    ] = 200,
) -> list[CallGraphResult]:
    """Build bounded callgraph from roots with depth/node/edge limits."""
    roots = normalize_list_input(roots)
    if max_depth < 0:
        max_depth = 0
    if max_nodes <= 0 or max_nodes > 100000:
        max_nodes = 100000
    if max_edges <= 0 or max_edges > 200000:
        max_edges = 200000
    if max_edges_per_func <= 0 or max_edges_per_func > 5000:
        max_edges_per_func = 5000
    results = []

    for root in roots:
        try:
            ea = parse_address(root)
            func = idaapi.get_func(ea)
            if not func:
                results.append(
                    {
                        "root": root,
                        "error": "Function not found",
                        "nodes": [],
                        "edges": [],
                    }
                )
                continue

            nodes = {}
            edges = []
            visited = set()
            truncated = False
            per_func_capped = False
            limit_reason = None

            def hit_limit(reason: str):
                nonlocal truncated, limit_reason
                truncated = True
                limit_reason = reason

            def traverse(addr, depth):
                nonlocal per_func_capped
                if truncated:
                    return
                if depth > max_depth or addr in visited:
                    return
                if len(nodes) >= max_nodes:
                    hit_limit("nodes")
                    return
                visited.add(addr)

                f = idaapi.get_func(addr)
                if not f:
                    return

                func_name = ida_funcs.get_func_name(f.start_ea)
                nodes[hex(addr)] = {
                    "addr": hex(addr),
                    "name": func_name,
                    "depth": depth,
                }

                # Get callees
                edges_added = 0
                for item_ea in idautils.FuncItems(f.start_ea):
                    if truncated:
                        break
                    for xref in idautils.CodeRefsFrom(item_ea, 0):
                        if truncated:
                            break
                        if edges_added >= max_edges_per_func:
                            per_func_capped = True
                            break
                        callee_func = idaapi.get_func(xref)
                        if callee_func:
                            if len(edges) >= max_edges:
                                hit_limit("edges")
                                break
                            edges.append(
                                {
                                    "from": hex(addr),
                                    "to": hex(callee_func.start_ea),
                                    "type": "call",
                                }
                            )
                            edges_added += 1
                            traverse(callee_func.start_ea, depth + 1)
                    if edges_added >= max_edges_per_func:
                        break

            traverse(ea, 0)

            results.append(
                {
                    "root": root,
                    "nodes": list(nodes.values()),
                    "edges": edges,
                    "max_depth": max_depth,
                    "truncated": truncated,
                    "limit_reason": limit_reason,
                    "max_nodes": max_nodes,
                    "max_edges": max_edges,
                    "max_edges_per_func": max_edges_per_func,
                    "per_func_capped": per_func_capped,
                }
            )

        except Exception as e:
            results.append({"root": root, "error": str(e), "nodes": [], "edges": []})

    return results
