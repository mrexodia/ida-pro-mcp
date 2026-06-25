import struct
from itertools import islice
from typing import Annotated, Any, NotRequired, Optional, TypedDict

import ida_bytes
import ida_funcs
import ida_ida
import ida_idaapi
import ida_kernwin
import ida_lines
import ida_nalt
import ida_name
import ida_typeinf
import ida_ua
import ida_xref
import idaapi
import idautils

from ._kernel import compat
from ._kernel.errors import InvalidArgumentError
from ._kernel.rpc import safety, title, tool
from ._kernel.sync import idasync, tool_timeout
from ._kernel.utils import (
    parse_address,
    get_cached_cfunc,
    iter_func_call_edges,
    normalize_list_input,
    normalize_dict_list,
    get_function,
    get_prototype,
    paginate,
    pattern_filter,
    get_stack_frame_variables_internal,
    decompile_function_safe,
    compact_whitespace,
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
    Ref,
    Xref,
    BasicBlock,
    StructFieldQuery,
    XrefQuery,
    InsnPattern,
    FuncProfileQuery,
    AnalyzeBatchQuery,
)


class DecompileResult(TypedDict):
    addr: str
    code: str | None
    refs: NotRequired[list[Ref]]
    error: NotRequired[str]


class ResultCursor(TypedDict, total=False):
    next: int
    done: bool
    cancelled: bool


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
    target: str
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
    target: str
    addr: str | None
    name: str | None
    analysis: AnalyzeBatchDetails | None
    error: str | None


class XrefsToResult(TypedDict, total=False):
    addr: str
    xrefs: list[Xref] | None
    more: bool
    xref_count: int
    message: str
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
    target: str
    resolved_addr: str | None
    direction: str
    xref_type: str
    data: list[XrefQueryRow]
    next_offset: int | None
    total: int
    message: str
    error: str | None


class StructFieldXrefsResult(TypedDict, total=False):
    struct: str
    field: str
    xrefs: list[Xref]
    message: str
    error: str


class CalleeResultItem(TypedDict):
    addr: str
    name: str
    type: str


class CalleesResult(TypedDict, total=False):
    addr: str
    callees: list[CalleeResultItem] | None
    more: bool
    has_indirect: bool
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


class EaToPseudocodeResult(TypedDict, total=False):
    addr: str
    func: str | None
    line_no: int | None
    line: str | None
    line_eas: list[str]
    error: str
    truncated: bool


class PseudocodeLineToEasResult(TypedDict, total=False):
    func: str
    line_no: int
    line: str | None
    eas: list[str]
    error: str
    truncated: bool


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
    decompile_error: str | None
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


def _collect_line_comments(ea: int) -> list[str]:
    out: list[str] = []
    i = 0
    while True:
        line = ida_lines.get_extra_cmt(ea, ida_lines.E_PREV + i)
        if line is None:
            break
        out.append(ida_lines.tag_remove(line))
        i += 1
    cmt = ida_bytes.get_cmt(ea, False)
    if cmt:
        out.append(cmt)
    rcmt = ida_bytes.get_cmt(ea, True)
    if rcmt and rcmt != cmt:
        out.append(rcmt)
    i = 0
    while True:
        line = ida_lines.get_extra_cmt(ea, ida_lines.E_NEXT + i)
        if line is None:
            break
        out.append(ida_lines.tag_remove(line))
        i += 1
    return out


def _resolve_ref_name(ea: int) -> str:
    name = ida_name.get_ea_name(ea)
    if name:
        return name
    func = idaapi.get_func(ea)
    if func and func.start_ea == ea:
        return ida_funcs.get_func_name(ea) or ""
    return ""


_STR_CODECS = {0: "utf-8", 1: "utf-16-le", 2: "utf-32-le"}


def _resolve_ref(ea: int) -> dict | None:
    name = _resolve_ref_name(ea)
    if not name:
        return None
    info: dict = {"addr": hex(ea), "name": name}
    flags = ida_bytes.get_flags(ea)
    if ida_bytes.is_strlit(flags):
        strtype = ida_nalt.get_str_type(ea)
        if strtype is None or strtype < 0:
            strtype = ida_nalt.STRTYPE_C
        raw = ida_bytes.get_strlit_contents(ea, -1, strtype)
        if raw:
            codec = _STR_CODECS.get(strtype & 3, "utf-8")
            try:
                info["string"] = raw.decode(codec, errors="replace")
            except Exception:
                pass
    return info


def _collect_decompile_refs(cfunc) -> list[dict]:
    import ida_hexrays

    seen: set[int] = set()
    refs: list[dict] = []

    class _Visitor(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)

        def visit_expr(self, e):
            if e.op == ida_hexrays.cot_obj:
                ea = e.obj_ea
                if ea != idaapi.BADADDR and ea not in seen:
                    seen.add(ea)
                    info = _resolve_ref(ea)
                    if info:
                        refs.append(info)
            return 0

    _Visitor().apply_to(cfunc.body, None)
    return refs


def _collect_line_refs(ea: int) -> list[dict]:
    seen: set[int] = set()
    refs: list[dict] = []
    for ref_ea in idautils.CodeRefsFrom(ea, False):
        if ref_ea == idaapi.BADADDR or ref_ea in seen:
            continue
        seen.add(ref_ea)
        info = _resolve_ref(ref_ea)
        if info:
            refs.append(info)
    for ref_ea in idautils.DataRefsFrom(ea):
        if ref_ea == idaapi.BADADDR or ref_ea in seen:
            continue
        seen.add(ref_ea)
        info = _resolve_ref(ref_ea)
        if info:
            refs.append(info)
    return refs


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
        lines.append(f"{item_ea:x}  {compact_whitespace(instruction)}")
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


@safety("READ")
@title("Decompile Function To Pseudocode")
@tool
@idasync
@tool_timeout(90.0)
def decompile(
    addr: Annotated[str, "Function address (hex like '0x401000') or symbol name to decompile"],
    include_addresses: Annotated[
        bool,
        "Append /*0xNNNN*/ line-address markers to each line (default: true). Set false to save tokens when you only need the logic, not addresses to pivot on.",
    ] = True,
) -> DecompileResult:
    """WHAT: Runs the Hex-Rays decompiler on one function and returns its C-like pseudocode, plus the global/string objects it references (`refs`).

WHEN TO USE: The primary way to understand what a single function does. Reach for this before `disasm` unless you specifically need raw instructions or a function the decompiler refuses.

RETURNS: {addr, code, refs?, error?}. `code` is null with `error` set when decompilation fails (no Hex-Rays license, undefined function, or a decompiler error). `refs` (when present) lists referenced named objects/strings so you can pivot with `xrefs_to`/`decompile` without re-parsing the text.

PRO-TIP: Keep `include_addresses=true` while exploring so you can copy a `/*0xNNNN*/` marker straight into `disasm`/`xrefs_to`; flip it off only for a final clean read. PITFALL: this takes one address, not a list -- call it once per function."""
    try:
        start = parse_address(addr)
        # SINGLE-PASS: decompile once via the per-IDB cfunc cache, then derive
        # BOTH the pseudocode text and the referenced-object `refs` from that one
        # cfunc. decompile_function_safe() is backed by the same cache (keyed on
        # the enclosing function's start_ea), so the text render reuses this exact
        # decompilation rather than triggering a second Hex-Rays pass.
        cfunc, cf_err = get_cached_cfunc(start)
        if cfunc is None:
            return {
                "addr": addr,
                "code": None,
                "error": cf_err or "Decompilation failed",
            }
        code, err = decompile_function_safe(start, include_addresses=include_addresses)
        if code is None:
            return {"addr": addr, "code": None, "error": err or "Decompilation failed"}
        result: DecompileResult = {"addr": addr, "code": code}
        try:
            refs = _collect_decompile_refs(cfunc)
            if refs:
                result["refs"] = refs
        except Exception:
            pass
        return result
    except Exception as e:
        return {"addr": addr, "code": None, "error": str(e)}


@safety("READ")
@title("Disassemble To Annotated Instructions")
@tool
@idasync
@tool_timeout(90.0)
def disasm(
    addr: Annotated[str, "Function address (hex like '0x401000') or symbol name. If it lands inside a function, items are walked from here to the function end; otherwise instructions are decoded sequentially to the end of the segment."],
    max_instructions: Annotated[
        int, "Max instructions to return in this page (default: 5000, clamped to 1..50000). Use with `offset` to page large functions."
    ] = 5000,
    offset: Annotated[int, "Skip the first N instructions before collecting (default: 0). Feed the cursor's `next` here to continue."] = 0,
    include_total: Annotated[
        bool, "Also count every instruction past the page to populate `total_instructions` (default: false; costs a full walk)."
    ] = False,
) -> DisasmResult:
    """WHAT: Disassembles a function (or a raw run of code) into per-line records carrying the address, instruction text, any label, inline comments, and resolved cross-references.

WHEN TO USE: When you need exact instruction-level detail -- operands, addresses to set breakpoints on, or a function Hex-Rays cannot decompile. For understanding logic, prefer `decompile`.

RETURNS: {addr, asm:{name,start_ea,segment,lines[],stack_frame?,return_type?,arguments?}, instruction_count, total_instructions?, cursor}. `cursor` is {next:N} when more remain or {done:true} at the end.

PRO-TIP: The richer per-line `comments`/`refs`/`label` fields make this strictly more informative than plain text -- use the `refs` to pivot without a second lookup. PITFALL: leave `include_total=false` while paging hot; it forces a full second pass just to compute the grand total."""

    # Enforce max limit
    if max_instructions <= 0 or max_instructions > 50000:
        max_instructions = 50000
    if offset < 0:
        offset = 0

    try:
        start = parse_address(addr)
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
                entry: dict = {
                    "addr": f"{ea:x}",
                    "instruction": compact_whitespace(instruction),
                }
                name = ida_name.get_ea_name(ea)
                if name:
                    entry["label"] = name
                comments = _collect_line_comments(ea)
                if comments:
                    entry["comments"] = comments
                refs = _collect_line_refs(ea)
                if refs:
                    entry["refs"] = refs
                lines.append(entry)
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


@safety("READ")
@title("Profile Functions With Metrics")
@tool
@idasync
@tool_timeout(120.0)
def func_profile(
    queries: Annotated[
        list[FuncProfileQuery] | FuncProfileQuery,
        "One or more profile queries. Each: {addr:'*'|name|hex, filter?:wildcard-on-name, offset?, count?:<=1000, sort_by?:'addr'|'name'|'size', descending?, include_lists?, max_items?, include_prototype?}. `addr='*'` profiles every function in the database.",
    ],
) -> list[FuncProfileResult]:
    """WHAT: Computes per-function summary metrics -- size, instruction/basic-block counts, caller/callee/string/constant counts, has_type, optional prototype -- across many functions at once, with filtering, sorting, and pagination.

WHEN TO USE: To triage or rank a whole binary or a name-filtered subset (e.g. "biggest functions", "functions touching the most strings") before deep-diving individual ones with `decompile`/`analyze_batch`.

RETURNS: list of {target, data:[FuncProfileItem...], next_offset, error}. With `include_lists=true` each item also carries the actual caller/callee/string/constant lists (each capped at `max_items` with a *_truncated flag); leave it false for pure counts.

PRO-TIP: Use `addr='*'` + `sort_by='size'` + `descending=true` to surface the heavyweight functions first. PITFALL: `include_lists=true` over `addr='*'` is expensive -- narrow with `filter` or page with `count`/`offset`."""
    queries = normalize_dict_list(queries)

    results: list[dict] = []
    for query in queries:
        q = str(query.get("addr", "*") or "*").strip()
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
                        "target": q,
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
                "target": q,
                "data": profiled,
                "next_offset": page["next_offset"],
                "error": None,
            }
        )

    return results


@safety("READ")
@title("Deep Analyze Functions (All Sections)")
@tool
@idasync
@tool_timeout(120.0)
def analyze_batch(
    queries: Annotated[
        list[AnalyzeBatchQuery] | AnalyzeBatchQuery,
        "One or more analysis queries. Each: {addr:name|hex (required)} plus toggles include_decompile/include_disasm/include_xrefs/include_callers/include_callees/include_strings/include_constants/include_basic_blocks/include_proto and the matching max_* caps. Every section except disasm defaults ON.",
    ],
) -> list[AnalyzeBatchResult]:
    """WHAT: One-shot, all-in-one read of a function -- prototype, decompilation, optional disassembly, xrefs to/from, callers, callees, referenced strings, constants, and basic blocks -- assembled per target with truncation flags.

WHEN TO USE: The fastest way to fully understand a function (or a handful) without firing `decompile`, `xrefs_to`, `callees`, `callgraph` separately. Ideal as the first deep call once `func_profile` or a search has pointed you at a target.

RETURNS: list of {target, addr, name, analysis:{...}, error}. Each section is null when its include_* toggle is off; lists carry *_count plus *_truncated so you know when a max_* cap clipped them.

PRO-TIP: Turn OFF sections you do not need (e.g. include_disasm stays off by default; set include_basic_blocks=false) to slash token cost on large functions. PITFALL: `include_decompile` needs Hex-Rays -- a missing license shows up as `analysis.decompile_error`, not a top-level error."""
    queries = normalize_dict_list(queries)

    results: list[dict] = []
    for query in queries:
        q = str(query.get("addr", "") or "").strip()
        if not q:
            results.append(
                {
                    "target": q,
                    "addr": None,
                    "name": None,
                    "analysis": None,
                    "error": "addr is required",
                }
            )
            continue

        start_ea, err = _resolve_function_start(q)
        if err is not None or start_ea is None:
            results.append(
                {
                    "target": q,
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
                code, err = decompile_function_safe(fn.start_ea)
                analysis["decompile"] = code
                if code is None:
                    analysis["decompile_error"] = err or "Decompilation failed"

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
                if not xrefs.get("to") and not xrefs.get("from"):
                    analysis["xrefs"]["message"] = "No cross-references to this address"

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
                    "target": q,
                    "addr": hex(fn.start_ea),
                    "name": fn_name,
                    "analysis": analysis,
                    "error": None,
                }
            )
        except Exception as e:
            results.append(
                {
                    "target": q,
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


@safety("READ")
@title("Find Cross-References To Addresses")
@tool
@idasync
def xrefs_to(
    addrs: Annotated[
        list[str] | str, "One address/name or a list of them to find inbound cross-references to (e.g. '0x11a9', 'check_pw', 'main'). Resolves names and hex."],
    limit: Annotated[int, "Max xrefs returned per target (default: 100, clamped to 1..1000)."] = 100,
) -> list[XrefsToResult]:
    """WHAT: Lists every location that references the given address(es) -- who calls a function, who reads/writes a global, who jumps to a label -- each tagged code/data and resolved to its enclosing function.

WHEN TO USE: The go-to "who uses this?" lookup -- find callers of a function, all readers of a global/string, or usages of a constant address. For richer filtering/pagination use `xref_query`; for struct fields use `xrefs_to_field`.

RETURNS: list of {addr, xrefs:[{addr,type,fn}], more, xref_count} (or {addr, xrefs:null, error}). `more=true` means the per-target `limit` clipped results; raise `limit` or switch to `xref_query` to page.

PRO-TIP: Pass several targets at once to fan out usage discovery in a single call. PITFALL: this is inbound-only (refs TO the target). For outbound refs (what a function references) use `xref_query` with direction='from' or read `decompile`/`disasm` refs."""
    addrs = normalize_list_input(addrs)

    if limit <= 0 or limit > 1000:
        limit = 1000

    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)
            if not ida_bytes.is_mapped(ea):
                results.append(
                    {
                        "addr": addr,
                        "xrefs": None,
                        "error": f"Address not mapped: {addr}",
                    }
                )
                continue

            xrefs = []
            more = False
            for xref in idautils.XrefsTo(ea):
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
            entry: XrefsToResult = {
                "addr": addr,
                "xrefs": xrefs,
                "more": more,
                "xref_count": len(xrefs),
            }
            if not xrefs:
                entry["message"] = "No cross-references to this address"
            results.append(entry)
        except Exception as e:
            results.append({"addr": addr, "xrefs": None, "error": str(e)})

    return results


@safety("READ")
@title("Query Cross-References (Filtered)")
@tool
@idasync
def xref_query(
    queries: Annotated[
        list[XrefQuery] | XrefQuery,
        "One or more xref queries. Each: {addr:name|hex (required), direction?:'to'|'from'|'both', xref_type?:'any'|'code'|'data', offset?, count?:<=5000, include_fn?, dedup?, sort_by?:'addr'|'type', descending?}.",
    ],
) -> list[XrefQueryResult]:
    """WHAT: The full-featured cross-reference query -- inbound and/or outbound refs for an address, filtered by code/data, deduplicated, sorted, and paginated.

WHEN TO USE: When the simple `xrefs_to` is not enough: you want OUTBOUND refs (direction='from'), both directions at once, only data vs only code refs, sorting, or paging through a hot symbol with thousands of references.

RETURNS: list of {target, resolved_addr, direction, xref_type, data:[{direction,addr,from,to,type,fn?}], next_offset, total, error}. `next_offset` is non-null when more rows remain -- feed it back as `offset`.

PRO-TIP: direction='from' turns this into "what does this function reference" without decompiling. PITFALL: `total` is the count after dedup/filter for the whole result, not just the returned page -- page with `offset`/`count` rather than cranking `count` to the max."""
    queries = normalize_dict_list(queries)

    results: list[dict] = []
    for query in queries:
        q = str(query.get("addr", "")).strip()
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
                raise ValueError("addr is required")
            try:
                target = parse_address(q)
            except Exception:
                target = idaapi.get_name_ea(idaapi.BADADDR, q)
                if target == idaapi.BADADDR:
                    raise ValueError(f"Failed to resolve address/name: {q}")

            if not ida_bytes.is_mapped(target):
                raise ValueError(f"Address not mapped: {q}")

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
            page_result: XrefQueryResult = {
                "target": q,
                "resolved_addr": hex(target),
                "direction": direction,
                "xref_type": xref_type,
                "data": page["data"],
                "next_offset": page["next_offset"],
                "total": len(rows),
                "error": None,
            }
            if len(rows) == 0:
                page_result["message"] = "No cross-references to this address"
            results.append(page_result)
        except Exception as e:
            results.append(
                {
                    "target": q,
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


@safety("READ")
@title("Find Cross-References To Struct Field")
@tool
@idasync
def xrefs_to_field(
    queries: Annotated[
        list[StructFieldQuery] | StructFieldQuery,
        "One or more {struct:'TypeName', field:'memberName'} pairs naming a struct member to find references to. The struct must already exist in the IDB type library.",
    ],
) -> list[StructFieldXrefsResult]:
    """WHAT: Lists every code/data location that references a specific structure member, by resolving the member's type-id (tid) and walking its xrefs.

WHEN TO USE: After a struct is recovered/declared, to find where one field is actually read or written -- e.g. which functions touch `Packet.opcode` or `Actor.hp`. This is field-granular; `xrefs_to` only works on addresses.

RETURNS: list of {struct, field, xrefs:[{addr,type,fn}], message?, error?}. `message` ("No cross-references...") appears when the field exists but is unreferenced; `error` when the struct/field/type-library cannot be resolved.

PRO-TIP: Pair with `read_struct`/`type_inspect` to confirm the member name first -- the lookup is exact on `struct.field`. PITFALL: only members IDA has applied as offsets in code produce xrefs; a field never accessed via the struct type returns empty even if the raw address is used elsewhere."""
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
            field_result: StructFieldXrefsResult = {
                "struct": struct_name,
                "field": field_name,
                "xrefs": xrefs,
            }
            if not xrefs:
                field_result["message"] = "No cross-references to this struct field"
            results.append(field_result)
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


@safety("READ")
@title("List Functions Called By Target")
@tool
@idasync
def callees(
    addrs: Annotated[list[str] | str, "One function address/name or a list (e.g. '0x123e', 'main') whose call targets you want."],
    limit: Annotated[int, "Max unique callees returned per function (default: 200, clamped to 1..500)."] = 200,
) -> list[CalleesResult]:
    """WHAT: Scans a function's instructions for call sites and returns the unique set of targets it calls, each tagged 'internal' (a known function in the IDB) or 'external' (import/thunk).

WHEN TO USE: To see a single function's immediate outgoing calls -- its direct dependencies. For multi-level/depth traversal use `callgraph`; for the reverse (who calls this) use `xrefs_to`.

RETURNS: list of {addr, callees:[{addr,name,type}], more} (or {addr, callees:null, error}). `more=true` means the `limit` clipped the set.

PRO-TIP: The 'external' tag quickly surfaces which API/imports a function leans on (e.g. recv/decrypt). PITFALL: only direct, statically-resolvable call targets are found -- indirect calls through a register/vtable will not appear; recover those via `decompile` or `analyze_batch`."""
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

            # Derive call edges from the shared chunk/tailcall/switch-aware
            # primitive so `callees` agrees exactly with api_graph's traversal
            # (same source of truth, transpose of `callers`). This picks up
            # tailcalls and resolved jump-table targets that the old per-insn
            # NN_call scan missed, and surfaces unresolved indirect sites.
            callees_dict: dict[int, dict] = {}
            indirect_seen = False
            more = False
            for edge in iter_func_call_edges(func_start, "out"):
                if len(callees_dict) >= limit:
                    more = True
                    break
                if edge.get("indirect") or edge.get("to") is None:
                    # Unresolved indirect/virtual callsite: tag once so callers
                    # know indirect targets exist without a per-site explosion.
                    indirect_seen = True
                    continue
                target = int(edge["to"])
                if target in callees_dict:
                    continue
                func_name = edge.get("target_name") or ida_name.get_name(target)
                if not func_name:
                    continue
                func_type = (
                    "internal"
                    if idaapi.get_func(target) is not None
                    else "external"
                )
                callees_dict[target] = {
                    "addr": hex(target),
                    "name": func_name,
                    "type": func_type,
                }

            entry: dict = {
                "addr": fn_addr,
                "callees": list(callees_dict.values()),
                "more": more,
            }
            if indirect_seen:
                entry["has_indirect"] = True
            results.append(entry)
        except Exception as e:
            results.append({"addr": fn_addr, "callees": None, "error": str(e)})

    return results


# ============================================================================
# Pattern Matching & Signature Tools
# ============================================================================


@safety("READ")
@title("Search Binary For Byte Pattern")
@tool
@idasync
def find_bytes(
    patterns: Annotated[
        list[str] | str, "One or more space-separated hex byte patterns; '??' is a wildcard byte (e.g. '48 8B ?? ??', 'E8 ?? ?? ?? ??'). Searches the whole address range min_ea..max_ea."
    ],
    limit: Annotated[int, "Max matches per pattern (default: 1000, clamped to 1..10000)."] = 1000,
    offset: Annotated[int, "Skip the first N matches before collecting (default: 0). Feed the cursor's `next` here to continue."] = 0,
) -> list[FindBytesResult]:
    """WHAT: Byte-signature search across the entire binary with masked-wildcard support, returning the address of each match with offset/limit pagination.

WHEN TO USE: To locate code/data by a known byte signature -- a call sequence, a prologue, a magic constant, or a relocatable pattern where some bytes vary ('??'). For instruction-semantic matching (mnemonic + operand) use `insn_query`; for values/strings/refs use `find`.

RETURNS: list of {pattern, matches:[hexaddr...], n, cursor, error?}. `cursor` is {next:N} for more, {done:true} when exhausted, or {next:N, cancelled:true} if a deadline interrupted the scan (partial results -- resume from `next`).

PRO-TIP: Mask out displacement/immediate bytes with '??' to make a signature survive relocation/recompiles. PITFALL: a `cancelled` cursor means the scan was cut short, not finished -- do not treat the result as the complete match set; re-issue from the cursor."""
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

        if ida_kernwin.user_cancelled():
            # Deadline fired set_cancelled() while ida_bytes.bin_search was
            # running; it bailed with BADADDR. Surface partial results with
            # a cancelled marker rather than claiming we finished the scan.
            cursor: ResultCursor = {"next": offset + len(matches), "cancelled": True}
        elif more:
            cursor = {"next": offset + limit}
        else:
            cursor = {"done": True}
        results.append(
            {
                "pattern": pattern,
                "matches": matches,
                "n": len(matches),
                "cursor": cursor,
            }
        )
    return results


# ============================================================================
# Control Flow Analysis
# ============================================================================


# Maximum pseudocode lines we will scan/index when bridging ea<->line. Bounds
# the token/work cost on pathologically large functions; mapping degrades to a
# `truncated` flag past this rather than fanning out unboundedly.
_PSEUDO_LINE_BUDGET = 4000


# Readable names for IDA's fc_block_type_t (FlowChart block.type) values. Built
# lazily from the live ida_gdl constants so it tracks the running SDK rather than
# hard-coding integers that drift across versions.
_BLOCK_TYPE_NAMES: dict[int, str] | None = None


def _block_type_name(bt: int) -> str:
    """Resolve a FlowChart block.type integer to a readable fc_block_type_t name
    (e.g. 'NORMAL', 'RET', 'CNDJMP', 'INDJUMP'), falling back to the raw int."""
    global _BLOCK_TYPE_NAMES
    if _BLOCK_TYPE_NAMES is None:
        names: dict[int, str] = {}
        try:
            import ida_gdl
            for attr in dir(ida_gdl):
                if attr.startswith("fcb_"):
                    val = getattr(ida_gdl, attr)
                    if isinstance(val, int):
                        # 'fcb_normal' -> 'NORMAL'
                        names.setdefault(val, attr[len("fcb_"):].upper())
        except Exception:
            names = {}
        _BLOCK_TYPE_NAMES = names
    return _BLOCK_TYPE_NAMES.get(bt, f"TYPE_{bt}")


def _build_line_ea_index(cfunc) -> tuple[dict[int, list[int]], dict[int, int], bool]:
    """Walk a decompiled function's rendered pseudocode once and build a bounded
    bidirectional map between source line numbers and instruction addresses.

    Returns (line_to_eas, ea_to_line, truncated):
      - line_to_eas: {line_no -> sorted [ea, ...]} of every distinct address the
        decompiler attributes to that line (via the cfunc eamap / boundaries).
      - ea_to_line: {ea -> line_no} inverse (first/lowest line wins per ea).
      - truncated: True if the function exceeded `_PSEUDO_LINE_BUDGET` lines and
        the index is partial.

    Strategy: the eamap (`cfunc.get_eamap()`) maps each ea to the ctree items it
    drives; each item carries an `.ea`. We render the pseudocode (`get_pseudocode`)
    and, per line, recover the representative item via `get_line_item` to learn
    the line's address, then attach every eamap ea whose nearest item ea falls on
    that line. This avoids a second decompile and stays O(lines)."""
    import ida_hexrays
    import ida_kernwin

    line_to_eas: dict[int, set[int]] = {}
    ea_to_line: dict[int, int] = {}
    truncated = False

    # eamap: ea -> [citem_t, ...]; invert to item-ea -> source ea so we can map
    # the per-line representative item back onto concrete instruction addresses.
    item_ea_to_eas: dict[int, set[int]] = {}
    try:
        eamap = cfunc.get_eamap()
        for src_ea, items in eamap.items():
            for it in items:
                iea = getattr(it, "ea", idaapi.BADADDR)
                if iea != idaapi.BADADDR:
                    item_ea_to_eas.setdefault(iea, set()).add(src_ea)
    except Exception:
        item_ea_to_eas = {}

    sv = cfunc.get_pseudocode()
    for idx, sl in enumerate(sv):
        if idx >= _PSEUDO_LINE_BUDGET:
            truncated = True
            break
        sl: ida_kernwin.simpleline_t
        _head = ida_hexrays.ctree_item_t()
        item = ida_hexrays.ctree_item_t()
        _tail = ida_hexrays.ctree_item_t()
        if not cfunc.get_line_item(sl.line, 0, False, _head, item, _tail):
            continue
        # The representative item's dstr() is "<hexea>: <expr>" when it carries
        # an address; that hexea is this line's anchor address.
        anchor_ea: int | None = None
        try:
            dstr = item.dstr()
            if dstr:
                ds = dstr.split(": ")
                if len(ds) == 2:
                    anchor_ea = int(ds[0], 16)
        except Exception:
            anchor_ea = None
        if anchor_ea is None:
            continue
        eas = line_to_eas.setdefault(idx, set())
        eas.add(anchor_ea)
        # Pull in every concrete ea the eamap attributes to this anchor item so
        # a single source line can expand to all its underlying instructions.
        for extra in item_ea_to_eas.get(anchor_ea, ()):  # type: ignore[arg-type]
            eas.add(extra)
        for e in eas:
            # First (lowest) line wins for a given ea -> stable inverse mapping.
            if e not in ea_to_line or idx < ea_to_line[e]:
                ea_to_line[e] = idx

    sorted_map: dict[int, list[int]] = {
        ln: sorted(s) for ln, s in line_to_eas.items()
    }
    return sorted_map, ea_to_line, truncated


@safety("READ")
@title("Map Address To Pseudocode Line")
@tool
@idasync
@tool_timeout(90.0)
def map_ea_to_pseudocode(
    addr: Annotated[str, "Instruction address (hex like '0x401037') or a symbol name inside a function. The enclosing function is decompiled and the line covering this address is returned."],
) -> EaToPseudocodeResult:
    """WHAT: Pivots from a raw instruction address to the decompiled pseudocode line it belongs to, using the Hex-Rays eamap/boundaries, so you can jump from a disasm/xref hit straight into the C-like view.

WHEN TO USE: After `disasm`, `xrefs_to`, or `find` hands you an address and you want to see where it lands in the pseudocode without eyeballing `/*0xNNNN*/` markers. The inverse of `map_pseudocode_line_to_eas`.

RETURNS: {addr, func, line_no, line, line_eas[], truncated?, error?}. `line_no` is 0-based into the function's pseudocode (matching the decompiler's own line indexing); `line` is the rendered text of that line; `line_eas` are every address attributed to that same line. `error` is set when the address is outside a function or Hex-Rays is unavailable.

PRO-TIP: Feed the returned `line_no` back into `map_pseudocode_line_to_eas` to get the full set of instructions for that line, or use `line_eas` directly. PITFALL: an exact address may sit between two lines (compiler scheduling); the nearest enclosing line is returned, and `truncated=true` means the function exceeded the line budget so a high line may be unmapped."""
    try:
        target = parse_address(addr)
        func = idaapi.get_func(target)
        if not func:
            return {"addr": addr, "func": None, "line_no": None, "line": None,
                    "line_eas": [], "error": "Address is not inside a function"}
        cfunc, cf_err = get_cached_cfunc(func.start_ea)
        if cfunc is None:
            return {"addr": addr, "func": ida_funcs.get_func_name(func.start_ea),
                    "line_no": None, "line": None, "line_eas": [],
                    "error": cf_err or "Decompilation failed"}

        line_to_eas, ea_to_line, truncated = _build_line_ea_index(cfunc)
        func_name = ida_funcs.get_func_name(func.start_ea)

        line_no = ea_to_line.get(target)
        if line_no is None:
            # No exact item carries this ea (e.g. mid-instruction or a prologue
            # ea with no ctree item). Fall back to the nearest line whose ea set
            # has the closest lower-or-equal anchor.
            best_line: int | None = None
            best_ea = -1
            for ea, ln in ea_to_line.items():
                if ea <= target and ea > best_ea:
                    best_ea = ea
                    best_line = ln
            line_no = best_line

        if line_no is None:
            return {"addr": addr, "func": func_name, "line_no": None, "line": None,
                    "line_eas": [], "truncated": truncated,
                    "error": "No pseudocode line maps to this address"}

        line_text: str | None = None
        try:
            sv = cfunc.get_pseudocode()
            if 0 <= line_no < len(sv):
                line_text = compact_whitespace(ida_lines.tag_remove(sv[line_no].line))
        except Exception:
            line_text = None

        result: EaToPseudocodeResult = {
            "addr": addr,
            "func": func_name,
            "line_no": line_no,
            "line": line_text,
            "line_eas": [hex(e) for e in line_to_eas.get(line_no, [])],
        }
        if truncated:
            result["truncated"] = True
        return result
    except Exception as e:
        return {"addr": addr, "func": None, "line_no": None, "line": None,
                "line_eas": [], "error": str(e)}


@safety("READ")
@title("Map Pseudocode Line To Addresses")
@tool
@idasync
@tool_timeout(90.0)
def map_pseudocode_line_to_eas(
    func: Annotated[str, "Function address (hex like '0x401000') or symbol name whose pseudocode you are indexing into."],
    line: Annotated[int, "0-based pseudocode line number (as reported by `map_ea_to_pseudocode` or the decompiler's own line indexing) to resolve back to instruction addresses."],
) -> PseudocodeLineToEasResult:
    """WHAT: Resolves a single decompiled pseudocode line back to the set of instruction addresses Hex-Rays attributes to it, the inverse of `map_ea_to_pseudocode`.

WHEN TO USE: When reading `decompile` output and you want to set a breakpoint, patch, or run `disasm`/`xrefs_to` against the exact instructions behind one suspicious line of C.

RETURNS: {func, line_no, line, eas[], truncated?, error?}. `line` is the rendered text at that index; `eas` is the sorted list of addresses for it (empty when the line is pure decompiler scaffolding like a brace or declaration with no backing instruction). `error` is set for a bad function or missing Hex-Rays.

PRO-TIP: `eas[0]` is typically the line's entry address -- a good breakpoint/patch target. PITFALL: line numbers are 0-based and specific to the *current* decompilation; if you rename/retype and force a recompile, re-fetch them. `truncated=true` means the function exceeded the line budget and high line numbers may resolve empty."""
    try:
        ea = parse_address(func)
        f = idaapi.get_func(ea)
        if not f:
            return {"func": func, "line_no": line, "line": None, "eas": [],
                    "error": "Function not found"}
        if line < 0:
            return {"func": func, "line_no": line, "line": None, "eas": [],
                    "error": "Line number must be >= 0"}
        cfunc, cf_err = get_cached_cfunc(f.start_ea)
        if cfunc is None:
            return {"func": func, "line_no": line, "line": None, "eas": [],
                    "error": cf_err or "Decompilation failed"}

        line_to_eas, _ea_to_line, truncated = _build_line_ea_index(cfunc)

        line_text: str | None = None
        try:
            sv = cfunc.get_pseudocode()
            if 0 <= line < len(sv):
                line_text = compact_whitespace(ida_lines.tag_remove(sv[line].line))
        except Exception:
            line_text = None

        result: PseudocodeLineToEasResult = {
            "func": func,
            "line_no": line,
            "line": line_text,
            "eas": [hex(e) for e in line_to_eas.get(line, [])],
        }
        if truncated:
            result["truncated"] = True
        return result
    except Exception as e:
        return {"func": func, "line_no": line, "line": None, "eas": [], "error": str(e)}


@safety("READ")
@title("Get Function Basic Blocks (CFG)")
@tool
@idasync
def basic_blocks(
    addrs: Annotated[list[str] | str, "One function address/name or a list (e.g. '0x123e', 'main') whose control-flow graph blocks you want."],
    max_blocks: Annotated[
        int, "Max basic blocks returned per function (default: 1000, clamped to 1..10000)."
    ] = 1000,
    offset: Annotated[int, "Skip the first N blocks before collecting (default: 0). Feed the cursor's `next` here to continue."] = 0,
) -> list[BasicBlocksResult]:
    """WHAT: Returns a function's control-flow graph as basic blocks -- each with start/end address, size, decoded block type, successor/predecessor block addresses, and loop tagging (back-edges / loop-header / loop-tail) -- with pagination.

WHEN TO USE: To reason about control flow explicitly: branch structure, loop bodies, fall-through vs jump targets, or to drive your own CFG analysis. For call-level structure use `callgraph`; for the linear instruction listing use `disasm`.

RETURNS: list of {addr, blocks:[BasicBlock...], count, total_blocks, cursor} (or {addr, error, blocks:[], cursor}). Each block adds `type_name` (readable fc_block_type_t, e.g. 'NORMAL'/'RET'/'CNDJMP') and, when it closes a loop, `back_edges:[hexaddr...]` + `is_loop_tail:true`; targets of a back-edge get `is_loop_header:true`. `total_blocks` is the full CFG size; `cursor` is {next:N} or {done:true}.

PRO-TIP: Loop detection is precomputed -- scan for `is_loop_header` to find loop entries and `back_edges` to see which block jumps back to them, no instruction re-decoding required. PITFALL: `count` is the page size, `total_blocks` is the whole function -- compare them before assuming you have the full CFG; loop tags are computed over the full CFG, not just the returned page."""
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
                succ_eas = [succ.start_ea for succ in block.succs()]
                # A successor whose start address is <= this block's start is a
                # back-edge (it jumps to an already-seen point in the listing) =>
                # this block closes a loop and that successor is the loop header.
                back_edges = sorted(
                    {hex(s) for s in succ_eas if s <= block.start_ea}
                )
                bb: dict = {
                    "start": hex(block.start_ea),
                    "end": hex(block.end_ea),
                    "size": block.end_ea - block.start_ea,
                    "type": block.type,
                    "type_name": _block_type_name(block.type),
                    "successors": [hex(s) for s in succ_eas],
                    "predecessors": [hex(pred.start_ea) for pred in block.preds()],
                }
                if back_edges:
                    bb["back_edges"] = back_edges
                    bb["is_loop_tail"] = True
                all_blocks.append(bb)

            # Second pass: a block is a loop header iff some other block has a
            # back-edge targeting it (i.e. it is the lower-address end of a loop).
            loop_headers = {
                be for b in all_blocks for be in b.get("back_edges", [])
            }
            for b in all_blocks:
                if b["start"] in loop_headers:
                    b["is_loop_header"] = True

            # Apply pagination
            total_blocks = len(all_blocks)
            blocks = all_blocks[offset: offset + max_blocks]
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


@safety("READ")
@title("Find Strings, Immediates Or Refs")
@tool
@idasync
def find(
    type: Annotated[
        str,
        "What kind of search: 'string' (raw UTF-8 substring across the whole image), 'immediate' (an integer used as an immediate operand, executable segments only), 'data_ref' (data references to an address), or 'code_ref' (code references to an address).",
    ],
    targets: Annotated[
        list[str | int] | str | int,
        "One target or a list. For 'string': the text. For 'immediate': the integer (decimal or '0x..' string). For 'data_ref'/'code_ref': the address/name being referenced.",
    ],
    limit: Annotated[int, "Max matches per target (default: 1000, clamped to 1..10000)."] = 1000,
    offset: Annotated[int, "Skip the first N matches before collecting (default: 0). Feed the cursor's `next` here to continue."] = 0,
) -> list[FindResult]:
    """WHAT: A four-mode locator -- find a UTF-8 string in the image, find where an integer appears as an instruction immediate, or find the data/code references to a given address -- all with offset/limit pagination.

WHEN TO USE: Broad "where does X appear?" discovery. Use 'immediate' to hunt magic numbers/opcodes/constants in code, 'string' for raw text not yet typed as a strlit, and 'data_ref'/'code_ref' as a quick reference lookup (richer filtering lives in `xref_query`).

RETURNS: list of {query, matches:[hexaddr...], count, cursor, error?}. `cursor` is {done:true}, {next:N}, or {next:N, cancelled:true} when a deadline cut a scan short.

PRO-TIP: 'immediate' tries both 4- and 8-byte encodings and back-resolves to the instruction start, so a opcode constant is found even mid-instruction. PITFALL: 'string' is a raw byte substring, not the strings list -- it matches bytes regardless of typing, and a `cancelled` cursor means the scan is incomplete."""
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
            scan_error: str | None = None
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
            except Exception as e:
                # Surface the failure instead of silently returning a partial
                # set with error=None (the audit flagged this swallow).
                scan_error = str(e)

            if ida_kernwin.user_cancelled():
                cursor = {"next": offset + len(matches), "cancelled": True}
            elif more:
                cursor = {"next": offset + limit}
            else:
                cursor = {"done": True}
            results.append(
                {
                    "query": pattern_str,
                    "matches": matches,
                    "count": len(matches),
                    "cursor": cursor,
                    "error": scan_error,
                }
            )

    elif type == "immediate":
        # Search for immediate values.
        #
        # PAGING: `offset` is interpreted as a RESUME ADDRESS (next_start-style
        # cursor), not a count of matches to skip. The previous implementation
        # re-scanned from every executable segment's start each page and skipped
        # `offset` already-seen matches -- quadratic, because cursor.next =
        # offset+limit forced re-decoding (and re-`_resolve_immediate_insn_start`)
        # of the entire prefix on every page. Here a page resumes exactly at the
        # last cursor EA, so each page costs O(page) decode work. Dedup is stable
        # *within a single scan* (seen_insn) which is all that is needed once
        # scanning is monotonic in address.
        for value in targets:
            if isinstance(value, str):
                raw_value = value
                try:
                    value = int(value, 0)
                except ValueError:
                    # Previously coerced to 0 (a silent wrong-result swallow):
                    # report it as a structured invalid-argument error instead.
                    err = InvalidArgumentError(
                        f"Not a valid immediate: {raw_value!r}"
                    )
                    results.append(
                        {
                            "query": raw_value,
                            "matches": [],
                            "count": 0,
                            "cursor": {"done": True},
                            "error": err.message,
                        }
                    )
                    continue

            matches: list[str] = []
            more = False
            next_resume = 0
            scan_error: str | None = None
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

                resume_ea = offset if offset > 0 else 0
                seen_insn: set[int] = set()
                for seg_ea in idautils.Segments():
                    if more:
                        break
                    seg = idaapi.getseg(seg_ea)
                    if not seg or not (seg.perm & idaapi.SEGPERM_EXEC):
                        continue
                    # Skip whole segments that lie entirely before the resume EA.
                    if resume_ea and seg.end_ea <= resume_ea:
                        continue
                    scan_from = max(seg.start_ea, resume_ea)

                    # Collect address-ordered immediate matches in this segment by
                    # merging the per-encoding byte searches, advancing the single
                    # cursor that lies furthest behind on each step.
                    cursors = []
                    for normalized, size, pattern_bytes in candidates:
                        cursors.append(
                            {
                                "size": size,
                                "bytes": pattern_bytes,
                                "mask": b"\xff" * size,
                                "normalized": normalized,
                                "ea": scan_from,
                            }
                        )

                    while not more:
                        # Find next raw byte hit for each candidate at/after its ea.
                        best_ea = idaapi.BADADDR
                        for c in cursors:
                            if c["ea"] == idaapi.BADADDR or c["ea"] >= seg.end_ea:
                                continue
                            hit = _raw_bin_search(
                                c["ea"], seg.end_ea, c["bytes"], c["mask"]
                            )
                            c["ea"] = hit if hit != idaapi.BADADDR else idaapi.BADADDR
                            if c["ea"] != idaapi.BADADDR and c["ea"] < best_ea:
                                best_ea = c["ea"]
                        if best_ea == idaapi.BADADDR:
                            break

                        # The normalized (masked) encoding of whichever candidate
                        # landed here -- preserves matching of negative immediates
                        # whose operand value IDA reports in masked form.
                        alt_value = next(
                            (c["normalized"] for c in cursors if c["ea"] == best_ea),
                            None,
                        )
                        insn_start = _resolve_immediate_insn_start(
                            best_ea, value, seg.start_ea, alt_value
                        )
                        if insn_start is not None and insn_start not in seen_insn:
                            seen_insn.add(insn_start)
                            if len(matches) >= limit:
                                more = True
                                next_resume = best_ea
                                break
                            matches.append(hex(insn_start))

                        # Advance every cursor sitting on best_ea past it.
                        for c in cursors:
                            if c["ea"] == best_ea:
                                c["ea"] = best_ea + 1
            except Exception as e:
                # Surface the failure instead of silently swallowing it.
                scan_error = str(e)

            if ida_kernwin.user_cancelled():
                cursor = {"next": next_resume or offset, "cancelled": True}
            elif more:
                cursor = {"next": next_resume}
            else:
                cursor = {"done": True}
            results.append(
                {
                    "query": value,
                    "matches": matches,
                    "count": len(matches),
                    "cursor": cursor,
                    "error": scan_error,
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


@safety("READ")
@title("Query Instructions By Mnemonic/Operand")
@tool
@idasync
def insn_query(
    queries: Annotated[
        list[InsnPattern] | InsnPattern,
        "One or more instruction patterns. Each: {mnem?:'call'|'mov'|'*', op0?/op1?/op2?:int operand value, op_any?:int matched against any operand} + a scope (func | segment | start[/end]) and offset?/count?/max_scan_insns?/allow_broad?/include_fn?/include_disasm?.",
    ],
) -> list[InsnQueryResult]:
    """WHAT: Semantic instruction search -- decodes instructions in a scoped range and matches on mnemonic and/or specific operand values (positional op0/op1/op2 or op_any), returning matching addresses.

WHEN TO USE: When you need instruction meaning, not raw bytes -- e.g. "every `call` in this function", "every instruction with immediate 0x539", "all `mov` whose op1 is this global". Complements `find_bytes` (byte signatures) and `find type='immediate'` (immediate-only).

RETURNS: list of {query, ranges, matches:[{addr,disasm?,fn?}], count, cursor, scanned, truncated, next_start, error?}. `truncated=true` with a `next_start` means the `max_scan_insns` budget was hit -- resume the scan from `next_start`.

PRO-TIP: Always scope it (func/segment/start..end); the scan decodes every instruction, so a tight range is far cheaper and avoids needing `allow_broad`. PITFALL: a whole-binary scan requires `allow_broad=true` and can hit `max_scan_insns` -- distinguish `truncated` (scan budget) from `cursor.next` (result paging)."""
    queries = normalize_dict_list(queries)

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
                    row["disasm"] = compact_whitespace(ida_lines.tag_remove(line)) if line else ""
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


@safety("READ")
@title("Export Functions (JSON/Header/Protos)")
@tool
@idasync
def export_funcs(
    addrs: Annotated[list[str] | str, "One function address/name or a list (e.g. '0x123e', 'main') to export."],
    format: Annotated[
        str,
        "Output format: 'json' (default; full per-function dump with asm, decompilation, comments, xrefs), 'c_header' (a single string of `prototype;` lines), or 'prototypes' (name+prototype pairs only).",
    ] = "json",
) -> ExportFuncsJsonResult | ExportFuncsHeaderResult | ExportFuncsPrototypesResult:
    """WHAT: Bulk-exports one or more functions in a chosen shape -- a rich JSON record (prototype, size, comments, assembly, decompilation, xrefs), a synthesized C header of prototypes, or a compact prototype list.

WHEN TO USE: To capture analysis results for many functions in one call -- e.g. snapshot a subsystem to JSON, or generate a `.h` of recovered signatures to import elsewhere. For interactive single-function reading prefer `decompile`/`analyze_batch`.

RETURNS: shape depends on `format`: {format:'json', functions:[...]}, {format:'c_header', content:'...'}, or {format:'prototypes', functions:[{name,prototype}]}. In JSON, per-function failures appear as {addr, error} entries.

PRO-TIP: Use 'prototypes'/'c_header' for a cheap signature survey; only reach for 'json' when you actually need the asm/decompile/xref payload (it is the heaviest). PITFALL: 'c_header'/'prototypes' silently skip functions with no recovered prototype -- a short header may just mean missing types, not missing functions."""
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
                code, err = decompile_function_safe(ea)
                func_data["code"] = code
                if code is None and err:
                    func_data["decompile_error"] = err
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


@safety("READ")
@title("Build Bounded Call Graph")
@tool
@idasync
def callgraph(
    roots: Annotated[
        list[str] | str, "One root function address/name or a list to start the outward (callees) traversal from."
    ],
    max_depth: Annotated[int, "How many call levels to descend from each root (default: 5; 0 = root only). Clamped to >=0."] = 5,
    max_nodes: Annotated[
        int, "Hard cap on total nodes in a graph (default: 1000, clamped to 1..100000). Hitting it sets truncated + limit_reason='nodes'."
    ] = 1000,
    max_edges: Annotated[
        int, "Hard cap on total edges in a graph (default: 5000, clamped to 1..200000). Hitting it sets truncated + limit_reason='edges'."
    ] = 5000,
    max_edges_per_func: Annotated[
        int, "Cap on outgoing edges recorded per function (default: 200, clamped to 1..5000). Hitting it sets per_func_capped (a soft, local cap, not whole-graph truncation)."
    ] = 200,
) -> list[CallGraphResult]:
    """WHAT: Builds a bounded, breadth-limited call graph by descending callees from each root, returning nodes (addr, name, depth) and call edges, with explicit limits so it never explodes.

WHEN TO USE: To map how a function reaches a subsystem -- the transitive callee tree several levels deep. For a single level of callees use `callees`; for callers use `xrefs_to`.

RETURNS: list of {root, nodes, edges, max_depth, truncated, limit_reason, per_func_capped, ...caps} (or {root, error, nodes:[], edges:[]}). Check `truncated`/`limit_reason` to know whether a global cap clipped the graph.

PRO-TIP: Start with a small `max_depth` (2-3) and widen only if the graph is not yet truncated -- it is the cheapest knob. PITFALL: `per_func_capped=true` (from `max_edges_per_func`) is a per-node soft cap that can silently drop edges without setting `truncated`; raise it if a fan-out-heavy function looks under-connected."""
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
