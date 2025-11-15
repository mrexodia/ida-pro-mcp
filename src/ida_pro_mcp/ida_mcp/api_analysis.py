from typing import Annotated, Optional
import ida_hexrays
import ida_kernwin
import ida_lines
import ida_funcs
import idaapi
import idautils
import idc
import ida_typeinf
import ida_nalt
import ida_bytes
import ida_ida
import ida_entry
import ida_search
import ida_idaapi
import ida_xref
from .rpc import jsonrpc
from .sync import idaread, is_window_active
from .utils import (
    parse_address,
    normalize_list_input,
    normalize_dict_list,
    get_function,
    get_prototype,
    get_stack_frame_variables_internal,
    decompile_checked,
    decompile_function_safe,
    get_assembly_lines,
    get_all_xrefs,
    get_all_comments,
    get_callees,
    get_callers,
    get_xrefs_from_internal,
    extract_function_strings,
    extract_function_constants,
    Function,
    DisassemblyLine,
    Argument,
    StackFrameVariable,
    DisassemblyFunction,
    Xref,
    String,
    FunctionAnalysis,
    PatternMatch,
    BasicBlock,
)

# ============================================================================
# Code Analysis & Decompilation
# ============================================================================


@jsonrpc
@idaread
def decompile(
    addrs: Annotated[list[str] | str, "Address(es)"],
) -> list[dict]:
    """Decompile functions"""
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            start = parse_address(addr)
            cfunc = decompile_checked(start)
            if is_window_active():
                ida_hexrays.open_pseudocode(start, ida_hexrays.OPF_REUSE)
            sv = cfunc.get_pseudocode()
            code = ""
            for i, sl in enumerate(sv):
                sl: ida_kernwin.simpleline_t
                item = ida_hexrays.ctree_item_t()
                ea = None if i > 0 else cfunc.entry_ea
                if cfunc.get_line_item(sl.line, 0, False, None, item, None):
                    dstr: str | None = item.dstr()
                    if dstr:
                        ds = dstr.split(": ")
                        if len(ds) == 2:
                            try:
                                ea = int(ds[0], 16)
                            except ValueError:
                                pass
                line = ida_lines.tag_remove(sl.line)
                if len(code) > 0:
                    code += "\n"
                if not ea:
                    code += f"/* line: {i} */ {line}"
                else:
                    code += f"/* line: {i}, address: {hex(ea)} */ {line}"

            results.append({"addr": addr, "code": code})
        except Exception as e:
            results.append({"addr": addr, "code": None, "error": str(e)})

    return results


@jsonrpc
@idaread
def disasm(
    addrs: Annotated[list[str] | str, "Address(es)"],
) -> list[dict]:
    """Disassemble functions"""
    addrs = normalize_list_input(addrs)
    results = []

    for start_addr in addrs:
        try:
            start = parse_address(start_addr)
            func = idaapi.get_func(start)
            if not func:
                results.append(
                    {"addr": start_addr, "asm": None, "error": "No function found"}
                )
                continue
            if is_window_active():
                ida_kernwin.jumpto(start)

            func_name: str = ida_funcs.get_func_name(func.start_ea) or "<unnamed>"

            # Get segment from first instruction
            first_seg = idaapi.getseg(func.start_ea)
            segment_name = idaapi.get_segm_name(first_seg) if first_seg else "UNKNOWN"

            # Build disassembly string
            lines_str = f"{func_name} ({segment_name} @ {hex(func.start_ea)}):"
            for ea in idautils.FuncItems(func.start_ea):
                if ea == idaapi.BADADDR:
                    continue

                mnem: str = idc.print_insn_mnem(ea) or ""
                ops: list[str] = []
                for n in range(8):
                    if idc.get_operand_type(ea, n) == idaapi.o_void:
                        break
                    ops.append(idc.print_operand(ea, n) or "")
                instruction = f"{mnem} {', '.join(ops)}".rstrip()

                # Format: addr_without_0x  instruction
                lines_str += f"\n{ea:x}  {instruction}"

            rettype = None
            args: Optional[list[Argument]] = None
            tif = ida_typeinf.tinfo_t()
            if ida_nalt.get_tinfo(tif, func.start_ea) and tif.is_func():
                ftd = ida_typeinf.func_type_data_t()
                if tif.get_func_details(ftd):
                    rettype = str(ftd.rettype)
                    args = [
                        Argument(name=(a.name or f"arg{i}"), type=str(a.type))
                        for i, a in enumerate(ftd)
                    ]

            out: DisassemblyFunction = {
                "name": func_name,
                "start_ea": hex(func.start_ea),
                "stack_frame": get_stack_frame_variables_internal(func.start_ea, False),
                "lines": lines_str,
            }
            if rettype:
                out["return_type"] = rettype
            if args is not None:
                out["arguments"] = args

            results.append({"addr": start_addr, "asm": out})
        except Exception as e:
            results.append({"addr": start_addr, "asm": None, "error": str(e)})

    return results


# ============================================================================
# Cross-Reference Analysis
# ============================================================================


@jsonrpc
@idaread
def xrefs_to(
    addrs: Annotated[list[str] | str, "Address(es)"],
) -> list[dict]:
    """Get xrefs to addresses"""
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            xrefs = []
            xref: ida_xref.xrefblk_t
            for xref in idautils.XrefsTo(parse_address(addr)):
                xrefs += [
                    Xref(
                        addr=hex(xref.frm),
                        type="code" if xref.iscode else "data",
                        fn=get_function(xref.frm, raise_error=False),
                    )
                ]
            results.append({"addr": addr, "xrefs": xrefs})
        except Exception as e:
            results.append({"addr": addr, "xrefs": None, "error": str(e)})

    return results


@jsonrpc
@idaread
def xrefs_to_field(
    queries: Annotated[list[dict] | dict, "[{struct, field}, ...] or {struct, field}"],
) -> list[dict]:
    """Get xrefs to struct fields"""

    def parse_struct_field(s: str) -> dict:
        # Support "StructName.field" or "StructName::field" syntax
        if "." in s:
            parts = s.split(".", 1)
            return {"struct": parts[0].strip(), "field": parts[1].strip()}
        elif "::" in s:
            parts = s.split("::", 1)
            return {"struct": parts[0].strip(), "field": parts[1].strip()}
        # Just field name without struct
        return {"struct": "", "field": s.strip()}

    queries = normalize_dict_list(queries, parse_struct_field)

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


@jsonrpc
@idaread
def callees(
    addrs: Annotated[list[str] | str, "Address(es)"],
) -> list[dict]:
    """Get function callees"""
    addrs = normalize_list_input(addrs)
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
            func_end = idc.find_func_end(func_start)
            callees: list[dict[str, str]] = []
            current_ea = func_start
            while current_ea < func_end:
                insn = idaapi.insn_t()
                idaapi.decode_insn(insn, current_ea)
                if insn.itype in [idaapi.NN_call, idaapi.NN_callfi, idaapi.NN_callni]:
                    target = idc.get_operand_value(current_ea, 0)
                    target_type = idc.get_operand_type(current_ea, 0)
                    if target_type in [idaapi.o_mem, idaapi.o_near, idaapi.o_far]:
                        func_type = (
                            "internal"
                            if idaapi.get_func(target) is not None
                            else "external"
                        )
                        func_name = idc.get_name(target)
                        if func_name is not None:
                            callees.append(
                                {
                                    "addr": hex(target),
                                    "name": func_name,
                                    "type": func_type,
                                }
                            )
                current_ea = idc.next_head(current_ea, func_end)

            unique_callee_tuples = {tuple(callee.items()) for callee in callees}
            unique_callees = [dict(callee) for callee in unique_callee_tuples]
            results.append({"addr": fn_addr, "callees": unique_callees})
        except Exception as e:
            results.append({"addr": fn_addr, "callees": None, "error": str(e)})

    return results


@jsonrpc
@idaread
def callers(
    addrs: Annotated[list[str] | str, "Address(es)"],
) -> list[dict]:
    """Get function callers"""
    addrs = normalize_list_input(addrs)
    results = []

    for fn_addr in addrs:
        try:
            callers = {}
            for caller_addr in idautils.CodeRefsTo(parse_address(fn_addr), 0):
                func = get_function(caller_addr, raise_error=False)
                if not func:
                    continue
                insn = idaapi.insn_t()
                idaapi.decode_insn(insn, caller_addr)
                if insn.itype not in [
                    idaapi.NN_call,
                    idaapi.NN_callfi,
                    idaapi.NN_callni,
                ]:
                    continue
                callers[func["addr"]] = func

            results.append({"addr": fn_addr, "callers": list(callers.values())})
        except Exception as e:
            results.append({"addr": fn_addr, "callers": None, "error": str(e)})

    return results


@jsonrpc
@idaread
def entrypoints() -> list[Function]:
    """Get entry points"""
    result = []
    for i in range(ida_entry.get_entry_qty()):
        ordinal = ida_entry.get_entry_ordinal(i)
        addr = ida_entry.get_entry(ordinal)
        func = get_function(addr, raise_error=False)
        if func is not None:
            result.append(func)
    return result


# ============================================================================
# Comprehensive Function Analysis
# ============================================================================


@jsonrpc
@idaread
def analyze_funcs(addrs: Annotated[list[str], "Address(es)"]) -> list[FunctionAnalysis]:
    """Analyze functions: decomp, xrefs, callees, strings"""
    results = []
    for addr in addrs:
        try:
            ea = parse_address(addr)
            func = idaapi.get_func(ea)

            if not func:
                results.append(
                    FunctionAnalysis(
                        addr=addr,
                        name=None,
                        code=None,
                        asm=None,
                        xto=[],
                        xfrom=[],
                        callees=[],
                        callers=[],
                        strings=[],
                        constants=[],
                        blocks=[],
                        error="Function not found",
                    )
                )
                continue

            # Get basic blocks
            flowchart = idaapi.FlowChart(func)
            blocks = []
            for block in flowchart:
                blocks.append(
                    {
                        "start": hex(block.start_ea),
                        "end": hex(block.end_ea),
                        "type": block.type,
                    }
                )

            result = FunctionAnalysis(
                addr=addr,
                name=ida_funcs.get_func_name(func.start_ea),
                code=decompile_function_safe(ea),
                asm=get_assembly_lines(ea),
                xto=[
                    Xref(
                        addr=hex(x.frm),
                        type="code" if x.iscode else "data",
                        fn=get_function(x.frm, raise_error=False),
                    )
                    for x in idautils.XrefsTo(ea, 0)
                ],
                xfrom=get_xrefs_from_internal(ea),
                callees=get_callees(addr),
                callers=get_callers(addr),
                strings=extract_function_strings(ea),
                constants=extract_function_constants(ea),
                blocks=blocks,
                error=None,
            )
            results.append(result)
        except Exception as e:
            results.append(
                FunctionAnalysis(
                    addr=addr,
                    name=None,
                    code=None,
                    asm=None,
                    xto=[],
                    xfrom=[],
                    callees=[],
                    callers=[],
                    strings=[],
                    constants=[],
                    blocks=[],
                    error=str(e),
                )
            )
    return results


# ============================================================================
# Pattern Matching & Signature Tools
# ============================================================================


@jsonrpc
@idaread
def find_bytes(
    patterns: Annotated[list[str], "Byte patterns (e.g. '48 8B ?? ??')"],
) -> list[PatternMatch]:
    """Find byte patterns"""
    results = []
    for pattern in patterns:
        matches = []
        try:
            # Parse the pattern
            compiled = ida_bytes.compiled_binpat_vec_t()
            err = ida_bytes.parse_binpat_str(
                compiled, ida_ida.inf_get_min_ea(), pattern, 16
            )
            if err:
                results.append(PatternMatch(pattern=pattern, matches=[], count=0))
                continue

            # Search for matches
            ea = ida_ida.inf_get_min_ea()
            while ea != idaapi.BADADDR:
                ea = ida_bytes.bin_search(
                    ea, ida_ida.inf_get_max_ea(), compiled, ida_bytes.BIN_SEARCH_FORWARD
                )
                if ea != idaapi.BADADDR:
                    matches.append(hex(ea))
                    ea += 1
        except Exception:
            pass

        results.append(
            PatternMatch(pattern=pattern, matches=matches, count=len(matches))
        )
    return results


@jsonrpc
@idaread
def find_insns(
    sequences: Annotated[list[list[str]], "Instruction sequences"],
) -> list[dict]:
    """Find instruction sequences"""
    results = []

    for sequence in sequences:
        if not sequence:
            results.append({"sequence": sequence, "matches": [], "count": 0})
            continue

        matches = []
        # Scan all code segments
        for seg_ea in idautils.Segments():
            seg = idaapi.getseg(seg_ea)
            if not seg or not (seg.perm & idaapi.SEGPERM_EXEC):
                continue

            ea = seg.start_ea
            while ea < seg.end_ea:
                # Try to match sequence starting at ea
                match_ea = ea
                matched = True

                for expected_mnem in sequence:
                    insn = idaapi.insn_t()
                    if idaapi.decode_insn(insn, match_ea) == 0:
                        matched = False
                        break

                    actual_mnem = idc.print_insn_mnem(match_ea)
                    if actual_mnem != expected_mnem:
                        matched = False
                        break

                    match_ea = idc.next_head(match_ea, seg.end_ea)
                    if match_ea == idaapi.BADADDR:
                        matched = False
                        break

                if matched:
                    matches.append(hex(ea))

                ea = idc.next_head(ea, seg.end_ea)
                if ea == idaapi.BADADDR:
                    break

        results.append(
            {"sequence": sequence, "matches": matches, "count": len(matches)}
        )

    return results


# ============================================================================
# Control Flow Analysis
# ============================================================================


@jsonrpc
@idaread
def basic_blocks(addrs: Annotated[list[str], "Address(es)"]) -> list[dict]:
    """Get basic blocks"""
    results = []
    for fn_addr in addrs:
        try:
            ea = parse_address(fn_addr)
            func = idaapi.get_func(ea)
            if not func:
                results.append(
                    {"addr": fn_addr, "error": "Function not found", "blocks": []}
                )
                continue

            flowchart = idaapi.FlowChart(func)
            blocks = []
            for block in flowchart:
                blocks.append(
                    BasicBlock(
                        start=hex(block.start_ea),
                        end=hex(block.end_ea),
                        size=block.end_ea - block.start_ea,
                        type=block.type,
                        successors=[hex(succ.start_ea) for succ in block.succs()],
                        predecessors=[hex(pred.start_ea) for pred in block.preds()],
                    )
                )

            results.append(
                {"addr": fn_addr, "blocks": blocks, "count": len(blocks), "error": None}
            )
        except Exception as e:
            results.append({"addr": fn_addr, "error": str(e), "blocks": []})
    return results


@jsonrpc
@idaread
def find_paths(
    queries: Annotated[
        list[dict] | dict, "Source/target pairs or single {source, target}"
    ],
) -> list[dict]:
    """Find execution paths"""
    queries = normalize_dict_list(queries)
    results = []

    for query in queries:
        source = parse_address(query["source"])
        target = parse_address(query["target"])

        # Get containing function
        func = idaapi.get_func(source)
        if not func:
            results.append(
                {
                    "source": query["source"],
                    "target": query["target"],
                    "paths": [],
                    "reachable": False,
                    "error": "Source not in a function",
                }
            )
            continue

        # Build flow graph
        flowchart = idaapi.FlowChart(func)

        # Find source and target blocks
        source_block = None
        target_block = None
        for block in flowchart:
            if block.start_ea <= source < block.end_ea:
                source_block = block
            if block.start_ea <= target < block.end_ea:
                target_block = block

        if not source_block or not target_block:
            results.append(
                {
                    "source": query["source"],
                    "target": query["target"],
                    "paths": [],
                    "reachable": False,
                    "error": "Could not find basic blocks",
                }
            )
            continue

        # Simple BFS to find paths
        paths = []
        queue = [([source_block], {source_block.id})]

        while queue and len(paths) < 10:  # Limit paths
            path, visited = queue.pop(0)
            current = path[-1]

            if current.id == target_block.id:
                paths.append([hex(b.start_ea) for b in path])
                continue

            for succ in current.succs():
                if succ.id not in visited and len(path) < 20:  # Limit depth
                    queue.append((path + [succ], visited | {succ.id}))

        results.append(
            {
                "source": query["source"],
                "target": query["target"],
                "paths": paths,
                "reachable": len(paths) > 0,
                "error": None,
            }
        )

    return results


# ============================================================================
# Search Operations
# ============================================================================


@jsonrpc
@idaread
def search(
    queries: Annotated[
        list[dict] | dict,
        "{ ty: 'immediate', q: int, start?: addr } | { ty: 'string', q: str } | { ty: 'data_ref', q: addr } | { ty: 'code_ref', q: addr }",
    ],
) -> list[dict]:
    """Search (ty: 'immediate'|'string'|'data_ref'|'code_ref', q: value/pattern/target depending on ty)"""
    queries = normalize_dict_list(
        queries, lambda s: {"ty": "string", "q": s}
    )
    results = []

    for query in queries:
        try:
            query_type = query.get("ty")
            matches = []

            if query_type == "immediate":
                # Search for immediate values
                # q: the immediate value to search for (int)
                value = query.get("q", 0)
                if isinstance(value, str):
                    # Try to parse as hex or decimal
                    try:
                        value = int(value, 0)
                    except ValueError:
                        value = 0
                start_ea = parse_address(
                    query.get("start", hex(ida_ida.inf_get_min_ea()))
                )

                ea = start_ea
                while ea != idaapi.BADADDR:
                    ea = ida_search.find_imm(ea, ida_search.SEARCH_DOWN, value)
                    if ea != idaapi.BADADDR:
                        matches.append(hex(ea))
                        ea = idc.next_head(ea, ida_ida.inf_get_max_ea())

            elif query_type == "string":
                # Search for strings containing pattern
                # q: the pattern to search for in strings (str)
                pattern = query.get("q", "")
                for s in idautils.Strings():
                    if pattern.lower() in str(s).lower():
                        matches.append(hex(s.ea))

            elif query_type == "data_ref":
                # Find all data references to a target
                # q: the target address to find references to (addr str)
                target_str = query.get("q")
                if target_str is None:
                    continue
                target = parse_address(target_str)
                for xref in idautils.DataRefsTo(target):
                    matches.append(hex(xref))

            elif query_type == "code_ref":
                # Find all code references to a target
                # q: the target address to find references to (addr str)
                target_str = query.get("q")
                if target_str is None:
                    continue
                target = parse_address(target_str)
                for xref in idautils.CodeRefsTo(target, 0):
                    matches.append(hex(xref))

            results.append(
                {
                    "query": query,
                    "matches": matches,
                    "count": len(matches),
                    "error": None,
                }
            )

        except Exception as e:
            results.append({"query": query, "matches": [], "count": 0, "error": str(e)})

    return results


# ============================================================================
# Export Operations
# ============================================================================


@jsonrpc
@idaread
def export_funcs(
    addrs: Annotated[list[str], "Address(es)"],
    format: Annotated[str, "Format: json|c_header|prototypes"] = "json",
) -> dict:
    """Export functions"""
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


@jsonrpc
@idaread
def callgraph(
    roots: Annotated[list[str], "Root addresses"],
    max_depth: Annotated[int, "Max depth"] = 5,
) -> list[dict]:
    """Get call graph"""
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

            def traverse(addr, depth):
                if depth > max_depth or addr in visited:
                    return
                visited.add(addr)

                f = idaapi.get_func(addr)
                if not f:
                    return

                func_name = ida_funcs.get_func_name(f.start_ea)
                nodes[hex(addr)] = {"addr": hex(addr), "name": func_name, "depth": depth}

                # Get callees
                for item_ea in idautils.FuncItems(f.start_ea):
                    for xref in idautils.CodeRefsFrom(item_ea, 0):
                        callee_func = idaapi.get_func(xref)
                        if callee_func:
                            edges.append(
                                {
                                    "from": hex(addr),
                                    "to": hex(callee_func.start_ea),
                                    "type": "call",
                                }
                            )
                            traverse(callee_func.start_ea, depth + 1)

            traverse(ea, 0)

            results.append(
                {
                    "root": root,
                    "nodes": list(nodes.values()),
                    "edges": edges,
                    "max_depth": max_depth,
                    "error": None,
                }
            )

        except Exception as e:
            results.append({"root": root, "error": str(e), "nodes": [], "edges": []})

    return results


# ============================================================================
# Cross-Reference Matrix
# ============================================================================


@jsonrpc
@idaread
def xref_matrix(entities: Annotated[list[str], "Address(es)"]) -> dict:
    """Build xref matrix"""
    matrix = {}

    for source in entities:
        try:
            source_ea = parse_address(source)
            matrix[source] = {}

            for target in entities:
                if source == target:
                    continue

                target_ea = parse_address(target)

                # Count references from source to target
                count = 0
                for xref in idautils.XrefsFrom(source_ea, 0):
                    if xref.to == target_ea:
                        count += 1

                if count > 0:
                    matrix[source][target] = count

        except Exception:
            matrix[source] = {"error": "Failed to process"}

    return {"matrix": matrix, "entities": entities}


# ============================================================================
# String Analysis
# ============================================================================


@jsonrpc
@idaread
def analyze_strings(
    filters: Annotated[
        list[dict] | dict,
        "[{pattern, min_length, ...}, ...] or {pattern, min_length, ...}",
    ],
) -> list[dict]:
    """Analyze strings"""
    filters = normalize_dict_list(filters)
    all_strings = []

    # Collect all strings once
    for s in idautils.Strings():
        try:
            all_strings.append(
                {
                    "addr": hex(s.ea),
                    "length": s.length,
                    "string": str(s),
                    "type": s.strtype,
                }
            )
        except Exception:
            pass

    results = []
    for filt in filters:
        pattern = filt.get("pattern", "").lower()
        min_length = filt.get("min_length", 0)

        matches = []
        for s in all_strings:
            if len(s["string"]) < min_length:
                continue
            if pattern and pattern not in s["string"].lower():
                continue

            # Add xref info
            s_ea = parse_address(s["addr"])
            xrefs = [hex(x.frm) for x in idautils.XrefsTo(s_ea, 0)]

            matches.append({**s, "xrefs": xrefs, "xref_count": len(xrefs)})

        results.append({"filter": filt, "matches": matches, "count": len(matches)})

    return results
