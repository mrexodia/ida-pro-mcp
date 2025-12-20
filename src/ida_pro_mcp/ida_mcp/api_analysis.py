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
from .rpc import tool
from .sync import idasync, is_window_active
from .tests import (
    test,
    assert_has_keys,
    assert_non_empty,
    assert_is_list,
    get_any_function,
    get_any_string,
)
from .utils import (
    parse_address,
    normalize_list_input,
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
    Argument,
    DisassemblyFunction,
    Xref,
    FunctionAnalysis,
    BasicBlock,
    PathQuery,
    StructFieldQuery,
    StringFilter,
    InsnPattern,
)

# ============================================================================
# String Cache
# ============================================================================

# Cache for idautils.Strings() to avoid rebuilding on every call
_strings_cache: Optional[list[dict]] = None
_strings_cache_md5: Optional[str] = None


def _get_cached_strings_dict() -> list[dict]:
    """Get cached strings as dicts, rebuilding if IDB changed"""
    global _strings_cache, _strings_cache_md5

    # Get current IDB modification hash
    current_md5 = ida_nalt.retrieve_input_file_md5()

    # Rebuild cache if needed
    if _strings_cache is None or _strings_cache_md5 != current_md5:
        _strings_cache = []
        for s in idautils.Strings():
            try:
                _strings_cache.append(
                    {
                        "addr": hex(s.ea),
                        "length": s.length,
                        "string": str(s),
                        "type": s.strtype,
                    }
                )
            except Exception:
                pass
        _strings_cache_md5 = current_md5

    return _strings_cache


# ============================================================================
# Code Analysis & Decompilation
# ============================================================================


@tool
@idasync
def decompile(
    addrs: Annotated[list[str] | str, "Function addresses to decompile"],
) -> list[dict]:
    """Decompile functions to pseudocode"""
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


@test()
def test_decompile_valid_function():
    """Decompile returns code for valid function"""
    func_addr = get_any_function()
    assert func_addr is not None, "No functions in IDB"
    result = decompile(func_addr)
    assert len(result) == 1, f"Expected 1 result, got {len(result)}"
    assert_has_keys(result[0], "addr", "code")
    assert result[0]["code"] is not None, "Code should not be None"
    assert_non_empty(result[0]["code"])


@test()
def test_decompile_invalid_address():
    """Decompile returns error for invalid address"""
    result = decompile("0xDEADBEEF")
    assert len(result) == 1
    assert "error" in result[0], "Expected error for invalid address"


@test()
def test_decompile_batch():
    """Decompile handles multiple addresses"""
    func_addr = get_any_function()
    assert func_addr is not None, "No functions in IDB"
    result = decompile([func_addr, func_addr])
    assert len(result) == 2, f"Expected 2 results, got {len(result)}"


@tool
@idasync
def disasm(
    addrs: Annotated[list[str] | str, "Function addresses to disassemble"],
    max_instructions: Annotated[
        int, "Max instructions per function (default: 5000, max: 50000)"
    ] = 5000,
    offset: Annotated[int, "Skip first N instructions (default: 0)"] = 0,
) -> list[dict]:
    """Disassemble functions to assembly instructions"""
    addrs = normalize_list_input(addrs)

    # Enforce max limit
    if max_instructions <= 0 or max_instructions > 50000:
        max_instructions = 50000

    results = []

    for start_addr in addrs:
        try:
            start = parse_address(start_addr)
            func = idaapi.get_func(start)

            if is_window_active():
                ida_kernwin.jumpto(start)

            # Get segment info
            seg = idaapi.getseg(start)
            if not seg:
                results.append(
                    {
                        "addr": start_addr,
                        "asm": None,
                        "error": "No segment found",
                        "cursor": {"done": True},
                    }
                )
                continue

            segment_name = idaapi.get_segm_name(seg) if seg else "UNKNOWN"

            # Collect instructions
            all_instructions = []

            if func:
                # Function exists: disassemble function items starting from requested address
                func_name: str = ida_funcs.get_func_name(func.start_ea) or "<unnamed>"
                header_addr = start  # Use requested address, not function start

                for ea in idautils.FuncItems(func.start_ea):
                    if ea == idaapi.BADADDR:
                        continue
                    # Skip instructions before the requested start address
                    if ea < start:
                        continue

                    # Use generate_disasm_line to get full line with comments
                    line = idc.generate_disasm_line(ea, 0)
                    instruction = ida_lines.tag_remove(line) if line else ""
                    all_instructions.append((ea, instruction))
            else:
                # No function: disassemble sequentially from start address
                func_name = "<no function>"
                header_addr = start

                ea = start
                while (
                    ea < seg.end_ea
                    and len(all_instructions) < max_instructions + offset
                ):
                    if ea == idaapi.BADADDR:
                        break

                    insn = idaapi.insn_t()
                    if idaapi.decode_insn(insn, ea) == 0:
                        break

                    # Use generate_disasm_line to get full line with comments
                    line = idc.generate_disasm_line(ea, 0)
                    instruction = ida_lines.tag_remove(line) if line else ""
                    all_instructions.append((ea, instruction))

                    ea = idc.next_head(ea, seg.end_ea)

            # Apply pagination
            total_insns = len(all_instructions)
            paginated_insns = all_instructions[offset : offset + max_instructions]
            has_more = offset + max_instructions < total_insns

            # Build disassembly string from paginated instructions
            lines_str = f"{func_name} ({segment_name} @ {hex(header_addr)}):"
            for ea, instruction in paginated_insns:
                lines_str += f"\n{ea:x}  {instruction}"

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
                "lines": lines_str,
            }
            if stack_frame:
                out["stack_frame"] = stack_frame
            if rettype:
                out["return_type"] = rettype
            if args is not None:
                out["arguments"] = args

            results.append(
                {
                    "addr": start_addr,
                    "asm": out,
                    "instruction_count": len(paginated_insns),
                    "total_instructions": total_insns,
                    "cursor": (
                        {"next": offset + max_instructions}
                        if has_more
                        else {"done": True}
                    ),
                }
            )
        except Exception as e:
            results.append(
                {
                    "addr": start_addr,
                    "asm": None,
                    "error": str(e),
                    "cursor": {"done": True},
                }
            )

    return results


@test()
def test_disasm_valid_function():
    """Disassembly returns lines for valid function"""
    func_addr = get_any_function()
    if not func_addr:
        return
    result = disasm(func_addr)
    assert len(result) == 1, f"Expected 1 result, got {len(result)}"
    assert_has_keys(result[0], "addr", "asm", "instruction_count", "cursor")
    assert result[0]["asm"] is not None, "asm should not be None"
    assert_has_keys(result[0]["asm"], "name", "start_ea", "lines")
    assert_non_empty(result[0]["asm"]["lines"])


@test()
def test_disasm_pagination():
    """Disassembly offset/max_instructions work"""
    func_addr = get_any_function()
    if not func_addr:
        return
    # Get first 5 instructions
    result1 = disasm(func_addr, max_instructions=5, offset=0)
    assert len(result1) == 1
    assert result1[0]["instruction_count"] <= 5

    # Get next 5 with offset
    result2 = disasm(func_addr, max_instructions=5, offset=5)
    assert len(result2) == 1
    # Either we have more instructions or we're done
    assert "cursor" in result2[0]


@test()
def test_disasm_unmapped_address():
    """disasm handles unmapped address gracefully (covers lines 199-207)"""
    from .tests import get_unmapped_address

    result = disasm(get_unmapped_address())
    assert len(result) == 1
    # Should either have error or empty asm
    assert result[0].get("error") is not None or result[0]["asm"] is None


@test()
def test_disasm_data_segment():
    """disasm handles address in data segment (covers lines 232-252)"""
    from .tests import get_data_address

    data_addr = get_data_address()
    if not data_addr:
        return

    result = disasm(data_addr)
    assert len(result) == 1
    # Should succeed but show "<no function>" or similar
    # The key is it doesn't crash on non-code


# ============================================================================
# Cross-Reference Analysis
# ============================================================================


@tool
@idasync
def xrefs_to(
    addrs: Annotated[list[str] | str, "Addresses to find cross-references to"],
) -> list[dict]:
    """Get all cross-references to specified addresses"""
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


@test()
def test_xrefs_to():
    """xrefs_to returns cross-references"""
    func_addr = get_any_function()
    if not func_addr:
        return
    result = xrefs_to(func_addr)
    assert len(result) == 1, f"Expected 1 result, got {len(result)}"
    assert_has_keys(result[0], "addr", "xrefs")
    # xrefs is a list (may be empty for functions with no callers)
    assert_is_list(result[0]["xrefs"])


@test()
def test_xrefs_to_invalid():
    """xrefs_to handles invalid address gracefully"""
    result = xrefs_to("0xDEADBEEFDEADBEEF")
    assert len(result) == 1
    # Should either return empty xrefs or an error, not crash
    assert "xrefs" in result[0] or "error" in result[0]


@tool
@idasync
def xrefs_to_field(queries: list[StructFieldQuery] | StructFieldQuery) -> list[dict]:
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


@test()
def test_xrefs_to_field_nonexistent_struct():
    """xrefs_to_field handles nonexistent struct gracefully"""
    result = xrefs_to_field({"struct": "NonExistentStruct12345", "field": "field"})
    assert_is_list(result, min_length=1)
    assert_has_keys(result[0], "struct", "field", "xrefs")
    # Should have error or empty xrefs for nonexistent struct
    assert result[0].get("error") is not None or result[0]["xrefs"] == []


@test()
def test_xrefs_to_field_batch():
    """xrefs_to_field handles multiple queries"""
    result = xrefs_to_field(
        [
            {"struct": "NonExistentStruct1", "field": "field1"},
            {"struct": "NonExistentStruct2", "field": "field2"},
        ]
    )
    assert_is_list(result, min_length=2)
    for item in result:
        assert_has_keys(item, "struct", "field", "xrefs")


# ============================================================================
# Call Graph Analysis
# ============================================================================


@tool
@idasync
def callees(
    addrs: Annotated[list[str] | str, "Function addresses to get callees for"],
) -> list[dict]:
    """Get all functions called by the specified functions"""
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


@test()
def test_callees():
    """callees returns called functions"""
    func_addr = get_any_function()
    if not func_addr:
        return
    result = callees(func_addr)
    assert len(result) == 1, f"Expected 1 result, got {len(result)}"
    assert_has_keys(result[0], "addr", "callees")
    # callees is a list (may be empty for leaf functions)
    assert_is_list(result[0]["callees"])


@test()
def test_callees_multiple():
    """callees works on multiple functions (sampling test)"""
    from .tests import get_n_functions

    addrs = get_n_functions()
    if len(addrs) < 2:
        return

    result = callees(addrs)
    assert len(result) == len(addrs)
    for r in result:
        assert_has_keys(r, "addr", "callees")
        # Each should have a callees list (may be empty) or error
        if r.get("error") is None:
            assert_is_list(r["callees"])


@test()
def test_callees_invalid_address():
    """callees handles invalid address (covers error path)"""
    from .tests import get_unmapped_address

    result = callees(get_unmapped_address())
    assert len(result) == 1
    # Should return error or empty callees
    assert result[0].get("error") is not None or result[0]["callees"] is None


@tool
@idasync
def callers(
    addrs: Annotated[list[str] | str, "Function addresses to get callers for"],
) -> list[dict]:
    """Get all functions that call the specified functions"""
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


@test()
def test_callers():
    """callers returns calling functions"""
    func_addr = get_any_function()
    if not func_addr:
        return
    result = callers(func_addr)
    assert len(result) == 1, f"Expected 1 result, got {len(result)}"
    assert_has_keys(result[0], "addr", "callers")
    # callers is a list (may be empty for entry points)
    assert_is_list(result[0]["callers"])


@tool
@idasync
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


@test()
def test_entrypoints():
    """entrypoints returns entry points list"""
    result = entrypoints()
    # Result is a list of Function dicts (may be empty for some binaries)
    assert_is_list(result)
    # If there are entry points, they should have proper structure
    if len(result) > 0:
        assert_has_keys(result[0], "addr", "name")


# ============================================================================
# Comprehensive Function Analysis
# ============================================================================


@tool
@idasync
def analyze_funcs(
    addrs: Annotated[list[str] | str, "Function addresses to comprehensively analyze"],
) -> list[FunctionAnalysis]:
    """Comprehensive function analysis: decompilation, xrefs, callees, strings, constants, blocks"""
    addrs = normalize_list_input(addrs)
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


@test()
def test_analyze_funcs():
    """analyze_funcs returns comprehensive analysis with all fields"""
    func_addr = get_any_function()
    if not func_addr:
        return
    result = analyze_funcs(func_addr)
    assert len(result) == 1, f"Expected 1 result, got {len(result)}"
    # Check all expected fields are present
    assert_has_keys(
        result[0],
        "addr",
        "name",
        "code",
        "asm",
        "xto",
        "xfrom",
        "callees",
        "callers",
        "strings",
        "constants",
        "blocks",
    )
    # Lists should be lists (may be empty)
    assert_is_list(result[0]["xto"])
    assert_is_list(result[0]["xfrom"])
    assert_is_list(result[0]["callees"])
    assert_is_list(result[0]["callers"])
    assert_is_list(result[0]["strings"])
    assert_is_list(result[0]["constants"])
    assert_is_list(result[0]["blocks"])


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
) -> list[dict]:
    """Search for byte patterns in the binary (supports wildcards with ??)"""
    patterns = normalize_list_input(patterns)

    # Enforce max limit
    if limit <= 0 or limit > 10000:
        limit = 10000

    results = []
    for pattern in patterns:
        all_matches = []
        try:
            # Parse the pattern
            compiled = ida_bytes.compiled_binpat_vec_t()
            err = ida_bytes.parse_binpat_str(
                compiled, ida_ida.inf_get_min_ea(), pattern, 16
            )
            if err:
                results.append(
                    {
                        "pattern": pattern,
                        "matches": [],
                        "count": 0,
                        "cursor": {"done": True},
                    }
                )
                continue

            # Search for all matches
            ea = ida_ida.inf_get_min_ea()
            while ea != idaapi.BADADDR:
                ea = ida_bytes.bin_search(
                    ea, ida_ida.inf_get_max_ea(), compiled, ida_bytes.BIN_SEARCH_FORWARD
                )
                if ea != idaapi.BADADDR:
                    all_matches.append(hex(ea))
                    ea += 1
        except Exception:
            pass

        # Apply pagination
        if limit > 0:
            matches = all_matches[offset : offset + limit]
            has_more = offset + limit < len(all_matches)
        else:
            matches = all_matches[offset:]
            has_more = False

        results.append(
            {
                "pattern": pattern,
                "matches": matches,
                "count": len(matches),
                "cursor": {"next": offset + limit} if has_more else {"done": True},
            }
        )
    return results


@test()
def test_find_bytes():
    """find_bytes byte pattern search works"""
    # Search for a common byte sequence (0x00 0x00) that should exist in most binaries
    result = find_bytes("00 00")
    assert len(result) == 1, f"Expected 1 result, got {len(result)}"
    assert_has_keys(result[0], "pattern", "matches", "count", "cursor")
    assert_is_list(result[0]["matches"])
    # Should find at least some matches in most binaries
    # (but we don't require it since it's binary-agnostic)


@tool
@idasync
def find_insns(
    sequences: Annotated[
        list[list[str]] | list[str], "Instruction mnemonic sequences to search for"
    ],
    limit: Annotated[
        int, "Max matches per sequence (default: 1000, max: 10000)"
    ] = 1000,
    offset: Annotated[int, "Skip first N matches (default: 0)"] = 0,
) -> list[dict]:
    """Search for sequences of instruction mnemonics in the binary"""
    # Handle single sequence vs array of sequences
    if sequences and isinstance(sequences[0], str):
        sequences = [sequences]

    # Enforce max limit
    if limit <= 0 or limit > 10000:
        limit = 10000

    results = []

    for sequence in sequences:
        if not sequence:
            results.append(
                {
                    "sequence": sequence,
                    "matches": [],
                    "count": 0,
                    "cursor": {"done": True},
                }
            )
            continue

        all_matches = []
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
                    all_matches.append(hex(ea))

                ea = idc.next_head(ea, seg.end_ea)
                if ea == idaapi.BADADDR:
                    break

        # Apply pagination
        if limit > 0:
            matches = all_matches[offset : offset + limit]
            has_more = offset + limit < len(all_matches)
        else:
            matches = all_matches[offset:]
            has_more = False

        results.append(
            {
                "sequence": sequence,
                "matches": matches,
                "count": len(matches),
                "cursor": {"next": offset + limit} if has_more else {"done": True},
            }
        )

    return results


@test()
def test_find_insns():
    """find_insns instruction sequence search works"""
    # Search for a common instruction (ret) - architecture independent name check
    result = find_insns(["ret"])
    assert len(result) == 1, f"Expected 1 result, got {len(result)}"
    assert_has_keys(result[0], "sequence", "matches", "count", "cursor")
    assert_is_list(result[0]["matches"])
    # Most binaries have at least one ret instruction


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
) -> list[dict]:
    """Get control flow graph basic blocks for functions"""
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
            has_more = offset + max_blocks < total_blocks

            results.append(
                {
                    "addr": fn_addr,
                    "blocks": blocks,
                    "count": len(blocks),
                    "total_blocks": total_blocks,
                    "cursor": (
                        {"next": offset + max_blocks} if has_more else {"done": True}
                    ),
                    "error": None,
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


@test()
def test_basic_blocks():
    """basic_blocks returns CFG blocks"""
    func_addr = get_any_function()
    if not func_addr:
        return
    result = basic_blocks(func_addr)
    assert len(result) == 1, f"Expected 1 result, got {len(result)}"
    assert_has_keys(result[0], "addr", "blocks", "count", "cursor")
    assert_is_list(result[0]["blocks"])
    # Every function has at least one basic block
    if result[0]["count"] > 0:
        assert_has_keys(
            result[0]["blocks"][0],
            "start",
            "end",
            "size",
            "type",
            "successors",
            "predecessors",
        )


@tool
@idasync
def find_paths(queries: list[PathQuery] | PathQuery) -> list[dict]:
    """Find execution paths between source and target addresses"""
    if isinstance(queries, dict):
        queries = [queries]
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


@test()
def test_find_paths_same_function():
    """find_paths returns paths within a function"""
    func_addr = get_any_function()
    if not func_addr:
        return
    # Query path from function start to itself (trivial path)
    result = find_paths({"source": func_addr, "target": func_addr})
    assert_is_list(result, min_length=1)
    assert_has_keys(result[0], "source", "target", "paths", "reachable")
    # Path to itself is always reachable
    assert result[0]["reachable"] is True


@test()
def test_find_paths_invalid_source():
    """find_paths handles invalid source address"""
    result = find_paths(
        {"source": "0xDEADBEEFDEADBEEF", "target": "0xDEADBEEFDEADBEEF"}
    )
    assert_is_list(result, min_length=1)
    # Should have error or reachable=False
    assert result[0].get("error") is not None or result[0]["reachable"] is False


# ============================================================================
# Search Operations
# ============================================================================


@tool
@idasync
def search(
    type: Annotated[
        str, "Search type: 'string', 'immediate', 'data_ref', or 'code_ref'"
    ],
    targets: Annotated[
        list[str | int] | str | int, "Search targets (strings, integers, or addresses)"
    ],
    limit: Annotated[int, "Max matches per target (default: 1000, max: 10000)"] = 1000,
    offset: Annotated[int, "Skip first N matches (default: 0)"] = 0,
) -> list[dict]:
    """Search for patterns in the binary (strings, immediate values, or references)"""
    if not isinstance(targets, list):
        targets = [targets]

    # Enforce max limit to prevent token overflow
    if limit <= 0 or limit > 10000:
        limit = 10000

    results = []

    if type == "string":
        # Search for strings containing pattern
        all_strings = _get_cached_strings_dict()
        for pattern in targets:
            pattern_str = str(pattern)
            all_matches = [
                s["addr"]
                for s in all_strings
                if pattern_str.lower() in s["string"].lower()
            ]

            # Apply pagination
            matches = all_matches[offset : offset + limit]
            has_more = offset + limit < len(all_matches)

            results.append(
                {
                    "query": pattern_str,
                    "matches": matches,
                    "count": len(matches),
                    "cursor": {"next": offset + limit} if has_more else {"done": True},
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

            all_matches = []
            try:
                ea = ida_ida.inf_get_min_ea()
                while ea < ida_ida.inf_get_max_ea():
                    result = ida_search.find_imm(ea, ida_search.SEARCH_DOWN, value)
                    if result[0] == idaapi.BADADDR:
                        break
                    all_matches.append(hex(result[0]))
                    ea = result[0] + 1
            except Exception:
                pass

            # Apply pagination
            matches = all_matches[offset : offset + limit]
            has_more = offset + limit < len(all_matches)

            results.append(
                {
                    "query": value,
                    "matches": matches,
                    "count": len(matches),
                    "cursor": {"next": offset + limit} if has_more else {"done": True},
                    "error": None,
                }
            )

    elif type == "data_ref":
        # Find all data references to targets
        for target_str in targets:
            try:
                target = parse_address(str(target_str))
                all_matches = [hex(xref) for xref in idautils.DataRefsTo(target)]

                # Apply pagination
                if limit > 0:
                    matches = all_matches[offset : offset + limit]
                    has_more = offset + limit < len(all_matches)
                else:
                    matches = all_matches[offset:]
                    has_more = False

                results.append(
                    {
                        "query": str(target_str),
                        "matches": matches,
                        "count": len(matches),
                        "cursor": (
                            {"next": offset + limit} if has_more else {"done": True}
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
                all_matches = [hex(xref) for xref in idautils.CodeRefsTo(target, 0)]

                # Apply pagination
                if limit > 0:
                    matches = all_matches[offset : offset + limit]
                    has_more = offset + limit < len(all_matches)
                else:
                    matches = all_matches[offset:]
                    has_more = False

                results.append(
                    {
                        "query": str(target_str),
                        "matches": matches,
                        "count": len(matches),
                        "cursor": (
                            {"next": offset + limit} if has_more else {"done": True}
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


@test()
def test_search_string():
    """search finds strings containing pattern"""
    # Search for a common string pattern (empty pattern matches all)
    result = search(type="string", targets=[""])
    assert_is_list(result, min_length=1)
    assert_has_keys(result[0], "query", "matches", "count", "cursor")
    assert_is_list(result[0]["matches"])


@test()
def test_search_immediate():
    """search finds immediate values"""
    # Search for 0 - a common immediate value in most binaries
    result = search(type="immediate", targets=[0])
    assert_is_list(result, min_length=1)
    assert_has_keys(result[0], "query", "matches", "count", "cursor")
    assert_is_list(result[0]["matches"])


@test()
def test_search_code_ref():
    """search finds code references"""
    func_addr = get_any_function()
    if not func_addr:
        return
    result = search(type="code_ref", targets=[func_addr])
    assert_is_list(result, min_length=1)
    assert_has_keys(result[0], "query", "matches", "count", "cursor")
    assert_is_list(result[0]["matches"])


@test()
def test_search_invalid_type():
    """search returns error for invalid type"""
    result = search(type="invalid_type", targets=["test"])
    assert_is_list(result, min_length=1)
    assert result[0].get("error") is not None


@tool
@idasync
def find_insn_operands(
    patterns: list[InsnPattern] | InsnPattern,
    limit: Annotated[int, "Max matches per pattern (default: 1000, max: 10000)"] = 1000,
    offset: Annotated[int, "Skip first N matches (default: 0)"] = 0,
) -> list[dict]:
    """Find instructions with specific mnemonics and operand values"""
    if isinstance(patterns, dict):
        patterns = [patterns]

    # Enforce max limit
    if limit <= 0 or limit > 10000:
        limit = 10000

    results = []
    for pattern in patterns:
        all_matches = _find_insn_pattern(pattern)

        # Apply pagination
        if limit > 0:
            matches = all_matches[offset : offset + limit]
            has_more = offset + limit < len(all_matches)
        else:
            matches = all_matches[offset:]
            has_more = False

        results.append(
            {
                "pattern": pattern,
                "matches": matches,
                "count": len(matches),
                "cursor": {"next": offset + limit} if has_more else {"done": True},
            }
        )
    return results


def _find_insn_pattern(pattern: dict) -> list[str]:
    """Internal helper to find instructions matching a pattern"""
    mnem = pattern.get("mnem", "").lower()
    op0_val = pattern.get("op0")
    op1_val = pattern.get("op1")
    op2_val = pattern.get("op2")
    any_val = pattern.get("op_any")

    matches = []

    # Scan all executable segments
    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        if not seg or not (seg.perm & idaapi.SEGPERM_EXEC):
            continue

        ea = seg.start_ea
        while ea < seg.end_ea:
            # Check mnemonic
            if mnem and idc.print_insn_mnem(ea).lower() != mnem:
                ea = idc.next_head(ea, seg.end_ea)
                if ea == idaapi.BADADDR:
                    break
                continue

            # Check specific operand positions
            match = True
            if op0_val is not None:
                if idc.get_operand_value(ea, 0) != op0_val:
                    match = False

            if op1_val is not None:
                if idc.get_operand_value(ea, 1) != op1_val:
                    match = False

            if op2_val is not None:
                if idc.get_operand_value(ea, 2) != op2_val:
                    match = False

            # Check any operand
            if any_val is not None and match:
                found_any = False
                for i in range(8):
                    if idc.get_operand_type(ea, i) == idaapi.o_void:
                        break
                    if idc.get_operand_value(ea, i) == any_val:
                        found_any = True
                        break
                if not found_any:
                    match = False

            if match:
                matches.append(hex(ea))

            ea = idc.next_head(ea, seg.end_ea)
            if ea == idaapi.BADADDR:
                break

    return matches


@test()
def test_find_insn_operands_mnem_only():
    """find_insn_operands finds instructions by mnemonic"""
    # Search for 'ret' instruction - common in most binaries
    result = find_insn_operands({"mnem": "ret"})
    assert_is_list(result, min_length=1)
    assert_has_keys(result[0], "pattern", "matches", "count", "cursor")
    assert_is_list(result[0]["matches"])


@test()
def test_find_insn_operands_with_operand():
    """find_insn_operands handles operand filtering"""
    # Search for any instruction - just verify the structure is correct
    result = find_insn_operands({"mnem": "nop"})
    assert_is_list(result, min_length=1)
    assert_has_keys(result[0], "pattern", "matches", "count", "cursor")


@test()
def test_find_insn_operands_batch():
    """find_insn_operands handles multiple patterns"""
    result = find_insn_operands([{"mnem": "ret"}, {"mnem": "nop"}])
    assert_is_list(result, min_length=2)
    for item in result:
        assert_has_keys(item, "pattern", "matches", "count", "cursor")


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
) -> dict:
    """Export function data in various formats"""
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


@test()
def test_export_funcs_json():
    """export_funcs returns function data in json format"""
    func_addr = get_any_function()
    if not func_addr:
        return
    result = export_funcs([func_addr])
    assert_has_keys(result, "format", "functions")
    assert result["format"] == "json"
    assert_is_list(result["functions"], min_length=1)
    # Check structure of function data
    assert_has_keys(result["functions"][0], "addr", "name", "prototype", "size")


@test()
def test_export_funcs_c_header():
    """export_funcs generates c_header format"""
    func_addr = get_any_function()
    if not func_addr:
        return
    result = export_funcs([func_addr], format="c_header")
    assert_has_keys(result, "format", "content")
    assert result["format"] == "c_header"
    assert isinstance(result["content"], str)


@test()
def test_export_funcs_prototypes():
    """export_funcs generates prototypes format"""
    func_addr = get_any_function()
    if not func_addr:
        return
    result = export_funcs([func_addr], format="prototypes")
    assert_has_keys(result, "format", "functions")
    assert result["format"] == "prototypes"
    assert_is_list(result["functions"])


@test()
def test_export_funcs_invalid_address():
    """export_funcs handles invalid address"""
    result = export_funcs(["0xDEADBEEFDEADBEEF"])
    assert_has_keys(result, "format", "functions")
    assert_is_list(result["functions"], min_length=1)
    assert result["functions"][0].get("error") is not None


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
) -> list[dict]:
    """Build call graph starting from root functions"""
    roots = normalize_list_input(roots)
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
                nodes[hex(addr)] = {
                    "addr": hex(addr),
                    "name": func_name,
                    "depth": depth,
                }

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


@test()
def test_callgraph():
    """callgraph call graph traversal works"""
    func_addr = get_any_function()
    if not func_addr:
        return
    result = callgraph(func_addr, max_depth=2)
    assert len(result) == 1, f"Expected 1 result, got {len(result)}"
    assert_has_keys(result[0], "root", "nodes", "edges", "max_depth")
    assert_is_list(result[0]["nodes"])
    assert_is_list(result[0]["edges"])
    # Root node should at least contain itself
    if len(result[0]["nodes"]) > 0:
        assert_has_keys(result[0]["nodes"][0], "addr", "name", "depth")


# ============================================================================
# Cross-Reference Matrix
# ============================================================================


@tool
@idasync
def xref_matrix(
    entities: Annotated[
        list[str] | str, "Addresses to build cross-reference matrix for"
    ],
) -> dict:
    """Build matrix showing cross-references between entities"""
    entities = normalize_list_input(entities)
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


@test()
def test_xref_matrix_single_entity():
    """xref_matrix returns matrix structure for single entity"""
    func_addr = get_any_function()
    if not func_addr:
        return
    result = xref_matrix([func_addr])
    assert_has_keys(result, "matrix", "entities")
    assert isinstance(result["matrix"], dict)
    assert_is_list(result["entities"], min_length=1)


@test()
def test_xref_matrix_multiple_entities():
    """xref_matrix handles multiple entities"""
    # Get first two functions if available
    funcs = []
    for ea in idautils.Functions():
        funcs.append(hex(ea))
        if len(funcs) >= 2:
            break
    if len(funcs) < 2:
        return
    result = xref_matrix(funcs)
    assert_has_keys(result, "matrix", "entities")
    assert isinstance(result["matrix"], dict)
    assert_is_list(result["entities"], min_length=2)


@test()
def test_xref_matrix_invalid_address():
    """xref_matrix handles invalid address gracefully"""
    result = xref_matrix(["0xDEADBEEFDEADBEEF"])
    assert_has_keys(result, "matrix", "entities")
    # Should have error in matrix for invalid address
    assert "0xDEADBEEFDEADBEEF" in result["matrix"]


# ============================================================================
# String Analysis
# ============================================================================


@tool
@idasync
def analyze_strings(
    filters: list[StringFilter] | StringFilter,
    limit: Annotated[int, "Max matches per filter (default: 1000, max: 10000)"] = 1000,
    offset: Annotated[int, "Skip first N matches (default: 0)"] = 0,
) -> list[dict]:
    """Analyze and filter strings in the binary"""
    if isinstance(filters, dict):
        filters = [filters]

    # Enforce max limit
    if limit <= 0 or limit > 10000:
        limit = 10000

    # Use cached strings to avoid rebuilding on every call
    all_strings = _get_cached_strings_dict()

    results = []

    for filt in filters:
        pattern = filt.get("pattern", "").lower()
        min_length = filt.get("min_length", 0)

        # Find all matching strings
        all_matches = []
        for s in all_strings:
            if len(s["string"]) < min_length:
                continue
            if pattern and pattern not in s["string"].lower():
                continue

            # Add xref info
            s_ea = parse_address(s["addr"])
            xrefs = [hex(x.frm) for x in idautils.XrefsTo(s_ea, 0)]
            all_matches.append({**s, "xrefs": xrefs, "xref_count": len(xrefs)})

        # Apply pagination
        if limit > 0:
            matches = all_matches[offset : offset + limit]
            has_more = offset + limit < len(all_matches)
        else:
            matches = all_matches[offset:]
            has_more = False

        results.append(
            {
                "filter": filt,
                "matches": matches,
                "count": len(matches),
                "cursor": {"next": offset + limit} if has_more else {"done": True},
            }
        )

    return results


@test()
def test_analyze_strings_empty_filter():
    """analyze_strings returns strings with empty filter"""
    result = analyze_strings({})
    assert_is_list(result, min_length=1)
    assert_has_keys(result[0], "filter", "matches", "count", "cursor")
    assert_is_list(result[0]["matches"])


@test()
def test_analyze_strings_pattern():
    """analyze_strings filters by pattern"""
    # Get any string first to know what to search for
    str_addr = get_any_string()
    if not str_addr:
        return
    # Just test that pattern filtering works (may find nothing if no matches)
    result = analyze_strings({"pattern": "a"})
    assert_is_list(result, min_length=1)
    assert_has_keys(result[0], "filter", "matches", "count", "cursor")


@test()
def test_analyze_strings_min_length():
    """analyze_strings filters by min_length"""
    result = analyze_strings({"min_length": 5})
    assert_is_list(result, min_length=1)
    assert_has_keys(result[0], "filter", "matches", "count", "cursor")
    # All matches should have length >= 5
    for match in result[0]["matches"]:
        assert len(match["string"]) >= 5


@test()
def test_analyze_strings_batch():
    """analyze_strings handles multiple filters"""
    result = analyze_strings([{"pattern": "a"}, {"min_length": 10}])
    assert_is_list(result, min_length=2)
    for item in result:
        assert_has_keys(item, "filter", "matches", "count", "cursor")
