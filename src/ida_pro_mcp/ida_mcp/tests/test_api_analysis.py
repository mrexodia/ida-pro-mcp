"""Tests for api_analysis API functions."""

# Import test framework from parent
from ..framework import (
    test,
    assert_has_keys,
    assert_is_list,
    get_any_function,
    get_n_functions,
    get_data_address,
    get_unmapped_address,
    get_functions_with_calls,
    get_functions_with_callers,
)

# Import functions under test
from ..api_analysis import (
    decompile,
    disasm,
    xrefs_to,
    xrefs_to_field,
    callees,
    find_bytes,
    basic_blocks,
    find,
    export_funcs,
    callgraph,
)

# Import sync module for IDAError


# ============================================================================
# Tests for decompile
# ============================================================================


@test()
def test_decompile_valid_function():
    """decompile returns code for a valid function"""
    fn_addr = get_any_function()
    if not fn_addr:
        return

    result = decompile(fn_addr)
    assert isinstance(result, dict)
    assert_has_keys(result, "addr")
    # Either has code or has an error
    assert result.get("code") is not None or result.get("error") is not None


@test()
def test_decompile_invalid_address():
    """decompile handles invalid address gracefully"""
    result = decompile(get_unmapped_address())
    assert isinstance(result, dict)
    # Should have an error
    assert result.get("error") is not None or result.get("code") is None


@test()
def test_decompile_batch():
    """decompile can be called for multiple addresses"""
    addrs = get_n_functions(3)
    if len(addrs) < 2:
        return

    results = [decompile(addr) for addr in addrs]
    assert len(results) == len(addrs)
    for r in results:
        assert isinstance(r, dict)
        assert_has_keys(r, "addr")


@test()
def test_decompile_by_name():
    """decompile accepts a function name string"""
    import ida_funcs

    fn_addr = get_any_function()
    if not fn_addr:
        return

    name = ida_funcs.get_func_name(int(fn_addr, 16))
    if not name:
        return

    result = decompile(name)
    assert result.get("error") is None
    assert result.get("code") is not None


@test()
def test_decompile_unknown_name():
    """decompile returns error for unknown function name"""
    result = decompile("nonexistent_function_xyz")
    assert result.get("error") is not None
    assert "Function not found" in result["error"]


# ============================================================================
# Tests for disasm
# ============================================================================


@test()
def test_disasm_valid_function():
    """disasm returns assembly for a valid function"""
    fn_addr = get_any_function()
    if not fn_addr:
        return

    result = disasm(fn_addr)
    assert isinstance(result, dict)
    assert_has_keys(result, "addr")
    # Should have asm output or error
    assert result.get("asm") is not None or result.get("error") is not None


@test()
def test_disasm_pagination():
    """disasm respects max_instructions parameter"""
    fn_addr = get_any_function()
    if not fn_addr:
        return

    result = disasm(fn_addr, max_instructions=10)
    assert isinstance(result, dict)
    assert result.get("instruction_count", 0) <= 10


@test()
def test_disasm_unmapped_address():
    """disasm handles unmapped address"""
    result = disasm(get_unmapped_address())
    assert isinstance(result, dict)
    # Should have error or empty asm
    assert (
        result.get("error") is not None
        or result.get("asm") == ""
        or result.get("asm") is None
    )


@test()
def test_disasm_data_segment():
    """disasm handles data segment addresses"""
    data_addr = get_data_address()
    if not data_addr:
        return

    result = disasm(data_addr)
    assert isinstance(result, dict)
    assert_has_keys(result, "addr")


@test()
def test_disasm_by_name():
    """disasm accepts a function name string"""
    import ida_funcs

    fn_addr = get_any_function()
    if not fn_addr:
        return

    name = ida_funcs.get_func_name(int(fn_addr, 16))
    if not name:
        return

    result = disasm(name)
    assert result.get("error") is None
    assert result.get("asm") is not None


@test()
def test_disasm_unknown_name():
    """disasm returns error for unknown function name"""
    result = disasm("nonexistent_function_xyz")
    assert result.get("error") is not None
    assert "Function not found" in result["error"]


@test()
def test_disasm_interior_address_preserves_cursor():
    """disasm start_ea reflects the queried address for pagination, not func entry"""
    import idc
    import idaapi

    fn_addr = get_any_function()
    if not fn_addr:
        return

    ea = int(fn_addr, 16)
    func = idaapi.get_func(ea)
    if not func:
        return

    interior = idc.next_head(func.start_ea, func.end_ea)
    if interior == idaapi.BADADDR or interior == func.start_ea:
        return

    result = disasm(hex(interior))
    assert result.get("asm") is not None
    assert result["asm"]["start_ea"] == hex(interior)


# ============================================================================
# Tests for xrefs_to
# ============================================================================


@test()
def test_xrefs_to():
    """xrefs_to returns cross-references for a function"""
    fn_addrs = get_functions_with_callers()
    if not fn_addrs:
        # Fallback to any function
        fn_addr = get_any_function()
        if not fn_addr:
            return
    else:
        fn_addr = fn_addrs[0]

    result = xrefs_to(fn_addr)
    assert_is_list(result, min_length=1)
    r = result[0]
    assert_has_keys(r, "addr", "xrefs")


@test()
def test_xrefs_to_invalid():
    """xrefs_to handles invalid address"""
    result = xrefs_to(get_unmapped_address())
    assert_is_list(result, min_length=1)
    # Should return empty xrefs or error
    r = result[0]
    assert_has_keys(r, "addr")


# ============================================================================
# Tests for xrefs_to_field
# ============================================================================


@test()
def test_xrefs_to_field_nonexistent_struct():
    """xrefs_to_field handles non-existent struct"""
    result = xrefs_to_field({"struct": "NonExistentStruct", "field": "nonexistent"})
    assert_is_list(result, min_length=1)
    r = result[0]
    assert r.get("error") is not None


@test()
def test_xrefs_to_field_batch():
    """xrefs_to_field handles batch queries"""
    result = xrefs_to_field(
        [
            {"struct": "Struct1", "field": "field1"},
            {"struct": "Struct2", "field": "field2"},
        ]
    )
    assert_is_list(result, min_length=2)


# ============================================================================
# Tests for callees
# ============================================================================


@test()
def test_callees():
    """callees returns functions called by a function"""
    fn_addrs = get_functions_with_calls()
    if not fn_addrs:
        fn_addr = get_any_function()
        if not fn_addr:
            return
    else:
        fn_addr = fn_addrs[0]

    result = callees(fn_addr)
    assert_is_list(result, min_length=1)
    r = result[0]
    assert_has_keys(r, "addr", "callees")


@test()
def test_callees_multiple():
    """callees handles multiple addresses"""
    addrs = get_n_functions(3)
    if len(addrs) < 2:
        return

    result = callees(addrs)
    assert len(result) == len(addrs)


@test()
def test_callees_invalid_address():
    """callees handles invalid address"""
    result = callees(get_unmapped_address())
    assert_is_list(result, min_length=1)
    r = result[0]
    assert_has_keys(r, "addr")


# ============================================================================
# Tests for find_bytes
# ============================================================================


@test()
def test_find_bytes():
    """find_bytes can search for byte patterns"""
    # Search for common bytes that should exist
    result = find_bytes("00 00")
    assert_is_list(result, min_length=1)
    r = result[0]
    assert_has_keys(r, "pattern", "matches")


# ============================================================================
# Tests for basic_blocks
# ============================================================================


@test()
def test_basic_blocks():
    """basic_blocks returns blocks for a function"""
    fn_addr = get_any_function()
    if not fn_addr:
        return

    result = basic_blocks(fn_addr)
    assert_is_list(result, min_length=1)
    r = result[0]
    assert_has_keys(r, "addr", "blocks", "error")


# ============================================================================
# Tests for find
# ============================================================================


@test()
def test_find_string():
    """find can search for strings"""
    # Most binaries have some strings
    result = find("string", "*")
    assert_is_list(result, min_length=1)
    r = result[0]
    assert_has_keys(r, "query", "matches", "error")


@test()
def test_find_invalid_type():
    """find handles invalid search type"""
    result = find("invalid_type", "test")
    assert_is_list(result, min_length=1)
    r = result[0]
    # Should have error for invalid type
    assert r.get("error") is not None


# ============================================================================
# Tests for export_funcs
# ============================================================================


@test()
def test_export_funcs_json():
    """export_funcs returns JSON format"""
    fn_addr = get_any_function()
    if not fn_addr:
        return

    result = export_funcs(fn_addr, format="json")
    assert isinstance(result, dict)
    assert result.get("format") == "json"
    functions = result.get("functions", [])
    assert_is_list(functions, min_length=1)
    assert_has_keys(functions[0], "addr")


@test()
def test_export_funcs_c_header():
    """export_funcs returns C header format"""
    fn_addr = get_any_function()
    if not fn_addr:
        return

    result = export_funcs(fn_addr, format="c_header")
    assert isinstance(result, dict)
    assert result.get("format") == "c_header"
    assert isinstance(result.get("content"), str)


@test()
def test_export_funcs_invalid_address():
    """export_funcs handles invalid address"""
    result = export_funcs(get_unmapped_address(), format="json")
    assert isinstance(result, dict)
    assert result.get("format") == "json"
    functions = result.get("functions", [])
    assert_is_list(functions, min_length=1)
    assert functions[0].get("error") is not None


# ============================================================================
# Tests for callgraph
# ============================================================================


@test()
def test_callgraph():
    """callgraph returns call graph data"""
    fn_addr = get_any_function()
    if not fn_addr:
        return

    result = callgraph(fn_addr)
    assert_is_list(result, min_length=1)
    r = result[0]
    assert_has_keys(r, "root", "nodes", "edges")
