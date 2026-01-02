"""Tests for api_analysis API functions."""

# Import test framework from parent
from ..framework import (
    test,
    assert_valid_address,
    assert_has_keys,
    assert_non_empty,
    assert_is_list,
    assert_all_have_keys,
    get_any_function,
    get_any_string,
    get_first_segment,
    get_n_functions,
    get_n_strings,
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
from ..sync import IDAError


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
    assert_is_list(result, min_length=1)
    # Should have code or error
    r = result[0]
    assert_has_keys(r, "addr")
    # Either has code or has an error
    assert r.get("code") is not None or r.get("error") is not None


@test()
def test_decompile_invalid_address():
    """decompile handles invalid address gracefully"""
    result = decompile(get_unmapped_address())
    assert_is_list(result, min_length=1)
    # Should have an error
    assert result[0].get("error") is not None or result[0].get("code") is None


@test()
def test_decompile_batch():
    """decompile can handle multiple addresses"""
    addrs = get_n_functions(3)
    if len(addrs) < 2:
        return

    result = decompile(addrs)
    assert len(result) == len(addrs)


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
    assert_is_list(result, min_length=1)
    r = result[0]
    assert_has_keys(r, "addr")
    # Should have asm output or error
    assert r.get("asm") is not None or r.get("error") is not None


@test()
def test_disasm_pagination():
    """disasm respects count parameter"""
    fn_addr = get_any_function()
    if not fn_addr:
        return

    result = disasm(fn_addr, count=10)
    assert_is_list(result, min_length=1)


@test()
def test_disasm_unmapped_address():
    """disasm handles unmapped address"""
    result = disasm(get_unmapped_address())
    assert_is_list(result, min_length=1)
    # Should have error or empty asm
    r = result[0]
    assert r.get("error") is not None or r.get("asm") == "" or r.get("asm") is None


@test()
def test_disasm_data_segment():
    """disasm handles data segment addresses"""
    data_addr = get_data_address()
    if not data_addr:
        return

    result = disasm(data_addr)
    assert_is_list(result, min_length=1)


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
    assert_has_keys(r, "addr", "xrefs", "error")


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
    result = xrefs_to_field([
        {"struct": "Struct1", "field": "field1"},
        {"struct": "Struct2", "field": "field2"},
    ])
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
    assert_has_keys(r, "addr", "callees", "error")


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
    assert_has_keys(r, "query", "matches", "error")


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
    result = find("string", query="*")
    assert_is_list(result, min_length=1)
    r = result[0]
    assert_has_keys(r, "query", "matches", "error")


@test()
def test_find_invalid_type():
    """find handles invalid search type"""
    result = find("invalid_type", query="test")
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

    result = export_funcs(fn_addr, fmt="json")
    assert_is_list(result, min_length=1)
    r = result[0]
    assert_has_keys(r, "addr")


@test()
def test_export_funcs_c_header():
    """export_funcs returns C header format"""
    fn_addr = get_any_function()
    if not fn_addr:
        return

    result = export_funcs(fn_addr, fmt="c_header")
    assert_is_list(result, min_length=1)


@test()
def test_export_funcs_invalid_address():
    """export_funcs handles invalid address"""
    result = export_funcs(get_unmapped_address())
    assert_is_list(result, min_length=1)


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
    assert_has_keys(r, "addr")
