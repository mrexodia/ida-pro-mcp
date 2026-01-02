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
from ..api_analysis import *

# Import sync module for IDAError
from ..sync import IDAError


# ============================================================================
# Tests
# ============================================================================

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


@test()
def test_entrypoints():
    """entrypoints returns entry points list"""
    result = entrypoints()
    # Result is a list of Function dicts (may be empty for some binaries)
    assert_is_list(result)
    # If there are entry points, they should have proper structure
    if len(result) > 0:
        assert_has_keys(result[0], "addr", "name")


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


@test()
def test_find_bytes():
    """find_bytes byte pattern search works"""
    # Search for a common byte sequence (0x00 0x00) that should exist in most binaries
    result = find_bytes("00 00")
    assert len(result) == 1, f"Expected 1 result, got {len(result)}"
    assert_has_keys(result[0], "pattern", "matches", "count", "cursor")
    assert_is_list(result[0]["matches"])


@test()
def test_find_insns():
    """find_insns instruction sequence search works"""
    # Search for a common instruction (ret) - architecture independent name check
    result = find_insns(["ret"])
    assert len(result) == 1, f"Expected 1 result, got {len(result)}"
    assert_has_keys(result[0], "sequence", "matches", "count", "cursor")
    assert_is_list(result[0]["matches"])


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


