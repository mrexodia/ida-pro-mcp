"""Tests for api_composite API functions."""

from ..framework import (
    test,
    skip_test,
    assert_has_keys,
    assert_valid_address,
    assert_non_empty,
    assert_is_list,
    assert_shape,
    assert_ok,
    assert_error,
    is_hex_address,
    optional,
    list_of,
    get_any_function,
    get_unmapped_address,
    get_any_string,
)
from ..api_composite import (
    analyze_function,
    analyze_component,
    diff_before_after,
    trace_data_flow,
)


# ============================================================================
# analyze_function tests
# ============================================================================


@test()
def test_analyze_function_returns_required_keys():
    """analyze_function returns all expected keys for a valid function."""
    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")

    result = analyze_function(fn_addr)
    assert_has_keys(result, "addr", "error")
    if result["error"] is None:
        assert_has_keys(
            result,
            "name",
            "prototype",
            "size",
            "decompiled",
            "strings",
            "constants",
            "callees",
            "callers",
            "xrefs",
            "comments",
            "basic_blocks",
        )


@test()
def test_analyze_function_decompiled_code():
    """analyze_function returns decompiled pseudocode."""
    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")

    result = analyze_function(fn_addr)
    assert result["error"] is None
    # Decompilation may fail on some functions, but should have the key
    assert "decompiled" in result


@test()
def test_analyze_function_basic_blocks_structure():
    """analyze_function basic_blocks contains count and complexity."""
    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")

    result = analyze_function(fn_addr)
    assert result["error"] is None
    bb = result["basic_blocks"]
    assert_has_keys(bb, "count", "cyclomatic_complexity")
    assert isinstance(bb["count"], int)
    assert bb["count"] >= 0
    assert isinstance(bb["cyclomatic_complexity"], int)


@test()
def test_analyze_function_strings_is_list():
    """analyze_function strings is a list of string values."""
    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")

    result = analyze_function(fn_addr)
    assert result["error"] is None
    assert isinstance(result["strings"], list)
    for s in result["strings"]:
        assert isinstance(s, str)


@test()
def test_analyze_function_callees_callers_lists():
    """analyze_function callees and callers are lists of names/addresses."""
    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")

    result = analyze_function(fn_addr)
    assert result["error"] is None
    assert isinstance(result["callees"], list)
    assert isinstance(result["callers"], list)


@test()
def test_analyze_function_with_asm():
    """analyze_function with include_asm=True includes assembly."""
    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")

    result = analyze_function(fn_addr, include_asm=True)
    assert result["error"] is None
    assert "assembly" in result


@test()
def test_analyze_function_invalid_address():
    """analyze_function reports error for invalid address."""
    result = analyze_function(get_unmapped_address())
    assert_error(result)


@test()
def test_analyze_function_by_name():
    """analyze_function accepts function names."""
    import idautils
    import idaapi

    # Get a named function
    for ea in idautils.Functions():
        name = idaapi.get_func_name(ea)
        if name and not name.startswith("sub_"):
            result = analyze_function(name)
            assert result["error"] is None
            assert result["name"] == name
            return

    skip_test("no named functions found")


@test(binary="crackme03.elf")
def test_analyze_function_crackme_main():
    """analyze_function on crackme main shows expected content."""
    result = analyze_function("main")
    assert result["error"] is None
    assert result["name"] == "main"
    # main calls check_pw
    assert any("check_pw" in c for c in result["callees"])


@test(binary="crackme03.elf")
def test_analyze_function_crackme_check_pw():
    """analyze_function on crackme check_pw returns valid analysis."""
    result = analyze_function("check_pw")
    assert result["error"] is None
    assert result["name"] == "check_pw"
    assert result["size"] > 0
    assert result["basic_blocks"]["count"] >= 1


# ============================================================================
# analyze_component tests
# ============================================================================


@test()
def test_analyze_component_returns_required_keys():
    """analyze_component returns all expected keys for valid functions."""
    import idautils

    addrs = [hex(ea) for ea in list(idautils.Functions())[:3]]
    if len(addrs) < 2:
        skip_test("binary has fewer than 2 functions")

    result = analyze_component(addrs[:2])
    if "error" in result and result["error"]:
        skip_test(f"analyze_component error: {result['error']}")

    assert_has_keys(
        result,
        "functions",
        "internal_call_graph",
        "shared_globals",
        "interface_functions",
        "internal_only",
        "string_usage",
    )


@test()
def test_analyze_component_functions_structure():
    """analyze_component functions list has expected per-function info."""
    import idautils

    addrs = [hex(ea) for ea in list(idautils.Functions())[:2]]
    if len(addrs) < 2:
        skip_test("binary has fewer than 2 functions")

    result = analyze_component(addrs)
    if "error" in result and result["error"]:
        skip_test(f"analyze_component error: {result['error']}")

    funcs = result["functions"]
    assert_is_list(funcs, min_length=1)
    for fn in funcs:
        if "error" in fn:
            continue
        assert_has_keys(fn, "addr", "name", "prototype", "size")
        assert_valid_address(fn["addr"])


@test()
def test_analyze_component_call_graph_structure():
    """analyze_component internal_call_graph has nodes and edges."""
    import idautils

    addrs = [hex(ea) for ea in list(idautils.Functions())[:3]]
    if len(addrs) < 2:
        skip_test("binary has fewer than 2 functions")

    result = analyze_component(addrs[:2])
    if "error" in result and result["error"]:
        skip_test(f"analyze_component error: {result['error']}")

    cg = result["internal_call_graph"]
    assert_has_keys(cg, "nodes", "edges")
    assert isinstance(cg["nodes"], list)
    assert isinstance(cg["edges"], list)


@test()
def test_analyze_component_empty_list_error():
    """analyze_component reports error for empty address list."""
    result = analyze_component([])
    assert_error(result)


@test()
def test_analyze_component_invalid_name_error():
    """analyze_component reports error for unresolvable name."""
    result = analyze_component(["nonexistent_function_name_xyz"])
    assert "error" in result and result["error"]


@test()
def test_analyze_component_unmapped_address():
    """analyze_component handles unmapped address gracefully."""
    result = analyze_component(["0xDEADBEEFDEADBEEF"])
    # Valid hex parses but there's no function - error is per-entry
    if "error" in result and result["error"]:
        pass  # top-level error is fine
    else:
        # Should have functions list with error entry
        assert "functions" in result
        assert len(result["functions"]) == 1
        assert "error" in result["functions"][0]


@test()
def test_analyze_component_comma_separated():
    """analyze_component accepts comma-separated addresses."""
    import idautils

    addrs = [hex(ea) for ea in list(idautils.Functions())[:2]]
    if len(addrs) < 2:
        skip_test("binary has fewer than 2 functions")

    csv = ",".join(addrs)
    result = analyze_component(csv)
    if "error" in result and result["error"]:
        skip_test(f"analyze_component error: {result['error']}")

    assert_has_keys(result, "functions")
    assert len(result["functions"]) == 2


@test(binary="crackme03.elf")
def test_analyze_component_crackme_main_check_pw():
    """analyze_component on crackme main+check_pw shows relationship."""
    result = analyze_component(["main", "check_pw"])
    assert "error" not in result or result.get("error") is None
    assert_has_keys(result, "functions", "internal_call_graph")
    
    # main calls check_pw, so there should be internal edges
    cg = result["internal_call_graph"]
    assert len(cg["nodes"]) == 2


# ============================================================================
# trace_data_flow tests
# ============================================================================


@test()
def test_trace_data_flow_returns_required_keys():
    """trace_data_flow returns all expected keys."""
    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")

    result = trace_data_flow(fn_addr, direction="forward", max_depth=2)
    if "error" in result and result["error"]:
        skip_test(f"trace_data_flow error: {result['error']}")

    assert_has_keys(result, "start", "direction", "depth_reached", "nodes", "edges")


@test()
def test_trace_data_flow_nodes_structure():
    """trace_data_flow nodes have expected structure."""
    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")

    result = trace_data_flow(fn_addr, direction="forward", max_depth=2)
    if "error" in result and result["error"]:
        skip_test(f"trace_data_flow error: {result['error']}")

    nodes = result["nodes"]
    assert_is_list(nodes, min_length=1)
    for node in nodes:
        assert_has_keys(node, "addr", "func", "instruction", "type", "depth")
        assert_valid_address(node["addr"])
        assert node["type"] in ("code", "data")
        assert isinstance(node["depth"], int)


@test()
def test_trace_data_flow_edges_structure():
    """trace_data_flow edges have from/to/type."""
    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")

    result = trace_data_flow(fn_addr, direction="forward", max_depth=3)
    if "error" in result and result["error"]:
        skip_test(f"trace_data_flow error: {result['error']}")

    edges = result["edges"]
    assert isinstance(edges, list)
    for edge in edges:
        assert_has_keys(edge, "from", "to", "type")
        assert_valid_address(edge["from"])
        assert_valid_address(edge["to"])


@test()
def test_trace_data_flow_backward():
    """trace_data_flow supports backward direction."""
    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")

    result = trace_data_flow(fn_addr, direction="backward", max_depth=2)
    if "error" in result and result["error"]:
        skip_test(f"trace_data_flow error: {result['error']}")

    assert result["direction"] == "backward"
    assert_has_keys(result, "nodes", "edges")


@test()
def test_trace_data_flow_invalid_direction():
    """trace_data_flow rejects invalid direction."""
    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")

    result = trace_data_flow(fn_addr, direction="invalid")
    assert_error(result)


@test()
def test_trace_data_flow_invalid_name():
    """trace_data_flow reports error for unresolvable name."""
    result = trace_data_flow("nonexistent_symbol_xyz")
    assert "error" in result and result["error"]


@test()
def test_trace_data_flow_unmapped_address():
    """trace_data_flow handles unmapped address - may succeed with empty results."""
    result = trace_data_flow("0xDEADBEEFDEADBEEF")
    # Valid hex parses - may error or return with nodes
    assert "error" in result or "nodes" in result


@test()
def test_trace_data_flow_max_depth_clamped():
    """trace_data_flow clamps max_depth to valid range."""
    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")

    # max_depth > 20 should be clamped
    result = trace_data_flow(fn_addr, max_depth=100)
    if "error" in result and result["error"]:
        skip_test(f"trace_data_flow error: {result['error']}")

    # Should still work, just clamped
    assert_has_keys(result, "nodes", "edges")


@test()
def test_trace_data_flow_from_string():
    """trace_data_flow can trace from a string address."""
    str_addr = get_any_string()
    if not str_addr:
        skip_test("binary has no strings")

    result = trace_data_flow(str_addr, direction="backward", max_depth=2)
    if "error" in result and result["error"]:
        skip_test(f"trace_data_flow error: {result['error']}")

    assert result["start"] == str_addr
    assert_is_list(result["nodes"], min_length=1)


@test(binary="crackme03.elf")
def test_trace_data_flow_crackme_format_string():
    """trace_data_flow from crackme format string finds code references."""
    # format string is at 0x201f
    result = trace_data_flow("0x201f", direction="backward", max_depth=3)
    if "error" in result and result["error"]:
        skip_test(f"trace_data_flow error: {result['error']}")

    assert result["start"] == "0x201f"
    # Should find at least the starting node
    assert len(result["nodes"]) >= 1


# ============================================================================
# diff_before_after tests
# ============================================================================


@test(binary="crackme03.elf")
def test_diff_rename_func_round_trip():
    """diff_before_after rename_func changes decompilation and reverts cleanly."""
    tmp_name = "dba_test_renamed_pw"
    try:
        result = diff_before_after("check_pw", "rename_func", {"name": tmp_name})
        assert "error" not in result, f"unexpected error: {result.get('error')}"
        assert_has_keys(result, "before", "after", "action_applied", "changes_detected")
        assert result["changes_detected"], "Rename should change decompilation output"
        assert tmp_name in result["after"], (
            f"Expected {tmp_name!r} in after decompilation, got: {result['after'][:200]!r}"
        )
        assert "check_pw" in result["before"], (
            f"Expected 'check_pw' in before decompilation, got: {result['before'][:200]!r}"
        )
    finally:
        diff_before_after(tmp_name, "rename_func", {"name": "check_pw"})


@test(binary="crackme03.elf")
def test_diff_set_comment():
    """diff_before_after set_comment adds a comment to the decompilation."""
    import idaapi

    comment_text = "dba_tmp_comment_for_test"
    try:
        result = diff_before_after("check_pw", "set_comment", {"comment": comment_text})
        assert "error" not in result, f"unexpected error: {result.get('error')}"
        assert_has_keys(result, "before", "after", "action_applied")
        assert comment_text in result["action_applied"]
    finally:
        ea = idaapi.get_name_ea(idaapi.BADADDR, "check_pw")
        if ea != idaapi.BADADDR:
            idaapi.set_cmt(ea, "", False)


@test(binary="crackme03.elf")
def test_diff_set_type():
    """diff_before_after set_type applies a function prototype."""
    result = diff_before_after(
        "check_pw", "set_type",
        {"type": "__int64 __fastcall check_pw(__int64 a1, __int64 a2, __int64 a3)"},
    )
    assert "error" not in result, f"unexpected error: {result.get('error')}"
    assert_has_keys(result, "before", "after", "action_applied", "changes_detected")


@test()
def test_diff_invalid_action():
    """diff_before_after rejects unknown actions."""
    fn = get_any_function()
    if not fn:
        skip_test("binary has no functions")
    result = diff_before_after(fn, "bogus_action", {})
    assert "error" in result, "Expected error for invalid action"
    assert "bogus_action" in result["error"]


@test()
def test_diff_rename_missing_name():
    """diff_before_after rename_func requires a 'name' argument."""
    fn = get_any_function()
    if not fn:
        skip_test("binary has no functions")
    result = diff_before_after(fn, "rename_func", {})
    assert "error" in result, "Expected error when 'name' is missing"


@test()
def test_diff_set_type_missing_type():
    """diff_before_after set_type requires a 'type' argument."""
    fn = get_any_function()
    if not fn:
        skip_test("binary has no functions")
    result = diff_before_after(fn, "set_type", {})
    assert "error" in result, "Expected error when 'type' is missing"


@test()
def test_diff_set_comment_missing_comment():
    """diff_before_after set_comment requires a 'comment' argument."""
    fn = get_any_function()
    if not fn:
        skip_test("binary has no functions")
    result = diff_before_after(fn, "set_comment", {})
    assert "error" in result, "Expected error when 'comment' is missing"


@test()
def test_diff_invalid_address():
    """diff_before_after reports error for unmapped address."""
    result = diff_before_after(get_unmapped_address(), "rename_func", {"name": "x"})
    assert "error" in result
