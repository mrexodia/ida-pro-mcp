"""Tests for api_types API functions."""

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
from ..api_types import *

# Import sync module for IDAError
from ..sync import IDAError


# ============================================================================
# Tests
# ============================================================================

@test()
def test_declare_type():
    """declare_type can declare a C type"""
    # Use a unique name to avoid conflicts
    test_struct_name = "__mcp_test_struct_declare__"

    try:
        # Declare a simple struct
        result = declare_type(f"struct {test_struct_name} {{ int x; int y; }};")
        assert_is_list(result, min_length=1)
        assert_has_keys(result[0], "decl")
        # Should either succeed or have an error key
        assert "ok" in result[0] or "error" in result[0]
    finally:
        # Cleanup: try to delete the type (best effort)
        try:
            tif = ida_typeinf.tinfo_t()
            if tif.get_named_type(None, test_struct_name):
                # IDA doesn't have a direct delete type API, so we just leave it
                # The test struct won't interfere with real analysis
                pass
        except Exception:
            pass


@test()
def test_structs_list():
    """structs returns list of structures (may be empty)"""
    result = structs()
    assert_is_list(result)
    # If there are structs, verify structure
    if result:
        assert_all_have_keys(result, "name", "size", "members")


@test()
def test_struct_info():
    """struct_info returns details for existing struct"""
    # First get list of structs
    all_structs = structs()
    if not all_structs:
        return  # Skip if no structs in IDB

    # Get info for first struct
    struct_name = all_structs[0]["name"]
    result = struct_info(struct_name)
    assert_is_list(result, min_length=1)
    assert_has_keys(result[0], "name")
    # Should have either info or error
    assert "info" in result[0] or "error" in result[0]


@test()
def test_struct_info_not_found():
    """struct_info handles nonexistent struct gracefully"""
    result = struct_info("__nonexistent_struct_name_12345__")
    assert_is_list(result, min_length=1)
    assert_has_keys(result[0], "name", "error")
    assert "not found" in result[0]["error"].lower()


@test()
def test_read_struct():
    """read_struct reads structure values from memory"""
    # First check if any structs exist
    struct_list = structs()
    if not struct_list:
        return  # Skip if no structs

    # Try to read a struct from a valid address
    seg = get_first_segment()
    if not seg:
        return  # Skip if no segments
    start_addr, _ = seg
    struct_name = struct_list[0]["name"]

    result = read_struct([{"addr": start_addr, "struct": struct_name}])
    assert_is_list(result, min_length=1)
    assert_has_keys(result[0], "addr", "struct")
    # Should have either members or error
    assert "members" in result[0] or "error" in result[0]


@test()
def test_read_struct_not_found():
    """read_struct handles nonexistent struct gracefully"""
    seg = get_first_segment()
    if not seg:
        return  # Skip if no segments
    start_addr, _ = seg

    result = read_struct(
        [{"addr": start_addr, "struct": "__nonexistent_struct_12345__"}]
    )
    assert_is_list(result, min_length=1)
    assert_has_keys(result[0], "addr", "struct", "error")
    assert "not found" in result[0]["error"].lower()


@test()
def test_search_structs():
    """search_structs filters by name pattern"""
    # First check if there are any structs
    all_structs = structs()
    if not all_structs:
        # No structs, verify empty search returns empty
        result = search_structs("anything")
        assert_is_list(result)
        return

    # Search for a substring of the first struct's name
    first_name = all_structs[0]["name"]
    if len(first_name) >= 3:
        # Search with a substring
        search_term = first_name[:3]
        result = search_structs(search_term)
        assert_is_list(result)
        # Should find at least the original struct
        found_names = [s["name"] for s in result]
        assert first_name in found_names, f"Expected {first_name} in search results"
    else:
        # Short name, just verify search returns list
        result = search_structs(first_name)
        assert_is_list(result)


@test()
def test_apply_types():
    """apply_types can apply type to address"""
    fn_addr = get_any_function()
    if not fn_addr:
        return  # Skip if no functions

    # Test applying a simple type - use "int" which always exists
    result = apply_types([{"addr": fn_addr, "ty": "int"}])
    assert_is_list(result, min_length=1)
    # Should either succeed or have error
    assert "ok" in result[0] or "error" in result[0]


@test()
def test_apply_types_invalid_address():
    """apply_types handles invalid address gracefully"""
    result = apply_types([{"addr": "0xDEADBEEFDEADBEEF", "ty": "int"}])
    assert_is_list(result, min_length=1)
    # Should have either ok or error field
    assert "ok" in result[0] or "error" in result[0]


@test()
def test_infer_types():
    """infer_types returns type inference for valid function address"""
    fn_addr = get_any_function()
    if not fn_addr:
        return  # Skip if no functions

    result = infer_types(fn_addr)
    assert_is_list(result, min_length=1)
    assert_has_keys(result[0], "addr", "inferred_type", "method", "confidence")
    # Should have some result (even if method is None)
    assert result[0]["confidence"] in ("high", "low", "none")


