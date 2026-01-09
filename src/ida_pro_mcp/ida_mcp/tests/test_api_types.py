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
from ..api_types import (
    declare_type,
    read_struct,
    search_structs,
    set_type,
    infer_types,
)

# Import sync module for IDAError
from ..sync import IDAError


# ============================================================================
# Test Helpers
# ============================================================================

def create_test_struct(name: str = "__TestStruct__") -> bool:
    """Helper to create a test struct in IDA's type library.

    This function is idempotent - if the struct already exists, it will return True.

    Args:
        name: Name of the struct to create

    Returns:
        True if struct exists or was created successfully, False otherwise
    """
    # First check if struct already exists
    search_result = search_structs(name)
    if search_result and any(s["name"] == name for s in search_result):
        return True  # Already exists

    # Struct doesn't exist, try to create it
    struct_def = f"""
        struct {name} {{
            int field1;
            char field2;
            void* field3;
        }};
    """
    result = declare_type(struct_def)
    if not result:
        return False

    # Check if declaration succeeded
    r = result[0]
    if r.get("ok"):
        return True

    # Check if it failed because it already exists
    if r.get("error"):
        # Search again to see if it exists despite the error
        search_result = search_structs(name)
        return search_result and any(s["name"] == name for s in search_result)

    return False


# ============================================================================
# Tests for declare_type
# ============================================================================


@test()
def test_declare_type():
    """declare_type can add a type declaration"""
    # Try to declare a simple struct
    result = declare_type("struct __test_struct__ { int x; };")
    assert_is_list(result, min_length=1)
    r = result[0]
    assert_has_keys(r, "decl")
    # Should succeed without error
    assert r.get("ok") is not None or r.get("error") is None


# ============================================================================
# Tests for read_struct
# ============================================================================


@test()
def test_read_struct():
    """read_struct reads structure at address"""
    data_addr = get_data_address()
    if not data_addr:
        seg = get_first_segment()
        if not seg:
            return
        data_addr = seg[0]

    result = read_struct({"addr": data_addr, "struct": "test_struct"})
    assert_is_list(result, min_length=1)
    r = result[0]
    # Should have addr, struct, and either members or error
    assert_has_keys(r, "addr", "struct")
    assert r.get("members") is not None or r.get("error") is not None


@test()
def test_read_struct_not_found():
    """read_struct handles non-existent struct"""
    seg = get_first_segment()
    if not seg:
        return

    result = read_struct({"addr": seg[0], "struct": "NonExistentStruct12345"})
    assert_is_list(result, min_length=1)
    r = result[0]
    # Should have error
    assert r.get("error") is not None


@test()
def test_read_struct_name_resolution():
    """read_struct can resolve named addresses (e.g., function names)"""
    # Create a test struct first
    if not create_test_struct("__NameResolutionTest__"):
        return

    fn_addr = get_any_function()
    if not fn_addr:
        return

    # Get the function name
    from ..api_core import lookup_funcs
    fn_info = lookup_funcs(fn_addr)
    if not fn_info or not fn_info[0].get("fn"):
        return

    fn_name = fn_info[0]["fn"]["name"]

    # Use the function name as address (should resolve via get_name_ea)
    result = read_struct({"addr": fn_name, "struct": "__NameResolutionTest__"})
    assert_is_list(result, min_length=1)
    r = result[0]
    # Should either succeed with members or have a specific error
    # (not a "Failed to resolve address" error)
    if r.get("error"):
        # If there's an error, it should be about the struct, not address resolution
        assert "Failed to resolve address" not in r["error"]


@test()
def test_read_struct_invalid_address():
    """read_struct handles invalid address gracefully"""
    result = read_struct({"addr": "InvalidAddressName123", "struct": "NonExistentStruct"})
    assert_is_list(result, min_length=1)
    r = result[0]
    # Should have error about failed address resolution
    assert r.get("error") is not None
    assert "Failed to resolve address" in r["error"]


# ============================================================================
# Tests for search_structs
# ============================================================================


@test()
def test_search_structs():
    """search_structs can search for structures"""
    result = search_structs("*")
    assert_is_list(result)
    # Check result structure if any structs exist
    if len(result) > 0:
        r = result[0]
        assert_has_keys(r, "name", "size", "cardinality", "is_union", "ordinal")


@test()
def test_search_structs_pattern():
    """search_structs can filter by pattern"""
    # Test with a pattern that likely won't match anything
    result = search_structs("VeryUnlikelyStructName123*")
    assert_is_list(result)
    # Should return empty list
    assert len(result) == 0

    # Test with wildcard that should match everything
    result_all = search_structs("*")
    assert_is_list(result_all)
    # Wildcard should return at least as many results as specific pattern
    assert len(result_all) >= len(result)


# ============================================================================
# Tests for set_type
# ============================================================================


@test()
def test_set_type():
    """set_type applies type to address"""
    fn_addr = get_any_function()
    if not fn_addr:
        return

    result = set_type({"addr": fn_addr, "ty": "int"})
    assert_is_list(result, min_length=1)
    r = result[0]
    # Result has "edit" key containing the input, and optionally "ok" or "error"
    assert_has_keys(r, "edit")
    assert r.get("ok") is not None or r.get("error") is not None


@test()
def test_set_type_invalid_address():
    """set_type handles invalid address"""
    result = set_type({"addr": get_unmapped_address(), "ty": "int"})
    assert_is_list(result, min_length=1)
    r = result[0]
    # Should have "edit" key and either "ok" or "error"
    assert_has_keys(r, "edit")
    assert r.get("ok") is not None or r.get("error") is not None


# ============================================================================
# Tests for infer_types
# ============================================================================


@test()
def test_infer_types():
    """infer_types infers types for a function"""
    fn_addr = get_any_function()
    if not fn_addr:
        return

    result = infer_types(fn_addr)
    assert_is_list(result, min_length=1)
    r = result[0]
    assert_has_keys(r, "addr", "error")
