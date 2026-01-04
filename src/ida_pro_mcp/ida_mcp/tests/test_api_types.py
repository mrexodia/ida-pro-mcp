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
# Tests for declare_type
# ============================================================================


@test()
def test_declare_type():
    """declare_type can add a type declaration"""
    # Try to declare a simple struct
    result = declare_type("struct __test_struct__ { int x; };")
    assert_is_list(result, min_length=1)
    r = result[0]
    assert_has_keys(r, "decl", "success", "error")


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
    assert_has_keys(r, "addr", "struct", "error")


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


# ============================================================================
# Tests for search_structs
# ============================================================================


@test()
def test_search_structs():
    """search_structs can search for structures"""
    result = search_structs("*")
    assert_is_list(result, min_length=1)
    r = result[0]
    assert_has_keys(r, "query", "results", "error")


@test()
def test_search_structs_pattern():
    """search_structs can filter by pattern"""
    result = search_structs("test*")
    assert_is_list(result, min_length=1)


# ============================================================================
# Tests for set_type
# ============================================================================


@test()
def test_set_type():
    """set_type applies type to address"""
    fn_addr = get_any_function()
    if not fn_addr:
        return

    result = set_type({"addr": fn_addr, "type": "int"})
    assert_is_list(result, min_length=1)
    r = result[0]
    assert_has_keys(r, "addr", "error")


@test()
def test_set_type_invalid_address():
    """set_type handles invalid address"""
    result = set_type({"addr": get_unmapped_address(), "type": "int"})
    assert_is_list(result, min_length=1)
    r = result[0]
    # Should have error or handle gracefully
    assert_has_keys(r, "addr")


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
