"""Tests for api_stack API functions."""

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
from ..api_stack import *

# Import sync module for IDAError
from ..sync import IDAError


# ============================================================================
# Tests
# ============================================================================

@test()
def test_stack_frame():
    """stack_frame returns stack variables for a valid function"""
    fn_addr = get_any_function()
    if not fn_addr:
        return  # Skip if no functions

    result = stack_frame(fn_addr)
    assert_is_list(result, min_length=1)
    assert_has_keys(result[0], "addr", "vars")
    # vars can be None if function has no stack frame, or a list
    # Just verify the structure is correct
    assert result[0]["addr"] == fn_addr
    assert "error" not in result[0] or result[0].get("error") is None


@test()
def test_stack_frame_no_function():
    """stack_frame handles invalid address gracefully"""
    # Use an address that's unlikely to be a valid function
    result = stack_frame("0xDEADBEEFDEADBEEF")
    assert_is_list(result, min_length=1)
    # Should return error, not crash
    assert "error" in result[0]
    assert result[0]["error"] is not None


@test()
def test_declare_delete_stack():
    """declare_stack and delete_stack create/delete stack variables"""
    fn_addr = get_any_function()
    if not fn_addr:
        return  # Skip if no functions

    # First check if the function has a stack frame
    frame_result = stack_frame(fn_addr)
    if not frame_result or frame_result[0].get("error"):
        return  # Skip if function has no frame

    test_var_name = "__mcp_test_var__"

    try:
        # Try to create a stack variable at offset 0x10
        # Use "int" as the type - a basic type that should exist
        declare_result = declare_stack(
            {"addr": fn_addr, "offset": "0x10", "name": test_var_name, "ty": "int"}
        )
        assert_is_list(declare_result, min_length=1)
        assert_has_keys(declare_result[0], "addr", "name")

        # If creation succeeded, try to delete it
        if declare_result[0].get("ok"):
            delete_result = delete_stack({"addr": fn_addr, "name": test_var_name})
            assert_is_list(delete_result, min_length=1)
            assert_has_keys(delete_result[0], "addr", "name")
        # If creation failed (e.g., no frame, offset conflict), that's OK
        # The test verifies the API handles it gracefully without crashing
    except Exception:
        # If any operation fails, ensure cleanup is attempted
        try:
            delete_stack({"addr": fn_addr, "name": test_var_name})
        except Exception:
            pass
        raise


