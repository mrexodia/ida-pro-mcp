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
from ..api_stack import (
    stack_frame,
    declare_stack,
    delete_stack,
)

# Import sync module for IDAError
from ..sync import IDAError


# ============================================================================
# Tests for stack_frame
# ============================================================================


@test()
def test_stack_frame():
    """stack_frame returns stack frame info for a function"""
    fn_addr = get_any_function()
    if not fn_addr:
        return

    result = stack_frame(fn_addr)
    assert_is_list(result, min_length=1)
    r = result[0]
    assert_has_keys(r, "addr", "frame", "error")


@test()
def test_stack_frame_no_function():
    """stack_frame handles non-function address"""
    data_addr = get_data_address()
    if not data_addr:
        return

    result = stack_frame(data_addr)
    assert_is_list(result, min_length=1)
    r = result[0]
    # Should have error or null frame
    assert r.get("error") is not None or r.get("frame") is None


# ============================================================================
# Tests for declare_stack / delete_stack
# ============================================================================


@test(skip=True)  # Skip by default as it modifies the database
def test_declare_delete_stack():
    """declare_stack and delete_stack work together"""
    fn_addr = get_any_function()
    if not fn_addr:
        return

    # Try to declare a stack variable
    result = declare_stack({
        "func": fn_addr,
        "name": "__test_var__",
        "offset": -8,
        "type": "int"
    })
    assert_is_list(result, min_length=1)
    r = result[0]
    assert_has_keys(r, "func", "error")

    # If declare succeeded, try to delete
    if r.get("error") is None:
        del_result = delete_stack({
            "func": fn_addr,
            "name": "__test_var__"
        })
        assert_is_list(del_result, min_length=1)
