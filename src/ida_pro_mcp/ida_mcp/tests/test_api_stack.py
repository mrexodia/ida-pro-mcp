"""Tests for api_stack API functions."""

# Import test framework from parent
from ..framework import (
    test,
    assert_has_keys,
    assert_is_list,
    get_any_function,
    get_data_address,
)

# Import functions under test
from ..api_stack import (
    stack_frame,
    declare_stack,
    delete_stack,
)

# Import sync module for IDAError


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
    assert_has_keys(r, "addr", "vars")


@test()
def test_stack_frame_no_function():
    """stack_frame handles non-function address"""
    data_addr = get_data_address()
    if not data_addr:
        return

    result = stack_frame(data_addr)
    assert_is_list(result, min_length=1)
    r = result[0]
    # Should have error or null vars
    assert r.get("error") is not None or r.get("vars") is None


# ============================================================================
# Tests for declare_stack / delete_stack
# ============================================================================


@test()
def test_declare_delete_stack_roundtrip():
    """declare_stack and delete_stack work together"""
    fn_addr = get_any_function()
    if not fn_addr:
        return

    try:
        # Try to declare a stack variable
        result = declare_stack(
            {"addr": fn_addr, "name": "__test_var__", "offset": -8, "ty": "int"}
        )
        assert_is_list(result, min_length=1)
        r = result[0]
        assert_has_keys(r, "addr", "name")
    finally:
        # Always try to clean up, even if declare failed
        delete_stack({"addr": fn_addr, "name": "__test_var__"})
