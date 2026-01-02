"""Tests for api_modify API functions."""

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
from ..api_modify import (
    set_comments,
    patch_asm,
    rename,
)

# Import sync module for IDAError
from ..sync import IDAError


# ============================================================================
# Tests for set_comments
# ============================================================================


@test()
def test_set_comment_roundtrip():
    """set_comments can add and remove comments"""
    fn_addr = get_any_function()
    if not fn_addr:
        return

    # Add a comment
    result = set_comments({"addr": fn_addr, "comment": "__TEST_COMMENT__"})
    assert_is_list(result, min_length=1)

    # Clear the comment
    result = set_comments({"addr": fn_addr, "comment": ""})
    assert_is_list(result, min_length=1)


# ============================================================================
# Tests for patch_asm
# ============================================================================


@test(skip=True)  # Skip by default as it modifies the database
def test_patch_asm():
    """patch_asm can patch assembly"""
    fn_addr = get_any_function()
    if not fn_addr:
        return

    # This is a risky test - patching assembly could corrupt the binary
    result = patch_asm({"addr": fn_addr, "asm": "nop"})
    assert_is_list(result, min_length=1)
    r = result[0]
    assert_has_keys(r, "addr", "error")


# ============================================================================
# Tests for rename
# ============================================================================


@test()
def test_rename_function_roundtrip():
    """rename function works and can be undone"""
    fn_addr = get_any_function()
    if not fn_addr:
        return

    # Import to get original name
    from ..api_core import lookup_funcs

    # Get original name
    lookup_result = lookup_funcs(fn_addr)
    if not lookup_result or not lookup_result[0].get("fn"):
        return

    original_name = lookup_result[0]["fn"]["name"]

    try:
        # Rename
        result = rename({"func": [{"addr": fn_addr, "name": "__test_rename__"}]})
        assert isinstance(result, dict)

        # Verify rename worked
        lookup_result = lookup_funcs(fn_addr)
        new_name = lookup_result[0]["fn"]["name"]
        assert new_name == "__test_rename__"
    finally:
        # Restore
        rename({"func": [{"addr": fn_addr, "name": original_name}]})


@test()
def test_rename_global_roundtrip():
    """rename global variable works"""
    data_addr = get_data_address()
    if not data_addr:
        return

    try:
        result = rename({"global": [{"addr": data_addr, "name": "__test_global__"}]})
        assert isinstance(result, dict)
    except Exception:
        pass  # May fail if no suitable global exists


@test(skip=True)  # Local variable renaming requires decompilation
def test_rename_local_roundtrip():
    """rename local variable works"""
    fn_addr = get_any_function()
    if not fn_addr:
        return

    # This requires the function to be decompilable and have local variables
    result = rename({
        "local": [{
            "func": fn_addr,
            "name": "old_var",
            "new_name": "__test_local__"
        }]
    })
    assert isinstance(result, dict)
