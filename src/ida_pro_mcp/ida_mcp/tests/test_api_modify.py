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
from ..api_modify import *

# Import sync module for IDAError
from ..sync import IDAError


# ============================================================================
# Tests
# ============================================================================

@test()
def test_set_comment_roundtrip():
    """set_comments can set and clear comments"""
    fn_addr = get_any_function()
    if not fn_addr:
        return  # Skip if no functions

    # Get original comment (may be None/empty)
    original_comment = idc.get_cmt(int(fn_addr, 16), False) or ""

    try:
        # Set a test comment
        result = set_comments({"addr": fn_addr, "comment": "__test_comment__"})
        assert_is_list(result, min_length=1)
        assert_has_keys(result[0], "addr")
        # Either "ok" or "error" should be present
        assert "ok" in result[0] or "error" in result[0]

        # Verify comment was set
        new_comment = idc.get_cmt(int(fn_addr, 16), False)
        assert new_comment == "__test_comment__", (
            f"Expected '__test_comment__', got {new_comment!r}"
        )
    finally:
        # Restore original comment
        set_comments({"addr": fn_addr, "comment": original_comment})


@test()
def test_patch_asm():
    """patch_asm returns proper result structure"""
    fn_addr = get_any_function()
    if not fn_addr:
        return  # Skip if no functions

    # Get original bytes at function start for potential restore
    ea = int(fn_addr, 16)
    original_bytes = ida_bytes.get_bytes(ea, 16)
    if not original_bytes:
        return  # Skip if can't read bytes

    # Try to assemble a NOP (this may fail depending on architecture)
    # We're just testing the API returns proper structure, not necessarily succeeding
    result = patch_asm({"addr": fn_addr, "asm": "nop"})
    assert_is_list(result, min_length=1)
    assert_has_keys(result[0], "addr")
    # Result should have either "ok" or "error"
    assert "ok" in result[0] or "error" in result[0]

    # Restore original bytes if patch succeeded
    if result[0].get("ok"):
        ida_bytes.patch_bytes(ea, original_bytes)


@test()
def test_rename_function_roundtrip():
    """rename can rename and restore function names"""
    from .api_core import lookup_funcs

    fn_addr = get_any_function()
    if not fn_addr:
        return  # Skip if no functions

    # Get original name
    lookup_result = lookup_funcs(fn_addr)
    if not lookup_result or not lookup_result[0].get("fn"):
        return  # Skip if lookup failed
    original_name = lookup_result[0]["fn"]["name"]

    try:
        # Rename the function
        result = rename({"func": [{"addr": fn_addr, "name": "__test_func_name__"}]})
        assert_has_keys(result, "func")
        assert_is_list(result["func"], min_length=1)
        assert_has_keys(result["func"][0], "addr", "name", "ok")
        assert result["func"][0]["ok"], (
            f"Rename failed: {result['func'][0].get('error')}"
        )

        # Verify the change
        new_lookup = lookup_funcs(fn_addr)
        new_name = new_lookup[0]["fn"]["name"]
        assert new_name == "__test_func_name__", (
            f"Expected '__test_func_name__', got {new_name!r}"
        )
    finally:
        # Restore original name
        rename({"func": [{"addr": fn_addr, "name": original_name}]})


@test()
def test_rename_global_roundtrip():
    """rename can rename and restore global names"""
    from .api_core import list_globals

    # Get a global variable
    globals_result = list_globals({"count": 1})
    if not globals_result or not globals_result[0]["data"]:
        return  # Skip if no globals

    global_info = globals_result[0]["data"][0]
    original_name = global_info["name"]
    global_info["addr"]

    # Skip system globals that can't be renamed
    if original_name.startswith("__") or original_name.startswith("."):
        return

    result = {}
    try:
        # Rename the global
        result = rename(
            {"data": [{"old": original_name, "new": "__test_global_name__"}]}
        )
        assert_has_keys(result, "data")
        assert_is_list(result["data"], min_length=1)
        assert_has_keys(result["data"][0], "old", "new", "ok")

        # Only verify change if rename succeeded (some globals may not be renameable)
        if result["data"][0]["ok"]:
            # Verify we can look it up by new name
            ea = idaapi.get_name_ea(idaapi.BADADDR, "__test_global_name__")
            assert ea != idaapi.BADADDR, "Could not find renamed global"
    finally:
        # Restore original name (only if rename succeeded)
        if result.get("data") and result["data"][0].get("ok"):
            rename({"data": [{"old": "__test_global_name__", "new": original_name}]})


@test()
def test_rename_local_roundtrip():
    """rename can rename and restore local variable names"""
    from .api_analysis import decompile

    fn_addr = get_any_function()
    if not fn_addr:
        return  # Skip if no functions

    # Try to decompile to get local variables
    try:
        dec_result = decompile(fn_addr)
    except IDAError:
        return  # Skip if decompilation fails

    if not dec_result or dec_result[0].get("error"):
        return  # Skip if decompilation failed

    # Get local variables from decompiled code
    lvars = dec_result[0].get("lvars", [])
    if not lvars:
        return  # Skip if no local variables

    # Find a regular local (not argument)
    test_lvar = None
    for lvar in lvars:
        if not lvar.get("is_arg"):
            test_lvar = lvar
            break

    if not test_lvar:
        return  # Skip if no non-argument local found

    original_name = test_lvar["name"]

    result = {}
    try:
        # Rename the local variable
        result = rename(
            {
                "local": [
                    {
                        "func_addr": fn_addr,
                        "old": original_name,
                        "new": "__test_local__",
                    }
                ]
            }
        )
        assert_has_keys(result, "local")
        assert_is_list(result["local"], min_length=1)
        assert_has_keys(result["local"][0], "func_addr", "old", "new", "ok")

        # We don't assert ok=True because some locals may not be renameable
    finally:
        # Restore original name if rename succeeded
        if result.get("local") and result["local"][0].get("ok"):
            rename(
                {
                    "local": [
                        {
                            "func_addr": fn_addr,
                            "old": "__test_local__",
                            "new": original_name,
                        }
                    ]
                }
            )


