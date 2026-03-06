"""Tests for api_modify API functions."""

# Import test framework from parent
from ..framework import (
    test,
    assert_has_keys,
    assert_is_list,
    get_any_function,
    get_data_address,
)

# Import functions under test
from ..api_modify import (
    set_comments,
    patch_asm,
    rename,
    define_func,
    define_code,
    undefine,
)

# Import sync module for IDAError


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


@test()
def test_patch_asm_roundtrip():
    """patch_asm can patch assembly and be restored"""
    fn_addr = get_any_function()
    if not fn_addr:
        return

    # Import memory functions for backup/restore
    from ..api_memory import get_bytes, patch

    # Read original bytes (enough for a nop instruction)
    original = get_bytes({"addr": fn_addr, "size": 16})
    assert_is_list(original, min_length=1)
    original_data = original[0].get("data")
    if not original_data:
        return

    try:
        # Patch with nop
        result = patch_asm({"addr": fn_addr, "asm": "nop"})
        assert_is_list(result, min_length=1)
        r = result[0]
        assert_has_keys(r, "addr")
    finally:
        # Restore original bytes
        patch({"addr": fn_addr, "data": original_data})


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

    result = rename({"global": [{"addr": data_addr, "name": "__test_global__"}]})
    assert isinstance(result, dict)
    assert_has_keys(result, "data", "global", "summary")
    assert_is_list(result["global"], min_length=1)


@test()
def test_rename_dry_run_summary():
    """rename supports dry_run and returns summary counters"""
    fn_addr = get_any_function()
    if not fn_addr:
        return

    result = rename({"func": [{"addr": fn_addr, "name": "__test_dry_run__"}], "dry_run": True})
    assert isinstance(result, dict)
    assert_has_keys(result, "func", "summary")
    assert result["summary"]["dry_run"] is True
    assert_is_list(result["func"], min_length=1)
    assert result["func"][0].get("dry_run") is True


@test()
def test_rename_stop_on_error():
    """rename can stop on first error"""
    fn_addr = get_any_function()
    if not fn_addr:
        return

    result = rename(
        {
            "func": [
                {"addr": "0x0", "name": "__invalid__"},
                {"addr": fn_addr, "name": "__should_not_run__"},
            ],
            "stop_on_error": True,
        }
    )
    assert isinstance(result, dict)
    assert_has_keys(result, "func", "summary")
    # Stop-on-error should keep only the first failed item.
    assert len(result["func"]) == 1
    assert result["summary"]["stopped"] is True


@test()
def test_rename_local_error_handling():
    """rename local variable handles errors gracefully"""
    fn_addr = get_any_function()
    if not fn_addr:
        return

    # Try to rename a non-existent local variable - should return error, not crash
    result = rename(
        {
            "local": [
                {
                    "func": fn_addr,
                    "name": "__nonexistent_var__",
                    "new_name": "__test_local__",
                }
            ]
        }
    )
    assert isinstance(result, dict)
    # Should have local key with results
    assert "local" in result


# ============================================================================
# Tests for define_func / define_code / undefine
# ============================================================================


@test()
def test_define_undefine_func_roundtrip():
    """define_func and undefine work together - undefine existing func then redefine"""
    import ida_funcs
    import idaapi

    # Get an existing function to test with
    fn_addr = get_any_function()
    if not fn_addr:
        return

    fn_ea = int(fn_addr, 16)
    func = idaapi.get_func(fn_ea)
    if not func:
        return

    # Save function bounds for restoration
    start_ea = func.start_ea
    end_ea = func.end_ea

    try:
        # Undefine the function
        undef_result = undefine({"addr": fn_addr, "end": hex(end_ea)})
        assert_is_list(undef_result, min_length=1)

        # Verify function is gone
        assert idaapi.get_func(start_ea) is None

        # Re-define the function with explicit bounds
        result = define_func({"addr": hex(start_ea), "end": hex(end_ea)})
        assert_is_list(result, min_length=1)
        r = result[0]
        assert r.get("ok") is True or r.get("error") is None
    finally:
        # Ensure function is restored even if test fails
        if idaapi.get_func(start_ea) is None:
            ida_funcs.add_func(start_ea, end_ea)


@test()
def test_define_func_already_exists():
    """define_func returns error for existing function"""
    fn_addr = get_any_function()
    if not fn_addr:
        return

    result = define_func({"addr": fn_addr})
    assert_is_list(result, min_length=1)
    r = result[0]
    assert r.get("error") is not None
    assert "already exists" in r["error"]


@test()
def test_define_func_batch():
    """define_func accepts batch input"""
    fn_addr = get_any_function()
    if not fn_addr:
        return

    # Both should fail (already exist), but tests batch handling
    result = define_func([{"addr": fn_addr}, {"addr": fn_addr}])
    assert_is_list(result, min_length=2)


@test()
def test_define_code_on_existing_code():
    """define_code handles already-defined code gracefully"""
    # Get an existing function address - it's already code
    fn_addr = get_any_function()
    if not fn_addr:
        return

    # Calling define_code on existing code should succeed (it's idempotent)
    # or return an appropriate response
    result = define_code({"addr": fn_addr})
    assert_is_list(result, min_length=1)
    r = result[0]
    assert_has_keys(r, "addr")
    # Should either succeed or have a meaningful response
    assert (
        r.get("ok") is True or r.get("length") is not None or r.get("error") is not None
    )


@test()
def test_undefine_batch():
    """undefine accepts batch input"""
    fn_addr = get_any_function()
    if not fn_addr:
        return

    # Test that batch input is accepted (will likely fail on function, but tests parsing)
    result = undefine([{"addr": fn_addr}])
    assert_is_list(result, min_length=1)
