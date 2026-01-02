"""Tests for api_core API functions."""

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
from ..api_core import *

# Import sync module for IDAError
from ..sync import IDAError


# ============================================================================
# Tests
# ============================================================================

@test()
def test_idb_meta():
    """idb_meta returns valid metadata with all required fields"""
    meta = idb_meta()
    assert_has_keys(
        meta, "path", "module", "base", "size", "md5", "sha256", "crc32", "filesize"
    )
    assert_non_empty(meta["path"])
    assert_non_empty(meta["module"])
    assert_valid_address(meta["base"])
    assert_valid_address(meta["size"])


@test()
def test_lookup_funcs_by_address():
    """lookup_funcs can find function by address"""
    fn_addr = get_any_function()
    if not fn_addr:
        return  # Skip if no functions

    result = lookup_funcs(fn_addr)
    assert_is_list(result, min_length=1)
    assert result[0]["fn"] is not None
    assert result[0]["error"] is None
    assert_has_keys(result[0]["fn"], "addr", "name", "size")


@test()
def test_lookup_funcs_invalid():
    """lookup_funcs returns error for invalid address"""
    # Use an address that's unlikely to be a valid function
    result = lookup_funcs("0xDEADBEEFDEADBEEF")
    assert_is_list(result, min_length=1)
    assert result[0]["fn"] is None
    assert result[0]["error"] is not None


@test()
def test_lookup_funcs_wildcard():
    """lookup_funcs with '*' returns all functions (covers lines 132-134)"""
    result = lookup_funcs("*")
    assert_is_list(result, min_length=1)
    # All results should have query="*" and a function
    for r in result:
        assert r["query"] == "*"
        assert r["fn"] is not None


@test()
def test_lookup_funcs_empty():
    """lookup_funcs with empty string returns all functions (covers lines 132-134)"""
    result = lookup_funcs("")
    assert_is_list(result, min_length=1)
    assert result[0]["query"] == "*"


@test()
def test_lookup_funcs_malformed_hex():
    """lookup_funcs handles malformed hex address (covers lines 148-149)"""
    # This looks like an address but isn't valid hex
    result = lookup_funcs("0xZZZZ")
    assert_is_list(result, min_length=1)
    # Should return error since it's not a valid address or name
    assert result[0]["error"] is not None


@test()
def test_lookup_funcs_data_address():
    """lookup_funcs with valid address but not a function (covers lines 162-164)"""
    from .tests import get_data_address

    data_addr = get_data_address()
    if not data_addr:
        return  # Skip if no data segments

    result = lookup_funcs(data_addr)
    assert_is_list(result, min_length=1)
    # Should return "Not a function" error
    assert result[0]["fn"] is None
    assert "Not a function" in str(result[0]["error"]) or "Not found" in str(
        result[0]["error"]
    )


@test()
def test_cursor_addr():
    """cursor_addr returns valid address or handles headless mode"""
    try:
        result = cursor_addr()
        # If it succeeds, verify it's a valid hex address
        assert_valid_address(result)
    except IDAError:
        pass  # Expected in headless mode without GUI


@test()
def test_cursor_func():
    """cursor_func returns function info or handles headless mode"""
    try:
        result = cursor_func()
        # Result can be None if cursor is not in a function
        if result is not None:
            assert_has_keys(result, "addr", "name", "size")
            assert_valid_address(result["addr"])
    except IDAError:
        pass  # Expected in headless mode or if cursor not in function


@test()
def test_int_convert():
    """int_convert properly converts numbers"""
    result = int_convert({"text": "0x41"})
    assert_is_list(result, min_length=1)
    assert result[0]["error"] is None
    assert result[0]["result"] is not None
    conv = result[0]["result"]
    assert_has_keys(conv, "decimal", "hexadecimal", "bytes", "binary")
    assert conv["decimal"] == "65"
    assert conv["hexadecimal"] == "0x41"
    assert conv["ascii"] == "A"


@test()
def test_int_convert_invalid_text():
    """int_convert handles invalid number text (covers lines 252-256)"""
    result = int_convert({"text": "not_a_number"})
    assert_is_list(result, min_length=1)
    assert result[0]["result"] is None
    assert result[0]["error"] is not None
    assert "Invalid number" in result[0]["error"]


@test()
def test_int_convert_overflow():
    """int_convert handles overflow with small size (covers lines 269-277)"""
    # Try to fit a large number into 1 byte
    result = int_convert({"text": "0xFFFF", "size": 1})
    assert_is_list(result, min_length=1)
    assert result[0]["result"] is None
    assert result[0]["error"] is not None
    assert "too big" in result[0]["error"]


@test()
def test_int_convert_non_ascii():
    """int_convert handles non-ASCII bytes (covers lines 283-285)"""
    # 0x01 is not a printable ASCII character (control char)
    result = int_convert({"text": "0x01"})
    assert_is_list(result, min_length=1)
    assert result[0]["error"] is None
    # ascii should be None for non-printable bytes
    assert result[0]["result"]["ascii"] is None


@test()
def test_list_funcs():
    """list_funcs returns functions with proper structure"""
    result = list_funcs({})
    assert_is_list(result, min_length=1)
    page = result[0]
    assert_has_keys(page, "data", "next_offset")
    assert_is_list(page["data"], min_length=1)
    # Check first function has required keys
    fn = page["data"][0]
    assert_has_keys(fn, "addr", "name", "size")
    assert_valid_address(fn["addr"])


@test()
def test_list_funcs_pagination():
    """list_funcs pagination works correctly"""
    # Get first 2 functions
    result1 = list_funcs({"offset": 0, "count": 2})
    assert_is_list(result1, min_length=1)
    page1 = result1[0]
    assert len(page1["data"]) <= 2

    # Get next 2 functions
    if page1["next_offset"] is not None:
        result2 = list_funcs({"offset": page1["next_offset"], "count": 2})
        page2 = result2[0]
        # Verify we got different functions (if there are enough)
        if page2["data"]:
            assert page1["data"][0]["addr"] != page2["data"][0]["addr"]


@test()
def test_list_globals():
    """list_globals returns global variables with proper structure"""
    result = list_globals({})
    assert_is_list(result, min_length=1)
    page = result[0]
    assert_has_keys(page, "data", "next_offset")
    # Globals list may be empty for some binaries
    if page["data"]:
        glob = page["data"][0]
        assert_has_keys(glob, "addr", "name")
        assert_valid_address(glob["addr"])


@test()
def test_list_globals_pagination():
    """list_globals pagination works correctly"""
    # Get first 2 globals
    result1 = list_globals({"offset": 0, "count": 2})
    assert_is_list(result1, min_length=1)
    page1 = result1[0]
    assert len(page1["data"]) <= 2

    # Get next 2 globals if available
    if page1["next_offset"] is not None and page1["data"]:
        result2 = list_globals({"offset": page1["next_offset"], "count": 2})
        page2 = result2[0]
        # Verify we got different globals (if there are enough)
        if page2["data"]:
            assert page1["data"][0]["addr"] != page2["data"][0]["addr"]


@test()
def test_imports():
    """imports returns list of imported functions"""
    result = imports(0, 50)
    assert_has_keys(result, "data", "next_offset")
    # Imports may be empty for some binaries (static linking)
    if result["data"]:
        imp = result["data"][0]
        assert_has_keys(imp, "addr", "imported_name", "module")
        assert_valid_address(imp["addr"])


@test()
def test_imports_pagination():
    """imports pagination works correctly"""
    # Get first 2 imports
    result1 = imports(0, 2)
    assert_has_keys(result1, "data", "next_offset")
    assert len(result1["data"]) <= 2

    # Get next 2 imports if available
    if result1["next_offset"] is not None and result1["data"]:
        result2 = imports(result1["next_offset"], 2)
        # Verify we got different imports (if there are enough)
        if result2["data"]:
            assert result1["data"][0]["addr"] != result2["data"][0]["addr"]


@test()
def test_strings():
    """strings returns string list with proper structure"""
    result = strings({})
    assert_is_list(result, min_length=1)
    page = result[0]
    assert_has_keys(page, "data", "next_offset")
    # If there are strings, check structure
    if page["data"]:
        string_item = page["data"][0]
        assert_has_keys(string_item, "addr", "length", "string")
        assert_valid_address(string_item["addr"])


@test()
def test_segments():
    """segments returns list of memory segments"""
    result = segments()
    assert_is_list(result, min_length=1)
    seg = result[0]
    assert_has_keys(seg, "name", "start", "end", "size", "permissions")
    assert_valid_address(seg["start"])
    assert_valid_address(seg["end"])


@test()
def test_local_types():
    """local_types returns list of local types"""
    result = local_types()
    # Result is a list of strings describing local types
    assert isinstance(result, list), f"Expected list, got {type(result).__name__}"
    # Local types may be empty for some binaries
    if result:
        # Each item should be a string describing a type
        assert isinstance(result[0], str), (
            f"Expected string items, got {type(result[0]).__name__}"
        )


