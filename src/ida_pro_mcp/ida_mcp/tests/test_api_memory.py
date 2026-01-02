"""Tests for api_memory API functions."""

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
from ..api_memory import *

# Import sync module for IDAError
from ..sync import IDAError


# ============================================================================
# Tests
# ============================================================================

@test()
def test_get_bytes():
    """get_bytes reads raw bytes from a valid address"""
    seg = get_first_segment()
    if not seg:
        return  # Skip if no segments

    start_addr, _ = seg
    result = get_bytes({"addr": start_addr, "size": 16})
    assert_is_list(result, min_length=1)
    assert_has_keys(result[0], "addr", "data")
    assert result[0]["addr"] == start_addr
    assert_non_empty(result[0]["data"])
    # Data should be space-separated hex values like "0x41 0x42 0x43"
    assert " " in result[0]["data"] or result[0]["data"].startswith("0x")


@test()
def test_get_bytes_invalid():
    """get_bytes handles invalid address (returns 0xff bytes or error)"""
    result = get_bytes({"addr": "0xDEADBEEFDEADBEEF", "size": 16})
    assert_is_list(result, min_length=1)
    assert_has_keys(result[0], "addr")
    # IDA returns 0xff bytes for unmapped addresses, so we just verify structure
    # Either has data (0xff bytes) or error
    assert "data" in result[0] or "error" in result[0]


@test()
def test_get_u8():
    """get_u8 reads 8-bit unsigned integer from valid address"""
    seg = get_first_segment()
    if not seg:
        return  # Skip if no segments

    start_addr, _ = seg
    result = get_u8(start_addr)
    assert_is_list(result, min_length=1)
    assert_has_keys(result[0], "addr", "value")
    assert result[0]["addr"] == start_addr
    # Value should be an integer 0-255
    assert isinstance(result[0]["value"], int)
    assert 0 <= result[0]["value"] <= 255


@test()
def test_get_u16():
    """get_u16 reads 16-bit unsigned integer from valid address"""
    seg = get_first_segment()
    if not seg:
        return  # Skip if no segments

    start_addr, _ = seg
    result = get_u16(start_addr)
    assert_is_list(result, min_length=1)
    assert_has_keys(result[0], "addr", "value")
    assert result[0]["addr"] == start_addr
    # Value should be an integer 0-65535
    assert isinstance(result[0]["value"], int)
    assert 0 <= result[0]["value"] <= 0xFFFF


@test()
def test_get_u32():
    """get_u32 reads 32-bit unsigned integer from valid address"""
    seg = get_first_segment()
    if not seg:
        return  # Skip if no segments

    start_addr, _ = seg
    result = get_u32(start_addr)
    assert_is_list(result, min_length=1)
    assert_has_keys(result[0], "addr", "value")
    assert result[0]["addr"] == start_addr
    # Value should be an integer 0-0xFFFFFFFF
    assert isinstance(result[0]["value"], int)
    assert 0 <= result[0]["value"] <= 0xFFFFFFFF


@test()
def test_get_u64():
    """get_u64 reads 64-bit unsigned integer from valid address"""
    seg = get_first_segment()
    if not seg:
        return  # Skip if no segments

    start_addr, _ = seg
    result = get_u64(start_addr)
    assert_is_list(result, min_length=1)
    assert_has_keys(result[0], "addr", "value")
    assert result[0]["addr"] == start_addr
    # Value should be an integer 0-0xFFFFFFFFFFFFFFFF
    assert isinstance(result[0]["value"], int)
    assert 0 <= result[0]["value"] <= 0xFFFFFFFFFFFFFFFF


@test()
def test_get_string():
    """get_string reads string at valid string address"""
    str_addr = get_any_string()
    if not str_addr:
        return  # Skip if no strings in binary

    result = get_string(str_addr)
    assert_is_list(result, min_length=1)
    assert_has_keys(result[0], "addr", "value")
    assert result[0]["addr"] == str_addr
    # Value should be a non-empty string (or None with error for edge cases)
    if result[0].get("error") is None:
        assert isinstance(result[0]["value"], str)
        assert_non_empty(result[0]["value"])


@test()
def test_get_global_value():
    """get_global_value reads global variable value by address"""
    seg = get_first_segment()
    if not seg:
        return  # Skip if no segments

    start_addr, _ = seg
    result = get_global_value(start_addr)
    assert_is_list(result, min_length=1)
    assert_has_keys(result[0], "query", "value", "error")
    assert result[0]["query"] == start_addr
    # May have value or error depending on whether it's a valid global
    # Either value or error should be set
    assert result[0]["value"] is not None or result[0]["error"] is not None


@test()
def test_patch():
    """patch modifies bytes and can be restored"""
    seg = get_first_segment()
    if not seg:
        return  # Skip if no segments

    start_addr, _ = seg

    # Read original bytes
    original = get_bytes({"addr": start_addr, "size": 1})
    if not original or not original[0].get("data"):
        return  # Skip if can't read original bytes

    # Parse original byte (format is "0xNN")
    original_data = original[0]["data"].split()[0]  # Get first byte
    original_hex = original_data.replace("0x", "")  # Convert "0x90" -> "90"

    try:
        # Patch with a different byte (0x00 if different, else 0x01)
        test_byte = "00" if original_hex != "00" else "01"
        result = patch([{"addr": start_addr, "data": test_byte}])
        assert_is_list(result, min_length=1)
        assert_has_keys(result[0], "addr", "size")
        # Verify either success or error key
        assert result[0].get("ok") is True or result[0].get("error") is not None
        if result[0].get("ok"):
            assert result[0]["size"] == 1
    finally:
        # Restore original byte
        patch([{"addr": start_addr, "data": original_hex}])


@test()
def test_patch_invalid_address():
    """patch handles invalid address gracefully"""
    result = patch([{"addr": "invalid_address", "data": "90"}])
    assert_is_list(result, min_length=1)
    assert_has_keys(result[0], "addr", "error")
    assert result[0]["error"] is not None


@test()
def test_patch_invalid_hex_data():
    """patch handles invalid hex data gracefully"""
    seg = get_first_segment()
    if not seg:
        return  # Skip if no segments

    start_addr, _ = seg
    result = patch([{"addr": start_addr, "data": "not_valid_hex"}])
    assert_is_list(result, min_length=1)
    assert_has_keys(result[0], "addr", "error")
    assert result[0]["error"] is not None


