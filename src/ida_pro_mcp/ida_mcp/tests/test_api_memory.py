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
from ..api_memory import (
    get_bytes,
    get_int,
    get_string,
    get_global_value,
    patch,
    put_int,
)

# Import sync module for IDAError
from ..sync import IDAError


# ============================================================================
# Tests for get_bytes
# ============================================================================


@test()
def test_get_bytes():
    """get_bytes reads bytes from a valid address"""
    seg = get_first_segment()
    if not seg:
        return

    start_addr, _ = seg
    result = get_bytes({"addr": start_addr, "size": 16})
    assert_is_list(result, min_length=1)
    r = result[0]
    assert_has_keys(r, "addr", "hex", "error")
    if r["error"] is None:
        assert r["hex"] is not None


@test()
def test_get_bytes_invalid():
    """get_bytes handles invalid address"""
    result = get_bytes({"addr": get_unmapped_address(), "size": 16})
    assert_is_list(result, min_length=1)
    r = result[0]
    # Should have error or empty data
    assert r.get("error") is not None or r.get("hex") == ""


# ============================================================================
# Tests for get_int
# ============================================================================


@test()
def test_get_int_u8():
    """get_int reads 8-bit unsigned integer"""
    seg = get_first_segment()
    if not seg:
        return

    start_addr, _ = seg
    result = get_int({"addr": start_addr, "size": 1})
    assert_is_list(result, min_length=1)
    r = result[0]
    assert_has_keys(r, "addr", "value", "error")


@test()
def test_get_int_u16():
    """get_int reads 16-bit unsigned integer"""
    seg = get_first_segment()
    if not seg:
        return

    start_addr, _ = seg
    result = get_int({"addr": start_addr, "size": 2})
    assert_is_list(result, min_length=1)
    r = result[0]
    assert_has_keys(r, "addr", "value", "error")


@test()
def test_get_int_u32():
    """get_int reads 32-bit unsigned integer"""
    seg = get_first_segment()
    if not seg:
        return

    start_addr, _ = seg
    result = get_int({"addr": start_addr, "size": 4})
    assert_is_list(result, min_length=1)
    r = result[0]
    assert_has_keys(r, "addr", "value", "error")


@test()
def test_get_int_u64():
    """get_int reads 64-bit unsigned integer"""
    seg = get_first_segment()
    if not seg:
        return

    start_addr, _ = seg
    result = get_int({"addr": start_addr, "size": 8})
    assert_is_list(result, min_length=1)
    r = result[0]
    assert_has_keys(r, "addr", "value", "error")


# ============================================================================
# Tests for get_string
# ============================================================================


@test()
def test_get_string():
    """get_string reads string from a valid address"""
    str_addr = get_any_string()
    if not str_addr:
        return

    result = get_string(str_addr)
    assert_is_list(result, min_length=1)
    r = result[0]
    assert_has_keys(r, "addr", "value", "error")


# ============================================================================
# Tests for get_global_value
# ============================================================================


@test()
def test_get_global_value():
    """get_global_value retrieves global variable value"""
    # Try to get value at a data address
    data_addr = get_data_address()
    if not data_addr:
        seg = get_first_segment()
        if not seg:
            return
        data_addr = seg[0]

    result = get_global_value(data_addr)
    assert_is_list(result, min_length=1)
    r = result[0]
    assert_has_keys(r, "addr", "error")


# ============================================================================
# Tests for patch
# ============================================================================


@test(skip=True)  # Skip by default as it modifies the database
def test_patch():
    """patch writes bytes to address"""
    seg = get_first_segment()
    if not seg:
        return

    start_addr, _ = seg
    # Read original bytes first
    original = get_bytes({"addr": start_addr, "size": 4})

    try:
        result = patch({"addr": start_addr, "hex": "90909090"})
        assert_is_list(result, min_length=1)
        r = result[0]
        assert_has_keys(r, "addr", "error")
    finally:
        # Restore original bytes
        if original and original[0].get("hex"):
            patch({"addr": start_addr, "hex": original[0]["hex"]})


@test()
def test_patch_invalid_address():
    """patch handles invalid address"""
    result = patch({"addr": get_unmapped_address(), "hex": "90"})
    assert_is_list(result, min_length=1)
    r = result[0]
    # Should have error
    assert r.get("error") is not None


@test()
def test_patch_invalid_hex_data():
    """patch handles invalid hex data"""
    seg = get_first_segment()
    if not seg:
        return

    start_addr, _ = seg
    result = patch({"addr": start_addr, "hex": "ZZZZ"})
    assert_is_list(result, min_length=1)
    r = result[0]
    # Should have error for invalid hex
    assert r.get("error") is not None
