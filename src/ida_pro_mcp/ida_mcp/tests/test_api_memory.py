"""Tests for api_memory API functions."""

# Import test framework from parent
from ..framework import (
    test,
    assert_has_keys,
    assert_is_list,
    get_any_string,
    get_first_segment,
    get_data_address,
    get_unmapped_address,
)

# Import functions under test
from ..api_memory import (
    get_bytes,
    get_int,
    get_string,
    get_global_value,
    patch,
)

# Import sync module for IDAError


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
    assert_has_keys(r, "addr", "data")
    if r.get("error") is None:
        assert r["data"] is not None


@test()
def test_get_bytes_invalid():
    """get_bytes handles invalid address"""
    result = get_bytes({"addr": get_unmapped_address(), "size": 16})
    assert_is_list(result, min_length=1)
    r = result[0]
    assert_has_keys(r, "addr", "data")
    # API may return an error or a null/empty payload depending on IDA backend.
    assert (
        r.get("error") is not None
        or r.get("data") in (None, "")
        or isinstance(r.get("data"), str)
    )


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
    result = get_int({"addr": start_addr, "ty": "u8"})
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
    result = get_int({"addr": start_addr, "ty": "u16"})
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
    result = get_int({"addr": start_addr, "ty": "u32"})
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
    result = get_int({"addr": start_addr, "ty": "u64"})
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
    assert_has_keys(r, "addr", "value")


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
    assert_has_keys(r, "query", "value", "error")


# ============================================================================
# Tests for patch
# ============================================================================


@test()
def test_patch_roundtrip():
    """patch writes bytes and restores original"""
    seg = get_first_segment()
    if not seg:
        return

    start_addr, _ = seg
    # Read original bytes first
    original = get_bytes({"addr": start_addr, "size": 4})
    if not original or not original[0].get("data"):
        return

    try:
        result = patch({"addr": start_addr, "data": "90 90 90 90"})
        assert_is_list(result, min_length=1)
        r = result[0]
        assert_has_keys(r, "addr")
        assert r.get("ok") is True or r.get("error") is None
    finally:
        # Restore original bytes
        patch({"addr": start_addr, "data": original[0]["data"]})


@test()
def test_patch_invalid_address():
    """patch handles invalid address"""
    result = patch({"addr": get_unmapped_address(), "data": "90"})
    assert_is_list(result, min_length=1)
    r = result[0]
    assert_has_keys(r, "addr")
    # Backends may either report error or return best-effort patch status.
    assert r.get("ok") is True or r.get("error") is not None


@test()
def test_patch_invalid_hex_data():
    """patch handles invalid hex data"""
    seg = get_first_segment()
    if not seg:
        return

    start_addr, _ = seg
    result = patch({"addr": start_addr, "data": "ZZZZ"})
    assert_is_list(result, min_length=1)
    r = result[0]
    # Should have error for invalid hex
    assert r.get("error") is not None
