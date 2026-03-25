"""Tests for api_memory API functions."""

from ..framework import (
    test,
    skip_test,
    assert_non_empty,
    assert_is_list,
    assert_shape,
    assert_ok,
    assert_error,
    optional,
    get_first_segment,
    get_data_address,
    get_unmapped_address,
    get_named_address,
)
from ..api_memory import (
    get_bytes,
    get_int,
    get_string,
    get_global_value,
    patch,
    put_int,
)


CRACKME_FORMAT = "0x201f"
CRACKME_DSO_HANDLE = "0x4008"


def _plain_hex_bytes(text: str) -> str:
    return text.replace("0x", "").replace(" ", "").lower()


@test()
def test_get_bytes_reads_valid_region():
    """get_bytes returns a non-empty hex byte string for a mapped region."""
    seg = get_first_segment()
    if not seg:
        skip_test("binary has no segments")

    start_addr, _ = seg
    result = get_bytes({"addr": start_addr, "size": 16})
    assert_shape(result, [{"addr": str, "data": optional(str), "error": optional(str)}])
    assert_ok(result[0], "data")
    parts = result[0]["data"].split()
    assert len(parts) == 16
    assert all(part.startswith("0x") for part in parts)


@test()
def test_get_bytes_invalid():
    """get_bytes reports an error for an unmapped address."""
    result = get_bytes({"addr": get_unmapped_address(), "size": 16})
    assert_is_list(result, min_length=1)
    if result[0].get("data") is None:
        assert_error(result[0])


@test()
def test_get_int_reads_common_integer_sizes():
    """get_int can read common unsigned integer sizes from a mapped region."""
    seg = get_first_segment()
    if not seg:
        skip_test("binary has no segments")

    start_addr, _ = seg
    for ty in ("u8", "u16", "u32", "u64"):
        result = get_int({"addr": start_addr, "ty": ty})
        assert_is_list(result, min_length=1)
        entry = result[0]
        assert entry["addr"] == start_addr
        assert entry["ty"].startswith(ty)
        assert "error" not in entry
        assert isinstance(entry["value"], int)


@test(binary="crackme03.elf")
def test_get_string_reads_known_crackme_format_string():
    """get_string returns the exact known crackme success format string."""
    result = get_string(CRACKME_FORMAT)
    assert_is_list(result, min_length=1)
    assert_ok(result[0], "value")
    assert result[0]["value"] == "Yes, %s is correct!\n"


@test()
def test_get_global_value():
    """get_global_value returns a non-empty representation for a named global."""
    named = get_named_address("format") or get_data_address()
    if not named:
        skip_test("binary has no suitable named or data address")

    query = "format" if get_named_address("format") else named
    result = get_global_value(query)
    assert_is_list(result, min_length=1)
    assert_ok(result[0], "value")
    assert_non_empty(result[0]["value"])


@test(binary="crackme03.elf")
def test_get_global_value_known_format_symbol():
    """get_global_value resolves the crackme format symbol by name."""
    result = get_global_value("format")
    assert_is_list(result, min_length=1)
    assert_ok(result[0], "value")
    assert result[0]["value"] == '"Yes, %s is correct!"'


@test()
def test_patch_roundtrip_changes_and_restores_bytes():
    """patch modifies bytes at an address and restoration returns the original bytes."""
    data_addr = get_data_address()
    if not data_addr:
        skip_test("binary has no data segment")

    original = get_bytes({"addr": data_addr, "size": 4})[0]
    assert_ok(original, "data")
    original_data = original["data"]
    original_plain = _plain_hex_bytes(original_data)
    replacement = "90 90 90 90"
    if original_plain == replacement.replace(" ", ""):
        replacement = "cc cc cc cc"

    try:
        patched = patch({"addr": data_addr, "data": replacement})[0]
        assert "error" not in patched
        changed = get_bytes({"addr": data_addr, "size": 4})[0]
        assert _plain_hex_bytes(changed["data"]) == replacement.replace(" ", "")
    finally:
        patch({"addr": data_addr, "data": original_plain})

    restored = get_bytes({"addr": data_addr, "size": 4})[0]
    assert _plain_hex_bytes(restored["data"]) == original_plain


@test()
def test_patch_invalid_address():
    """patch reports an error for an unmapped address."""
    result = patch({"addr": get_unmapped_address(), "data": "90"})
    assert_is_list(result, min_length=1)
    entry = result[0]
    assert entry["addr"] == get_unmapped_address()
    assert_error(entry, contains="Address not mapped")


@test()
def test_patch_invalid_hex_data():
    """patch rejects invalid hexadecimal payloads."""
    data_addr = get_data_address()
    if not data_addr:
        skip_test("binary has no data segment")

    result = patch({"addr": data_addr, "data": "ZZZZ"})
    assert_is_list(result, min_length=1)
    assert_error(result[0])


@test(binary="crackme03.elf")
def test_put_int_roundtrip_u64():
    """put_int writes a 64-bit value that can be read back and restored."""
    original = get_int({"addr": CRACKME_DSO_HANDLE, "ty": "u64"})[0]
    assert_ok(original, "value")
    original_value = original["value"]
    new_value = original_value ^ 0x55

    try:
        written = put_int(
            {"addr": CRACKME_DSO_HANDLE, "ty": "u64", "value": hex(new_value)}
        )[0]
        assert "error" not in written
        roundtrip = get_int({"addr": CRACKME_DSO_HANDLE, "ty": "u64"})[0]
        assert roundtrip["value"] == new_value
    finally:
        restore = put_int(
            {"addr": CRACKME_DSO_HANDLE, "ty": "u64", "value": hex(original_value)}
        )[0]
        assert "error" not in restore

    restored = get_int({"addr": CRACKME_DSO_HANDLE, "ty": "u64"})[0]
    assert restored["value"] == original_value


@test()
def test_put_int_roundtrip_signed_i16():
    """put_int correctly writes and restores signed 16-bit integers."""
    data_addr = get_data_address()
    if not data_addr:
        skip_test("binary has no data segment")

    original = get_bytes({"addr": data_addr, "size": 2})[0]
    assert_ok(original, "data")
    original_plain = _plain_hex_bytes(original["data"])

    try:
        written = put_int({"addr": data_addr, "ty": "i16", "value": "-2"})[0]
        assert "error" not in written
        roundtrip = get_int({"addr": data_addr, "ty": "i16"})[0]
        assert roundtrip["value"] == -2
    finally:
        patch({"addr": data_addr, "data": original_plain})

    restored = get_bytes({"addr": data_addr, "size": 2})[0]
    assert _plain_hex_bytes(restored["data"]) == original_plain


@test()
def test_put_int_overflow():
    """put_int reports overflow when the value does not fit the target type."""
    data_addr = get_data_address()
    if not data_addr:
        skip_test("binary has no data segment")

    result = put_int({"addr": data_addr, "ty": "u8", "value": "0x100"})[0]
    assert "error" in result
    assert_error(result, contains="does not fit")


@test()
def test_put_int_invalid_address():
    """put_int rejects writes to unmapped addresses."""
    result = put_int({"addr": get_unmapped_address(), "ty": "u32", "value": "1"})[0]
    assert "error" in result
    assert_error(result, contains="Address not mapped")


@test()
def test_get_global_value_not_found():
    """get_global_value reports unknown names as not found."""
    result = get_global_value("definitely_not_a_global_symbol")
    assert_is_list(result, min_length=1)
    assert_error(result[0], contains="Not found")
