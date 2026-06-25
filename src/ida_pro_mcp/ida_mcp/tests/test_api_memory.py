"""Tests for api_memory API functions."""

from .._kernel.framework import (
    test,
    skip_test,
    patching_enabled,
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
from .._kernel.utils import read_bytes_bss_safe, read_int_bss_safe


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
def test_patch_withheld_by_default():
    """AXIS-7 INVARIANT: with the gate closed (default), patch only PREVIEWS and
    writes nothing — analysis must never mutate the binary's bytes."""
    data_addr = get_data_address()
    if not data_addr:
        skip_test("binary has no data segment")

    before = _plain_hex_bytes(get_bytes({"addr": data_addr, "size": 4})[0]["data"])
    resp = patch({"addr": data_addr, "data": "90 90 90 90"})
    assert isinstance(resp, dict), f"expected envelope dict, got {type(resp).__name__}"
    assert resp["applied"] is False, "patch must not write without explicit consent"
    entry = resp["results"][0]
    assert entry.get("applied") is False
    # The preview still reports the original bytes that WOULD be overwritten.
    assert entry.get("original") is not None
    after = _plain_hex_bytes(get_bytes({"addr": data_addr, "size": 4})[0]["data"])
    assert after == before, "bytes changed despite a withheld (preview) patch"


@test()
def test_patch_roundtrip_changes_and_restores_bytes():
    """With patching enabled and confirmed, patch modifies bytes; restore puts them back."""
    data_addr = get_data_address()
    if not data_addr:
        skip_test("binary has no data segment")

    original = get_bytes({"addr": data_addr, "size": 4})[0]
    assert_ok(original, "data")
    original_plain = _plain_hex_bytes(original["data"])
    replacement = "90 90 90 90"
    if original_plain == replacement.replace(" ", ""):
        replacement = "cc cc cc cc"

    with patching_enabled():
        try:
            resp = patch({"addr": data_addr, "data": replacement}, confirm=True, dry_run=False)
            assert resp["applied"] is True
            entry = resp["results"][0]
            assert "error" not in entry
            assert entry["original"] is not None
            changed = get_bytes({"addr": data_addr, "size": 4})[0]
            assert _plain_hex_bytes(changed["data"]) == replacement.replace(" ", "")
        finally:
            patch({"addr": data_addr, "data": original_plain}, confirm=True, dry_run=False)

    restored = get_bytes({"addr": data_addr, "size": 4})[0]
    assert _plain_hex_bytes(restored["data"]) == original_plain


@test()
def test_patch_invalid_address():
    """patch reports a per-item error for an unmapped address (even in preview)."""
    resp = patch({"addr": get_unmapped_address(), "data": "90"})
    entry = resp["results"][0]
    assert entry["addr"] == get_unmapped_address()
    assert_error(entry, contains="mapped")


@test()
def test_patch_invalid_hex_data():
    """patch rejects invalid hexadecimal payloads (per-item error in the envelope)."""
    data_addr = get_data_address()
    if not data_addr:
        skip_test("binary has no data segment")

    resp = patch({"addr": data_addr, "data": "ZZZZ"})
    assert_error(resp["results"][0])


@test(binary="crackme03.elf")
def test_put_int_roundtrip_u64():
    """put_int writes a 64-bit value (enabled+confirmed) that reads back and restores."""
    original = get_int({"addr": CRACKME_DSO_HANDLE, "ty": "u64"})[0]
    assert_ok(original, "value")
    original_value = original["value"]
    new_value = original_value ^ 0x55

    with patching_enabled():
        try:
            written = put_int(
                {"addr": CRACKME_DSO_HANDLE, "ty": "u64", "value": hex(new_value)},
                confirm=True,
                dry_run=False,
            )
            assert written["applied"] is True
            assert "error" not in written["results"][0]
            roundtrip = get_int({"addr": CRACKME_DSO_HANDLE, "ty": "u64"})[0]
            assert roundtrip["value"] == new_value
        finally:
            put_int(
                {"addr": CRACKME_DSO_HANDLE, "ty": "u64", "value": hex(original_value)},
                confirm=True,
                dry_run=False,
            )

    restored = get_int({"addr": CRACKME_DSO_HANDLE, "ty": "u64"})[0]
    assert restored["value"] == original_value


@test()
def test_put_int_roundtrip_signed_i16():
    """put_int correctly writes and restores signed 16-bit integers (enabled+confirmed)."""
    data_addr = get_data_address()
    if not data_addr:
        skip_test("binary has no data segment")

    original = get_bytes({"addr": data_addr, "size": 2})[0]
    assert_ok(original, "data")
    original_plain = _plain_hex_bytes(original["data"])

    with patching_enabled():
        try:
            written = put_int(
                {"addr": data_addr, "ty": "i16", "value": "-2"}, confirm=True, dry_run=False
            )
            assert written["applied"] is True
            assert "error" not in written["results"][0]
            roundtrip = get_int({"addr": data_addr, "ty": "i16"})[0]
            assert roundtrip["value"] == -2
        finally:
            patch({"addr": data_addr, "data": original_plain}, confirm=True, dry_run=False)

    restored = get_bytes({"addr": data_addr, "size": 2})[0]
    assert _plain_hex_bytes(restored["data"]) == original_plain


@test()
def test_put_int_overflow():
    """put_int reports overflow when the value does not fit the target type."""
    data_addr = get_data_address()
    if not data_addr:
        skip_test("binary has no data segment")

    resp = put_int({"addr": data_addr, "ty": "u8", "value": "0x100"})
    entry = resp["results"][0]
    assert "error" in entry
    assert_error(entry, contains="does not fit")


@test()
def test_put_int_invalid_address():
    """put_int rejects writes to unmapped addresses (per-item error in the envelope)."""
    resp = put_int({"addr": get_unmapped_address(), "ty": "u32", "value": "1"})
    entry = resp["results"][0]
    assert "error" in entry
    assert_error(entry, contains="mapped")


@test()
def test_get_global_value_not_found():
    """get_global_value reports unknown names as not found."""
    result = get_global_value("definitely_not_a_global_symbol")
    assert_is_list(result, min_length=1)
    assert_error(result[0], contains="Not found")


# ============================================================================
# BSS / unloaded-byte handling
# ============================================================================


def _find_unloaded_addr() -> int | None:
    """Find an address whose byte is not loaded in the IDB.

    Prefers SEG_BSS segments (most portable signal), falls back to any segment
    whose starting byte reports is_loaded=False. Returns None if the binary
    has no unloaded region - in which case BSS tests should skip.
    """
    import ida_bytes
    import idaapi
    import idautils

    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        if seg is None:
            continue
        if seg.type == idaapi.SEG_BSS:
            return seg.start_ea

    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        if seg is None:
            continue
        if not ida_bytes.is_loaded(seg.start_ea):
            return seg.start_ea

    return None


def _find_named_bss_symbol() -> str | None:
    """Find a named global whose starting byte is not loaded (BSS-like)."""
    import ida_bytes
    import idaapi
    import idautils

    for addr, name in idautils.Names():
        if not name:
            continue
        if idaapi.get_func(addr):
            continue
        if not ida_bytes.is_loaded(addr):
            return name

    return None


@test()
def test_read_bytes_bss_safe_returns_zeros_for_unloaded():
    """read_bytes_bss_safe substitutes 0 for unloaded (BSS) bytes."""
    ea = _find_unloaded_addr()
    if ea is None:
        skip_test("binary has no unloaded/BSS region")

    raw = read_bytes_bss_safe(ea, 16)
    assert isinstance(raw, bytes)
    assert len(raw) == 16
    assert raw == b"\x00" * 16, f"expected all zeros, got {raw.hex()}"


@test()
def test_read_int_bss_safe_returns_zero_for_unloaded():
    """read_int_bss_safe returns 0 for every int width on unloaded bytes."""
    ea = _find_unloaded_addr()
    if ea is None:
        skip_test("binary has no unloaded/BSS region")

    for size in (1, 2, 4, 8):
        assert read_int_bss_safe(ea, size) == 0, (
            f"expected 0 for size {size}, got {read_int_bss_safe(ea, size):#x}"
        )


@test()
def test_get_int_reads_bss_region_as_zero():
    """get_int returns 0, not the 0xff sentinel, for unloaded (BSS) bytes."""
    ea = _find_unloaded_addr()
    if ea is None:
        skip_test("binary has no unloaded/BSS region")

    for ty in ("u8", "u16", "u32", "u64", "i32", "i64"):
        result = get_int({"addr": hex(ea), "ty": ty})
        assert_is_list(result, min_length=1)
        entry = result[0]
        assert "error" not in entry, (
            f"get_int({ty}) at BSS errored: {entry.get('error')!r}"
        )
        assert entry["value"] == 0, (
            f"expected 0 for {ty} at BSS, got {entry['value']!r}"
        )


@test()
def test_get_bytes_reads_bss_region_as_zero():
    """get_bytes returns zeroed bytes for an unloaded (BSS) region."""
    ea = _find_unloaded_addr()
    if ea is None:
        skip_test("binary has no unloaded/BSS region")

    result = get_bytes({"addr": hex(ea), "size": 8})
    assert_is_list(result, min_length=1)
    entry = result[0]
    assert_ok(entry, "data")
    parts = entry["data"].split()
    assert len(parts) == 8
    assert all(int(p, 16) == 0 for p in parts), (
        f"expected all zeros for BSS, got {entry['data']!r}"
    )


@test()
def test_get_global_value_bss_symbol_is_zero():
    """get_global_value on a BSS-resident named global returns 0, not 0xff."""
    import ida_bytes

    name = _find_named_bss_symbol()
    if name is None:
        skip_test("binary has no named BSS global")

    result = get_global_value(name)
    assert_is_list(result, min_length=1)
    entry = result[0]
    assert_ok(entry, "value")
    value_str = entry["value"]

    # Integer-sized globals return a single "0x0". Larger shapes return a
    # space-separated run of per-byte hex values.
    parts = value_str.split()
    assert parts, f"unexpected empty value for BSS global {name}"
    assert all(int(p, 16) == 0 for p in parts), (
        f"expected all zeros for BSS global {name}, got {value_str!r}"
    )
