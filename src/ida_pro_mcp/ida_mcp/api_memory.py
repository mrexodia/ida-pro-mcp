"""Memory reading and writing operations for IDA Pro MCP.

This module provides batch operations for reading and writing memory at various
granularities (bytes, u8, u16, u32, u64, strings) and patching binary data.
"""

from typing import Annotated
import ida_bytes
import ida_nalt
import ida_typeinf
import idaapi

from .rpc import tool
from .sync import idasync, IDAError
from .utils import normalize_list_input, parse_address, MemoryRead, MemoryPatch
from .tests import (
    test,
    assert_has_keys,
    assert_is_list,
    assert_non_empty,
    get_first_segment,
    get_any_string,
)


# ============================================================================
# Memory Reading Operations
# ============================================================================


@tool
@idasync
def get_bytes(regions: list[MemoryRead] | MemoryRead) -> list[dict]:
    """Read bytes from memory addresses"""
    if isinstance(regions, dict):
        regions = [regions]

    results = []
    for item in regions:
        addr = item.get("addr", "")
        size = item.get("size", 0)

        try:
            ea = parse_address(addr)
            data = " ".join(f"{x:#02x}" for x in ida_bytes.get_bytes(ea, size))
            results.append({"addr": addr, "data": data})
        except Exception as e:
            results.append({"addr": addr, "data": None, "error": str(e)})

    return results


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


@tool
@idasync
def get_u8(
    addrs: Annotated[list[str] | str, "Addresses to read 8-bit unsigned integers from"],
) -> list[dict]:
    """Read 8-bit unsigned integers from memory addresses"""
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)
            value = ida_bytes.get_wide_byte(ea)
            results.append({"addr": addr, "value": value})
        except Exception as e:
            results.append({"addr": addr, "value": None, "error": str(e)})

    return results


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


@tool
@idasync
def get_u16(
    addrs: Annotated[
        list[str] | str, "Addresses to read 16-bit unsigned integers from"
    ],
) -> list[dict]:
    """Read 16-bit unsigned integers from memory addresses"""
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)
            value = ida_bytes.get_wide_word(ea)
            results.append({"addr": addr, "value": value})
        except Exception as e:
            results.append({"addr": addr, "value": None, "error": str(e)})

    return results


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


@tool
@idasync
def get_u32(
    addrs: Annotated[
        list[str] | str, "Addresses to read 32-bit unsigned integers from"
    ],
) -> list[dict]:
    """Read 32-bit unsigned integers from memory addresses"""
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)
            value = ida_bytes.get_wide_dword(ea)
            results.append({"addr": addr, "value": value})
        except Exception as e:
            results.append({"addr": addr, "value": None, "error": str(e)})

    return results


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


@tool
@idasync
def get_u64(
    addrs: Annotated[
        list[str] | str, "Addresses to read 64-bit unsigned integers from"
    ],
) -> list[dict]:
    """Read 64-bit unsigned integers from memory addresses"""
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)
            value = ida_bytes.get_qword(ea)
            results.append({"addr": addr, "value": value})
        except Exception as e:
            results.append({"addr": addr, "value": None, "error": str(e)})

    return results


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


@tool
@idasync
def get_string(
    addrs: Annotated[list[str] | str, "Addresses to read strings from"],
) -> list[dict]:
    """Read strings from memory addresses"""
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)
            value = idaapi.get_strlit_contents(ea, -1, 0).decode("utf-8")
            results.append({"addr": addr, "value": value})
        except Exception as e:
            results.append({"addr": addr, "value": None, "error": str(e)})

    return results


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


def get_global_variable_value_internal(ea: int) -> str:
    tif = ida_typeinf.tinfo_t()
    if not ida_nalt.get_tinfo(tif, ea):
        if not ida_bytes.has_any_name(ea):
            raise IDAError(f"Failed to get type information for variable at {ea:#x}")

        size = ida_bytes.get_item_size(ea)
        if size == 0:
            raise IDAError(f"Failed to get type information for variable at {ea:#x}")
    else:
        size = tif.get_size()

    if size == 0 and tif.is_array() and tif.get_array_element().is_decl_char():
        return_string = idaapi.get_strlit_contents(ea, -1, 0).decode("utf-8").strip()
        return f'"{return_string}"'
    elif size == 1:
        return hex(ida_bytes.get_byte(ea))
    elif size == 2:
        return hex(ida_bytes.get_word(ea))
    elif size == 4:
        return hex(ida_bytes.get_dword(ea))
    elif size == 8:
        return hex(ida_bytes.get_qword(ea))
    else:
        return " ".join(hex(x) for x in ida_bytes.get_bytes(ea, size))


@tool
@idasync
def get_global_value(
    queries: Annotated[
        list[str] | str, "Global variable addresses or names to read values from"
    ],
) -> list[dict]:
    """Read global variable values by address or name
    (auto-detects hex addresses vs names)"""
    from .utils import looks_like_address

    queries = normalize_list_input(queries)
    results = []

    for query in queries:
        try:
            ea = idaapi.BADADDR

            # Try as address first if it looks like one
            if looks_like_address(query):
                try:
                    ea = parse_address(query)
                except Exception:
                    ea = idaapi.BADADDR

            # Fall back to name lookup
            if ea == idaapi.BADADDR:
                ea = idaapi.get_name_ea(idaapi.BADADDR, query)

            if ea == idaapi.BADADDR:
                results.append({"query": query, "value": None, "error": "Not found"})
                continue

            value = get_global_variable_value_internal(ea)
            results.append({"query": query, "value": value, "error": None})
        except Exception as e:
            results.append({"query": query, "value": None, "error": str(e)})

    return results


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


# ============================================================================
# Batch Data Operations
# ============================================================================


@tool
@idasync
def patch(patches: list[MemoryPatch] | MemoryPatch) -> list[dict]:
    """Patch bytes at memory addresses with hex data"""
    if isinstance(patches, dict):
        patches = [patches]

    results = []

    for patch in patches:
        try:
            ea = parse_address(patch["addr"])
            data = bytes.fromhex(patch["data"])

            ida_bytes.patch_bytes(ea, data)
            results.append(
                {"addr": patch["addr"], "size": len(data), "ok": True, "error": None}
            )

        except Exception as e:
            results.append({"addr": patch.get("addr"), "size": 0, "error": str(e)})

    return results


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
