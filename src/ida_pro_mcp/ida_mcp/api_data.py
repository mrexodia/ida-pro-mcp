"""Data definition operations for IDA Pro MCP.

Provides tools for creating data items: bytes, words, dwords, qwords,
floats, doubles, strings, arrays, and alignment directives.
"""

from typing import Annotated, TypedDict

import ida_bytes
import ida_nalt
import idaapi
import idc

from .rpc import tool
from .sync import idasync, IDAError
from .utils import parse_address, normalize_list_input


# ============================================================================
# TypedDict Definitions
# ============================================================================


class MakeDataOp(TypedDict, total=False):
    addr: Annotated[str, "Address"]
    type: Annotated[
        str,
        "Data type: byte|word|dword|qword|oword|float|double|tbyte|packreal|yword|zword",
    ]
    count: Annotated[int, "Number of items for array (default 1)"]


class MakeStringOp(TypedDict, total=False):
    addr: Annotated[str, "Start address"]
    length: Annotated[int, "String length (0=auto-detect)"]
    strtype: Annotated[int, "String type: 0=C, 1=Pascal, 2=LEN2, 3=Unicode, 5=UTF16"]


class MakeArrayOp(TypedDict, total=False):
    addr: Annotated[str, "Start address"]
    elem_size: Annotated[int, "Element size in bytes (1,2,4,8)"]
    count: Annotated[int, "Number of elements"]


# ============================================================================
# Data type mapping
# ============================================================================

_DATA_TYPE_MAP = {
    "byte": (ida_bytes.byte_flag(), 1),
    "word": (ida_bytes.word_flag(), 2),
    "dword": (ida_bytes.dword_flag(), 4),
    "qword": (ida_bytes.qword_flag(), 8),
    "oword": (ida_bytes.oword_flag(), 16),
    "float": (ida_bytes.float_flag(), 4),
    "double": (ida_bytes.double_flag(), 8),
    "tbyte": (ida_bytes.tbyte_flag(), 10),
    "packreal": (ida_bytes.packreal_flag(), 12),
}

# yword and zword may not exist in older IDA versions
if hasattr(ida_bytes, "yword_flag"):
    _DATA_TYPE_MAP["yword"] = (ida_bytes.yword_flag(), 32)
if hasattr(ida_bytes, "zword_flag"):
    _DATA_TYPE_MAP["zword"] = (ida_bytes.zword_flag(), 64)


# ============================================================================
# Data Definition Tools
# ============================================================================


@tool
@idasync
def make_data(items: list[MakeDataOp] | MakeDataOp) -> list[dict]:
    """Create data item(s) at address(es).

    Supported types: byte, word, dword, qword, oword, float, double, tbyte, packreal, yword, zword.
    Use count > 1 to create an array of that type.
    """
    if isinstance(items, dict):
        items = [items]

    results = []
    for item in items:
        try:
            ea = parse_address(item.get("addr", "0"))
            dtype = item.get("type", "byte").lower()
            count = item.get("count", 1)

            if dtype not in _DATA_TYPE_MAP:
                results.append(
                    {
                        "addr": hex(ea),
                        "error": f"Unknown type: {dtype}. Use: {', '.join(_DATA_TYPE_MAP.keys())}",
                    }
                )
                continue

            flag, elem_size = _DATA_TYPE_MAP[dtype]
            total_size = elem_size * count

            if count > 1:
                # Create array
                ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, total_size)
                ok = ida_bytes.create_data(ea, flag, elem_size, count)
            else:
                ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, elem_size)
                ok = ida_bytes.create_data(ea, flag, elem_size, 0)

            results.append({"addr": hex(ea), "type": dtype, "count": count, "ok": ok})
        except Exception as e:
            results.append({"addr": item.get("addr", ""), "error": str(e)})
    return results


@tool
@idasync
def make_string(items: list[MakeStringOp] | MakeStringOp) -> list[dict]:
    """Create string(s) at address(es).

    String types: 0=C (null-terminated), 1=Pascal (length-prefixed),
    2=LEN2 (2-byte length), 3=Unicode/UTF-16, 5=UTF-16.
    Set length=0 for auto-detection.
    """
    if isinstance(items, dict):
        items = [items]

    results = []
    for item in items:
        try:
            ea = parse_address(item.get("addr", "0"))
            length = item.get("length", 0)
            strtype = item.get("strtype", idc.STRTYPE_C)

            if length == 0:
                # Auto-detect: let IDA figure out the length
                ok = ida_bytes.create_strlit(ea, 0, strtype)
            else:
                ok = ida_bytes.create_strlit(ea, ea + length, strtype)

            results.append({"addr": hex(ea), "strtype": strtype, "ok": ok})
        except Exception as e:
            results.append({"addr": item.get("addr", ""), "error": str(e)})
    return results


@tool
@idasync
def make_array(items: list[MakeArrayOp] | MakeArrayOp) -> list[dict]:
    """Create array(s) at address(es) with specified element size and count."""
    if isinstance(items, dict):
        items = [items]

    size_to_flag = {
        1: ida_bytes.byte_flag(),
        2: ida_bytes.word_flag(),
        4: ida_bytes.dword_flag(),
        8: ida_bytes.qword_flag(),
    }

    results = []
    for item in items:
        try:
            ea = parse_address(item.get("addr", "0"))
            elem_size = item.get("elem_size", 1)
            count = item.get("count", 1)

            flag = size_to_flag.get(elem_size)
            if flag is None:
                results.append(
                    {
                        "addr": hex(ea),
                        "error": f"Unsupported element size: {elem_size}. Use 1, 2, 4, or 8.",
                    }
                )
                continue

            total = elem_size * count
            ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, total)
            ok = ida_bytes.create_data(ea, flag, elem_size, count)
            results.append(
                {"addr": hex(ea), "elem_size": elem_size, "count": count, "ok": ok}
            )
        except Exception as e:
            results.append({"addr": item.get("addr", ""), "error": str(e)})
    return results


@tool
@idasync
def make_align(
    addrs: Annotated[str, "Addresses, comma-separated"],
    alignment: Annotated[int, "Alignment boundary (power of 2)"] = 0,
) -> list[dict]:
    """Create alignment directive(s) at address(es)."""
    items = normalize_list_input(addrs)
    results = []
    for item in items:
        try:
            ea = parse_address(item)
            ok = idc.create_align(ea, alignment, 0)
            results.append({"addr": hex(ea), "ok": bool(ok)})
        except Exception as e:
            results.append({"addr": item, "error": str(e)})
    return results


@tool
@idasync
def get_data_type(
    addrs: Annotated[str, "Addresses, comma-separated"],
) -> list[dict]:
    """Get the data type and flags at address(es)."""
    items = normalize_list_input(addrs)
    results = []
    for item in items:
        try:
            ea = parse_address(item)
            flags = ida_bytes.get_flags(ea)
            size = ida_bytes.get_item_size(ea)

            dtype = "unknown"
            if ida_bytes.is_code(flags):
                dtype = "code"
            elif ida_bytes.is_byte(flags):
                dtype = "byte"
            elif ida_bytes.is_word(flags):
                dtype = "word"
            elif ida_bytes.is_dword(flags):
                dtype = "dword"
            elif ida_bytes.is_qword(flags):
                dtype = "qword"
            elif ida_bytes.is_oword(flags):
                dtype = "oword"
            elif ida_bytes.is_float(flags):
                dtype = "float"
            elif ida_bytes.is_double(flags):
                dtype = "double"
            elif ida_bytes.is_strlit(flags):
                dtype = "string"
            elif ida_bytes.is_struct(flags):
                dtype = "struct"
            elif ida_bytes.is_align(flags):
                dtype = "align"

            results.append(
                {
                    "addr": hex(ea),
                    "type": dtype,
                    "size": size,
                    "is_head": ida_bytes.is_head(flags),
                    "has_value": ida_bytes.has_value(flags),
                    "is_loaded": ida_bytes.is_loaded(ea),
                }
            )
        except Exception as e:
            results.append({"addr": item, "error": str(e)})
    return results
