"""Fixup and relocation operations for IDA Pro MCP.

Provides tools for listing and querying fixups (relocations) in the database.
"""

from typing import Annotated

import ida_fixup
import ida_ida
import idaapi
import idc

from .rpc import tool
from .sync import idasync
from .utils import parse_address, normalize_list_input, paginate


# ============================================================================
# Fixup type names
# ============================================================================

_FIXUP_TYPES = {}
for _name, _label in [
    ("FIXUP_BYTE", "byte"),
    ("FIXUP_SHORT", "short"),
    ("FIXUP_OFF16", "off16"),
    ("FIXUP_OFF32", "off32"),
    ("FIXUP_OFF64", "off64"),
    ("FIXUP_HI8", "hi8"),
    ("FIXUP_LOW16", "low16"),
    ("FIXUP_HI16", "hi16"),
]:
    if hasattr(ida_fixup, _name):
        _FIXUP_TYPES[getattr(ida_fixup, _name)] = _label


def _fixup_info(ea: int) -> dict | None:
    """Get fixup info at an address."""
    fd = ida_fixup.fixup_data_t()
    if not ida_fixup.get_fixup(fd, ea):
        return None

    ftype = fd.get_type()
    return {
        "addr": hex(ea),
        "type": ftype,
        "type_name": _FIXUP_TYPES.get(ftype, f"unknown({ftype})"),
        "offset": hex(fd.off),
        "is_extdef": bool(fd.has_base()),
    }


# ============================================================================
# Fixup Tools
# ============================================================================


@tool
@idasync
def list_fixups(
    start: Annotated[str, "Start address (default: beginning)"] = "",
    end: Annotated[str, "End address (default: end of database)"] = "",
    offset: Annotated[int, "Pagination offset"] = 0,
    count: Annotated[int, "Max results (0=all, default 500)"] = 500,
) -> list[dict]:
    """List all fixups (relocations) in the database or within a range."""
    if start:
        start_ea = parse_address(start)
    else:
        start_ea = ida_ida.inf_get_min_ea()

    if end:
        end_ea = parse_address(end)
    else:
        end_ea = ida_ida.inf_get_max_ea()

    fixups = []
    ea = ida_fixup.get_first_fixup_ea()
    while ea != idaapi.BADADDR:
        if ea >= start_ea and ea < end_ea:
            info = _fixup_info(ea)
            if info:
                fixups.append(info)
        ea = ida_fixup.get_next_fixup_ea(ea)

    return paginate(fixups, offset, count)


@tool
@idasync
def get_fixup(
    addrs: Annotated[str, "Addresses to check for fixups, comma-separated"],
) -> list[dict]:
    """Get fixup information at specific address(es)."""
    items = normalize_list_input(addrs)
    results = []
    for item in items:
        try:
            ea = parse_address(item)
            info = _fixup_info(ea)
            if info:
                results.append(info)
            else:
                results.append({"addr": hex(ea), "has_fixup": False})
        except Exception as e:
            results.append({"addr": item, "error": str(e)})
    return results


@tool
@idasync
def fixup_count() -> dict:
    """Count total number of fixups in the database."""
    count = 0
    ea = ida_fixup.get_first_fixup_ea()
    while ea != idaapi.BADADDR:
        count += 1
        ea = ida_fixup.get_next_fixup_ea(ea)
    return {"count": count}
