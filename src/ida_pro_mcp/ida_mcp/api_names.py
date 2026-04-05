"""Name operations for IDA Pro MCP.

Provides tools for listing names, demangling, and name management.
"""

from typing import Annotated

import ida_name
import ida_ida
import idaapi
import idautils
import idc

from .rpc import tool
from .sync import idasync
from .utils import parse_address, normalize_list_input, paginate, pattern_filter


# ============================================================================
# Name Tools
# ============================================================================


@tool
@idasync
def list_names(
    pattern: Annotated[str, "Optional glob pattern to filter names"] = "",
    offset: Annotated[int, "Pagination offset"] = 0,
    count: Annotated[int, "Max results (0=all, default 500)"] = 500,
) -> list[dict]:
    """List all named addresses in the database."""
    names = []
    for ea, name in idautils.Names():
        if pattern and not pattern_filter(name, pattern):
            continue
        names.append(
            {
                "addr": hex(ea),
                "name": name,
            }
        )

    return paginate(names, offset, count)


@tool
@idasync
def demangle(
    names: Annotated[str, "Mangled names, comma-separated"],
    disable_mask: Annotated[int, "Demangling options mask (default 0)"] = 0,
) -> list[dict]:
    """Demangle C++/decorated name(s)."""
    items = normalize_list_input(names)
    results = []
    for name in items:
        demangled = ida_name.demangle_name(name, disable_mask)
        results.append(
            {
                "mangled": name,
                "demangled": demangled if demangled else None,
            }
        )
    return results


@tool
@idasync
def get_name_at(
    addrs: Annotated[str, "Addresses, comma-separated"],
) -> list[dict]:
    """Get the name at address(es), including auto-generated names."""
    items = normalize_list_input(addrs)
    results = []
    for item in items:
        try:
            ea = parse_address(item)
            name = ida_name.get_name(ea) or ""
            long_name = ida_name.get_long_name(ea) or ""
            demangled = ida_name.demangle_name(name, 0) if name else None
            is_user = (
                bool(ida_name.get_name_flags(ea) & ida_name.SN_NON_AUTO)
                if name
                else False
            )

            results.append(
                {
                    "addr": hex(ea),
                    "name": name,
                    "long_name": long_name,
                    "demangled": demangled,
                    "is_user_defined": is_user,
                }
            )
        except Exception as e:
            results.append({"addr": item, "error": str(e)})
    return results


@tool
@idasync
def name_to_addr(
    names: Annotated[str, "Names to resolve, comma-separated"],
) -> list[dict]:
    """Resolve name(s) to address(es)."""
    items = normalize_list_input(names)
    results = []
    for name in items:
        ea = ida_name.get_name_ea(idaapi.BADADDR, name)
        if ea != idaapi.BADADDR:
            results.append({"name": name, "addr": hex(ea)})
        else:
            results.append({"name": name, "error": "Name not found"})
    return results


@tool
@idasync
def set_name_flags(
    addr: Annotated[str, "Address"],
    name: Annotated[str, "New name"],
    flags: Annotated[
        int,
        "Name flags (SN_CHECK=0, SN_NOCHECK=1, SN_PUBLIC=2, SN_NON_PUBLIC=4, SN_WEAK=8, SN_NON_WEAK=16, SN_AUTO=32, SN_NON_AUTO=64, SN_NOLIST=128, SN_LOCAL=256)",
    ] = 0,
) -> dict:
    """Set a name at an address with specific flags."""
    ea = parse_address(addr)
    ok = ida_name.set_name(ea, name, flags)
    return {"addr": hex(ea), "name": name, "ok": ok}


@tool
@idasync
def name_count() -> dict:
    """Count total named addresses in the database."""
    count = sum(1 for _ in idautils.Names())
    return {"count": count}
