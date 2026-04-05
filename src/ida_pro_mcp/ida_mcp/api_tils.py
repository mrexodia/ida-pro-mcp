"""Type library (TIL) management for IDA Pro MCP.

Provides tools for listing, loading, and importing from type libraries.
"""

from typing import Annotated

import ida_typeinf
import idaapi

from .rpc import tool
from .sync import idasync, IDAError
from .utils import normalize_list_input, paginate, pattern_filter


# ============================================================================
# TIL Tools
# ============================================================================


@tool
@idasync
def list_tils() -> list[dict]:
    """List all loaded type libraries (TILs)."""
    tils = []
    ti = ida_typeinf.get_idati()
    if ti:
        tils.append(
            {
                "name": ti.name or "local",
                "desc": ti.desc or "",
                "is_local": True,
                "ntypes": ti.get_ordinal_qty() - 1,
            }
        )
        # List dependent TILs
        for i in range(ti.get_number_of_bases()):
            base = ti.get_base(i)
            if base:
                tils.append(
                    {
                        "name": base.name or f"base_{i}",
                        "desc": base.desc or "",
                        "is_local": False,
                        "ntypes": base.get_ordinal_qty() - 1
                        if base.get_ordinal_qty() > 0
                        else 0,
                    }
                )
    return tils


@tool
@idasync
def load_til(
    names: Annotated[
        str, "TIL names to load, comma-separated (e.g., 'mssdk_win10', 'ntapi')"
    ],
) -> list[dict]:
    """Load type library/libraries by name."""
    items = normalize_list_input(names)
    results = []
    for name in items:
        try:
            result = ida_typeinf.add_til(name, ida_typeinf.ADDTIL_DEFAULT)
            if result:
                results.append({"name": name, "ok": True})
            else:
                results.append({"name": name, "error": "Failed to load TIL"})
        except Exception as e:
            results.append({"name": name, "error": str(e)})
    return results


@tool
@idasync
def til_types(
    til_name: Annotated[str, "TIL name (empty for local types)"] = "",
    pattern: Annotated[str, "Optional glob pattern to filter type names"] = "",
    offset: Annotated[int, "Pagination offset"] = 0,
    count: Annotated[int, "Max results (0=all, default 500)"] = 500,
) -> list[dict]:
    """List types in a type library."""
    ti = ida_typeinf.get_idati()
    if not ti:
        raise IDAError("No type library available")

    # Find the right TIL
    target = ti
    if til_name:
        found = False
        for i in range(ti.get_number_of_bases()):
            base = ti.get_base(i)
            if base and base.name == til_name:
                target = base
                found = True
                break
        if not found:
            raise IDAError(f"TIL not found: {til_name}")

    types = []
    for ordinal in range(1, target.get_ordinal_qty()):
        name = ida_typeinf.get_numbered_type_name(target, ordinal)
        if not name:
            continue
        if pattern and not pattern_filter(name, pattern):
            continue

        tif = ida_typeinf.tinfo_t()
        if tif.get_numbered_type(target, ordinal):
            types.append(
                {
                    "ordinal": ordinal,
                    "name": name,
                    "type_str": tif.dstr() or "",
                    "size": tif.get_size()
                    if tif.get_size() != idaapi.BADSIZE
                    else None,
                    "is_struct": tif.is_struct(),
                    "is_union": tif.is_union(),
                    "is_enum": tif.is_enum(),
                    "is_typedef": tif.is_typedef(),
                    "is_func": tif.is_func(),
                    "is_ptr": tif.is_ptr(),
                }
            )

    return paginate(types, offset, count)


@tool
@idasync
def import_type(
    til_name: Annotated[str, "Source TIL name"],
    type_names: Annotated[str, "Type names to import, comma-separated"],
) -> list[dict]:
    """Import type(s) from a loaded TIL into the local type library."""
    items = normalize_list_input(type_names)
    ti = ida_typeinf.get_idati()
    if not ti:
        raise IDAError("No type library available")

    # Find source TIL
    source = None
    for i in range(ti.get_number_of_bases()):
        base = ti.get_base(i)
        if base and base.name == til_name:
            source = base
            break

    if source is None:
        raise IDAError(f"TIL not found: {til_name}")

    results = []
    for name in items:
        try:
            tif = ida_typeinf.tinfo_t()
            if tif.get_named_type(source, name):
                ordinal = tif.force_tid()
                if ordinal:
                    results.append({"name": name, "ordinal": ordinal, "ok": True})
                else:
                    results.append({"name": name, "error": "Failed to import"})
            else:
                results.append({"name": name, "error": "Type not found in TIL"})
        except Exception as e:
            results.append({"name": name, "error": str(e)})
    return results
