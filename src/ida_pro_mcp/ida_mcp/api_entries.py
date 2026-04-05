"""Entry point and export management for IDA Pro MCP.

Provides tools for listing, adding, and deleting entry points and exports.
"""

from typing import Annotated, TypedDict

import ida_entry
import ida_name
import idaapi

from .rpc import tool, unsafe
from .sync import idasync, IDAError
from .utils import parse_address, normalize_list_input, paginate, pattern_filter


# ============================================================================
# TypedDict Definitions
# ============================================================================


class EntryAdd(TypedDict, total=False):
    ordinal: Annotated[int, "Ordinal number"]
    addr: Annotated[str, "Address (hex)"]
    name: Annotated[str, "Entry point name"]
    is_func: Annotated[bool, "Mark as function entry (default true)"]


# ============================================================================
# Entry Point Tools
# ============================================================================


@tool
@idasync
def list_entries(
    pattern: Annotated[str, "Optional glob pattern to filter by name"] = "",
    offset: Annotated[int, "Pagination offset"] = 0,
    count: Annotated[int, "Max results (0=all)"] = 0,
) -> list[dict]:
    """List all entry points (exports) in the binary."""
    entries = []
    for i in range(ida_entry.get_entry_qty()):
        ordinal = ida_entry.get_entry_ordinal(i)
        ea = ida_entry.get_entry(ordinal)
        name = ida_entry.get_entry_name(ordinal) or ""
        entries.append(
            {
                "ordinal": ordinal,
                "addr": hex(ea),
                "name": name,
                "index": i,
            }
        )

    if pattern:
        entries = [e for e in entries if pattern_filter(e["name"], pattern)]

    return paginate(entries, offset, count)


@tool
@idasync
def get_entry(
    entries: Annotated[str, "Ordinal numbers or names, comma-separated"],
) -> list[dict]:
    """Get entry point information by ordinal or name."""
    items = normalize_list_input(entries)
    results = []
    for item in items:
        try:
            # Try as ordinal
            try:
                ordinal = int(item)
                ea = ida_entry.get_entry(ordinal)
                if ea != idaapi.BADADDR:
                    name = ida_entry.get_entry_name(ordinal) or ""
                    results.append({"ordinal": ordinal, "addr": hex(ea), "name": name})
                    continue
            except ValueError:
                pass

            # Try as name - scan all entries
            found = False
            for i in range(ida_entry.get_entry_qty()):
                ordinal = ida_entry.get_entry_ordinal(i)
                name = ida_entry.get_entry_name(ordinal) or ""
                if name == item:
                    ea = ida_entry.get_entry(ordinal)
                    results.append({"ordinal": ordinal, "addr": hex(ea), "name": name})
                    found = True
                    break

            if not found:
                results.append({"entry": item, "error": "Not found"})
        except Exception as e:
            results.append({"entry": item, "error": str(e)})
    return results


@unsafe
@tool
@idasync
def add_entry(items: list[EntryAdd] | EntryAdd) -> list[dict]:
    """Add entry point(s) to the binary."""
    if isinstance(items, dict):
        items = [items]

    results = []
    for item in items:
        try:
            ordinal = item.get("ordinal", ida_entry.get_entry_qty())
            addr_str = item.get("addr", "0")
            name = item.get("name", "")
            is_func = item.get("is_func", True)

            ea = parse_address(addr_str)
            if ida_entry.add_entry(ordinal, ea, name, is_func):
                results.append(
                    {"ordinal": ordinal, "addr": hex(ea), "name": name, "ok": True}
                )
            else:
                results.append({"ordinal": ordinal, "error": "Failed to add entry"})
        except Exception as e:
            results.append({"entry": str(item), "error": str(e)})
    return results


@unsafe
@tool
@idasync
def delete_entry(
    ordinals: Annotated[str, "Ordinal numbers to delete, comma-separated"],
) -> list[dict]:
    """Delete entry point(s) by ordinal."""
    items = normalize_list_input(ordinals)
    results = []
    for item in items:
        try:
            ordinal = int(item)
            if ida_entry.del_entry(ordinal):
                results.append({"ordinal": ordinal, "ok": True})
            else:
                results.append({"ordinal": ordinal, "error": "Failed to delete"})
        except Exception as e:
            results.append({"ordinal": item, "error": str(e)})
    return results


@tool
@idasync
def entry_count() -> dict:
    """Get the total number of entry points."""
    return {"count": ida_entry.get_entry_qty()}
