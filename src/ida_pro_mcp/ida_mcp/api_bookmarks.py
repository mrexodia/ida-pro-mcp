"""Bookmark and color management for IDA Pro MCP.

Provides tools for managing marked positions (bookmarks) and
setting colors on functions, instructions, and segments.
"""

from typing import Annotated, TypedDict

import ida_moves
import ida_nalt
import ida_funcs
import idaapi
import idc

from .rpc import tool, unsafe
from .sync import idasync, IDAError
from .utils import parse_address, normalize_list_input


# ============================================================================
# TypedDict Definitions
# ============================================================================


class BookmarkAdd(TypedDict, total=False):
    addr: Annotated[str, "Address to bookmark"]
    description: Annotated[str, "Bookmark description"]


class ColorOp(TypedDict, total=False):
    addr: Annotated[str, "Address to color"]
    color: Annotated[int, "RGB color as integer (0xBBGGRR), or -1 to clear"]
    scope: Annotated[str, "line|func|segment (default: line)"]


# ============================================================================
# Bookmark Tools
# ============================================================================


@tool
@idasync
def list_bookmarks() -> list[dict]:
    """List all marked positions (bookmarks) in the database."""
    bookmarks = []
    for slot in range(1, 1025):
        ea = idc.get_bookmark(slot)
        if ea is None or ea == idaapi.BADADDR:
            continue
        desc = idc.get_bookmark_desc(slot) or ""
        bookmarks.append(
            {
                "slot": slot,
                "addr": hex(ea),
                "description": desc,
            }
        )
    return bookmarks


@tool
@idasync
def add_bookmark(items: list[BookmarkAdd] | BookmarkAdd) -> list[dict]:
    """Add bookmark(s) at address(es)."""
    if isinstance(items, dict):
        items = [items]

    results = []
    for item in items:
        try:
            ea = parse_address(item.get("addr", "0"))
            desc = item.get("description", "")

            # Find first free slot
            slot = None
            for s in range(1, 1025):
                if idc.get_bookmark(s) is None or idc.get_bookmark(s) == idaapi.BADADDR:
                    slot = s
                    break

            if slot is None:
                results.append({"addr": hex(ea), "error": "No free bookmark slots"})
                continue

            idc.put_bookmark(ea, 0, 0, 0, slot, desc)
            results.append({"addr": hex(ea), "slot": slot, "ok": True})
        except Exception as e:
            results.append({"addr": item.get("addr", ""), "error": str(e)})
    return results


@tool
@idasync
def delete_bookmark(
    slots: Annotated[str, "Bookmark slot numbers to delete, comma-separated"],
) -> list[dict]:
    """Delete bookmark(s) by slot number."""
    items = normalize_list_input(slots)
    results = []
    for item in items:
        try:
            slot = int(item)
            idc.put_bookmark(idaapi.BADADDR, 0, 0, 0, slot, "")
            results.append({"slot": slot, "ok": True})
        except Exception as e:
            results.append({"slot": item, "error": str(e)})
    return results


# ============================================================================
# Color Tools
# ============================================================================


@tool
@idasync
def set_color(items: list[ColorOp] | ColorOp) -> list[dict]:
    """Set colors on instructions, functions, or segments.

    Color is 0xBBGGRR format. Use -1 (0xFFFFFFFF) to clear.
    Scope: 'line' (default) colors a single instruction,
    'func' colors the entire function, 'segment' colors the segment.
    """
    if isinstance(items, dict):
        items = [items]

    results = []
    for item in items:
        try:
            ea = parse_address(item.get("addr", "0"))
            color = item.get("color", 0xFFFFFF)
            scope = item.get("scope", "line")

            if color == -1:
                color = 0xFFFFFFFF  # idc.DEFCOLOR

            if scope == "func":
                what = idc.CIC_FUNC
            elif scope == "segment":
                what = idc.CIC_SEGM
            else:
                what = idc.CIC_ITEM

            idc.set_color(ea, what, color)
            results.append({"addr": hex(ea), "scope": scope, "ok": True})
        except Exception as e:
            results.append({"addr": item.get("addr", ""), "error": str(e)})
    return results


@tool
@idasync
def get_color(
    addrs: Annotated[str, "Addresses, comma-separated"],
    scope: Annotated[str, "line|func|segment (default: line)"] = "line",
) -> list[dict]:
    """Get the color at address(es)."""
    items = normalize_list_input(addrs)
    results = []
    for item in items:
        try:
            ea = parse_address(item)
            if scope == "func":
                what = idc.CIC_FUNC
            elif scope == "segment":
                what = idc.CIC_SEGM
            else:
                what = idc.CIC_ITEM

            color = idc.get_color(ea, what)
            results.append(
                {
                    "addr": hex(ea),
                    "color": hex(color) if color != 0xFFFFFFFF else None,
                    "scope": scope,
                }
            )
        except Exception as e:
            results.append({"addr": item, "error": str(e)})
    return results
