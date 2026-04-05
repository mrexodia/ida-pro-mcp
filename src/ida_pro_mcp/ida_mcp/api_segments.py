"""Segment management operations for IDA Pro MCP.

Provides tools for listing, creating, modifying, and deleting segments,
as well as querying segment attributes and permissions.
"""

from typing import Annotated, NotRequired, TypedDict

import ida_segment
import ida_bytes
import ida_name
import idaapi
import idc

from .rpc import tool, unsafe
from .sync import idasync, IDAError
from .utils import parse_address, normalize_list_input, paginate, pattern_filter


# ============================================================================
# TypedDict Definitions
# ============================================================================


class SegmentCreate(TypedDict, total=False):
    name: Annotated[str, "Segment name"]
    start: Annotated[str, "Start address (hex)"]
    size: Annotated[int, "Size in bytes"]
    sclass: Annotated[str, "Segment class (CODE, DATA, BSS, STACK, etc.)"]
    bitness: Annotated[int, "0=16bit, 1=32bit, 2=64bit"]
    align: Annotated[
        int, "Alignment (0=byte, 1=word, 2=dword, 3=para, 4=page, 5=dbl_page, 9=4k)"
    ]
    perm: Annotated[int, "Permissions bitmask (1=exec, 2=write, 4=read)"]


class SegmentModify(TypedDict, total=False):
    segment: Annotated[str, "Segment name or address within segment"]
    name: Annotated[str, "New segment name"]
    sclass: Annotated[str, "New segment class"]
    perm: Annotated[int, "New permissions bitmask"]
    align: Annotated[int, "New alignment"]
    bitness: Annotated[int, "New bitness (0/1/2)"]


# ============================================================================
# Helpers
# ============================================================================


def _seg_info(seg: ida_segment.segment_t) -> dict:
    """Convert segment_t to dict."""
    return {
        "name": ida_segment.get_segm_name(seg) or "",
        "start": hex(seg.start_ea),
        "end": hex(seg.end_ea),
        "size": seg.size(),
        "bitness": seg.bitness,
        "align": seg.align,
        "perm": seg.perm,
        "perm_str": "".join(
            [
                "r" if seg.perm & ida_segment.SEGPERM_READ else "-",
                "w" if seg.perm & ida_segment.SEGPERM_WRITE else "-",
                "x" if seg.perm & ida_segment.SEGPERM_EXEC else "-",
            ]
        )
        if seg.perm
        else "---",
        "type": seg.type,
        "sclass": ida_segment.get_segm_class(seg) or "",
        "use32": seg.bitness == 1,
        "use64": seg.bitness == 2,
        "is_loader_segm": bool(seg.is_loader_segm()),
    }


def _find_segment(name_or_addr: str) -> ida_segment.segment_t:
    """Find segment by name or address."""
    # Try as segment name first
    seg = ida_segment.get_segm_by_name(name_or_addr)
    if seg:
        return seg

    # Try as address
    try:
        ea = parse_address(name_or_addr)
        seg = ida_segment.getseg(ea)
        if seg:
            return seg
    except Exception:
        pass

    raise IDAError(f"Segment not found: {name_or_addr}")


# ============================================================================
# Segment Tools
# ============================================================================


@tool
@idasync
def list_segments(
    pattern: Annotated[str, "Optional glob pattern to filter by name"] = "",
    offset: Annotated[int, "Pagination offset"] = 0,
    count: Annotated[int, "Max results (0=all)"] = 0,
) -> list[dict]:
    """List all memory segments with attributes and permissions."""
    segments = []
    for i in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(i)
        if seg:
            segments.append(_seg_info(seg))

    if pattern:
        segments = [s for s in segments if pattern_filter(s["name"], pattern)]

    return paginate(segments, offset, count)


@tool
@idasync
def get_segment(
    segments: Annotated[str, "Segment names or addresses, comma-separated"],
) -> list[dict]:
    """Get detailed information about specific segment(s)."""
    items = normalize_list_input(segments)
    results = []
    for item in items:
        try:
            seg = _find_segment(item)
            info = _seg_info(seg)
            # Add extra detail
            info["orgbase"] = hex(seg.orgbase)
            results.append(info)
        except Exception as e:
            results.append({"segment": item, "error": str(e)})
    return results


@unsafe
@tool
@idasync
def create_segment(items: list[SegmentCreate] | SegmentCreate) -> list[dict]:
    """Create new memory segment(s)."""
    if isinstance(items, dict):
        items = [items]

    results = []
    for item in items:
        try:
            name = item.get("name", "")
            start_str = item.get("start", "0")
            size = item.get("size", 0)
            sclass = item.get("sclass", "DATA")
            bitness = item.get("bitness", 2)
            align_val = item.get("align", ida_segment.saAbs)
            perm = item.get("perm", 0)

            start_ea = int(start_str, 0) if isinstance(start_str, str) else start_str
            end_ea = start_ea + size

            seg = ida_segment.segment_t()
            seg.start_ea = start_ea
            seg.end_ea = end_ea
            seg.align = align_val
            seg.bitness = bitness
            seg.perm = perm

            if not ida_segment.add_segm_ex(
                seg, name, sclass, ida_segment.ADDSEG_OR_DIE
            ):
                results.append({"name": name, "error": "Failed to create segment"})
            else:
                results.append({"name": name, "start": hex(start_ea), "ok": True})
        except Exception as e:
            results.append({"name": item.get("name", ""), "error": str(e)})
    return results


@unsafe
@tool
@idasync
def modify_segment(items: list[SegmentModify] | SegmentModify) -> list[dict]:
    """Modify segment attributes (name, class, permissions, alignment, bitness)."""
    if isinstance(items, dict):
        items = [items]

    results = []
    for item in items:
        seg_id = item.get("segment", "")
        try:
            seg = _find_segment(seg_id)

            if "name" in item:
                ida_segment.set_segm_name(seg, item["name"])
            if "sclass" in item:
                ida_segment.set_segm_class(seg, item["sclass"])
            if "perm" in item:
                seg.perm = item["perm"]
                ida_segment.update_segm(seg)
            if "align" in item:
                seg.align = item["align"]
                ida_segment.update_segm(seg)
            if "bitness" in item:
                ida_segment.set_segm_addressing(seg, item["bitness"])

            results.append({"segment": seg_id, "ok": True})
        except Exception as e:
            results.append({"segment": seg_id, "error": str(e)})
    return results


@unsafe
@tool
@idasync
def delete_segment(
    segments: Annotated[str, "Segment names or addresses, comma-separated"],
    disable: Annotated[int, "SEGMOD_KILL=0 (default), SEGMOD_KEEP=1"] = 0,
) -> list[dict]:
    """Delete segment(s) from the database."""
    items = normalize_list_input(segments)
    results = []
    for item in items:
        try:
            seg = _find_segment(item)
            if ida_segment.del_segm(seg.start_ea, disable):
                results.append({"segment": item, "ok": True})
            else:
                results.append({"segment": item, "error": "Failed to delete"})
        except Exception as e:
            results.append({"segment": item, "error": str(e)})
    return results


@tool
@idasync
def segment_bytes(
    segment: Annotated[str, "Segment name or address"],
    offset: Annotated[int, "Byte offset within segment"] = 0,
    size: Annotated[int, "Number of bytes (default 256, max 4096)"] = 256,
) -> dict:
    """Read raw bytes from a segment."""
    seg = _find_segment(segment)
    size = min(size, 4096)
    start = seg.start_ea + offset
    end = min(start + size, seg.end_ea)
    actual_size = end - start
    if actual_size <= 0:
        return {"segment": segment, "error": "Offset beyond segment end"}
    data = ida_bytes.get_bytes(start, actual_size)
    hex_str = " ".join(f"{b:02x}" for b in data) if data else ""
    return {
        "segment": segment,
        "start": hex(start),
        "size": actual_size,
        "data": hex_str,
    }
