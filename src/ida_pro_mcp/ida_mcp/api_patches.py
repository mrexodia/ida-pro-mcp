"""Patch database management for IDA Pro MCP.

Provides tools for listing applied patches, getting original bytes,
and reverting patches.
"""

from typing import Annotated

import ida_bytes
import idaapi
import idc

from .rpc import tool, unsafe
from .sync import idasync, IDAError
from .utils import parse_address, normalize_list_input


# ============================================================================
# Patch Tools
# ============================================================================


@tool
@idasync
def list_patches(
    max_results: Annotated[int, "Maximum patches to return (default 1000)"] = 1000,
) -> list[dict]:
    """List all patched bytes in the database."""
    patches = []

    def visitor(ea, fpos, org_val, patch_val):
        patches.append(
            {
                "addr": hex(ea),
                "file_offset": hex(fpos) if fpos >= 0 else None,
                "original": hex(org_val),
                "patched": hex(patch_val),
            }
        )
        return 0 if len(patches) < max_results else 1

    ida_bytes.visit_patched_bytes(0, idaapi.BADADDR, visitor)
    return patches


@tool
@idasync
def get_original_byte(
    addrs: Annotated[str, "Addresses to get original bytes, comma-separated"],
    size: Annotated[int, "Number of bytes at each address (default 1)"] = 1,
) -> list[dict]:
    """Get original (unpatched) byte value(s) at address(es)."""
    items = normalize_list_input(addrs)
    results = []
    for item in items:
        try:
            ea = parse_address(item)
            if size == 1:
                orig = ida_bytes.get_original_byte(ea)
                current = ida_bytes.get_byte(ea)
                results.append(
                    {
                        "addr": hex(ea),
                        "original": hex(orig),
                        "current": hex(current),
                        "is_patched": orig != current,
                    }
                )
            else:
                orig_bytes = []
                curr_bytes = []
                patched = False
                for i in range(size):
                    o = ida_bytes.get_original_byte(ea + i)
                    c = ida_bytes.get_byte(ea + i)
                    orig_bytes.append(o)
                    curr_bytes.append(c)
                    if o != c:
                        patched = True
                results.append(
                    {
                        "addr": hex(ea),
                        "original": " ".join(f"{b:02x}" for b in orig_bytes),
                        "current": " ".join(f"{b:02x}" for b in curr_bytes),
                        "is_patched": patched,
                    }
                )
        except Exception as e:
            results.append({"addr": item, "error": str(e)})
    return results


@unsafe
@tool
@idasync
def revert_patch(
    addrs: Annotated[str, "Addresses to revert to original bytes, comma-separated"],
    size: Annotated[int, "Number of bytes to revert at each address (default 1)"] = 1,
) -> list[dict]:
    """Revert patched bytes back to original values."""
    items = normalize_list_input(addrs)
    results = []
    for item in items:
        try:
            ea = parse_address(item)
            reverted = 0
            for i in range(size):
                orig = ida_bytes.get_original_byte(ea + i)
                ida_bytes.patch_byte(ea + i, orig)
                reverted += 1
            results.append({"addr": hex(ea), "reverted_bytes": reverted, "ok": True})
        except Exception as e:
            results.append({"addr": item, "error": str(e)})
    return results


@tool
@idasync
def patch_count() -> dict:
    """Count total number of patched bytes."""
    count = 0

    def visitor(ea, fpos, org_val, patch_val):
        nonlocal count
        count += 1
        return 0

    ida_bytes.visit_patched_bytes(0, idaapi.BADADDR, visitor)
    return {"count": count}
