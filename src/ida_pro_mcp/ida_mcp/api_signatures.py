"""FLIRT signature operations for IDA Pro MCP.

Provides tools for applying and managing FLIRT signatures.
"""

from typing import Annotated

import ida_funcs
import ida_loader
import idaapi

from .rpc import tool
from .sync import idasync, IDAError
from .utils import normalize_list_input


# ============================================================================
# Signature Tools
# ============================================================================


@tool
@idasync
def apply_sig(
    names: Annotated[
        str, "Signature file names, comma-separated (e.g., 'vc64rtf', 'msvcrt')"
    ],
) -> list[dict]:
    """Apply FLIRT signature file(s) to the database."""
    items = normalize_list_input(names)
    results = []
    for name in items:
        try:
            result = ida_funcs.plan_to_apply_idasgn(name)
            if result == 0:
                results.append({"name": name, "ok": True})
            elif result == -1:
                results.append({"name": name, "error": "Signature file not found"})
            elif result == 1:
                results.append({"name": name, "ok": True, "note": "Already applied"})
            else:
                results.append({"name": name, "error": f"Unknown result: {result}"})
        except Exception as e:
            results.append({"name": name, "error": str(e)})
    return results


@tool
@idasync
def list_applied_sigs() -> list[dict]:
    """List all currently applied FLIRT signature files."""
    sigs = []
    n = ida_funcs.get_idasgn_qty()
    for i in range(n):
        desc = ida_funcs.get_idasgn_desc_with_matches(i)
        if desc:
            name, optlibs, matches = desc
            sigs.append(
                {
                    "index": i,
                    "name": name,
                    "matches": matches,
                }
            )
    return sigs
