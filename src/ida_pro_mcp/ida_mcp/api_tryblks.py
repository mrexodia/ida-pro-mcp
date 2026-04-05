"""Exception handling block operations for IDA Pro MCP.

Provides tools for listing try/catch/finally blocks and exception handlers.
"""

from typing import Annotated

import ida_tryblks
import ida_funcs
import idaapi
import idc

from .rpc import tool
from .sync import idasync, IDAError
from .utils import parse_address, normalize_list_input


# ============================================================================
# Try Block Tools
# ============================================================================


@tool
@idasync
def list_tryblks(
    addrs: Annotated[str, "Function addresses or names, comma-separated"],
) -> list[dict]:
    """List try/catch/exception handler blocks in function(s)."""
    items = normalize_list_input(addrs)
    results = []

    for item in items:
        try:
            ea = parse_address(item)
            func = ida_funcs.get_func(ea)
            if not func:
                results.append({"addr": item, "error": "Not in a function"})
                continue

            tbv = ida_tryblks.tryblks_t()
            n = ida_tryblks.get_tryblks(tbv, func.start_ea)

            func_result = {
                "func": hex(func.start_ea),
                "func_name": idc.get_func_name(func.start_ea) or "",
                "tryblk_count": n,
                "tryblks": [],
            }

            for i in range(n):
                tb = tbv.get(i)
                blk = {
                    "index": i,
                    "try_start": hex(tb.start_ea),
                    "try_end": hex(tb.end_ea),
                    "catch_count": tb.size(),
                    "catches": [],
                }

                for j in range(tb.size()):
                    catch = tb.get(j)
                    catch_info = {
                        "index": j,
                        "start": hex(catch.start_ea),
                        "end": hex(catch.end_ea),
                    }
                    blk["catches"].append(catch_info)

                func_result["tryblks"].append(blk)

            results.append(func_result)
        except Exception as e:
            results.append({"addr": item, "error": str(e)})

    return results


@tool
@idasync
def tryblk_count(
    addrs: Annotated[str, "Function addresses or names, comma-separated"],
) -> list[dict]:
    """Count try blocks in function(s)."""
    items = normalize_list_input(addrs)
    results = []

    for item in items:
        try:
            ea = parse_address(item)
            func = ida_funcs.get_func(ea)
            if not func:
                results.append({"addr": item, "error": "Not in a function"})
                continue

            tbv = ida_tryblks.tryblks_t()
            n = ida_tryblks.get_tryblks(tbv, func.start_ea)
            results.append(
                {
                    "func": hex(func.start_ea),
                    "func_name": idc.get_func_name(func.start_ea) or "",
                    "count": n,
                }
            )
        except Exception as e:
            results.append({"addr": item, "error": str(e)})

    return results
