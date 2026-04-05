"""Auto-analysis control for IDA Pro MCP.

Provides tools for triggering reanalysis, waiting for analysis completion,
and managing the auto-analysis queue.
"""

from typing import Annotated

import ida_auto
import ida_bytes
import ida_ida
import ida_funcs
import idaapi
import idc

from .rpc import tool
from .sync import idasync, IDAError, tool_timeout
from .utils import parse_address, normalize_list_input


# ============================================================================
# Auto-Analysis Tools
# ============================================================================


@tool
@idasync
def analysis_state() -> dict:
    """Get the current auto-analysis state and queue info."""
    return {
        "is_auto_enabled": ida_auto.auto_is_ok(),
        "min_ea": hex(ida_ida.inf_get_min_ea()),
        "max_ea": hex(ida_ida.inf_get_max_ea()),
    }


@tool
@idasync
@tool_timeout(300.0)
def wait_for_analysis(
    timeout_secs: Annotated[int, "Timeout in seconds (default 60)"] = 60,
) -> dict:
    """Wait for auto-analysis to complete."""
    result = ida_auto.auto_wait()
    return {
        "ok": True,
        "result": result,
    }


@tool
@idasync
def reanalyze(
    addrs: Annotated[
        str, "Addresses or ranges (start-end), comma-separated. Empty = full reanalysis"
    ] = "",
) -> list[dict]:
    """Trigger reanalysis of address(es) or address range(s).

    Format: "0x401000" for single address, "0x401000-0x402000" for range.
    Empty string triggers full database reanalysis.
    """
    if not addrs.strip():
        # Full reanalysis
        ida_auto.auto_mark_range(
            ida_ida.inf_get_min_ea(),
            ida_ida.inf_get_max_ea(),
            ida_auto.AU_FINAL,
        )
        return [{"scope": "full", "ok": True}]

    items = normalize_list_input(addrs)
    results = []
    for item in items:
        try:
            if "-" in item and not item.startswith("-"):
                parts = item.split("-", 1)
                start = parse_address(parts[0].strip())
                end = parse_address(parts[1].strip())
                ida_auto.auto_mark_range(start, end, ida_auto.AU_FINAL)
                results.append({"start": hex(start), "end": hex(end), "ok": True})
            else:
                ea = parse_address(item)
                ida_auto.auto_mark_range(ea, ea + 1, ida_auto.AU_FINAL)
                results.append({"addr": hex(ea), "ok": True})
        except Exception as e:
            results.append({"addr": item, "error": str(e)})
    return results


@tool
@idasync
def plan_and_wait(
    start: Annotated[str, "Start address"],
    end: Annotated[str, "End address"],
) -> dict:
    """Plan range for analysis and wait for it to complete.

    This is useful when you want to ensure a specific range has been
    fully analyzed before proceeding with other operations.
    """
    start_ea = parse_address(start)
    end_ea = parse_address(end)
    ida_auto.plan_range(start_ea, end_ea)
    ida_auto.auto_wait()
    return {"start": hex(start_ea), "end": hex(end_ea), "ok": True}


@tool
@idasync
def set_auto_analysis(
    enabled: Annotated[bool, "Enable or disable auto-analysis"],
) -> dict:
    """Enable or disable automatic analysis."""
    if enabled:
        ida_auto.enable_auto(True)
    else:
        ida_auto.enable_auto(False)
    return {"enabled": enabled, "ok": True}
