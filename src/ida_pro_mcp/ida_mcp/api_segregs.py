"""Segment register tracking for IDA Pro MCP.

Provides tools for getting and setting segment register values at addresses.
"""

from typing import Annotated

import ida_segregs
import ida_idp
import ida_ida
import idaapi
import idc

from .rpc import tool, unsafe
from .sync import idasync, IDAError
from .utils import parse_address, normalize_list_input


# ============================================================================
# Segment Register Tools
# ============================================================================


@tool
@idasync
def list_segregs() -> list[dict]:
    """List all segment registers for the current processor."""
    regs = []
    for i in range(
        ida_idp.ph_get_regnames().__len__()
        if hasattr(ida_idp, "ph_get_regnames")
        else 0
    ):
        pass

    # Use the standard approach: iterate known segment register indices
    # IDA tracks segment registers from 0 to ph.reg_last_sreg
    result = []
    try:
        for i in range(idaapi.ph_get_cnbits()):
            pass
    except Exception:
        pass

    # Simpler approach: list registers that have segment register change points
    reg_names = []
    for reg_idx in range(64):  # Reasonable upper bound
        try:
            name = ida_idp.get_reg_name(reg_idx, 0)
            if name:
                # Check if this is a segment register
                sreg_range = ida_segregs.get_sreg_range(
                    ida_ida.inf_get_min_ea(), reg_idx
                )
                if sreg_range:
                    reg_names.append(
                        {
                            "index": reg_idx,
                            "name": name,
                        }
                    )
        except Exception:
            continue

    return reg_names


@tool
@idasync
def get_segreg(
    addrs: Annotated[str, "Addresses, comma-separated"],
    reg: Annotated[str, "Segment register name (e.g., 'cs', 'ds', 'fs', 'gs')"],
) -> list[dict]:
    """Get segment register value at address(es)."""
    items = normalize_list_input(addrs)

    # Resolve register name to index
    reg_idx = None
    for i in range(64):
        try:
            name = ida_idp.get_reg_name(i, 0)
            if name and name.lower() == reg.lower():
                reg_idx = i
                break
        except Exception:
            continue

    if reg_idx is None:
        raise IDAError(f"Unknown segment register: {reg}")

    results = []
    for item in items:
        try:
            ea = parse_address(item)
            val = idc.get_sreg(ea, reg)
            results.append(
                {
                    "addr": hex(ea),
                    "reg": reg,
                    "value": val if val != idaapi.BADSEL else None,
                }
            )
        except Exception as e:
            results.append({"addr": item, "error": str(e)})
    return results


@unsafe
@tool
@idasync
def set_segreg(
    addr: Annotated[str, "Address or range start"],
    reg: Annotated[str, "Segment register name"],
    value: Annotated[int, "Register value"],
    end: Annotated[str, "Range end address (default: next instruction)"] = "",
) -> dict:
    """Set segment register value at an address or range."""
    ea = parse_address(addr)
    if end:
        end_ea = parse_address(end)
    else:
        end_ea = idc.next_head(ea, idaapi.BADADDR)
        if end_ea == idaapi.BADADDR:
            end_ea = ea + 1

    ok = ida_segregs.split_sreg_range(
        ea, idc.str2reg(reg), value, ida_segregs.SR_user, False
    )
    return {"addr": hex(ea), "reg": reg, "value": value, "ok": ok}
