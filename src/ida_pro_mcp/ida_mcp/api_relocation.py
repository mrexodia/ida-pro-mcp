from typing import Annotated, TypedDict, NotRequired
import idaapi
from .rpc import tool
from .sync import idasync
from .utils import parse_address


class RelocationDeltaResult(TypedDict):
    """Result of calculating the delta between static and runtime base."""
    ida_imagebase: str       # e.g. "0x140000000"
    runtime_base: str        # e.g. "0x7ffe12340000"
    delta: str               # e.g. "0x7fbe12340000" (signed hex)
    delta_int: int           # signed integer delta
    idb_path: str            # current IDB path for context
    input_file: str          # original input file name


class AddressConversionResult(TypedDict):
    """Result of converting a single address between IDA and runtime."""
    input_address: str       # e.g. "0x140001000"
    output_address: str      # e.g. "0x7ffe12341000"
    direction: str           # "ida_to_runtime" or "runtime_to_ida"
    delta: str               # applied delta
    references: NotRequired[list[dict]]
    # For ida_to_runtime: optionally list code refs at the converted address
    # For runtime_to_ida: include function, segment, and xref info


class RebaseResult(TypedDict):
    """Result of rebasing the IDB."""
    old_imagebase: str
    new_imagebase: str
    delta: str
    delta_int: int
    ok: bool
    warning: NotRequired[str]


@tool
def calculate_relocation_delta(
    runtime_base: Annotated[
        str,
        "Runtime base address from debugger, in hex (e.g. '0x7FFE12340000' or '7FFE12340000')"
    ],
) -> RelocationDeltaResult:
    """Calculate the relocation delta between IDA's static base and a runtime base.

    Pure read-only operation — does NOT modify the IDB. Use this FIRST to
    verify the offset before converting addresses or rebasing.

    Returns the signed delta so the agent can understand both the magnitude
    and direction of the relocation. A positive delta means the runtime base
    is higher than the IDA base (common for ASLR'd 64-bit binaries).

    Example:
      IDA imagebase: 0x140000000
      Runtime base:  0x7FFE12340000
      Delta:         0x7FBE12340000 (positive, runtime > IDA)
    """
    try:
        rt_base = int(runtime_base, 0)
    except ValueError as e:
        return {
            "ida_imagebase": hex(idaapi.get_imagebase()),
            "runtime_base": runtime_base,
            "delta": "0x0",
            "delta_int": 0,
            "idb_path": "",
            "input_file": "",
        }  # error case handled by MCP framework

    ida_base = idaapi.get_imagebase()
    delta = rt_base - ida_base

    import idc
    import ida_nalt

    return {
        "ida_imagebase": hex(ida_base),
        "runtime_base": hex(rt_base),
        "delta": hex(delta),
        "delta_int": delta,
        "idb_path": idc.get_idb_path() or "",
        "input_file": ida_nalt.get_input_file_path() or "",
    }


@tool
def convert_ida_to_runtime(
    ida_address: Annotated[
        str,
        "IDA static address (hex), e.g. '0x140001000' or 'main' (resolved via name)"
    ],
    runtime_base: Annotated[
        str,
        "Runtime base address from debugger, in hex (e.g. '0x7FFE12340000')"
    ],
) -> AddressConversionResult:
    """Convert an IDA address to its runtime address in the debugged process.

    Resolves named symbols (e.g. 'main', 'DllMain') to their IDA addresses
    automatically. Use this when the agent needs to tell the debugger where
    to set breakpoints or read memory.

    The result includes optional code reference info so the agent can
    immediately understand the context at the converted address.
    """
    try:
        ida_ea = parse_address(ida_address)
    except Exception:
        # Fallback: try name resolution
        ea = idaapi.get_name_ea(idaapi.BADADDR, str(ida_address))
        if ea == idaapi.BADADDR:
            # Return error in result dict pattern
            return {
                "input_address": str(ida_address),
                "output_address": "0x0",
                "direction": "ida_to_runtime",
                "delta": "0x0",
            }
        ida_ea = ea

    rt_base = int(runtime_base, 0)
    delta = rt_base - idaapi.get_imagebase()
    rt_ea = ida_ea + delta

    result: AddressConversionResult = {
        "input_address": hex(ida_ea),
        "output_address": hex(rt_ea),
        "direction": "ida_to_runtime",
        "delta": hex(delta),
    }

    # Enrich with context if possible
    try:
        import idautils
        refs = []
        for xr in idautils.XrefsFrom(ida_ea, 0):
            if len(refs) >= 10:
                break
            fn = idaapi.get_func(xr.to)
            refs.append({
                "addr": hex(xr.to),
                "name": (idaapi.get_name(xr.to) or hex(xr.to)),
                "type": "code" if xr.iscode else "data",
            })
        if refs:
            result["references"] = refs
    except Exception:
        pass

    return result


@tool
def convert_runtime_to_ida(
    runtime_address: Annotated[
        str,
        "Runtime address from debugger, in hex (e.g. '0x7FFE12341000')"
    ],
    runtime_base: Annotated[
        str,
        "Runtime base address (module base in debugger), in hex"
    ],
) -> AddressConversionResult:
    """Convert a debugger runtime address back to an IDA static address.

    Use this when the debugger hits a breakpoint or shows a callstack
    entry, and the agent needs to decompile or analyze that location
    in IDA. Includes function/segment/xref context at the resolved IDA
    address to save round-trips.
    """
    try:
        rt_ea = int(runtime_address, 0)
    except ValueError:
        return {
            "input_address": str(runtime_address),
            "output_address": "0x0",
            "direction": "runtime_to_ida",
            "delta": "0x0",
        }

    rt_base = int(runtime_base, 0)
    delta = rt_base - idaapi.get_imagebase()
    ida_ea = rt_ea - delta

    result: AddressConversionResult = {
        "input_address": hex(rt_ea),
        "output_address": hex(ida_ea),
        "direction": "runtime_to_ida",
        "delta": hex(delta),
    }

    # Enrich with segment and function context
    try:
        refs = []
        seg = idaapi.getseg(ida_ea)
        if seg:
            refs.append({
                "addr": hex(ida_ea),
                "segment": idaapi.get_segm_name(seg),
                "permissions": f"{'r' if seg.perm & 4 else ''}{'w' if seg.perm & 2 else ''}{'x' if seg.perm & 1 else ''}",
            })
        func = idaapi.get_func(ida_ea)
        if func:
            refs.append({
                "addr": hex(ida_ea),
                "function": idaapi.get_name(func.start_ea) or hex(func.start_ea),
                "offset_from_start": hex(ida_ea - func.start_ea),
            })
        if refs:
            result["references"] = refs
    except Exception:
        pass

    return result


@tool
@idasync
def set_relocation_base(
    runtime_base: Annotated[
        str,
        "New runtime base to rebase the IDB to, in hex (e.g. '0x7FFE12340000')"
    ],
) -> RebaseResult:
    """Permanently rebase the IDB to match a runtime base address.

    THIS MODIFIES THE DATABASE. After rebasing, all IDA addresses will
    match the debugger's view without needing conversion. Uses
    idaapi.rebase_program() with MSF_NOFIX=0 to update all references.

    Warning: this is a destructive operation on the IDB. Consider saving
    a copy first, or using calculate_relocation_delta + conversion tools
    instead for read-only workflows.

    Only call this when the agent and user agree that a persistent rebase
    is appropriate (e.g., for a long analysis session of a relocated DLL).
    """
    old_base = idaapi.get_imagebase()
    new_base = int(runtime_base, 0)
    delta = new_base - old_base

    if delta == 0:
        return {
            "old_imagebase": hex(old_base),
            "new_imagebase": hex(new_base),
            "delta": "0x0",
            "delta_int": 0,
            "ok": True,
            "warning": "No rebase needed — runtime base matches IDA imagebase",
        }

    ok = idaapi.rebase_program(delta, 0)  # MSF_NOFIX = 0

    return {
        "old_imagebase": hex(old_base),
        "new_imagebase": hex(idaapi.get_imagebase()),
        "delta": hex(delta),
        "delta_int": delta,
        "ok": ok == 0,  # rebase_program returns 0 on success
    }
