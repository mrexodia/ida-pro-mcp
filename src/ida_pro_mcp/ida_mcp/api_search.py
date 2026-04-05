"""Extended search operations for IDA Pro MCP.

Provides tools for searching text in disassembly, immediate values,
and various search modes beyond the existing find_bytes and find_regex.
"""

from typing import Annotated

import ida_search
import ida_bytes
import ida_ida
import idaapi
import idc

from .rpc import tool
from .sync import idasync, IDAError
from .utils import parse_address, normalize_list_input


# ============================================================================
# Search Tools
# ============================================================================


@tool
@idasync
def search_text(
    text: Annotated[str, "Text to search for in disassembly listing"],
    start: Annotated[str, "Start address (default: beginning of database)"] = "",
    direction: Annotated[str, "forward|backward (default: forward)"] = "forward",
    case_sensitive: Annotated[bool, "Case-sensitive search (default: false)"] = False,
    max_results: Annotated[int, "Maximum results to return (default: 100)"] = 100,
) -> list[dict]:
    """Search for text in the disassembly listing (instruction mnemonics, operands, comments)."""
    if start:
        ea = parse_address(start)
    else:
        ea = ida_ida.inf_get_min_ea()

    flags = ida_search.SEARCH_REGEX
    if not case_sensitive:
        flags |= ida_search.SEARCH_NOCASE
    if direction == "backward":
        flags |= ida_search.SEARCH_UP
    else:
        flags |= ida_search.SEARCH_DOWN

    results = []
    for _ in range(max_results):
        ea = ida_search.find_text(ea, 0, 0, text, flags)
        if ea == idaapi.BADADDR:
            break
        disasm = idc.GetDisasm(ea) or ""
        results.append(
            {
                "addr": hex(ea),
                "disasm": disasm,
            }
        )
        ea = idc.next_head(ea, idaapi.BADADDR)
        if ea == idaapi.BADADDR:
            break

    return results


@tool
@idasync
def search_imm(
    value: Annotated[str, "Immediate value to search for (hex or decimal)"],
    start: Annotated[str, "Start address (default: beginning)"] = "",
    max_results: Annotated[int, "Maximum results (default: 100)"] = 100,
) -> list[dict]:
    """Search for an immediate (constant) value in instruction operands."""
    imm = int(value, 0)

    if start:
        ea = parse_address(start)
    else:
        ea = ida_ida.inf_get_min_ea()

    flags = ida_search.SEARCH_DOWN | ida_search.SEARCH_NEXT

    results = []
    for _ in range(max_results):
        ea = ida_search.find_imm(ea, flags, imm)[0]
        if ea == idaapi.BADADDR:
            break
        disasm = idc.GetDisasm(ea) or ""
        func_name = idc.get_func_name(ea) or ""
        results.append(
            {
                "addr": hex(ea),
                "disasm": disasm,
                "func": func_name,
            }
        )
        ea = idc.next_head(ea, idaapi.BADADDR)
        if ea == idaapi.BADADDR:
            break

    return results


@tool
@idasync
def search_not_func(
    start: Annotated[str, "Start address (default: beginning)"] = "",
    max_results: Annotated[int, "Maximum results (default: 100)"] = 100,
) -> list[dict]:
    """Find code that is not part of any function (orphan code)."""
    if start:
        ea = parse_address(start)
    else:
        ea = ida_ida.inf_get_min_ea()

    end_ea = ida_ida.inf_get_max_ea()
    results = []

    while ea < end_ea and len(results) < max_results:
        flags = ida_bytes.get_flags(ea)
        if ida_bytes.is_code(flags):
            func = idaapi.get_func(ea)
            if func is None:
                disasm = idc.GetDisasm(ea) or ""
                results.append(
                    {
                        "addr": hex(ea),
                        "disasm": disasm,
                    }
                )
        ea = idc.next_head(ea, end_ea)
        if ea == idaapi.BADADDR:
            break

    return results


@tool
@idasync
def search_undefined(
    start: Annotated[str, "Start address (default: beginning)"] = "",
    max_results: Annotated[int, "Maximum results (default: 100)"] = 100,
) -> list[dict]:
    """Find undefined (unexplored) bytes in the database."""
    if start:
        ea = parse_address(start)
    else:
        ea = ida_ida.inf_get_min_ea()

    end_ea = ida_ida.inf_get_max_ea()
    flags = ida_search.SEARCH_DOWN

    results = []
    for _ in range(max_results):
        ea = ida_search.find_unknown(ea, flags)
        if ea == idaapi.BADADDR:
            break
        results.append(
            {
                "addr": hex(ea),
                "byte": hex(ida_bytes.get_byte(ea)),
            }
        )
        ea += 1

    return results


@tool
@idasync
def search_error(
    start: Annotated[str, "Start address (default: beginning)"] = "",
    max_results: Annotated[int, "Maximum results (default: 100)"] = 100,
) -> list[dict]:
    """Find addresses flagged with analysis errors."""
    if start:
        ea = parse_address(start)
    else:
        ea = ida_ida.inf_get_min_ea()

    flags = ida_search.SEARCH_DOWN

    results = []
    for _ in range(max_results):
        ea = ida_search.find_error(ea, flags)
        if ea == idaapi.BADADDR:
            break
        disasm = idc.GetDisasm(ea) or ""
        results.append(
            {
                "addr": hex(ea),
                "disasm": disasm,
            }
        )
        ea = idc.next_head(ea, idaapi.BADADDR)
        if ea == idaapi.BADADDR:
            break

    return results
