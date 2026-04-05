"""Problem list management for IDA Pro MCP.

Provides tools for listing and managing analysis problems.
"""

from typing import Annotated

import ida_problems
import ida_ida
import idaapi
import idc

from .rpc import tool
from .sync import idasync
from .utils import parse_address, paginate


# ============================================================================
# Problem type names
# ============================================================================

_PROBLEM_TYPES = {
    ida_problems.PR_BADSTACK: "bad_stack",
    ida_problems.PR_ATTN: "attention",
    ida_problems.PR_FINAL: "final",
    ida_problems.PR_NOBASE: "no_base",
    ida_problems.PR_NONAME: "no_name",
    ida_problems.PR_MANYLINES: "many_lines",
    ida_problems.PR_JUMP: "jump",
    ida_problems.PR_DISASM: "disasm",
    ida_problems.PR_HEAD: "head",
    ida_problems.PR_ILLADDR: "illegal_addr",
    ida_problems.PR_NOXREFS: "no_xrefs",
    ida_problems.PR_NOCMT: "no_comment",
    ida_problems.PR_NOFOP: "no_fop",
    ida_problems.PR_ROLLED: "rolled",
    ida_problems.PR_DECIMP: "dec_import",
}


# ============================================================================
# Problem Tools
# ============================================================================


@tool
@idasync
def list_problems(
    problem_type: Annotated[
        str, "Problem type filter (bad_stack, attention, final, etc.) or empty for all"
    ] = "",
    offset: Annotated[int, "Pagination offset"] = 0,
    count: Annotated[int, "Max results (0=all, default 500)"] = 500,
) -> list[dict]:
    """List analysis problems in the database."""
    type_filter = None
    if problem_type:
        for k, v in _PROBLEM_TYPES.items():
            if v == problem_type:
                type_filter = k
                break
        if type_filter is None:
            return [
                {
                    "error": f"Unknown problem type: {problem_type}. Valid: {', '.join(_PROBLEM_TYPES.values())}"
                }
            ]

    problems = []
    types_to_check = (
        [type_filter] if type_filter is not None else list(_PROBLEM_TYPES.keys())
    )

    for ptype in types_to_check:
        ea = ida_problems.get_problem(ptype, ida_ida.inf_get_min_ea())
        while ea != idaapi.BADADDR:
            desc = ida_problems.get_problem_desc(ptype, ea) or ""
            problems.append(
                {
                    "addr": hex(ea),
                    "type": _PROBLEM_TYPES.get(ptype, f"unknown({ptype})"),
                    "type_id": ptype,
                    "description": desc,
                    "disasm": idc.GetDisasm(ea) or "",
                }
            )
            ea = ida_problems.get_problem(ptype, ea + 1)

    # Sort by address
    problems.sort(key=lambda p: int(p["addr"], 16))
    return paginate(problems, offset, count)


@tool
@idasync
def problem_count() -> dict:
    """Count problems by type."""
    counts = {}
    for ptype, name in _PROBLEM_TYPES.items():
        count = 0
        ea = ida_problems.get_problem(ptype, ida_ida.inf_get_min_ea())
        while ea != idaapi.BADADDR:
            count += 1
            ea = ida_problems.get_problem(ptype, ea + 1)
        if count > 0:
            counts[name] = count

    return {"counts": counts, "total": sum(counts.values())}
