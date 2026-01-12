"""UI API Functions - IDA UI interactions"""

from typing import Annotated

import ida_kernwin

from .rpc import tool
from .sync import idasync


@tool
@idasync
def get_output_log(
    lines: Annotated[int, "Number of lines to retrieve (-1 for all)"] = -1,
) -> dict:
    """Get IDA Output window log messages"""
    log_lines = ida_kernwin.msg_get_lines(lines)
    return {
        "lines": log_lines,
        "count": len(log_lines),
    }
