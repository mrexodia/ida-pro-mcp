"""Compact toolset for IDA Pro MCP.

This module intentionally exposes only a small set of aggregated tools to avoid
polluting the MCP context with dozens of atomic capabilities.
"""

from __future__ import annotations

from typing import Annotated, TypedDict

import idaapi
import ida_funcs
import idautils
import idc

from .rpc import tool
from .sync import IDAError, idasync
from .utils import (
    get_function,
    looks_like_address,
    parse_address,
)


class DisasmResult(TypedDict):
    text: str
    count: int
    total: int
    cursor: dict


class DecompileResult(TypedDict):
    code: str | None
    error: str | None


def _resolve_func_start(query: str) -> int:
    query = (query or "").strip()
    if not query:
        raise IDAError("Empty function query")

    if looks_like_address(query):
        ea = parse_address(query)
    else:
        ea = idaapi.get_name_ea(idaapi.BADADDR, query)

    if ea == idaapi.BADADDR:
        raise IDAError(f"Function not found: {query}")

    func = idaapi.get_func(ea)
    if not func:
        raise IDAError(f"Not a function: {query}")

    return func.start_ea


def _format_insn(ea: int) -> str:
    mnem = idc.print_insn_mnem(ea) or ""
    operands: list[str] = []
    for idx in range(8):
        if idc.get_operand_type(ea, idx) == idaapi.o_void:
            break
        operands.append(idc.print_operand(ea, idx) or "")
    instruction = f"{mnem} {', '.join(operands)}".rstrip()
    return instruction


def _disasm_function(
    func_start: int,
    *,
    offset: int,
    count: int,
) -> DisasmResult:
    func = idaapi.get_func(func_start)
    if not func:
        return {
            "text": "",
            "count": 0,
            "total": 0,
            "cursor": {"done": True},
        }

    if count <= 0:
        count = 300
    if count > 5000:
        count = 5000
    if offset < 0:
        offset = 0

    items = list(idautils.FuncItems(func.start_ea))
    total = len(items)

    selected = items[offset : offset + count]
    lines = [f"{hex(ea)}  {_format_insn(ea)}" for ea in selected]

    next_offset = offset + count
    cursor = {"next": next_offset} if next_offset < total else {"done": True}

    return {
        "text": "\n".join(lines),
        "count": len(selected),
        "total": total,
        "cursor": cursor,
    }





@tool
@idasync
def list_user_funcs() -> list[str]:
    """列出当前 IDB 中用户代码函数名称（排除库函数、跳板、导入等）。"""
    
    func_names: list[str] = []
    excluded_segments = {".plt", ".idata", ".got", ".plt.sec", ".init", ".fini"}
    
    for ea in idautils.Functions():
        ea = int(ea)
        func = idaapi.get_func(ea)
        if not func:
            continue
        
        flags = idc.get_func_flags(func.start_ea)
        if flags & ida_funcs.FUNC_LIB:
            continue
        if flags & ida_funcs.FUNC_THUNK:
            continue
        
        seg = idaapi.getseg(func.start_ea)
        seg_name = idaapi.get_segm_name(seg) if seg else ""
        if seg_name in excluded_segments:
            continue
        
        name = ida_funcs.get_func_name(func.start_ea)
        if name and not name.startswith("__imp_") and not name.startswith("j_"):
            func_names.append(name)
    
    return func_names


@tool
@idasync
def view_func(query: Annotated[str, "函数名或地址"]) -> dict:
    """查看函数的反编译与带地址汇编。"""

    func_start = _resolve_func_start(query)
    fn = get_function(func_start)

    result: dict = {"function": fn}

    from .utils import decompile_function_safe

    code = decompile_function_safe(func_start)
    result["decompile"] = DecompileResult(
        code=code,
        error=None if code is not None else "Hex-Rays 不可用或反编译失败",
    )

    result["disasm"] = _disasm_function(func_start, offset=0, count=300)

    return result
