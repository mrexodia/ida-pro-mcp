"""Compact toolset for IDA Pro MCP.

This module intentionally exposes only a small set of aggregated tools to avoid
polluting the MCP context with dozens of atomic capabilities.
"""

from __future__ import annotations

from typing import Annotated, Literal, TypedDict

import idaapi
import ida_funcs
import idautils
import idc

from .rpc import tool
from .sync import IDAError, idasync
from .utils import (
    Function,
    BasicBlock,
    get_callees,
    get_callers,
    get_function,
    looks_like_address,
    paginate,
    parse_address,
    pattern_filter,
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


def _has_user_name(ea: int) -> bool:
    flags = idaapi.get_flags(ea)
    checker = getattr(idaapi, "has_user_name", None)
    if checker is not None:
        return bool(checker(flags))

    try:
        import ida_name

        checker = getattr(ida_name, "has_user_name", None)
        if checker is not None:
            return bool(checker(flags))
    except Exception:
        pass

    return False


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


def _cfg_blocks(func_start: int, *, max_blocks: int, offset: int) -> dict:
    if max_blocks <= 0:
        max_blocks = 200
    if max_blocks > 10000:
        max_blocks = 10000
    if offset < 0:
        offset = 0

    func = idaapi.get_func(func_start)
    if not func:
        return {"blocks": [], "count": 0, "total_blocks": 0, "cursor": {"done": True}}

    flowchart = idaapi.FlowChart(func)
    all_blocks: list[dict] = []

    for block in flowchart:
        terminator_ea = idc.prev_head(block.end_ea, block.start_ea)
        terminator = None
        terminator_addr = None
        if terminator_ea != idaapi.BADADDR:
            terminator_addr = hex(terminator_ea)
            terminator = _format_insn(terminator_ea)

        all_blocks.append(
            {
                **BasicBlock(
                    start=hex(block.start_ea),
                    end=hex(block.end_ea),
                    size=block.end_ea - block.start_ea,
                    type=block.type,
                    successors=[hex(succ.start_ea) for succ in block.succs()],
                    predecessors=[hex(pred.start_ea) for pred in block.preds()],
                ),
                "terminator_addr": terminator_addr,
                "terminator": terminator,
            }
        )

    total_blocks = len(all_blocks)
    blocks = all_blocks[offset : offset + max_blocks]
    more = offset + max_blocks < total_blocks

    return {
        "blocks": blocks,
        "count": len(blocks),
        "total_blocks": total_blocks,
        "cursor": {"next": offset + max_blocks} if more else {"done": True},
    }


def _resolve_main(main: str) -> int:
    main = (main or "auto").strip()
    if main != "auto":
        return _resolve_func_start(main)

    for name in ("main", "WinMain", "wWinMain", "mainCRTStartup", "_start", "start"):
        ea = idaapi.get_name_ea(idaapi.BADADDR, name)
        if ea != idaapi.BADADDR:
            func = idaapi.get_func(ea)
            if func:
                return func.start_ea

    try:
        entry0 = idaapi.get_entry(0)
        if entry0 != idaapi.BADADDR:
            func = idaapi.get_func(entry0)
            if func:
                return func.start_ea
    except Exception:
        pass

    for ea in idautils.Functions():
        return int(ea)

    raise IDAError("No functions found in current database")


def _build_callgraph(
    root: int,
    *,
    max_depth: int,
    max_nodes: int,
    max_edges: int,
    max_edges_per_func: int,
) -> dict:
    if max_depth < 0:
        max_depth = 0
    if max_nodes <= 0 or max_nodes > 100000:
        max_nodes = 100000
    if max_edges <= 0 or max_edges > 200000:
        max_edges = 200000
    if max_edges_per_func <= 0 or max_edges_per_func > 5000:
        max_edges_per_func = 5000

    nodes: dict[str, dict] = {}
    edges: list[dict] = []
    visited: set[int] = set()
    truncated = False
    per_func_capped = False
    limit_reason: str | None = None

    def hit_limit(reason: str) -> None:
        nonlocal truncated, limit_reason
        truncated = True
        limit_reason = reason

    def traverse(addr: int, depth: int) -> None:
        nonlocal per_func_capped
        if truncated:
            return
        if depth > max_depth or addr in visited:
            return
        if len(nodes) >= max_nodes:
            hit_limit("nodes")
            return

        visited.add(addr)

        func = idaapi.get_func(addr)
        if not func:
            return

        func_name = ida_funcs.get_func_name(func.start_ea)
        nodes[hex(func.start_ea)] = {
            "addr": hex(func.start_ea),
            "name": func_name,
            "depth": depth,
        }

        edges_added = 0
        for item_ea in idautils.FuncItems(func.start_ea):
            if truncated:
                break

            for xref in idautils.CodeRefsFrom(item_ea, 0):
                if truncated:
                    break
                if edges_added >= max_edges_per_func:
                    per_func_capped = True
                    break

                callee = idaapi.get_func(xref)
                if not callee:
                    continue

                if len(edges) >= max_edges:
                    hit_limit("edges")
                    break

                edges.append(
                    {
                        "from": hex(func.start_ea),
                        "to": hex(callee.start_ea),
                        "type": "call",
                    }
                )
                edges_added += 1
                traverse(callee.start_ea, depth + 1)

            if edges_added >= max_edges_per_func:
                break

    traverse(root, 0)

    return {
        "root": hex(root),
        "nodes": list(nodes.values()),
        "edges": edges,
        "max_depth": max_depth,
        "truncated": truncated,
        "limit_reason": limit_reason,
        "max_nodes": max_nodes,
        "max_edges": max_edges,
        "max_edges_per_func": max_edges_per_func,
        "per_func_capped": per_func_capped,
    }


@tool
@idasync
def main_flow(
    main: Annotated[str, "main 函数名/地址；auto=自动探测"] = "auto",
    include_cfg: Annotated[bool, "是否返回 main 的 CFG basic blocks"] = True,
    include_callgraph: Annotated[bool, "是否返回从 main 出发的调用图"] = True,
    cfg_max_blocks: Annotated[int, "CFG 返回的最大 block 数"] = 200,
    cfg_offset: Annotated[int, "CFG block 分页 offset"] = 0,
    call_max_depth: Annotated[int, "调用图最大深度"] = 5,
    call_max_nodes: Annotated[int, "调用图最大节点数"] = 1000,
    call_max_edges: Annotated[int, "调用图最大边数"] = 5000,
    call_max_edges_per_func: Annotated[int, "单函数最大出边数"] = 200,
) -> dict:
    """从 main 出发查看调用走向，并可附带 main 的 CFG basic blocks。"""

    main_start = _resolve_main(main)
    main_fn = get_function(main_start)

    result: dict = {"main": main_fn}

    if include_cfg:
        result["cfg"] = _cfg_blocks(
            main_start, max_blocks=cfg_max_blocks, offset=cfg_offset
        )

    if include_callgraph:
        result["callgraph"] = _build_callgraph(
            main_start,
            max_depth=call_max_depth,
            max_nodes=call_max_nodes,
            max_edges=call_max_edges,
            max_edges_per_func=call_max_edges_per_func,
        )

    return result


@tool
@idasync
def list_user_funcs(
    mode: Annotated[
        Literal["non_library", "user_named"],
        "non_library=排除库/导入/跳板；user_named=仅列用户命名函数",
    ] = "non_library",
    filter: Annotated[str, "按函数名过滤：子串/Glob/Regex(/re/i)"] = "",
    offset: Annotated[int, "分页 offset"] = 0,
    count: Annotated[int, "分页 count"] = 200,
) -> dict:
    """列出当前 IDB 中“更像用户代码”的函数（分页）。"""

    if count <= 0:
        count = 200
    if count > 5000:
        count = 5000
    if offset < 0:
        offset = 0

    all_items: list[dict] = []
    dropped = {
        "lib": 0,
        "thunk": 0,
        "import": 0,
        "segment": 0,
        "user_named": 0,
    }

    excluded_segments = {".plt", ".idata", ".got", ".plt.sec", ".init", ".fini"}

    func_eas = list(idautils.Functions())
    for ea in func_eas:
        ea = int(ea)
        func = idaapi.get_func(ea)
        if not func:
            continue

        flags = ida_funcs.get_func_flags(func.start_ea)
        if flags & ida_funcs.FUNC_LIB:
            dropped["lib"] += 1
            continue
        if flags & ida_funcs.FUNC_THUNK:
            dropped["thunk"] += 1
            continue

        seg = idaapi.getseg(func.start_ea)
        seg_name = idaapi.get_segm_name(seg) if seg else ""
        if seg_name in excluded_segments:
            dropped["segment"] += 1
            continue

        name = ida_funcs.get_func_name(func.start_ea) or "<unnamed>"
        if name.startswith("__imp_") or name.startswith("j_"):
            dropped["import"] += 1
            continue

        if mode == "user_named" and not _has_user_name(func.start_ea):
            dropped["user_named"] += 1
            continue

        all_items.append(
            {
                **Function(
                    addr=hex(func.start_ea),
                    name=name,
                    size=hex(func.end_ea - func.start_ea),
                ),
                "segment": seg_name,
            }
        )

    all_items = pattern_filter(all_items, filter, "name")
    page = paginate(all_items, offset, count)

    return {
        **page,
        "stats": {
            "total_funcs": len(func_eas),
            "kept_total": len(all_items),
            "dropped": dropped,
        },
    }


@tool
@idasync
def view_func(
    query: Annotated[str, "函数名或地址"],
    include_decompile: Annotated[bool, "是否返回反编译"] = True,
    include_disasm: Annotated[bool, "是否返回带地址汇编"] = True,
    disasm_offset: Annotated[int, "汇编分页 offset(按指令条数)"] = 0,
    disasm_count: Annotated[int, "汇编分页 count(按指令条数)"] = 300,
    include_xrefs: Annotated[bool, "是否返回 callers/callees"] = True,
) -> dict:
    """查看函数的反编译与带地址汇编（便于断点定位）。"""

    func_start = _resolve_func_start(query)
    fn = get_function(func_start)

    result: dict = {"function": fn}

    if include_decompile:
        from .utils import decompile_function_safe

        code = decompile_function_safe(func_start)
        result["decompile"] = DecompileResult(
            code=code,
            error=None if code is not None else "Hex-Rays 不可用或反编译失败",
        )

    if include_disasm:
        result["disasm"] = _disasm_function(
            func_start, offset=disasm_offset, count=disasm_count
        )

    if include_xrefs:
        result["callers"] = get_callers(hex(func_start), limit=200)
        result["callees"] = get_callees(hex(func_start))

    return result
