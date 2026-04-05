"""Graph and flowchart operations for IDA Pro MCP.

Provides tools for flowchart analysis, dominator trees, and graph traversal.
"""

from typing import Annotated

import ida_gdl
import ida_funcs
import ida_xref
import idaapi
import idc

from .rpc import tool
from .sync import idasync, IDAError
from .utils import parse_address, normalize_list_input


# ============================================================================
# Graph Tools
# ============================================================================


@tool
@idasync
def flowchart(
    addrs: Annotated[str, "Function addresses or names, comma-separated"],
    include_edges: Annotated[
        bool, "Include edge (successor/predecessor) info (default true)"
    ] = True,
) -> list[dict]:
    """Get the control flow graph (flowchart) for function(s).

    Returns basic blocks with their start/end addresses and edges.
    More detailed than basic_blocks - includes predecessor and successor info.
    """
    items = normalize_list_input(addrs)
    results = []

    for item in items:
        try:
            ea = parse_address(item)
            func = ida_funcs.get_func(ea)
            if not func:
                results.append({"addr": item, "error": "Not in a function"})
                continue

            fc = ida_gdl.FlowChart(func)
            blocks = []

            for block in fc:
                blk = {
                    "id": block.id,
                    "start": hex(block.start_ea),
                    "end": hex(block.end_ea),
                    "size": block.end_ea - block.start_ea,
                    "type": block.type,
                }

                if include_edges:
                    succs = []
                    for succ in block.succs():
                        succs.append(
                            {
                                "id": succ.id,
                                "start": hex(succ.start_ea),
                            }
                        )
                    blk["successors"] = succs

                    preds = []
                    for pred in block.preds():
                        preds.append(
                            {
                                "id": pred.id,
                                "start": hex(pred.start_ea),
                            }
                        )
                    blk["predecessors"] = preds

                blocks.append(blk)

            results.append(
                {
                    "func": hex(func.start_ea),
                    "func_name": idc.get_func_name(func.start_ea) or "",
                    "block_count": len(blocks),
                    "blocks": blocks,
                }
            )
        except Exception as e:
            results.append({"addr": item, "error": str(e)})

    return results


@tool
@idasync
def func_tails(
    addrs: Annotated[str, "Function addresses or names, comma-separated"],
) -> list[dict]:
    """Get function tail chunks (non-contiguous code belonging to a function)."""
    items = normalize_list_input(addrs)
    results = []

    for item in items:
        try:
            ea = parse_address(item)
            func = ida_funcs.get_func(ea)
            if not func:
                results.append({"addr": item, "error": "Not in a function"})
                continue

            tails = []
            # Main chunk
            tails.append(
                {
                    "start": hex(func.start_ea),
                    "end": hex(func.end_ea),
                    "is_main": True,
                }
            )

            # Iterate tail chunks
            fii = ida_funcs.func_tail_iterator_t(func)
            ok = fii.first()
            while ok:
                area = fii.chunk()
                if area.start_ea != func.start_ea:
                    tails.append(
                        {
                            "start": hex(area.start_ea),
                            "end": hex(area.end_ea),
                            "is_main": False,
                        }
                    )
                ok = fii.next()

            results.append(
                {
                    "func": hex(func.start_ea),
                    "func_name": idc.get_func_name(func.start_ea) or "",
                    "chunk_count": len(tails),
                    "chunks": tails,
                }
            )
        except Exception as e:
            results.append({"addr": item, "error": str(e)})

    return results


@tool
@idasync
def cfg_edges(
    addrs: Annotated[str, "Function addresses or names, comma-separated"],
) -> list[dict]:
    """Get all CFG edges (source -> target) for function(s).

    Returns a flat list of edges suitable for graph visualization tools.
    """
    items = normalize_list_input(addrs)
    results = []

    for item in items:
        try:
            ea = parse_address(item)
            func = ida_funcs.get_func(ea)
            if not func:
                results.append({"addr": item, "error": "Not in a function"})
                continue

            fc = ida_gdl.FlowChart(func)
            edges = []
            for block in fc:
                for succ in block.succs():
                    edges.append(
                        {
                            "from": hex(block.start_ea),
                            "to": hex(succ.start_ea),
                            "from_id": block.id,
                            "to_id": succ.id,
                        }
                    )

            results.append(
                {
                    "func": hex(func.start_ea),
                    "func_name": idc.get_func_name(func.start_ea) or "",
                    "edge_count": len(edges),
                    "edges": edges,
                }
            )
        except Exception as e:
            results.append({"addr": item, "error": str(e)})

    return results


@tool
@idasync
def block_at(
    addrs: Annotated[str, "Addresses, comma-separated"],
) -> list[dict]:
    """Get the basic block containing each address."""
    items = normalize_list_input(addrs)
    results = []

    for item in items:
        try:
            ea = parse_address(item)
            func = ida_funcs.get_func(ea)
            if not func:
                results.append({"addr": item, "error": "Not in a function"})
                continue

            fc = ida_gdl.FlowChart(func)
            found = False
            for block in fc:
                if block.start_ea <= ea < block.end_ea:
                    results.append(
                        {
                            "addr": hex(ea),
                            "block_id": block.id,
                            "block_start": hex(block.start_ea),
                            "block_end": hex(block.end_ea),
                            "block_size": block.end_ea - block.start_ea,
                            "func": idc.get_func_name(func.start_ea) or "",
                        }
                    )
                    found = True
                    break
            if not found:
                results.append({"addr": hex(ea), "error": "Address not in any block"})
        except Exception as e:
            results.append({"addr": item, "error": str(e)})

    return results
