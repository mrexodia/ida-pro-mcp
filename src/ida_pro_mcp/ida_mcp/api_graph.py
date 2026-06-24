"""Read-only graph-navigation RE tools (base /mcp, no extension gate).

These tools answer the high-level "how does this function sit in the call
graph?" questions that the single-level primitives (`callees`, `xrefs_to`,
`callgraph`) only partially cover:

  * callers_recursive  -- the transitive set of functions that (eventually)
    reach a target ("what calls into this?").
  * callees_recursive  -- the transitive set of functions a target
    (eventually) calls ("what does this subsystem touch?").
  * data_refs          -- every DATA cross-reference to an address/global,
    each tagged read/write with its instruction and enclosing function
    ("who touches this global/field?").
  * reaches            -- a bounded reachability query between two functions,
    returning the call path when one exists ("can A call B?").

The IDA-touching work is delegated to the existing xref/caller/callee helpers
in utils/api_analysis. The traversal, deduplication and depth-bounding logic
lives in idaapi-free pure helpers (`_bfs_bounded`, `_dedup_chain`,
`_reconstruct_path`) so it can be unit-tested headless without a live database.
"""

from typing import Annotated, Callable, NotRequired, TypedDict

import ida_bytes
import ida_funcs
import ida_name
import idaapi
import idautils

from .rpc import safety, title, tool
from .sync import idasync, tool_timeout
from .utils import (
    Function,
    get_function,
    parse_address,
)


# ============================================================================
# Result TypedDicts
# ============================================================================


class GraphNode(TypedDict):
    addr: str
    name: str
    depth: int


GraphEdge = TypedDict(
    "GraphEdge",
    {"from": str, "to": str},
)


class RecursiveGraphResult(TypedDict, total=False):
    root: str
    resolved_addr: str | None
    direction: str
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    node_count: int
    edge_count: int
    max_depth: int
    max_nodes: int
    truncated: bool
    error: str


class DataRefRow(TypedDict, total=False):
    addr: str
    type: str
    instruction: str
    fn: Function | None


class DataRefsResult(TypedDict, total=False):
    target: str
    resolved_addr: str | None
    name: str | None
    refs: list[DataRefRow]
    ref_count: int
    truncated: bool
    message: str
    error: str


class ReachesResult(TypedDict, total=False):
    from_addr: str
    to_addr: str
    resolved_from: str | None
    resolved_to: str | None
    reachable: bool
    depth: int | None
    path: list[GraphNode]
    max_depth: int
    explored: int
    truncated: bool
    error: str


# ============================================================================
# Pure helpers (idaapi-free; unit-tested headless)
# ============================================================================


def _dedup_chain(items):
    """Return `items` with duplicates removed, preserving first-seen order.

    Pure and hashable-element only; used to stabilise neighbour lists before
    they are turned into edges so the same edge is never recorded twice.
    """
    seen = set()
    out = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def _bfs_bounded(
    start: int,
    neighbors: Callable[[int], list[int]],
    max_depth: int,
    max_nodes: int,
):
    """Breadth-first traversal bounded by depth and node count.

    `neighbors(node)` returns the adjacent node ids for one node. The start
    node is recorded at depth 0 and never re-expanded. Traversal stops once
    `max_nodes` distinct nodes have been recorded (the offending expansion is
    abandoned and `truncated` is set) or `max_depth` is exceeded.

    Returns (depths, edges, truncated) where:
      * depths: dict[node -> depth] of every recorded node (incl. start),
      * edges:  list of (from, to) pairs actually traversed (deduplicated),
      * truncated: True when a cap stopped the walk early.

    Pure: no IDA calls. `neighbors` is the only seam to the database.
    """
    if max_depth < 0:
        max_depth = 0
    if max_nodes < 1:
        max_nodes = 1

    depths: dict[int, int] = {start: 0}
    edges: list[tuple[int, int]] = []
    edge_seen: set[tuple[int, int]] = set()
    truncated = False
    frontier = [start]

    depth = 0
    while frontier and depth < max_depth:
        next_frontier: list[int] = []
        for node in frontier:
            for nxt in _dedup_chain(neighbors(node)):
                edge = (node, nxt)
                if edge not in edge_seen:
                    edge_seen.add(edge)
                    edges.append(edge)
                if nxt in depths:
                    continue
                if len(depths) >= max_nodes:
                    truncated = True
                    return depths, edges, truncated
                depths[nxt] = depth + 1
                next_frontier.append(nxt)
        frontier = next_frontier
        depth += 1

    if frontier and depth >= max_depth:
        # There were still nodes whose neighbours we never expanded because the
        # depth cap stopped us. Probe whether any expansion would have added a
        # genuinely new node; if so the result is depth-truncated.
        for node in frontier:
            for nxt in neighbors(node):
                if nxt not in depths:
                    truncated = True
                    return depths, edges, truncated

    return depths, edges, truncated


def _reconstruct_path(
    start: int,
    goal: int,
    neighbors: Callable[[int], list[int]],
    max_depth: int,
):
    """Bounded BFS shortest path from `start` to `goal`.

    Returns (path, explored, truncated):
      * path: list of node ids from start..goal inclusive, or [] if `goal`
        is not reachable within `max_depth`,
      * explored: number of distinct nodes visited,
      * truncated: True when the depth bound stopped expansion while unvisited
        neighbours remained (so a longer path might exist beyond the bound).

    Pure: `neighbors` is the only database seam.
    """
    if max_depth < 0:
        max_depth = 0
    if start == goal:
        return [start], 1, False

    parents: dict[int, int] = {start: start}
    frontier = [start]
    explored = 1
    truncated = False

    depth = 0
    while frontier and depth < max_depth:
        next_frontier: list[int] = []
        for node in frontier:
            for nxt in _dedup_chain(neighbors(node)):
                if nxt in parents:
                    continue
                parents[nxt] = node
                explored += 1
                if nxt == goal:
                    path = [goal]
                    cur = goal
                    while cur != start:
                        cur = parents[cur]
                        path.append(cur)
                    path.reverse()
                    return path, explored, False
                next_frontier.append(nxt)
        frontier = next_frontier
        depth += 1

    if frontier and depth >= max_depth:
        for node in frontier:
            for nxt in neighbors(node):
                if nxt not in parents:
                    truncated = True
                    break
            if truncated:
                break

    return [], explored, truncated


# ============================================================================
# IDA-backed neighbour functions
# ============================================================================


def _func_name(start_ea: int) -> str:
    return ida_funcs.get_func_name(start_ea) or "<unnamed>"


def _direct_callees(start_ea: int) -> list[int]:
    """Distinct start-EAs of functions directly called from `start_ea`.

    Walks the function's instructions and follows code refs to any address
    that lands inside a known function, returning that function's start.
    """
    func = idaapi.get_func(start_ea)
    if not func:
        return []
    out: list[int] = []
    for item_ea in idautils.FuncItems(func.start_ea):
        for target in idautils.CodeRefsFrom(item_ea, 0):
            callee = idaapi.get_func(target)
            if callee:
                out.append(callee.start_ea)
    return _dedup_chain(out)


def _direct_callers(start_ea: int) -> list[int]:
    """Distinct start-EAs of functions that call into `start_ea`.

    Only call-type references are counted, so fall-through/jump neighbours do
    not masquerade as callers.
    """
    out: list[int] = []
    for caller_site in idautils.CodeRefsTo(start_ea, 0):
        caller = idaapi.get_func(caller_site)
        if not caller:
            continue
        insn = idaapi.insn_t()
        idaapi.decode_insn(insn, caller_site)
        if insn.itype not in (idaapi.NN_call, idaapi.NN_callfi, idaapi.NN_callni):
            continue
        out.append(caller.start_ea)
    return _dedup_chain(out)


def _build_recursive_result(
    root: str,
    start_ea: int,
    direction: str,
    neighbors: Callable[[int], list[int]],
    max_depth: int,
    max_nodes: int,
) -> RecursiveGraphResult:
    depths, edges, truncated = _bfs_bounded(start_ea, neighbors, max_depth, max_nodes)

    nodes: list[GraphNode] = [
        {"addr": hex(ea), "name": _func_name(ea), "depth": depths[ea]}
        for ea in sorted(depths, key=lambda e: (depths[e], e))
    ]
    edge_rows: list[GraphEdge] = [
        {"from": hex(frm), "to": hex(to)} for frm, to in edges
    ]
    return {
        "root": root,
        "resolved_addr": hex(start_ea),
        "direction": direction,
        "nodes": nodes,
        "edges": edge_rows,
        "node_count": len(nodes),
        "edge_count": len(edge_rows),
        "max_depth": max_depth,
        "max_nodes": max_nodes,
        "truncated": truncated,
        "error": None,
    }


def _resolve_func_start(query: str) -> tuple[int | None, str | None]:
    q = str(query or "").strip()
    if not q:
        return None, "Function query is required"
    try:
        ea = parse_address(q)
    except Exception:
        ea = idaapi.get_name_ea(idaapi.BADADDR, q)
    if ea is None or ea == idaapi.BADADDR:
        return None, f"Failed to resolve: {q}"
    func = idaapi.get_func(ea)
    if not func:
        return None, f"Not a function: {q}"
    return func.start_ea, None


# ============================================================================
# Tools
# ============================================================================


@safety("READ")
@title("Recursive Callers (What Reaches This)")
@tool
@idasync
@tool_timeout(120.0)
def callers_recursive(
    ea: Annotated[
        str,
        "Target function address (hex like '0x401000') or symbol name. The transitive set of functions that can eventually reach it is returned.",
    ],
    max_depth: Annotated[
        int,
        "How many call levels to ascend from the target (default: 3; 0 = target only). Clamped to 0..50.",
    ] = 3,
    max_nodes: Annotated[
        int,
        "Hard cap on total functions recorded (default: 300, clamped to 1..20000). Hitting it sets truncated=true.",
    ] = 300,
) -> RecursiveGraphResult:
    """WHAT: Computes the transitive closure of *callers* of a function -- every function that can eventually reach the target through one or more direct calls -- via a depth- and node-bounded breadth-first walk up the call graph.

WHEN TO USE: To answer "what reaches this function?" -- e.g. which subsystems funnel into a decrypt routine, an allocator, or a packet handler. For a single level of callers use `xrefs_to`; for the downward (callee) direction use `callees_recursive`.

RETURNS: {root, resolved_addr, direction:'callers', nodes:[{addr,name,depth}], edges:[{from,to}], node_count, edge_count, max_depth, max_nodes, truncated, error?}. `depth` is the call distance from the target (0 = the target itself). `truncated=true` means a cap stopped the walk -- raise `max_depth`/`max_nodes` to widen.

PRO-TIP: Start with `max_depth=2-3`; the caller closure of a hot leaf function fans out fast. PITFALL: only direct, statically-resolvable call sites are followed -- indirect calls through registers/vtables will not appear, so a sparse result can mean dynamic dispatch, not isolation."""
    try:
        start_ea, err = _resolve_func_start(ea)
        if err is not None or start_ea is None:
            return {
                "root": ea,
                "resolved_addr": None,
                "direction": "callers",
                "nodes": [],
                "edges": [],
                "node_count": 0,
                "edge_count": 0,
                "error": err or "Failed to resolve function",
            }
        if max_depth < 0:
            max_depth = 0
        if max_depth > 50:
            max_depth = 50
        if max_nodes <= 0 or max_nodes > 20000:
            max_nodes = 20000
        return _build_recursive_result(
            ea, start_ea, "callers", _direct_callers, max_depth, max_nodes
        )
    except Exception as e:
        return {
            "root": ea,
            "resolved_addr": None,
            "direction": "callers",
            "nodes": [],
            "edges": [],
            "node_count": 0,
            "edge_count": 0,
            "error": str(e),
        }


@safety("READ")
@title("Recursive Callees (What This Touches)")
@tool
@idasync
@tool_timeout(120.0)
def callees_recursive(
    ea: Annotated[
        str,
        "Root function address (hex like '0x401000') or symbol name. The transitive set of functions it can eventually call is returned.",
    ],
    max_depth: Annotated[
        int,
        "How many call levels to descend from the root (default: 3; 0 = root only). Clamped to 0..50.",
    ] = 3,
    max_nodes: Annotated[
        int,
        "Hard cap on total functions recorded (default: 300, clamped to 1..20000). Hitting it sets truncated=true.",
    ] = 300,
) -> RecursiveGraphResult:
    """WHAT: Computes the transitive closure of *callees* of a function -- every function the root can eventually call -- via a depth- and node-bounded breadth-first walk down the call graph.

WHEN TO USE: To answer "what does this subsystem touch?" -- map the full footprint of a feature entry point before reading it, or scope the blast radius of a change. For a single level use `callees`; for the upward (caller) direction use `callers_recursive`; for a richer edge graph with per-func caps use `callgraph`.

RETURNS: {root, resolved_addr, direction:'callees', nodes:[{addr,name,depth}], edges:[{from,to}], node_count, edge_count, max_depth, max_nodes, truncated, error?}. `depth` is the call distance from the root (0 = the root itself). `truncated=true` means a cap stopped the walk.

PRO-TIP: Use a small `max_depth` first and widen until `truncated` clears -- a deep closure over a generic entry point can pull in most of the CRT. PITFALL: indirect/virtual calls are not followed, so the closure is a lower bound on what actually runs."""
    try:
        start_ea, err = _resolve_func_start(ea)
        if err is not None or start_ea is None:
            return {
                "root": ea,
                "resolved_addr": None,
                "direction": "callees",
                "nodes": [],
                "edges": [],
                "node_count": 0,
                "edge_count": 0,
                "error": err or "Failed to resolve function",
            }
        if max_depth < 0:
            max_depth = 0
        if max_depth > 50:
            max_depth = 50
        if max_nodes <= 0 or max_nodes > 20000:
            max_nodes = 20000
        return _build_recursive_result(
            ea, start_ea, "callees", _direct_callees, max_depth, max_nodes
        )
    except Exception as e:
        return {
            "root": ea,
            "resolved_addr": None,
            "direction": "callees",
            "nodes": [],
            "edges": [],
            "node_count": 0,
            "edge_count": 0,
            "error": str(e),
        }


@safety("READ")
@title("Data References To Address (Who Touches This)")
@tool
@idasync
def data_refs(
    ea: Annotated[
        str,
        "Address/name of the global, field or datum (hex like '0x4ab120' or a symbol). Every DATA cross-reference to it is returned.",
    ],
    limit: Annotated[
        int,
        "Max data references returned (default: 500, clamped to 1..10000). Hitting it sets truncated=true.",
    ] = 500,
) -> DataRefsResult:
    """WHAT: Lists every DATA cross-reference to an address -- each location that reads or writes the given global/field -- tagged read vs write, with the referencing instruction text and its enclosing function.

WHEN TO USE: To answer "who touches this global/field?" -- find all readers and writers of a config flag, a state variable, a singleton pointer, or a recovered struct field's backing address. This is data-only; for call/code references and the full filterable query use `xref_query`, and for struct-member granularity use `xrefs_to_field`.

RETURNS: {target, resolved_addr, name, refs:[{addr,type:'read'|'write'|'data',instruction,fn}], ref_count, truncated, message?, error?}. `type` is 'write' when the reference writes the datum, 'read' when it reads it, else 'data'. `message` appears when the address exists but has no data refs.

PRO-TIP: Filter mentally on `type='write'` to find the few places that *mutate* a global -- usually the initialiser/setter you actually want. PITFALL: only references IDA has resolved as data xrefs appear; a value reached purely by pointer arithmetic at runtime will not show up here."""
    try:
        try:
            target = parse_address(ea)
        except Exception:
            target = idaapi.get_name_ea(idaapi.BADADDR, str(ea).strip())
        if target is None or target == idaapi.BADADDR or not ida_bytes.is_mapped(target):
            return {
                "target": ea,
                "resolved_addr": None,
                "name": None,
                "refs": [],
                "ref_count": 0,
                "truncated": False,
                "error": f"Address not mapped: {ea}",
            }

        if limit <= 0 or limit > 10000:
            limit = 10000

        name = ida_name.get_ea_name(target) or None
        refs: list[DataRefRow] = []
        truncated = False
        seen: set[int] = set()

        for xref in idautils.XrefsTo(target, 0):
            if xref.iscode:
                continue
            frm = xref.frm
            if frm in seen:
                continue
            seen.add(frm)
            if len(refs) >= limit:
                truncated = True
                break
            kind = "data"
            if xref.type == idaapi.dr_W:
                kind = "write"
            elif xref.type == idaapi.dr_R:
                kind = "read"
            instruction = ""
            line = idaapi.generate_disasm_line(frm, 0)
            if line:
                instruction = idaapi.tag_remove(line)
            refs.append(
                {
                    "addr": hex(frm),
                    "type": kind,
                    "instruction": instruction.strip(),
                    "fn": get_function(frm, raise_error=False),
                }
            )

        result: DataRefsResult = {
            "target": ea,
            "resolved_addr": hex(target),
            "name": name,
            "refs": refs,
            "ref_count": len(refs),
            "truncated": truncated,
            "error": None,
        }
        if not refs:
            result["message"] = "No data references to this address"
        return result
    except Exception as e:
        return {
            "target": ea,
            "resolved_addr": None,
            "name": None,
            "refs": [],
            "ref_count": 0,
            "truncated": False,
            "error": str(e),
        }


@safety("READ")
@title("Reachability Path Between Functions")
@tool
@idasync
@tool_timeout(120.0)
def reaches(
    from_ea: Annotated[
        str,
        "Source function address (hex like '0x401000') or symbol name -- the call path is searched starting here.",
    ],
    to_ea: Annotated[
        str,
        "Destination function address (hex) or symbol name -- the function we are asking whether the source can reach.",
    ],
    max_depth: Annotated[
        int,
        "Maximum call-path length to search (default: 6; clamped to 0..50). A path longer than this is reported as not found within the bound (truncated=true).",
    ] = 6,
) -> ReachesResult:
    """WHAT: Bounded reachability query over the call graph -- decides whether `from_ea` can reach `to_ea` through some chain of direct calls within `max_depth` hops, and returns the shortest such call path when one exists.

WHEN TO USE: To answer "can A call into B?" -- e.g. does this command handler ever reach the network send, does this UI action touch the save routine. A precise yes/no-plus-path where `callees_recursive` would dump the whole closure.

RETURNS: {from_addr, to_addr, resolved_from, resolved_to, reachable, depth, path:[{addr,name,depth}], max_depth, explored, truncated, error?}. `reachable=true` carries the `path` (source..destination, `depth` = its length) and the count of functions `explored`. `truncated=true` with `reachable=false` means no path was found *within the bound* -- raise `max_depth` before concluding it is unreachable.

PRO-TIP: The returned `path` is a concrete call chain you can walk with `decompile` to see exactly how A reaches B. PITFALL: a `false` result is only conclusive up to `max_depth` and only over statically-resolved direct calls -- indirect dispatch can connect functions this query cannot see."""
    try:
        start_ea, err_from = _resolve_func_start(from_ea)
        goal_ea, err_to = _resolve_func_start(to_ea)
        if err_from is not None or start_ea is None:
            return {
                "from_addr": from_ea,
                "to_addr": to_ea,
                "resolved_from": None,
                "resolved_to": hex(goal_ea) if goal_ea is not None else None,
                "reachable": False,
                "path": [],
                "error": err_from or "Failed to resolve source function",
            }
        if err_to is not None or goal_ea is None:
            return {
                "from_addr": from_ea,
                "to_addr": to_ea,
                "resolved_from": hex(start_ea),
                "resolved_to": None,
                "reachable": False,
                "path": [],
                "error": err_to or "Failed to resolve destination function",
            }

        if max_depth < 0:
            max_depth = 0
        if max_depth > 50:
            max_depth = 50

        path_eas, explored, truncated = _reconstruct_path(
            start_ea, goal_ea, _direct_callees, max_depth
        )
        path: list[GraphNode] = [
            {"addr": hex(node), "name": _func_name(node), "depth": i}
            for i, node in enumerate(path_eas)
        ]
        reachable = bool(path_eas)
        return {
            "from_addr": from_ea,
            "to_addr": to_ea,
            "resolved_from": hex(start_ea),
            "resolved_to": hex(goal_ea),
            "reachable": reachable,
            "depth": (len(path_eas) - 1) if reachable else None,
            "path": path,
            "max_depth": max_depth,
            "explored": explored,
            "truncated": truncated,
            "error": None,
        }
    except Exception as e:
        return {
            "from_addr": from_ea,
            "to_addr": to_ea,
            "resolved_from": None,
            "resolved_to": None,
            "reachable": False,
            "path": [],
            "error": str(e),
        }


__all__ = [
    "callers_recursive",
    "callees_recursive",
    "data_refs",
    "reaches",
    "_bfs_bounded",
    "_dedup_chain",
    "_reconstruct_path",
]
