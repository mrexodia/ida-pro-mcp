"""Russian-doll comprehension tools: nested views over the call graph and CFG.

These tools answer "let me understand this code by zooming in and out" rather
than dumping a single flat closure. They form a set of nested dolls:

  * call_hierarchy    -- the WIDE view: a signed depth-banded view of who calls
    into a root and what it calls out to, both directions at once. The nested
    dolls are the LEVELS (-2..+2): negative = callers (In), positive = callees
    (Out), 0 = the root itself.
  * function_skeleton -- the FINE view: the control-flow skeleton of ONE
    function -- every basic block, its terminating branch + a human-readable
    condition, true/false successors, the calls it makes, loop back-edges, and
    (when Hex-Rays decompiles it) the REAL guard expressions that gate each call.
  * module_hierarchy  -- the SUBSYSTEM view: auto-grows a member set from a seed
    function, classifies interface vs internal members, and emits the inner
    intra-set call graph plus the outer reaches-out / reached-by-in edges and
    shared globals. Supersedes analyze_component with a true nested view.
  * hierarchy_runtime_overlay -- merges live probe/trace hit-counts (from
    trace.py) onto a static call_hierarchy so an agent can see which dolls
    actually executed. Read-only; degrades gracefully with no debugger.

DRILL PROTOCOL: every hierarchy node carries drill={into:'function_skeleton',
addr} and expand={tool:'call_hierarchy', addr, direction}; truncated shells and
collapsed-leaf bundles carry a `continue` cursor. So an agent can zoom a node ->
its skeleton block -> a guarded call and back out without ever dumping the whole
closure.

All IDA-touching call-graph work is delegated to the Batch-2 seams in `utils`
(iter_func_call_edges, walk_call_tree, get_cached_cfunc, classify_code_edge),
so both directions are exact transposes, recursion/cycles are handled centrally,
and switch / chunk / tail-call awareness comes for free. Indirect/virtual call
sites are surfaced explicitly (ctree cit_call + get_switch_info) rather than
silently dropped, so vtable-heavy classes are not falsely sparse.
"""

from __future__ import annotations

from typing import Annotated, NotRequired, Optional, TypedDict

import fnmatch

import ida_funcs
import ida_hexrays
import idaapi
import idautils
import idc

from ._kernel import trace as _trace
from ._kernel.rpc import ext, safety, title, tool
from ._kernel.sync import get_tool_deadline, idasync, tool_timeout
from ._kernel.utils import (
    get_cached_cfunc,
    get_function,
    get_prototype,
    iter_func_call_edges,
    parse_address,
    walk_call_tree,
)


# ============================================================================
# Bounds (token budgets)
# ============================================================================

_MAX_DEPTH_CAP = 8
_MAX_NODES_CAP = 2000
_MAX_EDGES_CAP = 4000
_MAX_BLOCKS = 400
_MAX_CALLS_PER_BLOCK = 24
_MAX_GUARDED_CALLS = 200
_MODULE_MEMBER_CAP = 120
_MODULE_EDGE_CAP = 2000


# ============================================================================
# Result TypedDicts
# ============================================================================


class HierNode(TypedDict, total=False):
    addr: str
    name: str
    is_leaf: bool
    is_recursive: bool
    indirect_only: bool
    prototype: str | None
    drill: dict
    expand: dict


HierEdge = TypedDict(
    "HierEdge",
    {
        "from": str,
        "to": str,
        "kind": str,         # call|tailcall|jump|indirect
        "indirect": bool,
        "site": str,         # call-site ea
        "count": int,
    },
)


class HierLevel(TypedDict):
    level: int               # signed band: -2..+2 (neg=callers, pos=callees, 0=root)
    addrs: list[str]


class CallHierarchyResult(TypedDict, total=False):
    root: str
    resolved_addr: str | None
    direction: str
    levels: list[HierLevel]
    nodes: list[HierNode]
    edges: list[HierEdge]
    indirect_leaves: list[str]
    node_count: int
    edge_count: int
    max_depth: int
    max_nodes: int
    truncated: bool
    continue_cursor: NotRequired[dict]
    error: str


class SkeletonCall(TypedDict, total=False):
    site: str
    target: str | None
    name: str | None
    kind: str
    indirect: bool


class SkeletonBlock(TypedDict, total=False):
    id: int
    start: str
    end: str
    terminator: str | None
    condition: str | None
    true_succ: str | None
    false_succ: str | None
    succ_ids: list[int]
    calls_here: list[SkeletonCall]
    is_loop_head: bool
    back_edges: list[int]


class GuardedCall(TypedDict, total=False):
    call: str
    guard: str
    site: str | None


class FunctionSkeletonResult(TypedDict, total=False):
    func: str
    resolved_addr: str | None
    name: str
    prototype: str | None
    block_count: int
    edge_count: int
    cyclomatic_complexity: int
    loop_count: int
    blocks: list[SkeletonBlock]
    guarded_calls: list[GuardedCall]
    indirect_sites: list[str]
    decompiled: bool
    decompile_error: str | None
    truncated: bool
    error: str


class ModuleMember(TypedDict, total=False):
    addr: str
    name: str
    role: str                # "interface" | "internal"
    prototype: str | None
    drill: dict
    expand: dict


ModuleEdge = TypedDict(
    "ModuleEdge",
    {"from": str, "to": str, "name": str},
)


class ModuleSharedGlobal(TypedDict):
    addr: str
    name: str
    accessed_by: list[str]


class ModuleHierarchyResult(TypedDict, total=False):
    seed: str
    resolved_addr: str | None
    members: list[ModuleMember]
    interface: list[str]
    internal: list[str]
    inner_call_graph: dict           # {nodes, edges} intra-set
    reaches_out: list[ModuleEdge]    # member -> outside dependency
    reached_by_in: list[ModuleEdge]  # outside consumer -> member
    shared_globals: list[ModuleSharedGlobal]
    member_count: int
    truncated: bool
    error: str


class OverlayEdge(TypedDict, total=False):
    from_: str
    to: str
    kind: str
    hits: int
    taken: bool


class HierarchyRuntimeOverlayResult(TypedDict, total=False):
    root: str
    direction: str
    runtime: str                     # "present" | "no_runtime_data"
    static: CallHierarchyResult
    edge_hits: list[OverlayEdge]
    block_executed: list[dict]
    records_seen: int
    error: str


# ============================================================================
# Internal helpers (resolution + naming)
# ============================================================================


def _func_name(start_ea: int) -> str:
    return ida_funcs.get_func_name(start_ea) or "<unnamed>"


def _resolve_func_start(query: str) -> tuple[int | None, str | None]:
    """Resolve an address/name to the start EA of its enclosing function."""
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


def _prototype_for(start_ea: int) -> Optional[str]:
    func = idaapi.get_func(start_ea)
    if func is None:
        return None
    try:
        return get_prototype(func)
    except Exception:
        return None


def _name_matches_any(name: str, patterns: list[str]) -> bool:
    """Glob-match a function name against any of the exclude patterns."""
    low = (name or "").lower()
    for pat in patterns:
        if fnmatch.fnmatch(low, pat):
            return True
    return False


def _parse_excludes(exclude: str) -> list[str]:
    """Comma-separated globs -> list of lowercase fnmatch patterns."""
    out: list[str] = []
    for tok in (exclude or "").split(","):
        tok = tok.strip().lower()
        if not tok:
            continue
        # bare token w/o glob metacharacters -> substring match
        if "*" not in tok and "?" not in tok and "[" not in tok:
            tok = f"*{tok}*"
        out.append(tok)
    return out


def _ctree_indirect_sites(start_ea: int) -> list[int]:
    """Recover indirect/virtual call-site EAs via the ctree (cit_call/cot_call).

    Walks the cached cfunc's expressions for cot_call nodes whose callee is not a
    plain object reference (i.e. computed: register/vtable/member-pointer) and
    returns their addresses. Unified with the mnemonic-level indirect edges so
    vtable-heavy classes are not silently sparse. Returns [] when the function
    will not decompile.
    """
    cfunc, err = get_cached_cfunc(start_ea)
    if cfunc is None or err is not None:
        return []
    sites: set[int] = set()

    class _V(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)

        def visit_expr(self, e):
            try:
                if e.op == ida_hexrays.cot_call and e.x is not None:
                    # A direct call has callee op == cot_obj (named function).
                    if e.x.op != ida_hexrays.cot_obj:
                        ea = e.ea
                        if ea != idaapi.BADADDR:
                            sites.add(int(ea))
            except Exception:
                pass
            return 0

    try:
        _V().apply_to(cfunc.body, None)
    except Exception:
        return []
    return sorted(sites)


# ============================================================================
# call_hierarchy -- the WIDE view
# ============================================================================


def _drill(addr_hex: str) -> dict:
    return {"into": "function_skeleton", "addr": addr_hex}


def _expand(addr_hex: str, direction: str) -> dict:
    return {"tool": "call_hierarchy", "addr": addr_hex, "direction": direction}


def _walk_band(
    start_ea: int,
    wdir: str,
    depth: int,
    node_budget: int,
    deadline: float | None,
) -> tuple[dict[int, int], list[tuple[int, int, str, bool, int]], set[int], bool]:
    """Walk one direction and return (depths, edge_tuples, recursive_eas, hit_cap).

    depths maps func start_ea -> shallowest band distance (>=0). edge_tuples are
    (from_ea, to_ea, kind, indirect, site_ea) oriented in the *call* direction
    (caller -> callee) regardless of walk direction. recursive_eas holds
    self-recursive functions.
    """
    walk = walk_call_tree(
        start_ea,
        depth=depth,
        node_budget=node_budget,
        direction=wdir,
        deadline=deadline,
    )
    depths: dict[int, int] = {}
    recursive: set[int] = set()
    for node in walk:
        ea = node["ea"]
        if node.get("back_edge"):
            continue
        if node.get("is_recursive"):
            recursive.add(ea)
        d = node["depth"]
        if ea not in depths or d < depths[ea]:
            depths[ea] = d
    hit_cap = len(depths) >= node_budget

    # Re-derive concrete call/jump edges between the discovered functions, so we
    # carry kind + site (walk_call_tree only yields nodes).
    edges: list[tuple[int, int, str, bool, int]] = []
    seen: set[tuple] = set()
    for fea in list(depths.keys()):
        for edge in iter_func_call_edges(fea, "out"):
            to = edge.get("to")
            site = edge.get("from")
            kind = edge.get("kind", "call")
            indirect = bool(edge.get("indirect"))
            if to is None:
                continue
            callee = idaapi.get_func(to)
            callee_start = callee.start_ea if callee is not None else None
            if callee_start is None or callee_start not in depths:
                continue
            key = (fea, callee_start, kind, site)
            if key in seen:
                continue
            seen.add(key)
            edges.append((fea, callee_start, kind, indirect, int(site)))
    return depths, edges, recursive, hit_cap


@safety("READ")
@title("Call Hierarchy (Nested In/Out Dolls)")
@tool
@idasync
@tool_timeout(120.0)
def call_hierarchy(
    root: Annotated[
        str,
        "Root function address (hex like '0x401000') or symbol name. The nested in/out call hierarchy around it is returned.",
    ],
    direction: Annotated[
        str,
        "Which dolls to expand: 'both' (callers AND callees), 'out' (callees only) or 'in' (callers only). Default: 'both'.",
    ] = "both",
    depth: Annotated[
        int,
        "How many levels to expand on each side (default 3; 0 = root only). Clamped to 0..8. Becomes the |level| band magnitude.",
    ] = 3,
    max_nodes: Annotated[
        int,
        "Hard cap on total functions recorded across both sides (default 200, clamped 1..2000). Hitting it sets truncated=true.",
    ] = 200,
    include_indirect: Annotated[
        bool,
        "Surface unresolved indirect/virtual call sites (from mnemonics AND the ctree) as explicit leaf nodes instead of dropping them. Default: true.",
    ] = True,
    exclude: Annotated[
        str,
        "Comma-separated name globs to prune (e.g. 'sub_*,_*,*alloc*'); bare tokens become substring matches. Pruned functions are not expanded.",
    ] = "",
    collapse_leaves: Annotated[
        bool,
        "Mark terminal callees/callers as leaves (is_leaf) so the agent can skip re-expanding them. Default: true.",
    ] = True,
) -> CallHierarchyResult:
    """WHAT: The WIDE russian-doll view of a function's place in the call graph. Walks BOTH directions at once (callers = In, callees = Out) with identical, exact-transpose edge semantics, and returns signed depth-band LEVELS (-2..+2: negative = callers, positive = callees, 0 = root) -- the nested dolls -- plus the NODES and the tagged call/jump/tailcall/indirect EDGES that wire them. Every node carries a drill ({into:'function_skeleton', addr}) and an expand ({tool:'call_hierarchy', addr, direction}) so you can zoom without dumping the whole closure.

WHEN TO USE: As the first orientation call on an unknown function -- see who funnels into it and what it touches in one shot. For a single side use 'out'/'in'; for the per-block control-flow detail of one node use function_skeleton; for the live executed subset use hierarchy_runtime_overlay.

RETURNS: {root, resolved_addr, direction, levels:[{level,addrs}], nodes:[{addr,name,is_leaf,is_recursive,indirect_only,prototype,drill,expand}], edges:[{from,to,kind,indirect,site,count}], indirect_leaves, node_count, edge_count, max_depth, max_nodes, truncated, continue_cursor?, error?}. Unresolved indirect/virtual sites become explicit leaf nodes (indirect_only=true) so a sparse closure is never silently dropped. truncated=true with a continue_cursor means a budget stopped the walk -- raise depth/max_nodes or re-call with the cursor.

PRO-TIP: Start with direction='both', depth=2 to get the lay of the land, then expand the one node that matters with its `expand` payload. PITFALL: only statically-resolved direct calls become expandable nodes; indirect/virtual dispatch shows as indirect_only leaves -- check those before concluding a class is isolated."""
    try:
        start_ea, err = _resolve_func_start(root)
        if err is not None or start_ea is None:
            return {
                "root": root,
                "resolved_addr": None,
                "direction": direction,
                "levels": [],
                "nodes": [],
                "edges": [],
                "node_count": 0,
                "edge_count": 0,
                "error": err or "Failed to resolve function",
            }

        direction = direction if direction in ("both", "out", "in") else "both"
        if depth < 0:
            depth = 0
        if depth > _MAX_DEPTH_CAP:
            depth = _MAX_DEPTH_CAP
        if max_nodes <= 0 or max_nodes > _MAX_NODES_CAP:
            max_nodes = _MAX_NODES_CAP

        excludes = _parse_excludes(exclude)
        deadline = get_tool_deadline()

        # Split the node budget across both active sides.
        sides: list[str] = []
        if direction in ("both", "out"):
            sides.append("out")
        if direction in ("both", "in"):
            sides.append("in")
        per_side_budget = max(1, max_nodes // max(1, len(sides)))

        # band_depth[ea] -> signed level; positive = out (callees), negative = in.
        band: dict[int, int] = {start_ea: 0}
        recursive_all: set[int] = set()
        all_edges: list[tuple[int, int, str, bool, int]] = []
        truncated = False

        for side in sides:
            depths, edges, recursive, hit_cap = _walk_band(
                start_ea, side, depth, per_side_budget, deadline
            )
            truncated = truncated or hit_cap
            recursive_all |= recursive
            sign = 1 if side == "out" else -1
            for ea, d in depths.items():
                if ea == start_ea:
                    continue
                signed = sign * d if d != 0 else sign
                # keep the band closest to the root (smallest magnitude)
                if ea not in band or abs(signed) < abs(band[ea]):
                    band[ea] = signed
            all_edges.extend(edges)

        # Apply exclude pruning: drop excluded functions (never the root).
        if excludes:
            pruned = {
                ea for ea in band
                if ea != start_ea and _name_matches_any(_func_name(ea), excludes)
            }
            for ea in pruned:
                band.pop(ea, None)
            all_edges = [
                e for e in all_edges if e[0] not in pruned and e[1] not in pruned
            ]

        # Aggregate edges by (from,to,kind) with a count; collect distinct sites.
        edge_agg: dict[tuple, dict] = {}
        for frm, to, kind, indirect, site in all_edges:
            key = (frm, to, kind)
            row = edge_agg.get(key)
            if row is None:
                row = {
                    "from": hex(frm),
                    "to": hex(to),
                    "kind": kind,
                    "indirect": indirect,
                    "site": hex(site),
                    "count": 0,
                }
                edge_agg[key] = row
                if len(edge_agg) >= _MAX_EDGES_CAP:
                    truncated = True
            row["count"] += 1
        edges_out: list[HierEdge] = list(edge_agg.values())

        # Which functions have at least one outgoing/incoming edge in-set?
        has_out: set[int] = set()
        has_in: set[int] = set()
        for frm, to, _k, _i, _s in all_edges:
            has_out.add(frm)
            has_in.add(to)

        # Indirect leaves: explicit unresolved sites of the ROOT (mnemonic + ctree).
        indirect_leaves: list[str] = []
        indirect_only_eas: set[int] = set()
        if include_indirect:
            seen_sites: set[int] = set()
            for edge in iter_func_call_edges(start_ea, "out"):
                if edge.get("indirect") and edge.get("from") is not None:
                    site = int(edge["from"])
                    if site not in seen_sites:
                        seen_sites.add(site)
                        indirect_leaves.append(hex(site))
            for site in _ctree_indirect_sites(start_ea):
                if site not in seen_sites:
                    seen_sites.add(site)
                    indirect_leaves.append(hex(site))

        # Build nodes.
        nodes: list[HierNode] = []
        for ea in sorted(band, key=lambda e: (band[e], e)):
            addr_hex = hex(ea)
            level = band[ea]
            # leaf: terminal in its expansion direction
            if level > 0:
                is_leaf = ea not in has_out
            elif level < 0:
                is_leaf = ea not in has_in
            else:
                is_leaf = (ea not in has_out) and (ea not in has_in)
            node_dir = "out" if level > 0 else ("in" if level < 0 else direction)
            row: HierNode = {
                "addr": addr_hex,
                "name": _func_name(ea),
                "is_leaf": bool(is_leaf) if collapse_leaves else False,
                "is_recursive": ea in recursive_all,
                "indirect_only": ea in indirect_only_eas,
                "prototype": _prototype_for(ea),
                "drill": _drill(addr_hex),
                "expand": _expand(addr_hex, node_dir),
            }
            nodes.append(row)

        # Bucket nodes into signed levels (the dolls).
        levels_map: dict[int, list[str]] = {}
        for ea in band:
            levels_map.setdefault(band[ea], []).append(hex(ea))
        levels: list[HierLevel] = [
            {"level": lv, "addrs": sorted(levels_map[lv])}
            for lv in sorted(levels_map.keys())
        ]

        result: CallHierarchyResult = {
            "root": root,
            "resolved_addr": hex(start_ea),
            "direction": direction,
            "levels": levels,
            "nodes": nodes,
            "edges": edges_out,
            "indirect_leaves": indirect_leaves,
            "node_count": len(nodes),
            "edge_count": len(edges_out),
            "max_depth": depth,
            "max_nodes": max_nodes,
            "truncated": truncated,
            "error": None,
        }
        if truncated:
            result["continue_cursor"] = {
                "tool": "call_hierarchy",
                "root": hex(start_ea),
                "direction": direction,
                "depth": min(depth + 1, _MAX_DEPTH_CAP),
                "max_nodes": min(max_nodes * 2, _MAX_NODES_CAP),
            }
        return result
    except Exception as e:
        return {
            "root": root,
            "resolved_addr": None,
            "direction": direction,
            "levels": [],
            "nodes": [],
            "edges": [],
            "node_count": 0,
            "edge_count": 0,
            "error": str(e),
        }


# ============================================================================
# function_skeleton -- the FINE view
# ============================================================================

# Human-readable rendering of common conditional-branch mnemonics. The branch
# is "taken when <cond>"; we phrase it as the if-test on the prior compare.
_COND_PHRASES = {
    "jz": "if (x == 0)",
    "je": "if (a == b)",
    "jnz": "if (x != 0)",
    "jne": "if (a != b)",
    "jg": "if (a > b)",      # signed
    "jge": "if (a >= b)",
    "jl": "if (a < b)",
    "jle": "if (a <= b)",
    "ja": "if (a > b)",      # unsigned
    "jae": "if (a >= b)",
    "jb": "if (a < b)",
    "jbe": "if (a <= b)",
    "js": "if (sign set)",
    "jns": "if (sign clear)",
    "jo": "if (overflow)",
    "jno": "if (no overflow)",
    "jc": "if (carry)",
    "jnc": "if (no carry)",
    "jp": "if (parity even)",
    "jnp": "if (parity odd)",
    "jcxz": "if (cx == 0)",
    "jecxz": "if (ecx == 0)",
    "jrcxz": "if (rcx == 0)",
    # AArch64 conditional branches
    "cbz": "if (x == 0)",
    "cbnz": "if (x != 0)",
    "tbz": "if (bit == 0)",
    "tbnz": "if (bit != 0)",
}


def _human_condition(mnem: str) -> Optional[str]:
    return _COND_PHRASES.get(mnem.lower())


def _last_insn_ea(block_start: int, block_end: int) -> int:
    """EA of the final instruction head in a [start,end) block."""
    last = block_start
    ea = block_start
    while ea < block_end and ea != idaapi.BADADDR:
        last = ea
        ea = idc.next_head(ea, block_end)
    return last


@safety("READ")
@title("Function Skeleton (Blocks + Conditions + Guarded Calls)")
@tool
@idasync
@tool_timeout(120.0)
def function_skeleton(
    func: Annotated[
        str,
        "Function address (hex like '0x401000') or symbol name. Its control-flow skeleton is returned.",
    ],
) -> FunctionSkeletonResult:
    """WHAT: The FINE russian-doll view of ONE function -- its control-flow skeleton. Builds the CFG (idaapi.FlowChart) and, for EACH basic block, reports the terminating branch instruction, a HUMAN-readable condition (jz -> 'if (x == 0)'), the true/false successor blocks, the calls made in that block (calls_here), loop-back/back-edge markers, and the function's cyclomatic complexity. When Hex-Rays decompiles the function it ALSO walks the ctree (cot_if/cot_for/cot_while/cot_call) to attach the REAL guard expressions, yielding guarded_calls like "decrypt() fires under if (g_init && argc>1)".

WHEN TO USE: After call_hierarchy points you at one function and you want its internal shape -- the conditions+jumps half of comprehension -- without reading the full pseudocode. The natural drill target of every hierarchy node's drill={into:'function_skeleton'} payload.

RETURNS: {func, resolved_addr, name, prototype, block_count, edge_count, cyclomatic_complexity, loop_count, blocks:[{id,start,end,terminator,condition,true_succ,false_succ,succ_ids,calls_here,is_loop_head,back_edges}], guarded_calls:[{call,guard,site}], indirect_sites, decompiled, decompile_error?, truncated, error?}. condition is the human phrasing of the block's terminating conditional branch; true_succ/false_succ are the taken/fallthrough targets. guarded_calls comes from the ctree and is empty when the decompiler is unavailable.

PRO-TIP: Scan guarded_calls first -- it tells you which calls are conditional and under what predicate, the fastest way to find the "only runs when X" paths. PITFALL: condition is a structural label from the branch mnemonic, not a recovered expression; for the real predicate use the guard field in guarded_calls (decompiler-backed)."""
    try:
        start_ea, err = _resolve_func_start(func)
        if err is not None or start_ea is None:
            return {
                "func": func,
                "resolved_addr": None,
                "blocks": [],
                "error": err or "Failed to resolve function",
            }

        f = idaapi.get_func(start_ea)
        if f is None:
            return {
                "func": func,
                "resolved_addr": hex(start_ea),
                "blocks": [],
                "error": f"No function at {hex(start_ea)}",
            }

        # --- CFG ---
        fc = idaapi.FlowChart(f, flags=idaapi.FC_PREDS)
        # Map block start -> id for back-edge detection.
        block_starts: dict[int, int] = {}
        block_list = []
        for blk in fc:
            block_starts[blk.start_ea] = blk.id
            block_list.append(blk)

        blocks: list[SkeletonBlock] = []
        total_edges = 0
        loop_count = 0
        truncated = False

        for blk in block_list:
            if len(blocks) >= _MAX_BLOCKS:
                truncated = True
                break
            b_start = blk.start_ea
            b_end = blk.end_ea
            succ_ids: list[int] = []
            for s in blk.succs():
                succ_ids.append(s.id)
                total_edges += 1
            # back-edges: successor whose start <= this block's start (loop back).
            back_edges = [sid for sid in succ_ids
                          if sid <= blk.id]
            is_loop_head = bool(back_edges)
            if is_loop_head:
                loop_count += 1

            term_ea = _last_insn_ea(b_start, b_end)
            mnem = (idc.print_insn_mnem(term_ea) or "").strip()
            condition = _human_condition(mnem) if mnem else None

            # true/false successors: for a conditional branch the taken target is
            # the operand; the fallthrough is the next instruction's block.
            true_succ = None
            false_succ = None
            if condition is not None:
                try:
                    tgt = idc.get_operand_value(term_ea, 0)
                except Exception:
                    tgt = idaapi.BADADDR
                fall = idc.next_head(term_ea, b_end + 0x1000)
                for s in blk.succs():
                    if s.start_ea == tgt:
                        true_succ = hex(s.start_ea)
                    elif s.start_ea == fall:
                        false_succ = hex(s.start_ea)
                # fill any gap from succ list
                if true_succ is None or false_succ is None:
                    for s in blk.succs():
                        sh = hex(s.start_ea)
                        if sh != true_succ and false_succ is None and sh != false_succ:
                            if true_succ is None:
                                true_succ = sh
                            else:
                                false_succ = sh

            # calls in this block.
            calls_here: list[SkeletonCall] = []
            ea = b_start
            while ea < b_end and ea != idaapi.BADADDR:
                if len(calls_here) >= _MAX_CALLS_PER_BLOCK:
                    break
                insn = idaapi.insn_t()
                if idaapi.decode_insn(insn, ea) > 0 and idaapi.is_call_insn(insn):
                    op0 = idc.get_operand_type(ea, 0)
                    if op0 in (idaapi.o_near, idaapi.o_far):
                        tgt = idc.get_operand_value(ea, 0)
                        calls_here.append({
                            "site": hex(ea),
                            "target": hex(tgt),
                            "name": idc.get_name(tgt) or None,
                            "kind": "call",
                            "indirect": False,
                        })
                    else:
                        calls_here.append({
                            "site": hex(ea),
                            "target": None,
                            "name": None,
                            "kind": "indirect",
                            "indirect": True,
                        })
                ea = idc.next_head(ea, b_end)

            blocks.append({
                "id": blk.id,
                "start": hex(b_start),
                "end": hex(b_end),
                "terminator": mnem or None,
                "condition": condition,
                "true_succ": true_succ,
                "false_succ": false_succ,
                "succ_ids": succ_ids,
                "calls_here": calls_here,
                "is_loop_head": is_loop_head,
                "back_edges": back_edges,
            })

        block_count = len(block_list)
        # cyclomatic complexity = E - N + 2 (single connected component).
        cyclomatic = total_edges - block_count + 2 if block_count else 0

        # --- ctree guard recovery ---
        guarded_calls: list[GuardedCall] = []
        decompiled = False
        decompile_error: str | None = None
        cfunc, derr = get_cached_cfunc(start_ea)
        if cfunc is None or derr is not None:
            decompile_error = derr
        else:
            decompiled = True
            try:
                guarded_calls = _collect_guarded_calls(cfunc)
            except Exception:
                guarded_calls = []

        # indirect sites (mnemonic + ctree, unified).
        indirect_sites: list[str] = []
        seen_sites: set[int] = set()
        for edge in iter_func_call_edges(start_ea, "out"):
            if edge.get("indirect") and edge.get("from") is not None:
                s = int(edge["from"])
                if s not in seen_sites:
                    seen_sites.add(s)
                    indirect_sites.append(hex(s))
        for s in _ctree_indirect_sites(start_ea):
            if s not in seen_sites:
                seen_sites.add(s)
                indirect_sites.append(hex(s))

        return {
            "func": func,
            "resolved_addr": hex(start_ea),
            "name": _func_name(start_ea),
            "prototype": _prototype_for(start_ea),
            "block_count": block_count,
            "edge_count": total_edges,
            "cyclomatic_complexity": cyclomatic,
            "loop_count": loop_count,
            "blocks": blocks,
            "guarded_calls": guarded_calls,
            "indirect_sites": indirect_sites,
            "decompiled": decompiled,
            "decompile_error": decompile_error,
            "truncated": truncated,
            "error": None,
        }
    except Exception as e:
        return {
            "func": func,
            "resolved_addr": None,
            "blocks": [],
            "error": str(e),
        }


def _expr_text(cfunc, expr) -> str:
    """Best-effort one-line source text of a ctree expression."""
    try:
        import ida_lines
        s = expr.print1(None)
        if s:
            return ida_lines.tag_remove(s).strip()
    except Exception:
        pass
    return "<expr>"


def _call_name(cfunc, call_expr) -> Optional[str]:
    """Resolve the callee name of a cot_call expression, if direct."""
    try:
        callee = call_expr.x
        if callee is None:
            return None
        if callee.op == ida_hexrays.cot_obj:
            ea = callee.obj_ea
            nm = idc.get_name(ea)
            if nm:
                return nm
        return _expr_text(cfunc, callee)
    except Exception:
        return None


def _collect_guarded_calls(cfunc) -> list[GuardedCall]:
    """Walk the ctree statements; attach the enclosing if/for/while guard to
    every cot_call found beneath it.

    Returns guarded_calls like {"call": "decrypt", "guard": "g_init && argc > 1",
    "site": "0x.."}. Only calls that sit under at least one structural guard are
    reported (unconditional calls are omitted -- the skeleton's per-block
    calls_here already covers those).
    """
    out: list[GuardedCall] = []

    def _calls_in(expr, guard: str):
        # collect cot_call expressions inside an expression subtree
        found: list = []

        class _CV(ida_hexrays.ctree_visitor_t):
            def __init__(self):
                ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)

            def visit_expr(self, e):
                if e.op == ida_hexrays.cot_call:
                    found.append(e)
                return 0

        try:
            cv = _CV()
            cv.apply_to(expr, None)
        except Exception:
            pass
        for ce in found:
            if len(out) >= _MAX_GUARDED_CALLS:
                break
            name = _call_name(cfunc, ce) or "<call>"
            site = ce.ea if ce.ea != idaapi.BADADDR else None
            out.append({
                "call": name,
                "guard": guard,
                "site": hex(site) if site is not None else None,
            })

    class _SV(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)

        def visit_insn(self, ins):
            if len(out) >= _MAX_GUARDED_CALLS:
                return 1
            try:
                if ins.op == ida_hexrays.cit_if and ins.cif is not None:
                    guard = "if (" + _expr_text(cfunc, ins.cif.expr) + ")"
                    if ins.cif.ithen is not None:
                        _calls_in(ins.cif.ithen, guard)
                    if ins.cif.ielse is not None:
                        _calls_in(ins.cif.ielse, "else of " + guard)
                elif ins.op == ida_hexrays.cit_for and ins.cfor is not None:
                    guard = "for (" + _expr_text(cfunc, ins.cfor.expr) + ")"
                    if ins.cfor.body is not None:
                        _calls_in(ins.cfor.body, guard)
                elif ins.op == ida_hexrays.cit_while and ins.cwhile is not None:
                    guard = "while (" + _expr_text(cfunc, ins.cwhile.expr) + ")"
                    if ins.cwhile.body is not None:
                        _calls_in(ins.cwhile.body, guard)
                elif ins.op == ida_hexrays.cit_do and ins.cdo is not None:
                    guard = "do-while (" + _expr_text(cfunc, ins.cdo.expr) + ")"
                    if ins.cdo.body is not None:
                        _calls_in(ins.cdo.body, guard)
            except Exception:
                pass
            return 0

    try:
        _SV().apply_to(cfunc.body, None)
    except Exception:
        return out
    # De-duplicate by (call, guard, site).
    seen: set[tuple] = set()
    uniq: list[GuardedCall] = []
    for g in out:
        key = (g.get("call"), g.get("guard"), g.get("site"))
        if key in seen:
            continue
        seen.add(key)
        uniq.append(g)
    return uniq


# ============================================================================
# module_hierarchy -- the SUBSYSTEM view
# ============================================================================


def _grow_members(seed_ea: int, grow_depth: int, deadline: float | None) -> list[int]:
    """Auto-grow a member set from a seed via a low-depth callee walk."""
    walk = walk_call_tree(
        seed_ea,
        depth=grow_depth,
        node_budget=_MODULE_MEMBER_CAP,
        direction="out",
        deadline=deadline,
    )
    members: list[int] = []
    seen: set[int] = set()
    for node in walk:
        if node.get("back_edge"):
            continue
        ea = node["ea"]
        if ea in seen:
            continue
        seen.add(ea)
        members.append(ea)
        if len(members) >= _MODULE_MEMBER_CAP:
            break
    return members


@safety("READ")
@title("Module Hierarchy (Auto-Grown Subsystem)")
@tool
@idasync
@tool_timeout(180.0)
def module_hierarchy(
    seed: Annotated[
        str,
        "Seed function address (hex like '0x401000') or symbol name. The subsystem is grown from it.",
    ],
    grow_depth: Annotated[
        int,
        "How many callee levels to absorb into the member set (default 2; clamped 0..4). Deeper pulls in more of the subsystem.",
    ] = 2,
) -> ModuleHierarchyResult:
    """WHAT: The SUBSYSTEM russian-doll view. Auto-grows a member set from a seed function (callees to grow_depth), classifies each member as interface (called from OUTSIDE the set) vs internal, and emits the inner intra-set call graph plus the outer reaches_out (dependencies the subsystem calls) and reached_by_in (external API consumers) edges and the globals shared by two or more members. Each member carries drill/expand payloads into function_skeleton / call_hierarchy. Supersedes analyze_component with a true nested view (you give it ONE seed, not a hand-built list).

WHEN TO USE: When a seed function looks like the entry point of a feature/component and you want the whole subsystem mapped -- its API surface, its internal helpers, what it depends on, and who depends on it -- in one nested response.

RETURNS: {seed, resolved_addr, members:[{addr,name,role,prototype,drill,expand}], interface, internal, inner_call_graph:{nodes,edges}, reaches_out:[{from,to,name}], reached_by_in:[{from,to,name}], shared_globals:[{addr,name,accessed_by}], member_count, truncated, error?}. role is 'interface' when a member is called from outside the grown set, else 'internal'. reaches_out is the subsystem's outward dependencies; reached_by_in is its external consumers.

PRO-TIP: Read the `interface` members first -- they are the subsystem's public API; then follow inner_call_graph down into the internal helpers. PITFALL: the boundary is whatever grow_depth absorbed -- if reaches_out is huge the subsystem is under-grown (raise grow_depth) or genuinely leaky; if interface is empty you seeded an internal helper, not an entry point."""
    import idautils as _idautils
    from collections import defaultdict

    try:
        start_ea, err = _resolve_func_start(seed)
        if err is not None or start_ea is None:
            return {
                "seed": seed,
                "resolved_addr": None,
                "members": [],
                "error": err or "Failed to resolve function",
            }
        if grow_depth < 0:
            grow_depth = 0
        if grow_depth > 4:
            grow_depth = 4

        deadline = get_tool_deadline()
        member_eas = _grow_members(start_ea, grow_depth, deadline)
        member_set = set(member_eas)
        truncated = len(member_eas) >= _MODULE_MEMBER_CAP

        # Inner call graph + outer reaches-out.
        inner_nodes = [hex(ea) for ea in member_eas]
        inner_edges: list[ModuleEdge] = []
        reaches_out: list[ModuleEdge] = []
        inner_seen: set[tuple] = set()
        out_seen: set[tuple] = set()
        for ea in member_eas:
            for edge in iter_func_call_edges(ea, "out"):
                to = edge.get("to")
                if to is None or edge.get("kind") not in ("call", "tailcall"):
                    continue
                callee = idaapi.get_func(to)
                callee_start = callee.start_ea if callee is not None else None
                if callee_start is None:
                    continue
                if callee_start in member_set:
                    key = (ea, callee_start)
                    if key not in inner_seen:
                        inner_seen.add(key)
                        inner_edges.append({
                            "from": hex(ea),
                            "to": hex(callee_start),
                            "name": _func_name(callee_start),
                        })
                else:
                    key = (ea, callee_start)
                    if key not in out_seen and len(reaches_out) < _MODULE_EDGE_CAP:
                        out_seen.add(key)
                        reaches_out.append({
                            "from": hex(ea),
                            "to": hex(callee_start),
                            "name": _func_name(callee_start),
                        })

        # Interface vs internal + reached-by-in (external consumers).
        interface: list[str] = []
        internal: list[str] = []
        reached_by_in: list[ModuleEdge] = []
        in_seen: set[tuple] = set()
        for ea in member_eas:
            external_caller = False
            has_any_caller = False
            for edge in iter_func_call_edges(ea, "in"):
                site = edge.get("from")
                caller = idaapi.get_func(site) if site is not None else None
                caller_start = caller.start_ea if caller is not None else None
                if caller_start is None:
                    continue
                has_any_caller = True
                if caller_start not in member_set:
                    external_caller = True
                    key = (caller_start, ea)
                    if key not in in_seen and len(reached_by_in) < _MODULE_EDGE_CAP:
                        in_seen.add(key)
                        reached_by_in.append({
                            "from": hex(caller_start),
                            "to": hex(ea),
                            "name": _func_name(ea),
                        })
            # Interface = called from outside the set OR a root/entry with no
            # detectable direct callers at all (an entry point is entered
            # indirectly by the CRT / via a pointer, so it has no call edge but
            # is still the subsystem's public surface). Internal = called only
            # from within the set.
            if external_caller or not has_any_caller:
                interface.append(hex(ea))
            else:
                internal.append(hex(ea))

        # Shared globals (data refs out of >= 2 members).
        func_globals: dict[int, set[int]] = {}
        for ea in member_eas:
            accessed: set[int] = set()
            func = idaapi.get_func(ea)
            if func is not None:
                for head in _idautils.Heads(func.start_ea, func.end_ea):
                    for xref in _idautils.XrefsFrom(head, 0):
                        if xref.iscode:
                            continue
                        ref_func = idaapi.get_func(xref.to)
                        if ref_func is None and idaapi.is_loaded(xref.to):
                            accessed.add(xref.to)
            func_globals[ea] = accessed

        global_refcount: dict[int, list[str]] = defaultdict(list)
        for ea, gset in func_globals.items():
            fname = _func_name(ea)
            for g in gset:
                global_refcount[g].append(fname)
        shared_globals: list[ModuleSharedGlobal] = []
        for g_ea, accessors in sorted(global_refcount.items()):
            if len(accessors) >= 2:
                shared_globals.append({
                    "addr": hex(g_ea),
                    "name": idaapi.get_name(g_ea) or hex(g_ea),
                    "accessed_by": sorted(accessors),
                })

        members: list[ModuleMember] = []
        for ea in member_eas:
            addr_hex = hex(ea)
            role = "interface" if addr_hex in interface else "internal"
            members.append({
                "addr": addr_hex,
                "name": _func_name(ea),
                "role": role,
                "prototype": _prototype_for(ea),
                "drill": _drill(addr_hex),
                "expand": _expand(addr_hex, "both"),
            })

        return {
            "seed": seed,
            "resolved_addr": hex(start_ea),
            "members": members,
            "interface": interface,
            "internal": internal,
            "inner_call_graph": {"nodes": inner_nodes, "edges": inner_edges},
            "reaches_out": reaches_out,
            "reached_by_in": reached_by_in,
            "shared_globals": shared_globals,
            "member_count": len(members),
            "truncated": truncated,
            "error": None,
        }
    except Exception as e:
        return {
            "seed": seed,
            "resolved_addr": None,
            "members": [],
            "error": str(e),
        }


# ============================================================================
# hierarchy_runtime_overlay -- the LIVE view (debugger extension)
# ============================================================================


def _norm_ea(value) -> Optional[int]:
    """Coerce a probe record ea value (hex str or int) to an int."""
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            return None
    return None


@ext("dbg")
@safety("READ")
@title("Hierarchy Runtime Overlay (Merge Probe Hits)")
@tool
@idasync
@tool_timeout(120.0)
def hierarchy_runtime_overlay(
    root: Annotated[
        str,
        "Root function address (hex like '0x401000') or symbol name. The static call_hierarchy around it is built then overlaid with live hit-counts.",
    ],
    direction: Annotated[
        str,
        "Which dolls to expand on the static hierarchy: 'both', 'out' or 'in'. Default: 'both'.",
    ] = "both",
    depth: Annotated[
        int,
        "Static hierarchy expansion depth (default 3; clamped 0..8).",
    ] = 3,
) -> HierarchyRuntimeOverlayResult:
    """WHAT: Merges live probe/trace hit-counts onto a STATIC call_hierarchy by edge/function key, so you see which dolls actually executed. Builds the static hierarchy around root, drains the probe ring (trace.py ProbeRing), and tags each static edge with taken/hits (matched by call-site / caller->callee key) and each block/function with an executed hit count. READ-ONLY: it never sets breakpoints, never patches, never resumes -- it only reads already-captured probe records.

WHEN TO USE: After a debugging/probe session, to fold runtime evidence back onto the static structure -- find the hot path, confirm a guarded call actually fired, or spot statically-reachable edges that never ran. Pair with the probe toolkit (probe_add / probe_drain) which captures the hits this tool reads.

RETURNS: {root, direction, runtime:'present'|'no_runtime_data', static:<call_hierarchy result>, edge_hits:[{from_,to,kind,hits,taken}], block_executed:[{addr,name,hits}], records_seen, error?}. runtime='no_runtime_data' means the probe ring was empty (no live session / nothing captured) -- the static hierarchy is still returned, just with zero overlay. This is honest: an empty overlay is reported, never faked.

PRO-TIP: Cross-reference edge_hits taken=false edges with the static edges to find code that is statically reachable but never executed in your session -- candidate dead paths or untriggered features. PITFALL: coverage is only as good as the probes you installed; a taken=false edge may simply lack a probe, not be unreachable. Install entry/caller probes on the functions you care about first."""
    try:
        static = call_hierarchy(
            root=root,
            direction=direction,
            depth=depth,
            max_nodes=_MAX_NODES_CAP,
            include_indirect=True,
            exclude="",
            collapse_leaves=True,
        )
        if static.get("error"):
            return {
                "root": root,
                "direction": direction,
                "runtime": "no_runtime_data",
                "static": static,
                "edge_hits": [],
                "block_executed": [],
                "records_seen": 0,
                "error": static.get("error"),
            }

        # Drain the probe ring (non-destructive).
        try:
            ring = _trace.get_probe_ring()
            records = ring.drain(since_cursor=0, limit=65536)
        except Exception:
            records = []

        records_seen = len(records)
        runtime = "present" if records_seen else "no_runtime_data"

        # Per-function executed counts: a record's ea identifies the probed
        # function entry; the captured "caller" gives the inbound edge.
        func_hits: dict[int, int] = {}
        edge_hits_map: dict[tuple, int] = {}
        for rec in records:
            if not isinstance(rec, dict):
                continue
            ea = _norm_ea(rec.get("ea") or rec.get("func"))
            if ea is not None:
                func = idaapi.get_func(ea)
                fstart = func.start_ea if func is not None else ea
                func_hits[fstart] = func_hits.get(fstart, 0) + 1
                captured = rec.get("captured") or {}
                caller_v = captured.get("caller", rec.get("caller"))
                caller_ea = _norm_ea(caller_v)
                if caller_ea is not None:
                    cfunc = idaapi.get_func(caller_ea)
                    cstart = cfunc.start_ea if cfunc is not None else caller_ea
                    key = (cstart, fstart)
                    edge_hits_map[key] = edge_hits_map.get(key, 0) + 1

        # Build edge overlay keyed off the static edges.
        edge_hits: list[OverlayEdge] = []
        for e in static.get("edges", []):
            try:
                frm = int(e["from"], 16)
                to = int(e["to"], 16)
            except (ValueError, KeyError, TypeError):
                continue
            hits = edge_hits_map.get((frm, to), 0)
            edge_hits.append({
                "from_": e["from"],
                "to": e["to"],
                "kind": e.get("kind", "call"),
                "hits": hits,
                "taken": hits > 0,
            })

        # Block/function executed overlay keyed off static nodes.
        block_executed: list[dict] = []
        for n in static.get("nodes", []):
            try:
                ea = int(n["addr"], 16)
            except (ValueError, KeyError, TypeError):
                continue
            hits = func_hits.get(ea, 0)
            if hits:
                block_executed.append({
                    "addr": n["addr"],
                    "name": n.get("name", ""),
                    "hits": hits,
                })

        return {
            "root": root,
            "direction": direction,
            "runtime": runtime,
            "static": static,
            "edge_hits": edge_hits,
            "block_executed": block_executed,
            "records_seen": records_seen,
            "error": None,
        }
    except Exception as e:
        return {
            "root": root,
            "direction": direction,
            "runtime": "no_runtime_data",
            "static": {},
            "edge_hits": [],
            "block_executed": [],
            "records_seen": 0,
            "error": str(e),
        }


__all__ = [
    "call_hierarchy",
    "function_skeleton",
    "module_hierarchy",
    "hierarchy_runtime_overlay",
]
