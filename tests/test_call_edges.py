"""Headless unit tests for the Batch-2 call-edge / call-tree seams in utils.py.

Two pure-ish helpers underpin the whole call-graph stack now:

  * ``utils.classify_code_edge`` -- decodes one instruction and labels the edge
    leaving it as call / tailcall / jump / fallthrough / indirect.
  * ``utils.walk_call_tree`` -- iterative BFS over the call graph with depth,
    node, and time budgets plus cycle/back-edge detection.

Neither runs against a live IDB here. ``classify_code_edge`` is driven by
monkeypatching the thin IDA seams it consults (``_insn_at`` and a handful of
``idaapi``/``idc`` callables), so we can synthesise representative x86-style
encodings. ``walk_call_tree`` is driven by monkeypatching ``_call_neighbors``
-- its single graph seam -- with in-memory adjacency dicts, which lets us prove
the budget/cycle/termination contract without IDA. The package imports cleanly
under the conftest idaapi stub.
"""

import time

import idaapi
import idc

from ida_pro_mcp.ida_mcp import utils


# ---------------------------------------------------------------------------
# classify_code_edge
#
# The function consults: utils._insn_at(ea), idaapi.is_call_insn(insn),
# idc.get_operand_type(ea,0), idc.print_insn_mnem(ea), idc.get_operand_value,
# idaapi.get_func(ea). We pin the operand-type / itype constants to concrete
# ints and stub those seams per-case.
# ---------------------------------------------------------------------------


# Distinct concrete operand-type sentinels (the stub would otherwise hand back
# MagicMocks that compare unequal to everything).
_O_VOID = 0
_O_REG = 1
_O_MEM = 2
_O_NEAR = 7
_O_FAR = 6


def _pin_operand_constants(monkeypatch):
    monkeypatch.setattr(idaapi, "o_void", _O_VOID, raising=False)
    monkeypatch.setattr(idaapi, "o_reg", _O_REG, raising=False)
    monkeypatch.setattr(idaapi, "o_mem", _O_MEM, raising=False)
    monkeypatch.setattr(idaapi, "o_near", _O_NEAR, raising=False)
    monkeypatch.setattr(idaapi, "o_far", _O_FAR, raising=False)


class _FakeFunc:
    def __init__(self, start_ea):
        self.start_ea = start_ea


def _install_edge_stubs(
    monkeypatch,
    *,
    decodable=True,
    is_call=False,
    op0_type=_O_VOID,
    mnem="",
    operand_value=0,
    funcs=None,
):
    """Wire up classify_code_edge's seams for a single synthetic instruction.

    `funcs` maps an EA -> start_ea for idaapi.get_func (a function starts at
    `start_ea` exactly when get_func(ea).start_ea == ea).
    """
    _pin_operand_constants(monkeypatch)
    funcs = funcs or {}

    monkeypatch.setattr(
        utils, "_insn_at", lambda ea: (object() if decodable else None)
    )
    monkeypatch.setattr(idaapi, "is_call_insn", lambda insn: is_call)
    monkeypatch.setattr(idc, "get_operand_type", lambda ea, n: op0_type)
    monkeypatch.setattr(idc, "print_insn_mnem", lambda ea: mnem)
    monkeypatch.setattr(idc, "get_operand_value", lambda ea, n: operand_value)

    def _get_func(ea):
        if ea in funcs:
            return _FakeFunc(funcs[ea])
        return None

    monkeypatch.setattr(idaapi, "get_func", _get_func)


def test_classify_undecodable_defaults_to_fallthrough(monkeypatch):
    _install_edge_stubs(monkeypatch, decodable=False)
    assert utils.classify_code_edge(0x1000) == "fallthrough"


def test_classify_direct_near_call(monkeypatch):
    # call sub_2000  (near operand) -> direct call
    _install_edge_stubs(
        monkeypatch, is_call=True, op0_type=_O_NEAR, mnem="call"
    )
    assert utils.classify_code_edge(0x1000) == "call"


def test_classify_indirect_register_call(monkeypatch):
    # call rax  (register operand) -> indirect
    _install_edge_stubs(
        monkeypatch, is_call=True, op0_type=_O_REG, mnem="call"
    )
    assert utils.classify_code_edge(0x1000) == "indirect"


def test_classify_memory_call_is_indirect(monkeypatch):
    # call [rip+x] (o_mem) -> indirect: the real callee is the pointed-to value.
    _install_edge_stubs(
        monkeypatch, is_call=True, op0_type=_O_MEM, mnem="call"
    )
    assert utils.classify_code_edge(0x1000) == "indirect"


def test_classify_tailcall_jmp_to_other_func_start(monkeypatch):
    # jmp sub_2000, where 0x2000 is the *start* of a different function, and the
    # source 0x1000 lives in another function (start 0x900) -> tailcall.
    _install_edge_stubs(
        monkeypatch,
        is_call=False,
        op0_type=_O_NEAR,
        mnem="jmp",
        operand_value=0x2000,
        funcs={0x2000: 0x2000, 0x1000: 0x900},
    )
    assert utils.classify_code_edge(0x1000) == "tailcall"


def test_classify_jump_within_same_function(monkeypatch):
    # jmp into the middle / same function -> plain jump, not a tailcall.
    # target 0x1100 is not a function start (get_func(0x1100).start_ea==0x900).
    _install_edge_stubs(
        monkeypatch,
        is_call=False,
        op0_type=_O_NEAR,
        mnem="jmp",
        operand_value=0x1100,
        funcs={0x1100: 0x900, 0x1000: 0x900},
    )
    assert utils.classify_code_edge(0x1000) == "jump"


def test_classify_conditional_jump_to_func_start_in_same_func(monkeypatch):
    # jz that targets a function start that is ALSO the source's own function
    # start -> jump (self recursion entry is not a tailcall).
    _install_edge_stubs(
        monkeypatch,
        is_call=False,
        op0_type=_O_NEAR,
        mnem="jz",
        operand_value=0x900,
        funcs={0x900: 0x900, 0x1000: 0x900},
    )
    assert utils.classify_code_edge(0x1000) == "jump"


def test_classify_indirect_jump_register(monkeypatch):
    # jmp rax (register operand, not a direct target) -> indirect.
    _install_edge_stubs(
        monkeypatch, is_call=False, op0_type=_O_REG, mnem="jmp"
    )
    assert utils.classify_code_edge(0x1000) == "indirect"


def test_classify_non_branch_is_fallthrough(monkeypatch):
    # mov eax, ebx -> fallthrough (decodable, not a call, not a jump).
    _install_edge_stubs(
        monkeypatch, is_call=False, op0_type=_O_REG, mnem="mov"
    )
    assert utils.classify_code_edge(0x1000) == "fallthrough"


# ---------------------------------------------------------------------------
# walk_call_tree
#
# Driven by monkeypatching utils._call_neighbors(ea, direction) with in-memory
# adjacency. get_tool_deadline() returns None headless (no @idasync body), so
# the deadline path is inert unless we pass one explicitly.
# ---------------------------------------------------------------------------


def _patch_neighbors(monkeypatch, graph):
    """Drive walk_call_tree against `graph` (dict ea -> list of neighbour eas)."""
    monkeypatch.setattr(
        utils, "_call_neighbors", lambda ea, direction: list(graph.get(ea, []))
    )


def _by_ea(nodes):
    """First (shallowest-recorded) non-back-edge node per ea."""
    out = {}
    for n in nodes:
        if n["back_edge"]:
            continue
        out.setdefault(n["ea"], n)
    return out


def test_walk_root_only_at_depth_zero(monkeypatch):
    _patch_neighbors(monkeypatch, {1: [2, 3]})
    nodes = utils.walk_call_tree(1, depth=0, node_budget=100)
    assert len(nodes) == 1
    root = nodes[0]
    assert root["ea"] == 1
    assert root["depth"] == 0
    assert root["parent"] is None
    # depth==0 means no neighbours were expanded -> recorded as a leaf.
    assert root["is_leaf"] is True


def test_walk_records_bfs_depths(monkeypatch):
    _patch_neighbors(monkeypatch, {1: [2], 2: [3], 3: [4]})
    nodes = utils.walk_call_tree(1, depth=3, node_budget=100)
    depths = {n["ea"]: n["depth"] for n in nodes if not n["back_edge"]}
    assert depths == {1: 0, 2: 1, 3: 2, 4: 3}
    # Parent chain is the call chain.
    by = _by_ea(nodes)
    assert by[1]["parent"] is None
    assert by[2]["parent"] == 1
    assert by[3]["parent"] == 2
    assert by[4]["parent"] == 3


def test_walk_depth_bound_stops_descent(monkeypatch):
    _patch_neighbors(monkeypatch, {1: [2], 2: [3], 3: [4]})
    nodes = utils.walk_call_tree(1, depth=1, node_budget=100)
    eas = {n["ea"] for n in nodes if not n["back_edge"]}
    assert eas == {1, 2}  # 3 and 4 are beyond the depth bound


def test_walk_node_budget_caps_distinct_nodes(monkeypatch):
    # Fan-out wider than the budget: root + budget-1 children get recorded, then
    # the walk stops (the node that would exceed the cap is not added).
    _patch_neighbors(monkeypatch, {1: [2, 3, 4, 5, 6]})
    nodes = utils.walk_call_tree(1, depth=3, node_budget=3)
    distinct = {n["ea"] for n in nodes if not n["back_edge"]}
    assert len(distinct) <= 3


def test_walk_flags_back_edge_on_cycle(monkeypatch):
    # 1 -> 2 -> 3 -> 1 : the 3->1 edge is a back-edge to an already-visited node.
    _patch_neighbors(monkeypatch, {1: [2], 2: [3], 3: [1]})
    nodes = utils.walk_call_tree(1, depth=10, node_budget=100)
    back = [n for n in nodes if n["back_edge"]]
    assert back, "expected a back-edge node flagging the cycle"
    assert any(n["ea"] == 1 for n in back), "back-edge should point at node 1"
    # Each function is still recorded exactly once as a real node.
    real = [n for n in nodes if not n["back_edge"]]
    assert {n["ea"] for n in real} == {1, 2, 3}


def test_walk_flags_self_recursion(monkeypatch):
    # A function that calls itself: is_recursive set, no infinite loop.
    _patch_neighbors(monkeypatch, {1: [1, 2], 2: []})
    nodes = utils.walk_call_tree(1, depth=5, node_budget=100)
    root = next(n for n in nodes if n["ea"] == 1 and not n["back_edge"])
    assert root["is_recursive"] is True


def test_walk_terminates_on_deep_cyclic_graph(monkeypatch):
    # Long chain that loops back on itself; without cycle detection this would
    # recurse/loop forever. Assert it terminates promptly and records each node
    # once with no RecursionError.
    n = 500
    graph = {i: [i + 1] for i in range(n)}
    graph[n] = [0]  # close the cycle back to the root
    _patch_neighbors(monkeypatch, graph)

    started = time.monotonic()
    nodes = utils.walk_call_tree(0, depth=10_000, node_budget=10_000)
    elapsed = time.monotonic() - started

    assert elapsed < 5.0, "walk_call_tree did not terminate promptly"
    real = {x["ea"] for x in nodes if not x["back_edge"]}
    assert real == set(range(n + 1))  # every function visited exactly once
    # The closing edge n->0 lands on the already-visited root: a back-edge.
    assert any(x["back_edge"] and x["ea"] == 0 for x in nodes)


def test_walk_deadline_bails_early(monkeypatch):
    # An already-expired deadline stops the walk at the root frontier.
    _patch_neighbors(monkeypatch, {1: [2], 2: [3]})
    nodes = utils.walk_call_tree(
        1, depth=10, node_budget=100, deadline=time.monotonic() - 1.0
    )
    assert nodes == []


def test_walk_negative_depth_clamped(monkeypatch):
    _patch_neighbors(monkeypatch, {1: [2]})
    nodes = utils.walk_call_tree(1, depth=-5, node_budget=100)
    assert [n["ea"] for n in nodes] == [1]


def test_walk_direction_normalised(monkeypatch):
    # Any direction other than "in" collapses to "out"; assert the seam receives
    # exactly one of the two normalised values.
    seen_dirs = []

    def _neighbors(ea, direction):
        seen_dirs.append(direction)
        return []

    monkeypatch.setattr(utils, "_call_neighbors", _neighbors)
    utils.walk_call_tree(1, depth=1, node_budget=100, direction="garbage")
    assert seen_dirs == ["out"]

    seen_dirs.clear()
    utils.walk_call_tree(1, depth=1, node_budget=100, direction="in")
    assert seen_dirs == ["in"]
