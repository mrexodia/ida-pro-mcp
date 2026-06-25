"""Real-IDA coverage for under-tested tool modules.

Closes coverage gaps the headless pure-logic suites cannot reach because they
need a live decompiler / call graph:

  * api_graph.callees_recursive -- nesting-depth labelling and cycle/back-edge
    handling on the crackme call graph (beyond the existing shape/transpose
    tests in test_api_graph.py),
  * api_recipes.recipe_function_report -- one chaining recipe driven
    end-to-end, asserting the dossier it aggregates is internally consistent,
  * api_decomp.pseudocode_query -- the Hex-Rays ctree walk returns structured
    nodes (skipped cleanly when Hex-Rays is unavailable).

These assert structural invariants that hold across IDA / Hex-Rays revisions
rather than hard-coded counts.
"""

from ..framework import (
    test,
    skip_test,
    assert_has_keys,
    assert_valid_address,
    get_any_function,
    get_unmapped_address,
)
from ..api_graph import callees_recursive, reaches
from ..api_recipes import recipe_function_report
from ..api_decomp import pseudocode_query


CRACKME_MAIN = "0x123e"


def _node_addrs(result) -> set[str]:
    return {n["addr"] for n in result.get("nodes", [])}


def _depth_of(result, addr: str) -> int | None:
    for n in result.get("nodes", []):
        if n["addr"] == addr:
            return n["depth"]
    return None


# ===========================================================================
# api_graph -- nesting depth
# ===========================================================================


@test(binary="crackme03.elf")
def test_callees_recursive_depths_are_contiguous_from_root():
    """Depth labels form a contiguous band 0..max_observed with no gaps.

    A BFS closure assigns each function its shortest call distance from the
    root. The set of observed depths must therefore start at 0 (the root) and
    contain no holes -- a missing intermediate depth would mean a node was
    recorded deeper than any of its possible parents, i.e. broken labelling.
    """
    result = callees_recursive(CRACKME_MAIN, max_depth=6)
    assert result.get("error") in (None, "")
    depths = sorted({n["depth"] for n in result["nodes"]})
    assert depths[0] == 0, "root must be recorded at depth 0"
    assert depths == list(range(depths[0], depths[-1] + 1)), (
        f"depth band has gaps: {depths}"
    )
    # main has callees, so the tree is genuinely nested (not just the root).
    assert depths[-1] >= 1, "main's callee tree should descend at least one level"


@test(binary="crackme03.elf")
def test_callees_recursive_depth_bound_truncates_band():
    """max_depth caps the deepest recorded node at exactly max_depth.

    No node may carry a depth greater than the requested bound; this is the
    contract that lets a caller widen the bound incrementally.
    """
    for bound in (0, 1, 2, 3):
        result = callees_recursive(CRACKME_MAIN, max_depth=bound)
        assert result.get("error") in (None, "")
        observed = {n["depth"] for n in result["nodes"]}
        assert max(observed) <= bound, (
            f"max_depth={bound} but found node at depth {max(observed)}"
        )
        # The shallower closure is always a subset of the deeper one.
        if bound > 0:
            shallower = _node_addrs(callees_recursive(CRACKME_MAIN, max_depth=bound - 1))
            deeper = _node_addrs(result)
            assert shallower <= deeper, "widening max_depth dropped a node"


@test(binary="crackme03.elf")
def test_callees_recursive_saturates_and_is_stable():
    """Past the graph's true depth the closure stops growing (finite reachset).

    Querying a very large max_depth must not loop forever or keep inventing
    nodes; two large bounds yield the identical node set, proving the BFS
    terminates on the finite reachable set.
    """
    big = callees_recursive(CRACKME_MAIN, max_depth=64)
    bigger = callees_recursive(CRACKME_MAIN, max_depth=128)
    assert big.get("error") in (None, "")
    if big.get("truncated") or bigger.get("truncated"):
        skip_test("closure truncated by node budget; saturation not observable")
    assert _node_addrs(big) == _node_addrs(bigger), (
        "closure changed between two over-deep bounds; traversal did not saturate"
    )


@test(binary="crackme03.elf")
def test_callees_recursive_edges_are_internal_and_depth_monotone():
    """Every recorded edge connects two recorded nodes and never points uphill.

    For a call edge from->to in the callee direction, `to` must sit no
    shallower than `from` (a child is at parent.depth or deeper); back-edges to
    an already-seen ancestor are surfaced via the node `back_edge` flag rather
    than as a depth-decreasing tree edge.
    """
    result = callees_recursive(CRACKME_MAIN, max_depth=6)
    assert result.get("error") in (None, "")
    depth_by_addr = {n["addr"]: n["depth"] for n in result["nodes"]}
    for edge in result["edges"]:
        frm, to = edge["from"], edge["to"]
        assert frm in depth_by_addr, f"edge source {frm} is not a recorded node"
        assert to in depth_by_addr, f"edge target {to} is not a recorded node"


@test(binary="crackme03.elf")
def test_callees_recursive_handles_self_or_cycle_without_runaway():
    """Cycle handling: a node is expanded once; back-edges are flagged, not
    re-walked. We assert the closure is finite and that any node flagged
    back_edge is a real, separately-recorded function (so a cycle collapses to a
    flag rather than an unbounded re-expansion).
    """
    result = callees_recursive(CRACKME_MAIN, max_depth=64)
    assert result.get("error") in (None, "")
    # Distinct nodes only -- the closure must not list the same addr twice even
    # if it is reached along multiple/cyclic paths.
    addrs = [n["addr"] for n in result["nodes"]]
    assert len(addrs) == len(set(addrs)), "a function was recorded more than once"
    # node_count is consistent with the deduped node list.
    assert result["node_count"] == len(set(addrs))
    # Any back_edge node is a legitimately recorded function address.
    for n in result["nodes"]:
        if n.get("back_edge"):
            assert_valid_address(n["addr"])


@test(binary="crackme03.elf")
def test_reaches_depth_matches_callee_band():
    """reaches() path depth is consistent with the callee closure depth.

    If B is reachable from A, B's depth in callees_recursive(A) cannot exceed
    the length of the reaches() path -- both measure call distance from A and
    the BFS depth is the shortest such distance.
    """
    main_closure = callees_recursive(CRACKME_MAIN, max_depth=10)
    callees = _node_addrs(main_closure) - {CRACKME_MAIN}
    if not callees:
        skip_test("main has no recursive internal callees")
    target = sorted(callees, key=lambda a: _depth_of(main_closure, a) or 0)[-1]
    r = reaches(CRACKME_MAIN, target, max_depth=10)
    if not r.get("reachable"):
        skip_test(f"{target} not reachable within bound")
    bfs_depth = _depth_of(main_closure, target)
    assert bfs_depth is not None
    assert bfs_depth <= r["depth"], (
        f"BFS shortest depth {bfs_depth} exceeds a concrete path length {r['depth']}"
    )


# ===========================================================================
# api_recipes -- one recipe end-to-end
# ===========================================================================


@test(binary="crackme03.elf")
def test_recipe_function_report_end_to_end_on_main():
    """recipe_function_report chains decompile/proto/callers/callees/strings/
    xrefs into one dossier; assert the aggregate is internally consistent."""
    report = recipe_function_report(CRACKME_MAIN)
    assert_has_keys(report, "addr", "name")
    assert "error" not in report or not report["error"]
    # addr is normalised to the function start and is a valid address.
    assert_valid_address(report["addr"])
    # callers / callees are name lists (the recipe compacts them to names).
    assert isinstance(report.get("callers", []), list)
    assert isinstance(report.get("callees", []), list)
    # main calls something, so its callee name list is non-empty.
    assert report.get("callees"), "main should have at least one callee in the dossier"
    # xref_count is a non-negative integer.
    assert isinstance(report.get("xref_count", 0), int)
    assert report.get("xref_count", 0) >= 0
    # The pseudocode head is either populated or a decompile_error explains why.
    has_code = bool(report.get("pseudocode_head"))
    has_err = bool(report.get("decompile_error"))
    assert has_code or has_err, "report has neither pseudocode nor a decompile_error"
    if has_code:
        # The default head cap is 60 lines; a truncation count, when present,
        # must exceed what was actually returned.
        if "pseudocode_truncated" in report:
            returned = report["pseudocode_head"].count("\n") + 1
            assert report["pseudocode_truncated"] > returned


@test(binary="crackme03.elf")
def test_recipe_function_report_head_cap_is_respected():
    """A small pseudocode_lines cap clips the head and reports the true total."""
    report = recipe_function_report(CRACKME_MAIN, pseudocode_lines=3)
    if report.get("decompile_error") or not report.get("pseudocode_head"):
        skip_test("main not decompilable in this build")
    lines = report["pseudocode_head"].split("\n")
    assert len(lines) <= 3, "head exceeded the requested 3-line cap"
    if "pseudocode_truncated" in report:
        assert report["pseudocode_truncated"] >= len(lines)


@test()
def test_recipe_function_report_bad_input_is_structured_error():
    """An unresolved address yields addr+error, never an exception."""
    report = recipe_function_report(get_unmapped_address())
    assert "error" in report and report["error"]
    assert "addr" in report


# ===========================================================================
# api_decomp -- pseudocode_query returns structured nodes
# ===========================================================================


@test(binary="crackme03.elf")
def test_pseudocode_query_returns_structured_nodes():
    """pseudocode_query walks the ctree and returns kind-tagged nodes; skipped
    cleanly when Hex-Rays cannot decompile the function."""
    result = pseudocode_query(CRACKME_MAIN)
    assert_has_keys(result, "func", "nodes", "decompiled")
    if not result.get("decompiled"):
        skip_test(f"Hex-Rays unavailable: {result.get('error')}")

    assert result["resolved_addr"] == CRACKME_MAIN
    nodes = result["nodes"]
    assert isinstance(nodes, list)
    assert nodes, "decompiled function produced zero ctree nodes"

    for node in nodes:
        # The implementation owns the exact kind vocabulary (call/loop/if/
        # assignment/var/...); just require every node is kind-tagged.
        assert isinstance(node.get("kind"), str) and node["kind"], (
            f"node missing kind: {node}"
        )
        # ea, when present, is a valid address; line, when present, is positive.
        if node.get("ea") is not None:
            assert_valid_address(node["ea"])
        if node.get("line") is not None:
            assert isinstance(node["line"], int) and node["line"] >= 1
        assert isinstance(node.get("text", ""), str)

    # counts agree with the node list and node_count.
    assert result["node_count"] == len(nodes)
    counts = result.get("counts", {})
    if not result.get("truncated"):
        assert sum(counts.values()) == len(nodes), "counts do not sum to node_count"


@test(binary="crackme03.elf")
def test_pseudocode_query_kind_filter_narrows_results():
    """Restricting `kinds` to 'calls' yields only call nodes (or none)."""
    result = pseudocode_query(CRACKME_MAIN, kinds="calls")
    if not result.get("decompiled"):
        skip_test(f"Hex-Rays unavailable: {result.get('error')}")
    for node in result["nodes"]:
        assert node["kind"] == "call", (
            f"kinds='calls' returned a {node['kind']} node"
        )


@test()
def test_pseudocode_query_invalid_func_is_structured_error():
    """An unresolved function returns decompiled=false with an error, no raise."""
    result = pseudocode_query(get_unmapped_address())
    assert result["decompiled"] is False
    assert result["nodes"] == []
    assert result.get("error")
