"""Real-IDA tests for the recursive call-graph tools in api_graph.

Batch-2 rebuilt the call-edge layer on a single source of truth
(``utils.iter_func_call_edges``) so that the callee and caller directions are
exact transposes and both are chunk-/tail-call-/switch-aware. Hard-coded
callee/caller *counts* are therefore no longer stable across IDA/Hex-Rays
revisions, so these tests assert the structural invariants that MUST hold
regardless of the exact set:

  * callers_recursive / callees_recursive return the documented shape,
  * the two directions are consistent transposes (X in callees(root) <=> root
    reachable in callers(X)),
  * reaches() agrees with the callee closure,
  * back-edge / depth bounding behave as documented.
"""

from ..framework import (
    test,
    skip_test,
    assert_has_keys,
    assert_valid_address,
)
from ..api_graph import (
    callees_recursive,
    callers_recursive,
    reaches,
)
from ..api_analysis import callees as callees_tool


CRACKME_MAIN = "0x123e"
CRACKME_CHECK_PW = "0x11a9"


def _node_addrs(result) -> set[str]:
    return {n["addr"] for n in result.get("nodes", [])}


@test(binary="crackme03.elf")
def test_callees_recursive_shape_and_root():
    """callees_recursive returns the documented shape with the root at depth 0."""
    result = callees_recursive(CRACKME_MAIN, max_depth=3)
    assert_has_keys(
        result,
        "root",
        "resolved_addr",
        "direction",
        "nodes",
        "edges",
        "node_count",
        "edge_count",
    )
    assert result["direction"] == "callees"
    assert result["error"] in (None, "")
    assert result["resolved_addr"] == CRACKME_MAIN
    root = next((n for n in result["nodes"] if n["addr"] == CRACKME_MAIN), None)
    assert root is not None, "root must appear among nodes"
    assert root["depth"] == 0
    for node in result["nodes"]:
        assert_valid_address(node["addr"])
        assert node["depth"] >= 0


@test(binary="crackme03.elf")
def test_callees_recursive_reaches_check_pw():
    """The downward closure of main includes its direct callee check_pw."""
    result = callees_recursive(CRACKME_MAIN, max_depth=3)
    assert CRACKME_CHECK_PW in _node_addrs(result)


@test(binary="crackme03.elf")
def test_direct_callees_subset_of_recursive_closure():
    """Every direct callee of main is in the recursive callee closure.

    callees() is the single-level view; callees_recursive() is its transitive
    closure, so the former must be a subset of the latter regardless of how the
    exact set shifted with chunk/tail-call awareness.
    """
    direct = callees_tool(CRACKME_MAIN)
    entry = direct[0]
    if not entry.get("callees"):
        skip_test("main has no resolved direct callees")
    direct_internal = {
        c["addr"] for c in entry["callees"] if c.get("type") == "internal"
    }
    if not direct_internal:
        skip_test("main has no internal direct callees to compare")

    closure = _node_addrs(callees_recursive(CRACKME_MAIN, max_depth=5))
    missing = direct_internal - closure
    assert not missing, f"internal direct callees missing from closure: {missing}"


@test(binary="crackme03.elf")
def test_callers_callees_are_transposes():
    """callees(root) and callers(target) agree: a callee's closure can reach back.

    For every internal function Y reachable from main's callee closure, main must
    appear in Y's recursive *caller* closure. This is the transpose invariant the
    Batch-2 unification guarantees (callees == transpose(callers)).
    """
    closure = callees_recursive(CRACKME_MAIN, max_depth=4)
    if closure.get("truncated"):
        skip_test("callee closure truncated; transpose check would be partial")
    callee_addrs = _node_addrs(closure) - {CRACKME_MAIN}
    if not callee_addrs:
        skip_test("main has no recursive internal callees")

    checked = 0
    for addr in list(callee_addrs)[:8]:  # cap work; sample is representative
        up = callers_recursive(addr, max_depth=6)
        if up.get("error"):
            continue
        if up.get("truncated"):
            continue
        up_addrs = _node_addrs(up)
        # main must be among the things that (transitively) reach this callee.
        assert CRACKME_MAIN in up_addrs, (
            f"transpose broken: {addr} is in callees(main) but main is not in "
            f"callers({addr})"
        )
        checked += 1
    if checked == 0:
        skip_test("no untruncated caller closures available to verify transpose")


@test(binary="crackme03.elf")
def test_reaches_agrees_with_callee_closure():
    """reaches(main, check_pw) is True and yields a path main..check_pw."""
    result = reaches(CRACKME_MAIN, CRACKME_CHECK_PW, max_depth=6)
    assert result.get("error") in (None, "")
    assert result["reachable"] is True
    path = result["path"]
    assert path[0]["addr"] == CRACKME_MAIN
    assert path[-1]["addr"] == CRACKME_CHECK_PW
    # depth is the path length (edges), == len(path)-1.
    assert result["depth"] == len(path) - 1
    # Path nodes are call-ordered with monotonically increasing depth.
    for i, node in enumerate(path):
        assert node["depth"] == i


@test(binary="crackme03.elf")
def test_reaches_consistent_with_recursive_closure():
    """If reaches(a,b) is True then b is in callees_recursive(a)'s closure."""
    result = reaches(CRACKME_MAIN, CRACKME_CHECK_PW, max_depth=6)
    if not result["reachable"]:
        skip_test("check_pw not reachable from main in this build")
    closure = callees_recursive(CRACKME_MAIN, max_depth=6)
    assert CRACKME_CHECK_PW in _node_addrs(closure)


@test(binary="crackme03.elf")
def test_reaches_unreachable_within_bound():
    """A backwards query (check_pw -> main) is not reachable; reported cleanly."""
    result = reaches(CRACKME_CHECK_PW, CRACKME_MAIN, max_depth=6)
    assert result.get("error") in (None, "")
    # check_pw is a leaf-ish helper; it should not call back up into main.
    assert result["reachable"] is False
    assert result["path"] == []


@test(binary="crackme03.elf")
def test_callees_recursive_depth_zero_is_root_only():
    """max_depth=0 records only the root function."""
    result = callees_recursive(CRACKME_MAIN, max_depth=0)
    assert result.get("error") in (None, "")
    assert _node_addrs(result) == {CRACKME_MAIN}


@test(binary="crackme03.elf")
def test_callers_recursive_of_check_pw_includes_main():
    """main reaches check_pw, so main is in check_pw's recursive caller closure."""
    result = callers_recursive(CRACKME_CHECK_PW, max_depth=4)
    assert result.get("error") in (None, "")
    assert result["direction"] == "callers"
    assert CRACKME_MAIN in _node_addrs(result)


@test()
def test_callees_recursive_invalid_root_is_structured_error():
    """An unresolved root degrades to a structured error result, never raises."""
    from ..framework import get_unmapped_address

    result = callees_recursive(get_unmapped_address(), max_depth=2)
    assert isinstance(result, dict)
    assert result["direction"] == "callees"
    assert result["nodes"] == []
    assert result.get("error")
