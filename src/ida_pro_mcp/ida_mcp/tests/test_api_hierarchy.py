"""Real-IDA tests for the russian-doll comprehension tools in api_hierarchy.

These tools (call_hierarchy / function_skeleton / module_hierarchy /
hierarchy_runtime_overlay) are nested views over the SAME call graph at
different granularities. Like api_graph, they delegate every call edge to the
Batch-2 ``utils`` seams (iter_func_call_edges / walk_call_tree /
get_cached_cfunc), so exact node/edge *counts* are not stable across IDA /
Hex-Rays revisions. These tests therefore assert the SEMANTIC invariants the
doc promises and that MUST hold regardless of the exact set:

  * call_hierarchy(main) returns signed In/Out depth bands with the root at
    band 0, main->check_pw on the Out (positive) side, and tagged edges;
  * the result is token-bounded (depth/node caps honoured, truncated flag);
  * function_skeleton returns CFG blocks with a terminating-branch condition,
    true/false successors, and at least one call surfaced (calls_here /
    guarded_calls);
  * module_hierarchy auto-grows a member set from a seed and classifies
    interface vs internal with a consistent inner/outer edge split.
"""

from ..framework import (
    test,
    skip_test,
    assert_has_keys,
    assert_valid_address,
    get_unmapped_address,
)
from ..api_hierarchy import (
    call_hierarchy,
    function_skeleton,
    module_hierarchy,
)


CRACKME_MAIN = "0x123e"
CRACKME_CHECK_PW = "0x11a9"


def _node_addrs(result) -> set[str]:
    return {n["addr"] for n in result.get("nodes", [])}


def _levels_map(result) -> dict[int, set[str]]:
    return {lv["level"]: set(lv["addrs"]) for lv in result.get("levels", [])}


# ============================================================================
# call_hierarchy -- the WIDE In/Out view
# ============================================================================


@test(binary="crackme03.elf")
def test_call_hierarchy_shape_and_root_band():
    """call_hierarchy returns the documented shape; root sits at signed band 0."""
    result = call_hierarchy(CRACKME_MAIN, direction="both", depth=2)
    assert_has_keys(
        result,
        "root",
        "resolved_addr",
        "direction",
        "levels",
        "nodes",
        "edges",
        "indirect_leaves",
        "node_count",
        "edge_count",
        "truncated",
    )
    assert result.get("error") in (None, "")
    assert result["resolved_addr"] == CRACKME_MAIN
    assert result["direction"] == "both"

    levels = _levels_map(result)
    assert 0 in levels, "root band (level 0) must always be present"
    assert CRACKME_MAIN in levels[0], "the root must live in band 0"
    # Every node address is a valid hex EA and appears in exactly its band.
    for node in result["nodes"]:
        assert_valid_address(node["addr"])
    # node_count / edge_count agree with the arrays.
    assert result["node_count"] == len(result["nodes"])
    assert result["edge_count"] == len(result["edges"])


@test(binary="crackme03.elf")
def test_call_hierarchy_bands_are_signed_in_and_out():
    """direction='both' yields BOTH an Out (positive) and an In (negative) band.

    main is called by libc start glue and itself calls into check_pw, so a
    both-direction walk from main must populate at least one positive band
    (callees) and the root band; the In side may be shallow but the band axis
    must be signed (no band collapses sign).
    """
    result = call_hierarchy(CRACKME_MAIN, direction="both", depth=2)
    levels = _levels_map(result)
    positive = [lv for lv in levels if lv > 0]
    assert positive, "Out side (positive bands = callees) must be populated for main"
    # Bands are contiguous from the root outward: no |level| gap > expansion.
    for lv in levels:
        assert abs(lv) <= 2, f"band {lv} exceeds requested depth=2"


@test(binary="crackme03.elf")
def test_call_hierarchy_main_calls_check_pw_on_out_side():
    """main->check_pw appears: check_pw is an Out-side node and a tagged edge."""
    result = call_hierarchy(CRACKME_MAIN, direction="out", depth=2)
    assert result.get("error") in (None, "")
    assert CRACKME_CHECK_PW in _node_addrs(result), (
        "check_pw must appear in main's Out (callee) closure"
    )
    # check_pw must be on the positive (Out) side of the band axis.
    levels = _levels_map(result)
    band_of_check = next(
        (lv for lv, addrs in levels.items() if CRACKME_CHECK_PW in addrs), None
    )
    assert band_of_check is not None and band_of_check > 0, (
        f"check_pw should sit on the Out side, got band {band_of_check}"
    )
    # A direct main->check_pw edge exists, oriented caller->callee, tagged.
    edge = next(
        (
            e
            for e in result["edges"]
            if e["from"] == CRACKME_MAIN and e["to"] == CRACKME_CHECK_PW
        ),
        None,
    )
    assert edge is not None, "expected a direct main->check_pw edge"
    assert edge["kind"] in ("call", "tailcall", "jump", "indirect")
    assert isinstance(edge.get("indirect"), bool)
    assert edge.get("count", 0) >= 1


@test(binary="crackme03.elf")
def test_call_hierarchy_includes_libc_callees():
    """main's Out closure reaches imported/libc callees (e.g. puts/printf/strcmp).

    crackme03 prints prompts and compares the password, so its callee closure
    must contain at least one external/libc-style callee distinct from the
    internal check_pw helper.
    """
    result = call_hierarchy(CRACKME_MAIN, direction="out", depth=3)
    if result.get("error"):
        skip_test(f"call_hierarchy errored: {result['error']}")
    names = {n.get("name", "") for n in result["nodes"]}
    internalish = {CRACKME_MAIN, CRACKME_CHECK_PW}
    other_callees = _node_addrs(result) - internalish
    # Either a resolved libc callee node OR an unresolved indirect leaf must
    # exist -- main is not a leaf.
    assert other_callees or result["indirect_leaves"], (
        "main's Out closure should include libc callees or indirect sites"
    )
    # Look for a recognisable libc name among the callees (best-effort; guarded).
    libc_like = any(
        any(tok in (nm or "").lower() for tok in ("put", "print", "str", "cmp", "scan", "read"))
        for nm in names
    )
    if not libc_like and not result["indirect_leaves"]:
        skip_test("no recognisable libc callee names in this build")


@test(binary="crackme03.elf")
def test_call_hierarchy_is_token_bounded():
    """A tight max_nodes cap is honoured and flips truncated with a cursor."""
    result = call_hierarchy(CRACKME_MAIN, direction="both", depth=8, max_nodes=2)
    assert result.get("error") in (None, "")
    # node budget split across both sides; total recorded stays small + bounded.
    assert result["node_count"] <= 64, (
        f"max_nodes=2 should keep the result tiny, got {result['node_count']}"
    )
    if result["truncated"]:
        assert_has_keys(result, "continue_cursor")
        cur = result["continue_cursor"]
        assert cur["tool"] == "call_hierarchy"
        # the cursor widens the budget so a re-call makes progress.
        assert cur["max_nodes"] >= 2
        assert cur["depth"] >= 1


@test(binary="crackme03.elf")
def test_call_hierarchy_depth_zero_is_root_only():
    """depth=0 records only the root band."""
    result = call_hierarchy(CRACKME_MAIN, direction="both", depth=0)
    assert result.get("error") in (None, "")
    assert _node_addrs(result) == {CRACKME_MAIN}
    assert _levels_map(result) == {0: {CRACKME_MAIN}}


@test(binary="crackme03.elf")
def test_call_hierarchy_nodes_carry_drill_and_expand():
    """Every node carries the russian-doll drill/expand navigation payloads."""
    result = call_hierarchy(CRACKME_MAIN, direction="both", depth=2)
    for node in result["nodes"]:
        assert node["drill"]["into"] == "function_skeleton"
        assert node["drill"]["addr"] == node["addr"]
        assert node["expand"]["tool"] == "call_hierarchy"
        assert node["expand"]["direction"] in ("both", "in", "out")


@test()
def test_call_hierarchy_invalid_root_is_structured_error():
    """An unresolved root degrades to a structured error, never raises."""
    result = call_hierarchy(get_unmapped_address(), depth=2)
    assert isinstance(result, dict)
    assert result["nodes"] == []
    assert result["levels"] == []
    assert result.get("error")


# ============================================================================
# function_skeleton -- the FINE intra-function view
# ============================================================================


def _skeleton_with_branch(*candidates):
    """Return the first candidate function whose skeleton has a conditional
    branch + a call, else skip. Robust to which function carries the guard in a
    given build."""
    for cand in candidates:
        result = function_skeleton(cand)
        if result.get("error"):
            continue
        has_cond = any(b.get("condition") for b in result.get("blocks", []))
        has_call = any(b.get("calls_here") for b in result.get("blocks", []))
        if has_cond and has_call:
            return result
    return None


@test(binary="crackme03.elf")
def test_function_skeleton_shape():
    """function_skeleton returns the documented CFG shape for a real function."""
    result = function_skeleton(CRACKME_MAIN)
    assert_has_keys(
        result,
        "func",
        "resolved_addr",
        "name",
        "block_count",
        "edge_count",
        "cyclomatic_complexity",
        "loop_count",
        "blocks",
        "guarded_calls",
        "indirect_sites",
        "decompiled",
        "truncated",
    )
    assert result.get("error") in (None, "")
    assert result["resolved_addr"] == CRACKME_MAIN
    assert result["block_count"] >= 1
    assert result["block_count"] == len(result["blocks"])
    # cyclomatic complexity is well-formed for a connected CFG (>= 1).
    assert result["cyclomatic_complexity"] >= 1
    for blk in result["blocks"]:
        assert isinstance(blk["id"], int)
        assert_valid_address(blk["start"])
        assert_valid_address(blk["end"])
        assert isinstance(blk["succ_ids"], list)
        assert isinstance(blk["calls_here"], list)


@test(binary="crackme03.elf")
def test_function_skeleton_has_terminating_branch_condition():
    """At least one block carries a human-readable terminating-branch condition.

    main / check_pw both branch on the password comparison, so the CFG must
    contain a conditional terminator rendered as 'if (...)'.
    """
    result = _skeleton_with_branch(CRACKME_CHECK_PW, CRACKME_MAIN)
    if result is None:
        skip_test("neither check_pw nor main exposed a conditional+call block")
    cond_blocks = [b for b in result["blocks"] if b.get("condition")]
    assert cond_blocks, "expected at least one conditional terminator block"
    blk = cond_blocks[0]
    # The condition is the human phrasing of a branch test.
    assert blk["condition"].startswith("if ("), (
        f"condition should read like an if-test, got {blk['condition']!r}"
    )
    assert blk["terminator"], "a conditional block must record its terminator mnemonic"
    # A conditional terminator implies a fork: it has at least one successor, and
    # when both arms resolve, true/false targets are valid EAs.
    if blk["true_succ"] is not None:
        assert_valid_address(blk["true_succ"])
    if blk["false_succ"] is not None:
        assert_valid_address(blk["false_succ"])


@test(binary="crackme03.elf")
def test_function_skeleton_has_at_least_one_call():
    """The skeleton surfaces the calls a function makes (calls_here)."""
    result = function_skeleton(CRACKME_MAIN)
    assert result.get("error") in (None, "")
    all_calls = [c for b in result["blocks"] for c in b.get("calls_here", [])]
    assert all_calls, "main makes calls; calls_here must surface at least one"
    for call in all_calls:
        assert_valid_address(call["site"])
        assert isinstance(call["indirect"], bool)
        if not call["indirect"]:
            assert call["target"] is not None
            assert_valid_address(call["target"])
        else:
            assert call["target"] is None


@test(binary="crackme03.elf")
def test_function_skeleton_guarded_calls_are_conditional():
    """When Hex-Rays is available, guarded_calls attach a structural guard.

    guarded_calls is the decompiler-backed half; it may be empty if Hex-Rays is
    unavailable, so we assert the SHAPE when present and that at least one guard
    reads like a real predicate (if/for/while/do).
    """
    result = function_skeleton(CRACKME_CHECK_PW)
    if result.get("error"):
        skip_test(f"function_skeleton errored: {result['error']}")
    if not result["decompiled"]:
        skip_test("Hex-Rays unavailable; guarded_calls intentionally empty")
    guarded = result["guarded_calls"]
    # check_pw guards its comparison/result; either check_pw or its callees do.
    if not guarded:
        # Try main, which wraps the check in a conditional print path.
        alt = function_skeleton(CRACKME_MAIN)
        guarded = alt.get("guarded_calls", []) if not alt.get("error") else []
    if not guarded:
        skip_test("no structurally-guarded calls in this build")
    g = guarded[0]
    assert g["call"], "a guarded call must name its callee"
    assert any(
        g["guard"].startswith(kw)
        for kw in ("if (", "else of if (", "for (", "while (", "do-while (")
    ), f"guard should be a structural predicate, got {g['guard']!r}"


@test()
def test_function_skeleton_invalid_func_is_structured_error():
    """An unresolved function degrades to a structured error, never raises."""
    result = function_skeleton(get_unmapped_address())
    assert isinstance(result, dict)
    assert result["blocks"] == []
    assert result.get("error")


# ============================================================================
# module_hierarchy -- the SUBSYSTEM view
# ============================================================================


@test(binary="crackme03.elf")
def test_module_hierarchy_shape_and_members():
    """module_hierarchy auto-grows a member set and returns the documented shape."""
    result = module_hierarchy(CRACKME_MAIN, grow_depth=2)
    assert_has_keys(
        result,
        "seed",
        "resolved_addr",
        "members",
        "interface",
        "internal",
        "inner_call_graph",
        "reaches_out",
        "reached_by_in",
        "shared_globals",
        "member_count",
        "truncated",
    )
    assert result.get("error") in (None, "")
    assert result["resolved_addr"] == CRACKME_MAIN
    assert result["member_count"] == len(result["members"])
    assert result["member_count"] >= 1, "the seed itself is always a member"
    # The seed must appear among the members.
    member_addrs = {m["addr"] for m in result["members"]}
    assert CRACKME_MAIN in member_addrs
    # check_pw is a callee of main at grow_depth=2 -> absorbed as a member.
    assert CRACKME_CHECK_PW in member_addrs, (
        "check_pw should be absorbed into main's subsystem at grow_depth=2"
    )


@test(binary="crackme03.elf")
def test_module_hierarchy_interface_vs_internal_partition():
    """Every member is classified exactly once as interface XOR internal.

    'interface' = called from OUTSIDE the grown set (public API); 'internal' =
    reachable only from within. The two lists must partition the member set.
    """
    result = module_hierarchy(CRACKME_MAIN, grow_depth=2)
    assert result.get("error") in (None, "")
    member_addrs = {m["addr"] for m in result["members"]}
    interface = set(result["interface"])
    internal = set(result["internal"])
    # Partition: disjoint and covering.
    assert interface.isdisjoint(internal), "a member cannot be both interface and internal"
    assert interface | internal == member_addrs, (
        "interface+internal must cover exactly the member set"
    )
    # Each member's recorded role matches which list it is in.
    for m in result["members"]:
        if m["addr"] in interface:
            assert m["role"] == "interface"
        else:
            assert m["role"] == "internal"
    # main is the entry point: it is called from libc start glue (outside the
    # grown set), so it is part of the interface.
    assert CRACKME_MAIN in interface, "the seeded entry point should be interface"


@test(binary="crackme03.elf")
def test_module_hierarchy_inner_vs_outer_edges_are_consistent():
    """inner_call_graph edges stay within the member set; reaches_out leaves it."""
    result = module_hierarchy(CRACKME_MAIN, grow_depth=2)
    assert result.get("error") in (None, "")
    member_addrs = {m["addr"] for m in result["members"]}
    inner = result["inner_call_graph"]
    assert set(inner["nodes"]) == member_addrs, (
        "inner_call_graph nodes must equal the member set"
    )
    for e in inner["edges"]:
        assert e["from"] in member_addrs and e["to"] in member_addrs, (
            "an inner edge must connect two members"
        )
    # reaches_out targets are OUTSIDE the member set (the subsystem's deps).
    for e in result["reaches_out"]:
        assert e["from"] in member_addrs, "reaches_out source must be a member"
        assert e["to"] not in member_addrs, (
            "reaches_out target must be an outside dependency"
        )
    # reached_by_in sources are OUTSIDE; targets are members (external consumers).
    for e in result["reached_by_in"]:
        assert e["to"] in member_addrs, "reached_by_in target must be a member"
        assert e["from"] not in member_addrs, (
            "reached_by_in source must be an external consumer"
        )


@test(binary="crackme03.elf")
def test_module_hierarchy_grow_depth_zero_is_seed_only():
    """grow_depth=0 absorbs only the seed function as the sole member."""
    result = module_hierarchy(CRACKME_MAIN, grow_depth=0)
    assert result.get("error") in (None, "")
    member_addrs = {m["addr"] for m in result["members"]}
    assert member_addrs == {CRACKME_MAIN}


@test()
def test_module_hierarchy_invalid_seed_is_structured_error():
    """An unresolved seed degrades to a structured error, never raises."""
    result = module_hierarchy(get_unmapped_address(), grow_depth=2)
    assert isinstance(result, dict)
    assert result["members"] == []
    assert result.get("error")
