"""Unit tests for api_graph's pure traversal logic.

api_graph exposes four IDA-backed graph-navigation tools, but the load-bearing
traversal/dedup/depth-bounding lives in idaapi-free pure helpers so it can be
exercised headless without a live database:

  * _dedup_chain      -- order-preserving de-duplication of neighbour lists,
  * _bfs_bounded      -- depth- and node-bounded breadth-first closure,
  * _reconstruct_path -- bounded shortest-path call-chain search.

The helpers take a `neighbors(node) -> list[int]` callback as their only seam
to the graph, so tests drive them against plain in-memory adjacency dicts. The
package imports cleanly under the conftest idaapi stub, which also lets us cover
the tools' bad-input degradation paths.
"""

from ida_pro_mcp.ida_mcp import api_graph


def _adj(graph):
    """Turn an adjacency dict into a neighbors(node) callback."""
    return lambda node: list(graph.get(node, []))


# --------------------------------------------------------------------------
# _dedup_chain
# --------------------------------------------------------------------------


def test_dedup_chain_preserves_first_seen_order():
    assert api_graph._dedup_chain([3, 1, 3, 2, 1, 4]) == [3, 1, 2, 4]


def test_dedup_chain_empty():
    assert api_graph._dedup_chain([]) == []


def test_dedup_chain_all_unique():
    assert api_graph._dedup_chain([1, 2, 3]) == [1, 2, 3]


# --------------------------------------------------------------------------
# _bfs_bounded
# --------------------------------------------------------------------------


def test_bfs_records_start_at_depth_zero():
    depths, edges, truncated = api_graph._bfs_bounded(1, _adj({}), 3, 100)
    assert depths == {1: 0}
    assert edges == []
    assert truncated is False


def test_bfs_simple_chain_depths():
    graph = {1: [2], 2: [3], 3: [4]}
    depths, edges, truncated = api_graph._bfs_bounded(1, _adj(graph), 3, 100)
    assert depths == {1: 0, 2: 1, 3: 2, 4: 3}
    assert ("1", "2") not in edges  # edges are int tuples, sanity below
    assert (1, 2) in edges and (2, 3) in edges and (3, 4) in edges
    assert truncated is False


def test_bfs_depth_zero_is_root_only_but_truncated_when_more_exists():
    graph = {1: [2]}
    depths, edges, truncated = api_graph._bfs_bounded(1, _adj(graph), 0, 100)
    assert depths == {1: 0}
    assert truncated is True


def test_bfs_depth_bound_truncates():
    graph = {1: [2], 2: [3], 3: [4]}
    depths, _edges, truncated = api_graph._bfs_bounded(1, _adj(graph), 1, 100)
    assert depths == {1: 0, 2: 1}
    assert truncated is True


def test_bfs_depth_bound_exact_not_truncated():
    graph = {1: [2], 2: [3]}
    depths, _edges, truncated = api_graph._bfs_bounded(1, _adj(graph), 2, 100)
    assert depths == {1: 0, 2: 1, 3: 2}
    assert truncated is False


def test_bfs_node_cap_truncates():
    graph = {1: [2, 3, 4, 5]}
    depths, _edges, truncated = api_graph._bfs_bounded(1, _adj(graph), 5, 3)
    assert len(depths) == 3  # start + 2 before the cap stops the expansion
    assert truncated is True


def test_bfs_cycle_does_not_loop_forever():
    graph = {1: [2], 2: [3], 3: [1]}
    depths, edges, truncated = api_graph._bfs_bounded(1, _adj(graph), 10, 100)
    assert depths == {1: 0, 2: 1, 3: 2}
    # The back-edge 3->1 is recorded but never re-expands node 1.
    assert (3, 1) in edges
    assert truncated is False


def test_bfs_diamond_records_shortest_depth():
    # 1 -> 2 -> 4 and 1 -> 3 -> 4: node 4 first reached at depth 2 via either.
    graph = {1: [2, 3], 2: [4], 3: [4]}
    depths, edges, truncated = api_graph._bfs_bounded(1, _adj(graph), 5, 100)
    assert depths[4] == 2
    assert (2, 4) in edges and (3, 4) in edges
    assert truncated is False


def test_bfs_dedups_repeated_edges():
    graph = {1: [2, 2, 2]}
    depths, edges, _truncated = api_graph._bfs_bounded(1, _adj(graph), 3, 100)
    assert depths == {1: 0, 2: 1}
    assert edges.count((1, 2)) == 1


def test_bfs_negative_depth_clamped_to_zero():
    graph = {1: [2]}
    depths, _edges, truncated = api_graph._bfs_bounded(1, _adj(graph), -5, 100)
    assert depths == {1: 0}
    assert truncated is True


# --------------------------------------------------------------------------
# _reconstruct_path
# --------------------------------------------------------------------------


def test_path_start_equals_goal():
    path, explored, truncated = api_graph._reconstruct_path(7, 7, _adj({}), 6)
    assert path == [7]
    assert explored == 1
    assert truncated is False


def test_path_simple_chain():
    graph = {1: [2], 2: [3], 3: [4]}
    path, _explored, truncated = api_graph._reconstruct_path(1, 4, _adj(graph), 6)
    assert path == [1, 2, 3, 4]
    assert truncated is False


def test_path_shortest_through_diamond():
    graph = {1: [2, 3], 2: [4], 3: [4]}
    path, _explored, _truncated = api_graph._reconstruct_path(1, 4, _adj(graph), 6)
    assert path[0] == 1 and path[-1] == 4
    assert len(path) == 3  # one intermediate hop, not two


def test_path_unreachable_returns_empty():
    graph = {1: [2], 2: [3]}
    path, _explored, truncated = api_graph._reconstruct_path(1, 99, _adj(graph), 6)
    assert path == []
    assert truncated is False


def test_path_beyond_depth_bound_truncated():
    graph = {1: [2], 2: [3], 3: [4]}
    path, _explored, truncated = api_graph._reconstruct_path(1, 4, _adj(graph), 2)
    assert path == []
    assert truncated is True


def test_path_within_depth_bound_exact():
    graph = {1: [2], 2: [3]}
    path, _explored, truncated = api_graph._reconstruct_path(1, 3, _adj(graph), 2)
    assert path == [1, 2, 3]
    assert truncated is False


def test_path_handles_cycle():
    graph = {1: [2], 2: [3, 1], 3: [4]}
    path, _explored, _truncated = api_graph._reconstruct_path(1, 4, _adj(graph), 6)
    assert path == [1, 2, 3, 4]


def test_path_explored_counts_distinct_nodes():
    graph = {1: [2, 3], 2: [], 3: []}
    path, explored, _truncated = api_graph._reconstruct_path(1, 99, _adj(graph), 6)
    assert path == []
    assert explored == 3  # start + 2 neighbours


# --------------------------------------------------------------------------
# tool degradation on bad input (under the conftest idaapi stub)
#
# parse_address("not_an_address") on the stub raises, and the stub's
# idaapi.get_name_ea returns a MagicMock that is not BADADDR; the tools must
# still return a structured dict and never raise.
# --------------------------------------------------------------------------


def test_callers_recursive_returns_dict_on_garbage_input():
    result = api_graph.callers_recursive("")
    assert isinstance(result, dict)
    assert result["direction"] == "callers"
    assert result["error"]


def test_callees_recursive_returns_dict_on_garbage_input():
    result = api_graph.callees_recursive("")
    assert isinstance(result, dict)
    assert result["direction"] == "callees"
    assert result["error"]


def test_data_refs_returns_dict_on_empty_input():
    result = api_graph.data_refs("")
    assert isinstance(result, dict)
    assert "refs" in result
    assert result["refs"] == []


def test_reaches_returns_dict_on_garbage_source():
    result = api_graph.reaches("", "")
    assert isinstance(result, dict)
    assert result["reachable"] is False
    assert result["error"]


# --------------------------------------------------------------------------
# module surface
# --------------------------------------------------------------------------


def test_module_exports_all_tools():
    expected = {"callers_recursive", "callees_recursive", "data_refs", "reaches"}
    assert expected.issubset(set(api_graph.__all__))
    for name in expected:
        assert hasattr(api_graph, name)


def test_module_exports_pure_helpers():
    for name in ("_bfs_bounded", "_dedup_chain", "_reconstruct_path"):
        assert name in api_graph.__all__
        assert hasattr(api_graph, name)
