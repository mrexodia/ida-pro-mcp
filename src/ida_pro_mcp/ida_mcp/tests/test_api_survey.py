"""Tests for api_survey API functions."""

from ..framework import (
    test,
    skip_test,
    assert_has_keys,
    assert_is_list,
    assert_non_empty,
    assert_valid_address,
    optional,
    get_any_function,
)
from ..api_survey import survey_binary


# ============================================================================
# survey_binary
# ============================================================================


@test()
def test_survey_binary_standard():
    """survey_binary returns full triage report in standard mode."""
    result = survey_binary()
    assert_has_keys(result, "metadata", "statistics", "segments", "entrypoints")
    assert_has_keys(result, "interesting_strings", "interesting_functions",
                    "imports_by_category", "call_graph_summary")


@test()
def test_survey_binary_minimal():
    """survey_binary minimal mode omits heavy analysis."""
    result = survey_binary(detail_level="minimal")
    assert_has_keys(result, "metadata", "statistics", "segments", "entrypoints")
    # Minimal mode should NOT include these
    assert "interesting_strings" not in result
    assert "interesting_functions" not in result
    assert "imports_by_category" not in result
    assert "call_graph_summary" not in result


@test()
def test_survey_binary_metadata_shape():
    """survey_binary metadata has required fields."""
    result = survey_binary()
    meta = result["metadata"]
    assert_has_keys(meta, "module", "arch", "base_address")
    assert_non_empty(meta["module"])
    assert_non_empty(meta["arch"])


@test()
def test_survey_binary_statistics_shape():
    """survey_binary statistics contains function/string counts."""
    result = survey_binary()
    stats = result["statistics"]
    assert_has_keys(stats, "total_functions", "total_strings", "total_segments")
    assert isinstance(stats["total_functions"], int)
    assert stats["total_functions"] > 0
    assert isinstance(stats["total_strings"], int)


@test()
def test_survey_binary_segments():
    """survey_binary returns non-empty segment list."""
    result = survey_binary()
    assert_is_list(result["segments"], min_length=1)
    seg = result["segments"][0]
    assert_has_keys(seg, "name", "start", "end", "size", "perm")


@test()
def test_survey_binary_entrypoints():
    """survey_binary returns entry points."""
    result = survey_binary()
    assert isinstance(result["entrypoints"], list)
    if result["entrypoints"]:
        ep = result["entrypoints"][0]
        assert_has_keys(ep, "addr", "name")


@test()
def test_survey_binary_interesting_strings():
    """survey_binary interesting_strings are ranked by xref count."""
    result = survey_binary()
    strings = result["interesting_strings"]
    assert isinstance(strings, list)
    assert len(strings) <= 15
    if len(strings) >= 2:
        # Should be sorted descending by xref_count
        assert strings[0]["xref_count"] >= strings[1]["xref_count"]
    if strings:
        assert_has_keys(strings[0], "addr", "string", "xref_count")


@test()
def test_survey_binary_interesting_functions():
    """survey_binary interesting_functions include classification."""
    result = survey_binary()
    funcs = result["interesting_functions"]
    assert isinstance(funcs, list)
    assert len(funcs) <= 15
    if funcs:
        f = funcs[0]
        assert_has_keys(f, "addr", "name", "size", "xref_count", "callee_count", "type")
        assert f["type"] in ("thunk", "wrapper", "leaf", "dispatcher", "complex")


@test()
def test_survey_binary_imports_by_category():
    """survey_binary categorizes imports."""
    result = survey_binary()
    cats = result["imports_by_category"]
    assert isinstance(cats, dict)
    expected_cats = {"crypto", "network", "file_io", "process", "registry", "other"}
    assert expected_cats == set(cats.keys())
    for cat, entries in cats.items():
        assert isinstance(entries, list)
        for entry in entries:
            assert_has_keys(entry, "addr", "name", "module")


@test()
def test_survey_binary_call_graph_summary():
    """survey_binary returns call graph statistics."""
    result = survey_binary()
    cg = result["call_graph_summary"]
    assert_has_keys(cg, "total_edges", "root_functions", "leaf_functions_count")
    assert isinstance(cg["total_edges"], int)
    assert isinstance(cg["root_functions"], list)
    assert isinstance(cg["leaf_functions_count"], int)
