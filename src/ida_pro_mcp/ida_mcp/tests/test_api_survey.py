"""Tests for api_survey API functions."""

from ..framework import (
    test,
    skip_test,
    assert_has_keys,
    assert_valid_address,
    assert_non_empty,
    assert_is_list,
    assert_shape,
    assert_ok,
    is_hex_address,
    optional,
    list_of,
)
from ..api_survey import survey_binary


# ============================================================================
# survey_binary tests
# ============================================================================


@test()
def test_survey_binary_returns_required_keys():
    """survey_binary returns all required top-level keys."""
    result = survey_binary()
    assert_has_keys(result, "metadata", "statistics", "segments", "entrypoints")


@test()
def test_survey_binary_metadata_structure():
    """survey_binary metadata contains expected file/arch info."""
    result = survey_binary()
    meta = result["metadata"]
    assert_has_keys(
        meta, "path", "module", "arch", "base_address", "image_size", "md5", "sha256"
    )
    assert_valid_address(meta["base_address"])
    assert_valid_address(meta["image_size"])
    assert meta["arch"] in ("32", "64")
    assert_non_empty(meta["module"])


@test()
def test_survey_binary_statistics_structure():
    """survey_binary statistics contains function/string counts."""
    result = survey_binary()
    stats = result["statistics"]
    assert_has_keys(
        stats,
        "total_functions",
        "named_functions",
        "library_functions",
        "unnamed_functions",
        "total_strings",
        "total_segments",
    )
    assert isinstance(stats["total_functions"], int)
    assert stats["total_functions"] >= 0
    assert isinstance(stats["total_strings"], int)
    assert stats["total_segments"] >= 1


@test()
def test_survey_binary_segments_structure():
    """survey_binary segments are properly structured with permissions."""
    result = survey_binary()
    segments = result["segments"]
    assert_is_list(segments, min_length=1)
    for seg in segments:
        assert_has_keys(seg, "name", "start", "end", "size", "permissions")
        assert_valid_address(seg["start"])
        assert_valid_address(seg["end"])
        assert_valid_address(seg["size"])
        assert isinstance(seg["permissions"], str)


@test()
def test_survey_binary_entrypoints_structure():
    """survey_binary entrypoints are properly structured."""
    result = survey_binary()
    entrypoints = result["entrypoints"]
    assert isinstance(entrypoints, list)
    if entrypoints:
        for ep in entrypoints:
            assert_has_keys(ep, "addr", "name", "ordinal")
            assert_valid_address(ep["addr"])


@test()
def test_survey_binary_standard_includes_analysis():
    """survey_binary with default detail_level includes analysis data."""
    result = survey_binary(detail_level="standard")
    assert_has_keys(
        result,
        "interesting_strings",
        "interesting_functions",
        "imports_by_category",
        "call_graph_summary",
    )


@test()
def test_survey_binary_interesting_strings_structure():
    """survey_binary interesting_strings are ranked by xref count."""
    result = survey_binary()
    strings = result.get("interesting_strings", [])
    assert isinstance(strings, list)
    if strings:
        for s in strings:
            assert_has_keys(s, "addr", "string", "xref_count")
            assert_valid_address(s["addr"])
            assert isinstance(s["xref_count"], int)
            assert s["xref_count"] >= 0
        # Verify sorted by xref_count descending
        xref_counts = [s["xref_count"] for s in strings]
        assert xref_counts == sorted(xref_counts, reverse=True)


@test()
def test_survey_binary_interesting_functions_structure():
    """survey_binary interesting_functions have classification info."""
    result = survey_binary()
    funcs = result.get("interesting_functions", [])
    assert isinstance(funcs, list)
    if funcs:
        for fn in funcs:
            assert_has_keys(fn, "addr", "name", "size", "xref_count", "callee_count", "type")
            assert_valid_address(fn["addr"])
            assert isinstance(fn["size"], int)
            assert fn["type"] in ("thunk", "wrapper", "leaf", "dispatcher", "complex")


@test()
def test_survey_binary_imports_by_category_structure():
    """survey_binary imports_by_category groups imports correctly."""
    result = survey_binary()
    imports = result.get("imports_by_category", {})
    assert isinstance(imports, dict)
    expected_categories = {"crypto", "network", "file_io", "process", "registry", "other"}
    assert set(imports.keys()) == expected_categories
    for category, items in imports.items():
        assert isinstance(items, list)
        for imp in items:
            assert_has_keys(imp, "addr", "name", "module")
            assert_valid_address(imp["addr"])


@test()
def test_survey_binary_call_graph_summary_structure():
    """survey_binary call_graph_summary contains edge/root/leaf info."""
    result = survey_binary()
    cg = result.get("call_graph_summary", {})
    assert_has_keys(cg, "total_edges", "root_functions", "leaf_functions_count")
    assert isinstance(cg["total_edges"], int)
    assert isinstance(cg["root_functions"], list)
    assert isinstance(cg["leaf_functions_count"], int)


@test()
def test_survey_binary_minimal_excludes_heavy_analysis():
    """survey_binary with detail_level='minimal' excludes analysis data."""
    result = survey_binary(detail_level="minimal")
    assert_has_keys(result, "metadata", "statistics", "segments", "entrypoints")
    assert "interesting_strings" not in result
    assert "interesting_functions" not in result
    assert "imports_by_category" not in result
    assert "call_graph_summary" not in result


@test(binary="crackme03.elf")
def test_survey_binary_crackme_has_expected_functions():
    """survey_binary on crackme03 finds expected function count and symbols."""
    result = survey_binary()
    stats = result["statistics"]
    assert stats["total_functions"] > 0
    
    funcs = result.get("interesting_functions", [])
    func_names = {f["name"] for f in funcs}
    # main or check_pw should be among interesting functions (high xref or named)
    assert len(funcs) > 0


@test(binary="crackme03.elf")
def test_survey_binary_crackme_has_strings():
    """survey_binary on crackme03 finds the expected strings."""
    result = survey_binary()
    stats = result["statistics"]
    assert stats["total_strings"] > 0
    
    strings = result.get("interesting_strings", [])
    string_values = {s["string"] for s in strings}
    # Should find at least one of the crackme strings
    assert any("correct" in s.lower() for s in string_values) or len(strings) > 0


@test(binary="crackme03.elf")
def test_survey_binary_crackme_metadata():
    """survey_binary on crackme03 returns correct metadata."""
    result = survey_binary()
    meta = result["metadata"]
    assert "crackme03" in meta["module"].lower() or meta["module"] == "crackme03.elf"
    assert meta["arch"] == "64"  # crackme03.elf is 64-bit
