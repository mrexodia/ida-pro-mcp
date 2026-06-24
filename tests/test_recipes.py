"""Unit tests for api_recipes' pure logic.

api_recipes' tools chain IDA capabilities, but their parsing/aggregation/ranking
is factored into idaapi-free pure helpers (``_rank_candidates``, ``_merge_report``,
``_dedup_preserve``, ``_score_crypto_loop``, ``_classify_dispatch``). Those run
headless under the conftest idaapi stub, so they are exercised directly here
without a live database.
"""

from ida_pro_mcp.ida_mcp import api_recipes


# --------------------------------------------------------------------------
# _rank_candidates
# --------------------------------------------------------------------------


def test_rank_candidates_sorts_descending():
    items = [
        {"addr": "0x1", "score": 5},
        {"addr": "0x2", "score": 50},
        {"addr": "0x3", "score": 12},
    ]
    ranked = api_recipes._rank_candidates(items)
    assert [c["score"] for c in ranked] == [50, 12, 5]


def test_rank_candidates_top_caps():
    items = [{"addr": hex(i), "score": i} for i in range(10)]
    ranked = api_recipes._rank_candidates(items, top=3)
    assert len(ranked) == 3
    assert [c["score"] for c in ranked] == [9, 8, 7]


def test_rank_candidates_top_none_returns_all():
    items = [{"addr": hex(i), "score": i} for i in range(4)]
    assert len(api_recipes._rank_candidates(items, top=None)) == 4
    assert len(api_recipes._rank_candidates(items, top=0)) == 4


def test_rank_candidates_missing_score_treated_as_zero():
    items = [{"addr": "0xa"}, {"addr": "0xb", "score": 1}]
    ranked = api_recipes._rank_candidates(items)
    assert ranked[0]["addr"] == "0xb"
    assert ranked[1].get("score", 0) == 0


def test_rank_candidates_non_int_score_treated_as_zero():
    items = [{"addr": "0xa", "score": "high"}, {"addr": "0xb", "score": 3}]
    ranked = api_recipes._rank_candidates(items)
    assert ranked[0]["addr"] == "0xb"


def test_rank_candidates_tie_broken_by_addr_deterministic():
    items = [
        {"addr": "0x10", "score": 7},
        {"addr": "0x30", "score": 7},
        {"addr": "0x20", "score": 7},
    ]
    ranked = api_recipes._rank_candidates(items)
    # Equal scores -> addr lexical descending (reverse=True).
    assert [c["addr"] for c in ranked] == ["0x30", "0x20", "0x10"]


def test_rank_candidates_custom_score_key():
    items = [{"addr": "0x1", "weight": 2}, {"addr": "0x2", "weight": 9}]
    ranked = api_recipes._rank_candidates(items, score_key="weight")
    assert ranked[0]["addr"] == "0x2"


def test_rank_candidates_empty():
    assert api_recipes._rank_candidates([]) == []


# --------------------------------------------------------------------------
# _merge_report
# --------------------------------------------------------------------------


def test_merge_report_later_overrides_scalar():
    merged = api_recipes._merge_report({"a": 1}, {"a": 2})
    assert merged["a"] == 2


def test_merge_report_none_does_not_overwrite():
    merged = api_recipes._merge_report({"a": 1}, {"a": None})
    assert merged["a"] == 1


def test_merge_report_none_passes_when_absent():
    merged = api_recipes._merge_report({}, {"a": None})
    assert merged["a"] is None


def test_merge_report_concats_lists_dedup():
    merged = api_recipes._merge_report({"xs": [1, 2]}, {"xs": [2, 3]})
    assert merged["xs"] == [1, 2, 3]


def test_merge_report_list_over_scalar_replaces():
    merged = api_recipes._merge_report({"x": 1}, {"x": [1, 2]})
    assert merged["x"] == [1, 2]


def test_merge_report_skips_empty_parts():
    merged = api_recipes._merge_report({}, None, {"a": 1})
    assert merged == {"a": 1}


def test_merge_report_no_parts():
    assert api_recipes._merge_report() == {}


# --------------------------------------------------------------------------
# _dedup_preserve
# --------------------------------------------------------------------------


def test_dedup_preserve_order():
    assert api_recipes._dedup_preserve(["b", "a", "b", "c", "a"]) == ["b", "a", "c"]


def test_dedup_preserve_empty():
    assert api_recipes._dedup_preserve([]) == []


def test_dedup_preserve_keeps_unhashable():
    # Unhashable items can't be tracked but must not be dropped or raise.
    out = api_recipes._dedup_preserve([{"a": 1}, {"a": 1}])
    assert out == [{"a": 1}, {"a": 1}]


# --------------------------------------------------------------------------
# _score_crypto_loop
# --------------------------------------------------------------------------


def test_score_crypto_loop_no_ops_is_zero():
    score, reasons = api_recipes._score_crypto_loop([], 3)
    assert score == 0
    assert reasons == []


def test_score_crypto_loop_lone_xor_no_loop_is_zero():
    score, reasons = api_recipes._score_crypto_loop(["xor"], 0)
    assert score == 0


def test_score_crypto_loop_rotate_in_loop_scores_high():
    score, reasons = api_recipes._score_crypto_loop(["xor", "rol", "shl"], 2)
    # 3 families*3 + rotate(2) + loop(2) + extra-loop(1) = 14
    assert score == 14
    assert any("rotate" in r for r in reasons)
    assert any("loop" in r for r in reasons)


def test_score_crypto_loop_distinct_families_counted_once():
    # Repeated mnemonics collapse to distinct families.
    s_dup, _ = api_recipes._score_crypto_loop(["xor", "xor", "xor"], 1)
    s_single, _ = api_recipes._score_crypto_loop(["xor"], 1)
    assert s_dup == s_single


def test_score_crypto_loop_multi_family_no_loop_weak_but_nonzero():
    score, reasons = api_recipes._score_crypto_loop(["xor", "shl"], 0)
    assert score > 0
    assert any("no loop" in r for r in reasons)


def test_score_crypto_loop_extra_loops_capped():
    s_few, _ = api_recipes._score_crypto_loop(["xor", "rol"], 2)
    s_many, _ = api_recipes._score_crypto_loop(["xor", "rol"], 50)
    # Extra-loop bonus is capped at +3, so the gap is bounded.
    assert s_many - s_few <= 3


def test_score_crypto_loop_case_insensitive():
    s_lower, _ = api_recipes._score_crypto_loop(["xor", "rol"], 1)
    s_upper, _ = api_recipes._score_crypto_loop(["XOR", "ROL"], 1)
    assert s_lower == s_upper


# --------------------------------------------------------------------------
# _classify_dispatch
# --------------------------------------------------------------------------


def test_classify_dispatch_small():
    assert api_recipes._classify_dispatch(3, 8) == "small_switch"


def test_classify_dispatch_dispatcher():
    assert api_recipes._classify_dispatch(10, 8) == "dispatcher"


def test_classify_dispatch_large():
    # >= max(min*4, 32) -> large
    assert api_recipes._classify_dispatch(64, 8) == "large_dispatcher"


def test_classify_dispatch_large_floor_32():
    # With a tiny min_cases, the floor of 32 governs "large".
    assert api_recipes._classify_dispatch(40, 2) == "large_dispatcher"
    assert api_recipes._classify_dispatch(20, 2) == "dispatcher"


# --------------------------------------------------------------------------
# module surface
# --------------------------------------------------------------------------


def test_module_exports_all_tools():
    expected = {
        "recipe_function_report",
        "recipe_string_to_code",
        "recipe_import_usage",
        "recipe_dispatch_scan",
        "recipe_crypto_candidates",
    }
    assert expected.issubset(set(api_recipes.__all__))
    for name in expected:
        assert hasattr(api_recipes, name)


def test_pure_helpers_exported():
    for name in ("_rank_candidates", "_merge_report", "_dedup_preserve",
                 "_score_crypto_loop", "_classify_dispatch"):
        assert name in api_recipes.__all__
