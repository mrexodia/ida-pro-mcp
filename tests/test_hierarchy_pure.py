"""Headless unit tests for the PURE helpers in api_hierarchy.

The russian-doll comprehension tools (call_hierarchy / function_skeleton /
module_hierarchy) all touch IDA at call time, but a handful of their building
blocks are pure data transforms with no IDA dependency: the exclude-glob parser,
the name matcher, the human-condition table, the drill/expand cursor builders,
and the probe-record EA coercion used by the runtime overlay. Those are exactly
the pieces that can be verified deterministically headless.

The package imports cleanly under the conftest idaapi stub (api_hierarchy only
subclasses IDA ctree visitors *inside* functions, never at import time), so we
can import the module and exercise the pure helpers directly.
"""

from ida_pro_mcp.ida_mcp import api_hierarchy as h


# ---------------------------------------------------------------------------
# _parse_excludes -- comma-separated globs -> lowercase fnmatch patterns
# ---------------------------------------------------------------------------


def test_parse_excludes_empty_is_empty():
    assert h._parse_excludes("") == []
    assert h._parse_excludes("   ") == []
    assert h._parse_excludes(",, ,") == []


def test_parse_excludes_bare_token_becomes_substring_glob():
    # A bare token with no glob metacharacters is wrapped as *token*.
    assert h._parse_excludes("alloc") == ["*alloc*"]
    assert h._parse_excludes("Alloc") == ["*alloc*"], "tokens are lowercased"


def test_parse_excludes_preserves_explicit_globs():
    # Tokens that already contain glob metacharacters are kept verbatim.
    assert h._parse_excludes("sub_*") == ["sub_*"]
    assert h._parse_excludes("_*,foo?bar") == ["_*", "foo?bar"]
    assert h._parse_excludes("a[bc]d") == ["a[bc]d"]


def test_parse_excludes_splits_and_trims():
    assert h._parse_excludes("sub_*, _*, *alloc* ") == ["sub_*", "_*", "*alloc*"]


# ---------------------------------------------------------------------------
# _name_matches_any -- glob match a function name against exclude patterns
# ---------------------------------------------------------------------------


def test_name_matches_any_substring_pattern():
    pats = h._parse_excludes("alloc")
    assert h._name_matches_any("malloc", pats)
    assert h._name_matches_any("free_alloc_pool", pats)
    assert not h._name_matches_any("strcmp", pats)


def test_name_matches_any_is_case_insensitive():
    pats = h._parse_excludes("Alloc")
    assert h._name_matches_any("MALLOC", pats)


def test_name_matches_any_prefix_glob():
    pats = h._parse_excludes("sub_*")
    assert h._name_matches_any("sub_401000", pats)
    assert not h._name_matches_any("main", pats)


def test_name_matches_any_no_patterns_never_matches():
    assert not h._name_matches_any("anything", [])


# ---------------------------------------------------------------------------
# _human_condition -- branch mnemonic -> human-readable if-test
# ---------------------------------------------------------------------------


def test_human_condition_known_mnemonics():
    assert h._human_condition("jz") == "if (x == 0)"
    assert h._human_condition("jnz") == "if (x != 0)"
    assert h._human_condition("jne") == "if (a != b)"
    # AArch64 compare-and-branch is covered too.
    assert h._human_condition("cbz") == "if (x == 0)"


def test_human_condition_is_case_insensitive():
    assert h._human_condition("JZ") == h._human_condition("jz")
    assert h._human_condition("Jge") == "if (a >= b)"


def test_human_condition_unconditional_branch_is_none():
    # An unconditional jmp / ret / call has no condition phrasing.
    assert h._human_condition("jmp") is None
    assert h._human_condition("ret") is None
    assert h._human_condition("nop") is None


def test_human_condition_phrases_all_start_with_if():
    # Every entry in the table is rendered as an if-test (the doc's promise).
    for phrase in h._COND_PHRASES.values():
        assert phrase.startswith("if ("), phrase


# ---------------------------------------------------------------------------
# _drill / _expand -- the russian-doll navigation cursors
# ---------------------------------------------------------------------------


def test_drill_targets_function_skeleton():
    d = h._drill("0x401000")
    assert d == {"into": "function_skeleton", "addr": "0x401000"}


def test_expand_carries_tool_and_direction():
    e = h._expand("0x401000", "out")
    assert e == {"tool": "call_hierarchy", "addr": "0x401000", "direction": "out"}
    assert h._expand("0x401000", "in")["direction"] == "in"


# ---------------------------------------------------------------------------
# _norm_ea -- coerce a probe-record EA (hex str / int / junk) to an int
# (the runtime-overlay key normalisation; pure)
# ---------------------------------------------------------------------------


def test_norm_ea_passthrough_int():
    assert h._norm_ea(0x401000) == 0x401000
    assert h._norm_ea(0) == 0


def test_norm_ea_parses_hex_and_decimal_strings():
    assert h._norm_ea("0x401000") == 0x401000
    assert h._norm_ea("4198400") == 4198400  # base-0 also accepts decimal
    assert h._norm_ea("0o17") == 0o17


def test_norm_ea_none_and_garbage_are_none():
    assert h._norm_ea(None) is None
    assert h._norm_ea("not-an-address") is None
    assert h._norm_ea([1, 2, 3]) is None
