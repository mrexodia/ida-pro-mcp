"""Tests for profile-file parsing and registry filtering."""

import contextlib
from pathlib import Path

from ..framework import test
from ..profile import apply_profile, dump_profile, load_profile, parse_profile
from ..rpc import MCP_SERVER


@contextlib.contextmanager
def _saved_tools():
    """Restore MCP_SERVER.tools.methods so registry tests are non-destructive."""
    original = MCP_SERVER.tools.methods.copy()
    try:
        yield
    finally:
        MCP_SERVER.tools.methods = original


@test()
def test_parse_profile_strips_comments_and_blanks():
    """Comments, inline comments, blank lines, and whitespace are stripped."""
    text = "\n".join(
        [
            "# header comment",
            "",
            "  decompile_function  ",
            "list_functions # trailing comment",
            "# full-line comment",
            "\t",
            "get_function",
        ]
    )
    assert parse_profile(text) == {"decompile_function", "list_functions", "get_function"}


@test()
def test_parse_profile_empty_returns_empty_set():
    """Empty or comment-only text yields an empty whitelist."""
    assert parse_profile("") == set()
    assert parse_profile("# only comments\n\n#another") == set()


@test()
def test_load_profile_round_trip():
    """load_profile + dump_profile round-trip through the filesystem."""
    import tempfile

    names = {"decompile_function", "list_functions", "get_xrefs"}
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False, encoding="utf-8"
    ) as f:
        f.write(dump_profile(names, header="test header"))
        path = Path(f.name)
    try:
        assert load_profile(path) == names
    finally:
        path.unlink()


@test()
def test_dump_profile_is_deterministic():
    """dump_profile sorts names so output is stable across runs."""
    a = dump_profile({"b_tool", "a_tool", "c_tool"})
    b = dump_profile(["c_tool", "a_tool", "b_tool"])
    assert a == b
    assert a.splitlines() == ["a_tool", "b_tool", "c_tool"]


@test()
def test_dump_profile_header_is_commented():
    """Header lines are emitted as ``#`` comments followed by a blank line."""
    out = dump_profile({"x"}, header="line1\nline2")
    assert out.startswith("# line1\n# line2\n\nx\n")


@test()
def test_apply_profile_keeps_whitelist_and_protected():
    """apply_profile retains whitelisted + protected names, drops the rest."""
    tools = {"a": 1, "b": 2, "c": 3, "mgmt": 4}
    kept, unknown = apply_profile(
        tools, whitelist={"a", "c"}, protected={"mgmt"}
    )
    assert set(tools) == {"a", "c", "mgmt"}
    assert kept == ["a", "c"]
    assert unknown == []


@test()
def test_apply_profile_reports_unknown_entries():
    """Whitelist entries not in the registry are returned as unknown."""
    tools = {"real_tool": 1}
    kept, unknown = apply_profile(tools, whitelist={"real_tool", "typo_tool"})
    assert kept == ["real_tool"]
    assert unknown == ["typo_tool"]
    assert set(tools) == {"real_tool"}


@test()
def test_apply_profile_empty_whitelist_keeps_only_protected():
    """An empty whitelist still preserves protected tools."""
    tools = {"a": 1, "mgmt": 2}
    kept, unknown = apply_profile(tools, whitelist=set(), protected={"mgmt"})
    assert set(tools) == {"mgmt"}
    assert kept == []
    assert unknown == []


@test()
def test_apply_profile_survives_missing_protected():
    """Protected names that aren't registered don't crash or re-appear."""
    tools = {"a": 1}
    kept, unknown = apply_profile(
        tools, whitelist={"a"}, protected={"ghost_mgmt"}
    )
    assert set(tools) == {"a"}
    assert kept == ["a"]
    assert unknown == []


@test()
def test_apply_profile_against_real_registry():
    """Filtering the live MCP_SERVER registry keeps only the whitelist."""
    with _saved_tools():
        registered = set(MCP_SERVER.tools.methods)
        # Pick a couple of real tool names to whitelist.
        sample = sorted(registered)[:2]
        assert len(sample) == 2, "Expected ≥2 registered tools for this test"
        kept, unknown = apply_profile(
            MCP_SERVER.tools.methods, whitelist=set(sample)
        )
        assert set(MCP_SERVER.tools.methods) == set(sample)
        assert kept == sorted(sample)
        assert unknown == []


@test()
def test_export_round_trips_through_parse_profile():
    """Dumping the live registry and re-parsing yields the same names."""
    names = sorted(MCP_SERVER.tools.methods.keys())
    text = dump_profile(names, header="ida-pro-mcp profile export")
    assert parse_profile(text) == set(names)


@test()
def test_bundled_profiles_reference_known_tools():
    """Shipped profile files list only tools that exist in the registry."""
    import os

    registered = set(MCP_SERVER.tools.methods)
    # repo-root/profiles relative to src/ida_pro_mcp/ida_mcp/tests/test_profile.py
    here = Path(__file__).resolve()
    root = here.parents[4]
    for name in ("readonly.txt", "triage.txt"):
        path = root / "profiles" / name
        if not path.exists():
            continue  # running from installed package without repo layout
        whitelist = load_profile(path)
        unknown = whitelist - registered
        assert not unknown, f"{name}: unknown tools {sorted(unknown)}"
