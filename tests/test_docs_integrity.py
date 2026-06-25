"""Integrity guard for the in-tool documentation corpus.

The docs subsystem (``api_docs``) serves ``docs/*.md`` bodies indexed by
``docs/_meta.yaml`` (topic -> {title, description, priority, tools}). Two kinds
of reference inside that corpus can silently rot:

    * cross-links of the form ``ida://docs/<topic>`` embedded in a doc body or
      in the ``_meta.yaml`` index -- a typo or a renamed/removed topic turns
      these into dead ends, and
    * the ``tools:`` list on a ``_meta.yaml`` topic -- this is the
      question->tool bridge ``search_docs`` surfaces, so a stale name sends a
      caller to a tool that does not exist.

This module asserts that EVERY such reference resolves:

    1. every ``_meta.yaml`` topic has a matching ``<topic>.md`` body (and every
       shipped ``.md`` has a meta entry, so nothing is orphaned),
    2. every ``ida://docs/<topic>`` cross-link (in any body or in the meta
       descriptions) names a real topic, and
    3. every name in any topic's ``tools:`` list is a real registered MCP tool.

Headless: importing ``ida_pro_mcp.ida_mcp`` (under the conftest idaapi stub)
populates the tool registry, and ``api_docs`` reads the doc corpus straight off
the package data, so no live IDA is needed.
"""

import re
from importlib import resources as _resources

import pytest

# Populate the tool registry (decorator side effects) so tools: lists can be
# validated against the real registered surface.
import ida_pro_mcp.ida_mcp  # noqa: F401
from ida_pro_mcp.ida_mcp import api_docs
from ida_pro_mcp.ida_mcp._kernel.rpc import MCP_SERVER


# ``{topic}`` is the templated-resource placeholder used in prose/code blocks
# (e.g. the @resource("ida://docs/{topic}") declaration documented inside
# mcp-server-architecture.md); it is not a concrete cross-link and must not be
# resolved. The character class already excludes braces, so the placeholder
# never matches, but we keep an explicit guard for clarity.
_CROSSLINK_RE = re.compile(r"ida://docs/([a-z0-9][a-z0-9_\-]*)")


@pytest.fixture(scope="module")
def meta() -> dict:
    m = api_docs._load_meta()
    assert m, "doc _meta.yaml failed to load or is empty"
    return m


@pytest.fixture(scope="module")
def topics(meta) -> set[str]:
    return set(meta.keys())


@pytest.fixture(scope="module")
def md_topics() -> set[str]:
    pkg = api_docs._DOCS_PACKAGE
    return {
        p.name[:-3]
        for p in _resources.files(pkg).iterdir()
        if p.name.endswith(".md")
    }


@pytest.fixture(scope="module")
def registered_tools() -> set[str]:
    return set(MCP_SERVER.tools.methods)


# ---------------------------------------------------------------------------
# meta <-> body file consistency
# ---------------------------------------------------------------------------


def test_corpus_is_non_trivially_populated(topics):
    # The shipped corpus is sizeable; a near-empty meta means the loader broke.
    assert len(topics) >= 20


def test_every_meta_topic_has_a_body(topics, md_topics):
    missing = topics - md_topics
    assert not missing, f"_meta.yaml topics without a <topic>.md body: {sorted(missing)}"


def test_every_body_has_a_meta_entry(topics, md_topics):
    orphan = md_topics - topics
    assert not orphan, f"shipped .md files with no _meta.yaml entry: {sorted(orphan)}"


def test_every_topic_body_loads(topics):
    for topic in topics:
        body = api_docs._load_body(topic)
        assert body is not None and body.strip(), f"empty/unloadable body for {topic}"


def test_every_topic_has_a_title(meta):
    for topic, entry in meta.items():
        assert str(entry.get("title") or "").strip(), f"{topic} has no title"


# ---------------------------------------------------------------------------
# cross-link resolution
# ---------------------------------------------------------------------------


def _crosslinks_in(text: str) -> set[str]:
    return {
        ref
        for ref in _CROSSLINK_RE.findall(text or "")
        if ref != "topic"  # the {topic} template placeholder, defensively
    }


def test_body_crosslinks_resolve(topics):
    """Every ``ida://docs/<topic>`` link inside a doc body names a real topic."""
    bad: dict[str, set[str]] = {}
    for topic in topics:
        body = api_docs._load_body(topic) or ""
        for ref in _crosslinks_in(body):
            if ref not in topics:
                bad.setdefault(topic, set()).add(ref)
    assert not bad, f"dangling ida://docs cross-links: { {k: sorted(v) for k, v in bad.items()} }"


def test_meta_description_crosslinks_resolve(meta, topics):
    """Cross-links embedded in _meta.yaml titles/descriptions also resolve."""
    bad: dict[str, set[str]] = {}
    for topic, entry in meta.items():
        text = f"{entry.get('title', '')} {entry.get('description', '')}"
        for ref in _crosslinks_in(text):
            if ref not in topics:
                bad.setdefault(topic, set()).add(ref)
    assert not bad, f"dangling cross-links in _meta.yaml: { {k: sorted(v) for k, v in bad.items()} }"


def test_index_resource_only_references_real_topics(topics):
    """The generated ``ida://docs`` index lists exactly the known topics."""
    index = api_docs.docs_index_resource()
    for ref in _crosslinks_in(index):
        assert ref in topics, f"index references unknown topic: {ref}"
    # Every topic must appear in the index so none is unreachable from it.
    for topic in topics:
        assert f"ida://docs/{topic}" in index, f"{topic} missing from docs index"


def test_unknown_topic_resource_degrades_gracefully(topics):
    """Requesting a non-existent topic returns a not-found body, never raises,
    and points at the real index rather than a dead link."""
    assert "no-such-topic-xyz" not in topics
    body = api_docs.docs_topic_resource("no-such-topic-xyz")
    assert "not found" in body.lower()
    assert "ida://docs" in body


# ---------------------------------------------------------------------------
# tools: lists name real registered tools
# ---------------------------------------------------------------------------


def test_meta_tools_lists_name_real_tools(meta, registered_tools):
    """Every name in any topic's ``tools:`` list is a registered MCP tool.

    This is the question->tool bridge; a stale name here routes a caller to a
    tool that does not exist.
    """
    bad: dict[str, set[str]] = {}
    for topic, entry in meta.items():
        for name in api_docs._tools_of(entry):
            if name not in registered_tools:
                bad.setdefault(topic, set()).add(name)
    assert not bad, f"_meta.yaml tools: names with no registered tool: { {k: sorted(v) for k, v in bad.items()} }"


def test_at_least_one_topic_declares_tools(meta):
    """Sanity: the tools: bridge is actually exercised by the shipped corpus."""
    with_tools = [t for t, e in meta.items() if api_docs._tools_of(e)]
    assert with_tools, "no topic declares a tools: list; the bridge is untested"


def test_declared_tools_are_unique_within_a_topic(meta):
    """A topic's tools: list must not contain duplicates (the parser dedups, so
    this confirms the dedup actually holds for the shipped data)."""
    for topic, entry in meta.items():
        names = api_docs._tools_of(entry)
        assert len(names) == len(set(names)), f"{topic} has duplicate tools: entries"
