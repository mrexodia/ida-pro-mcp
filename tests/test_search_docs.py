"""Unit tests for api_docs.search_docs scoring/ordering.

Most tests drive a tiny in-memory docs set injected into the module caches so
the scoring is deterministic and independent of the shipped doc bodies. A
couple of smoke tests exercise the real seeded docs (overview / tools-reference
/ probe-toolkit).
"""

import pytest

from ida_pro_mcp.ida_mcp import api_docs


@pytest.fixture
def tiny_docs(monkeypatch):
    """Replace the doc meta + body caches with a small deterministic set.

    title weight 5x, description 2x, body 1x (per search_docs).
    """
    meta = {
        "alpha": {"title": "Alpha probe guide", "description": "about probes", "priority": 100},
        "beta": {"title": "Beta tools", "description": "tools reference", "priority": 50},
        "gamma": {"title": "Gamma", "description": "", "priority": 10},
    }
    bodies = {
        "alpha": "probe probe probe and more text about probing",
        "beta": "this doc mentions probe exactly once",
        "gamma": "nothing relevant here at all",
    }

    monkeypatch.setattr(api_docs, "_meta_cache", meta, raising=False)
    monkeypatch.setattr(api_docs, "_body_cache", dict(bodies), raising=False)
    # Make _load_body read from our injected bodies, ignoring the filesystem.
    monkeypatch.setattr(api_docs, "_load_body", lambda topic: bodies.get(topic))
    # Make _load_meta return our injected meta.
    monkeypatch.setattr(api_docs, "_load_meta", lambda: meta)
    return meta, bodies


def test_empty_query_returns_empty(tiny_docs):
    assert api_docs.search_docs("") == []
    assert api_docs.search_docs("   ") == []


def test_no_match_returns_index_pointer(tiny_docs):
    # A non-empty query with no match returns a synthetic pointer to the docs
    # index (ida://docs) instead of a dead-end empty list, so the caller always
    # has a next step.
    hits = api_docs.search_docs("zzzznotpresent")
    assert len(hits) == 1
    assert hits[0]["topic"] == "docs"
    assert hits[0]["uri"] == "ida://docs"


def test_title_weight_dominates_ordering(tiny_docs):
    # "probe" appears in alpha's title (5) + desc (2) + body (3) = 10,
    # in beta's body once (1). alpha must rank first.
    hits = api_docs.search_docs("probe")
    topics = [h["topic"] for h in hits]
    assert topics[0] == "alpha"
    assert "beta" in topics
    assert "gamma" not in topics


def test_scores_are_computed_as_expected(tiny_docs):
    hits = {h["topic"]: h["score"] for h in api_docs.search_docs("probe")}
    # Scoring now adds stemming (probes->probe), synonyms, and body-length
    # normalization, so exact values are implementation detail. The invariant is
    # relative: alpha (title+desc+body matches) outscores beta (single body hit),
    # and both are positive.
    assert hits["alpha"] > hits["beta"] > 0


def test_limit_is_respected(tiny_docs):
    hits = api_docs.search_docs("probe tools", limit=1)
    assert len(hits) == 1


def test_limit_zero_returns_empty(tiny_docs):
    assert api_docs.search_docs("probe", limit=0) == []


def test_bad_limit_falls_back_to_default(tiny_docs):
    # Non-int limit must not raise; falls back to 5.
    hits = api_docs.search_docs("probe", limit="notanint")  # type: ignore[arg-type]
    assert isinstance(hits, list)


def test_hit_shape(tiny_docs):
    hit = api_docs.search_docs("probe")[0]
    assert set(hit.keys()) == {"topic", "title", "score", "snippet", "uri", "tools"}
    assert hit["uri"] == f"ida://docs/{hit['topic']}"
    assert hit["title"] == "Alpha probe guide"
    assert isinstance(hit["score"], float)
    assert isinstance(hit["snippet"], str)
    assert isinstance(hit["tools"], list)


def test_tie_break_is_alphabetical_by_topic(tiny_docs, monkeypatch):
    # Two docs with identical score must order by topic name.
    meta = {
        "zeta": {"title": "match", "description": "", "priority": 1},
        "aaa": {"title": "match", "description": "", "priority": 1},
    }
    monkeypatch.setattr(api_docs, "_load_meta", lambda: meta)
    monkeypatch.setattr(api_docs, "_load_body", lambda topic: "")
    hits = api_docs.search_docs("match")
    assert [h["topic"] for h in hits] == ["aaa", "zeta"]


# --------------------------------------------------------------------------
# Smoke tests over the real seeded docs (no monkeypatch).
# --------------------------------------------------------------------------


def test_seeded_docs_searchable():
    hits = api_docs.search_docs("probe")
    topics = [h["topic"] for h in hits]
    assert "probe-toolkit" in topics


def test_seeded_docs_ordering_is_score_desc():
    hits = api_docs.search_docs("tools")
    scores = [h["score"] for h in hits]
    assert scores == sorted(scores, reverse=True)
