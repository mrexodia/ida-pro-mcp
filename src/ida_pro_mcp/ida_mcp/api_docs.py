"""Documentation subsystem for the IDA Pro MCP server.

Exposes a small, browsable documentation set as MCP resources plus a
term-frequency search tool. Doc bodies live as Markdown files under the sibling
``docs/`` package directory, indexed by ``docs/_meta.yaml`` (topic ->
{title, description, priority}). Adding a doc requires NO code change: drop a
``.md`` file and add a matching ``_meta.yaml`` entry.

Resources:
    ida://docs            -> a generated Markdown index of all topics
    ida://docs/{topic}    -> one topic body (raw Markdown)

Tools:
    search_docs(query, limit=5) -> ranked matches with topic/title/score/snippet/uri
"""

import re
import threading
from importlib import resources as _resources
from typing import Annotated, TypedDict

from .rpc import resource, tool, safety, title


# ============================================================================
# Result shapes
# ============================================================================


class DocSearchHit(TypedDict):
    topic: str
    title: str
    score: float
    snippet: str
    uri: str


# ============================================================================
# Doc loading + cache
# ============================================================================

_DOCS_PACKAGE = __package__ + ".docs"
_META_FILE = "_meta.yaml"

_cache_lock = threading.Lock()
_meta_cache: dict | None = None
_body_cache: dict[str, str] = {}


def _parse_simple_yaml(text: str) -> dict:
    """Parse the restricted two-level mapping used by docs/_meta.yaml.

    Shape:
        topic:
          title: ...
          description: ...
          priority: 100

    Only top-level keys (no indent) and 2-space-indented child keys are
    recognized. Values are parsed as int when numeric, else as a string with
    optional surrounding quotes stripped. Blank lines and ``#`` comments are
    ignored. This avoids a hard PyYAML dependency for a fixed, simple schema.
    """
    result: dict = {}
    current: dict | None = None
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        if not line.startswith(" "):
            key = line.rstrip(":").strip()
            if not key:
                continue
            current = {}
            result[key] = current
        else:
            if current is None:
                continue
            stripped = line.strip()
            if ":" not in stripped:
                continue
            k, _, v = stripped.partition(":")
            current[k.strip()] = _coerce_scalar(v.strip())
    return result


def _coerce_scalar(value: str):
    if not value:
        return ""
    if (value[0] == value[-1]) and value[0] in ("'", '"') and len(value) >= 2:
        return value[1:-1]
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        pass
    return value


def _load_meta() -> dict:
    global _meta_cache
    with _cache_lock:
        if _meta_cache is not None:
            return _meta_cache
        try:
            text = _resources.files(_DOCS_PACKAGE).joinpath(_META_FILE).read_text(encoding="utf-8")
            meta = _parse_simple_yaml(text)
        except Exception:
            meta = {}
        _meta_cache = meta
        return meta


def _load_body(topic: str) -> str | None:
    with _cache_lock:
        if topic in _body_cache:
            return _body_cache[topic]
    try:
        text = _resources.files(_DOCS_PACKAGE).joinpath(f"{topic}.md").read_text(encoding="utf-8")
    except Exception:
        return None
    with _cache_lock:
        _body_cache[topic] = text
    return text


def _ordered_topics() -> list[str]:
    meta = _load_meta()
    return sorted(
        meta.keys(),
        key=lambda t: (-_priority_of(meta.get(t, {})), t),
    )


def _priority_of(entry: dict) -> float:
    try:
        return float(entry.get("priority", 0))
    except (TypeError, ValueError):
        return 0.0


# ============================================================================
# Resources
# ============================================================================


@resource("ida://docs", mime="text/markdown")
def docs_index_resource() -> str:
    """Generated Markdown index of all documentation topics."""
    meta = _load_meta()
    lines = ["# IDA Pro MCP Documentation", ""]
    if not meta:
        lines.append("_No documentation topics found._")
        return "\n".join(lines) + "\n"
    for topic in _ordered_topics():
        entry = meta.get(topic, {})
        title_text = str(entry.get("title") or topic)
        description = str(entry.get("description") or "").strip()
        lines.append(f"## {title_text}")
        lines.append("")
        lines.append(f"- URI: `ida://docs/{topic}`")
        if description:
            lines.append(f"- {description}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


@resource("ida://docs/{topic}", mime="text/markdown")
def docs_topic_resource(topic: Annotated[str, "Documentation topic id"]) -> str:
    """Return one documentation topic body as raw Markdown."""
    body = _load_body(topic)
    if body is not None:
        return body
    available = ", ".join(_ordered_topics()) or "(none)"
    return (
        f"# Topic not found: {topic}\n\n"
        f"Available topics: {available}\n\n"
        f"Read the index at `ida://docs`.\n"
    )


# ============================================================================
# Search tool
# ============================================================================

_WORD_RE = re.compile(r"[a-z0-9_]+")


def _tokenize(text: str) -> list[str]:
    return _WORD_RE.findall(text.lower())


def _snippet_for(body: str, terms: list[str], width: int = 200) -> str:
    low = body.lower()
    best = -1
    for term in terms:
        idx = low.find(term)
        if idx != -1 and (best == -1 or idx < best):
            best = idx
    if best == -1:
        snippet = body[:width]
    else:
        start = max(0, best - width // 4)
        snippet = body[start:start + width]
    snippet = " ".join(snippet.split())
    if len(body) > len(snippet):
        snippet = snippet + " ..."
    return snippet


@safety("READ")
@title("Search the MCP documentation")
@tool
def search_docs(query: str, limit: int = 5) -> list[DocSearchHit]:
    """Term-frequency search over the cached MCP docs.

    Scores each topic by how often the query terms appear in its title,
    description, and body (title/description weighted higher), and returns the
    top matches with a snippet and the ``ida://docs/{topic}`` URI to read.
    """
    terms = _tokenize(query or "")
    if not terms:
        return []

    meta = _load_meta()
    topics = list(meta.keys()) or _ordered_topics()

    hits: list[DocSearchHit] = []
    for topic in topics:
        entry = meta.get(topic, {})
        title_text = str(entry.get("title") or topic)
        description = str(entry.get("description") or "")
        body = _load_body(topic) or ""

        title_tokens = _tokenize(title_text + " " + topic)
        desc_tokens = _tokenize(description)
        body_tokens = _tokenize(body)

        score = 0.0
        for term in terms:
            score += 5.0 * title_tokens.count(term)
            score += 2.0 * desc_tokens.count(term)
            score += 1.0 * body_tokens.count(term)

        if score <= 0:
            continue

        hits.append(
            DocSearchHit(
                topic=topic,
                title=title_text,
                score=score,
                snippet=_snippet_for(body or description, terms),
                uri=f"ida://docs/{topic}",
            )
        )

    hits.sort(key=lambda h: (-h["score"], h["topic"]))
    try:
        n = max(0, int(limit))
    except (TypeError, ValueError):
        n = 5
    return hits[:n]


__all__ = [
    "DocSearchHit",
    "docs_index_resource",
    "docs_topic_resource",
    "search_docs",
]
