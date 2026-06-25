"""Documentation subsystem for the IDA Pro MCP server.

Exposes a small, browsable documentation set as MCP resources plus a
term-frequency search tool. Doc bodies live as Markdown files under the sibling
``docs/`` package directory, indexed by ``docs/_meta.yaml`` (topic ->
{title, description, priority, tools}). Adding a doc requires NO code change:
drop a ``.md`` file and add a matching ``_meta.yaml`` entry. The optional
``tools:`` key is a comma-separated list of the callable MCP tool names the
topic documents; ``search_docs`` surfaces it on every hit so the caller goes
straight from a query to the tool to call (not just a doc URI to read).

Resources:
    ida://docs            -> a generated Markdown index of all topics
    ida://docs/{topic}    -> one topic body (raw Markdown)

Tools:
    search_docs(query, limit=5) -> ranked matches with
        topic/title/score/snippet/uri/tools
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
    tools: list[str]


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


def _tools_of(entry: dict) -> list[str]:
    """Return the callable tool names a topic documents.

    The ``tools:`` value in ``_meta.yaml`` is a comma-separated string (the
    restricted parser stores scalars only). Split, trim, and drop blanks so the
    caller gets a clean list of MCP tool names to call next.
    """
    raw = entry.get("tools")
    if not raw:
        return []
    if isinstance(raw, (list, tuple)):
        parts = [str(p) for p in raw]
    else:
        parts = str(raw).replace(";", ",").split(",")
    seen: list[str] = []
    for part in parts:
        name = part.strip()
        if name and name not in seen:
            seen.append(name)
    return seen


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

# Reverse-engineering domain synonyms. Each query term is expanded with its
# partners so a user's word finds docs written with the sibling word (and vice
# versa). Bidirectional: every key/value pair is mirrored at module load.
_SYNONYM_SEED: dict[str, list[str]] = {
    "rename": ["renaming", "name"],
    "xref": ["cross", "reference", "xrefs"],
    "watch": ["espion", "watchpoint"],
    "probe": ["sonde", "instrument"],
    "hierarchy": ["call", "tree", "callgraph"],
}


def _build_synonyms(seed: dict[str, list[str]]) -> dict[str, set[str]]:
    table: dict[str, set[str]] = {}
    for key, vals in seed.items():
        group = {key, *vals}
        for word in group:
            table.setdefault(word, set()).update(group - {word})
    return table


_SYNONYMS = _build_synonyms(_SYNONYM_SEED)


def _stem(word: str) -> str:
    """Very light suffix stripping so plurals/gerunds collide with the root.

    Not a real stemmer - just enough to make rename/renaming/renames and
    xref/xrefs share a token. Short tokens are left intact.
    """
    for suffix in ("ing", "ies", "es", " s"[1:], "ed"):
        if len(word) > len(suffix) + 2 and word.endswith(suffix):
            return word[: -len(suffix)]
    return word


def _tokenize(text: str) -> list[str]:
    return _WORD_RE.findall(text.lower())


def _expand_terms(terms: list[str]) -> dict[str, float]:
    """Expand query terms with synonyms + stems, each carrying a weight.

    Original terms weigh 1.0; synonym/stem expansions weigh 0.5 so a direct hit
    always outranks a synonym hit. Returns {term: weight}.
    """
    weighted: dict[str, float] = {}

    def _add(term: str, weight: float) -> None:
        if term and weight > weighted.get(term, 0.0):
            weighted[term] = weight

    for term in terms:
        _add(term, 1.0)
        stem = _stem(term)
        if stem != term:
            _add(stem, 0.7)
        for syn in _SYNONYMS.get(term, ()):  # type: ignore[arg-type]
            _add(syn, 0.5)
            syn_stem = _stem(syn)
            if syn_stem != syn:
                _add(syn_stem, 0.4)
    return weighted


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
def search_docs(
    query: Annotated[
        str,
        "Search terms or a natural-language question (e.g. 'rename a function', "
        "'watch a struct field', 'call tree'). RE-domain synonyms "
        "(rename/renaming, xref/cross-reference, watch/espion, probe/sonde, "
        "hierarchy/call-tree) and simple plurals/gerunds are expanded automatically.",
    ],
    limit: Annotated[int, "Max number of ranked topic hits to return (default 5)."] = 5,
) -> list[DocSearchHit]:
    """Term-frequency search over the cached MCP docs.

    Scores each topic by how often the query terms (plus RE-domain synonyms and
    light stems) appear in its title, description, body, and declared tool names
    - title/description/tools weighted higher - normalized by body length so a
    long doc does not win on raw count. Each hit carries a snippet, the
    ``ida://docs/{topic}`` URI to read, AND the ``tools`` it documents so you can
    go straight from question to the tool to call. On zero matches it returns a
    single synthetic hit pointing at the ``ida://docs`` index.
    """
    raw_terms = _tokenize(query or "")
    if not raw_terms:
        return []

    weighted = _expand_terms(raw_terms)

    meta = _load_meta()
    topics = list(meta.keys()) or _ordered_topics()

    hits: list[DocSearchHit] = []
    for topic in topics:
        entry = meta.get(topic, {})
        title_text = str(entry.get("title") or topic)
        description = str(entry.get("description") or "")
        body = _load_body(topic) or ""
        tools = _tools_of(entry)

        title_tokens = [_stem(t) for t in _tokenize(title_text + " " + topic)]
        desc_tokens = [_stem(t) for t in _tokenize(description)]
        body_tokens = [_stem(t) for t in _tokenize(body)]
        tool_tokens = [_stem(t) for t in _tokenize(" ".join(tools))]

        # Length normalization: dampen raw body counts by doc size so a long
        # topic does not dominate purely by repetition.
        body_norm = 1.0 + (len(body_tokens) / 400.0)

        score = 0.0
        for term, weight in weighted.items():
            stem = _stem(term)
            score += weight * 5.0 * title_tokens.count(stem)
            score += weight * 4.0 * tool_tokens.count(stem)
            score += weight * 2.0 * desc_tokens.count(stem)
            score += weight * (1.0 / body_norm) * body_tokens.count(stem)

        if score <= 0:
            continue

        hits.append(
            DocSearchHit(
                topic=topic,
                title=title_text,
                score=round(score, 4),
                snippet=_snippet_for(body or description, list(weighted)),
                uri=f"ida://docs/{topic}",
                tools=tools,
            )
        )

    hits.sort(key=lambda h: (-h["score"], h["topic"]))
    try:
        n = max(0, int(limit))
    except (TypeError, ValueError):
        n = 5

    if not hits:
        # Dead ends are unhelpful: hand back a pointer to the browsable index
        # instead of an empty list so the caller always has a next step.
        return [
            DocSearchHit(
                topic="docs",
                title="IDA Pro MCP Documentation (index)",
                score=0.0,
                snippet=(
                    f"No topic matched {raw_terms!r}. Browse the full index at "
                    f"ida://docs, or query ida://tools for the authoritative "
                    f"live tool list."
                ),
                uri="ida://docs",
                tools=[],
            )
        ]
    return hits[:n]


__all__ = [
    "DocSearchHit",
    "docs_index_resource",
    "docs_topic_resource",
    "search_docs",
]
