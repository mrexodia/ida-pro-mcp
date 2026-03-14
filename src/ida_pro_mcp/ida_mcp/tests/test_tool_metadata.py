"""Tests for high-signal MCP tool metadata."""

import ast
import re
from pathlib import Path

from ..framework import test


# Tool docstrings are model-facing MCP descriptions in this repository; see
# CLAUDE.md: "The function docstring becomes the MCP tool description."
# Anthropic's tool-use guidance recommends detailed descriptions, ideally 3-4
# sentences, rather than ultra-short labels:
# https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use
# Keep a loose upper bound here to catch accidental prompt stuffing / policy text
# while still allowing informative descriptions for richer tools.
MAX_DOCSTRING_WORDS = 120
PLACEHOLDER_PARAM_DESCRIPTIONS = {"address", "offset", "count"}


def _is_tool_decorator(dec: ast.expr) -> bool:
    if isinstance(dec, ast.Name):
        return dec.id == "tool"
    if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Name):
        return dec.func.id == "tool"
    return False


def _iter_tool_functions():
    root = Path(__file__).resolve().parents[1]
    for path in sorted(root.glob("api_*.py")):
        source = path.read_text(encoding="utf-8")
        module = ast.parse(source)
        for node in module.body:
            if isinstance(node, ast.FunctionDef) and any(
                _is_tool_decorator(d) for d in node.decorator_list
            ):
                yield path, node


def _word_count(text: str) -> int:
    return len(re.findall(r"\b\w+\b", text))


def _iter_annotated_descriptions(node: ast.FunctionDef):
    for arg in [*node.args.args, *node.args.kwonlyargs]:
        ann = arg.annotation
        if not (
            isinstance(ann, ast.Subscript)
            and isinstance(ann.value, ast.Name)
            and ann.value.id == "Annotated"
        ):
            continue
        if isinstance(ann.slice, ast.Tuple) and len(ann.slice.elts) >= 2:
            maybe_desc = ann.slice.elts[1]
            if isinstance(maybe_desc, ast.Constant) and isinstance(maybe_desc.value, str):
                yield arg.arg, maybe_desc.value


@test()
def test_tool_docstrings_present_and_high_signal():
    """Tool docstrings are present, informative, and avoid anti-py_eval nudging."""
    failures: list[str] = []
    for path, node in _iter_tool_functions():
        doc = ast.get_docstring(node) or ""
        if not doc.strip():
            failures.append(f"{path.name}:{node.lineno} {node.name} has empty docstring")
            continue
        words = _word_count(doc)
        if words > MAX_DOCSTRING_WORDS:
            failures.append(
                f"{path.name}:{node.lineno} {node.name} has {words} words (> {MAX_DOCSTRING_WORDS})"
            )
        lower_doc = doc.lower()
        if "py_eval" in lower_doc and (
            "avoid " in lower_doc
            or "instead of" in lower_doc
            or "replace " in lower_doc
        ):
            failures.append(
                f"{path.name}:{node.lineno} {node.name} includes anti-py_eval nudging"
            )

    assert not failures, "\n".join(failures)


@test()
def test_tool_param_descriptions_specific():
    """Annotated parameter descriptions should not use generic placeholders."""
    failures: list[str] = []
    for path, node in _iter_tool_functions():
        for arg_name, description in _iter_annotated_descriptions(node):
            norm = description.strip().lower().rstrip(".")
            if norm in PLACEHOLDER_PARAM_DESCRIPTIONS:
                failures.append(
                    f"{path.name}:{node.lineno} {node.name}({arg_name}) has generic description {description!r}"
                )

    assert not failures, "\n".join(failures)
