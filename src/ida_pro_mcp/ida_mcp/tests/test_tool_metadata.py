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


# Stdlib/primitive type names that are OK to appear in a union alongside a
# TypedDict-like name only when the union is a simple single-or-list shortcut.
_PRIMITIVE_TYPE_NAMES = {"str", "int", "float", "bool", "bytes", "dict"}

# Parameter names whose annotations are allowed to include a bare `str` because
# the string carries no ambiguity - they're simple scalar inputs, not TypedDict
# shortcuts. Example: `addr: str`, `addrs: list[str] | str`.
_PLAIN_STRING_PARAMS = {
    "addr",
    "addrs",
    "name",
    "target",
    "targets",
    "patterns",
    "decls",
    "roots",
    "path",
    "type",
    "format",
}


def _union_elements(node: ast.expr) -> list[ast.expr]:
    """Flatten `A | B | C` into [A, B, C]. Non-union returns [node]."""
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        return _union_elements(node.left) + _union_elements(node.right)
    return [node]


def _is_typed_dict_like(name: str) -> bool:
    """Heuristic: CamelCase name that ends with a wrapper-ish suffix."""
    if not name or not name[0].isupper():
        return False
    suffixes = (
        "Query",
        "Op",
        "Pattern",
        "Edit",
        "Batch",
        "Rename",
        "Read",
        "Write",
        "Inspect",
        "Decl",
        "Delete",
        "Conversion",
        "Upsert",
    )
    return any(name.endswith(s) for s in suffixes)


def _contains_name(node: ast.expr, names: set[str]) -> bool:
    for elt in ast.walk(node):
        if isinstance(elt, ast.Name) and elt.id in names:
            return True
    return False


def _iter_tool_arg_annotations(node: ast.FunctionDef):
    for arg in [*node.args.args, *node.args.kwonlyargs]:
        ann = arg.annotation
        if ann is None:
            continue
        if (
            isinstance(ann, ast.Subscript)
            and isinstance(ann.value, ast.Name)
            and ann.value.id == "Annotated"
            and isinstance(ann.slice, ast.Tuple)
            and ann.slice.elts
        ):
            yield arg.arg, ann.slice.elts[0]
        else:
            yield arg.arg, ann


@test()
def test_tool_params_no_bare_string_or_dict_fallback():
    """Tool parameters must not pair a TypedDict-like name with bare str/dict.

    Catches schemas like `list[FooQuery] | FooQuery | str` where the bare-string
    branch collapses the typed shape in the emitted JSONSchema, leaving the
    model with no way to know what the string actually means.
    """
    failures: list[str] = []
    for path, node in _iter_tool_functions():
        for arg_name, ann in _iter_tool_arg_annotations(node):
            elements = _union_elements(ann)
            if len(elements) < 2:
                continue
            has_typed_dict_like = any(
                _contains_name(e, set())
                or any(
                    isinstance(n, ast.Name) and _is_typed_dict_like(n.id)
                    for n in ast.walk(e)
                )
                for e in elements
            )
            if not has_typed_dict_like:
                continue
            has_bare_string = any(
                isinstance(e, ast.Name) and e.id == "str" for e in elements
            )
            has_bare_dict = any(
                isinstance(e, ast.Name) and e.id == "dict" for e in elements
            )
            if has_bare_string and arg_name not in _PLAIN_STRING_PARAMS:
                failures.append(
                    f"{path.name}:{node.lineno} {node.name}({arg_name}) "
                    f"has a typed shape unioned with bare `str` - "
                    f"the string branch erases the typed schema"
                )
            if has_bare_dict:
                failures.append(
                    f"{path.name}:{node.lineno} {node.name}({arg_name}) "
                    f"has a typed shape unioned with bare `dict` - "
                    f"the dict branch erases the typed schema"
                )

    assert not failures, "\n".join(failures)


@test()
def test_tool_param_typed_dicts_have_required_core():
    """TypedDicts used as tool param shapes must declare a required core.

    A `total=False` TypedDict emits `required: []` in the schema, leaving the
    model no signal about what it must supply. At least one field should be
    marked required (via default `total=True` + `NotRequired` for the rest),
    unless the shape is a pure filter/pagination wrapper where every field is
    genuinely optional.
    """
    # Pure-filter wrappers where every field really is optional.
    ALLOW_EMPTY_REQUIRED = {
        "RenameBatch",  # at least one of func/local/stack/data (enforced in body)
        "FunctionQuery",
        "ListQuery",
        "ImportQuery",
        "TypeQuery",
        "InsnPattern",
        "FuncProfileQuery",
        "StructRead",
        "DefineOp",
        "UndefineOp",
        "NumberConversion",
        "EnumUpsert",
        "EnumMemberUpsert",
    }

    utils_path = Path(__file__).resolve().parents[1] / "utils.py"
    tree = ast.parse(utils_path.read_text(encoding="utf-8"))

    failures: list[str] = []
    for node in tree.body:
        if not isinstance(node, ast.ClassDef):
            continue
        bases = [ast.unparse(b) for b in node.bases]
        if not any("TypedDict" in b for b in bases):
            continue
        if node.name in ALLOW_EMPTY_REQUIRED:
            continue

        # Is the class declared total=False?
        total_false = any(
            isinstance(kw, ast.keyword)
            and kw.arg == "total"
            and isinstance(kw.value, ast.Constant)
            and kw.value.value is False
            for kw in node.keywords
        )

        fields: list[tuple[str, ast.expr]] = []
        for stmt in node.body:
            if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                fields.append((stmt.target.id, stmt.annotation))

        if not fields:
            continue

        required_count = 0
        for _, ann in fields:
            # Unwrap Annotated[...] to inspect the inner type
            inner = ann
            if (
                isinstance(inner, ast.Subscript)
                and isinstance(inner.value, ast.Name)
                and inner.value.id == "Annotated"
                and isinstance(inner.slice, ast.Tuple)
                and inner.slice.elts
            ):
                inner = inner.slice.elts[0]

            is_not_required = (
                isinstance(inner, ast.Subscript)
                and isinstance(inner.value, ast.Name)
                and inner.value.id == "NotRequired"
            )
            # total=False + no NotRequired wrapper = optional
            # total=True (default) + no NotRequired wrapper = required
            if not total_false and not is_not_required:
                required_count += 1

        if required_count == 0:
            failures.append(
                f"utils.py:{node.lineno} {node.name} has no required fields - "
                f"emits `required: []` in the schema; either add a required "
                f"field or allow-list it as a pure-filter wrapper"
            )

    assert not failures, "\n".join(failures)
