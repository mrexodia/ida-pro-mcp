"""A minimal, side-effect-free expression evaluator for probe predicates.

The probe/watch toolkit lets callers attach a boolean *predicate* (and a
breakpoint *condition*) expressed as a small Python-like expression over the
captured values. Historically these were evaluated with the builtin ``eval``
and an emptied ``__builtins__``. That is NOT a sandbox: an expression such as
``().__class__.__bases__[0].__subclasses__()`` reaches ``os`` / ``subprocess``
through ordinary attribute access, so a predicate string was effectively
arbitrary code execution against the host.

This module evaluates a *whitelisted* AST directly. There is no ``eval`` /
``exec`` anywhere, and attribute access (``.``) and function calls are simply
not implemented — so the subclass-traversal escape has no surface to stand on.
Only literals, names bound in the supplied environment, indexing, and
boolean / comparison / arithmetic / bitwise / conditional operators are
supported. Anything else raises :class:`UnsafeExpressionError`.

The evaluator is pure stdlib and imports no IDA modules, so it is fully unit
testable in a headless environment.
"""

from __future__ import annotations

import ast
import operator
from typing import Any, Mapping

__all__ = ["safe_eval", "UnsafeExpressionError"]


class UnsafeExpressionError(ValueError):
    """Raised when an expression uses a construct outside the safe whitelist."""


_BIN_OPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
    ast.LShift: operator.lshift,
    ast.RShift: operator.rshift,
    ast.BitOr: operator.or_,
    ast.BitXor: operator.xor,
    ast.BitAnd: operator.and_,
}

_UNARY_OPS = {
    ast.UAdd: operator.pos,
    ast.USub: operator.neg,
    ast.Invert: operator.invert,
    ast.Not: operator.not_,
}

_CMP_OPS = {
    ast.Eq: operator.eq,
    ast.NotEq: operator.ne,
    ast.Lt: operator.lt,
    ast.LtE: operator.le,
    ast.Gt: operator.gt,
    ast.GtE: operator.ge,
    ast.In: lambda a, b: a in b,
    ast.NotIn: lambda a, b: a not in b,
    ast.Is: operator.is_,
    ast.IsNot: operator.is_not,
}

# Guard against CPU/memory DoS via huge integer exponentiation / shifts.
_MAX_POW_EXP = 1024
_MAX_SHIFT = 1024


def _eval(node: ast.AST, env: Mapping[str, Any]) -> Any:
    if isinstance(node, ast.Expression):
        return _eval(node.body, env)

    if isinstance(node, ast.Constant):
        return node.value

    if isinstance(node, ast.Name):
        if node.id in env:
            return env[node.id]
        raise UnsafeExpressionError(f"unknown name: {node.id!r}")

    if isinstance(node, ast.BoolOp):
        if isinstance(node.op, ast.And):
            result: Any = True
            for value in node.values:
                result = _eval(value, env)
                if not result:
                    return result
            return result
        # Or
        result = False
        for value in node.values:
            result = _eval(value, env)
            if result:
                return result
        return result

    if isinstance(node, ast.UnaryOp):
        op = _UNARY_OPS.get(type(node.op))
        if op is None:
            raise UnsafeExpressionError(
                f"unary operator not allowed: {type(node.op).__name__}"
            )
        return op(_eval(node.operand, env))

    if isinstance(node, ast.BinOp):
        op = _BIN_OPS.get(type(node.op))
        if op is None:
            raise UnsafeExpressionError(
                f"binary operator not allowed: {type(node.op).__name__}"
            )
        left = _eval(node.left, env)
        right = _eval(node.right, env)
        if isinstance(node.op, ast.Pow) and isinstance(right, int) and right > _MAX_POW_EXP:
            raise UnsafeExpressionError("exponent too large")
        if isinstance(node.op, (ast.LShift, ast.RShift)) and isinstance(right, int) and right > _MAX_SHIFT:
            raise UnsafeExpressionError("shift amount too large")
        return op(left, right)

    if isinstance(node, ast.Compare):
        left = _eval(node.left, env)
        for op_node, comparator in zip(node.ops, node.comparators):
            op = _CMP_OPS.get(type(op_node))
            if op is None:
                raise UnsafeExpressionError(
                    f"comparator not allowed: {type(op_node).__name__}"
                )
            right = _eval(comparator, env)
            if not op(left, right):
                return False
            left = right
        return True

    if isinstance(node, ast.IfExp):
        return _eval(node.body, env) if _eval(node.test, env) else _eval(node.orelse, env)

    if isinstance(node, ast.Subscript):
        container = _eval(node.value, env)
        key = _eval(node.slice, env)
        return container[key]

    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        items = [_eval(elt, env) for elt in node.elts]
        if isinstance(node, ast.Tuple):
            return tuple(items)
        if isinstance(node, ast.Set):
            return set(items)
        return items

    if isinstance(node, ast.Dict):
        return {
            _eval(key, env): _eval(value, env)
            for key, value in zip(node.keys, node.values)
        }

    raise UnsafeExpressionError(
        f"expression element not allowed: {type(node).__name__}"
    )


def safe_eval(expression: str, env: Mapping[str, Any]) -> Any:
    """Evaluate *expression* against *env* with no side effects or escape surface.

    *env* maps the only names the expression may reference (e.g. ``c``, ``old``,
    ``new``). Raises :class:`UnsafeExpressionError` on a syntax error, an unknown
    name, or any construct outside the whitelist (calls, attribute access,
    comprehensions, lambdas, walrus, etc.).
    """
    try:
        tree = ast.parse(expression, mode="eval")
    except SyntaxError as exc:
        raise UnsafeExpressionError(f"syntax error: {exc.msg}") from exc
    return _eval(tree, env)
