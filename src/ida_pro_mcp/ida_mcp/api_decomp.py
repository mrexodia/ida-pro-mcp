"""Decompiler comprehension: ctree / microcode / local-variable tooling.

These tools read the Hex-Rays *intermediate* representations directly instead of
scraping pseudocode text, so an agent gets decompiler-accurate structure:

  * pseudocode_query    -- STRUCTURED ctree nodes (calls / loops / ifs /
    assignments / variable uses) with ea, line number, parent kind and the
    rendered sub-expression. Replaces regex/heuristic text scraping of the
    pseudocode.
  * lvar_usage          -- a decompiler-accurate def-use map: every reference to
    a local variable tagged read / write / addr, plus the syntactic context it
    appears in (call_arg / comparison / condition / return / ...).
  * set_lvar            -- persistently rename / retype / comment a decompiler
    local via modify_user_lvar_info, so the change survives re-decompilation
    (the rename-only path in api_modify does not retype or comment).
  * microcode_text      -- the gen_microcode() listing at a chosen maturity.
  * microcode_calls     -- resolved call arguments (MicroCallInfo) off the
    microcode, the IR-level view of an indirect/typed call site.

EVERYTHING here is guarded: Hex-Rays may be absent (no decompiler license, or a
function it refuses), and the microcode API surface varies across builds, so each
entry point degrades to a clear `error` string rather than raising. Outputs are
bounded by per-tool caps so a pathological function cannot blow the token budget.

All ctree access reuses utils.get_cached_cfunc so a query does not trigger a
fresh decompilation, and set_lvar calls utils.bump_decompile_dirty afterwards so
the cache (and downstream pseudocode) reflects the edit.
"""

from __future__ import annotations

from typing import Annotated, Optional, TypedDict

import idaapi
import idc

from ._kernel.rpc import safety, title, tool
from ._kernel.sync import idasync, tool_timeout
from ._kernel.utils import (
    bump_decompile_dirty,
    get_cached_cfunc,
    parse_address,
)


# ============================================================================
# Bounds (token budgets)
# ============================================================================

_MAX_NODES = 600           # pseudocode_query: max structured nodes returned
_MAX_LVAR_REFS = 800       # lvar_usage: max per-variable references
_MAX_MICROCODE_LINES = 4000  # microcode_text: max emitted lines
_MAX_MICRO_CALLS = 400     # microcode_calls: max resolved call sites
_SUBEXPR_CAP = 240         # max chars of a rendered sub-expression


# ============================================================================
# Result TypedDicts
# ============================================================================


class PseudoNode(TypedDict, total=False):
    kind: str            # call|loop|if|assignment|var
    ea: str | None
    line: int | None
    parent: str | None   # parent ctree-item kind label
    text: str            # rendered sub-expression / statement head
    subkind: str         # for loops: for|while|do; for vars: read|write|addr
    name: str            # for var/call nodes: variable / callee name


class PseudocodeQueryResult(TypedDict, total=False):
    func: str
    resolved_addr: str | None
    name: str
    kinds: list[str]
    nodes: list[PseudoNode]
    counts: dict[str, int]
    node_count: int
    truncated: bool
    decompiled: bool
    error: str


class LvarRef(TypedDict, total=False):
    ea: str | None
    line: int | None
    access: str          # read|write|addr
    context: str         # call_arg|comparison|condition|return|assign_rhs|...
    text: str


class LvarUsageItem(TypedDict, total=False):
    name: str
    type: str
    is_arg: bool
    read_count: int
    write_count: int
    addr_count: int
    refs: list[LvarRef]
    refs_truncated: bool


class LvarUsageResult(TypedDict, total=False):
    func: str
    resolved_addr: str | None
    name: str
    variables: list[LvarUsageItem]
    decompiled: bool
    error: str


class SetLvarResult(TypedDict, total=False):
    func: str
    resolved_addr: str | None
    var: str
    renamed_to: str | None
    retyped_to: str | None
    commented: bool
    applied: list[str]
    error: str


class MicrocodeTextResult(TypedDict, total=False):
    func: str
    resolved_addr: str | None
    name: str
    maturity: str
    lines: list[str]
    line_count: int
    block_count: int
    truncated: bool
    error: str


class MicroCall(TypedDict, total=False):
    ea: str | None
    callee: str | None
    return_type: str | None
    arg_count: int
    args: list[dict]
    solid_args: bool
    spoiled: bool


class MicrocodeCallsResult(TypedDict, total=False):
    func: str
    resolved_addr: str | None
    name: str
    maturity: str
    calls: list[MicroCall]
    call_count: int
    truncated: bool
    error: str


# ============================================================================
# Shared helpers
# ============================================================================


def _resolve_func_start(query: str) -> tuple[int | None, str | None]:
    """Resolve an address/name to the start EA of its enclosing function."""
    q = str(query or "").strip()
    if not q:
        return None, "Function query is required"
    try:
        ea = parse_address(q)
    except Exception:
        ea = idaapi.get_name_ea(idaapi.BADADDR, q)
    if ea is None or ea == idaapi.BADADDR:
        return None, f"Failed to resolve: {q}"
    func = idaapi.get_func(ea)
    if not func:
        return None, f"Not a function: {q}"
    return func.start_ea, None


def _func_name(start_ea: int) -> str:
    import ida_funcs

    return ida_funcs.get_func_name(start_ea) or "<unnamed>"


def _expr_text(expr) -> str:
    """Best-effort one-line source text of a ctree expression/statement."""
    try:
        import ida_lines

        s = expr.print1(None)
        if s:
            text = ida_lines.tag_remove(s).strip()
            text = " ".join(text.split())
            if len(text) > _SUBEXPR_CAP:
                return text[:_SUBEXPR_CAP] + "..."
            return text
    except Exception:
        pass
    return "<expr>"


def _line_no_for_ea(cfunc, ea: int) -> Optional[int]:
    """Map an item EA back to a 1-based pseudocode line number, if possible."""
    if ea is None or ea == idaapi.BADADDR:
        return None
    try:
        import ida_hexrays

        # eamap maps ea -> list of citems; pair with the printed line via the
        # boundaries() map when available.
        ea2lt = getattr(cfunc, "get_boundaries", None)
        # Fall back to the simple linear scan over the pseudocode object.
        sv = cfunc.get_pseudocode()
        if not sv:
            return None
        target = ida_hexrays.tag_addr(ea) if hasattr(ida_hexrays, "tag_addr") else None
        for i, sl in enumerate(sv):
            if target and target in sl.line:
                return i + 1
    except Exception:
        return None
    return None


def _ctree_item_kind(item) -> str:
    """Human label for a ctree item op code (best-effort)."""
    try:
        import ida_hexrays

        op = item.op
        names = {
            ida_hexrays.cot_call: "call",
            ida_hexrays.cot_asg: "assignment",
            ida_hexrays.cit_if: "if",
            ida_hexrays.cit_for: "for",
            ida_hexrays.cit_while: "while",
            ida_hexrays.cit_do: "do",
            ida_hexrays.cit_return: "return",
            ida_hexrays.cit_switch: "switch",
            ida_hexrays.cit_block: "block",
            ida_hexrays.cot_var: "var",
        }
        return names.get(op, str(op))
    except Exception:
        return "?"


# ============================================================================
# pseudocode_query -- STRUCTURED ctree nodes
# ============================================================================


@safety("READ")
@title("Pseudocode Query (Structured ctree Nodes)")
@tool
@idasync
@tool_timeout(90.0)
def pseudocode_query(
    func: Annotated[
        str,
        "Function address (hex like '0x401000') or symbol name whose decompiler ctree is queried.",
    ],
    kinds: Annotated[
        str,
        "Comma-separated node kinds to collect: any of 'calls,loops,ifs,assignments,vars'. Default collects all of them.",
    ] = "calls,loops,ifs,assignments,vars",
) -> PseudocodeQueryResult:
    """WHAT: Walks the Hex-Rays ctree of one function and returns STRUCTURED nodes -- calls (cot_call), loops (cit_for/while/do), ifs (cit_if), assignments (cot_asg) and variable uses (cot_var) -- each with its ea, pseudocode line number, the kind of its enclosing parent item, and the rendered sub-expression. This is the decompiler-accurate alternative to regex/heuristic scraping of the pseudocode text.

WHEN TO USE: When you need to programmatically locate structure inside a function -- "every call and the condition that guards it", "all loops", "every write to a variable" -- without re-parsing C text and getting fooled by string literals, macros, or line wrapping. Pair with lvar_usage for a full def-use picture and function_skeleton for the CFG view.

RETURNS: {func, resolved_addr, name, kinds, nodes:[{kind, ea, line, parent, text, subkind?, name?}], counts:{kind:n}, node_count, truncated, decompiled, error?}. `subkind` distinguishes loop flavour (for/while/do); `name` carries the callee/variable name where known. truncated=true means the per-call node cap clipped the walk.

PRO-TIP: Narrow `kinds` (e.g. kinds='calls,ifs') to slash token cost and keep the parent linkage usable. PITFALL: nodes come from the decompiled ctree -- a function Hex-Rays refuses returns decompiled=false with an `error`; fall back to disasm/insn_query for those."""
    import ida_hexrays

    requested = {k.strip().lower() for k in (kinds or "").split(",") if k.strip()}
    if not requested:
        requested = {"calls", "loops", "ifs", "assignments", "vars"}
    # normalise singular/plural aliases
    want_calls = "calls" in requested or "call" in requested
    want_loops = "loops" in requested or "loop" in requested
    want_ifs = "ifs" in requested or "if" in requested
    want_asg = "assignments" in requested or "assignment" in requested or "asg" in requested
    want_vars = "vars" in requested or "var" in requested

    try:
        start_ea, err = _resolve_func_start(func)
        if err is not None or start_ea is None:
            return {
                "func": func,
                "resolved_addr": None,
                "nodes": [],
                "decompiled": False,
                "error": err or "Failed to resolve function",
            }

        cfunc, derr = get_cached_cfunc(start_ea)
        if cfunc is None or derr is not None:
            return {
                "func": func,
                "resolved_addr": hex(start_ea),
                "name": _func_name(start_ea),
                "kinds": sorted(requested),
                "nodes": [],
                "node_count": 0,
                "decompiled": False,
                "error": derr or "Decompilation failed",
            }

        nodes: list[PseudoNode] = []
        counts: dict[str, int] = {}
        truncated = {"v": False}

        def _add(kind: str, ea, text: str, parent: str | None, **extra) -> None:
            if len(nodes) >= _MAX_NODES:
                truncated["v"] = True
                return
            counts[kind] = counts.get(kind, 0) + 1
            row: PseudoNode = {
                "kind": kind,
                "ea": hex(ea) if (ea is not None and ea != idaapi.BADADDR) else None,
                "line": _line_no_for_ea(cfunc, ea) if ea is not None else None,
                "parent": parent,
                "text": text,
            }
            row.update(extra)
            nodes.append(row)

        cfunc_ref = cfunc

        class _Visitor(ida_hexrays.ctree_visitor_t):
            def __init__(self):
                ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_PARENTS)

            def _parent_kind(self):
                try:
                    p = self.parent_insn() or self.parent_expr()
                    if p is not None:
                        return _ctree_item_kind(p)
                except Exception:
                    pass
                return None

            def visit_insn(self, ins):
                if truncated["v"]:
                    return 1
                try:
                    op = ins.op
                    if want_ifs and op == ida_hexrays.cit_if and ins.cif is not None:
                        _add(
                            "if",
                            ins.ea,
                            "if (" + _expr_text(ins.cif.expr) + ")",
                            self._parent_kind(),
                        )
                    elif want_loops and op == ida_hexrays.cit_for and ins.cfor is not None:
                        _add("loop", ins.ea, "for (" + _expr_text(ins.cfor.expr) + ")",
                             self._parent_kind(), subkind="for")
                    elif want_loops and op == ida_hexrays.cit_while and ins.cwhile is not None:
                        _add("loop", ins.ea, "while (" + _expr_text(ins.cwhile.expr) + ")",
                             self._parent_kind(), subkind="while")
                    elif want_loops and op == ida_hexrays.cit_do and ins.cdo is not None:
                        _add("loop", ins.ea, "do-while (" + _expr_text(ins.cdo.expr) + ")",
                             self._parent_kind(), subkind="do")
                except Exception:
                    pass
                return 0

            def visit_expr(self, e):
                if truncated["v"]:
                    return 1
                try:
                    op = e.op
                    if want_calls and op == ida_hexrays.cot_call:
                        name = _callee_name(e)
                        _add("call", e.ea, _expr_text(e), self._parent_kind(),
                             name=name or "<indirect>")
                    elif want_asg and op == ida_hexrays.cot_asg:
                        _add("assignment", e.ea, _expr_text(e), self._parent_kind())
                    elif want_vars and op == ida_hexrays.cot_var:
                        vname = _var_name(cfunc_ref, e)
                        _add("var", e.ea, vname or _expr_text(e),
                             self._parent_kind(), name=vname or "")
                except Exception:
                    pass
                return 0

        try:
            _Visitor().apply_to(cfunc.body, None)
        except Exception as e:
            return {
                "func": func,
                "resolved_addr": hex(start_ea),
                "name": _func_name(start_ea),
                "kinds": sorted(requested),
                "nodes": nodes,
                "node_count": len(nodes),
                "counts": counts,
                "truncated": truncated["v"],
                "decompiled": True,
                "error": f"ctree walk failed: {e}",
            }

        return {
            "func": func,
            "resolved_addr": hex(start_ea),
            "name": _func_name(start_ea),
            "kinds": sorted(requested),
            "nodes": nodes,
            "node_count": len(nodes),
            "counts": counts,
            "truncated": truncated["v"],
            "decompiled": True,
            "error": None,
        }
    except Exception as e:
        return {
            "func": func,
            "resolved_addr": None,
            "nodes": [],
            "decompiled": False,
            "error": str(e),
        }


def _callee_name(call_expr) -> Optional[str]:
    """Resolve the callee name of a cot_call expression, if direct."""
    try:
        import ida_hexrays

        callee = call_expr.x
        if callee is None:
            return None
        if callee.op == ida_hexrays.cot_obj:
            nm = idc.get_name(callee.obj_ea)
            if nm:
                return nm
        if callee.op == ida_hexrays.cot_helper:
            return getattr(callee, "helper", None)
    except Exception:
        pass
    return None


def _var_name(cfunc, var_expr) -> Optional[str]:
    """Resolve the lvar name of a cot_var expression."""
    try:
        idx = var_expr.v.idx
        lvars = cfunc.get_lvars()
        if lvars is not None and 0 <= idx < lvars.size():
            return lvars[idx].name
    except Exception:
        pass
    return None


# ============================================================================
# lvar_usage -- decompiler-accurate def-use map
# ============================================================================


def _classify_access(parent_op) -> str:
    """Map the immediate parent op of a var reference to read/write/addr.

    addr  : the var is the operand of '&' (cot_ref).
    write : the var is the LHS of an assignment family op.
    read  : everything else (default).
    """
    try:
        import ida_hexrays

        if parent_op == ida_hexrays.cot_ref:
            return "addr"
        asg_ops = {
            ida_hexrays.cot_asg,
            ida_hexrays.cot_asgadd,
            ida_hexrays.cot_asgsub,
            ida_hexrays.cot_asgmul,
            ida_hexrays.cot_asgsdiv,
            ida_hexrays.cot_asgudiv,
            ida_hexrays.cot_asgsmod,
            ida_hexrays.cot_asgumod,
            ida_hexrays.cot_asgband,
            ida_hexrays.cot_asgbor,
            ida_hexrays.cot_asgxor,
            ida_hexrays.cot_asgshl,
            ida_hexrays.cot_asgsshr,
            ida_hexrays.cot_asgushr,
        }
        if parent_op in asg_ops:
            return "write"
    except Exception:
        pass
    return "read"


def _classify_context(visitor) -> str:
    """Best-effort syntactic context of the current var reference."""
    try:
        import ida_hexrays

        pe = visitor.parent_expr()
        pi = visitor.parent_insn()
        if pi is not None:
            if pi.op == ida_hexrays.cit_if:
                return "condition"
            if pi.op in (ida_hexrays.cit_for, ida_hexrays.cit_while, ida_hexrays.cit_do):
                return "loop_condition"
            if pi.op == ida_hexrays.cit_return:
                return "return"
        if pe is not None:
            op = pe.op
            if op == ida_hexrays.cot_call:
                return "call_arg"
            cmp_ops = {
                ida_hexrays.cot_eq, ida_hexrays.cot_ne,
                ida_hexrays.cot_slt, ida_hexrays.cot_sle,
                ida_hexrays.cot_sgt, ida_hexrays.cot_sge,
                ida_hexrays.cot_ult, ida_hexrays.cot_ule,
                ida_hexrays.cot_ugt, ida_hexrays.cot_uge,
            }
            if op in cmp_ops:
                return "comparison"
            if op == ida_hexrays.cot_asg:
                return "assignment"
            if op == ida_hexrays.cot_ref:
                return "address_of"
            if op in (ida_hexrays.cot_idx, ida_hexrays.cot_memref, ida_hexrays.cot_memptr):
                return "member_index"
    except Exception:
        pass
    return "expression"


@safety("READ")
@title("Local Variable Usage (Def-Use Map)")
@tool
@idasync
@tool_timeout(90.0)
def lvar_usage(
    func: Annotated[
        str,
        "Function address (hex like '0x401000') or symbol name whose local-variable usage is mapped.",
    ],
    var: Annotated[
        str,
        "Optional single local-variable name to restrict the map to (e.g. 'v3', 'key'). Empty = every local.",
    ] = "",
) -> LvarUsageResult:
    """WHAT: Builds a decompiler-accurate def-use map for a function's local variables by walking the ctree. For each variable it reports every reference tagged by access type (read / write / addr) and by syntactic context (call_arg / comparison / condition / return / assignment / member_index / ...), plus per-variable read/write/addr counts. This is far more precise than text-scraping because it uses the decompiler's own lvar indices.

WHEN TO USE: To understand how a specific local flows through a function -- where a key/counter is written, where a pointer is taken (addr), which calls consume it, and which conditions test it. The natural companion to pseudocode_query (structure) and set_lvar (rename/retype once you understand the var).

RETURNS: {func, resolved_addr, name, variables:[{name, type, is_arg, read_count, write_count, addr_count, refs:[{ea, line, access, context, text}], refs_truncated}], decompiled, error?}. Pass `var` to restrict to one variable. access is read|write|addr; context is the enclosing syntactic role.

PRO-TIP: A variable with addr_count>0 escapes by pointer -- treat it as potentially aliased before reasoning about its value. PITFALL: indices are the decompiler's, so two source variables that Hex-Rays coalesced share one entry; if a name looks wrong, re-decompile after set_lvar to split intent."""
    import ida_hexrays

    want_var = (var or "").strip()

    try:
        start_ea, err = _resolve_func_start(func)
        if err is not None or start_ea is None:
            return {
                "func": func,
                "resolved_addr": None,
                "variables": [],
                "decompiled": False,
                "error": err or "Failed to resolve function",
            }

        cfunc, derr = get_cached_cfunc(start_ea)
        if cfunc is None or derr is not None:
            return {
                "func": func,
                "resolved_addr": hex(start_ea),
                "name": _func_name(start_ea),
                "variables": [],
                "decompiled": False,
                "error": derr or "Decompilation failed",
            }

        lvars = cfunc.get_lvars()
        if lvars is None:
            return {
                "func": func,
                "resolved_addr": hex(start_ea),
                "name": _func_name(start_ea),
                "variables": [],
                "decompiled": True,
                "error": "No local variables",
            }

        # index -> accumulator
        acc: dict[int, dict] = {}
        for i in range(lvars.size()):
            lv = lvars[i]
            if want_var and lv.name != want_var:
                continue
            acc[i] = {
                "name": lv.name or f"lvar_{i}",
                "type": str(lv.type()) if hasattr(lv, "type") else "",
                "is_arg": bool(getattr(lv, "is_arg_var", False)),
                "read_count": 0,
                "write_count": 0,
                "addr_count": 0,
                "refs": [],
                "refs_truncated": False,
            }

        if not acc:
            return {
                "func": func,
                "resolved_addr": hex(start_ea),
                "name": _func_name(start_ea),
                "variables": [],
                "decompiled": True,
                "error": (f"Variable not found: {want_var}" if want_var else "No local variables"),
            }

        cfunc_ref = cfunc

        class _V(ida_hexrays.ctree_visitor_t):
            def __init__(self):
                ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_PARENTS)

            def visit_expr(self, e):
                try:
                    if e.op != ida_hexrays.cot_var:
                        return 0
                    idx = e.v.idx
                    bucket = acc.get(idx)
                    if bucket is None:
                        return 0
                    pe = self.parent_expr()
                    parent_op = pe.op if pe is not None else -1
                    # write only when this var is the LHS (x) of an asg.
                    access = "read"
                    if parent_op == ida_hexrays.cot_ref:
                        access = "addr"
                    elif _classify_access(parent_op) == "write" and pe is not None \
                            and getattr(pe, "x", None) is not None and pe.x.obj_id == e.obj_id:
                        access = "write"
                    context = _classify_context(self)
                    if access == "read":
                        bucket["read_count"] += 1
                    elif access == "write":
                        bucket["write_count"] += 1
                    else:
                        bucket["addr_count"] += 1
                    if len(bucket["refs"]) < _MAX_LVAR_REFS:
                        bucket["refs"].append({
                            "ea": hex(e.ea) if e.ea != idaapi.BADADDR else None,
                            "line": _line_no_for_ea(cfunc_ref, e.ea),
                            "access": access,
                            "context": context,
                            "text": _expr_text(pe) if pe is not None else _expr_text(e),
                        })
                    else:
                        bucket["refs_truncated"] = True
                except Exception:
                    pass
                return 0

        try:
            _V().apply_to(cfunc.body, None)
        except Exception as e:
            return {
                "func": func,
                "resolved_addr": hex(start_ea),
                "name": _func_name(start_ea),
                "variables": list(acc.values()),
                "decompiled": True,
                "error": f"ctree walk failed: {e}",
            }

        return {
            "func": func,
            "resolved_addr": hex(start_ea),
            "name": _func_name(start_ea),
            "variables": list(acc.values()),
            "decompiled": True,
            "error": None,
        }
    except Exception as e:
        return {
            "func": func,
            "resolved_addr": None,
            "variables": [],
            "decompiled": False,
            "error": str(e),
        }


# ============================================================================
# set_lvar -- persistent rename / retype / comment
# ============================================================================


def _find_lvar(cfunc, name: str):
    """Return (lvar, index) for the named local in cfunc, or (None, -1)."""
    lvars = cfunc.get_lvars()
    if lvars is None:
        return None, -1
    for i in range(lvars.size()):
        if lvars[i].name == name:
            return lvars[i], i
    return None, -1


def _parse_lvar_type(type_text: str):
    """Parse a C type string to a tinfo_t (best-effort, multiple fallbacks)."""
    import ida_typeinf

    text = (type_text or "").strip()
    if not text:
        return None
    flags = ida_typeinf.PT_SIL | ida_typeinf.PT_TYP
    parse_decl = getattr(ida_typeinf, "parse_decl", None)
    if callable(parse_decl):
        candidates = [text]
        if not text.endswith(";"):
            candidates.append(text + ";")
        for candidate in candidates:
            tif = ida_typeinf.tinfo_t()
            try:
                if parse_decl(tif, None, candidate, flags) is not None and not tif.empty():
                    return tif
            except Exception:
                continue
    # named-type fallback
    try:
        tif = ida_typeinf.tinfo_t()
        if tif.get_named_type(None, text):
            return tif
    except Exception:
        pass
    # legacy constructor fallback
    try:
        tif = ida_typeinf.tinfo_t(text, None, ida_typeinf.PT_SIL)
        if not tif.empty():
            return tif
    except Exception:
        pass
    return None


@safety("WRITE")
@title("Set Local Variable (Rename / Retype / Comment)")
@tool
@idasync
@tool_timeout(60.0)
def set_lvar(
    func: Annotated[
        str,
        "Function address (hex like '0x401000') or symbol name containing the local variable.",
    ],
    var: Annotated[
        str,
        "Current name of the local variable to edit (e.g. 'v3', 'a1'). Must match a decompiler local exactly.",
    ],
    name: Annotated[
        Optional[str],
        "New name for the variable. Omit/null to leave the name unchanged.",
    ] = None,
    type: Annotated[
        Optional[str],
        "New C type for the variable (e.g. 'int', 'char *', 'MyStruct *'). Omit/null to leave the type unchanged.",
    ] = None,
    comment: Annotated[
        Optional[str],
        "New decompiler comment to attach to the variable. Omit/null to leave the comment unchanged; pass '' to clear.",
    ] = None,
) -> SetLvarResult:
    """WHAT: Persistently renames, retypes, and/or comments ONE decompiler local variable via modify_user_lvar_info, so the change is saved in the IDB and survives re-decompilation. Unlike the rename-only path elsewhere, this single call can also apply a new C type and a per-variable comment in one transaction, then invalidates the cfunc cache so the next decompile reflects the edit.

WHEN TO USE: After lvar_usage / pseudocode_query reveal what a local actually is -- give it a meaningful name, pin its real type (e.g. promote an int to a struct pointer so the decompiler resolves member accesses), and leave a note. The mutating counterpart to the read-only comprehension tools in this module.

RETURNS: {func, resolved_addr, var, renamed_to?, retyped_to?, commented, applied:[...], error?}. `applied` lists which of name/type/comment actually took effect. `error` is set when the variable is not found, the type will not parse, or Hex-Rays is unavailable; partial success still reports what was applied.

PRO-TIP: Retype first to the real struct/pointer, then rename -- once the type is right the decompiler often reveals member accesses you can name more precisely. PITFALL: this edits IDB metadata, not bytes (it never patches); and a name colliding with an existing local/global is rejected by Hex-Rays, surfacing as an `error` with that field omitted from `applied`."""
    import ida_hexrays

    try:
        if not (var or "").strip():
            return {"func": func, "resolved_addr": None, "var": var,
                    "error": "var (current variable name) is required"}

        start_ea, err = _resolve_func_start(func)
        if err is not None or start_ea is None:
            return {"func": func, "resolved_addr": None, "var": var,
                    "error": err or "Failed to resolve function"}

        if not ida_hexrays.init_hexrays_plugin():
            return {"func": func, "resolved_addr": hex(start_ea), "var": var,
                    "error": "Hex-Rays decompiler is not available"}

        cfunc, derr = get_cached_cfunc(start_ea)
        if cfunc is None or derr is not None:
            return {"func": func, "resolved_addr": hex(start_ea), "var": var,
                    "error": derr or "Decompilation failed"}

        lv, idx = _find_lvar(cfunc, var.strip())
        if lv is None:
            return {"func": func, "resolved_addr": hex(start_ea), "var": var,
                    "error": f"Local variable not found: {var!r}"}

        applied: list[str] = []
        result: SetLvarResult = {
            "func": func,
            "resolved_addr": hex(start_ea),
            "var": var,
            "renamed_to": None,
            "retyped_to": None,
            "commented": False,
            "applied": applied,
            "error": None,
        }
        errors: list[str] = []

        # --- comment ---
        if comment is not None:
            try:
                lsi = ida_hexrays.lvar_saved_info_t()
                lsi.ll = lv
                lsi.name = lv.name
                lsi.type = lv.type()
                lsi.cmt = comment
                ok = ida_hexrays.modify_user_lvar_info(
                    start_ea, ida_hexrays.MLI_CMT, lsi
                )
                if ok:
                    applied.append("comment")
                    result["commented"] = True
                else:
                    errors.append("comment not applied")
            except Exception as e:
                errors.append(f"comment failed: {e}")

        # --- type ---
        if type is not None and str(type).strip():
            tif = _parse_lvar_type(str(type))
            if tif is None:
                errors.append(f"could not parse type: {type!r}")
            else:
                try:
                    lsi = ida_hexrays.lvar_saved_info_t()
                    lsi.ll = lv
                    lsi.name = lv.name
                    lsi.type = tif
                    ok = ida_hexrays.modify_user_lvar_info(
                        start_ea, ida_hexrays.MLI_TYPE, lsi
                    )
                    if ok:
                        applied.append("type")
                        result["retyped_to"] = str(tif)
                    else:
                        errors.append("type not applied")
                except Exception as e:
                    errors.append(f"type failed: {e}")

        # --- name (do last; rename_lvar is the supported persistent path) ---
        if name is not None and str(name).strip():
            new_name = str(name).strip()
            try:
                ok = ida_hexrays.rename_lvar(start_ea, var.strip(), new_name)
                if ok:
                    applied.append("name")
                    result["renamed_to"] = new_name
                else:
                    errors.append(f"rename to {new_name!r} not applied")
            except Exception as e:
                errors.append(f"rename failed: {e}")

        # Invalidate the cfunc cache so downstream decompiles see the edits.
        try:
            ida_hexrays.mark_cfunc_dirty(start_ea)
        except Exception:
            pass
        bump_decompile_dirty(start_ea)

        if errors and not applied:
            result["error"] = "; ".join(errors)
        elif errors:
            result["error"] = "partial: " + "; ".join(errors)
        return result
    except Exception as e:
        return {"func": func, "resolved_addr": None, "var": var, "error": str(e)}


# ============================================================================
# microcode_text -- gen_microcode listing
# ============================================================================


_MATURITIES = (
    "MMAT_GENERATED",
    "MMAT_PREOPTIMIZED",
    "MMAT_LOCOPT",
    "MMAT_CALLS",
    "MMAT_GLBOPT1",
    "MMAT_GLBOPT2",
    "MMAT_GLBOPT3",
    "MMAT_LVARS",
)


def _resolve_maturity(name: str):
    """Resolve a maturity name to its ida_hexrays constant, defaulting safely."""
    import ida_hexrays

    key = (name or "MMAT_GENERATED").strip().upper()
    if not key.startswith("MMAT_"):
        key = "MMAT_" + key
    val = getattr(ida_hexrays, key, None)
    if val is None:
        val = getattr(ida_hexrays, "MMAT_GENERATED", None)
        key = "MMAT_GENERATED"
    return val, key


def _gen_microcode(start_ea: int, maturity_val):
    """Generate microcode for a function up to `maturity_val`.

    Returns (mba_or_None, error_str_or_None). Guards the whole Hex-Rays surface
    so absent/variant builds degrade rather than raise.
    """
    import ida_hexrays

    func = idaapi.get_func(start_ea)
    if func is None:
        return None, f"No function at {hex(start_ea)}"
    try:
        hf = ida_hexrays.hexrays_failure_t()
        mbr = ida_hexrays.mba_ranges_t(func)
        # MMAT_PREOPTIMIZED is the practical floor for a well-formed mba; allow
        # the caller's requested maturity directly.
        mba = ida_hexrays.gen_microcode(
            mbr, hf, None, ida_hexrays.DECOMP_NO_WAIT, maturity_val
        )
        if mba is None:
            msg = ""
            try:
                msg = hf.desc()
            except Exception:
                msg = ""
            return None, msg or "gen_microcode returned no microcode"
        return mba, None
    except Exception as e:
        return None, f"gen_microcode failed: {e}"


def _collect_microcode_lines(mba, cap: int) -> tuple[list[str], bool]:
    """Render the mba to text lines, bounded by `cap`."""
    import ida_hexrays
    import ida_lines

    lines: list[str] = []
    truncated = {"v": False}

    class _Printer(ida_hexrays.vd_printer_t):
        def __init__(self):
            ida_hexrays.vd_printer_t.__init__(self)

        def print(self, indent, line):  # noqa: A003 - SDK signature
            if len(lines) >= cap:
                truncated["v"] = True
                return 0
            try:
                clean = ida_lines.tag_remove(line) if line else ""
            except Exception:
                clean = line or ""
            lines.append(clean.rstrip())
            return 1

    try:
        mba._print(_Printer())
    except Exception:
        # Fallback: iterate blocks and print each.
        try:
            qty = mba.qty
            for i in range(qty):
                if len(lines) >= cap:
                    truncated["v"] = True
                    break
                blk = mba.get_mblock(i)
                p = _Printer()
                try:
                    blk._print(p)
                except Exception:
                    pass
        except Exception:
            pass
    return lines, truncated["v"]


@safety("READ")
@title("Microcode Text (gen_microcode Listing)")
@tool
@idasync
@tool_timeout(90.0)
def microcode_text(
    func: Annotated[
        str,
        "Function address (hex like '0x401000') or symbol name whose microcode is generated.",
    ],
    maturity: Annotated[
        str,
        "Microcode maturity level: MMAT_GENERATED (default), MMAT_PREOPTIMIZED, MMAT_LOCOPT, MMAT_CALLS, MMAT_GLBOPT1/2/3, MMAT_LVARS. Later levels are more optimized (closer to pseudocode).",
    ] = "MMAT_GENERATED",
) -> MicrocodeTextResult:
    """WHAT: Generates the Hex-Rays MICROCODE (the decompiler's SSA-like intermediate representation) for one function at a chosen maturity level and returns it as text lines. MMAT_GENERATED is the raw lifted IR; later maturities (MMAT_GLBOPT*, MMAT_LVARS) progressively optimize toward the final pseudocode.

WHEN TO USE: When pseudocode hides what you need -- to see the IR before/after an optimization pass, inspect how a tricky instruction was lifted, or debug why the decompiler produced a given expression. This is a power-user view below the ctree; for normal comprehension use decompile / pseudocode_query.

RETURNS: {func, resolved_addr, name, maturity, lines:[str], line_count, block_count, truncated, error?}. `lines` is the rendered microcode (tags stripped); truncated=true means the line cap clipped a very large function. `error` is set when Hex-Rays is unavailable or microcode generation fails.

PRO-TIP: Compare MMAT_GENERATED vs MMAT_GLBOPT3 on the same function to see exactly what optimization removed or folded. PITFALL: microcode is verbose and build-specific -- do not parse it as a stable format; treat it as a diagnostic listing, not an API."""
    try:
        start_ea, err = _resolve_func_start(func)
        if err is not None or start_ea is None:
            return {"func": func, "resolved_addr": None, "lines": [],
                    "error": err or "Failed to resolve function"}

        try:
            import ida_hexrays
        except Exception as e:
            return {"func": func, "resolved_addr": hex(start_ea), "lines": [],
                    "error": f"Hex-Rays microcode API unavailable: {e}"}

        if not ida_hexrays.init_hexrays_plugin():
            return {"func": func, "resolved_addr": hex(start_ea), "lines": [],
                    "error": "Hex-Rays decompiler is not available"}

        maturity_val, maturity_name = _resolve_maturity(maturity)
        mba, gerr = _gen_microcode(start_ea, maturity_val)
        if mba is None:
            return {"func": func, "resolved_addr": hex(start_ea),
                    "name": _func_name(start_ea), "maturity": maturity_name,
                    "lines": [], "line_count": 0,
                    "error": gerr or "Microcode generation failed"}

        block_count = 0
        try:
            block_count = int(mba.qty)
        except Exception:
            block_count = 0

        lines, truncated = _collect_microcode_lines(mba, _MAX_MICROCODE_LINES)

        return {
            "func": func,
            "resolved_addr": hex(start_ea),
            "name": _func_name(start_ea),
            "maturity": maturity_name,
            "lines": lines,
            "line_count": len(lines),
            "block_count": block_count,
            "truncated": truncated,
            "error": None,
        }
    except Exception as e:
        return {"func": func, "resolved_addr": None, "lines": [], "error": str(e)}


# ============================================================================
# microcode_calls -- resolved call arguments (MicroCallInfo)
# ============================================================================


def _mop_text(mop) -> str:
    """Render a microcode operand to text, bounded."""
    import ida_lines

    try:
        s = mop._print() if hasattr(mop, "_print") else str(mop)
        if s:
            s = ida_lines.tag_remove(s).strip()
            s = " ".join(s.split())
            if len(s) > _SUBEXPR_CAP:
                return s[:_SUBEXPR_CAP] + "..."
            return s
    except Exception:
        pass
    try:
        return str(mop)
    except Exception:
        return "<mop>"


def _extract_call_args(mci) -> list[dict]:
    """Pull resolved arguments off a mcallinfo_t, bounded."""
    args: list[dict] = []
    try:
        arglist = mci.args
    except Exception:
        return args
    try:
        n = len(arglist)
    except Exception:
        try:
            n = arglist.size()
        except Exception:
            n = 0
    for i in range(min(n, 64)):
        try:
            ca = arglist[i]
        except Exception:
            break
        entry: dict = {"text": _mop_text(ca)}
        try:
            if getattr(ca, "name", None):
                entry["name"] = ca.name
        except Exception:
            pass
        try:
            t = ca.type
            if t is not None:
                entry["type"] = str(t)
        except Exception:
            pass
        args.append(entry)
    return args


@safety("READ")
@title("Microcode Calls (Resolved Call Arguments)")
@tool
@idasync
@tool_timeout(90.0)
def microcode_calls(
    func: Annotated[
        str,
        "Function address (hex like '0x401000') or symbol name whose call sites are resolved at the microcode level.",
    ],
) -> MicrocodeCallsResult:
    """WHAT: Generates microcode at MMAT_CALLS (where call arguments are solidified) and extracts each call instruction's resolved MicroCallInfo -- callee, return type, and the per-argument operands the decompiler recovered. This is the IR-level view of a call site, including typed/indirect calls that pseudocode renders opaquely.

WHEN TO USE: When you need the decompiler's recovered ARGUMENTS for calls -- especially indirect/virtual dispatch or variadic/typed calls where the pseudocode shows a bare pointer. Complements function_skeleton's guarded_calls (which gives the guard) and pseudocode_query calls (which gives the rendered text) with the underlying argument list.

RETURNS: {func, resolved_addr, name, maturity, calls:[{ea, callee, return_type, arg_count, args:[{text,name?,type?}], solid_args, spoiled}], call_count, truncated, error?}. `solid_args` indicates the argument list was fully resolved at this maturity. `error` is set when Hex-Rays is unavailable or microcode generation fails.

PRO-TIP: Use this on an indirect call site where decompile shows '(*v5)(a, b)' to recover the concrete argument expressions and their types. PITFALL: arg recovery depends on the callee's prototype being known -- an untyped indirect target yields generic args; set the call-site type first (set_type / set_lvar) to sharpen it."""
    try:
        start_ea, err = _resolve_func_start(func)
        if err is not None or start_ea is None:
            return {"func": func, "resolved_addr": None, "calls": [],
                    "error": err or "Failed to resolve function"}

        try:
            import ida_hexrays
        except Exception as e:
            return {"func": func, "resolved_addr": hex(start_ea), "calls": [],
                    "error": f"Hex-Rays microcode API unavailable: {e}"}

        if not ida_hexrays.init_hexrays_plugin():
            return {"func": func, "resolved_addr": hex(start_ea), "calls": [],
                    "error": "Hex-Rays decompiler is not available"}

        maturity_val = getattr(ida_hexrays, "MMAT_CALLS", None)
        if maturity_val is None:
            maturity_val, _ = _resolve_maturity("MMAT_CALLS")
        mba, gerr = _gen_microcode(start_ea, maturity_val)
        if mba is None:
            return {"func": func, "resolved_addr": hex(start_ea),
                    "name": _func_name(start_ea), "maturity": "MMAT_CALLS",
                    "calls": [], "call_count": 0,
                    "error": gerr or "Microcode generation failed"}

        calls: list[MicroCall] = []
        truncated = False

        try:
            m_call = getattr(ida_hexrays, "m_call", None)
            qty = int(mba.qty)
            for bi in range(qty):
                if len(calls) >= _MAX_MICRO_CALLS:
                    truncated = True
                    break
                blk = mba.get_mblock(bi)
                ins = blk.head
                while ins is not None:
                    if len(calls) >= _MAX_MICRO_CALLS:
                        truncated = True
                        break
                    try:
                        is_call = (m_call is not None and ins.opcode == m_call)
                    except Exception:
                        is_call = False
                    if is_call:
                        row = _describe_micro_call(ins)
                        if row is not None:
                            calls.append(row)
                    ins = ins.next
        except Exception as e:
            return {"func": func, "resolved_addr": hex(start_ea),
                    "name": _func_name(start_ea), "maturity": "MMAT_CALLS",
                    "calls": calls, "call_count": len(calls),
                    "error": f"microcode walk failed: {e}"}

        return {
            "func": func,
            "resolved_addr": hex(start_ea),
            "name": _func_name(start_ea),
            "maturity": "MMAT_CALLS",
            "calls": calls,
            "call_count": len(calls),
            "truncated": truncated,
            "error": None,
        }
    except Exception as e:
        return {"func": func, "resolved_addr": None, "calls": [], "error": str(e)}


def _describe_micro_call(ins) -> Optional[MicroCall]:
    """Build a MicroCall record from an m_call microinstruction."""
    try:
        ea = getattr(ins, "ea", idaapi.BADADDR)
        row: MicroCall = {
            "ea": hex(ea) if ea != idaapi.BADADDR else None,
            "callee": None,
            "return_type": None,
            "arg_count": 0,
            "args": [],
            "solid_args": False,
            "spoiled": False,
        }
        # The callee operand is ins.l; the mcallinfo is on ins.d.f (for m_call).
        try:
            row["callee"] = _mop_text(ins.l)
        except Exception:
            pass
        mci = None
        try:
            d = ins.d
            mci = getattr(d, "f", None)
        except Exception:
            mci = None
        if mci is not None:
            try:
                if getattr(mci, "return_type", None) is not None:
                    row["return_type"] = str(mci.return_type)
            except Exception:
                pass
            try:
                import ida_hexrays
                flags = getattr(mci, "flags", 0)
                fci_solid = getattr(ida_hexrays, "FCI_NOSIDE", None)
                fci_args = getattr(ida_hexrays, "FCI_FINAL", None)
                if fci_args is not None:
                    row["solid_args"] = bool(flags & fci_args)
            except Exception:
                pass
            args = _extract_call_args(mci)
            row["args"] = args
            row["arg_count"] = len(args)
        return row
    except Exception:
        return None


__all__ = [
    "pseudocode_query",
    "lvar_usage",
    "set_lvar",
    "microcode_text",
    "microcode_calls",
]
