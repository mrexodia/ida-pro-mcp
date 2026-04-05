"""Advanced Hex-Rays decompiler features for IDA Pro MCP.

Provides tools for microcode access, ctree walking, variable mapping,
and advanced decompiler queries.
"""

from typing import Annotated

import ida_hexrays
import ida_funcs
import idaapi
import idc

from .rpc import tool
from .sync import idasync, IDAError
from .utils import parse_address, normalize_list_input


def _ensure_hexrays():
    if not ida_hexrays.init_hexrays_plugin():
        raise IDAError("Hex-Rays decompiler not available")


# ============================================================================
# Ctree/Variable Tools
# ============================================================================


@tool
@idasync
def decompiler_vars(
    addrs: Annotated[str, "Function addresses or names, comma-separated"],
) -> list[dict]:
    """Get all local variables from the decompiler for function(s).

    Returns variable names, types, storage locations (register/stack),
    and usage information.
    """
    _ensure_hexrays()
    items = normalize_list_input(addrs)
    results = []

    for item in items:
        try:
            ea = parse_address(item)
            func = ida_funcs.get_func(ea)
            if not func:
                results.append({"addr": item, "error": "Not in a function"})
                continue

            cfunc = ida_hexrays.decompile(func.start_ea)
            if not cfunc:
                results.append({"addr": item, "error": "Decompilation failed"})
                continue

            variables = []
            lvars = cfunc.get_lvars()
            for i, lvar in enumerate(lvars):
                var_info = {
                    "index": i,
                    "name": lvar.name or f"v{i}",
                    "type": str(lvar.type()) if lvar.type() else None,
                    "is_arg": lvar.is_arg_var,
                    "is_result": lvar.is_result_var,
                    "is_stk_var": lvar.is_stk_var(),
                    "is_reg_var": lvar.is_reg_var(),
                    "has_user_name": lvar.has_user_name,
                    "has_user_type": lvar.has_user_type,
                    "width": lvar.width,
                }

                if lvar.is_reg_var():
                    var_info["reg"] = lvar.get_reg1_name() or ""
                if lvar.is_stk_var():
                    var_info["stkoff"] = lvar.get_stkoff()

                variables.append(var_info)

            results.append(
                {
                    "func": hex(func.start_ea),
                    "func_name": idc.get_func_name(func.start_ea) or "",
                    "var_count": len(variables),
                    "variables": variables,
                }
            )
        except Exception as e:
            results.append({"addr": item, "error": str(e)})

    return results


@tool
@idasync
def decompiler_labels(
    addrs: Annotated[str, "Function addresses or names, comma-separated"],
) -> list[dict]:
    """Get user-defined labels in decompiled function(s)."""
    _ensure_hexrays()
    items = normalize_list_input(addrs)
    results = []

    for item in items:
        try:
            ea = parse_address(item)
            func = ida_funcs.get_func(ea)
            if not func:
                results.append({"addr": item, "error": "Not in a function"})
                continue

            cfunc = ida_hexrays.decompile(func.start_ea)
            if not cfunc:
                results.append({"addr": item, "error": "Decompilation failed"})
                continue

            labels = []
            user_labels = ida_hexrays.restore_user_labels(func.start_ea)
            if user_labels:
                it = ida_hexrays.user_labels_begin(user_labels)
                while it != ida_hexrays.user_labels_end(user_labels):
                    org_label = ida_hexrays.user_labels_first(it)
                    name = ida_hexrays.user_labels_second(it)
                    labels.append(
                        {
                            "label_num": org_label,
                            "name": name,
                        }
                    )
                    it = ida_hexrays.user_labels_next(it)
                ida_hexrays.user_labels_free(user_labels)

            results.append(
                {
                    "func": hex(func.start_ea),
                    "func_name": idc.get_func_name(func.start_ea) or "",
                    "label_count": len(labels),
                    "labels": labels,
                }
            )
        except Exception as e:
            results.append({"addr": item, "error": str(e)})

    return results


@tool
@idasync
def microcode(
    addr: Annotated[str, "Function address or name"],
    maturity: Annotated[
        int, "Microcode maturity level 0-7 (0=generated, 7=lvars allocated). Default 7."
    ] = 7,
) -> dict:
    """Get microcode for a function at a specified maturity level.

    Maturity levels:
    0 = MMAT_GENERATED (initial)
    1 = MMAT_PREOPTIMIZED
    2 = MMAT_LOCOPT (local optimization)
    3 = MMAT_CALLS (call analysis)
    4 = MMAT_GLBOPT1 (global opt 1)
    5 = MMAT_GLBOPT2 (global opt 2)
    6 = MMAT_GLBOPT3 (global opt 3)
    7 = MMAT_LVARS (local variables allocated)
    """
    _ensure_hexrays()
    ea = parse_address(addr)
    func = ida_funcs.get_func(ea)
    if not func:
        raise IDAError(f"Not in a function: {addr}")

    hf = ida_hexrays.hexrays_failure_t()
    mbr = ida_hexrays.mba_ranges_t(func)
    mba = ida_hexrays.gen_microcode(mbr, hf, None, ida_hexrays.DECOMP_NO_WAIT, maturity)
    if not mba:
        raise IDAError(f"Microcode generation failed: {hf.str}")

    blocks = []
    for i in range(mba.qty):
        mblock = mba.get_mblock(i)
        insns = []
        insn = mblock.head
        while insn:
            insns.append(str(insn.dstr()))
            insn = insn.next

        blocks.append(
            {
                "index": i,
                "start": hex(mblock.start) if hasattr(mblock, "start") else None,
                "end": hex(mblock.end) if hasattr(mblock, "end") else None,
                "serial": mblock.serial,
                "type": mblock.type,
                "insn_count": len(insns),
                "insns": insns,
            }
        )

    return {
        "func": hex(func.start_ea),
        "func_name": idc.get_func_name(func.start_ea) or "",
        "maturity": maturity,
        "block_count": len(blocks),
        "blocks": blocks,
    }


@tool
@idasync
def ctree_summary(
    addrs: Annotated[str, "Function addresses or names, comma-separated"],
) -> list[dict]:
    """Get a summary of the ctree (AST) structure for decompiled function(s).

    Returns counts of different statement/expression types (if/while/for/call/etc.)
    which is useful for understanding function complexity and structure.
    """
    _ensure_hexrays()
    items = normalize_list_input(addrs)
    results = []

    for item in items:
        try:
            ea = parse_address(item)
            func = ida_funcs.get_func(ea)
            if not func:
                results.append({"addr": item, "error": "Not in a function"})
                continue

            cfunc = ida_hexrays.decompile(func.start_ea)
            if not cfunc:
                results.append({"addr": item, "error": "Decompilation failed"})
                continue

            class TreeVisitor(ida_hexrays.ctree_visitor_t):
                def __init__(self):
                    super().__init__(ida_hexrays.CV_FAST)
                    self.stmt_counts = {}
                    self.expr_counts = {}
                    self.call_targets = []
                    self.total_stmts = 0
                    self.total_exprs = 0

                def visit_insn(self, insn):
                    self.total_stmts += 1
                    name = ida_hexrays.get_ctype_name(insn.op)
                    self.stmt_counts[name] = self.stmt_counts.get(name, 0) + 1
                    return 0

                def visit_expr(self, expr):
                    self.total_exprs += 1
                    name = ida_hexrays.get_ctype_name(expr.op)
                    self.expr_counts[name] = self.expr_counts.get(name, 0) + 1

                    # Track call targets
                    if expr.op == ida_hexrays.cot_call:
                        if expr.x and expr.x.op == ida_hexrays.cot_obj:
                            target_name = idc.get_func_name(expr.x.obj_ea) or hex(
                                expr.x.obj_ea
                            )
                            self.call_targets.append(target_name)
                    return 0

            visitor = TreeVisitor()
            visitor.apply_to(cfunc.body, None)

            results.append(
                {
                    "func": hex(func.start_ea),
                    "func_name": idc.get_func_name(func.start_ea) or "",
                    "total_statements": visitor.total_stmts,
                    "total_expressions": visitor.total_exprs,
                    "statement_types": visitor.stmt_counts,
                    "expression_types": visitor.expr_counts,
                    "call_targets": visitor.call_targets,
                }
            )
        except Exception as e:
            results.append({"addr": item, "error": str(e)})

    return results


@tool
@idasync
def set_decompiler_var_type(
    func_addr: Annotated[str, "Function address or name"],
    var_name: Annotated[str, "Variable name"],
    new_type: Annotated[str, "New C type string"],
) -> dict:
    """Set the type of a local variable in the decompiler."""
    _ensure_hexrays()
    ea = parse_address(func_addr)
    func = ida_funcs.get_func(ea)
    if not func:
        raise IDAError(f"Not in a function: {func_addr}")

    cfunc = ida_hexrays.decompile(func.start_ea)
    if not cfunc:
        raise IDAError("Decompilation failed")

    # Find the variable
    lvars = cfunc.get_lvars()
    target_lvar = None
    for lvar in lvars:
        if lvar.name == var_name:
            target_lvar = lvar
            break

    if target_lvar is None:
        raise IDAError(f"Variable not found: {var_name}")

    tif = ida_typeinf.tinfo_t()
    if not tif.get_named_type(None, new_type):
        # Try parsing as a C declaration
        if not ida_typeinf.parse_decl(tif, None, f"{new_type};", ida_typeinf.PT_SIL):
            raise IDAError(f"Cannot parse type: {new_type}")

    import ida_typeinf

    lsi = ida_hexrays.lvar_saved_info_t()
    lsi.ll = target_lvar
    lsi.type = tif
    lsi.name = target_lvar.name
    lsi.flags = ida_hexrays.LVINF_TYPE

    if ida_hexrays.modify_user_lvar_info(func.start_ea, ida_hexrays.MLI_SET_TYPE, lsi):
        return {
            "func": hex(func.start_ea),
            "var": var_name,
            "type": new_type,
            "ok": True,
        }
    else:
        return {
            "func": hex(func.start_ea),
            "var": var_name,
            "error": "Failed to set type",
        }


@tool
@idasync
def set_decompiler_var_name(
    func_addr: Annotated[str, "Function address or name"],
    old_name: Annotated[str, "Current variable name"],
    new_name: Annotated[str, "New variable name"],
) -> dict:
    """Rename a local variable in the decompiler."""
    _ensure_hexrays()
    ea = parse_address(func_addr)
    func = ida_funcs.get_func(ea)
    if not func:
        raise IDAError(f"Not in a function: {func_addr}")

    cfunc = ida_hexrays.decompile(func.start_ea)
    if not cfunc:
        raise IDAError("Decompilation failed")

    lvars = cfunc.get_lvars()
    target_lvar = None
    for lvar in lvars:
        if lvar.name == old_name:
            target_lvar = lvar
            break

    if target_lvar is None:
        raise IDAError(f"Variable not found: {old_name}")

    lsi = ida_hexrays.lvar_saved_info_t()
    lsi.ll = target_lvar
    lsi.name = new_name
    lsi.flags = ida_hexrays.LVINF_NAME

    if ida_hexrays.modify_user_lvar_info(func.start_ea, ida_hexrays.MLI_SET_NAME, lsi):
        return {
            "func": hex(func.start_ea),
            "old_name": old_name,
            "new_name": new_name,
            "ok": True,
        }
    else:
        return {
            "func": hex(func.start_ea),
            "old_name": old_name,
            "error": "Failed to rename",
        }
