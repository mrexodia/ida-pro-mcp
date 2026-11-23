from typing import Annotated, TypedDict
import ast
import io
import sys
import idaapi
import idc
import ida_bytes
import ida_dbg
import ida_entry
import ida_frame
import ida_funcs
import ida_hexrays
import ida_ida
import ida_kernwin
import ida_lines
import ida_nalt
import ida_name
import ida_segment
import ida_typeinf
import ida_xref

import os

from .rpc import tool, unsafe
from .sync import idasync
from .utils import parse_address, get_function

# ============================================================================
# Shared execution context
# ============================================================================


_LAZY_EXEC_MODULES = (
    "idautils",
    "ida_allins",
    "ida_auto",
    "ida_bitrange",
    "ida_dirtree",
    "ida_diskio",
    "ida_expr",
    "ida_fixup",
    "ida_fpro",
    "ida_gdl",
    "ida_graph",
    "ida_idd",
    "ida_idp",
    "ida_ieee",
    "ida_libfuncs",
    "ida_loader",
    "ida_merge",
    "ida_mergemod",
    "ida_moves",
    "ida_netnode",
    "ida_offset",
    "ida_pro",
    "ida_problems",
    "ida_range",
    "ida_regfinder",
    "ida_registry",
    "ida_search",
    "ida_segregs",
    "ida_srclang",
    "ida_strlist",
    "ida_struct",
    "ida_tryblks",
    "ida_ua",
    "ida_undo",
    "ida_enum",
)
_CACHED_LAZY_MODULES: dict[str, object] = {}
_PENDING_LAZY_MODULES: list[str] = list(_LAZY_EXEC_MODULES)


def _get_lazy_exec_modules() -> dict[str, object]:
    if _PENDING_LAZY_MODULES:
        still_missing: list[str] = []
        for module_name in _PENDING_LAZY_MODULES:
            try:
                _CACHED_LAZY_MODULES[module_name] = __import__(module_name)
            except Exception:
                still_missing.append(module_name)
        _PENDING_LAZY_MODULES[:] = still_missing
    if _PENDING_LAZY_MODULES:
        resolved = dict(_CACHED_LAZY_MODULES)
        for module_name in _PENDING_LAZY_MODULES:
            resolved[module_name] = None
        return resolved
    return _CACHED_LAZY_MODULES


def _make_exec_globals() -> dict:
    """Build an execution context with all IDA modules available."""
    globals_dict = {
        "__builtins__": __builtins__,
        "idaapi": idaapi,
        "idc": idc,
        "ida_bytes": ida_bytes,
        "ida_dbg": ida_dbg,
        "ida_entry": ida_entry,
        "ida_frame": ida_frame,
        "ida_funcs": ida_funcs,
        "ida_hexrays": ida_hexrays,
        "ida_ida": ida_ida,
        "ida_kernwin": ida_kernwin,
        "ida_lines": ida_lines,
        "ida_nalt": ida_nalt,
        "ida_name": ida_name,
        "ida_segment": ida_segment,
        "ida_typeinf": ida_typeinf,
        "ida_xref": ida_xref,
        "parse_address": parse_address,
        "get_function": get_function,
    }
    globals_dict.update(_get_lazy_exec_modules())
    return globals_dict


class PythonExecResult(TypedDict):
    result: str
    stdout: str
    stderr: str


_persisted_locals: dict = {}


# ============================================================================
# Python Evaluation
# ============================================================================


@tool
@idasync
@unsafe
def py_eval(
    code: Annotated[str, "Python code"],
    new_locals: Annotated[
        bool,
        "False (default): reuse the locals namespace from previous py_eval calls, so variables assigned earlier remain visible (Jupyter-like persistence). True: reset and start with a fresh locals namespace.",
    ] = False,
) -> PythonExecResult:
    """Execute Python in IDA context and return result/stdout/stderr.

    Locals persistence (Jupyter-style): the locals namespace persists across
    calls by default, so variables, imports, and definitions from previous
    calls stay visible. Pass new_locals=True to reset the stored namespace
    and start fresh.

    Note: the globals namespace (IDA modules and helpers) is always rebuilt
    per call; only locals persist. Jupyter-style last-expression return:
    if the code ends with an expression, its value is returned in "result".
    """
    # Capture stdout/stderr
    stdout_capture = io.StringIO()
    stderr_capture = io.StringIO()
    old_stdout = sys.stdout
    old_stderr = sys.stderr

    try:
        sys.stdout = stdout_capture
        sys.stderr = stderr_capture

        exec_globals = _make_exec_globals()
        if new_locals:
            _persisted_locals.clear()
        exec_globals.update(_persisted_locals)

        result_value = None
        exec_locals = _persisted_locals

        # Parse code with AST to properly handle execution
        try:
            tree = ast.parse(code)
        except SyntaxError:
            # If parsing fails, fall back to direct exec
            exec(code, exec_globals, exec_locals)
            exec_globals.update(exec_locals)
            if "result" in exec_locals:
                result_value = str(exec_locals["result"])
            elif exec_locals:
                last_key = list(exec_locals.keys())[-1]
                result_value = str(exec_locals[last_key])
        else:
            if not tree.body:
                # Empty code
                pass
            elif len(tree.body) == 1 and isinstance(tree.body[0], ast.Expr):
                # Single expression - use eval
                result_value = str(eval(code, exec_globals))
            elif isinstance(tree.body[-1], ast.Expr):
                # Multiple statements, last one is an expression (Jupyter-style)
                # Execute all statements except the last
                if len(tree.body) > 1:
                    exec_tree = ast.Module(body=tree.body[:-1], type_ignores=[])
                    exec(
                        compile(exec_tree, "<string>", "exec"),
                        exec_globals,
                        exec_locals,
                    )
                    exec_globals.update(exec_locals)
                # Eval only the last expression
                eval_tree = ast.Expression(body=tree.body[-1].value)
                result_value = str(
                    eval(compile(eval_tree, "<string>", "eval"), exec_globals)
                )
            else:
                # All statements (no trailing expression)
                exec(code, exec_globals, exec_locals)
                exec_globals.update(exec_locals)
                # Return 'result' variable if explicitly set
                if "result" in exec_locals:
                    result_value = str(exec_locals["result"])
                # Return last assigned variable
                elif exec_locals:
                    last_key = list(exec_locals.keys())[-1]
                    result_value = str(exec_locals[last_key])

        # Collect output
        stdout_text = "" if stdout_capture.closed else stdout_capture.getvalue()
        stderr_text = "" if stderr_capture.closed else stderr_capture.getvalue()

        return {
            "result": result_value or "",
            "stdout": stdout_text,
            "stderr": stderr_text,
        }

    except Exception:
        import traceback

        return {
            "result": "",
            "stdout": "" if stdout_capture.closed else stdout_capture.getvalue(),
            "stderr": traceback.format_exc(),
        }
    finally:
        sys.stdout = old_stdout
        sys.stderr = old_stderr


@tool
@idasync
@unsafe
def py_exec_file(
    file_path: Annotated[str, "Absolute path to a Python script to execute"],
) -> PythonExecResult:
    """Execute a Python script file in IDA context and return stdout/stderr.

    Unlike py_eval, this runs the entire file with exec() using a single shared
    globals dict (no locals split), so top-level definitions are visible to all
    code in the script. Handles large scripts that would be unwieldy as inline code.
    """
    if not os.path.isfile(file_path):
        return {"result": "", "stdout": "", "stderr": f"File not found: {file_path}"}

    stdout_capture = io.StringIO()
    stderr_capture = io.StringIO()
    old_stdout = sys.stdout
    old_stderr = sys.stderr

    try:
        sys.stdout = stdout_capture
        sys.stderr = stderr_capture

        exec_globals = _make_exec_globals()
        exec_globals["__file__"] = file_path
        exec_globals["__name__"] = "__main__"
        exec_globals["__package__"] = None

        with open(file_path, "r", encoding="utf-8") as f:
            code = f.read()

        exec(compile(code, file_path, "exec"), exec_globals)

        stdout_text = stdout_capture.getvalue()
        stderr_text = stderr_capture.getvalue()

        result_value = ""
        if "result" in exec_globals and exec_globals["result"] is not None:
            result_value = str(exec_globals["result"])

        return {
            "result": result_value,
            "stdout": stdout_text,
            "stderr": stderr_text,
        }

    except Exception:
        import traceback

        return {
            "result": "",
            "stdout": stdout_capture.getvalue(),
            "stderr": traceback.format_exc(),
        }
    finally:
        sys.stdout = old_stdout
        sys.stderr = old_stderr
