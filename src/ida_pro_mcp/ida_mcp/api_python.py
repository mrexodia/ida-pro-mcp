import ast
import io
import os
import sys
from contextlib import nullcontext
from typing import Annotated, TypedDict

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
import idaapi
import idc

from ._kernel.rpc import tool, safety, title
from ._kernel.sync import idasync
from ._kernel.consent import block_byte_writes
from ._kernel.utils import parse_address, get_function

# Largest script file py_exec_file will read (a guard against a runaway/abusive
# path on a network-reachable server). Real IDAPython scripts are far smaller.
_MAX_SCRIPT_BYTES = 4 * 1024 * 1024


def _create_undo_point() -> None:
    """Best-effort IDA undo checkpoint before an injected script may mutate the
    database, so the user can Edit > Undo a scripted change."""
    try:
        import ida_undo

        ida_undo.create_undo_point(b"ida_mcp", b"py_exec")
    except Exception:
        pass


# ============================================================================
# Shared execution context
# ============================================================================


def _make_exec_globals() -> dict:
    """Build an execution context with all IDA modules available."""

    def lazy_import(module_name):
        try:
            return __import__(module_name)
        except Exception:
            return None

    return {
        "__builtins__": __builtins__,
        "idaapi": idaapi,
        "idc": idc,
        "idautils": lazy_import("idautils"),
        "ida_allins": lazy_import("ida_allins"),
        "ida_auto": lazy_import("ida_auto"),
        "ida_bitrange": lazy_import("ida_bitrange"),
        "ida_bytes": ida_bytes,
        "ida_dbg": ida_dbg,
        "ida_dirtree": lazy_import("ida_dirtree"),
        "ida_diskio": lazy_import("ida_diskio"),
        "ida_entry": ida_entry,
        "ida_expr": lazy_import("ida_expr"),
        "ida_fixup": lazy_import("ida_fixup"),
        "ida_fpro": lazy_import("ida_fpro"),
        "ida_frame": ida_frame,
        "ida_funcs": ida_funcs,
        "ida_gdl": lazy_import("ida_gdl"),
        "ida_graph": lazy_import("ida_graph"),
        "ida_hexrays": ida_hexrays,
        "ida_ida": ida_ida,
        "ida_idd": lazy_import("ida_idd"),
        "ida_idp": lazy_import("ida_idp"),
        "ida_ieee": lazy_import("ida_ieee"),
        "ida_kernwin": ida_kernwin,
        "ida_libfuncs": lazy_import("ida_libfuncs"),
        "ida_lines": ida_lines,
        "ida_loader": lazy_import("ida_loader"),
        "ida_merge": lazy_import("ida_merge"),
        "ida_mergemod": lazy_import("ida_mergemod"),
        "ida_moves": lazy_import("ida_moves"),
        "ida_nalt": ida_nalt,
        "ida_name": ida_name,
        "ida_netnode": lazy_import("ida_netnode"),
        "ida_offset": lazy_import("ida_offset"),
        "ida_pro": lazy_import("ida_pro"),
        "ida_problems": lazy_import("ida_problems"),
        "ida_range": lazy_import("ida_range"),
        "ida_regfinder": lazy_import("ida_regfinder"),
        "ida_registry": lazy_import("ida_registry"),
        "ida_search": lazy_import("ida_search"),
        "ida_segment": ida_segment,
        "ida_segregs": lazy_import("ida_segregs"),
        "ida_srclang": lazy_import("ida_srclang"),
        "ida_strlist": lazy_import("ida_strlist"),
        "ida_struct": lazy_import("ida_struct"),
        "ida_tryblks": lazy_import("ida_tryblks"),
        "ida_typeinf": ida_typeinf,
        "ida_ua": lazy_import("ida_ua"),
        "ida_undo": lazy_import("ida_undo"),
        "ida_xref": ida_xref,
        "ida_enum": lazy_import("ida_enum"),
        "parse_address": parse_address,
        "get_function": get_function,
    }


class PythonExecResult(TypedDict):
    result: str
    stdout: str
    stderr: str


# ============================================================================
# Python Evaluation
# ============================================================================


@safety("EXECUTE")
@title("Evaluate Python (IDA Context)")
@tool
@idasync
def py_eval(
    code: Annotated[
        str,
        "Python source to run inside IDA. May be a single expression, a block of statements, or statements with a trailing expression (Jupyter-style); the trailing expression's value, or a top-level `result` variable, becomes the returned result.",
    ],
    allow_patch: Annotated[
        bool,
        "Permit the snippet to write the analysed program's BYTES (ida_bytes/idc patch_*/put_*). Default false: image-byte writes raise PatchBlockedError so analysis never patches the binary. Set true ONLY when the user explicitly asked to patch (an undo point is created first).",
    ] = False,
) -> PythonExecResult:
    """WHAT: Execute an inline Python snippet in the live IDA process with every common `ida_*` module (plus `idaapi`, `idc`, `idautils`, and the `parse_address`/`get_function` helpers) pre-injected into a single shared namespace, capturing the computed value, stdout, and stderr.

    WHEN-TO-USE: For one-off IDAPython probes and scripted edits that are too specific for a dedicated tool — querying or mutating the database, walking xrefs, reading bytes, driving the decompiler. Prefer `py_exec_file` instead when the script is large or multi-line enough to be unwieldy as an inline string.

    RETURNS: A PythonExecResult with `result` (stringified value of the trailing expression or of a `result` variable, else ""), `stdout`, and `stderr`. Exceptions do not raise — the full traceback is returned in `stderr` (partial stdout preserved).

    PITFALL: This is arbitrary code execution against the open database and can irreversibly modify or corrupt the IDB metadata; there is no sandbox. By DEFAULT (allow_patch=false) image-byte writes — `ida_bytes`/`idc` `patch_*`/`put_*` — are BLOCKED and raise PatchBlockedError, so understanding a binary never patches it (axis-7 rule); pass allow_patch=true only on an explicit user request to patch. To return a value from a statement block, assign it to a variable named `result`."""
    # Capture stdout/stderr
    stdout_capture = io.StringIO()
    stderr_capture = io.StringIO()
    old_stdout = sys.stdout
    old_stderr = sys.stderr

    try:
        sys.stdout = stdout_capture
        sys.stderr = stderr_capture

        # Single shared namespace for globals and locals so closures,
        # recursion and comprehensions resolve names correctly (matching
        # how py_exec_file runs). Using two separate dicts breaks any code
        # that relies on top-level names being visible from nested scopes.
        ns = _make_exec_globals()

        result_value = None

        if allow_patch:
            _create_undo_point()
        # Fence image-byte writes unless the caller explicitly opted in.
        guard = nullcontext() if allow_patch else block_byte_writes()

        with guard:
            # Parse code with AST to properly handle execution
            try:
                tree = ast.parse(code)
            except SyntaxError:
                # If parsing fails, fall back to direct exec
                exec(code, ns, ns)
                if "result" in ns:
                    result_value = str(ns["result"])
            else:
                if not tree.body:
                    # Empty code
                    pass
                elif len(tree.body) == 1 and isinstance(tree.body[0], ast.Expr):
                    # Single expression - use eval
                    result_value = str(eval(code, ns, ns))
                elif isinstance(tree.body[-1], ast.Expr):
                    # Multiple statements, last one is an expression (Jupyter-style)
                    # Execute all statements except the last
                    if len(tree.body) > 1:
                        exec_tree = ast.Module(body=tree.body[:-1], type_ignores=[])
                        exec(
                            compile(exec_tree, "<string>", "exec"),
                            ns,
                            ns,
                        )
                    # Eval only the last expression
                    eval_tree = ast.Expression(body=tree.body[-1].value)
                    result_value = str(
                        eval(compile(eval_tree, "<string>", "eval"), ns, ns)
                    )
                else:
                    # All statements (no trailing expression)
                    exec(code, ns, ns)
                    # Return 'result' variable only if explicitly set. The old
                    # "last assigned variable" heuristic was order-dependent and
                    # unreliable, so it is dropped.
                    if "result" in ns:
                        result_value = str(ns["result"])

        # Collect output
        stdout_text = stdout_capture.getvalue()
        stderr_text = stderr_capture.getvalue()

        return {
            "result": result_value or "",
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


@safety("EXECUTE")
@title("Execute Python Script File (IDA Context)")
@tool
@idasync
def py_exec_file(
    file_path: Annotated[
        str,
        "Absolute path to a UTF-8 Python script file on the IDA host's filesystem. Read and executed as if it were the main module.",
    ],
) -> PythonExecResult:
    """WHAT: Read a Python script from disk and execute its entire contents in the live IDA process via `exec()`, using one shared globals dict (the same pre-injected `ida_*`/`idaapi`/`idc`/helper context as `py_eval`) with `__name__` set to "__main__", capturing the script's stdout and stderr.

    WHEN-TO-USE: For larger or multi-line IDAPython scripts that would be awkward or error-prone to pass as an inline string to `py_eval`. Because it runs with a single namespace (no separate locals dict), top-level `def`/`class`/imports are visible to all nested code in the script — making it the right choice when a snippet relies on its own helper functions or recursion.

    RETURNS: A PythonExecResult with `result` (str of a top-level `result` variable if the script sets one to a non-None value, else ""), `stdout`, and `stderr`. A missing file or any raised exception is reported in `stderr` (partial stdout preserved) rather than raising.

    PITFALL: The path is resolved on the machine running IDA, not the MCP client — pass an absolute path that exists there. Like `py_eval`, this is unsandboxed arbitrary execution that can permanently alter the IDB."""
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
