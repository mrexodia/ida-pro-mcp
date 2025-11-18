from typing import Annotated
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

from .rpc import tool, unsafe
from .sync import idaread
from .utils import parse_address, get_function

# ============================================================================
# Python Evaluation
# ============================================================================


@tool
@idaread
@unsafe
def py_eval(
    code: Annotated[str, "Python code"],
) -> dict:
    """Execute Python code in IDA context.
    Returns dict with result/stdout/stderr.
    Has access to all IDA API modules.
    Supports Jupyter-style evaluation."""
    # Capture stdout/stderr
    stdout_capture = io.StringIO()
    stderr_capture = io.StringIO()
    old_stdout = sys.stdout
    old_stderr = sys.stderr

    try:
        sys.stdout = stdout_capture
        sys.stderr = stderr_capture

        # Create execution context with IDA modules (lazy import to avoid errors)
        def lazy_import(module_name):
            try:
                return __import__(module_name)
            except Exception:
                return None

        exec_globals = {
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

        result_value = None

        # Try evaluation first (for simple expressions)
        try:
            result_value = str(eval(code, exec_globals))
        except Exception:
            # Execute as statements
            exec_locals = {}
            exec(code, exec_globals, exec_locals)

            # Merge locals into globals for multi-statement blocks
            exec_globals.update(exec_locals)

            # Try to eval the last line as an expression (Jupyter-style)
            lines = code.strip().split("\n")
            if lines:
                last_line = lines[-1].strip()
                if last_line and not last_line.startswith(
                    (
                        "#",
                        "import ",
                        "from ",
                        "def ",
                        "class ",
                        "if ",
                        "for ",
                        "while ",
                        "with ",
                        "try:",
                    )
                ):
                    try:
                        result_value = str(eval(last_line, exec_globals))
                    except Exception:
                        pass

            # Return 'result' variable if explicitly set
            if result_value is None and "result" in exec_locals:
                result_value = str(exec_locals["result"])

            # Return last assigned variable
            if result_value is None and exec_locals:
                last_key = list(exec_locals.keys())[-1]
                result_value = str(exec_locals[last_key])

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
            "stdout": "",
            "stderr": traceback.format_exc(),
        }
    finally:
        sys.stdout = old_stdout
        sys.stderr = old_stderr
