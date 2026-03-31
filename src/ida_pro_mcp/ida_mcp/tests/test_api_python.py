"""Tests for api_python API functions."""

import contextlib
import os
import tempfile

from ..framework import test
from ..api_python import py_eval, py_exec_file


@contextlib.contextmanager
def _tmp_script(content):
    """Write content to a temporary .py file, yield its path, then clean up."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False, encoding="utf-8") as f:
        f.write(content)
    try:
        yield f.name
    finally:
        os.unlink(f.name)


@test()
def test_py_eval_expression_result():
    """py_eval evaluates a single expression and returns its value as text."""
    result = py_eval("1 + 2")
    assert result["result"] == "3"
    assert result["stdout"] == ""
    assert result["stderr"] == ""


@test()
def test_py_eval_jupyter_style_last_expression():
    """py_eval returns the trailing expression value after executing prior statements."""
    result = py_eval("x = 40\ny = 2\nx + y")
    assert result["result"] == "42"
    assert result["stderr"] == ""


@test()
def test_py_eval_stdout_capture():
    """py_eval captures stdout separately from the result value."""
    result = py_eval('print("hello from ida")\nresult = 7')
    assert result["result"] == "7"
    assert result["stdout"] == "hello from ida\n"
    assert result["stderr"] == ""


@test()
def test_py_eval_stderr_capture():
    """py_eval captures explicit stderr output."""
    code = 'import sys\nsys.stderr.write("warn\\n")\nresult = "done"'
    result = py_eval(code)
    assert result["result"] == "done"
    assert result["stdout"] == ""
    assert result["stderr"] == "warn\n"


@test(binary="crackme03.elf")
def test_py_eval_has_access_to_ida_modules_and_helpers():
    """py_eval exposes IDA modules plus helper functions like get_function()."""
    result = py_eval('hex(idaapi.get_imagebase()), get_function(0x123e)["name"]')
    assert result["stderr"] == ""
    assert result["result"] == "('0x0', 'main')"


@test()
def test_py_eval_exception_goes_to_stderr():
    """py_eval returns traceback text in stderr when code raises an exception."""
    result = py_eval('raise RuntimeError("boom")')
    assert result["result"] == ""
    assert result["stdout"] == ""
    assert "RuntimeError: boom" in result["stderr"]


@test()
def test_py_exec_file_runs_script_and_captures_stdout():
    """py_exec_file executes a script file and captures its stdout."""
    with _tmp_script('print("hello from file")\nresult = 42\n') as path:
        out = py_exec_file(path)
        assert out["stdout"] == "hello from file\n"
        assert out["result"] == "42"
        assert out["stderr"] == ""


@test()
def test_py_exec_file_returns_error_for_missing_file():
    """py_exec_file returns an error in stderr when the file doesn't exist."""
    out = py_exec_file("/nonexistent/script.py")
    assert "File not found" in out["stderr"]
    assert out["result"] == ""


@test()
def test_py_exec_file_shared_globals():
    """py_exec_file uses shared globals so top-level defs are visible later in the script."""
    with _tmp_script('def add(a, b): return a + b\nresult = add(3, 4)\n') as path:
        out = py_exec_file(path)
        assert out["result"] == "7"
        assert out["stderr"] == ""


@test()
def test_py_exec_file_sets_dunder_file():
    """py_exec_file sets __file__ in the execution context."""
    with _tmp_script('result = __file__\n') as path:
        out = py_exec_file(path)
        assert out["result"] == path
        assert out["stderr"] == ""


@test()
def test_py_exec_file_sets_dunder_name_main():
    """py_exec_file should execute scripts as __main__ so __name__ guards run."""
    script = 'if __name__ == "__main__":\n    result = "ran"\nelse:\n    result = __name__\n'
    with _tmp_script(script) as path:
        out = py_exec_file(path)
        assert out["result"] == "ran"
        assert out["stderr"] == ""


@test()
def test_py_exec_file_captures_exception_in_stderr():
    """py_exec_file captures script exceptions in stderr."""
    with _tmp_script('raise ValueError("script error")\n') as path:
        out = py_exec_file(path)
        assert "ValueError: script error" in out["stderr"]
        assert out["result"] == ""
