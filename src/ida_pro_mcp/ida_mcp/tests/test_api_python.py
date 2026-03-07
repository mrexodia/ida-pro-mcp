"""Tests for api_python API functions."""

from ..framework import test
from ..api_python import py_eval


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
