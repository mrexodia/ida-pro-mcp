# IDA Pro MCP Test Plan

## Overview

This document describes the testing framework for ida-pro-mcp. The framework provides:

1. **In-place tests** - `@test` decorated functions alongside implementations in `api_*.py` files
2. **IDA console runner** - `from ida_mcp.tests import run_tests` for manual testing inside IDA
3. **Standalone idalib runner** - `ida-mcp-test` script for automated headless testing
4. **Binary-agnostic assertions** - Tests that work on any binary without hardcoded values

## Architecture

### File Structure

```
src/ida_pro_mcp/
├── ida_mcp/
│   ├── tests.py              # Test framework (runner, helpers, @test decorator)
│   ├── api_core.py           # + test_* functions for core APIs
│   ├── api_analysis.py       # + test_* functions for analysis APIs
│   ├── api_memory.py         # + test_* functions for memory APIs
│   ├── api_types.py          # + test_* functions for type APIs
│   ├── api_modify.py         # + test_* functions for modification APIs (with cleanup)
│   ├── api_stack.py          # + test_* functions for stack APIs
│   ├── api_resources.py      # + test_* functions for MCP resources
│   └── __init__.py           # Updated to export run_tests
└── ...

devdocs/
├── test-plan.md              # This document
└── test-progress.md          # Progress tracking

crackme03.elf                  # Test binary
```

### Test Registration

Tests are registered using the `@test` decorator from `tests.py`:

```python
from .tests import test

@test()
def test_idb_meta():
    """Test idb_meta returns valid metadata"""
    meta = idb_meta()
    assert_has_keys(meta, "path", "module", "base", "size")
    assert_non_empty(meta["path"])
```

Tests are auto-categorized by their source module (extracted from `func.__module__`).

### Test Storage

```python
# In tests.py
@dataclass
class TestInfo:
    func: Callable
    binary: str
    module: str      # Auto-extracted: "api_core", "api_analysis", etc.

TESTS: dict[str, TestInfo] = {}  # name -> TestInfo
```

## Test Framework API

### `tests.py` Module

```python
# Decorator
def test(binary: str = "", skip: bool = False) -> Callable:
    """Register a test function.

    Args:
        binary: Specific binary to run for
        skip: If True, test will be skipped
    """

# Runner
def run_tests(
    pattern: str = "*",           # Glob pattern for test names
    category: str = "*",          # Filter by module (api_core, api_analysis, etc.)
    verbose: bool = True,         # Print progress
    stop_on_failure: bool = False # Stop at first failure
) -> TestResults:
    """Run registered tests and return results."""

# Results
@dataclass
class TestResults:
    passed: int
    failed: int
    skipped: int
    total_time: float
    results: list[TestResult]

@dataclass
class TestResult:
    name: str
    category: str
    status: Literal["passed", "failed", "skipped"]
    duration: float
    error: Optional[str]       # Error message
    traceback: Optional[str]   # Full traceback for failures

# Helper assertions (for use in test functions)
def assert_valid_address(addr: str) -> None:
    """Assert addr is a valid hex string starting with 0x"""

def assert_has_keys(d: dict, *keys: str) -> None:
    """Assert dict has all specified keys"""

def assert_non_empty(value: Any) -> None:
    """Assert value is not None and not empty"""

def assert_is_list(value: Any, min_length: int = 0) -> None:
    """Assert value is a list with at least min_length items"""

def assert_all_have_keys(items: list[dict], *keys: str) -> None:
    """Assert all dicts in list have specified keys"""

# Helper utilities (for getting test data)
def get_any_function() -> Optional[str]:
    """Returns address of first function, or None if no functions"""

def get_any_string() -> Optional[str]:
    """Returns address of first string, or None if no strings"""

def get_first_segment() -> Optional[tuple[str, str]]:
    """Returns (start_addr, end_addr) of first segment, or None"""
```

### Error Handling in Tests

Tools raise `IDAError` for IDA-specific errors. Tests should catch and assert on these:

```python
from .sync import IDAError

@test()
def test_decompile_invalid_address():
    """decompile raises IDAError for invalid addresses"""
    try:
        decompile("0xDEADBEEFDEADBEEF")
        assert False, "Expected IDAError"
    except IDAError as e:
        assert "not found" in str(e).lower() or "failed" in str(e).lower()
```

### Console Usage

```python
# From IDA Python console:
from ida_mcp.tests import run_tests

# Run all tests
run_tests()

# Run specific category
run_tests(category="api_core")

# Run tests matching pattern
run_tests(pattern="*decompile*")

# Combine filters
run_tests(pattern="test_list_*", category="api_core")

# Stop on first failure
run_tests(stop_on_failure=True)
```

### Standalone Runner

Entry point added to `pyproject.toml`:

```toml
[project.scripts]
ida-mcp-test = "ida_pro_mcp.ida_mcp.tests:main"
```

Usage:

```bash
# Run all tests on the test binary
ida-mcp-test tests/crackme03.elf

# Run specific category
ida-mcp-test tests/crackme03.elf --category api_core

# Run with pattern
ida-mcp-test tests/crackme03.elf --pattern "*meta*"

# Stop on first failure
ida-mcp-test tests/crackme03.elf --stop-on-failure

# Quiet output
ida-mcp-test tests/crackme03.elf --quiet
```

## Test Categories

### Phase 1: Framework + Basic Tests

| Category | Module | Test Count | Priority | Notes |
|----------|--------|------------|----------|-------|
| framework | `tests.py` | - | P0 | Test runner infrastructure |
| core | `api_core.py` | 8-10 | P0 | `idb_meta`, `list_funcs`, `strings`, `int_convert`, etc. |

### Phase 2: Parallel Implementation

| Category | Module | Est. Tests | Priority | Notes |
|----------|--------|------------|----------|-------|
| analysis | `api_analysis.py` | 12-15 | P1 | `decompile`, `disasm`, `xrefs_to`, `callees`, etc. |
| memory | `api_memory.py` | 6-8 | P1 | `get_bytes`, `get_u8/16/32/64`, `get_string` |
| types | `api_types.py` | 6-8 | P2 | `structs`, `struct_info`, `infer_types` |
| modify | `api_modify.py` | 4-6 | P2 | `set_comments`, `rename` (with cleanup) |
| stack | `api_stack.py` | 3-4 | P3 | `stack_frame` |
| resources | `api_resources.py` | 8-10 | P3 | MCP resource endpoints |

**Skipped**: `api_debug.py` and `api_python.py` (marked `@unsafe`)

## Test Patterns

### 1. Schema Validation

Verify return types match expected structure:

```python
@test()
def test_idb_meta_schema():
    """idb_meta returns properly structured metadata"""
    meta = idb_meta()
    assert_has_keys(meta, "path", "module", "base", "size", "md5", "sha256", "crc32", "filesize")
    assert_valid_address(meta["base"])
    assert_valid_address(meta["size"])
```

### 2. Non-Empty Results

Verify APIs return data on valid binaries:

```python
@test()
def test_list_funcs_returns_functions():
    """list_funcs returns at least one function"""
    result = list_funcs({})
    assert_is_list(result, min_length=1)
    page = result[0]
    assert_has_keys(page, "data", "next_offset")
    assert len(page["data"]) > 0
    assert_all_have_keys(page["data"], "addr", "name", "size")
```

### 3. Referential Integrity

Verify cross-API consistency:

```python
@test()
def test_listed_functions_are_valid():
    """Functions from list_funcs can be looked up"""
    result = list_funcs({"count": 5})
    for fn in result[0]["data"][:3]:
        lookup = lookup_funcs(fn["addr"])
        assert lookup[0]["fn"] is not None
        assert lookup[0]["error"] is None
```

### 4. Error Handling

Verify invalid inputs raise IDAError:

```python
@test()
def test_decompile_invalid_address():
    """decompile raises IDAError for invalid addresses"""
    try:
        decompile("0xDEADBEEFDEADBEEF")
        assert False, "Expected IDAError to be raised"
    except IDAError:
        pass  # Expected
```

### 5. Round-Trip with Cleanup

Test modify operations with cleanup:

```python
@test()
def test_set_comment_roundtrip():
    """set_comments can set and clear comments"""
    fn_addr = get_any_function()
    if not fn_addr:
        return  # Skip if no functions

    original_comment = ""  # Assume empty initially
    test_comment = "__TEST_COMMENT_12345__"

    try:
        # Set comment
        result = set_comments({"addr": fn_addr, "comment": test_comment})
        assert result[0].get("ok", False) or "error" not in result[0]
    finally:
        # Cleanup: restore original
        set_comments({"addr": fn_addr, "comment": original_comment})
```

### 6. Batch Operations

Verify batch input handling:

```python
@test()
def test_decompile_batch():
    """decompile handles multiple addresses"""
    result = list_funcs({"count": 3})
    addrs = [fn["addr"] for fn in result[0]["data"]]

    results = decompile(addrs)
    assert len(results) == len(addrs)
    for r in results:
        assert_has_keys(r, "addr")
        assert "code" in r or "error" in r
```

## Output Format

### Verbose Output (default)

```
================================================================================
IDA Pro MCP Test Runner
Binary: crackme03.elf
================================================================================

[api_core] Running 8 tests...
  + test_idb_meta (0.02s)
  + test_idb_meta_schema (0.01s)
  + test_list_funcs_returns_functions (0.15s)
  + test_strings_returns_strings (0.08s)
  x test_int_convert_formats (0.01s)
    AssertionError: Expected 'binary' key in result

    Traceback (most recent call last):
      File ".../api_core.py", line 123, in test_int_convert_formats
        assert "binary" in result["result"]
    AssertionError

  + test_lookup_funcs_by_address (0.03s)
  + test_lookup_funcs_by_name (0.02s)
  - test_segments_permissions (skipped)

[api_analysis] Running 12 tests...
  + test_decompile_valid_function (0.45s)
  ...

================================================================================
Results: 18 passed, 1 failed, 1 skipped (2.34s)
================================================================================
```

### Quiet Mode (`--quiet`)

```
Results: 18 passed, 1 failed, 1 skipped (2.34s)

Failed tests:
  test_int_convert_formats: AssertionError: Expected 'binary' key in result
```

## Implementation Notes

### Thread Safety

- Tests are regular Python functions (no `@idaread`/`@idawrite`)
- The functions they call (`idb_meta`, `decompile`, etc.) handle thread sync
- Test runner executes tests sequentially (no parallel execution)

### idalib Considerations

- When running via idalib, `ida_kernwin` functions may behave differently
- Skip tests that require GUI when running headless
- Use `idapro.open_database()` / `idapro.close_database()` lifecycle in standalone runner

### Cleanup Pattern

Tests that modify state MUST clean up after themselves:

```python
@test()
def test_rename_function():
    fn_addr = get_any_function()
    original_name = get_function_name(fn_addr)

    try:
        rename({"func": [{"addr": fn_addr, "name": "__test_name__"}]})
        # ... assertions ...
    finally:
        rename({"func": [{"addr": fn_addr, "name": original_name}]})
```

### Known Issues to Test

Based on GitHub issues:
- Issue #205: `get_function()` returns input addr instead of `fn.start_ea`
- Issue #200: APIs returning invalid responses
- Issue #208: Strings operation timing out

## Code Coverage

Coverage is configured in `pyproject.toml` to only include project source files:

```toml
[tool.coverage.run]
source = ["src/ida_pro_mcp"]
omit = [
    "*/zeromcp/*",
]

[tool.coverage.report]
exclude_lines = [
    "pragma: no cover",
    "if __name__ == .__main__.:",
    "raise NotImplementedError",
]
```

### Running Coverage

```bash
# Run tests with coverage
uv run coverage run -m ida_pro_mcp.test crackme03.elf

# Show coverage report
uv run coverage report --show-missing

# Generate HTML report
uv run coverage html
open htmlcov/index.html
```

## Future Extensions

### Binary-specific tests

```python
@test(binary="notepad.exe")
def test_notepad_specific():
    """Test specific to notepad.exe"""
    ...
```

### AST Transformation (Future)

Transform `@test` functions to generate JSON-RPC MCP calls for external testing.
