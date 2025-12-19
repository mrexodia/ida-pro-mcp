# IDA Pro MCP Test Framework

This document provides detailed documentation for the test framework used in ida-pro-mcp.

## Overview

The test framework is a custom, lightweight testing solution designed specifically for testing IDA Pro MCP tools. It supports:

- **Inline tests** - Tests defined right after the functions they test in `api_*.py` files
- **IDA console runner** - Run tests interactively inside IDA Pro
- **Standalone runner** - Run tests headlessly using idalib
- **Code coverage** - Measure code coverage of API implementations
- **Binary-agnostic assertions** - Tests that work on any binary

## Architecture

```
src/ida_pro_mcp/
├── ida_mcp/
│   ├── tests.py              # Test framework core
│   │   ├── @test decorator   # Register test functions
│   │   ├── run_tests()       # Test runner
│   │   ├── TestResults       # Result aggregation
│   │   ├── assert_*          # Assertion helpers
│   │   └── get_any_*         # Test data helpers
│   ├── api_core.py           # Functions + tests
│   ├── api_analysis.py       # Functions + tests
│   └── ...
├── test.py                   # Standalone runner (idalib)
└── ...
```

## Test Registration

### The `@test` Decorator

```python
from .tests import test

@test()
def test_idb_meta():
    """Test description"""
    meta = idb_meta()
    assert_has_keys(meta, "path", "module", "base")
```

#### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `expression` | `str` | `""` | Future: expression for binary-specific tests (NOT IMPLEMENTED) |
| `skip` | `bool` | `False` | Skip this test |

#### Examples

```python
# Basic test
@test()
def test_basic():
    pass

# Skipped test
@test(skip=True)
def test_broken():
    pass
```

### Test Placement

Tests should be placed **immediately after** the function they test:

```python
@tool
@idaread
def idb_meta() -> Metadata:
    """Get IDB metadata"""
    return Metadata(...)


@test()
def test_idb_meta():
    """idb_meta returns valid metadata"""
    meta = idb_meta()
    assert_has_keys(meta, "path", "module")
```

This keeps tests close to implementation and makes it easy to see test coverage.

### Test Auto-Discovery

Tests are automatically discovered and categorized by their module:

```python
# In api_core.py
@test()
def test_idb_meta():  # Registered as category="api_core"
    pass

# In api_analysis.py
@test()
def test_decompile():  # Registered as category="api_analysis"
    pass
```

## Assertion Helpers

Import helpers from `tests.py`:

```python
from .tests import (
    test,
    assert_has_keys,
    assert_valid_address,
    assert_non_empty,
    assert_is_list,
    assert_all_have_keys,
)
```

### `assert_has_keys(d, *keys)`

Assert a dict contains all specified keys:

```python
meta = idb_meta()
assert_has_keys(meta, "path", "module", "base", "size")
```

### `assert_valid_address(addr)`

Assert a string is a valid hex address:

```python
assert_valid_address("0x401000")    # OK
assert_valid_address("-0x10")       # OK (negative)
assert_valid_address("401000")      # FAIL - no 0x prefix
assert_valid_address("not_addr")    # FAIL - not hex
```

### `assert_non_empty(value)`

Assert value is not None and not empty:

```python
assert_non_empty("hello")           # OK
assert_non_empty([1, 2, 3])         # OK
assert_non_empty("")                # FAIL
assert_non_empty([])                # FAIL
assert_non_empty(None)              # FAIL
```

### `assert_is_list(value, min_length=0)`

Assert value is a list with minimum length:

```python
assert_is_list([1, 2, 3])           # OK
assert_is_list([1, 2], min_length=2) # OK
assert_is_list([1], min_length=2)   # FAIL - too short
assert_is_list("string")            # FAIL - not a list
```

### `assert_all_have_keys(items, *keys)`

Assert all dicts in a list have specified keys:

```python
funcs = [{"addr": "0x1", "name": "a"}, {"addr": "0x2", "name": "b"}]
assert_all_have_keys(funcs, "addr", "name")  # OK
assert_all_have_keys(funcs, "addr", "size")  # FAIL - missing "size"
```

## Test Data Helpers

### `get_any_function() -> Optional[str]`

Get address of first function (for tests needing a valid function):

```python
fn_addr = get_any_function()
if not fn_addr:
    return  # Skip test if no functions

result = decompile(fn_addr)
assert result[0]["code"] is not None
```

### `get_any_string() -> Optional[str]`

Get address of first string:

```python
str_addr = get_any_string()
if not str_addr:
    return  # Skip if no strings

result = get_string(str_addr)
assert result[0]["value"] is not None
```

### `get_first_segment() -> Optional[tuple[str, str]]`

Get first segment's (start, end) addresses:

```python
seg = get_first_segment()
if not seg:
    return

start_addr, end_addr = seg
result = get_bytes({"addr": start_addr, "size": 16})
```

## Running Tests

### From IDA Console

```python
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

# Quiet mode (just summary)
run_tests(verbose=False)
```

### From Command Line

```bash
# Basic usage
ida-mcp-test tests/crackme03.elf

# Filter by category
ida-mcp-test tests/crackme03.elf --category api_core

# Filter by pattern
ida-mcp-test tests/crackme03.elf --pattern "*meta*"

# List available tests
ida-mcp-test tests/crackme03.elf --list

# Stop on first failure
ida-mcp-test tests/crackme03.elf --stop-on-failure

# With code coverage
ida-mcp-test tests/crackme03.elf --coverage

# HTML coverage report
ida-mcp-test tests/crackme03.elf --coverage --coverage-report html
```

## Code Coverage

Code coverage is measured using the `coverage` package with `uv run coverage run`.

### Running with Coverage

```bash
# Run tests with coverage
uv run coverage run -m ida_pro_mcp.test crackme03.elf

# Show coverage report in terminal
uv run coverage report --show-missing

# Generate HTML report
uv run coverage html
open htmlcov/index.html

# Generate XML report (for CI)
uv run coverage xml

# Generate JSON report
uv run coverage json

# Combine multiple coverage runs
uv run coverage combine
uv run coverage report
```

### Coverage Configuration

Create a `.coveragerc` file or add to `pyproject.toml`:

```toml
[tool.coverage.run]
source = ["ida_pro_mcp.ida_mcp"]
omit = [
    "*/tests.py",
    "*/zeromcp/*",
    "*/__init__.py",
]

[tool.coverage.report]
exclude_lines = [
    "pragma: no cover",
    "if TYPE_CHECKING:",
    "raise NotImplementedError",
]
```

## Test Patterns

### 1. Schema Validation

Verify return types match expected structure:

```python
@test()
def test_idb_meta():
    """idb_meta returns properly structured metadata"""
    meta = idb_meta()
    assert_has_keys(meta, "path", "module", "base", "size", "md5", "sha256")
    assert_valid_address(meta["base"])
```

### 2. Non-Empty Results

Verify APIs return data on valid binaries:

```python
@test()
def test_list_funcs():
    """list_funcs returns at least one function"""
    result = list_funcs({})
    assert_is_list(result, min_length=1)
    assert_is_list(result[0]["data"], min_length=1)
```

### 3. Error Handling

Verify invalid inputs raise `IDAError`:

```python
from .sync import IDAError

@test()
def test_decompile_invalid():
    """decompile raises IDAError for invalid address"""
    try:
        decompile("0xDEADBEEFDEADBEEF")
        assert False, "Expected IDAError"
    except IDAError:
        pass  # Expected
```

### 4. Referential Integrity

Verify cross-API consistency:

```python
@test()
def test_functions_are_decompilable():
    """Functions from list_funcs can be decompiled"""
    result = list_funcs({"count": 3})
    for fn in result[0]["data"]:
        dec = decompile(fn["addr"])
        # Should either have code or specific error, not crash
        assert "code" in dec[0] or "error" in dec[0]
```

### 5. Round-Trip with Cleanup

Test modifications and restore original state:

```python
@test()
def test_rename_roundtrip():
    """rename function works and can be undone"""
    fn_addr = get_any_function()
    if not fn_addr:
        return

    # Get original name
    original = lookup_funcs(fn_addr)[0]["fn"]["name"]

    try:
        # Rename
        rename({"func": [{"addr": fn_addr, "name": "__test__"}]})

        # Verify
        new_name = lookup_funcs(fn_addr)[0]["fn"]["name"]
        assert new_name == "__test__"
    finally:
        # Restore
        rename({"func": [{"addr": fn_addr, "name": original}]})
```

### 6. Batch Operations

Verify batch input handling:

```python
@test()
def test_batch_operations():
    """Operations handle multiple inputs"""
    result = list_funcs({"count": 3})
    addrs = [fn["addr"] for fn in result[0]["data"]]

    # Batch lookup
    results = lookup_funcs(addrs)
    assert len(results) == len(addrs)
```

## Test Results

### `TestResult` Structure

```python
@dataclass
class TestResult:
    name: str                          # Test function name
    category: str                      # Module category (api_core, etc.)
    status: Literal["passed", "failed", "skipped"]
    duration: float                    # Execution time in seconds
    error: Optional[str]               # Error message if failed
    traceback: Optional[str]           # Full traceback if failed
```

### `TestResults` Aggregate

```python
@dataclass
class TestResults:
    passed: int
    failed: int
    skipped: int
    total_time: float
    results: list[TestResult]
```

### Programmatic Access

```python
results = run_tests(verbose=False)

print(f"Passed: {results.passed}")
print(f"Failed: {results.failed}")

for r in results.results:
    if r.status == "failed":
        print(f"{r.name}: {r.error}")
        print(r.traceback)
```

## Adding New Tests

### Step-by-Step

1. **Identify the function to test** in the appropriate `api_*.py` file

2. **Add imports** at the top of the file:
   ```python
   from .tests import (
       test,
       assert_has_keys,
       assert_valid_address,
       # ... other helpers you need
   )
   ```

3. **Write the test** immediately after the function:
   ```python
   @tool
   @idaread
   def my_function(...):
       ...


   @test()
   def test_my_function():
       """Description of what the test verifies"""
       result = my_function(...)
       assert_has_keys(result, "key1", "key2")
   ```

4. **Run the test**:
   ```bash
   ida-mcp-test tests/crackme03.elf --pattern "test_my_function"
   ```

### Best Practices

1. **Test name**: Use `test_<function_name>` or `test_<function_name>_<scenario>`

2. **Docstring**: First line describes what the test verifies

3. **Binary-agnostic**: Don't hardcode addresses or expected values

4. **Skip gracefully**: Return early if required data isn't available
   ```python
   fn_addr = get_any_function()
   if not fn_addr:
       return  # Skip, don't fail
   ```

5. **Cleanup**: Restore state for tests that modify the IDB
   ```python
   try:
       # Modify
   finally:
       # Restore
   ```

6. **Error handling**: Use `try/except IDAError` for expected errors
