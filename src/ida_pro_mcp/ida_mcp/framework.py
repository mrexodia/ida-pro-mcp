"""IDA Pro MCP Test Framework

This module provides a custom test framework for testing IDA MCP tools.
Tests can be defined inline or in separate test files using the @test decorator.

Usage from IDA console:
    from ida_mcp.tests import run_tests
    run_tests()                    # Run all tests
    run_tests(category="api_core") # Run specific category
    run_tests(pattern="*meta*")    # Run tests matching pattern

Usage from command line:
    ida-mcp-test tests/crackme03.elf
    ida-mcp-test tests/crackme03.elf --category api_core
    ida-mcp-test tests/crackme03.elf --pattern "*meta*"
"""

import fnmatch
import time
import traceback
from dataclasses import dataclass, field
from typing import Any, Callable, Literal, Optional


# ============================================================================
# Test Registry
# ============================================================================


@dataclass
class TestInfo:
    """Information about a registered test."""

    func: Callable
    binary: str  # Specific binary this test applies to
    module: str  # Auto-extracted category: "api_core", "api_analysis", etc.
    skip: bool = False


# Global test registry: name -> TestInfo
TESTS: dict[str, TestInfo] = {}


def test(*, binary: str = "", skip: bool = False) -> Callable:
    """Decorator to register a test function.

    Args:
        binary: Name of the specific binary this test applies to
        skip: If True, test will be skipped

    Example:
        @test()
        def test_idb_meta():
            meta = idb_meta()
            assert_has_keys(meta, "path", "module")

        @test(skip=True)
        def test_broken_feature():
            # This test is skipped
            pass

        @test(binary="crackme03.elf")
        def test_crackme_specific():
            # Only runs for crackme03.elf
            pass
    """

    def decorator(func: Callable) -> Callable:
        # Extract module category from function's module name
        # Handles both inline tests (api_core) and separate test files (test_api_core)
        # e.g., "ida_pro_mcp.ida_mcp.api_core" -> "api_core"
        # e.g., "ida_pro_mcp.ida_mcp.tests.test_api_core" -> "api_core"
        module_name = func.__module__
        if "." in module_name:
            category = module_name.rsplit(".", 1)[-1]
        else:
            category = module_name
        
        # Remove "test_" prefix if present (for separate test files)
        if category.startswith("test_"):
            category = category[5:]

        # Register the test
        TESTS[func.__name__] = TestInfo(
            func=func,
            binary=binary,
            module=category,
            skip=skip,
        )
        return func

    return decorator


# ============================================================================
# Test Results
# ============================================================================


@dataclass
class TestResult:
    """Result of a single test execution."""

    name: str
    category: str
    status: Literal["passed", "failed", "skipped"]
    duration: float = 0.0
    error: Optional[str] = None
    traceback: Optional[str] = None


@dataclass
class TestResults:
    """Aggregate results of a test run."""

    passed: int = 0
    failed: int = 0
    skipped: int = 0
    total_time: float = 0.0
    results: list[TestResult] = field(default_factory=list)

    def add(self, result: TestResult) -> None:
        """Add a test result and update counts."""
        self.results.append(result)
        if result.status == "passed":
            self.passed += 1
        elif result.status == "failed":
            self.failed += 1
        elif result.status == "skipped":
            self.skipped += 1


# ============================================================================
# Assertion Helpers
# ============================================================================


def assert_valid_address(addr: str) -> None:
    """Assert addr is a valid hex string starting with 0x."""
    assert isinstance(addr, str), f"Expected string, got {type(addr).__name__}"
    assert addr.startswith("0x") or addr.startswith("-0x"), (
        f"Expected hex address, got {addr!r}"
    )
    # Verify it's a valid hex number
    try:
        int(addr, 16)
    except ValueError:
        raise AssertionError(f"Invalid hex address: {addr!r}")


def assert_has_keys(d: dict, *keys: str) -> None:
    """Assert dict has all specified keys."""
    assert isinstance(d, dict), f"Expected dict, got {type(d).__name__}"
    missing = [k for k in keys if k not in d]
    assert not missing, f"Missing keys: {missing}"


def assert_non_empty(value: Any) -> None:
    """Assert value is not None and not empty."""
    assert value is not None, "Value is None"
    if hasattr(value, "__len__"):
        assert len(value) > 0, f"Value is empty: {value!r}"


def assert_is_list(value: Any, min_length: int = 0) -> None:
    """Assert value is a list with at least min_length items."""
    assert isinstance(value, list), f"Expected list, got {type(value).__name__}"
    assert len(value) >= min_length, (
        f"Expected at least {min_length} items, got {len(value)}"
    )


def assert_all_have_keys(items: list[dict], *keys: str) -> None:
    """Assert all dicts in list have specified keys."""
    assert_is_list(items)
    for i, item in enumerate(items):
        assert isinstance(item, dict), f"Item {i} is not a dict: {type(item).__name__}"
        missing = [k for k in keys if k not in item]
        assert not missing, f"Item {i} missing keys: {missing}"


# ============================================================================
# Test Configuration
# ============================================================================

# Default sample size for deterministic sampling helpers
# Can be overridden by test runner via set_sample_size()
_sample_size: int = 5


def set_sample_size(n: int) -> None:
    """Set the sample size for deterministic sampling helpers.

    Called by test runner to configure how many items to sample.
    """
    global _sample_size
    _sample_size = max(1, n)


def get_sample_size() -> int:
    """Get the current sample size."""
    return _sample_size


# ============================================================================
# Test Data Helpers
# ============================================================================


def get_any_function() -> Optional[str]:
    """Returns address of first function, or None if no functions.

    Must be called from within IDA context.
    """
    import idautils

    for ea in idautils.Functions():
        return hex(ea)
    return None


def get_any_string() -> Optional[str]:
    """Returns address of first string, or None if no strings.

    Must be called from within IDA context.
    """
    import idaapi

    for i in range(idaapi.get_strlist_qty()):
        si = idaapi.string_info_t()
        if idaapi.get_strlist_item(si, i):
            return hex(si.ea)
    return None


def get_first_segment() -> Optional[tuple[str, str]]:
    """Returns (start_addr, end_addr) of first segment, or None.

    Must be called from within IDA context.
    """
    import idaapi
    import idautils

    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        if seg:
            return (hex(seg.start_ea), hex(seg.end_ea))
    return None


def _deterministic_sample(items: list, n: int) -> list:
    """Select n items deterministically based on binary name.

    Uses hash of (binary_name, item_index) for reproducible but varied selection.
    """
    import hashlib

    if len(items) <= n:
        return items

    binary_name = get_current_binary_name()

    # Create (hash, item) pairs for sorting
    def item_hash(idx: int) -> int:
        key = f"{binary_name}:{idx}".encode()
        return int(hashlib.md5(key).hexdigest(), 16)

    indexed = [(item_hash(i), item) for i, item in enumerate(items)]
    indexed.sort(key=lambda x: x[0])

    return [item for _, item in indexed[:n]]


def get_n_functions(n: Optional[int] = None) -> list[str]:
    """Get N function addresses, deterministically selected.

    Selection is based on binary name for reproducibility across runs.
    Returns up to N addresses (fewer if binary has fewer functions).

    Args:
        n: Number of functions to return. Defaults to global sample_size.
    """
    import idautils

    if n is None:
        n = _sample_size

    all_funcs = [hex(ea) for ea in idautils.Functions()]
    return _deterministic_sample(all_funcs, n)


def get_n_strings(n: Optional[int] = None) -> list[str]:
    """Get N string addresses, deterministically selected.

    Args:
        n: Number of strings to return. Defaults to global sample_size.
    """
    import idaapi

    if n is None:
        n = _sample_size

    all_strings = []
    for i in range(idaapi.get_strlist_qty()):
        si = idaapi.string_info_t()
        if idaapi.get_strlist_item(si, i):
            all_strings.append(hex(si.ea))

    return _deterministic_sample(all_strings, n)


def get_data_address() -> Optional[str]:
    """Get an address in a data segment (not code).

    Useful for testing error paths when code address is expected.
    """
    import idaapi
    import idautils

    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        if seg and not (seg.perm & idaapi.SEGPERM_EXEC):
            # Return first address in non-executable segment
            return hex(seg.start_ea)
    return None


def get_unmapped_address() -> str:
    """Get an address that is not mapped in the binary.

    Useful for testing error paths for invalid addresses.
    """
    return "0xDEADBEEFDEADBEEF"


def get_functions_with_calls() -> list[str]:
    """Get functions that contain call instructions (have callees).

    Useful for testing callees() on functions that actually call others.
    """
    import idaapi
    import idautils

    result = []
    for func_ea in idautils.Functions():
        func = idaapi.get_func(func_ea)
        if not func:
            continue

        # Check if function contains any call instructions
        has_call = False
        for head in idautils.Heads(func.start_ea, func.end_ea):
            insn = idaapi.insn_t()
            if idaapi.decode_insn(insn, head) > 0:
                if insn.itype in [idaapi.NN_call, idaapi.NN_callfi, idaapi.NN_callni]:
                    has_call = True
                    break

        if has_call:
            result.append(hex(func_ea))

    return _deterministic_sample(result, _sample_size)


def get_functions_with_callers() -> list[str]:
    """Get functions that are called by other functions (have callers).

    Useful for testing callers() on functions that are actually called.
    """
    import idaapi
    import idautils

    result = []
    for func_ea in idautils.Functions():
        # Check if this function has any code references to it
        has_caller = False
        for xref in idautils.XrefsTo(func_ea, 0):
            if xref.iscode:
                caller_func = idaapi.get_func(xref.frm)
                if caller_func and caller_func.start_ea != func_ea:
                    has_caller = True
                    break

        if has_caller:
            result.append(hex(func_ea))

    return _deterministic_sample(result, _sample_size)


# ============================================================================
# Test Runner
# ============================================================================


def get_current_binary_name() -> str:
    """Get the name of the currently loaded binary.

    Returns:
        The filename of the current IDB (e.g., "crackme03.elf")
    """
    import idaapi

    return idaapi.get_root_filename()


def run_tests(
    pattern: str = "*",
    category: str = "*",
    verbose: bool = True,
    stop_on_failure: bool = False,
) -> TestResults:
    """Run registered tests and return results.

    Args:
        pattern: Glob pattern to filter test names (e.g., "*meta*")
        category: Filter by module category (e.g., "api_core", "api_analysis")
        verbose: Print progress and results
        stop_on_failure: Stop at first failure

    Returns:
        TestResults with pass/fail counts and individual results
    """
    results = TestResults()
    start_time = time.time()

    # Get current binary name for filtering binary-specific tests
    current_binary = get_current_binary_name()

    # Group tests by category
    tests_by_category: dict[str, list[tuple[str, TestInfo]]] = {}
    for name, info in sorted(TESTS.items()):
        # Filter by pattern
        if not fnmatch.fnmatch(name, pattern):
            continue
        # Filter by category
        if category != "*" and info.module != category:
            continue
        # Filter by binary - skip tests for other binaries
        if info.binary and info.binary != current_binary:
            continue

        if info.module not in tests_by_category:
            tests_by_category[info.module] = []
        tests_by_category[info.module].append((name, info))

    if not tests_by_category:
        if verbose:
            print(f"No tests found matching pattern={pattern!r}, category={category!r}")
        return results

    # Print header
    if verbose:
        print("=" * 80)
        print("IDA Pro MCP Test Runner")
        print("=" * 80)
        print()

    # Run tests by category
    for cat_name in sorted(tests_by_category.keys()):
        tests = tests_by_category[cat_name]
        if verbose:
            print(f"[{cat_name}] Running {len(tests)} tests...")

        for name, info in tests:
            result = _run_single_test(name, info, verbose)
            results.add(result)

            if result.status == "failed" and stop_on_failure:
                if verbose:
                    print()
                    print("Stopping on first failure.")
                break

        if stop_on_failure and results.failed > 0:
            break

        if verbose:
            print()

    results.total_time = time.time() - start_time

    # Print summary
    if verbose:
        print("=" * 80)
        status_parts = []
        if results.passed:
            status_parts.append(f"{results.passed} passed")
        if results.failed:
            status_parts.append(f"{results.failed} failed")
        if results.skipped:
            status_parts.append(f"{results.skipped} skipped")
        print(f"Results: {', '.join(status_parts)} ({results.total_time:.2f}s)")
        print("=" * 80)

    return results


def _run_single_test(name: str, info: TestInfo, verbose: bool) -> TestResult:
    """Run a single test and return the result."""
    # Handle skipped tests
    if info.skip:
        if verbose:
            print(f"  - {name} (skipped)")
        return TestResult(
            name=name,
            category=info.module,
            status="skipped",
        )

    # Run the test
    start_time = time.time()
    try:
        info.func()
        duration = time.time() - start_time

        if verbose:
            print(f"  + {name} ({duration:.2f}s)")

        return TestResult(
            name=name,
            category=info.module,
            status="passed",
            duration=duration,
        )

    except Exception as e:
        duration = time.time() - start_time
        error_msg = str(e)
        tb = traceback.format_exc()

        if verbose:
            print(f"  x {name} ({duration:.2f}s)")
            print(f"    {type(e).__name__}: {error_msg}")
            print()
            # Indent traceback
            for line in tb.strip().split("\n"):
                print(f"    {line}")
            print()

        return TestResult(
            name=name,
            category=info.module,
            status="failed",
            duration=duration,
            error=f"{type(e).__name__}: {error_msg}",
            traceback=tb,
        )
