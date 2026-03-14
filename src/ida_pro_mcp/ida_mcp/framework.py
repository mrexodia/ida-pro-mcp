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
from types import UnionType
from typing import (
    Annotated,
    Any,
    Callable,
    Literal,
    NotRequired,
    Optional,
    Required,
    Union,
    get_args,
    get_origin,
    get_type_hints,
    is_typeddict,
)


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


class SkipTest(Exception):
    """Raised by tests to indicate a runtime skip condition."""


def skip_test(reason: str = "") -> None:
    """Skip the current test at runtime."""
    raise SkipTest(reason or "skipped")


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
    try:
        int(addr, 16)
    except ValueError:
        raise AssertionError(f"Invalid hex address: {addr!r}")


@dataclass(frozen=True)
class OptionalShape:
    schema: Any


@dataclass(frozen=True)
class ListOfShape:
    schema: Any
    min_length: int = 0
    max_length: int | None = None


@dataclass(frozen=True)
class OneOfShape:
    schemas: tuple[Any, ...]


def optional(schema: Any) -> OptionalShape:
    """Allow a key/value to be missing or None, otherwise validate against schema."""
    return OptionalShape(schema)


def list_of(
    schema: Any, *, min_length: int = 0, max_length: int | None = None
) -> ListOfShape:
    """Validate a list where every element matches schema."""
    return ListOfShape(schema, min_length=min_length, max_length=max_length)


def one_of(*schemas: Any) -> OneOfShape:
    """Validate a value against any one of the supplied schemas."""
    return OneOfShape(tuple(schemas))


def is_hex_address(value: Any) -> bool:
    try:
        assert_valid_address(value)
    except AssertionError:
        return False
    return True


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


def assert_has_keys(mapping: Any, *keys: str) -> None:
    """Assert mapping contains the requested keys."""
    assert isinstance(mapping, dict), f"Expected dict, got {type(mapping).__name__}"
    missing = [key for key in keys if key not in mapping]
    assert not missing, f"Missing keys: {', '.join(repr(key) for key in missing)}"


def _assert_shape(value: Any, schema: Any, path: str) -> None:
    if isinstance(schema, OptionalShape):
        if value is None:
            return
        return _assert_shape(value, schema.schema, path)

    if isinstance(schema, OneOfShape):
        errors = []
        for option in schema.schemas:
            try:
                _assert_shape(value, option, path)
                return
            except AssertionError as e:
                errors.append(str(e))
        raise AssertionError(
            f"{path} did not match any allowed schema: {'; '.join(errors)}"
        )

    if isinstance(schema, ListOfShape):
        assert isinstance(value, list), (
            f"{path}: expected list, got {type(value).__name__}"
        )
        assert len(value) >= schema.min_length, (
            f"{path}: expected at least {schema.min_length} items, got {len(value)}"
        )
        if schema.max_length is not None:
            assert len(value) <= schema.max_length, (
                f"{path}: expected at most {schema.max_length} items, got {len(value)}"
            )
        for i, item in enumerate(value):
            _assert_shape(item, schema.schema, f"{path}[{i}]")
        return

    if isinstance(schema, dict):
        assert isinstance(value, dict), (
            f"{path}: expected dict, got {type(value).__name__}"
        )
        for key, subschema in schema.items():
            if isinstance(subschema, OptionalShape):
                if key not in value or value[key] is None:
                    continue
                _assert_shape(value[key], subschema.schema, f"{path}.{key}")
                continue
            assert key in value, f"{path}: missing key {key!r}"
            _assert_shape(value[key], subschema, f"{path}.{key}")
        return

    if isinstance(schema, list):
        assert len(schema) == 1, "List schema must contain exactly one item schema"
        return _assert_shape(value, list_of(schema[0]), path)

    if schema is Any:
        return

    if is_typeddict(schema):
        return assert_typed_dict(value, schema, label=path)

    if isinstance(schema, type):
        assert isinstance(value, schema), (
            f"{path}: expected {schema.__name__}, got {type(value).__name__}"
        )
        return

    if callable(schema):
        assert schema(value), f"{path}: predicate failed for value {value!r}"
        return

    assert value == schema, f"{path}: expected {schema!r}, got {value!r}"


def assert_shape(value: Any, schema: Any, *, label: str = "value") -> None:
    """Assert an ad-hoc response shape.

    Schema supports:
    - Python types (str, int, dict, ...)
    - callables returning truthy/falsey
    - dicts of key -> schema
    - [schema] for homogeneous lists
    - optional(schema), list_of(schema), one_of(...)
    - TypedDict classes
    """
    _assert_shape(value, schema, label)


def _normalize_expected_type(tp: Any) -> Any:
    origin = get_origin(tp)
    while origin in (Annotated, Required, NotRequired):
        tp = get_args(tp)[0]
        origin = get_origin(tp)
    return tp


def _assert_type_matches(value: Any, tp: Any, path: str) -> None:
    tp = _normalize_expected_type(tp)
    origin = get_origin(tp)

    if tp is Any:
        return

    if origin in (Union, UnionType):
        errors = []
        for arg in get_args(tp):
            try:
                _assert_type_matches(value, arg, path)
                return
            except AssertionError as e:
                errors.append(str(e))
        raise AssertionError(f"{path}: no union variant matched: {'; '.join(errors)}")

    if origin is Literal:
        allowed = get_args(tp)
        assert value in allowed, f"{path}: expected one of {allowed!r}, got {value!r}"
        return

    if origin is list:
        assert isinstance(value, list), (
            f"{path}: expected list, got {type(value).__name__}"
        )
        args = get_args(tp)
        if args:
            for i, item in enumerate(value):
                _assert_type_matches(item, args[0], f"{path}[{i}]")
        return

    if origin is dict:
        assert isinstance(value, dict), (
            f"{path}: expected dict, got {type(value).__name__}"
        )
        args = get_args(tp)
        if len(args) == 2:
            key_tp, val_tp = args
            for key, item in value.items():
                _assert_type_matches(key, key_tp, f"{path}.keys()")
                _assert_type_matches(item, val_tp, f"{path}[{key!r}]")
        return

    if origin is tuple:
        assert isinstance(value, tuple), (
            f"{path}: expected tuple, got {type(value).__name__}"
        )
        args = get_args(tp)
        if len(args) == 2 and args[1] is Ellipsis:
            for i, item in enumerate(value):
                _assert_type_matches(item, args[0], f"{path}[{i}]")
        elif args:
            assert len(value) == len(args), (
                f"{path}: expected tuple of length {len(args)}, got {len(value)}"
            )
            for i, (item, item_tp) in enumerate(zip(value, args)):
                _assert_type_matches(item, item_tp, f"{path}[{i}]")
        return

    if is_typeddict(tp):
        return assert_typed_dict(value, tp, label=path)

    if isinstance(tp, type):
        assert isinstance(value, tp), (
            f"{path}: expected {tp.__name__}, got {type(value).__name__}"
        )


def assert_typed_dict(
    value: Any, typed_dict_cls: type, *, label: str = "value"
) -> None:
    """Assert a dict conforms to a TypedDict definition."""
    assert is_typeddict(typed_dict_cls), f"{typed_dict_cls!r} is not a TypedDict"
    assert isinstance(value, dict), (
        f"{label}: expected dict, got {type(value).__name__}"
    )

    annotations = get_type_hints(typed_dict_cls, include_extras=True)
    required = set(getattr(typed_dict_cls, "__required_keys__", annotations.keys()))

    missing = [key for key in sorted(required) if key not in value]
    assert not missing, f"{label}: missing required keys {missing}"

    for key, expected_type in annotations.items():
        if key in value:
            _assert_type_matches(value[key], expected_type, f"{label}.{key}")


def assert_ok(result: dict, *required_keys: str) -> None:
    """Assert a result dict represents success and contains required keys."""
    assert isinstance(result, dict), f"Expected dict, got {type(result).__name__}"
    error = result.get("error")
    assert error in (None, ""), f"Expected success, got error: {error!r}"
    for key in required_keys:
        assert key in result, f"Missing key: {key}"
        assert result[key] is not None, f"Expected non-None value for key: {key}"


def assert_error(result: dict, *, contains: str | None = None) -> None:
    """Assert a result dict represents an error."""
    assert isinstance(result, dict), f"Expected dict, got {type(result).__name__}"
    error = result.get("error")
    assert isinstance(error, str) and error, f"Expected non-empty error, got {error!r}"
    if contains is not None:
        assert contains in error, f"Expected {contains!r} in error {error!r}"


# ============================================================================
# Test Configuration
# ============================================================================

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


def get_named_function(name: str) -> Optional[str]:
    """Return the address of a named function, or None if it does not exist."""
    import idaapi

    ea = idaapi.get_name_ea(idaapi.BADADDR, name)
    if ea == idaapi.BADADDR:
        return None
    func = idaapi.get_func(ea)
    if not func:
        return None
    return hex(func.start_ea)


def get_named_address(name: str) -> Optional[str]:
    """Return the address of any named item, or None if absent."""
    import idaapi

    ea = idaapi.get_name_ea(idaapi.BADADDR, name)
    if ea == idaapi.BADADDR:
        return None
    return hex(ea)


def get_string_address_containing(text: str) -> Optional[str]:
    """Return the address of the first string containing text, or None."""
    import idaapi
    import idc

    for i in range(idaapi.get_strlist_qty()):
        si = idaapi.string_info_t()
        if not idaapi.get_strlist_item(si, i):
            continue
        raw = idc.get_strlit_contents(si.ea, -1, 0)
        if not raw:
            continue
        try:
            decoded = raw.decode("utf-8", errors="replace")
        except Exception:
            continue
        if text in decoded:
            return hex(si.ea)
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
    failures_only: bool = False,
) -> TestResults:
    """Run registered tests and return results.

    Args:
        pattern: Glob pattern to filter test names (e.g., "*meta*")
        category: Filter by module category (e.g., "api_core", "api_analysis")
        verbose: Print progress and results for every test
        stop_on_failure: Stop at first failure
        failures_only: Print only failing tests (useful in non-interactive CI logs)

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
        if verbose or failures_only:
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
            result = _run_single_test(name, info, verbose, failures_only)
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
    if verbose or failures_only:
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
        if verbose:
            print("=" * 80)

    return results


def _run_single_test(
    name: str, info: TestInfo, verbose: bool, failures_only: bool = False
) -> TestResult:
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

    except SkipTest as e:
        duration = time.time() - start_time
        if verbose:
            reason = str(e) or "skipped"
            print(f"  - {name} ({reason})")
        return TestResult(
            name=name,
            category=info.module,
            status="skipped",
            duration=duration,
            error=str(e) or None,
        )

    except Exception as e:
        duration = time.time() - start_time
        error_msg = str(e)
        tb = traceback.format_exc()

        if verbose or failures_only:
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
