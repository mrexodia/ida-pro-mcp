"""Standalone test runner for IDA Pro MCP using idalib.

Usage:
    ida-mcp-test tests/crackme03.elf
    ida-mcp-test tests/crackme03.elf --category api_core
    ida-mcp-test tests/crackme03.elf --pattern "*meta*"

With coverage:
    uv run coverage run -m ida_pro_mcp.test crackme03.elf
    uv run coverage report
    uv run coverage html
"""

import sys
import argparse
from pathlib import Path

# idapro must go first to initialize idalib
import idapro
import ida_auto


def main() -> int:
    """Entry point for ida-mcp-test command."""
    parser = argparse.ArgumentParser(
        description="Run IDA Pro MCP tests using idalib",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ida-mcp-test tests/crackme03.elf
  ida-mcp-test tests/crackme03.elf --category api_core
  ida-mcp-test tests/crackme03.elf --pattern "*meta*"
  ida-mcp-test tests/crackme03.elf --stop-on-failure

With coverage:
  uv run coverage run -m ida_pro_mcp.test crackme03.elf
  uv run coverage report --show-missing
  uv run coverage html && open htmlcov/index.html
        """,
    )
    parser.add_argument("binary", type=Path, help="Path to binary file to analyze")
    parser.add_argument(
        "--pattern",
        "-p",
        default="*",
        help="Glob pattern to filter test names (default: *)",
    )
    parser.add_argument(
        "--category",
        "-c",
        default="*",
        help="Filter by module category (default: *)",
    )
    parser.add_argument(
        "--stop-on-failure",
        "-x",
        action="store_true",
        help="Stop at first failure",
    )
    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Quiet mode - only show summary",
    )
    parser.add_argument(
        "--list",
        "-l",
        action="store_true",
        help="List available tests without running them",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Show IDA console messages",
    )
    parser.add_argument(
        "--sample-size",
        "-n",
        type=int,
        default=5,
        help="Number of items for sampling-based tests (default: 5)",
    )

    args = parser.parse_args()

    # Check binary exists
    if not args.binary.exists():
        print(f"Error: Binary not found: {args.binary}", file=sys.stderr)
        return 1

    # Configure IDA console output
    if args.verbose:
        idapro.enable_console_messages(True)
    else:
        idapro.enable_console_messages(False)

    # Open database
    print(f"Opening database for: {args.binary}")
    if idapro.open_database(str(args.binary), run_auto_analysis=True):
        print("Error: Failed to open database", file=sys.stderr)
        return 1

    # Wait for auto-analysis
    print("Waiting for auto-analysis...")
    ida_auto.auto_wait()
    print()

    try:
        # Import test framework and API modules AFTER idalib is initialized
        # This triggers the @test decorators to register tests
        from ida_pro_mcp.ida_mcp.framework import run_tests, TESTS, set_sample_size
        
        # Import all test modules to register the tests
        from ida_pro_mcp.ida_mcp.tests import (
            test_api_core,
            test_api_analysis,
            test_api_memory,
            test_api_modify,
            test_api_types,
            test_api_stack,
            test_api_resources,
        )

        # Configure sample size for deterministic sampling helpers
        set_sample_size(args.sample_size)

        # Handle --list
        if args.list:
            print("Available tests:")
            by_category: dict[str, list[str]] = {}
            for name, info in sorted(TESTS.items()):
                if info.module not in by_category:
                    by_category[info.module] = []
                by_category[info.module].append(name)

            for cat in sorted(by_category.keys()):
                print(f"\n[{cat}]")
                for name in by_category[cat]:
                    info = TESTS[name]
                    skip_marker = " (skip)" if info.skip else ""
                    print(f"  {name}{skip_marker}")
            return 0

        # Run tests
        results = run_tests(
            pattern=args.pattern,
            category=args.category,
            verbose=not args.quiet,
            stop_on_failure=args.stop_on_failure,
        )

        # In quiet mode, print summary
        if args.quiet:
            status_parts = []
            if results.passed:
                status_parts.append(f"{results.passed} passed")
            if results.failed:
                status_parts.append(f"{results.failed} failed")
            if results.skipped:
                status_parts.append(f"{results.skipped} skipped")
            print(f"Results: {', '.join(status_parts)} ({results.total_time:.2f}s)")

            if results.failed:
                print("\nFailed tests:")
                for r in results.results:
                    if r.status == "failed":
                        print(f"  {r.name}: {r.error}")

        return 1 if results.failed > 0 else 0

    finally:
        # Close database
        idapro.close_database()


if __name__ == "__main__":
    sys.exit(main())
