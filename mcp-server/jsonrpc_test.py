"""
Comprehensive JSON-RPC 2.0 test suite for MCP implementation
"""
import json
import sys
import traceback
import re
from typing import Optional, Any

from jsonrpc import JsonRpcRegistry

# Create registry and register test methods
jsonrpc = JsonRpcRegistry()

@jsonrpc.method
def subtract(minuend: int, subtrahend: int) -> int:
    return minuend - subtrahend

@jsonrpc.method
def sum_array(numbers: list) -> int:
    return sum(numbers)

@jsonrpc.method
def update(a: int, b: int, c: int, d: int, e: int) -> str:
    return "updated"

@jsonrpc.method
def foobar() -> str:
    return "bar"

@jsonrpc.method
def notify_hello(value: int) -> None:
    pass

@jsonrpc.method
def notify_sum(a: int, b: int, c: int) -> None:
    pass

@jsonrpc.method
def get_data() -> list:
    return ["hello", 5]

@jsonrpc.method
def greet(name: str, greeting: str = "Hello") -> str:
    return f"{greeting}, {name}!"

@jsonrpc.method
def process_optional(value: Optional[int]) -> str:
    return f"Got: {value}"

@jsonrpc.method
def union_test(id: int | str) -> str:
    return f"ID: {id}"

@jsonrpc.method
def list_test(items: list[str]) -> int:
    return len(items)


def matches_response(actual: dict | None, expected: dict | None) -> bool:
    """Check if actual response matches expected, with regex support for error messages."""
    if actual is None and expected is None:
        return True
    if actual is None or expected is None:
        return False

    # Check top-level keys
    if set(actual.keys()) != set(expected.keys()):
        return False

    for key in expected.keys():
        actual_val = actual[key]
        expected_val = expected[key]

        # Handle error object specially for regex matching
        if key == "error" and isinstance(expected_val, dict) and isinstance(actual_val, dict):
            # Check code exactly
            if actual_val.get("code") != expected_val.get("code"):
                return False

            # Check message with regex support
            expected_msg = expected_val.get("message", "")
            actual_msg = actual_val.get("message", "")
            if isinstance(expected_msg, str) and expected_msg.startswith("regex:"):
                pattern = expected_msg[6:]  # Remove "regex:" prefix
                if not re.search(pattern, actual_msg):
                    return False
            else:
                if actual_msg != expected_msg:
                    return False

            # For data field, support regex patterns
            if "data" in expected_val:
                expected_data = expected_val["data"]
                actual_data = actual_val.get("data", "")

                # If expected_data starts with "regex:", treat it as a regex pattern
                if isinstance(expected_data, str) and expected_data.startswith("regex:"):
                    pattern = expected_data[6:]  # Remove "regex:" prefix
                    if not re.search(pattern, str(actual_data)):
                        return False
                else:
                    # Exact match
                    if actual_data != expected_data:
                        return False
            elif "data" in actual_val:
                # Actual has data but expected doesn't - that's ok
                pass
        else:
            # Exact match for other fields
            if actual_val != expected_val:
                return False

    return True


def test_rpc(request: Any, expected_response: dict | None = None, description: str = ""):
    """Helper to test RPC calls"""
    print(f"\n{'='*60}")
    print(f"Test: {description}")
    print(f"--> {request}")

    try:
        result = jsonrpc.dispatch(request)
    except Exception as e:
        print(f"\n❌ UNEXPECTED EXCEPTION:")
        traceback.print_exc()
        sys.exit(1)

    if result is None:
        print("<-- (no response - notification)")
        if expected_response is not None:
            print(f"\n❌ FAIL: Expected response but got None")
            print(f"Expected: {json.dumps(expected_response, indent=2)}")
            sys.exit(1)
    else:
        result_json = json.dumps(result, indent=2)
        print(f"<-- {result_json}")

        if expected_response is not None:
            if not matches_response(result, expected_response):
                print(f"\n❌ FAIL: Response mismatch")
                print(f"Expected: {json.dumps(expected_response, indent=2)}")
                print(f"Got:      {result_json}")
                sys.exit(1)

    print("✓ PASS")
    return result


def run_all_tests():
    print("="*60)
    print("JSON-RPC 2.0 COMPLIANCE TESTS")
    print("="*60)

    # ========================================
    # SPEC EXAMPLES
    # ========================================

    # Positional parameters
    test_rpc(
        {"jsonrpc": "2.0", "method": "subtract", "params": [42, 23], "id": 1},
        {"jsonrpc": "2.0", "result": 19, "id": 1},
        "Positional params - subtract(42, 23)"
    )

    test_rpc(
        '{"jsonrpc": "2.0", "method": "subtract", "params": [23, 42], "id": 2}',
        {"jsonrpc": "2.0", "result": -19, "id": 2},
        "Positional params - subtract(23, 42)"
    )

    # Named parameters
    test_rpc(
        '{"jsonrpc": "2.0", "method": "subtract", "params": {"subtrahend": 23, "minuend": 42}, "id": 3}',
        {"jsonrpc": "2.0", "result": 19, "id": 3},
        "Named params - order independent (1)"
    )

    test_rpc(
        '{"jsonrpc": "2.0", "method": "subtract", "params": {"minuend": 42, "subtrahend": 23}, "id": 4}',
        {"jsonrpc": "2.0", "result": 19, "id": 4},
        "Named params - order independent (2)"
    )

    # Notifications (no response)
    test_rpc(
        '{"jsonrpc": "2.0", "method": "update", "params": [1,2,3,4,5]}',
        None,
        "Notification - update (no id)"
    )

    test_rpc(
        '{"jsonrpc": "2.0", "method": "foobar"}',
        None,
        "Notification - foobar (no params, no id)"
    )

    # Non-existent method
    test_rpc(
        '{"jsonrpc": "2.0", "method": "does_not_exist", "id": "1"}',
        {"jsonrpc": "2.0", "error": {"code": -32601, "message": "regex:Method.*not found"}, "id": "1"},
        "Non-existent method error"
    )

    # Invalid JSON - use regex to match error since different parsers give different messages
    test_rpc(
        '{"jsonrpc": "2.0", "method": "foobar, "params": "bar", "baz]',
        {"jsonrpc": "2.0", "error": {"code": -32700, "message": "JSON parse error", "data": "regex:Expecting"}, "id": None},
        "Parse error - invalid JSON"
    )

    test_rpc(
        1234,
        {"jsonrpc": "2.0", "error": {"code": -32700, "message": "JSON parse error", "data": "regex:object must be"}, "id": None},
        "Parse error - invalid JSON"
    )

    # Invalid Request object - method is not a string
    test_rpc(
        '{"jsonrpc": "2.0", "method": 1, "params": "bar"}',
        {"jsonrpc": "2.0", "error": {"code": -32600, "message": "Invalid request: 'method' must be a string"}, "id": None},
        "Invalid Request - method is number"
    )

    # Missing jsonrpc version
    test_rpc(
        '{"method": "subtract", "params": [1, 2], "id": 1}',
        {"jsonrpc": "2.0", "error": {"code": -32600, "message": "Invalid request: 'jsonrpc' must be '2.0'"}, "id": None},
        "Invalid Request - missing jsonrpc field"
    )

    # Wrong jsonrpc version
    test_rpc(
        '{"jsonrpc": "1.0", "method": "subtract", "params": [1, 2], "id": 1}',
        {"jsonrpc": "2.0", "error": {"code": -32600, "message": "Invalid request: 'jsonrpc' must be '2.0'"}, "id": None},
        "Invalid Request - wrong jsonrpc version"
    )

    # Missing method
    test_rpc(
        '{"jsonrpc": "2.0", "params": [1, 2], "id": 1}',
        {"jsonrpc": "2.0", "error": {"code": -32600, "message": "Invalid request: 'method' is required"}, "id": None},
        "Invalid Request - missing method"
    )

    # Empty array (not valid single request)
    test_rpc(
        '[]',
        {"jsonrpc": "2.0", "error": {"code": -32600, "message": "Invalid request: must be a JSON object"}, "id": None},
        "Invalid Request - empty array"
    )

    # Non-object request
    test_rpc(
        '"not an object"',
        {"jsonrpc": "2.0", "error": {"code": -32600, "message": "Invalid request: must be a JSON object"}, "id": None},
        "Invalid Request - string instead of object"
    )

    test_rpc(
        '123',
        {"jsonrpc": "2.0", "error": {"code": -32600, "message": "Invalid request: must be a JSON object"}, "id": None},
        "Invalid Request - number instead of object"
    )

    # Request with id: null (valid request, not a notification)
    test_rpc(
        '{"jsonrpc": "2.0", "method": "foobar", "id": null}',
        {"jsonrpc": "2.0", "result": "bar", "id": None},
        "Valid request with id: null"
    )

    # ========================================
    # PARAMETER VALIDATION TESTS
    # ========================================

    # Wrong number of positional params - too few
    test_rpc(
        '{"jsonrpc": "2.0", "method": "subtract", "params": [42], "id": 1}',
        {"jsonrpc": "2.0", "error": {"code": -32602, "message": "Invalid params: expected at least 2 arguments, got 1"}, "id": 1},
        "Invalid params - too few positional arguments"
    )

    # Wrong number of positional params - too many
    test_rpc(
        '{"jsonrpc": "2.0", "method": "subtract", "params": [42, 23, 10], "id": 1}',
        {"jsonrpc": "2.0", "error": {"code": -32602, "message": "Invalid params: expected at most 2 arguments, got 3"}, "id": 1},
        "Invalid params - too many positional arguments"
    )

    # Missing required named param
    test_rpc(
        '{"jsonrpc": "2.0", "method": "subtract", "params": {"minuend": 42}, "id": 1}',
        {"jsonrpc": "2.0", "error": {"code": -32602, "message": "Invalid params: missing required parameters: ['subtrahend']"}, "id": 1},
        "Invalid params - missing required parameter"
    )

    # Extra named param
    test_rpc(
        '{"jsonrpc": "2.0", "method": "subtract", "params": {"minuend": 42, "subtrahend": 23, "extra": 1}, "id": 1}',
        {"jsonrpc": "2.0", "error": {"code": -32602, "message": "Invalid params: unexpected parameters: ['extra']"}, "id": 1},
        "Invalid params - unexpected parameter"
    )

    # Wrong type - string instead of int
    test_rpc(
        '{"jsonrpc": "2.0", "method": "subtract", "params": [42, "not a number"], "id": 1}',
        {"jsonrpc": "2.0", "error": {"code": -32602, "message": "Invalid params: subtrahend expected int, got str"}, "id": 1},
        "Invalid params - wrong type (str instead of int)"
    )

    # Wrong type - list instead of int
    test_rpc(
        '{"jsonrpc": "2.0", "method": "subtract", "params": {"minuend": 42, "subtrahend": [1, 2]}, "id": 1}',
        {"jsonrpc": "2.0", "error": {"code": -32602, "message": "Invalid params: subtrahend expected int, got list"}, "id": 1},
        "Invalid params - wrong type (list instead of int)"
    )

    # Null for non-optional param
    test_rpc(
        '{"jsonrpc": "2.0", "method": "subtract", "params": [42, null], "id": 1}',
        {"jsonrpc": "2.0", "error": {"code": -32602, "message": "Invalid params: subtrahend cannot be null"}, "id": 1},
        "Invalid params - null for non-optional parameter"
    )

    # Params is invalid type (not array or object)
    test_rpc(
        '{"jsonrpc": "2.0", "method": "subtract", "params": "invalid", "id": 1}',
        {"jsonrpc": "2.0", "error": {"code": -32602, "message": "Invalid params: must be array or object"}, "id": 1},
        "Invalid params - string instead of array/object"
    )

    test_rpc(
        '{"jsonrpc": "2.0", "method": "subtract", "params": 123, "id": 1}',
        {"jsonrpc": "2.0", "error": {"code": -32602, "message": "Invalid params: must be array or object"}, "id": 1},
        "Invalid params - number instead of array/object"
    )

    test_rpc(
        '{"jsonrpc": "2.0", "method": "subtract", "params": null, "id": 1}',
        {"jsonrpc": "2.0", "error": {"code": -32602, "message": "Missing required params"}, "id": 1},
        "Invalid params - null for required params"
    )

    # ========================================
    # DEFAULT PARAMETERS TESTS
    # ========================================

    # Function with default param - omit optional param (positional)
    test_rpc(
        '{"jsonrpc": "2.0", "method": "greet", "params": ["Alice"], "id": 1}',
        {"jsonrpc": "2.0", "result": "Hello, Alice!", "id": 1},
        "Default param - omit optional (positional)"
    )

    # Function with default param - provide optional param (positional)
    test_rpc(
        '{"jsonrpc": "2.0", "method": "greet", "params": ["Alice", "Hi"], "id": 1}',
        {"jsonrpc": "2.0", "result": "Hi, Alice!", "id": 1},
        "Default param - provide optional (positional)"
    )

    # Function with default param - omit optional param (named)
    test_rpc(
        '{"jsonrpc": "2.0", "method": "greet", "params": {"name": "Bob"}, "id": 1}',
        {"jsonrpc": "2.0", "result": "Hello, Bob!", "id": 1},
        "Default param - omit optional (named)"
    )

    # Function with default param - provide optional param (named)
    test_rpc(
        '{"jsonrpc": "2.0", "method": "greet", "params": {"name": "Bob", "greeting": "Hey"}, "id": 1}',
        {"jsonrpc": "2.0", "result": "Hey, Bob!", "id": 1},
        "Default param - provide optional (named)"
    )

    # Function with no params - omit params field
    test_rpc(
        '{"jsonrpc": "2.0", "method": "get_data", "id": 1}',
        {"jsonrpc": "2.0", "result": ["hello", 5], "id": 1},
        "No params function - params field omitted"
    )

    # Function with no params - empty array
    test_rpc(
        '{"jsonrpc": "2.0", "method": "get_data", "params": [], "id": 1}',
        {"jsonrpc": "2.0", "result": ["hello", 5], "id": 1},
        "No params function - empty array"
    )

    # Function with no params - empty object
    test_rpc(
        '{"jsonrpc": "2.0", "method": "get_data", "params": {}, "id": 1}',
        {"jsonrpc": "2.0", "result": ["hello", 5], "id": 1},
        "No params function - empty object"
    )

    # ========================================
    # UNION TYPE TESTS
    # ========================================

    # Union type - int
    test_rpc(
        '{"jsonrpc": "2.0", "method": "union_test", "params": [123], "id": 1}',
        {"jsonrpc": "2.0", "result": "ID: 123", "id": 1},
        "Union type (int | str) - int value"
    )

    # Union type - str
    test_rpc(
        '{"jsonrpc": "2.0", "method": "union_test", "params": ["abc"], "id": 1}',
        {"jsonrpc": "2.0", "result": "ID: abc", "id": 1},
        "Union type (int | str) - str value"
    )

    # Union type - invalid type
    test_rpc(
        '{"jsonrpc": "2.0", "method": "union_test", "params": [[1, 2, 3]], "id": 1}',
        {"jsonrpc": "2.0", "error": {"code": -32602, "message": "Invalid params: id has invalid type"}, "id": 1},
        "Union type (int | str) - invalid list"
    )

    # ========================================
    # OPTIONAL TYPE TESTS
    # ========================================

    # Optional - provide value
    test_rpc(
        '{"jsonrpc": "2.0", "method": "process_optional", "params": [42], "id": 1}',
        {"jsonrpc": "2.0", "result": "Got: 42", "id": 1},
        "Optional type - provide value"
    )

    # Optional - provide null
    test_rpc(
        '{"jsonrpc": "2.0", "method": "process_optional", "params": [null], "id": 1}',
        {"jsonrpc": "2.0", "result": "Got: None", "id": 1},
        "Optional type - provide null"
    )

    # ========================================
    # GENERIC TYPE TESTS
    # ========================================

    # list[T] - valid list
    test_rpc(
        '{"jsonrpc": "2.0", "method": "list_test", "params": [["a", "b", "c"]], "id": 1}',
        {"jsonrpc": "2.0", "result": 3, "id": 1},
        "Generic type list[str] - valid list (no inner validation)"
    )

    # list[T] - wrong outer type
    test_rpc(
        '{"jsonrpc": "2.0", "method": "list_test", "params": ["not a list"], "id": 1}',
        {"jsonrpc": "2.0", "error": {"code": -32602, "message": "Invalid params: items expected list, got str"}, "id": 1},
        "Generic type list[str] - wrong outer type"
    )

    # ========================================
    # NOTIFICATION ERROR HANDLING
    # ========================================

    # Notification with error (should return None, no response)
    test_rpc(
        '{"jsonrpc": "2.0", "method": "does_not_exist"}',
        None,
        "Notification - error does not produce response"
    )

    # Notification with invalid params (should return None, no response)
    test_rpc(
        '{"jsonrpc": "2.0", "method": "subtract", "params": [1]}',
        None,
        "Notification - invalid params does not produce response"
    )

    print("\n" + "="*60)
    print("ALL TESTS PASSED! ✓")
    print("="*60)


if __name__ == "__main__":
    run_all_tests()