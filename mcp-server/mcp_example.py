"""Example MCP server with test tools"""
import time
from typing import Annotated, Optional, TypedDict, NotRequired
from mcp import McpToolRegistry, McpToolError, McpServer

# Create tool registry
mcp = McpToolRegistry()

class SystemInfo(TypedDict):
    platform: Annotated[str, "Operating system platform"]
    python_version: Annotated[str, "Python version"]
    machine: Annotated[str, "Machine architecture"]
    timestamp: Annotated[float, "Current timestamp"]

class GreetingResponse(TypedDict):
    message: Annotated[str, "Greeting message"]
    name: Annotated[str, "Name that was greeted"]
    age: Annotated[NotRequired[int], "Age if provided"]

@mcp.tool
def divide(
    numerator: Annotated[float, "Numerator"],
    denominator: Annotated[float, "Denominator"]
) -> float:
    """Divide two numbers (no zero check - tests natural exceptions)"""
    return numerator / denominator

@mcp.tool
def greet(
    name: Annotated[str, "Name to greet"],
    age: Annotated[Optional[int], "Age of person"] = None
) -> GreetingResponse:
    """Generate a greeting message"""
    if age is not None:
        return {
            "message": f"Hello, {name}! You are {age} years old.",
            "name": name,
            "age": age
        }
    return {
        "message": f"Hello, {name}!",
        "name": name
    }

@mcp.tool
def get_system_info() -> SystemInfo:
    """Get system information"""
    import platform
    return {
        "platform": platform.system(),
        "python_version": platform.python_version(),
        "machine": platform.machine(),
        "timestamp": time.time()
    }

@mcp.tool
def failing_tool(message: Annotated[str, "Error message to raise"]) -> str:
    """Tool that always fails (for testing error handling)"""
    raise McpToolError(message)

class StructInfo(TypedDict):
    name: Annotated[str, "Structure name"]
    size: Annotated[int, "Structure size in bytes"]
    fields: Annotated[list[str], "List of field names"]

@mcp.tool
def struct_get(
    names: Annotated[list[str], "Array of structure names"]
         | Annotated[str, "Single structure name"]
) -> list[StructInfo]:
    """Retrieve structure information by names"""
    return [
        {
            "name": name,
            "size": 128,  # Dummy size
            "fields": ["field1", "field2", "field3"]  # Dummy fields
        }
        for name in (names if isinstance(names, list) else [names])
    ]

if __name__ == "__main__":
    print("Starting MCP Example Server...")
    print("\nAvailable tools:")
    for name in mcp.methods.keys():
        func = mcp.methods[name]
        print(f"  - {name}: {func.__doc__}")

    server = McpServer("127.0.0.1", 13337, mcp)
    server.start()

    print("\n" + "="*60)
    print("Server is running. Press Ctrl+C to stop.")
    print("="*60)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\nStopping server...")
        server.stop()
        print("Server stopped.")
