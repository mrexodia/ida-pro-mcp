# IDA Pro MCP

Simple [MCP Server](https://modelcontextprotocol.io/introduction) to allow vibe reversing in IDA Pro.

https://github.com/user-attachments/assets/6ebeaa92-a9db-43fa-b756-eececce2aca0

The binaries and prompt for the video are available in the [mcp-reversing-dataset](https://github.com/mrexodia/mcp-reversing-dataset) repository.

Available functionality:

- `get_metadata()`: Get metadata about the current IDB.
- `get_function_by_name(name)`: Get a function by its name.
- `get_function_by_address(address)`: Get a function by its address.
- `get_current_address()`: Get the address currently selected by the user.
- `get_current_function()`: Get the function currently selected by the user.
- `convert_number(text, size)`: Convert a number (decimal, hexadecimal) to different representations.
- `list_functions(offset, count)`: List all functions in the database (paginated).
- `list_globals_filter(offset, count, filter)`: List matching globals in the database (paginated, filtered).
- `list_globals(offset, count)`: List all globals in the database (paginated).
- `list_strings_filter(offset, count, filter)`: List matching strings in the database (paginated, filtered).
- `list_strings(offset, count)`: List all strings in the database (paginated).
- `list_local_types()`: List all Local types in the database.
- `decompile_function(address)`: Decompile a function at the given address.
- `disassemble_function(start_address)`: Get assembly code (address: instruction; comment) for a function.
- `get_xrefs_to(address)`: Get all cross references to the given address.
- `get_xrefs_to_field(struct_name, field_name)`: Get all cross references to a named struct field (member).
- `get_entry_points()`: Get all entry points in the database.
- `set_comment(address, comment)`: Set a comment for a given address in the function disassembly and pseudocode.
- `rename_local_variable(function_address, old_name, new_name)`: Rename a local variable in a function.
- `rename_global_variable(old_name, new_name)`: Rename a global variable.
- `set_global_variable_type(variable_name, new_type)`: Set a global variable's type.
- `rename_function(function_address, new_name)`: Rename a function.
- `set_function_prototype(function_address, prototype)`: Set a function's prototype.
- `declare_c_type(c_declaration)`: Create or update a local type from a C declaration.
- `set_local_variable_type(function_address, variable_name, new_type)`: Set a local variable's type.

Unsafe functions (`--unsafe` flag required):

- `dbg_get_registers()`: Get all registers and their values. This function is only available when debugging.
- `dbg_get_call_stack()`: Get the current call stack.
- `dbg_list_breakpoints()`: List all breakpoints in the program.
- `dbg_start_process()`: Start the debugger.
- `dbg_exit_process()`: Exit the debugger.
- `dbg_continue_process()`: Continue the debugger.
- `dbg_run_to(address)`: Run the debugger to the specified address.
- `dbg_set_breakpoint(address)`: Set a breakpoint at the specified address.
- `dbg_delete_breakpoint(address)`: del a breakpoint at the specified address.
- `dbg_enable_breakpoint(address, enable)`: Enable or disable a breakpoint at the specified address.

## Prerequisites

- [Python](https://www.python.org/downloads/) (**3.11 or higher**)
  - Use `idapyswitch` to switch to the newest Python version
- [IDA Pro](https://hex-rays.com/ida-pro) (8.3 or higher, 9 recommended), **IDA Free is not supported**

## Installation

Clone this repository and run the bootstrap script with the path to your
downloaded model:

```sh
git clone https://github.com/mrexodia/ida-pro-mcp
cd ida-pro-mcp
scripts/bootstrap.sh /path/to/model.gguf
scripts/install_ida_plugin.sh
```

The script creates a virtual environment and writes the model location to
`~/Library/Application Support/ida-offline-mcp/settings.json`.

Run `scripts/install_ida_plugin.sh` to place the plugin in
`~/.idapro/plugins/`.  Start IDA and choose `Edit -> Plugins -> MCP` to launch
the chat dock.  Make sure an IDB is loaded or the menu entry will not appear.

### Environment variables

Outbound network access from IDAPython is blocked by default.  Set `ALLOW_NET=1`
before starting IDA if you want to enable connections to external services.

## Prompt Engineering

LLMs are prone to hallucinations and you need to be specific with your prompting. For reverse engineering the conversion between integers and bytes are especially problematic. Below is a minimal example prompt, feel free to start a discussion or open an issue if you have good results with a different prompt:

> Your task is to analyze a crackme in IDA Pro. You can use the MCP tools to retrieve information. In general use the following strategy:
> - Inspect the decompilation and add comments with your findings
> - Rename variables to more sensible names
> - Change the variable and argument types if necessary (especially pointer and array types)
> - Change function names to be more descriptive
> - If more details are necessary, disassemble the function and add comments with your findings
> - NEVER convert number bases yourself. Use the convert_number MCP tool if needed!
> - Do not attempt brute forcing, derive any solutions purely from the disassembly and simple python scripts
> - Create a report.md with your findings and steps taken at the end
> - When you find a solution, prompt to user for feedback with the password you found

This prompt was just the first experiment, please share if you found ways to improve the output!

## Tips for Enhancing LLM Accuracy

Large Language Models (LLMs) are powerful tools, but they can sometimes struggle with complex mathematical calculations or exhibit "hallucinations" (making up facts). Make sure to tell the LLM to use the `conver_number` MCP and you might also need [math-mcp](https://github.com/EthanHenrickson/math-mcp) for certain operations.

Another thing to keep in mind is that LLMs will not perform well on obfuscated code. Before trying to use an LLM to solve the problem, take a look around the binary and spend some time (automatically) removing the following things:

- String encryption
- Import hashing
- Control flow flattening
- Code encryption
- Anti-decompilation tricks

You should also use a tool like Lumina or FLIRT to try and resolve all the open source library code and the C++ STL, this will further improve the accuracy.


## Manual Installation

_Note_: This section is for LLMs and power users who need detailed installation instructions.

### Manual plugin installation
1. Copy or symlink `src/ida_pro_mcp/plugin/__init__.py` to `~/.idapro/plugins/mcp-plugin.py`.
2. Open an IDB and click **Edit -> Plugins -> MCP** to start the server.



## Development

Adding new features is a super easy and streamlined process. All you have to do is add a new `@jsonrpc` function to [`plugin/__init__.py`](https://github.com/mrexodia/ida-pro-mcp/blob/164df8cf4ae251cc9cc0f464591fa6df8e0d9df4/src/ida_pro_mcp/plugin/__init__.py#L406-L419) and your function will be available in the MCP server without any additional boilerplate! Below is a video where I add the `get_metadata` function in less than 2 minutes (including testing):

https://github.com/user-attachments/assets/951de823-88ea-4235-adcb-9257e316ae64

Run the plugin inside IDA Pro and it will automatically launch the offline core.
You can then access your new JSON-RPC methods directly from the chat dock.

Generate the changelog of direct commits to `main`:

```sh
git log --first-parent --no-merges 1.2.0..main "--pretty=- %s"
```
