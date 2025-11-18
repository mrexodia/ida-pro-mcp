# IDA Pro MCP

Simple [MCP Server](https://modelcontextprotocol.io/introduction) to allow vibe reversing in IDA Pro.

https://github.com/user-attachments/assets/6ebeaa92-a9db-43fa-b756-eececce2aca0

The binaries and prompt for the video are available in the [mcp-reversing-dataset](https://github.com/mrexodia/mcp-reversing-dataset) repository.

## MCP Resources

**Resources** are browsable IDB state endpoints that provide read-only access to binary metadata, functions, strings, and types. Unlike tools (which perform actions), resources follow REST-like URI patterns for efficient data exploration.

**Core IDB State:**
- `ida://idb/metadata` - IDB file info (path, arch, base, size, hashes)
- `ida://idb/segments` - Memory segments with permissions
- `ida://idb/entrypoints` - Entry points (main, TLS callbacks, etc.)

**Code Browsing:**
- `ida://functions` - List all functions (paginated, filterable)
- `ida://function/{addr}` - Function details by address
- `ida://globals` - List global variables (paginated, filterable)
- `ida://global/{name_or_addr}` - Global variable details

**Data Exploration:**
- `ida://strings` - All strings (paginated, filterable)
- `ida://string/{addr}` - String details at address
- `ida://imports` - Imported functions (paginated)
- `ida://import/{name}` - Import details by name
- `ida://exports` - Exported functions (paginated)
- `ida://export/{name}` - Export details by name

**Type Information:**
- `ida://types` - All local types
- `ida://structs` - All structures/unions
- `ida://struct/{name}` - Structure definition with fields

**Analysis Context:**
- `ida://xrefs/to/{addr}` - Cross-references to address
- `ida://xrefs/from/{addr}` - Cross-references from address
- `ida://stack/{func_addr}` - Stack frame variables

**UI State:**
- `ida://cursor` - Current cursor position and function
- `ida://selection` - Current selection range

**Debug State (when debugger active):**
- `ida://debug/breakpoints` - All breakpoints
- `ida://debug/registers` - Current register values
- `ida://debug/callstack` - Current call stack

## Core Functions

- `idb_meta()`: Get IDB metadata (path, module, base address, size, hashes).
- `lookup_funcs(queries)`: Get function(s) by address or name (auto-detects, accepts list or comma-separated string).
- `cursor_addr()`: Get current cursor address.
- `cursor_func()`: Get current function at cursor.
- `int_convert(inputs)`: Convert numbers to different formats (decimal, hex, bytes, ASCII, binary).
- `list_funcs(queries)`: List functions (paginated, filtered).
- `list_globals(queries)`: List global variables (paginated, filtered).
- `imports(offset, count)`: List all imported symbols with module names (paginated).
- `strings(queries)`: List strings in the database (paginated, filtered).
- `segments()`: List all memory segments with permissions.
- `local_types()`: List all local types defined in the database.
- `decompile(addrs)`: Decompile function(s) at given address(es).
- `disasm(addrs)`: Disassemble function(s) with full details (arguments, stack frame, etc).
- `xrefs_to(addrs)`: Get all cross-references to address(es).
- `xrefs_to_field(queries)`: Get cross-references to specific struct field(s).
- `callees(addrs)`: Get functions called by function(s) at address(es).
- `callers(addrs)`: Get functions that call the function(s) at address(es).
- `entrypoints()`: Get all program entry points.

## Modification Operations

- `set_comments(items)`: Set comments at address(es) in both disassembly and decompiler views.
- `patch_asm(items)`: Patch assembly instructions at address(es).
- `declare_type(decls)`: Declare C type(s) in the local type library.

## Memory Reading Operations

- `get_bytes(addrs)`: Read raw bytes at address(es).
- `get_u8(addrs)`: Read 8-bit unsigned integer(s).
- `get_u16(addrs)`: Read 16-bit unsigned integer(s).
- `get_u32(addrs)`: Read 32-bit unsigned integer(s).
- `get_u64(addrs)`: Read 64-bit unsigned integer(s).
- `get_string(addrs)`: Read null-terminated string(s).
- `get_global_value(queries)`: Read global variable value(s) by address or name (auto-detects, compile-time values).

## Stack Frame Operations

- `stack_frame(addrs)`: Get stack frame variables for function(s).
- `declare_stack(items)`: Create stack variable(s) at specified offset(s).
- `delete_stack(items)`: Delete stack variable(s) by name.

## Structure Operations

- `structs()`: List all defined structures with members.
- `struct_info(names)`: Get detailed information about structure(s).
- `read_struct(queries)`: Read structure field values at specific address(es).
- `search_structs(filter)`: Search structures by name pattern.

## Debugger Operations (Unsafe)

- `dbg_regs()`: Get all registers for all threads.
- `dbg_regs_thread(tids)`: Get all registers for specific thread(s).
- `dbg_regs_cur()`: Get all registers for current thread.
- `dbg_gpregs_thread(tids)`: Get general-purpose registers for thread(s).
- `dbg_current_gpregs()`: Get general-purpose registers for current thread.
- `dbg_regs_for_thread(thread_id, register_names)`: Get specific registers for a thread.
- `dbg_current_regs(register_names)`: Get specific registers for current thread.
- `dbg_callstack()`: Get call stack with module and symbol information.
- `dbg_list_bps()`: List all breakpoints with their status.
- `dbg_start()`: Start debugger process.
- `dbg_exit()`: Exit debugger process.
- `dbg_continue()`: Continue debugger execution.
- `dbg_run_to(addr)`: Run debugger to specific address.
- `dbg_add_bp(addrs)`: Add breakpoint(s) at address(es).
- `dbg_step_into()`: Step into instruction.
- `dbg_step_over()`: Step over instruction.
- `dbg_delete_bp(addrs)`: Delete breakpoint(s) at address(es).
- `dbg_enable_bp(items)`: Enable or disable breakpoint(s).
- `dbg_read_mem(regions)`: Read memory from debugged process.
- `dbg_write_mem(regions)`: Write memory to debugged process.

## Advanced Analysis Operations

- `py_eval(code)`: Execute arbitrary Python code in IDA context (returns dict with result/stdout/stderr, supports Jupyter-style evaluation).
- `analyze_funcs(addrs)`: Comprehensive function analysis (decompilation, assembly, xrefs, callees, callers, strings, constants, basic blocks).

## Pattern Matching & Search

- `find_bytes(patterns, limit=1000, offset=0)`: Find byte pattern(s) in binary (e.g., "48 8B ?? ??"). Max limit: 10000. Returns `cursor: {next: N}` or `{done: true}`.
- `find_insns(sequences, limit=1000, offset=0)`: Find instruction sequence(s) in code. Max limit: 10000. Returns `cursor: {next: N}` or `{done: true}`.
- `find_insn_operands(patterns, limit=1000, offset=0)`: Find instructions with specific operand values. Max limit: 10000. Returns `cursor: {next: N}` or `{done: true}`.
- `search(type, targets, limit=1000, offset=0)`: Advanced search (immediate values, strings, data/code references). Max limit: 10000. Returns `cursor: {next: N}` or `{done: true}`.

## Control Flow Analysis

- `basic_blocks(addrs)`: Get basic blocks with successors and predecessors.
- `find_paths(queries)`: Find execution paths between source and target addresses.

## Type Operations

- `apply_types(applications)`: Apply type(s) to functions, globals, locals, or stack variables.
- `infer_types(addrs)`: Infer types at address(es) using Hex-Rays or heuristics.

## Export Operations

- `export_funcs(addrs, format)`: Export function(s) in specified format (json, c_header, or prototypes).

## Graph Operations

- `callgraph(roots, max_depth)`: Build call graph from root function(s) with configurable depth.

## Batch Operations

- `rename(batch)`: Unified batch rename operation for functions, globals, locals, and stack variables (accepts dict with optional `func`, `data`, `local`, `stack` keys).
- `patch(patches)`: Patch multiple byte sequences at once.

## Cross-Reference Analysis

- `xref_matrix(entities)`: Build cross-reference matrix between multiple addresses.

## String Analysis

- `analyze_strings(filters, limit=1000, offset=0)`: Analyze strings with pattern matching, length filtering, and xref information. Max limit: 10000. Returns `cursor: {next: N}` or `{done: true}`.

**Key Features:**

- **Type-safe API**: All functions use strongly-typed parameters with TypedDict schemas for better IDE support and LLM structured outputs
- **Batch-first design**: Most operations accept both single items and lists
- **Consistent error handling**: All batch operations return `[{..., error: null|string}, ...]`
- **Cursor-based pagination**: Search functions return `cursor: {next: offset}` or `{done: true}` (default limit: 1000, enforced max: 10000 to prevent token overflow)
- **Performance**: Strings are cached with MD5-based invalidation to avoid repeated `build_strlist` calls in large projects

## Prerequisites

- [Python](https://www.python.org/downloads/) (**3.11 or higher**)
  - Use `idapyswitch` to switch to the newest Python version
- [IDA Pro](https://hex-rays.com/ida-pro) (8.3 or higher, 9 recommended), **IDA Free is not supported**
- Supported MCP Client (pick one you like)
  - [Cline](https://cline.bot)
  - [Roo Code](https://roocode.com)
  - [Claude](https://claude.ai/download)
  - [Cursor](https://cursor.com)
  - [VSCode Agent Mode](https://github.blog/news-insights/product-news/github-copilot-agent-mode-activated/)
  - [Windsurf](https://windsurf.com)
  - [Other MCP Clients](https://modelcontextprotocol.io/clients#example-clients): Run `ida-pro-mcp --config` to get the JSON config for your client.

## Installation

Install the latest version of the IDA Pro MCP package:

```sh
pip uninstall ida-pro-mcp
pip install https://github.com/mrexodia/ida-pro-mcp/archive/refs/heads/main.zip
```

Configure the MCP servers and install the IDA Plugin:

```
ida-pro-mcp --install
```

**Important**: Make sure you completely restart IDA/Visual Studio Code/Claude for the installation to take effect. Claude runs in the background and you need to quit it from the tray icon.

https://github.com/user-attachments/assets/65ed3373-a187-4dd5-a807-425dca1d8ee9

_Note_: You need to load a binary in IDA before the plugin menu will show up.

## Prompt Engineering

LLMs are prone to hallucinations and you need to be specific with your prompting. For reverse engineering the conversion between integers and bytes are especially problematic. Below is a minimal example prompt, feel free to start a discussion or open an issue if you have good results with a different prompt:

```md
Your task is to analyze a crackme in IDA Pro. You can use the MCP tools to retrieve information. In general use the following strategy:

- Inspect the decompilation and add comments with your findings
- Rename variables to more sensible names
- Change the variable and argument types if necessary (especially pointer and array types)
- Change function names to be more descriptive
- If more details are necessary, disassemble the function and add comments with your findings
- NEVER convert number bases yourself. Use the `int_convert` MCP tool if needed!
- Do not attempt brute forcing, derive any solutions purely from the disassembly and simple python scripts
- Create a report.md with your findings and steps taken at the end
- When you find a solution, prompt to user for feedback with the password you found
```

This prompt was just the first experiment, please share if you found ways to improve the output!

Another prompt by [@can1357](https://github.com/can1357):

```md
Your task is to create a complete and comprehensive reverse engineering analysis. Reference AGENTS.md to understand the project goals and ensure the analysis serves our purposes.

Use the following systematic methodology:

1. **Decompilation Analysis**
   - Thoroughly inspect the decompiler output
   - Add detailed comments documenting your findings
   - Focus on understanding the actual functionality and purpose of each component (do not rely on old, incorrect comments)

2. **Improve Readability in the Database**
   - Rename variables to sensible, descriptive names
   - Correct variable and argument types where necessary (especially pointers and array types)
   - Update function names to be descriptive of their actual purpose

3. **Deep Dive When Needed**
   - If more details are necessary, examine the disassembly and add comments with findings
   - Document any low-level behaviors that aren't clear from the decompilation alone
   - Use sub-agents to perform detailed analysis

4. **Important Constraints**
   - NEVER convert number bases yourself - use the int_convert MCP tool if needed
   - Use MCP tools to retrieve information as necessary
   - Derive all conclusions from actual analysis, not assumptions

5. **Documentation**
   - Produce comprehensive RE/*.md files with your findings
   - Document the steps taken and methodology used
   - When asked by the user, ensure accuracy over previous analysis file
   - Organize findings in a way that serves the project goals outlined in AGENTS.md or CLAUDE.md
```

Live stream discussing prompting and showing some real-world malware analysis:

[![](https://img.youtube.com/vi/iFxNuk3kxhk/0.jpg)](https://www.youtube.com/watch?v=iFxNuk3kxhk)

## Tips for Enhancing LLM Accuracy

Large Language Models (LLMs) are powerful tools, but they can sometimes struggle with complex mathematical calculations or exhibit "hallucinations" (making up facts). Make sure to tell the LLM to use the `int_convert` MCP tool and you might also need [math-mcp](https://github.com/EthanHenrickson/math-mcp) for certain operations.

Another thing to keep in mind is that LLMs will not perform well on obfuscated code. Before trying to use an LLM to solve the problem, take a look around the binary and spend some time (automatically) removing the following things:

- String encryption
- Import hashing
- Control flow flattening
- Code encryption
- Anti-decompilation tricks

You should also use a tool like Lumina or FLIRT to try and resolve all the open source library code and the C++ STL, this will further improve the accuracy.

## SSE Transport & Headless MCP

You can run an SSE server to connect to the user interface like this:

```sh
uv run ida-pro-mcp --transport http://127.0.0.1:8744/sse
```

After installing [`idalib`](https://docs.hex-rays.com/user-guide/idalib) you can also run a headless SSE server:

```sh
uv run idalib-mcp --host 127.0.0.1 --port 8745 path/to/executable
```

_Note_: The `idalib` feature was contributed by [Willi Ballenthin](https://github.com/williballenthin).

## Comparison with other MCP servers

There are a few IDA Pro MCP servers floating around, but I created my own for a few reasons:

1. Installation should be fully automated.
2. The architecture of other plugins make it difficult to add new functionality quickly (too much boilerplate of unnecessary dependencies).
3. Learning new technologies is fun!

If you want to check them out, here is a list (in the order I discovered them):

- https://github.com/taida957789/ida-mcp-server-plugin (SSE protocol only, requires installing dependencies in IDAPython).
- https://github.com/fdrechsler/mcp-server-idapro (MCP Server in TypeScript, excessive boilerplate required to add new functionality).
- https://github.com/MxIris-Reverse-Engineering/ida-mcp-server (custom socket protocol, boilerplate).

Feel free to open a PR to add your IDA Pro MCP server here.

## Development

Adding new features is a super easy and streamlined process. All you have to do is add a new `@tool` function to the modular API files in `src/ida_pro_mcp/ida_mcp/api_*.py` and your function will be available in the MCP server without any additional boilerplate! Below is a video where I add the `get_metadata` function in less than 2 minutes (including testing):

https://github.com/user-attachments/assets/951de823-88ea-4235-adcb-9257e316ae64

To test the MCP server itself:

```sh
npx -y @modelcontextprotocol/inspector
```

This will open a web interface at http://localhost:5173 and allow you to interact with the MCP tools for testing.

For testing I create a symbolic link to the IDA plugin and then POST a JSON-RPC request directly to `http://localhost:13337/mcp`. After [enabling symbolic links](https://learn.microsoft.com/en-us/windows/apps/get-started/enable-your-device-for-development) you can run the following command:

```sh
uv run ida-pro-mcp --install
```

Generate the changelog of direct commits to `main`:

```sh
git log --first-parent --no-merges 1.2.0..main "--pretty=- %s"
```
