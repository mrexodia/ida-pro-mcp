# IDA Pro MCP (AriusII fork)

An [MCP server](https://modelcontextprotocol.io/introduction) that exposes a live
IDA Pro database — static analysis **and** the debugger — to an MCP client, so an
LLM can reverse engineer interactively.

This is a **fork** of [`mrexodia/ida-pro-mcp`](https://github.com/mrexodia/ida-pro-mcp).
The upstream project (by [@mrexodia](https://github.com/mrexodia) and
[@can1357](https://github.com/can1357)) is the original work; this fork tracks it
and tightens the project around a single supported configuration. All upstream
credit stays intact (authors, license, the prompt-engineering guidance below).

## Fork focus

This fork narrows and hardens the upstream server for one target environment and
a specific reversing workflow:

- **IDA 9.3 / Python 3.13 alignment.** The plugin floor is `idaVersions >=9.3`
  and the CI matrix is pinned to `9.3`. Python support is `>=3.11,<3.14` (3.13 is
  the intended runtime — use `idapyswitch` to select the newest interpreter).
- **The `@safety` / `@ext` model.** Every tool declares a safety class
  (`READ` / `WRITE` / `DESTRUCTIVE` / `EXECUTE`) that maps to MCP tool
  annotations and the unsafe gate, and a single extension group (`@ext("dbg")`)
  keeps the entire debugger + instrumentation toolkit hidden until a client opts
  in via `?ext=dbg`.
- **The probe / autopilot toolkit.** A non-stopping live-debugger probe layer
  (`api_probes`) that instruments a *running* target without ever calling
  `dbg_start` and without halting it — instrument → run → drain.
- **`ida-domain`-backed tools.** Higher-level survey/composite tools
  (`survey_binary`, `analyze_func`, `analyze_component`, `diff_before_after`,
  the `idb_open` warm-up path) build on the [`ida-domain`](https://pypi.org/project/ida-domain/)
  API for richer one-shot analysis.
- **An in-MCP documentation corpus.** Server docs ship inside the MCP itself,
  browsable as resources under `ida://docs` and searchable with `search_docs` —
  the model can read how the server works without leaving the session.

> This is a fork; upstream is <https://github.com/mrexodia/ida-pro-mcp>.

## Prerequisites

- [Python](https://www.python.org/downloads/) **3.11–3.13** (3.13 recommended).
  Use `idapyswitch` to point IDA at the newest interpreter.
- [IDA Pro](https://hex-rays.com/ida-pro) **9.3 or higher**. **IDA Free is not supported.**
- [uv](https://astral.sh/uv) for running the server.
- A supported MCP client (Claude Code, Claude Desktop, Cursor, VS Code, Cline,
  Codex, Gemini CLI, and the other clients listed by `ida-pro-mcp --config`).

## Installation (AriusII fork)

Clone and run directly with `uv` (the fork is not published to a package index):

```bash
git clone https://github.com/AriusII/ida-pro-mcp
cd ida-pro-mcp
```

### Install the IDA plugin + client config

From the checkout, register the MCP server with your client and install the IDA
plugin:

```bash
uv run ida-pro-mcp --install
```

Run `uv run ida-pro-mcp --config` to print the JSON config block for a client
you wire up manually.

**Important:** completely restart IDA and your MCP client after installing. Some
clients run in the background and must be quit from the tray icon.

### Headless (`idalib`)

The headless server needs `idalib` activated:

```bash
# windows
uv run "C:\Program Files\IDA Professional 9.3\idalib\python\py-activate-idalib.py"
# macos
uv run "/Applications/IDA Professional 9.3.app/Contents/MacOS/idalib/python/py-activate-idalib.py"
```

## Usage

### GUI plugin (Streamable HTTP)

With IDA open on a database and the plugin installed, the server listens on
`http://127.0.0.1:13337/mcp` (legacy SSE at `/sse`). Point your client at that
endpoint.

### Headless `idalib-mcp`

Run the supervisor against a binary, or start empty and open files later:

```bash
# start with a binary
uv run idalib-mcp --host 127.0.0.1 --port 8745 path/to/executable
# start empty, open files with idb_open(...) later
uv run idalib-mcp --host 127.0.0.1 --port 8745
# stdio for stdio-based clients
uv run idalib-mcp --stdio
```

Each open database lives in its own detached idalib worker that outlives the
supervisor; a later supervisor adopts a worker that already has the file open.
Workers self-exit after an idle TTL. Every tool call carries an explicit
`database` argument (the session id from `idb_open` / `idb_list`); there is no
implicit "current database".

```bash
uv run idalib-mcp --stdio --max-workers 4
```

```python
idb_open("/path/to/binary_a.exe", preferred_session_id="binary_a")
decompile("main", database="binary_a")
xrefs_to("ImportantExport", database="binary_a")
```

## Capability / extension groups

The HTTP transport accepts an `?ext=<group>` query parameter that reveals tools
hidden behind an extension gate. The model is **two views**: the base endpoint
exposes every static-analysis tool (including the `ida-domain`-backed `domain_*`
tools), and the single `dbg` gate is a **superset** that adds the entire
live-debugger and instrumentation toolkit on top:

| Endpoint | Surfaces |
|---|---|
| `http://127.0.0.1:13337/mcp` | all static-analysis tools (incl. the `ida-domain` `domain_*` tools) |
| `…/mcp?ext=dbg` | + the debugger tools (`dbg_*`), live-memory readers, and the non-stopping probe / watch / autopilot toolkit |

There is exactly one extension group, `dbg`, and the entire probe/watch/trace/
appcall/snapshot toolkit lives under it (it is meaningless without a live
debugger). Calling a gated tool without enabling `dbg` returns an error
explaining how to enable it. The `ida-domain`-backed `domain_*` tools are part of
the base view and degrade gracefully (a clean error, never a crash) when the
ida-domain SDK is unavailable.

## Tools & docs overview

Tools are plain Python functions registered with the project's `@tool` decorator
(not FastMCP), grouped by `api_*` module — core lookups, analysis, memory reads,
types, modify ops, stack frames, debugger, python eval, survey, composite
analysis, probes, sigmaker, and docs. Their JSON schemas are generated from the
function type hints, so `tools/list` always matches the signatures.

Representative families:

- **Core / query:** `lookup_funcs`, `list_funcs`, `list_globals`, `imports`,
  `decompile`, `disasm`, `xrefs_to`, `xrefs_to_field`, `callees`, `int_convert`.
- **Memory:** `get_bytes`, `get_int`, `get_string`, `get_global_value`.
- **Modify / types:** `rename`, `set_comments`, `set_type`, `declare_type`,
  `define_func`, `define_code`, `undefine`, `patch_asm`, `infer_types`.
- **Survey / composite:** `survey_binary`, `analyze_func`, `analyze_component`,
  `diff_before_after`, `export_funcs`, `callgraph`.
- **Search:** `find_regex`, `find_bytes`, `find_insns`, `find`.
- **Debugger (`?ext=dbg`):** `dbg_start`, `dbg_continue`, `dbg_run_to`,
  `dbg_step_*`, breakpoint / register / stack / memory tools.
- **Probes (`?ext=dbg`):** `probe_add`, `trace_calls`, `watch_field`,
  `probe_net`, `run_until`, `probe_drain`, `probe_list`, `probe_clear`.
- **ida-domain (base `/mcp`):** `domain_functions`, `domain_function_pseudocode`,
  `domain_xrefs`, `domain_strings`, `domain_segments`, `domain_types`,
  `domain_entry_points`.

**Resources** are browsable read-only state addressed by URI: `ida://idb/metadata`,
`ida://idb/segments`, `ida://idb/entrypoints`, `ida://cursor`, `ida://selection`,
`ida://types`, `ida://structs`, `ida://struct/{name}`, `ida://import/{name}`,
`ida://export/{name}`, `ida://xrefs/from/{addr}`.

**In-MCP documentation** ships under `ida://docs`:

- `ida://docs` — generated index of topics.
- `ida://docs/{topic}` — one topic body (`overview`, `tools-reference`,
  `probe-toolkit`).
- `search_docs(query, limit)` — term-frequency search over all docs, returning
  `ida://docs/{topic}` URIs.

**Prompts** are slash-command workflow guides surfaced via `prompts/get`:
`probe_workflow`, `crypto_hunt`, `opcode_map`.

For how to add a tool, resource, doc, or prompt — naming, the safety classes,
the `@ext` gating model, the docs-authoring contract, and the testing approach —
see [`CONVENTIONS.md`](CONVENTIONS.md).

## Prompt engineering

LLMs hallucinate, and the conversion between integers and bytes is especially
error-prone — always tell the model to use the `int_convert` tool rather than
converting bases itself. A minimal starting prompt:

```md
Your task is to analyze a crackme in IDA Pro. You can use the MCP tools to retrieve information. In general use the
following strategy:

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

A more systematic prompt by [@can1357](https://github.com/can1357):

```md
Your task is to create a complete and comprehensive reverse engineering analysis. Reference AGENTS.md to understand the
project goals and ensure the analysis serves our purposes.

Use the following systematic methodology:

1. **Decompilation Analysis**
    - Thoroughly inspect the decompiler output
    - Add detailed comments documenting your findings
    - Focus on understanding the actual functionality and purpose of each component (do not rely on old, incorrect
      comments)

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

LLMs do not perform well on obfuscated code. Before analysis, automatically strip
string encryption, import hashing, control-flow flattening, code encryption, and
anti-decompilation tricks, and use Lumina / FLIRT to resolve library code and the
C++ STL — all of this improves accuracy. For heavy math beyond `int_convert`,
[math-mcp](https://github.com/EthanHenrickson/math-mcp) can help.

## Development

Add a new capability by adding a `@tool` (or `@resource` / `@prompt`) function to
the relevant `src/ida_pro_mcp/ida_mcp/api_*.py` module — the decorators register
it with no extra boilerplate. Add a doc topic by dropping `docs/<topic>.md` and a
`docs/_meta.yaml` entry, with no code change. The full contributor contract —
the `@tool` idiom, naming, safety classes, `@ext` gating, resource URIs, the
docs-authoring contract, and the two test suites — lives in
[`CONVENTIONS.md`](CONVENTIONS.md).

Tests:

```bash
# headless pure-logic suite (stubs IDA via conftest.py)
uv run pytest tests/ -q
# the idalib end-to-end test used by CI
uv run ida-mcp-test tests/crackme03.elf -q
```

To exercise the MCP protocol surface with the inspector:

```bash
npx -y @modelcontextprotocol/inspector
```

## Credits & license

Original project and the bulk of the implementation: **[@mrexodia](https://github.com/mrexodia)**
and **[@can1357](https://github.com/can1357)** — see
[`mrexodia/ida-pro-mcp`](https://github.com/mrexodia/ida-pro-mcp). The `idalib`
headless feature was contributed by
[Willi Ballenthin](https://github.com/williballenthin).

This fork keeps the upstream MIT license. See [`LICENSE`](LICENSE).
