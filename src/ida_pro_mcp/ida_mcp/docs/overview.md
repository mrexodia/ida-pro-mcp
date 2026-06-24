# IDA Pro MCP Overview

The IDA Pro MCP server exposes the live IDA Pro database (static analysis **and**
the `?ext=dbg` debugger) to an MCP client. It speaks the Model Context Protocol
over Streamable HTTP (`/mcp`) and legacy SSE (`/sse`), and offers three kinds of
capability:

- **Tools** — callable actions and queries (`tools/call`). Most analysis work
  goes through tools (disassemble, decompile, rename, type, search, debug).
- **Resources** — browsable read-only state addressed by URI (`resources/read`).
  Examples: `ida://idb/metadata`, `ida://idb/segments`, `ida://struct/{name}`,
  and this documentation set under `ida://docs`.
- **Prompts** — reusable guides surfaced as slash-commands (`prompts/get`), e.g.
  `probe_workflow`, `crypto_hunt`, `opcode_map`.

## Endpoints and extensions

The HTTP transport supports an `?ext=<group>` query parameter that reveals tools
hidden behind an extension gate. The most important is the debugger extension:

```
http://127.0.0.1:13337/mcp?ext=dbg
```

This is a **superset** endpoint — it surfaces the `dbg_*` debugger tools and the
probe toolkit in addition to all static-analysis tools. The base `/mcp`
endpoint exposes static tools only. Multiple groups can be combined:
`?ext=dbg,probes`.

## Where to start

1. Read `ida://docs/tools-reference` for the tool taxonomy and safety classes.
2. Use the `ida://idb/metadata` resource to confirm which database is loaded
   (path, architecture, base address, hashes) before trusting any output.
3. For live-debugger instrumentation without halting the target, read
   `ida://docs/probe-toolkit` and run the `probe_workflow` prompt.

## Discovering docs

- `resources/list` lists static docs.
- `resources/read` with `ida://docs` returns this generated index.
- `resources/read` with `ida://docs/{topic}` returns one topic body.
- The `search_docs` tool does term-frequency search across all docs and returns
  matching `ida://docs/{topic}` URIs.

Adding a new doc requires **no code change**: drop a `.md` file into the
`docs/` directory and add a matching entry to `docs/_meta.yaml`.
