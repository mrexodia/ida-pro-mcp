# Tools Reference

Tools are registered with the `@tool` decorator and grouped by API module
(`api_core`, `api_analysis`, `api_memory`, `api_types`, `api_modify`,
`api_stack`, `api_debug`, `api_python`, `api_survey`, `api_composite`,
`api_probes`, `api_sigmaker`, ...). Each tool's input/output schema is generated
from its Python type hints, so the schema you see in `tools/list` always matches
the function signature.

## Safety classes

Every tool is classified with `@safety(LEVEL)`, which emits MCP tool
annotations and (for the unsafe levels) registers the tool as unsafe:

| Level         | readOnly | destructive | idempotent | openWorld | Unsafe |
|---------------|----------|-------------|------------|-----------|--------|
| `READ`        | yes      | no          | yes        | no        | no     |
| `WRITE`       | no       | no          | yes        | no        | no     |
| `DESTRUCTIVE` | no       | yes         | no         | no        | yes    |
| `EXECUTE`     | no       | yes         | no         | yes       | yes    |

- **READ** — pure queries (disassemble, decompile, list, search).
- **WRITE** — idempotent IDB edits (rename, set type, set comment).
- **DESTRUCTIVE** — non-idempotent IDB edits (undefine, delete).
- **EXECUTE** — runs code or resumes the debuggee (python eval, appcall,
  `run_until`). Treat as a deliberate, confirmed action.

## Extension gating (`?ext`)

Tools decorated with `@ext("group")` are hidden by default and only appear when
the client connects with the matching `?ext=group` query parameter. Calling a
gated tool without enabling its group returns an `isError` response explaining
how to enable it.

- `@ext("dbg")` — debugger tools (`dbg_*`) and a few live-memory readers.
- `@ext("probes")` — the non-stopping probe / watch / autopilot toolkit.

Combine groups with a comma: `?ext=dbg,probes`.

## Titles and descriptions

`@title("...")` attaches a human-friendly display title; the tool description is
taken from the function docstring. Keep docstrings accurate — they are the
primary thing the client model reads when deciding whether to call a tool.

## Output limiting

Large structured results are automatically truncated for the inline response and
cached server-side; the response carries a `download_url` under
`_meta.ida_mcp` so the full payload can be fetched with `curl`. Prefer narrow,
targeted queries to avoid hitting the limit.
