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
| `PATCH`       | no       | yes         | no         | no        | yes    |
| `EXECUTE`     | no       | yes         | no         | yes       | yes    |

- **READ** — pure queries (disassemble, decompile, list, search).
- **WRITE** — reversible, idempotent IDB *annotations*: `rename`,
  `set_comments` / `append_comments`, set/declare/apply type. These layer
  metadata onto the IDB; they never touch the program bytes.
- **DESTRUCTIVE** — non-idempotent IDB edits that lose info (`undefine`,
  delete/clear definitions).
- **PATCH** — binary-byte writers that rewrite the program itself: `patch`,
  `patch_asm`, `put_int`. Destructive **and** consent-gated **and** unsafe — see
  the dedicated section below. Off-limits during analysis.
- **EXECUTE** — runs code or resumes the debuggee (python eval, appcall,
  `run_until`). Treat as a deliberate, confirmed action.

### The `PATCH` tier — binary-byte writers (consent-gated)

`patch` (raw byte patch), `patch_asm` (assemble-and-overwrite), and `put_int`
(write an integer at an address) rewrite the analysed program's bytes. They are
the most dangerous mutation the server exposes and are **never used during
analysis** — only on an explicit user request. Each is gated three ways:

- **Server flag.** Refused unless the server runs with `IDA_MCP_ALLOW_PATCH`.
- **Per-call `confirm=true`.** No implicit/default-on path.
- **`dry_run` preview.** Run with `dry_run` to see exactly which bytes would
  change; only after the user approves that preview do you write for real.

Two companion tools manage applied patches:

- **`revert_patch`** — restores the original bytes for a patched range.
- **`list_patches`** — enumerates every patch applied to the IDB (for audit /
  selective revert).

Injected Python (`py_eval` / `py_exec_file`, `EXECUTE`) must likewise not patch
program bytes unless patching has been explicitly allowed.

## Extension gating (`?ext`)

Tools decorated with `@ext("group")` are hidden by default and only appear when
the client connects with the matching `?ext=group` query parameter. Calling a
gated tool without enabling its group returns an `isError` response explaining
how to enable it.

- `@ext("dbg")` — debugger tools (`dbg_*`), live-memory readers, **and the entire
  non-stopping probe / watch / autopilot toolkit**. This is the sole extension
  group; the probes share it because they are meaningless without a live debugger.

The base `/mcp` view exposes all static-analysis tools (including the `ida-domain`
`domain_*` tools); `?ext=dbg` is the only superset.

## Titles and descriptions

`@title("...")` attaches a human-friendly display title; the tool description is
taken from the function docstring. Keep docstrings accurate — they are the
primary thing the client model reads when deciding whether to call a tool.

## Output limiting

Large structured results are automatically truncated for the inline response and
cached server-side; the response carries a `download_url` under
`_meta.ida_mcp` so the full payload can be fetched with `curl`. Prefer narrow,
targeted queries to avoid hitting the limit.
