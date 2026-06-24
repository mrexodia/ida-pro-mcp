# MCP Server Architecture

How *this* IDA Pro MCP server is built, end to end. Read this when you want to
add a tool, understand why a call hung or got truncated, enable hidden tools, or
debug a transport problem. Everything below is the real implementation in
`ida_pro_mcp/ida_mcp/` — there is **no FastMCP, no `mcp` SDK, no pydantic**. The
whole MCP stack is hand-rolled on the Python standard library (`http.server`,
`json`, `inspect`, `typing.get_type_hints`) so it can run inside IDA's embedded
CPython with zero pip installs.

## The big picture

```
  MCP client (Claude, Inspector, curl)
        |  JSON-RPC 2.0 over HTTP /mcp (or /sse, or stdio)
        v
  zeromcp/mcp.py  McpHttpRequestHandler   <- parse ?ext=, CORS/Host guard, sessions
        |  registry.dispatch(body)
        v
  zeromcp/jsonrpc.py  JsonRpcRegistry     <- method lookup, param coercion/validation
        |
        v
  McpServer  tools/list, tools/call, resources/*, prompts/*
        |  calls the registered @tool function on the HTTP worker thread
        v
  sync.py  @idasync                        <- marshals onto IDA's main thread
        |  idaapi.execute_sync(..., MFF_WRITE)
        v
  your api_*.py tool body  (idaapi / ida_* / ida-domain)
```

A worker thread per request runs the HTTP handler; the actual IDA work is
trampolined onto the single IDA main thread by `@idasync`. Get that split wrong
and you crash IDA — it is the most important invariant in the codebase.

## The decorator idiom (the zeromcp `@tool` model)

A tool is just a plain Python function with type hints and a docstring. You
register and classify it by stacking decorators. The canonical full stack, from
**outermost to innermost**, is:

```python
from .rpc import tool, safety, title, ext
from .sync import idasync, tool_timeout

@ext("dbg")             # optional: hide behind ?ext=dbg (the sole group)
@safety("EXECUTE")      # optional: safety class + MCP annotations
@title("Run until hit") # optional: human-friendly toolDef.title
@tool                   # REQUIRED: registers into MCP_SERVER.tools
@idasync                # REQUIRED for any tool touching IDA state
@tool_timeout(120.0)    # optional: per-tool timeout override (INNERMOST)
def run_until(timeout_ms: int, target_ea: str | None = None) -> RunResult:
    """One-line summary becomes the tool description."""
    ...
```

Why this order matters:

- `@tool` must see the function *after* `@idasync` has wrapped it, so the
  registered callable is the main-thread-marshaling one. `@tool` is just
  `MCP_SERVER.tool(func)` (`rpc.py`), which calls `self.tools.method(func)` and
  invalidates the schema cache.
- `@safety` / `@title` / `@ext` set `__mcp_*__` attributes / populate registries.
  They wrap *around* `@tool` so the attributes are visible when `tools/list`
  later reflects over the function via `getattr`.
- `@tool_timeout` and `@keep_batch` set attributes read **inside** `@idasync`'s
  wrapper, so they must be applied to the raw function — i.e. listed **after**
  `@idasync` (innermost). Put them above `@idasync` and they are silently lost.

There is **no schema written by hand**. The function signature *is* the schema
(next section). A read-only tool that does no IDA work can be as short as
`@safety("READ")` + `@tool` (see `search_docs` in `api_docs.py`).

### Resources and prompts use the same idiom

```python
@resource("ida://idb/segments")          # static resource
@idasync
def idb_segments_resource() -> list[Segment]: ...

@resource("ida://docs/{topic}", mime="text/markdown")   # templated resource
def docs_topic_resource(topic: Annotated[str, "topic id"]) -> str: ...

@prompt
def crypto_hunt() -> str: ...            # returns guide text, no IDA calls
```

`{param}` in a resource URI makes it a *template* (listed under
`resources/templates/list`); the server turns `{param}` into a regex named group
and binds matches positionally to the function args (`_mcp_resources_read`).

## The schema engine (`McpServer._build_tool_schema`)

On `tools/list`, the server reflects each function with
`typing.get_type_hints(func, include_extras=True)` and `inspect.signature`, then
maps Python types to JSON Schema in `_type_to_json_schema`:

| Python hint | JSON Schema |
|---|---|
| `int / float / str / bool` | `integer / number / string / boolean` |
| `list[T]` | `{"type":"array","items": <T>}` |
| `dict[str, T]` | `{"type":"object","additionalProperties": <T>}` |
| `X \| Y`, `Optional[X]` | `{"anyOf": [...]}` |
| `Annotated[T, "desc"]` | `<T>` + `"description": "desc"` |
| `TypedDict` | `object` with `properties` + `required` + `additionalProperties:false` |
| `Any` | `{}` (unconstrained) |
| `NotRequired[T]` | unwrapped to `<T>` |

Pro-tips and gotchas:

- **Describe params with `Annotated`.** `addr: Annotated[str, "Effective
  address (hex)"]` is the only way to attach a per-parameter description; it
  lands in `inputSchema.properties.addr.description`.
- **Defaults become `required` omission + a `default` key.** A param with a
  default is dropped from `required`; if the default is JSON-serializable it is
  also emitted as `"default"`. Non-serializable defaults are silently skipped
  (no crash, just no default in the schema).
- **Return types drive `outputSchema` and structured output.** If the function
  has a non-`None` return annotation, it becomes `outputSchema`. Non-object
  returns (e.g. `-> list[Hit]`) are wrapped as
  `{"type":"object","properties":{"result": <...>}}` because `tools/call` only
  passes *dicts* through unwrapped (see below). A `TypedDict` / `dict` return
  flows through as `structuredContent` directly.
- **Schemas are memoized** per function object in `_tool_schema_cache` and
  invalidated on every registry mutation (`invalidate_tool_schema_cache`). Reflection
  over TypedDicts is expensive; this keeps `tools/list` cheap.
- Use `TypedDict` (with `total=False` for partial results, e.g.
  `DebugControlResult`) for any structured return. It gives clients a real
  output schema and lets the test framework's `assert_typed_dict` validate it.

### `tools/call` result shaping

`_mcp_tools_call` dispatches the tool through the JSON-RPC registry, then wraps
the result into MCP's content envelope:

```json
{
  "content": [{"type": "text", "text": "<json>"}],
  "structuredContent": <dict-result, or {"result": <non-dict>}>,
  "isError": false
}
```

On top of that, `rpc.py` monkey-patches `tools/call` (`_install_tools_call_patch`)
to enforce an **output size limit** of `OUTPUT_LIMIT_MAX_CHARS = 50000`. If the
serialized `structuredContent` exceeds it, the full result is cached under a
UUID, a depth/breadth-truncated *preview* is returned instead, and `_meta.ida_mcp`
carries a `download_url` (`/output/<id>.json`) plus a `curl` hint. The full
payload is fetched lazily by the HTTP handler (`_handle_output_download` in
`http.py`). Implication: a tool can return a huge list safely — the client sees a
preview and a download link, never a 2 MB blob inline.

## `@idasync` — main-thread marshaling

`sync.py` is the heart of correctness. IDA's SDK is **not** thread-safe; almost
everything must run on IDA's main (UI) thread. `@idasync` wraps a tool so its
body executes via `idaapi.execute_sync(runned, idaapi.MFF_WRITE)` while the HTTP
worker thread blocks on a `queue.Queue` for the result.

Key design points:

- **One unified decorator.** There is no `@idaread`/`@idawrite` split anymore —
  even "read" operations (decompilation, type creation as a side effect) can need
  write access, so everything uses `MFF_WRITE`.
- **Batch mode is forced on.** Inside `_sync_wrapper`, `idc.batch(1)` suppresses
  UI refresh/dialogs for the duration, then restores the prior value. This makes
  bulk operations fast and non-interactive. Opt out with `@keep_batch` when the
  tool schedules async work that runs *after* `execute_sync` returns (e.g.
  `start_process` popping a dialog later); that tool must restore batch itself,
  typically from a `DBG_Hooks` callback. Read the pre-call value via
  `get_pre_call_batch()`.
- **Per-thread re-entrancy guard.** `_call_depth_state` is a `threading.local`
  depth counter. If a tool body (on the same thread) invokes another `@idasync`
  function, depth > 0 and it raises `IDASyncError("Call stack is not empty")`.
  This used to be a global LifoQueue that spuriously collided across concurrent
  requests — it is now per-thread, so parallel tool calls on different worker
  threads don't fight. **Do not call one `@idasync` tool from inside another;**
  factor out a plain helper instead.
- **Timeouts + cancellation.** `sync_wrapper` arms two mechanisms when a deadline
  or a client cancel token exists:
  1. A `threading.Timer` fires `ida_kernwin.set_cancelled()` at the deadline.
     Many SDK calls (`find_bytes`, `decompile`, `build_strlist`, `auto_wait`,
     ...) poll `user_cancelled()` and bail with `BADADDR`/`MERR_CANCELED`,
     freeing the main thread instead of running to completion. `set_cancelled()`
     is thread-safe, so firing it from the Timer is allowed.
  2. A `sys.setprofile` hook checks the request-level cancel event (MCP
     `notifications/cancelled`, LSP error `-32800`) and the monotonic deadline on
     every Python call, raising `CancelledError` / `IDASyncError`. The profiler
     is only installed when a deadline or cancel token is actually armed (no
     overhead otherwise), and there's a 5 s grace window after native cancel so a
     tool can format a *partial* response.
- **Self-monitoring for tight loops.** GIL contention can starve the profiler on
  hot native loops, so long-walking tools should read `get_tool_deadline()` and
  bail cleanly: `if time.monotonic() >= (get_tool_deadline() or inf): break`.
  Default timeout is 60 s (`IDA_MCP_TOOL_TIMEOUT_SEC`); override per-tool with
  `@tool_timeout(seconds)`.

## The `@safety` 4-class model

`@safety(level)` (`rpc.py`) classifies a tool and emits the MCP
`toolAnnotations` hints, so a client / config UI can reason about risk:

| Level | readOnly | destructive | idempotent | openWorld | Also marks UNSAFE? |
|---|---|---|---|---|---|
| `READ` | true | false | true | false | no |
| `WRITE` | false | false | true | false | no |
| `DESTRUCTIVE` | false | true | false | false | **yes** |
| `EXECUTE` | false | true | false | **true** | **yes** |

- `READ` — pure inspection (disasm, decompile, list functions, `search_docs`).
- `WRITE` — idempotent IDB mutation (rename, set comment, declare type).
- `DESTRUCTIVE` — non-idempotent / data-losing IDB change (undefine, delete
  stack var, clear probes).
- `EXECUTE` — runs code in the target / debuggee (`run_until`, `dbg_continue`,
  `py_exec_file`); `openWorldHint` signals effects outside the IDB.

`DESTRUCTIVE` and `EXECUTE` automatically add the function name to `MCP_UNSAFE`
(so `@safety` subsumes the legacy `@unsafe` decorator for those levels). The
config UI (`/config.html`) flags `MCP_UNSAFE` tools with a ⚠️ and offers a
"Disable unsafe" quick toggle. The annotation is advisory metadata — the server
does not itself refuse unsafe calls; gating is left to the client / operator and
to the per-tool enable list.

## `@ext` capability gating (`?ext=dbg`)

By default the heavy/dangerous live-debugger tools are **hidden**. `@ext("group")`
registers a tool into `MCP_EXTENSIONS[group]`; it is invisible in `tools/list`
and refused by `tools/call` unless the request URL carries `?ext=group`.

How it flows:

- The HTTP handler parses `?ext=dbg` once per request
  (`_parse_extensions`) into a set and stashes it in a `threading.local`
  (`_enabled_extensions`).
- `tools/list` skips any tool whose group isn't enabled
  (`_get_tool_extension` + the enabled set).
- `tools/call` on a hidden tool returns an error: *"Tool 'x' requires extension
  'dbg'. Enable with ?ext=dbg"*.

Groups are **arbitrary strings, wired lazily** — `@ext("dbg")` needs no extra
registration; the server resolves any group generically. There is exactly one
group in use:

- `?ext=dbg` — the live debugger toolset (`api_debug.py`: breakpoints, registers,
  step, `dbg_read`/`dbg_write`, stacktrace) **plus the entire non-stopping
  probe / watch / autopilot toolkit** (`api_probes.py`), which is meaningless
  without a live debugger and so shares the gate.

The repo's `.mcp.json` registers the URL `http://127.0.0.1:13337/mcp?ext=dbg` so
the static **and** debugger tools are both visible from one connection.
**Pitfall:** if the `dbg_*` / `probe_*` tools are "missing", you are almost
certainly connected to the base `/mcp` with no `?ext=`. Re-register with the
query string. The `ext` param works on both `/mcp` (Streamable HTTP) and `/sse`.

## Resources & the docs subsystem

Resources model browsable, read-only state (MCP philosophy: *tools act,
resources are read*). `api_resources.py` exposes `ida://idb/metadata`,
`ida://idb/segments`, `ida://cursor`, `ida://struct/{name}`, `ida://xrefs/from/{addr}`,
etc. A `str` handler result is emitted verbatim (markdown/plain text round-trips);
anything else is JSON-encoded.

The **docs subsystem** (`api_docs.py` — this file's neighbor) is a self-contained,
zero-code-change knowledge base:

- Bodies are Markdown files in this `docs/` package directory.
- `docs/_meta.yaml` indexes them: `topic -> {title, description, priority}`. It
  is parsed by a tiny restricted-YAML parser (two-level mapping only) to avoid a
  PyYAML dependency — so keep entries to top-level `topic:` + 2-space-indented
  `title/description/priority`.
- `ida://docs` returns a generated index (ordered by descending `priority`);
  `ida://docs/{topic}` returns one body; `search_docs(query, limit)` is a
  term-frequency search weighting title (×5) > description (×2) > body (×1).

**Adding a doc requires no code:** drop `mytopic.md` here and add a matching
`_meta.yaml` entry. Bodies and meta are cached (`_body_cache`, `_meta_cache`);
restart IDA to pick up edits. Keep `prompts.py` guides in sync with the doc set.

## Transports

`zeromcp/mcp.py` serves three transports from one `McpServer`:

1. **Streamable HTTP** — `POST /mcp`. Protocol version `2025-06-18`. The first
   `initialize` mints an `Mcp-Session-Id` (echoed on every response). Notifications
   return `202 Accepted`; calls return `200` with the JSON-RPC result.
2. **HTTP+SSE** (legacy) — `GET /sse` opens the event stream and emits an
   `endpoint` event with `/sse?session=<id>`; the client `POST`s JSON-RPC there
   and the response comes back as an SSE `message` event. Protocol `2024-11-05`.
   30 s keep-alive pings; disconnects are detected via `select()` + `MSG_PEEK`.
3. **stdio** — `McpServer.stdio()`, line-delimited JSON-RPC on stdin/stdout, for
   embedding without a socket.

Security hardening baked into the handler:

- **DNS-rebinding defense:** when bound to loopback, `Host` headers that don't
  resolve to loopback are rejected (`_host_header_allowed_for_bind`), and a
  disallowed `Origin` is `403`'d — closing the same-origin CORS bypass.
- **CORS policy** is operator-configurable via `/config.html`
  (`unrestricted` / `local` / `direct`); default `local` allows only
  `localhost`/`127.0.0.1` on any port.
- **Body limits + decompression:** 10 MB `post_body_limit`, gzip/deflate request
  bodies supported, chunked transfer decoded with the same cap.
- **Reverse-proxy aware:** `X-Forwarded-*` / `Forwarded` / a custom
  `X-IDA-MCP-External-Base` header are honored to build correct external
  download URLs behind a proxy.
- **Per-tool enablement** is persisted in the IDB itself via netnodes
  (`http.py` `config_json_get/set` on `$ ida_mcp.enabled_tools`), so a profile of
  enabled tools survives restarts and travels with the database.

## Error model

- Tool bodies raise `IDAError` (`sync.py`) for clean, user-facing failures — it
  subclasses `McpToolError`, which `McpRpcRegistry.map_exception` turns into
  JSON-RPC code `-32000` with just the message (no traceback leak).
- Unexpected exceptions become `-32603` with a formatted traceback (unless
  `redact_exceptions` is set).
- Cancellation surfaces as `-32800` (LSP "request cancelled").
- Param validation lives in `jsonrpc.py` `_call`: missing/extra params and type
  mismatches raise `-32602`. Note the **string-JSON coercion hack** — when a
  union param doesn't include `str` but the client sends a JSON string (some MCP
  clients stringify objects), it is `json.loads`-parsed before validation. Design
  list/dict params with this in mind.

## Cheat sheet: adding a tool

1. Pick the right `api_*.py` module (or make one and import it in `__init__.py`).
2. Write a function with `Annotated` params and a `TypedDict`/typed return.
3. Stack decorators: `@safety(...)` → (`@title`) → `@tool` → `@idasync` →
   (`@tool_timeout`). Add `@ext("dbg")` if it should be hidden (the sole group).
4. Touch IDA only through `idaapi`/`ida_*`/`ida-domain` *inside* the body — never
   from module top level, never from another `@idasync` body.
5. Return small; large results auto-truncate with a download link.
6. Add a `@test()` in the same module (see `framework.py`) and run
   `ida-mcp-test <binary>` to verify the shape with `assert_typed_dict` /
   `assert_ok`.
