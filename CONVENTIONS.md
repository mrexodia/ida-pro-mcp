# CONVENTIONS

Engineering standards for the **Tools** (MCP tools, resources, prompts) and the
**Docs** corpus of `ida-pro-mcp`. This is the contract a contributor follows to
add a tool, a resource, a doc topic, or a prompt without breaking the server.

The server is built on the project-local **`zeromcp`** layer (NOT FastMCP). Tools
are plain Python functions wrapped with the `@tool` decorator from
`ida_pro_mcp.ida_mcp.rpc`; their input/output JSON schemas are generated from the
function's type hints. Everything below describes that idiom as it is actually
shipped.

---

## 1. Project layout

```
src/ida_pro_mcp/ida_mcp/
  rpc.py            # decorators: @tool @resource @prompt @safety @title @ext @unsafe; MCP_SERVER, MCP_UNSAFE, MCP_EXTENSIONS
  sync.py           # @idasync / @tool_timeout (run on IDA main thread); IDAError. Imports idaapi at module top.
  http.py           # HTTP request handler, ?ext gating, /output/<id> download
  trace.py          # always-on tool-call trace (IDB netnode) + ProbeRing / probe registry / record_probe_event
  zeromcp/          # the MCP server core (registry, schema builder, jsonrpc). Excluded from ruff/coverage. Do NOT FastMCP.
  api_core.py       # one module per tool family:
  api_analysis.py   #   core / analysis / memory / types / modify / stack / debug / python /
  api_memory.py     #   resources / survey / composite / probes / sigmaker / docs
  api_types.py
  api_modify.py
  api_stack.py
  api_debug.py
  api_python.py
  api_resources.py  # @resource definitions (browsable IDB state)
  api_survey.py
  api_composite.py
  api_probes.py     # probe/watch/autopilot toolkit (@ext("probes"))
  api_sigmaker.py
  api_docs.py       # search_docs tool + ida://docs resources
  prompts.py        # @prompt slash-command guides
  docs/             # documentation bodies (*.md) + _meta.yaml index  (shipped as package-data)
  tests/            # in-IDA test suite (@test framework, NOT pytest) + mcp_mode round-trip harness
tests/              # repo-root HEADLESS pytest suite (pure-logic; stubs IDA via conftest.py)
```

Every API module is registered by importing it in `__init__.py` (the manifest):
both `from . import api_<name>` in the import block AND the matching entry in
`__all__`. Importing the module is what runs its `@tool` / `@resource` /
`@prompt` decorators and registers them with `MCP_SERVER`.

---

## 2. The `@tool` idiom (NOT FastMCP)

A tool is a plain function decorated with `@tool`. The schema is derived from
type hints, so the hints ARE the contract:

```python
from typing import TypedDict
from .rpc import tool, safety, title

class MyResult(TypedDict):
    value: int
    note: str

@safety("READ")
@title("Do the thing")
@tool
def verb_noun(target: str, limit: int = 5) -> MyResult:
    """One-line WHAT. Then WHEN to use it. Then what it RETURNS.

    The docstring is the tool description the client model reads when deciding
    whether to call the tool. Keep it accurate and self-contained.
    """
    ...
    return MyResult(value=1, note="ok")
```

- **No FastMCP.** Do not import `fastmcp` / `mcp.server.fastmcp`. The decorators
  in `rpc.py` over `zeromcp` are the only registration path.
- **Type hints are mandatory** for every parameter and the return — the schema
  builder reads them. Parameters with defaults become optional in `inputSchema`;
  the default is embedded when it is JSON-serializable.
- **Return a `TypedDict`** (object-shaped) so the result maps to a clean
  `outputSchema`. Non-object returns (e.g. `list[X]`, `str`) are wrapped by the
  builder in a `{"result": ...}` envelope; a `list[TypedDict]` outputs as an
  object-rooted schema. Prefer an explicit `TypedDict` for anything non-trivial.
- **Use `Annotated[T, "description"]`** to document a single parameter.
- **IDA work runs on the main thread:** wrap the IDA-touching body with
  `@idasync` (innermost, under `@tool`). Long waits add `@tool_timeout`.

---

## 3. Adding a TOOL — checklist

1. **Name** it `verb_noun` (see §4). Pick the right `api_*` module by family.
2. **`@title("Human Friendly Title")`** — short display title.
3. **Docstring** = what / when / returns (the model reads it).
4. **Return a `TypedDict`** describing the result shape.
5. **`@safety(CLASS)`** — classify it (see §4); DESTRUCTIVE/EXECUTE auto-register
   as unsafe.
6. **`@idasync`** the IDA-touching body; add `@ext("group")` if it should be
   hidden behind a `?ext` flag.
7. **Register**: the module is already imported in `__init__.py`; if it is a NEW
   module, add `from . import api_<name>` and the `__all__` entry there.
8. **Test** it (see §11). Pure helpers get a headless pytest in repo-root
   `tests/`; in-IDA behavior gets a `@test` in `src/.../tests/`.

Canonical decorator order (outermost → innermost):

```python
@ext("probes")        # optional: extension gating
@safety("EXECUTE")    # safety class (emits annotations, may mark unsafe)
@title("...")         # optional display title
@tool                 # registration (required, must be directly above the fn body wrappers)
@idasync              # run on IDA main thread (for IDA-touching tools)
@tool_timeout(...)    # optional, innermost: bounded waiting tools
def verb_noun(...): ...
```

---

## 4. Tool naming + the 4-class safety reference

**Naming:** `verb_noun`, lower_snake_case (`list_globals`, `set_comments`,
`decompile`, `probe_add`, `search_docs`). Verb first. Keep names stable — they
are the public tool ids in `tools/list`.

**Safety classes** — `@safety(LEVEL)` emits MCP tool annotations and, for the
unsafe levels, adds the tool to `MCP_UNSAFE`:

| Level         | readOnly | destructive | idempotent | openWorld | Unsafe | Use for                                                    |
|---------------|----------|-------------|------------|-----------|--------|------------------------------------------------------------|
| `READ`        | true     | false       | true       | false     | no     | pure queries (disasm, decompile, list, search, drain)      |
| `WRITE`       | false    | false       | true       | false     | no     | idempotent IDB edits (rename, set type, set comment)       |
| `DESTRUCTIVE` | false    | true        | false      | false     | yes    | non-idempotent IDB edits (undefine, delete)                |
| `EXECUTE`     | false    | true        | false      | **true**  | yes    | runs code / resumes debuggee (py_eval, appcall, run_until) |

- `@safety("DESTRUCTIVE")` and `@safety("EXECUTE")` **subsume `@unsafe`** — they
  register the function name into `MCP_UNSAFE` automatically. The standalone
  `@unsafe` decorator still exists for back-compat.
- `EXECUTE` is the only class with `openWorldHint: true` — that is the bit that
  distinguishes "runs/resumes code" from a plain destructive IDB edit.
- Each level's annotation dict is **copied** onto the function (not shared), so
  mutating one tool's annotations never leaks to another.

---

## 5. Resources vs Tools vs Docs — decision rule

- **Resource** (`@resource`) — *browsable read-only state* addressed by a URI.
  Use when the client should be able to GET a named thing (IDB metadata, a doc
  body, a list of strings). No side effects, no expensive on-demand compute that
  needs parameters beyond the URI template.
- **Tool** (`@tool`) — an *action or a parameterized query*: anything that
  mutates state, runs code, or needs arguments richer than a URI path.
- **Doc** (`docs/<topic>.md`) — *human/agent-readable prose* about how the server
  works. Surfaced as the `ida://docs/{topic}` resource and searchable via
  `search_docs`. Use for guidance, not live data.

Rule of thumb: *fetch a known thing by URI → resource; do/compute something →
tool; explain something → doc.*

---

## 6. Resource URI standard

- Scheme is **`ida://`**. Path segments name the thing:
  `ida://idb/metadata`, `ida://docs`, `ida://docs/{topic}`.
- Register with `@resource(uri, mime=...)`. Default mime is
  `application/json`; doc/markdown resources pass `mime="text/markdown"`.
- Templated URIs use `{name}` segments and a matching `Annotated[str, "..."]`
  parameter, e.g. `@resource("ida://docs/{topic}")` with `topic: Annotated[str, "..."]`.
- IDA-touching resources also wrap the body with `@idasync`.
- Return a `TypedDict` (JSON resources) or `str` (markdown/text resources); the
  schema is generated the same way as for tools.

---

## 7. Adding DOCUMENTATION (no code edit)

Documentation is data, not code. To add a topic:

1. Drop `docs/<topic>.md` (the body, raw Markdown).
2. Add a matching entry to `docs/_meta.yaml`:

   ```yaml
   <topic>:
     title: Human Title
     description: One-line summary used in the index and search.
     priority: 60        # higher sorts earlier in the index
   ```

3. That's it — no Python change. The doc is immediately served at
   `ida://docs/<topic>`, listed in `ida://docs`, and indexed by `search_docs`.

`_meta.yaml` uses a **restricted two-level mapping** (top-level topic key, then
2-space-indented `title` / `description` / `priority`). It is parsed by a small
built-in parser (`_parse_simple_yaml`), so no PyYAML dependency — keep entries to
that shape. New `*.md` / `_meta.yaml` files are shipped because
`pyproject.toml` lists `docs/*.md` and `docs/_meta.yaml` under package-data.

---

## 8. Adding a PROMPT

Prompts are slash-command guides surfaced via `prompts/list` / `prompts/get`.
Add a `@prompt`-decorated function in `prompts.py` returning the guide text:

```python
from .rpc import prompt

@prompt
def my_workflow() -> str:
    """One-line summary shown in prompts/list."""
    return "# My workflow\n\n...steps...\n"
```

- The function name is the prompt id; the docstring is its summary.
- Prompts **describe** a workflow — they do not call IDA themselves.
- Add the name to `prompts.py`'s `__all__`.
- Keep prompts in sync with the `docs/` topics they reference.

---

## 9. `search_docs` contract

`search_docs(query: str, limit: int = 5) -> list[DocSearchHit]`, classified
`@safety("READ")`.

- **Tokenization:** lowercased, `[a-z0-9_]+` words. Empty/whitespace query →
  `[]`. (Token equality is exact: `"probe"` does NOT match the token `"probes"`.)
- **Scoring** per topic, summed over query terms:
  `title+topic` token hits ×5, `description` ×2, `body` ×1.
- Topics scoring `<= 0` are dropped.
- **Ordering:** score descending, ties broken by `topic` ascending.
- `limit` clamps the result count; non-int / negative `limit` falls back to 5;
  `limit=0` → `[]`.
- Each hit: `{topic, title, score (float), snippet, uri}` where
  `uri == "ida://docs/{topic}"`.

---

## 10. MCP capability matrix

| Capability     | Decorator                                       | Registry                      | Surfaced as                                                              |
|----------------|-------------------------------------------------|-------------------------------|--------------------------------------------------------------------------|
| Tool           | `@tool` (+ `@safety`/`@title`/`@ext`)           | `MCP_SERVER.tools`            | `tools/list`, `tools/call`                                               |
| Resource       | `@resource(uri, mime=...)`                      | `MCP_SERVER` resources        | `resources/list`, `resources/read`                                       |
| Prompt         | `@prompt`                                       | `MCP_SERVER` prompts          | `prompts/list`, `prompts/get`                                            |
| Unsafe gate    | `@safety("DESTRUCTIVE"\|"EXECUTE")` / `@unsafe` | `MCP_UNSAFE` set              | filtered out under idalib `--unsafe` gating; ⚠️ in HTTP listing          |
| Extension gate | `@ext("group")`                                 | `MCP_EXTENSIONS[group]`       | hidden until client uses `?ext=group` (shipped groups: `dbg`, `probes`, `domain`; comma-combine: `?ext=dbg,probes,domain`) |
| Title          | `@title("...")`                                 | `func.__mcp_title__`          | `title` field in tool schema                                             |
| Annotations    | `@safety(...)`                                  | `func.__mcp_annotations__`    | `annotations` (readOnly/destructive/idempotent/openWorld hints)          |
| Output limit   | (automatic)                                     | `_output_cache`               | truncated inline + `_meta.ida_mcp.download_url`                          |
| Trace          | (automatic)                                     | IDB netnode `$ ida_mcp.trace` | every `tools/call` recorded; export via `ida-mcp-trace-dump`             |

---

## 11. Testing & validation

Two suites:

- **Headless pytest** (`tests/` at repo root): pure-logic units that must run
  without IDA. `tests/conftest.py` installs MagicMock-backed fake IDA modules
  (`idaapi`, `ida_*`, `idc`, `ida_domain`, …) into `sys.modules` via a meta-path
  finder BEFORE the package imports them, so `parse_capture_spec`,
  `build_probe_record`, `ProbeRing`, the `@safety` / `@title` decorators, the
  schema builder, and `search_docs` are all exercisable headless. The suite also
  covers the MCP protocol surface without IDA — `tools/list`, the result
  envelope, schema generation, output truncation, transport / browser guards,
  the no-stdout-prints invariant, the installer scope messages, and the idalib
  supervisor / worker lifecycle. Run the whole suite (or a single file):

  ```bash
  uv --directory . run pytest tests/ -q
  uv --directory . run pytest tests/test_probe_ring.py tests/test_search_docs.py -q
  ```

- **In-IDA suite** (`src/ida_pro_mcp/ida_mcp/tests/`): uses the project's own
  `@test` framework (not pytest) and a `mcp_mode` round-trip harness that runs
  every `@tool` through a real MCP client/server HTTP round-trip and validates
  each response against its advertised `outputSchema`.

After editing any `.py`, byte-compile it:

```bash
uv --directory . run python -m py_compile <file>
```

Keep new pure-logic in a clearly separated, IDA-free section of its module (as
`api_probes.py` does) so it stays headless-testable.

---

## 12. PR checklist

- [ ] Tool named `verb_noun`; in the right `api_*` module.
- [ ] `@tool` (NOT FastMCP) with full type hints; returns a `TypedDict`.
- [ ] `@title` set; docstring states what / when / returns.
- [ ] `@safety(CLASS)` chosen correctly (DESTRUCTIVE/EXECUTE for unsafe ops).
- [ ] `@idasync` on IDA-touching bodies; `@ext` if it should be gated.
- [ ] New module imported in `__init__.py` (import block AND `__all__`).
- [ ] Docs added as `docs/<topic>.md` + `_meta.yaml` entry when behavior is
  user-facing (no code edit needed for docs).
- [ ] Prompts updated/added in `prompts.py` (+ `__all__`) and kept in sync with
  the docs they reference.
- [ ] Headless pytest added for pure logic; in-IDA `@test` for live behavior.
- [ ] `py_compile` clean; pytest green.
- [ ] No FastMCP import, no decompiler/pseudo-C pasted, no hardcoded target
  addresses in tool code.
