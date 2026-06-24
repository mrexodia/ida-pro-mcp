# Tool Authoring Guide

This is the end-to-end recipe for adding a high-quality tool to the IDA Pro MCP
server: how to name it, how to write the model-facing docstring, how to type its
parameters and its return value so the MCP layer emits a correct `inputSchema`
and `outputSchema`, which `@safety` class to pick, where to register it, and how
to cover it with a hermetic test that runs under plain `pytest` (no live IDA).

Everything below is grounded in how the server actually builds schemas
(`zeromcp/mcp.py::_build_tool_schema`) and decorates tools (`rpc.py`). Read one
existing tool in `api_core.py` (e.g. `lookup_funcs`, `int_convert`) alongside
this guide — they are the canonical examples.

## The anatomy of a tool

A tool is a plain Python function in one of the `api_*.py` modules, decorated so
the MCP server discovers it and so IDA executes it on the right thread:

```python
@tool
@title("Lookup Functions")
@safety("READ")
@idasync
def lookup_funcs(
    queries: Annotated[
        list[str] | str,
        "One or more function references, each an address (0x401000 / sub_401000) "
        "or a symbol name (e.g. 'main'). Pass '*' to fetch the first 1000 functions.",
    ],
) -> list[LookupFuncResult]:
    """WHAT: ...
    WHEN TO USE: ...
    RETURNS: ...
    PRO-TIP / PITFALL: ...
    """
    ...
```

Decorator order matters. Apply them top-down as:

1. `@tool` — registers the function with `MCP_SERVER` (outermost; it must see the
   final, fully-decorated function so its name, docstring and type hints are intact).
2. `@title(...)` / `@safety(...)` — metadata-only; they set attributes
   (`__mcp_title__`, `__mcp_annotations__`) and return the function unchanged.
3. `@idasync` — innermost of the MCP decorators. It marshals the call onto IDA's
   main thread via `idaapi.execute_sync`. **Any tool that touches the IDB, the
   disassembler, Hex-Rays, or the debugger MUST be `@idasync`.** Pure-arithmetic
   tools that never read IDA state (like `int_convert`) may omit it.

`@idasync` must be the closest decorator to `def` so that what `@tool` registers
is the thread-marshalling wrapper, not the raw function.

## Naming: `verb_noun`, snake_case

Tool names are the function names verbatim — `func.__name__` becomes the MCP
tool `name`. Follow the house style:

- **`verb_noun`**, lower snake_case: `list_funcs`, `get_bytes`, `set_comments`,
  `read_struct`, `find_regex`, `xrefs_to`. The verb says the action; the noun
  says the subject.
- Common verbs already in use: `list_/get_/read_` (read one or many),
  `find_/search_/lookup_` (locate), `set_/rename/declare_/define_` (mutate),
  `analyze_/survey_/trace_` (compute), `dbg_*` (debugger).
- Keep it short and unambiguous. The model picks tools largely by name, so a
  precise verb beats a clever one. Don't shadow an existing tool's verb with a
  near-synonym (`fetch_bytes` vs `get_bytes`) — pick one convention.
- Plural noun when the tool is inherently batch (`lookup_funcs`, `imports`);
  singular when it acts on one target (`read_struct`, `decompile`).

## `@title` — the human-friendly label

`@title("Lookup Functions")` sets `toolDef.title`, a short Title-Case label MCP
clients show in pickers/UX. It is **optional but recommended**. It does not
affect model behavior or schema validation — the docstring does that. Keep it to
2-4 words; do not duplicate the docstring here.

## The docstring IS the tool description

The function docstring is copied verbatim (stripped) into the MCP tool
`description` — it is **model-facing prompt text**, not internal notes. This is
the single highest-leverage thing you write: the model decides whether and how
to call your tool almost entirely from it.

Use the four-part WHAT / WHEN / RETURNS / PRO-TIP|PITFALL structure that the rest
of the server uses:

```python
    """WHAT: Resolve each query to a function and return its descriptor,
    auto-detecting whether the query is an address (0x.. / sub_..) or a name.

    WHEN TO USE: The fast lookup when you already know which function(s) you want
    by address or name; prefer func_query when you need to FILTER or paginate.

    RETURNS: One row per query, each {query, fn, error}; fn is None and error is
    set ("Not found" / "Not a function") when the query does not resolve.

    PRO-TIP: Results are aligned 1:1 and in order with the inputs, so you can zip
    them back. The bulk '*' mode caps at 1000 functions.
    """
```

Rules enforced by `tests/test_tool_metadata.py` (your tool will fail CI otherwise):

- **Non-empty** docstring. Empty docstrings are rejected.
- **Word budget: max 120 words.** Be dense, not verbose — this is the upper bound
  to catch prompt-stuffing, not a target. Aim for ~3-6 sentences.
- **No anti-`py_eval` nudging** — do not write "avoid py_eval / use this
  instead". Describe your tool's job, not other tools' shortcomings.

Beyond CI: always state the WHEN-TO-USE boundary against the nearest sibling tool
(when to use this vs. `func_query`/`list_funcs`), and call out at least one
non-obvious PITFALL (off-by-one, little-endian, lazy init, pagination cap).

## Parameters: `Annotated[Type, "description"]`

Each parameter's type hint is turned into a JSON-schema property
(`_type_to_json_schema`). A parameter with **no default becomes `required`**; a
parameter with a JSON-serializable default is optional and its default is emitted
into the schema. So choose defaults deliberately.

Wrap every non-trivial parameter in `Annotated[T, "..."]` — the second element
is the per-parameter description the model sees:

```python
from typing import Annotated

addr: Annotated[str, "Address as 0x-hex or a symbol name; resolved via parse_address."]
count: Annotated[int, "Max rows to return; defaults to 100, hard cap 1000."] = 100
```

Guidance, including rules enforced by `test_tool_metadata.py`:

- **Param descriptions must be specific.** The bare placeholders `address`,
  `offset`, `count` are rejected — describe the format, units, range, and
  sentinel values (`'*'`, `''`, `0`).
- **Prefer batch-friendly shapes.** The house pattern is `list[X] | X` so a tool
  accepts one item or many. Pair it with `normalize_list_input` /
  `normalize_dict_list` (in `utils.py`) to coerce inside the body.
- **Use a TypedDict for structured inputs** (e.g. `ListQuery`, `EntityQuery` in
  `utils.py`) rather than a free-form `dict`. **Never union a TypedDict shape
  with bare `str` or bare `dict`** (e.g. `list[FooQuery] | FooQuery | str`): the
  loose branch erases the typed schema in the emitted JSONSchema, and
  `test_tool_params_no_bare_string_or_dict_fallback` will fail. Bare `str` is
  only allowed for genuinely scalar params (`addr`, `name`, `path`, ...).
- **Input TypedDicts need a required core.** A `total=False` TypedDict emits
  `required: []`, giving the model no signal. Make the load-bearing field
  required (default `total=True`, mark the rest `NotRequired`), unless the shape
  is a pure filter/pagination wrapper (those are allow-listed in
  `test_tool_param_typed_dicts_have_required_core`).
- Addresses are always passed/returned as **hex strings** (`"0x401000"`), never
  raw ints — use `parse_address` (utils) to decode and `hex(ea)` to encode.

## Return type: a TypedDict for structured output

The return annotation drives the tool's `outputSchema`, which lets MCP clients
validate and structure the result. **Always annotate the return type** and
prefer a `TypedDict` over a bare `dict`:

```python
from typing import TypedDict, NotRequired

class LookupFuncResult(TypedDict):
    query: str
    fn: Function | None       # Function is itself a TypedDict in utils.py
    error: str | None

def lookup_funcs(...) -> list[LookupFuncResult]: ...
```

How the server wraps it (`_build_tool_schema`):

- An **object-like** return (a TypedDict, or a `list`/union of objects) is used
  directly as `outputSchema`. A union-of-objects gets `type: "object"` hoisted on
  so MCP validators accept it.
- A **non-object** return (e.g. a bare `list[str]`, `int`, `bool`) is wrapped as
  `{"result": <schema>}` with `result` required. That's fine, but a named
  TypedDict is clearer to the model — prefer it.
- A `-> None` return emits no `outputSchema`.

Conventions for result shapes:

- Carry an `error: str | None` field rather than raising for *expected* failures
  (not-found, not-a-function), so a batch call returns a row per input instead of
  aborting the whole call. Use `assert_ok` / `assert_error` in tests to check it.
- Define new result/param TypedDicts next to the tool in its `api_*.py`, or in
  `utils.py` if shared. Reuse existing ones (`Function`, `Import`, `Page[T]`,
  `ConvertedNumber`) where they fit.
- Keep outputs bounded. The server truncates any structured result over ~50k
  chars and hands back a download URL (`rpc._install_tools_call_patch`); design
  pagination (`Page[T]`, `next_offset`) into list tools instead of dumping
  everything.

## `@safety` — classify what the tool can do

`@safety(level)` sets the MCP tool annotations the client uses to gate/confirm
calls, and for the dangerous levels it also marks the tool "unsafe" (added to
`MCP_UNSAFE`, gating it behind the server's unsafe-tools allowance). Pick the
*least* powerful level that is still accurate:

| Level | readOnly | destructive | idempotent | openWorld | Use for |
|-------|----------|-------------|------------|-----------|---------|
| `READ` | ✓ | ✗ | ✓ | ✗ | Never mutates the IDB or process state: queries, lookups, decompile, disasm, xrefs, reads. |
| `WRITE` | ✗ | ✗ | ✓ | ✗ | Reversible, idempotent IDB edits: rename, set comment, declare/apply type, define func. |
| `DESTRUCTIVE` | ✗ | ✓ | ✗ | ✗ | Mutations that lose info or are not safely repeatable: patch bytes, undefine, delete. Also → `MCP_UNSAFE`. |
| `EXECUTE` | ✗ | ✓ | ✗ | ✓ | Runs code / touches the outside world: `py_eval`, debugger run/continue, anything non-deterministic. Also → `MCP_UNSAFE`. |

Notes:

- An unknown level raises `ValueError` at import time — typos fail fast.
- `READ` and `WRITE` are *idempotent*: calling twice with the same args yields the
  same end state. If your "write" can't promise that, it's `DESTRUCTIVE`.
- `@safety("DESTRUCTIVE")` and `@safety("EXECUTE")` subsume the legacy `@unsafe`
  decorator — you don't need both. `@unsafe` still works standalone for
  back-compat but new tools should use `@safety`.
- Be honest: a `READ` tool that secretly creates a struct is a correctness and
  trust bug. The hint drives whether a client auto-runs or asks the user.

### Extension gating with `@ext`

If the tool should be hidden unless a client opts in, add `@ext("group")`
(`rpc.py`). E.g. the debugger tools use `@ext("dbg")` and only appear when the
client connects with `?ext=dbg`. The group string is arbitrary and wired lazily.

## Registering the tool

Two things must be true for the tool to go live:

1. **It lives in an `api_*.py` module that `__init__.py` imports.** Registration
   is a side effect of `@tool` running at import time. The existing modules
   (`api_core`, `api_analysis`, `api_memory`, `api_types`, `api_modify`,
   `api_stack`, `api_debug`, `api_python`, ...) are already imported in
   `__init__.py`. **Add your tool to an existing module** that matches its domain
   — that requires no `__init__.py` change.
2. **If you create a brand-new `api_*.py` module**, you must add it to the import
   block in `__init__.py` (and to `__all__`), or its `@tool` functions never run
   and the tool simply doesn't exist. (This file may be outside your edit scope —
   prefer extending an existing module.)

Pick the module by subsystem: core/listing → `api_core`; functions/xrefs/
decompile → `api_analysis`; bytes/strings/search → `api_memory`; types/structs/
enums → `api_types`; rename/comment/define → `api_modify`; stack frames →
`api_stack`; debugger → `api_debug`; arbitrary IDAPython → `api_python`.

## Hermetic test via the conftest idaapi stub

`ida_pro_mcp.ida_mcp` imports native IDA modules (`idaapi`, `idc`, ...) at import
time, which don't exist outside IDA. `tests/conftest.py` solves this: a
meta-path finder installs `MagicMock`-backed fake IDA modules into `sys.modules`
**before** the package is imported, so the package imports and pure-logic runs
under plain `pytest`. A few import-time values are pinned to real values
(`idaapi.get_kernel_version() == "9.3"`, `execute_sync` runs the callback inline).

This means you can unit-test:

- **Pure logic** with no IDA state — parsers, formatters, validation, schema
  shape. `int_convert` is the model: it never touches the IDB, so it runs fully
  under the stub.
- **The decorators / metadata** — that `@safety` set the right annotations and
  `@title` set the label.
- **Error/validation branches** that short-circuit before any real IDA call.

What you generally cannot assert headlessly: the *content* returned from a live
IDB (function lists, real bytes). Those are covered by the in-IDA framework
(`@framework.test`, run via `ida-mcp-test <binary>`); guard them with
`skip_test(...)` when there's no database.

### A pure-logic test (runs under `pytest`)

Put it in `tests/test_api_<module>.py`. Use the project's framework assertions:

```python
from ..api_core import int_convert
from ..framework import test, assert_shape, optional

@test()
def test_int_convert_basic():
    """int_convert returns every representation of a hex literal without an IDB."""
    result = int_convert([{"text": "0x41", "size": 8}])
    assert_shape(
        result,
        [{"input": str, "result": optional(dict), "error": optional(str)}],
    )
    row = result[0]
    assert row["error"] is None
    assert row["result"]["decimal"] == 65
```

### A metadata test (verifies `@safety` / `@title`)

```python
from ..api_modify import rename

@test()
def test_rename_is_write_safe():
    """rename is annotated WRITE (idempotent, non-destructive) and titled."""
    ann = getattr(rename, "__mcp_annotations__", {})
    assert ann.get("readOnlyHint") is False
    assert ann.get("destructiveHint") is False
    assert ann.get("idempotentHint") is True
    assert getattr(rename, "__mcp_title__", None)
```

### Running the tests

The `@test()` decorator (`framework.py`) registers into the framework's own
registry, but each function is a plain callable that `pytest` collects and runs
directly. Run the headless suite from the repo root:

```bash
pytest src/ida_pro_mcp/ida_mcp/tests/test_api_core.py -q
```

`tests/conftest.py` (at `tests/conftest.py` in the repo) installs the IDA stub
before collection, so no IDA process is required. The in-IDA framework runner
(`run_tests(...)` / `ida-mcp-test`) reuses the *same* `@test`-decorated
functions against a real binary when you need live coverage.

## Pre-flight checklist

- [ ] `verb_noun` snake_case name; doesn't collide with an existing tool.
- [ ] Decorators in order: `@tool` → `@title` → `@safety` → `@idasync` (closest to `def`).
- [ ] `@idasync` present iff the tool touches IDA/IDB/Hex-Rays/debugger.
- [ ] Docstring: WHAT/WHEN/RETURNS/PITFALL, < 120 words, no anti-`py_eval` text.
- [ ] Every param is `Annotated[T, "specific description"]`; no `address`/`offset`/`count` placeholders.
- [ ] No TypedDict shape unioned with bare `str`/`dict`; input TypedDicts have a required core.
- [ ] Return type is a TypedDict (or list/union of them); expected failures carried as `error`, not raised.
- [ ] Correct least-privilege `@safety` level; `@ext("...")` if it should be hidden by default.
- [ ] Lives in an imported `api_*.py` (or new module added to `__init__.py`).
- [ ] At least one hermetic test (pure-logic or metadata) green under `pytest`; live behavior guarded with `skip_test`.
- [ ] `pytest src/ida_pro_mcp/ida_mcp/tests/ -q` passes — including `test_tool_metadata.py`.
