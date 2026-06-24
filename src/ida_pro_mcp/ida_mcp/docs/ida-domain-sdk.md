# The ida-domain SDK

`ida-domain` is Hex-Rays' modern, Pythonic API for the IDA database. It wraps the
classic `ida_*` SWIG modules (`idaapi`, `ida_funcs`, `ida_bytes`, `idautils`, ...)
in domain objects — functions, strings, xrefs, types, segments, bytes — so you
work with first-class entities instead of bare effective addresses and integer
flags. This server's higher-level tools (`func_query`, `entity_query`,
`xref_query`, `get_pseudocode`, `basic_blocks`, ...) are built on top of it.

This doc is the orientation you need when you drop into raw IDAPython via
`py_eval` / `py_exec_file` and want the *clean* API rather than the legacy one,
or when you want to understand what the typed tools are doing underneath.

> **Tier note:** `ida-domain` *complements* the SDK; it does not replace it. The
> classic modules are still there and still authoritative for anything the domain
> layer hasn't wrapped. Mixing the two in one script is supported and common.

## Requirements

- **IDA Pro 9.1.0+** (this server targets 9.3).
- **Python 3.9+**.
- Installed with `pip install ida-domain`. It is versioned independently of IDA,
  so it can be upgraded without touching the IDA install.

For **headless** use (a standalone interpreter, not the IDA GUI) the `idalib`
runtime must be reachable. Point it at the install:

```bash
export IDADIR="/path/to/IDA"   # Windows: set IDADIR=C:\Program Files\IDA Pro 9.3
```

When you run code through this MCP server (`py_eval`, `py_exec_file`), you are
already **inside the live IDA process** — `idalib`/`IDADIR` setup does not apply,
and you attach to the open database with the no-argument form (see below).

## The two ways to open a database

`ida-domain` has one entry point, `Database.open`, and its behavior forks on
whether you pass a path.

```python
Database.open(path=None, args=None, save_on_close=True, hooks=None)
```

### Headless (standalone script, idalib)

```python
from ida_domain import Database

with Database.open(path="/samples/doida.idb", save_on_close=False) as db:
    for func in db.functions:
        print(func.name, hex(func.start_ea))
```

- A **path is required**; it spins up the headless kernel against that `.idb`
  (or a fresh disassembly of a binary).
- `save_on_close=False` is the safe default for read-only analysis — it prevents
  an accidental rewrite of the IDB on exit.

### In-GUI / live process (this is the MCP case)

```python
from ida_domain import Database

with Database.open() as db:        # NO path -> attaches to the open database
    print(db.path, db.architecture, hex(db.minimum_ea), hex(db.maximum_ea))
```

> "When running inside IDA, call `Database.open()` with no arguments to get a
> handle to the currently open database."

When you author a `py_exec_file` snippet for this server, **always use the
no-arg form** — you want the database the maintainer already has loaded, never a
second headless kernel. The `?ext=dbg` debugger tools operate on that same live
database.

The `with` block is the idiom: it handles kernel init/teardown and the
save-on-close decision deterministically. Avoid the bare
`db = Database(); db.open(...)` form unless you have a reason — you then own
`db.close()`.

## Database object — top-level handles

| Property | Meaning |
|---|---|
| `db.minimum_ea`, `db.maximum_ea` | address space bounds (use as the range for FlowChart, scans) |
| `db.current_ea` | cursor EA (GUI) |
| `db.architecture` | processor string (e.g. `"metapc"`) |
| `db.path` | IDB path — **echo this to confirm the right DB is loaded before trusting output** |
| `db.metadata` | metadata dataclass (hashes, base, etc.) |

Each entity collection below is reachable as a property on `db` and is iterable.

## Functions — `db.functions`

```python
for func in db.functions:
    print(func.name, hex(func.start_ea), hex(func.end_ea), func.size)

fn   = db.functions.get_all()                  # materialized list
name = db.functions.get_name(func)
sig  = db.functions.get_signature(func)         # prototype
fc   = db.functions.get_flowchart(func)         # FlowChart (see below)
dis  = db.functions.get_disassembly(func)       # list[str]
pc   = db.functions.get_pseudocode(func)        # decompiler output
lvars= db.functions.get_local_variables(func)
```

A `func` object carries `name`, `start_ea`, `end_ea`, `size` directly — no
`get_func()` round-trip. To find the function containing an address, iterate or
fall back to the SDK `ida_funcs.get_func(ea)`.

## Decompilation / pseudocode — `get_pseudocode`

```python
func = next(iter(db.functions))
pc = db.functions.get_pseudocode(func)
text = pc.to_text()        # list[str] of decompiled lines
print("\n".join(text))
```

Pitfalls:

- **Hex-Rays must be present.** `get_pseudocode` depends on the decompiler
  plugin for the target architecture. On a build without it (or an unsupported
  processor) it will fail — guard with `try/except` in a probe and report the
  failure rather than fabricating C. (`ida-domain` does *not* expose an
  availability check; if you need one, fall back to the SDK
  `ida_hexrays.init_hexrays_plugin()`.)
- The output is **dirty-room material** for this project. Pseudo-C with
  `sub_*`, `loc_*`, `_DWORD`, `__thiscall` must never cross the clean-room
  firewall — it lands under `Docs/RE/_dirty/` and is rewritten into neutral
  specs. Prefer the server's `decompile` tool, which routes through the same
  call but tracks provenance.

## Flowchart / basic blocks — `get_flowchart`

```python
fc = db.functions.get_flowchart(func)
for bb in fc:
    print(hex(bb.start_ea), hex(bb.end_ea))
```

Or construct one directly over an address range:

```python
import ida_domain.flowchart
fc = ida_domain.flowchart.FlowChart(db, func, (db.minimum_ea, db.maximum_ea))
for bb in fc:
    print(f"BB 0x{bb.start_ea:x}-0x{bb.end_ea:x}")
```

Basic blocks expose `start_ea` / `end_ea`. For CFG edges (successors /
predecessors), the underlying object is IDA's `BasicBlock`, so `bb.succs()` /
`bb.preds()` from the SDK remain available on the wrapped node. This server's
`basic_blocks` tool returns a normalized, edge-annotated view if you want that
without hand-rolling it.

## Bytes — `db.bytes`

The clean replacement for scattered `ida_bytes.get_byte`/`get_wide_dword`
helpers:

```python
b   = db.bytes.get_byte_at(ea)
w   = db.bytes.get_word_at(ea)
d   = db.bytes.get_dword_at(ea)
q   = db.bytes.get_qword_at(ea)
s   = db.bytes.get_cstring_at(ea)          # NUL-terminated C string
dis = db.bytes.get_disassembly_at(ea)

hit = db.bytes.find_bytes_between(b"\x55\x8b\xec", db.minimum_ea, db.maximum_ea)

is_c = db.bytes.is_code_at(ea)
is_d = db.bytes.is_data_at(ea)
db.bytes.patch_byte_at(ea, 0x90)           # WRITE — only when intended
```

Flag inspection uses the `ByteFlags` IntFlag enum instead of raw `FF_*` masks:

```python
from ida_domain.bytes import ByteFlags
db.bytes.check_flags_at(ea, ByteFlags.CODE)
db.bytes.has_any_flags_at(ea, ByteFlags.BYTE | ByteFlags.WORD)
```

> For game text in this project (CP949 Korean), `get_cstring_at` returns raw
> bytes/latin decoding — re-decode with code page 949 yourself; the SDK has no
> CP949 awareness.

## Strings — `db.strings`

```python
for item in db.strings:
    print(hex(item.address), item.length, str(item))
```

Each item (a `StringItem`) has `address` and `length`; the text is `str(item)`.
The collection is the analyzed string list (Shift-F12 equivalent), so its
contents depend on prior auto-analysis, not a live memory scan.

## Cross-references — `db.xrefs`

```python
for x in db.xrefs.to_ea(target):     # who references target
    print(hex(x.frm), hex(x.to), x.type)
db.xrefs.from_ea(ea)                  # what ea references
db.xrefs.calls_to_ea(fn_ea)          # call-type only
db.xrefs.jumps_to_ea(ea)
db.xrefs.reads_of_ea(global_ea)      # data reads
db.xrefs.writes_to_ea(global_ea)     # data writes
```

The `calls_to_ea` / `reads_of_ea` / `writes_to_ea` filters are the payoff over
raw `idautils.XrefsTo(ea)` — you skip the manual `xref.type` discrimination
that trips people up. An xref's kind is still on `xref.type` (`.name` gives the
symbolic form, e.g. a far-call) when you need the distinction.

## Types — `db.types`

```python
for t in db.types:
    print(t.get_type_name(), hex(t.get_tid()))

til = db.types.load_library("/path/to/types.til")
db.types.parse_declarations(til, "struct Foo { int a; char b[8]; };")
db.types.parse_one_declaration(til, "typedef int handle_t;")
db.types.import_from_library(til)
db.types.export_to_library(til)
db.types.create_library("/out/proj.til", "project types")
```

This is the clean path for local-type / TIL work that otherwise means
`idc.parse_decls` plus `ida_typeinf` juggling. The server's `declare_type` /
`type_apply_batch` tools sit on top of this and add dry-run-then-apply safety.

## Segments — `db.segments`

```python
for seg in db.segments:
    print(seg.name, hex(seg.start_ea), hex(seg.end_ea), seg.size, seg.type)
all_segs = db.segments.get_all()
```

## Names, entries, comments, heads, instructions

```python
for ea, name in db.names:            # (address, name) tuples
    print(hex(ea), name)

for entry in db.entries:             # exports / entry points
    print(entry.name, hex(entry.address), entry.ordinal)

for info in db.comments:
    print(hex(info.ea), info.comment, info.repeatable)

for head_ea in db.heads:             # code/data item starts
    pass

for inst in db.instructions:
    print(db.instructions.get_disassembly(inst))
```

Note that `db.names` yields **tuples**, while `db.entries` and `db.comments`
yield **objects** — easy to mix up. Unpack names as `for ea, name in db.names`.

## When to prefer ida-domain over raw IDAPython

Reach for `ida-domain` when:

- You want **typed, discoverable** access — `func.start_ea` beats remembering
  `func.start_ea` lives on the `func_t` from `ida_funcs.get_func(ea)`.
- You want the **filtered xref helpers** (`calls_to_ea`, `writes_to_ea`) instead
  of hand-filtering `idautils.XrefsTo`.
- You want **iterables** over collections (`db.functions`, `db.strings`) rather
  than `idautils.Functions()` generators that hand back bare EAs.
- You want the `ByteFlags` enum instead of bitmasking `FF_*`.

Stay on the **raw SDK** (or mix it in) when:

- You need a call `ida-domain` hasn't wrapped — segment creation, plugin hooks,
  `ida_hexrays` ctree walking, `appcall`, processor-module specifics. There is
  **no `ProcessorModule` / `appcall` wrapper** in the domain layer today.
- You need the *exact* legacy behavior the rest of the codebase relies on.

Mixing is first-class — pull the EA off a domain object and hand it to the SDK:

```python
import ida_domain, ida_funcs, ida_hexrays

with ida_domain.Database.open() as db:           # live DB
    for func in db.functions.get_all():
        # domain object -> SDK call
        print(ida_funcs.get_func_name(func.start_ea))
        cfunc = ida_hexrays.decompile(func.start_ea)   # SDK ctree
        if cfunc:
            # walk cfunc.body with the SDK visitor API ...
            pass
```

## MCP exploitation tips

- **Confirm the DB first.** In any `py_exec_file` probe, print `db.path` and the
  EA bounds before acting — never trust output if the wrong/empty IDB is loaded
  (STOP and report instead).
- **No-arg open inside the server.** `Database.open()` with no path; never spin a
  headless kernel and never `dbg_start` — the maintainer F9-launches the
  debuggee and you pilot it.
- **One `RESULT_JSON` line.** Wrap freeform domain queries so they emit a single
  machine-readable result line (the `ida-py` skill's harness does this).
- **Prefer the typed tools** (`func_query`, `xref_query`, `entity_query`,
  `get_pseudocode`, `basic_blocks`, `type_inspect`) for routine work — they are
  this exact API plus output limiting, provenance, and dry-run safety. Drop to a
  raw `ida-domain` snippet only for the one-off the fixed tools don't cover.
- **Pseudocode is dirty-room output** — quarantine it under `Docs/RE/_dirty/`,
  rewrite to neutral specs, never paste into committed files or C#.

## Reference

Full upstream reference: `https://ida-domain.docs.hex-rays.com/` (the
machine-readable digest used to ground this doc lives at
`https://ida-domain.docs.hex-rays.com/llms-full.txt`).
