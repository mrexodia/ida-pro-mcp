# Scripting & Automation: Driving IDA with py_eval / py_exec_file

The two `EXECUTE`-class tools — **`py_eval`** (inline source) and
**`py_exec_file`** (an absolute-path `.py` on the IDA host) — are the
escape hatch for everything the typed tools don't cover: batch sweeps over
every function, custom xref/data-flow walks, bespoke struct probes, one-off
mutations. This doc is the *automation* playbook — how to write a batch loop
that finishes, the main-thread rule that governs every snippet, how to get a
structured value back, and the clean-room note discipline that keeps the
output shippable.

For the per-API recipe catalogue (enumerate funcs/strings, xrefs, byte reads,
type apply) see **IDAPython Cookbook**. This doc is the layer above: how to
*orchestrate* those recipes into repeatable automation.

> **Reach for a typed tool first.** `list_funcs`, `xrefs_to`, `get_bytes`,
> `analyze_batch`, `decompile`, `find_bytes`, `declare_type`, `rename` are
> validated, schema-typed, batchable, and cheaper. Use `py_eval` only for the
> query no fixed tool expresses. The full picture of which to prefer is in
> **Tools Reference** and **Performance & Scale**.

---

## 1. The execution contract (read before writing any snippet)

Both tools run your code **synchronously on IDA's main thread**, in batch
mode, with one shared namespace, and return a `PythonExecResult`:

```json
{ "result": "<str>", "stdout": "<captured prints>", "stderr": "<traceback or warnings>" }
```

Five facts that follow directly from the implementation:

1. **You are already on the main thread.** Each call is wrapped in
   `idaapi.execute_sync(runned, MFF_WRITE)` by the `@idasync` decorator (write
   mode — even "read" probes get write access because Hex-Rays needs it). See
   the main-thread rule in §2.

2. **Modules are pre-injected.** `idaapi`, `idc`, `idautils`, `ida_bytes`,
   `ida_funcs`, `ida_xref`, `ida_name`, `ida_nalt`, `ida_typeinf`,
   `ida_segment`, `ida_hexrays`, `ida_dbg`, `ida_search`, `ida_strlist`,
   `ida_ua`, `ida_auto`, `ida_loader`, `ida_entry`, `ida_frame`, `ida_kernwin`,
   `ida_lines`, plus dozens more, are in the namespace already — no `import`
   needed for the staples. Two helpers are injected too:
   **`parse_address(s)`** (accepts `"0x401000"`, `"401000"`, or a symbol name)
   and **`get_function(ea)`**. You can still `import` anything else.

3. **Exceptions never raise out of the tool.** A traceback is returned in
   `stderr` with `result`/`stdout` blanked (`py_eval`) or with partial stdout
   preserved (`py_exec_file`). So a failed snippet looks like a success at the
   transport layer — **always inspect `stderr`**, don't trust an empty
   `result` to mean "ran clean."

4. **No sandbox, no undo.** `safety("EXECUTE")` — this is arbitrary code
   against the open IDB and can irreversibly corrupt it. Dry-run mutations
   (print what you *would* change) before applying; see §5.

5. **Bounded by a timeout.** Default 60 s (`IDA_MCP_TOOL_TIMEOUT_SEC`). The
   wrapper arms `ida_kernwin.set_cancelled()` at the deadline, so SDK calls
   that poll `user_cancelled()` (`bin_search`, `find_*`, `decompile`,
   `build_strlist`, `auto_wait`) bail with `BADADDR`/`None` near the limit.
   Long sweeps must self-bound — §3.

---

## 2. The main-thread rule (the one that bites)

Your snippet is **already inside** `execute_sync`. Therefore:

- **NEVER call `idaapi.execute_sync` yourself** inside a snippet. Nesting it
  re-enters the per-thread depth guard in `sync.py` and raises
  `IDASyncError: "Call stack is not empty"` (or deadlocks). The marshaling is
  done *for* you — just call the SDK directly.
- **Don't spawn a thread to call IDA SDK functions.** The IDA SDK is
  single-threaded; calls must happen on the main thread, which is the one
  running your snippet. A worker thread touching `ida_*` is undefined behavior.
- Pure-Python background work (a `threading.Timer`, a `concurrent.futures`
  pool over *non-IDA* data) is technically possible but pointless here — the
  whole call is already serialized on the main thread and bounded by the
  timeout. Keep snippets straight-line.

```python
# WRONG — deadlock / "Call stack is not empty"
def work(): return sum(1 for _ in idautils.Functions())
idaapi.execute_sync(work, idaapi.MFF_WRITE)

# RIGHT — you are already synced; just run it
result = sum(1 for _ in idautils.Functions())
```

---

## 3. Looping over functions safely

The bread-and-butter automation: visit every function, compute something,
return a table. Three things keep it from timing out or dying mid-walk.

### 3a. Self-bound against the deadline

The tool timeout fires `set_cancelled()`, but a tight pure-Python loop that
never calls a polling SDK function won't notice it. **Budget your own time**
and emit a `PARTIAL` marker so a truncated result is still useful:

```python
import time
budget = 45.0                       # under the 60s tool timeout, leaves headroom
start  = time.monotonic()
out, done = [], True
for ea in idautils.Functions():
    if time.monotonic() - start > budget:
        print(f"PARTIAL: stopped before {ea:#x} after {len(out)} funcs")
        done = False
        break
    f = ida_funcs.get_func(ea)
    out.append((f"{ea:#x}", ida_funcs.get_func_name(ea), f.end_ea - f.start_ea))
result = {"done": done, "count": len(out), "rows": out[:200]}
```

> `get_tool_deadline()` exists in `sync.py` but is **not importable from a
> snippet** — use a local `time.monotonic()` budget as above.

### 3b. Materialize before you mutate

`idautils.Functions()` / `Heads()` / `Strings()` are **live generators** over
the database. Adding/removing functions, patching bytes, or renaming *while
iterating* can skip or revisit items. Snapshot first:

```python
eas = list(idautils.Functions())        # freeze the set
for ea in eas:
    ida_name.set_name(ea, derive_name(ea), ida_name.SN_NOCHECK | ida_name.SN_FORCE)
result = len(eas)
```

### 3c. Guard every lookup that can fail

`get_func(ea)` returns `None` for non-function EAs; searches/`get_name_ea`
return `BADADDR`; `get_strlit_contents`/`get_bytes` return `None`; `decompile`
returns `None`. One unguarded `.start_ea` on a `None` aborts the whole sweep
(the traceback lands in `stderr` and you lose every row computed so far unless
you printed progressively). Filter defensively:

```python
BAD = idaapi.BADADDR
rows = []
for ea in list(idautils.Functions()):
    f = ida_funcs.get_func(ea)
    if not f:                              # data / undefined — skip
        continue
    cf = ida_hexrays.decompile(ea)
    if cf is None:                         # decompiler failed — note, don't crash
        rows.append((f"{ea:#x}", "DECOMPILE_FAILED"))
        continue
    rows.append((f"{ea:#x}", str(cf).count("\n")))   # e.g. pseudocode line count
result = rows[:200]
```

### 3d. Restrict the domain before walking it

Don't sweep the whole binary when a segment or an xref cone will do — fewer
items, no timeout. Scope to `.text`, or to the callees of a known entry point:

```python
seg = ida_segment.get_segm_by_name(".text")
funcs = list(idautils.Functions(seg.start_ea, seg.end_ea))
result = len(funcs)
```

---

## 4. Returning a result var

The return convention is **strict** — know which branch you hit:

| Snippet shape | What becomes `result` |
|---|---|
| A single trailing **expression** (last statement is an expression) | that expression's value, `str()`-ified |
| Statements with **no** trailing expression | the variable literally named **`result`**, if set; else `""` |
| `py_exec_file` script | top-level `result` var if non-`None`, else `""` |

There is **no** "last assigned variable" magic — the old heuristic was
removed. If you don't end on an expression and don't assign `result`, you get
an empty string back even though the code ran.

```python
# trailing-expression form (one-liners)
len(list(idautils.Functions()))

# result-var form (multi-statement — the safe default for automation)
counts = {}
for ea in idautils.Functions():
    s = idc.get_segm_name(ea)
    counts[s] = counts.get(s, 0) + 1
result = counts
```

**`result` is `str()`-ified.** A `dict`/`list` round-trips as its `repr`
(parseable-ish but lossy). For clean structured output that survives intact,
**`print(json.dumps(...))`** and read it from `stdout` instead — the
machine-readable channel:

```python
import json
payload = {"funcs": sum(1 for _ in idautils.Functions()),
           "segs":  [s for s in (idc.get_segm_name(e) for e in idautils.Functions())]}
print(json.dumps({"funcs": payload["funcs"]}))   # parse this from stdout
result = "ok"                                     # human-readable status
```

Pattern for large sweeps: **print rows as JSON-lines as you go** (so a timeout
still leaves you the rows printed before it fired), and set `result` to a
summary count:

```python
import json, time
start = time.monotonic(); n = 0
for ea in list(idautils.Functions()):
    if time.monotonic() - start > 45: break
    print(json.dumps({"ea": f"{ea:#x}", "name": ida_funcs.get_func_name(ea)}))
    n += 1
result = f"emitted {n}"
```

---

## 5. py_exec_file: when the snippet outgrows a string

Move to a `.py` file once the logic needs its own helper functions,
recursion, or more than ~30 lines — multi-line strings through `py_eval` get
unreadable and a stray quote breaks the whole call.

- **Path is on the IDA host**, not the MCP client. Pass an **absolute** path
  that exists on the machine running IDA; a relative/wrong-host path returns
  `File not found:` in `stderr`.
- Runs with **one shared globals dict** and `__name__ == "__main__"`, so
  top-level `def`/`class`/`import` are visible everywhere in the script
  (closures and recursion resolve correctly — unlike a naive `exec`).
- Same pre-injected modules and same `result`-var convention as `py_eval`.
- Ideal for **write-to-disk sweeps**: a whole-binary walk that would blow the
  inline timeout can stream results to a file and you read the file out-of-band
  — the file survives even if the tool call itself times out.

```python
# C:/work/sweep_strxrefs.py  — invoke via py_exec_file with this absolute path
import json, time
def callers_of_string(needle: bytes):
    hits = set()
    for s in idautils.Strings():
        raw = ida_bytes.get_strlit_contents(s.ea, s.length, s.strtype) or b""
        if needle in raw.lower():
            for xr in idautils.XrefsTo(s.ea, 0):
                f = ida_funcs.get_func(xr.frm)
                if f:
                    hits.add(ida_funcs.get_func_name(f.start_ea))
    return sorted(hits)

start = time.monotonic()
data = {"packet": callers_of_string(b"packet"),
        "login":  callers_of_string(b"login")}
with open(r"C:\work\strxrefs.json", "w", encoding="utf-8") as fh:
    json.dump(data, fh, ensure_ascii=False, indent=2)
print(f"done in {time.monotonic()-start:.1f}s")
result = {k: len(v) for k, v in data.items()}   # compact summary back over MCP
```

A typed-tool alternative exists for many sweeps — `analyze_batch` folds
decompile/disasm/xrefs/callees for *N* functions into one call. Prefer it when
the per-function output is one of those standard sections; drop to
`py_exec_file` for genuinely custom per-function logic.

---

## 6. Encoding & address hygiene (automation-fatal if ignored)

These compound across a loop — one wrong assumption corrupts every row:

- **Strings are `bytes`, game text is CP949.** `get_strlit_contents` returns
  `bytes`; decode with `.decode("cp949", "replace")`. ASCII/UTF-8 turns Korean
  into mojibake or raises mid-sweep.
- **`doida.exe` is 32-bit.** `BADADDR == 0xFFFFFFFF` here. Format addresses
  with `f"{ea:#x}"` — never hard-code an 8- vs 16-digit width. Branch on
  `ida_ida.inf_is_64bit()` if a script must be portable.
- **Normalize mid-item EAs** with `ida_bytes.get_item_head(ea)` before APIs
  that want an item head.
- **`patch_bytes` edits the IDB, not the live process.** To write the running
  debuggee use the `dbg_write` tool / `ida_dbg.write_dbg_memory`. Don't confuse
  static patches with live memory in an automation that does both.

---

## 7. Clean-room note discipline (non-negotiable for this project)

`py_eval`/`py_exec_file` operate on the **dirty side** of the firewall —
they read the binary and can emit Hex-Rays pseudo-C, autonames (`sub_xxxx`,
`loc_xxxx`), and addresses. Everything they produce is **tainted** until a
human rewrites it into a neutral spec. Rules for automation output:

- **Decompiler / autoname / address output goes only to `Docs/RE/_dirty/`**
  (gitignored quarantine) — never into a committed file, never pasted into C#.
  When a script writes to disk (§5), write under `_dirty/`.
- **What crosses the firewall is neutral prose**, hand-rewritten — never the
  raw `str(cfunc)` or a `result` blob copied verbatim. A sweep produces
  *evidence*; the spec author produces the *spec*.
- **Renames live in the IDB only.** If a batch renames functions to derived
  names, those names are dirty-side legibility aids; the committed glossary
  (`Docs/RE/names.yaml`) is orchestrator-owned and is the canonical source —
  don't let a script invent committed names. The dedicated path for IDB
  writes is the `ida-annotate` skill / `rename`+`declare_type` tools with a
  dry-run → apply gate, not an ad-hoc `set_name` sweep.
- **Pin provenance.** Stamp a sweep's output with the IDB hash so a finding is
  traceable to the exact database state:

```python
print(ida_nalt.retrieve_input_file_sha256().hex())   # pin every dirty dump to this
```

- **Don't fabricate.** If the MCP server is down or the wrong/empty DB is
  loaded, a snippet returns an error or zero rows — report that, never
  back-fill from memory or analogy. The binary is the only ground truth.

---

## 8. Quick reference

| Need | Do |
|---|---|
| One-line query | `py_eval` with a trailing expression |
| Multi-statement query | `py_eval`, end with `result = ...` |
| Structured output intact | `print(json.dumps(...))`, read `stdout` |
| > ~30 lines / helpers / recursion | `py_exec_file`, absolute host path |
| Whole-binary sweep | `py_exec_file` → write under `Docs/RE/_dirty/` |
| Standard per-func decompile/xref batch | `analyze_batch` (typed tool), not a loop |
| Avoid timeout | self-bound with `time.monotonic()`; `print` progress |
| Avoid corruption | snapshot generators with `list(...)`; dry-run mutations |
| Never do | nest `execute_sync`; thread into the SDK; trust empty `result`; commit dirty output |
