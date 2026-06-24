# IDAPython Cookbook

Copy-paste recipes for the IDAPython modules this server leans on:
`idautils`, `ida_funcs`, `ida_bytes`, `ida_xref` / `idautils.XrefsTo`,
`ida_typeinf`, `ida_name`, `ida_nalt`, and the `idc` convenience layer.

Run any of these through the **`py_eval`** tool (inline code) or **`py_exec_file`**
tool (an absolute-path script). Before reaching for raw IDAPython, check whether a
typed tool already does the job — `list_funcs`, `xrefs_to`, `get_bytes`, `patch`,
`declare_type`, `find_bytes`, `decompile`, etc. are faster, validated, and
return structured results. Use `py_eval` for the one-off query no fixed tool covers.

## How execution works here (read this first)

`py_eval` / `py_exec_file` are **already** marshalled onto the IDA main thread for
you (`idaapi.execute_sync(..., MFF_WRITE)` under the hood) and run inside IDA's
batch mode. Consequences:

- **Do NOT call `idaapi.execute_sync` yourself** inside a snippet — you are
  already on the main thread; nesting it deadlocks or raises
  `"Call stack is not empty"`.
- All common modules are **pre-injected** into the namespace: `idaapi`, `idc`,
  `idautils`, `ida_bytes`, `ida_funcs`, `ida_xref`, `ida_typeinf`, `ida_name`,
  `ida_nalt`, `ida_segment`, `ida_hexrays`, `ida_frame`, `ida_entry`, … plus two
  helpers `parse_address(s)` and `get_function(ea)`. You can still `import`
  anything else, but the staples need no import line.
- **Return value convention:** a single trailing **expression** is captured
  (Jupyter-style), OR set a variable named **`result`**. Everything is
  `str()`-ified into the `result` field; `print()` goes to `stdout`; tracebacks
  go to `stderr`. For structured data, build a `list`/`dict` and assign it to
  `result` (it round-trips as its `repr`), or `print(json.dumps(...))`.

```python
# trailing-expression form — value becomes result
import idautils
len(list(idautils.Functions()))
```

```python
# result-variable form — preferred for multi-statement snippets
counts = {}
for ea in idautils.Functions():
    counts.setdefault(idc.get_segm_name(ea), 0)
    counts[idc.get_segm_name(ea)] += 1
result = counts
```

## Gotchas that bite everyone

- **`BADADDR`** (`idaapi.BADADDR`, `0xFFFFFFFF` on 32-bit, `0xFFFFFFFFFFFFFFFF`
  on 64-bit) is the universal "not found / invalid" sentinel. Every search,
  `get_name_ea`, `next_head`, `prev_head`, `decompile`-failure path can hand it
  back. **Always test for it** before using an address; a `BADADDR` fed into
  `ida_bytes.get_bytes` returns garbage or `None`.
- **Address width.** `doida.exe` is 32-bit; masks and printf widths are 32-bit.
  Use `idaapi.get_inf_structure().is_64bit()` (older) or `ida_ida.inf_is_64bit()`
  to branch. Hex-format with `f"{ea:#x}"`, never a hard-coded 8/16 digit width.
- **Strings are bytes.** `ida_bytes.get_strlit_contents` returns **`bytes`**, not
  `str`. Game text is **CP949** — decode with `.decode("cp949", "replace")`, not
  ASCII/UTF-8, or Korean turns to mojibake. Names from `ida_name.get_name` are
  already `str`.
- **Effective address vs. item head.** Many APIs want the *head* of an item.
  Use `ida_bytes.get_item_head(ea)` / `idc.prev_head` to normalize a mid-item EA.
- **Don't mutate while iterating** an `idautils` generator (e.g. patching bytes
  during `idautils.Heads()`); materialize with `list(...)` first.
- **Timeouts.** Long walks are bounded (default 60 s, `IDA_MCP_TOOL_TIMEOUT_SEC`).
  For a whole-binary sweep, prefer `py_exec_file` writing results to disk over a
  giant inline loop, and emit progress with `print()` so a partial result
  survives a timeout.

## Enumerate functions

```python
# every function: ea, name, size
import idautils, ida_funcs
out = []
for ea in idautils.Functions():
    f = ida_funcs.get_func(ea)
    out.append((f"{ea:#x}", ida_funcs.get_func_name(ea), f.end_ea - f.start_ea))
result = out[:50]            # cap inline output; page or write-to-file for all
```

```python
# functions within a segment only
import idautils, ida_segment
seg = ida_segment.get_segm_by_name(".text")
result = [f"{ea:#x}" for ea in idautils.Functions(seg.start_ea, seg.end_ea)]
```

```python
# resolve a function by name, and the func containing an address
import ida_name, ida_funcs
ea = ida_name.get_name_ea(idaapi.BADADDR, "WinMain")   # BADADDR = "no context"
f  = ida_funcs.get_func(parse_address("0x401000"))     # owning func of any EA
result = (f"{ea:#x}", None if not f else f"{f.start_ea:#x}-{f.end_ea:#x}")
```

`get_func(ea)` returns `None` when `ea` is not inside a defined function (data,
or undefined bytes) — a very common source of `AttributeError` on `.start_ea`.

## Enumerate strings

`idautils.Strings()` reads the *string list* IDA already built. If it is empty or
stale, rebuild with `ida_strlist.build_strlist()` first.

```python
import idautils, ida_bytes
res = []
for s in idautils.Strings():
    raw = ida_bytes.get_strlit_contents(s.ea, s.length, s.strtype)
    if raw is None:
        continue
    res.append((f"{s.ea:#x}", raw.decode("cp949", "replace")))   # CP949 for KR text
result = [r for r in res if "login" in r[1].lower()][:30]
```

```python
# build the list if Strings() came back empty
import ida_strlist, idautils
ida_strlist.build_strlist()
result = sum(1 for _ in idautils.Strings())
```

## Walk cross-references

`idautils.XrefsTo` / `XrefsFrom` yield `xref` objects with `.frm`, `.to`,
`.type`, `.iscode`. `ida_xref` has the lower-level `get_first_cref_to` etc.;
prefer the `idautils` generators.

```python
# who references an address (code calls + data reads), with the caller function
import idautils, ida_funcs, ida_name
target = parse_address("0x004012A0")
hits = []
for xr in idautils.XrefsTo(target, 0):
    fn = ida_funcs.get_func(xr.frm)
    where = ida_name.get_name(fn.start_ea) if fn else "(no func)"
    hits.append((f"{xr.frm:#x}", "code" if xr.iscode else "data", where))
result = hits
```

```python
# all references a function makes OUT (its callees + globals it touches)
import idautils
src = parse_address("0x00401000")
result = [(f"{xr.frm:#x}", f"{xr.to:#x}") for xr in idautils.XrefsFrom(src, 0)]
```

```python
# string -> the functions that use it (the fast "find the subsystem" move)
import idautils, ida_bytes, ida_funcs
needle = b"packet"
out = set()
for s in idautils.Strings():
    raw = ida_bytes.get_strlit_contents(s.ea, s.length, s.strtype) or b""
    if needle in raw.lower():
        for xr in idautils.XrefsTo(s.ea, 0):
            f = ida_funcs.get_func(xr.frm)
            if f:
                out.add(ida_funcs.get_func_name(f.start_ea))
result = sorted(out)
```

`XrefsTo(ea, 0)` — the `0` is the `flags` arg; `idaapi.XREF_ALL` (0) keeps even
"flow" xrefs. Pass `idaapi.XREF_FAR`/`XREF_DATA` to filter. Code refs have
`.type` in `fl_CN/fl_CF` (near/far call) or `fl_JN/fl_JF` (jumps); data refs use
`dr_R/dr_W/dr_O` (read/write/offset).

## Read and patch bytes

```python
# read N bytes (returns bytes or None)
import ida_bytes
data = ida_bytes.get_bytes(parse_address("0x00410000"), 16)
result = data.hex(" ") if data else "no data"
```

```python
# typed reads (respect item size / endianness)
import ida_bytes
ea = parse_address("0x00420000")
result = (ida_bytes.get_byte(ea),
          ida_bytes.get_word(ea),     # u16
          ida_bytes.get_dword(ea),    # u32
          ida_bytes.get_qword(ea))    # u64
```

```python
# patch bytes into the IDB (analysis db, NOT the live process)
import ida_bytes
ea = parse_address("0x00401050")
orig = ida_bytes.get_bytes(ea, 2)
ida_bytes.patch_bytes(ea, b"\x90\x90")        # NOP NOP
result = (orig.hex(), ida_bytes.get_bytes(ea, 2).hex())
```

- `patch_bytes` / `patch_byte` edit the **database**, recorded as a patch you can
  later apply to a file with `ida_loader.gen_file`. To change the **live**
  debuggee's memory instead, use the `dbg_write` tool (or `ida_dbg.write_dbg_memory`),
  not `patch_bytes`.
- `get_original_byte(ea)` recovers the pre-patch value; `revert_byte` undoes one.
- After patching code, re-decode with `ida_bytes.del_items` + `ida_ua.create_insn`
  (or the `define_code` tool) so the disassembly reflects the new bytes.

## Search

```python
# byte / mask pattern search (prefer the find_bytes tool for the common case)
import ida_bytes, ida_ida
patcls = ida_bytes.compiled_binpat_vec_t()
# "55 8B EC" with a wildcard: "55 ? EC"
ida_bytes.parse_binpat_str(patcls, ida_ida.inf_get_min_ea(), "55 ? EC", 16)
ea = ida_bytes.bin_search(ida_ida.inf_get_min_ea(),
                          ida_ida.inf_get_max_ea(),
                          patcls, ida_bytes.BIN_SEARCH_FORWARD)
result = "not found" if ea == idaapi.BADADDR else f"{ea[0]:#x}"
```

```python
# immediate-value search (e.g. a magic constant), forward from min_ea
import ida_search, ida_ida
ea = ida_search.find_imm(ida_ida.inf_get_min_ea(),
                         ida_search.SEARCH_DOWN, 0xDEADBEEF)[0]
result = "not found" if ea == idaapi.BADADDR else f"{ea:#x}"
```

```python
# text/name search: resolve a symbol to its address
import ida_name
result = f"{ida_name.get_name_ea(idaapi.BADADDR, 'recv'):#x}"
```

The newer `bin_search` signature returns a tuple `(ea, ...)` in recent IDA — guard
both shapes. For everyday byte hunts the typed **`find_bytes`** tool wraps all of
this and returns clean results; reach for raw `bin_search` only for masked or
multi-pattern sweeps.

## Apply types and rename (ida_typeinf / ida_name)

```python
# rename an address (force=True overrides an existing name)
import ida_name
ok = ida_name.set_name(parse_address("0x00401000"),
                       "net_decrypt_packet",
                       ida_name.SN_NOCHECK | ida_name.SN_FORCE)
result = ok
```

```python
# apply a C declaration as the type of a function/data (parse then apply)
import ida_typeinf
ea = parse_address("0x00401000")
tif = ida_typeinf.tinfo_t()
decl = "int __cdecl decrypt(unsigned char *buf, int len);"
# PT_SIL = silent; til=None uses the local type library
ok = ida_typeinf.parse_decl(tif, None, decl, ida_typeinf.PT_SIL)
applied = ok is not None and ida_typeinf.apply_tinfo(
    ea, tif, ida_typeinf.TINFO_DEFINITE)
result = (ok is not None, applied)
```

```python
# read the existing type of an item back as a C string
import ida_typeinf
tif = ida_typeinf.tinfo_t()
ok = ida_typeinf.get_tinfo(tif, parse_address("0x00401000"))
result = str(tif) if ok else "no type"
```

- The high-level **`declare_type`** / **`set_type`** tools wrap `parse_decl` +
  `apply_tinfo` with validation and clean error messages — prefer them for
  applying struct/function types. Drop to raw `ida_typeinf` only for batch loops
  or introspection (`get_tinfo`, `tif.get_size()`, member iteration).
- For a clean-room project, remember: **rename to neutral, derived names** and
  never paste decompiler-invented identifiers into committed specs. Renames live
  in the IDB (dirty side) only.

## Disassembly and decompilation from Python

```python
# one disassembled line
import idc
result = idc.generate_disasm_line(parse_address("0x00401000"), 0)
```

```python
# iterate instruction heads in a function
import idautils, ida_funcs
f = ida_funcs.get_func(parse_address("0x00401000"))
result = [f"{h:#x}: {idc.generate_disasm_line(h, 0)}"
          for h in idautils.Heads(f.start_ea, f.end_ea)][:40]
```

```python
# decompile one function (Hex-Rays). Output is DIRTY-room pseudo-C.
import ida_hexrays
cf = ida_hexrays.decompile(parse_address("0x00401000"))
result = "decompile failed" if cf is None else str(cf)
```

`ida_hexrays.decompile` returns `None` on failure (and may need
`ida_hexrays.init_hexrays_plugin()` once). The typed **`decompile`** tool already
handles init + errors; use it instead of raw Hex-Rays unless you need the
`cfunc_t` object (ctree, lvars, `cf.get_pseudocode()`).

## Patterns worth keeping

```python
# robust EA resolution: accept "0x401000", "401000", or a symbol name
ea = parse_address("net_recv")     # provided helper; falls back to name lookup
```

```python
# JSON out for anything structured — survives the str() round-trip cleanly
import json, idautils
print(json.dumps({"funcs": sum(1 for _ in idautils.Functions())}))
```

```python
# bound a long sweep so a timeout still yields partial output
import idautils, time
from sync import get_tool_deadline      # not importable in snippet; use time budget
start = time.monotonic()
seen = []
for ea in idautils.Functions():
    if time.monotonic() - start > 45:   # self-bound under the 60s tool timeout
        print(f"PARTIAL: stopped at {ea:#x}")
        break
    seen.append(ea)
result = len(seen)
```

When a query grows past a handful of statements, put it in a `.py` file and call
`py_exec_file` with its absolute path — it runs with one shared global namespace
(top-level defs visible everywhere) and is far easier to iterate on than a giant
inline string.
