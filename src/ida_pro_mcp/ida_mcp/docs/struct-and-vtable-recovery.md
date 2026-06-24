# Recovering C++ Object Layouts, vtables & RTTI (via MCP)

This is the end-to-end recipe for turning `this`-relative access patterns in a C++
binary into a *declared* struct in the IDB, confirming that struct against a real
object at a live pointer, and walking a vtable to recover a polymorphic interface.
Every fact here is **measured against the loaded database** — never inferred from
memory or analogy.

> Tool names below are the bare `@tool` names. Over the wire they appear as
> `mcp__ida__<name>` (e.g. `mcp__ida__read_struct`). `tools/list` is authoritative
> for the exact schema.

The four pillars used throughout:

| Step | Tool | Safety |
|---|---|---|
| Define a recovered struct/enum | `declare_type` / `enum_upsert` | DESTRUCTIVE (writes IDB) |
| Attach a type to an address/local/stack | `set_type` / `type_apply_batch` | DESTRUCTIVE |
| Confirm a layout against bytes at an address | `read_struct` | READ |
| Confirm against a *live* object | `dbg_read` + `read_struct` | READ |

---

## 1. The mental model: an object is `this` + offsets

A C++ method is just a function whose first argument is `this` — the pointer to the
object. On 32-bit MSVC (the common legacy target) `this` arrives in **ECX**
(`__thiscall`); on x64 it is **RCX/`a1`**. Every field access in the decompiler then
looks like a constant offset off that pointer:

```c
// Hex-Rays of a __thiscall method (DIRTY — never paste into committed code)
v3 = *(_DWORD *)(this + 0x10);      // field at +0x10, 4 bytes
*(float *)(this + 0x2C) = a2;       // field at +0x2C, float
result = (*(int (__thiscall **)(...))(*(_DWORD *)this + 4))(this);  // vtable call
```

Read those three lines as a layout sketch, not as code:

- `*(_DWORD *)this` (offset 0) is the **vtable pointer** — its presence proves the
  class is polymorphic and pins the vtable's data address.
- `*(... )(this + 0x10)` → a `uint32_t`/pointer field at `+0x10`.
- `*(float *)(this + 0x2C)` → a `float` field at `+0x2C`.
- `(*(...)(*this + 4))(this)` → an **indirect call through vtable slot 1**
  (offset `+4` on 32-bit = slot index 1; `+8` per slot on 64-bit).

The whole recovery job is: collect every distinct offset, infer each field's width
and type from how it is used, fill the gaps, then `declare_type` the result.

> Pitfall — `this` is not always a method receiver. A "fat" struct passed by
> pointer to a free function reads identically. The vtable pointer at offset 0 is
> your strongest signal it is a real C++ polymorphic object.

---

## 2. Recipe: recover a layout from access patterns

### 2.1 Find the constructor (best anchor)

The constructor is where the vtable is *installed* and where most fields get their
first write — the single richest function for layout recovery. Locate it by
finding code that stores a vtable address into `[this+0]`:

```jsonc
// 1) Who writes near offset 0 of objects of this class? Decompile a method first.
decompile({ "ea": "0x401820" })
```

Look for the `*this = &vtable_addr;` store. Then pivot to **everything that uses
that vtable address** — those are the class's methods and its `new`/factory sites:

```jsonc
xrefs_to({ "ea": "0x4C8F30" })       // 0x4C8F30 = the vtable data EA
```

### 2.2 Harvest offsets across ALL methods, not one

A single method touches only a few fields. Decompile the constructor plus a handful
of the methods you found via the vtable xrefs, and union their offsets. Batch it:

```jsonc
decompile([
  { "ea": "0x401820" },   // ctor
  { "ea": "0x401C40" },   // a getter
  { "ea": "0x402010" }    // an update method
])
```

For each `*(T *)(this + OFF)` record `(OFF, sizeof(T), kind)`. Build a table:

| offset | width | inferred type | evidence |
|---|---|---|---|
| 0x00 | 4 | vtable ptr | `*this = &off_4C8F30` in ctor |
| 0x04 | 4 | `int` health | `*(_DWORD*)(this+4)` compared, decremented |
| 0x10 | 4 | ptr → another obj | passed as `this` to another method |
| 0x2C | 4 | `float` x | `*(float*)(this+0x2C)` in math |
| 0x30 | 4 | `float` y | adjacent, same math |

### 2.3 Infer widths you cannot see directly

- Access *width* = the cast: `_BYTE`=1, `_WORD`=2, `_DWORD`=4, `_QWORD`=8,
  `float`=4, `double`=8.
- A field passed as the `this`/ECX of *another* method is a **pointer to a nested
  object** — recover that class too and make the field a typed pointer.
- Unobserved gaps stay as padding bytes: `char gap_8[8];`. Do **not** invent fields
  to fill them; an honest gap is correctable later, a wrong field corrupts every
  downstream read.
- The total size is bounded below by `max(offset)+width`, and pinned exactly if you
  can find the allocation: `operator new(0x40)` ⇒ the object is `0x40` bytes.

### 2.4 Cross-check a field with `xrefs_to_field`

Once a *tentative* type exists, you can ask IDA for every site that touches one
field — invaluable for confirming a field's role and width is consistent:

```jsonc
xrefs_to_field({ "struct": "CActor", "field": "health" })
```

### 2.5 Declare it

Declare base/nested types first so later decls can reference them. `declare_type`
accepts several decls in one call and parses each independently:

```jsonc
declare_type([
  "struct CVec3 { float x; float y; float z; };",
  "struct CActor {"
  + " void *vtbl;"           // +0x00
  + " int health;"           // +0x04
  + " char gap_8[8];"        // +0x08 unobserved
  + " CVec3 *target;"        // +0x10
  + " char gap_14[24];"      // +0x14
  + " CVec3 pos;"            // +0x2C
  + " };"
])
```

The recovery is now *in the type library* but **not attached to anything**. Two
separate steps — defining a type and applying it — and forgetting the second is the
single most common confusion.

> Pitfall — declaration **order within a call** only matters when a later item
> names an earlier one. List `CVec3` before `CActor`. A conflicting redefinition
> surfaces as a parse `error` in that item's result entry — it does **not** silently
> overwrite — so re-declaring an identical struct is harmless and idempotent.

---

## 3. Confirm the layout at a pointer with `read_struct`

A declared struct is a *hypothesis* until you overlay it on real bytes. `read_struct`
takes the type + an address (or a symbol name in `addr`) and returns each member's
offset, type, size, and decoded value:

```jsonc
read_struct({ "addr": "0x6A1F40", "struct": "CActor" })
```

```jsonc
// returns
{ "addr": "0x6A1F40", "struct": "CActor", "members": [
  { "offset": "0x00000000", "type": "void *", "name": "vtbl",   "size": 4, "value": "0x004C8F30" },
  { "offset": "0x00000004", "type": "int",    "name": "health", "size": 4, "value": "0x00000064 (100)" },
  { "offset": "0x00000010", "type": "CVec3 *","name": "target", "size": 4, "value": "0x006A2210" },
  { "offset": "0x0000002C", "type": "float",  "name": "x",      "size": 4, "value": "[00 00 80 3F...]" }
]}
```

How to read the result for confirmation:

- **`vtbl` value equals the vtable EA you found in §2** → the layout is anchored
  correctly; offset 0 is genuinely the vtable pointer.
- A `health` of `100` (`0x64`) is a *plausible* value → field width/offset look
  right. A garbage value (e.g. `0x80808081`) means your offset or width is off by a
  few bytes; nudge the gap sizes and re-`declare_type`.
- Omit `"struct"` to reuse whatever type IDA already has applied at `addr`
  (auto-detected) — handy after you `set_type` the global.

> Pitfall — `read_struct` is **BSS-aware**: bytes in uninitialized segments come
> back as **zero**, matching runtime zero-init. An all-zero member can mean
> "unmapped/not yet written" rather than "the value is actually 0." `offset` is the
> member's offset *within the struct*, not an absolute address. The struct must
> already exist (`declare_type` first) or you get `Struct '…' not found`.

### Attach the type so the decompiler uses your names

To make every method's pseudocode show `actor->health` instead of
`*(_DWORD*)(this+4)`, apply the struct as the type of the `this` local (or the
global instance):

```jsonc
// Type the global object instance
set_type({ "addr": "0x6A1F40", "type": "CActor" })

// Type the 'this' local in a method so the WHOLE function re-renders with fields
set_type({ "addr": "0x402010", "variable": "this", "type": "CActor *" })
```

Batch many at once and get an aggregate pass/fail roll-up:

```jsonc
type_apply_batch({ "stop_on_error": false, "edits": [
  { "addr": "0x402010", "variable": "a1",   "type": "CActor *" },
  { "addr": "0x401C40", "variable": "this", "type": "CActor *" }
]})
```

> Pitfall — `set_type`/`type_apply_batch` are **DESTRUCTIVE** (they mutate the IDB).
> They fail if any referenced type is not declared yet — declare the whole
> dependency closure first. A failed apply returns `{ ok:false, error:... }` per
> edit rather than throwing.

---

## 4. Confirm against a LIVE object (the ground-truth pass)

Static bytes show the *initialized* image; only a running process shows the object
**as it actually is at runtime** (post-ctor, with real pointers resolved). The
sequence: break in a method, read `this`, dump the live bytes, overlay the struct.

1. Break where you have a `this` in hand (a method entry). With the maintainer's
   already-launched debug session, set the breakpoint and continue:

   ```jsonc
   dbg_add_bp({ "ea": "0x402010" })
   dbg_continue({})
   ```

2. When it hits, read the `this` register (32-bit `__thiscall` → ECX):

   ```jsonc
   dbg_regs_named({ "names": ["ecx"] })   // -> { "ecx": "0x06A1F40" }
   ```

3. Dump the live object's bytes through the debugger. **`dbg_read` reads through
   `PAGE_NOACCESS`** guard pages that a static read would miss:

   ```jsonc
   dbg_read({ "addr": "0x06A1F40", "size": 64 })
   // -> { "data": "308f4c00 64000000 ...", "size": 64 }
   ```

4. Overlay the struct on the **static** image of the same EA with `read_struct`, OR
   decode the live hex by hand against your offset table. If the live `vtbl` (first
   4/8 bytes) matches the vtable EA and the scalar fields hold sane values, the
   layout is **confirmed against ground truth**.

> Pitfalls — (a) `read_struct` overlays the *static* DB, not debuggee memory; to
> validate runtime values use `dbg_read` and compare offsets manually. (b) On x64,
> `this` is RCX (`dbg_regs_named({"names":["rcx"]})`) and vtable slots are 8 bytes
> apart. (c) Heap objects move between runs — re-read `this` each hit, never reuse a
> previous run's address. (d) Never call `dbg_start`; drive the maintainer's
> existing session.

---

## 5. Walking the vtable & RTTI

The vtable is a flat array of function pointers at the EA stored in `[this+0]`. Slot
*N* lives at `vtable_ea + N*ptr_size` (4 bytes on x86, 8 on x64).

### 5.1 Enumerate the slots

```jsonc
// Read the first 8 slots of a 32-bit vtable as raw pointers
get_bytes({ "addr": "0x4C8F30", "size": 32 })          // 8 * 4 bytes
// or one slot at a time, decoded:
get_int([
  { "ty": "u32le", "addr": "0x4C8F30" },               // slot 0
  { "ty": "u32le", "addr": "0x4C8F34" },               // slot 1
  { "ty": "u32le", "addr": "0x4C8F38" }                // slot 2
])
```

Each value is a method address — `decompile`/`func_query` each to role-tag the slot
(slot 0 is very often the destructor on MSVC). Stop enumerating when a "pointer"
falls outside the code segment or lands on the *next* class's vtable / RTTI data —
that is the array's end.

### 5.2 Declare the vtable as a function-pointer struct

Model the vtable so calls render as `obj->vtbl->Method()`:

```jsonc
declare_type([
  "struct CActor_vtbl {"
  + " void (__thiscall *dtor)(CActor *this);"          // slot 0
  + " int  (__thiscall *Update)(CActor *this);"        // slot 1
  + " void (__thiscall *Render)(CActor *this);"        // slot 2
  + " };"
])
set_type({ "addr": "0x4C8F30", "type": "CActor_vtbl" })
```

Then make `CActor.vtbl` a `CActor_vtbl *` and re-`declare_type` so virtual calls
get named in every method's pseudocode.

### 5.3 RTTI (MSVC)

If RTTI is present, the 4/8 bytes **just before** the vtable EA point at the
`RTTICompleteObjectLocator`, which chains to the `TypeDescriptor` holding the
mangled class name (`.?AVCActor@@`). This is the most reliable way to recover the
*real* class name and the base-class hierarchy:

```jsonc
get_int({ "ty": "u32le", "addr": "0x4C8F2C" })   // vtable_ea - 4  => COL pointer
// follow COL -> TypeDescriptor; read its name string:
get_string("0x4C9000")                           // ".?AVCActor@@"
```

Walk the COL's base-class array to recover inheritance and lay out base subobjects
at their correct offsets. Multiple inheritance shows up as **multiple vtable
pointers** at different offsets within one object — each its own `*_vtbl`.

> Pitfalls — (a) Compiler-generated thunks (`[thunk]:` adjustor stubs) appear as
> vtable slots under multiple inheritance; they just fix up `this` and tail-call the
> real method — follow through them. (b) Mid-vtable, an entry pointing at
> `_purecall` marks a pure-virtual slot. (c) GCC/Clang RTTI layout differs (vtable
> has a `-2` typeinfo slot and a top-offset) — confirm the toolchain before assuming
> MSVC COL layout.

---

## 6. Quick reference — the loop

1. `decompile` ctor + several methods → collect `this+OFF` offsets/widths.
2. `xrefs_to` the vtable EA → find all methods + factories.
3. Build the offset table; honest `gap_*` for the unknowns.
4. `declare_type` nested types first, then the class; `enum_upsert` any flag fields.
5. `read_struct` at a known instance → values sane? `vtbl` matches? If not, adjust
   gaps and redo step 4.
6. `set_type` / `type_apply_batch` the global + each method's `this` → pseudocode
   renders with field names.
7. Live confirm: `dbg_add_bp` → `dbg_continue` → `dbg_regs_named(ecx/rcx)` →
   `dbg_read` the object → compare against the table.
8. Vtable: `get_int` the slots, `decompile` each, `declare_type` a `*_vtbl`, recover
   RTTI name from `vtable_ea - ptr_size`.

**Clean-room reminder:** decompiler output (`_DWORD`, `this+0x10`, `sub_…`) is
DIRTY. Everything above is recovery *inside the IDB*; what crosses the firewall is a
neutral offset table written from scratch, never the pseudo-C.
