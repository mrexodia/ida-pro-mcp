# Type Reconstruction End-to-End (via MCP)

The full loop for turning untyped bytes in the IDB into a *named, applied, and
verified* type: **declare** a C type, **apply** it to a global/local/stack/function,
**verify** it against real bytes (static and live), and iterate. Every step here is a
single MCP tool call — names below are the bare `@tool` names; over the wire they are
`mcp__ida__<name>` (e.g. `mcp__ida__declare_type`). `tools/list` is authoritative for
each schema.

The cast of tools and their safety class:

| Step | Tool | Safety | Endpoint |
|---|---|---|---|
| Declare a struct/union/enum/typedef | `declare_type` (`enum_upsert` for enums) | DESTRUCTIVE | base |
| Suggest a starting-point type | `infer_types` | READ (advisory, no write) | base |
| Apply a type to addr/local/stack/func | `set_type` / `type_apply_batch` | DESTRUCTIVE | base |
| Verify the layout against static bytes | `read_struct` | READ | base |
| Verify against a *live* object/pointer | `read_struct_live` | READ | `?ext=dbg` |

The cardinal rule: **declaring a type and applying it are two different operations.**
`declare_type` only registers the type in the local type library; it attaches it to
nothing. Forgetting the apply step is the single most common point of confusion.

---

## 1. The declare → apply → verify loop

```
infer_types        (optional) "what does this byte range probably look like?"
      |
declare_type       register the C decl in the type library  [DESTRUCTIVE]
      |
read_struct        overlay it on real bytes — are the values sane?   [READ]
      |  (off-by-N? wrong width? -> edit gaps -> re-declare_type)
      |
set_type /         attach it so the decompiler renders field names   [DESTRUCTIVE]
type_apply_batch
      |
read_struct_live   confirm against a running object (post-ctor)      [READ, ?ext=dbg]
```

You loop steps 2–3 until `read_struct` shows plausible values, *then* apply. Applying a
wrong layout pollutes every function that touches the address, so verify before you
stamp.

---

## 2. (Optional) seed a type with `infer_types`

Before you hand-write a decl, ask IDA what it already thinks an untyped data item is.
`infer_types` is **advisory only** — despite the name it writes **nothing** to the IDB.

```jsonc
infer_types(["0x6A1F40", "g_session_key"])
```

```jsonc
[
  { "addr": "0x6A1F40",     "inferred_type": "int",        "method": "hexrays",    "confidence": "high" },
  { "addr": "g_session_key","inferred_type": "uint8_t[16]","method": "size_based", "confidence": "low" }
]
```

How to read it:

- `method: "hexrays"` / `confidence: "high"` — Hex-Rays guessed it from usage; trust it.
- `method: "existing"` — a type is already applied here; it is just echoing it back.
- `method: "size_based"` / `confidence: "low"` — it only mapped the item's *size* to a
  `uintN_t` (1→`uint8_t`, 2→`uint16_t`, 4→`uint32_t`, 8→`uint64_t`, else
  `uint8_t[size]`). Treat as a hint, not a fact.
- `method: null` / `confidence: "none"` with `inferred_type: null` — nothing could be
  inferred (e.g. no defined item at that EA).

> Pitfall — `infer_types` never modifies the IDB. To actually use a suggestion, feed it
> into `set_type` / `type_apply_batch`. Do not blindly apply a `size_based`/`low` guess —
> a 16-byte item is just as likely a struct as a `uint8_t[16]`.

---

## 3. Declare the type with `declare_type`

`declare_type` parses **C declarations** — `struct`, `union`, `enum`, `typedef` — and
registers each in the local type library. Pass one decl or a list; each is parsed
independently.

```jsonc
declare_type([
  "struct LoginReq {"
  + " uint16_t opcode;"      // +0x00
  + " uint16_t length;"      // +0x02
  + " char     account[32];" // +0x04  (CP949, fixed buffer — no managed string)
  + " uint32_t client_ver;"  // +0x24
  + " };"
])
```

```jsonc
// returns one entry per decl
[ { "decl": "struct LoginReq { ... };" } ]            // success
[ { "decl": "struct Bad { foo bar; };", "error": "Failed to parse:\n..." } ]  // failure
```

Dependency ordering and idempotency:

- **Order within a call matters only when a later decl names an earlier one.** Declare
  base/nested types first (earlier list items), then the aggregate that references them:

  ```jsonc
  declare_type([
    "struct Vec3 { float x; float y; float z; };",   // declare first
    "struct Entity { void *vtbl; int hp; Vec3 pos; };" // can now name Vec3
  ])
  ```

- **Re-declaring an identical type is harmless** (idempotent) — safe to re-run a whole
  manifest. A *conflicting* redefinition is reported as a parse `error` in that item's
  result entry and is **not** silently applied, so it never corrupts the existing type.

> Pitfall — a failed parse surfaces per-item in the returned list, not as a thrown
> error. Always scan the results for `"error"` rather than assuming success. The C
> dialect is IDA's, not a full compiler — keep decls plain (fixed arrays, `uintN_t`,
> pointers, nested UDTs); avoid bitfields-as-syntax and exotic attributes unless you
> have confirmed IDA parses them.

### Enums: prefer `enum_upsert` for incremental work

For an enum you discover constant-by-constant (an opcode table, flag bits), `enum_upsert`
is safer than re-`declare_type` because it **adds members without destructive replace** —
matching members are skipped, conflicts are reported, nothing is overwritten:

```jsonc
enum_upsert({ "name": "Opcode", "members": [
  { "name": "OP_LOGIN_REQ",  "value": "0x0001" },
  { "name": "OP_LOGIN_RESP", "value": "0x0002" }
]})
// re-run later with more members — already-present ones come back "skipped": true
```

Set `"bitfield": true` for flag enums. A member name already used in a *different* enum,
or a value already taken by a *different* name, is returned as a conflict (`summary.conflicts`)
and left untouched — resolve it by hand.

---

## 4. Verify against static bytes with `read_struct`

A declared struct is a *hypothesis*. `read_struct` overlays it onto the bytes at an
address and decodes every member — the fastest way to catch an off-by-N offset or a wrong
width before you commit.

```jsonc
read_struct({ "addr": "0x6A1F40", "struct": "LoginReq" })
```

```jsonc
{ "addr": "0x6A1F40", "struct": "LoginReq", "members": [
  { "offset": "0x00000000", "type": "uint16_t",  "name": "opcode",     "size": 2, "value": "0x0001 (1)" },
  { "offset": "0x00000002", "type": "uint16_t",  "name": "length",     "size": 2, "value": "0x0028 (40)" },
  { "offset": "0x00000004", "type": "char[32]",  "name": "account",    "size": 32,"value": "[68 65 72 6F ...]" },
  { "offset": "0x00000024", "type": "uint32_t",  "name": "client_ver", "size": 4, "value": "0x000003E8 (1000)" }
]}
```

How the `value` is rendered (so you can read it correctly):

- **Pointer** members → hex, width-padded to the pointer size (`0x004C8F30`).
- **Scalar** members of size 1/2/4/8 → hex **and** decimal: `0x0028 (40)`.
- **Anything else** (arrays, nested structs > 8 bytes) → the first **16 bytes** as a hex
  list, with a trailing `...` if the member is longer.

Reading it for confirmation:

- A `length` of `40` matching the actual payload, a `client_ver` of `1000` — *plausible*
  values mean the offset/width are right.
- A garbage scalar (`0x80808081`) means your offset or a preceding gap is wrong by a few
  bytes; adjust the layout, re-`declare_type`, re-`read_struct`.
- The `value` array of a `char[32]` lets you eyeball CP949 text bytes directly.

Convenience:

- Pass a **symbol name** in `addr` (`{"addr": "g_login_req", ...}`) and it is resolved
  automatically.
- **Omit `"struct"`** to reuse whatever type IDA already has applied at that address
  (auto-detected) — useful right after you `set_type` a global.
- Batch many reads in one call by passing a list of `{addr, struct}` objects.

> Pitfalls — (a) `read_struct` is **BSS-aware**: bytes in uninitialized segments come
> back as **zero** (matching runtime zero-init), so an all-zero member can mean
> "unmapped / not yet written," not "the value is genuinely 0." (b) `offset` is the
> member's offset *within the struct*, not an absolute address. (c) The struct must
> already exist — `declare_type` first or you get `Struct '…' not found`. (d) It overlays
> the **static** image; for runtime values use `read_struct_live` (§6).

---

## 5. Apply the type with `set_type` / `type_apply_batch`

Once the layout verifies, attach it so the decompiler renders `req->account` instead of
`*(char *)(a1 + 4)`. `set_type` infers the *kind* of edit from which fields you pass:

```jsonc
// global: name (or addr) + type
set_type({ "name": "g_login_req", "type": "LoginReq" })

// decompiler LOCAL variable: addr (of the function) + variable + type
set_type({ "addr": "0x402010", "variable": "a1", "type": "LoginReq *" })

// function SIGNATURE: addr + signature
set_type({ "addr": "0x402010", "signature": "int __cdecl handle_login(LoginReq *req)" })

// stack FRAME member: addr (of the function) + name (of the frame slot) + type
set_type({ "addr": "0x402010", "name": "v_buf", "type": "LoginReq" })
```

Each returns `{edit, kind, ok}` on success or `{edit, kind, error}` on failure (function
not found, local var missing, referenced type not declared, …).

For a whole recovered cluster, `type_apply_batch` applies many edits and rolls up the
status:

```jsonc
type_apply_batch({ "stop_on_error": false, "edits": [
  { "addr": "0x402010", "variable": "a1",   "type": "LoginReq *" },
  { "addr": "0x401C40", "variable": "this", "type": "LoginReq *" },
  { "name": "g_login_req",                  "type": "LoginReq"   }
]})
// -> { ok, applied, failed, stopped, results: [ <per-edit SetTypeResult>... ] }
```

> Pitfalls — (a) `set_type` / `type_apply_batch` are **DESTRUCTIVE** (they mutate the
> IDB) and every referenced type must already be declared — `declare_type` the full
> dependency closure first. (b) `type_apply_batch` is **NOT transactional**: edits applied
> before a failure stay applied even when `stop_on_error` halts the rest, so a re-run may
> re-apply some (the operations are idempotent, so that is safe). (c) Kind inference is
> heuristic — `addr`+`name` resolves to `stack` only when that name is a real frame
> member, else it falls through to `global`; set `"kind"` explicitly to remove ambiguity.
> (d) A `addr:typename` string shorthand is also accepted in place of a full edit object.

---

## 6. Confirm against a LIVE pointer with `read_struct_live`

Static bytes show the *initialized image*; only a running process shows the object **as
it actually is** — post-constructor, with real pointers and runtime values. This is the
ground-truth pass and lives on the **`?ext=dbg`** endpoint (it requires a live debugger
session — **never** call `dbg_start`; drive the maintainer's already-launched session).

`read_struct_live` reads `sizeof(type_name)` bytes from **live memory** at `ea`, overlays
the IDB type, and returns named fields plus the raw hex:

```jsonc
read_struct_live({ "ea": "0x06A1F40", "type_name": "LoginReq" })
```

```jsonc
{
  "fields": {
    "opcode":     { "offset": "0x0",  "value": "0x1",   "size": 2 },
    "length":     { "offset": "0x2",  "value": "0x28",  "size": 2 },
    "account":    { "offset": "0x4",  "hex": "6865726f00...", "size": 32 },
    "client_ver": { "offset": "0x24", "value": "0x3e8", "size": 4 }
  },
  "raw_hex": "0100 2800 6865726f00...",
  "_meta": { "ea": "0x6a1f40", "type": "LoginReq", "size": 40, "dirty": true }
}
```

Note the rendering differs from `read_struct`: scalar (1/2/4/8 byte, non-float) members
are `{offset, value(hex), size}`; everything else is `{offset, hex, size}`. There is no
decimal echo and no 16-byte cap — you get the full member hex.

### Pointer-chain dereference — the killer feature

`ea` may be a **pointer-chain expression** that is dereferenced live before the struct is
read, so you can walk from a known global through pointers to the actual object without a
manual two-step:

```jsonc
// *(g_session + 0x10) is a LoginReq* ; read what it points at
read_struct_live({ "ea": "[[g_session+0x10]+0x8]", "type_name": "LoginReq" })
```

`[X]` dereferences (reads a pointer-sized value at `X`); `+N` adds an offset; a bare
symbol name or address is the base. Combine for arbitrary chains.

### The live-confirm sequence (with a `this` in hand)

1. Break in a method where the object pointer is live and continue the maintainer's
   session (`dbg_add_bp` → `dbg_continue` on the `?ext=dbg` endpoint).
2. Read the receiver register — 32-bit `__thiscall` → ECX, x64 → RCX
   (`dbg_regs_named({"names":["ecx"]})`).
3. `read_struct_live({ "ea": "<ecx value>", "type_name": "<Class>" })`.
4. If the live values are sane (a `vtbl` matching the vtable EA, plausible scalars), the
   layout is **confirmed against ground truth** and the spec fact is debugger-proven.

> Pitfalls — (a) `read_struct_live` reads **debuggee** memory, `read_struct` reads the
> **static DB** — do not confuse them; live is the one that sees post-ctor state and reads
> *through* `PAGE_NOACCESS` guard pages. (b) The type's size must be sane (`0 < size ≤
> 1 MiB`) or it errors; an unsized/forward-declared type fails. (c) Heap objects move
> between runs — re-read the pointer each breakpoint hit, never reuse a prior run's
> address. (d) `_meta.dirty: true` marks the result as live-debugger output: clean-room
> findings cross the firewall only as neutral prose, never as transcribed bytes.

---

## 7. Worked end-to-end example

Recovering a packet struct from an untyped recv buffer:

```jsonc
// 1. What does IDA think the 40-byte item is?  (advisory)
infer_types(["g_login_req"])
// -> size_based uint8_t[40], low confidence — it's really a struct, declare it.

// 2. Declare the layout (decompiler showed a1+0/+2/+4/+0x24 access).
declare_type([
  "struct LoginReq { uint16_t opcode; uint16_t length; char account[32]; uint32_t client_ver; };"
])

// 3. Verify against the static bytes BEFORE applying.
read_struct({ "addr": "g_login_req", "struct": "LoginReq" })
// -> opcode=1, length=40, client_ver=1000 — all plausible. Good.

// 4. Apply to the handler's parameter so the function re-renders with field names.
set_type({ "addr": "0x402010", "variable": "a1", "type": "LoginReq *" })

// 5. Live ground-truth confirm at the real buffer (?ext=dbg session running).
read_struct_live({ "ea": "[g_recv_ctx+0x40]", "type_name": "LoginReq" })
// -> fields match a real captured login packet. Confirmed.
```

If step 3 had shown garbage `client_ver`, you would adjust the layout (e.g. an unobserved
2-byte gap before it), re-`declare_type`, re-`read_struct`, and only then apply.

---

## 8. Quick reference — the loop

1. `infer_types(addr)` — optional starting-point guess (advisory, no write).
2. `declare_type([...])` — register the C decl; nested/base types **first**; idempotent.
3. `read_struct({addr, struct})` — overlay on static bytes; values sane? `vtbl` matches?
   If not, adjust gaps/widths and go back to 2.
4. `set_type` / `type_apply_batch` — attach to global / local `variable` / stack `name` /
   function `signature`; DESTRUCTIVE, all referenced types must be declared.
5. `read_struct_live({ea, type_name})` — live confirm at a pointer (`?ext=dbg`), supports
   `[[base+off]+off]` pointer chains; reads through guard pages.

**Clean-room reminder:** the decompiler input you read offsets from (`_DWORD`, `a1+0x24`,
`sub_…`) is DIRTY. The type-library work above happens *inside the IDB*; what crosses the
firewall is a neutral, from-scratch offset table — never the pseudo-C, never the live
`raw_hex`.
