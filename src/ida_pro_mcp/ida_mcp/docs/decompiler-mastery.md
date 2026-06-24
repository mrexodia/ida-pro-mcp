# Mastering Hex-Rays Pseudocode Quality (via MCP)

The decompiler is the single highest-leverage RE view, but it ships you a *draft*:
invented `v3`/`a1` names, `_DWORD` casts, `(this + 0x10)` field pokes, fused or
spilled variables, and the occasional mis-typed loop. This doc is the craft of
turning that draft into pseudocode you can read at a glance — by typing it, naming
it, recognizing its idioms, and knowing when to abandon it for the disassembly.

The discipline never changes: **the type/name edits you make here are recovery
*inside the IDB*; the pseudo-C itself is DIRTY and never crosses the firewall.** What
ships is a neutral spec written from scratch.

> Tool names below are the bare `@tool` names. Over the wire they appear as
> `mcp__ida__<name>` (e.g. `mcp__ida__decompile`). `tools/list` is authoritative for
> the exact schema; the Python type hints *are* the schema.

The four levers and the tools that pull them:

| Lever | Tool(s) | Safety |
|---|---|---|
| Read / re-read the pseudocode | `decompile`, `analyze_function`, `analyze_batch`, `force_recompile` | READ / WRITE |
| Apply a recovered type (fn sig / global / local / stack) | `set_type`, `type_apply_batch`, `declare_type`, `enum_upsert` | WRITE / DESTRUCTIVE |
| Name things (fn / global / local / stack) | `rename` | WRITE |
| Fix operand representation (hex/dec/char/struct-offset) | `set_op_type` | DESTRUCTIVE |

---

## 1. The core loop: read → type → name → recompile → re-read

Every improvement is the same cycle, and the **recompile is not optional**:
pseudocode reflects new types/names only after Hex-Rays re-runs. Skip it and you read
the pre-edit version and conclude your edit "did nothing."

```jsonc
decompile({ "ea": "0x401820" })                       // 1. read the draft
declare_type([ "struct CHeader { ... };" ])           // 2a. define the type
set_type({ "addr": "0x401820", "signature":           // 2b. apply the fn prototype
           "int __thiscall Net_Decode(CConn *this, CHeader *h, int len)" })
rename({ "local": [ { "func_addr": "0x401820",        // 3. name the locals
                      "old": "v5", "new": "payloadLen" } ] })
force_recompile({ "addr": "0x401820" })               // 4. make Hex-Rays re-render
decompile({ "ea": "0x401820" })                       // 5. read the clean result
```

Pro-tips:
- **Type the function prototype first — it is the single highest-value edit.** A
  correct `set_type` signature (return type + each arg type) ripples through *every
  caller's* pseudocode for free, and often re-types the locals that derive from those
  args. Name and type the function before you fuss over its locals.
- **Name functions before locals.** A named callee makes the caller readable without
  touching the caller at all.
- `force_recompile` with `"addr": "*"` (or omitted) marks *every* function dirty —
  use it sparingly; normally pass the one `addr` you edited.

---

## 2. Applying types to clean the output

`(this + 0x10)` becomes `conn->seq` only once a struct type sits on the variable.
`set_type` is one tool with four `kind`s, inferred from the fields you pass:

| Target | Fields to pass | Example |
|---|---|---|
| Function signature | `addr` + `signature` | `{ "addr":"0x401820", "signature":"int __thiscall f(CConn *this, int n)" }` |
| Global / data | `name` (or `addr`) + `type` | `{ "name":"g_world", "type":"CWorld *" }` |
| Decompiler local | `addr` + `variable` + `type` | `{ "addr":"0x401820", "variable":"v5", "type":"CHeader *" }` |
| Stack / frame member | `addr` + `name` + `type` | `{ "addr":"0x401820", "name":"buf", "type":"char[256]" }` |

```jsonc
// Type the 'this' local so the WHOLE function re-renders with field names:
set_type({ "addr": "0x402010", "variable": "this", "type": "CActor *" })
```

Batch a recovered cluster and get an aggregate roll-up (with optional stop-on-error):

```jsonc
type_apply_batch({ "stop_on_error": false, "edits": [
  { "addr": "0x402010", "variable": "a1", "type": "CActor *" },
  { "addr": "0x401C40", "variable": "this", "type": "CActor *" },
  { "name": "g_actorTable", "type": "CActor *[64]" }
]})
```

Pro-tips & pitfalls:
- **Declare before you apply.** Every type named in a `set_type`/`type_apply_batch`
  must already live in the local type library (`declare_type` / `enum_upsert`). A
  missing type fails that edit with `"referenced type not declared"` — declare the
  whole dependency closure first (nested structs before the struct that holds them).
- **Apply an `enum` to the dispatch switch.** Define the opcode set with
  `enum_upsert`, then `set_type` the switch selector to it — every `case 0x1A:`
  becomes `case OP_MOVE:` across the binary.
- **Kind inference is heuristic.** `addr + name` resolves to `stack` *only* when that
  name is a real frame member, else it falls through to `global`. If an edit lands on
  the wrong kind, set `"kind"` explicitly.
- `type_apply_batch` is **not transactional** — edits applied before a stop-on-error
  failure stay applied. Re-running is safe (idempotent) but may re-report some as
  already-set.
- After any apply, **`force_recompile`** then `decompile` to read the payoff. A single
  good struct type routinely un-tangles three functions at once.

---

## 3. Splitting and joining variables

Hex-Rays often **fuses** two distinct logical variables into one slot (register
reuse), or **spills** one logical variable across several (`v5`, `v6`, `v7` that are
really the same pointer at different points). The classic GUI gestures are
*"Split variable"* and *"Force/Map to another variable"* in the pseudocode view.

> Reality over MCP: there is **no dedicated split/join tool**. Those are interactive
> Hex-Rays lvar-mapping operations. Drive them in the GUI when you must — but most of
> the *readability* they buy is reachable through this server by **typing and naming
> the slots and recompiling**, which is usually enough to disambiguate.

What to do over MCP instead:

- **A fused variable that is clearly two things** (e.g. `v4` is an `int` count early
  and a `char*` cursor later): type it to the dominant role with `set_type` local,
  rename it for that role, and leave a `set_comments` note at the reuse point. The
  honest comment beats a wrong unified type.
- **A spilled variable** (`v5`/`v6`/`v7` = the same object): give them the same
  recovered type with one `type_apply_batch`, and rename each to the *same intended
  name with a suffix* (`pHdr`, `pHdr2`) so a reader sees the chain. (IDA forbids two
  locals sharing one name in a function, so suffix rather than truly merge.)
- When fusing/splitting genuinely matters for correctness (a union, a tagged value),
  recover it as a **`union`** via `declare_type` and apply that — a union models "same
  bytes, two interpretations" exactly, no GUI mapping needed.

```jsonc
// Spilled pointer: unify the type, then make the chain obvious by name.
type_apply_batch({ "edits": [
  { "addr":"0x401820", "variable":"v5", "type":"CHeader *" },
  { "addr":"0x401820", "variable":"v6", "type":"CHeader *" }
]})
rename({ "local": [
  { "func_addr":"0x401820", "old":"v5", "new":"pHdr" },
  { "func_addr":"0x401820", "old":"v6", "new":"pHdr_alias" }
]})
force_recompile({ "addr":"0x401820" })
```

Pitfall: do **not** force a single type onto a genuinely-fused slot if the two roles
have incompatible widths — you will corrupt the *other* role's rendering. A comment +
two honest local types is safer than a wrong merge.

---

## 4. Naming for legibility

`rename` is a single transactional batch over four categories, processed in order
`func → data → local → stack`. Local renames require Hex-Rays; stack renames require
a real frame member (you cannot rename arguments or special frame slots).

```jsonc
rename({ "dry_run": true, "func": [ { "addr":"0x401230", "name":"Net_DecryptPacket" } ],
         "local": [ { "func_addr":"0x401230", "old":"v3", "new":"keyByte" } ],
         "stack": [ { "func_addr":"0x401230", "old":"var_20", "new":"plain" } ] })
```

Pro-tips:
- **Always `dry_run: true` first.** It validates every name and surfaces collisions
  without touching the IDB; then re-run to apply. Collisions are rejected unless
  `allow_overwrite: true`.
- Local item shape is `{ func_addr, old, new }` (the `old` is the current Hex-Rays
  name like `v5`); function item shape is `{ addr, name }`.
- Newly-named functions that had no prior user name are auto-filed under the IDA
  `/vibe/` function folder — reported as `dir: "vibe"`. Harmless; it just keeps your
  campaign's discoveries grouped.
- Name **outside-in**: the dispatch function, then its handlers, then each handler's
  locals. Each named layer makes the next layer's draft readable.
- Comments are cheap and idempotent — `set_comments` a one-line neutral note at every
  non-obvious branch. Future passes (and other agents) read them.

---

## 5. Recognizing decompiler idioms

The decompiler emits recurring shapes. Reading them at sight is most of the skill.

| Pseudocode shape | What it really is | Your move |
|---|---|---|
| `*(_DWORD *)(a1 + 0x10)` | field at `+0x10`, 4 bytes | recover the struct; `set_type` `a1` |
| `(*(int (__thiscall **)(...))(*(_DWORD *)this + 4))(this)` | call through **vtable slot 1** (`+4` on x86 = slot 1) | declare a `*_vtbl`; type `this->vtbl` |
| `result = a + 8 * (b >> 3) ...` | array index math (`elem_size * i`) | the multiplier is `sizeof(elem)`; type it as an array |
| `v3 = sub_X(); if (v3) ...` then `v3` used as ptr | a getter/factory returning a typed pointer | `set_type` `sub_X`'s return; `v3` re-types itself |
| `_BYTE`/`_WORD`/`_DWORD`/`_QWORD` cast | access width 1/2/4/8 | pick the field type from the cast width |
| `HIBYTE/LOBYTE/__PAIR64__/SHIDWORD` | sub-register / split-register access | usually a fused or wrong-width var — type it correctly |
| `if ( (a & 4) != 0 )` on a recurring field | a **flags bitfield** | `enum_upsert` a bitmask enum; type the field |
| `qmemcpy(dst, src, 0x20)` / inlined `rep movs` | fixed-size struct/array copy | the size pins a struct/array length |
| `__readfsdword(...)` / `__security_cookie` | SEH / stack-canary boilerplate | CRT noise — ignore, never rename CRT internals |
| `*(float *)(this + 0x2C)` near sibling offsets | a `float` vector field (x/y/z adjacent) | recover a `CVec3` and type the run |
| `j_sub_X` / `[thunk]:` adjustor | a jump thunk / MI `this`-adjustor | follow through to the real target |
| `LABEL_7:` + `goto` | irreducible CFG the lifter could not structure | reason from `basic_blocks`, not the goto soup |

Pro-tips:
- The width casts (`_BYTE`…`_QWORD`, `float`, `double`) are the **ground truth for
  field size** — read the cast, not the variable name.
- A local passed as the **first arg / ECX** of another `__thiscall` is a *pointer to a
  nested object* — recover that class and make the field a typed pointer.
- Use `infer_types({ "ea": ... })` to get IDA's heuristic guess as a *starting point*,
  then confirm/override with `declare_type` + `set_type`. Never ship its guess
  unverified.

---

## 6. When to decompile vs read the disassembly

The decompiler lifts; lifting can lie. Drop to `disasm` / `insn_query` when the lift
is untrustworthy or absent:

| Situation | Use |
|---|---|
| Normal function logic, control flow, field access | `decompile` (the default — read this first) |
| Multi-pass deep read (decompile + xrefs + locals in one report) | `analyze_function` |
| Triaging a *cluster* of related functions for role | `analyze_batch` |
| Hand-written asm, obfuscation, junk-byte anti-disasm | `disasm` + `insn_query` |
| You suspect a **mid-instruction EA** / garbage lift | `disasm` to re-anchor on a head |
| Exact flags/carry/`rep`-prefix/operand-semantics matter | `insn_query` (operand types/values) |
| A crypto inner loop (`xor`/`rol`/`ror`/`shld`) | `basic_blocks` to find the back-edge, then `disasm` the BB |
| `decompile` returns an error / Hex-Rays bails | `disasm`; fix definitions (`define_func`) and retry |
| Verifying the lifter did not fold away a side-effect | cross-check `disasm` against the pseudocode |

Pro-tips & pitfalls:
- **The decompiler can be wrong about types and fold instructions away.** When a
  conclusion is load-bearing (a struct size, a cipher constant, a length check),
  confirm it in `disasm`/`insn_query` — the lift is a *reconstruction*, not source.
- A function that **won't decompile** is usually a definition problem: `undefine` the
  bad region → `define_code` at the true start → `define_func` → `decompile` again.
- `analyze_batch` on the cluster *first*, then `decompile` only the two or three the
  summaries flag as load-bearing. Do not hand-decompile a subsystem function by
  function.
- Outputs are line-limited and cached behind a `download_url`; **narrow the EA / range
  instead of fetching megabytes.**
- `set_op_type` fixes a *single operand's* representation in the disassembly
  (`stroff` to render `[ebx+0x10]` as `[ebx+CConn.seq]`, or `hex`/`dec`/`char`) — the
  disassembly-side complement to typing a local in the pseudocode. It is DESTRUCTIVE
  (changes how the IDB renders); `kind:"stroff"` needs the `struct` name.

---

## 7. The polish loop — quick reference

1. `analyze_batch` the cluster → pick the load-bearing functions.
2. `decompile` one → read the draft; spot the `(this+OFF)` patterns and idioms (§5).
3. `declare_type`/`enum_upsert` the struct/enum you see.
4. `set_type` the **function prototype** first, then `this`/locals/globals (batch with
   `type_apply_batch`).
5. `rename` (`dry_run` → apply) the function, then locals, then stack slots.
6. Disambiguate fused/spilled slots by type + suffix-name + comment (§3); model true
   "same bytes, two meanings" as a `union`.
7. `force_recompile` → `decompile` → read the clean result; iterate.
8. Drop to `disasm`/`insn_query` for anything the lift makes you doubt (§6).
9. `idb_save`.

**Clean-room reminder:** `_DWORD`, `sub_…`, `this + 0x10`, `__thiscall`, the invented
`v3`/`a1` names — all DIRTY. Everything above improves the IDB. What crosses the
firewall is a neutral, from-scratch spec (offset table, field meanings, opcode
catalogue), never the pseudo-C.
