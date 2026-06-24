# IDA Pro 9.3 Essentials for Productive RE (via MCP)

This is the field guide to the IDA Pro concepts an MCP client actually needs, each
mapped to the concrete tool that drives it from this server. The golden rule of
RE through this MCP: **never trust memory or analogy — confirm every fact against
the loaded database.** Start by reading `ida://idb/metadata` (or call
`server_health`) to verify *which* binary is open, its architecture, base, and
hashes, before believing any address or byte.

> Tool names below are the bare `@tool` names. Over the wire they appear as
> `mcp__ida__<name>` (e.g. `mcp__ida__decompile`). Schemas come straight from the
> Python type hints, so `tools/list` is always authoritative.

---

## 1. The mental model: heads, EAs, and the linear address space

IDA models the program as one flat **effective-address (EA)** space. Every byte
is either *code* or *data*; the start of an instruction or data item is a **head**.
Most tools take an `ea` that can be a hex address (`0x401000`), a name
(`WinMain`), or — for live debugging — a pointer-chain expression
(`[[ebx+0x10]+0x8]`). Prefer **names over raw addresses**: addresses drift
between rebases and IDB versions, names are stable.

Pro-tips:
- An address landing mid-instruction is the #1 cause of garbage disassembly. If
  `disasm` looks wrong, you are probably not on a head — re-anchor on a function
  start (`func_query` / `list_funcs`) and walk forward.
- Auto-analysis is never "finished." Bytes IDA guessed as data may be code and
  vice-versa; treat the initial DB as a hypothesis, not ground truth.

---

## 2. The disassembly view (IDA-View)

This is the instruction-level view. Each line is one instruction with its EA,
mnemonic, operands, and any auto-comment. In the GUI you press `Space` to toggle
to graph mode; over MCP you read it as text.

| You want | MCP tool | Notes |
|---|---|---|
| Linear disassembly from an EA | `disasm(ea, count)` | Output is line-limited and cached; narrow your range. |
| Decode one instruction's structure | `insn_query(ea)` | Mnemonic + per-operand type/value — better than string-parsing `disasm`. |
| The CFG (graph view, programmatically) | `basic_blocks(ea)` | Returns the function's basic blocks + edges. |
| Function boundaries / profile | `func_profile(ea)` / `func_query` | Size, chunk count, flags, callers/callees summary. |

Pro-tips:
- Read with `insn_query` when you care about operand *semantics* (immediate vs
  memory vs register); read with `disasm` only when you want the human text.
- `basic_blocks` is how you reason about control flow without the GUI graph — use
  it to find loop back-edges (a crypto loop is a back-edge BB full of `xor`/`rol`).

---

## 3. The pseudocode view (Hex-Rays decompiler)

`F5` in the GUI. The decompiler lifts a function to C-like pseudocode. It is the
single highest-leverage RE view — but it is a *reconstruction*, not source: it
invents variable names, can mis-type, and folds away instructions.

| You want | MCP tool | Notes |
|---|---|---|
| Decompile one function | `decompile(ea)` | Pseudo-C + referenced names. The workhorse. |
| Force a fresh decompilation | `force_recompile(ea)` | Use after you change a type/name to see the effect. |
| Deep multi-pass read of a function | `analyze_function(ea)` | Decompile + xrefs + locals folded into one report. |
| Profile a whole subsystem at once | `analyze_batch(eas)` / `analyze_component` | Per-function role summaries; the triage tool. |

Pro-tips:
- After you `set_type` or `rename`, call `force_recompile` (or `decompile`
  again) — the pseudocode only reflects new types after a recompile. Improving
  one struct type often un-tangles three functions of pseudocode at once.
- `analyze_batch` on a cluster of related functions first, *then* `decompile` the
  two or three that the summaries flag as load-bearing. Do not hand-decompile a
  whole subsystem function-by-function.
- The decompiler's invented `v3`/`a1` names and `_DWORD` casts are noise — clean
  them by typing the function prototype and renaming locals (Section 6).

---

## 4. Cross-references (xrefs)

`X` on any symbol in the GUI. Xrefs answer "**who reaches this?**" (code calls,
data reads/writes) and "**what does this reach?**". They are how you climb from a
string/constant/global to the function that uses it — the fastest path into an
unknown subsystem.

| You want | MCP tool |
|---|---|
| All references TO an address/name | `xrefs_to(ea)` |
| References to a specific struct field | `xrefs_to_field(struct, field)` |
| Flexible xref query (to/from, code/data) | `xref_query(...)` |
| Callers / callees of a function | `callgraph(ea)` / `callees(ea)` |
| Forward/backward value flow from an insn | `trace_data_flow(ea, dir)` |

Pro-tips:
- The canonical subsystem-discovery move: `find`/`find_regex` a distinctive
  string ("login failed", a printf format, a filename like `data.vfs`) →
  `xrefs_to` the string → you're standing in the relevant function.
- `xrefs_to_field` is gold once you've recovered a struct: it finds every site
  that touches `header.opcode` or `actor.hp`, which is how you map a field's
  meaning across the whole binary.
- `trace_data_flow` beats eyeballing for "where does this recv buffer go?" /
  "what feeds this length field?".

---

## 5. The structures view (Local Types) and enums

`Shift+F1` in the GUI. IDA stores recovered C/C++ types — structs, unions, enums,
function prototypes — in the **Local Types** library, then overlays them on
disassembly/pseudocode so `*(a1+0x10)` becomes `actor->hp`. Recovering layouts is
where the biggest pseudocode-readability wins come from.

| You want | MCP tool |
|---|---|
| Inspect a known type's layout | `type_inspect(name)` / `read_struct(name)` |
| Query/search the type library | `type_query(...)` / `search_structs(...)` |
| Declare or replace a C type | `declare_type("struct X { ... };")` |
| Create/extend an enum | `enum_upsert(name, members)` |
| Apply many types in one shot | `type_apply_batch(...)` |
| Heuristically infer a type | `infer_types(ea)` |

Pro-tips:
- Recover layouts from `this+offset` access patterns: collect the distinct
  offsets a function pokes through a base pointer, then `declare_type` a struct
  with members at exactly those offsets. Re-decompile and watch the field
  accesses name themselves.
- Define an `enum` for an opcode/flag set, then apply it to the dispatch switch —
  the case labels become readable names everywhere.
- `read_struct(ea, type)` overlays a type onto *static* bytes; for *live* memory
  during debugging there is a separate `read_struct_live` (see the probe doc).

---

## 6. Naming and comments (legibility)

Renaming and commenting is the core deliverable of static RE — it turns
`sub_401230` into `Net_DecryptPacket` permanently in the IDB.

| You want | MCP tool | Safety |
|---|---|---|
| Rename a function / global / local | `rename(ea, name)` | WRITE |
| Bulk-rename by regex | `apply_name_regex(...)` | WRITE |
| Set a repeatable / line comment | `set_comments(...)` / `append_comments(...)` | WRITE |
| Set a function/data prototype | `set_type(ea, "decl")` | WRITE |
| Tag an operand's representation | `set_op_type(...)` | WRITE |

Pro-tips:
- Name **functions before locals**: a named function makes its callers'
  pseudocode readable for free via the call sites.
- `set_type` on a function prototype is the highest-value single edit — correct
  arg/return types ripple through every caller's pseudocode.
- Comments are WRITE (idempotent) and cheap — leave a one-line neutral note at
  every non-obvious branch; future passes (and other agents) read them.
- `apply_name_regex` is for mechanical sweeps (e.g. prefix a whole module), not
  for guessing — only apply names you can justify.

---

## 7. Auto-analysis: fixing IDA's guesses

When IDA misclassifies bytes you correct it explicitly. These are the
code/data-definition tools — the equivalent of `C` (make code), `D` (make data),
`U` (undefine), `P` (make function) in the GUI.

| GUI key | Meaning | MCP tool | Safety |
|---|---|---|---|
| `C` | Make code at cursor | `define_code(ea)` | WRITE |
| `P` | Create a function | `define_func(ea)` | WRITE |
| `D` | Make data of a size | `make_data(ea, size)` | WRITE |
| `U` | Undefine (revert to bytes) | `undefine(ea)` | DESTRUCTIVE |

Pro-tips:
- The usual repair sequence for a missed routine: `undefine` the bad region →
  `define_code` at the true instruction start → `define_func` → `decompile`.
- `undefine` is DESTRUCTIVE (non-idempotent) — it discards the current
  definition. Re-run it only when you mean to.
- After fixing definitions, persist with `idb_save` so the work survives a
  crash/reopen.

---

## 8. Bookmarks and navigation memory

IDA's marked positions (GUI `Alt+M` to mark, `Ctrl+M` to list) let you pin
addresses you'll return to — entry points, the dispatch switch, a crypto loop.

| You want | MCP tool |
|---|---|
| Add a bookmark at an EA | `add_bookmark(ea, description)` |

Pro-tips:
- Bookmark the **packet dispatch switch**, the **recv/decrypt boundary**, and any
  RTTI/vtable you resolve — these are the anchors you orbit for a whole campaign.
- Names are your other navigation memory: a disciplined renaming pass *is* a map.

---

## 9. Search and bytes

| You want | MCP tool |
|---|---|
| Find a string / immediate / name | `find(...)` |
| Regex search over text | `find_regex(pattern)` |
| Byte / pattern search | `find_bytes(pattern)` |
| Read raw bytes | `get_bytes(ea, n)` / `get_int` / `get_string` |
| Resolve a global's value | `get_global_value(name)` |
| List functions / globals / imports | `list_funcs` / `list_globals` / `imports` |

Pro-tips:
- `find_bytes` with a wildcarded pattern finds a function prologue or an
  S-box-shaped constant table across the image — the way to relocate a routine
  after a rebuild.
- `imports`/`imports_query` immediately reveal the subsystem surface: `recv`,
  `WSARecv`, `CreateFileA`, `CryptAcquireContext` each point at a cluster worth
  reading.

---

## 10. Survey, baseline, and persistence

| You want | MCP tool |
|---|---|
| One-shot binary census (segments, entrypoints, interesting strings/funcs) | `survey_binary` |
| Warm the analysis caches | `server_warmup` |
| Confirm DB identity / health | `server_health` |
| Save the IDB | `idb_save` |
| Export many function summaries | `export_funcs` |
| Diff before/after an edit | `diff_before_after` |

Recommended opening sequence for a fresh session:
1. `server_health` → confirm the *right* DB is loaded (path + hash). If it's the
   wrong or an empty DB, **stop** — never fabricate output.
2. `survey_binary` → get segments, entry points, candidate subsystems.
3. `find_regex` a subsystem's tell-tale string → `xrefs_to` → `decompile`.
4. Recover types (`declare_type`/`enum_upsert`), name (`rename`/`set_type`),
   comment (`set_comments`), then `force_recompile` to read the cleaner result.
5. `idb_save`.

---

## 11. Safety classes (what a tool can do)

Every tool carries a `@safety` level you should respect:

- **READ** — pure queries (`disasm`, `decompile`, `xrefs_to`, `type_inspect`).
  Fan these out freely and in parallel.
- **WRITE** — idempotent IDB edits (`rename`, `set_type`, `set_comments`,
  `declare_type`). Safe to re-run; this is the bulk of legibility work.
- **DESTRUCTIVE** — non-idempotent edits (`undefine`, `make_data` over existing
  code). Run deliberately.
- **EXECUTE** — runs code or resumes the debuggee (`appcall`, `run_until`). A
  single, confirmed human action — never loop it.

## 12. Common pitfalls

- **Mid-instruction EAs** → garbage `disasm`. Re-anchor on a head/function start.
- **Believing stale pseudocode** → always `force_recompile` after a type/name
  change; otherwise you read the pre-edit version.
- **Address-based references** → prefer names; addresses move across rebases.
- **Over-broad reads** → outputs are truncated + cached behind a `download_url`;
  narrow the query instead of fetching megabytes.
- **Assuming auto-analysis is complete** → IDA's code/data split is a guess;
  verify and fix with the Section 7 tools.
- **Wrong DB loaded** → `server_health` first, every session; if the MCP is down
  or the DB is empty, stop and report rather than inventing facts.
