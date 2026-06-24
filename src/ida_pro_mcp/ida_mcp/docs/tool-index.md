# Tool Index

A scannable map of **every** tool family in this server: what each is for, its
**safety class**, and which **`?ext` group** (if any) gates it. Use it as a quick
lookup — "which tool do I reach for, and is it safe / available?" — then open the
family's deep-dive doc for usage.

## How to read this index

- **Safety class** (`@safety(...)`) — drives MCP annotations + the unsafe flag:
  - `READ` — pure query, read-only, idempotent. Safe to fan out massively.
  - `WRITE` — idempotent IDB edit (rename, set type, set comment, save).
  - `DESTRUCTIVE` — non-idempotent IDB edit / patch (undefine, delete, patch
    bytes). Flagged **unsafe**.
  - `EXECUTE` — runs code or resumes the debuggee (py_eval, appcall, run_until).
    Flagged **unsafe + openWorld**. Treat as a deliberate, confirmed action.
- **Ext group** (`@ext(...)`) — hidden unless the client connects with the
  matching query param. No ext = always visible.
  - `dbg` — debugger control + a few live-memory readers. Connect `?ext=dbg`.
  - `domain` — the ida-domain SDK mirror tools. Connect `?ext=domain`.
  - `probes` — non-stopping probe / watch / autopilot toolkit. Connect
    `?ext=probes` (needs a live session, so practically `?ext=dbg,probes`).
  - Combine: `?ext=dbg,probes,domain`.

Pro-tip: the committed `.mcp.json` registers `?ext=dbg` — that is a **superset**
(static tools + debugger tools). If `dbg_*` are missing you are on the bare base
endpoint; re-register on `?ext=...`. Always-on families (core/query, memory,
modify, types, stack, analysis, composite, survey, sigmaker, probes-listing,
docs) need **no** ext param.

---

## Family lookup table

| Family | Module | Ext | Safety (range) | One-line purpose |
|---|---|---|---|---|
| Core / query | `api_core` | — | READ (+1 WRITE) | Census the IDB: functions, globals, imports, strings; filtered queries; save. |
| Memory | `api_memory` | — | READ + DESTRUCTIVE | Read/write raw bytes, typed ints, strings, global values at an EA. |
| Modify | `api_modify` | — | WRITE + DESTRUCTIVE | Legibility edits: rename, comment, bookmark, (re)define code/data, patch asm. |
| Types | `api_types` | — | READ + DESTRUCTIVE | Declare/inspect/apply C types, enums, structs; overlay a type on bytes. |
| Stack | `api_stack` | — | READ + DESTRUCTIVE | Inspect and declare/delete a function's stack-frame variables. |
| Analysis | `api_analysis` | — | READ | Decompile/disasm, xrefs, callees/callgraph, byte/insn search, profiling. |
| Composite | `api_composite` | — | READ (+1 DESTRUCTIVE) | One-call bundles: analyze a function/component, data-flow, before/after diff. |
| Survey | `api_survey` | — | READ | Single broad first-look census of the whole binary. |
| Sigmaker | `api_sigmaker` | — | READ | Synthesize AOB / wildcarded byte-pattern signatures to relocate code/data. |
| Debugger | `api_debug` | **dbg** | READ + EXECUTE | Drive a live debugger: bps, step/continue, regs, stack, live read/write. |
| Probes | `api_probes` | **probes** / dbg | READ → EXECUTE/DESTRUCTIVE | Non-stopping probes/watchpoints/autopilot + live struct/appcall helpers. |
| Domain | `api_domain` | **domain** | READ | ida-domain SDK mirror: functions/strings/xrefs/types/segments/pseudocode. |
| Python | `api_python` | — | EXECUTE | Run arbitrary IDAPython: `py_eval`, `py_exec_file`. The escape hatch. |
| Docs | `api_docs` | — | READ | Search this in-server documentation corpus (`search_docs`). |

---

## Family detail (tool rosters)

### Core / query — `api_core` (no ext)
The baseline IDB census layer. Start here every session.
- READ: `server_health`, `server_warmup`, `lookup_funcs`, `int_convert`,
  `list_funcs`, `func_query`, `list_globals`, `entity_query`, `imports`,
  `imports_query`, `find_regex`, `search_text`.
- WRITE: `idb_save`.
- Pro-tip: prefer the `*_query` variants (`func_query`, `entity_query`,
  `imports_query`) over the bare `list_*` — they filter/sort/project server-side,
  so you pull far fewer rows. `entity_query` unifies functions/globals/imports/
  strings/names behind one call.

### Memory — `api_memory` (no ext)
Static (IDB) byte/value access at an address. For **live** memory use the dbg
readers below.
- READ: `get_bytes`, `get_int`, `get_string`, `get_global_value`.
- DESTRUCTIVE: `patch`, `put_int`.
- Pitfall: `patch`/`put_int` rewrite the IDB bytes — not the on-disk file and not
  the live process. They are destructive + non-idempotent.

### Modify — `api_modify` (no ext)
The legibility / annotation surface (clean-room: never paste pseudo-C).
- WRITE (idempotent): `add_bookmark`, `force_recompile`.
- DESTRUCTIVE: `set_comments`, `append_comments`, `patch_asm`, `rename`,
  `define_func`, `define_code`, `undefine`, `set_op_type`, `make_data`.
- Pro-tip: `rename`/`set_comments` are flagged DESTRUCTIVE because they overwrite
  prior names/comments (non-idempotent), even though they feel like simple edits.

### Types — `api_types` (no ext)
C type / struct / enum reconstruction and application.
- READ: `read_struct`, `search_structs`, `type_query`, `type_inspect`,
  `infer_types`.
- DESTRUCTIVE: `declare_type`, `enum_upsert`, `set_type`, `type_apply_batch`.
- Pro-tip: `read_struct` overlays an IDB type onto a static EA's bytes into a
  named-field dict; the live twin is `read_struct_live` (probes/dbg).
  `type_apply_batch` applies many type assignments in one call.

### Stack — `api_stack` (no ext)
Per-function stack-frame variables.
- READ: `stack_frame`.
- DESTRUCTIVE: `declare_stack`, `delete_stack`.

### Analysis — `api_analysis` (no ext)
The deep static-reading workhorse (all READ).
- `decompile`, `disasm`, `func_profile`, `analyze_batch`, `xrefs_to`,
  `xref_query`, `xrefs_to_field`, `callees`, `callgraph`, `find_bytes`,
  `basic_blocks`, `find`, `insn_query`, `export_funcs`.
- Pro-tip: `analyze_batch` profiles a whole candidate subsystem in one call —
  the fast way to triage many related functions before reading one closely with
  `decompile`. `xrefs_to_field` is offset-aware ("who touches `this+0x10`").

### Composite — `api_composite` (no ext)
High-level one-call bundles that fan several primitives internally.
- READ: `analyze_function`, `analyze_component`, `trace_data_flow`.
- DESTRUCTIVE: `diff_before_after` (it runs a write step between two reads).
- Pro-tip: `analyze_function` is the single best "tell me everything about this
  function" call; `trace_data_flow` follows a value forward/backward (where does
  this recv buffer go / what feeds this length field).

### Survey — `api_survey` (no ext)
- READ: `survey_binary` — one broad first-look census (segments, imports,
  exports, strings, candidate subsystems) to orient before drilling in.

### Sigmaker — `api_sigmaker` (no ext, all READ)
- `make_signature`, `make_signature_for_function`, `make_signature_for_range`,
  `find_xref_signatures`.
- Pro-tip: output comes in four formats (ida / x64dbg / mask / bitmask); these
  AOB signatures relocate a function across builds — distinct from IDA FLIRT
  `.sig` libraries.

### Debugger — `api_debug` (**`?ext=dbg`**)
Drive a live session the maintainer already F9-launched. **Never `dbg_start`**
on this project (it exists but is the wrong door for the live-attach workflow).
- READ: `dbg_status`, `dbg_bps`, `dbg_regs_all`, `dbg_regs`, `dbg_regs_remote`,
  `dbg_gpregs`, `dbg_gpregs_remote`, `dbg_regs_named`, `dbg_regs_named_remote`,
  `dbg_stacktrace`, `dbg_read`.
- EXECUTE: `dbg_start`, `dbg_exit`, `dbg_continue`, `dbg_run_to`,
  `dbg_step_into`, `dbg_step_over`, `dbg_add_bp`, `dbg_delete_bp`,
  `dbg_toggle_bp`, `dbg_set_bp_condition`, `dbg_write`.
- Pro-tip: `dbg_read` reads **through** PAGE_NOACCESS — use it to read live
  packet buffers a normal read would fault on.

### Probes — `api_probes` (**`?ext=probes`**; live readers under `dbg`)
The non-stopping observe-while-running layer + live-memory helpers.
- READ: `probe_list`, `probe_drain`, `trace_summary`, `diff_buffers`,
  `appcall_inspect`, `read_struct_live` (`dbg`).
- EXECUTE: `probe_add`, `run_until`, `watch_field`, `watch_region`,
  `trace_calls`, `probe_net`, `appcall` (`dbg`), `snapshot_save`,
  `snapshot_restore`, `autopilot_run`.
- DESTRUCTIVE: `probe_clear`, `probe_arm`.
- Pro-tip: the loop is **instrument → run → drain** — `probe_add`/`trace_calls`/
  `watch_field`, then `run_until`, then `probe_drain` (pass the returned `cursor`
  back as `since_cursor`). Probes always return `False`, so the target never
  halts. `appcall` actually CALLS debuggee code — single, human-confirmed only,
  never in a loop.

### Domain — `api_domain` (**`?ext=domain`**, all READ)
A Pythonic ida-domain SDK mirror of the core queries.
- `domain_functions`, `domain_function_pseudocode`, `domain_xrefs`,
  `domain_strings`, `domain_segments`, `domain_types`, `domain_entry_points`.
- Pro-tip: these overlap the core/analysis tools; reach for them when you want
  the ida-domain object model's shape. Gated off by default to keep the default
  toolset lean.

### Python — `api_python` (no ext, EXECUTE)
- `py_eval` — run an inline IDAPython snippet (the escape hatch for any one-off
  query the fixed tools don't cover).
- `py_exec_file` — run a larger script from disk (write-to-disk batch work).
- Pitfall: snippets already run **on the IDA main thread** — never nest
  `execute_sync` inside them. Return a result var or `json.dumps(...)` to stdout;
  self-bound against the call timeout. EXECUTE-class: treat as deliberate.

### Docs — `api_docs` (no ext, READ)
- `search_docs(query, limit)` — full-text search over this in-server
  documentation corpus (the family deep-dives and methodology guides).
- Pro-tip: search here first when unsure which tool fits a task — it returns the
  topic doc that names the exact tool to call.

---

## Quick "which family?" cheatsheet

- *Orient on a fresh DB* → Survey (`survey_binary`) + Core (`server_health`).
- *Find a function / string / import* → Core `*_query` / `find_regex`.
- *Read one function closely* → Composite `analyze_function` / Analysis
  `decompile`.
- *Who calls / reaches X* → Analysis `xrefs_to`, `callgraph`, `xrefs_to_field`.
- *Recover a struct / vtable* → Types (`read_struct`, `declare_type`) + Stack.
- *Annotate the IDB* → Modify (`rename`, `set_comments`) + Types.
- *Relocate code across builds* → Sigmaker.
- *Anything no fixed tool covers* → Python (`py_eval`).
- *Watch live values without stopping* → Probes (instrument→run→drain).
- *Step / breakpoint / read live memory* → Debugger (`?ext=dbg`).
