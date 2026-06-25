--- Part A maps to axis 3 (methodology / pro-tips). Part B maps to axis 5 (in-tool docs linking + what is good/possible/exploitable). Every concrete proposal is tagged with the axis it serves. ---

# RE Brainstorming + Tool-Docs Strategy

## Purpose & framing

This document is the model-facing methodology and documentation contract for an AI agent driving IDA Pro 9.3 through this MCP. It synthesizes the 18 audits into two halves:

- **Part A (axis 3):** an opinionated reverse-engineering methodology for an agent — static-first, then targeted dynamic; how to use the probe/watch/snapshot/trace toolkit safely; how to read the russian-doll call view; how to survive Hex-Rays variance; and the never-patch-without-consent rule.
- **Part B (axis 5):** a concrete plan for in-tool documentation — how the 27-doc corpus, the `ida://` resources, the prompts, and the ~100 tools should cross-link; how each tool should advertise what is *safe / possible / exploitable*; and which new playbooks/docs to add and which existing-doc bugs to fix.

The two halves are deliberately coupled: the methodology in Part A is only useful if the docs in Part B make it discoverable at the moment of tool selection.

---

# PART A — RE Best-Practices / Pro-Tips / Methodology (axis 3)

## A0. The prime directives (read these first)

1. **Static first, dynamic to confirm.** Decompilation, xrefs, strings, imports, types and the call hierarchy answer the *what*; the debugger answers the *what-actually-happens*. Never reach for the debugger to learn something the static surface already knows. Dynamic work is for confirming a hypothesis, resolving an indirect target, or observing runtime data (decrypted buffers, computed keys, dispatch values).
2. **Never patch the analysed module unless the user explicitly asks.** `patch`, `patch_asm`, `put_int` and `py_eval`/`py_exec_file` (which can call `ida_bytes.patch_bytes`) write real image bytes. These are *not analysis tools*. They are off-limits during investigation. (Full rule: §A6.)
3. **One hypothesis at a time, written in neutral prose.** Note the IDB SHA you are working against; never let dirty pseudo-C leak across the clean-room boundary into deliverables.
4. **Bound everything.** Every recursive/whole-image operation (callgraph, dispatcher scan, crypto scan, survey, probe rings) must be depth/node/time-budgeted. Start narrow, widen only when a `truncated` flag is clear.

## A1. The investigation loop

```
orient → census → anchor → read → annotate → (only if needed) confirm-dynamically → re-read
```

- **Orient.** `survey_binary` once for whole-binary triage (metadata, segments, entrypoints, hot strings/functions, categorized imports). Confirm the IDB matches the sample (hash). Use `ida://idb/metadata`, `ida://idb/segments`, `ida://idb/entrypoints`.
- **Census.** `list_funcs`/`func_query`/`entity_query` for the function/global/import population; `imports` for the API surface.
- **Anchor.** Work *outward from known anchors*: strings → the code that uses them (`recipe_string_to_code`, `find_regex`), imports → call sites (`recipe_import_usage`), dispatchers (`recipe_dispatch_scan`), entrypoints. Anchors are cheap certainty; start there, never from address 0.
- **Read.** `decompile` is the primary lens; `disasm` when Hex-Rays lies or for byte-precise work; `analyze_function`/`recipe_function_report` for a one-call dossier.
- **Annotate back.** Rename (`rename`), comment (`set_comments`/`append_comments`), apply types (`set_type`, `declare_type`). After any metadata edit that affects pseudocode, **force a recompile** (§A4).
- **Confirm dynamically** only when static is ambiguous (§A3).

## A2. Reading the russian-doll call view — wider and finer

The call-hierarchy story is currently spread across `callgraph`, `callees_recursive`, `callers_recursive`, `reaches`, `basic_blocks`, and `analyze_component`. Until the unified `call_hierarchy` / `function_skeleton` tools land (designed in the audits), drive it manually with this discipline:

**Zoom-out (wider / module view):**
- `callers_recursive(target)` answers *what reaches this* (the In-calls, fan-in). It correctly filters to real call instructions.
- `callees_recursive(target)` / `callgraph(target)` answers *what this touches* (the Out-calls, fan-out).
- `reaches(A, B)` answers *does A reach B* and returns a concrete path.
- `analyze_component(set)` treats a set of functions as a subsystem (interface vs internal, shared globals).

**Zoom-in (finer / intra-function view):**
- `basic_blocks(func)` gives the CFG skeleton (successors/predecessors, loop structure).
- `decompile` + `analyze_function` give conditions and the calls-on-each-path as text.

**Critical pitfalls baked into today's graph tools (know these or be misled):**
- **Direction asymmetry.** `callers_recursive` filters to genuine `call` instructions; `callees_recursive`/`reaches`/`callgraph` do **not** — they follow *all* code refs, so a tail-call `jmp` or a jump-table landing at a function start is counted as a "callee". A reported "A reaches B" can therefore traverse a non-call jump. Treat downward closures as an *over-approximation* and upward closures as the trustworthy direction until the edge-classification fix lands.
- **Indirect/virtual calls are invisible.** Every static call edge is direct-only; vtable and register-indirect calls are silently dropped. A vtable-heavy class looks artificially sparse. When a function "calls nothing" but clearly dispatches, suspect indirect calls and switch to dynamic (`trace_calls`, probes on the indirect site) to resolve targets.
- **Chunked functions.** `analyze_batch`'s callee list uses `find_func_end` and walks only the first chunk; `callees()` uses `func.end_ea`. They disagree on tail-chunked functions — prefer `callees()` and cross-check.
- **`reaches` default depth is shallow (6).** "Unreachable" is only conclusive up to `max_depth`; widen before concluding isolation.

**Methodology for the nested view:** start at an interface function, `callers_recursive` to see who drives it (wide In), `callees_recursive` bounded to depth 2-3 to see what it orchestrates (wide Out), then `basic_blocks`+`decompile` on the hot node to see *which call fires under which condition* (fine). Iterate depth outward until `truncated` clears.

## A3. Dynamic RE — probes, watches, snapshots, traces, done safely

The dynamic toolkit is gated behind `?ext=dbg` and is the axis-2 powerhouse. The mental model is **two layers**:

- **Stop-the-world** (`dbg_*`): start/continue/step, breakpoints (incl. conditional), register/stack/memory read+write. Halts the target.
- **Non-stopping instrumentation** (probes/watches/traces/snapshots/appcall): a probe is a Python-condition breakpoint that captures into a ring buffer and **always returns False**, so the debuggee never halts. This is the preferred way to observe a running target.

**The non-stopping loop:** `instrument → run free → drain → reason`.
1. **Instrument** with `probe_add` / `trace_calls` / `watch_field` / `probe_api_call` while suspended. Probes never call `dbg_start` — you must already have a session.
2. **Run** with `run_until` (resumes and returns the records produced) — do **not** poll `dbg_status` in a tight loop.
3. **Drain** with `probe_drain` (non-destructive, cursor-based) and roll up with `trace_summary` / `diff_buffers` / `probe_stats`.
4. **Reason** offline over the rollups, not over raw hits.

**Safe-use rules and sharp edges (from the audits — these are real, not theoretical):**

- **`trace_calls(capture_ret=True)` does NOT capture the return value today.** It only appends an English instruction string telling you to place a return-site probe yourself. Same for `probe_net` pre/post. Do not trust a "return value" field from these until `trace_calls_full` lands; capture returns manually with a one-shot probe at `[esp]`/`[rsp]`.
- **`every_nth` sampling is a no-op.** The dispatcher records every hit. Throttle hot probes with `max_hits` or a tight `condition`, never with `every_nth`.
- **Argument capture is 32-bit-stack-only.** On x64 the first args live in registers (rcx/rdx/r8/r9 Win64; rdi/rsi/rdx/rcx/r8/r9 SysV). `argN` reads off the stack and is **garbage for register-passed x64 args**. On x64, read the ABI registers directly until conv-aware capture lands.
- **Hardware watches: 4 slots, alignment matters.** `watch_field` arms one DR slot; `watch_region` arms the *largest aligned slot* and change-detects the whole range — **writes inside the range but outside the armed slot are silently missed**. A 5th watch can fail silently (slot exhaustion). Budget your watches; verify with `probe_stats`.
- **Snapshots are best-effort, in-process, register+explicit-range only.** They are lost on server restart, have no diff, and **no same-process identity check** — restoring a stale snapshot into a relaunched process writes to wrong addresses and can crash the debuggee. Snapshot before any `appcall`; never restore across a process relaunch.
- **`appcall` executes target code.** Always `appcall_inspect` / dry-run first, require explicit human confirmation, run it exactly once (never in a loop), and snapshot beforehand. It can corrupt debuggee state.
- **`run_until` status is unreliable when records drain.** Any drained record currently forces `status='hit'`, clobbering a true `exited`/`timeout`. Cross-check `dbg_status` after a run that mattered.
- **`dbg_step_into`/`dbg_step_over` are asynchronous.** The returned post-step IP is often stale; re-read state after a short settle, or prefer `run_until` to a target.
- **GP register reads are x86/x64-only.** On ARM/AArch64/MIPS `dbg_gpregs*` return empty — read named registers instead.
- **Autopilot is the safe sequencer.** `autopilot_run` whitelists only non-code-injecting primitives and rejects `patch`/`appcall`/`dbg_write` at plan time. Use it for unattended multi-step runs; `probe_clear` acts as the interrupt.

**When to debug at all:** indirect/virtual dispatch resolution, decrypted/decompressed buffers, computed keys/opcodes, anti-analysis behavior, and confirming a static hypothesis you cannot otherwise prove. If static answers it, don't run.

## A4. Surviving Hex-Rays variance (pseudocode comprehension)

- **The decompiler cache goes stale after edits.** After `rename`, `set_type`, `declare_type`, `set_op_type`, `make_data`, or any lvar edit, the pseudocode is stale until you call `force_recompile` on the enclosing function. Make this reflexive: *edit → force_recompile → re-read*.
- **Pseudocode is a draft, not ground truth.** When pseudocode and disassembly disagree, the disassembly wins. Drop to `disasm`/`basic_blocks` for byte-precise or control-flow-precise reasoning.
- **`decompile`'s `refs` list is incomplete.** It only visits `cot_obj` objects, so globals reached via other expression kinds are missed. Don't assume "no refs" means "references nothing."
- **Decompiler warnings are not surfaced.** When pseudocode looks wrong, suspect a Hex-Rays failure you can't see; corroborate with disasm.
- **Idiom recognition over literal reading.** Compiler idioms (multiply-by-reciprocal division, `xor reg,reg` zeroing, `rep stos` memset, sign-extension, switch lowering) should be recognized as their semantics, not transcribed literally. The decompiler-mastery doc's idiom table is the reference.
- **`infer_types` is advisory and writes nothing.** Its `'hexrays'`/`'high'` labels overstate a heuristic guess; a known ASCII string can come back as `uint8_t[N]`. Treat its output as a suggestion to verify, never as fact.
- **`read_struct` decodes scalars as unsigned.** Signed/float/double/bool/enum/bitfield members render incorrectly today. Cross-check member semantics against the declared type.

## A5. Memory comprehension

- **BSS is zero, not 0xFF.** The read helpers are BSS-aware; a global in `.bss` reads as zero by design, not a failed read.
- **Know string encoding.** `get_string` and char-array globals currently hardcode UTF-8 and mis-decode UTF-16/UTF-32/Pascal. For wide strings, read raw bytes and decode yourself, or check `strtype` until per-type decoding lands.
- **Endianness comes from the type suffix, not the DB.** `get_int`/`put_int` default little-endian regardless of DB byte order — be explicit on big-endian images.
- **Address vs name ambiguity.** A symbol whose name is all hex characters (`face`, `beef`) is mis-resolved as an address. Disambiguate by passing an explicit `0x` prefix for addresses.
- **Classify pointers by region.** A captured pointer is meaningless without knowing whether it lands in image/heap/stack/mapped memory. Use the live memory map (when `memory_map` lands) or `dbg_read` around the address to orient.

## A6. The never-patch-without-consent rule (axis 7, restated as methodology)

This is a **methodology rule**, not just a guardrail. The agent must internalize it:

- **Binary-mutating tools** (`patch`, `patch_asm`, `put_int`) rewrite IDB *bytes*. They are classified DESTRUCTIVE/unsafe but, crucially, they are the **same safety tier** as metadata edits like `make_data`/`define_code` — so "unsafe is enabled" does NOT mean "patching is invited." The agent must treat byte-writes as requiring an explicit, specific user request naming the address and intent.
- **Python injection can patch silently.** `py_eval`/`py_exec_file` run unsandboxed and can call `ida_bytes.patch_bytes`. The same consent rule applies to any injected script: no byte-writes without explicit request.
- **`dbg_write` writes live process memory, not the image** — distinct from patching, but still a state mutation; snapshot first and prefer it over image patching for runtime experiments.
- **The autopilot whitelist is the model to imitate**: it rejects `patch`/`patch_asm`/`appcall`/`dbg_write` at plan time. An agent should self-impose the same rejection unless the user explicitly authorized the write.
- **Metadata edits are reversible; byte-writes are not** (no original-byte capture today). When patching is genuinely requested, capture and report original bytes and confirm reversibility before writing.

## A7. Scripting injection (axis 6) — when and how

- Prefer dedicated typed tools (`decompile`, `xrefs_to`, `get_bytes`, `rename`) before `py_eval`. Injection is the escape hatch for batch sweeps and version-sensitive ctree/microcode work, not the default.
- Injected code already runs on the IDA main thread — do not re-marshal with `execute_sync`.
- Return structured data via a `result` variable or `json.dumps`; self-bound loops (no `while True` — there is no reliable timeout interruption for pure-Python loops, and a runaway freezes the whole server).
- `ida_kernwin.msg()` writes to the output window, not captured stdout — use `print`.
- Honor the clean-room and never-patch rules inside scripts.

---

# PART B — In-Tool Documentation Strategy (axis 5)

## B0. State of the corpus

The 27-file corpus (`docs/*.md` + `_meta.yaml`) is genuinely strong on methodology (`re-methodology.md`, `pro-tips-and-pitfalls.md`) and on the probe toolkit (`watchpoints-and-tracepoints.md`, `autopilot-playbook.md` are best-in-class). It is data-driven (drop a `.md` + a `_meta.yaml` entry, no code change) and served via `ida://docs` resources and the `search_docs` tool. But the audits found correctness bugs and gaps that actively mislead an agent at the point of tool selection. Fix those first.

## B1. Fix the factual contradictions (highest leverage, do immediately)

These are correctness bugs in model-facing prompt material — they tell the agent the wrong thing about *what is safe*.

1. **Safety-class contradiction for `rename`/`set_comments`/`append_comments`.** These are `@safety('DESTRUCTIVE')` in code, but `tools-reference.md`, `tool-authoring-guide.md` (including its example test asserting `destructiveHint=False`), `decompiler-mastery.md`, `getting-started.md`, and `type-reconstruction.md` all label them WRITE. Only `tool-index.md` is correct. Reconcile **everything to match the code's classification**, and decide deliberately: if these *should* be WRITE (reversible metadata edits), reclassify in code and reserve DESTRUCTIVE for byte-writers — that is the cleaner taxonomy (see B5). Either way, docs and code must agree. This directly governs whether the agent fans out edits freely or confirms first.
2. **Fictional ext groups.** `prompts.py` tells clients to connect with `?ext=dbg,probes` (lines 19/57/80/164) and `tool-index.md` invents `probes` and `domain` ext columns. The **only** ext group in code is `dbg`. An agent following the probe prompts connects to a non-existent gate and the probe toolkit is unreachable. Replace every `?ext=dbg,probes` with `?ext=dbg` and fix the index's Ext columns.
3. **Roster incompleteness in `tool-index.md`** (the doc that claims to map "every tool family"). Missing: the entire `api_graph` family (`callees_recursive`, `callers_recursive`, `reaches`, `data_refs`), the entire `api_recipes` family (5 tools), plus `memory_scan`, `probe_api_call`, `snapshot_delete`. Add them.
4. **`trace_calls` return-capture overstatement.** Multiple docs and the tool docstring imply paired entry+return capture; it does not exist. Mark this limitation prominently in `watchpoints-and-tracepoints.md` and the tool docstring until the feature ships.

## B2. The cross-linking model: tools ⇄ docs ⇄ resources ⇄ prompts

Today the four surfaces are linked only by hand-written prose, which is exactly why the `?ext=probes` drift happened. Establish a **single source-of-truth mapping** and derive the rest:

- **Add a `tools:` list per topic in `_meta.yaml`.** `search_docs` then returns concrete *callable tool names* alongside the doc URI — closing the docs→tool loop (today it returns only a URI, a dead end). The "search here first when unsure which tool fits" promise becomes real.
- **Add a queryable tool-catalog resource `ida://tools`** generated from the live registry (name/title/safety/ext). This is the source of truth that makes the `?ext=probes` class of drift impossible, and lets an agent discover the real tool surface without trusting prose.
- **Generate the `(connect ?ext=...)` line in prompts from `MCP_EXTENSIONS`** so a prompt can never name a group that isn't registered.
- **Add `See also:` to every tool docstring and every resource docstring**, cross-linking siblings by name: e.g. `structs_resource` ⇄ `search_structs` ⇄ `ida://docs/type-reconstruction`; `xrefs_from_resource` ⇄ `xrefs_to`; `decompile` ⇄ `disasm` ⇄ `basic_blocks`. The cross-surface links currently live only in `tool-index.md`, not where the client first meets the tool.
- **Improve `search_docs` recall** (it is the "first stop"): add a small RE-domain synonym map (rename↔renaming, xref↔cross-reference, watch↔espion, probe↔sonde), light stemming, doc-length normalization, and a no-results fallback that points at the `ida://docs` index instead of returning an empty list. Annotate its params (currently bare `query`/`limit`, violating the project convention).

## B3. How each tool should advertise safe / possible / exploitable

Standardize every tool docstring (the docstring *is* the MCP description) on the existing WHAT/WHEN/RETURNS/PRO-TIP/PITFALL template, and add three explicit signals:

- **SAFE:** the safety class in plain words — READ (free to fan out), WRITE (idempotent IDB metadata), DESTRUCTIVE (overwrites/irreversible; confirm intent), EXECUTE (runs target/host code). Crucially distinguish *IDB-metadata edits* from *binary-byte writes* — both are DESTRUCTIVE today but the agent must treat byte-writes as never-without-consent (§A6). Recommend a distinct **PATCH/MUTATES-BINARY** signal in the docstring for `patch`/`patch_asm`/`put_int` and for the injection tools that can call `patch_bytes`.
- **POSSIBLE:** the precise capability and its honest limits — e.g. "callees are direct-only; indirect/virtual calls are dropped"; "argN is 32-bit-stack-only"; "watch_region can miss writes outside the armed slot"; "decompile refs are incomplete (cot_obj only) and stale after edits". An agent that knows the limit chooses the right tool.
- **EXPLOITABLE / NEXT STEP:** what to chain next. e.g. `probe_add`/`trace_calls` → `run_until` → `probe_drain`/`trace_summary` → `diff_buffers`; `appcall_inspect` ↔ `appcall`; `decompile` → `force_recompile` after edits; `recipe_dispatch_scan` → `decompile` to map case→handler; `watch_*` → `probe_stats` for backpressure.

Enforce with a meta-test: every registered tool must carry `@title` and a docstring whose first sentence is an imperative verb (audits found uneven `@title` coverage).

## B4. New playbooks and docs to add

Concrete additions, each closing a gap the audits found:

1. **`call-hierarchy-russian-doll.md`** (axis 2, the owner's headline ask — *currently undocumented*). The wide+fine workflow: `survey_binary` → pick subsystem → `module_hierarchy`/`analyze_component` (outer shells, interface vs internal) → `callers_recursive`+`callees_recursive` rooted (In/Out rings) → `basic_blocks`+`decompile` for guarded calls (which call fires under which condition) → `reaches` to confirm a path. Include depth/cap heuristics (start depth 2, widen until `truncated` clears) and the direction-asymmetry + indirect-call caveats from §A2.
2. **`recipes.md`** (axis 5 — the `recipe_*` family is invisible in the entire corpus). Document `recipe_function_report`, `recipe_string_to_code`, `recipe_import_usage`, `recipe_dispatch_scan`, `recipe_crypto_candidates`, and cross-link them from `crypto-hunting.md` and `opcode-and-packet-re.md`.
3. **"Mutating the binary" section** in `re-methodology.md` + a tip in `pro-tips-and-pitfalls.md` (axis 7 — *no explicit consent rule exists anywhere today*). State plainly: `patch`/`patch_asm`/`put_int` and injected byte-writes only on explicit user request; cite the autopilot whitelist as the model behavior to imitate; note patches change IDB bytes (not the on-disk file or live process).
4. **`pseudocode-comprehension.md` / dynamic-overlay deep-dive** (axis 2): the ctree/microcode/lvar-usage story (once `pseudocode_query`, `lvar_usage`, `set_lvar`, `microcode_text`, and the live `pseudocode_at` overlay land), plus the staleness/force_recompile contract.
5. **Debug-toolkit cross-link doc** wiring `dbg_*` to the probe/watch/snapshot/trace toolkit, with the safe-use rules from §A3 (4-slot limit, async stepping, snapshot identity, appcall-once) consolidated in one place.

Also: add depth/cost guidance for the recursive graph tools to `pro-tips-and-pitfalls.md`; document the silent truncation caps (`survey_binary` 5k-string cap, `_MAX_ENCLOSING=500`, `get_callers` 50-cap, `trace_data_flow` 200-node cap) wherever they bite; and gate `cursor`/`selection` resources as GUI-only (they return junk under the shipped headless idalib server).

## B5. Architectural docs hygiene to prevent regressions

- **Make prompts and the tool-index *derive* their endpoint/ext/safety facts** from the registry (`MCP_EXTENSIONS`, the catalog resource) rather than hand-syncing. Hand-syncing is what produced the `?ext=probes` and rename-WRITE drift.
- **Adopt and document a naming standard** (axis 4) in `tool-authoring-guide.md`: bare verbs for the default static namespace; `dbg_*` for debugger control; one recognizable family identity for the probe/watch/snapshot/trace instrumentation toolkit (it shares one ext but reads as scattered names); `recipe_*`/`py_*`/`domain_*` for their families; reserve `list_<noun>` (enumerate) / `<noun>_query` (filter) / `<noun>_inspect` (deep read). Resolve the `domain_*` backend-prefix leak (it names the SDK, not the capability, and duplicates canonical tools) by folding into canonical tools with a `backend=` flag or aliasing. Never rename a shipped tool in place — add an alias, mark the old deprecated.
- **Fix the `tool-authoring-guide` example** so it teaches correct classification (use a genuinely WRITE/idempotent tool like `add_bookmark`/`force_recompile` for the WRITE example, and `rename` as the DESTRUCTIVE example), so new authors learn the project's real convention.

---

## Summary table — axis mapping of every proposal

| Proposal | Axis |
|---|---|
| Static-first methodology, investigation loop, anchors | 3 |
| Russian-doll reading discipline (wide In / fine Out, direction-asymmetry & indirect-call caveats) | 3 (supports 2) |
| Probe/watch/snapshot/trace safe-use rules (4-slot, async-step, snapshot identity, appcall-once, every_nth no-op, x64 args) | 3 (supports 2) |
| Hex-Rays variance survival (force_recompile, draft-not-truth, idioms) | 3 |
| Memory comprehension (BSS, encoding, endianness, pointer classification) | 3 |
| Never-patch-without-consent as methodology | 7 (via 3) |
| Scripting-injection discipline | 3 (supports 6) |
| Fix rename/set_comments safety-class contradiction across 5+ docs | 5 |
| Fix `?ext=dbg,probes` / fictional ext groups in prompts + index | 5 |
| Complete tool-index rosters (graph, recipes, memory_scan, probe_api_call, snapshot_delete) | 5 |
| `tools:` per-topic in `_meta.yaml`; `search_docs` returns tool names | 5 |
| `ida://tools` catalog resource as single source of truth | 5 |
| Derive prompt ext-line from `MCP_EXTENSIONS` | 5 (supports 1) |
| `See also:` cross-links on every tool + resource docstring | 5 |
| `search_docs` synonyms/stemming/length-norm/no-results fallback | 5 |
| SAFE / POSSIBLE / EXPLOITABLE docstring signals | 5 (supports 4) |
| New doc: `call-hierarchy-russian-doll.md` | 5 (serves 2) |
| New doc: `recipes.md` | 5 |
| New section: "Mutating the binary" consent rule | 5 (serves 7) |
| New doc: pseudocode/microcode comprehension + dynamic overlay | 5 (serves 2) |
| Document truncation caps; gate GUI-only resources | 5 (supports 8) |
| Naming standard + `domain_*` de-leak + no-in-place-rename | 4 |
| Fix tool-authoring-guide WRITE/DESTRUCTIVE example | 4 |
