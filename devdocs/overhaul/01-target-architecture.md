# IDA Pro MCP — Target Architecture (Axis 1) & Tool-Naming Standard (Axis 4)

This document synthesizes 18 module audits into one prescriptive specification for (a) the target folder/subfolder layout and migration plan, and (b) the tool-naming taxonomy with a concrete rename table and compatibility costs. It is written so an implementer can execute it commit-by-commit without breaking the `@tool` registry, `__init__.py` import side-effects, or `@ext("dbg")` grouping.

---

## PART A — TARGET ARCHITECTURE (Axis 1)

### A.1 The registration model as it actually works today

Registration is **purely side-effect-driven**. `__init__.py` imports every `api_*` module in sequence; at import time the decorator stack runs and populates global state. Any reorg MUST preserve these invariants (from `core-infra` and `design:arch-naming` audits):

- **INV-1 — Every tool module is imported exactly once during package init** so its `@tool`/`@safety`/`@ext`/`@title`/`@tool_timeout` decorators execute. The import block *is* the manifest; there is no separate registry file.
- **INV-2 — `@ext("dbg")` grouping is by decorator, not by file.** `MCP_EXTENSIONS["dbg"]` is built lazily as `@ext("dbg")` fires (22 occurrences in `api_debug.py`, 26 in `api_probes.py`). **Moving files between folders cannot change ext grouping as long as imports still fire.** `api_domain.py` carries no `@ext`, so it is base-endpoint.
- **INV-3 — Post-import ordering hooks must stay ordered:** `trace.configure_idb()` runs after `trace` import; `api_core.init_caches()` warms the strings cache; `rpc._install_tools_call_patch()` installs the truncation middleware; `trace.install_tracer()` must wrap *after* the truncation patch (both monkeypatch `registry.methods['tools/call']`).
- **INV-4 — `MCP_UNSAFE` is populated by `@safety("DESTRUCTIVE"|"EXECUTE")` and `@unsafe` at import time.** Reclassifying a tool's safety changes which set it lands in — a behavioral change, not a layout change.

The decorator stack order is load-bearing and only prose-documented: `@tool` → `@idasync` → `[@tool_timeout | @keep_batch]` → `@safety` → `@ext`. Attributes (`__ida_mcp_timeout_sec__`, `__mcp_annotations__`) are read via `getattr`, so a misplaced decorator silently no-ops.

### A.2 Proposed folder/subfolder layout

Group by **concern** mirroring the owner's axes: static-analysis / dynamic-debug / types / scripting / orchestration / infrastructure / docs. Names are chosen so `framework.py`'s existing `__module__`-prefix-stripping yields a clean capability-family label per tool.

```
src/ida_pro_mcp/
  ida_mcp/
    __init__.py            # single explicit registration block (see A.4)
    _manifest.py           # NEW: TOOL_PACKAGES list + post-import hook order

    _kernel/               # INFRASTRUCTURE (defines zero @tool)
      rpc.py               #   registry, output-truncation+download middleware, @safety/@ext/@tool
      sync.py              #   @idasync, timeout/cancellation, batch-mode, get_tool_deadline
      http.py              #   request handler, config UI, output download
      discovery.py         #   instance registration/liveness
      profile.py
      compat.py            #   IDA 8.4–9.3 version gating (extend to 9.3, see A.6)
      framework.py         #   test framework + module-name → family label hook
      utils.py             #   shared helpers, TypedDicts, paginate, parse_address, batch
      prompts.py           #   @prompt workflow guides (ext line generated, A.6)
      zeromcp/             #   vendored MCP/JSON-RPC core (already correctly layered)

    static/                # STATIC ANALYSIS + safe IDB reads
      api_core.py          #   metadata, functions, globals, imports, entity_query, segments*
      api_analysis.py      #   decompile, disasm, profile, xrefs, callgraph, search, CFG
      api_graph.py         #   callers/callees_recursive, reaches, data_refs
      api_memory.py        #   get_bytes/get_int/get_string/get_global_value (reads)
      api_stack.py         #   stack_frame (read) + declare/delete_stack
      api_sigmaker.py      #   signature creation/scan + sigmaker.py
      api_hierarchy.py     #   NEW: call_hierarchy / function_skeleton / module_hierarchy (russian-doll, A.5)

    mutate/                # IDB-METADATA WRITES + isolated BINARY-BYTE writers
      api_modify.py        #   comments, rename, define_*, set_op_type, make_data, force_recompile
      api_patch.py         #   NEW: split out patch_asm/patch/put_int (byte writers, A.5/axis-7)

    types/                 # TYPE SYSTEM (kept separate per scope priority)
      api_types.py         #   declare/enum/read/search/query/inspect/set/infer

    dynamic/               # DEBUG + INSTRUMENTATION (all @ext("dbg"))
      api_debug.py         #   lifecycle, stepping, breakpoints, registers, memory
      probes/              #   NEW package (api_probes.py was 2505 LOC — split)
        capture.py         #     pure: parse_capture_spec, parse_ptr_chain, build_probe_record
        install.py         #     probe_add/list/drain/clear/arm/stats, dispatcher
        watch.py           #     watch_field/watch_region (+ reg_watch, A.5)
        trace.py           #     trace_calls/probe_net/trace_summary/diff_buffers
        live_mem.py        #     memory_scan/read_struct_live/snapshot_*
        execute.py         #     appcall/appcall_inspect
        pilot.py           #     autopilot_run, plan_autopilot (pure)
      trace_backend.py     #   (was trace.py) ProbeRing, netnode persistence, pure analytics

    scripting/             # PYTHON INJECTION (axis 6)
      api_python.py        #   py_eval, py_exec_file (consent gate, A.6)

    workflows/             # ORCHESTRATION / composed playbooks
      api_survey.py        #   survey_binary
      api_composite.py     #   analyze_function/component, diff_before_after, trace_data_flow
      api_recipes.py       #   recipe_* family
      api_domain.py        #   ida-domain SDK mirrors (rename/dedupe, Part B)

    knowledge/             # IN-TOOL DOCS + ida:// RESOURCES (axis 5)
      api_docs.py          #   search_docs + docs_topic resources
      api_resources.py     #   ida://... resources
      docs/                #   27 .md + _meta.yaml corpus
```

**Why these groupings (audit-traced):**

- `static/` vs `mutate/` separation directly answers `api_modify.py`'s central finding: the irreversible byte-writers (`patch_asm:397`, `make_data:1406 del_items`, `patch`/`put_int` in `api_memory.py:380,442`) are conflated with reversible metadata edits under one `DESTRUCTIVE` tier. Putting byte-writers in their own `api_patch.py` file makes them trivial to gate and audit (axis 7).
- `dynamic/probes/` package answers the explicit architecture note in the `api_probes.py` and `design:debug-wishlist` audits: the 2505-line module "is doing too much" and should be split with the pure-logic layer (`capture.py`, `pilot.py`) isolated for headless testing.
- `api_hierarchy.py` co-locates the russian-doll tools the `design:russian-dolls` audit specifies, composing the existing `api_graph` BFS helpers rather than reimplementing them (the `analyze_component` audit flagged that it reimplements a weaker flat graph).
- `workflows/` keeps the high-level composed tools (`api_composite`/`api_recipes`/`api_survey`/`api_domain`) out of the primitive layers, matching the `api_composite + api_recipes + api_survey` audit's note that they orchestrate primitives.

### A.3 Migration plan — WITHOUT breaking the registry, imports, or ext grouping

Risk is **MEDIUM and mechanical**, with two real hazards identified in `design:arch-naming`:

**Hazard 1 — Deep imports.** External code imports submodules directly: `idalib_server.py` does `from ida_pro_mcp.ida_mcp.api_core import (...)` and `from ida_pro_mcp.ida_mcp import trace`; `framework.py` string-parses dotted module names like `ida_pro_mcp.ida_mcp.api_core` to derive the `api_core` label.

**Hazard 2 — Import-order coupling.** The post-import hooks (INV-3) and the two `tools/call` monkeypatches must keep their order.

**Execution sequence (commit-by-commit, each green before the next):**

1. **Commit 1 — Move files into subpackages, add compat shims.** For every moved module, leave a thin top-level re-export shim at the old path:
   ```python
   # ida_mcp/api_core.py  (shim)
   from .static.api_core import *  # noqa: F401,F403
   ```
   Shims preserve deep importers (`idalib_server.py`) and `framework.py`'s name-stripping. **Imports still fire from the same `__init__.py` order**, so INV-1/INV-2/INV-3/INV-4 are byte-for-byte preserved. `@ext("dbg")` grouping is unaffected because it is decorator-derived (INV-2).
2. **Commit 2 — Verify green** with the headless runner on both fixtures: `uv run ida-mcp-test tests/crackme03.elf -q` and `tests/typed_fixture.elf -q`. Add a meta-test asserting `tools/list` count and the `MCP_EXTENSIONS["dbg"]` membership set are unchanged (snapshot-compare against pre-move).
3. **Commit 3 — Replace the hand-maintained import block with `importlib`-driven discovery** (see A.4). This removes the silent-drop foot-gun.
4. **Commit 4 — Update `framework.py` name-stripping** to take the last path component (`__module__.rsplit('.',1)[-1]`) so it is layout-independent, and update `idalib_server.py` to import from canonical subpackage paths.
5. **Commit 5 — Delete the shims** once all internal callers are updated; keep any shim that a *public* entrypoint depends on.

Do the byte-writer split (`api_patch.py`) and the `probes/` package split as **separate follow-up commits** after the layout move stabilizes, so a registry regression is bisectable.

### A.4 The new registration manifest (`_manifest.py`)

The current `__init__.py` import block is the **sole registration manifest**; adding a module but forgetting its import silently drops every tool in it with no error (flagged in `core-infra` and `design:arch-naming`). Replace it with data-driven discovery while keeping the post-import hooks explicit:

```python
# _manifest.py
TOOL_PACKAGES = [
    "ida_mcp.static.api_core",   "ida_mcp.static.api_analysis",
    "ida_mcp.static.api_graph",  "ida_mcp.static.api_memory",
    "ida_mcp.static.api_stack",  "ida_mcp.static.api_sigmaker",
    "ida_mcp.static.api_hierarchy",
    "ida_mcp.mutate.api_modify", "ida_mcp.mutate.api_patch",
    "ida_mcp.types.api_types",
    "ida_mcp.dynamic.api_debug", "ida_mcp.dynamic.probes",   # package __init__ imports its submodules
    "ida_mcp.scripting.api_python",
    "ida_mcp.workflows.api_survey",   "ida_mcp.workflows.api_composite",
    "ida_mcp.workflows.api_recipes",  "ida_mcp.workflows.api_domain",
    "ida_mcp.knowledge.api_docs",     "ida_mcp.knowledge.api_resources",
]

# __init__.py (after kernel import)
import importlib
from ._manifest import TOOL_PACKAGES
for mod in TOOL_PACKAGES:
    importlib.import_module(mod)          # decorators fire here (INV-1)
from . import trace_backend as _trace
_trace.configure_idb()                    # INV-3, explicit ordering preserved
api_core.init_caches()
```

Add a registration meta-test: assert every `**/api_*.py` and every `probes/*.py` module is listed in `TOOL_PACKAGES`, so a new file that is never imported fails CI instead of silently dropping its tools.

### A.5 Co-locating the axis-2 capabilities

- **Russian-doll view (`static/api_hierarchy.py`):** new `call_hierarchy` (bidirectional In/Out, signed-depth shells), `function_skeleton` (CFG + branch conditions + guarded calls via Hex-Rays ctree), `module_hierarchy` (wraps `analyze_component`), and `hierarchy_runtime_overlay` (`@ext("dbg")`, `@safety("READ")`). These **compose** `api_graph._bfs_bounded`/`_direct_callers`/`_direct_callees` and `basic_blocks`, per the `design:russian-dolls` spec. Prerequisite fix (also `api_graph` audit): unify `_direct_callees` to filter `NN_call*`/tail-call exactly like `_direct_callers` so In and Out edges share semantics, and add a shared `classify_code_edge()` returning `call|tailcall|jump|fallthrough|indirect`.
- **Probe split (`dynamic/probes/`):** the dispatcher + sha1 probe-id keying is the extension seam; new probe kinds (`reg_watch`, `branch_trace`, real return-leg of `trace_calls_full`, `call_tree`, `run_timeline`) route through `install.py`'s `_install_code_probe`/`_probe_dispatch` and add a `spec['kind']` branch — never a parallel mechanism. Pure reshapers (`build_call_tree`, `summarize_branches`) land in `trace_backend.py` so they stay headless-testable (`api_probes.py` has **zero** test coverage today — `tests` audit's biggest gap).

### A.6 Shared-helper consolidation (infra layer)

Audits repeatedly found duplicated/inconsistent helpers. Consolidate into `_kernel/utils.py` and `_kernel/compat.py`:

| Concern | Current state (audit) | Target consolidation |
|---|---|---|
| Callee/caller walking | `utils.get_callees` (uses `idc.find_func_end`, single-chunk, no indirect) vs `api_analysis._collect_callees_for_function` (`func.end_ea`) vs `api_graph._direct_callees` (unfiltered) — **3 disagreeing implementations** | One `walk_call_edges(ea, classify=True, chunk_aware=True)` using `func_tail_iterator`, returning edge kind; all modules call it |
| Function/import enumeration | `list_funcs`/`func_query`/`list_globals`/`entity_query`/`imports` each re-enumerate the whole image per call; `entity_query` 'names' walks imports twice | Lock-guarded session caches mirroring `_strings_cache`, invalidated on rename/define events; route `_collect_entities` + tools through them |
| Large-output handling | `rpc.py` download-URL at 50000 chars **and** `utils.handle_large_output` file-spill at 3000 lines — two strategies, two shapes | Collapse into the `rpc.py` truncation+download envelope; one threshold, one cache (switch FIFO→LRU eviction; cap dict-key fan-out) |
| Type-to-string | `member.type._print()` (private) in `read_struct`, `type_query`, `type_inspect`, `api_resources` | Single `compat.type_str(tif)` using public `str(tif)` |
| Ordinal limit | `type_query` calls `ida_typeinf.get_ordinal_limit()` directly (breaks <8.4) vs `search_structs` uses `compat.get_ordinal_limit()` | Route **all** ordinal/enum SDK access through `compat` |
| Range parsing | every `define`/`undefine`/probe re-splits `'start:end'` | `utils.parse_range('start:end' | 'start+size')` |
| Batch envelope | every batch tool reinvents `{results, errors, stop_on_error}` | `utils.batch_apply(items, fn, stop_on_error, dry_run)` with isinstance guards (fixes the recurring non-dict-element AttributeError) |
| Consent/dry-run | enforced ad-hoc per tool; none central | `_kernel` `guard_write(explicit_consent)` / `@mutates` that byte-writers and `py_*` must call (axis 7) |
| Budgeted recursion | `callgraph`/`callees_recursive` each roll their own bounded walk | `walk_call_tree(ea, depth, node_budget, deadline=get_tool_deadline())` generator with cycle detection — the russian-doll/graph backbone |
| Error taxonomy | single `IDAError`; `parse_address` raises misleading "missing 0x prefix" for not-found names | `NotFoundError`/`InvalidArgumentError`/`VersionUnsupportedError`/`FeatureUnavailableError` subclasses with distinct RPC codes |
| compat coverage | tops out at 9.0 gating | extend wrappers/probes to 9.3 (`ida_dirtree`, newer `parse_decls`, microcode helpers) |
| Prompt ext line | `prompts.py` hardcodes the (wrong) `?ext=dbg,probes` | generate the `(connect ?ext=...)` sentence from `rpc.MCP_EXTENSIONS` so it can never name a non-existent group |

Also formalize the two `tools/call` monkeypatches into an explicit ordered **middleware chain** (`consent → trace → truncate → handler`) instead of import-order-dependent global mutation.

---

## PART B — TOOL-NAMING STANDARD (Axis 4)

### B.1 Taxonomy

- **Form:** `verb_noun` for actions; `list_<noun>` / `<noun>_query` / `inspect_<noun>` for the three read patterns.
- **Domain prefix ONLY where a real namespace exists.** Static analysis is the **default namespace and carries NO prefix** (`decompile`, `disasm`, `find`, `rename`, `list_funcs`). Prefixes encode **capability, not backend**.

| Family | Prefix / convention | Examples |
|---|---|---|
| Static analysis | none (default) | `decompile`, `disasm`, `callgraph`, `xrefs_to` |
| Live debugger control | `dbg_*` (already consistent) | `dbg_start`, `dbg_step_into`, `dbg_bps` |
| Dynamic instrumentation | shared family, ext=dbg | `probe_*`, `watch_*`, `snapshot_*`, `trace_*`, `appcall*`, `autopilot_run` |
| Composed playbooks | `recipe_*` | `recipe_crypto_candidates` |
| ida-domain backend | **remove `domain_*`** (leaks backend) | fold into canonical tools / `backend=` flag |
| Python injection | `py_*` | `py_eval`, `py_exec_file` |
| Knowledge | `docs_*` / `search_docs` | `search_docs` |

**Naming rules (write into `tool-authoring-guide.md`):**
- **RULE A** — one verb per read pattern: `list_<noun>`=bounded enumeration, `<noun>_query`=filtered/predicate, `inspect_<noun>`=single-entity deep read. Deprecate-alias redundant forms.
- **RULE B** — prefixes encode capability, not backend (`domain_*` violates this).
- **RULE C** — the ext=dbg instrumentation toolkit must read as one family in docs (via the `framework.py` family facet) even where names lack a literal shared prefix.
- **RULE D** — every tool MUST have `@title` + an imperative verb-first first-sentence docstring. Enforce with a meta-test (coverage is uneven: `api_debug` fully titled, others lighter).
- **RULE E** — no helper-shaped registered names (`*_internal`, leading underscore). `get_global_variable_value_internal` must not be a tool; `get_global_value` is the single surface.
- **RULE F (compatibility)** — **NEVER rename a shipped tool in place.** Add the new name, register the old name as a deprecated alias whose docstring points to the new one, keep both for ≥1 release, then remove the alias.

### B.2 Recommended renames + compatibility cost

| Current name(s) | Issue (audit) | Recommended action | Compatibility cost |
|---|---|---|---|
| `find` (4 modes) | overloaded; overlaps `xref_query`/`find_bytes`/`insn_query`; immediate mode buggy | split into `find_string` + `find_immediate`; drop `data_ref`/`code_ref` (use `xref_query`) | LOW — keep `find` as deprecated alias dispatching by `type` |
| `domain_functions/strings/xrefs/types/segments/entry_points` | prefix names the SDK backend; duplicate canonical tools with divergent shapes | fold into canonical tools behind `backend="domain"`, or rename to capability names; keep `domain_*` as hidden aliases | MEDIUM — both shapes must coexist 1 release; reconcile xref vocab (`read/write/data` vs SDK enum) |
| `list_funcs` + `func_query` + `lookup_funcs` + `entity_query` (+`domain_functions`) | five differently-named function enumerators, no rule | canonical = `list_funcs` (enumerate), `func_query` (filter), `inspect_func` (deep); demote `lookup_funcs`/`entity_query`-functions to aliases | MEDIUM — alias + docstring rule; add `total` to all pages |
| `xrefs_to` + `xref_query` + `xrefs_to_field` (+`domain_xrefs`,`data_refs`) | overlapping xref retrieval, inconsistent type taxonomy | canonical = `xref_query` (filtered), `xrefs_to` (inbound shortcut), `xrefs_to_field` (member); unify type vocab `call|jump|read|write|offset|data`; demote `domain_xrefs` | MEDIUM — vocab change is a shape change; gate behind alias |
| `rename_at_ea` | second entry point for `rename` | keep `rename` as the public tool; `rename_at_ea` becomes internal helper (RULE E) | LOW — if not registered, no cost; else alias |
| `trace_calls(capture_ret=…)` | param lies (no real return capture) | implement real entry/return pairing as `trace_calls_full`; rename/remove `capture_ret` advisory; `trace_calls` keeps entry-only | LOW-MEDIUM — additive new tool; mark old param deprecated |
| `every_nth` (probe_add param) | accepted but inert (no-op sampler) | implement in dispatcher OR remove the param | LOW — implementing is preferred; removal is breaking-ish |
| `infer_types` | implies mutation; mislabels `hexrays`/`high` | rename to `suggest_types`; keep `infer_types` alias | LOW |
| `trace_data_flow` | xref BFS, not data-flow | rename to `trace_xrefs`; keep alias | LOW |
| `define_code` | defines ONE instruction, not a region | rename to `make_insn` (or title-clarify); keep alias | LOW |
| `dbg_regs_remote`/`dbg_gpregs_remote`/`dbg_regs_named_remote` | `_remote` means "by tid", not remote debugging | rename `*_by_tid`; keep `_remote` aliases | LOW |
| `search_docs` params | bare `query`/`limit`, no `Annotated` | add `Annotated` descriptions (no rename) | NONE |

### B.3 Safety-classification corrections (axis 4 + axis 7)

The audits found `rename`/`set_comments`/`append_comments` are `@safety("DESTRUCTIVE")` in code but documented as `WRITE` in 4+ docs (only `tool-index.md` is correct). This mislabels what is safe to fan out vs confirm. **Reconcile by reclassifying reversible IDB-metadata edits as `WRITE`** and reserving `DESTRUCTIVE` (or a new `PATCH`/byte-write tier requiring per-call consent) for the actual image-byte writers now isolated in `mutate/api_patch.py`. Fix every doc to match, and add a meta-test asserting: (1) every byte-writer is in the highest tier + registered unsafe; (2) no `api_hierarchy`/`static` tool is unsafe; (3) byte content is unchanged after a read-only workflow (encodes the never-patch-without-consent invariant in CI). Also reclassify the inverted `api_probes` taxonomy (`snapshot_delete`/`probe_arm` are `DESTRUCTIVE` but touch nothing in the target, while `snapshot_restore`/`appcall` mutate the live debuggee but are only `EXECUTE`).

### B.4 Discoverability fixes that pair with naming

- Fix the **fictional ext groups**: replace `?ext=dbg,probes` (`prompts.py`) and the `probes`/`domain` ext columns (`tool-index.md`) with `?ext=dbg` everywhere — the only registered group. Generate the prompt ext line from `MCP_EXTENSIONS` (A.6) so the drift cannot recur.
- Make `tool-index.md` rosters **complete**: add the missing `api_graph`, `api_recipes`, `memory_scan`, `probe_api_call`, `snapshot_delete`, and the new `api_hierarchy` family.
- Add a queryable **`ida://tools`** resource generated from the live registry (name/title/safety/ext/family) so clients discover the true surface — and so the single-source mapping prevents future naming/ext drift.

