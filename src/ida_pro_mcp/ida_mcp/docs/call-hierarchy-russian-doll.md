# Call Hierarchy: the Russian-Doll Comprehension Workflow

The `api_hierarchy` family is built for one job: **understand code by zooming
in and out**, not by dumping a single flat call closure you then have to read in
full. The tools nest like russian dolls — each one is a different *granularity*
of the same call graph, and every node it returns carries a `drill` / `expand`
payload that tells you exactly which tool to call next on which address.

| Tool | View | Doll = | Direction |
|---|---|---|---|
| `survey_binary` | the whole binary | subsystems | — |
| `module_hierarchy` | one subsystem | members (interface vs internal) | grown from a seed |
| `call_hierarchy` | one function's neighbourhood | signed depth bands (-N..+N) | In (callers) + Out (callees) |
| `function_skeleton` | inside one function | basic blocks + guarded calls | intra-function CFG |
| `hierarchy_runtime_overlay` | which dolls *executed* | live edge hits | overlay on `call_hierarchy` |

All four static tools delegate their call-edge work to the Batch-2 seams in
`utils` (`iter_func_call_edges`, `walk_call_tree`, `get_cached_cfunc`,
`classify_code_edge`), so In and Out are exact transposes, recursion/cycles are
handled centrally, and switch / chunk / tail-call awareness comes for free.

---

## The wide-then-fine workflow

The intended path is **wide first, fine last** — establish the shape of the
neighbourhood before you read any one function closely.

### 1. Survey → pick a subsystem

Start with `survey_binary` to get segments, imports/exports, strings, and the
candidate subsystem seeds. Pick a seed function that looks like the entry point
of a feature (a dispatcher, a `*_init`, a command handler, a decrypt routine).

### 2. `module_hierarchy(seed)` — the OUTER shells

Grow the subsystem from that one seed and read its API surface:

```
module_hierarchy(seed="0x401000", grow_depth=2)
```

Read the result in this order:

1. **`interface`** members first — these are called from *outside* the grown set,
   so they are the subsystem's public API. (`role:"interface"` on the member.)
2. **`internal`** members next — the private helpers, reachable only from within.
3. **`inner_call_graph`** to see how the members wire to each other.
4. **`reaches_out`** = the subsystem's *outward dependencies* (what it calls that
   is NOT a member). **`reached_by_in`** = its external *consumers* (who calls in).
5. **`shared_globals`** = data items two or more members touch — usually the
   subsystem's state.

`module_hierarchy` **supersedes `analyze_component`**: you give it ONE seed
instead of a hand-built member list, and it classifies interface vs internal for
you. Use `analyze_component` only when you already have an exact member set.

**grow_depth heuristic**: start at `grow_depth=2`. If `reaches_out` is huge the
subsystem is *under-grown* (raise `grow_depth` so more callees become members) —
or it is genuinely leaky. If `interface` is **empty** you seeded an internal
helper, not an entry point: re-seed on one of the `reached_by_in` callers.

### 3. `call_hierarchy(func)` — the In / Out depth bands

Once a member matters, root a hierarchy on it and look both ways at once:

```
call_hierarchy(root="0x401120", direction="both", depth=2)
```

The result is **signed depth-band LEVELS** — the dolls:

- `level 0`  = the root itself
- `level -1, -2, ...` = **In** side — direct callers, their callers, …
- `level +1, +2, ...` = **Out** side — direct callees, their callees, …

So a `levels` array like `[{-2:[...]}, {-1:[...]}, {0:[root]}, {+1:[...]},
{+2:[...]}]` reads literally as "two bands of callers, the root, two bands of
callees". `edges` are tagged `kind: call|tailcall|jump|indirect` and always
oriented caller→callee regardless of which side they were discovered on.

Use `direction="out"` for callees-only or `"in"` for callers-only when you only
care about one side.

### 4. `function_skeleton(func)` — which call fires under which condition

Drill into the one node that matters. This is the `drill={into:'function_skeleton',
addr}` target on every hierarchy node:

```
function_skeleton(func="0x401120")
```

You get the per-basic-block CFG skeleton: each block's terminating branch, a
**human-readable condition** (`jz → "if (x == 0)"`), its true/false successors,
the calls made in that block (`calls_here`), and loop back-edges, plus the
function's `cyclomatic_complexity` and `loop_count`.

The payoff field is **`guarded_calls`**: when Hex-Rays decompiles the function,
the tool walks the ctree (`cit_if` / `cit_for` / `cit_while` / `cit_do`) and
attaches the *real* guard expression to every call beneath it — e.g.
`{"call":"decrypt","guard":"if (g_init && argc > 1)","site":"0x.."}`. **Scan
`guarded_calls` first** — it is the fastest way to find the "this only runs when
X" paths without reading the full pseudocode.

> PITFALL: a block's `condition` is a *structural label* derived from the branch
> mnemonic (`jnz → "if (x != 0)"`), not a recovered expression. For the true
> predicate use the `guard` field of `guarded_calls`, which is decompiler-backed.
> `guarded_calls` is empty when Hex-Rays is unavailable — the per-block
> `calls_here` still covers every call, just without the predicate.

### 5. `reaches(a, b)` — confirm a specific path

When the skeleton suggests "the guarded call eventually reaches X", confirm it
with the analysis-family `reaches(from, to)` — it returns `reachable` plus the
concrete call-ordered `path`. Use it to prove a chain (e.g. `main → check_pw →
strcmp`) actually exists before you build a hypothesis on it.

### 6. `hierarchy_runtime_overlay(func)` — light up the taken edges

After a debugging/probe session, fold the runtime evidence back onto the static
structure (requires `?ext=dbg`):

```
hierarchy_runtime_overlay(root="0x401120", direction="both", depth=2)
```

It builds the static `call_hierarchy`, drains the probe ring (`trace.py`
`ProbeRing`), and tags each static edge with `taken`/`hits` and each function
with an executed count. `runtime:"present"` vs `"no_runtime_data"` is **honest**
— an empty overlay (no live session / nothing captured) is reported, never
faked, and the static hierarchy still comes back.

> PRO-TIP: cross-reference `edge_hits` with `taken:false` against the static
> edges to find code that is statically reachable but never executed — candidate
> dead paths or untriggered features.
> PITFALL: coverage is only as good as the probes you installed. A `taken:false`
> edge may simply lack a probe, not be unreachable. Install entry/caller probes
> on the functions you care about first (`probe_add` / `trace_calls`).

---

## Depth & cap heuristics

Every tool here is **token-bounded** — it will stop at a depth/node/edge cap and
set `truncated:true` rather than blow your context. Tune deliberately:

- **Start at `depth=2`.** It is almost always enough to orient. Widen *only the
  one side / one node that matters*, and only until `truncated` clears.
- **Widen-until-clear**: if `truncated:true` comes back, the result also carries
  a `continue_cursor` with the next `depth`/`max_nodes` to try. Re-call with it
  (it roughly doubles `max_nodes` and bumps `depth` by one) rather than guessing.
- **`max_nodes`** (default 200, hard cap 2000) is split across the active sides:
  `direction="both"` gives each side ~half. If one side is huge, switch to
  `direction="out"` / `"in"` so the full budget goes to the side you care about.
- **`exclude`** prunes noise: comma-separated name globs (`"sub_*,_*,*alloc*"`);
  bare tokens become substring matches. Pruned functions are not expanded, so
  excluding `*alloc*,*free*,_*` often clears truncation that was just libc churn.
- **`depth` is clamped 0..8**, `function_skeleton` caps at 400 blocks /
  24 calls-per-block / 200 guarded calls, `module_hierarchy` caps at 120 members.
  Hitting any cap sets `truncated:true` — treat it as "this view is partial",
  not "this is the whole story".

Rule of thumb: **never start wide.** `depth=2, direction="both"` then expand the
single node whose `expand` payload you need. Dumping `depth=8` on `main` of a
large binary is the anti-pattern this family exists to replace.

---

## Indirect-call & direction caveats

These two caveats decide whether a sparse-looking result is real or an artifact:

- **Indirect / virtual dispatch is NOT a direct edge.** Only statically-resolved
  *direct* calls become expandable hierarchy nodes. Calls through a register,
  vtable slot, or function pointer cannot be resolved statically, so they appear
  as **explicit indirect leaves** instead of being silently dropped:
  - `call_hierarchy` surfaces them in `indirect_leaves` (unified from BOTH the
    mnemonic-level edges AND the Hex-Rays ctree `cot_call` walk, so vtable-heavy
    C++ classes are not falsely reported as isolated).
  - `function_skeleton` surfaces them in `indirect_sites` and as
    `calls_here[*].indirect:true` entries with `target:null`.
  - **Always check the indirect leaves before concluding a class/function is
    isolated.** A dispatcher that looks like it calls nothing is usually calling
    everything through a table — confirm with a `recipe_dispatch_scan` or a live
    `trace_calls` probe on the indirect site.

- **Direction is about *which doll you expand*, not edge orientation.** `"in"`
  expands callers, `"out"` expands callees, but every emitted `edge` is always
  oriented caller→callee. The In and Out walks are exact transposes (X in
  `out(root)` ⇔ root in `in(X)`), so you can root on either end of a suspected
  path and get a consistent graph. Pick the direction with the *smaller* fan-out
  as your root to stay under the node budget — usually `"in"` (a function has
  fewer callers than transitive callees).

- **Recursion is marked, not followed forever.** Self-recursive functions carry
  `is_recursive:true`; cycle back-edges are detected centrally in
  `walk_call_tree` and do not inflate the band depth. A recursive node is still a
  leaf for expansion purposes — don't re-expand it expecting new structure.

---

## One-glance recipe

```
survey_binary()                                  # 1. whole binary → seeds
module_hierarchy(seed, grow_depth=2)             # 2. subsystem: interface vs internal
call_hierarchy(member, direction="both", depth=2)# 3. In/Out bands around it
function_skeleton(member)                         # 4. guarded_calls: which call when
reaches(member, suspected_sink)                   # 5. confirm the path exists
hierarchy_runtime_overlay(member)                 # 6. (?ext=dbg) light up taken edges
```

Widen one step at a time, follow `truncated` → `continue_cursor`, and always
check `indirect_leaves` before calling a node a dead end.
