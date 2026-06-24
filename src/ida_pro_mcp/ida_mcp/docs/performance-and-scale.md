# Performance & Scale: Working Fast on Large Binaries

The dominant cost in an MCP-driven RE session is **round trips**, not IDA's own
analysis. Every tool call crosses HTTP/JSON-RPC, marshals through the
`@idasync` main-thread queue, runs, and serializes a result back. On a big IDB
(`doida.exe` has tens of thousands of functions) the difference between a fast
session and a painful one is almost entirely *how many calls you make* and *how
much each one returns*. This doc is the playbook for keeping both small.

The three levers, in order of impact:

1. **Batch** — fold N targets into one call.
2. **Project / cap** — return only the columns and lines you need.
3. **Warm caches** — let the strings cache and tool-schema cache absorb repeat work.

---

## 1. The cost model (why batching dominates)

A single `mcp__ida__decompile` of one function and a batch of 20 functions cost
roughly the same *per-function IDA work*. The difference is **19 fewer round
trips**: 19 fewer JSON-RPC frames, 19 fewer `@idasync` enqueue/wait cycles, 19
fewer LLM tool-call turns. Tool-call turns are the scarcest resource — each one
burns context and latency — so the rule of thumb is:

> If you are about to call the same tool more than twice in a row with different
> addresses, you almost certainly want the batch form instead.

Nearly every read tool in this server already accepts a **list** where you'd
expect a scalar. When in doubt, pass a list.

---

## 2. Batch tools — the ones that take a list

| Instead of N calls to… | Use this once | Notes |
|---|---|---|
| `decompile` / `disasm` / `xrefs_to` / `callees` per function | `analyze_batch` | One query object per function; toggle sections off |
| `get_bytes` per region | `get_bytes` (already a list) | Pass `[{addr,size}, …]` |
| `get_int` per scalar | `get_int` (already a list) | `[{ty,addr}, …]` |
| `list_funcs` + `list_globals` + `imports` + `find_regex` | `entity_query` (list of queries) | One schema across 5 entity kinds |
| `type_apply` per function | `type_apply_batch` | Bulk typing |
| `append_comments` / `set_comments` per ea | already batch | List of `{addr, comment}` |

### `analyze_batch` — the workhorse

`analyze_batch` is the single most valuable batch tool for reading code. One
query object per function, each carrying `include_*` toggles:

```jsonc
// mcp__ida__analyze_batch
{ "queries": [
    { "addr": "0x401000",
      "include_decompile": true,
      "include_disasm": false,        // OFF by default — token-heavy
      "include_basic_blocks": false,  // turn off what you won't read
      "include_constants": false },
    { "addr": "sub_4021A0" },         // every section except disasm defaults ON
    { "addr": "0x402F00" }
] }
```

Every section returns a `*_count` and `*_truncated` flag, so you know when a
`max_*` cap clipped a list. **Turn OFF sections you won't read** — on a large
function `include_disasm` and a full `include_decompile` each dominate the
payload. A missing Hex-Rays license shows up as `analysis.decompile_error` on
the row, not a top-level failure, so the rest of the row is still usable.

For a single function the composite `analyze_function` (in `api_composite`) is
the same idea pre-tuned for one target: decompile capped at 100 lines, top ~10
deduped strings, top ~10 non-trivial constants, callee/caller **names only**.
Prefer it over hand-chaining `decompile` + `strings` + `xrefs_to` + `callees`.

For a *cluster* of functions that look like one subsystem, `analyze_component`
takes the whole list and returns the internal call graph, shared globals, and
the interface-vs-internal split in one call — far cheaper than reconstructing
that by hand from per-function xrefs.

---

## 3. Projection & pagination — shrink every payload

A batch that returns 4 KB per row still hurts if you only needed two columns.
`entity_query` supports column projection and pagination directly:

```jsonc
// mcp__ida__entity_query — only the columns you need, paginated
{ "queries": [
    { "kind": "functions",
      "regex": "recv|decrypt|packet",
      "fields": ["addr", "name"],   // project: drop size/segment/flags/etc.
      "sort_by": "size", "descending": true,
      "count": 50, "offset": 0 }
] }
```

- `fields` trims the row to just the listed keys — use it aggressively on big
  result sets.
- `total` in the response is the **full filtered count before pagination**, so
  you can size your next page without a probe call.
- `next_offset` is the cursor for the following page; loop until it's null.
- `kind: "strings"` is served straight from the **warm strings cache** (below).

Default `count` is 100. Don't pull 10k rows to eyeball the first screen —
page it.

---

## 4. The strings cache

`idautils.Strings()` is expensive to enumerate on a large image. The server
builds the full `[(ea, text), …]` list **once**, lazily, on first access and
keeps it in `api_core._strings_cache` behind a lock. Every consumer
(`entity_query kind=strings`, `survey_binary`, the interesting-strings ranking)
reads the cached list, not a fresh enumeration.

Practical consequences:

- **The first strings-touching call pays the build cost; the rest are cheap.**
  `server_warmup` (run automatically by `open_file`) pre-builds it so even the
  first call is warm. Check `server_health().strings_cache_ready` /
  `strings_cache_size` to confirm.
- The cache is **invalidated on IDB mutation** via
  `invalidate_strings_cache()`. After you create new strings (defining data,
  patching) the next strings query rebuilds — expect that one call to be slower.
- It is a list, not an index — substring/regex filters in `entity_query` scan it
  linearly. That's fine (it's in-memory Python), but it means a tight `regex`
  plus `fields` projection is the cheap way to slice it, not pulling all strings
  and filtering client-side.

---

## 5. The tool-schema cache

The MCP layer (`zeromcp/mcp.py`) memoizes each tool's generated JSON schema in
`_tool_schema_cache`, keyed by the function object. `tools/list` is therefore
nearly free to re-issue, and the schema is built once per process. You normally
don't touch this, but two facts matter:

- A schema is a **pure function of the tool + its name**, so re-listing tools
  costs nothing after warmup.
- The cache is dropped by `invalidate_tool_schema_cache()` only when the tool
  registry changes (e.g. an `?ext=` extension toggles which tools are exposed).
  If you switch endpoints/extensions mid-session, expect one re-generation.

The takeaway: **don't re-fetch `tools/list` defensively** between calls — it's
cached, but the round trip still costs you a turn.

---

## 6. Bulk byte reads

`get_bytes` takes a **list** of `{addr, size}` regions and returns one result
per region, in order, with per-region error isolation (a bad region returns
`{addr, data: null, error}` instead of aborting the batch). Use it to pull an
opcode blob, several struct instances, or a scatter of globals in one call:

```jsonc
// mcp__ida__get_bytes — many regions, one round trip
{ "regions": [
    { "addr": "0x44A100", "size": 64 },
    { "addr": "g_packetTable", "size": 256 },
    { "addr": "0x44C000", "size": 16 }
] }
```

Pro-tips and pitfalls:

- Reads are **BSS-safe**: uninitialized `.bss` bytes come back as zeros rather
  than failing — handy for reading a zero-init table, but it means "all zeros"
  can mean "uninitialized," not "value is 0."
- `data` is a **hex STRING** (`"0x4d 0x5a .."`), not a byte array. Parse before
  arithmetic.
- For a *typed scalar*, prefer `get_int` (also a list) — it handles
  width/sign/endianness (`i8/u8/…/u64`, `le|be`) so you don't hand-assemble
  bytes.
- For a *typed struct over an IDB type*, prefer `read_struct` (static) or
  `read_struct_live` (debugger) — they overlay the type into named fields
  instead of you slicing offsets out of a hex blob.
- Keep individual `size` sane. A 1 MB read serializes to a ~3 MB hex string and
  will dwarf your context. Read the header, decide, then read the body.

---

## 7. Bounded probe rings (live sessions)

Under the debugger, the **non-stopping probe** layer (`api_probes`) is built for
volume: you instrument hot sites, let the process run, and drain captures —
without ever halting on each hit. The buffering is deliberately **bounded** so a
hot function can't blow up memory.

The capture buffer is a `ProbeRing` (`trace.py`):

- Default capacity **4096** records, hard max **65536**.
- `buffer_mode: "circular"` (default) **evicts the oldest** record on overflow
  and bumps a `dropped` counter — you keep the *most recent* N events.
- `buffer_mode: "linear"` **stops appending** once full (also counting
  `dropped`) — you keep the *first* N events and nothing newer.

`probe_drain` returns `{records, cursor, dropped}`. The discipline:

```text
cursor = 0
loop:
    r = probe_drain(since_cursor=cursor, limit=512)
    process(r.records)
    cursor = r.cursor          # feed it back next time
    if r.dropped > 0: …        # you are draining too slowly — see below
```

- Draining is **non-destructive and cursor-based** — pass the returned `cursor`
  back as `since_cursor` to get only new records. Don't re-drain from 0.
- A nonzero `dropped` is the signal you're producing faster than you drain.
  Fixes, in order: **narrow the probe** (a tighter `condition`/predicate, a
  smaller `mem(...)` slice), **lower `max_hits`** (the probe self-disarms at its
  budget via `del_bpt`), or drain more often / with a larger `limit`.
- `mem(arg1, 256)` captures **256 bytes per hit**. On a per-packet recv that is
  huge. Capture the *length* arg plus a *modest* slice, then read the full
  buffer once with `read_struct_live`/`get_bytes` only on the hit you care about.

---

## 8. Keeping a live probe session stable on hot functions

A probe is a breakpoint carrying a Python condition that captures values,
records, decrements a hit budget, and **always returns `False`** so the
debuggee never stops. That design is what makes it safe to instrument a hot
path — but a few rules keep it stable:

- **Never probe a function that runs every frame with `max_hits` left wide
  open.** Set a tight budget (`max_hits: 8`) so the probe self-disarms quickly.
  You can always re-arm. An un-budgeted probe on the render loop will flood the
  ring and slow the target to a crawl.
- **Gate with a `condition`/predicate** so the record is only written when it
  matters. The predicate runs over the captured dict (`c`), e.g.
  `c['arg2'] != '0x0'`. A probe that fires 10000×/s but records 3 times is fine;
  one that records 10000×/s is not.
- **Watchpoints record only on change.** `watch_field` uses a hardware data
  breakpoint and a change-detector — it writes a record only when the watched
  value actually changes, so it's cheap on a field that's read constantly but
  written rarely. Remember the hardware limits: **4 slots**, size **1/2/4** (8
  on 64-bit), **naturally aligned**. Split a large field into aligned
  sub-watches.
- **Install is idempotent.** Probe ids are a stable hash of
  `(ea, capture, condition)`, so re-issuing the same `probe_add` reuses the
  existing breakpoint instead of stacking duplicates on the hot site. Lean on
  this rather than `probe_clear`-then-re-add loops.
- **Use `run_until` with a timeout, not an open-ended continue.** Pass
  `probe_id` to get exactly that probe's records back in the `buffer`, and a
  `timeout_ms` so a probe that never hits returns control instead of hanging.
- **Drain, then clear.** When done with a site, `probe_clear(probe_id)` deletes
  its breakpoint so it stops costing the target anything. `probe_clear()` with
  no id removes them all.
- **Persisted overflow.** Probe events are also written as JSONL under
  `IDA_MCP_PROBE_DIR` (default `<tempdir>/ida_mcp_probes`). Set it to a stable
  path for a long capture so even ring-evicted records survive on disk for
  offline analysis.

> The probe layer **never calls `dbg_start`** — it hard-requires a session the
> maintainer already launched (F9). If you get a "no live debugger session"
> error, that's the guard, not a bug.

---

## 9. `survey_binary` — one call instead of an opening barrage

Don't fire `list_funcs`, `imports`, and `find_regex` separately just to get
oriented. `survey_binary` bundles metadata, segments, entrypoints, stats, the
top-15 strings and functions by xref count, categorized imports, and a
call-graph summary in **one** call.

Scale caveats baked in:

- On a binary with **>10,000 functions** the xref-based rankings
  (`interesting_functions`, `call_graph_summary`) are computed over only the
  first 10k functions — a `_note` field says so. Treat the "top" lists as an
  approximation; follow up with `func_query`/`entity_query` for an exhaustive
  scan.
- Interesting-string ranking caps at the first 5000 strings and 200 xrefs per
  string.
- For a *very* large IDB use `detail_level: "minimal"` to skip the xref-heavy
  sections entirely and get just metadata/stats/segments/entrypoints fast.

---

## 10. Quick checklist

- Calling the same tool 3+ times with different addresses? → **batch it**
  (`analyze_batch`, `get_bytes`, `get_int`, `entity_query` list).
- Big result set? → **`fields` projection + `count`/`offset` pagination**.
- Opening a new IDB? → **`survey_binary`** first; `"minimal"` if it's huge.
- Reading one function deeply? → **`analyze_function`** (capped) over manual chaining.
- Strings feel slow on the first call? → it's the **cache build**; warm via
  `server_warmup`, check `server_health`.
- Live session, hot path? → **tight `max_hits` + a `condition` + change-only
  `watch_field`**, drain by **cursor**, watch the **`dropped`** counter,
  `probe_clear` when done.
