# Watchpoints & Tracepoints — Deep Dive

This is the *mechanics* companion to `probe-toolkit.md`. Where that doc sketches
the `instrument -> run -> drain` loop, this one drills into the three live-spy
primitives — **non-stopping tracepoints** (`probe_add`), **hardware data
watchpoints** (`watch_field`), and **runtime call graphs** (`trace_calls`) — plus
the conditional-capture engine, the ring-buffer / `dropped` accounting, and the
hard CPU limits you *will* hit if you over-arm.

Every tool here lives behind `?ext=probes` (the debugger helpers behind
`?ext=dbg`) and **hard-requires a live session the maintainer already launched
(F9)**. None of them ever call `dbg_start`. If the debugger is off you get an
explanatory `{"error": ...}`, not a crash.

---

## 1. The non-stopping tracepoint (`probe_add`)

A tracepoint is an ordinary IDA breakpoint whose **condition is Python that
always returns `False`**. IDA evaluates the condition, the condition does all the
useful work (capture + record + budget), and because it returns `False` the
debuggee is *resumed transparently* — the process never visibly stops.

The condition string that gets written onto the breakpoint is literally:

```python
_IDA_MCP_PROBE_DISPATCH('probe_<ea>_<hash>') if '_IDA_MCP_PROBE_DISPATCH' in dir() else False
```

A single dispatcher is published into `__main__`; every probe's condition is just
a call into it keyed by `probe_id`. On each hit the dispatcher:

1. looks up the probe spec (bails to `False` if missing or disarmed),
2. evaluates the **capture plan** against the suspended thread,
3. applies the optional **predicate** (a Python gate — see §4),
4. records the event into the ring + session JSONL,
5. increments the hit count and **self-disarms (`del_bpt`) at `max_hits`**,
6. returns `False`.

Any exception inside the dispatcher is swallowed and also returns `False`, so a
malformed capture spec can **never** halt the target.

### Calling it

```jsonc
probe_add(
  ea       = "0x401abc",                 // address, name, or expression parse_address() accepts
  capture  = ["ecx", "arg0", "mem(arg1, 64)"],
  condition = "int(c['arg0'],16) == 7",  // optional Python predicate over `c`
  max_hits = 1024,                        // budget; self-disarms here
  every_nth = 1,                          // advisory sampler (recorded on the spec)
  buffer_mode = "circular"                // or "linear"
)
```

Returns a `ProbeRef`: `{probe_id, ea, kind, capture, condition, max_hits, armed,
installed, reused}`. `reused: true` means an identical probe already existed —
installs are **idempotent** over `(ea, capture, condition)` (the `probe_id` is a
sha1 of that triple), so re-issuing the same call is safe and cheap.

### Capture tokens (the spec language)

| Token | Meaning |
|---|---|
| `eax`, `ecx`, `rdi`, `al`, ... | a register value (32/64-bit register set) |
| `argN` | the Nth **stack** arg at callee entry: `[esp + ptr*(N+1)]` |
| `ret` | the return-value register (`eax` / `rax`) |
| `caller` | return address at entry == `[esp]` (the call site) |
| `mem(<expr>, <n>)` | `n` bytes at `<expr>`; `<expr>` may add regs / `argN` / `caller` / `ret` / hex literals, e.g. `mem(arg1+0x10, 256)` |

`mem(...)` size is clamped to `0..4096`. Unrecognized tokens don't abort the
install — they're recorded with `{"error": "unrecognized capture token"}` in the
event so a partly-valid spec still arms.

> **`argN` is the STACK slot, always.** For `__thiscall` the `this` pointer is in
> `ecx`, **not** `arg0`. Capture `this` explicitly with the `ecx` token; `arg0`
> remains the first *stack* argument. `trace_calls(conv="thiscall")` does this for
> you. Getting this wrong silently mislabels every argument by one.

> **Captures snapshot the value at the breakpoint's PC.** Register-arg ABIs (x64
> fastcall, or any value already moved out of its home slot) mean `argN` only
> reads the right thing **at function entry** before the prologue shuffles the
> stack. Probe the first instruction of the callee, not mid-body.

---

## 2. Hardware data watchpoints (`watch_field`) — spy on a struct field

`watch_field` installs a **hardware data breakpoint** (CPU debug register,
`BPT_WRITE` or `BPT_RDWR`) on a memory location, wraps it in the same
non-stopping condition, and adds a **change-detector**: it records an event
*only when the watched bytes actually change* since the last hit. Unchanged
writes (a store of the same value) are silently suppressed.

This is the canonical way to answer **"who writes this struct field, and what
does it change to?"** — point it at `base_ptr + offset` and let the spies catch
every mutator across the whole run.

```jsonc
watch_field(
  base_ptr  = "0x0A1B2C30",   // live object pointer (from a prior probe / read_struct_live)
  offset    = 0x1C,           // field offset within the struct
  size      = 4,              // 1 / 2 / 4 (or 8 on 64-bit) — see HW limits
  mode      = "write",        // "write" -> BPT_WRITE, "rdwr" -> BPT_RDWR
  predicate = "int(new,16) > int(old,16)",  // optional gate over old/new
  max_hits  = 512
)
// or address-form: watch_field(ea="0x6C8420", size=4, mode="write")
```

Effective address = `base_ptr + offset` (falls back to `ea + offset`). On each
change the event's `captured` dict is:

```jsonc
{ "field": "0x0a1b2c4c", "old": "11000000", "new": "12000000",
  "writer_pc": "0x401d77", "caller": "0x442310" }
```

`writer_pc` is the instruction that performed the store — the function you were
hunting. `old`/`new` are little-endian hex of the raw bytes.

### Field-spy idiom (the high-value pattern)

1. `read_struct_live(ea, "my_struct_t")` to confirm layout + grab the live
   pointer and the field's current value.
2. `watch_field(base_ptr=ea, offset=<field>, size=<field_size>, mode="write")`.
3. `run_until(timeout_ms=...)`, exercise the target (in-game action, packet, UI
   click).
4. `probe_drain(...)` and read `writer_pc` for each change — that's your writer
   set. Cross-reference each `writer_pc`/`caller` back in static analysis.

Use `mode="rdwr"` when you need to catch the field being *read* too (e.g. a
flag consumed elsewhere), but reads are far more frequent than writes — expect
heavy traffic and a low `max_hits`.

---

## 3. HARDWARE-SLOT & GRANULARITY LIMITS (read before you over-arm)

Data watchpoints use the x86 **debug registers DR0–DR3**. This is a hard CPU
ceiling, not a software policy:

- **Only 4 hardware data slots exist, process-wide.** A 5th `watch_field` will
  fail to arm or silently never fire. Budget them. `probe_clear(probe_id)` frees
  a slot the instant you're done with a field.
- **Size must be 1, 2, or 4 bytes** (8 only on a 64-bit target). `watch_field`
  rejects anything else up front with
  `{"error": "watch size must be 1/2/4 (8 on 64-bit); got N"}`.
- **The address must be naturally aligned** to its size (a 4-byte watch on an
  address not divisible by 4 won't fire reliably). The hardware enforces
  alignment; an unaligned watch is the classic "my watchpoint never triggers"
  trap.
- **Watching a wide field?** Split it into aligned sub-watches — but remember
  each sub-watch eats one of the 4 slots. Watching a 16-byte field exactly is
  impossible in one slot; pick the 4 bytes that actually matter, or fall back to
  a **software tracepoint** (`probe_add` with `mem(...)` capture) at the known
  writer instead.
- **Code probes are unlimited** — `probe_add` / `trace_calls` use software
  (`BPT_SOFT`) breakpoints, which are not slot-limited. Reserve the 4 precious HW
  slots for *data* and spend code probes freely.

> **Pro-tip — prefer a code tracepoint when you already know the writer.** If
> static analysis already points at the store instruction, a `probe_add` there
> with `mem(<dest>, 4)` capture is cheaper (no HW slot) and just as informative
> as a watchpoint. Use `watch_field` for *discovery* (unknown writer), code
> probes for *confirmation* (known writer).

---

## 4. Conditional capture — make probes cheap

Both the `condition` (on `probe_add`) and `predicate` (on `watch_field`) are a
**Python expression evaluated in a sandbox** (`__builtins__` stripped) with:

- `c` — the captured dict (tracepoints), keys are your raw capture tokens.
- `old` / `new` — the pre/post values (watchpoints).

It runs **after** the capture, gating whether the event is *recorded* (a
non-matching predicate returns early with no ring entry). On error the predicate
defaults to **`True`** (fail-open — it never silently drops everything because of
a typo, it over-records instead).

```python
# only record when arg0 is opcode 0x12
condition = "int(c['arg0'], 16) == 0x12"

# only record growth of a counter field
predicate = "int(new,16) > int(old,16)"

# record when a captured byte slice starts with a magic
condition = "c['mem(arg1, 4)']['hex'].startswith('deadbeef')"
```

### Keeping conditions cheap (the throughput rule)

A probe on a hot function (per-frame tick, recv loop, allocator) can fire
thousands of times a second. The condition runs **in-process, on the debuggee's
thread, on every hit** — an expensive condition throttles the target.

- **Filter on a register/arg, not on `mem(...)`.** `mem(...)` performs a live
  `dbg_read_memory` *before* the predicate even runs — so a `mem` token is paid
  on every hit regardless of the condition. Gate on `c['ecx']` / `c['arg0']`
  (cheap register reads) and only add `mem(...)` once the cheap filter is tight.
- **Integer compares beat string ops.** `int(c['arg0'],16) == 0x12` is far
  cheaper than substring/`.startswith` on a hex blob. Push string matching to the
  drain side (filter in `probe_drain`) where it runs out-of-band.
- **Lower `max_hits` is a condition.** The cheapest gate of all is the budget:
  if you only need the first 8 occurrences, set `max_hits=8` and the probe
  self-disarms (frees the breakpoint) instead of evaluating forever.
- **`every_nth` is advisory today.** It's recorded on the spec for the caller but
  the dispatcher records *every* hit; don't rely on it for sampling — use
  `max_hits` + a tight `condition` instead.

> **Two-stage discovery.** Arm a broad probe with a *small* `max_hits` and no
> condition to learn the value distribution; `probe_drain`; then re-arm with a
> precise `condition` and a large `max_hits` for the real capture. The first
> probe self-disarms, so there's nothing to clean up.

---

## 5. Ring buffer & `dropped` semantics

Captured events flow into a bounded **`ProbeRing`** (default cap 4096, hard max
65536) and are *also* appended to a per-session JSONL file. Drains read the ring;
the JSONL is the durable record.

- `buffer_mode="circular"` (default): on overflow the **oldest** record is
  evicted and the `dropped` counter increments. You always keep the most recent
  N events — ideal for "what happened just before the crash".
- `buffer_mode="linear"`: on overflow the ring **stops accepting** new records,
  sets `full=true`, and increments `dropped` for each rejected event. You keep
  the *first* N events — ideal for "capture the start of a sequence exactly".

The **seq cursor is monotonic for the whole lifetime of the ring**, even across
eviction. So the drain protocol is stable:

```jsonc
r1 = probe_drain(since_cursor=0)            // -> {records, cursor: 128, dropped: 0}
r2 = probe_drain(since_cursor=r1.cursor)    // -> only records after seq 127
```

Always feed the returned `cursor` back as `since_cursor`. Drains are
**non-destructive** (they snapshot, never pop), so two consumers can read the
same window; the cursor is how *you* track your own progress.

### Reading `dropped`

`dropped > 0` in a drain result means **you lost events** — your probe fired
faster than you drained, or your `max_hits`/cap was too small. Reactions:

- raise the cap up front: the ring can be re-created via the probe session config
  (`configure_probes(session_id, cap=..., buffer_mode=...)`);
- tighten the `condition` so fewer events are recorded;
- drain more often / inside a shorter `run_until` window;
- switch to `linear` if you only care about the opening of the sequence.

The JSONL on disk is **not** subject to the ring cap — every recorded event is
written there, so even with `dropped > 0` in the ring you can recover the full
stream from `IDA_MCP_PROBE_DIR` (defaults to `<tempdir>/ida_mcp_probes`; set it
to a stable path to collect across sessions). Each record carries `_meta` with
the IDB input-file `sha256` and `dirty: true` (firewall provenance).

---

## 6. Runtime call graphs (`trace_calls`)

`trace_calls` is `probe_add` specialized for **"what calls this, with what, and
what does it return"** across a live run — a *dynamic* callgraph to complement
the static `callgraph` / `xrefs_to` tools.

```jsonc
trace_calls(
  ea          = "0x401abc",
  conv        = "thiscall",  // thiscall | cdecl | stdcall
  argc        = 4,           // how many args to capture
  capture_ret = true,
  max_hits    = 2048
)
```

It builds the capture spec for you per convention:

- always captures **`caller`** (the call site — the edge source in the graph),
- `thiscall` additionally captures **`ecx`** (the `this` pointer),
- then `arg0..arg(argc-1)` as stack slots.

Every hit therefore yields one **caller -> callee** edge plus the argument vector
at that call. Drain the probe and group by `caller` to reconstruct who actually
reached this function at runtime (which dead-looking static xrefs are live, which
hot path dominates).

### Return values are a known limitation

A non-stopping entry probe **cannot install a one-shot return breakpoint without
stopping**, so `trace_calls(capture_ret=True)` does *not* automatically capture
`eax` at the return. The returned `ProbeRef` annotates this with an explicit
instruction:

```
"ret@return-site (place a probe_add(ret) at the call's return address)"
```

To capture returns: read `caller` from the entry events, then `probe_add` at
each call's **return address** (the instruction after the `call`) with capture
`["ret"]`. The two probe streams join on `caller` / call site to pair args with
results.

---

## 7. The buffer-path convenience: `probe_net`

`probe_net` is a thin wrapper that installs `probe_add` tracepoints at
**caller-supplied** recv / decrypt / send addresses (nothing hardcoded), each
capturing `[buf_arg, len_arg, mem(buf_arg, 256)]`. With `pre_post=True` it
annotates `decrypt_ea` so you remember to place a paired probe at the decrypt
**return site** and diff the buffer before/after the transform — the standard way
to byte-prove a cipher boundary against ground truth. It's pure convenience over
§1; the same result is achievable with three `probe_add` calls.

---

## 8. End-to-end recipe

```jsonc
// 1. instrument (mix of code + data spies)
probe_add(ea="recv_handler", capture=["arg0","arg1","mem(arg0,256)"],
          condition="int(c['arg1'],16) > 0", max_hits=256)
watch_field(base_ptr="0x0A1B2C30", offset=0x1C, size=4, mode="write")
trace_calls(ea="actor_update", conv="thiscall", argc=2)

// 2. run (maintainer triggers the in-game event)
run_until(timeout_ms=8000)

// 3. drain incrementally
d = probe_drain(since_cursor=0)
// ... inspect d.records, watch d.dropped; loop with since_cursor=d.cursor

// 4. inspect a live object the probes pointed you at
read_struct_live(ea="[[0x0A1B2C30+0x10]+0x8]", type_name="actor_t")

// 5. free everything (releases HW slots + breakpoints)
probe_clear()   // omit probe_id to clear ALL
```

### Pitfall checklist

- **Watchpoint never fires** -> almost always alignment or you blew past the
  4-slot limit. Verify `size` divides the address; `probe_clear` stale watches.
- **`argN` looks garbage** -> wrong convention (`this` is in `ecx` for thiscall),
  or you probed past the prologue. Probe the entry instruction.
- **`dropped` keeps climbing** -> condition too loose / cap too small / draining
  too slowly. Tighten the condition, raise the cap, or go `linear`.
- **Probe seems to do nothing** -> confirm a live session (`?ext=dbg,probes` and
  a process the maintainer F9-launched); these tools refuse to `dbg_start`.
- **Don't `appcall` in a loop** — it executes target code; it's a single,
  human-confirmed action, never part of an automated probe flow.
