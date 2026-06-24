# Live Debugging and Tracing

This server can drive a **live** IDA debugger session, not just static analysis.
Two layers sit on top of that:

1. The **`dbg_*` tools** (`api_debug`) — classic stop-the-world debugging:
   breakpoints, single-step, registers, stack, read/write debuggee memory.
2. The **PROBE / AUTOPILOT** layer (`api_probes`) — *non-stopping* instrumentation
   that lets the target run free while you collect captured events. This is the
   high-throughput path and the one you should reach for first for anything that
   fires more than a couple of times.

Both layers **hard-require a debugger that is already running** and will fail with
an explanatory error otherwise. The probe layer NEVER calls `dbg_start`. See the
companion doc `probe-toolkit.md` for the full token grammar; this doc is about the
*workflow* — when to stop, when to run free, and how to reason from drained data.

## Extension gating

The debugger and probe tools are gated behind MCP `?ext=` flags so a default
connection stays read-only/static:

- `?ext=dbg` — exposes `dbg_start`, `dbg_continue`, `dbg_run_to`, `dbg_step_*`,
  `dbg_add_bp`, `dbg_regs*`, `dbg_read`, `dbg_write`, `read_struct_live`,
  `appcall_inspect`.
- `?ext=probes` — exposes `probe_add`, `run_until`, `watch_field`, `trace_calls`,
  `probe_net`, `appcall`, `snapshot_*`.
- Combine them: `?ext=dbg,probes`.

`probe_list` / `probe_drain` are `@safety("READ")` and ungated — you can drain a
ring even from a static connection.

## The dbg_* tools (stop-the-world)

| Tool | Purpose |
|------|---------|
| `dbg_status` | Lifecycle state (`running` / `suspended` / `not_running`) + IP if suspended. **Call this first** — most tools require a *suspended* process. |
| `dbg_start` | Launch the configured target. The maintainer usually F9-launches instead; prefer not to call this. |
| `dbg_continue` / `dbg_run_to(addr)` | Resume; `run_to` resumes until an address is reached. |
| `dbg_step_into` / `dbg_step_over` | One instruction (into / over calls). |
| `dbg_add_bp(addrs)` / `dbg_delete_bp` / `dbg_toggle_bp` / `dbg_bps` | Software breakpoint management (batch-capable; pass a list). |
| `dbg_set_bp_condition` | Attach an IDC/Python condition to a breakpoint. |
| `dbg_regs` / `dbg_gpregs` / `dbg_regs_named("RAX,RBX")` | Registers for the current thread. `*_remote` / `*_all` variants take/iterate thread IDs. |
| `dbg_stacktrace` | Call stack with module + symbol per frame. |
| `dbg_read(regions)` / `dbg_write(regions)` | Read/write debuggee memory. Batch: pass `[{"addr","size"}, ...]`. |

### A minimal stop-and-inspect loop

```
dbg_status()                                  -> {"state":"suspended","ip":"0x401000"}
dbg_add_bp(["0x4031A0"])                       # the function you care about
dbg_continue()                                 # run; user triggers the event in-app
dbg_status()                                   -> suspended at 0x4031A0
dbg_gpregs()                                   # ecx = this, args on the stack
dbg_read([{"addr":"0x4031A0_arg_ptr","size":64}])
dbg_stacktrace()                               # who called us
```

### dbg_read reads THROUGH guard pages

`dbg_read` uses `dbg_read_memory`, which reads live process memory directly — it
sees `PAGE_NOACCESS` / freshly-decrypted buffers that a *static* `get_bytes` on
the IDB cannot. When you need the real runtime bytes (a decrypted packet, a
heap struct), use `dbg_read`, not the static readers. Returned `data` is hex.

### Pitfalls (dbg layer)

- **"Debugger is running" errors.** Register/memory/step tools require
  `DSTATE_SUSP`. If a `dbg_continue` left the process running, wait for it to hit
  a breakpoint (or use the probe layer's `run_until`, which waits for you).
- **`dbg_start` return code lies.** `start_process` returns -1 even on success;
  the tool trusts the actual debugger state instead. Don't retry on a non-zero
  code — call `dbg_status`.
- **Don't busy-loop `dbg_step_*`.** Single-stepping over a hot loop through MCP
  is brutally slow (one round-trip per instruction). For anything that iterates,
  use a probe instead.

## Why async probing beats single-step

Single-step and breakpoint-then-inspect are *synchronous*: every event costs a
full MCP round-trip and **halts the whole process** while you think. For a
function that fires hundreds of times a second (a packet handler, a per-frame
tick, a memcpy on the recv path), that is unusable — you stop the world, read
two registers, resume, and the timing-sensitive target has already drifted or
the interesting call has flown past.

A **probe** inverts this. It is a breakpoint whose Python condition:

1. evaluates a small **capture spec** (registers, stack args, return value,
   caller, memory slices),
2. appends the captured values to an in-process **ring buffer**,
3. decrements a hit budget and **self-disarms** (`del_bpt`) when spent,
4. **always returns `False`** — so IDA never actually stops the debuggee.

The process runs at full speed; you collect a *time series* of every hit and
reason about it offline. No round-trip per hit, no halting, no timing skew.

## The PROBE / AUTOPILOT model: instrument -> run free -> drain -> reason

### 1. Instrument

```
probe_add(
    ea="0x004031A0",
    capture=["ecx", "arg0", "arg1", "mem(arg1,64)", "caller"],
    max_hits=256,
)
```

Capture tokens (full grammar in `probe-toolkit.md`):

- `eax`, `ecx`, `rdi`, ... — register value
- `argN` — Nth stack arg at callee entry (cdecl/thiscall slot layout)
- `ret` — return-value register (eax/rax)
- `caller` — return address at `[esp]` on entry
- `mem(<expr>, <n>)` — `n` bytes at `<expr>`, where `<expr>` mixes regs / `argN` /
  `caller` / hex literals, e.g. `mem(arg1+0x10, 256)`

Higher-level installers:

- `trace_calls(ea, conv="thiscall", argc=4)` — auto-builds the capture list for a
  function's args (thiscall adds `ecx`/this).
- `watch_field(ea|base_ptr, size, mode="write")` — a **hardware** data watchpoint
  that records **only when the value changes**, capturing `{old,new,writer_pc,
  caller}`. Use this to answer "*what code writes this field?*"
- `probe_net(recv_ea, decrypt_ea, send_ea, buf_arg, len_arg)` — convenience buffer
  probes for a recv/decrypt/send path (addresses are caller-supplied, never
  hardcoded).

Installs are **idempotent** on `(ea, capture, condition)` — re-running the same
`probe_add` reuses the existing probe (`reused: true`) instead of stacking
duplicates.

### 2. Run free

```
run_until(timeout_ms=5000, probe_id="probe_4031a0_ab12cd34ef")
```

`run_until` resumes the suspended process and **pumps `wait_for_next_event` in
~100 ms slices** until one of: a probe records a hit, `target_ea` is reached, or
the timeout elapses. It returns `{status, stopped_ea, elapsed_ms, hit_probe,
buffer}` where `status ∈ {hit, timeout, exited, suspended}` and `buffer` holds
records produced by `probe_id` during *this* run.

Because probes don't stop, `run_until` is your "let it cook" primitive — set a
generous timeout, let dozens of hits accumulate, then drain.

### 3. Drain

```
probe_drain(since_cursor=0, filter={"probe_id":"..."}, limit=512)
   -> {"records":[...], "cursor":128, "dropped":0}
probe_drain(since_cursor=128, ...)          # pass cursor back; never re-read
```

`probe_drain` is **non-destructive** and ordered oldest-first. The ring stamps
each record with a monotonic `_seq`; `cursor` is the next seq to request. The
cursor stays valid **even after eviction**, so the loop is stable:

```
cursor = 0
loop:
    res = run_until(timeout_ms=3000, probe_id=PID)
    page = probe_drain(since_cursor=cursor, filter={"probe_id":PID})
    process(page["records"])
    cursor = page["cursor"]
    if res["status"] in ("exited",): break
```

### 4. Reason

The drained records are a clean dataset. Diff `mem(...)` slices across hits to
isolate which bytes change (a length field, a sequence counter), correlate
`caller` values to find the hot call site, or watch `old`/`new` from a
`watch_field` to pin the single instruction that mutates a struct member.

## run_until vs polling

**Prefer `run_until` over a `dbg_continue` + `dbg_status` poll loop.** `run_until`
already internalizes the event pump (`_continue_and_wait`): it resumes, waits in
bounded slices, and returns a structured status with the probe buffer attached.
A hand-rolled `dbg_continue` / `dbg_status` poll instead spends round-trips
asking "are we there yet?", can miss a transient suspension between polls, and
gives you no buffer. Reach for the manual poll only when you are doing pure
stop-the-world stepping with no probes installed.

`target_ea` turns `run_until` into a "continue to here, but also collect anything
my probes catch on the way" primitive — strictly better than `dbg_run_to` when
probes are armed.

## IDA_MCP_PROBE_DIR

Probe events are also persisted to disk as JSONL so a run survives the session.
The directory is the `IDA_MCP_PROBE_DIR` environment variable; **unset it defaults
to `<tempdir>/ida_mcp_probes`**. Set it to a stable path before launching IDA to
keep a durable capture log you can post-process with other tooling:

```
export IDA_MCP_PROBE_DIR=/work/mh/probes   # set BEFORE the IDA/MCP process starts
```

The in-memory ring (`ProbeRing`) is bounded: default cap **4096**, hard max
**65536** records. In the default **circular** mode the oldest record is evicted
on overflow and the `dropped` counter (surfaced by `probe_drain`) increments — if
you see `dropped > 0`, you lost data: drain more often, raise `max_hits`
discipline, or tighten the `condition`/`predicate` so fewer hits are recorded.
**linear** mode stops appending when full instead of evicting.

## Filtering at the source: conditions and predicates

`probe_add(condition=...)` is a **Python predicate** evaluated over the captured
dict (bound as `c`) in a sandboxed namespace. Use it to record only interesting
hits and keep the ring from filling with noise:

```
probe_add(ea="0x4031A0",
          capture=["arg0","arg1"],
          condition="int(c['arg0'],16) == 0x1F")   # only opcode 0x1F
```

`watch_field(predicate=...)` works the same over `old`/`new`. Filtering at the
source beats draining everything and filtering client-side: it costs nothing on
the hot path and never evicts good data.

## Live struct + appcall helpers

- `read_struct_live(ea, type_name)` overlays an IDB type onto live bytes and
  returns named fields. `ea` may be a **pointer chain** like `[[base+0x10]+0x8]`,
  dereferenced live — ideal for walking a `this` pointer to a nested struct
  without manual `dbg_read` math.
- `appcall(ea, prototype, args, confirm)` marshals (and, with `confirm=True` on a
  **suspended** process, CALLS) a function in the target. **It executes target
  code** — use it as a single, deliberate, human-confirmed action, **never inside
  a probe/run/drain loop**. `appcall_inspect` resolves the prototype types
  without calling anything.
- `snapshot_save` / `snapshot_restore` capture/restore named registers + bounded
  memory ranges. **Best-effort only** — not a full process snapshot; anything not
  explicitly captured is unchanged on restore.

## Cleanup

`probe_clear(probe_id=None)` removes one probe or all of them and deletes the
underlying breakpoints (when the debugger is live). Always clear your probes
before handing the session back or re-instrumenting a different code path —
orphaned non-stopping breakpoints keep firing their conditions and quietly burn
hit budget. `dbg_exit` terminates the whole session.

## Recommended default workflow

1. `dbg_status` — confirm a *suspended* live session exists (do not `dbg_start`
   if the maintainer already launched it).
2. `probe_add` / `trace_calls` / `watch_field` at the sites of interest, with a
   `condition` to suppress noise and a sane `max_hits`.
3. `run_until` with a generous timeout while the maintainer drives the in-app
   event.
4. `probe_drain` in a cursor loop until drained; reason over the records.
5. `probe_clear` when done.

Single-step (`dbg_step_*`) is the fallback for a one-off, low-frequency
inspection — not the workhorse.
