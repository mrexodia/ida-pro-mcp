# Autopilot Playbook: Worked End-to-End Examples

This is the hands-on companion to `probe-toolkit.md` and `debugging-and-tracing.md`.
It walks two complete instrument -> run -> drain -> reason loops with the **exact
tool calls and their returned shapes**, so you can copy the pattern for any new
target. Both examples assume a live debugger session the maintainer already
F9-launched in IDA, reachable over `?ext=dbg`. None of these tools call
`dbg_start` — if there is no live session every `@safety("EXECUTE")` probe tool
returns `{"error": "No live debugger session..."}`.

## The five-beat loop

Every autopilot investigation is the same five beats. Memorize them:

1. **Instrument** — install non-stopping probes with `probe_add` / `watch_field` /
   `trace_calls` / `probe_net`. Each is a breakpoint that captures a tiny spec and
   *always returns `False`*, so the target never halts.
2. **Run** — `run_until(timeout_ms, target_ea=, probe_id=)` resumes the process and
   lets the probes fire. (Or sequence several resume/observe beats in one call with
   `autopilot_run`.)
3. **Drain** — `probe_drain(since_cursor=, filter=, limit=)` pulls captured records,
   oldest first, non-destructively. Feed the returned `cursor` back next time.
4. **Summarize** — `trace_summary(group_by=, filter=)` collapses 10^5 hits into a
   per-group rollup so you reason over the call tree, not a byte firehose.
   `diff_buffers(a_hex, b_hex)` byte-diffs a pre/post pair.
5. **Reason** — this is *your* step, not a tool. Read the drained/summarized
   records, form the next hypothesis, then either tighten a probe (`probe_arm`,
   a `condition=` predicate) or move to the next site. There is **no `reason`
   tool**; "reason" is the analyst beat that turns captured data into a finding.

Cheap throughput rule: **drain rarely, summarize first.** A hot function can emit
tens of thousands of records per run. Call `trace_summary` to see the shape, then
`probe_drain` only the few records you actually need (use a `filter=`).

---

## Example A — Capture an inbound packet at `recv`/decrypt

Goal: prove where decrypted packet bytes first appear, capture one packet's
opcode + payload, and confirm the decrypt boundary by diffing the buffer
before vs. after the transform. Addresses below are placeholders — substitute the
ones you recovered statically (e.g. via `opcode-and-packet-re.md`). Say you found:

- the recv wrapper at `0x004510A0` (signature `int recv_wrapper(sock, char *buf, int len)`),
- the in-place decrypt at `0x00452300` (`void decrypt(char *buf, int len)`),
- the decrypt **return site** (instruction after the `call decrypt`) at `0x00451130`.

### A1. Instrument the recv + decrypt path

`probe_net` is the convenience wrapper for exactly this shape. It captures the
buffer pointer, the length, and a 256-byte slice off `buf_arg` at each site:

```
probe_net(
    recv_ea="0x004510A0",
    decrypt_ea="0x00452300",
    buf_arg="arg1",        # char *buf is the 2nd stack arg (arg0=sock, arg1=buf)
    len_arg="arg2",
    pre_post=True,
)
```

Returns one `ProbeRef` per site under `installed`:

```json
{
  "installed": [
    {"probe_id": "net_recv_4510a0_1a2b3c4d5e", "ea": "0x4510a0",
     "kind": "net_recv", "capture": ["arg1", "arg2", "mem(arg1,256)"],
     "max_hits": 4096, "armed": true, "installed": true, "reused": false},
    {"probe_id": "net_decrypt_pre_452300_f00dca7e91", "ea": "0x452300",
     "kind": "net_decrypt_pre",
     "capture": ["arg1", "arg2", "mem(arg1,256)",
                 "pre/post: place probe_add at decrypt return site capturing mem(arg1,256)"]}
  ]
}
```

`probe_net` deliberately does **not** auto-install the post-transform probe (that
would have to read the buffer at the *return* site, which it can't know). Place it
yourself at the decrypt return site so you capture the *same* buffer after decrypt
ran. The decrypt is in-place, so its `buf` lives in `ecx`/the stashed arg — easiest
is to probe the return site and read the buffer pointer the caller still holds. If
the caller keeps `buf` in a register across the call (inspect statically), capture
that; otherwise re-probe `decrypt_ea` itself for the *pre* image and the return
site for the *post* image off the same pointer value you saw at entry:

```
probe_add(
    ea="0x00451130",            # the call's return site
    capture=["mem(0x004A9F40,256)"],   # buf is a known global here; else use the reg holding it
    max_hits=64,
)
```

Returns:

```json
{"probe_id": "probe_451130_77c1aa20b3", "ea": "0x451130", "kind": "probe",
 "capture": ["mem(0x4a9f40,256)"], "max_hits": 64, "armed": true,
 "installed": true, "reused": false}
```

Confirm what's armed before you run:

```
probe_list()
-> {"probes": [
     {"probe_id": "net_recv_4510a0_...", "ea": "0x4510a0", "kind": "net_recv",
      "hits": 0, "max_hits": 4096, "armed": true},
     {"probe_id": "net_decrypt_pre_452300_...", "hits": 0, "armed": true},
     {"probe_id": "probe_451130_...", "hits": 0, "armed": true}
   ]}
```

### A2. Run until a packet arrives

Resume and wait for the recv probe to fire. Pass its `probe_id` so the records it
captured during the run come back inline in `buffer`:

```
run_until(timeout_ms=15000, probe_id="net_recv_4510a0_1a2b3c4d5e")
```

In the live game, send/trigger the action that produces the packet. On a hit:

```json
{
  "status": "hit",
  "stopped_ea": null,
  "elapsed_ms": 2310.4,
  "hit_probe": "net_recv_4510a0_1a2b3c4d5e",
  "buffer": [
    {"_seq": 41, "probe_id": "net_recv_4510a0_1a2b3c4d5e", "kind": "net_recv",
     "ea": "0x4510a0", "hit": 1, "tid": 4120,
     "captured": {
       "arg1": "0x4a9f40",
       "arg2": "0x2c",
       "mem(arg1,256)": {"addr": "0x4a9f40",
         "hex": "9f31aa07c4...<encrypted 44 bytes>..."}}}
  ]
}
```

Note `status` is `"hit"` (not `"timeout"`) *because* the probe recorded during the
run — `run_until` upgrades the status whenever the named probe produced records.
`arg2` = `0x2c` = 44 bytes — that is the packet length. The `hex` here is still
**encrypted** (this is the recv site, before decrypt).

### A3. Drain the pre/post pair

Pull the decrypt-pre and return-site records. Filter by probe so you only get the
two you care about, and remember the cursor:

```
probe_drain(since_cursor=0, filter={"kind": "net_decrypt_pre"}, limit=16)
```

```json
{"records": [
   {"_seq": 42, "probe_id": "net_decrypt_pre_452300_...", "kind": "net_decrypt_pre",
    "captured": {"arg1": "0x4a9f40", "arg2": "0x2c",
      "mem(arg1,256)": {"addr": "0x4a9f40", "hex": "9f31aa07c4...(encrypted)"}}}
 ],
 "cursor": 43, "dropped": 0}
```

```
probe_drain(since_cursor=0, filter={"probe_id": "probe_451130_77c1aa20b3"}, limit=16)
```

```json
{"records": [
   {"_seq": 43, "probe_id": "probe_451130_77c1aa20b3", "kind": "probe",
    "captured": {"mem(0x4a9f40,256)":
      {"addr": "0x4a9f40", "hex": "0300...(plaintext)...opcode+payload"}}}
 ],
 "cursor": 44, "dropped": 0}
```

### A4. Diff to confirm the decrypt boundary

Feed the two `hex` strings to `diff_buffers`. If decrypt is a real transform every
byte (or most) changes; if it's a no-op, `equal: true` tells you you mis-located
the boundary:

```
diff_buffers(
    a_hex="9f31aa07c4...(pre, encrypted)",
    b_hex="0300...(post, plaintext)",
)
```

```json
{"len_a": 44, "len_b": 44, "first_diff": 0,
 "changed_offsets": [0,1,2,3,4,5,6,7,...,43], "equal": false}
```

`first_diff: 0` and a fully-changed buffer confirm the transform spans the whole
packet — `0x00452300` **is** the decrypt boundary. Now the plaintext `hex` is what
you reverse: the leading bytes are the opcode (`0x0003`), the rest the body —
hand that to the field-layout work in `opcode-and-packet-re.md`.

### A5. Reason, then iterate

You now have a clean-room fact: *opcode 0x0003 arrives as a 44-byte packet,
decrypted in place at the function whose first plaintext appears at the call's
return site.* If you want **every** opcode, don't stream — re-run with a higher
`max_hits` and a wider trigger, then summarize by where the buffer came from:

```
trace_summary(group_by="probe_id", filter={"kind": "net_decrypt_pre"})
```

```json
{"group_by": "probe_id", "total_records": 1873, "distinct_groups": 1,
 "groups": [{"key": "net_decrypt_pre_452300_...", "count": 1873,
             "distinct_callers": 2, "callers": ["0x451100", "0x451130"]}]}
```

Two distinct callers = the decrypt is reached from two sites — worth a look. Tear
down when done:

```
probe_clear()        # removes ALL probes + their breakpoints
```

---

## Example B — Catch the write that changes a struct field

Goal: find *who* writes a particular object field and *what* value it lands, using
a non-stopping hardware data watchpoint. Say the player HP lives at `this+0x40` and
at the moment you start the `this` pointer is `0x0A33B0C0`, so the field address is
`0x0A33B100`. (If you only have `this` in a register, snapshot it first with a
quick `read_struct_live` or `dbg_regs`.)

### B1. Watch the field

`watch_field` installs a HW data breakpoint (`BPT_WRITE`) whose Python condition
reads the field, compares to the last value, and **records only on change** —
emitting `{field, old, new, writer_pc, caller, tid}` — then returns `False`:

```
watch_field(
    ea="0x0A33B0C0",    # base = this
    offset=0x40,        # field offset -> watches 0x0A33B100
    size=4,             # HP is a 4-byte int; size must be 1/2/4 (8 on 64-bit)
    mode="write",
    max_hits=256,
)
```

```json
{"probe_id": "watch_a33b100_0c1d2e3f40", "ea": "0xa33b100", "kind": "watch",
 "capture": ["size4", "write"], "max_hits": 256, "armed": true,
 "installed": true, "reused": false}
```

> HW-slot limit: there are only **4** CPU debug registers. `size` must be 1/2/4
> (8 on 64-bit) and naturally aligned. Oversized/unaligned/excess watches fail or
> never fire — split a wide field into aligned sub-watches. If `installed` came back
> `false` with an error, you're out of slots: `probe_clear` an old watch first.

You can scope it with a `predicate` (a Python expr with `old`/`new`/`c` bound) so
it only records, say, *damage* (HP dropping), not heals:

```
watch_field(ea="0x0A33B0C0", offset=0x40, size=4, mode="write",
            predicate="int(new,16) < int(old,16)", max_hits=64)
```

### B2. Run free while you trigger the change

```
run_until(timeout_ms=20000, probe_id="watch_a33b100_0c1d2e3f40")
```

In game, take damage. On the first write:

```json
{"status": "hit", "elapsed_ms": 5102.7,
 "hit_probe": "watch_a33b100_0c1d2e3f40",
 "buffer": [
   {"_seq": 88, "probe_id": "watch_a33b100_...", "kind": "watch", "hit": 1,
    "tid": 4120,
    "captured": {"field": "0xa33b100", "old": "000003e8", "new": "0000037f",
                 "writer_pc": "0x0046ab12", "caller": "0x0046a9c0"}}]}
```

Read it: HP went `0x3e8` (1000) -> `0x37f` (895), a 105 hit. The **instruction**
that wrote it is `writer_pc = 0x0046ab12`; the function that *called* the writer is
`caller = 0x0046a9c0`. Those two addresses are your next static-analysis targets —
the damage-application routine.

### B3. Drain the full change history

Trigger a few more hits, then drain everything this watch saw:

```
probe_drain(since_cursor=0, filter={"probe_id": "watch_a33b100_0c1d2e3f40"}, limit=128)
```

```json
{"records": [
   {"_seq": 88, "captured": {"old": "000003e8", "new": "0000037f",
       "writer_pc": "0x0046ab12", "caller": "0x0046a9c0"}},
   {"_seq": 91, "captured": {"old": "0000037f", "new": "00000300",
       "writer_pc": "0x0046ab12", "caller": "0x0046a9c0"}},
   {"_seq": 95, "captured": {"old": "00000300", "new": "00000258",
       "writer_pc": "0x00470d44", "caller": "0x00470c10"}}
 ], "cursor": 96, "dropped": 0}
```

### B4. Summarize the writers

Which code paths touch this field, and how often? Group by `pc` (the writer
instruction):

```
trace_summary(group_by="pc", filter={"probe_id": "watch_a33b100_0c1d2e3f40"})
```

```json
{"group_by": "pc", "total_records": 3, "distinct_groups": 2,
 "groups": [
   {"key": "0x46ab12", "count": 2, "distinct_callers": 1, "callers": ["0x46a9c0"]},
   {"key": "0x470d44", "count": 1, "distinct_callers": 1, "callers": ["0x470c10"]}
 ]}
```

Two distinct writers: `0x46ab12` (the common combat-damage path, 2 hits) and
`0x470d44` (a second path — maybe a DoT/poison tick). Group by `caller` instead to
see it from the call-tree edge.

### B5. Confirm the field's container live

Now that you know the field, overlay the whole struct from live memory to read
its neighbors — handy to confirm you have the right object and the right offset:

```
read_struct_live(ea="0x0A33B0C0", type_name="player_t")
```

```json
{"fields": {
   "id":  {"offset": "0x0", "value": "0x1f4", "size": 4},
   "hp":  {"offset": "0x40", "value": "0x258", "size": 4},
   "max_hp": {"offset": "0x44", "value": "0x3e8", "size": 4}},
 "raw_hex": "f401...", "_meta": {"ea": "0xa33b0c0", "type": "player_t", "size": 256, "dirty": true}}
```

`ea` also accepts a pointer chain — if the player object hangs off a global at
`g_world+0x10` you can write `read_struct_live("[[g_world+0x10]+0x0]", "player_t")`
and it dereferences live.

### B6. Reason

Clean-room fact: *the player HP field at object+0x40 is written by two routines;
the primary combat-damage path's writer instruction and its caller are known.*
That is the seam to document and re-implement. Disable the watch while you read the
two routines statically (keep its records), then re-arm later:

```
probe_arm(probe_id="watch_a33b100_0c1d2e3f40", armed=false)
# ...static work...
probe_arm(probe_id="watch_a33b100_0c1d2e3f40", armed=true)
```

---

## Sequencing many beats in one call: `autopilot_run`

When the loop is mechanical — *resume, drain, resume, drain* — hand the whole
sequence to `autopilot_run` instead of issuing each call yourself. It executes
**only** a whitelist of safe primitives (`continue`, `run_until`, `read_regs`,
`read_memory`, `probe_drain`) and **rejects at plan time** anything that injects
code or mutates the image (`appcall`, `patch`, `probe_add`, `watch_field`,
`trace_calls`, `snapshot_restore`, `dbg_start`, `dbg_write`, `set_reg`). Install
your probes first with the normal tools, *then* let autopilot drive the run/drain:

```
autopilot_run(steps=[
    {"action": "run_until", "timeout_ms": 15000,
     "probe_id": "net_recv_4510a0_1a2b3c4d5e"},
    {"action": "probe_drain", "filter": {"kind": "net_decrypt_pre"}, "limit": 32},
    {"action": "run_until", "timeout_ms": 15000,
     "probe_id": "net_recv_4510a0_1a2b3c4d5e"},
    {"action": "probe_drain", "filter": {"kind": "net_decrypt_pre"}, "limit": 32}
], step_budget=16)
```

Returns a transcript plus *why* it stopped:

```json
{"steps_run": 4, "stopped_reason": "completed",
 "transcript": [
   {"action": "run_until", "status": "suspended", "stopped_ea": "0x451130",
    "elapsed_ms": 1820.0, "hits": 1, "hit_probe": "net_recv_4510a0_..."},
   {"action": "probe_drain", "count": 1, "records": [ ... ]},
   {"action": "run_until", "status": "suspended", "hits": 1, "...": "..."},
   {"action": "probe_drain", "count": 1, "records": [ ... ]}
 ]}
```

`stopped_reason` is the load-bearing field. Watch for:

- `completed` — ran every step.
- `budget_reached` — hit `step_budget`; raise it or split the run.
- `process_exited` — the target died mid-run; nothing more to drain.
- `unexpected_timeout` — a `run_until` step timed out without suspending (the event
  never happened — re-check your trigger or widen `timeout_ms`).
- `not_suspended` — the process wasn't suspended at a step boundary.
- `invalid_plan` — a forbidden/malformed step; the `error` field names it.
- `primitive_error` / `bad_target` — a `read_memory`/`run_until` arg was bad.

**The interrupt:** `autopilot_run` has no kill switch of its own. To break a loop
that's waiting in `run_until`, call `probe_clear()` (from another beat) to remove
the probe it's waiting on — the next `run_until` then times out and the loop ends.

---

## Pitfalls and pro-tips (read before your first run)

- **Drain is non-destructive and cursor-based.** Records stay in the ring; the
  `cursor` you get back is the next `_seq` to ask for. Pass it as the next
  `since_cursor` to page forward, or re-pass `0` to re-read from the top.
- **`status: "hit"` vs `"suspended"`/`"timeout"`.** `run_until` reports `"hit"`
  whenever the named `probe_id` produced records during the run — even if the
  process is now suspended for another reason. No `probe_id` -> you get the raw
  `_continue_and_wait` status. Always pass the `probe_id` you care about.
- **`condition=` on `probe_add` is a predicate, not an IDA bpt condition.** It's a
  Python expr over the captured dict bound as `c` (e.g. `condition="int(c['arg2'],16) > 64"`),
  evaluated in a sandbox; an error/non-bool **does not suppress** the record (it
  records anyway), so a typo silently fails open.
- **`watch_field` records on *change*, period.** It seeds the last value at install
  time, so the *first* write that differs from the seed is the first record. Reads
  never record unless `mode="rdwr"` and the value changed.
- **`mem(expr, n)` caps at 4096 bytes** and `expr` is additive only — regs, `argN`,
  `caller`, `ret`, and hex literals joined by `+` (e.g. `mem(arg1+0x10, 64)`). For
  pointer *chains* (`[[base+0x10]+0x8]`) use `read_struct_live`, not a capture token.
- **`argN` is the stack slot at callee entry** ( `[esp + ptr*(N+1)]` ), uniform for
  cdecl/stdcall/thiscall. For a thiscall `this`, capture `ecx` explicitly —
  `trace_calls(conv="thiscall")` does this for you.
- **Drowning in records?** Don't `probe_drain` a hot probe blind — `trace_summary`
  first to see counts/callers, then drain with a tight `filter`. `dropped` in the
  drain/summary result is your overflow signal (the ring is circular by default).
- **`appcall` is never an autopilot step.** It executes target code; run it once,
  by hand, `confirm=False` first (dry-run resolves the prototype), and only
  `confirm=True` on a *suspended* process. See `appcall-guide.md`.
- **Persisting a run:** set `IDA_MCP_PROBE_DIR` to a stable path before the session
  to collect the JSONL probe ring across runs (default is `<tempdir>/ida_mcp_probes`).
- **Tear down between investigations.** `probe_clear()` removes every probe and its
  breakpoint; leftover armed watches eat your 4 HW slots and leftover code probes
  add condition-eval overhead on hot functions.
