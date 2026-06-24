# Probe / Watch / Autopilot Toolkit

The probe toolkit (`api_probes`, gated behind `?ext=dbg` — the same view as the
debugger tools) lets you observe a **running** target without ever halting it and
**without calling `dbg_start`**. It requires a live debugger session the
maintainer already launched (F9) in IDA.

## The non-stopping probe

A probe is a breakpoint carrying a Python condition that, on each hit:

1. evaluates a small **capture spec**,
2. records the event into the probe ring buffer,
3. decrements a hit budget and self-disarms at the budget,
4. **always returns `False`** so the debuggee never actually stops.

This means you can instrument many sites in a live process and watch values flow
through them while the process keeps running.

### Capture tokens

A capture spec is a list of tokens:

- `eax`, `ecx`, `esp`, `rdi`, ... — a register value
- `argN` — the Nth stack argument at callee entry (cdecl/thiscall layout)
- `ret` — the return-value register (eax / rax)
- `caller` — the return address read from `[esp]` at function entry
- `mem(<expr>, <n>)` — `n` bytes of memory at `<expr>`, where `<expr>` may
  reference regs / `argN` / `caller` / hex literals, e.g. `mem(arg1, 256)`

## The instrument -> run -> drain loop

1. **Instrument.** Install probes at the addresses of interest:
    - `probe_add(ea, capture, condition=None, max_hits=...)` — a generic site.
    - `trace_calls(ea, conv, argc, capture_ret)` — entry-side call tracing.
    - `watch_field(ea | base_ptr, size, mode)` — a hardware data watchpoint that
      records ONLY on value change (4 debug-register slots; size 1/2/4, 8 on
      64-bit; naturally aligned).
    - `probe_net(recv_ea, decrypt_ea, send_ea, buf_arg, len_arg)` — convenience
      buffer probes for a network recv/decrypt/send path (addresses are
      caller-supplied, never hardcoded).
2. **Run.** Resume the target and let probes fire:
    - `run_until(timeout_ms, target_ea=None, probe_id=None)` — resume until a
      probe hits, an address is reached, or the timeout elapses. When `probe_id`
      is given, records captured during the run are returned in `buffer`.
3. **Drain.** Pull captured records (non-destructive, oldest first):
    - `probe_drain(since_cursor, filter, limit)` — returns `{records, cursor,
     dropped}`; pass the returned `cursor` back as `since_cursor` next time.
    - `probe_list()` — list installed probes and their hit counts.
    - `probe_clear(probe_id=None)` — remove one probe or all of them.

## IDA_MCP_PROBE_DIR

Probe events are persisted as JSONL. The directory is controlled by the
`IDA_MCP_PROBE_DIR` environment variable; when unset it defaults to
`<tempdir>/ida_mcp_probes`. Set it to a stable path to collect a probe run
across sessions.

## Live-memory helpers (under `?ext=dbg`)

- `read_struct_live(ea, type_name)` — read `sizeof(type)` bytes from live memory
  and overlay an IDB type into a named-field dict. `ea` may be a pointer-chain
  expression like `[[base+0x10]+0x8]`, dereferenced live.
- `appcall(ea, prototype, args, confirm)` — marshal (and, with `confirm=True` on
  a suspended process, CALL) a function in the debuggee. Executes target code;
  use only as a deliberate, single, human-confirmed action — never in a loop.
- `appcall_inspect(ea, prototype)` — resolve a prototype's arg/return types
  without calling anything.
- `snapshot_save` / `snapshot_restore` — best-effort register + bounded
  memory-range capture and restore (NOT a full process snapshot).

## Safety

All state-mutating / resuming probe tools are `@safety("EXECUTE")` or
`@safety("DESTRUCTIVE")`; read-only listing/draining is `@safety("READ")`. None
of them ever start a debugger — they hard-require an existing live session and
fail with an explanatory error otherwise.
