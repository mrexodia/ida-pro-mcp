# A Disciplined RE Methodology

Reverse engineering through this server is most effective when it follows a tight
loop: **form a hypothesis, confirm it with a cheap static read, then prove it
dynamically only when static evidence runs out.** This doc lays out that loop,
the order to attack an unknown binary in, how to take clean-room-safe notes, and
exactly which server tools serve each step. Read `ida://docs/overview` and
`ida://docs/tools-reference` first for the tool taxonomy and safety classes.

## The core loop: hypothesis -> static read -> dynamic confirm

Every fact you commit to should pass through three states:

1. **Hypothesis.** A specific, falsifiable claim — "function X decrypts the recv
   buffer in place", "opcode 0x12 dispatches to handler at A", "field +0x1C is a
   u32 entity id". A hypothesis names *what* you expect *where* and *how you will
   check it*.
2. **Static read.** The cheapest confirmation: disassembly, decompilation,
   xrefs, data-flow. Static analysis is free, repeatable, and non-perturbing —
   it never changes the target. **Do this first, always.** Most hypotheses are
   confirmed or killed here.
3. **Dynamic confirm.** When static analysis is ambiguous (indirect calls,
   runtime-computed addresses, encrypted/packed regions, "is this *actually* the
   value at runtime"), drop to the debugger to observe ground truth. Dynamic
   evidence is authoritative but expensive: it requires a live session, it
   perturbs timing, and it only proves the *one* path you exercised.

The discipline is to **never skip step 2 to jump to step 3**, and **never
promote a step-1 hypothesis to a fact without reaching step 2 or 3.** A
plausible decompile is a hypothesis, not a fact, until an xref or a live read
backs it.

### Why static-first

- It is non-destructive and infinitely repeatable; you can fan out hundreds of
  reads in parallel without consequence.
- It covers *all* paths at once, where the debugger only sees the path you ran.
- It is the only mode available when no live session exists.

Reach for the debugger when, and only when, static analysis genuinely cannot
decide the question (see "When to use the debugger vs static" below).

## Working outward from anchors

Do not start by reading function `0x00401000` and walking forward. Start from
**anchors** — observable, named, high-signal features of the binary — and let
xrefs pull you toward the code that matters.

### 1. Census first

Get the lay of the land before drilling. `survey_binary` gives a one-call
orientation (segments, entry points, counts, notable imports/strings).
`server_health` / `server_warmup` confirm a database is actually loaded and
responsive — **always confirm which IDB is open before trusting any output;**
fabricating analysis against the wrong or empty database is the classic failure.

```
survey_binary()                  # high-level census
list_funcs(...)                  # function inventory
imports() / imports_query(...)   # what the binary calls out to
list_globals(...)                # named data
```

### 2. Strings -> code

Strings are the single richest anchor in most binaries. A format string, an
error message, a registry key, a file extension, a protocol literal — each is a
labelled doorway into the subsystem that uses it. The workflow:

```
find_regex("recv|decrypt|opcode|\\.pak|session")   # locate the literal
xrefs_to(<string_ea>)                               # who references it
```

Then decompile the referencing function. A function that prints
`"unknown opcode %d"` is sitting next to your dispatch logic; a function near
`"failed to decrypt"` is on the crypto path. `find` / `find_bytes` /
`find_regex` locate text and byte patterns; `get_string` reads a literal at a
known address.

### 3. Imports -> capability map

Imports tell you *what the binary can do* and *where it does it*. `recv` /
`WSARecv` / `connect` mark the network seam; `CreateFileA` / `ReadFile` /
`memcpy` near a magic constant mark asset I/O; `CryptAcquireContext` or a
conspicuous absence of crypto imports (hand-rolled cipher) marks the crypto
path. Use `imports_query` to filter, then `xrefs_to` each interesting import to
find its call sites — those call sites are your real entry points.

### 4. Dispatch tables -> handler maps

Command/opcode handling almost always funnels through a **switch / jump table**
or an array of function pointers. Find the network read loop (via the `recv`
xref from step 3), decompile it, and look for the indexed dispatch. A jump table
gives you the entire opcode space in one structure: each case resolves to a
handler function, yielding an `opcode -> handler` map that seeds the whole
protocol. Use `disasm` on the dispatch site, `xref_query` to resolve the table,
and `decompile` on each handler.

This outward order — **census -> strings -> imports -> dispatch -> handlers ->
structs** — consistently reaches the load-bearing code far faster than a linear
read, because every step is pulled by an xref from a thing you already
understand.

## The static-read toolset, by question

| Question | Tool(s) |
|---|---|
| What does this function do? | `decompile`, `disasm`, `func_profile` |
| Who calls / references this? | `xrefs_to`, `xref_query` |
| What does this function call? | `callees`, `callgraph` |
| How does this function sit in its subsystem? | `callgraph` (bounded), `analyze_batch` |
| Where does this value come from / go to? | `trace_data_flow` |
| What is the shape of this object? | `read_struct`, `search_structs`, `infer_types` |
| Profile a whole candidate subsystem at once | `analyze_batch`, `func_query`, `insn_query`, `entity_query` |

Pro-tips:

- **`trace_data_flow` is your scalpel for fields and buffers.** Trace *backward*
  from a length check to find what computes the length; trace *forward* from a
  `recv` buffer to find where it is decrypted and parsed. This is how you turn
  "there's a buffer here" into "byte +0 is opcode, +1..2 is length".
- **`callgraph` bounded around a target** answers "what is this function's
  neighbourhood" without dumping the entire program graph.
- **`analyze_batch` / `func_query`** let you profile many related functions in
  one call to triage which few deserve a close `decompile` — far cheaper than
  decompiling everything.
- A clean `decompile` is a **hypothesis generator**, not proof. Hex-Rays infers
  types and can be wrong about signedness, struct boundaries, and tail calls.
  Cross-check anything load-bearing with `disasm` and `trace_data_flow`.

## When to use the debugger vs static

Stay static unless one of these is true; then go dynamic for *exactly* that
question and return to static:

**Use the debugger when:**

- The control flow is **indirect** — a `call [eax+0x10]` (vtable / callback)
  whose target you cannot resolve statically. Break at the call and read the
  resolved target from registers.
- The data is **runtime-derived** — keys, session tokens, decrypted payloads,
  heap-allocated structs at addresses unknown until execution. Static analysis
  shows the *shape*; only a live read shows the *value*.
- The region is **packed / encrypted / self-modifying** on disk — the bytes you
  need don't exist until the process unpacks them in memory.
- You need to **confirm a boundary** — "is the buffer plaintext before this call
  and ciphertext after?" Read memory pre- and post-call.
- A static hypothesis is **plausible but unfalsifiable statically** and the cost
  of being wrong is high (e.g., a cipher you're about to reimplement).

**Stay static when:**

- The answer is visible in the disassembly/decompile (most of the time).
- You want *all* paths, not one (the debugger only proves the path you ran).
- No live session exists, or perturbing the target is risky.

### Dynamic confirmation, the safe way

This server's debugger tools live behind `?ext=dbg`
(`http://127.0.0.1:13337/mcp?ext=dbg`). **Never call `dbg_start` as part of
analysis** — attach to a session the human already launched. Set a breakpoint at
the hypothesized site, continue until a real event drives it, then read ground
truth:

```
dbg_add_bp(<handler_ea>)         # arm the hypothesized site
dbg_continue()                   # run until a real packet/event hits it
dbg_gpregs()                     # read resolved args / pointers
dbg_read(<ptr>, <n>)             # read the live buffer (reads through PAGE_NOACCESS)
dbg_stacktrace()                 # confirm the caller chain
```

`dbg_run_to(<ea>)` runs to a one-shot address. To watch values flow **without
ever halting the target**, prefer the non-stopping probe toolkit
(`?ext=dbg`): `probe_add` / `watch_field` / `run_until` / `probe_drain`,
and live overlays like `read_struct_live`. See `ida://docs/probe-toolkit` for
the instrument -> run -> drain loop. Probes are ideal for confirming a struct
layout or a cipher boundary on real traffic while the process keeps running.

After dynamic confirmation, **fold the proven fact back into your static notes**
and continue static. The debugger answered one question; it is not the place to
live.

## Clean-room note-taking

The legal and engineering value of an RE session is the **neutral notes** it
produces — not the decompiler output, which is tainted. Keep a firewall between
what you read and what you write down:

- **Record facts, not transcriptions.** Write "the recv handler reads a 2-byte
  little-endian length at offset +2, then copies `length` bytes into a fixed
  buffer" — *not* a paste of the Hex-Rays pseudo-C. Describe behaviour, layout,
  constants, and offsets in your own words and in plain tables/math.
- **Strip every decompiler artifact.** No `sub_xxxx`, `loc_xxxx`, `_DWORD`,
  `__thiscall`, `*(_DWORD *)(a1 + 4)`, or mangled names in any note you intend
  to keep. Those are the things the firewall exists to keep out.
- **Pin provenance.** Every note should be traceable to the database it came
  from: record the IDB identity / hash (from `survey_binary` / metadata) so a
  later reader knows which build a fact describes. When a fact and the binary
  disagree later, the binary wins and the note is corrected.
- **Separate hypothesis from proof.** Tag each fact with its confidence and how
  it was confirmed (static-only, debugger-confirmed, capture-confirmed). A
  field you *think* is an entity id reads differently from one you *watched* be
  an entity id at runtime.
- **One direction of trust.** Notes are derived from the binary; code is derived
  from notes. Code is never its own source of truth — if code and a note
  disagree, re-verify against the binary, don't "fix" the note to match the
  code.

A good note is **dense, neutral, and falsifiable**: offsets in a table,
constants in hex, behaviour in prose, each line you could hand to someone who
has never seen the binary and they could reimplement from it without ever
touching a decompiler.

## A worked sequence (protocol example)

1. **Census** — `survey_binary`, confirm the right IDB is loaded.
2. **Anchor** — `find_regex("opcode|unknown packet")`, `imports_query("recv")`.
3. **Reach the seam** — `xrefs_to(recv)` -> `decompile` the read loop.
4. **Map dispatch** — `disasm` the switch, `xref_query` the jump table -> the
   `opcode -> handler` set.
5. **Read handlers** — `analyze_batch` to triage, `decompile` the interesting
   few, `trace_data_flow` from the buffer to recover each field's offset/size.
6. **Confirm the cipher boundary** — if the buffer is encrypted, `?ext=dbg`:
   `dbg_add_bp` at decrypt entry, `dbg_continue`, `dbg_read` the buffer before
   and after to prove plaintext-out.
7. **Write neutral notes** — opcode table, per-packet field tables, cipher
   described in words/math, each tagged with confidence and IDB hash.

That sequence — anchored, static-first, dynamically confirmed only where
necessary, and journaled in clean-room-neutral prose — is the whole method.
