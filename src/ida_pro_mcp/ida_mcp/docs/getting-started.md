# Getting Started

This is the five-minute on-ramp for driving the IDA Pro MCP server in a fresh
session. It tells you, in order, how to confirm a database is loaded, take a
census, and drill into the code that matters - and which tool does each step.
Read `ida://docs/overview` for the capability model and
`ida://docs/tools-reference` for the full tool taxonomy and safety classes.

## 0. Confirm you are connected to the right database

**The single worst failure mode is analyzing the wrong (or empty) IDB and
fabricating output against it.** Before trusting anything:

```
server_health()     # is a database open and the server responsive?
server_warmup()     # warm caches; cheap to call, makes later calls snappy
```

Then read the metadata resource to see *which* binary is loaded - path,
architecture, image base, and file hashes (pin the SHA-256 in your notes so the
whole analysis is reproducible against one exact binary):

```
resources/read  ida://idb/metadata
```

If `server_health` reports no database, or the hash is not the binary you mean
to study, **STOP and report it.** Do not guess; do not "remember" addresses from
a previous session - rebasing or a different build invalidates every address.

## 1. Take a census before you drill

Get the lay of the land in one or two calls instead of wandering function by
function:

```
survey_binary()                  # segments, entry points, counts, notable imports/strings
list_funcs()                     # function inventory (page it on large binaries)
imports()                        # what the binary calls out to (recv/send, CreateFile, crypto APIs)
list_globals()                   # named data; often the dispatch tables and config blobs
```

`survey_binary` is the highest-signal single call - it folds the segment map,
entry points, and notable import/string evidence into one orientation. On a big
target, do not dump every string; use `ida://docs/performance-and-scale` for the
batched / cached approach.

## 2. Work outward from anchors, not from 0x401000

Do not read forward from the entry point. Start from **anchors** - strings,
imports, exports, named globals - and let cross-references pull you toward the
interesting code:

```
find("password")                 # locate a string / name / pattern
find_regex("connect|recv|WSA")   # regex over names/strings
xrefs_to(ea)                     # who reaches this address?
xref_query(...)                  # richer xref filtering (to/from, code/data)
```

Imports are the best anchors for subsystem hunting:

| Looking for     | Anchor imports to xref out from                          |
|-----------------|---------------------------------------------------------|
| Networking      | `recv` / `send` / `WSARecv` / `connect` / `select`      |
| Asset / file IO | `CreateFileA` / `ReadFile` / `fopen` / `mmap`           |
| Crypto          | `CryptAcquireContext`, constant tables, XOR/ROL loops   |
| Config / text   | `GetPrivateProfileString`, CP949 string literals        |

## 3. Read one function closely

Once an anchor points you at a function, read it:

```
disasm(ea, count)                # raw disassembly, ground truth for instruction shape
decompile(ea)                    # Hex-Rays pseudo-C (a hypothesis to confirm, not a fact)
callees(ea) / callgraph(ea)      # how it sits in its subsystem
basic_blocks(ea)                 # control-flow shape (the switch / the loop)
analyze_function(ea)             # folded summary: callers, callees, role hints
```

Treat decompiler output as a **hypothesis**, never a fact, until an xref, a
data-flow trace, or a live read backs it. See `ida://docs/re-methodology` for the
hypothesis -> static read -> dynamic confirm discipline.

## 4. Record what you learn back into the IDB

As facts firm up, annotate so the next pass is faster (these are WRITE-class
tools; see safety classes in `ida://docs/tools-reference`):

```
rename(ea, "recv_dispatch")      # kill sub_xxxx / loc_xxxx noise
set_comments(ea, "opcode switch")# neutral, human note at a site
declare_type("struct Pkt {...}") # commit a recovered layout
set_type(ea, "...")              # apply a prototype to a function
```

Prefer the batch variants (`append_comments`, `type_apply_batch`) for many edits
at once. Annotations are idempotent in spirit - re-applying the same name is a
no-op.

## 5. Confirm dynamically only when static runs out

Indirect calls, runtime-computed addresses, packed/encrypted regions, and "is
this *actually* the value at runtime" questions need the live debugger. Connect
on the debugger-extended endpoint:

```
http://127.0.0.1:13337/mcp?ext=dbg
```

This is a **superset** endpoint - it surfaces the `dbg_*` tools and the probe
toolkit *in addition* to all static tools. The base `/mcp` endpoint is
static-only; if the `dbg_*` tools are missing you are on the wrong endpoint.

```
dbg_add_bp(ea)                   # set a breakpoint
dbg_continue()                   # run to it
dbg_gpregs() / dbg_regs(...)     # read registers at the hit
dbg_read(addr, n)                # read memory (reads THROUGH PAGE_NOACCESS)
```

For observing a running target **without halting it**, use the non-stopping
probe layer instead (`probe_add`, `run_until`, `probe_drain`) - read
`ida://docs/probe-toolkit` and the `probe_workflow` prompt. Pilot a session the
maintainer already launched; **never call `dbg_start` yourself** in this project.

## Where to go next

| You want to...                          | Read                                   |
|-----------------------------------------|----------------------------------------|
| Map IDA concepts to MCP tools           | `ida://docs/ida-pro-essentials`        |
| The disciplined RE loop                 | `ida://docs/re-methodology`            |
| Copy-paste IDAPython recipes            | `ida://docs/idapython-cookbook`        |
| Recover an opcode / packet protocol     | `ida://docs/opcode-and-packet-re`      |
| Recover a C++ struct / vtable           | `ida://docs/struct-and-vtable-recovery`|
| Find the cipher                         | `ida://docs/crypto-hunting`            |
| Drive the live debugger / trace         | `ida://docs/debugging-and-tracing`     |
| Go fast on a huge binary                | `ida://docs/performance-and-scale`     |
| Dense tips & traps                      | `ida://docs/pro-tips-and-pitfalls`     |
