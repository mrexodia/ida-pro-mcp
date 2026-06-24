# RE + IDA + MCP Glossary

A concise, scannable glossary of the terms that show up across these docs, IDA
Pro, reverse engineering, and this MCP server. Definitions are operational — each
entry says what the thing *is* and, where it matters, which real server tool or
resource touches it (`disasm`, `decompile`, `xrefs_to`, `dbg_read`, `read_struct`,
`make_signature`, …). Skim for the term, then jump to the deep-dive doc named in
**See**.

---

## Addresses & layout

- **ea (effective address)** — a single linear address in the binary's address
  space; the universal handle in IDA/IDAPython. Most tools take an `ea` (hex
  string like `"0x401000"` or int). The runtime equivalent is the **VA**.
- **BADADDR** — IDA's "no such address" sentinel: **all-ones**
  (`0xFFFFFFFF` on 32-bit, `0xFFFFFFFFFFFFFFFF` on 64-bit), *not* `0`. Always
  test `ea == BADADDR`; never `if ea:` (a valid EA can be small/zero-ish).
- **RVA (relative virtual address)** — an offset from the module's image base.
  `static EA = preferred image base + RVA`. Captures and `dbg_*` reads may use a
  rebased base; translate, don't paste a static EA into `dbg_read`.
- **VA (virtual address)** — the runtime address of a byte once the module is
  mapped. Equals the static EA only when the module loads at its preferred base
  (ASLR/rebasing breaks that assumption).
- **image base** — the address the loader maps the module's first byte to. Read
  it from `ida://idb/metadata` before trusting any absolute address.
- **segment** — a named region of the address space (`.text`, `.data`, `.rdata`,
  `.idata`, …). `get_segm_name` returns empty/None just past a segment end — that
  reads as "no data" when it really means "wrong address."
- **range `[start, end)`** — IDA address ranges are half-open: `end` is
  **exclusive**. A function's last byte is `end_ea - 1`. Classic off-by-one site.

## Code structure

- **basic block** — a maximal straight-line run of instructions with one entry
  and one exit (ends at a branch/call/return or a branch target). The node unit
  of a control-flow graph (CFG); IDA's flowchart / `ida_gufunc` is built from
  these. Tracepoints and coverage reason in basic-block terms.
- **CFG (control-flow graph)** — basic blocks as nodes, branches as edges; what
  the graph view and a function's flowchart render.
- **callgraph** — functions as nodes, calls as edges. The `callgraph` /
  `callees` / `callers` family answers "how this function sits in its subsystem."
- **xref (cross-reference)** — a recorded link between two locations: a **code
  xref** (call/jump) or a **data xref** (read/write of a global/string/constant).
  `xrefs_to(ea)` = "who reaches this"; `xrefs_from` = "what this reaches";
  `xref_query` finds every site touching a constant; `xrefs_to_field` finds every
  access to one struct member. **No xrefs ≠ unused** — vtable/jump-table targets
  reached via computed pointers show zero xrefs.
- **prologue / epilogue** — the function's setup (`push ebp; mov ebp, esp; sub
  esp, N`) and teardown (`leave; ret`). Used by signature/FLIRT heuristics to
  find function starts.
- **switch / jump table** — a dispatch implemented as an indirect `jmp` through a
  table of handler addresses. Often **not** auto-recovered — a lone indirect jump
  is the usual cause of "missing" opcode handlers; hunt the table manually.
  See **opcode-and-packet-re**.

## Decompilation & disassembly

- **disassembly (`disasm`)** — the instruction-level listing; the **source of
  truth** for what executes.
- **pseudocode / Hex-Rays (`decompile`)** — C-like reconstruction. A convenience
  *interpretation*: it can mis-type, miss tail calls, and invent locals. Fix the
  prototype, then re-decompile. **Never paste raw pseudo-C across the clean-room
  firewall** — describe it in neutral prose.
- **autoname** — IDA's placeholder names: `sub_401000` (function), `loc_…`
  (label), `dword_…`/`off_…` (data), `nullsub_…`. Noise to be replaced with
  meaningful names via `rename` — but only glossary-approved names cross the
  firewall.
- **tail call** — a `jmp` to another function instead of `call; ret`. Truncates
  decompilation early; abrupt pseudocode often means a tail call or `__noreturn`.

## Types & data

- **tinfo (type info, `tinfo_t`)** — IDA's internal representation of a C/C++
  type (its prototype, struct layout, pointer-ness). `set_type` / `declare_type`
  / `type_apply_batch` manipulate tinfo; a correct prototype is what turns
  `*(a1+8)` noise into named fields. See **type-reconstruction**.
- **struct / UDT (user-defined type)** — a named record of fields at fixed byte
  offsets. `+0x10` means **byte** offset 16 (not element index). `read_struct`
  overlays a declared type onto bytes — verify the type first or you get
  confidently-wrong field names.
- **pack / alignment** — `#pragma pack(1)` removes inter-field padding; wire/file
  structs are almost always packed. A default-aligned IDA struct inserts phantom
  padding and shifts every later field. See **struct-and-vtable-recovery**.
- **enum** — a named set of integer constants. Promote opcode/flag immediates via
  `enum_upsert` so `case 0x42:` reads as `case OP_LOGIN:` at every xref.
- **vtable (virtual method table)** — an array of function pointers a polymorphic
  C++ object points to via its first member (the vtable pointer). Slot stride =
  pointer size (4 bytes in 32-bit `doida.exe`). Walking it recovers a class's
  virtual interface. See **struct-and-vtable-recovery**.
- **RTTI (run-time type information)** — MSVC's emitted type metadata
  (`TypeDescriptor`, `RTTICompleteObjectLocator`, class hierarchy) that, when
  present, names a class and its bases from a vtable. The fastest way to label a
  C++ object hierarchy.

## Signatures & identification

- **FLIRT (Fast Library Identification and Recognition Technology)** — IDA's
  built-in scheme that matches library functions against `.sig` pattern files to
  auto-name CRT/STL/known-library code. Reduces the noise you must reverse by
  hand. Distinct from this server's byte-pattern signatures below.
- **AOB / byte-pattern signature** — an "array of bytes" pattern, often with
  wildcards for relocated/variable bytes (call targets, immediates), used to
  **relocate** a function or datum across builds. `make_signature` /
  `make_signature_for_function` / `make_signature_for_range` /
  `find_xref_signatures` emit `ida` / `x64dbg` / `mask` / `bitmask` forms. Mask
  out variable bytes or the pattern matches only the one sample you built it on.
  See **signatures-and-flirt**.

## Live debugging & instrumentation (`?ext=dbg`)

- **breakpoint** — a stop-on-execute trap at an address. Set, then continue until
  it hits on a real event (a received packet, a login, an asset load), then read
  registers/memory. **Never call `dbg_start`** in this workflow — pilot the
  already-launched session.
- **watchpoint (data/HW breakpoint)** — stops/records when a memory address is
  read or written (backed by CPU debug registers — only a few HW slots exist).
  Acts as a **struct-field spy**: catch every writer of one field. See
  **watchpoints-and-tracepoints**.
- **tracepoint** — a **non-stopping** instrumentation point: it captures
  registers/memory/expressions and lets the target run free, draining records
  into a ring buffer. The core of the instrument → run → drain loop; supports
  conditional capture and ring/dropped semantics. See **watchpoints-and-tracepoints**.
- **probe / autopilot** — this server's non-stopping live layer (`probe_add`,
  `probe_net`, `trace_calls`, `run_until`, autopilot) that instruments hot
  functions and drains results without halting. See **probe-toolkit** /
  **autopilot-playbook**.
- **appcall** — invoking a function **in the live debuggee** with your own
  arguments to test a parser/decryptor directly. Requires a correct prototype and
  a suspended target; dry-run first, and beware side effects. See **appcall-guide**.
- **dbg_read** — reads live process memory, **through `PAGE_NOACCESS`** — it can
  pull guard-page / just-decrypted buffers a normal read would fault on. Ideal for
  cipher pre/post buffers and structs at a live pointer.

## Calling conventions (32-bit MSVC — `doida.exe`)

- **`__cdecl`** — args pushed right-to-left on the stack; **caller** cleans the
  stack; supports varargs.
- **`__stdcall`** — stack args, but the **callee** cleans (`ret N`). The Win32 API
  convention.
- **`__thiscall`** — C++ instance methods: `this` in **`ecx`**, other args on the
  stack, callee-cleaned. A bare `this` local in pseudocode usually means the
  convention wasn't set — set it so `this->field` decoding appears.
- **`__fastcall`** — first two integer args in `ecx`/`edx`, rest on the stack.
- **return value** — integers/pointers in **`eax`** (64-bit in `edx:eax`).
  These slot mappings are what a `trace_calls` / `probe_add` capture spec must
  target to read the right argument live. See **calling-conventions-abi**.

## Crypto recovery

- **S-box (substitution box)** — a constant lookup table (often 256 bytes / 256
  dwords) that a cipher indexes; a high-xref constant table is the tell. See
  **crypto-hunting**.
- **key schedule** — the routine that expands a key into round keys/state before
  encryption. Usually a tight loop walked out from the recv/decrypt path.
- **crypto-shaped loop** — a loop dense with `xor` / `rol` / `ror` / `shl|shr` /
  table indexing over a buffer — the heuristic fingerprint of a cipher. The
  deliverable that crosses the firewall is a **neutral algorithm description in
  words and math**, never transcribed code.

## Protocol / packet recovery

- **opcode** — the small integer at the head of a packet that selects its handler;
  the index into the dispatch switch/jump table. See **opcode-and-packet-re**.
- **dispatch / recv handler** — the function that reads a frame and routes on the
  opcode (the switch). Map opcode → handler address, then infer each packet's
  field layout, then confirm live with a `probe_net` pre/post capture.
- **wire struct / packet layout** — the packed (`pack=1`) byte layout of a
  packet's fields. Recovered from the handler's field accesses; confirmed against
  capture bytes.

## This MCP server

- **MCP (Model Context Protocol)** — the protocol this server speaks (Streamable
  HTTP at `/mcp`, legacy SSE at `/sse`) to expose **tools**, **resources**, and
  **prompts** to a client. See **mcp-server-architecture**.
- **tool** — a callable action/query (`tools/call`); input/output schemas are
  generated from Python type hints, so `tools/list` always matches the signature.
- **resource** — browsable read-only state addressed by URI (`resources/read`),
  e.g. `ida://idb/metadata`, `ida://idb/segments`, `ida://struct/{name}`, the
  docs under `ida://docs`.
- **prompt** — a reusable guide surfaced as a slash-command (`prompts/get`), e.g.
  `probe_workflow`, `crypto_hunt`, `opcode_map`.
- **safety class** — the `@safety(LEVEL)` classification driving MCP annotations
  and unsafe-gating: **READ** (pure queries), **WRITE** (idempotent IDB edits like
  rename/set-type), **DESTRUCTIVE** (non-idempotent edits like undefine/delete),
  **EXECUTE** (runs code / resumes the debuggee — python eval, appcall,
  `run_until`). See **tools-reference**.
- **ext group (`?ext`)** — the `@ext("group")` gate that hides tools until the
  client connects with the matching query param. There is exactly one group:
  **`?ext=dbg`** surfaces the `dbg_*` debugger tools **and the entire probe
  toolkit** (the probes are meaningless without a live debugger, so they share
  the gate). The base `/mcp` view exposes all static-analysis tools (including
  the `ida-domain` `domain_*` tools). The committed config registers the
  `?ext=dbg` superset endpoint.
- **structured output** — a tool result returned as a typed object (from its
  TypedDict output schema) rather than free text, so the client can index fields
  directly. Large payloads are auto-truncated inline and cached; the full result
  is fetched via the `download_url` under `_meta.ida_mcp`. See
  **performance-and-scale**.
- **`@idasync` / main-thread marshaling** — the decorator that runs a tool body on
  IDA's main thread (IDA's API is not thread-safe). In an EXECUTE-class Python
  snippet you are **already on the main thread** — never nest `execute_sync`. See
  **scripting-automation**.
- **idalib** — IDA's headless library mode (drive the analysis engine without the
  GUI). Relevant for batch/automation contexts; this server normally attaches to
  a live GUI database. See **ida-domain-sdk**.
- **ida-domain** — the modern Pythonic SDK (`Database.open`, `functions`,
  `strings`, `xrefs`, `types`, `segments`, `bytes`, `flowchart`, `pseudocode`)
  preferred over raw IDAPython where it covers the need. See **ida-domain-sdk**.
- **IDAPython** — the raw scripting API (`idautils`, `ida_funcs`, `ida_bytes`,
  `ida_typeinf`, `idc`, …). The escape hatch for any query the fixed tools don't
  cover. See **idapython-cookbook**.

## Process & firewall

- **IDB (IDA database)** — the `.idb`/`.i64` analysis database. Confirm *which* IDB
  is loaded (path + hashes via `ida://idb/metadata`) before trusting output; the
  wrong/empty IDB produces plausible garbage.
- **clean-room firewall** — the dirty → spec → engineer pipeline: IDA findings
  land in a gitignored dirty quarantine, are **rewritten** (never copied) into
  neutral committed specs, and only those specs feed implementation. No pseudo-C,
  autonames, or addresses cross into shipped artifacts.
- **ground truth** — the binary itself, observed through IDA (static **and** the
  live debugger). Static analysis forms the hypothesis; the debugger confirms it.
  When a note and the binary disagree, the binary wins.

---

**See also:** `ida-pro-essentials` (concepts → tools), `tools-reference` (taxonomy
+ safety classes), `pro-tips-and-pitfalls` (the trap field guide), and the
deep-dive docs named per section above.
