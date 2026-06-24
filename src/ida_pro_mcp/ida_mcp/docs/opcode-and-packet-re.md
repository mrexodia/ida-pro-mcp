# Recovering a Network Protocol — End-to-End Recipe

This is the full pipeline for reversing a client/server wire protocol through the
IDA Pro MCP: **find the receive dispatch → map opcode→handler → infer per-packet
field layouts → confirm everything live with `probe_net`**. It is written against
a real 32-bit MSVC target (a game client), but the method generalizes to any
length-prefixed, opcode-dispatched binary protocol.

> Tool names below are bare `@tool` names. Over the wire they are
> `mcp__ida__<name>` (e.g. `mcp__ida__xrefs_to`). The schemas in `tools/list`
> are always authoritative. The `probe_*` / `probe_net` tools live behind the
> `?ext=probes` gate and **hard-require a live debugger session the maintainer
> already launched (F9)** — they never call `dbg_start`.

The golden rule: **static analysis forms the hypothesis; the live debugger
confirms it byte-for-byte.** Never ship an opcode, offset, or field type that the
running process has not actually produced.

---

## 0. Orient first (don't skip)

Before touching the protocol, confirm *which* binary is loaded and its bitness —
arg layout, pointer size, and dispatch idioms all depend on it.

- `server_health` / read `ida://idb/metadata` — image name, arch, base, hashes.
- A 32-bit image means cdecl/stdcall stack args and `thiscall` via `ecx`; a
  64-bit image means the first four args are in `rcx/rdx/r8/r9` (Win64). The
  probe capture tokens (`arg0`, `ecx`, `mem(arg1,256)`) assume the 32-bit layout
  unless the IDB reports 64-bit.

---

## 1. Find the receive path (the socket → parser seam)

The dispatch table is downstream of `recv`. Start from the imports and strings,
not from guesswork.

**Import-anchored search** — find every call site of the socket recv primitives:

```
imports_query     query="recv"          # ws2_32 recv / recvfrom / WSARecv
xrefs_to          ea="recv"             # every caller of the import thunk
```

Walk each caller with `decompile` (or `disasm`) and look for the classic
**framing loop**: read into a ring/accumulation buffer, peek a length field,
wait until `available >= header+length`, then hand a complete frame to a parser.
That parser is your dispatch entry.

**String-anchored search** — error strings near the parser are gold:

```
find_regex        pattern="unknown (opcode|packet|message|cmd)"
find_regex        pattern="invalid (length|size|header)"
xrefs_to          ea=<string ea>        # the handler that prints it = the dispatcher
```

**Subsystem census** (when you don't even know where to start): use the
`ida-recon` STRING-HUNT angle — census imports+strings and tag the networking
cluster (`recv`, `send`, `WSA*`, `htons`, `ntohl`, "packet", "opcode"). The
densest cluster of net imports + net strings is the protocol module.

Pro-tips:
- `ntohs`/`ntohl`/`htons` near a buffer read almost always mark the **header**
  (opcode and/or length are frequently big-endian on the wire even on x86).
- The recv buffer is rarely the parse buffer. Decryption usually copies/transforms
  recv → a plaintext frame buffer first; the dispatch reads the *plaintext*. Trace
  the data, don't assume (`trace_data_flow`, §2).

---

## 2. Find the dispatch table / switch

Once you have the parser function, the opcode→handler mapping takes one of three
shapes. Identify which.

### (a) Compiler jump table (dense `switch`)

A dense `switch(opcode)` compiles to an indirect jump through a table of code
addresses: `jmp ds:jpt_xxxx[eax*4]` preceded by a range check
(`cmp eax, N; ja default`). To recover it:

```
decompile     ea=<parser>          # Hex-Rays renders it as a clean switch{}
disasm        ea=<parser> count=400
```

Hex-Rays usually reconstructs the `switch` and its cases directly — that is the
fastest read. If it doesn't (obfuscated/again-data table), find the table base
operand in the `jmp` and dump it:

```
insn_query    ea=<parser ea> ...   # locate the indirect jmp (mnem "jmp", memory operand)
get_bytes     ea=<jpt base> size=<(max_case+1)*4>   # raw u32 code pointers, little-endian
```

Each 4-byte entry is a handler EA (32-bit). Watch for an **indirection table**:
`cmp; ja; movzx ecx, byte[idx_tbl+eax]; jmp dword[jpt+ecx*4]` — a `u8` index
table collapses sparse opcodes onto a small jump table. Dump **both** tables and
compose `handler = jpt[ idx_tbl[opcode] ]`.

### (b) Handler array indexed by opcode

A global array of function pointers (often `{opcode, fn}` or a flat `fn[256]`)
indexed at runtime: `call dword ptr [tbl + eax*4]`.

```
list_globals                       # or search_structs for an array-of-funcptr global
get_bytes     ea=<tbl> size=<N*4>  # N consecutive code pointers
xrefs_to_field                     # if the table is a typed struct array
```

Then resolve each non-null pointer to a function name with `func_query` /
`lookup_funcs`.

### (c) Registration / if-else ladder

Handlers register themselves at init (`RegisterHandler(0x1A, &fn)`), or the
parser is a long `if (op==0x01) ... else if (op==0x02) ...` chain.

```
xrefs_to      ea=<register fn>     # every registration call site
```

Read each call site's args (`disasm`) to harvest the literal opcode + handler.
The if-else ladder is just `decompile` + read the constants.

**Cross-check with the `ida-opcode-map` skill** — it automates locating the
switch/jump table and resolving each case to a handler, writing
opcode→handler-address pairs to the dirty quarantine.

---

## 3. Build the opcode → handler map

For every case/entry you found, resolve and label:

```
func_query    query=<handler ea>           # canonical name, size, signature
callgraph     ea=<handler> depth=1          # what each handler calls (parse vs apply)
func_profile  ea=<handler>                  # quick role summary
```

Tabulate as `opcode | handler_ea | handler_name | direction | size`. Keep
**direction** explicit (C2S vs S2C): a client binary *parses* S2C in the dispatch
and *builds* C2S near the `send` import — find the build sites with
`imports_query query="send"` + `xrefs_to`, and pair the opcode constants written
there with their packet builders.

Pro-tips:
- A handler that is tiny and just stores fields is a pure deserializer — ideal for
  layout recovery. A handler that immediately calls game logic mixes parse + apply;
  isolate the parse prologue.
- Opcode constants are frequently `enum`-like. Once recovered, `enum_upsert` the
  set into the IDB so every `cmp eax, 0x1A` reads as `cmp eax, OP_LOGIN_ACK`.
- Annotate as you go via the `ida-annotate` skill (rename `sub_xxxx` →
  `handle_<name>`, comment the opcode) so the second pass is legible. Apply only
  glossary-approved names; dry-run → apply.

---

## 4. Infer per-packet field layouts (static)

For one handler, recover the field structure of the packet it parses.

1. **Read it.** `decompile ea=<handler>`. The body reads the frame buffer at
   fixed offsets — `*(buf+0)`, `*(WORD*)(buf+2)`, `*(DWORD*)(buf+4)`,
   `strcpy(dst, buf+8)`. Each access is a field: offset = constant, size = access
   width, type = how it's used.

2. **Trace the buffer pointer** to see exactly which bytes feed which field:

```
trace_data_flow   ea=<insn that loads buf> direction="forward"
```

   This follows the recv/plaintext buffer forward into each field read — the
   ground truth for "where does this length come from / where does byte N go."

3. **Name the offsets** into a struct and let IDA propagate types:

```
declare_type      ...    # e.g. struct LoginAck { u16 op; u16 len; u32 uid; char name[16]; }
set_type          ea=<buf param>    # apply the struct to the parser's buffer arg
read_struct       ...               # confirm member offsets line up
```

   Once the struct is applied, `decompile` re-renders the handler with
   `pkt->uid`, `pkt->name` instead of raw offsets — instant validation that the
   layout is self-consistent.

4. **Mind the wire conventions:**
   - **Endianness:** check for `ntohs/ntohl` (or `bswap`, `xchg al,ah`) on the
     field — header fields are often big-endian, body fields little-endian. Get
     this wrong and a 2-byte length reads as 0x0100 instead of 0x0001.
   - **Pack/alignment:** wire structs are almost always `#pragma pack(1)` — no
     padding. Declare them packed or your offsets drift after the first odd-sized
     field.
   - **Variable-length:** a length field followed by `memcpy(dst, buf+k, len)` is
     a var-length blob; a `while`/loop over a count field is a repeated record.
     These can't be a fixed struct — note the count/length field that drives them.
   - **Strings:** CP949 (Korean) is common in this target. Length-prefixed vs
     NUL-terminated matters — read which the parser uses (`strlen` vs explicit
     length) before deciding.

**Capture-diff cross-check (no IDA):** if you have packet captures, the
`pcap-extract` FIELD-DIFF angle aligns two packets of the same opcode and
highlights which byte columns vary — that pins the dynamic fields independently
of the static read.

---

## 5. Confirm live with `probe_net` (recv / decrypt / send, pre/post)

Static layout is a hypothesis until the running process produces those bytes.
`probe_net` installs **non-stopping** buffer-capturing probes at the recv,
decrypt, and send addresses *you* supply (never hardcoded), so you watch real
frames flow without ever halting the client.

**Pre-req:** a live debugger session the maintainer F9-launched. Verify with
`server_health` / the `ida-mcp-connect` skill; the `probe_*` tools fail with an
explanatory error if no session is live.

### 5.1 Install the probes

```
probe_net
   recv_ea     = "<recv-caller / frame-assembled ea>"
   decrypt_ea  = "<decrypt routine entry ea>"
   send_ea     = "<send builder / send-caller ea>"
   buf_arg     = "arg1"      # the buffer-pointer argument (default arg1)
   len_arg     = "arg2"      # the length argument        (default arg2)
   pre_post    = true        # also intend a post-decrypt read at the return site
```

Each address gets a probe capturing `[buf_arg, len_arg, mem(buf_arg,256)]` — the
pointer, the length, and up to 256 bytes of the buffer. `buf_arg`/`len_arg` map
to the calling convention: for a 32-bit `__cdecl`/`__stdcall` `parse(buf, len)`
the defaults `arg1`/`arg2` are correct; for `__thiscall` use `ecx` for `this` and
shift the stack args.

> Pick the **right `decrypt_ea`**: the *entry* captures ciphertext (pre), the
> *return site* captures plaintext (post). `pre_post=true` flags the intent but
> you must place the paired post probe yourself at the decrypt return address:
>
> ```
> probe_add   ea="<decrypt return-site ea>"  capture=["mem(<saved buf ptr>,256)"]  max_hits=64
> ```
>
> Capturing both lets you diff the same bytes before vs after the cipher — the
> definitive way to confirm a decryption boundary and key behaviour.

### 5.2 Run, then drain

The debuggee must be **suspended** to start a run. Resume and let probes fire:

```
run_until    timeout_ms=15000  probe_id="<the recv probe_id from probe_net>"
```

`run_until` returns `status` in `{hit, timeout, exited, suspended}` and, when
`probe_id` is passed, the records that probe captured during the run in `buffer`.
For everything captured across all probes, drain the ring (non-destructive,
oldest-first, cursor-based):

```
probe_drain   since_cursor=0  filter={"kind":"net_recv"}  limit=512
# feed the returned `cursor` back as since_cursor next time; watch `dropped`
probe_list                      # ids + hit counts
```

Each record's `captured` dict holds the hex slice, e.g.
`mem(arg1,256) -> {"addr":"0x...","hex":"1a00 0c00 ..."}`. Decode it against your
§4 struct: first `u16` should be your opcode, next `u16` your length, then the
body fields at the offsets you predicted.

### 5.3 The pre/post decrypt diff (proving the cipher boundary)

1. Probe at `decrypt_ea` entry → capture ciphertext slice (`net_decrypt_pre`).
2. Probe at the decrypt **return site** → capture the same buffer (plaintext).
3. `run_until` to catch one frame; `probe_drain` both.
4. Compare the two hex slices byte-for-byte. If they differ and the post-slice
   parses cleanly as your struct, the decrypt boundary and your layout are both
   confirmed. If pre==post, you probed the wrong site (the transform is in-place
   elsewhere, or the data was already plaintext).

For the cipher itself (key schedule, S-box), hand off to the `ida-crypto-hunt`
skill — but byte-prove the boundary here first so you know *where* to look.

### 5.4 Verify a parsed struct against live memory

When a handler stores the frame into a typed object, read that object live and
confirm the fields landed where your struct says:

```
read_struct_live   ea="[[<entity base>+0x10]+0x4]"  type_name="LoginAck"
```

`read_struct_live` dereferences the pointer-chain live and overlays the IDB type
into a named-field dict — `pkt->uid`, `pkt->name` with real runtime values. If
those match the wire bytes you drained, the layout is end-to-end proven.

### 5.5 Clean up

```
probe_clear                     # remove ALL probes + their breakpoints
probe_clear   probe_id="<id>"   # or just one
```

Probes self-disarm at `max_hits` (recv/send default 4096), but clear them when
done so a later run isn't polluted by stale captures.

---

## 6. Pitfalls & best practices

- **Probe the assembled frame, not raw `recv`.** `recv` hands you partial,
  still-encrypted TCP segments — length and opcode may be split across reads.
  Probe the function that receives a *complete, decrypted* frame (downstream of
  the framing loop and decrypt), or your `mem()` slice is noise.
- **`thiscall` confusion.** If the parser is a C++ method, `arg1` is *not* the
  buffer — `ecx` is `this`, and the buffer is a later stack arg. Read the
  prologue; set `buf_arg` accordingly. Use `trace_calls conv="thiscall"` to dump
  `ecx`+stack args and discover which slot is the buffer.
- **256-byte cap.** `probe_net` slices 256 bytes; for larger frames place a wider
  `probe_add ... capture=["mem(arg1,1024)"]` (max 4096 per `mem` token).
- **Big-endian header.** The #1 layout bug. Confirm `ntoh*` presence statically,
  then sanity-check live: a plausible small opcode/length means your endianness
  is right; a giant number means you swapped it.
- **Don't trust Hex-Rays offsets blindly.** It can fold/reorder field reads.
  `trace_data_flow` from the buffer load is the authoritative offset source.
- **One frame is not a spec.** Drain several frames of the same opcode (or
  FIELD-DIFF captures) before fixing a field as constant vs variable.
- **Clean-room firewall.** Live captures and decompiler output are *dirty*. What
  crosses into a committed spec is a **neutral description** (opcode table, field
  offset/size/type/endianness) — never pasted pseudo-C, never raw captured
  payload bytes. Promote with the `re-promote` skill.
- **Never `dbg_start`.** Every `probe_*` tool refuses to launch a debugger; it
  requires the maintainer's F9 session. If the tools error with "No live
  debugger session," that session isn't running — stop and report.

---

## 7. The recipe in one screen

```
# orient
server_health
# find recv path
imports_query query="recv";  xrefs_to ea="recv";  find_regex pattern="unknown opcode"
# find dispatch
decompile ea=<parser>                      # read the switch
get_bytes ea=<jpt> size=<(N+1)*4>          # or dump the jump/handler table
# map opcodes
func_query / callgraph per handler  ->  opcode|handler|dir|size  (+ enum_upsert)
# infer layout
decompile ea=<handler>;  trace_data_flow ea=<buf load> direction=forward
declare_type LoginAck{...};  set_type ea=<buf arg>   # re-decompile reads as pkt->field
# confirm live (F9 session)
probe_net recv_ea=.. decrypt_ea=.. send_ea=.. buf_arg=arg1 len_arg=arg2 pre_post=true
probe_add ea=<decrypt return> capture=["mem(<bufptr>,256)"]   # post-decrypt
run_until timeout_ms=15000 probe_id=<recv id>
probe_drain filter={"kind":"net_recv"}     # decode hex vs struct
read_struct_live ea="[[base+0x10]+0x4]" type_name="LoginAck"   # field-level proof
probe_clear
```
