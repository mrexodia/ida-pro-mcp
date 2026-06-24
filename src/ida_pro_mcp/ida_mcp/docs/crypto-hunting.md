# Crypto Hunting: Ciphers, Key Schedules, and the Cipher Boundary

Hand-rolled packet ciphers are everywhere in game and legacy network clients,
and they almost never use the OS crypto API. This doc is the focused recipe for
finding the cipher and its key schedule in a binary: how a crypto loop *looks*
in disassembly, how to detect S-boxes and constant tables, how to walk out from
the `recv`/decrypt seam, and how to **prove** the plaintext/ciphertext boundary
live with a buffer pre/post probe. It is algorithm-level and neutral — describe
the math, never transcribe the code.

Read `ida://docs/re-methodology` (the static-first loop) and
`ida://docs/probe-toolkit` (the non-stopping probe) first; this doc specialises
both to crypto. There is also a `/crypto_hunt` prompt that summarises the four
angles.

## What a cipher looks like in disassembly

You are pattern-matching against a handful of recurring shapes. None of them
require the binary to *call* anything — that is exactly why crypto imports are
usually absent.

- **Dense bit-ops over a buffer.** A tight loop whose body is dominated by
  `xor`, `rol`, `ror`, `shl`/`shr`, `add`/`sub`, `not`, `and`/`or` — far more
  bit-twiddling per iteration than ordinary code. A stream/feedback cipher reads
  a byte, mixes it with key/state, writes it back; a block cipher does several
  rounds of mixing on a fixed-width chunk.
- **A rolling index with wraparound.** `inc`/`add` of an index followed by
  `and 0xFF` (or `... % keylen`, often a power-of-two mask) is the keystream
  pointer of an RC4-style or repeating-XOR scheme. The mask value *is* the key
  length minus one.
- **Two pointers advancing together.** `src` and `dst` (often the same buffer →
  **in-place** transform) plus a length counter. In-place decrypt over the recv
  buffer is the single most common shape on a network path.
- **Table-indexed substitution.** `movzx reg, byte ptr [table + idx]` inside the
  loop, where `table` is a 256-byte (or 256-dword) constant — an S-box lookup.
- **A separate setup loop run once.** The **key schedule**: a loop that fills a
  256-byte state from a key (the RC4 KSA: a swap loop over `S[i]`), or that
  expands a short key into round keys / a larger table. It runs at connect /
  login time, not per packet — find it by xref from the per-packet loop to the
  state buffer it consumes.

Cipher identity hints (state these as hypotheses, confirm with bytes):

- **RC4** — 256-byte state, a KSA swap loop, then a PRGA loop with two indices
  `i`/`j`, a swap, and `S[(S[i]+S[j]) & 0xFF]` xored into the data. No round
  constants.
- **TEA/XTEA** — a magic constant `0x9E3779B9` (the golden-ratio delta) and a
  32-round loop over a 64-bit block with shifts by 4/5 and `+= delta`.
- **AES** — a 256-byte S-box, the Rcon bytes, and `0x1B` appearing in `xtime`
  (GF(2^8) multiply). If you see AES tables, suspect a software AES, not the
  CryptoAPI.
- **CRC / checksum, not crypto** — a 256-entry *dword* table and a single
  `xor`/`shr 8`/table-index per byte with **no key input** is a CRC32, not a
  cipher. Do not mistake it for encryption; it usually guards the frame instead.
- **Plain repeating-XOR** — one `xor` against a short repeating key with a mask;
  the weakest and most common.

## Finding the loops statically

`insn_query` is the scalpel here: it scans instructions by mnemonic with an
optional scope, so you can ask "where is the binary dense in rotates/xors". Run
several mnemonics and look for **functions that show up in more than one
result** — that overlap is your candidate set.

```
insn_query([{"mnem": "rol"}, {"mnem": "ror"}])    # rotates are rare → high signal
insn_query({"mnem": "xor"})                        # noisy alone; intersect with rotates
insn_query({"mnem": "xor", "segment": ".text"})    # scope to code
```

Rotates (`rol`/`ror`) are the highest-signal mnemonic: ordinary compiled code
almost never emits them, so a function with several is very likely a cipher,
hash, or PRNG. Intersect the rotate hits with the `xor` hits and you have a
short list.

Then profile the candidates in one call. `func_profile` with
`include_lists: true` returns each function's referenced **constants** and
strings — a cheap way to spot `0x9E3779B9`, `0x1B`, an S-box address, or a key
length without decompiling:

```
func_profile([{"addr": "<cand>", "include_lists": true}, ...])
```

Confirm the winner with `decompile` + `disasm`, and use `trace_data_flow`
(backward from the loop's data pointer) to find what feeds the buffer — that
trail usually lands on the recv/framing code.

Pro-tips:

- **Scope every scan.** Pass `segment`/`func`/`start`+`end` to `insn_query` so
  you are searching code, not data, and not the CRT.
- **Rotates first, xors second.** Sort candidates by rotate density; it cuts the
  list faster than xor count.
- A `decompile` of a crypto loop is a *hypothesis*. Hex-Rays mangles rotates
  (often as `(x<<n)|(x>>(32-n))`), gets signedness wrong, and hides the mask.
  Read the `disasm` for the real bit-ops before you believe the algorithm.

## Detecting S-boxes and constant tables

The key material and substitution tables are static data, so you can find them
without running anything.

- **256-byte permutation (S-box).** A region of exactly 256 bytes where every
  value `0x00..0xFF` appears exactly once is an S-box (AES forward S-box, an
  RC4 initial identity before KSA, etc.). Read it and check the permutation
  property; that alone names the cipher family.
- **Known-constant fingerprints.** Search for the deltas/round constants
  directly. `find("immediate", [0x9E3779B9])` finds TEA/XTEA setup;
  `find("immediate", [0x1B])` is weak alone but corroborates AES near an S-box.
- **Large aligned constant arrays.** A power-of-two-sized, 16-byte-aligned blob
  referenced *inside* the crypto loop is the table the cipher indexes. Find the
  reference site, then read the table.

```
find("immediate", ["0x9E3779B9"])     # TEA/XTEA delta as an immediate operand
find_bytes("63 7C 77 7B F2 6B 6F C5") # the first bytes of the AES forward S-box
get_bytes([{"addr": "<table_ea>", "size": 256}])   # read it and test the property
xrefs_to("<table_ea>")                 # who indexes it → the cipher loop
list_globals(...) / get_global_value("<name>")     # named key/state globals
```

How to read it back: `get_bytes` returns raw bytes for a permutation/property
check; `get_string` reads a literal; `get_global_value` resolves a named global
to a value. To find a table from the loop instead of the loop from a table,
`xref_query`/`xrefs_to` the address the `movzx ..., byte ptr [tbl+idx]` uses.

Pitfalls:

- **A CRC table is 256 *dwords*, not bytes**, and is keyless — do not promote it
  to "the cipher".
- The 256-byte identity `00 01 02 ... FF` is an *un-keyed* RC4 state; the real
  permutation only exists after the KSA runs (so confirm live, below).
- Endianness: AES/TEA constants are little-endian in an x86 immediate; search
  the immediate form, not the byte string, when using `find("immediate", ...)`.

## Walking out from the recv/decrypt path

Top-down from the network seam is the most reliable route, because the cipher is
whatever transforms the recv buffer before it is parsed.

1. **Find the seam.** `imports_query("recv")` / `imports_query("WSARecv")`, then
   `xrefs_to(<recv>)` to the framing reader (the function that loops reading a
   header then a body).
2. **Follow the buffer.** From the framing reader, `trace_data_flow(<buf>,
   "forward")` to where the bytes are consumed. The transform that sits between
   "bytes arrived" and "fields are read" is the decrypt.
3. **Confirm in-place vs copy.** If `src == dst` the decrypt mutates the recv
   buffer; otherwise it writes a plaintext buffer the parser reads. Either way,
   the call *boundary* is what you will prove live.
4. **Find the schedule.** From the decrypt loop, `xrefs_to` the state/key buffer
   it reads. One xref writes it (the key schedule, run at login/connect); the
   others read it. The writer is the KSA / key expansion.

The send side mirrors this: `xrefs_to(send)` → the framing writer → the
**encrypt** loop, which usually shares the cipher (and key) with decrypt. Proving
both directions pins the algorithm.

## Proving the boundary live (buffer pre/post probe)

Static analysis gives you the *shape*; only a live read proves "plaintext on one
side, ciphertext on the other" and recovers the *runtime* key/state (KSA output,
session keys, and tokens never exist on disk). Use the debugger
(`?ext=dbg`) or, better, the **non-stopping probe** (also `?ext=dbg`).
**Never call `dbg_start`** — attach to the session the maintainer F9-launched.

### The pre/post pair

The proof is two reads of the *same* buffer address: once **before** the decrypt
runs, once **after**. If "before" is ciphertext and "after" is structured
plaintext (a recognisable opcode/length header), the boundary is proven and you
have a ciphertext↔plaintext pair to validate your algorithm against.

With the debugger (stops the target):

```
dbg_add_bp("<decrypt_entry>")
dbg_continue()                       # run until a real packet hits it
dbg_gpregs()                         # resolve buf ptr + len from the arg regs/stack
dbg_read("<buf>", <len>)             # CIPHERTEXT in (reads through PAGE_NOACCESS)
dbg_run_to("<decrypt_return>")       # one-shot to the return site
dbg_read("<buf>", <len>)             # PLAINTEXT out — same address, transformed
```

With the non-stopping probe (target keeps running — preferred for live traffic):

```
probe_net(recv_ea="<recv>", decrypt_ea="<decrypt>", send_ea="<send>",
          buf_arg=1, len_arg=2)      # convenience pre-buffer probes on the path
# or build the pair by hand:
probe_add("<decrypt_entry>",  capture=["mem(arg1, 256)"], max_hits=8)   # before
probe_add("<decrypt_return>", capture=["mem(arg1, 256)"], max_hits=8)   # after
run_until(timeout_ms=8000)
probe_drain(since_cursor=0, filter=None, limit=64)   # compare before/after bytes
```

`probe_net` installs the buffer probes for a recv/decrypt/send path from
caller-supplied addresses (never hardcoded); `buf_arg`/`len_arg` are the 1-based
arg positions of the buffer pointer and length at the callee entry. The `after`
probe at the return site captures the transformed buffer at the same pointer.
`probe_drain` pulls the records oldest-first — diff the two captures byte for
byte.

### Recovering the live key / state

To dump the *runtime* key schedule (e.g. the 256-byte RC4 state after KSA, or
expanded round keys), read the state global/heap region live after the schedule
has run:

- `read_struct_live("<state_ea>", "<type>")` overlays an IDB type onto live
  memory; the `ea` may be a pointer chain like `[[base+0x10]+0x8]`.
- Or break after the KSA and `dbg_read("<state_ea>", 256)`.
- `watch_field("<key_ptr>", 4, mode)` records when the key/state changes (a
  4-slot HW watchpoint) — useful to catch a per-session rekey without stopping.

Validate end-to-end: take the captured ciphertext, run it through your neutral
reimplementation with the recovered key, and check it reproduces the captured
plaintext. That byte-for-byte match is the only real proof the algorithm is
correct.

## Clean-room output

The deliverable that crosses the firewall is a **neutral algorithm description
in words and math** — the cipher family, the round structure, the index/mask
arithmetic, the key length, the schedule (in equations), and the constants in
hex. Pin it to the IDB identity (from `survey_binary`) and tag each fact by how
it was confirmed (static-only / debugger-confirmed / pair-validated). **Never**
paste decompiler pseudo-C, autonames, or transcribed key bytes into a kept note
— describe what the loop computes, not how Hex-Rays printed it.

## Checklist

1. `insn_query` rotates+xors → intersect → candidate functions.
2. `func_profile(include_lists)` → spot magic constants / table refs cheaply.
3. `find`/`find_bytes` known constants + S-box bytes; `get_bytes` to test the
   256-permutation property; `xrefs_to` the table to land on the loop.
4. `imports_query("recv")` → `xrefs_to` → `trace_data_flow` to the in-place
   transform; `xrefs_to` the state buffer to find the schedule (KSA).
5. `?ext=dbg`: pre/post buffer pair (`probe_net` / paired `probe_add` +
   `run_until` + `probe_drain`) to prove the boundary; `read_struct_live` /
   `dbg_read` to dump the runtime key/state.
6. Reimplement neutrally, validate against the captured ciphertext↔plaintext
   pair, and write the algorithm down in words and math only.
