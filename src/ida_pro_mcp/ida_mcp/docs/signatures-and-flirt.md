# Byte-Pattern Signatures & FLIRT-Style Identification (via MCP)

This server can synthesize **byte-pattern signatures** — the AOB / "array-of-bytes"
patterns with wildcarded operands that x64dbg, Cheat Engine, ReClass, and IDA's own
binary search all consume. They solve one problem: **naming the same code site in a
different build of the binary**, where every address has moved but the instruction
stream is nearly identical. The classic use in this project is *relocating a
recovered function across `Main.exe` → `doida.exe`* (or across two patch revisions of
`doida.exe`) without re-doing the reverse from scratch.

> Tool names below are the bare `@tool` names. Over the wire they appear as
> `mcp__ida__<name>` (e.g. `mcp__ida__make_signature`). `tools/list` is authoritative
> for the exact schema.

## FLIRT vs. these signatures — a clarification up front

IDA's built-in **FLIRT** (Fast Library Identification and Recognition Technology) is a
*different* mechanism: it ships pre-built `.sig` pattern libraries to auto-name **CRT
and third-party library** functions at load time, and you generate those with the
external `sigmake`/`pcf` tooling, not from MCP. **This server does not author FLIRT
`.sig` files.** What it produces is the more general, ad-hoc cousin: a single AOB
signature for *one* function or code site that you (or another tool) scan for. Reach
for these when the target is *application* code FLIRT will never recognize — your own
recovered packet handlers, the recv dispatch, a cipher loop — and you need a portable
locator for it. The phrase "FLIRT-style identification" in this doc means exactly
that: identifying a known function in an unknown build by its byte fingerprint.

---

## 1. The four tools at a glance

| Tool | Anchors at | Guarantees uniqueness? | Use when |
|---|---|---|---|
| `make_signature` | the **exact address** you give | yes (auto-extends) | a mid-function code site (a specific `call`, a loop head, a constant load) |
| `make_signature_for_function` | the enclosing function's **entry** (`start_ea`) | yes (auto-extends) | "give me a signature for this whole function" — the common case |
| `make_signature_for_range` | a **fixed `[start, end)` span** you choose | **no** — reports a `unique` flag, never extends | you already selected the exact bytes and want full control of the bounds |
| `find_xref_signatures` | the **code that references** a target | yes (per referencing site) | the target has no signaturable bytes of its own — data, a global, a vtable slot, a string |

All four take an `addrs` argument that accepts a hex address (`"0x401000"`), a **name**
(`"main"`, `"sub_402000"`), or a **list** of either, and a `format` (see §3). They are
all `safety("READ")` — pure analysis, no IDB writes.

### make_signature — a specific code site

```jsonc
make_signature(addrs="0x401A37", format="ida")
// -> [{ "query":"0x401A37", "addr":"0x401a37",
//       "signature":"8B 4D ? 51 E8 ? ? ? ? 83 C4 04",
//       "format":"ida", "unique": true }]
```

It walks instructions **forward** from the address, wildcarding operands, appending
bytes until the pattern matches exactly one place in the image, then **trims trailing
wildcards** off the end. The `unique` field is not a hope — it is **re-verified by an
actual scan** of the database after generation.

### make_signature_for_function — the whole function

```jsonc
make_signature_for_function(addrs="RecvDispatch", format="x64dbg")
// -> [{ "query":"RecvDispatch", "addr":"0x4032b0", "name":"RecvDispatch",
//       "signature":"55 8B EC 83 EC ?? 53 56 57 8B 7D ??", "format":"x64dbg" }]
```

Resolves the input to its **enclosing function** and signatures from `start_ea`,
*regardless of where inside the function your address landed*. This is the go-to for
"signature this function by name." Note there is **no `unique` flag** in the result
(uniqueness is still the generation goal, it just isn't echoed back) — and if the
address is not inside a defined function you get `"error": "No function at 0x…"`.

### make_signature_for_range — exact bounds, no auto-extend

```jsonc
make_signature_for_range(start="0x401000", end="0x401012", format="mask")
// end is EXCLUSIVE
```

This encodes **exactly** the bytes in `[start, end)`. It does **not** grow the range to
force uniqueness — it just tells you, via the `unique` flag, whether the span you chose
happens to be unique. A short range will very often come back `"unique": false`; that
is your cue to widen `end`. **`end` is exclusive**, so an off-by-one silently drops the
last instruction.

### find_xref_signatures — signaturing the un-signaturable

You cannot make a code signature for a *data* address — there are no instructions to
walk (`make_signature` raises `"Cannot create code signature for data"`). Instead,
signature the **code that touches the datum**:

```jsonc
find_xref_signatures(addrs="0x4F1200", format="ida", top=5, max_length=250)
// -> [{ "query":"0x4F1200", "addr":"0x4f1200",
//       "total_xrefs": 7,
//       "signatures": [
//         { "xref_addr":"0x40a1b0", "signature":"68 00 12 4F 00 E8 ? ? ? ?", "length":10 },
//         ... up to `top` entries, shortest first ...
//       ] }]
```

For each input it finds every **code** xref pointing **at** the target, builds a unique
signature at each referencing site, sorts them shortest-first (ties broken by fewest
wildcards — the *most specific* among equal-length wins), and returns the `top` of
them. This is how you relocate a **string literal, a config global, a vtable, or a
jump-table entry** across builds: you re-find the *code* that loads it, then read the
operand to recover the moved data address. A target with **no incoming code xrefs**
returns an empty `signatures` list — that is a result, not an error. Only **code**
xrefs are considered; data-to-data references are ignored.

---

## 2. The relocation workflow — porting a function across builds

This is the payoff. You reversed a function in build A and want it in build B.

1. **In build A's IDB**, signature the function:
   `make_signature_for_function(addrs="LoginPacketParser")`.
   Pick a `format` your scanning tool understands (x64dbg for the x32dbg MCP, mask for
   a C++ `FindPattern`, ida for IDA's own binary search). Save the string.
2. **Load build B's IDB** (the maintainer switches the loaded database — this server
   acts on *whichever IDB is currently open*; there is no cross-database tool).
3. **Scan build B for the pattern.** This server has **no `scan_signature` MCP tool** —
   it builds signatures, it does not expose a one-shot pattern search back to you.
   Scan with one of:
   - **IDA's binary search** in build B (Search → Sequence of bytes, or `ida_bytes`
     via the `ida-py` escape hatch) using the **`ida` format** string;
   - the **x32dbg MCP** `PatternFindMem` on the running build-B process, using the
     **`x64dbg` format** string;
   - any external AOB scanner with the **mask** or **bitmask** format.
4. **Confirm the hit is the right function** — verify a few instructions, the call
   targets, and the surrounding xrefs match build A. A unique-in-A signature is **not
   guaranteed unique in B**; treat the scan result as a hypothesis until corroborated.
5. **Re-anchor.** Once located, rename it in build B's IDB (`rename`) so subsequent RE
   builds on the recovered name.

> Pitfall — uniqueness is a per-database property. The `unique: true` you got in build
> A says nothing about build B. Always re-verify the scan count in the target build;
> if build B returns multiple hits, lengthen the signature (raise `max_length` and
> re-generate, or fall back to a longer `make_signature_for_range`).

---

## 3. Output formats — pick the one your consumer parses

The `format` argument is one of four (default `"ida"`). Same pattern, four encodings:

| `format` | Example (same 4 bytes, 2 wildcarded) | Consumer |
|---|---|---|
| `ida` | `8B 4D ? 51` | IDA binary search; this server's own re-verify |
| `x64dbg` | `8B 4D ?? 51` | x64dbg / the **x32dbg MCP** `PatternFindMem` |
| `mask` | `\x8B\x4D\x00\x51 xx?x` | classic C++ `FindPattern(pattern, mask)` |
| `bitmask` | `0x8B, 0x4D, 0x00, 0x51 0b1101` | byte-array + binary mask (note the mask is **reversed** / little-end-first) |

Key encoding facts:
- **`ida`** uses a **single `?`** per wildcard byte; **`x64dbg`** uses **`??`**. Do not
  feed an x64dbg `??` string to an `ida`-expecting consumer or vice-versa.
- **`mask` / `bitmask`** emit a literal `\x00` / `0x00` for wildcard positions; the
  *mask* string is what actually marks them wildcard (`?` / `0`), **not** the byte
  value. The byte value at a wildcard slot is meaningless — never read it.
- The **bitmask** binary string is **little-endian relative to the byte order**
  (`mask_str[::-1]`): the first byte's mask bit is the **rightmost** bit of `0b…`.

---

## 4. Uniqueness — how it works and where it bites

The maker grows the pattern until `SignatureSearcher.is_unique` returns true.
`is_unique` is **bail-at-second-match**: it stops scanning the instant it sees a second
hit, because uniqueness only depends on whether the count is 0, 1, or 2+. That makes it
cheap even on a large image where a short, common prefix (`55 8B EC` — every MSVC
function prologue) would otherwise match millions of positions.

What `wildcard_operands` (default `true`) actually wildcards: **operand bytes that
encode addresses that move between builds** — memory references, near/far call & jump
displacements. It deliberately **does NOT wildcard immediates** (`mov rcx, 0x13371338`)
— a literal baked into the encoding does not shift between builds, so wildcarding it
would only throw away the very bytes that make the signature distinctive. This is an
intentional improvement over naive operand-wildcarding; keep `wildcard_operands=true`
for cross-build portability and only set it `false` if you need a byte-exact signature
of one specific build (which will not survive recompilation).

**Pitfalls:**
- **`unique: false` on `make_signature` / `make_signature_for_range`** means the maker
  hit `max_length` (default 1000 bytes) before a distinguishing pattern emerged, *or*
  (for range) the fixed span simply is not unique. Remedies: raise `max_length`, pick a
  more distinctive start address (one with a constant load or a string reference
  nearby), or widen the range.
- **An entirely-wildcard tail is trimmed**, so a signature can end on a real byte even
  if the last instruction's operand was wildcarded. Lengths in `find_xref_signatures`
  reflect the trimmed pattern.
- **`make_signature_for_range` never auto-extends.** It is the one tool that respects
  your bounds literally; if you want a guaranteed-unique result, use the other two.
- **Names resolve through the IDB.** A stale or renamed symbol fails to resolve
  (`"Cannot resolve address or name: …"`). Pass a raw `0x…` address if the name is in
  flux.
- **Data addresses have no code signature.** Use `find_xref_signatures`, not
  `make_signature`, for globals/strings/vtables.

---

## 5. Tips for *good*, portable signatures

- **Prefer `make_signature_for_function`** for "find this function again." Function
  entries (the prologue + first distinctive work) are the most stable anchor across
  recompiles.
- **The shortest unique signature is not always the most portable.** A short signature
  riding on one immediate constant breaks if that constant changes; a slightly longer
  one spanning a call + a string-load is more robust. When porting matters, sanity-read
  the pattern rather than trusting length alone.
- **Anchor on a string or constant when you can.** A function that loads a unique
  string is trivially relocatable: `find_xref_signatures` on the string's address gives
  you a signature *at the call site* that survives almost any reshuffle. This is the
  single most reliable cross-build technique in this project — find the CP949 string,
  signature its referrer.
- **Batch it.** All four address-taking tools accept a **list** of addresses/names and
  return one result object per input, so you can signature a whole recovered subsystem
  (every packet handler) in one call and stash the patterns for the next build.
- **Keep `top` small** in `find_xref_signatures` for heavily-referenced data — building
  a signature at every one of hundreds of call sites is slow; you only need a handful
  of short, unique ones.
- **Record the source build.** A signature is only meaningful relative to the image it
  was made from. When you stash one (e.g. in a dirty RE note), record which build's IDB
  produced it and which build you confirmed it against — addresses change, so the
  *pattern* plus its provenance is the durable artifact.

---

## 6. Quick reference

```text
relocate ONE function across builds:
  build A IDB:  make_signature_for_function(addrs="<name>", format="x64dbg")
  build B:      scan the string with PatternFindMem (x32dbg MCP) or IDA binary search
  confirm:      verify prologue + calls + xrefs, then rename in B

relocate a DATA item (string / global / vtable):
  find_xref_signatures(addrs="<data ea>", top=5)   -> signatures at its CODE referrers
  scan one in the new build, read the operand to recover the moved data address

a specific code site (not the entry):   make_signature(addrs="<ea>")
exact byte span you already picked:      make_signature_for_range(start, end)  # end EXCLUSIVE, no auto-extend
```
