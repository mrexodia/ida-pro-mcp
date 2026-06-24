# Pro-Tips & Pitfalls

A dense, scannable field guide to IDA, reverse engineering, and this MCP server.
Each line is a standalone tip, trick, or trap. Skim for the one that fits your
current wall. Tool names are this server's real tools (`decompile`, `set_type`,
`get_bytes`, `dbg_read`, …).

---

## Ground truth & sanity

- **Trust the database, not your memory.** Confirm every offset/opcode/constant in IDA before writing it down — analogy is how wrong specs are born.
- **Verify which DB is loaded first.** Read `ida://idb/metadata` (path, arch, base, hashes) before trusting any output; the wrong/empty IDB silently produces plausible garbage.
- **Pin the IDB SHA in your notes.** When you cite a fact, also note the binary hash — a re-analysis or different build invalidates raw addresses.
- **If the server returns empty/None where you expect data, the DB may not be analyzed yet** — run `server_warmup` / let auto-analysis finish, don't conclude "it isn't there."
- **Static forms the hypothesis; the debugger confirms it.** Never ship a load-bearing fact on decompiler output alone if a breakpoint can prove it.

## Address math (where hours die)

- **`BADADDR` is not 0 — it's all-ones** (`0xFFFFFFFF` / `0xFFFFFFFFFFFFFFFF`). Always test `ea == BADADDR`, never `if ea:` (a valid EA can be 0-ish; image base usually isn't, but don't assume).
- **Off-by-one on ranges:** IDA ranges are `[start, end)` — `end` is exclusive. A function's last byte is `end_ea - 1`, not `end_ea`.
- **`next_head`/`prev_head` walk DEFINED items, not bytes.** Stepping by `+1` lands mid-instruction; step by item length (`get_item_size`) or use head navigation.
- **Image base ≠ file offset ≠ runtime VA.** Static EA = preferred base + RVA; under the live debugger the module may be rebased — translate, don't paste a static EA into `dbg_read`.
- **Struct field at `+0x10`** means byte offset 16; don't confuse element index with byte offset on arrays (`idx * elemsize`).
- **Segment boundaries:** an EA just past a segment end belongs to the *next* segment (or none) — `get_segm_name` returns empty/None there, which reads as "no data" when it's really "wrong address."
- **32-bit vs 64-bit pointer size** changes every struct stride. A vtable of 4-byte slots in `doida.exe` (32-bit) is not 8-byte — verify with the binary's bitness from metadata.

## Decompilation & disassembly

- **Hex-Rays output is an interpretation, not the binary.** `disasm` is the source of truth; `decompile` is a convenience that can mis-type, miss tail calls, and invent locals.
- **A wrong function prototype poisons the whole pseudocode.** Fix the signature with `set_type` first, then re-`decompile` — variable types and call sites snap into place.
- **`__thiscall` / `ecx`-passed `this`** is often shown as a bare local — set the calling convention on the prototype so `this->field` decoding appears.
- **`_DWORD *` casts everywhere = missing struct.** Recover the type (`declare_type`), apply it (`set_type` / `type_apply_batch`), then the `*(a1+8)` noise becomes named fields.
- **Decompiler caches per function.** After a rename/retype, force a refresh (`force_recompile`) or you'll keep reading the stale tree — see *Stale caches* below.
- **Tail-call / no-return functions** truncate the decompilation early. If pseudocode ends abruptly, check for `__noreturn` and `jmp`-style tail calls in `disasm`.
- **Switch tables** may not be auto-recovered; if a dispatch looks like a single indirect `jmp`, hunt the jump table manually (this is the usual cause of "missing" opcode handlers).

## Types, structs & enums

- **Apply types in dependency order:** declare leaf structs/enums before the structs that embed them, or `declare_type` rejects the forward reference.
- **`type_apply_batch` over many `set_type` calls** — one batch is faster and atomic-ish; per-call retyping triggers repeated reanalysis.
- **Size mismatch on apply = silent misread.** If your struct is bigger than the data region, neighboring fields get clobbered in the view; cross-check `sizeof` against the access stride you observed.
- **Enums make dispatch readable.** Promote opcode/flag immediates to an enum (`enum_upsert`) so `case 0x42:` reads as `case OP_LOGIN:` across every xref.
- **Pack matters.** Wire/file structs are usually `#pragma pack(1)`; an IDA struct with default alignment inserts phantom padding and shifts every later field — declare packed layouts explicitly.
- **`read_struct` overlays a type onto bytes** — verify the type first; overlaying the wrong type returns confidently-wrong named fields.
- **Bitfields and unions** rarely auto-recover; reading the same offset as two sizes across call sites is the tell for a union.

## Search & xrefs

- **Strings are the fastest subsystem locator.** Xref a UI/log/error string (`xrefs_to`) to land directly in the relevant function — faster than reading callgraphs cold.
- **`find_bytes` vs `find_regex` vs `search_text`:** bytes for opcode/signature patterns, regex for disasm-text patterns, `search_text` for the listing. Pick by what you actually know.
- **A constant with many xrefs is a key/seed/table base** — `xref_query` a magic number to find every site that consumes it (great for crypto/format hunting).
- **`xrefs_to_field`** finds every access to one struct member — use it to confirm a field's real width/role across all readers/writers.
- **Wildcards in signatures:** mask out relocated/variable bytes (call targets, immediates) or your `find_bytes` pattern matches only the one sample you built it from.
- **No xrefs ≠ unused.** Data reached only via computed pointers (vtables, jump tables, runtime fixups) shows zero xrefs — don't assume dead code.

## Debugging & tracing (`?ext=dbg`)

- **Never call `dbg_start`** in this workflow — the maintainer F9-launches; you pilot the existing live session. Starting your own detaches/desyncs ground truth.
- **`dbg_read` reads THROUGH `PAGE_NOACCESS`** — it can pull guard-page / decrypted-buffer memory a normal read would fault on. Use it for cipher pre/post buffers.
- **Translate static EA → runtime EA** before `dbg_add_bp` if the module is rebased (ASLR/relocation). A breakpoint at a stale VA simply never hits.
- **Breakpoint that never fires?** Wrong thread, not-yet-loaded module, rebased address, or the path is never exercised — confirm the module is mapped and trigger the real event (send the packet, click the button).
- **Read registers AT the breakpoint, before stepping.** `dbg_step_over` mutates `eax`/flags; capture `dbg_gpregs` first, then step.
- **`argN` layout depends on convention.** cdecl/stdcall args are on the stack at entry; `__thiscall` puts `this` in `ecx`. Reading "arg1" as a stack slot for a thiscall method gives you the wrong value.
- **`caller` = `[esp]` at function entry** (the return address) — only valid *at entry*, before the prologue pushes. After prologue, recompute via the frame.
- **Use probes to watch a value flow without halting** (`?ext=dbg`): probes return `False` so the process keeps running — far better than single-stepping a hot loop.
- **Hardware data watchpoints are scarce: 4 DR slots, size 1/2/4 (8 on x64), naturally aligned.** Misaligned or oversized = silently no fire. `watch_field` records only on change.
- **`appcall` EXECUTES target code** — single, human-confirmed, never in a loop; a bad prototype corrupts the stack and crashes the debuggee.

## Performance & throughput

- **Cap your reads.** Pull bounded slices (`get_bytes` with a sane length, `disasm` line limits, `analyze_batch` over a function set) instead of dumping whole segments into context.
- **Batch the IDB writes.** This server is built to run wide — fan out parallel reads and use `type_apply_batch` / `append_comments` over many singletons; retry on conflict rather than throttling.
- **Decompiling everything is slow and noisy.** Triage with strings/xrefs/`func_profile` to the handful of functions worth a full `decompile`.
- **`func_query` / `entity_query` / `list_funcs` with filters** beat client-side filtering of a full dump — push the predicate to the server.
- **Avoid re-deriving settled facts.** Check the committed specs first; only re-open a question when the binary actually disputes the doc.

## Encoding (CP949 / Korean text)

- **Game text is CP949, not UTF-8/ASCII.** `get_string` on Korean strings needs the right codec; raw bytes look like garbage if decoded as ASCII.
- **In Python tooling, register the provider once:** `Encoding.RegisterProvider(CodePagesEncodingProvider.Instance)` then `Encoding.GetEncoding(949)` — without it, code page 949 throws.
- **A CP949 string is multi-byte:** a "10-character" Korean label is >10 bytes — never size a buffer by character count; size by byte length.
- **Hexdump first, decode second.** When a string field looks wrong, dump the bytes (`get_bytes`) and identify the encoding before trusting any decoded view.
- **Null-termination vs length-prefixed:** wire strings are often length-prefixed (not null-terminated). `get_string`'s C-string assumption stops at the first `0x00` and truncates.

## Stale caches (the silent liar)

- **Decompiler cache:** after `rename` / `set_type` / struct apply, the cached pseudocode is stale — `force_recompile` (or re-`decompile`) before reading.
- **Strings cache:** this server caches the strings list; after defining new strings/data call `invalidate_strings_cache` or you'll search an old snapshot.
- **Auto-analysis lag:** right after `define_func` / `define_code` / `make_data`, dependent views may be mid-reanalysis — let it settle (`server_warmup`) before querying results.
- **`diff_before_after`** confirms a write actually changed what you intended — use it to catch a no-op edit (wrong EA, already-applied) before moving on.
- **Save deliberately.** `idb_save` persists your annotations; a crash loses uncommitted renames/types. Save after a meaningful batch, not after every micro-edit.
- **Resource reads are point-in-time.** `ida://idb/segments` etc. reflect the DB at read time; re-read after structural edits rather than reusing an old payload.

## Clean-room discipline (non-negotiable here)

- **Never paste Hex-Rays pseudo-C** (`sub_xxxx`, `loc_xxxx`, `_DWORD`, `__thiscall`, `*(_DWORD*)…`, mangled names) into any committed file or C#. Decompiler output stays in the dirty quarantine.
- **Cross the firewall as neutral prose + math only** — describe the algorithm/layout in your own words; do not transcribe code.
- **Cite the spec, not the binary, in implementation code:** `// spec: Docs/RE/formats/terrain.md`. No raw addresses in shipped artifacts.
- **Don't commit originals** (`*.exe`, `*.vfs`, captures, autonames) or anything under `_dirty/`.

---

### Fast triage checklist

1. Confirm the right IDB is loaded (`ida://idb/metadata`).
2. Find the subsystem via a string xref, not by reading cold.
3. Fix the function prototype, then decompile.
4. Recover & apply the struct/enum; re-decompile.
5. Confirm the load-bearing fact under the live debugger (`?ext=dbg`).
6. Write it as neutral prose; cite the spec; save the IDB.
