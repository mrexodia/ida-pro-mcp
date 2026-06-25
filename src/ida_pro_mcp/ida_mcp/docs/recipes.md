# Recipe Tools: One-Call RE Playbooks

The `api_recipes` family packages the most common multi-step RE chores into a
single `READ`-class call that fans many primitives internally and returns one
structured report. Reach for a recipe when you would otherwise hand-chain
`list_*` -> `xrefs_to` -> `decompile` -> `func_profile` yourself: the recipe does
the chaining server-side and gives you the synthesized answer in one round-trip.

All five tools are **READ** (pure queries, no IDB mutation) and need **no `?ext`
group** — they are part of the base static view.

> The roster below is authoritative as of writing, but the live, generated list
> is always under the `ida://tools` resource (and the family appears in
> `tool-index`). Query that for the current signatures.

---

## The five recipes

### `recipe_function_report(ea, pseudocode_lines=60)`
A complete first-look **dossier on one function**: name, recovered
prototype/signature, the head of its decompiled pseudocode (head-capped to stay
token-cheap), its callers and callees, the strings it references, and a total
xref count — by chaining decompile / prototype / callers / callees / strings /
xref into one response.

- **Use it** as the very first call when you land on an unknown function and want
  the whole picture cheaply, before deciding whether to read it in full.
- **Returns** `addr`, `name`, `prototype`, `pseudocode_head`
  (`pseudocode_truncated` holds the true line count when capped),
  `decompile_error` if Hex-Rays failed, `callers`, `callees`, `strings`,
  `xref_count`.
- **Pro-tip**: a high `xref_count` with a tiny body is usually a hot utility
  (allocator, logger, string helper) — skip reading it.

### `recipe_string_to_code(text, max_matches=50)`
Answers **"where is this message produced?"** Finds every string literal
containing `text`, follows each one's cross-references back to the using code, and
resolves the enclosing function — so an on-screen / logged / protocol string
becomes a short list of the functions that emit it.

- **Use it** when you have a piece of user-visible / logged / protocol text and
  want to jump straight to the producing code.
- **Returns** `query`, `match_count`, `sites` (per-reference `string_addr`,
  `string`, `ref_addr`, `func_addr`, `func_name`), and `functions` (the deduped
  shortlist of enclosing function addresses).
- **Pitfall**: matching is plain **case-sensitive substring**, not regex; a
  string reached via a computed pointer has no xrefs and yields no sites.

### `recipe_import_usage(name)`
Builds a **usage map for one imported API**. Resolves `name` to its import thunk /
IAT entry, finds every call site that reaches it, and resolves each call site's
enclosing function — one call instead of "list imports" then "xrefs to the
import" then "function at each xref".

- **Use it** to find who calls a particular OS / CRT / library function (e.g.
  every caller of `recv` to find the network read path).
- **Returns** `name`, `import_addr` (or `None` if unresolved), `call_site_count`,
  `sites`, and the deduped caller `functions` list.

### `recipe_dispatch_scan(min_cases=8)`
Scans the whole database for **large switch / jump-table constructs** — the
classic shape of an opcode or command dispatcher — and ranks them by approximate
case count, using IDA's recovered switch metadata.

- **Use it** as the opening move when hunting a packet/opcode dispatcher, command
  router, or state machine.
- **Returns** `min_cases`, `candidate_count`, and `candidates` ranked by
  `case_count` descending — each with `addr` (the switch instruction),
  `func_addr` + `func_name`, `case_count`, and `kind`
  (`large_dispatcher` / `dispatcher` / `small_switch`).

### `recipe_crypto_candidates(top=20)`
Statically ranks functions by **how crypto-shaped they look** — bodies that are a
tight loop dominated by XOR / ROL / ROR / SHL / SHR over a buffer. A **neutral
heuristic** that surfaces candidates; it never claims a function IS a cipher.

- **Use it** as the first sweep when hunting a packet cipher, checksum, hash, or
  obfuscation routine, before reading any function.
- **Returns** `top`, `candidate_count`, and `candidates` ranked by `score`
  descending — each with `addr`, `name`, `score`, `ops`, `loop_count`, and
  `reasons`.
- **Pro-tip**: a rotate (`rol`/`ror`) inside a loop is the strongest tell and is
  weighted accordingly — start at the top.

---

## How recipes fit the larger workflows

- **Opcode / packet protocol recovery** — `recipe_dispatch_scan` finds the
  dispatcher; `recipe_string_to_code` jumps from a protocol string to its handler.
  See `opcode-and-packet-re` for the end-to-end loop (then confirm live with
  `probe_net`).
- **Crypto hunting** — `recipe_crypto_candidates` is the static first sweep;
  `recipe_function_report` then gives the full dossier on each top candidate. See
  `crypto-hunting` for walking out from the recv/decrypt path and proving the
  boundary live.
- **Subsystem mapping** — `recipe_import_usage` finds every caller of an API; pair
  it with the `call-hierarchy-russian-doll` workflow to zoom in/out on the
  resulting functions.

Recipes are composites, not magic: when the synthesized report is not quite the
shape you need, fall back to the underlying primitives (`decompile`, `xrefs_to`,
`func_profile`, `entity_query`) or the `py_eval` escape hatch.
