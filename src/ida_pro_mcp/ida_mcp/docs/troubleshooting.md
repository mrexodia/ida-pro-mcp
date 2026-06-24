# Troubleshooting This Server

A symptom -> cause -> fix field guide for the failures that actually stop a
session: no debugger, `BADADDR`, missing Hex-Rays license, ungated `?ext`
groups, idalib-vs-GUI confusion, and CP949 text. Each entry tells you what you
*see*, why it happens, and the exact tool call or change that fixes it.

When in doubt, start with the two cheapest sanity calls — they pre-empt half the
entries below:

```
server_health()                  # is a DB open and the server alive?
resources/read  ida://idb/metadata   # WHICH binary, arch, base, hashes
```

---

## 1. "No debugger session" / process not suspended

**Symptom.** A `dbg_*` or probe call returns an `isError` response such as
*"debugger is not running"* / *"process is not suspended"*, or `dbg_gpregs` /
`dbg_read` / `dbg_step_over` fail even though IDA looks like it is debugging.

**Cause.** The `dbg_*` (`api_debug`) and probe (`api_probes`) tools **hard-require
a debugger that is already running**, and the register/memory/step tools further
require the process to be in `DSTATE_SUSP` (suspended). A `dbg_continue` that
left the target running, a target that already exited, or a session that was
never launched all produce this. This is *not* the same as the extension-gating
error in §4 — here the tool is visible and reachable; the debuggee state is
wrong.

**Fix.** Probe the lifecycle before anything else and act on the state:

```
dbg_status()    -> {"state": "running" | "suspended" | "not_running", "ip": ...}
```

- `not_running` — the maintainer must F9-launch the client. **Do not call
  `dbg_start` yourself** in this project (it detaches/desyncs ground truth and
  its return code lies — `start_process` returns -1 even on success).
- `running` — wait for a breakpoint to hit, or, with probes installed, use
  `run_until(timeout_ms=...)` which resumes and pumps `wait_for_next_event` in
  ~100 ms slices until a hit/timeout — it *waits for you* instead of failing.
- `suspended` — you are good; read registers/memory **now, before stepping**
  (`dbg_step_over` mutates `eax`/flags).

Pro-tip: a breakpoint that never fires is usually a rebased address (§ below),
the wrong thread, an unmapped module, or a code path the user never triggered —
not a server bug. `probe_list` / `probe_drain` are `@safety("READ")` and ungated,
so you can drain an existing ring even when no live session is attachable.

## 2. `is_debugger_on` / how to gate dynamic work safely

**Symptom.** You want to run a dynamic step but are unsure a live session exists,
so calls intermittently fail; or an automated sweep blindly calls `dbg_read` and
errors out on the static legs.

**Cause.** There is no single boolean to "just check" before every call from the
client side — the authoritative source of truth is `dbg_status()` (and, inside
IDAPython via `py_eval`, `idaapi.is_debugger_on()`). Treating "IDA is open" as
"debugger is live" is the mistake.

**Fix.** Make the liveness check explicit and branch on it:

- From the MCP client: call `dbg_status()` first and only proceed to
  register/memory tools when `state == "suspended"`.
- From IDAPython (e.g. inside a `py_eval`/`py_exec_file` helper): guard with
  `idaapi.is_debugger_on()` and `idaapi.get_process_state()` before touching
  `dbg_read_memory` / register APIs. If it returns false, emit a clear result var
  rather than throwing — the EXECUTE-class Python tools surface your result, so a
  graceful `{"error": "no live debugger"}` is far more useful than a traceback.

Rule of thumb: static recovery forms the hypothesis; the debugger *confirms* it.
Never block static progress on a debugger that is not up — fall back to `disasm`
/ `decompile` / `get_bytes` and revisit the dynamic confirm when the maintainer
launches.

## 3. `BADADDR` returned where you expected an address

**Symptom.** A resolver tool or `py_eval` snippet returns `0xFFFFFFFF` (32-bit
`doida.exe`) or `0xFFFFFFFFFFFFFFFF` (64-bit), and downstream calls that take an
`ea` then fail or read garbage. Or `if ea:` "works" until it silently doesn't.

**Cause.** `BADADDR` is IDA's not-found sentinel, and it is **all-ones, not 0** —
`get_name_ea`, `next_head`, `get_first_cref_to`, `Functions()` boundaries, etc.
return it when there is nothing there. `if ea:` is true for `BADADDR` (it is
nonzero), so the failure leaks past the guard and you paste an invalid address
into the next tool.

**Fix.**

- Always test `ea == idaapi.BADADDR` (or `== 0xFFFFFFFF` for the 32-bit target),
  **never** the truthiness of `ea`. A valid EA can legitimately be small; the
  sentinel is the big all-ones value.
- If a name/string resolver returns `BADADDR`, the symbol genuinely is not in
  this IDB — re-check the name spelling/mangling and confirm the right DB is
  loaded (`ida://idb/metadata`) before assuming the feature is missing.
- Remember IDA ranges are `[start, end)` (end exclusive): a function's last byte
  is `end_ea - 1`. Stepping `+1` from `next_head` lands mid-instruction — use
  `get_item_size`.
- If a *resource* read returns empty where you expected data, the DB may simply
  be mid-analysis — `server_warmup()` / let auto-analysis finish before
  concluding "it isn't there." Empty != `BADADDR`; don't conflate the two.

## 4. `?ext` group not enabled (dbg / probes tools missing or refusing)

**Symptom.** The `dbg_*` / `probe_*` / `appcall` tools do not appear in
`tools/list`, OR calling one returns an `isError` response that explains how to
enable its group.

**Cause.** Those tools are decorated with `@ext("dbg")` / `@ext("probes")` and
are **hidden by default**; they only register when the client connects with the
matching `?ext=` query parameter. The committed `.mcp.json` should already use
the debugger-extended endpoint, but a session connected to the bare `/mcp` is
static-only.

**Fix.** Connect on the extension-enabled endpoint (the `?ext=dbg` endpoint is a
**superset** — it surfaces the `dbg_*` and probe tools *in addition to* every
static tool):

```
http://127.0.0.1:13337/mcp?ext=dbg            # debugger tools
http://127.0.0.1:13337/mcp?ext=dbg,probes      # debugger + non-stopping probes
```

Re-register the server on the right endpoint if needed:

```powershell
claude mcp add --transport http ida "http://127.0.0.1:13337/mcp?ext=dbg"
```

Notes:
- Combine groups with a comma (`?ext=dbg,probes`); order does not matter.
- `probe_list` / `probe_drain` are ungated (`@safety("READ")`) — they work from a
  static connection, but the *installers* (`probe_add`, `run_until`,
  `watch_field`, `trace_calls`, `probe_net`, `appcall`) need `?ext=probes`.
- If `dbg_*` is missing you are simply on the wrong endpoint — this is a
  connection-string fix, not a server restart.

## 5. Missing / unlicensed Hex-Rays decompiler

**Symptom.** `decompile` (and anything that depends on pseudocode, e.g. a
decompile-one export) returns an `isError` / empty result mentioning the
decompiler being unavailable or no license, while `disasm`, `get_bytes`, xrefs,
types and the rest of the static tools work fine.

**Cause.** Hex-Rays decompilation is a **separately-licensed IDA add-on** and is
also architecture-specific (an x86 decompiler license does not decompile ARM).
If the loaded IDA install lacks the matching Hex-Rays license, every pseudocode
path fails even though disassembly is fully available.

**Fix.**

- Confirm the target arch from `ida://idb/metadata` and verify a Hex-Rays
  license for *that* architecture is installed in this IDA. There is no
  server-side workaround — the server only exposes what the local IDA can do.
- Work from `disasm` instead: it is the **ground truth** anyway (pseudocode is an
  interpretation that can mis-type, miss tail calls, and invent locals). For
  protocol/struct recovery, disassembly + xrefs + `read_struct` overlays get you
  there without the decompiler.
- If decompilation *was* working and suddenly returns stale/empty output after a
  rename or `set_type`, that is the **cache**, not the license — `force_recompile`
  (or re-`decompile`) to refresh, and fix a wrong prototype with `set_type`
  *first* so the whole pseudocode snaps into place.

## 6. idalib (headless) vs in-GUI (this server's mode)

**Symptom.** A `py_eval` / `py_exec_file` snippet that opens a database
(`ida_domain.Database.open(path=...)`, idalib setup, `IDADIR` juggling) fails,
spins up a *second* kernel, or operates on the wrong DB; or you try to
`dbg_start` headlessly and nothing attaches.

**Cause.** This MCP server runs **in-process inside the live IDA GUI**, not as a
standalone idalib interpreter. `Database.open` forks on its argument: a **path**
opens a *new headless kernel* (idalib mode), while **no arguments** attaches to
the *already-open* database. Passing a path from inside the server tries to boot
a second kernel against the same IDB — wrong DB, contention, or outright failure.
idalib/`IDADIR` setup only applies to truly standalone scripts.

**Fix.**

- Inside the server (the normal case), **never pass a path** — use
  `ida_domain.Database.open()` with no arguments to grab a handle to the live DB,
  or just use raw IDAPython (`idautils`/`ida_funcs`/`ida_bytes`) directly, which
  already targets the open database.
- Run the `dbg_*` tools against the maintainer's F9-launched session; **never
  `dbg_start`** and never try to launch a debuggee from a headless kernel.
- Reserve idalib (`Database.open(path=..., save_on_close=False)`) for genuinely
  out-of-process batch tooling that is *not* going through this MCP server. If you
  see two databases in play, you have accidentally crossed this line.

## 7. CP949 / Korean text decodes as garbage

**Symptom.** A string field reads as mojibake, truncates early, or a "10-letter"
Korean label looks far longer in bytes; `get_string` returns a mangled or
clipped value.

**Cause.** All game text in the Martial Heroes client is **CP949 (Korean
code page 949)**, *not* UTF-8/ASCII. Decoding CP949 bytes as ASCII yields
garbage; and `get_string`'s C-string assumption stops at the first `0x00`, which
truncates length-prefixed wire strings (these are often **not** null-terminated).
CP949 is also multi-byte, so character count != byte count.

**Fix.**

- **Hexdump first, decode second.** When a string looks wrong, pull the raw bytes
  (`get_bytes`) and identify the encoding before trusting any decoded view.
- Decode with code page 949 explicitly. In C#/.NET tooling you must register the
  provider **once** or CP949 throws:

  ```csharp
  Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
  var cp949 = Encoding.GetEncoding(949);
  ```

  In IDAPython, decode the bytes yourself: `data.decode("cp949")` (Python ships
  the `cp949` codec) rather than relying on a C-string reader.
- For wire/file strings, treat them as **length-prefixed**, not null-terminated —
  read the length field and slice exactly that many *bytes* (never size a buffer
  by character count). A `get_string` that stops short is the tell that you hit
  an embedded `0x00` inside a length-delimited blob.

---

### Fast triage order

1. `server_health()` — is a DB even open and the server alive?
2. `ida://idb/metadata` — is it the *right* binary (arch/base/hashes)?
3. Missing `dbg_*`/`probe_*` tools -> reconnect on `?ext=dbg[,probes]` (§4).
4. `dbg_*` errors -> `dbg_status()`; act on `not_running`/`running`/`suspended` (§1, §2).
5. `decompile` empty -> Hex-Rays license/arch, or just a stale cache (§5).
6. `0xFFFFFFFF` back from a resolver -> it's `BADADDR`; the symbol isn't there (§3).
7. Garbled strings -> hexdump then decode as CP949 (§7).
8. A second database appeared -> you passed a path to idalib from in-GUI (§6).
