# Appcall: Call a Function in the Live Process

`appcall` lets you **invoke a function inside the running debuggee with your own
arguments**, then read the value it returns — without waiting for the program to
call it naturally. It is the fastest way to *test a hypothesis about a function's
behavior*: feed a suspected parser, decryptor, hash, or validator some input you
control and watch what it produces, instead of breakpointing and hoping the app
exercises that path on its own.

This is `idaapi.Appcall` (a.k.a. IDA's "appcall" mechanism) surfaced as two MCP
tools:

| Tool | Ext | Safety | What it does |
|------|-----|--------|--------------|
| `appcall_inspect` | `?ext=dbg` | READ | Parse the prototype, report the arg/return types. **Never executes.** |
| `appcall` | `?ext=probes` | EXECUTE | Resolve+marshal args; with `confirm=True` on a suspended process, **actually calls the function.** |

> EXECUTE-class. `appcall(confirm=True)` runs target code on the target's own
> threads. Treat every call as a deliberate, human-confirmed action — see
> **Safety caveats** at the bottom. Never put it in a probe/run/drain loop.

## When to reach for it

- You found `sub_4031A0` and suspect it's *"decrypt one packet body"*. Rather
  than capturing a live ciphertext and tracing it through, write the ciphertext
  into a scratch buffer and **call the decryptor on it directly**, then read the
  plaintext back.
- You want to confirm a checksum/hash function: call it on a known input and
  compare the return value against the algorithm you reverse-engineered.
- You want to exercise a string/format parser, a coordinate transform, a
  table-lookup, an `atoi`-style converter — any pure-ish function whose output is
  a deterministic function of its inputs.

`appcall` shines for **leaf-ish, side-effect-light functions**. The more global
state, allocation, threading, or I/O a function touches, the more dangerous and
less reproducible a manual call becomes (see caveats).

## Prerequisites

1. A **live debugger session the maintainer already launched** (F9 in IDA). Both
   tools hard-require `ida_dbg.is_debugger_on()` and **never call `dbg_start`**.
   If there's no session you get:
   `"No live debugger session. ... It will NOT call dbg_start."`
2. For an *actual call*, the process must be **SUSPENDED** (`DSTATE_SUSP`).
   Confirm with `dbg_status` first — it should report `state: suspended`.
   `appcall_inspect` and the `appcall` dry-run only need the session to exist;
   they don't require suspension.
3. The right `?ext=` flag on the MCP connection: `appcall_inspect` needs
   `?ext=dbg`, the executing `appcall` needs `?ext=probes`. A combined
   `?ext=dbg,probes` connection has both.

## Step 1 — Write the prototype, inspect it

The `prototype` is a **C function declaration string** that tells IDA the
calling convention, argument types, and return type to marshal. Use the
function's name as a placeholder (any name works; only the types and convention
matter):

```
appcall_inspect(
    ea="0x004031A0",
    prototype="int __cdecl decrypt(unsigned char *buf, int len, unsigned int key);"
)
-> {"resolved_proto":"... @ 0x4031a0",
    "arg_types":["unsigned char *","int","unsigned int"],
    "ret_type":"int", ...}
```

Always `appcall_inspect` **before** you call. It parses the decl through
`ida_typeinf.parse_decl` and shows you exactly how IDA will marshal each slot. If
`arg_types` comes back empty or wrong, your prototype string is malformed or the
convention is wrong — fix it now, before executing anything.

Prototype tips:

- **State the calling convention explicitly**: `__cdecl`, `__stdcall`,
  `__thiscall`, `__fastcall`. For a C++ method, `__thiscall` means the **first
  argument is `this`** (the object pointer in `ecx` on x86) — pass the object
  pointer as `args[0]`.
- A trailing `;` is optional — the tools add one if missing.
- Pointers: declare `char *` / `unsigned char *` / `void *`. You pass an
  **address** (an integer) for a pointer argument — appcall does NOT copy a Python
  bytes object into the target for you. You must place the bytes in target memory
  yourself first (see Step 2).
- Return type drives how the result is interpreted. `int`/`unsigned int` come
  back as a number; a pointer return comes back as an address you then `dbg_read`.

## Step 2 — Stage your input in target memory

For pointer arguments you need real bytes living at a real address in the
debuggee. Two clean options:

**(a) Reuse an existing writable scratch region** — a global buffer, a `.bss`
slot, the top of the current stack below `esp`. Write your input with `dbg_write`:

```
dbg_write([{"addr":"0x00500000",
            "data":"a1b2c3d4e5f6...."}])     # hex string, your ciphertext
```

**(b) Allocate** in the target (via IDAPython `py_eval` /
`ida_dbg.add_virt_module`-free path) if you have no safe scratch — but reusing a
known-idle global is simpler and avoids leaking memory.

Then pass that address as the pointer arg. Example for the decrypt prototype
above, decrypting 64 bytes you just wrote to `0x00500000` with key `0xDEADBEEF`:

```
args = ["0x00500000", 64, "0xDEADBEEF"]
```

Integers may be given as decimal ints or hex strings; the tool marshals them
through the prototype.

## Step 3 — Dry-run first (mandatory discipline)

`appcall` defaults to `confirm=False`, which is a **dry run**: it resolves the
prototype and echoes the marshalled args **without calling anything**.

```
appcall(ea="0x004031A0",
        prototype="int __cdecl decrypt(unsigned char *buf, int len, unsigned int key);",
        args=["0x00500000", 64, "0xDEADBEEF"])
-> {"dry_run":true,
    "resolved_proto":"... @ 0x4031a0",
    "marshalled_args":["0x00500000",64,"0xDEADBEEF"],
    "ret":null, "exception":null}
```

Read it back carefully:

- Is `resolved_proto`'s address the function you meant?
- Are `marshalled_args` the count and values you intended? A missing/extra arg
  here means the prototype's arity disagrees with your `args` list — a real call
  would corrupt the stack.

**Only after the dry run looks correct** do you flip `confirm=True`.

## Step 4 — Execute

```
appcall(ea="0x004031A0",
        prototype="int __cdecl decrypt(unsigned char *buf, int len, unsigned int key);",
        args=["0x00500000", 64, "0xDEADBEEF"],
        confirm=True)
-> {"dry_run":false, "resolved_proto":"... @ 0x4031a0",
    "marshalled_args":[...], "ret":0, "exception":null}
```

`ret` is the function's return value (coerced to `int` when possible, otherwise a
`repr`). If the function decrypts **in place**, the plaintext now lives at your
buffer — read it back:

```
dbg_read([{"addr":"0x00500000","size":64}])   -> {"data":"<hex plaintext>"}
```

Compare that against the algorithm you reversed. If it matches, you've *proved*
the function's role against ground truth — exactly the dirty-room confirmation
step.

## Exceptions and failure modes

`appcall` reports failures in the `exception` field rather than throwing, so you
always get a structured result:

| `exception` value | Meaning / fix |
|---|---|
| `"process must be SUSPENDED to appcall"` | You ran `confirm=True` while the process was running. Stop it (hit a breakpoint, or step) so `dbg_status` shows `suspended`, then retry. |
| `"process not suspended"` (in `error`) | Same cause, surfaced as the top-level error too. |
| A marshalling error string | The prototype didn't match `args` (wrong arity, wrong pointer/int type). Re-`appcall_inspect`. |
| An access-violation / target-side fault string | The function dereferenced a bad pointer (e.g. you passed an address with no valid bytes, or `len` too large). Re-stage the buffer; shrink `len`. |
| `"No live debugger session..."` (in `error`) | No debuggee. The maintainer must F9-launch; the tool will not start one. |

A target-side crash during the call can leave the debuggee at a fault location
or in a degraded state — see caveats. If `ret` is `null` and `exception` is set,
**no useful value was produced**; treat the call as failed, not as "returned 0".

## Safety caveats — read before `confirm=True`

Appcall **hijacks a real thread in the target to run the function**, then
restores context. That is inherently invasive:

1. **It executes target code.** Side effects are *real*: a function that writes
   globals, frees memory, sends a socket, or takes a lock **will do so**. Pick
   leaf/pure functions; avoid anything that touches the network, the heap
   allocator's bookkeeping, or synchronization primitives unless you accept the
   consequences.
2. **A bad call can crash or wedge the process.** Wrong convention, wrong arity,
   or a pointer to garbage → stack imbalance or access violation. The dry-run +
   `appcall_inspect` discipline exists precisely to catch this before it happens.
3. **Re-entrancy / lock deadlock.** If you suspend the process *inside* a
   function that holds a lock, then appcall a function that wants the same lock,
   you deadlock the target. Prefer suspending at a quiescent point (a breakpoint
   on an idle path, not deep inside the subsystem you're calling).
4. **Never inside an automated loop.** `appcall(confirm=True)` is explicitly *not*
   for probe/run/drain automation. The non-stopping probe layer
   (`probe_add`/`run_until`/`probe_drain`, see `debugging-and-tracing.md`) is the
   tool for "observe this function many times"; appcall is for "call it once,
   deliberately."
5. **It mutates live state — protect what you can.** Before a risky call, capture
   a best-effort safety net:

   ```
   snapshot_save("pre_appcall",
                 ranges=[{"addr":"0x00500000","size":256}])
   appcall(..., confirm=True)
   snapshot_restore("pre_appcall")   # rolls back the captured regs + ranges
   ```

   Note `snapshot_save`/`snapshot_restore` are **best-effort**: they restore only
   the named GP registers and the explicit memory ranges you listed — **not** the
   full address space, heap, handles, or thread state. They cannot undo a network
   send or a freed allocation. Use them as a convenience, not a guarantee.
6. **Result is dirty-room.** Like all live-debugger output, an appcall result is
   raw observation of the binary. It crosses the clean-room firewall only as
   neutral prose (the algorithm you confirmed), never as transcribed bytes or
   pseudo-code. The tool tags its result `"_meta":{"dirty":true}` to remind you.

## Quick reference

```
# 1. confirm a suspended session
dbg_status()                              # state: suspended

# 2. understand the prototype (no execution)
appcall_inspect(ea, prototype)

# 3. stage pointer args
dbg_write([{"addr": scratch, "data": "<hex input>"}])

# 4. dry-run to verify marshalling
appcall(ea, prototype, args)              # confirm defaults False

# 5. (optional) safety net
snapshot_save("pre", ranges=[{"addr": scratch, "size": N}])

# 6. execute
appcall(ea, prototype, args, confirm=True)

# 7. read results / roll back
dbg_read([{"addr": scratch, "size": N}])
snapshot_restore("pre")
```

See also: `debugging-and-tracing.md` (the dbg/probe layers and suspension
model), `probe-toolkit.md` (non-stopping observation when you want *many* hits
instead of *one deliberate call*).
