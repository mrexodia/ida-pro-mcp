# 32-bit x86 Calling Conventions & ABI for RE

Most legacy targets (and this server's primary `doida.exe` workload) are **32-bit
MSVC**. Before you can capture a function's arguments — statically or live — you
have to know **where the arguments live**: which are in registers, which are on
the stack, who pops them, and where `this` is. This doc maps the three MSVC
calling conventions onto the exact capture specs you feed `trace_calls` /
`probe_add`, so a live capture reads the *right* slots.

> Tool names below are bare `@tool` names; over the wire they are
> `mcp__ida__<name>` (e.g. `mcp__ida__trace_calls`). The probe/debug tools are
> gated — connect with `?ext=dbg`. `tools/list` is authoritative for schemas.

---

## The one-line mental model

On 32-bit x86 the stack at a callee's **entry** (immediately after the `call`,
before any prologue) looks like this:

```
[esp+0x00] = return address   (the `caller` token)
[esp+0x04] = first stack arg   (argN slot 0)
[esp+0x08] = second stack arg  (argN slot 1)
[esp+0x0C] = third stack arg   ...
```

The capture engine reads stack args from exactly these slots:
`argN` → `[esp + 4*(N+1)]`. So `arg0` is `[esp+4]`, `arg1` is `[esp+8]`, etc.
`caller` is `[esp]`. **This is only valid at function entry** — once the prologue
runs `push ebp; mov ebp, esp; sub esp, ...`, `esp` has moved and the `argN`
offsets are wrong. Always probe the **first instruction** of the function.

---

## The three MSVC conventions

| Convention | `this` | Args | Who cleans the stack | Decompiler tag |
|---|---|---|---|---|
| `__cdecl` | n/a | **all on stack**, right→left push | **caller** (`add esp, N` after the call) | `__cdecl` |
| `__stdcall` | n/a | **all on stack**, right→left push | **callee** (`ret N`) | `__stdcall` |
| `__thiscall` | **ECX** | `this` in ECX, **remaining args on stack** | **callee** (`ret N`) | `__thiscall` |

Key facts for capture:

- **`__cdecl`** — the default for free C functions and **all varargs** functions
  (`printf`, `sprintf`). Args are all on the stack; `arg0`..`argN-1` map cleanly.
  Caller cleans up, so you'll see `add esp, 0xNN` at the **call site** (not in the
  callee) — that `0xNN/4` is the argument count, a handy way to confirm `argc`.
- **`__stdcall`** — the Win32 API convention. Args all on the stack, **same slot
  layout as cdecl**, so the capture spec is identical. The only difference is who
  pops: the callee ends with `ret 0xNN`, and `0xNN/4` is the exact argument count
  — read it straight off the `ret` to pin `argc` without guessing.
- **`__thiscall`** — MSVC C++ member functions. **`ecx = this`**; the *explicit*
  args start on the stack at `[esp+4]`. Callee cleans (`ret N`). This is the one
  that bites people: if you treat a thiscall method as cdecl, `arg0` will read
  the first *explicit* arg, not `this` — you must capture `ecx` separately.

> There is no `__fastcall`-by-default in this codebase's target, but if you meet
> it: MSVC `__fastcall` passes the first two DWORD args in **ECX then EDX**, the
> rest on the stack; callee cleans. Capture `["ecx","edx","arg0",...]`.

---

## Where each thing lives — quick reference

| You want | cdecl | stdcall | thiscall |
|---|---|---|---|
| `this` | — | — | `ecx` |
| 1st explicit arg | `arg0` (`[esp+4]`) | `arg0` | `arg0` (`[esp+4]`) |
| 2nd explicit arg | `arg1` (`[esp+8]`) | `arg1` | `arg1` (`[esp+8]`) |
| return value (int/ptr) | `eax` / `ret` | `eax` / `ret` | `eax` / `ret` |
| 64-bit return | `edx:eax` (hi:lo) | same | same |
| float/double return | `st(0)` (x87) | same | same |
| caller (return site) | `caller` | `caller` | `caller` |

Notes:
- **`eax` is the integer/pointer return.** The `ret` token resolves to `eax` on
  32-bit (`rax` on 64-bit) — capture `ret` only **at the return site**, not at
  entry (at entry `eax` is the *previous* call's leftover).
- **64-bit integer returns** come back in `edx:eax` (high dword in EDX). Capture
  both: `["eax","edx"]`.
- **Float/double returns** are on the x87 stack (`st0`), **not** in eax — a raw
  `eax`/`ret` capture is garbage for a `float`-returning function.
- Struct-by-value returns get a hidden first pointer arg (caller-allocated
  sret); it shifts all your `argN` by one.

---

## Capturing args & `this` live

### thiscall — use `trace_calls` (it adds `ecx` for you)

`trace_calls(ea, conv="thiscall", argc=N)` auto-builds the capture list:
`["caller", "ecx", "arg0", ..., "arg{N-1}"]`. The `ecx` token *is* `this`.

```
trace_calls(ea="0x004031A0", conv="thiscall", argc=3)
run_until(timeout_ms=5000)              # maintainer triggers the event in-app
probe_drain(since_cursor=0, filter={"probe_id":"..."})
```

Each drained record then has `ecx` (the `this` pointer), `arg0..arg2` (the
explicit args as hex), and `caller`. Feed `ecx` to `read_struct_live(ecx,
"YourClass")` to overlay a recovered layout on the live object.

### cdecl / stdcall — same call, different `conv`

```
trace_calls(ea="0x00405500", conv="cdecl",  argc=4)   # no ecx in the spec
trace_calls(ea="0x00405500", conv="stdcall", argc=4)  # identical slot layout
```

For cdecl/stdcall the spec is `["caller","arg0",...,"arg{N-1}"]` — no `ecx`,
because there is no implicit `this`.

### Hand-rolled `probe_add` capture specs

When you want exactly the slots you need (and to dereference args), build the
spec yourself. `probe_add(ea, capture=[...])` defaults to `conv="cdecl"` for its
`argN` math — **pass `conv="thiscall"` only matters if you use `argN`; `ecx` is
read directly regardless.**

```
# thiscall method: grab this, two args, and 64 bytes of the object at this+0
probe_add(ea="0x004031A0",
          capture=["ecx", "arg0", "arg1", "mem(ecx,64)"],
          max_hits=256)

# a packet handler: opcode in arg0, buffer ptr in arg1, dump 256 bytes of it
probe_add(ea="0x00408000",
          capture=["arg0", "arg1", "mem(arg1,256)"],
          condition="int(c['arg0'],16) == 0x1F",   # only opcode 0x1F
          max_hits=64)
```

`mem(<expr>, <n>)` evaluates `<expr>` over the live regs / `argN` / `caller` /
hex literals, so `mem(arg1+0x10, 128)` dumps a field inside the struct an arg
points at, and `mem(ecx+0x2C, 4)` reads a single member. This is how you turn a
"pointer arg" into the **bytes it points at** in one capture.

### Capturing the return value

`eax` at entry is meaningless. To get the return value, capture `ret` **at the
return site**. `trace_calls(..., capture_ret=True, auto_return=True)` tells you
where that site is: on the first entry hit, drain the probe, read its `caller`
value (the instruction after the `call`), and place a probe there:

```
trace_calls(ea="0x00405500", conv="cdecl", argc=2, capture_ret=True)
run_until(timeout_ms=4000)
page = probe_drain(since_cursor=0, filter={"probe_id":"<entry_id>"})
ret_site = page["records"][0]["caller"]      # e.g. "0x004061C7"
probe_add(ea=ret_site, capture=["ret"], max_hits=64)   # eax at return
```

---

## Varargs (`__cdecl` only)

Variadic functions are **always `__cdecl`** (the callee can't know the arg count,
so the caller must clean up). There is no register magic — every variadic arg is
a stack slot after the fixed args:

```
int sprintf(char *dst, const char *fmt, ...);
   arg0 = dst        [esp+4]
   arg1 = fmt        [esp+8]
   arg2 = first vararg  [esp+0xC]
   arg3 = second vararg [esp+0x10]
```

To capture a format string and its first variadic value:

```
probe_add(ea="<sprintf_ea>",
          capture=["arg0", "arg1", "mem(arg1,128)", "arg2"],
          max_hits=128)
```

`mem(arg1,128)` dumps the format string bytes (CP949 — decode with code page 949,
not UTF-8). The number/width of varargs is whatever the format string implies;
the ABI gives you no count, so read the `fmt` to know how many slots are live.

---

## Confirming a convention before you capture

Never assume — confirm against the loaded DB:

1. **Read the prototype.** `decompile` / function info shows IDA's inferred tag
   (`__thiscall`, `__cdecl`, `__stdcall`). IDA's guess is usually right but can
   be wrong on indirect/vtable calls — verify with the disassembly.
2. **Look at the epilogue.** `ret 0xNN` ⇒ callee-cleans ⇒ **stdcall or
   thiscall**, and `0xNN/4` is the stack-arg count. Bare `ret` ⇒ caller-cleans ⇒
   **cdecl** (or thiscall with 0 stack args).
3. **Look at the call site.** `add esp, 0xNN` right after the `call` ⇒
   caller-cleans ⇒ **cdecl/varargs**, and `0xNN/4` is the arg count.
4. **Look for ECX setup.** A `mov ecx, <ptr>` or `lea ecx, ...` immediately
   before the `call` ⇒ **thiscall** (ecx = this). No ecx load ⇒ free function.

Cross-check the recovered `argc` from the `ret N` / `add esp, N` against your
`trace_calls(argc=...)` — if they disagree, your captured `argN` slots are
shifted and the high args will be garbage.

---

## Pitfalls

- **Probing past the prologue.** Capture at the function's **first byte**. If you
  probe after `push ebp; mov ebp,esp`, `esp` has shifted by 4 and every `argN`
  (and `caller`) is off by one slot. (`mem(ebp+8,...)` is the post-prologue
  equivalent of `arg0`, if you must probe later.)
- **Treating a thiscall method as cdecl.** You'll miss `this` entirely and read
  `this`'s explicit args one slot early — capture `ecx`.
- **Reading `ret`/`eax` at entry.** It's the previous call's return value. Only
  capture `ret` at the return site (see above).
- **Float returns via `eax`.** `st0`, not `eax`. A float-returning function's
  `eax` is junk.
- **64-bit return truncation.** Grab `edx` too (`edx:eax`).
- **Hidden sret pointer.** A struct-by-value return inserts a hidden pointer as
  `arg0`, pushing every real arg down one — your indices are all +1.
- **stdcall vs cdecl have identical capture specs** — the only observable
  difference is *who pops*; don't waste time distinguishing them just to capture
  args (you only need the right `argc`).
- **CP949 text.** String args (paths, names, format strings) in this target are
  Korean code page 949 — decode `mem(...)` dumps with cp949, never UTF-8.
