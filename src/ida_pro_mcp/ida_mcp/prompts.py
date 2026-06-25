"""Slash-command prompt guides for the IDA Pro MCP server.

Each ``@prompt`` is surfaced to the client as a reusable guide (prompts/list,
prompts/get). They return guide text describing how to drive a workflow; they do
not call IDA themselves. Keep them in sync with the doc set under ``ida://docs``.
"""

from ._kernel.rpc import MCP_EXTENSIONS, prompt


def _ext_connect_clause(default: str = "dbg") -> str:
    """Render a "?ext=<group,...>" connect clause from the live extension registry.

    Generated at prompt-build time from rpc.MCP_EXTENSIONS so a prompt can never
    name an extension group that does not exist. Falls back to `default` only if
    the registry is somehow empty (e.g. extensions imported lazily). Groups are
    sorted for a stable rendering.
    """
    groups = sorted(g for g in MCP_EXTENSIONS.keys() if g)
    return "?ext=" + (",".join(groups) if groups else default)


@prompt
def probe_workflow() -> str:
    """How to use the non-stopping probe toolkit to observe a live target."""
    ext = _ext_connect_clause()
    return (
        "# Probe workflow (instrument -> run -> drain)\n"
        "\n"
        "Goal: observe a RUNNING target without halting it and without ever\n"
        "calling dbg_start. Requires a live debugger session the maintainer\n"
        f"already launched (F9). Connect with {ext}.\n"
        "\n"
        "1. INSTRUMENT. Install non-stopping probes at addresses of interest:\n"
        "   - probe_add(ea, capture=[...], max_hits=N) for a generic site.\n"
        "     Capture tokens: registers (eax/ecx/...), argN, ret, caller,\n"
        "     mem(<expr>,<n>) e.g. mem(arg1,256).\n"
        "   - trace_calls(ea, conv, argc, capture_ret) for call tracing.\n"
        "   - watch_field(ea|base_ptr, size, mode) for a change-only data\n"
        "     watchpoint (4 HW slots; size 1/2/4, 8 on 64-bit; aligned).\n"
        "   - probe_net(recv_ea, decrypt_ea, send_ea, buf_arg, len_arg) for a\n"
        "     network path (addresses are yours to supply, never hardcoded).\n"
        "2. RUN. run_until(timeout_ms, target_ea=None, probe_id=None) resumes\n"
        "   the target until a probe hits, an address is reached, or timeout.\n"
        "3. DRAIN. probe_drain(since_cursor, filter, limit) pulls records\n"
        "   oldest-first; pass the returned cursor back next call. Use\n"
        "   probe_list() to see hits and probe_clear(probe_id) to tear down.\n"
        "\n"
        "Probe events persist as JSONL under IDA_MCP_PROBE_DIR (defaults to\n"
        "<tempdir>/ida_mcp_probes). See resource ida://docs/probe-toolkit.\n"
    )


@prompt
def crypto_hunt() -> str:
    """Guide for locating the packet cipher and key schedule in the target."""
    ext = _ext_connect_clause()
    return (
        "# Crypto hunt\n"
        "\n"
        "Recover the packet cipher / key schedule so the wire format can be\n"
        "interoperated with. Fuse three angles, then confirm live.\n"
        "\n"
        "1. STATIC SHAPE. Find crypto-shaped loops: dense XOR/ROL/ROR/SHL/SHR\n"
        "   over a buffer with a rolling index. Use the search / disasm tools\n"
        "   and decompile candidates.\n"
        "2. CALL PATH. Walk xrefs out from the socket recv/decrypt path: from\n"
        "   the recv import, to the framing reader, to the in-place transform.\n"
        "3. CONSTANT TABLES. Hunt S-box / key-material: 256-entry byte tables,\n"
        "   large constant arrays referenced inside the loop.\n"
        f"4. CONFIRM LIVE. With {ext}, probe_net(recv_ea, decrypt_ea)\n"
        "   and capture the buffer pre/post transform (place a paired probe at\n"
        "   the decrypt return site) to byte-prove the algorithm.\n"
        "\n"
        "Cross the firewall as a NEUTRAL algorithm description in words and\n"
        "math only - never transcribed code.\n"
    )


@prompt
def opcode_map() -> str:
    """Guide for recovering the opcode -> handler dispatch map."""
    ext = _ext_connect_clause()
    return (
        "# Opcode map\n"
        "\n"
        "Recover the raw opcode -> handler map the network reader dispatches on.\n"
        "\n"
        "1. FIND THE DISPATCH. Locate the large switch / jump table in the\n"
        "   packet reader (the function that consumes a decoded frame and\n"
        "   branches on a type byte/word). disasm + decompile to confirm the\n"
        "   indexed jump and the case range.\n"
        "2. RESOLVE CASES. For each case, resolve the branch target to its\n"
        "   handler function; record (opcode, handler-address) pairs.\n"
        f"3. CONFIRM LIVE. With {ext}, probe the dispatch site and\n"
        "   run_until to observe real opcodes flowing on actual traffic.\n"
        "\n"
        "Promotion to the clean opcode catalogue is a separate step: the clean\n"
        "catalogue carries no addresses, only opcode + name + direction +\n"
        "size + status.\n"
    )


@prompt
def getting_started() -> str:
    """First-session checklist for driving this server end to end."""
    ext = _ext_connect_clause()
    return (
        "# Getting started\n"
        "\n"
        "A fresh-session on-ramp. Full guide: ida://docs/getting-started.\n"
        "\n"
        "0. CONFIRM THE DB. server_health() and server_warmup(), then read the\n"
        "   resource ida://idb/metadata to see WHICH binary is loaded (path,\n"
        "   arch, image base, SHA-256). If it is the wrong/empty IDB, STOP and\n"
        "   report - never fabricate output or reuse old addresses.\n"
        "1. CENSUS. survey_binary() for one-call orientation; list_funcs(),\n"
        "   imports(), list_globals() for the inventory.\n"
        "2. ANCHOR. Start from strings/imports/globals, not 0x401000. find /\n"
        "   find_regex to locate an anchor, xrefs_to / xref_query to follow it.\n"
        "3. READ ONE FUNCTION. disasm + decompile (a hypothesis, not a fact),\n"
        "   callees / callgraph for context, basic_blocks for the switch/loop.\n"
        "4. ANNOTATE. rename / set_comments / declare_type / set_type as facts\n"
        "   firm up (WRITE-class tools; prefer the *_batch variants).\n"
        f"5. CONFIRM LIVE only when static runs out - connect {ext} and use\n"
        "   the dbg_* tools, or the non-stopping probe toolkit. Never dbg_start.\n"
        "\n"
        "See also: ida://docs/overview, ida://docs/re-methodology,\n"
        "ida://docs/ida-pro-essentials, ida://docs/tools-reference.\n"
    )


@prompt
def struct_recovery() -> str:
    """Guide for recovering a C++ struct / object layout and confirming it live."""
    ext = _ext_connect_clause()
    return (
        "# Struct & vtable recovery\n"
        "\n"
        "Recover a C++ object layout from access patterns and prove it.\n"
        "Full guide: ida://docs/struct-and-vtable-recovery.\n"
        "\n"
        "1. FIND THE OBJECT. Locate a function that takes the object as `this`\n"
        "   (ecx on __thiscall) or a base pointer, then decompile it.\n"
        "2. HARVEST OFFSETS. Every `*(base + 0xNN)` access is a field. Record\n"
        "   offset + access width (byte/word/dword) + how it is used (counter,\n"
        "   pointer, flags). xrefs_to_field helps find all readers/writers of a\n"
        "   known offset across the binary.\n"
        "3. DECLARE THE TYPE. declare_type a `struct {...}` with the recovered\n"
        "   fields (pad gaps with reserved bytes), then set_type on the function\n"
        "   so `this` is typed and Hex-Rays renders field names.\n"
        "4. WALK THE VTABLE. If polymorphic, resolve the vtable from its data EA\n"
        "   or installing constructor; role-tag each slot (ctor/dtor, per-frame\n"
        "   virtual, getter, serialize) and harvest RTTI for the class name.\n"
        f"5. CONFIRM LIVE. With {ext}, break where a real instance exists,\n"
        "   grab the pointer from a register, and read_struct / dbg_read at it to\n"
        "   verify field values match the declared layout.\n"
        "\n"
        "Cross the firewall as a neutral offset table - never pasted pseudo-C.\n"
    )


@prompt
def packet_re() -> str:
    """Guide for recovering a network opcode map and packet field layouts."""
    ext = _ext_connect_clause()
    return (
        "# Packet / protocol recovery\n"
        "\n"
        "Recover the opcode->handler map and packet field layouts, then confirm\n"
        "on live traffic. Full guide: ida://docs/opcode-and-packet-re.\n"
        "\n"
        "1. FIND THE RECV DISPATCH. Walk xrefs from the recv import to the\n"
        "   framing reader to the function that branches on a type byte/word.\n"
        "   disasm + decompile to confirm the indexed jump and case range; see\n"
        "   the opcode_map prompt for the dispatch-table step.\n"
        "2. MAP OPCODE -> HANDLER. Resolve each case target to its handler and\n"
        "   record (opcode, handler) pairs.\n"
        "3. INFER FIELD LAYOUT. In each handler, read how the buffer is sliced -\n"
        "   each `*(buf + 0xNN)` read is a field at that offset with that width.\n"
        "   Build the packet struct (see the struct_recovery prompt).\n"
        f"4. CONFIRM LIVE. With {ext}, probe_net(recv_ea, decrypt_ea,\n"
        "   send_ea, buf_arg, len_arg) and run_until to capture real opcodes and\n"
        "   buffer bytes pre/post decrypt, then probe_drain to read them.\n"
        "\n"
        "If bytes look scrambled, the cipher sits between recv and dispatch -\n"
        "see the crypto_hunt prompt and ida://docs/crypto-hunting. Promote to a\n"
        "clean catalogue with NO addresses (opcode + name + direction + size).\n"
    )


@prompt
def debugging_session() -> str:
    """Guide for driving a live debugger / non-stopping trace session."""
    ext = _ext_connect_clause()
    return (
        "# Live debugging session\n"
        "\n"
        "Confirm a static hypothesis against runtime ground truth. Full guides:\n"
        "ida://docs/debugging-and-tracing, ida://docs/watchpoints-and-tracepoints.\n"
        "\n"
        f"0. ENDPOINT. Connect {ext} (superset: dbg_* + probes on top of all\n"
        "   static tools). If dbg_* tools are missing you are on the base /mcp\n"
        "   endpoint. Pilot a session the maintainer already launched - NEVER\n"
        "   call dbg_start.\n"
        "\n"
        "STOPPING MODE (precise, halts the target):\n"
        "  1. dbg_add_bp(ea) at the hypothesized site.\n"
        "  2. dbg_continue() until it hits on a real event.\n"
        "  3. dbg_gpregs / dbg_regs_named to read registers; dbg_read(addr, n)\n"
        "     to read memory (reads THROUGH PAGE_NOACCESS); dbg_stacktrace for\n"
        "     the call chain. dbg_step_over / dbg_step_into to advance.\n"
        "\n"
        "NON-STOPPING MODE (observe without halting - preferred on hot paths):\n"
        "  1. probe_add(ea, capture=[...]) / trace_calls / watch_field to\n"
        "     instrument; watch_field is a HW data watchpoint (4 slots, aligned,\n"
        "     size 1/2/4/8) - a struct-field spy.\n"
        "  2. run_until(timeout_ms) to resume until a probe hits or timeout.\n"
        "  3. probe_drain(cursor, ...) to pull records oldest-first; pass the\n"
        "     returned cursor back next call. See the probe_workflow prompt.\n"
        "\n"
        "To test a parser/decryptor by calling it with your own args while the\n"
        "target is suspended, see appcall and ida://docs/appcall-guide.\n"
    )


__all__ = [
    "probe_workflow",
    "crypto_hunt",
    "opcode_map",
    "getting_started",
    "struct_recovery",
    "packet_re",
    "debugging_session",
]
