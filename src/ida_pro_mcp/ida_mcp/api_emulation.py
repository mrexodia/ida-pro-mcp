"""Function emulation via Unicorn Engine for IDA Pro MCP.

Provides tools to emulate functions and shellcode with controlled inputs,
letting the LLM verify hypotheses by running code in a sandboxed CPU emulator.

Requires optional dependency: pip install unicorn
"""

from typing import Annotated

from .rpc import tool, ext, unsafe
from .sync import idasync, tool_timeout, IDAError
from .utils import parse_address

try:
    import unicorn
    from unicorn import x86_const, arm_const

    HAS_UNICORN = True
except ImportError:
    HAS_UNICORN = False

_UNICORN_MISSING = {
    "error": "Unicorn engine not installed. Install with: pip install unicorn"
}

# Stack layout constants
_STACK_ADDR = 0x7F000000
_STACK_SIZE = 0x100000  # 1 MB
_AUTO_MAP_SIZE = 0x1000  # 4 KB pages for auto-mapping

# Sentinel return address: emulation stops when execution reaches here.
# Chosen to be in unmapped space; the fetch-unmapped hook aborts emulation.
_SENTINEL_RET_ADDR = 0xDEAD0000

# Win64 shadow space (32 bytes reserved above return address)
_WIN64_SHADOW_SIZE = 32

# x64 argument registers per ABI
_X64_ARG_REGS_SYSV = [
    x86_const.UC_X86_REG_RDI,
    x86_const.UC_X86_REG_RSI,
    x86_const.UC_X86_REG_RDX,
    x86_const.UC_X86_REG_RCX,
    x86_const.UC_X86_REG_R8,
    x86_const.UC_X86_REG_R9,
] if HAS_UNICORN else []

_X64_ARG_REGS_WIN = [
    x86_const.UC_X86_REG_RCX,
    x86_const.UC_X86_REG_RDX,
    x86_const.UC_X86_REG_R8,
    x86_const.UC_X86_REG_R9,
] if HAS_UNICORN else []

# x64 GP registers for final state reporting
_X64_GP_REGS = {
    "rax": x86_const.UC_X86_REG_RAX,
    "rbx": x86_const.UC_X86_REG_RBX,
    "rcx": x86_const.UC_X86_REG_RCX,
    "rdx": x86_const.UC_X86_REG_RDX,
    "rsi": x86_const.UC_X86_REG_RSI,
    "rdi": x86_const.UC_X86_REG_RDI,
    "rbp": x86_const.UC_X86_REG_RBP,
    "rsp": x86_const.UC_X86_REG_RSP,
    "r8": x86_const.UC_X86_REG_R8,
    "r9": x86_const.UC_X86_REG_R9,
    "r10": x86_const.UC_X86_REG_R10,
    "r11": x86_const.UC_X86_REG_R11,
    "r12": x86_const.UC_X86_REG_R12,
    "r13": x86_const.UC_X86_REG_R13,
    "r14": x86_const.UC_X86_REG_R14,
    "r15": x86_const.UC_X86_REG_R15,
    "rip": x86_const.UC_X86_REG_RIP,
} if HAS_UNICORN else {}

# x86 (32-bit) GP registers
_X86_GP_REGS = {
    "eax": x86_const.UC_X86_REG_EAX,
    "ebx": x86_const.UC_X86_REG_EBX,
    "ecx": x86_const.UC_X86_REG_ECX,
    "edx": x86_const.UC_X86_REG_EDX,
    "esi": x86_const.UC_X86_REG_ESI,
    "edi": x86_const.UC_X86_REG_EDI,
    "ebp": x86_const.UC_X86_REG_EBP,
    "esp": x86_const.UC_X86_REG_ESP,
    "eip": x86_const.UC_X86_REG_EIP,
} if HAS_UNICORN else {}

# ARM GP registers
_ARM_GP_REGS = {
    "r0": arm_const.UC_ARM_REG_R0,
    "r1": arm_const.UC_ARM_REG_R1,
    "r2": arm_const.UC_ARM_REG_R2,
    "r3": arm_const.UC_ARM_REG_R3,
    "r4": arm_const.UC_ARM_REG_R4,
    "r5": arm_const.UC_ARM_REG_R5,
    "r6": arm_const.UC_ARM_REG_R6,
    "r7": arm_const.UC_ARM_REG_R7,
    "r8": arm_const.UC_ARM_REG_R8,
    "r9": arm_const.UC_ARM_REG_R9,
    "r10": arm_const.UC_ARM_REG_R10,
    "r11": arm_const.UC_ARM_REG_R11,
    "r12": arm_const.UC_ARM_REG_R12,
    "sp": arm_const.UC_ARM_REG_SP,
    "lr": arm_const.UC_ARM_REG_LR,
    "pc": arm_const.UC_ARM_REG_PC,
} if HAS_UNICORN else {}

# ARM argument registers (AAPCS: r0-r3)
_ARM_ARG_REGS = [
    arm_const.UC_ARM_REG_R0,
    arm_const.UC_ARM_REG_R1,
    arm_const.UC_ARM_REG_R2,
    arm_const.UC_ARM_REG_R3,
] if HAS_UNICORN else []


def _is_windows_binary():
    """Return True if the loaded binary is a PE file (Windows ABI)."""
    import ida_ida
    return ida_ida.inf_get_filetype() == ida_ida.f_PE


def _get_arch_config(func_ea=None):
    """Determine Unicorn arch/mode from IDA's current processor.

    Must be called from IDA main thread (inside @idasync context).
    When *func_ea* is provided, ARM Thumb mode is auto-detected.
    Returns (uc_arch, uc_mode, sp_reg, ret_reg, gp_regs, arg_regs, ptr_size)
    or raises IDAError.
    """
    import idaapi
    import idc
    from . import compat

    proc_id = idaapi.ph.id
    is_64 = compat.inf_is_64bit()

    # PLFM_386 = x86 family
    if proc_id == idaapi.PLFM_386:
        if is_64:
            arg_regs = _X64_ARG_REGS_WIN if _is_windows_binary() else _X64_ARG_REGS_SYSV
            return (
                unicorn.UC_ARCH_X86,
                unicorn.UC_MODE_64,
                x86_const.UC_X86_REG_RSP,
                x86_const.UC_X86_REG_RAX,
                _X64_GP_REGS,
                arg_regs,
                8,
            )
        else:
            return (
                unicorn.UC_ARCH_X86,
                unicorn.UC_MODE_32,
                x86_const.UC_X86_REG_ESP,
                x86_const.UC_X86_REG_EAX,
                _X86_GP_REGS,
                [],  # x86/32 uses stack for args
                4,
            )
    # PLFM_ARM = ARM family
    elif proc_id == idaapi.PLFM_ARM:
        if is_64:
            raise IDAError(
                "AArch64 (ARM64) emulation is not yet supported. "
                "Supported: x86, x64, arm (32-bit)"
            )
        # Detect Thumb vs ARM mode from IDA's T segment register
        uc_mode = unicorn.UC_MODE_ARM
        if func_ea is not None:
            t_reg = idc.get_sreg(func_ea, "T")
            if t_reg == 1:
                uc_mode = unicorn.UC_MODE_THUMB
        return (
            unicorn.UC_ARCH_ARM,
            uc_mode,
            arm_const.UC_ARM_REG_SP,
            arm_const.UC_ARM_REG_R0,
            _ARM_GP_REGS,
            _ARM_ARG_REGS,
            4,
        )
    else:
        raise IDAError(
            f"Unsupported processor (id={proc_id}). "
            "Supported architectures: x86, x64, arm (32-bit)"
        )


def _align_down(addr, alignment):
    """Align address down to boundary."""
    return addr & ~(alignment - 1)


def _align_up(addr, alignment):
    """Align address up to boundary."""
    return (addr + alignment - 1) & ~(alignment - 1)


def _setup_emulator(uc_arch, uc_mode, sp_reg, ptr_size):
    """Create emulator instance, map stack, return (uc, memory_writes, unmapped_accesses, insn_count)."""
    uc = unicorn.Uc(uc_arch, uc_mode)

    # Map stack
    uc.mem_map(_STACK_ADDR, _STACK_SIZE, unicorn.UC_PROT_ALL)
    # SP points to middle of stack, giving room for both pushes and local vars
    sp = _STACK_ADDR + _STACK_SIZE // 2
    # Align SP to 16 bytes (required by x64 ABI, harmless elsewhere)
    sp = _align_down(sp, 16)
    uc.reg_write(sp_reg, sp)

    # Tracking state
    memory_writes = []
    unmapped_accesses = []
    insn_count = [0]

    # Hook: track memory writes
    def _hook_mem_write(uc, access, address, size, value, user_data):
        memory_writes.append({
            "addr": hex(address),
            "size": size,
            "value": hex(value),
        })

    uc.hook_add(unicorn.UC_HOOK_MEM_WRITE, _hook_mem_write)

    # Hook: auto-map unmapped data accesses (read, write only — NOT fetch)
    def _hook_mem_data_unmapped(uc, access, address, size, value, user_data):
        page_addr = _align_down(address, _AUTO_MAP_SIZE)
        try:
            uc.mem_map(page_addr, _AUTO_MAP_SIZE, unicorn.UC_PROT_ALL)
        except unicorn.UcError:
            # Already mapped (race or overlap) — ignore
            pass
        unmapped_accesses.append({
            "addr": hex(address),
            "size": size,
            "access": "write" if access == unicorn.UC_MEM_WRITE_UNMAPPED else "read",
        })
        return True  # continue emulation

    uc.hook_add(
        unicorn.UC_HOOK_MEM_READ_UNMAPPED | unicorn.UC_HOOK_MEM_WRITE_UNMAPPED,
        _hook_mem_data_unmapped,
    )

    # Hook: stop on unmapped instruction fetch (e.g. RET to sentinel address)
    def _hook_mem_fetch_unmapped(uc, access, address, size, value, user_data):
        unmapped_accesses.append({
            "addr": hex(address),
            "size": size,
            "access": "fetch",
        })
        return False  # stop emulation

    uc.hook_add(unicorn.UC_HOOK_MEM_FETCH_UNMAPPED, _hook_mem_fetch_unmapped)

    return uc, memory_writes, unmapped_accesses, insn_count


def _set_args(uc, args_int, arg_regs, sp_reg, ptr_size, uc_arch, uc_mode, is_windows=False):
    """Place arguments in registers and/or stack per calling convention.

    Builds a proper call frame:
    - x86/32: push sentinel return address, then args right-to-left
    - x64 SysV: push sentinel return address, args in regs, overflow on stack
    - x64 Win: push sentinel return address + 32-byte shadow space, args in regs
    - ARM: set LR to sentinel, args in r0–r3, overflow on stack
    """
    sp = uc.reg_read(sp_reg)
    sentinel = _SENTINEL_RET_ADDR.to_bytes(ptr_size, byteorder="little")

    if uc_arch == unicorn.UC_ARCH_ARM:
        # ARM: sentinel goes in LR; no return address on stack
        uc.reg_write(arm_const.UC_ARM_REG_LR, _SENTINEL_RET_ADDR)
        for i, arg in enumerate(args_int):
            if i < len(arg_regs):
                uc.reg_write(arg_regs[i], arg)
            else:
                sp -= ptr_size
                uc.mem_write(sp, arg.to_bytes(ptr_size, byteorder="little"))
        uc.reg_write(sp_reg, sp)
        return

    if uc_mode == unicorn.UC_MODE_32 and not arg_regs:
        # x86/32 cdecl: push args right-to-left, then push sentinel return address
        for arg in reversed(args_int):
            sp -= ptr_size
            uc.mem_write(sp, arg.to_bytes(ptr_size, byteorder="little"))
        sp -= ptr_size
        uc.mem_write(sp, sentinel)
        uc.reg_write(sp_reg, sp)
        return

    # x64: push sentinel return address first
    sp -= ptr_size
    uc.mem_write(sp, sentinel)

    # Win64: reserve 32 bytes of shadow space above the return address
    if is_windows and uc_mode == unicorn.UC_MODE_64:
        sp -= _WIN64_SHADOW_SIZE

    # Register-based args; overflow to stack
    for i, arg in enumerate(args_int):
        if i < len(arg_regs):
            uc.reg_write(arg_regs[i], arg)
        else:
            sp -= ptr_size
            uc.mem_write(sp, arg.to_bytes(ptr_size, byteorder="little"))

    uc.reg_write(sp_reg, sp)

def _read_registers(uc, gp_regs):
    """Read all GP registers, return as {name: hex_value}."""
    return {name: hex(uc.reg_read(reg)) for name, reg in gp_regs.items()}


def _parse_arch_string(arch_str):
    """Convert user-supplied architecture string to (uc_arch, uc_mode, sp_reg, ret_reg, gp_regs, arg_regs, ptr_size)."""
    arch_str = arch_str.strip().lower()
    if arch_str in ("x64", "x86_64", "amd64"):
        return (
            unicorn.UC_ARCH_X86,
            unicorn.UC_MODE_64,
            x86_const.UC_X86_REG_RSP,
            x86_const.UC_X86_REG_RAX,
            _X64_GP_REGS,
            _X64_ARG_REGS_SYSV,  # shellcode: default to SysV
            8,
        )
    elif arch_str in ("x86", "i386", "x86_32"):
        return (
            unicorn.UC_ARCH_X86,
            unicorn.UC_MODE_32,
            x86_const.UC_X86_REG_ESP,
            x86_const.UC_X86_REG_EAX,
            _X86_GP_REGS,
            [],
            4,
        )
    elif arch_str in ("arm", "arm32"):
        return (
            unicorn.UC_ARCH_ARM,
            unicorn.UC_MODE_ARM,
            arm_const.UC_ARM_REG_SP,
            arm_const.UC_ARM_REG_R0,
            _ARM_GP_REGS,
            _ARM_ARG_REGS,
            4,
        )
    else:
        raise IDAError(
            f"Unsupported architecture: '{arch_str}'. "
            "Supported: 'x86', 'x64', 'arm'"
        )


def _parse_hex_bytes(data_str):
    """Parse hex string (space-separated or continuous) into bytes."""
    cleaned = data_str.replace(" ", "").strip()
    if not cleaned:
        raise IDAError("Empty shellcode data")
    try:
        return bytes.fromhex(cleaned)
    except ValueError as e:
        raise IDAError(f"Invalid hex bytes: {e}")


# ============================================================================
# Tools
# ============================================================================


@ext("emu")
@unsafe
@tool
@idasync
@tool_timeout(60.0)
def emulate_function(
    addr: Annotated[str, "Function address to emulate"],
    args: Annotated[
        list[str] | str, "Arguments as hex values (e.g. ['0x41414141', '4'])"
    ] = [],
    max_instructions: Annotated[
        int, "Max instructions to execute (default: 10000)"
    ] = 10000,
    memory_regions: Annotated[
        list[dict] | None,
        "Additional memory to map: [{addr, size, data?, perm?}]",
    ] = None,
) -> dict:
    """Emulate a function with concrete arguments using Unicorn Engine.

    Reads function bytes from the IDB, sets up a CPU emulator with the
    correct architecture, maps memory, configures arguments per calling
    convention, and runs up to max_instructions. Returns the return value,
    register state, and all memory writes observed during execution.
    """
    if not HAS_UNICORN:
        return _UNICORN_MISSING

    import ida_bytes
    import ida_funcs
    import ida_segment
    import idaapi

    ea = parse_address(addr)
    func = ida_funcs.get_func(ea)
    if func is None:
        raise IDAError(f"No function at {hex(ea)}")

    # Resolve architecture from IDA
    uc_arch, uc_mode, sp_reg, ret_reg, gp_regs, arg_regs, ptr_size = (
        _get_arch_config(func_ea=func.start_ea)
    )

    # Read function's segment bytes
    seg = ida_segment.getseg(func.start_ea)
    if seg is None:
        raise IDAError(f"No segment for function at {hex(func.start_ea)}")

    seg_size = seg.end_ea - seg.start_ea
    seg_bytes = ida_bytes.get_bytes(seg.start_ea, seg_size)
    if seg_bytes is None:
        raise IDAError(
            f"Failed to read {seg_size} bytes at {hex(seg.start_ea)}"
        )

    # Set up emulator
    uc, memory_writes, unmapped_accesses, insn_count = _setup_emulator(
        uc_arch, uc_mode, sp_reg, ptr_size
    )

    # Map the segment containing the function
    map_base = _align_down(seg.start_ea, _AUTO_MAP_SIZE)
    map_end = _align_up(seg.end_ea, _AUTO_MAP_SIZE)
    map_size = map_end - map_base
    try:
        uc.mem_map(map_base, map_size, unicorn.UC_PROT_ALL)
    except unicorn.UcError as e:
        raise IDAError(f"Failed to map segment memory: {e}")
    uc.mem_write(seg.start_ea, seg_bytes)

    # Map user-specified memory regions
    if memory_regions:
        for region in memory_regions:
            r_addr = int(str(region.get("addr", "0")), 0)
            r_size = int(str(region.get("size", "0x1000")), 0)
            r_perm = int(str(region.get("perm", str(unicorn.UC_PROT_ALL))), 0)
            r_base = _align_down(r_addr, _AUTO_MAP_SIZE)
            r_map_size = _align_up(r_size + (r_addr - r_base), _AUTO_MAP_SIZE)
            try:
                uc.mem_map(r_base, r_map_size, r_perm)
            except unicorn.UcError:
                pass  # may overlap existing mapping
            r_data = region.get("data")
            if r_data:
                uc.mem_write(r_addr, _parse_hex_bytes(str(r_data)))

    # Parse arguments
    if isinstance(args, str):
        args = [a.strip() for a in args.split(",") if a.strip()]
    args_int = [int(str(a), 0) for a in args]

    is_windows = _is_windows_binary()
    _set_args(uc, args_int, arg_regs, sp_reg, ptr_size, uc_arch, uc_mode, is_windows=is_windows)

    # Instruction counting hook
    def _hook_code(uc_instance, address, size, user_data):
        insn_count[0] += 1
        if insn_count[0] >= max_instructions:
            uc_instance.emu_stop()

    uc.hook_add(unicorn.UC_HOOK_CODE, _hook_code)

    # Run emulation
    stopped_reason = "completed"
    error_msg = None
    try:
        uc.emu_start(func.start_ea, func.end_ea, timeout=0, count=0)
    except unicorn.UcError as e:
        error_msg = str(e)
        if insn_count[0] >= max_instructions:
            stopped_reason = "max_instructions"
        elif "fetch" in str(e).lower():
            # Unmapped instruction fetch — most likely RET hit the sentinel
            stopped_reason = "returned"
        elif "unmapped" in str(e).lower():
            stopped_reason = "unmapped_memory"
        else:
            stopped_reason = "crash"

    if error_msg is None and insn_count[0] >= max_instructions:
        stopped_reason = "max_instructions"

    # Collect results
    retval = uc.reg_read(ret_reg)
    registers = _read_registers(uc, gp_regs)

    return {
        "addr": hex(ea),
        "return_value": hex(retval),
        "instructions_executed": insn_count[0],
        "memory_writes": memory_writes,
        "unmapped_accesses": unmapped_accesses,
        "registers": registers,
        "error": error_msg,
        "stopped_reason": stopped_reason,
    }


@ext("emu")
@unsafe
@tool
@idasync
@tool_timeout(60.0)
def emulate_shellcode(
    data: Annotated[
        str, "Hex bytes to emulate (space-separated or continuous)"
    ],
    arch: Annotated[str, "Architecture: 'x86', 'x64', 'arm'"] = "x64",
    base_addr: Annotated[str, "Base address to load at"] = "0x10000",
    max_instructions: Annotated[int, "Max instructions"] = 10000,
) -> dict:
    """Emulate raw shellcode bytes with the Unicorn Engine.

    Loads hex-encoded bytes at the specified base address and emulates
    execution. Not tied to any IDB function — useful for analyzing
    extracted shellcode, encoded payloads, or ROP chains.
    """
    if not HAS_UNICORN:
        return _UNICORN_MISSING

    code = _parse_hex_bytes(data)
    base = int(base_addr, 0)

    uc_arch, uc_mode, sp_reg, ret_reg, gp_regs, arg_regs, ptr_size = (
        _parse_arch_string(arch)
    )

    # Set up emulator
    uc, memory_writes, unmapped_accesses, insn_count = _setup_emulator(
        uc_arch, uc_mode, sp_reg, ptr_size
    )

    # Map code
    map_base = _align_down(base, _AUTO_MAP_SIZE)
    map_size = _align_up(len(code) + (base - map_base), _AUTO_MAP_SIZE)
    # Ensure at least one page
    if map_size == 0:
        map_size = _AUTO_MAP_SIZE
    try:
        uc.mem_map(map_base, map_size, unicorn.UC_PROT_ALL)
    except unicorn.UcError as e:
        raise IDAError(f"Failed to map code memory at {hex(map_base)}: {e}")
    uc.mem_write(base, code)

    # Instruction counting hook
    def _hook_code(uc_instance, address, size, user_data):
        insn_count[0] += 1
        if insn_count[0] >= max_instructions:
            uc_instance.emu_stop()

    uc.hook_add(unicorn.UC_HOOK_CODE, _hook_code)

    # Emulate: start at base, end at base + len(code)
    end_addr = base + len(code)
    stopped_reason = "completed"
    error_msg = None
    try:
        uc.emu_start(base, end_addr, timeout=0, count=0)
    except unicorn.UcError as e:
        error_msg = str(e)
        if insn_count[0] >= max_instructions:
            stopped_reason = "max_instructions"
        elif "fetch" in str(e).lower():
            stopped_reason = "returned"
        elif "unmapped" in str(e).lower():
            stopped_reason = "unmapped_memory"
        else:
            stopped_reason = "crash"

    if error_msg is None and insn_count[0] >= max_instructions:
        stopped_reason = "max_instructions"

    retval = uc.reg_read(ret_reg)
    registers = _read_registers(uc, gp_regs)

    return {
        "addr": hex(base),
        "return_value": hex(retval),
        "instructions_executed": insn_count[0],
        "memory_writes": memory_writes,
        "unmapped_accesses": unmapped_accesses,
        "registers": registers,
        "error": error_msg,
        "stopped_reason": stopped_reason,
    }
