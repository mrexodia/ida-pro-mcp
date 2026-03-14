"""Server-side preprocessing: obfuscation detection and resolution.

These tools detect and report (and where possible, resolve) obfuscation
patterns *before* the LLM sees the binary. All tools are gated behind
``?ext=preprocess`` so they are opt-in.
"""

from __future__ import annotations

from typing import Annotated

from .rpc import tool, ext, unsafe
from .sync import idasync, tool_timeout, IDAError
from .utils import parse_address
from . import compat

# ============================================================================
# Known Windows APIs for import-hash resolution
# ============================================================================

KNOWN_APIS: list[str] = [
    # Loader / process
    "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
    "GetProcAddress", "FreeLibrary", "GetModuleHandleA", "GetModuleHandleW",
    "GetModuleFileNameA", "GetModuleFileNameW",
    "ExitProcess", "TerminateProcess", "CreateProcessA", "CreateProcessW",
    "WinExec", "ShellExecuteA", "ShellExecuteW",
    # Memory
    "VirtualAlloc", "VirtualAllocEx", "VirtualFree", "VirtualFreeEx",
    "VirtualProtect", "VirtualProtectEx", "VirtualQuery", "VirtualQueryEx",
    "HeapCreate", "HeapAlloc", "HeapFree", "HeapReAlloc",
    "GlobalAlloc", "GlobalFree", "GlobalLock", "GlobalUnlock",
    "LocalAlloc", "LocalFree",
    "RtlMoveMemory", "RtlZeroMemory", "RtlCopyMemory",
    "NtAllocateVirtualMemory", "NtProtectVirtualMemory",
    # File I/O
    "CreateFileA", "CreateFileW", "ReadFile", "WriteFile", "CloseHandle",
    "DeleteFileA", "DeleteFileW", "CopyFileA", "CopyFileW",
    "MoveFileA", "MoveFileW", "GetFileSize", "SetFilePointer",
    "CreateFileMappingA", "CreateFileMappingW",
    "MapViewOfFile", "UnmapViewOfFile",
    "FindFirstFileA", "FindFirstFileW", "FindNextFileA", "FindNextFileW",
    # Registry
    "RegOpenKeyExA", "RegOpenKeyExW", "RegQueryValueExA", "RegQueryValueExW",
    "RegSetValueExA", "RegSetValueExW", "RegCloseKey",
    "RegCreateKeyExA", "RegCreateKeyExW", "RegDeleteKeyA", "RegDeleteKeyW",
    # Networking (WinInet)
    "InternetOpenA", "InternetOpenW", "InternetConnectA", "InternetConnectW",
    "HttpOpenRequestA", "HttpOpenRequestW",
    "HttpSendRequestA", "HttpSendRequestW",
    "InternetReadFile", "InternetCloseHandle",
    "InternetOpenUrlA", "InternetOpenUrlW",
    # Networking (Winsock)
    "WSAStartup", "WSACleanup", "WSAGetLastError",
    "socket", "connect", "send", "recv", "bind", "listen", "accept",
    "closesocket", "select", "ioctlsocket",
    "getaddrinfo", "freeaddrinfo", "gethostbyname",
    "WSASocketA", "WSASocketW",
    # Threading
    "CreateThread", "CreateRemoteThread", "CreateRemoteThreadEx",
    "ResumeThread", "SuspendThread", "TerminateThread",
    "WaitForSingleObject", "WaitForMultipleObjects",
    "Sleep", "SleepEx",
    "CreateMutexA", "CreateMutexW", "OpenMutexA", "OpenMutexW",
    "CreateEventA", "CreateEventW",
    "SetEvent", "ResetEvent",
    "EnterCriticalSection", "LeaveCriticalSection",
    "InitializeCriticalSection", "DeleteCriticalSection",
    # Injection / hooking
    "WriteProcessMemory", "ReadProcessMemory",
    "NtWriteVirtualMemory", "NtReadVirtualMemory",
    "OpenProcess", "GetCurrentProcess", "GetCurrentProcessId",
    "GetCurrentThread", "GetCurrentThreadId",
    "QueueUserAPC", "NtQueueApcThread",
    "SetWindowsHookExA", "SetWindowsHookExW",
    # Crypto
    "CryptAcquireContextA", "CryptAcquireContextW",
    "CryptCreateHash", "CryptHashData", "CryptDeriveKey",
    "CryptEncrypt", "CryptDecrypt", "CryptReleaseContext",
    "CryptDestroyHash", "CryptDestroyKey",
    "BCryptOpenAlgorithmProvider", "BCryptCloseAlgorithmProvider",
    # Misc
    "GetLastError", "SetLastError",
    "GetTickCount", "GetTickCount64",
    "GetSystemTime", "GetLocalTime",
    "GetComputerNameA", "GetComputerNameW",
    "GetUserNameA", "GetUserNameW",
    "GetTempPathA", "GetTempPathW",
    "GetEnvironmentVariableA", "GetEnvironmentVariableW",
    "SetEnvironmentVariableA", "SetEnvironmentVariableW",
    "GetWindowsDirectoryA", "GetWindowsDirectoryW",
    "GetSystemDirectoryA", "GetSystemDirectoryW",
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
    "OutputDebugStringA", "OutputDebugStringW",
    "GetVersionExA", "GetVersionExW",
    "GetCommandLineA", "GetCommandLineW",
    "GetStartupInfoA", "GetStartupInfoW",
    "LookupPrivilegeValueA", "AdjustTokenPrivileges",
    "OpenProcessToken",
    # NT
    "NtCreateFile", "NtClose", "NtQueryInformationProcess",
    "NtQuerySystemInformation", "NtSetInformationThread",
    "LdrLoadDll", "LdrGetProcedureAddress",
    "RtlInitUnicodeString",
]


# ---------------------------------------------------------------------------
# Hash algorithms
# ---------------------------------------------------------------------------

def _ror13_add_hash(name: str) -> int:
    h = 0
    for c in name:
        h = (((h >> 13) | (h << 19)) + ord(c)) & 0xFFFFFFFF
    return h


def _crc32_hash(name: str) -> int:
    import binascii
    return binascii.crc32(name.encode("ascii")) & 0xFFFFFFFF


def _djb2_hash(name: str) -> int:
    h = 5381
    for c in name:
        h = ((h * 33) + ord(c)) & 0xFFFFFFFF
    return h


def _fnv1a_hash(name: str) -> int:
    h = 0x811C9DC5
    for c in name:
        h = ((h ^ ord(c)) * 0x01000193) & 0xFFFFFFFF
    return h


def _murmurhash3_32(name: str) -> int:
    """Simplified MurmurHash3 x86 32-bit with seed=0."""
    data = name.encode("ascii")
    length = len(data)
    h = 0  # seed
    c1, c2 = 0xCC9E2D51, 0x1B873593
    nblocks = length // 4

    for i in range(nblocks):
        k = int.from_bytes(data[i * 4:(i + 1) * 4], "little")
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF
        h ^= k
        h = ((h << 13) | (h >> 19)) & 0xFFFFFFFF
        h = (h * 5 + 0xE6546B64) & 0xFFFFFFFF

    tail = data[nblocks * 4:]
    k = 0
    if len(tail) >= 3:
        k ^= tail[2] << 16
    if len(tail) >= 2:
        k ^= tail[1] << 8
    if len(tail) >= 1:
        k ^= tail[0]
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF
        h ^= k

    h ^= length
    h ^= h >> 16
    h = (h * 0x85EBCA6B) & 0xFFFFFFFF
    h ^= h >> 13
    h = (h * 0xC2B2AE35) & 0xFFFFFFFF
    h ^= h >> 16
    return h


_HASH_FUNCS = {
    "ror13_add": _ror13_add_hash,
    "crc32": _crc32_hash,
    "djb2": _djb2_hash,
    "fnv1a": _fnv1a_hash,
    "murmurhash3": _murmurhash3_32,
}

# Pre-built databases (module-load-time).
HASH_DBS: dict[str, dict[int, str]] = {
    algo: {fn(api): api for api in KNOWN_APIS}
    for algo, fn in _HASH_FUNCS.items()
}

# ============================================================================
# Known crypto constants
# ============================================================================

_AES_SBOX_PREFIX = bytes([
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
    0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
])

_AES_INV_SBOX_PREFIX = bytes([
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38,
    0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
])

_SHA256_H0_BE = bytes([0x6A, 0x09, 0xE6, 0x67])

_MD5_A0_LE = bytes([0x01, 0x23, 0x45, 0x67])

_MD5_T1_LE = bytes([0xD7, 0x6A, 0xA4, 0x78])

_CRC32_ENTRY1 = bytes([0x96, 0x30, 0x07, 0x77])

_CHACHA_CONST = b"expand 32-byte k"

_TEA_DELTA_BE = bytes([0x9E, 0x37, 0x79, 0xB9])
_TEA_DELTA_LE = bytes([0xB9, 0x79, 0x37, 0x9E])

# DES initial permutation table (first 16 entries, byte representation)
_DES_IP_TABLE = bytes([
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
])

# Crypto signatures: (pattern_bytes, algorithm, constant_name)
_CRYPTO_SIGNATURES: list[tuple[bytes, str, str]] = [
    (_AES_SBOX_PREFIX, "AES", "S-box"),
    (_AES_INV_SBOX_PREFIX, "AES", "Inverse S-box"),
    (_SHA256_H0_BE, "SHA-256", "Initial hash value H0 (big-endian)"),
    (_MD5_A0_LE, "MD5", "Initial A0 (little-endian)"),
    (_MD5_T1_LE, "MD5", "T-table entry T[1] (little-endian)"),
    (_CRC32_ENTRY1, "CRC32", "Polynomial table entry[1]"),
    (_CHACHA_CONST, "ChaCha20/Salsa20", "expand 32-byte k"),
    (_TEA_DELTA_BE, "TEA/XTEA", "Delta constant (big-endian)"),
    (_TEA_DELTA_LE, "TEA/XTEA", "Delta constant (little-endian)"),
    (_DES_IP_TABLE, "DES", "Initial permutation table (prefix)"),
]


# ============================================================================
# Tool 1: detect_obfuscation
# ============================================================================

@ext("preprocess")
@tool
@idasync
@tool_timeout(120.0)
def detect_obfuscation() -> dict:
    """Scan the binary for common obfuscation indicators.

    Detects: control-flow flattening, opaque predicates, string encryption,
    import hashing, and anti-disassembly tricks.  Returns structured results
    with detection flags, counts, and example addresses.
    """
    import idaapi
    import idautils
    import idc
    import ida_bytes
    import ida_segment

    processor = idaapi.get_inf_structure().procname.lower()
    is_x86 = processor in ("metapc", "")

    # --- helpers ---
    def _hex(ea: int) -> str:
        return f"0x{ea:X}"

    # ----- control-flow flattening -----
    cff_functions: list[dict] = []
    func_count = 0
    for ea in idautils.Functions():
        if func_count >= 500:
            break
        func_count += 1
        func = idaapi.get_func(ea)
        if func is None:
            continue
        try:
            fc = idaapi.FlowChart(func)
        except Exception:
            continue
        blocks = list(fc)
        n_blocks = len(blocks)
        if n_blocks < 6:
            continue

        # Count how many blocks each block is targeted by
        target_counts: dict[int, int] = {}
        for blk in blocks:
            for succ_idx in range(blk.nsucc()):
                succ_ea = fc[blk.succ(succ_idx)].start_ea if blk.succ(succ_idx) < len(blocks) else None
                if succ_ea is not None:
                    target_counts[succ_ea] = target_counts.get(succ_ea, 0) + 1

        # A dispatcher is a block targeted by >50% of blocks
        threshold = n_blocks * 0.5
        for blk_ea, cnt in target_counts.items():
            if cnt > threshold:
                pct = cnt / n_blocks * 100
                if pct >= 80:
                    fname = idc.get_func_name(ea) or _hex(ea)
                    cff_functions.append({
                        "addr": _hex(ea),
                        "name": fname,
                        "blocks": n_blocks,
                        "dispatcher": _hex(blk_ea),
                        "pct_to_dispatcher": round(pct, 1),
                    })
                break

    cff_detected = len(cff_functions) > 0
    cff_result = {
        "detected": cff_detected,
        "indicators": cff_functions[:20],
    }

    # ----- opaque predicates (x86 only) -----
    opaque: list[dict] = []
    if is_x86:
        insn_count = 0
        for seg_ea in idautils.Segments():
            seg = ida_segment.getseg(seg_ea)
            if seg is None or seg.type != ida_segment.SEG_CODE:
                continue
            ea = seg.start_ea
            while ea < seg.end_ea and insn_count < 1000:
                insn_count += 1
                mnem = idc.print_insn_mnem(ea)
                if mnem and mnem.startswith("j") and mnem not in ("jmp",):
                    # conditional branch
                    xrefs = list(idautils.XrefsFrom(ea, 0))
                    code_targets = [x for x in xrefs if x.type in (
                        idaapi.fl_JF, idaapi.fl_JN, idaapi.fl_F,
                    )]
                    if len(code_targets) == 2:
                        # Check if either target is only reachable from this branch
                        t0_xrefs = [x for x in idautils.XrefsTo(code_targets[0].to, 0)
                                    if x.frm != ea]
                        t1_xrefs = [x for x in idautils.XrefsTo(code_targets[1].to, 0)
                                    if x.frm != ea]
                        if len(t0_xrefs) == 0 or len(t1_xrefs) == 0:
                            opaque.append({
                                "addr": _hex(ea),
                                "mnemonic": mnem,
                                "never_taken_branch": _hex(
                                    code_targets[0].to if len(t0_xrefs) == 0 else code_targets[1].to
                                ),
                            })
                ea = idc.next_head(ea, seg.end_ea)
                if ea == idc.BADADDR:
                    break

    opaque_result = {
        "detected": len(opaque) > 0,
        "count": len(opaque),
        "examples": opaque[:20],
    }

    # ----- string encryption heuristic -----
    # Functions called >10 times with different immediates, having no string
    # refs themselves.
    call_info: dict[int, set[int]] = {}  # callee_ea -> set of immediate args
    insn_scanned = 0
    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        if seg is None or seg.type != ida_segment.SEG_CODE:
            continue
        ea = seg.start_ea
        while ea < seg.end_ea and insn_scanned < 5000:
            insn_scanned += 1
            mnem = idc.print_insn_mnem(ea)
            if mnem == "call":
                target = idc.get_operand_value(ea, 0)
                if target and target != idc.BADADDR:
                    # Look for a push/mov immediate just before the call
                    prev = idc.prev_head(ea, 0)
                    if prev != idc.BADADDR:
                        prev_mnem = idc.print_insn_mnem(prev)
                        if prev_mnem in ("push", "mov"):
                            op_type = idc.get_operand_type(prev, 0 if prev_mnem == "push" else 1)
                            if op_type == idc.o_imm:
                                imm = idc.get_operand_value(prev, 0 if prev_mnem == "push" else 1)
                                call_info.setdefault(target, set()).add(imm)
            ea = idc.next_head(ea, seg.end_ea)
            if ea == idc.BADADDR:
                break

    str_enc_indicators: list[dict] = []
    for callee, imms in call_info.items():
        if len(imms) > 10:
            # Check if the function itself has string references
            func = idaapi.get_func(callee)
            if func is None:
                continue
            has_strings = False
            fea = func.start_ea
            while fea < func.end_ea:
                for dref in idautils.DataRefsFrom(fea):
                    stype = idc.get_str_type(dref)
                    if stype is not None and stype >= 0:
                        has_strings = True
                        break
                if has_strings:
                    break
                fea = idc.next_head(fea, func.end_ea)
                if fea == idc.BADADDR:
                    break
            if not has_strings:
                fname = idc.get_func_name(callee) or _hex(callee)
                str_enc_indicators.append({
                    "addr": _hex(callee),
                    "name": fname,
                    "unique_immediate_args": len(imms),
                })

    str_enc_result = {
        "detected": len(str_enc_indicators) > 0,
        "indicators": str_enc_indicators[:20],
    }

    # ----- import hashing -----
    # Functions taking a single int arg, called with many different constants
    import_hash_indicators: list[dict] = []
    for callee, imms in call_info.items():
        if len(imms) < 5:
            continue
        func = idaapi.get_func(callee)
        if func is None:
            continue
        # Heuristic: small function, many unique constant call sites
        try:
            fc = idaapi.FlowChart(func)
            n_blocks = sum(1 for _ in fc)
        except Exception:
            n_blocks = 999
        if n_blocks <= 30 and len(imms) >= 10:
            fname = idc.get_func_name(callee) or _hex(callee)
            import_hash_indicators.append({
                "addr": _hex(callee),
                "name": fname,
                "unique_hash_args": len(imms),
                "sample_hashes": [f"0x{h:08X}" for h in sorted(imms)[:5]],
            })

    import_hash_result = {
        "detected": len(import_hash_indicators) > 0,
        "indicators": import_hash_indicators[:10],
    }

    # ----- anti-disassembly -----
    anti_disasm: list[dict] = []
    if is_x86:
        for seg_ea in idautils.Segments():
            seg = ida_segment.getseg(seg_ea)
            if seg is None or seg.type != ida_segment.SEG_CODE:
                continue
            ea = seg.start_ea
            scan_limit = min(seg.end_ea, seg.start_ea + 0x100000)
            while ea < scan_limit:
                b = ida_bytes.get_byte(ea)
                if b == 0xCC:
                    # int 3 inside code
                    if idaapi.is_code(idaapi.get_flags(ea)):
                        anti_disasm.append({
                            "addr": _hex(ea),
                            "type": "int3_in_code",
                        })
                elif b == 0xCD:
                    next_b = ida_bytes.get_byte(ea + 1)
                    if next_b == 0x2D and idaapi.is_code(idaapi.get_flags(ea)):
                        anti_disasm.append({
                            "addr": _hex(ea),
                            "type": "int_2d",
                        })
                # Overlapping instructions: if ea is data but inside a code
                # instruction boundary (previous head != ea but ea < next head
                # of previous head)
                flags = idaapi.get_flags(ea)
                if not idaapi.is_head(flags) and idaapi.is_code(flags):
                    anti_disasm.append({
                        "addr": _hex(ea),
                        "type": "overlapping_instruction",
                    })
                ea += 1
                if len(anti_disasm) >= 50:
                    break
            if len(anti_disasm) >= 50:
                break

    anti_disasm_result = {
        "detected": len(anti_disasm) > 0,
        "indicators": anti_disasm[:20],
    }

    # ----- summary -----
    parts: list[str] = []
    if cff_detected:
        parts.append(f"Control-flow flattening detected in {len(cff_functions)} function(s)")
    if opaque_result["detected"]:
        parts.append(f"Opaque predicates: {opaque_result['count']} candidate(s)")
    if str_enc_result["detected"]:
        parts.append(f"Possible string encryption stubs: {len(str_enc_indicators)}")
    if import_hash_result["detected"]:
        parts.append(f"Possible import hashing: {len(import_hash_indicators)} function(s)")
    if anti_disasm_result["detected"]:
        parts.append(f"Anti-disassembly tricks: {len(anti_disasm)} indicator(s)")
    if not parts:
        parts.append("No significant obfuscation indicators detected")

    return {
        "control_flow_flattening": cff_result,
        "opaque_predicates": opaque_result,
        "string_encryption": str_enc_result,
        "import_hashing": import_hash_result,
        "anti_disassembly": anti_disasm_result,
        "summary": "; ".join(parts),
    }


# ============================================================================
# Tool 2: resolve_import_hashes
# ============================================================================

@ext("preprocess")
@unsafe
@tool
@idasync
def resolve_import_hashes(
    hash_func_addr: Annotated[str, "Address of the hash resolution function"],
    hash_db: Annotated[
        str,
        "Hash algorithm: 'ror13_add', 'crc32', 'djb2', 'fnv1a', 'murmurhash3'",
    ] = "ror13_add",
) -> dict:
    """Resolve hashed API imports by matching observed hash constants to known
    Windows API names using the specified algorithm.

    Finds all call sites of the hash resolution function, extracts the
    immediate hash argument at each site, looks it up in a pre-computed
    database, and renames/comments the result.
    """
    import idaapi
    import idautils
    import idc
    import ida_name

    if hash_db not in HASH_DBS:
        raise IDAError(
            f"Unknown hash algorithm '{hash_db}'. "
            f"Supported: {', '.join(sorted(HASH_DBS))}"
        )

    ea = parse_address(hash_func_addr)
    func = idaapi.get_func(ea)
    if func is None:
        raise IDAError(f"No function at {hash_func_addr}")

    db = HASH_DBS[hash_db]
    resolved: list[dict] = []
    unresolved: list[dict] = []

    for xref in idautils.XrefsTo(func.start_ea, 0):
        call_ea = xref.frm
        if not idaapi.is_code(idaapi.get_flags(call_ea)):
            continue

        # Walk backwards from call to find the immediate argument.
        # Look at the previous 4 instructions for a push/mov imm.
        hash_val: int | None = None
        scan_ea = call_ea
        for _ in range(4):
            scan_ea = idc.prev_head(scan_ea, 0)
            if scan_ea == idc.BADADDR:
                break
            mnem = idc.print_insn_mnem(scan_ea)
            if mnem in ("push", "mov"):
                idx = 0 if mnem == "push" else 1
                if idc.get_operand_type(scan_ea, idx) == idc.o_imm:
                    hash_val = idc.get_operand_value(scan_ea, idx) & 0xFFFFFFFF
                    break

        if hash_val is None:
            continue

        api_name = db.get(hash_val)
        entry = {
            "addr": f"0x{call_ea:X}",
            "hash": f"0x{hash_val:08X}",
        }

        if api_name is not None:
            entry["api_name"] = api_name
            resolved.append(entry)
            # Add comment at call site
            existing = idc.get_cmt(call_ea, 0) or ""
            tag = f"[API] {api_name}"
            if tag not in existing:
                idc.set_cmt(call_ea, f"{existing}  {tag}".strip() if existing else tag, 0)
            # Try to rename the result location if the next instruction
            # stores to a named location (best effort, don't fail)
        else:
            unresolved.append(entry)

    total = len(resolved) + len(unresolved)
    return {
        "resolved": resolved,
        "unresolved": unresolved,
        "total_sites": total,
    }


# ============================================================================
# Tool 3: detect_crypto_constants
# ============================================================================

@ext("preprocess")
@tool
@idasync
@tool_timeout(120.0)
def detect_crypto_constants() -> dict:
    """Scan the binary for known cryptographic constants (AES, SHA-256, MD5,
    CRC32, ChaCha20/Salsa20, TEA/XTEA, DES, RC4).

    Returns a list of findings with addresses, containing function, algorithm,
    and constant name.
    """
    import idaapi
    import ida_bytes
    import ida_funcs
    import idc

    min_ea = compat.inf_get_min_ea()
    max_ea = compat.inf_get_max_ea()

    def _hex(ea: int) -> str:
        return f"0x{ea:X}"

    def _func_info(ea: int) -> tuple[str, str]:
        """Return (func_addr_hex, func_name) for the function containing ea."""
        func = ida_funcs.get_func(ea)
        if func is None:
            return ("", "")
        return (_hex(func.start_ea), idc.get_func_name(func.start_ea) or _hex(func.start_ea))

    findings: list[dict] = []

    # Search for each crypto signature
    for pattern, algorithm, const_name in _CRYPTO_SIGNATURES:
        ea = min_ea
        while ea < max_ea:
            ea = compat.raw_bin_search(
                ea, max_ea, pattern, None,
                ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOBREAK,
            )
            if ea == idc.BADADDR:
                break
            func_addr, func_name = _func_info(ea)
            findings.append({
                "addr": _hex(ea),
                "func_addr": func_addr,
                "func_name": func_name,
                "algorithm": algorithm,
                "constant_name": const_name,
            })
            ea += len(pattern)  # advance past this match

    # RC4 identity permutation: 256 sequential bytes 00 01 02 ... FF
    # Only search in data-like regions to reduce false positives
    rc4_pattern = bytes(range(256))
    ea = min_ea
    while ea < max_ea:
        ea = compat.raw_bin_search(
            ea, max_ea, rc4_pattern, None,
            ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOBREAK,
        )
        if ea == idc.BADADDR:
            break
        func_addr, func_name = _func_info(ea)
        findings.append({
            "addr": _hex(ea),
            "func_addr": func_addr,
            "func_name": func_name,
            "algorithm": "RC4",
            "constant_name": "Identity permutation (S-box init)",
        })
        ea += 256

    # CRC32 table: entry[0] = 00000000, entry[1] = 77073096 (LE)
    crc32_header = b"\x00\x00\x00\x00\x96\x30\x07\x77"
    ea = min_ea
    while ea < max_ea:
        ea = compat.raw_bin_search(
            ea, max_ea, crc32_header, None,
            ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOBREAK,
        )
        if ea == idc.BADADDR:
            break
        func_addr, func_name = _func_info(ea)
        findings.append({
            "addr": _hex(ea),
            "func_addr": func_addr,
            "func_name": func_name,
            "algorithm": "CRC32",
            "constant_name": "Lookup table (standard polynomial)",
        })
        ea += 8

    # Summary
    algo_set = {f["algorithm"] for f in findings}
    if findings:
        summary = (
            f"Found {len(findings)} crypto constant(s) for: "
            + ", ".join(sorted(algo_set))
        )
    else:
        summary = "No known cryptographic constants detected"

    return {
        "findings": findings,
        "summary": summary,
    }


# ============================================================================
# Tool 4: classify_functions
# ============================================================================

@ext("preprocess")
@tool
@idasync
@tool_timeout(120.0)
def classify_functions() -> dict:
    """Classify all functions by behavioural pattern.

    Categories: library, thunk, wrapper, dispatcher, leaf, entry, large,
    tiny.  A function may appear in multiple categories.

    Returns per-category lists and aggregate statistics.  Capped at 5000
    functions.
    """
    import idaapi
    import idautils
    import idc
    import ida_funcs

    def _hex(ea: int) -> str:
        return f"0x{ea:X}"

    classifications: dict[str, list[dict]] = {
        "library": [],
        "thunk": [],
        "wrapper": [],
        "dispatcher": [],
        "leaf": [],
        "entry": [],
        "large": [],
        "tiny": [],
    }

    func_count = 0
    for ea in idautils.Functions():
        if func_count >= 5000:
            break
        func_count += 1

        func = idaapi.get_func(ea)
        if func is None:
            continue

        fname = idc.get_func_name(ea) or _hex(ea)
        flags = func.flags
        func_size = func.end_ea - func.start_ea

        # Basic block count
        try:
            fc = idaapi.FlowChart(func)
            blocks = list(fc)
            n_blocks = len(blocks)
        except Exception:
            n_blocks = 0
            blocks = []

        # Instruction count (for tiny classification)
        insn_count = 0
        cur = func.start_ea
        while cur < func.end_ea:
            insn_count += 1
            cur = idc.next_head(cur, func.end_ea)
            if cur == idc.BADADDR:
                break

        # Callees / callers
        callees: set[int] = set()
        callers: set[int] = set()
        cur = func.start_ea
        while cur < func.end_ea:
            for xref in idautils.XrefsFrom(cur, 0):
                if xref.type in (idaapi.fl_CF, idaapi.fl_CN):
                    callees.add(xref.to)
            cur = idc.next_head(cur, func.end_ea)
            if cur == idc.BADADDR:
                break
        for xref in idautils.XrefsTo(ea, 0):
            if xref.type in (idaapi.fl_CF, idaapi.fl_CN):
                callers.add(xref.frm)

        base = {"addr": _hex(ea), "name": fname}

        # library: FLIRT-identified or known library name patterns
        if flags & idaapi.FUNC_LIB:
            classifications["library"].append({**base, "detail": "FLIRT-identified"})
        elif fname.startswith(("_", "__")) and not fname.startswith("sub_"):
            classifications["library"].append({**base, "detail": "Library name pattern"})

        # thunk: single-instruction jump, small size
        if flags & idaapi.FUNC_THUNK or (func_size <= 8 and insn_count <= 2):
            first_mnem = idc.print_insn_mnem(ea)
            if first_mnem == "jmp" or flags & idaapi.FUNC_THUNK:
                classifications["thunk"].append({**base, "detail": f"size={func_size}"})

        # wrapper: calls exactly one other function and is small
        if len(callees) == 1 and n_blocks <= 3 and insn_count <= 15:
            target = next(iter(callees))
            target_name = idc.get_func_name(target) or _hex(target)
            classifications["wrapper"].append({
                **base, "detail": f"wraps {target_name}",
            })

        # dispatcher: high fan-out
        if len(callees) > 10:
            classifications["dispatcher"].append({
                **base, "detail": f"callees={len(callees)}",
            })

        # leaf: no callees
        if len(callees) == 0:
            classifications["leaf"].append({**base, "detail": f"insns={insn_count}"})

        # entry: no callers
        if len(callers) == 0:
            classifications["entry"].append({**base, "detail": "no callers"})

        # large
        if n_blocks > 200:
            classifications["large"].append({
                **base, "detail": f"blocks={n_blocks}",
            })

        # tiny
        if n_blocks < 3 and insn_count < 10:
            classifications["tiny"].append({
                **base, "detail": f"blocks={n_blocks}, insns={insn_count}",
            })

    statistics = {cat: len(entries) for cat, entries in classifications.items()}

    return {
        "classifications": classifications,
        "statistics": statistics,
    }
