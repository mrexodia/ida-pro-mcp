"""Security analysis tools for vulnerability detection and reverse engineering.

Provides automated detection of common vulnerability patterns, crypto algorithm
identification, and taint-like data flow analysis from sources to sinks.
"""

from __future__ import annotations

from collections import defaultdict
from itertools import islice
from typing import Annotated

import idaapi
import idautils
import ida_bytes
import ida_funcs
import ida_nalt
import ida_ua
import idc

from .rpc import tool
from .sync import idasync, tool_timeout, IDAError
from .utils import (
    parse_address,
    normalize_list_input,
    get_function,
    get_prototype,
    decompile_function_safe,
)


# ============================================================================
# Dangerous Function Patterns
# ============================================================================

# Maps dangerous sink functions to vulnerability class and severity
_DANGEROUS_SINKS: dict[str, dict] = {
    # Buffer overflow - critical
    "strcpy":    {"vuln": "buffer_overflow", "severity": "critical", "note": "No bounds check, use strncpy/strlcpy"},
    "strcat":    {"vuln": "buffer_overflow", "severity": "critical", "note": "No bounds check, use strncat/strlcat"},
    "gets":      {"vuln": "buffer_overflow", "severity": "critical", "note": "Always unsafe, use fgets"},
    "scanf":     {"vuln": "buffer_overflow", "severity": "high",     "note": "Unbounded %s, use width specifier"},
    "sscanf":    {"vuln": "buffer_overflow", "severity": "high",     "note": "Unbounded %s, use width specifier"},
    "vscanf":    {"vuln": "buffer_overflow", "severity": "high",     "note": "Unbounded %s format"},
    "wcscpy":    {"vuln": "buffer_overflow", "severity": "critical", "note": "Wide-char strcpy, no bounds check"},
    "wcscat":    {"vuln": "buffer_overflow", "severity": "critical", "note": "Wide-char strcat, no bounds check"},
    "lstrcpyA":  {"vuln": "buffer_overflow", "severity": "critical", "note": "Win32 strcpy, no bounds check"},
    "lstrcpyW":  {"vuln": "buffer_overflow", "severity": "critical", "note": "Win32 wide strcpy, no bounds check"},
    "lstrcatA":  {"vuln": "buffer_overflow", "severity": "critical", "note": "Win32 strcat, no bounds check"},
    "lstrcatW":  {"vuln": "buffer_overflow", "severity": "critical", "note": "Win32 wide strcat, no bounds check"},
    # Unsafe memory ops
    "memcpy":    {"vuln": "buffer_overflow", "severity": "medium",   "note": "Check size param for user control"},
    "memmove":   {"vuln": "buffer_overflow", "severity": "medium",   "note": "Check size param for user control"},
    "RtlCopyMemory": {"vuln": "buffer_overflow", "severity": "medium", "note": "Check size param"},
    # Format string
    "printf":    {"vuln": "format_string", "severity": "high",   "note": "Check if format is user-controlled"},
    "fprintf":   {"vuln": "format_string", "severity": "high",   "note": "Check if format is user-controlled"},
    "sprintf":   {"vuln": "format_string", "severity": "critical", "note": "Format string + no bounds check"},
    "snprintf":  {"vuln": "format_string", "severity": "medium", "note": "Bounded but check format param"},
    "vprintf":   {"vuln": "format_string", "severity": "high",   "note": "va_list format string"},
    "vsprintf":  {"vuln": "format_string", "severity": "critical", "note": "va_list + no bounds"},
    "vsnprintf": {"vuln": "format_string", "severity": "medium", "note": "Bounded va_list format"},
    "syslog":    {"vuln": "format_string", "severity": "high",   "note": "Check if format is user-controlled"},
    "wprintf":   {"vuln": "format_string", "severity": "high",   "note": "Wide-char format string"},
    "swprintf":  {"vuln": "format_string", "severity": "high",   "note": "Wide-char sprintf"},
    "OutputDebugStringA": {"vuln": "format_string", "severity": "low", "note": "Debug info leak"},
    # Command injection
    "system":    {"vuln": "command_injection", "severity": "critical", "note": "Shell command execution"},
    "popen":     {"vuln": "command_injection", "severity": "critical", "note": "Shell command via pipe"},
    "_popen":    {"vuln": "command_injection", "severity": "critical", "note": "Shell command via pipe"},
    "execl":     {"vuln": "command_injection", "severity": "critical", "note": "Process execution"},
    "execle":    {"vuln": "command_injection", "severity": "critical", "note": "Process execution"},
    "execlp":    {"vuln": "command_injection", "severity": "critical", "note": "Process execution"},
    "execv":     {"vuln": "command_injection", "severity": "critical", "note": "Process execution"},
    "execve":    {"vuln": "command_injection", "severity": "critical", "note": "Process execution"},
    "execvp":    {"vuln": "command_injection", "severity": "critical", "note": "Process execution"},
    "WinExec":   {"vuln": "command_injection", "severity": "critical", "note": "Win32 command execution"},
    "ShellExecuteA": {"vuln": "command_injection", "severity": "critical", "note": "Win32 shell execute"},
    "ShellExecuteW": {"vuln": "command_injection", "severity": "critical", "note": "Win32 shell execute"},
    "CreateProcessA": {"vuln": "command_injection", "severity": "high", "note": "Process creation"},
    "CreateProcessW": {"vuln": "command_injection", "severity": "high", "note": "Process creation"},
    # Use-after-free related
    "free":      {"vuln": "use_after_free", "severity": "medium", "note": "Check for use after this call"},
    "realloc":   {"vuln": "use_after_free", "severity": "medium", "note": "Old pointer invalid after realloc"},
    "HeapFree":  {"vuln": "use_after_free", "severity": "medium", "note": "Check for use after free"},
    "LocalFree": {"vuln": "use_after_free", "severity": "medium", "note": "Check for use after free"},
    "GlobalFree": {"vuln": "use_after_free", "severity": "medium", "note": "Check for use after free"},
    # Integer overflow
    "atoi":      {"vuln": "integer_overflow", "severity": "medium", "note": "No overflow check, use strtol"},
    "atol":      {"vuln": "integer_overflow", "severity": "medium", "note": "No overflow check, use strtol"},
    "atoll":     {"vuln": "integer_overflow", "severity": "medium", "note": "No overflow check"},
    # Race conditions (TOCTOU)
    "access":    {"vuln": "toctou", "severity": "medium", "note": "Time-of-check/time-of-use race"},
    # Network
    "recv":      {"vuln": "untrusted_input", "severity": "medium", "note": "Network input - validate before use"},
    "recvfrom":  {"vuln": "untrusted_input", "severity": "medium", "note": "Network input - validate before use"},
    "WSARecv":   {"vuln": "untrusted_input", "severity": "medium", "note": "Win32 network input"},
    "ReadFile":  {"vuln": "untrusted_input", "severity": "low",    "note": "File input - validate before use"},
    "InternetReadFile": {"vuln": "untrusted_input", "severity": "medium", "note": "Internet input"},
}

# Stripped name variants to match (IDA may add prefixes/suffixes)
_SINK_NAMES_LOWER = {k.lower(): k for k in _DANGEROUS_SINKS}


# ============================================================================
# Crypto Constants
# ============================================================================

# Well-known crypto S-box / round constant fragments (first 16 bytes as signature)
_CRYPTO_SIGNATURES: list[dict] = [
    # AES
    {"name": "AES S-Box", "bytes": bytes([0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76]), "algo": "AES", "type": "sbox"},
    {"name": "AES Inv S-Box", "bytes": bytes([0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB]), "algo": "AES", "type": "sbox_inv"},
    {"name": "AES Rcon", "bytes": bytes([0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]), "algo": "AES", "type": "rcon"},
    # DES
    {"name": "DES Initial Perm", "bytes": bytes([58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4]), "algo": "DES", "type": "permutation"},
    {"name": "DES S-Box 1", "bytes": bytes([14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7]), "algo": "DES", "type": "sbox"},
    # MD5 round constants (T[1..4] as 32-bit LE)
    {"name": "MD5 T constants", "bytes": bytes([0x78, 0xA4, 0x6A, 0xD7, 0x56, 0xB7, 0xC7, 0xE8, 0xDB, 0x70, 0x20, 0x24, 0xEE, 0xCE, 0xBD, 0xC1]), "algo": "MD5", "type": "round_constants"},
    # SHA-256 initial hash values (first 8 bytes: H0=6a09e667)
    {"name": "SHA-256 Init H", "bytes": bytes([0x67, 0xe6, 0x09, 0x6a, 0x85, 0xae, 0x67, 0xbb, 0x72, 0xf3, 0x6e, 0x3c, 0x3a, 0xf5, 0x4f, 0xa5]), "algo": "SHA-256", "type": "init_hash"},
    # SHA-256 round constants K (first 16 bytes)
    {"name": "SHA-256 K", "bytes": bytes([0x98, 0x2F, 0x8A, 0x42, 0x91, 0x44, 0x37, 0x71, 0xCF, 0xFB, 0xC0, 0xB5, 0xA5, 0xDB, 0xB5, 0xE9]), "algo": "SHA-256", "type": "round_constants"},
    # RC4 (detected by 0-255 identity permutation init pattern)
    {"name": "RC4 S-Box Init", "bytes": bytes(range(16)), "algo": "RC4", "type": "sbox_init"},
    # Blowfish P-array (first 16 bytes of P[0..3])
    {"name": "Blowfish P-array", "bytes": bytes([0x24, 0x3F, 0x6A, 0x88, 0x85, 0xA3, 0x08, 0xD3, 0x13, 0x19, 0x8A, 0x2E, 0x03, 0x70, 0x73, 0x44]), "algo": "Blowfish", "type": "p_array"},
    # CRC32 table (first 16 bytes of standard polynomial)
    {"name": "CRC32 Table", "bytes": bytes([0x00, 0x00, 0x00, 0x00, 0x96, 0x30, 0x07, 0x77, 0x2C, 0x61, 0x0E, 0xEE, 0xBA, 0x51, 0x09, 0x99]), "algo": "CRC32", "type": "lookup_table"},
    # TEA/XTEA delta constant
    {"name": "TEA Delta", "bytes": bytes([0x79, 0xB9, 0x9E, 0x9A]), "algo": "TEA/XTEA", "type": "constant"},
    # Whirlpool S-box
    {"name": "Whirlpool S-Box", "bytes": bytes([0x18, 0x23, 0xC6, 0xE8, 0x87, 0xB8, 0x01, 0x4F, 0x36, 0xA6, 0xD2, 0xF5, 0x79, 0x6F, 0x91, 0x52]), "algo": "Whirlpool", "type": "sbox"},
]

# Magic constants often found in crypto implementations
_CRYPTO_MAGIC_CONSTANTS: dict[int, str] = {
    0x67452301: "MD5/SHA-1 init A",
    0xEFCDAB89: "MD5/SHA-1 init B",
    0x98BADCFE: "MD5/SHA-1 init C",
    0x10325476: "MD5/SHA-1 init D",
    0xC3D2E1F0: "SHA-1 init E",
    0x6A09E667: "SHA-256 init H0",
    0xBB67AE85: "SHA-256 init H1",
    0x3C6EF372: "SHA-256 init H2",
    0xA54FF53A: "SHA-256 init H3",
    0x510E527F: "SHA-256 init H4",
    0x9B05688C: "SHA-256 init H5",
    0x1F83D9AB: "SHA-256 init H6",
    0x5BE0CD19: "SHA-256 init H7",
    0x5A827999: "SHA-1 K0",
    0x6ED9EBA1: "SHA-1 K1",
    0x8F1BBCDC: "SHA-1 K2",
    0xCA62C1D6: "SHA-1 K3",
    0x9E3779B9: "TEA/XTEA delta",
    0x61C88647: "TEA/XTEA delta (neg)",
    0xB7E15163: "RC5/RC6 P constant",
    0x9E3779B1: "RC5/RC6 Q constant",
    0x428A2F98: "SHA-256 K[0]",
    0x71374491: "SHA-256 K[1]",
    0xB5C0FBCF: "SHA-256 K[2]",
    0xE9B5DBA5: "SHA-256 K[3]",
}


# ============================================================================
# Internal Helpers
# ============================================================================

_MAX_SCAN_FUNCS = 5000
_MAX_XREFS_PER_SINK = 200


def _strip_ida_name(name: str) -> str:
    """Strip IDA prefixes/suffixes to get base function name."""
    # Remove common prefixes: _, __, j_, .
    stripped = name.lstrip("_").lstrip(".")
    if stripped.startswith("j_"):
        stripped = stripped[2:]
    # Remove @N suffix (stdcall decoration)
    if "@" in stripped:
        stripped = stripped.split("@")[0]
    # Remove imp_ prefix
    if stripped.startswith("imp_"):
        stripped = stripped[4:]
    return stripped


def _match_sink(name: str) -> tuple[str, dict] | None:
    """Match a function name against known dangerous sinks."""
    stripped = _strip_ida_name(name)
    key = stripped.lower()
    if key in _SINK_NAMES_LOWER:
        canonical = _SINK_NAMES_LOWER[key]
        return canonical, _DANGEROUS_SINKS[canonical]
    return None


def _get_callers_of(ea: int, limit: int = _MAX_XREFS_PER_SINK) -> list[dict]:
    """Get functions that call the given address."""
    callers = []
    for xref in islice(idautils.XrefsTo(ea, 0), limit):
        if xref.type not in (idaapi.fl_CF, idaapi.fl_CN, idaapi.fl_JF, idaapi.fl_JN):
            continue
        func = ida_funcs.get_func(xref.frm)
        if func:
            caller_name = idc.get_name(func.start_ea, 0) or hex(func.start_ea)
            callers.append({
                "caller": caller_name,
                "caller_addr": hex(func.start_ea),
                "call_site": hex(xref.frm),
            })
    return callers


# ============================================================================
# MCP Tools
# ============================================================================


@tool
@idasync
@tool_timeout(120)
def detect_vulns(
    addrs: Annotated[
        list[str] | str | None,
        "Function addresses/names to scan (comma-separated). Omit to scan all functions."
    ] = None,
    vuln_types: Annotated[
        list[str] | str | None,
        "Filter by vuln type: buffer_overflow, format_string, command_injection, use_after_free, integer_overflow, toctou, untrusted_input"
    ] = None,
    severity: Annotated[
        str | None,
        "Minimum severity: critical, high, medium, low"
    ] = None,
    offset: Annotated[int, "Skip first N findings (default 0)"] = 0,
    count: Annotated[int, "Max findings to return (default 100, 0=all)"] = 100,
) -> dict:
    """Scan functions for dangerous API calls and common vulnerability patterns.

    Returns categorized findings with call sites, severity, and remediation notes.
    Scans imports and direct calls for known dangerous sinks like strcpy, sprintf, system, etc.
    """
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    min_severity = severity_order.get(severity or "low", 3)

    # Parse vuln type filter
    type_filter: set[str] | None = None
    if vuln_types:
        type_filter = set(normalize_list_input(vuln_types))

    # Determine which functions to scan
    if addrs:
        func_eas = []
        for a in normalize_list_input(addrs):
            try:
                func_eas.append(parse_address(a))
            except IDAError:
                pass
    else:
        func_eas = list(islice(idautils.Functions(), _MAX_SCAN_FUNCS))

    # Phase 1: Find all dangerous sinks in the binary (imports + named functions)
    sink_locations: dict[int, tuple[str, dict]] = {}  # ea -> (canonical_name, info)

    # Check imports
    nimps = ida_nalt.get_import_module_qty()
    for i in range(nimps):
        collected: list[tuple[int, str]] = []

        def imp_cb(ea: int, name: str | None, ordinal: int) -> bool:
            if name:
                collected.append((ea, name))
            return True

        ida_nalt.enum_import_names(i, imp_cb)
        for ea, name in collected:
            match = _match_sink(name)
            if match:
                sink_locations[ea] = match

    # Check named functions
    for ea in idautils.Functions():
        name = idc.get_name(ea, 0) or ""
        if not name:
            continue
        match = _match_sink(name)
        if match:
            sink_locations[ea] = match

    # Phase 2: For each target function, find calls to dangerous sinks
    findings: list[dict] = []
    scanned = 0

    for func_ea in func_eas:
        func = ida_funcs.get_func(func_ea)
        if not func:
            continue

        func_name = idc.get_name(func.start_ea, 0) or hex(func.start_ea)
        scanned += 1

        for head in idautils.Heads(func.start_ea, func.end_ea):
            if not ida_bytes.is_code(ida_bytes.get_flags(head)):
                continue

            for xref in idautils.XrefsFrom(head, 0):
                if xref.type not in (idaapi.fl_CF, idaapi.fl_CN):
                    continue

                target = xref.to
                if target not in sink_locations:
                    continue

                sink_name, info = sink_locations[target]
                sev = info["severity"]

                # Apply filters
                if severity_order.get(sev, 3) > min_severity:
                    continue
                if type_filter and info["vuln"] not in type_filter:
                    continue

                findings.append({
                    "func": func_name,
                    "func_addr": hex(func.start_ea),
                    "call_site": hex(head),
                    "sink": sink_name,
                    "vuln": info["vuln"],
                    "severity": sev,
                    "note": info["note"],
                })

    # Sort by severity
    findings.sort(key=lambda f: severity_order.get(f["severity"], 3))

    # Build summary
    by_type: dict[str, int] = defaultdict(int)
    by_severity: dict[str, int] = defaultdict(int)
    for f in findings:
        by_type[f["vuln"]] += 1
        by_severity[f["severity"]] += 1

    total = len(findings)
    if count == 0:
        page = findings[offset:]
    else:
        page = findings[offset:offset + count]
    has_more = offset + len(page) < total

    return {
        "scanned": scanned,
        "total_findings": total,
        "by_type": dict(by_type),
        "by_severity": dict(by_severity),
        "findings": page,
        "offset": offset,
        "count": len(page),
        "next_offset": offset + len(page) if has_more else None,
    }


@tool
@idasync
@tool_timeout(120)
def find_crypto(
    scan_constants: Annotated[bool, "Scan for magic constants in code"] = True,
    scan_tables: Annotated[bool, "Scan binary for known S-box/lookup tables"] = True,
    offset: Annotated[int, "Skip first N findings (default 0)"] = 0,
    count: Annotated[int, "Max findings per algorithm (default 50, 0=all)"] = 50,
) -> dict:
    """Detect cryptographic algorithms by finding known constants, S-boxes, and lookup tables.

    Identifies AES, DES, MD5, SHA-1/256, RC4, Blowfish, TEA/XTEA, CRC32, Whirlpool
    by matching byte signatures and magic constants in the binary.
    """
    results: list[dict] = []

    # Phase 1: Scan for magic constants in function code
    if scan_constants:
        seen_constants: set[tuple[int, int]] = set()  # (func_ea, constant)

        for func_ea in islice(idautils.Functions(), _MAX_SCAN_FUNCS):
            func = ida_funcs.get_func(func_ea)
            if not func:
                continue

            for head in idautils.Heads(func.start_ea, func.end_ea):
                if not ida_bytes.is_code(ida_bytes.get_flags(head)):
                    continue

                insn = ida_ua.insn_t()
                if ida_ua.decode_insn(insn, head) == 0:
                    continue

                for op_idx in range(ida_ua.UA_MAXOP):
                    op = insn.ops[op_idx]
                    if op.type == ida_ua.o_void:
                        break
                    if op.type == ida_ua.o_imm:
                        val = op.value & 0xFFFFFFFF
                        if val in _CRYPTO_MAGIC_CONSTANTS:
                            key = (func_ea, val)
                            if key not in seen_constants:
                                seen_constants.add(key)
                                func_name = idc.get_name(func_ea, 0) or hex(func_ea)
                                results.append({
                                    "type": "magic_constant",
                                    "addr": hex(head),
                                    "func": func_name,
                                    "func_addr": hex(func_ea),
                                    "value": hex(val),
                                    "algo": _CRYPTO_MAGIC_CONSTANTS[val],
                                })

    # Phase 2: Scan binary segments for known S-box / table signatures
    if scan_tables:
        seg = idaapi.get_first_seg()
        while seg:
            seg_start = seg.start_ea
            seg_end = seg.end_ea

            for sig in _CRYPTO_SIGNATURES:
                pattern = sig["bytes"]
                pattern_len = len(pattern)
                ea = seg_start

                while ea < seg_end - pattern_len:
                    found = ida_bytes.bin_search(
                        ea, seg_end, pattern, None,
                        ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOBREAK,
                        0,
                    )
                    if found == idaapi.BADADDR or found >= seg_end:
                        break

                    # Verify full match
                    candidate = ida_bytes.get_bytes(found, pattern_len)
                    if candidate == pattern:
                        # Find containing function if any
                        func = ida_funcs.get_func(found)
                        func_name = None
                        if func:
                            func_name = idc.get_name(func.start_ea, 0) or hex(func.start_ea)

                        results.append({
                            "type": sig["type"],
                            "addr": hex(found),
                            "func": func_name,
                            "algo": sig["algo"],
                            "name": sig["name"],
                            "size": pattern_len,
                        })

                    ea = found + pattern_len

            seg = idaapi.get_next_seg(seg.start_ea)

    # Deduplicate and group by algorithm
    by_algo: dict[str, list[dict]] = defaultdict(list)
    for r in results:
        by_algo[r["algo"]].append(r)

    cap = count if count > 0 else None
    return {
        "total_findings": len(results),
        "algorithms_found": list(by_algo.keys()),
        "by_algorithm": {
            algo: hits[offset:offset + cap] if cap else hits[offset:]
            for algo, hits in by_algo.items()
        },
    }


@tool
@idasync
@tool_timeout(60)
def find_dangerous_callers(
    sink: Annotated[str, "Dangerous function name or address (e.g. 'strcpy', '0x401000')"],
    max_depth: Annotated[int, "How many call levels up to trace (default 3)"] = 3,
    offset: Annotated[int, "Skip first N edges (default 0)"] = 0,
    count: Annotated[int, "Max edges to return (default 200, 0=all)"] = 200,
) -> dict:
    """Trace all call paths leading to a dangerous sink function.

    Given a dangerous function (e.g. strcpy, system), finds all callers recursively
    up to max_depth levels. Useful for finding which code paths reach dangerous sinks.
    """
    max_depth = min(max_depth, 10)

    # Resolve sink address
    sink_ea = None
    try:
        sink_ea = parse_address(sink)
    except IDAError:
        pass

    if sink_ea is None:
        # Search by name
        for ea in idautils.Functions():
            name = idc.get_name(ea, 0) or ""
            if _strip_ida_name(name).lower() == sink.lower():
                sink_ea = ea
                break
        # Also check imports
        if sink_ea is None:
            nimps = ida_nalt.get_import_module_qty()
            for i in range(nimps):
                collected: list[tuple[int, str]] = []

                def imp_cb(ea: int, name: str | None, ordinal: int) -> bool:
                    if name:
                        collected.append((ea, name))
                    return True

                ida_nalt.enum_import_names(i, imp_cb)
                for ea, name in collected:
                    if _strip_ida_name(name).lower() == sink.lower():
                        sink_ea = ea
                        break
                if sink_ea is not None:
                    break

    if sink_ea is None:
        raise IDAError(f"Could not find sink function: {sink!r}")

    sink_name = idc.get_name(sink_ea, 0) or hex(sink_ea)

    # BFS upward through callers
    visited: set[int] = set()
    edges: list[dict] = []
    queue: list[tuple[int, int]] = [(sink_ea, 0)]  # (ea, depth)

    while queue:
        current_ea, depth = queue.pop(0)
        if current_ea in visited or depth > max_depth:
            continue
        visited.add(current_ea)

        for xref in islice(idautils.XrefsTo(current_ea, 0), _MAX_XREFS_PER_SINK):
            if xref.type not in (idaapi.fl_CF, idaapi.fl_CN, idaapi.fl_JF, idaapi.fl_JN):
                continue
            caller_func = ida_funcs.get_func(xref.frm)
            if not caller_func:
                continue
            caller_ea = caller_func.start_ea
            caller_name = idc.get_name(caller_ea, 0) or hex(caller_ea)
            target_name = idc.get_name(current_ea, 0) or hex(current_ea)

            edges.append({
                "caller": caller_name,
                "caller_addr": hex(caller_ea),
                "call_site": hex(xref.frm),
                "target": target_name,
                "target_addr": hex(current_ea),
                "depth": depth,
            })

            if caller_ea not in visited and depth + 1 <= max_depth:
                queue.append((caller_ea, depth + 1))

    # Build call chain summary
    root_callers = [e for e in edges if e["depth"] == max_depth or
                    e["caller_addr"] not in {e2["target_addr"] for e2 in edges}]

    total_edges = len(edges)
    if count == 0:
        page = edges[offset:]
    else:
        page = edges[offset:offset + count]
    has_more = offset + len(page) < total_edges

    return {
        "sink": sink_name,
        "sink_addr": hex(sink_ea),
        "total_callers": len(visited) - 1,
        "total_edges": total_edges,
        "max_depth": max_depth,
        "edges": page,
        "offset": offset,
        "count": len(page),
        "next_offset": offset + len(page) if has_more else None,
        "root_entry_points": [e["caller"] for e in root_callers],
    }


@tool
@idasync
@tool_timeout(60)
def detect_stack_strings(
    addrs: Annotated[
        list[str] | str | None,
        "Function addresses/names to scan. Omit to scan all."
    ] = None,
    min_length: Annotated[int, "Minimum string length to report (default 4)"] = 4,
    offset: Annotated[int, "Skip first N results (default 0)"] = 0,
    count: Annotated[int, "Max results to return (default 200, 0=all)"] = 200,
) -> dict:
    """Detect strings constructed on the stack (anti-analysis / obfuscation technique).

    Finds byte-by-byte or word-by-word string construction patterns where individual
    characters are moved to stack locations. Common in malware to evade static string detection.
    """
    if addrs:
        func_eas = []
        for a in normalize_list_input(addrs):
            try:
                func_eas.append(parse_address(a))
            except IDAError:
                pass
    else:
        func_eas = list(islice(idautils.Functions(), _MAX_SCAN_FUNCS))

    results: list[dict] = []

    for func_ea in func_eas:
        func = ida_funcs.get_func(func_ea)
        if not func:
            continue

        func_name = idc.get_name(func.start_ea, 0) or hex(func.start_ea)

        # Track mov [rbp-X], imm8 patterns (stack byte stores)
        stack_stores: dict[int, list[tuple[int, int]]] = defaultdict(list)  # offset -> [(ea, byte_val)]

        for head in idautils.Heads(func.start_ea, func.end_ea):
            if not ida_bytes.is_code(ida_bytes.get_flags(head)):
                continue

            insn = ida_ua.insn_t()
            if ida_ua.decode_insn(insn, head) == 0:
                continue

            # Look for: mov [stack_var], immediate_byte
            if insn.itype not in (idaapi.NN_mov, idaapi.NN_movzx):
                continue

            op0 = insn.ops[0]
            op1 = insn.ops[1]

            # Destination must be stack reference, source must be immediate
            if op0.type not in (ida_ua.o_displ, ida_ua.o_phrase) or op1.type != ida_ua.o_imm:
                continue

            val = op1.value & 0xFF
            if val < 0x20 or val > 0x7E:  # Printable ASCII only
                continue

            # Use displacement as stack offset key
            offset = op0.addr if op0.type == ida_ua.o_displ else op0.value
            stack_stores[offset].append((head, val))

        # Find contiguous stack store sequences that form strings
        if not stack_stores:
            continue

        offsets = sorted(stack_stores.keys())
        current_string = []
        current_start = None
        current_addrs = []

        for i, off in enumerate(offsets):
            if current_string and off != offsets[i - 1] + 1:
                # Gap - emit current string if long enough
                if len(current_string) >= min_length:
                    results.append({
                        "func": func_name,
                        "func_addr": hex(func_ea),
                        "string": "".join(current_string),
                        "length": len(current_string),
                        "first_insn": hex(current_addrs[0]),
                    })
                current_string = []
                current_addrs = []

            # Take the last store to this offset
            ea, val = stack_stores[off][-1]
            current_string.append(chr(val))
            current_addrs.append(ea)

        # Flush remaining
        if len(current_string) >= min_length:
            results.append({
                "func": func_name,
                "func_addr": hex(func_ea),
                "string": "".join(current_string),
                "length": len(current_string),
                "first_insn": hex(current_addrs[0]),
            })

    total = len(results)
    if count == 0:
        page = results[offset:]
    else:
        page = results[offset:offset + count]
    has_more = offset + len(page) < total

    return {
        "total": total,
        "results": page,
        "offset": offset,
        "count": len(page),
        "next_offset": offset + len(page) if has_more else None,
    }


@tool
@idasync
@tool_timeout(120)
def trace_source_to_sink(
    sources: Annotated[
        list[str] | str,
        "Source function names/addrs (e.g. 'recv,ReadFile,InternetReadFile')"
    ],
    sinks: Annotated[
        list[str] | str,
        "Sink function names/addrs (e.g. 'strcpy,system,sprintf')"
    ],
    max_depth: Annotated[int, "Max call chain depth (default 5)"] = 5,
    offset: Annotated[int, "Skip first N paths (default 0)"] = 0,
    count: Annotated[int, "Max paths to return (default 100, 0=all)"] = 100,
) -> dict:
    """Find call chains connecting input sources to dangerous sinks.

    Traces forward from source functions (recv, ReadFile, etc.) and backward from
    sink functions (strcpy, system, etc.) to find functions that appear in both sets,
    indicating potential vulnerability paths where untrusted data reaches dangerous APIs.
    """
    max_depth = min(max_depth, 10)

    source_names = normalize_list_input(sources)
    sink_names = normalize_list_input(sinks)

    def resolve_func_ea(name: str) -> int | None:
        """Resolve function name to EA, checking both functions and imports."""
        try:
            return parse_address(name)
        except IDAError:
            pass
        for ea in idautils.Functions():
            fn = idc.get_name(ea, 0) or ""
            if _strip_ida_name(fn).lower() == name.lower():
                return ea
        # Check imports
        nimps = ida_nalt.get_import_module_qty()
        for i in range(nimps):
            collected: list[tuple[int, str]] = []

            def imp_cb(ea: int, n: str | None, ordinal: int) -> bool:
                if n:
                    collected.append((ea, n))
                return True

            ida_nalt.enum_import_names(i, imp_cb)
            for ea, n in collected:
                if _strip_ida_name(n).lower() == name.lower():
                    return ea
        return None

    # Resolve source and sink EAs
    source_eas: dict[int, str] = {}
    for name in source_names:
        ea = resolve_func_ea(name)
        if ea is not None:
            source_eas[ea] = idc.get_name(ea, 0) or name

    sink_eas: dict[int, str] = {}
    for name in sink_names:
        ea = resolve_func_ea(name)
        if ea is not None:
            sink_eas[ea] = idc.get_name(ea, 0) or name

    if not source_eas:
        raise IDAError(f"No source functions found: {source_names}")
    if not sink_eas:
        raise IDAError(f"No sink functions found: {sink_names}")

    # BFS forward from sources: find all functions reachable from callers of sources
    forward_reachable: dict[int, int] = {}  # func_ea -> depth from source

    queue: list[tuple[int, int]] = []
    for src_ea in source_eas:
        for xref in islice(idautils.XrefsTo(src_ea, 0), _MAX_XREFS_PER_SINK):
            if xref.type not in (idaapi.fl_CF, idaapi.fl_CN):
                continue
            caller = ida_funcs.get_func(xref.frm)
            if caller:
                queue.append((caller.start_ea, 0))

    while queue:
        ea, depth = queue.pop(0)
        if ea in forward_reachable or depth > max_depth:
            continue
        forward_reachable[ea] = depth

        # Follow callees
        func = ida_funcs.get_func(ea)
        if not func:
            continue
        for head in idautils.Heads(func.start_ea, func.end_ea):
            if not ida_bytes.is_code(ida_bytes.get_flags(head)):
                continue
            for xref in idautils.XrefsFrom(head, 0):
                if xref.type in (idaapi.fl_CF, idaapi.fl_CN):
                    target_func = ida_funcs.get_func(xref.to)
                    if target_func and target_func.start_ea not in forward_reachable:
                        queue.append((target_func.start_ea, depth + 1))

    # BFS backward from sinks: find all functions that call sinks
    backward_reachable: dict[int, int] = {}  # func_ea -> depth from sink

    queue = []
    for sink_ea in sink_eas:
        for xref in islice(idautils.XrefsTo(sink_ea, 0), _MAX_XREFS_PER_SINK):
            if xref.type not in (idaapi.fl_CF, idaapi.fl_CN):
                continue
            caller = ida_funcs.get_func(xref.frm)
            if caller:
                queue.append((caller.start_ea, 0))

    while queue:
        ea, depth = queue.pop(0)
        if ea in backward_reachable or depth > max_depth:
            continue
        backward_reachable[ea] = depth

        for xref in islice(idautils.XrefsTo(ea, 0), _MAX_XREFS_PER_SINK):
            if xref.type not in (idaapi.fl_CF, idaapi.fl_CN):
                continue
            caller = ida_funcs.get_func(xref.frm)
            if caller and caller.start_ea not in backward_reachable:
                queue.append((caller.start_ea, depth + 1))

    # Intersection: functions reachable from both sources and sinks
    intersection = set(forward_reachable.keys()) & set(backward_reachable.keys())

    paths: list[dict] = []
    for ea in intersection:
        name = idc.get_name(ea, 0) or hex(ea)
        paths.append({
            "func": name,
            "func_addr": hex(ea),
            "depth_from_source": forward_reachable[ea],
            "depth_from_sink": backward_reachable[ea],
            "total_distance": forward_reachable[ea] + backward_reachable[ea],
        })

    paths.sort(key=lambda p: p["total_distance"])

    total = len(paths)
    if count == 0:
        page = paths[offset:]
    else:
        page = paths[offset:offset + count]
    has_more = offset + len(page) < total

    return {
        "sources": {hex(ea): name for ea, name in source_eas.items()},
        "sinks": {hex(ea): name for ea, name in sink_eas.items()},
        "forward_reachable_count": len(forward_reachable),
        "backward_reachable_count": len(backward_reachable),
        "intersection_count": total,
        "paths": page,
        "offset": offset,
        "count": len(page),
        "next_offset": offset + len(page) if has_more else None,
    }
