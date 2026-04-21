"""String Deobfuscation and VM Handler Detection.

This module provides tools for:
- Detecting encrypted/obfuscated strings
- Decrypting strings with various algorithms (XOR, ADD, ROT13)
- Detecting VM-based obfuscation
- Reconstructing VM handler tables

IDA API: ida_bytes, ida_nalt, ida_segment, ida_ua
"""

import re
from typing import Annotated, NotRequired, TypedDict

import idaapi
import ida_bytes
import ida_nalt
import ida_segment
import ida_ua
import idautils

from .rpc import tool
from .sync import idasync
from .utils import normalize_list_input, parse_address


class EncryptedStringResult(TypedDict):
    """Result of encrypted string detection."""

    address: str
    algorithm: str
    key: str
    decrypted: str
    confidence: float
    error: NotRequired[str]


class DecryptionResult(TypedDict):
    """Result of decrypt operation."""

    address: str
    original: NotRequired[str]
    decrypted: str
    success: bool
    error: NotRequired[str]


class ObfuscationTypeResult(TypedDict):
    """Result of auto-detect obfuscation."""

    address: str
    detected_type: str
    confidence: float
    details: NotRequired[str]


class VMHandlerResult(TypedDict):
    """Result of VM handler detection."""

    address: str
    handler_type: str
    confidence: float
    handler_table: NotRequired[str]
    instruction_count: int
    error: NotRequired[str]


class HandlerTableResult(TypedDict):
    """Result of handler table reconstruction."""

    base_address: str
    entry_size: int
    handlers: list[str]
    total: int


class StringScanResult(TypedDict):
    """Result of string scanning."""

    matches: list[dict]
    total: int
    truncated: bool


def _xOR(data: bytes, key: int) -> bytes:
    """XOR data with a single-byte key.

    Args:
        data: Bytes to decrypt
        key: Single byte XOR key (0-255)

    Returns:
        Decrypted bytes
    """
    result = bytearray(len(data))
    for i, b in enumerate(data):
        result[i] = b ^ key
    return bytes(result)


def _xOR_string(data: bytes, key: str) -> str | None:
    """XOR data with a multi-byte key (cycling).

    Args:
        data: Bytes to decrypt
        key: Hex string (e.g., "0xAA") or regular string

    Returns:
        Decrypted string or None if invalid
    """
    if not data:
        return None

    try:
        if key.startswith("0x"):
            key_byte = int(key, 16) & 0xFF
            return _xOR(data, key_byte).decode("utf-8", errors="replace")
        elif len(key) > 0:
            key_bytes = key.encode("utf-8")
            if not key_bytes:
                return None
            result = bytearray(len(data))
            for i, b in enumerate(data):
                result[i] = b ^ key_bytes[i % len(key_bytes)]
            return result.decode("utf-8", errors="replace")
    except Exception:
        return None


def _add_decrypt(data: bytes, key: int) -> bytes:
    """ADD/SUB decryption (increment each byte by key).

    Args:
        data: Bytes to decrypt
        key: Integer to add (mod 256)

    Returns:
        Decrypted bytes
    """
    result = bytearray(len(data))
    for i, b in enumerate(data):
        result[i] = (b + key) & 0xFF
    return bytes(result)


def _rot13_char(c: int) -> int:
    """Apply ROT13 to a single character.

    Args:
        c: ASCII code

    Returns:
        ROT13'd ASCII code
    """
    if 65 <= c <= 77 or 97 <= c <= 109:
        return c + 13
    elif 78 <= c <= 90 or 110 <= c <= 122:
        return c - 13
    return c


def _rot13(data: bytes) -> bytes:
    """Apply ROT13 to data.

    Args:
        data: Bytes to decrypt

    Returns:
        Decrypted bytes
    """
    result = bytearray(len(data))
    for i, b in enumerate(data):
        result[i] = _rot13_char(b)
    return bytes(result)


def _is_readable_string(data: bytes, min_length: int = 4) -> bool:
    """Check if bytes look like a valid string.

    Args:
        data: Bytes to check
        min_length: Minimum valid length

    Returns:
        True if looks like a valid string
    """
    if not data or len(data) < min_length:
        return False

    if b"\x00" in data:
        data = data[: data.index(b"\x00")]

    if len(data) < min_length:
        return False

    printable_count = 0
    for b in data:
        if 32 <= b <= 126:
            printable_count += 1
        elif b == 0 or b == 9 or b == 10 or b == 13:
            continue
        else:
            return False

    return printable_count >= len(data) * 0.8


def _scan_for_encrypted_strings(
    start_ea: int,
    end_ea: int,
    min_length: int = 4,
    algorithms: list[str] | None = None,
) -> list[dict]:
    """Scan a memory range for potentially encrypted strings.

    Args:
        start_ea: Start address
        end_ea: End address
        min_length: Minimum string length
        algorithms: List of algorithms to try

    Returns:
        List of potential encrypted string results
    """
    if algorithms is None:
        algorithms = ["xor", "add", "rot13"]

    results = []
    chunk_size = 256
    step = 16

    for ea in range(start_ea, end_ea, step):
        if ea + chunk_size > end_ea:
            break

        data = ida_bytes.get_bytes(ea, chunk_size)
        if not data or len(data) < min_length:
            continue

        for algo in algorithms:
            decrypted = None
            key_used = ""

            if algo == "xor":
                for key in range(1, 256):
                    test = _xOR(data, key)
                    if _is_readable_string(test, min_length):
                        decrypted = test
                        key_used = hex(key)
                        break

            elif algo == "add":
                for key in range(1, 256):
                    test = _add_decrypt(data, key)
                    if _is_readable_string(test, min_length):
                        decrypted = test
                        key_used = hex(key)
                        break

            elif algo == "rot13":
                if _is_readable_string(_rot13(data), min_length):
                    decrypted = _rot13(data)
                    key_used = "rot13"

            if decrypted:
                try:
                    decoded = decrypted.decode("utf-8", errors="replace")
                    if "\x00" in decoded:
                        decoded = decoded[: decoded.index("\x00")]
                    results.append(
                        {
                            "address": hex(ea),
                            "algorithm": algo,
                            "key": key_used,
                            "decrypted": decoded[:128],
                            "confidence": 0.7,
                        }
                    )
                    break
                except Exception:
                    continue

    return results


@tool
@idasync
def find_encrypted_strings(
    patterns: Annotated[
        list[str] | str, "Byte patterns to search for (e.g., '48 8B ?? ??')"
    ] = "",
    min_length: Annotated[int, "Minimum string length to report"] = 4,
    section: Annotated[str, "Section filter (.text, .data, .rdata, '')"] = "",
    encoding: Annotated[str, "Output encoding (utf-8, utf-16)"] = "utf-8",
) -> StringScanResult:
    """Find potentially encrypted/obfuscated strings in memory.

    Scans for strings that may be encrypted (XOR, ADD, ROT13).
    Use this to discover obfuscated strings in packed malware.
    """
    try:
        sections_to_scan = []

        if section:
            seg = ida_segment.getnseg(ida_segment.get_segm_qty() - 1)
            for i in range(ida_segment.get_segm_qty()):
                seg = ida_segment.getnseg(i)
                if seg and ida_segment.get_segm_name(seg) == section:
                    sections_to_scan.append((seg.start_ea, seg.end_ea))
                    break
        else:
            for i in range(ida_segment.get_segm_qty()):
                seg = ida_segment.getnseg(i)
                if seg and seg.perm & ida_segment.SEGPERM_READ:
                    sections_to_scan.append((seg.start_ea, seg.end_ea))

        all_results = []
        for start_ea, end_ea in sections_to_scan:
            if end_ea - start_ea > 10 * 1024 * 1024:
                end_ea = start_ea + 10 * 1024 * 1024

            results = _scan_for_encrypted_strings(start_ea, end_ea, min_length)
            all_results.extend(results)

        truncated = len(all_results) > 500
        if truncated:
            all_results = all_results[:500]

        return {
            "matches": all_results,
            "total": len(all_results),
            "truncated": truncated,
        }
    except Exception as e:
        return {
            "matches": [],
            "total": 0,
            "truncated": False,
            "error": str(e),
        }


@tool
@idasync
def decrypt_strings(
    addresses: Annotated[list[str] | str, "String addresses to decrypt"],
    algorithm: Annotated[str, "Decryption algorithm: xor, add, rot13, custom"],
    key: Annotated[str, "Decryption key (hex like '0xAA' or string)"] = "",
    key_func: Annotated[
        str, "Custom Python decryption function (use py_eval instead)"
    ] = "",
) -> list[DecryptionResult]:
    """Decrypt strings at specified addresses.

    Decrypts one or more strings using the specified algorithm.
    Supports XOR (single-byte or multi-byte key), ADD, ROT13, or custom.
    """
    addrs = normalize_list_input(addresses)
    results = []

    algo = algorithm.strip().lower() if algorithm else "xor"

    for addr_str in addrs:
        try:
            ea = parse_address(addr_str)
        except Exception as e:
            results.append(
                {
                    "address": addr_str,
                    "decrypted": "",
                    "success": False,
                    "error": f"Invalid address: {e}",
                }
            )
            continue

        try:
            raw = ida_bytes.get_bytes(ea, 256)
            if not raw:
                results.append(
                    {
                        "address": addr_str,
                        "decrypted": "",
                        "success": False,
                        "error": "Cannot read bytes",
                    }
                )
                continue

            if b"\x00" in raw:
                raw = raw[: raw.index(b"\x00")]

            decrypted = ""
            original_hex = raw.hex()

            if algo == "xor":
                decrypted = _xOR_string(raw, key) or ""
            elif algo == "add":
                try:
                    key_val = int(key, 16) if key.startswith("0x") else int(key, 10)
                    decrypted = _add_decrypt(raw, key_val & 0xFF).decode(
                        "utf-8", errors="replace"
                    )
                except Exception:
                    decrypted = ""
            elif algo == "rot13":
                decrypted = _rot13(raw).decode("utf-8", errors="replace")
            elif algo == "custom":
                decrypted = raw.decode("utf-8", errors="replace")
            else:
                decrypted = raw.decode("utf-8", errors="replace")

            results.append(
                {
                    "address": addr_str,
                    "original": original_hex[:64],
                    "decrypted": decrypted[:256],
                    "success": bool(decrypted),
                }
            )

        except Exception as e:
            results.append(
                {
                    "address": addr_str,
                    "decrypted": "",
                    "success": False,
                    "error": str(e),
                }
            )

    return results


@tool
@idasync
def auto_detect_obfuscation(
    addresses: Annotated[list[str] | str, "String addresses to analyze"],
) -> list[ObfuscationTypeResult]:
    """Auto-detect obfuscation type for strings.

    Analyzes strings and attempts to detect the obfuscation algorithm used.
    Returns detected type and confidence score.
    """
    addrs = normalize_list_input(addresses)
    results = []

    for addr_str in addrs:
        try:
            ea = parse_address(addr_str)
        except Exception as e:
            results.append(
                {
                    "address": addr_str,
                    "detected_type": "unknown",
                    "confidence": 0.0,
                    "details": f"Invalid address: {e}",
                }
            )
            continue

        try:
            raw = ida_bytes.get_bytes(ea, 256)
            if not raw:
                results.append(
                    {
                        "address": addr_str,
                        "detected_type": "unknown",
                        "confidence": 0.0,
                        "details": "Cannot read bytes",
                    }
                )
                continue

            if b"\x00" in raw:
                raw = raw[: raw.index(b"\x00")]

            detected_type = "plain"
            confidence = 1.0

            xor_candidates = []
            for k in range(1, 256):
                test = _xOR(raw, k)
                if _is_readable_string(test, 4):
                    xor_candidates.append(hex(k))

            add_candidates = []
            for k in range(1, 256):
                test = _add_decrypt(raw, k)
                if _is_readable_string(test, 4):
                    add_candidates.append(hex(k))

            rot13_test = _rot13(raw)
            if _is_readable_string(rot13_test, 4):
                detected_type = "rot13"
                confidence = 0.8
            elif xor_candidates:
                if len(xor_candidates) == 1:
                    detected_type = f"xor:{xor_candidates[0]}"
                    confidence = 0.9
                else:
                    detected_type = f"xor (multiple keys: {len(xor_candidates)})"
                    confidence = 0.6
            elif add_candidates:
                detected_type = f"add:{add_candidates[0]}"
                confidence = 0.7
            elif _is_readable_string(raw, 4):
                detected_type = "plain"
                confidence = 1.0
            else:
                detected_type = "unknown"
                confidence = 0.0

            results.append(
                {
                    "address": addr_str,
                    "detected_type": detected_type,
                    "confidence": confidence,
                }
            )

        except Exception as e:
            results.append(
                {
                    "address": addr_str,
                    "detected_type": "error",
                    "confidence": 0.0,
                    "details": str(e),
                }
            )

    return results


# VM Handler Detection


@tool
@idasync
def detect_vm_handlers(
    function: Annotated[str, "Function address or name to analyze"],
    pattern: Annotated[str, "Optional custom dispatcher pattern"] = "",
) -> list[VMHandlerResult]:
    """Detect VM handler/dispatcher in a function.

    Analyzes a function to detect if it's a VM interpreter.
    Looks for common VM patterns:
    - Indirect jumps (jmp [reg + scale])
    - Handler table dispatch (mov reg, [table + index]; jmp reg)
    - Big switch statements
    """
    try:
        ea = parse_address(function)
        func = idaapi.get_func(ea)
        if not func:
            return [
                {
                    "address": function,
                    "handler_type": "not_function",
                    "confidence": 0.0,
                    "error": "Not a function",
                }
            ]
    except Exception as e:
        return [
            {
                "address": function,
                "handler_type": "error",
                "confidence": 0.0,
                "error": str(e),
            }
        ]

    results = []

    indirect_jumps = 0
    handler_table_refs = 0
    big_switches = 0
    mov_reg_index = 0

    for item_ea in idautils.FuncItems(func.start_ea):
        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, item_ea) == 0:
            continue

        mnem = insn.get_canon_mnem().lower()

        if mnem == "jmp":
            if insn.ops[0].type in (ida_ua.o_mem, ida_ua.o_far):
                indirect_jumps += 1
            if insn.ops[0].type == ida_ua.o_displ:
                handler_table_refs += 1

        elif mnem == "mov" and insn.ops[0].type == ida_ua.o_reg:
            if insn.ops[1].type in (ida_ua.o_mem, ida_ua.o_displ):
                mov_reg_index += 1

    for xref in idautils.XrefsFrom(func.start_ea, 0):
        target = xref.to
        target_func = idaapi.get_func(target)
        if target_func and (target_func.end_ea - target_func.start_ea) > 1000:
            big_switches += 1

    confidence = 0.0
    handler_type = "none"

    if indirect_jumps > 3 and handler_table_refs > 3:
        handler_type = "indirect_jump_dispatcher"
        confidence = min(0.7, (indirect_jumps + handler_table_refs) / 20.0)
    elif mov_reg_index > 2 and indirect_jumps > 2:
        handler_type = "handler_table_dispatch"
        confidence = min(0.8, (mov_reg_index + indirect_jumps) / 15.0)
    elif big_switches > 2:
        handler_type = "large_switch"
        confidence = 0.6

    results.append(
        {
            "address": function,
            "handler_type": handler_type,
            "confidence": confidence,
            "instruction_count": func.end_ea - func.start_ea,
        }
    )

    return results


@tool
@idasync
def reconstruct_handler_table(
    function: Annotated[str, "VM dispatcher function address"],
    handler_size: Annotated[int, "Handler entry size (4=32bit, 8=64bit)"] = 4,
) -> HandlerTableResult:
    """Reconstruct a VM handler table.

    Attempts to find and reconstruct the handler table for a VM.
    Uses the dispatcher function to find the table base.
    """
    try:
        ea = parse_address(function)
        func = idaapi.get_func(ea)
        if not func:
            return {
                "base_address": function,
                "entry_size": handler_size,
                "handlers": [],
                "total": 0,
                "error": "Not a function",
            }
    except Exception as e:
        return {
            "base_address": function,
            "entry_size": handler_size,
            "handlers": [],
            "total": 0,
            "error": str(e),
        }

    handler_table_ea = idaapi.BADADDR

    for item_ea in idautils.FuncItems(func.start_ea):
        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, item_ea) == 0:
            continue

        if insn.get_canon_mnem().lower() == "mov":
            if insn.ops[1].type == ida_ua.o_mem:
                handler_table_ea = insn.ops[1].addr
                break

    if handler_table_ea == idaapi.BADADDR:
        return {
            "base_address": function,
            "entry_size": handler_size,
            "handlers": [],
            "total": 0,
            "error": "Handler table not found",
        }

    handlers = []
    max_handlers = 256
    entry_size_bytes = handler_size

    for i in range(max_handlers):
        entry_ea = handler_table_ea + (i * entry_size_bytes)
        if not ida_bytes.is_mapped(entry_ea):
            break

        if entry_size_bytes == 4:
            entry_val = ida_bytes.get_long(entry_ea)
        else:
            entry_val = ida_bytes.get_qword(entry_ea)

        if entry_val == 0 or entry_val == idaapi.BADADDR:
            break

        handlers.append(hex(entry_val))

    return {
        "base_address": hex(handler_table_ea),
        "entry_size": handler_size,
        "handlers": handlers[:100],
        "total": len(handlers),
    }


@tool
@idasync
def analyze_vm_instructions(
    handler_table_address: Annotated[str, "Handler table base address"],
    max_handlers: Annotated[int, "Maximum handlers to analyze"] = 256,
) -> list[dict]:
    """Analyze VM instructions from handler table.

    Decodes instructions at each handler address in the table.
    Note: This is a best-effort analysis; VM instruction sets vary.
    """
    try:
        table_ea = parse_address(handler_table_address)
    except Exception as e:
        return [
            {
                "handler": handler_table_address,
                "error": f"Invalid address: {e}",
            }
        ]

    results = []
    entry_size = 4

    for i in range(max_handlers):
        entry_ea = table_ea + (i * entry_size)
        if not ida_bytes.is_mapped(entry_ea):
            break

        entry_val = ida_bytes.get_long(entry_ea)
        if entry_val == 0 or entry_val == idaapi.BADADDR:
            break

        insn_text = ""
        if ida_bytes.is_code(ida_bytes.get_flags(entry_val)):
            line = idaapi.generate_disasm_line(entry_val, 0)
            insn_text = line if line else ""

        results.append(
            {
                "index": i,
                "handler": hex(entry_val),
                "disassembly": insn_text[:64],
            }
        )

    return results
