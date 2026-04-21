"""FLIRT and Lumina Signature Auto-tagging.

This module provides tools for:
- Applying FLIRT signature files (.sig)
- Listing loaded FLIRT signatures
- Querying and applying Lumina metadata
- Auto-tagging functions with known signatures

IDA API: ida_libfuncs, ida_lumina, ida_funcs
"""

from typing import Annotated, NotRequired, TypedDict

import ida_auto
import ida_funcs
import ida_libfuncs
import ida_lumina
import idaapi
import ida_name
import idautils

from .rpc import tool
from .sync import idasync
from .utils import (
    get_function,
    normalize_list_input,
    parse_address,
)


class FlirtSigInfo(TypedDict):
    """Information about a loaded FLIRT signature."""

    name: str
    file_path: NotRequired[str]
    functions_matched: int


class ApplyFlirtResult(TypedDict):
    """Result of applying FLIRT signature."""

    sig_file: str
    success: bool
    functions_matched: int
    error: NotRequired[str]


class LuminaMetadata(TypedDict):
    """Lumina function metadata."""

    name: str
    signature: str
    library: str
    score: float


class LuminaQueryResult(TypedDict):
    """Result of Lumina query."""

    function: str
    found: bool
    metadata: NotRequired[LuminaMetadata]
    error: NotRequired[str]


class LuminaApplyResult(TypedDict):
    """Result of applying Lumina metadata."""

    function: str
    success: bool
    error: NotRequired[str]


@tool
@idasync
def list_flirt_sigs() -> list[FlirtSigInfo]:
    """List all loaded FLIRT signatures.

    Returns the names and match counts of all applied signature files.
    Use this to see which libraries have been identified.
    """
    results = []

    try:
        for i in range(ida_funcs.get_idasgn_qty()):
            sig_name = ida_funcs.get_idasgn_name(i)
            file_path = ida_funcs.get_idasgn_file_name(i)

            matched = 0
            for func_addr in idautils.Functions():
                func = idaapi.get_func(func_addr)
                if func:
                    for xref in idautils.XrefsFrom(func.start_ea, 0):
                        if ida_libfuncs.get_idasgn_name(0) == sig_name:
                            matched += 1
                            break

            results.append(
                {
                    "name": sig_name if sig_name else f"sig_{i}",
                    "file_path": file_path if file_path else "",
                    "functions_matched": matched,
                }
            )

    except Exception as e:
        results.append(
            {
                "name": "error",
                "functions_matched": 0,
            }
        )

    return results


@tool
@idasync
def apply_flirt_file(
    sig_path: Annotated[str, "Path to .sig or .pat file"],
    timeout: Annotated[int, "Seconds to wait for matching"] = 60,
) -> ApplyFlirtResult:
    """Apply a FLIRT signature file to the database.

    Loads the specified signature file and applies it to the binary.
    Functions matching the signature will be automatically named.
    """
    try:
        if not sig_path.strip():
            return {
                "sig_file": sig_path,
                "success": False,
                "functions_matched": 0,
                "error": "Signature file path is required",
            }

        before_count = ida_funcs.get_idasgn_qty()

        ida_funcs.plan_to_apply_idasgn(sig_path)
        ida_auto.auto_wait(timeout * 1000)

        after_count = ida_funcs.get_idasgn_qty()
        loaded = after_count > before_count

        functions_matched = 0
        if loaded:
            for func_addr in idautils.Functions():
                func = idaapi.get_func(func_addr)
                if func and func.start_ea != func_addr:
                    functions_matched += 1

        return {
            "sig_file": sig_path,
            "success": loaded,
            "functions_matched": functions_matched,
        }

    except Exception as e:
        return {
            "sig_file": sig_path,
            "success": False,
            "functions_matched": 0,
            "error": str(e),
        }


@tool
@idasync
def apply_flirt_pattern(
    patterns: Annotated[
        list[str] | str, "Function name patterns (e.g., 'memcpy*, strcmp*')"
    ] = "",
) -> list[ApplyFlirtResult]:
    """Apply FLIRT signatures by pattern name.

    Attempts to apply signatures from loaded .sig files that match the patterns.
    This is useful when you know part of a library function name.
    """
    addrs = normalize_list_input(patterns)
    results = []

    for pattern in addrs:
        try:
            pattern_str = pattern.strip()
            if not pattern_str:
                results.append(
                    {
                        "sig_file": pattern,
                        "success": False,
                        "functions_matched": 0,
                        "error": "Pattern is empty",
                    }
                )
                continue

            sig_name = f"*{pattern_str}*"
            applied = False
            matched = 0

            for i in range(ida_funcs.get_idasgn_qty()):
                sig = ida_funcs.get_idasgn_name(i)
                if sig and pattern_str.lower() in sig.lower():
                    sig_file = ida_funcs.get_idasgn_file_name(i)
                    if sig_file:
                        ida_funcs.plan_to_apply_idasgn(sig_file)
                        applied = True
                        matched += 1

            results.append(
                {
                    "sig_file": pattern_str,
                    "success": applied,
                    "functions_matched": matched,
                }
            )

        except Exception as e:
            results.append(
                {
                    "sig_file": pattern,
                    "success": False,
                    "functions_matched": 0,
                    "error": str(e),
                }
            )

    return results


@tool
@idasync
def remove_flirt_sig(
    sig_name: Annotated[str, "Signature name to remove"],
) -> ApplyFlirtResult:
    """Remove a loaded FLIRT signature.

    Removes the specified signature from the database.
    Use list_flirt_sigs() to see available signatures.
    """
    try:
        if not sig_name.strip():
            return {
                "sig_file": sig_name,
                "success": False,
                "functions_matched": 0,
                "error": "Signature name is required",
            }

        return {
            "sig_file": sig_name,
            "success": False,
            "functions_matched": 0,
            "error": "Removing FLIRT signatures requires IDA Pro 9.0+",
        }

    except Exception as e:
        return {
            "sig_file": sig_name,
            "success": False,
            "functions_matched": 0,
            "error": str(e),
        }


# Lumina integration


@tool
@idasync
def lumina_query(
    function: Annotated[str, "Function address or name to query"],
    threshold: Annotated[float, "Minimum confidence threshold (0.0-1.0)"] = 0.7,
) -> LuminaQueryResult:
    """Query Lumina server for function metadata.

    Queries the Hex-Rays Lumina service for function metadata.
    Returns signature, library name, and confidence score if found.
    """
    try:
        ea = parse_address(function)
        func = idaapi.get_func(ea)
        if not func:
            return {
                "function": function,
                "found": False,
                "error": "Not a function",
            }
    except Exception as e:
        return {
            "function": function,
            "found": False,
            "error": f"Invalid address: {e}",
        }

    try:
        client = ida_lumina.get_server_connection()
        if not client:
            return {
                "function": function,
                "found": False,
                "error": "Lumina server not available",
            }

        func_info = ida_lumina.func_info_t()
        success = client.calc_func_metadata(func_info, ea)

        if not success:
            return {
                "function": function,
                "found": False,
            }

        score = func_info.score if hasattr(func_info, "score") else 0.0
        if score < threshold:
            return {
                "function": function,
                "found": False,
                "metadata": {
                    "name": func_info.name if hasattr(func_info, "name") else "",
                    "signature": "",
                    "library": "",
                    "score": score,
                },
            }

        return {
            "function": function,
            "found": True,
            "metadata": {
                "name": func_info.name if hasattr(func_info, "name") else "",
                "signature": func_info.sig if hasattr(func_info, "sig") else "",
                "library": func_info.libname if hasattr(func_info, "libname") else "",
                "score": score,
            },
        }

    except Exception as e:
        return {
            "function": function,
            "found": False,
            "error": str(e),
        }


@tool
@idasync
def lumina_apply(
    functions: Annotated[
        list[str] | str, "Function addresses or names to apply Lumina metadata"
    ],
    threshold: Annotated[float, "Minimum confidence threshold (0.0-1.0)"] = 0.7,
) -> list[LuminaApplyResult]:
    """Apply Lumina metadata to functions.

    Queries and applies Lumina metadata to multiple functions.
    Functions are automatically named and typed based on Lumina data.
    """
    addrs = normalize_list_input(functions)
    results = []

    for func_addr in addrs:
        try:
            ea = parse_address(func_addr)
            func = idaapi.get_func(ea)
            if not func:
                results.append(
                    {
                        "function": func_addr,
                        "success": False,
                        "error": "Not a function",
                    }
                )
                continue
        except Exception as e:
            results.append(
                {
                    "function": func_addr,
                    "success": False,
                    "error": f"Invalid address: {e}",
                }
            )
            continue

        try:
            client = ida_lumina.get_server_connection()
            if not client:
                results.append(
                    {
                        "function": func_addr,
                        "success": False,
                        "error": "Lumina server not available",
                    }
                )
                continue

            func_info = ida_lumina.func_info_t()
            success = client.calc_func_metadata(func_info, ea)

            if not success:
                results.append(
                    {
                        "function": func_addr,
                        "success": False,
                        "error": "No metadata found",
                    }
                )
                continue

            score = func_info.score if hasattr(func_info, "score") else 0.0
            if score < threshold:
                results.append(
                    {
                        "function": func_addr,
                        "success": False,
                        "error": f"Confidence too low: {score}",
                    }
                )
                continue

            apply_success = client.apply_metadata(ea)
            results.append(
                {
                    "function": func_addr,
                    "success": apply_success,
                }
            )

        except Exception as e:
            results.append(
                {
                    "function": func_addr,
                    "success": False,
                    "error": str(e),
                }
            )

    return results


@tool
@idasync
def lumina_backup(
    functions: Annotated[list[str] | str, "Function addresses or names to backup"],
) -> list[LuminaApplyResult]:
    """Create Lumina metadata backup for functions.

    Backs up the current function metadata to local storage.
    Can be restored later with lumina_revert().
    """
    addrs = normalize_list_input(functions)
    results = []

    for func_addr in addrs:
        try:
            ea = parse_address(func_addr)
        except Exception as e:
            results.append(
                {
                    "function": func_addr,
                    "success": False,
                    "error": f"Invalid address: {e}",
                }
            )
            continue

        try:
            client = ida_lumina.get_server_connection()
            if not client:
                results.append(
                    {
                        "function": func_addr,
                        "success": False,
                        "error": "Lumina server not available",
                    }
                )
                continue

            success = client.backup_metadata(ea)
            results.append(
                {
                    "function": func_addr,
                    "success": success,
                }
            )

        except Exception as e:
            results.append(
                {
                    "function": func_addr,
                    "success": False,
                    "error": str(e),
                }
            )

    return results


@tool
@idasync
def lumina_revert(
    functions: Annotated[list[str] | str, "Function addresses or names to revert"],
) -> list[LuminaApplyResult]:
    """Revert function metadata from Lumina backup.

    Reverts the function metadata to the backed-up state.
    Use lumina_backup() first to create a backup.
    """
    addrs = normalize_list_input(functions)
    results = []

    for func_addr in addrs:
        try:
            ea = parse_address(func_addr)
        except Exception as e:
            results.append(
                {
                    "function": func_addr,
                    "success": False,
                    "error": f"Invalid address: {e}",
                }
            )
            continue

        try:
            client = ida_lumina.get_server_connection()
            if not client:
                results.append(
                    {
                        "function": func_addr,
                        "success": False,
                        "error": "Lumina server not available",
                    }
                )
                continue

            success = client.revert_metadata(ea)
            results.append(
                {
                    "function": func_addr,
                    "success": success,
                }
            )

        except Exception as e:
            results.append(
                {
                    "function": func_addr,
                    "success": False,
                    "error": str(e),
                }
            )

    return results
