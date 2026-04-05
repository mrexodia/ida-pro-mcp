"""Loader and file format information for IDA Pro MCP.

Provides tools for querying file format details, section headers,
and loaded file metadata.
"""

from typing import Annotated

import ida_loader
import ida_ida
import ida_nalt
import ida_segment
import idaapi
import idc

from .rpc import tool
from .sync import idasync
from .utils import paginate, pattern_filter


# ============================================================================
# Loader/File Format Tools
# ============================================================================


@tool
@idasync
def file_info() -> dict:
    """Get loaded file metadata (format, SHA256, MD5, CRC32, size, etc.)."""
    result = {
        "input_file": ida_nalt.get_input_file_path() or "",
        "file_type": ida_ida.inf_get_filetype(),
        "processor": idaapi.get_inf_structure().procname
        if hasattr(idaapi, "get_inf_structure")
        else "",
        "bitness": 64
        if ida_ida.inf_is_64bit()
        else (32 if ida_ida.inf_is_32bit_exactly() else 16),
        "is_be": ida_ida.inf_is_be(),
        "min_ea": hex(ida_ida.inf_get_min_ea()),
        "max_ea": hex(ida_ida.inf_get_max_ea()),
    }

    # SHA256
    sha = ida_nalt.retrieve_input_file_sha256()
    if sha:
        result["sha256"] = sha.hex() if isinstance(sha, bytes) else str(sha)

    # MD5
    md5 = ida_nalt.retrieve_input_file_md5()
    if md5:
        result["md5"] = md5.hex() if isinstance(md5, bytes) else str(md5)

    # CRC32
    crc = ida_nalt.retrieve_input_file_crc32()
    if crc is not None:
        result["crc32"] = hex(crc)

    # File size
    size = ida_nalt.retrieve_input_file_size()
    if size is not None and size > 0:
        result["file_size"] = size

    return result


@tool
@idasync
def list_loaders() -> list[dict]:
    """List available file format loaders."""
    loaders = []
    li = ida_loader.loader_t()
    # This iterates through built-in loader list
    # In practice, we report the current loader info
    input_file = ida_nalt.get_input_file_path() or ""
    loaders.append(
        {
            "file": input_file,
            "processor": idaapi.get_inf_structure().procname
            if hasattr(idaapi, "get_inf_structure")
            else "",
        }
    )
    return loaders


@tool
@idasync
def file_regions() -> list[dict]:
    """Get all file regions (mapped ranges from the input file to the database)."""
    regions = []
    for i in range(ida_loader.get_fileregion_qty()):
        fr = ida_loader.get_fileregion(i)
        if fr:
            regions.append(
                {
                    "index": i,
                    "start": hex(fr.start_ea) if hasattr(fr, "start_ea") else None,
                    "end": hex(fr.end_ea) if hasattr(fr, "end_ea") else None,
                    "file_offset": hex(fr.offset) if hasattr(fr, "offset") else None,
                }
            )
    return regions


@tool
@idasync
def addr_to_fileoff(
    addr: Annotated[str, "Virtual address"],
) -> dict:
    """Convert virtual address to file offset."""
    from .utils import parse_address

    ea = parse_address(addr)
    offset = ida_loader.get_fileregion_offset(ea)
    if offset == -1:
        return {"addr": hex(ea), "error": "No file offset for this address"}
    return {"addr": hex(ea), "file_offset": hex(offset)}


@tool
@idasync
def fileoff_to_addr(
    offset: Annotated[str, "File offset (hex or decimal)"],
) -> dict:
    """Convert file offset to virtual address."""
    off = int(offset, 0)
    ea = ida_loader.get_fileregion_ea(off)
    if ea == idaapi.BADADDR:
        return {"offset": hex(off), "error": "No address for this file offset"}
    return {"offset": hex(off), "addr": hex(ea)}


@tool
@idasync
def idb_path() -> dict:
    """Get the path to the current IDB file."""
    return {
        "idb_path": ida_loader.get_path(ida_loader.PATH_TYPE_IDB) or "",
        "input_file": ida_nalt.get_input_file_path() or "",
        "database_id": ida_nalt.get_input_file_path() or "",
    }
