#!/usr/bin/env python3
"""Binary Information Extraction Script

This script extracts comprehensive information from an IDA database for use in
writing binary-specific tests. It's designed to be used by LLMs to understand
the structure of a binary before writing targeted tests.

Usage:
    uv run python tests/binary_info.py <binary_path>

Example:
    uv run python tests/binary_info.py tests/crackme03.elf

The output includes:
- Metadata (filename, address range)
- Segments (name, range, size)
- Entry points
- Functions (with sizes)
- Strings (with content)
- Imports
- Globals
- Cross-references for key functions
- Basic blocks for main function
"""

import sys
import json
from pathlib import Path


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    binary_path = sys.argv[1]
    if not Path(binary_path).exists():
        print(f"Error: Binary not found: {binary_path}")
        sys.exit(1)

    # Import and open database
    import idapro

    idapro.open_database(binary_path, True)

    import idaapi
    import idautils
    import idc
    import ida_funcs
    import ida_name
    import ida_bytes
    import ida_entry

    info = {}

    # Metadata
    info["metadata"] = {
        "filename": idaapi.get_root_filename(),
        "min_ea": hex(idaapi.inf_get_min_ea()),
        "max_ea": hex(idaapi.inf_get_max_ea()),
    }

    # Segments
    info["segments"] = []
    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        info["segments"].append(
            {
                "name": idaapi.get_segm_name(seg),
                "start": hex(seg.start_ea),
                "end": hex(seg.end_ea),
                "size": hex(seg.end_ea - seg.start_ea),
            }
        )

    # Entry points
    info["entrypoints"] = []
    entry_count = ida_entry.get_entry_qty()
    for i in range(entry_count):
        ordinal = ida_entry.get_entry_ordinal(i)
        ea = ida_entry.get_entry(ordinal)
        name = ida_entry.get_entry_name(ordinal)
        info["entrypoints"].append(
            {
                "name": name,
                "addr": hex(ea),
                "ordinal": ordinal,
            }
        )

    # Functions
    info["functions"] = []
    for ea in idautils.Functions():
        name = ida_funcs.get_func_name(ea)
        func = ida_funcs.get_func(ea)
        size = func.end_ea - func.start_ea if func else 0

        # Get callers
        callers = []
        for xref in idautils.XrefsTo(ea):
            if xref.type in [idaapi.fl_CN, idaapi.fl_CF]:
                caller_func = ida_funcs.get_func(xref.frm)
                if caller_func:
                    caller_name = ida_funcs.get_func_name(caller_func.start_ea)
                    if caller_name and caller_name not in callers:
                        callers.append(caller_name)

        # Get callees
        callees = []
        if func:
            for head in idautils.Heads(func.start_ea, func.end_ea):
                for xref in idautils.XrefsFrom(head):
                    if xref.type in [idaapi.fl_CN, idaapi.fl_CF]:
                        callee_name = ida_funcs.get_func_name(xref.to)
                        if callee_name and callee_name not in callees:
                            callees.append(callee_name)

        info["functions"].append(
            {
                "name": name,
                "addr": hex(ea),
                "end": hex(func.end_ea) if func else None,
                "size": size,
                "callers": callers,
                "callees": callees,
            }
        )

    # Strings
    info["strings"] = []
    str_count = idaapi.get_strlist_qty()
    for i in range(str_count):
        si = idaapi.string_info_t()
        if idaapi.get_strlist_item(si, i):
            content = idc.get_strlit_contents(si.ea, -1, 0)
            if content:
                try:
                    decoded = content.decode("utf-8", errors="replace")
                except Exception:
                    decoded = repr(content)
                info["strings"].append(
                    {
                        "addr": hex(si.ea),
                        "length": si.length,
                        "content": decoded,
                    }
                )

    # Imports
    info["imports"] = []

    def imp_cb(ea, name, ordinal):
        info["imports"].append(
            {
                "name": name,
                "addr": hex(ea),
            }
        )
        return True

    for idx in range(idaapi.get_import_module_qty()):
        idaapi.get_import_module_name(idx)
        idaapi.enum_import_names(idx, imp_cb)

    # Globals (named addresses that aren't functions)
    info["globals"] = []
    for ea, name in idautils.Names():
        if not ida_funcs.get_func(ea):
            # Get size if possible
            size = ida_bytes.get_item_size(ea)
            info["globals"].append(
                {
                    "name": name,
                    "addr": hex(ea),
                    "size": size,
                }
            )

    # Basic blocks for main (if exists)
    main_ea = ida_name.get_name_ea(idaapi.BADADDR, "main")
    if main_ea != idaapi.BADADDR:
        func = ida_funcs.get_func(main_ea)
        if func:
            info["main_basic_blocks"] = []
            fc = idaapi.FlowChart(func)
            for block in fc:
                succs = [hex(s.start_ea) for s in block.succs()]
                info["main_basic_blocks"].append(
                    {
                        "start": hex(block.start_ea),
                        "end": hex(block.end_ea),
                        "size": block.end_ea - block.start_ea,
                        "successors": succs,
                    }
                )

    idapro.close_database(False)

    # Output as formatted JSON
    print(json.dumps(info, indent=2))


if __name__ == "__main__":
    main()
