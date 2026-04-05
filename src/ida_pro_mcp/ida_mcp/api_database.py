"""Database management operations for IDA Pro MCP.

Provides tools for database snapshots, export, undo/redo,
database options/settings, and additional file loading.
"""

from typing import Annotated, TypedDict

import ida_loader
import ida_ida
import ida_kernwin
import ida_auto
import ida_nalt
import ida_bytes
import ida_segment
import idaapi
import idc

from .rpc import tool, unsafe
from .sync import idasync, tool_timeout


# ============================================================================
# Open File Tool
# ============================================================================


@unsafe
@tool
def open_file(
    path: Annotated[str, "Path to the binary or IDB file to open"],
) -> dict:
    """Open a binary or IDB file in IDA Pro.

    Saves and closes the current IDA instance, then launches a new one
    with the specified file. The MCP server is started automatically
    in the new instance.
    """
    import os
    import subprocess
    import sys
    import threading

    if not os.path.isfile(path):
        return {"ok": False, "error": f"File not found: {path}"}

    abs_path = os.path.abspath(path)

    # sys.executable is the IDA binary (ida.exe / ida64.exe)
    ida_exe = sys.executable
    if not os.path.isfile(ida_exe) or "ida" not in os.path.basename(ida_exe).lower():
        return {"ok": False, "error": f"Cannot determine IDA executable: {ida_exe}"}

    # Save current database
    try:
        ida_loader.save_database("", 0)
    except Exception:
        pass

    # Write a startup script that auto-starts the MCP server
    import tempfile

    startup_script = tempfile.NamedTemporaryFile(
        mode="w", suffix=".py", prefix="ida_mcp_start_", delete=False
    )
    startup_script.write(
        'import ida_loader\nida_loader.load_and_run_plugin("ida_mcp", 0)\n'
    )
    startup_script.close()

    # Launch helper that waits for old IDA to exit, launches new IDA
    # (with -S script to auto-start MCP), and auto-dismisses dialogs.
    if sys.platform == "win32":
        python_exe = os.path.join(sys.prefix, "python.exe")
        if not os.path.isfile(python_exe):
            import shutil

            python_exe = shutil.which("python") or shutil.which("python3") or "python"

        launch_script = (
            _DIALOG_AUTO_OK_SCRIPT.replace("__OLD_PID__", str(os.getpid()))
            .replace("__IDA_EXE__", ida_exe)
            .replace("__STARTUP_SCRIPT__", startup_script.name)
            .replace("__FILEPATH__", abs_path)
        )
        subprocess.Popen(
            [python_exe, "-c", launch_script],
            creationflags=0x08000000,  # CREATE_NO_WINDOW
        )

    # Close the current IDA instance after a short delay
    # (allows the MCP response to be sent first)
    def _quit():
        def _do():
            idc.qexit(0)
            return False

        ida_kernwin.execute_ui_requests([_do])

    timer = threading.Timer(1.0, _quit)
    timer.daemon = True
    timer.start()

    return {
        "ok": True,
        "path": abs_path,
        "ida_exe": ida_exe,
        "message": f"Launched IDA with {os.path.basename(abs_path)}. Current instance will close.",
    }


# Helper script that auto-clicks OK/Load existing on IDA dialogs.
_DIALOG_AUTO_OK_SCRIPT = r"""
import ctypes
import subprocess
import time

OLD_PID = __OLD_PID__
IDA_EXE = r"__IDA_EXE__"
STARTUP_SCRIPT = r"__STARTUP_SCRIPT__"
FILEPATH = r"__FILEPATH__"

user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32
user32.GetTopWindow.argtypes = [ctypes.c_void_p]
user32.GetTopWindow.restype = ctypes.c_void_p
user32.GetWindow.argtypes = [ctypes.c_void_p, ctypes.c_uint]
user32.GetWindow.restype = ctypes.c_void_p
user32.IsWindowVisible.argtypes = [ctypes.c_void_p]
user32.GetWindowTextW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_int]
user32.FindWindowExW.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_wchar_p]
user32.FindWindowExW.restype = ctypes.c_void_p
user32.SendMessageW.argtypes = [ctypes.c_void_p, ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p]
user32.PostMessageW.argtypes = [ctypes.c_void_p, ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p]
user32.SetForegroundWindow.argtypes = [ctypes.c_void_p]

BM_CLICK = 0x00F5


def find_window_by_title(title):
    hwnd = user32.GetTopWindow(None)
    while hwnd:
        if user32.IsWindowVisible(hwnd):
            txt = ctypes.create_unicode_buffer(512)
            user32.GetWindowTextW(hwnd, txt, 512)
            if txt.value == title:
                return hwnd
        hwnd = user32.GetWindow(hwnd, 2)
    return None


def click_button(parent, text):
    child = user32.FindWindowExW(parent, None, None, None)
    while child:
        txt = ctypes.create_unicode_buffer(256)
        user32.GetWindowTextW(child, txt, 256)
        if txt.value == text:
            user32.SendMessageW(child, BM_CLICK, None, None)
            return True
        if click_button(child, text):
            return True
        child = user32.FindWindowExW(parent, child, None, None)
    return False


# Wait for old IDA to exit before launching the new one
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
SYNCHRONIZE = 0x00100000
handle = kernel32.OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, False, OLD_PID)
if handle:
    kernel32.WaitForSingleObject(handle, 30000)  # wait up to 30s
    kernel32.CloseHandle(handle)
else:
    time.sleep(3)  # fallback

# Launch new IDA
subprocess.Popen([IDA_EXE, "-S" + STARTUP_SCRIPT, FILEPATH])

# Wait for and dismiss "Load a new file" (loader selection) dialog
for _ in range(300):  # up to 30 seconds
    time.sleep(0.1)
    dlg = find_window_by_title("Load a new file")
    if dlg:
        time.sleep(0.5)
        click_button(dlg, "OK")
        break

# Give IDA time to process the loader selection before the next dialog
time.sleep(3)

# Wait for and dismiss "Please confirm" (existing DB) dialog.
# Qt buttons may not have Win32 HWNDs, so use keyboard accelerators:
# &Load existing -> Alt+L, &Overwrite -> Alt+O
WM_KEYDOWN = 0x0100
WM_KEYUP = 0x0101
WM_SYSKEYDOWN = 0x0104
WM_SYSKEYUP = 0x0105
VK_MENU = 0x12  # Alt key
for _ in range(300):  # up to 30 seconds
    time.sleep(0.1)
    dlg = find_window_by_title("Please confirm")
    if dlg:
        time.sleep(0.5)
        # Qt buttons don't have Win32 HWNDs, use Alt+L accelerator
        user32.SetForegroundWindow(dlg)
        time.sleep(0.3)
        user32.PostMessageW(dlg, WM_SYSKEYDOWN, VK_MENU, 0)
        time.sleep(0.05)
        user32.PostMessageW(dlg, WM_SYSKEYDOWN, ord('L'), 0)
        time.sleep(0.05)
        user32.PostMessageW(dlg, WM_SYSKEYUP, ord('L'), 0)
        user32.PostMessageW(dlg, WM_KEYUP, VK_MENU, 0)
        break
"""


# ============================================================================
# TypedDict Definitions
# ============================================================================


class SnapshotCreate(TypedDict, total=False):
    description: Annotated[str, "Snapshot description"]


class LoadFileOp(TypedDict, total=False):
    path: Annotated[str, "Path to the file to load"]
    offset: Annotated[int, "File offset to load from (default 0)"]
    addr: Annotated[str, "Address to load at"]
    size: Annotated[int, "Number of bytes to load (0=all)"]


# ============================================================================
# Snapshot (Undo Point) Tools
# ============================================================================


@tool
@idasync
def list_snapshots() -> list[dict]:
    """List all database snapshots (undo points).

    Snapshots are restore points that allow undoing changes to the database.
    """
    snapshots = []
    ssv = ida_kernwin.snapshots_t()  # type: ignore[attr-defined]  # ty: ignore[unresolved-attribute]
    if hasattr(ida_kernwin, "get_snapshots"):
        ok = ida_kernwin.get_snapshots(ssv)
        if ok:
            for i in range(ssv.size()):
                s = ssv.get(i)
                snapshots.append(
                    {
                        "index": i,
                        "id": s.id if hasattr(s, "id") else i,
                        "description": s.desc if hasattr(s, "desc") else "",
                        "filename": s.filename if hasattr(s, "filename") else "",
                    }
                )
    return snapshots


@unsafe
@tool
@idasync
def take_snapshot(
    description: Annotated[str, "Snapshot description"] = "MCP snapshot",
) -> dict:
    """Take a database snapshot (undo point).

    Creates a restore point that can be used to undo changes.
    """
    ss = ida_kernwin.snapshot_t()  # type: ignore[attr-defined]  # ty: ignore[unresolved-attribute]
    ss.desc = description
    if ida_kernwin.take_database_snapshot(ss):
        return {"ok": True, "description": description}
    return {"ok": False, "error": "Failed to take snapshot"}


@unsafe
@tool
@idasync
def restore_snapshot(
    index: Annotated[int, "Snapshot index to restore (from list_snapshots)"],
) -> dict:
    """Restore a database snapshot (undo to a previous state)."""
    ssv = ida_kernwin.snapshots_t()  # type: ignore[attr-defined]  # ty: ignore[unresolved-attribute]
    if hasattr(ida_kernwin, "get_snapshots"):
        ok = ida_kernwin.get_snapshots(ssv)
        if ok and index < ssv.size():
            ss = ssv.get(index)
            if ida_kernwin.restore_database_snapshot(ss):
                return {"ok": True, "index": index}
            return {"ok": False, "error": "Failed to restore snapshot"}
    return {"ok": False, "error": f"Snapshot {index} not found"}


# ============================================================================
# Export Tools
# ============================================================================


@tool
@idasync
@tool_timeout(300.0)
def export_database(
    path: Annotated[str, "Output file path"],
    format: Annotated[str, "Export format: idc|asm|map|lst|html|dif"] = "asm",
) -> dict:
    """Export the database to various formats.

    Formats:
    - idc: IDC script that recreates the database
    - asm: Assembly listing
    - map: MAP file (symbols and addresses)
    - lst: Full listing with hex dump
    - html: HTML formatted listing
    - dif: Difference file (patches)
    """
    format_flags = {
        "idc": ida_loader.OFILE_IDC,
        "asm": ida_loader.OFILE_ASM,
        "map": ida_loader.OFILE_MAP,
        "lst": ida_loader.OFILE_LST,
        "dif": ida_loader.OFILE_DIF,
    }

    if format == "html":
        # HTML export uses a different mechanism
        try:
            with open(path, "w") as f:
                f.write("<html><body><pre>\n")
                ea = ida_ida.inf_get_min_ea()
                end = ida_ida.inf_get_max_ea()
                count = 0
                while ea < end and count < 100000:
                    line = idc.generate_disasm_line(ea, 0)
                    if line:
                        import html as html_mod

                        f.write(html_mod.escape(line) + "\n")
                    ea = idc.next_head(ea, end)
                    if ea == idaapi.BADADDR:
                        break
                    count += 1
                f.write("</pre></body></html>\n")
            return {"ok": True, "path": path, "format": format}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    flag = format_flags.get(format)
    if flag is None:
        return {
            "ok": False,
            "error": f"Unknown format: {format}. Use: {', '.join(format_flags.keys())}",
        }

    try:
        ofile = ida_loader.gen_file(
            flag, path, ida_ida.inf_get_min_ea(), ida_ida.inf_get_max_ea(), 0
        )
        return {"ok": ofile >= 0, "path": path, "format": format}
    except Exception as e:
        return {"ok": False, "error": str(e)}


# ============================================================================
# Database Options/Settings Tools
# ============================================================================


@tool
@idasync
def get_db_options() -> dict:
    """Get current database analysis options and settings."""
    result = {
        "analysis": {
            "af": hex(ida_ida.inf_get_af()),
            "af2": hex(ida_ida.inf_get_af2()),
        },
        "addressing": {
            "is_64bit": ida_ida.inf_is_64bit(),
            "is_32bit": ida_ida.inf_is_32bit_exactly(),
            "is_be": ida_ida.inf_is_be(),
        },
        "display": {
            "show_auto": ida_ida.inf_get_show_auto(),  # type: ignore[attr-defined]  # ty: ignore[unresolved-attribute]
            "show_void": ida_ida.inf_get_show_void(),  # type: ignore[attr-defined]  # ty: ignore[unresolved-attribute]
            "show_xref_fncoff": ida_ida.inf_get_xref_show(),  # type: ignore[attr-defined]  # ty: ignore[unresolved-attribute]
        },
        "type_info": {
            "cc_id": ida_ida.inf_get_cc_id(),
            "size_ldbl": ida_ida.inf_get_size_ldbl(),  # type: ignore[attr-defined]  # ty: ignore[unresolved-attribute]
        },
        "paths": {
            "idb_path": ida_loader.get_path(ida_loader.PATH_TYPE_IDB) or "",
            "input_file": ida_nalt.get_input_file_path() or "",
        },
        "database_change_count": ida_ida.inf_get_database_change_count(),
    }
    return result


@unsafe
@tool
@idasync
def set_db_option(
    option: Annotated[str, "Option name: af|af2|show_auto|show_void|cc_id"],
    value: Annotated[str, "Value to set (hex or decimal)"],
) -> dict:
    """Set a database analysis option."""
    val = int(value, 0)

    setters = {
        "af": ida_ida.inf_set_af,
        "af2": ida_ida.inf_set_af2,
        "show_auto": ida_ida.inf_set_show_auto,
        "show_void": ida_ida.inf_set_show_void,
        "cc_id": ida_ida.inf_set_cc_id,
    }

    setter = setters.get(option)
    if setter is None:
        return {
            "ok": False,
            "error": f"Unknown option: {option}. Use: {', '.join(setters.keys())}",
        }

    setter(val)  # type: ignore[arg-type]  # ty: ignore[invalid-argument-type]
    return {"option": option, "value": hex(val), "ok": True}


# ============================================================================
# Additional File Loading Tools
# ============================================================================


@unsafe
@tool
@idasync
def load_binary_file(
    path: Annotated[str, "Path to binary file to load"],
    addr: Annotated[str, "Address to load the file at"],
    offset: Annotated[int, "File offset to start loading from"] = 0,
    size: Annotated[int, "Number of bytes to load (0=entire file)"] = 0,
) -> dict:
    """Load a binary file into the database at a specified address.

    This loads raw bytes from a file into the IDA database, creating
    or overwriting data at the specified address.
    """
    import os

    ea = int(addr, 0) if isinstance(addr, str) else addr

    if not os.path.isfile(path):
        return {"ok": False, "error": f"File not found: {path}"}

    with open(path, "rb") as f:
        if offset:
            f.seek(offset)
        if size > 0:
            data = f.read(size)
        else:
            data = f.read()

    if not data:
        return {"ok": False, "error": "No data to load"}

    # Write bytes into the database
    for i, byte in enumerate(data):
        ida_bytes.patch_byte(ea + i, byte)

    return {
        "ok": True,
        "addr": hex(ea),
        "size": len(data),
        "path": path,
    }


@tool
@idasync
def db_statistics() -> dict:
    """Get database statistics (function count, segment count, name count, etc.)."""
    import idautils

    func_count = 0
    for _ in idautils.Functions():
        func_count += 1

    seg_count = ida_segment.get_segm_qty()

    name_count = 0
    for _ in idautils.Names():
        name_count += 1

    import ida_entry

    entry_count = ida_entry.get_entry_qty()

    code_size = 0
    data_size = 0
    for i in range(seg_count):
        seg = ida_segment.getnseg(i)
        if seg:
            sclass = ida_segment.get_segm_class(seg) or ""
            if sclass == "CODE":
                code_size += seg.size()
            else:
                data_size += seg.size()

    return {
        "functions": func_count,
        "segments": seg_count,
        "names": name_count,
        "entries": entry_count,
        "code_size": code_size,
        "data_size": data_size,
        "total_size": ida_ida.inf_get_max_ea() - ida_ida.inf_get_min_ea(),
        "min_ea": hex(ida_ida.inf_get_min_ea()),
        "max_ea": hex(ida_ida.inf_get_max_ea()),
        "database_change_count": ida_ida.inf_get_database_change_count(),
    }


# ============================================================================
# Undo/Redo Tools (IDA 9+)
# ============================================================================


@unsafe
@tool
@idasync
def undo() -> dict:
    """Undo the last database operation (IDA 9+)."""
    if not hasattr(ida_auto, "undo"):
        return {"ok": False, "error": "Undo not available (requires IDA 9+)"}
    try:
        ok = ida_auto.undo()
        return {"ok": ok}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@unsafe
@tool
@idasync
def redo() -> dict:
    """Redo the last undone operation (IDA 9+)."""
    if not hasattr(ida_auto, "redo"):
        return {"ok": False, "error": "Redo not available (requires IDA 9+)"}
    try:
        ok = ida_auto.redo()
        return {"ok": ok}
    except Exception as e:
        return {"ok": False, "error": str(e)}
