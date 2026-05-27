"""Instance discovery for IDA Pro MCP.

IDA plugin instances register themselves by writing JSON files to
{ida_user_dir}/mcp/instances/. The MCP server discovers running
instances by reading these files and validating PID liveness.
"""

import datetime
import glob
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from typing import TypedDict


class LaunchInstanceResult(TypedDict, total=False):
    success: bool
    host: str
    port: int
    binary: str
    pid: int
    message: str
    error: str


class InstanceInfo(TypedDict, total=False):
    host: str
    port: int
    pid: int
    binary: str
    idb_path: str
    started_at: str
    backend: str  # "gui" or "worker"


def _get_ida_user_dir() -> str:
    if sys.platform == "win32":
        return os.path.join(os.environ["APPDATA"], "Hex-Rays", "IDA Pro")
    return os.path.join(os.path.expanduser("~"), ".idapro")


def get_instances_dir() -> str:
    return os.path.join(_get_ida_user_dir(), "mcp", "instances")


def _instance_file_path(port: int) -> str:
    return os.path.join(get_instances_dir(), f"instance_{port}.json")


def register_instance(
    host: str, port: int, pid: int, binary: str, idb_path: str, backend: str = "gui"
) -> str:
    """Write an instance registration file. Returns the file path."""
    info: InstanceInfo = {
        "host": host,
        "port": port,
        "pid": pid,
        "binary": binary,
        "idb_path": idb_path,
        "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "backend": backend,
    }
    instances_dir = get_instances_dir()
    os.makedirs(instances_dir, exist_ok=True)
    file_path = _instance_file_path(port)
    # Atomic write
    fd, tmp_path = tempfile.mkstemp(dir=instances_dir, prefix=".tmp_", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(info, f, indent=2)
        os.replace(tmp_path, file_path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
    return file_path


def unregister_instance(port: int) -> bool:
    """Remove an instance registration file. Returns True if removed."""
    file_path = _instance_file_path(port)
    try:
        os.unlink(file_path)
        return True
    except OSError:
        return False


def is_pid_alive(pid: int) -> bool:
    """Check if a process is still running."""
    if sys.platform == "win32":
        import ctypes

        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        handle = ctypes.windll.kernel32.OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION, False, pid
        )
        if handle:
            ctypes.windll.kernel32.CloseHandle(handle)
            return True
        return False
    else:
        try:
            os.kill(pid, 0)
            return True
        except PermissionError:
            return True  # Process exists, we lack permission
        except ProcessLookupError:
            return False
        except OSError:
            return False


def probe_instance(host: str, port: int, timeout: float = 2.0) -> bool:
    """Check if an instance is reachable via TCP."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False


def discover_instances() -> list[InstanceInfo]:
    """Scan for registered instances, cleaning up stale entries."""
    instances_dir = get_instances_dir()
    if not os.path.isdir(instances_dir):
        return []

    result: list[InstanceInfo] = []
    pattern = os.path.join(instances_dir, "instance_*.json")
    for file_path in glob.glob(pattern):
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                info: InstanceInfo = json.load(f)
        except (json.JSONDecodeError, OSError):
            try:
                os.unlink(file_path)
            except OSError:
                pass
            continue

        if not all(k in info for k in ("host", "port", "pid")):
            try:
                os.unlink(file_path)
            except OSError:
                pass
            continue

        if not is_pid_alive(info["pid"]):
            try:
                os.unlink(file_path)
            except OSError:
                pass
            continue

        # Secondary check: verify the instance is actually listening.
        # Catches PID reuse (Windows can recycle PIDs quickly) and
        # cases where the process is alive but the server crashed.
        if not probe_instance(info["host"], info["port"], timeout=1.0):
            try:
                os.unlink(file_path)
            except OSError:
                pass
            continue

        result.append(info)

    result.sort(key=lambda x: x.get("started_at", ""))
    return result


def _find_existing_idb(file_path: str) -> str | None:
    """Return the path of an existing IDB next to `file_path`, if any."""
    base = os.path.splitext(file_path)[0]
    for ext in (".i64", ".idb"):
        idb_path = base + ext
        if os.path.isfile(idb_path):
            return idb_path
    return None


def _get_ida_executable() -> str:
    """Return the executable path of the current IDA process (or the
    interpreter when not running inside IDA)."""
    if sys.platform == "linux":
        try:
            return os.readlink("/proc/self/exe")
        except OSError:
            pass
    return sys.executable


def launch_gui_instance(
    file_path: str,
    *,
    autonomous: bool = False,
    new_database: bool = False,
    timeout: int = 30,
) -> LaunchInstanceResult:
    """Launch a new IDA GUI process for `file_path` and wait for it to register."""
    if not os.path.isfile(file_path):
        return {"success": False, "error": f"File not found: {file_path}"}

    ida_exe = _get_ida_executable()
    if not os.path.isfile(ida_exe):
        return {"success": False, "error": f"Cannot find IDA executable: {ida_exe}"}

    target = file_path
    if not new_database:
        existing_idb = _find_existing_idb(file_path)
        if existing_idb:
            target = existing_idb

    args = [ida_exe]
    if autonomous:
        args.append("-A")
    if new_database:
        args.append("-c")
    args.append(target)

    before = {(i["host"], i["port"]) for i in discover_instances()}

    try:
        subprocess.Popen(
            args,
            creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
            if sys.platform == "win32" else 0,
        )
    except Exception as e:
        return {"success": False, "error": f"Failed to launch IDA: {e}"}

    if timeout == 0:
        return {"success": True, "message": "IDA launched, not waiting for registration"}

    deadline = time.monotonic() + timeout
    new_instance = None
    while time.monotonic() < deadline:
        time.sleep(1)
        for inst in discover_instances():
            key = (inst["host"], inst["port"])
            if key not in before:
                new_instance = inst
                break
        if new_instance:
            break

    if not new_instance:
        return {
            "success": True,
            "message": f"IDA launched but did not register within {timeout}s.",
        }

    return {
        "success": True,
        "host": new_instance["host"],
        "port": new_instance["port"],
        "binary": new_instance.get("binary", ""),
        "pid": int(new_instance["pid"]) if new_instance.get("pid") is not None else 0,
    }
