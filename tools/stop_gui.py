#!/usr/bin/env python3
"""Stop Tunnel GUI processes belonging to this checkout.

This is intentionally narrower than ``pkill tunnel``/``taskkill``: only
commands whose arguments point at this project directory and match one of the
GUI, desktop-daemon, or native-core entry points are selected.  It is safe to
run before every GUI launch and can also be used manually as the exit script.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import signal
import subprocess
import sys
import time


def _root(value: str | None) -> Path:
    return Path(value).expanduser().resolve() if value else Path(__file__).resolve().parents[1]


def _markers(root: Path) -> tuple[str, ...]:
    # Use the full checkout path for the safety boundary, then require a
    # process entry point.  This prevents another user's tunnel or an
    # unrelated executable named ``tunnel`` from being touched.
    base = str(root).replace("\\", "/").rstrip("/").casefold()
    return (
        f"{base}/gui/main.py",
        f"{base}/tools/launch_gui.py",
        f"{base}/remote_desktop/daemon.py",
        f"{base}/build/tunnel",
        f"{base}/build/gui/",  # packaged Windows GUI (checked with filename below)
    )


def _matches(command: str, root: Path) -> bool:
    value = command.replace("\\", "/").casefold()
    base = str(root).replace("\\", "/").rstrip("/").casefold()
    if base not in value:
        return False
    if any(marker in value for marker in _markers(root)[:-1]):
        return True
    # Do not match arbitrary build/gui paths (for example a PyInstaller build
    # command); only a running packaged GUI or its bundled tunnel.exe is a
    # process we own.
    package = f"{base}/build/gui/" in value
    return package and ("tunnelui.exe" in value or "tunnel.exe" in value)


def _posix_processes(root: Path) -> list[int]:
    result: list[int] = []
    proc = Path("/proc")
    if not proc.is_dir():
        return result
    for entry in proc.iterdir():
        if not entry.name.isdecimal():
            continue
        pid = int(entry.name)
        if pid == os.getpid():
            continue
        try:
            command = os.fsdecode((entry / "cmdline").read_bytes()).replace("\x00", " ").strip()
        except OSError:
            continue
        if command and _matches(command, root):
            result.append(pid)
    return result


def _windows_processes(root: Path) -> list[int]:
    # WMI/CIM is available on supported Windows versions and exposes command
    # lines, unlike tasklist.  Keep the filter in Python so the project path
    # is passed without shell quoting or wildcard interpretation.
    script = (
        "$ErrorActionPreference='SilentlyContinue'; "
        "Get-CimInstance Win32_Process | "
        "ForEach-Object { if ($_.ProcessId -ne $PID) { "
        "[Console]::WriteLine(\"$($_.ProcessId)`t$($_.CommandLine)`t$($_.ExecutablePath)\") } }"
    )
    try:
        completed = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, timeout=10, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    result: list[int] = []
    for line in completed.stdout.splitlines():
        parts = line.split("\t", 2)
        if not parts or not parts[0].isdigit():
            continue
        command = "\t".join(parts[1:])
        if _matches(command, root):
            result.append(int(parts[0]))
    return result


def _processes(root: Path) -> list[int]:
    return _posix_processes(root) if os.name != "nt" else _windows_processes(root)


def _terminate(pids: list[int], quiet: bool) -> int:
    if not pids:
        return 0
    if not quiet:
        print("stopping Tunnel GUI processes: " + ", ".join(str(pid) for pid in pids))
    if os.name == "nt":
        for pid in pids:
            subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        return len(pids)
    for pid in pids:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        except PermissionError:
            if not quiet:
                print(f"warning: permission denied stopping PID {pid}", file=sys.stderr)
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        alive = [pid for pid in pids if Path(f"/proc/{pid}").exists()]
        if not alive:
            return len(pids)
        time.sleep(0.1)
    for pid in pids:
        if not Path(f"/proc/{pid}").exists():
            continue
        try:
            os.kill(pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
    # Do not remove the lock/endpoint while a killed process still has the
    # old inode open; otherwise an immediate restart could acquire a new lock
    # path while the previous daemon is still unwinding.
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        if not any(Path(f"/proc/{pid}").exists() for pid in pids):
            break
        time.sleep(0.05)
    return len(pids)


def _remove_state(root: Path, quiet: bool) -> None:
    # These are runtime discovery/lock files.  Keep configuration and logs so
    # a failed start remains diagnosable.
    paths = (root / "desktop-host.json", root / "desktop-host.lock",
             root / "desktop-exit.json", root / "background" / "status.json")
    for path in paths:
        try:
            path.unlink(missing_ok=True)
        except OSError as error:
            if not quiet:
                print(f"warning: cannot remove {path}: {error}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, help="Tunnel checkout to clean")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)
    root = _root(str(args.root) if args.root else None)
    if not root.is_dir():
        print(f"Tunnel directory not found: {root}", file=sys.stderr)
        return 1
    pids = _processes(root)
    _terminate(pids, args.quiet)
    _remove_state(root, args.quiet)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
