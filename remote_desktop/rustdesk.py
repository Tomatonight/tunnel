"""Small process adapter for an installed RustDesk client.

Tunnel owns the virtual network and peer authentication.  RustDesk owns the
desktop protocol, codec, input handling and fullscreen window.  This module
intentionally does not download, bundle, or reimplement RustDesk; it only
locates an administrator-provided client and starts it without a shell.
"""
from __future__ import annotations

import os
from pathlib import Path
import ipaddress
import shutil
import signal
import subprocess
from typing import Any


class RustDeskError(ValueError):
    """A user-correctable RustDesk integration error."""


def _validate_target(value: Any) -> str:
    if not isinstance(value, str):
        raise RustDeskError("RustDesk 对端必须是 Tunnel 虚拟 IP。")
    target = value.strip()
    if not target or len(target) > 128:
        raise RustDeskError("RustDesk 对端必须是 Tunnel 虚拟 IP。")
    try:
        ipaddress.ip_address(target)
    except ValueError:
        raise RustDeskError("RustDesk 对端必须是 Tunnel 虚拟 IP，不能使用 RustDesk ID。") from None
    return target


def _validate_password(value: Any) -> str:
    if value is None:
        return ""
    if not isinstance(value, str) or len(value.encode("utf-8")) > 4096:
        raise RustDeskError("RustDesk 密码无效。")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise RustDeskError("RustDesk 密码不能包含控制字符。")
    return value


class RustDeskLauncher:
    """Locate and manage RustDesk processes started by this GUI instance."""

    def __init__(self, directory: str | os.PathLike[str]):
        self.directory = Path(directory).resolve()
        self._children: dict[int, subprocess.Popen] = {}
        self._last_error = ""

    def _candidates(self) -> list[Path]:
        explicit = os.environ.get("TUNNEL_RUSTDESK_BIN", "").strip()
        candidates: list[Path] = [Path(explicit)] if explicit else []
        names = ("rustdesk.exe", "RustDesk.exe") if os.name == "nt" else ("rustdesk", "RustDesk")
        for name in names:
            candidates.extend((self.directory / "third_party" / "rustdesk" / name,
                               self.directory / "tools" / name,
                               self.directory / ".deps" / "rustdesk" / name))
        found = shutil.which("rustdesk") or shutil.which("RustDesk")
        if found:
            candidates.append(Path(found))
        if os.name == "nt":
            for base in (os.environ.get("ProgramFiles", ""), os.environ.get("LOCALAPPDATA", "")):
                if base:
                    candidates.append(Path(base) / "RustDesk" / "RustDesk.exe")
        result: list[Path] = []
        seen: set[str] = set()
        for candidate in candidates:
            if not candidate:
                continue
            try:
                resolved = candidate.expanduser().resolve()
            except OSError:
                continue
            key = os.path.normcase(str(resolved))
            if key not in seen and resolved.is_file():
                seen.add(key)
                result.append(resolved)
        return result

    def executable(self) -> Path | None:
        candidates = self._candidates()
        return candidates[0] if candidates else None

    def status(self) -> dict[str, Any]:
        dead: list[int] = []
        processes = []
        for pid, child in self._children.items():
            code = child.poll()
            if code is None:
                processes.append(pid)
            else:
                dead.append(pid)
        for pid in dead:
            self._children.pop(pid, None)
        executable = self.executable()
        return {"available": executable is not None, "executable": str(executable) if executable else "",
                "running": bool(processes), "pids": processes, "error": self._last_error}

    def _spawn(self, arguments: list[str], *, prefix: list[str] | None = None) -> dict[str, Any]:
        executable = self.executable()
        if executable is None:
            raise RustDeskError("未找到 RustDesk。请安装 RustDesk，或设置 TUNNEL_RUSTDESK_BIN。")
        options: dict[str, Any] = {
            "cwd": str(executable.parent),
            "stdin": subprocess.DEVNULL,
            "stdout": subprocess.DEVNULL,
            "stderr": subprocess.DEVNULL,
        }
        if os.name == "nt":
            options["creationflags"] = subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            options["start_new_session"] = True
        try:
            child = subprocess.Popen([*(prefix or []), str(executable), *arguments], **options)
        except OSError as error:
            self._last_error = str(error)
            raise RustDeskError("无法启动 RustDesk：" + str(error)) from None
        self._children[child.pid] = child
        self._last_error = ""
        return {"pid": child.pid, "executable": str(executable), "running": child.poll() is None}

    def connect(self, target: Any, password: Any = None) -> dict[str, Any]:
        """Open a RustDesk control session to a target ID/address."""
        target = _validate_target(target)
        password = _validate_password(password)
        arguments = ["--connect", target]
        if password:
            arguments.extend(("--password", password))
        result = self._spawn(arguments)
        result["target"] = target
        return result

    def host(self, password: Any) -> dict[str, Any]:
        """Start RustDesk with a permanent password for incoming sessions."""
        password = _validate_password(password)
        if not password:
            raise RustDeskError("启动 RustDesk 被控端必须提供密码。")
        arguments = ["--password", password]
        prefix = None
        # Debian/Ubuntu installs run the RustDesk service as root.  A normal
        # desktop-user invocation is rejected with “administrative privileges
        # required”, so use a non-interactive sudo only when available.  The
        # build script normally applies this once as root; this covers keys
        # changed later in the GUI without ever opening a password prompt.
        if os.name != "nt" and os.geteuid() != 0:
            sudo = shutil.which("sudo")
            if sudo:
                prefix = [sudo, "-n"]
        result = self._spawn(arguments, prefix=prefix)
        # RustDesk's --password command normally exits after handing the
        # update to its service.  Detect immediate administrative failures
        # instead of reporting a false "started" state from Popen alone.
        child = self._children.get(result["pid"])
        if child is not None:
            try:
                code = child.wait(timeout=1)
            except subprocess.TimeoutExpired:
                code = None
            if code is not None:
                self._children.pop(child.pid, None)
                if code != 0:
                    raise RustDeskError("RustDesk 被控端无法应用永久密码，请以管理员/root运行构建脚本。")
                result["running"] = False
        result["mode"] = "host"
        return result

    def stop(self, pid: Any = None) -> dict[str, Any]:
        """Stop only RustDesk children created by this launcher instance."""
        targets = list(self._children)
        if pid is not None:
            try:
                requested = int(pid)
            except (TypeError, ValueError):
                raise RustDeskError("RustDesk 进程号无效。") from None
            targets = [requested] if requested in self._children else []
        stopped = []
        for item in targets:
            child = self._children.get(item)
            if child is None or child.poll() is not None:
                self._children.pop(item, None)
                continue
            try:
                if os.name == "nt":
                    subprocess.run(["taskkill", "/PID", str(child.pid), "/T", "/F"],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
                else:
                    os.killpg(child.pid, signal.SIGTERM)
                child.wait(timeout=5)
            except (OSError, ProcessLookupError, subprocess.TimeoutExpired):
                try:
                    child.kill()
                    child.wait(timeout=2)
                except (OSError, subprocess.TimeoutExpired):
                    pass
            self._children.pop(item, None)
            stopped.append(item)
        return {"stopped": stopped, **self.status()}

    def close(self) -> None:
        self.stop()
