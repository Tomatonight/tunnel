#!/usr/bin/env python3
"""Small cross-platform launcher for the Tunnel desktop UI.

The launcher keeps privilege/session setup in Python so shell, batch, and VBS
entry points share the same path and argument handling.
"""
from __future__ import annotations

import ctypes
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]


def configure_rustdesk_host(root: Path) -> None:
    """Apply the saved Tunnel password before dropping root privileges.

    ``run-gui.sh`` is commonly invoked with sudo so the TUN core can receive
    CAP_NET_ADMIN.  RustDesk's Linux service is also root-owned and rejects
    ``--password`` from the desktop user; configure it here while we still
    have the caller's root privileges.  This is a no-op for disabled/missing
    remote sharing and for non-root launches.
    """
    if os.name == "nt" or os.geteuid() != 0:
        return
    try:
        document = json.loads((root / "configure.json").read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return
    remote = document.get("remote_desktop") if isinstance(document, dict) else None
    password = remote.get("shared_key") if isinstance(remote, dict) and remote.get("enabled") is True else None
    if not isinstance(password, str) or not password.strip():
        return
    explicit = os.environ.get("TUNNEL_RUSTDESK_BIN", "").strip()
    candidates = [Path(explicit)] if explicit else []
    candidates.extend((root / ".deps" / "rustdesk" / "rustdesk",
                       root / "tools" / "rustdesk" / "rustdesk"))
    found = shutil.which("rustdesk") or shutil.which("RustDesk")
    if found:
        candidates.append(Path(found))
    executable = next((item for item in candidates if item and item.is_file()), None)
    if executable is None:
        return
    for arguments in (("--option", "direct-server", "Y"),
                      ("--option", "direct-access-port", "21118"),
                      ("--option", "approve-mode", "password"),
                      ("--option", "verification-method", "use-permanent-password"),
                      ("--password", password)):
        try:
            completed = subprocess.run([str(executable), *arguments], cwd=executable.parent,
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                       timeout=15, check=False)
        except (OSError, subprocess.SubprocessError):
            return
        if completed.returncode:
            return


def die(message: str) -> int:
    print(message, file=sys.stderr)
    return 1


def package_name(root: Path) -> str | None:
    marker = root / "build" / "gui" / "current-package.txt"
    try:
        value = marker.read_text(encoding="ascii").strip()
    except OSError:
        return None
    if value and all(ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-" for ch in value):
        return value
    return None


def windows_package(root: Path) -> Path | None:
    name = package_name(root)
    candidates: list[Path] = []
    if name:
        candidates.append(root / "build" / "gui" / name / "TunnelUI.exe")
    # Keep one current fallback for packages built before the marker was
    # introduced; the versioned names were temporary recovery directories.
    candidates.append(root / "build" / "gui" / "TunnelUI-live" / "TunnelUI.exe")
    candidates.append(root / "build" / "gui" / "TunnelUI" / "TunnelUI.exe")
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def launch_windows(root: Path, arguments: list[str]) -> int:
    executable = windows_package(root)
    if executable is None:
        return die("Tunnel GUI package not found. Run build.bat --gui first.")
    params = subprocess.list2cmdline(["--config-dir", str(root), *arguments])
    shell32 = ctypes.windll.shell32
    shell32.ShellExecuteW.restype = ctypes.c_void_p
    result = shell32.ShellExecuteW(None, "runas", str(executable), params, str(root), 1)
    if result <= 32:
        return die(f"Unable to start Tunnel GUI (ShellExecute error {result}).")
    return 0


def session_environment(environment: dict[str, str]) -> None:
    """Import variables exported by the current desktop user session."""
    if os.name != "posix" or not shutil.which("systemctl"):
        return
    try:
        result = subprocess.run(["systemctl", "--user", "show-environment"],
                                capture_output=True, text=True, timeout=3, check=False)
    except (OSError, subprocess.SubprocessError):
        return
    for line in result.stdout.splitlines():
        key, separator, value = line.partition("=")
        if separator and key and key not in environment:
            environment[key] = value


def setup_linux_environment(environment: dict[str, str], uid: int) -> str:
    # A GUI started through `sudo` often inherits the caller's input-method
    # selectors.  On X11 WebKitGTK can keep trying a dead XIM/IBus socket;
    # every text field then appears to freeze because the input event loop is
    # blocked during focus.  Remove the inherited selectors before choosing
    # the session backend.  The toolkit's built-in context handles ordinary
    # ASCII entry (addresses and shared keys) without these variables.
    for key in ("GTK_IM_MODULE", "QT_IM_MODULE", "XMODIFIERS", "IBUS_ADDRESS", "IBUS_DAEMON",
                "GTK_MODULES", "QT_ACCESSIBILITY", "AT_SPI_BUS_ADDRESS", "AT_SPI_BUS"):
        environment.pop(key, None)
    runtime = environment.get("XDG_RUNTIME_DIR") or f"/run/user/{uid}"
    if Path(runtime).is_dir():
        environment["XDG_RUNTIME_DIR"] = runtime
        bus = Path(runtime) / "bus"
        if bus.is_socket() and not environment.get("DBUS_SESSION_BUS_ADDRESS"):
            environment["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path={bus}"

    wayland = environment.get("WAYLAND_DISPLAY", "")
    if not wayland and (Path(runtime) / "wayland-0").is_socket():
        wayland = "wayland-0"
        environment["WAYLAND_DISPLAY"] = wayland
    wayland_socket = Path(wayland) if wayland.startswith("/") else Path(runtime) / wayland if wayland else None
    if wayland_socket and wayland_socket.is_socket():
        environment.pop("DISPLAY", None)
        environment.pop("XAUTHORITY", None)
        environment["GDK_BACKEND"] = "wayland"
        environment["GTK_IM_MODULE"] = "ibus"
        environment["XMODIFIERS"] = "@im=ibus"
        return "wayland"

    # Do not leave a stale Wayland selector in the environment when falling
    # back to X11; GTK/WebKit otherwise keeps trying the dead socket.
    environment.pop("WAYLAND_DISPLAY", None)

    display = environment.get("DISPLAY", "")
    if not display:
        sockets = sorted(Path("/tmp/.X11-unix").glob("X*"))
        if sockets:
            display = ":" + sockets[0].name[1:]
            environment["DISPLAY"] = display
    if not display:
        raise RuntimeError("未找到图形显示，请在已登录的 Linux 桌面中运行。")
    if not environment.get("XAUTHORITY"):
        for candidate in sorted(Path(runtime).glob(".mutter-Xwaylandauth.*")):
            if candidate.is_file():
                environment["XAUTHORITY"] = str(candidate)
                break
        else:
            home = Path(environment.get("HOME", ""))
            if (home / ".Xauthority").is_file():
                environment["XAUTHORITY"] = str(home / ".Xauthority")
    environment["GDK_BACKEND"] = "x11"
    # Deliberately leave GTK_IM_MODULE/XMODIFIERS unset on X11.  For this
    # WebView-only UI that avoids both stale XIM sockets and an unavailable
    # IBus daemon, while preserving normal keyboard input.
    return "x11"


def ensure_capability(binary: Path, uid: int, gid: int) -> None:
    if not shutil.which("getcap") or not shutil.which("setcap"):
        raise RuntimeError("缺少 getcap/setcap，请安装 libcap2-bin。")
    current = subprocess.run(["getcap", str(binary)], capture_output=True, text=True, check=False).stdout
    if "cap_net_admin" in current and "cap_setpcap" in current:
        return
    if os.geteuid() != 0:
        raise RuntimeError(f"核心没有 CAP_NET_ADMIN。请执行：sudo {ROOT / 'run-gui.sh'}")
    subprocess.run(["chown", f"{uid}:{gid}", str(binary)], check=False)
    subprocess.run(["setcap", "cap_setpcap,cap_net_admin+eip", str(binary)], check=True)
    current = subprocess.run(["getcap", str(binary)], capture_output=True, text=True, check=False).stdout
    if "cap_net_admin" not in current or "cap_setpcap" not in current:
        raise RuntimeError("核心仍没有 CAP_NET_ADMIN/CAP_SETPCAP。")


def relaunch_as_desktop_user(root: Path, arguments: list[str], environment: dict[str, str], uid: int, gid: int) -> int:
    sudo = shutil.which("sudo")
    if not sudo:
        raise RuntimeError("sudo 不可用，请直接以桌面用户运行或安装 sudo。")
    user = str(uid)
    try:
        import pwd
        desktop = pwd.getpwuid(uid)
        desktop_name = desktop.pw_name
        desktop_home = desktop.pw_dir
    except (ImportError, KeyError):
        desktop_name = environment.get("USER", user)
        desktop_home = f"/home/{desktop_name}"
    command = [sudo, "-u", f"#{user}", "-g", f"#{gid}", "env"]
    environment = dict(environment)
    # sudo may preserve root's HOME when it is invoked from `sudo bash
    # run-gui.sh`.  The GUI then runs with the desktop user's UID but GTK,
    # WebKit and GVFS still try to use /root/.local, producing permission
    # warnings and breaking input-method/desktop integration.  Restore the
    # complete desktop profile before starting the WebView.
    environment["HOME"] = desktop_home
    environment["USER"] = desktop_name
    environment["LOGNAME"] = desktop_name
    for key, suffix in (("XDG_CONFIG_HOME", ".config"), ("XDG_DATA_HOME", ".local/share"),
                        ("XDG_CACHE_HOME", ".cache")):
        value = environment.get(key, "")
        if not value or value == "/root" or value.startswith("/root/"):
            environment[key] = str(Path(desktop_home) / suffix)
    for key in ("HOME", "USER", "LOGNAME", "DISPLAY", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR",
                "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "XAUTHORITY",
                "DBUS_SESSION_BUS_ADDRESS", "XDG_SESSION_TYPE", "XDG_CURRENT_DESKTOP",
                "XDG_SESSION_DESKTOP", "GDMSESSION", "GTK_MODULES", "QT_ACCESSIBILITY", "QT_IM_MODULE",
                "XDG_DATA_DIRS", "XDG_CONFIG_DIRS", "XDG_MENU_PREFIX", "XDG_SESSION_CLASS",
                "GTK_IM_MODULE", "XMODIFIERS", "GDK_BACKEND", "WEBKIT_DISABLE_DMABUF_RENDERER",
                "WEBKIT_DISABLE_COMPOSITING_MODE", "LIBGL_ALWAYS_SOFTWARE", "GSK_RENDERER"):
        if key in environment:
            command.append(f"{key}={environment[key]}")
    # A root-launched shell can carry an AT-SPI socket under /root.  Passing
    # that stale address to the desktop user's GTK process causes dbind to
    # report a permission error; this application does not provide an
    # accessibility bridge, so disable that optional integration explicitly.
    command.append("NO_AT_BRIDGE=1")
    for key in ("AT_SPI_BUS_ADDRESS", "AT_SPI_BUS"):
        environment.pop(key, None)
    command.extend([sys.executable, str(Path(__file__).resolve()), *arguments])
    os.execvpe(sudo, command, environment)
    return 0


def launch_posix(root: Path, arguments: list[str]) -> int:
    binary = root / "build" / "tunnel"
    python = root / ".venv-gui" / "bin" / "python"
    if not binary.is_file():
        return die(f"找不到核心程序，请先执行：sh {root / 'build.sh'}")
    if not python.is_file():
        return die(f"找不到 GUI 环境，请先执行：sh {root / 'build.sh'}")
    environment = dict(os.environ)
    uid = int(environment.get("SUDO_UID", os.getuid())) if os.geteuid() == 0 else os.getuid()
    gid = int(environment.get("SUDO_GID", os.getgid())) if os.geteuid() == 0 else os.getgid()
    if sys.platform.startswith("linux"):
        session_environment(environment)
        setup_linux_environment(environment, uid)
        configure_rustdesk_host(root)
        ensure_capability(binary, uid, gid)
        if os.geteuid() == 0 and uid != 0:
            return relaunch_as_desktop_user(root, arguments, environment, uid, gid)
    environment.update({"WEBKIT_DISABLE_DMABUF_RENDERER": "1", "WEBKIT_DISABLE_COMPOSITING_MODE": "1",
                        "LIBGL_ALWAYS_SOFTWARE": "1", "GSK_RENDERER": "cairo"})
    lock_file = None
    if sys.platform.startswith("linux"):
        import fcntl
        lock_path = Path(environment.get("XDG_RUNTIME_DIR", "/tmp")) / "tunnel-gui.lock"
        lock_file = lock_path.open("a+")
        try:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            return die("Tunnel GUI 已在运行，请先关闭已有窗口。")
        os.set_inheritable(lock_file.fileno(), True)
    command = [str(python), str(root / "gui" / "main.py"), "--binary", str(binary),
               "--config-dir", str(root), *arguments]
    os.execve(str(python), command, environment)
    return 0


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    try:
        if os.name == "nt":
            return launch_windows(ROOT, arguments)
        return launch_posix(ROOT, arguments)
    except (OSError, RuntimeError, ValueError) as error:
        return die(str(error))


if __name__ == "__main__":
    raise SystemExit(main())
