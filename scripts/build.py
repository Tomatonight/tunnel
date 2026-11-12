"""Build Tunnel on Windows, Linux, or macOS."""
from __future__ import annotations

import argparse
import filecmp
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request


ROOT = Path(__file__).resolve().parents[1]
RUSTDESK_VERSION = os.environ.get("TUNNEL_RUSTDESK_VERSION", "1.5.3")


def executable(name: str, local: Path | None = None) -> str:
    if local and local.is_file():
        return str(local)
    found = shutil.which(name)
    if found:
        return found
    raise SystemExit(f"{name} was not found; install CMake and a build tool, then retry.")


def run(command: list[str]) -> None:
    print("+", " ".join(command), flush=True)
    subprocess.run(command, cwd=ROOT, check=True)


def rustdesk_executable() -> str | None:
    """Return an installed RustDesk executable, if one is already available."""
    names = ("rustdesk.exe", "RustDesk.exe") if os.name == "nt" else ("rustdesk", "RustDesk")
    for name in names:
        found = shutil.which(name)
        if found:
            return found
    if os.name == "nt":
        for base in (os.environ.get("ProgramFiles", ""), os.environ.get("LOCALAPPDATA", "")):
            if base:
                candidate = Path(base) / "RustDesk" / "RustDesk.exe"
                if candidate.is_file():
                    return str(candidate)
        portable = ROOT / ".deps" / "rustdesk" / "RustDesk.exe"
        if portable.is_file():
            return str(portable)
    return None


def configure_rustdesk_direct() -> None:
    """Enable RustDesk direct-IP mode used by the Tunnel virtual network."""
    executable = rustdesk_executable()
    if not executable:
        return
    commands = [
        [executable, "--option", "direct-server", "Y"],
        [executable, "--option", "direct-access-port", "21118"],
        # Tunnel supplies the pre-shared key.  RustDesk must accept a
        # permanent password without waiting for a person at the host to
        # click the approval dialog.
        [executable, "--option", "approve-mode", "password"],
        [executable, "--option", "verification-method", "use-permanent-password"],
    ]
    if os.name != "nt" and os.geteuid() != 0:
        sudo = shutil.which("sudo")
        if sudo:
            commands = [[sudo, *command] for command in commands]
    for command in commands:
        try:
            run(command)
        except (OSError, subprocess.CalledProcessError) as error:
            print(f"RustDesk direct-IP setup was not applied: {error}; enable it in RustDesk Security settings.", flush=True)
            return


def configure_rustdesk_host() -> None:
    """Apply the Tunnel remote key to the installed RustDesk service.

    On Linux the packaged RustDesk service owns the host process as root, so
    running ``rustdesk --password`` only as the desktop user updates the wrong
    profile and leaves the approval dialog enabled.  The build is normally
    invoked with sudo on Linux; use that same privilege only for this one
    configuration command.  Missing/disabled remote sharing is intentionally
    a no-op.
    """
    config = ROOT / "configure.json"
    try:
        document = json.loads(config.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return
    remote = document.get("remote_desktop") if isinstance(document, dict) else None
    password = remote.get("shared_key") if isinstance(remote, dict) and remote.get("enabled") is True else None
    if not isinstance(password, str) or not password.strip():
        return
    executable = rustdesk_executable()
    if not executable:
        return
    command = [executable, "--password", password]
    if os.name != "nt" and os.geteuid() != 0:
        sudo = shutil.which("sudo")
        if not sudo:
            print("RustDesk permanent password was not applied: sudo is unavailable.", flush=True)
            return
        command.insert(0, sudo)
    try:
        completed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True,
                                   timeout=15, check=False)
    except (OSError, subprocess.SubprocessError) as error:
        print(f"RustDesk permanent password was not applied: {error}", flush=True)
        return
    if completed.returncode:
        print("RustDesk permanent password was not applied; run the build as administrator/root.", flush=True)
    else:
        print("RustDesk permanent password applied from remote_desktop.shared_key.", flush=True)


def _download_rustdesk(destination: Path, asset: str) -> None:
    """Download a release package, preferring the official GitHub asset."""
    urls = [
        f"https://github.com/rustdesk/rustdesk/releases/download/{RUSTDESK_VERSION}/{asset}",
        f"https://mirrors.nju.edu.cn/github-release/rustdesk/rustdesk/LatestRelease/{asset}",
    ]
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".download")
    last_error = None
    for url in urls:
        try:
            print(f"Downloading RustDesk: {url}", flush=True)
            request = urllib.request.Request(url, headers={"User-Agent": "Tunnel-build/1"})
            with urllib.request.urlopen(request, timeout=45) as response, temporary.open("wb") as output:
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    output.write(chunk)
            if temporary.stat().st_size > 1024 * 1024:
                temporary.replace(destination)
                return
            last_error = RuntimeError("downloaded file is unexpectedly small")
        except (OSError, urllib.error.URLError, urllib.error.HTTPError, RuntimeError) as error:
            last_error = error
            temporary.unlink(missing_ok=True)
            print(f"RustDesk download failed: {error}", flush=True)
    raise SystemExit(
        f"Unable to download RustDesk {RUSTDESK_VERSION}. "
        "Check network access or rerun with --skip-rustdesk."
    ) from last_error


def ensure_rustdesk(skip: bool) -> None:
    """Install RustDesk when building the desktop GUI.

    RustDesk remains an external dependency: only the platform package is
    installed, never copied into Tunnel's source or Windows package.  The
    escape hatch is useful for offline/core-only builds.
    """
    if skip or os.environ.get("TUNNEL_SKIP_RUSTDESK") == "1":
        print("Skipping RustDesk installation (--skip-rustdesk)", flush=True)
        return
    existing = rustdesk_executable()
    if existing:
        print(f"Reusing RustDesk: {existing}", flush=True)
        configure_rustdesk_direct()
        return
    if os.name == "nt":
        winget = shutil.which("winget")
        if winget:
            try:
                run([winget, "install", "--id", "RustDesk.RustDesk", "--exact", "--silent",
                     "--accept-package-agreements", "--accept-source-agreements"])
            except subprocess.CalledProcessError:
                print("winget did not provide RustDesk; falling back to the portable official release.", flush=True)
        if not rustdesk_executable():
            portable = ROOT / ".deps" / "rustdesk" / "RustDesk.exe"
            _download_rustdesk(portable, f"rustdesk-{RUSTDESK_VERSION}-x86_64.exe")
        if not rustdesk_executable():
            raise SystemExit("RustDesk installation completed but rustdesk.exe was not found.")
        configure_rustdesk_direct()
        return
    if platform.system() != "Linux":
        print("RustDesk installation is automatic only on Linux and Windows; install it manually on this platform.", flush=True)
        return
    machine = platform.machine().lower()
    suffix = "x86_64" if machine in {"x86_64", "amd64"} else "aarch64" if machine in {"aarch64", "arm64"} else ""
    if not suffix or not shutil.which("dpkg"):
        raise SystemExit("Automatic RustDesk installation requires a Debian/Ubuntu x86_64 or aarch64 host; use --skip-rustdesk for a core-only build.")
    package = ROOT / ".deps" / "rustdesk" / f"rustdesk-{RUSTDESK_VERSION}-{suffix}.deb"
    if not package.is_file() or package.stat().st_size <= 1024 * 1024:
        _download_rustdesk(package, f"rustdesk-{RUSTDESK_VERSION}-{suffix}.deb")
    installer = shutil.which("apt-get")
    if not installer:
        raise SystemExit("apt-get was not found; install RustDesk manually or use --skip-rustdesk.")
    command = [installer, "install", "-y", str(package)]
    if os.geteuid() != 0:
        sudo = shutil.which("sudo")
        if not sudo:
            raise SystemExit("RustDesk installation needs root or sudo; install it manually or use --skip-rustdesk.")
        command.insert(0, sudo)
    run(command)
    if not rustdesk_executable():
        raise SystemExit("RustDesk package installed but the rustdesk executable was not found.")
    configure_rustdesk_direct()
    print(f"RustDesk installed: {rustdesk_executable()}", flush=True)


def usable_ninja(path: str) -> bool:
    """Return whether a Ninja path is a working executable, not a broken wrapper."""
    try:
        subprocess.run([path, "--version"], cwd=ROOT, check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       timeout=5)
    except (OSError, subprocess.SubprocessError):
        print(f"Ignoring unusable Ninja: {path}", flush=True)
        return False
    return True


def copy_windows_runtime(build_dir: Path, preserved: Path | None = None) -> None:
    if os.name != "nt":
        return

    def copy_runtime(source: Path, destination: Path) -> None:
        """Copy a runtime file unless the destination already has the same bytes.

        A running Tunnel process can keep its DLLs open on Windows. Rebuilding
        while that process is alive should remain harmless when the runtime is
        already current, while a genuinely changed DLL still needs an explicit
        and actionable failure instead of a cryptic WinError 32.
        """
        if destination.is_file():
            try:
                if filecmp.cmp(source, destination, shallow=False):
                    return
            except OSError:
                # Let the copy below produce the useful error message.
                pass
        try:
            shutil.copy2(source, destination)
        except PermissionError as error:
            raise SystemExit(
                f"cannot replace locked runtime file {destination}; "
                "close the running Tunnel/UI process and retry"
            ) from error

    bundled = ROOT / ".deps" / "mingw64" / "bin"
    if bundled.is_dir():
        for source in bundled.glob("*.dll"):
            copy_runtime(source, build_dir / source.name)
    if preserved:
        for name in ("wintun.dll", "WINTUN-LICENSE.txt"):
            source = preserved / name
            if source.is_file():
                copy_runtime(source, build_dir / name)
    vendor = ROOT / "third_party" / "windows"
    for name in ("wintun.dll", "WINTUN-LICENSE.txt"):
        source = vendor / name
        if source.is_file() and not (build_dir / name).is_file():
            copy_runtime(source, build_dir / name)


def build_linux_kernel_module(build_dir: Path, skip: bool) -> None:
    """Build the optional data-plane module alongside the native executable.

    The module is ABI-specific, so it is deliberately built on the target Linux
    machine rather than through the CMake C++ toolchain.  Keeping this step in
    the one-click build script also leaves Windows, macOS, and Android builds
    untouched.
    """
    if platform.system() != "Linux":
        return
    if skip:
        print("Skipping Linux kernel module build (--skip-kernel-module)")
        return
    command = [sys.executable, str(ROOT / "tools" / "build_kernel.py"),
               "--output", str(build_dir / "kernel")]
    headers = os.environ.get("TUNNEL_KERNEL_HEADERS")
    if headers:
        command += ["--headers", headers]
    jobs = os.environ.get("TUNNEL_KERNEL_JOBS")
    if jobs:
        command += ["--jobs", jobs]
    try:
        run(command)
    except subprocess.CalledProcessError as error:
        raise SystemExit(
            "Linux kernel module build failed. Install headers matching uname -r "
            "and kmod/build tools, or rerun with --skip-kernel-module to build "
            "the userspace TUN backend only."
        ) from error


def ensure_gui_dependencies(skip: bool) -> Path | None:
    """Prepare the Python GUI environment before the native configure step.

    Linux/macOS GUI dependencies are kept in a project-local environment so
    ``run-gui.sh`` never falls back to an unrelated system interpreter.  The
    CMake configure check receives the same interpreter and therefore catches
    a missing pywebview before any C++ compilation starts.
    """
    if skip or platform.system() not in {"Linux", "Darwin"}:
        return None
    system_python = shutil.which("python3") or shutil.which("python")
    if not system_python:
        raise SystemExit(
            "Python 3 is required for the desktop GUI. Install Python 3 and python3-venv, "
            "or rerun with --skip-gui-deps for a core-only build."
        )
    venv_dir = ROOT / ".venv-gui"
    python = venv_dir / "bin" / "python"
    if not python.is_file():
        run([system_python, "-m", "venv", "--system-site-packages", str(venv_dir)])
    requirements = ROOT / "gui" / "requirements.txt"
    # Installing on every build makes the normal edit/compile loop depend on
    # the network. Reinstall only when the requirements changed or the
    # environment no longer imports the GUI runtime.
    stamp = venv_dir / ".tunnel-requirements"
    requirement_files = [requirements, ROOT / "remote_desktop" / "requirements.txt"]
    digest = hashlib.sha256()
    for source in requirement_files:
        digest.update(str(source.relative_to(ROOT)).encode("utf-8"))
        digest.update(b"\0")
        digest.update(source.read_bytes())
    fingerprint = digest.hexdigest()
    try:
        needs_install = stamp.read_text(encoding="ascii").strip() != fingerprint
    except OSError:
        needs_install = True
    if not needs_install:
        try:
            run([str(python), "-c", "import webview"])
        except subprocess.CalledProcessError:
            needs_install = True
    if needs_install:
        run([str(python), "-m", "pip", "install", "-r", str(requirements)])
        run([str(python), "-c", "import webview"])
        stamp.write_text(fingerprint + "\n", encoding="ascii")
    else:
        print(f"Reusing GUI environment: {venv_dir}", flush=True)
    return python


def main() -> int:
    parser = argparse.ArgumentParser(description="Configure and build Tunnel")
    parser.add_argument("--gui", action="store_true", help="also package the desktop GUI on Windows")
    parser.add_argument("--clean", action="store_true", help="remove the build directory before configuring")
    parser.add_argument("--skip-kernel-module", action="store_true",
                        help="on Linux, skip the ABI-specific tunnel_kmod.ko build")
    parser.add_argument("--skip-gui-deps", action="store_true",
                        help="skip Linux/macOS GUI dependency preparation (core-only build)")
    parser.add_argument("--skip-rustdesk", action="store_true",
                        help="skip automatic RustDesk installation for desktop GUI builds")
    parser.add_argument("--tests", action="store_true",
                        help="build and run the native CTest suite after compiling")
    parser.add_argument("--build-type", choices=("Debug", "Release", "RelWithDebInfo", "MinSizeRel"),
                        default=os.environ.get("TUNNEL_BUILD_TYPE", "Release"),
                        help="CMake build type (default: Release; TUNNEL_BUILD_TYPE also supported)")
    args = parser.parse_args()

    build_dir = ROOT / "build"
    # RustDesk is needed by the desktop GUI, not by a core-only build.  Keep
    # --skip-gui-deps as the existing offline/core escape hatch and expose a
    # separate switch for users who already manage RustDesk themselves.
    desktop_build = not args.skip_gui_deps and (os.name != "nt" or args.gui)
    if desktop_build:
        ensure_rustdesk(args.skip_rustdesk)
        if not args.skip_rustdesk and os.environ.get("TUNNEL_SKIP_RUSTDESK") != "1":
            configure_rustdesk_host()
    gui_python = ensure_gui_dependencies(args.skip_gui_deps)
    with tempfile.TemporaryDirectory(prefix="tunnel-build-runtime-") as preserve_dir:
        preserved = Path(preserve_dir)
        if args.clean and build_dir.exists():
            for name in ("wintun.dll", "WINTUN-LICENSE.txt"):
                source = build_dir / name
                if source.is_file():
                    shutil.copy2(source, preserved / name)
            shutil.rmtree(build_dir)
        cache = build_dir / "CMakeCache.txt"
        if cache.is_file() and "CMAKE_CXX_COMPILER:FILEPATH=CMAKE_CXX_COMPILER-NOTFOUND" in cache.read_text(errors="ignore"):
            shutil.rmtree(build_dir)

        cmake = executable(
            "cmake",
            ROOT / ".build-tools" / "cmake" / "data" / "bin" / ("cmake.exe" if os.name == "nt" else "cmake"),
        )
        local_ninja = ROOT / ".build-tools" / "bin" / ("ninja.exe" if os.name == "nt" else "ninja")
        ninja = None
        candidates = []
        if local_ninja.is_file():
            candidates.append(str(local_ninja))
        path_ninja = shutil.which("ninja")
        if path_ninja:
            candidates.append(path_ninja)
        if os.name != "nt" and Path("/usr/bin/ninja").is_file():
            candidates.append("/usr/bin/ninja")
        for candidate in dict.fromkeys(candidates):
            if usable_ninja(candidate):
                ninja = candidate
                break

        configure = [cmake, "-S", str(ROOT), "-B", str(build_dir),
                     "-DCMAKE_BUILD_TYPE=" + args.build_type,
                     "-DBUILD_TESTING=" + ("ON" if args.tests else "OFF"),
                     "-DLIBEVENT_STATIC_LINK=OFF"]
        local_toolchain = ROOT / ".build-tools" / "zig-toolchain.cmake"
        if os.name == "nt" and local_toolchain.is_file():
            configure.append("-DCMAKE_TOOLCHAIN_FILE=.build-tools/zig-toolchain.cmake")
        if ninja:
            configure[3:3] = ["-G", "Ninja", "-DCMAKE_MAKE_PROGRAM=" + ninja]
        prefix = os.environ.get("CMAKE_PREFIX_PATH")
        bundled_prefix = ROOT / ".deps" / "mingw64"
        if not prefix and bundled_prefix.is_dir():
            prefix = str(bundled_prefix)
        if prefix:
            configure.append("-DCMAKE_PREFIX_PATH=" + prefix)
        if gui_python:
            configure.append("-DPython3_EXECUTABLE=" + str(gui_python))
            configure.append("-DTUNNEL_REQUIRE_GUI_DEPS=ON")
        elif args.skip_gui_deps:
            configure.append("-DTUNNEL_REQUIRE_GUI_DEPS=OFF")

        run(configure)
        run([cmake, "--build", str(build_dir), "--config", args.build_type, "--parallel"])
        # Native tests launch the freshly built executable on Windows, so its
        # dependent DLLs must be beside it before CTest starts.
        copy_windows_runtime(build_dir, preserved)
        if args.tests:
            ctest = executable(
                "ctest",
                ROOT / ".build-tools" / "cmake" / "data" / "bin" / ("ctest.exe" if os.name == "nt" else "ctest"),
            )
            run([ctest, "--test-dir", str(build_dir), "-C", args.build_type, "--output-on-failure"])
        build_linux_kernel_module(build_dir, args.skip_kernel_module)

        if args.gui:
            if os.name != "nt":
                raise SystemExit("--gui is currently available only for Windows desktop packaging; core build is complete.")
            run([sys.executable, str(ROOT / "gui" / "build_windows.py"), "--core-dir", str(build_dir)])

        print(f"Build complete: {build_dir}")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
