"""Build Tunnel on Windows, Linux, or macOS."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]


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


def copy_windows_runtime(build_dir: Path, preserved: Path | None = None) -> None:
    if os.name != "nt":
        return
    bundled = ROOT / ".deps" / "mingw64" / "bin"
    if bundled.is_dir():
        for source in bundled.glob("*.dll"):
            shutil.copy2(source, build_dir / source.name)
    if preserved:
        for name in ("wintun.dll", "WINTUN-LICENSE.txt"):
            source = preserved / name
            if source.is_file():
                shutil.copy2(source, build_dir / name)
    vendor = ROOT / "third_party" / "windows"
    for name in ("wintun.dll", "WINTUN-LICENSE.txt"):
        source = vendor / name
        if source.is_file() and not (build_dir / name).is_file():
            shutil.copy2(source, build_dir / name)


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
    run([str(python), "-m", "pip", "install", "-r", str(requirements)])
    run([str(python), "-c", "import webview"])
    return python


def main() -> int:
    parser = argparse.ArgumentParser(description="Configure and build Tunnel")
    parser.add_argument("--gui", action="store_true", help="also package the desktop GUI on Windows")
    parser.add_argument("--clean", action="store_true", help="remove the build directory before configuring")
    parser.add_argument("--skip-kernel-module", action="store_true",
                        help="on Linux, skip the ABI-specific tunnel_kmod.ko build")
    parser.add_argument("--skip-gui-deps", action="store_true",
                        help="skip Linux/macOS GUI dependency preparation (core-only build)")
    args = parser.parse_args()

    build_dir = ROOT / "build"
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
        ninja = str(local_ninja) if local_ninja.is_file() else shutil.which("ninja")

        configure = [cmake, "-S", str(ROOT), "-B", str(build_dir), "-DBUILD_TESTING=OFF", "-DLIBEVENT_STATIC_LINK=OFF"]
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
        elif args.skip_gui_deps:
            configure.append("-DTUNNEL_REQUIRE_GUI_DEPS=OFF")

        run(configure)
        run([cmake, "--build", str(build_dir), "--parallel"])
        build_linux_kernel_module(build_dir, args.skip_kernel_module)
        copy_windows_runtime(build_dir, preserved)

        if args.gui:
            if os.name != "nt":
                raise SystemExit("--gui is currently available only for Windows desktop packaging; core build is complete.")
            run([sys.executable, str(ROOT / "gui" / "build_windows.py"), "--core-dir", str(build_dir)])

        print(f"Build complete: {build_dir}")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
