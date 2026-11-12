"""Build Tunnel with a plain C/C++ compiler driver.

The build only needs a C++11 compiler driver -- g++ (gcc) or clang++ -- plus
OpenSSL 3.x and libevent core.  CMake and Ninja are not used: this module
compiles every translation unit itself, keeps an incremental object cache in
``build/obj``, links the executables and (optionally) runs the native tests.

Portable discovery keeps the same entry point working everywhere:

* compiler   : ``TUNNEL_CXX``, then g++/clang++/c++ on ``PATH``, then the
               well-known MinGW-w64 / MSYS2 / LLVM install directories.
* dependencies: the compiler's own prefix (``<prefix>/bin/g++`` ->
               ``<prefix>/include|lib``), ``TUNNEL_DEPS_ROOT``, extra
               ``TUNNEL_CFLAGS``/``TUNNEL_LDFLAGS``, and ``.deps/*`` bundles.
* libraries  : project headers and libraries are probed with real compile and
               link attempts, so static/shared names (``-levent_core`` vs
               ``-levent``) are selected by what actually links.
"""
from __future__ import annotations

import argparse
import concurrent.futures
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
BUILD_DIR = ROOT / "build"
OBJECT_DIR = BUILD_DIR / "obj"
EXE_SUFFIX = ".exe" if os.name == "nt" else ""
RUSTDESK_VERSION = os.environ.get("TUNNEL_RUSTDESK_VERSION", "1.5.3")

# Core translation units shared by the CLI and every native test target.
CORE_SOURCES = (
    "src/address.cpp", "src/crypto.cpp", "src/event.cpp", "src/gossip.cpp",
    "src/parse_config.cpp", "src/peer.cpp", "src/protocol.cpp", "src/tunnel.cpp",
    "src/udp_transport.cpp", "src/tls.cpp", "src/wire.cpp", "src/tcp_transport.cpp",
    "src/device.cpp", "src/kernel_device.cpp", "src/node.cpp",
    "src/address_service.cpp", "src/return_flows.cpp", "src/subnet_platform.cpp",
)

# (target name, source, extra arguments, timeout seconds)
TEST_TARGETS = (
    ("tunnel_tests", "tests/core_tests.cpp", ("config/default.json",), 15),
    ("runtime_tests", "tests/runtime_tests.cpp", (), 60),
    ("address_service_tests", "tests/address_service_tests.cpp", ("address-service-state",), 60),
    ("managed_node_tests", "tests/managed_node_tests.cpp", ("managed-node-state",), 60),
    ("device_address_tests", "tests/device_address_tests.cpp", (), 15),
    ("subnet_tests", "tests/subnet_tests.cpp", (), 30),
    ("remote_control_tests", "tests/remote_control_tests.cpp", (), 45),
    ("reload_tests", "tests/reload_tests.cpp", ("reload-state",), 90),
    ("tcp_data_tests", "tests/tcp_data_tests.cpp", (), 90),
)

COMPILER_NAMES = ("g++", "clang++", "c++")
WINDOWS_COMPILER_DIRS = (
    r"C:\msys64\mingw64\bin",
    r"C:\msys64\ucrt64\bin",
    r"C:\msys64\clang64\bin",
    r"C:\msys64\clangarm64\bin",
    r"C:\mingw64\bin",
    r"C:\mingw32\bin",
    r"C:\MinGW\bin",
    r"C:\LLVM\bin",
    r"C:\Program Files\LLVM\bin",
)
WINDOWS_PREFIX_DIRS = (
    r"C:\msys64\mingw64",
    r"C:\msys64\ucrt64",
    r"C:\msys64\clang64",
    r"C:\msys64\clangarm64",
    r"C:\mingw64",
    r"C:\mingw32",
    r"C:\MinGW",
)

BUILD_TYPE_FLAGS = {
    "Release": ("-O2", "-DNDEBUG"),
    "Debug": ("-O0", "-g"),
    "RelWithDebInfo": ("-O2", "-g", "-DNDEBUG"),
    "MinSizeRel": ("-Os", "-DNDEBUG"),
}

EVENT_PROBE = """#include <event2/event.h>
int main() { event_base* base = event_base_new(); if (base) event_base_free(base); return base ? 0 : 1; }
"""

OPENSSL_PROBE = """#include <openssl/ssl.h>
#include <openssl/evp.h>
int main() { return OPENSSL_init_ssl(0, nullptr) ? 0 : 1; }
"""

# Ordered candidates, most specific first; the first that links wins.
EVENT_LIBRARY_CANDIDATES = (
    ("-levent_core",),
    ("-levent",),
    ("-levent_core", "-levent_extra"),
)
OPENSSL_LIBRARY_CANDIDATES = (
    ("-lssl", "-lcrypto"),
)


class BuildError(SystemExit):
    """Raised for actionable build failures."""


def announce(message: str) -> None:
    print(message, flush=True)


def describe_exit(code: int) -> str:
    """Render a sub-process exit code, decoding the Windows DLL failure."""
    unsigned = code & 0xFFFFFFFF
    if code < 0 or unsigned >= 0x80000000:
        if unsigned == 0xC0000135:
            return ("exit code 0xC0000135 (a required compiler runtime DLL is missing; "
                    "the toolchain's bin directory must be on PATH)")
        return f"exit code 0x{unsigned:08X}"
    return f"exit code {code}"


def tool_path(path: Path) -> str:
    """Render a path for the compiler command line.

    MinGW's ``as`` converts arguments with the ANSI code page, so a project root
    such as ``C:\\...\\新建文件夹`` turns into mojibake and the assembler fails with
    "can't create ...: No such file or directory".  Every path inside the
    project is therefore passed relative to the working directory (which the OS
    resolves correctly); everything else stays absolute.
    """
    try:
        relative = path.resolve().relative_to(ROOT.resolve())
    except (ValueError, OSError):
        return str(path)
    rendered = str(relative)
    return rendered if rendered not in {"", "."} else "."


def run(command: list[str], verbose: bool = True) -> None:
    if verbose:
        announce("+ " + " ".join(command))
    subprocess.run(command, cwd=ROOT, check=True)


# --------------------------------------------------------------------------- #
# Toolchain discovery
# --------------------------------------------------------------------------- #

def _unique(paths) -> list[Path]:
    seen: set[str] = set()
    result: list[Path] = []
    for path in paths:
        if path is None:
            continue
        resolved = Path(path).expanduser()
        key = str(resolved).lower() if os.name == "nt" else str(resolved)
        if key in seen:
            continue
        seen.add(key)
        result.append(resolved)
    return result


def find_compiler() -> Path:
    override = os.environ.get("TUNNEL_CXX")
    if override:
        candidate = Path(override).expanduser()
        if candidate.is_file():
            return candidate
        found = shutil.which(override)
        if found:
            return Path(found)
        raise BuildError(f"TUNNEL_CXX={override} does not point at an executable compiler")

    for name in COMPILER_NAMES:
        found = shutil.which(name)
        if found:
            return Path(found)
    extra_dirs = os.environ.get("TUNNEL_COMPILER_DIRS")
    search_dirs = [Path(entry) for entry in extra_dirs.split(os.pathsep) if entry] if extra_dirs else []
    if os.name == "nt":
        search_dirs += [Path(entry) for entry in WINDOWS_COMPILER_DIRS]
    for directory in _unique(search_dirs):
        for name in ("g++", "clang++"):
            candidate = directory / (name + EXE_SUFFIX)
            if candidate.is_file():
                return candidate
    raise BuildError(
        "No C++ compiler was found. Install gcc/g++ or clang:\n"
        "  Linux   : sudo apt-get install -y build-essential\n"
        "  macOS   : xcode-select --install\n"
        "  Windows : winget install MSYS2.MSYS2, then "
        "pacman -S mingw-w64-x86_64-gcc (the script also finds C:\\msys64\\mingw64\\bin "
        "without a PATH change), or set TUNNEL_CXX to the compiler path."
    )


def _is_toolchain_prefix(prefix: Path) -> bool:
    """Return whether a prefix ships its own compiler driver."""
    for name in ("g++", "clang++", "gcc", "clang"):
        if (prefix / "bin" / (name + EXE_SUFFIX)).is_file():
            return True
    return False


def _same_path(left: Path, right: Path) -> bool:
    try:
        return left.resolve() == right.resolve()
    except OSError:
        return str(left).lower() == str(right).lower()


def dependency_prefixes(compiler: Path) -> list[Path]:
    """Return dependency install prefixes compatible with the chosen compiler.

    A prefix that ships its own compiler driver is skipped unless it is the
    chosen compiler's own prefix: mixing another toolchain (for example the
    32-bit ``C:\\MinGW`` tree) into ``-I`` shadows the MinGW-w64 stdio/crt
    headers and produces nonsense errors inside third-party headers.
    """
    own_prefix = compiler.parent.parent if compiler.parent.name.lower() == "bin" else None
    prefixes: list[Path] = []
    if own_prefix:
        prefixes.append(own_prefix)
    configured = os.environ.get("TUNNEL_DEPS_ROOT")
    if configured:
        prefixes.extend(Path(entry) for entry in configured.split(os.pathsep) if entry)
    if os.name == "nt":
        for entry in WINDOWS_PREFIX_DIRS:
            candidate = Path(entry)
            if own_prefix and _same_path(candidate, own_prefix):
                continue
            if _is_toolchain_prefix(candidate):
                continue
            prefixes.append(candidate)
    bundle_root = ROOT / ".deps"
    if bundle_root.is_dir():
        for child in sorted(bundle_root.iterdir()):
            if child.is_dir() and ((child / "include").is_dir() or (child / "lib").is_dir()):
                prefixes.append(child)
    return [prefix for prefix in _unique(prefixes) if prefix.is_dir()]


def include_dirs(prefixes: list[Path]) -> list[Path]:
    directories = [ROOT / "src", ROOT]
    directories += [prefix / "include" for prefix in prefixes if (prefix / "include").is_dir()]
    return _unique(directories)


def library_dirs(prefixes: list[Path]) -> list[Path]:
    directories: list[Path] = []
    for prefix in prefixes:
        for name in ("lib", "lib64", "lib/x86_64-linux-gnu"):
            candidate = prefix / name
            if candidate.is_dir():
                directories.append(candidate)
    return _unique(directories)


def prepare_environment(compiler: Path) -> None:
    """Expose the toolchain runtime DLLs to the compiler's own sub-processes.

    MinGW-w64 ``cc1plus``/``cc1`` load libisl, libmpc and libwinpthread from the
    compiler's bin directory.  ``g++`` only forwards the PATH it inherits, so a
    compiler that is installed but missing from PATH dies with a silent
    0xC0000135 (STATUS_DLL_NOT_FOUND) instead of a compiler diagnostic.
    """
    entries = [str(compiler.parent)]
    current = os.environ.get("PATH", "")
    os.environ["PATH"] = os.pathsep.join(entries + ([current] if current else []))
    announce("Runtime  : " + entries[0])


def runtime_dll_dirs(prefixes: list[Path], compiler: Path) -> list[Path]:
    directories = [compiler.parent]
    for prefix in prefixes:
        directories.append(prefix / "bin")
    return [directory for directory in _unique(directories) if directory.is_dir()]


# --------------------------------------------------------------------------- #
# Compiler flags and library probing
# --------------------------------------------------------------------------- #

def compile_flags(build_type: str, includes: list[Path]) -> list[str]:
    flags = ["-std=c++11", "-Wall", "-Wextra", "-Wpedantic", *BUILD_TYPE_FLAGS[build_type]]
    flags += [f"-I{tool_path(directory)}" for directory in includes]
    if os.name == "nt":
        flags += ["-DWIN32_LEAN_AND_MEAN", "-DNOMINMAX"]
    else:
        flags += ["-pthread", "-fPIC"]
    extra = os.environ.get("TUNNEL_CFLAGS")
    if extra:
        flags += extra.split()
    return flags


def link_flags(build_type: str, libraries: list[Path]) -> list[str]:
    flags = [f"-L{tool_path(directory)}" for directory in libraries]
    extra = os.environ.get("TUNNEL_LDFLAGS")
    if extra:
        flags += extra.split()
    if os.name != "nt":
        flags += ["-pthread"]
    return flags


def link_libraries() -> list[str]:
    libraries: list[str] = []
    if os.name == "nt":
        libraries += ["-lws2_32", "-liphlpapi"]
    return libraries


def probe(compiler: Path, flags: list[str], libraries: list[str], source: str,
          label: str, verbose: bool) -> tuple[bool, str]:
    with tempfile.TemporaryDirectory(prefix="tunnel-probe-") as workspace:
        directory = Path(workspace)
        source_file = directory / "probe.cpp"
        source_file.write_text(source, encoding="utf-8")
        executable = directory / ("probe" + EXE_SUFFIX)
        command = [str(compiler), *flags, str(source_file), "-o", str(executable), *libraries]
        if verbose:
            announce(f"+ [probe {label}] " + " ".join(command))
        completed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, errors="replace")
        if completed.returncode == 0:
            return True, ""
        detail = (completed.stderr or completed.stdout).strip()
        return False, f"{describe_exit(completed.returncode)}\n{detail}".strip()


def select_libraries(compiler: Path, flags: list[str], candidates, source: str, env_name: str,
                     label: str, hint: str, verbose: bool) -> list[str]:
    override = os.environ.get(env_name)
    if override:
        announce(f"{label}: using {env_name}={override}")
        return override.split()
    last_output = ""
    for candidate in candidates:
        ok, output = probe(compiler, flags, list(candidate), source, label, verbose)
        if ok:
            announce(f"{label}: {' '.join(candidate)}")
            return list(candidate)
        last_output = output
    raise BuildError(
        f"{label} was not found, so the project cannot be linked.\n{hint}\n"
        f"Set {env_name} to the linker flags if it lives in a custom prefix.\n"
        f"Last compiler output:\n{last_output}"
    )


def describe(compiler: Path, flags: list[str], includes: list[Path],
             libraries: list[Path]) -> None:
    version = subprocess.run([str(compiler), "--version"], capture_output=True, text=True, errors="replace")
    banner = (version.stdout or "").splitlines()
    announce(f"Compiler : {compiler}" + (f" ({banner[0].strip()})" if banner else ""))
    if includes:
        announce("Includes : " + ", ".join(str(entry) for entry in includes))
    if libraries:
        announce("Libraries: " + ", ".join(str(entry) for entry in libraries))


# --------------------------------------------------------------------------- #
# Object compilation
# --------------------------------------------------------------------------- #

def object_path(source: str) -> Path:
    return OBJECT_DIR / (source + ".o")


def dependency_file(obj: Path) -> Path:
    return obj.with_name(obj.name + ".d")


def is_stale(source: str, obj: Path) -> bool:
    source_file = ROOT / source
    if not obj.is_file() or not source_file.is_file():
        return True
    dep_file = dependency_file(obj)
    if not dep_file.is_file():
        return True
    try:
        text = dep_file.read_text(errors="replace").replace("\\\n", " ")
        stamp = obj.stat().st_mtime
    except OSError:
        return True
    _, _, dependencies = text.partition(":")
    for token in dependencies.split():
        candidate = Path(token.strip())
        if not candidate.is_absolute():
            candidate = ROOT / candidate
        try:
            if candidate.is_file() and candidate.stat().st_mtime > stamp:
                return True
        except OSError:
            return True
    return False


def reset_object_cache(flags: list[str], compiler: Path) -> None:
    """Drop cached objects when the compiler or the flags changed."""
    fingerprint = hashlib.sha256(
        ("\n".join([str(compiler), *flags])).encode("utf-8")).hexdigest()
    stamp = OBJECT_DIR / ".fingerprint"
    try:
        if stamp.read_text(encoding="ascii").strip() == fingerprint:
            return
    except OSError:
        pass
    if OBJECT_DIR.is_dir():
        shutil.rmtree(OBJECT_DIR, ignore_errors=True)
    OBJECT_DIR.mkdir(parents=True, exist_ok=True)
    stamp.write_text(fingerprint + "\n", encoding="ascii")


def compile_one(job) -> tuple[str, str | None]:
    source, compiler, flags, verbose = job
    obj = object_path(source)
    obj.parent.mkdir(parents=True, exist_ok=True)
    command = [str(compiler), *flags, "-MMD", "-MF", tool_path(dependency_file(obj)),
               "-c", tool_path(ROOT / source), "-o", tool_path(obj)]
    if verbose:
        announce("+ " + " ".join(command))
    completed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, errors="replace")
    if completed.returncode:
        detail = (completed.stdout + completed.stderr).strip() or describe_exit(completed.returncode)
        return source, detail
    return source, None


def compile_sources(sources, compiler: Path, flags: list[str], jobs: int, verbose: bool) -> None:
    pending = [source for source in sources if is_stale(source, object_path(source))]
    if not pending:
        announce(f"Compilation up to date ({len(sources)} files)")
        return
    announce(f"Compiling {len(pending)}/{len(sources)} file(s) with {jobs} job(s)")
    failures: list[tuple[str, str]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
        futures = {pool.submit(compile_one, (source, compiler, flags, verbose)): source
                   for source in pending}
        for future in concurrent.futures.as_completed(futures):
            source, error = future.result()
            if error:
                failures.append((source, error))
            elif not verbose:
                announce(f"  compiled {source}")
    if failures:
        report = "\n\n".join(f"--- {source} ---\n{error}" for source, error in failures)
        raise BuildError(f"{len(failures)} translation unit(s) failed to compile:\n{report}")
    for source in pending:
        if not object_path(source).is_file():
            raise BuildError(f"internal error: {object_path(source)} was not produced")


def link_executable(target: Path, objects: list[Path], compiler: Path, flags: list[str],
                    libraries: list[str], verbose: bool) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    command = [str(compiler), *[tool_path(obj) for obj in objects], "-o", tool_path(target),
               *flags, *libraries]
    if verbose:
        announce("+ " + " ".join(command))
    completed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, errors="replace")
    if completed.returncode:
        raise BuildError(f"linking {target.name} failed ({describe_exit(completed.returncode)}):\n"
                         f"{(completed.stderr or completed.stdout).strip()}")
    announce(f"  linked {target.relative_to(ROOT)}")


# --------------------------------------------------------------------------- #
# Platform extras
# --------------------------------------------------------------------------- #

def clean_build_directory() -> None:
    if not BUILD_DIR.is_dir():
        return
    preserved: dict[str, bytes] = {}
    for name in ("wintun.dll", "WINTUN-LICENSE.txt"):
        path = BUILD_DIR / name
        if path.is_file():
            preserved[name] = path.read_bytes()
    shutil.rmtree(BUILD_DIR)
    BUILD_DIR.mkdir(parents=True)
    for name, data in preserved.items():
        (BUILD_DIR / name).write_bytes(data)
    announce(f"Cleaned {BUILD_DIR}")


def required_dlls(executable: Path, compiler: Path) -> list[str]:
    objdump = shutil.which("objdump") or shutil.which("llvm-objdump")
    if not objdump:
        for name in ("objdump.exe", "llvm-objdump.exe"):
            candidate = compiler.parent / name
            if candidate.is_file():
                objdump = str(candidate)
                break
    if not objdump:
        return []
    completed = subprocess.run([objdump, "-p", tool_path(executable)], cwd=ROOT,
                               capture_output=True, text=True, errors="replace")
    if completed.returncode:
        announce(f"WARNING: objdump could not read {executable.name}: {describe_exit(completed.returncode)}")
        return []
    names = set()
    for line in completed.stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("DLL Name:"):
            names.add(stripped.split(":", 1)[1].strip())
    return sorted(names)


def copy_runtime_file(source: Path, destination: Path) -> bool:
    """Copy a runtime file unless the destination already holds the same bytes."""
    if destination.is_file():
        try:
            if source.stat().st_size == destination.stat().st_size and \
                    source.read_bytes() == destination.read_bytes():
                return False
        except OSError:
            pass
    try:
        shutil.copy2(source, destination)
        return True
    except PermissionError as error:
        raise BuildError(
            f"cannot replace locked runtime file {destination}; "
            "close the running Tunnel/UI process and retry") from error


def copy_windows_runtime(build_dir: Path, compiler: Path, prefixes: list[Path], verbose: bool) -> None:
    """Collect every DLL the freshly linked executables import.

    MinGW/OpenSSL/libevent runtime DLLs live next to the compiler instead of the
    system directories, so they must travel with ``tunnel.exe``.
    """
    if os.name != "nt":
        return
    vendor = ROOT / "third_party" / "windows"
    for name in ("wintun.dll", "WINTUN-LICENSE.txt"):
        source = vendor / name
        if source.is_file() and not (build_dir / name).is_file():
            copy_runtime_file(source, build_dir / name)

    search_dirs = runtime_dll_dirs(prefixes, compiler)
    system_dir = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
    copied: list[str] = []
    queue = sorted(build_dir.glob("*.exe"))
    visited: set[Path] = set()
    while queue:
        binary = queue.pop(0)
        if binary in visited:
            continue
        visited.add(binary)
        for name in required_dlls(binary, compiler):
            destination = build_dir / name
            if destination.is_file():
                queue.append(destination)
                continue
            if (system_dir / name).is_file():
                continue
            for directory in search_dirs:
                candidate = directory / name
                if candidate.is_file():
                    if copy_runtime_file(candidate, destination):
                        copied.append(name)
                    queue.append(destination)
                    break
            else:
                announce(f"WARNING: {name} (needed by {binary.name}) was not found in "
                         + ", ".join(str(entry) for entry in search_dirs))
    if copied:
        announce("Copied runtime DLLs: " + ", ".join(sorted(set(copied))))


def build_linux_kernel_module(build_dir: Path, skip: bool) -> None:
    """Build the optional data-plane module alongside the native executable.

    The module is ABI-specific, so it is deliberately built on the target Linux
    machine through the kernel build system rather than this C++ toolchain.
    """
    if platform.system() != "Linux":
        return
    if skip:
        announce("Skipping Linux kernel module build (--skip-kernel-module)")
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
        raise BuildError(
            "Linux kernel module build failed. Install headers matching uname -r "
            "and kmod/build tools, or rerun with --skip-kernel-module to build "
            "the userspace TUN backend only.") from error


def ensure_gui_dependencies(skip: bool) -> Path | None:
    """Prepare the Python GUI environment before compiling the native core."""
    if skip or platform.system() not in {"Linux", "Darwin"}:
        return None
    system_python = shutil.which("python3") or shutil.which("python")
    if not system_python:
        raise BuildError(
            "Python 3 is required for the desktop GUI. Install Python 3 and python3-venv, "
            "or rerun with --skip-gui-deps for a core-only build.")
    venv_dir = ROOT / ".venv-gui"
    python = venv_dir / "bin" / "python"
    if not python.is_file():
        run([system_python, "-m", "venv", "--system-site-packages", str(venv_dir)])
    requirements = ROOT / "gui" / "requirements.txt"
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
            run([str(python), "-c", "import webview"], verbose=False)
        except subprocess.CalledProcessError:
            needs_install = True
    if needs_install:
        run([str(python), "-m", "pip", "install", "-r", str(requirements)])
        run([str(python), "-c", "import webview"])
        stamp.write_text(fingerprint + "\n", encoding="ascii")
    else:
        announce(f"Reusing GUI environment: {venv_dir}")
    return python


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
    """Enable the RustDesk direct-IP mode used by the Tunnel virtual network."""
    executable = rustdesk_executable()
    if not executable:
        return
    commands = [
        [executable, "--option", "direct-server", "Y"],
        [executable, "--option", "direct-access-port", "21118"],
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
            announce(f"RustDesk direct-IP setup was not applied: {error}; "
                     "enable it in RustDesk Security settings.")
            return


def configure_rustdesk_host() -> None:
    """Apply the Tunnel remote key to the installed RustDesk service."""
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
            announce("RustDesk permanent password was not applied: sudo is unavailable.")
            return
        command.insert(0, sudo)
    try:
        completed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True,
                                   timeout=15, check=False)
    except (OSError, subprocess.SubprocessError) as error:
        announce(f"RustDesk permanent password was not applied: {error}")
        return
    if completed.returncode:
        announce("RustDesk permanent password was not applied; run the build as administrator/root.")
    else:
        announce("RustDesk permanent password applied from remote_desktop.shared_key.")


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
            announce(f"Downloading RustDesk: {url}")
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
            announce(f"RustDesk download failed: {error}")
    raise BuildError(
        f"Unable to download RustDesk {RUSTDESK_VERSION}. "
        "Check network access or rerun with --skip-rustdesk.") from last_error


def ensure_rustdesk(skip: bool) -> None:
    """Install RustDesk for desktop GUI builds; it stays an external dependency."""
    if skip or os.environ.get("TUNNEL_SKIP_RUSTDESK") == "1":
        announce("Skipping RustDesk installation (--skip-rustdesk)")
        return
    existing = rustdesk_executable()
    if existing:
        announce(f"Reusing RustDesk: {existing}")
        configure_rustdesk_direct()
        return
    if os.name == "nt":
        winget = shutil.which("winget")
        if winget:
            try:
                run([winget, "install", "--id", "RustDesk.RustDesk", "--exact", "--silent",
                     "--accept-package-agreements", "--accept-source-agreements"])
            except subprocess.CalledProcessError:
                announce("winget did not provide RustDesk; falling back to the portable official release.")
        if not rustdesk_executable():
            portable = ROOT / ".deps" / "rustdesk" / "RustDesk.exe"
            _download_rustdesk(portable, f"rustdesk-{RUSTDESK_VERSION}-x86_64.exe")
        if not rustdesk_executable():
            raise BuildError("RustDesk installation completed but rustdesk.exe was not found.")
        configure_rustdesk_direct()
        return
    if platform.system() != "Linux":
        announce("RustDesk installation is automatic only on Linux and Windows; install it manually on this platform.")
        return
    machine = platform.machine().lower()
    suffix = "x86_64" if machine in {"x86_64", "amd64"} else "aarch64" if machine in {"aarch64", "arm64"} else ""
    if not suffix or not shutil.which("dpkg"):
        raise BuildError("Automatic RustDesk installation requires a Debian/Ubuntu x86_64 or aarch64 host; "
                         "use --skip-rustdesk for a core-only build.")
    package = ROOT / ".deps" / "rustdesk" / f"rustdesk-{RUSTDESK_VERSION}-{suffix}.deb"
    if not package.is_file() or package.stat().st_size <= 1024 * 1024:
        _download_rustdesk(package, f"rustdesk-{RUSTDESK_VERSION}-{suffix}.deb")
    installer = shutil.which("apt-get")
    if not installer:
        raise BuildError("apt-get was not found; install RustDesk manually or use --skip-rustdesk.")
    command = [installer, "install", "-y", str(package)]
    if os.geteuid() != 0:
        sudo = shutil.which("sudo")
        if not sudo:
            raise BuildError("RustDesk installation needs root or sudo; install it manually or use --skip-rustdesk.")
        command.insert(0, sudo)
    run(command)
    if not rustdesk_executable():
        raise BuildError("RustDesk package installed but the rustdesk executable was not found.")
    configure_rustdesk_direct()
    announce(f"RustDesk installed: {rustdesk_executable()}")


# --------------------------------------------------------------------------- #
# Build driver
# --------------------------------------------------------------------------- #

def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Configure and build Tunnel with gcc/g++ (or clang++), without CMake")
    parser.add_argument("--gui", action="store_true", help="also package the desktop GUI on Windows")
    parser.add_argument("--clean", action="store_true", help="remove the build directory before compiling")
    parser.add_argument("--skip-kernel-module", action="store_true",
                        help="on Linux, skip the ABI-specific tunnel_kmod.ko build")
    parser.add_argument("--skip-gui-deps", action="store_true",
                        help="skip Linux/macOS GUI dependency preparation (core-only build)")
    parser.add_argument("--skip-rustdesk", action="store_true",
                        help="skip automatic RustDesk installation for desktop GUI builds")
    parser.add_argument("--tests", action="store_true",
                        help="build and run the native test suite after compiling")
    parser.add_argument("--jobs", type=int, default=int(os.environ.get("TUNNEL_JOBS", "0") or 0),
                        help="parallel compilation jobs (default: CPU count)")
    parser.add_argument("--verbose", "-v", action="store_true", help="print every compiler command")
    parser.add_argument("--build-type", choices=tuple(BUILD_TYPE_FLAGS),
                        default=os.environ.get("TUNNEL_BUILD_TYPE", "Release"),
                        help="optimisation profile (default: Release; TUNNEL_BUILD_TYPE also supported)")
    return parser.parse_args()


def main() -> int:
    args = parse_arguments()
    jobs = args.jobs if args.jobs > 0 else max(1, (os.cpu_count() or 1))
    verbose = args.verbose

    # RustDesk is needed by the desktop GUI, not by a core-only build.
    desktop_build = not args.skip_gui_deps and (os.name != "nt" or args.gui)
    if desktop_build:
        ensure_rustdesk(args.skip_rustdesk)
        if not args.skip_rustdesk and os.environ.get("TUNNEL_SKIP_RUSTDESK") != "1":
            configure_rustdesk_host()
    ensure_gui_dependencies(args.skip_gui_deps)

    if args.clean:
        clean_build_directory()
    BUILD_DIR.mkdir(parents=True, exist_ok=True)

    compiler = find_compiler()
    prefixes = dependency_prefixes(compiler)
    prepare_environment(compiler)
    includes = include_dirs(prefixes)
    libraries = library_dirs(prefixes)
    flags = compile_flags(args.build_type, includes)
    link_base = link_flags(args.build_type, libraries)
    platform_libraries = link_libraries()

    describe(compiler, flags, includes, libraries)
    event_libs = select_libraries(
        compiler, [*flags, *link_base, *platform_libraries], EVENT_LIBRARY_CANDIDATES,
        EVENT_PROBE, "TUNNEL_EVENT_LIBS", "libevent", (
            "Install libevent development files:\n"
            "  Linux   : sudo apt-get install -y libevent-dev\n"
            "  Debian  : the runtime package alone is not enough, headers are required\n"
            "  Windows : pacman -S mingw-w64-x86_64-libevent (MSYS2)\n"
            "  macOS   : brew install libevent"), verbose)
    ssl_libs = select_libraries(
        compiler, [*flags, *link_base, *platform_libraries], OPENSSL_LIBRARY_CANDIDATES,
        OPENSSL_PROBE, "TUNNEL_OPENSSL_LIBS", "OpenSSL 3.x", (
            "Install OpenSSL 3.x development files:\n"
            "  Linux   : sudo apt-get install -y libssl-dev\n"
            "  Windows : pacman -S mingw-w64-x86_64-openssl (MSYS2)\n"
            "  macOS   : brew install openssl@3 and set TUNNEL_DEPS_ROOT"), verbose)

    resolver_flags = [*flags, *link_base, *platform_libraries, *event_libs, *ssl_libs]

    reset_object_cache(resolver_flags, compiler)
    compile_sources(CORE_SOURCES, compiler, flags, jobs, verbose)

    core_objects = [object_path(source) for source in CORE_SOURCES]
    executable = BUILD_DIR / ("tunnel" + EXE_SUFFIX)
    compile_sources(("src/main.cpp",), compiler, flags, jobs, verbose)
    link_executable(executable, [object_path("src/main.cpp"), *core_objects],
                    compiler, link_base, [*event_libs, *ssl_libs, *platform_libraries], verbose)

    test_executables: list[tuple[str, Path, tuple[str, ...], int]] = []
    if args.tests:
        compile_sources([source for _, source, _, _ in TEST_TARGETS], compiler, flags, jobs, verbose)
        for name, source, arguments, timeout in TEST_TARGETS:
            target = BUILD_DIR / (name + EXE_SUFFIX)
            link_executable(target, [object_path(source), *core_objects], compiler,
                            link_base, [*event_libs, *ssl_libs, *platform_libraries], verbose)
            test_executables.append((name, target, arguments, timeout))

    copy_windows_runtime(BUILD_DIR, compiler, prefixes, verbose)

    if args.tests:
        announce("Running native tests")
        run([str(executable), "--check", str(ROOT / "config" / "default.json")])
        for name, target, arguments, timeout in test_executables:
            command = [str(target)]
            working_directory = ROOT
            for argument in arguments:
                if argument.startswith("config/"):
                    command.append(str(ROOT / argument))
                else:
                    # State names stay relative to the build directory: the
                    # Windows CRT converts argv with the ANSI code page, which
                    # corrupts non-ASCII paths that tests serialise into JSON.
                    command.append(argument)
                    working_directory = BUILD_DIR
            try:
                subprocess.run(command, cwd=working_directory, timeout=timeout, check=True)
            except subprocess.TimeoutExpired as error:
                raise BuildError(f"{name} timed out after {timeout}s") from error
            except subprocess.CalledProcessError as error:
                raise BuildError(f"{name} failed with exit code {error.returncode}") from error
            announce(f"  passed {name}")

    build_linux_kernel_module(BUILD_DIR, args.skip_kernel_module)

    if args.gui:
        if os.name != "nt":
            raise BuildError("--gui is currently available only for Windows desktop packaging; "
                             "core build is complete.")
        run([sys.executable, str(ROOT / "gui" / "build_windows.py"), "--core-dir", str(BUILD_DIR)])

    announce(f"Build complete: {BUILD_DIR}")
    announce(f"Executable    : {executable}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BuildError as error:
        print(error, file=sys.stderr)
        sys.exit(1)