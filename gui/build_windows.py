"""Build an unpacked Windows app using the already-built native core."""
import argparse
from datetime import datetime
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--core-dir", type=Path, default=ROOT / "build")
    # Keep the generated package away from the historical ``TunnelUI``
    # directory.  Older elevated GUI instances can leave that directory
    # owned by an administrator and PyInstaller then fails while replacing
    # its ``background`` files.  The launcher accepts this stable name and
    # the directory can be rebuilt by a normal developer session.
    parser.add_argument("--output-dir", type=Path, default=ROOT / "build" / "gui" / "TunnelUI-live",
                        help="Unpacked GUI package directory")
    args = parser.parse_args()
    if sys.platform != "win32":
        parser.error("Run this packager on Windows")
    core = args.core_dir.resolve()
    required = ["tunnel.exe", "wintun.dll", "WINTUN-LICENSE.txt"]
    for name in required:
        if not (core / name).is_file():
            parser.error("Missing native build dependency: " + str(core / name))
    examples = [ROOT / "examples" / name for name in ("address-server.json", "address-client.json", "subnet-gateway.json", "subnet-client.json", "desktop-host.json", "desktop-client.json", "tcp-node-a.json", "tcp-node-b.json")]
    for source in examples:
        if not source.is_file():
            parser.error("Missing configuration example: " + str(source))
    destination = args.output_dir.resolve()
    # A GUI started without ``--config-dir`` may have created a private
    # ``background`` directory inside an older package with administrator
    # ownership.  PyInstaller must delete the destination before collecting;
    # switch to a fresh sibling package when that state cannot be removed.
    if destination.exists():
        stale_state = destination / "background"
        try:
            if stale_state.exists():
                destination = destination.with_name(
                    destination.name + "-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
            else:
                probe = destination / ".tunnel-build-probe"
                probe.write_text("", encoding="ascii")
                probe.unlink()
        except OSError:
            destination = destination.with_name(
                destination.name + "-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
    destination.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run([sys.executable, "-m", "PyInstaller", "--noconfirm", "--windowed", "--onedir",
        "--paths", str(ROOT), "--collect-submodules", "remote_desktop",
        "--uac-admin", "--name", destination.name, "--distpath", str(destination.parent),
        # Keep PyInstaller's work/spec directories outside the distpath tree;
        # a sibling such as ``build/gui-work`` is still considered inside
        # ``build/gui`` by PyInstaller's path-prefix check.
        "--workpath", str(ROOT / "build" / "pyi-gui-work"), "--specpath", str(ROOT / "build" / "pyi-gui-spec"),
        # PyInstaller uses ';' as the source/destination separator on
        # Windows and ':' on POSIX.  This packager is Windows-only, but use
        # the platform separator explicitly so assets are actually bundled.
        "--add-data", str(ROOT / "gui" / "assets") + os.pathsep + "assets",
        "--add-data", str(ROOT / "config" / "default.json") + os.pathsep + ".", str(ROOT / "gui" / "main.py")], check=True)
    generated_gui = destination / (destination.name + ".exe")
    if generated_gui.is_file() and generated_gui.name != "TunnelUI.exe":
        # Keep a stable launcher name even when --output-dir uses a versioned
        # directory to avoid an old locked package.
        shutil.copy2(generated_gui, destination / "TunnelUI.exe")
    # A console entry point shares the profile and authenticated local host with
    # the GUI. Windowed executables do not reliably expose stdout to terminals.
    subprocess.run([sys.executable, "-m", "PyInstaller", "--noconfirm", "--console", "--onefile",
        "--paths", str(ROOT), "--collect-submodules", "remote_desktop",
        "--uac-admin", "--name", "TunnelCtl", "--distpath", str(destination),
        "--workpath", str(ROOT / "build" / "pyi-cli-work"), "--specpath", str(ROOT / "build" / "pyi-gui-spec"),
        str(ROOT / "tools" / "tunnel_cli.py")], check=True)
    for source in [core / "tunnel.exe", core / "WINTUN-LICENSE.txt", *core.glob("*.dll")]:
        shutil.copy2(source, destination / source.name)
    readme = (ROOT / "gui" / "README.md").read_text(encoding="utf-8")
    (destination / "README.md").write_text(readme.replace("../remote_desktop/README.md", "RemoteDesktop-README.md"), encoding="utf-8")
    shutil.copy2(ROOT / "remote_desktop" / "README.md", destination / "RemoteDesktop-README.md")
    # Keep the vendored noVNC license/version notices beside the packaged GUI.
    for notice in (ROOT / "third_party" / "novnc-LICENSE.txt", ROOT / "third_party" / "novnc-VERSION.txt"):
        shutil.copy2(notice, destination / notice.name)
    shutil.copy2(ROOT / "docs" / "cli.md", destination / "CLI-README.md")
    (destination / "examples").mkdir(exist_ok=True)
    for source in examples:
        shutil.copy2(source, destination / "examples" / source.name)
    # Let the launcher follow a fallback package created after an old package
    # became locked or administrator-owned.
    (destination.parent / "current-package.txt").write_text(destination.name + "\n", encoding="ascii")
    print(destination / "TunnelUI.exe")


if __name__ == "__main__":
    main()
