"""Build an unpacked Windows app using the already-built native core."""
import argparse
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--core-dir", type=Path, default=ROOT / "build")
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
    subprocess.run([sys.executable, "-m", "PyInstaller", "--noconfirm", "--windowed", "--onedir",
        "--paths", str(ROOT), "--collect-submodules", "remote_desktop",
        "--uac-admin", "--name", "TunnelUI", "--distpath", str(ROOT / "build" / "gui"),
        "--workpath", str(ROOT / "build" / "gui-work"), "--specpath", str(ROOT / "build" / "gui-spec"),
        "--add-data", str(ROOT / "gui" / "assets") + ":assets",
        "--add-data", str(ROOT / "configure.json") + ":.", str(ROOT / "gui" / "main.py")], check=True)
    destination = ROOT / "build" / "gui" / "TunnelUI"
    # A console entry point shares the profile and authenticated local host with
    # the GUI. Windowed executables do not reliably expose stdout to terminals.
    subprocess.run([sys.executable, "-m", "PyInstaller", "--noconfirm", "--console", "--onefile",
        "--paths", str(ROOT), "--collect-submodules", "remote_desktop",
        "--uac-admin", "--name", "TunnelCtl", "--distpath", str(destination),
        "--workpath", str(ROOT / "build" / "cli-work"), "--specpath", str(ROOT / "build" / "gui-spec"),
        str(ROOT / "tunnel_cli.py")], check=True)
    for source in [core / "tunnel.exe", core / "WINTUN-LICENSE.txt", *core.glob("*.dll")]:
        shutil.copy2(source, destination / source.name)
    readme = (ROOT / "gui" / "README.txt").read_text(encoding="utf-8")
    (destination / "README.txt").write_text(readme.replace("../remote_desktop/README.txt", "RemoteDesktop-README.txt"), encoding="utf-8")
    shutil.copy2(ROOT / "remote_desktop" / "README.txt", destination / "RemoteDesktop-README.txt")
    shutil.copy2(ROOT / "命令行说明.txt", destination / "CLI-README.txt")
    (destination / "examples").mkdir(exist_ok=True)
    for source in examples:
        shutil.copy2(source, destination / "examples" / source.name)
    print(destination / "TunnelUI.exe")


if __name__ == "__main__":
    main()
