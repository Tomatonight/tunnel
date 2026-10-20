"""Exercise the frozen background host using an isolated address-only service.

No TUN, screen capture, input injection, public listeners or real profile changes.
"""
import argparse
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from remote_desktop.host import BackgroundHost


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--package", type=Path, default=ROOT / "build/gui/TunnelUI")
    parser.add_argument("--output", type=Path, default=ROOT / "build/gui-tests/remote-package-background.json")
    args = parser.parse_args()
    package = args.package.resolve()
    result = {"ok": False, "checks": [], "scope": "real frozen daemon and loopback address service; no desktop capture or input"}
    child = host = None
    with tempfile.TemporaryDirectory(prefix="tunnel-package-remote-") as temporary:
        directory = Path(temporary)
        try:
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                port = reservation.getsockname()[1]
            config = directory / "configure.json"
            config.write_text(json.dumps({"address_server": {"address": "127.0.0.1:" + str(port),
                "bind_address": "127.0.0.1:" + str(port), "shared_key": secrets.token_hex(32),
                "networks": ["198.18.252.0/29"], "state_file": str(directory / "leases.json")}}), encoding="utf-8")
            status_path = directory / "status.json"
            binary = package / "tunnel.exe"
            host = BackgroundHost(binary, directory)
            command = [str(package / "TunnelUI.exe"), "--remote-daemon", "--binary", str(binary),
                       "--config", str(config), "--state-dir", str(directory), "--status-file", str(status_path)]
            options = {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {}
            child = subprocess.Popen(command, cwd=package, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL, **options)
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                state = host.status()
                if state.get("running"):
                    break
                if child.poll() is not None:
                    raise RuntimeError("Packaged daemon exited: " + str(state))
                time.sleep(0.1)
            else:
                raise RuntimeError("Packaged daemon startup timed out")
            result["checks"].append("frozen_daemon_launch")
            remote = host.request("remote_state")
            assert len(remote["identity"]["fingerprint"]) == 64
            assert not remote["config"]["enabled"] and not remote["listeners"]
            result["checks"].append("persistent_identity_and_disabled_desktop")
            second = BackgroundHost(binary, directory)
            assert second.status()["pid"] == state["pid"]
            assert second.request("remote_state")["identity"] == remote["identity"]
            result["checks"].append("fresh_host_reattaches")
            applied = second.request("remote_configure", {"config": {"enabled": False}})
            assert not applied["config"]["enabled"]
            result["checks"].append("authenticated_policy_update")
            second.stop()
            assert child.wait(timeout=10) == 0
            assert not second.status()["running"]
            result["checks"].append("reattached_host_stop_releases_process")
            result["ok"] = True
        except Exception as error:
            result["error"] = str(error)
        finally:
            if child and child.poll() is None:
                try:
                    host.stop()
                    child.wait(timeout=10)
                except Exception:
                    child.kill()
                    child.wait(timeout=10)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
