"""Authenticated local IPC and a GUI-independent desktop host process."""
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import threading
import time

from .security import _read, receive, send


def authenticate(sock, key, server=False):
    if server:
        first = secrets.token_bytes(32)
        sock.sendall(b"TDR1" + first)
        response = _read(sock, 64)
        second, signature = response[:32], response[32:]
        if not hmac.compare_digest(signature, hmac.digest(key, b"client" + first + second, "sha256")):
            raise PermissionError("Local desktop authentication failed")
        sock.sendall(hmac.digest(key, b"server" + first + second, "sha256"))
    else:
        hello = _read(sock, 36)
        if hello[:4] != b"TDR1":
            raise PermissionError("Unknown local desktop endpoint")
        first, second = hello[4:], secrets.token_bytes(32)
        sock.sendall(second + hmac.digest(key, b"client" + first + second, "sha256"))
        signature = _read(sock, 32)
        if not hmac.compare_digest(signature, hmac.digest(key, b"server" + first + second, "sha256")):
            raise PermissionError("Local desktop authentication failed")


class BackgroundHost:
    def __init__(self, binary, state_dir):
        self.binary = Path(binary).resolve()
        self.state_dir = Path(state_dir).resolve()
        self.endpoint = self.state_dir / "desktop-host.json"
        self.last_status = {"running": False, "pid": None, "exit_code": None, "error": ""}
        self.child = None

    def request(self, action, payload=None):
        data = json.loads(self.endpoint.read_text(encoding="utf-8"))
        with socket.create_connection(("127.0.0.1", data["port"]), timeout=3) as sock:
            sock.settimeout(None if action in ("apply_config", "remote_configure") else 12)
            authenticate(sock, bytes.fromhex(data["token"]))
            send(sock, {"action": action, "payload": payload or {}})
            reply = receive(sock)
        if not reply.get("ok"):
            raise ValueError(reply.get("error", "Desktop host request failed"))
        return reply["data"]

    def status(self):
        try:
            self.last_status = self.request("host_status")
        except (OSError, ValueError, EOFError):
            result = self.state_dir / "desktop-exit.json"
            value = {"running": False, "pid": None, "exit_code": None, "error": ""}
            try:
                value.update(json.loads(result.read_text(encoding="utf-8")))
            except (OSError, ValueError):
                pass
            self.last_status = value
        return dict(self.last_status)

    def is_running(self):
        return bool(self.status().get("running"))

    def start(self, config_path, status_path):
        if self.is_running():
            raise ValueError("Tunnel background host is already running")
        self.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        (self.state_dir / "desktop-exit.json").unlink(missing_ok=True)
        arguments = ["--binary", str(self.binary), "--state-dir", str(self.state_dir),
                     "--config", str(Path(config_path).resolve()), "--status-file", str(Path(status_path).resolve())]
        if getattr(sys, "frozen", False):
            command = [sys.executable, "--remote-daemon", *arguments]
        else:
            command = [sys.executable, "-m", "remote_desktop.daemon", *arguments]
        options = {"creationflags": subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt" else {"start_new_session": True}
        root = Path(sys.executable).parent if getattr(sys, "frozen", False) else Path(__file__).resolve().parent.parent
        with (self.state_dir / "desktop-host.log").open("ab") as output:
            child = subprocess.Popen(command, cwd=root, stdin=subprocess.DEVNULL, stdout=output, stderr=output, **options)
        self.child = child
        threading.Thread(target=child.wait, daemon=True).start()
        deadline = time.monotonic() + 15
        try:
            while time.monotonic() < deadline:
                state = self.status()
                if state.get("running"):
                    return state
                if child.poll() is not None:
                    raise ValueError(state.get("error") or "Tunnel background host failed; see desktop-host.log")
                time.sleep(0.1)
            raise TimeoutError("Tunnel background host startup timed out")
        except Exception:
            if child.poll() is None:
                try:
                    endpoint = json.loads(self.endpoint.read_text(encoding="utf-8"))
                    if endpoint.get("pid") == child.pid:
                        self.request("host_stop")
                        child.wait(timeout=5)
                except (OSError, ValueError, subprocess.TimeoutExpired):
                    pass
                if child.poll() is None:
                    # Killing this host closes its stdin pipe to the native
                    # core; --stdio-control then performs normal core cleanup.
                    child.terminate()
                    child.wait(timeout=5)
            raise

    def stop(self):
        if not self.is_running():
            return
        self.request("host_stop")
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if not self.endpoint.exists():
                if self.child:
                    self.child.wait(timeout=max(1, deadline - time.monotonic()))
                else:
                    # A reattached GUI has no Popen object. The directory lock
                    # is released only after core shutdown and state flushing.
                    from .daemon import InstanceLock
                    try:
                        lock = InstanceLock(self.state_dir / "desktop-host.lock")
                    except OSError:
                        time.sleep(0.1)
                        continue
                    lock.close()
                    # On Windows the detached process can still be closing its
                    # inherited log handles immediately after releasing the lock.
                    time.sleep(0.1)
                return
            time.sleep(0.1)
        raise TimeoutError("Tunnel background host did not stop")
