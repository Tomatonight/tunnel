"""Headless owner of the core and optional desktop service.

Run in the logged-in user's graphical session. This does not install a system
service or claim access to login/secure desktops.
"""
import argparse
import csv
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import threading
import time
import tempfile

from .core import CoreBridge
from .host import authenticate
from .runtime import Runtime
from .security import atomic_write, canonical, receive, send


class InstanceLock:
    def __init__(self, path):
        self.file = open(path, "a+b")
        self.file.seek(0)
        if os.name == "nt":
            import msvcrt
            if not self.file.read(1):
                self.file.write(b"0")
                self.file.flush()
            self.file.seek(0)
            msvcrt.locking(self.file.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(self.file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)

    def close(self):
        self.file.close()


def private_directory(path):
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name == "nt":
        options = {"creationflags": subprocess.CREATE_NO_WINDOW}
        identity = subprocess.check_output(["whoami", "/user", "/fo", "csv", "/nh"], text=True, **options)
        sid = next(csv.reader([identity.strip()]))[1]
        subprocess.run(["icacls", str(path), "/inheritance:r", "/grant:r",
                        "*" + sid + ":(OI)(CI)F", "*S-1-5-18:(OI)(CI)F"],
                       check=True, capture_output=True, **options)
    else:
        path.chmod(0o700)


class ConfigurationManager:
    """Serialize with the host guard; commit disk only after the core accepts it."""
    def __init__(self, core, runtime, path, document, normalize):
        self.core, self.runtime, self.path = core, runtime, Path(path)
        self.document, self.normalize = document, normalize

    def _apply_core(self, document):
        fd, name = tempfile.mkstemp(prefix=".reload-", suffix=".json", dir=self.path.parent)
        try:
            with os.fdopen(fd, "wb") as output:
                output.write(canonical(document))
                output.flush()
                os.fsync(output.fileno())
            result = self.core.call("config_apply", path=str(Path(name).resolve()))
            if not result.get("ok"):
                message = result.get("error", "Configuration apply failed")
                if result.get("rollback_error"):
                    message += "; rollback failed: " + result["rollback_error"]
                raise ValueError(message)
            return result
        finally:
            Path(name).unlink(missing_ok=True)

    def apply(self, document):
        candidate = self.normalize(document)
        previous = self.document
        result = self._apply_core(candidate)
        try:
            self.runtime.configure(candidate.get("remote_desktop", {"enabled": False}))
            atomic_write(self.path, canonical(candidate))
        except Exception as problem:
            try:
                self._apply_core(previous)
                self.runtime.configure(previous.get("remote_desktop", {"enabled": False}))
            except Exception as rollback:
                raise ValueError(f"Configuration commit failed: {problem}; rollback failed: {rollback}") from None
            raise ValueError(f"Configuration commit failed; previous configuration restored: {problem}") from None
        self.document = candidate
        messages = {"noop": "配置未变化", "remote": "远控配置已应用", "peers": "Peer 配置已应用，保留未变更的邻接",
                    "rebuild": "配置已应用，网络资源已重建，节点正在重新连接"}
        return dict(result, message=messages.get(result.get("mode"), "配置已应用"))


def main(argv=None):
    parser = argparse.ArgumentParser(description="Tunnel remote desktop background host")
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--state-dir", required=True, type=Path)
    parser.add_argument("--status-file", required=True, type=Path)
    args = parser.parse_args(argv)
    binary, config_path, state_dir, status_path = (p.resolve() for p in (args.binary, args.config, args.state_dir, args.status_file))
    private_directory(state_dir)
    instance = InstanceLock(state_dir / "desktop-host.lock")
    endpoint = state_dir / "desktop-host.json"
    stopping = threading.Event()
    core = runtime = listener = manager = None
    error = ""
    code = None
    key = secrets.token_bytes(32)
    guard = threading.RLock()
    workers_lock = threading.Lock()
    slots = threading.BoundedSemaphore(16)
    workers = set()

    def stop_signal(*unused):
        stopping.set()
    signal.signal(signal.SIGINT, stop_signal)
    signal.signal(signal.SIGTERM, stop_signal)

    def normalized(document):
        temporary = state_dir / "desktop-validation.json"
        atomic_write(temporary, canonical(document))
        try:
            result = subprocess.run([str(binary), str(temporary), "--normalize-config"],
                capture_output=True, text=True, encoding="utf-8", timeout=10,
                **({"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {}))
            if result.returncode:
                raise ValueError(result.stderr.strip() or "Invalid desktop configuration")
            return json.loads(result.stdout)
        finally:
            temporary.unlink(missing_ok=True)

    def handle(sock):
        try:
            sock.settimeout(12)
            authenticate(sock, key, server=True)
            message = receive(sock, 2 * 1024 * 1024)
            action, payload = message.get("action"), message.get("payload", {})
            if not isinstance(payload, dict):
                raise ValueError("Invalid local request")
            # Liveness must remain observable while a platform configuration
            # operation is pending; otherwise clients may try a second start.
            if action == "host_status":
                result = {"running": core.process.poll() is None, "stopping": stopping.is_set(),
                    "pid": os.getpid(), "core_pid": core.process.pid, "exit_code": core.process.poll(), "error": error,
                    "config_path": str(config_path), "status_path": str(status_path)}
                send(sock, {"ok": True, "data": result})
                return
            if action == "host_stop":
                stopping.set()
                send(sock, {"ok": True, "data": {"message": "Stopping background host"}})
                return
            with guard:
                if stopping.is_set():
                    raise ValueError("Background host is stopping")
                if action == "remote_configure":
                    sock.settimeout(None)
                    document = dict(manager.document)
                    document["remote_desktop"] = payload["config"]
                    result = manager.apply(document)
                elif action == "apply_config":
                    sock.settimeout(None)
                    result = manager.apply(payload["config"])
                elif action == "get_config":
                    result = {"config": manager.document}
                else:
                    result = runtime.request(action, payload)
            send(sock, {"ok": True, "data": result})
        except Exception as problem:
            try:
                send(sock, {"ok": False, "error": str(problem)[:500]})
            except Exception:
                pass
        finally:
            sock.close()
            slots.release()
            with workers_lock:
                workers.discard(threading.current_thread())

    try:
        document = normalized(json.loads(config_path.read_text(encoding="utf-8")))
        core = CoreBridge(binary, config_path, status_path, state_dir / "remote-core.log")
        # Initialization and the first RPC can include privileged TUN creation.
        core.call("remote_info")
        runtime = Runtime(core, state_dir, document.get("remote_desktop", {}))
        manager = ConfigurationManager(core, runtime, config_path, document, normalized)
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(8)
        listener.settimeout(0.5)
        atomic_write(endpoint, canonical({"pid": os.getpid(), "port": listener.getsockname()[1], "token": key.hex()}))
        while not stopping.is_set() and core.process.poll() is None:
            try:
                sock, _ = listener.accept()
            except socket.timeout:
                continue
            if not slots.acquire(blocking=False):
                sock.close()
                continue
            thread = threading.Thread(target=handle, args=(sock,), daemon=True)
            with workers_lock:
                workers.add(thread)
            thread.start()
        code = core.process.poll()
    except Exception as problem:
        error = str(problem)
        code = 1
    finally:
        stopping.set()
        if listener:
            listener.close()
        # Finish an in-flight apply before releasing the core it owns. A stop
        # request is acknowledged immediately, but never races a half commit.
        with guard:
            if runtime:
                runtime.close()
            if core:
                core.close()
                code = code if code is not None else core.process.returncode
                if code and not error:
                    error = "Tunnel core exited with status " + str(code)
        endpoint.unlink(missing_ok=True)
        atomic_write(state_dir / "desktop-exit.json", canonical({"running": False, "pid": None,
            "exit_code": code or 0, "error": error, "config_path": str(config_path), "status_path": str(status_path)}))
        instance.close()
    return code or 0


if __name__ == "__main__":
    raise SystemExit(main())
