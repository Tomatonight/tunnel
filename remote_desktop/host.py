"""Authenticated local IPC and a GUI-independent desktop host process."""
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
    # A normal daemon shutdown can spend up to eight seconds closing remote
    # desktop workers and another thirteen seconds waiting for the native core
    # (including its final process-group escalation).  Keep the owner wait
    # longer than that budget so a healthy stop is not reported as a timeout.
    STOP_TIMEOUT = 35

    def __init__(self, binary, state_dir, *, gui_owned=False):
        self.binary = Path(binary).resolve()
        self.state_dir = Path(state_dir).resolve()
        self.endpoint = self.state_dir / "desktop-host.json"
        self.last_status = {"running": False, "pid": None, "exit_code": None, "error": ""}
        self.child = None
        # GUI-owned daemons keep a second authenticated connection open for
        # their lifetime.  The daemon treats EOF on this connection (or on
        # its owner stdin pipe) as an ownership release and shuts down.  CLI
        # hosts leave this disabled so their detached service survives the
        # command that started it.
        self.gui_owned = bool(gui_owned)
        self._owner_socket = None
        self._owner_pipe = None
        # Keep one authenticated loopback RPC connection for the lifetime of
        # the host. Opening and authenticating a new socket for every video
        # frame adds several round trips and becomes the dominant cost at
        # 60 FPS. Requests are serialized because the daemon processes one
        # message at a time on each connection.
        self._rpc_socket = None
        self._rpc_lock = threading.RLock()

    def _close_owner(self):
        sock, self._owner_socket = self._owner_socket, None
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass
        pipe, self._owner_pipe = self._owner_pipe, None
        if pipe is not None:
            try:
                pipe.close()
            except OSError:
                pass

    def attach_owner(self):
        """Claim daemon ownership for a GUI process.

        This is deliberately separate from the normal request channel: a
        status poll or a transient RPC error must never accidentally release
        a daemon that belongs to another GUI/CLI.  It is safe to call more
        than once on the same BackgroundHost instance.
        """
        if not self.gui_owned:
            return False
        with self._rpc_lock:
            if self._owner_socket is not None:
                return True
            data = json.loads(self.endpoint.read_text(encoding="utf-8"))
            sock = socket.create_connection(("127.0.0.1", data["port"]), timeout=3)
            try:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                authenticate(sock, bytes.fromhex(data["token"]))
                sock.settimeout(5)
                send(sock, {"action": "owner_attach", "payload": {}})
                reply = receive(sock)
                if not reply.get("ok"):
                    message = str(reply.get("error", "Desktop host owner attach failed"))
                    if "unknown" in message.lower() and "action" in message.lower():
                        raise ValueError("后台版本不支持 GUI 生命周期绑定，请关闭旧后台后重启")
                    raise ValueError(message)
                sock.settimeout(None)
                self._owner_socket = sock
                return True
            except Exception:
                try:
                    sock.close()
                except OSError:
                    pass
                raise

    def _close_rpc(self):
        sock, self._rpc_socket = self._rpc_socket, None
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass

    def _terminate_child(self, child=None):
        """Terminate only the process group created by this host instance."""
        child = child or self.child
        if child is None or child.poll() is not None:
            return
        try:
            if os.name == "nt":
                subprocess.run(["taskkill", "/PID", str(child.pid), "/T", "/F"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               check=False)
            else:
                os.killpg(child.pid, 15)
        except (OSError, ProcessLookupError):
            try:
                child.terminate()
            except OSError:
                return
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                if os.name == "nt":
                    subprocess.run(["taskkill", "/PID", str(child.pid), "/T", "/F"],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                   check=False)
                else:
                    os.killpg(child.pid, 9)
            except (OSError, ProcessLookupError):
                try:
                    child.kill()
                except OSError:
                    pass
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass

    def request(self, action, payload=None):
        # Status and viewer-state calls must never hold the WebView hostage
        # while a stale endpoint or half-dead daemon is being detected.  A
        # configuration commit is allowed longer; all lightweight requests
        # have a bounded short timeout and status probing is attempted once.
        timeout = 30 if action in ("apply_config", "remote_configure") else 2 if action == "host_status" else 5
        attempts = 1 if action == "host_status" else 2
        with self._rpc_lock:
            # Retry once after dropping a stale connection. This is needed
            # when a detached GUI reconnects just as the daemon is restarting.
            for attempt in range(attempts):
                reply = None
                try:
                    sock = self._rpc_socket
                    if sock is None:
                        data = json.loads(self.endpoint.read_text(encoding="utf-8"))
                        sock = socket.create_connection(("127.0.0.1", data["port"]), timeout=3)
                        try:
                            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                        except OSError:
                            pass
                        authenticate(sock, bytes.fromhex(data["token"]))
                        self._rpc_socket = sock
                    # A stalled core must not leave the WebView waiting
                    # forever after a click. Configuration commits are allowed
                    # longer than status/input requests, but remain bounded.
                    sock.settimeout(timeout)
                    send(sock, {"action": action, "payload": payload or {}})
                    reply = receive(sock)
                    if not reply.get("ok"):
                        # The daemon closes a channel after an application
                        # exception to keep protocol state unambiguous. Drop
                        # this socket before surfacing the error so the next
                        # request reconnects directly instead of hitting a
                        # stale descriptor once.
                        self._close_rpc()
                        raise ValueError(reply.get("error", "Desktop host request failed"))
                    if action == "host_stop":
                        self._close_rpc()
                    return reply["data"]
                except ValueError:
                    # Keep a valid daemon connection after a normal rejected
                    # request, but close malformed protocol responses.
                    if reply is None or not isinstance(reply, dict):
                        self._close_rpc()
                    raise
                except (OSError, EOFError, TimeoutError, socket.timeout):
                    self._close_rpc()
                    if attempt:
                        raise
            raise RuntimeError("Desktop host request failed")

    def status(self):
        try:
            self.last_status = self.request("host_status")
        except (OSError, TimeoutError, ValueError, EOFError, RuntimeError):
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
        self._close_rpc()
        self._close_owner()
        if self.is_running():
            raise ValueError("Tunnel background host is already running")
        self.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        (self.state_dir / "desktop-exit.json").unlink(missing_ok=True)
        status_path = Path(status_path).resolve()
        arguments = ["--binary", str(self.binary), "--state-dir", str(self.state_dir),
                     "--config", str(Path(config_path).resolve()), "--status-file", str(status_path)]
        if self.gui_owned:
            arguments.append("--owner-stdin")
        if getattr(sys, "frozen", False):
            command = [sys.executable, "--remote-daemon", *arguments]
        else:
            command = [sys.executable, "-m", "remote_desktop.daemon", *arguments]
        options = {"creationflags": subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt" else {"start_new_session": True}
        root = Path(sys.executable).parent if getattr(sys, "frozen", False) else Path(__file__).resolve().parent.parent
        with (self.state_dir / "desktop-host.log").open("ab") as output:
            child = subprocess.Popen(command, cwd=root,
                stdin=subprocess.PIPE if self.gui_owned else subprocess.DEVNULL,
                stdout=output, stderr=output, **options)
        self.child = child
        self._owner_pipe = child.stdin if self.gui_owned else None
        threading.Thread(target=child.wait, daemon=True).start()
        deadline = time.monotonic() + 15
        try:
            while time.monotonic() < deadline:
                state = self.status()
                if state.get("running"):
                    # The local daemon endpoint only proves that the host
                    # authenticated; the native core may still be starting.
                    # Do not report a successful start until its atomic status
                    # file confirms that Node::start() completed.
                    try:
                        document = json.loads(status_path.read_text(encoding="utf-8"))
                    except (OSError, ValueError):
                        document = None
                    if isinstance(document, dict) and document.get("running") is True:
                        if self.gui_owned:
                            self.attach_owner()
                        return state
                if child.poll() is not None:
                    raise ValueError(state.get("error") or "Tunnel background host failed; see desktop-host.log")
                time.sleep(0.1)
            raise TimeoutError("Tunnel core startup timed out; see background/desktop-host.log and background/remote-core.log")
        except Exception:
            self._close_owner()
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
                    self._terminate_child(child)
            raise

    def stop(self):
        running = self.is_running()
        owned_channel = self._owner_socket is not None or self._owner_pipe is not None
        # A daemon that died before publishing its endpoint may still leave a
        # child process around.  Only terminate the process we spawned; never
        # use the PID from a stale endpoint to kill an unrelated process.
        if not running:
            self._close_rpc()
            self._close_owner()
            if self.child and self.child.poll() is None:
                self._terminate_child(self.child)
            # If status polling raced daemon shutdown, owner EOF still needs a
            # short grace period to let the daemon flush state and unlink its
            # endpoint.  Only wait when this instance actually held an owner
            # lease; a detached CLI daemon must remain untouched.
            if owned_channel:
                if self.child and self.child.poll() is not None:
                    try:
                        data = json.loads(self.endpoint.read_text(encoding="utf-8"))
                        if data.get("pid") == self.child.pid:
                            self.endpoint.unlink(missing_ok=True)
                    except (OSError, ValueError):
                        pass
                deadline = time.monotonic() + 20
                while self.endpoint.exists() and time.monotonic() < deadline:
                    time.sleep(0.1)
            return
        self.request("host_stop")
        self._close_rpc()
        self._close_owner()
        deadline = time.monotonic() + self.STOP_TIMEOUT
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
        # The daemon is still owned by this GUI.  Do not leave its process
        # group running after a bounded shutdown failure; the native core has
        # a parent-death guard as a second line of defence.
        if self.child and self.child.poll() is None:
            self._terminate_child(self.child)
        raise TimeoutError("Tunnel background host did not stop")

    def close(self):
        """Release all local resources; GUI callers should use stop first."""
        try:
            if self.gui_owned and (self.is_running() or self.child is not None):
                self.stop()
            else:
                self._close_rpc()
                self._close_owner()
        except Exception:
            # close() is used from GUI finalizers, where there is no later
            # request that can retry a timed-out stop.  Kill only the process
            # group created by this host instance and then re-raise so the
            # caller can report the failure without leaking the core.
            if self.gui_owned and self.child and self.child.poll() is None:
                self._terminate_child(self.child)
            raise
        finally:
            self._close_rpc()
            self._close_owner()
