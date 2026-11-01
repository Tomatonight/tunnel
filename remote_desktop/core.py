"""Private stdio bridge to the sole tunnel protocol thread."""
from collections import deque
import json
import os
from pathlib import Path
import queue
import subprocess
import threading


class CoreBridge:
    def __init__(self, binary, config_path, status_path, log_path, extra_args=()):
        self.pending = {}
        self.lock = threading.RLock()
        self.write_lock = threading.Lock()
        self.serial = 0
        self.logs = deque(maxlen=500)
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.log_path.write_text("", encoding="utf-8")
        self.process = subprocess.Popen([str(binary), str(config_path), "--stdio-control",
            "--status-file", str(status_path), *extra_args], cwd=str(Path(binary).parent),
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace", bufsize=1,
            **({"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {}))
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()

    def _read(self):
        with self.log_path.open("a", encoding="utf-8") as log:
            for line in self.process.stdout:
                if line.startswith("TUNNEL_RPC "):
                    try:
                        reply = json.loads(line[len("TUNNEL_RPC "):])
                        with self.lock:
                            target = self.pending.get(reply.get("id"))
                        if target:
                            target.put_nowait(reply)
                    except (ValueError, queue.Full):
                        pass
                else:
                    self.logs.append(line.rstrip())
                    log.write(line)
                    log.flush()
            with self.lock:
                # Preserve the last core diagnostic for startup failures.  A
                # module load or device permission error is written to stderr
                # immediately before exit; surfacing it here keeps the GUI
                # from reducing the useful message to only "core exited".
                detail = "Tunnel core exited"
                for line in reversed(self.logs):
                    if line.strip():
                        detail += ": " + line.strip()
                        break
                for target in self.pending.values():
                    try:
                        target.put_nowait({"ok": False, "error": detail})
                    except queue.Full:
                        pass

    def call(self, method, **params):
        target = queue.Queue(maxsize=1)
        with self.lock:
            if self.process.poll() is not None:
                raise RuntimeError("Tunnel core is not running")
            if len(self.pending) >= 32:
                raise RuntimeError("Too many pending tunnel requests")
            self.serial += 1
            identifier = self.serial
            self.pending[identifier] = target
        try:
            # Never hold the pending-map lock during a potentially blocking
            # pipe write: the stdout reader must keep draining core responses.
            with self.write_lock:
                self.process.stdin.write(json.dumps(dict(params, id=identifier, method=method), separators=(",", ":")) + "\n")
                self.process.stdin.flush()
        except Exception:
            with self.lock:
                self.pending.pop(identifier, None)
            raise
        try:
            # A configuration commit cannot be abandoned on a client timer:
            # the protocol thread could still commit it after we report failure.
            # EOF/process exit wakes all pending requests through the reader.
            reply = target.get(timeout=None if method == "config_apply" else 5)
            if not reply.get("ok"):
                raise ValueError(reply.get("error", "Core RPC failed"))
            return reply["result"]
        except queue.Empty:
            raise TimeoutError("Tunnel core RPC timed out") from None
        finally:
            with self.lock:
                self.pending.pop(identifier, None)

    def close(self):
        with self.write_lock:
            if self.process.poll() is None:
                try:
                    self.process.stdin.write("STOP\n")
                    self.process.stdin.flush()
                except OSError:
                    pass
        try:
            self.process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            self.process.terminate()
            self.process.wait(timeout=5)
        self.reader.join(timeout=2)
        for stream in (self.process.stdin, self.process.stdout):
            try:
                stream.close()
            except OSError:
                pass
