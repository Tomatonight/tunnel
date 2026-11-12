"""Minimal in-process host for the basic tunnel-only GUI mode."""
import json
import os
from pathlib import Path
import tempfile
import time

from remote_desktop.core import CoreBridge


class SimpleCoreHost:
    """Own one native core directly; no daemon, IPC socket, or remote desktop."""

    def __init__(self, binary, state_dir):
        self.binary = Path(binary).resolve()
        self.state_dir = Path(state_dir).resolve()
        self.core = None
        self.config_path = None
        self.status_path = None
        self.last_error = ""

    def _status_document(self):
        if not self.status_path:
            return {}
        try:
            value = json.loads(self.status_path.read_text(encoding="utf-8"))
            return value if isinstance(value, dict) else {}
        except (OSError, ValueError):
            return {}

    def status(self):
        process = self.core.process if self.core else None
        running = process is not None and process.poll() is None
        document = self._status_document()
        if process is not None and process.poll() is not None and not self.last_error:
            self.last_error = "Tunnel core exited with status " + str(process.returncode)
        return {
            "running": running,
            "pid": process.pid if process else None,
            "core_pid": process.pid if process else None,
            "exit_code": process.poll() if process else None,
            "error": self.last_error,
            "config_path": str(self.config_path) if self.config_path else "",
            "status_path": str(self.status_path) if self.status_path else "",
            "status": document,
        }

    def is_running(self):
        return bool(self.status().get("running"))

    def start(self, config_path, status_path):
        if self.is_running():
            raise ValueError("已有连接正在运行，请先断开。")
        self.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.config_path = Path(config_path).resolve()
        self.status_path = Path(status_path).resolve()
        self.status_path.unlink(missing_ok=True)
        self.last_error = ""
        self.core = CoreBridge(self.binary, self.config_path, self.status_path,
                               self.state_dir.parent / "remote-core.log")
        try:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                if self._status_document().get("running") is True:
                    return self.status()
                if self.core.process.poll() is not None:
                    raise RuntimeError(self.last_error or "Tunnel core exited during startup")
                time.sleep(.05)
            raise TimeoutError("Tunnel core startup timed out")
        except Exception:
            self.stop()
            raise

    def _apply_config(self, document):
        self.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        descriptor, name = tempfile.mkstemp(prefix=".simple-reload-", suffix=".json", dir=self.state_dir)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as output:
                descriptor = None
                json.dump(document, output, ensure_ascii=False, indent=2)
                output.write("\n")
                output.flush()
            result = self.core.call("config_apply", path=str(Path(name).resolve()))
            if not result.get("ok"):
                raise ValueError(result.get("error", "配置应用失败"))
            return result
        finally:
            if descriptor is not None:
                os.close(descriptor)
            Path(name).unlink(missing_ok=True)

    def request(self, action, payload=None):
        payload = payload or {}
        if action == "host_status":
            return self.status()
        if action == "host_stop":
            self.stop()
            return {"message": "已停止"}
        if action == "apply_config":
            return self._apply_config(payload.get("config", {}))
        if action == "remote_state":
            return {"enabled": False, "config": {"enabled": False}, "pending": [],
                    "devices": [], "sessions": [], "listeners": [], "identity": {}}
        if action == "remote_disconnect":
            return {"message": "远程桌面未启用"}
        if action.startswith("remote_"):
            raise ValueError("基础模式未启用远程桌面")
        raise ValueError("基础模式不支持此后台操作")

    def stop(self):
        if self.core is not None:
            self.core.close()
        self.core = None
