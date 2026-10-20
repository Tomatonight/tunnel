"""Desktop UI host. The tunnel child owns the sole protocol thread and UDP socket."""
from collections import deque
from contextlib import contextmanager
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import threading
import time

MAX_CONFIG = 1024 * 1024
UNSPECIFIED_REVISION = object()

# Source runs start in gui/, while frozen builds collect this package normally.
if not getattr(sys, "frozen", False):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from remote_desktop.host import BackgroundHost


def config_directory():
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    elif platform.system() == "Darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return base / "Tunnel"


class Controller:
    def __init__(self, binary, directory=None, example=None):
        self.binary = Path(binary).resolve()
        self.directory = Path(directory or config_directory()).resolve()
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path = self.directory / "configure.json"
        self.example = Path(example) if example else None
        self._state_lock = threading.RLock()
        self._operation = threading.Lock()
        self._process = None
        self._run = None
        self._monitor = None
        self._phase = "stopped"
        self._error = ""
        self._status = {}
        self._logs = deque(maxlen=500)
        self._serial = 0
        self._secrets = []
        self._last_status = None
        self._closed = False
        self._requires_tun = True
        self._background = BackgroundHost(self.binary, self.directory)
        self._background_dir = self.directory / "background"
        self._background_dir.mkdir(exist_ok=True, mode=0o700)
        self._log_offset = 0
        self._log_partial = b""
        self._detach_on_close = False
        self._last_background_error = ""
        self._remote_log_seen = set()
        self._refresh_background()
        self._add_log("info", "界面已就绪，导入或编辑配置后连接。")

    def _redact(self, message):
        for secret in sorted(self._secrets, key=len, reverse=True):
            message = message.replace(secret, "[密钥已隐藏]")
            message = message.replace(json.dumps(secret, ensure_ascii=True)[1:-1], "[密钥已隐藏]")
            message = message.replace(json.dumps(secret, ensure_ascii=False)[1:-1], "[密钥已隐藏]")
        return message[:4000]

    def _add_log(self, level, message):
        with self._state_lock:
            self._serial += 1
            self._logs.append({"id": self._serial, "time": datetime.now().strftime("%H:%M:%S"),
                               "level": level, "message": self._redact(str(message))})

    def _text(self, payload):
        text = payload.get("text")
        if not isinstance(text, str) or len(text.encode("utf-8")) > MAX_CONFIG:
            raise ValueError("配置必须为不超过 1 MiB 的 UTF-8 文本。")
        try:
            document = json.loads(text)
        except (ValueError, RecursionError):
            raise ValueError("JSON 格式不正确，请检查括号、逗号和引号。") from None
        if not isinstance(document, dict):
            raise ValueError("配置的最外层必须是 JSON 对象。")
        secrets = []
        def collect(value):
            if isinstance(value, dict):
                for name, item in value.items():
                    if name == "shared_key" and isinstance(item, str) and item:
                        secrets.append(item)
                    else:
                        collect(item)
            elif isinstance(value, list):
                for item in value:
                    collect(item)
        collect(document)
        with self._state_lock:
            self._secrets = list(dict.fromkeys(self._secrets + secrets))[-4096:]
        return text

    def _runtime_configuration(self, text):
        # Lease ownership must survive replacement of the private run directory.
        # Resolve relative state paths against the persistent configuration folder,
        # leaving the user's saved configuration portable and unchanged.
        document = json.loads(text)
        service = document.get("address_server")
        if isinstance(service, dict):
            state = Path(service.get("state_file", "address-leases.json"))
            if not state.is_absolute():
                state = self.directory / state
            service["state_file"] = str(state.resolve())
        return self._text({"text": json.dumps(document, ensure_ascii=False, indent=2) + "\n"})

    def _stage_private(self, text):
        # Atomic replacement; POSIX mode 0600, Windows inherits the user's profile ACL.
        fd, temporary = tempfile.mkstemp(prefix=".config-", suffix=".json", dir=self.directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
                stream.write(text)
                stream.flush()
                os.fsync(stream.fileno())
            return Path(temporary)
        except Exception:
            Path(temporary).unlink(missing_ok=True)
            raise

    def _write_private(self, path, text):
        temporary = self._stage_private(text)
        try:
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)

    @contextmanager
    def _configuration_lock(self):
        # The GUI and CLI may attach to the same daemon from different processes.
        # Hold this lock through runtime apply, persistence and any rollback.
        descriptor = os.open(self.directory / ".configure.lock", os.O_CREAT | os.O_RDWR, 0o600)
        with os.fdopen(descriptor, "r+b", buffering=0) as lock:
            if os.fstat(lock.fileno()).st_size == 0:
                lock.write(b"\0")
            deadline = time.monotonic() + 60
            while True:
                try:
                    if os.name == "nt":
                        import msvcrt
                        lock.seek(0)
                        msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
                    else:
                        import fcntl
                        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise ValueError("其他配置操作仍在进行，请稍后重试。") from None
                    time.sleep(.05)
            try:
                yield
            finally:
                if os.name == "nt":
                    lock.seek(0)
                    msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    fcntl.flock(lock, fcntl.LOCK_UN)

    def _saved_revision(self):
        try:
            return hashlib.sha256(self.path.read_bytes()).hexdigest()
        except FileNotFoundError:
            return None

    def _save_config(self, text, expected_sha256=UNSPECIFIED_REVISION):
        text = self._normalize(text)
        if expected_sha256 is not UNSPECIFIED_REVISION and expected_sha256 is not None:
            if not isinstance(expected_sha256, str) or len(expected_sha256) != 64 or any(c not in "0123456789abcdef" for c in expected_sha256):
                raise ValueError("配置版本标识无效，请重新载入后重试。")
        with self._configuration_lock():
            if expected_sha256 is not UNSPECIFIED_REVISION and self._saved_revision() != expected_sha256:
                raise ValueError("配置已被其他窗口或命令行修改，未覆盖。请重新载入并合并修改后重试。")
            running = self._background.is_running()
            previous = None
            if running:
                info = self._background.status()
                snapshot = Path(info.get("config_path") or self._background_dir / "configure.json")
                if snapshot.stat().st_size > MAX_CONFIG:
                    raise ValueError("运行配置超过 1 MiB，未应用修改。")
                previous = json.loads(self._text({"text": snapshot.read_text(encoding="utf-8")}))
            temporary = self._stage_private(text)
            result = {}
            try:
                if running:
                    result = self._background.request("apply_config", {
                        "config": json.loads(self._runtime_configuration(text))})
                try:
                    os.replace(temporary, self.path)
                except OSError as error:
                    if running:
                        try:
                            self._background.request("apply_config", {"config": previous})
                        except Exception as rollback:
                            message = "保存配置失败，运行配置回滚也失败；请检查当前状态并重试：%s；回滚：%s" % (error, rollback)
                            self._add_log("error", message)
                            raise ValueError(message) from None
                        raise ValueError("保存配置失败；已恢复原运行配置：%s" % error) from None
                    raise
            finally:
                temporary.unlink(missing_ok=True)
            self._requires_tun = bool(json.loads(text).get("address"))
            self._refresh_background()
            message = "配置已保存并应用"
            if not running:
                message = "配置已保存；连接时生效"
            elif isinstance(result, dict) and result.get("message"):
                message += "；" + str(result["message"])
            data = {**(result if isinstance(result, dict) else {}), "message": message, "text": text,
                    "revision": hashlib.sha256(text.encode("utf-8")).hexdigest(), "saved": True, "applied": running}
            self._add_log("info", message)
            return data

    def _spawn_options(self):
        return {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {}

    def _check_core(self, text, option):
        if not self.binary.is_file():
            raise ValueError("找不到 tunnel 核心程序：" + str(self.binary))
        fd, name = tempfile.mkstemp(prefix=".validate-", suffix=".json", dir=self.directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as file:
                file.write(text)
            checked = subprocess.run([str(self.binary), name, option], cwd=self.binary.parent,
                                     capture_output=True, timeout=15, **self._spawn_options())
            output = checked.stdout.decode("utf-8", errors="replace").strip()
            if checked.returncode:
                error = checked.stderr.decode("utf-8", errors="replace").strip()
                raise ValueError(self._redact(error) or "配置校验失败。")
            return output
        finally:
            Path(name).unlink(missing_ok=True)

    def _validate(self, text):
        return {"message": "配置校验通过", "details": self._check_core(text, "--check")}

    def _normalize(self, text):
        normalized = self._check_core(text, "--normalize-config") + "\n"
        # The native parser owns all compatibility and authorization rules.
        self._text({"text": normalized})
        return normalized

    def _generate_key(self):
        generated = subprocess.run([str(self.binary), "--generate-key"], cwd=self.binary.parent,
                                   capture_output=True, timeout=15, **self._spawn_options())
        key = generated.stdout.decode("ascii", errors="replace").strip()
        if generated.returncode or len(key) != 64 or any(c not in "0123456789abcdef" for c in key):
            raise ValueError("无法生成预共享密钥，请检查核心程序。")
        return {"key": key}

    def _load_config(self):
        source = self.path if self.path.exists() else self.example
        if source and source.is_file():
            if source.stat().st_size > MAX_CONFIG:
                raise ValueError("配置文件超过 1 MiB。")
            raw = source.read_bytes()
            text = raw.decode("utf-8-sig")
            revision = hashlib.sha256(raw).hexdigest() if source == self.path else None
            try:
                return {"text": self._normalize(self._text({"text": text})), "revision": revision}
            except (ValueError, OSError, subprocess.SubprocessError) as error:
                # Let the user repair invalid JSON; loading never overwrites their file.
                return {"text": text, "error": self._redact(str(error)), "revision": revision}
        return {"text": "", "revision": None}

    def _read_background_logs(self):
        path = self.directory / "remote-core.log"
        try:
            if path.stat().st_size < self._log_offset:
                self._log_offset = 0
                self._log_partial = b""
            with path.open("rb") as stream:
                stream.seek(self._log_offset)
                data = stream.read(64 * 1024)
                self._log_offset = stream.tell()
            lines = (self._log_partial + data).split(b"\n")
            self._log_partial = lines.pop()[-4096:]
            for line in lines:
                message = line.decode("utf-8", errors="replace").strip()
                if message:
                    self._add_log("error" if message.startswith("error:") else "info", message)
        except OSError:
            pass

    def _refresh_background(self):
        info = self._background.status()
        with self._state_lock:
            self._read_background_logs()
            if not info.get("running"):
                self._process = None
                self._status = {}
                self._last_status = None
                error = info.get("error") or ("核心程序退出（代码 %s）。" % info["exit_code"] if info.get("exit_code") else "")
                self._phase = "error" if error else "stopped"
                self._error = str(error)
                if error and error != self._last_background_error:
                    self._add_log("error", error)
                self._last_background_error = error
                return
            self._process = self._background
            path = Path(info.get("status_path") or self._background_dir / "status.json")
            try:
                stat = path.stat()
                if stat.st_size <= 8 * MAX_CONFIG:
                    status = json.loads(path.read_text(encoding="utf-8"))
                    if isinstance(status, dict):
                        self._status = status
                        # mtime measures core activity even after reconnecting the UI.
                        self._last_status = time.monotonic() - max(0, time.time() - stat.st_mtime)
                        self._phase = "running" if status.get("running") else "starting"
            except (OSError, ValueError):
                self._phase = "starting"
            self._error = str(info.get("error") or "")
            snapshot = Path(info.get("config_path") or self._background_dir / "configure.json")
            try:
                if snapshot.stat().st_size <= MAX_CONFIG:
                    document = json.loads(self._text({"text": snapshot.read_text(encoding="utf-8")}))
                    remote = document.get("remote_desktop", {})
                    self._detach_on_close = remote.get("enabled") is True and remote.get("unattended") is True
            except (OSError, ValueError):
                pass

    def _start(self, text):
        with self._configuration_lock():
            return self._start_locked(text)

    def _start_locked(self, text):
        if self._background.is_running():
            raise ValueError("已有连接正在运行或停止，请先断开。")
        text = self._normalize(text)
        self._write_private(self.path, text)
        snapshot = self._background_dir / "configure.json"
        status_path = self._background_dir / "status.json"
        self._write_private(snapshot, self._runtime_configuration(text))
        status_path.unlink(missing_ok=True)
        self._log_offset = 0
        self._log_partial = b""
        self._background.start(snapshot, status_path)
        self._requires_tun = bool(json.loads(text).get("address"))
        self._refresh_background()
        self._add_log("info", "正在建立隧道；保活 5 秒，通道失效阈值 20 秒。" if self._requires_tun else "正在启动地址分配服务；绑定记录保存在配置目录中。")
        return {"message": "已请求连接", "revision": self._saved_revision()}

    def _stop(self):
        with self._configuration_lock():
            return self._stop_locked()

    def _stop_locked(self):
        self._phase = "stopping"
        try:
            self._background.stop()
        except Exception as error:
            self._error = "后台服务尚未完成停止，请重试断开：" + str(error)
            raise ValueError(self._error) from None
        self._refresh_background()
        self._phase = "stopped"
        self._error = ""
        self._detach_on_close = False
        return {"message": "已断开"}

    def state(self):
        self._refresh_background()
        remote = {}
        if self._process is not None:
            try:
                remote = self._background.request("remote_state", {})
            except Exception as error:
                remote = {"error": str(error)}
        with self._state_lock:
            events = remote.get("logs", []) if isinstance(remote, dict) else []
            current = set()
            for event in events[-200:] if isinstance(events, list) else []:
                if not isinstance(event, dict):
                    continue
                key = (str(event.get("time", "")), str(event.get("message", "")))
                current.add(key)
                if key not in self._remote_log_seen:
                    self._add_log("info", "远程桌面：" + key[1])
            self._remote_log_seen = current
            return {"phase": self._phase, "error": self._error, "status": self._status,
                    "logs": list(self._logs), "config_path": str(self.path), "platform": platform.system(),
                    "remote_desktop": remote,
                    "status_stale": self._last_status is not None and time.monotonic() - self._last_status > 3}

    def request(self, message):
        try:
            if not isinstance(message, str) or len(message.encode("utf-8")) > 2 * MAX_CONFIG:
                raise ValueError("请求过大。")
            request = json.loads(message)
            if not isinstance(request, dict) or not isinstance(request.get("payload", {}), dict):
                raise ValueError("无效请求。")
            action, payload = request.get("action"), request.get("payload", {})
            if action == "get_state":
                data = self.state()
            elif action in ("remote_state", "remote_frame", "remote_input"):
                if self._closed:
                    raise ValueError("窗口已关闭，请重新打开应用。")
                data = self._background.request(action, payload)
            elif action == "clear_logs":
                with self._state_lock:
                    self._logs.clear()
                data = {"message": "日志已清空"}
            else:
                # JS bridge methods may arrive on several UI threads; lifecycle is serialized.
                with self._operation:
                    if self._closed and action not in ("load_config", "stop"):
                        raise ValueError("窗口已关闭，请重新打开应用。")
                    if action == "load_config":
                        data = self._load_config()
                    elif action == "generate_key":
                        data = self._generate_key()
                    elif action in ("validate_config", "normalize_config", "save_config", "apply_config", "start"):
                        text = self._text(payload)
                        if action == "start":
                            data = self._start(text)
                        elif action == "normalize_config":
                            data = {"text": self._normalize(text)}
                        elif action in ("save_config", "apply_config"):
                            data = self._save_config(text, payload.get("expected_sha256", UNSPECIFIED_REVISION))
                        else:
                            data = self._validate(text)
                    elif action == "stop":
                        data = self._stop()
                    elif action in ("remote_connect", "remote_disconnect", "remote_trust", "remote_authorize", "remote_reject", "remote_revoke", "remote_terminate"):
                        data = self._background.request(action, payload)
                    else:
                        raise ValueError("不支持的操作。")
            return json.dumps({"ok": True, "data": data}, ensure_ascii=False)
        except Exception as error:
            return json.dumps({"ok": False, "error": self._redact(str(error))}, ensure_ascii=False)

    def close(self):
        with self._operation:
            self._closed = True
            try:
                self._refresh_background()
                if self._detach_on_close and self._background.is_running():
                    self._background.request("remote_disconnect", {})
                    return True
                self._stop()
                return True
            except ValueError:
                self._closed = False
                return False
