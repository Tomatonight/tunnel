#!/usr/bin/env python3
"""Real remote desktop over two encrypted TUN nodes in isolated Linux netns.

Requires root, Xvfb, iproute2, the Python desktop dependencies and a native core.
The controlled display is a fresh Xvfb, never the user's active desktop. Desktop
daemons use their real persistent identity, local IPC, TLS and core membership.
"""
from __future__ import annotations

import argparse
import base64
import ctypes
import io
import json
import os
from pathlib import Path
import select
import shutil
import signal
import socket
import subprocess
import sys
import time
import traceback

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
NETWORK = "10.254.72.0/24"


def run(*command, check=True, timeout=20):
    result = subprocess.run(list(map(str, command)), text=True, capture_output=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError("command failed: " + " ".join(map(str, command)) + "\n" + result.stdout + result.stderr)
    return result


def wait(predicate, label, timeout=30):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        last = predicate()
        if last:
            return last
        time.sleep(.1)
    raise AssertionError("timeout: " + label + " (last=" + repr(last) + ")")


class IsolatedDisplay:
    def __init__(self):
        from remote_desktop.platforms import _X11Input
        self.native = None
        read_fd, write_fd = os.pipe()
        self.process = subprocess.Popen(["Xvfb", "-screen", "0", "800x600x24", "-nolisten", "tcp",
            "-nolisten", "unix", "-displayfd", str(write_fd)], pass_fds=(write_fd,),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        os.close(write_fd)
        try:
            if not select.select([read_fd], [], [], 10)[0]:
                raise RuntimeError("Xvfb startup timeout")
            display = os.read(read_fd, 80).decode("ascii").strip()
            if not display.isdigit():
                raise RuntimeError("Xvfb could not allocate a display")
            os.environ["DISPLAY"] = ":" + display
            os.environ.pop("WAYLAND_DISPLAY", None)
            os.environ["XDG_SESSION_TYPE"] = "x11"
            self.native = _X11Input()
            self.x = self.native.x
            self.x.XDefaultRootWindow.argtypes = [ctypes.c_void_p]
            self.x.XDefaultRootWindow.restype = ctypes.c_ulong
            self.x.XSetWindowBackground.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong]
            self.x.XSetWindowBackground.restype = ctypes.c_int
            self.x.XClearWindow.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
            self.x.XClearWindow.restype = ctypes.c_int
            self.x.XSync.argtypes = [ctypes.c_void_p, ctypes.c_int]
            self.x.XSync.restype = ctypes.c_int
            self.root = self.x.XDefaultRootWindow(self.native.display)
            self.x.XSetWindowBackground(self.native.display, self.root, 0x224466)
            self.x.XClearWindow(self.native.display, self.root)
            self.x.XSync(self.native.display, 0)
            self.x.XQueryPointer.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong), ctypes.POINTER(ctypes.c_ulong)] + [ctypes.POINTER(ctypes.c_int)] * 4 + [ctypes.POINTER(ctypes.c_uint)]
            self.x.XQueryPointer.restype = ctypes.c_int
            self.x.XQueryKeymap.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
            self.x.XQueryKeymap.restype = ctypes.c_int
        except Exception:
            self.close()
            raise
        finally:
            os.close(read_fd)

    def probe(self):
        root, child = ctypes.c_ulong(), ctypes.c_ulong()
        rx, ry, wx, wy, mask = ctypes.c_int(), ctypes.c_int(), ctypes.c_int(), ctypes.c_int(), ctypes.c_uint()
        assert self.x.XQueryPointer(self.native.display, self.root, ctypes.byref(root), ctypes.byref(child), ctypes.byref(rx), ctypes.byref(ry), ctypes.byref(wx), ctypes.byref(wy), ctypes.byref(mask))
        keys = (ctypes.c_uint8 * 32)()
        self.x.XQueryKeymap(self.native.display, keys)
        code = self.x.XKeysymToKeycode(self.native.display, self.x.XStringToKeysym(b"a"))
        return {"x": rx.value, "y": ry.value, "left": bool(mask.value & 256),
                "key_a": bool(keys[code // 8] & (1 << (code % 8)))}

    def close(self):
        if self.native:
            self.native.close()
            self.native = None
        self.process.terminate()
        try:
            self.process.wait(5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(5)


def worker(binary, config, state, role):
    from remote_desktop.host import BackgroundHost
    desktop = None
    host = BackgroundHost(binary, state)
    status = Path(state).parent / (role + ".status.json")
    def reply(value):
        print(json.dumps(value, separators=(",", ":")), flush=True)
    try:
        if role == "host":
            desktop = IsolatedDisplay()
        host.start(config, status)
        reply({"ok": True, "data": host.status()})
        for line in sys.stdin:
            try:
                message = json.loads(line)
                action, payload = message["action"], message.get("payload", {})
                if action == "probe":
                    result = desktop.probe()
                elif action == "restart":
                    host.stop()
                    result = host.start(config, status)
                elif action == "probe_public":
                    with socket.socket() as sock:
                        sock.settimeout(2)
                        result = {"errno": sock.connect_ex(("192.0.2.1", 47831))}
                elif action == "stop":
                    host.stop()
                    reply({"ok": True, "data": {"stopped": True}})
                    break
                else:
                    result = host.request(action, payload)
                reply({"ok": True, "data": result})
            except Exception as error:
                reply({"ok": False, "error": str(error)})
    except Exception as error:
        reply({"ok": False, "error": str(error)})
        traceback.print_exc(file=sys.stderr)
        return 1
    finally:
        try:
            host.stop()
        finally:
            if desktop:
                desktop.close()
    return 0


class Runner:
    def __init__(self, namespace, binary, config, state, role, work):
        self.log = (work / (role + "-worker.log")).open("w", encoding="utf-8")
        self.process = subprocess.Popen(["ip", "netns", "exec", namespace, sys.executable, str(Path(__file__).resolve()),
            "--worker", str(binary), str(config), str(state), role], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=self.log, text=True, bufsize=1, cwd=ROOT)
        self.receive(25)

    def receive(self, timeout=20):
        if not select.select([self.process.stdout], [], [], timeout)[0]:
            raise TimeoutError("worker response timed out")
        line = self.process.stdout.readline()
        if not line:
            raise RuntimeError("worker exited with " + str(self.process.poll()))
        result = json.loads(line)
        if not result.get("ok"):
            raise ValueError(result.get("error", "worker failed"))
        return result["data"]

    def call(self, action, **payload):
        self.process.stdin.write(json.dumps({"action": action, "payload": payload}) + "\n")
        self.process.stdin.flush()
        return self.receive(30 if action == "restart" else 20)

    def close(self):
        try:
            if self.process.poll() is None:
                self.call("stop")
            self.process.communicate(timeout=15)
        except Exception:
            self.process.terminate()
            try:
                self.process.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.communicate(timeout=5)
            raise
        finally:
            self.log.close()


def integration(binary, work):
    from PIL import Image
    if sys.platform != "linux" or os.geteuid() != 0:
        raise SystemExit("Run on Linux/WSL as root; only new test namespaces are modified")
    binary = binary.resolve(strict=True)
    work = work.resolve()
    work.mkdir(parents=True, exist_ok=True)
    prefix = "trd" + str(os.getpid())
    # Keep the running test independent of a developer rebuilding the main
    # executable, which otherwise causes ETXTBSY on a WSL-mounted workspace.
    snapshot = work / ("tunnel-" + prefix)
    shutil.copy2(binary, snapshot)
    binary = snapshot
    spaces = {role: prefix + suffix for role, suffix in (("host", "h"), ("client", "c"))}
    made, runners, passed, cleanup_errors = [], {}, [], []
    result = {"ok": False, "namespaces": spaces, "passed": passed}
    policy = {"enabled": True, "networks": [NETWORK], "access": "all_tunnel_nodes",
              "unattended": True, "port": 47831, "device_name": "isolated-host"}
    def mark(label):
        passed.append(label)
        print("PASS:", label, flush=True)
    def state(role):
        return runners[role].call("remote_state")
    def viewer():
        return state("client").get("viewer") or {}
    def connect(permission="control"):
        return runners["client"].call("remote_connect", address="10.254.72.1", tunnel=NETWORK, permission=permission)["session_id"]
    def connected():
        value = viewer()
        if value.get("status") == "error":
            raise AssertionError("viewer error: " + repr(value))
        return value if value.get("status") == "connected" else None
    def disconnect(session):
        runners["client"].call("remote_disconnect", session_id=session)
        wait(lambda: not state("host")["sessions"], "host session cleanup")
    def configure(access):
        policy["access"] = access
        runners["host"].call("remote_configure", config=dict(policy))
        wait(lambda: bool(state("host")["listeners"]), "desktop listener after policy change")
    def released():
        probe = runners["host"].call("probe")
        return not probe["left"] and not probe["key_a"]
    def hold(session):
        for event in ({"type": "mouse_move", "x": .25, "y": .75},
                      {"type": "mouse_button", "button": "left", "down": True},
                      {"type": "key", "key": "KeyA", "down": True}):
            runners["client"].call("remote_input", session_id=session, event=event)
        wait(lambda: runners["host"].call("probe") == {"x": 200, "y": 449, "left": True, "key_a": True}, "actual remote input")
    def wait_peer():
        def ready():
            for role in spaces:
                try:
                    status = json.loads((work / (role + ".status.json")).read_text())
                except (OSError, ValueError):
                    return False
                if not any(peer.get("state") == 3 for peer in status.get("peers", [])):
                    return False
            return True
        wait(ready, "encrypted tunnel peers", 40)
    try:
        existing = {line.split()[0] for line in run("ip", "netns", "list").stdout.splitlines()}
        assert not existing.intersection(spaces.values()), "namespace name collision"
        for name in spaces.values():
            run("ip", "netns", "add", name)
            made.append(name)
            run("ip", "-n", name, "link", "set", "lo", "up")
        left, right = prefix + "a", prefix + "b"
        run("ip", "-n", spaces["host"], "link", "add", left, "type", "veth", "peer", "name", right)
        run("ip", "-n", spaces["host"], "link", "set", right, "netns", spaces["client"])
        for role, device, last in (("host", left, 1), ("client", right, 2)):
            run("ip", "-n", spaces[role], "link", "set", device, "name", "eth0")
            run("ip", "-n", spaces[role], "address", "add", f"192.0.2.{last}/30", "dev", "eth0")
            run("ip", "-n", spaces[role], "link", "set", "eth0", "up")
            document = {"device_backend": "tun", "address": f"192.0.2.{last}:44000", "networks": [f"10.254.72.{last}/24"],
                "peers": [{"address": f"192.0.2.{3-last}:44000", "shared_key": "isolated-desktop-integration-psk"}],
                "remote_desktop": dict(policy) if role == "host" else {"enabled": False, "device_name": "isolated-client"}}
            config = work / (role + ".json")
            config.write_text(json.dumps(document, indent=2), encoding="utf-8")
            run(binary, config, "--check")
        for role in ("host", "client"):
            # Every run gets fresh identity state while preserving the current run
            # across the explicit daemon restart test below.
            state_dir = work / (role + "-state-" + prefix)
            runners[role] = Runner(spaces[role], binary, work / (role + ".json"), state_dir, role, work)
        wait_peer()
        wait(lambda: bool(state("host")["listeners"]), "virtual IP desktop listener")
        assert runners["client"].call("probe_public")["errno"] != 0
        mark("desktop listens on virtual IP only; two real encrypted TUN peers established")

        connect()
        first = wait(lambda: viewer() if viewer().get("status") == "trust_required" else None, "first-use host trust")
        identity = state("host")["identity"]
        assert first["identity"]["fingerprint"] == identity["fingerprint"]
        runners["client"].call("remote_trust", fingerprint=identity["fingerprint"])
        session = connect()
        wait(connected, "unattended all-member connection")
        assert not state("host")["devices"] and not state("host")["pending"]
        frame = wait(lambda: (lambda f: f if f.get("jpeg") else None)(runners["client"].call("remote_frame", session_id=session)), "actual JPEG frame")
        with Image.open(io.BytesIO(base64.b64decode(frame["jpeg"], validate=True))) as image:
            assert image.size == (800, 600)
            assert sum(abs(a - b) for a, b in zip(image.getpixel((600, 100)), (34, 68, 102))) < 8
        mark("TLS desktop handshake, persistent host trust, all-member unattended access and actual screenshot")
        hold(session)
        disconnect(session)
        wait(released, "disconnect releases remote input")
        mark("mouse and keyboard cross encrypted TUN/TLS; disconnect releases all held input")

        configure("authorized_devices")
        session = connect()
        pending = wait(lambda: state("host")["pending"], "first controller approval")[0]
        runners["host"].call("remote_authorize", request_id=pending["request_id"], permission="view", remember=True)
        assert wait(connected, "view-only authorization")["permission"] == "view"
        try:
            runners["client"].call("remote_input", session_id=session, event={"type": "key", "key": "KeyA", "down": True})
        except ValueError as error:
            assert "view-only" in str(error)
        else:
            raise AssertionError("view-only controller injected input")
        disconnect(session)
        session = connect()
        assert wait(connected, "remembered view-only reconnect")["permission"] == "view"
        assert not state("host")["pending"]
        controller = state("client")["identity"]["fingerprint"]
        runners["host"].call("remote_revoke", fingerprint=controller)
        wait(lambda: viewer().get("status") != "connected", "revocation closes viewer")
        wait(lambda: not state("host")["sessions"], "revocation closes host session")
        mark("attended device pairing, remembered view-only grant, input denial and immediate revocation")

        configure("all_tunnel_nodes")
        session = connect()
        wait(connected, "all-member reconnect")
        hold(session)
        configure("authorized_devices")
        wait(lambda: viewer().get("status") != "connected", "policy narrowing disconnects unlisted viewer")
        wait(released, "policy narrowing releases input")
        wait(lambda: not state("host")["sessions"], "policy change session cleanup")
        mark("all-member to device-list policy change revokes active control and releases held input")

        session = connect()
        pending = wait(lambda: state("host")["pending"], "control pairing")[0]
        runners["host"].call("remote_authorize", request_id=pending["request_id"], permission="control", remember=True)
        wait(connected, "control grant")
        disconnect(session)
        runners["host"].call("restart")
        wait_peer()
        assert state("host")["identity"]["fingerprint"] == identity["fingerprint"]
        wait(lambda: bool(state("host")["listeners"]), "listener after restart")
        session = connect()
        assert wait(connected, "unattended reconnect after host restart")["permission"] == "control"
        assert not state("host")["pending"]
        mark("daemon restart preserves device identity and controller grants for unattended reconnect")

        hold(session)
        run("ip", "-n", spaces["host"], "link", "set", "eth0", "down")
        wait(lambda: viewer().get("status") != "connected", "network loss terminates session", 30)
        wait(released, "network loss releases held input", 15)
        mark("physical transport loss ends remote desktop and releases held keys/buttons")
        result["ok"] = True
    except Exception as error:
        result["error"] = str(error)
        traceback.print_exc()
    finally:
        for role, runner in reversed(list(runners.items())):
            try:
                runner.close()
            except Exception as error:
                cleanup_errors.append(role + ": " + str(error))
        for name in reversed(made):
            pids = run("ip", "netns", "pids", name, check=False).stdout.split()
            for pid in pids:
                try:
                    os.kill(int(pid), signal.SIGTERM)
                except ProcessLookupError:
                    pass
            if pids:
                time.sleep(.5)
            for pid in run("ip", "netns", "pids", name, check=False).stdout.split():
                try:
                    os.kill(int(pid), signal.SIGKILL)
                except ProcessLookupError:
                    pass
            deleted = run("ip", "netns", "delete", name, check=False)
            if deleted.returncode:
                cleanup_errors.append(deleted.stderr)
        existing = {line.split()[0] for line in run("ip", "netns", "list").stdout.splitlines()}
        result["remaining_test_namespaces"] = sorted(existing.intersection(spaces.values()))
        result["cleanup_errors"] = cleanup_errors
        result["ok"] = result["ok"] and not cleanup_errors and not result["remaining_test_namespaces"]
        (work / "results.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(json.dumps(result, indent=2), flush=True)
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=Path("build-wsl/tunnel"))
    parser.add_argument("--work", type=Path, default=Path("build-wsl/remote-network-tests"))
    parser.add_argument("--worker", nargs=4, metavar=("BINARY", "CONFIG", "STATE", "ROLE"))
    args = parser.parse_args()
    raise SystemExit(worker(*args.worker) if args.worker else integration(args.binary, args.work))
