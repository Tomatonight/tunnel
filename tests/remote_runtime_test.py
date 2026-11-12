"""Real TLS, PSK authentication and membership checks; synthetic desktop only.

No input is sent to the developer's actual desktop. Real TUN/X11 verification
lives in remote_network_integration.py.
"""
import base64
import io
import json
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from PIL import Image
from remote_desktop.runtime import FRAME_INTERVAL, Runtime
from remote_desktop.security import Identity, DeviceStore, canonical, receive, send, MAX_FRAME
from remote_desktop.host import authenticate

NETWORK = "127.44.0.0/24"
REMOTE_PSK = "desktop-remote-test-secret"


def wait_for(predicate, seconds=8):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.02)
    raise AssertionError("Timed out waiting for desktop state")


class Membership:
    def __init__(self, index, registry):
        self.ip = "127.44.0." + str(index)
        self.node = "192.0.2." + str(index) + ":65535"
        self.key = Ed25519PrivateKey.generate()
        self.active = True
        self.registry = registry
        registry[self.node] = self

    def call(self, method, **p):
        if method == "remote_info":
            return {"node": self.node, "networks": [{"network": NETWORK, "tunnel_ip": self.ip}] if self.active else []}
        if method == "remote_sign":
            if not self.active or p["network"] != NETWORK:
                raise ValueError("Not active")
            return {"node": self.node, "network": NETWORK, "source_ip": self.ip,
                    "signature": self.key.sign(bytes.fromhex(p["payload"])).hex()}
        if method == "remote_verify":
            peer = self.registry.get(p["node"])
            valid = self.active and peer and peer.active and p["network"] == NETWORK and p["source_ip"] == peer.ip
            try:
                if valid:
                    peer.key.public_key().verify(bytes.fromhex(p["signature"]), bytes.fromhex(p["payload"]))
            except Exception:
                valid = False
            return {"valid": bool(valid)}
        raise ValueError("Unknown method")


class Desktop:
    def __init__(self):
        self.events = []
        self.releases = 0
        self.closed = False
        self.fail_close = False

    def capture(self):
        output = io.BytesIO()
        Image.new("RGB", (64, 32), (21, 121, 221)).save(output, format="JPEG")
        return {"jpeg": output.getvalue(), "width": 64, "height": 32}

    def input(self, event):
        self.events.append(event)

    def release_all(self):
        self.releases += 1
        if self.fail_close:
            raise RuntimeError("injected release failure")

    def close(self):
        self.closed = True
        if self.fail_close:
            raise RuntimeError("injected close failure")

    def capabilities(self):
        return {"keyboard": True, "pointer": True}


class FrameRateTests(unittest.TestCase):
    """Keep the capture and bridge polling cadence at the requested 60 FPS."""

    def test_runtime_capture_interval_is_sixty_fps(self):
        self.assertAlmostEqual(FRAME_INTERVAL, 1.0 / 60.0, places=6)

    def test_frontend_does_not_poll_at_legacy_five_fps_interval(self):
        source = (Path(__file__).resolve().parents[1] / "gui" / "assets" / "app.js").read_text(encoding="utf-8")
        self.assertNotIn("document.hidden ? 500 : 200", source)
        self.assertIn("1000 / 60", source)
        self.assertIn("freshFrame ? 0", source)


class DesktopTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="tunnel-desktop-test-")
        self.root = Path(self.temp.name)
        self.registry = {}
        self.server_core, self.client_core = Membership(1, self.registry), Membership(2, self.registry)
        reservation = socket.socket()
        reservation.bind((self.server_core.ip, 0))
        self.port = reservation.getsockname()[1]
        reservation.close()
        self.backends = []
        def backend():
            value = Desktop()
            self.backends.append(value)
            return value
        self.config = {"enabled": True, "networks": [NETWORK], "shared_key": REMOTE_PSK, "port": self.port}
        self.server = Runtime(self.server_core, self.root / "server", self.config, backend)
        self.client = Runtime(self.client_core, self.root / "client", {})
        wait_for(lambda: self.server.request("remote_state")["listeners"])

    def tearDown(self):
        self.client.close()
        self.server.close()
        self.temp.cleanup()

    def connect(self, permission="control", shared_key=REMOTE_PSK, client=None):
        client = client or self.client
        client.request("remote_connect", {"address": self.server_core.ip, "tunnel": NETWORK,
                                           "port": self.port, "permission": permission,
                                           "shared_key": shared_key})
        result = wait_for(lambda: client.request("remote_state")["viewer"]
                          if client.request("remote_state")["viewer"]["status"] != "connecting" else None)
        return result

    def viewer(self):
        return self.client.request("remote_state")["viewer"]

    def frame(self):
        return self.client.request("remote_frame", {"session_id": self.viewer()["session_id"]})

    def test_psk_connects_without_approval_frame_input_and_disconnect_release(self):
        result = self.connect()
        self.assertEqual(result["status"], "connected")
        self.assertFalse(self.server.request("remote_state")["pending"])
        frame = wait_for(lambda: self.frame() if self.frame().get("jpeg") else None)
        self.assertEqual(Image.open(io.BytesIO(base64.b64decode(frame["jpeg"]))).size, (64, 32))
        self.client.request("remote_input", {"session_id": self.viewer()["session_id"], "events": [
            {"type": "key", "key": "KeyA", "down": True},
            {"type": "mouse_move", "x": 0.25, "y": 0.5},
        ]})
        wait_for(lambda: len(self.backends[0].events) >= 2)
        self.assertEqual(self.backends[0].events[:2], [
            {"type": "key", "key": "KeyA", "down": True},
            {"type": "mouse_move", "x": 0.25, "y": 0.5},
        ])
        self.client.request("remote_disconnect", {})
        wait_for(lambda: self.backends[0].closed)
        self.assertGreater(self.backends[0].releases, 0)

    def test_network_membership_revocation_closes_active_session(self):
        self.assertEqual(self.connect()["status"], "connected")
        self.client_core.active = False
        wait_for(lambda: self.viewer()["status"] == "error")
        wait_for(lambda: not self.server.request("remote_state")["sessions"])

    def test_wrong_or_missing_psk_is_rejected_without_pending_or_session(self):
        result = self.connect(shared_key="wrong-secret")
        self.assertEqual(result["status"], "error")
        self.assertIn("shared key", result["error"].lower())
        self.assertFalse(self.server.request("remote_state")["pending"])
        self.assertFalse(self.server.request("remote_state")["sessions"])
        self.client.request("remote_disconnect", {})
        with self.assertRaisesRegex(ValueError, "shared key"):
            self.connect(shared_key="")
        self.assertFalse(self.server.request("remote_state")["pending"])
        self.assertFalse(self.server.request("remote_state")["sessions"])

    def test_enabled_remote_desktop_requires_nonempty_psk(self):
        with self.assertRaisesRegex(ValueError, "shared_key"):
            self.server.configure({"enabled": True, "networks": [NETWORK], "port": self.port})
        with self.assertRaises(ValueError):
            self.server.configure(dict(self.config, access="all_tunnel_nodes"))
        with self.assertRaises(ValueError):
            self.server.configure(dict(self.config, approval_required=False))

    def test_persistent_identity_and_corrupt_database_fail_closed(self):
        again = Identity(self.root / "server")
        self.assertEqual(again.fingerprint, self.server.identity.fingerprint)
        self.server.store.put("devices", dict(self.client.identity.info(), permission="view"))
        store = DeviceStore(self.root / "server")
        self.assertEqual(store.get("devices", self.client.identity.fingerprint)["permission"], "view")
        store.path.write_text('{"devices":{},"devices":{},"hosts":{}}')
        with self.assertRaises(ValueError):
            DeviceStore(self.root / "server")

    def test_clearing_device_name_restores_hostname_identity(self):
        original = socket.gethostname()
        self.server.configure(dict(self.config, device_name="custom-desktop"))
        self.assertEqual(self.server.identity.info()["name"], "custom-desktop")
        self.server.configure(dict(self.config, device_name=""))
        self.assertEqual(self.server.identity.info()["name"], original)

    def test_cleanup_failure_does_not_keep_busy_session(self):
        self.assertEqual(self.connect()["status"], "connected")
        self.backends[0].fail_close = True
        self.client.request("remote_disconnect", {})
        wait_for(lambda: not self.server.request("remote_state")["sessions"])
        self.assertTrue(self.backends[0].closed)
        self.assertEqual(self.connect()["status"], "connected")

    def test_invalid_current_member_cannot_start_screen_capture(self):
        original = self.server_core.call
        self.server_core.call = lambda method, **args: {"valid": False} if method == "remote_verify" else original(method, **args)
        self.assertEqual(self.connect()["status"], "error")
        self.assertFalse(self.backends)

    def test_server_enforces_view_only_even_if_client_forges_local_permission(self):
        self.assertEqual(self.connect(permission="view")["status"], "connected")
        self.client.viewer["permission"] = "control"
        self.client.request("remote_input", {"session_id": self.viewer()["session_id"],
            "event": {"type": "key", "key": "KeyA", "down": True}})
        wait_for(lambda: self.viewer()["status"] == "error")
        self.assertFalse(self.backends[0].events)

    def test_process_membership_key_rotation_invalidates_old_session_proof(self):
        self.assertEqual(self.connect()["status"], "connected")
        self.server_core.key = Ed25519PrivateKey.generate()
        wait_for(lambda: self.viewer()["status"] == "error")
        wait_for(lambda: not self.server.request("remote_state")["sessions"])

    def test_busy_session_does_not_allow_second_controller_to_take_over(self):
        self.assertEqual(self.connect()["status"], "connected")
        other_core = Membership(3, self.registry)
        other = Runtime(other_core, self.root / "other", {})
        try:
            other.request("remote_connect", {"address": self.server_core.ip, "tunnel": NETWORK,
                                              "port": self.port, "shared_key": REMOTE_PSK})
            wait_for(lambda: other.request("remote_state")["viewer"]["status"] == "error")
            self.assertIn("busy", other.request("remote_state")["viewer"]["error"])
            self.assertEqual(self.viewer()["status"], "connected")
        finally:
            other.close()


class LocalProtocolTests(unittest.TestCase):
    def test_authenticated_ipc_and_wrong_secret(self):
        for correct in (True, False):
            a, b = socket.socketpair()
            errors = []
            def server():
                try:
                    authenticate(a, b"a" * 32, server=True)
                    send(a, receive(a))
                except Exception as error:
                    errors.append(type(error).__name__)
                finally:
                    a.close()
            thread = threading.Thread(target=server)
            thread.start()
            try:
                if correct:
                    authenticate(b, b"a" * 32)
                    send(b, {"message": "hello"})
                    self.assertEqual(receive(b), {"message": "hello"})
                else:
                    with self.assertRaises((PermissionError, EOFError)):
                        authenticate(b, b"b" * 32)
            finally:
                b.close()
                thread.join(2)
            self.assertEqual(bool(errors), not correct)

    def test_oversize_and_duplicate_frames_rejected(self):
        import struct
        a, b = socket.socketpair()
        try:
            a.sendall(struct.pack("!I", MAX_FRAME + 1))
            with self.assertRaises(ValueError):
                receive(b)
            content = b'{"op":1,"op":2}'
            a.sendall(struct.pack("!I", len(content)) + content)
            with self.assertRaises(ValueError):
                receive(b)
        finally:
            a.close()
            b.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
