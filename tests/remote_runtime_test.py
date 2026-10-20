"""Real TLS, persistent identities and access policy; synthetic desktop only.

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
from remote_desktop.runtime import Runtime
from remote_desktop.security import Identity, DeviceStore, canonical, receive, send, MAX_FRAME
from remote_desktop.host import authenticate

NETWORK = "127.44.0.0/24"


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
        self.config = {"enabled": True, "networks": [NETWORK], "access": "all_tunnel_nodes", "unattended": True, "port": self.port}
        self.server = Runtime(self.server_core, self.root / "server", self.config, backend)
        self.client = Runtime(self.client_core, self.root / "client", {})
        wait_for(lambda: self.server.request("remote_state")["listeners"])

    def tearDown(self):
        self.client.close()
        self.server.close()
        self.temp.cleanup()

    def connect(self, trusted=True, permission="control"):
        if trusted:
            self.client.store.put("hosts", self.server.identity.info())
        self.client.request("remote_connect", {"address": self.server_core.ip, "tunnel": NETWORK,
                                              "port": self.port, "permission": permission})
        return wait_for(lambda: self.viewer() if self.viewer()["status"] != "connecting" else None)

    def viewer(self):
        return self.client.request("remote_state")["viewer"]

    def frame(self):
        return self.client.request("remote_frame", {"session_id": self.viewer()["session_id"]})

    def test_tls_pin_all_nodes_frame_input_and_disconnect_release(self):
        result = self.connect(trusted=False)
        self.assertEqual(result["status"], "trust_required")
        self.assertFalse(self.backends)
        self.client.request("remote_trust", {"fingerprint": result["identity"]["fingerprint"]})
        self.assertEqual(self.connect()["status"], "connected")
        frame = wait_for(lambda: self.frame() if self.frame().get("jpeg") else None)
        self.assertEqual(Image.open(io.BytesIO(base64.b64decode(frame["jpeg"]))).size, (64, 32))
        self.client.request("remote_input", {"session_id": self.viewer()["session_id"], "event": {"type": "key", "key": "KeyA", "down": True}})
        wait_for(lambda: self.backends[0].events)
        self.client.request("remote_disconnect", {})
        wait_for(lambda: self.backends[0].closed)
        self.assertGreater(self.backends[0].releases, 0)

    def test_authorized_mode_approval_view_only_and_revoke(self):
        self.server.configure(dict(self.config, access="authorized_devices"))
        wait_for(lambda: self.server.request("remote_state")["listeners"])
        self.assertEqual(self.connect()["status"], "pending")
        pending = self.server.request("remote_state")["pending"][0]
        self.server.request("remote_authorize", {"request_id": pending["request_id"], "permission": "view", "remember": True})
        wait_for(lambda: self.viewer()["status"] == "connected")
        self.assertEqual(self.viewer()["permission"], "view")
        with self.assertRaises(ValueError):
            self.client.request("remote_input", {"session_id": self.viewer()["session_id"], "event": {"type": "key", "key": "KeyA", "down": True}})
        self.server.request("remote_revoke", {"fingerprint": self.client.identity.fingerprint})
        wait_for(lambda: self.viewer()["status"] == "error")
        self.assertFalse(self.server.store.list("devices"))

    def test_mode_switch_disconnects_unlisted_controller(self):
        self.assertEqual(self.connect()["status"], "connected")
        self.server.configure(dict(self.config, access="authorized_devices"))
        wait_for(lambda: self.viewer()["status"] == "error")
        wait_for(lambda: not self.server.request("remote_state")["sessions"])

    def test_network_membership_revocation_closes_active_session(self):
        self.assertEqual(self.connect()["status"], "connected")
        self.client_core.active = False
        wait_for(lambda: self.viewer()["status"] == "error")
        wait_for(lambda: not self.server.request("remote_state")["sessions"])

    def test_unattended_false_requires_confirmation_even_for_saved_device(self):
        self.server.store.put("devices", dict(self.client.identity.info(), permission="control"))
        self.server.configure(dict(self.config, unattended=False, access="authorized_devices"))
        wait_for(lambda: self.server.request("remote_state")["listeners"])
        self.assertEqual(self.connect()["status"], "pending")
        pending = self.server.request("remote_state")["pending"][0]
        self.server.request("remote_terminate", {"session_id": pending["request_id"]})
        wait_for(lambda: self.viewer()["status"] == "error")

    def test_persistent_identity_and_corrupt_database_fail_closed(self):
        again = Identity(self.root / "server")
        self.assertEqual(again.fingerprint, self.server.identity.fingerprint)
        self.server.store.put("devices", dict(self.client.identity.info(), permission="view"))
        store = DeviceStore(self.root / "server")
        self.assertEqual(store.get("devices", self.client.identity.fingerprint)["permission"], "view")
        store.path.write_text('{"devices":{},"devices":{},"hosts":{}}')
        with self.assertRaises(ValueError):
            DeviceStore(self.root / "server")

    def test_cleanup_failure_does_not_keep_busy_session(self):
        self.assertEqual(self.connect()["status"], "connected")
        self.backends[0].fail_close = True
        self.client.request("remote_disconnect", {})
        wait_for(lambda: not self.server.request("remote_state")["sessions"])
        self.assertTrue(self.backends[0].closed)
        self.assertEqual(self.connect()["status"], "connected")

    def test_revoke_pending_approved_device_invalidates_grant(self):
        self.server.configure(dict(self.config, access="authorized_devices"))
        wait_for(lambda: self.server.request("remote_state")["listeners"])
        self.assertEqual(self.connect()["status"], "pending")
        self.server.request("remote_revoke", {"fingerprint": self.client.identity.fingerprint})
        wait_for(lambda: self.viewer()["status"] == "error")
        self.assertFalse(self.backends)

    def test_invalid_current_member_cannot_start_screen_capture(self):
        original = self.server_core.call
        self.server_core.call = lambda method, **args: {"valid": False} if method == "remote_verify" else original(method, **args)
        self.assertEqual(self.connect()["status"], "error")
        self.assertFalse(self.backends)

    def test_all_nodes_ignores_device_list_deletion_by_design(self):
        self.assertEqual(self.connect()["status"], "connected")
        self.server.request("remote_revoke", {"fingerprint": self.client.identity.fingerprint})
        time.sleep(.25)
        self.assertEqual(self.viewer()["status"], "connected")

    def test_policy_change_between_grant_and_session_registration(self):
        original = self.server._approval
        def racing_approval(*args):
            grant = original(*args)
            self.server.configure(dict(self.config, access="authorized_devices"))
            return grant
        self.server._approval = racing_approval
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
            other.store.put("hosts", self.server.identity.info())
            other.request("remote_connect", {"address": self.server_core.ip, "tunnel": NETWORK, "port": self.port})
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
