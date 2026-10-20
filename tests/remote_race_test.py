"""Deterministic authorization and shutdown races over real loopback TLS.

Only synthetic desktops receive input. Barriers hold a request at the specific
point where revocation/close used to race with an already decoded request.
"""
from pathlib import Path
import socket
import sys
import threading
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import remote_runtime_test as fixtures
import remote_desktop.runtime as runtime


class RaceTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.DesktopTests()
        self.fixture.setUp()

    def tearDown(self):
        self.fixture.tearDown()

    def _listed_mode(self, remember=False):
        case = self.fixture
        if remember:
            case.server.store.put("devices", dict(case.client.identity.info(), permission="control"))
        case.server.configure(dict(case.config, access="authorized_devices"))
        fixtures.wait_for(lambda: case.server.request("remote_state")["listeners"])

    def _buffered_input_revocation(self, action):
        case = self.fixture
        if action == "revoke":
            self._listed_mode(remember=True)
        self.assertEqual(case.connect()["status"], "connected")
        fixtures.wait_for(lambda: case.frame().get("jpeg"))
        original = runtime.receive
        reached, resume = threading.Event(), threading.Event()

        def receive(sock, *args, **kwargs):
            value = original(sock, *args, **kwargs)
            if sock.getsockname()[0] == case.server_core.ip and value.get("op") == "poll" and value.get("events"):
                reached.set()
                if not resume.wait(5):
                    raise AssertionError("buffered-input test barrier timed out")
            return value

        try:
            with patch.object(runtime, "receive", receive):
                case.client.request("remote_input", {"session_id": case.viewer()["session_id"],
                    "event": {"type": "key", "key": "KeyA", "down": True}})
                self.assertTrue(reached.wait(5), "server never received the input poll")
                if action == "mode":
                    case.server.configure(dict(case.config, access="authorized_devices"))
                elif action == "revoke":
                    case.server.request("remote_revoke", {"fingerprint": case.client.identity.fingerprint})
                else:
                    session = case.server.request("remote_state")["sessions"][0]
                    case.server.request("remote_terminate", {"session_id": session["session_id"]})
                resume.set()
                fixtures.wait_for(lambda: case.backends[0].closed)
                self.assertEqual(case.backends[0].events, [], "revoked input was injected after the revoke call returned")
                fixtures.wait_for(lambda: not case.server.request("remote_state")["sessions"])
        finally:
            resume.set()

    def test_policy_change_rejects_already_received_input(self):
        self._buffered_input_revocation("mode")

    def test_device_revoke_rejects_already_received_input(self):
        self._buffered_input_revocation("revoke")

    def test_terminate_rejects_already_received_input(self):
        self._buffered_input_revocation("terminate")

    def _stale_approval(self, action):
        case = self.fixture
        self._listed_mode()
        self.assertEqual(case.connect()["status"], "pending")
        pending = case.server.request("remote_state")["pending"][0]
        # The waiting worker cannot remove pending until this lock is released.
        # This models a stale UI approval arriving directly after revocation.
        with case.server.lock:
            if action == "revoke":
                case.server.request("remote_revoke", {"fingerprint": case.client.identity.fingerprint})
            elif action == "reject":
                case.server.request("remote_reject", {"request_id": pending["request_id"]})
            else:
                case.server.configure(dict(case.config, enabled=False))
            with self.assertRaisesRegex(ValueError, "expired"):
                case.server.request("remote_authorize", {"request_id": pending["request_id"],
                    "permission": "control", "remember": True})
            self.assertIsNone(case.server.store.get("devices", case.client.identity.fingerprint))
        fixtures.wait_for(lambda: not case.server.request("remote_state")["pending"])
        self.assertFalse(case.backends)

    def test_late_approval_cannot_restore_revoked_device(self):
        self._stale_approval("revoke")

    def test_late_approval_cannot_override_rejection(self):
        self._stale_approval("reject")

    def test_late_approval_cannot_survive_policy_change(self):
        self._stale_approval("mode")

    def test_duplicate_approval_cannot_raise_saved_permission(self):
        case = self.fixture
        self._listed_mode()
        self.assertEqual(case.connect()["status"], "pending")
        pending = case.server.request("remote_state")["pending"][0]
        with case.server.lock:
            case.server.request("remote_authorize", {"request_id": pending["request_id"], "permission": "view", "remember": True})
            with self.assertRaisesRegex(ValueError, "expired"):
                case.server.request("remote_authorize", {"request_id": pending["request_id"], "permission": "control", "remember": True})
            self.assertEqual(case.server.store.get("devices", case.client.identity.fingerprint)["permission"], "view")
        fixtures.wait_for(lambda: case.viewer()["status"] == "connected")
        self.assertEqual(case.viewer()["permission"], "view")

    def test_shutdown_closes_multiple_stalled_tls_handshakes(self):
        case = self.fixture
        clients = []
        try:
            for _ in range(8):
                clients.append(socket.create_connection((case.server_core.ip, case.port), timeout=2))
            fixtures.wait_for(lambda: len(case.server.workers) == len(clients))
            started = time.monotonic()
            case.server.close()
            elapsed = time.monotonic() - started
            self.assertLess(elapsed, 3, "shutdown waited for unauthenticated TLS timeouts")
            self.assertFalse(case.server.workers)
            self.assertFalse(case.server.connections)
            self.assertFalse(case.backends)
            for client in clients:
                try:
                    self.assertEqual(client.recv(1), b"")
                except (ConnectionError, OSError):
                    pass
        finally:
            for client in clients:
                client.close()

    def test_accept_thread_start_and_shutdown_are_serialized(self):
        case = self.fixture
        reached, resume = threading.Event(), threading.Event()
        original_start = threading.Thread.start
        errors = []
        connection = None
        closer = None

        def start(thread):
            if getattr(thread, "_target", None) == case.server._serve:
                reached.set()
                if not resume.wait(5):
                    raise AssertionError("thread-start test barrier timed out")
            return original_start(thread)

        def close():
            try:
                case.server.close()
            except Exception as error:
                errors.append(error)

        try:
            with patch.object(threading.Thread, "start", start):
                connection = socket.create_connection((case.server_core.ip, case.port), timeout=2)
                self.assertTrue(reached.wait(5))
                closer = threading.Thread(target=close)
                original_start(closer)
                time.sleep(.05)
                resume.set()
                closer.join(5)
                self.assertFalse(closer.is_alive())
                self.assertFalse(errors, repr(errors))
                self.assertFalse(case.server.workers)
                self.assertFalse(case.server.connections)
        finally:
            resume.set()
            if connection:
                connection.close()
            if closer:
                closer.join(5)

    def test_member_loss_releases_input_without_waiting_for_next_poll(self):
        case = self.fixture
        self.assertEqual(case.connect()["status"], "connected")
        case.client.request("remote_input", {"session_id": case.viewer()["session_id"],
            "event": {"type": "key", "key": "KeyA", "down": True}})
        fixtures.wait_for(lambda: case.backends[0].events)
        original = runtime.send
        reached, resume = threading.Event(), threading.Event()

        def send(sock, value):
            if sock.getsockname()[0] == case.client_core.ip and value.get("op") == "poll":
                reached.set()
                if not resume.wait(5):
                    raise AssertionError("silent-controller test barrier timed out")
            return original(sock, value)

        try:
            with patch.object(runtime, "send", send):
                self.assertTrue(reached.wait(3))
                case.client_core.active = False
                fixtures.wait_for(lambda: case.backends[0].closed, seconds=3)
                self.assertGreater(case.backends[0].releases, 0)
        finally:
            resume.set()

    def test_cancel_outbound_tls_handshake_closes_worker(self):
        case = self.fixture
        listener = socket.socket()
        accepted = None
        try:
            listener.bind((case.server_core.ip, 0))
            listener.listen(1)
            listener.settimeout(3)
            case.client.request("remote_connect", {"address": case.server_core.ip, "tunnel": fixtures.NETWORK,
                "port": listener.getsockname()[1]})
            accepted, _ = listener.accept()
            # This server intentionally sends no TLS response.
            case.client.request("remote_disconnect", {})
            fixtures.wait_for(lambda: not case.client.viewer["thread"].is_alive(), seconds=3)
            self.assertEqual(case.viewer()["status"], "disconnected")
            self.assertIsNone(case.client.viewer["socket"])
        finally:
            if accepted:
                accepted.close()
            listener.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
