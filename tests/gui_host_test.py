"""Desktop host contracts; --live also starts a real TUN and requires admin/root."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "gui"))
from controller import Controller
from main import Bridge, bundled_html

parser = argparse.ArgumentParser()
parser.add_argument("--binary", type=Path, default=ROOT / "build" / ("tunnel.exe" if os.name == "nt" else "tunnel"))
parser.add_argument("--live", action="store_true")
args, remaining = parser.parse_known_args()


def configuration():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    return json.dumps({"device_backend": "tun", "address": "127.0.0.1:%s" % port, "networks": ["198.18.253.1/30"],
                       "listen": {"bind_address": "127.0.0.1:%s" % port}, "peers": []})


class HostTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="tunnel-gui-test-")
        self.host = Controller(args.binary, self.temp.name, ROOT / "config" / "default.json")
        self.config = configuration()

    def tearDown(self):
        self.assertTrue(self.host.close())
        self.temp.cleanup()

    def call(self, action, **payload):
        return json.loads(self.host.request(json.dumps({"action": action, "payload": payload})))

    def test_validated_atomic_configuration(self):
        self.assertTrue(self.call("load_config")["ok"])
        self.assertTrue(self.call("save_config", text=self.config)["ok"])
        original = self.host.path.read_bytes()
        invalid = json.loads(self.config)
        invalid["tun_mtu"] = 20
        self.assertFalse(self.call("save_config", text=json.dumps(invalid))["ok"])
        self.assertEqual(self.host.path.read_bytes(), original)
        self.assertFalse(self.call("save_config", text='{"bad"')["ok"])
        self.assertFalse(self.call("validate_config", text="x" * (1024 * 1024 + 1))["ok"])
        self.assertEqual(list(self.host.directory.glob(".validate-*")), [])
        if os.name != "nt":
            self.assertEqual(self.host.path.stat().st_mode & 0o777, 0o600)

    def test_bounded_redacted_logs_and_errors(self):
        document = json.loads(self.config)
        secret = 'test-secret-"quoted"-0123456789'
        document["peers"] = [{"shared_key": secret}]
        self.host._text({"text": json.dumps(document)})
        for i in range(600):
            self.host._add_log("info", "%s %s" % (i, secret))
        logs = self.call("get_state")["data"]["logs"]
        self.assertEqual(len(logs), 500)
        self.assertNotIn(secret, " ".join(log["message"] for log in logs))
        self.assertEqual(len(set(log["id"] for log in logs)), 500)
        self.assertTrue(self.call("clear_logs")["ok"])
        self.assertEqual(self.call("get_state")["data"]["logs"], [])
        self.assertFalse(json.loads(self.host.request("[]"))["ok"])
        self.assertFalse(self.call("execute_shell", text="invalid")["ok"])

    def test_address_service_secrets_are_recursively_redacted(self):
        secrets = ['service-secret-"quoted"-中文', 'service-secret-"quoted"-中文-longer', "managed-client-private-key", "shared-server-private-key"]
        document = {"address_server": {"shared_key": secrets[3], "clients": [{"shared_key": value} for value in secrets[:2]]},
                    "address_clients": [{"shared_key": secrets[2]}]}
        self.host._text({"text": json.dumps(document, ensure_ascii=False)})
        for secret in secrets:
            self.host._add_log("error", "plain=" + secret + " encoded=" + json.dumps(secret, ensure_ascii=True) + " unicode=" + json.dumps(secret, ensure_ascii=False))
        output = json.dumps(self.host.state(), ensure_ascii=False)
        for secret in secrets:
            self.assertNotIn(secret, output)
            self.assertNotIn(json.dumps(secret, ensure_ascii=True)[1:-1], output)
        self.assertNotIn("-longer", output)

    def test_shared_address_service_modes_are_preserved_and_exclusive(self):
        endpoint = json.loads(self.config)["address"]
        service = {"address": endpoint, "shared_key": "one-private-service-key", "networks": ["198.18.252.0/29"]}
        source = json.dumps({"address_server": service})
        self.assertTrue(self.call("save_config", text=source)["ok"])
        saved = self.host.path.read_bytes()
        document = json.loads(self.call("load_config")["data"]["text"])
        self.assertEqual(document["address_server"]["shared_key"], service["shared_key"])
        self.assertNotIn("clients", document["address_server"])
        mixed = {"address_server": {**service, "clients": []}}
        self.assertFalse(self.call("save_config", text=json.dumps(mixed))["ok"])
        self.assertEqual(self.host.path.read_bytes(), saved)
        legacy = {"address_server": {"address": endpoint, "networks": ["198.18.252.0/29"], "clients": [{
            "address": "127.0.0.2:49011", "shared_key": "legacy-client-key", "networks": ["198.18.252.0/29"]}]}}
        normalized = self.call("normalize_config", text=json.dumps(legacy))
        self.assertTrue(normalized["ok"], normalized)
        preserved = json.loads(normalized["data"]["text"])["address_server"]
        self.assertNotIn("shared_key", preserved)
        self.assertEqual(preserved["clients"], legacy["address_server"]["clients"])

    def test_advertised_subnets_preserve_snat_and_reject_invalid_routes(self):
        document = json.loads(self.config)
        document["advertise_routes"] = [{"tunnel": "198.18.253.0/30", "prefix": "203.0.113.0/24", "snat": True}]
        saved = self.call("save_config", text=json.dumps(document))
        self.assertTrue(saved["ok"], saved)
        expected = document["advertise_routes"]
        self.assertEqual(json.loads(self.call("load_config")["data"]["text"])["advertise_routes"], expected)
        original = self.host.path.read_bytes()
        for change in ({"prefix": "198.18.253.0/30"}, {"prefix": "203.0.113.1/24"},
                       {"tunnel": "10.99.0.0/24"}, {"snat": "true"}, {"prefix": "fd00:90::/64"}):
            invalid = {**document, "advertise_routes": [{**expected[0], **change}]}
            self.assertFalse(self.call("save_config", text=json.dumps(invalid))["ok"], change)
            self.assertEqual(self.host.path.read_bytes(), original)
        overlap = {**document, "networks": ["198.18.253.1/30", "198.18.254.1/30"], "advertise_routes": [
            expected[0], {"tunnel": "198.18.254.0/30", "prefix": "203.0.113.0/25"}]}
        self.assertFalse(self.call("normalize_config", text=json.dumps(overlap))["ok"])
        managed = {"address": document["address"], "address_clients": [{"address": "127.0.0.2:49013", "shared_key": "managed-route-key", "networks": ["10.90.0.0/24"]}],
                   "advertise_routes": [{"tunnel": "10.90.0.0/24", "prefix": "203.0.113.0/24"}]}
        normalized = self.call("normalize_config", text=json.dumps(managed))
        self.assertTrue(normalized["ok"], normalized)
        route = json.loads(normalized["data"]["text"])["advertise_routes"][0]
        self.assertEqual(route["tunnel"], "10.90.0.0/24")
        self.assertFalse(route.get("snat", False))

    def test_address_service_runtime_state_path_is_persistent(self):
        source = {"address_server": {"address": "127.0.0.1:49011", "networks": ["10.90.0.0/24"], "clients": []}}
        original = json.dumps(source)
        runtime = json.loads(self.host._runtime_configuration(original))
        self.assertEqual(Path(runtime["address_server"]["state_file"]), self.host.directory / "address-leases.json")
        self.assertNotIn("state_file", source["address_server"])
        source["address_server"]["state_file"] = "bindings.json"
        runtime = json.loads(self.host._runtime_configuration(json.dumps(source)))
        self.assertEqual(Path(runtime["address_server"]["state_file"]), self.host.directory / "bindings.json")
        source["address_server"]["state_file"] = str(self.host.directory / "explicit.json")
        runtime = json.loads(self.host._runtime_configuration(json.dumps(source)))
        self.assertEqual(runtime["address_server"]["state_file"], source["address_server"]["state_file"])

    def test_address_service_only_start_restart_without_tun(self):
        endpoint = json.loads(self.config)["address"]
        document = {"address_server": {"address": endpoint, "bind_address": endpoint,
            "networks": ["198.18.252.0/29"], "clients": [{"address": "127.0.0.2:49011",
            "shared_key": "test-address-client-private-key", "networks": ["198.18.252.0/29"]}]}}
        source = json.dumps(document)
        normalized = self.call("normalize_config", text=source)
        self.assertTrue(normalized["ok"], normalized)
        normalized_document = json.loads(normalized["data"]["text"])
        self.assertEqual(set(normalized_document) - {"address_server", "device_backend"}, set())
        expected_backend = "kernel" if sys.platform.startswith("linux") else "tun"
        self.assertEqual(normalized_document.get("device_backend"), expected_backend)
        for _ in range(2):
            result = self.call("start", text=source)
            self.assertTrue(result["ok"], result)
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                state = self.host.state()
                if state["phase"] == "running" and state["status"].get("address_service", {}).get("server", {}).get("running"):
                    break
                self.assertNotEqual(state["phase"], "error", json.dumps(state))
                time.sleep(.1)
            else:
                self.fail("address server startup timeout: " + json.dumps(self.host.state()))
            self.assertEqual(state["status"].get("device"), "")
            self.assertEqual(state["status"].get("peers"), [])
            snapshots = list(self.host.directory.glob("background/configure.json"))
            self.assertEqual(len(snapshots), 1)
            runtime = json.loads(snapshots[0].read_text(encoding="utf-8"))
            self.assertEqual(Path(runtime["address_server"]["state_file"]), self.host.directory / "address-leases.json")
            self.assertTrue((self.host.directory / "address-leases.json").is_file())
            self.assertNotIn("state_file", json.loads(self.host.path.read_text(encoding="utf-8"))["address_server"])
            self.assertTrue(self.call("stop")["ok"])
            self.assertEqual(self.host.state()["phase"], "stopped")
            self.assertEqual(list(self.host.directory.glob("run-*")), [])
            self.assertTrue((self.host.directory / "address-leases.json").is_file())

    def test_bridge_requires_initial_page_token(self):
        bridge = Bridge(self.host, "private-page-token")
        for token in (None, "", "wrong-page-token", 123):
            response = bridge.request(json.dumps({"action": "get_state", "token": token}))
            self.assertFalse(json.loads(response)["ok"])
        self.assertTrue(json.loads(bridge.request(json.dumps({"action": "get_state", "token": "private-page-token"})))["ok"])
        html = bundled_html("private-page-token")
        self.assertIn('window.__TUNNEL_UI_TOKEN__="private-page-token"', html)
        self.assertNotIn('src="app.js"', html)
        self.assertNotIn('href="app.css"', html)
        self.assertIn('Content-Security-Policy', html)
        self.assertNotIn('href="remote.css"', html)

    def test_remote_actions_stay_on_authenticated_local_bridge(self):
        backend = Mock()
        backend.status.return_value = {"running": False}
        backend.request.return_value = {"session_id": "test-session", "jpeg": "not-a-real-frame"}
        self.host._background = backend
        bridge = Bridge(self.host, "private-page-token")
        payload = {"session_id": "test-session", "event": {"type": "key", "key": "KeyA", "down": True}}
        response = json.loads(bridge.request(json.dumps({"token": "private-page-token", "action": "remote_input", "payload": payload})))
        self.assertTrue(response["ok"])
        backend.request.assert_called_once_with("remote_input", payload)
        backend.request.reset_mock()
        response = json.loads(bridge.request(json.dumps({"token": "wrong-token", "action": "remote_input", "payload": payload})))
        self.assertFalse(response["ok"])
        backend.request.assert_not_called()
        self.assertFalse(self.call("remote_execute_shell")["ok"])

    def test_remote_events_enter_logs_once_and_clear_stays_clear(self):
        snapshot = self.host._background_dir / "configure.json"
        snapshot.write_text("{}", encoding="utf-8")
        backend = Mock()
        backend.status.return_value = {"running": True, "config_path": str(snapshot)}
        backend.request.return_value = {"logs": [{"time": 123.45, "message": "Desktop connected: test-device"}]}
        self.host._background = backend
        for _ in range(3):
            state = self.host.state()
        self.assertEqual(sum("Desktop connected" in entry["message"] for entry in state["logs"]), 1)
        self.call("clear_logs")
        self.assertEqual(self.host.state()["logs"], [])
        backend.status.return_value = {"running": False}

    def test_unattended_close_detaches_and_reopen_can_attach(self):
        snapshot = self.host._background_dir / "configure.json"
        snapshot.write_text(json.dumps({"remote_desktop": {"enabled": True, "unattended": True}}), encoding="utf-8")
        status_path = self.host._background_dir / "status.json"
        status_path.write_text(json.dumps({"running": True, "node": "test"}), encoding="utf-8")
        backend = Mock()
        backend.status.return_value = {"running": True, "config_path": str(snapshot), "status_path": str(status_path)}
        backend.is_running.return_value = True
        backend.request.return_value = {}
        self.host._background = backend
        self.assertTrue(self.host.close())
        backend.stop.assert_not_called()
        backend.request.assert_called_with("remote_disconnect", {})
        self.assertTrue(self.host.state()["status"]["running"])
        self.assertFalse(self.call("remote_connect", address="10.1.0.2")["ok"])
        # Explicit disconnect always stops the background process, even after detach.
        backend.status.return_value = {"running": False}
        self.assertTrue(self.call("stop")["ok"])
        backend.stop.assert_called_once()

    def running_backend(self):
        snapshot = self.host._background_dir / "configure.json"
        snapshot.write_text(self.host._runtime_configuration(self.host.path.read_text(encoding="utf-8")), encoding="utf-8")
        backend = Mock()
        backend.is_running.return_value = True
        backend.status.return_value = {"running": False, "config_path": str(snapshot)}
        backend.request.return_value = {"mode": "peers", "interrupted": False, "message": "节点配置已更新"}
        self.host._background = backend
        return backend, json.loads(snapshot.read_text(encoding="utf-8"))

    def test_entire_configuration_is_applied_before_save_success(self):
        document = json.loads(self.config)
        document["remote_desktop"] = {"enabled": True, "access": "all_tunnel_nodes", "unattended": True}
        document["peers"] = [{"address": "127.0.0.2:49005", "shared_key": "replacement-peer-key"}]
        document["tun_mtu"] = 1200
        self.assertTrue(self.call("save_config", text=self.config)["ok"])
        original = self.host.path.read_bytes()
        backend, _ = self.running_backend()
        backend.request.side_effect = ValueError("policy rejected")
        rejected = self.call("save_config", text=json.dumps(document))
        self.assertFalse(rejected["ok"])
        self.assertEqual(self.host.path.read_bytes(), original)
        backend.request.assert_called_once()
        self.assertEqual(backend.request.call_args.args[0], "apply_config")
        applied = backend.request.call_args.args[1]["config"]
        self.assertEqual(applied["remote_desktop"]["networks"], ["198.18.253.0/30"])
        self.assertEqual(applied["peers"], document["peers"])
        self.assertEqual(applied["tun_mtu"], 1200)
        self.assertEqual(list(self.host.directory.glob(".config-*")), [])
        backend.request.side_effect = None
        saved = self.call("save_config", text=json.dumps(document))
        self.assertTrue(saved["ok"], saved)
        self.assertIn("配置已保存并应用", saved["data"]["message"])
        self.assertEqual(saved["data"]["mode"], "peers")
        self.assertEqual(json.loads(self.host.path.read_text(encoding="utf-8"))["remote_desktop"]["access"], "all_tunnel_nodes")

    def test_runtime_apply_uses_persistent_service_state_and_portable_saved_path(self):
        self.assertTrue(self.call("save_config", text=self.config)["ok"])
        backend, _ = self.running_backend()
        document = json.loads(self.config)
        document["address_server"] = {"address": "127.0.0.1:49011", "shared_key": "server-test-key",
                                      "networks": ["198.18.252.0/29"], "state_file": "manual-leases.json"}
        saved = self.call("apply_config", text=json.dumps(document))
        self.assertTrue(saved["ok"], saved)
        applied = backend.request.call_args.args[1]["config"]
        self.assertEqual(Path(applied["address_server"]["state_file"]), self.host.directory / "manual-leases.json")
        self.assertEqual(json.loads(self.host.path.read_text(encoding="utf-8"))["address_server"]["state_file"], "manual-leases.json")

    def test_revision_check_prevents_stale_gui_or_cli_overwrite(self):
        loaded = self.call("load_config")["data"]
        self.assertIsNone(loaded["revision"])
        first = self.call("save_config", text=self.config, expected_sha256=None)
        self.assertTrue(first["ok"], first)
        previous = self.host.path.read_bytes()
        revision = hashlib.sha256(previous).hexdigest()
        self.assertEqual(first["data"]["revision"], revision)
        self.assertEqual(self.call("load_config")["data"]["revision"], revision)
        backend, _ = self.running_backend()
        for expected in (None, "f" * 64, "invalid"):
            result = self.call("save_config", text=self.config, expected_sha256=expected)
            self.assertFalse(result["ok"], expected)
            self.assertEqual(self.host.path.read_bytes(), previous)
        backend.request.assert_not_called()
        result = self.call("save_config", text=self.config, expected_sha256=revision)
        self.assertTrue(result["ok"], result)
        backend.request.assert_called_once()
        self.assertEqual(result["data"]["revision"], revision)

    def test_write_preflight_failure_never_changes_running_configuration(self):
        self.assertTrue(self.call("save_config", text=self.config)["ok"])
        original = self.host.path.read_bytes()
        backend, _ = self.running_backend()
        with patch.object(self.host, "_stage_private", side_effect=OSError("disk full")):
            saved = self.call("save_config", text=self.config)
        self.assertFalse(saved["ok"])
        self.assertIn("disk full", saved["error"])
        backend.request.assert_not_called()
        self.assertEqual(self.host.path.read_bytes(), original)

    def test_persist_failure_rolls_back_runtime_and_preserves_saved_configuration(self):
        self.assertTrue(self.call("save_config", text=self.config)["ok"])
        original = self.host.path.read_bytes()
        backend, previous = self.running_backend()
        document = json.loads(self.config)
        document["tun_mtu"] = 1200
        with patch("controller.os.replace", side_effect=OSError("replace denied")):
            saved = self.call("save_config", text=json.dumps(document))
        self.assertFalse(saved["ok"])
        self.assertIn("已恢复原运行配置", saved["error"])
        self.assertEqual(backend.request.call_count, 2)
        backend.request.assert_called_with("apply_config", {"config": previous})
        self.assertEqual(self.host.path.read_bytes(), original)
        self.assertEqual(list(self.host.directory.glob(".config-*")), [])

    def test_rollback_failure_is_explicit_and_does_not_report_saved(self):
        self.assertTrue(self.call("save_config", text=self.config)["ok"])
        original = self.host.path.read_bytes()
        backend, _ = self.running_backend()
        backend.request.side_effect = [{"mode": "rebuild"}, ValueError("old socket unavailable")]
        with patch("controller.os.replace", side_effect=OSError("replace denied")):
            saved = self.call("save_config", text=self.config)
        self.assertFalse(saved["ok"])
        self.assertIn("运行配置回滚也失败", saved["error"])
        self.assertIn("old socket unavailable", saved["error"])
        self.assertEqual(self.host.path.read_bytes(), original)
        self.assertEqual(list(self.host.directory.glob(".config-*")), [])

    def test_closed_window_cannot_start_queued_work(self):
        self.assertTrue(self.host.close())
        self.assertFalse(self.call("start", text=self.config)["ok"])
        self.assertFalse(self.call("save_config", text=self.config)["ok"])
        self.assertIsNone(self.host._process)

    def test_legacy_migration_preserves_permissions_and_file_on_load(self):
        local = json.loads(self.config)["address"]
        secret = 'test-secret-中文-"quote"'
        legacy = json.dumps({"listen": {"address": local, "enabled": False,
            "bind_address": "127.0.0.1:49005", "networks": []}, "peers": [
            {"address": "127.0.0.2:49005", "shared_key": secret, "networks": [
                {"tunnel": "10.44.0.0/24", "tunnel_ip": "10.44.0.1"}]},
            {"address": "127.0.0.3:49005", "shared_key": "second-private-key", "networks": [
                {"tunnel": "fd00:44::/64", "tunnel_ip": "fd00:44::1"}]}]}, ensure_ascii=False)
        self.host.path.write_text(legacy, encoding="utf-8")
        loaded = self.call("load_config")
        self.assertTrue(loaded["ok"])
        migrated = json.loads(loaded["data"]["text"])
        self.assertEqual(set(migrated["networks"]), {"10.44.0.1/24", "fd00:44::1/64"})
        self.assertEqual(migrated["listen"], {"enabled": False, "networks": [], "bind_address": "127.0.0.1:49005"})
        self.assertEqual(migrated["peers"][0]["networks"], ["10.44.0.0/24"])
        self.assertEqual(migrated["peers"][1]["networks"], ["fd00:44::/64"])
        self.assertEqual(migrated["peers"][0]["shared_key"], secret)
        self.assertEqual(self.host.path.read_text(encoding="utf-8"), legacy)
        normalized = self.call("normalize_config", text=loaded["data"]["text"])
        self.assertEqual(normalized["data"]["text"], loaded["data"]["text"])
        self.assertTrue(self.call("save_config", text=legacy)["ok"])
        self.assertEqual(json.loads(self.host.path.read_text(encoding="utf-8")), migrated)
        self.assertNotIn(secret, json.dumps(self.host.state(), ensure_ascii=False))

    def test_invalid_import_is_retained_for_repair(self):
        for invalid in ('{"unfinished":', '{"address":"127.0.0.1:1234","networks":["bad"]}'):
            self.host.path.write_text(invalid, encoding="utf-8")
            loaded = self.call("load_config")
            self.assertTrue(loaded["ok"])
            self.assertEqual(loaded["data"]["text"], invalid)
            self.assertTrue(loaded["data"]["error"])
            self.assertFalse(self.call("normalize_config", text=invalid)["ok"])
            self.assertEqual(self.host.path.read_text(encoding="utf-8"), invalid)

    def test_added_network_requires_explicit_peer_permission(self):
        document = json.loads(self.config)
        document["peers"] = [{"address": "127.0.0.2:49005", "shared_key": "test-peer-key"}]
        self.assertTrue(self.call("save_config", text=json.dumps(document))["ok"])
        original = self.host.path.read_bytes()
        document["networks"].append("fd00:44::1/64")
        self.assertFalse(self.call("save_config", text=json.dumps(document))["ok"])
        self.assertEqual(self.host.path.read_bytes(), original)
        document["peers"][0]["networks"] = ["198.18.253.0/30"]
        self.assertTrue(self.call("save_config", text=json.dumps(document))["ok"])
        self.assertEqual(json.loads(self.host.path.read_text())["peers"][0]["networks"], ["198.18.253.0/30"])

    def test_generated_key_is_private_and_usable(self):
        first, second = self.call("generate_key"), self.call("generate_key")
        self.assertTrue(first["ok"] and second["ok"])
        key = first["data"]["key"]
        self.assertRegex(key, "^[0-9a-f]{64}$")
        self.assertNotEqual(key, second["data"]["key"])
        self.assertNotIn(key, json.dumps(self.host.state()))
        document = json.loads(self.config)
        document["peers"] = [{"address": "127.0.0.2:49005", "shared_key": key}]
        self.assertTrue(self.call("validate_config", text=json.dumps(document))["ok"])

    @unittest.skipUnless(args.live, "requires --live and TUN privileges")
    def test_real_core_start_stop_restart_and_close(self):
        def wait_phase(phase):
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                state = self.host.state()
                if state["phase"] == phase:
                    return state
                if state["phase"] == "error":
                    self.fail(json.dumps(state, ensure_ascii=False))
                time.sleep(.1)
            self.fail("phase timeout: " + json.dumps(self.host.state(), ensure_ascii=False))
        self.assertTrue(self.call("start", text=self.config)["ok"])
        state = wait_phase("running")
        self.assertTrue(state["status"]["running"])
        self.assertTrue(state["status"]["device"])
        self.assertFalse(self.call("start", text=self.config)["ok"])
        self.assertTrue(self.call("stop")["ok"])
        self.assertEqual(wait_phase("stopped")["status"], {})
        self.assertEqual(list(self.host.directory.glob("run-*")), [])
        self.assertTrue(self.call("start", text=self.config)["ok"])
        wait_phase("running")
        self.assertTrue(self.host.close())
        self.assertEqual(wait_phase("stopped")["status"], {})


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]] + remaining, verbosity=2)
