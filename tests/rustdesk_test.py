import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from remote_desktop.rustdesk import RustDeskError, RustDeskLauncher


class FakeProcess:
    _next = 7000

    def __init__(self, args, **_kwargs):
        self.args = args
        self.pid = FakeProcess._next
        FakeProcess._next += 1
        self.returncode = None

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        self.returncode = 0
        return 0

    def kill(self):
        self.returncode = -9


class RustDeskTests(unittest.TestCase):
    def test_requires_installed_client(self):
        with tempfile.TemporaryDirectory() as directory:
            launcher = RustDeskLauncher(directory)
            with patch.dict(os.environ, {"TUNNEL_RUSTDESK_BIN": ""}, clear=False), \
                 patch("shutil.which", return_value=None):
                with self.assertRaises(RustDeskError):
                    launcher.connect("10.0.0.5", "secret")

    def test_connect_uses_argument_list_and_never_shell(self):
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / ("rustdesk.exe" if os.name == "nt" else "rustdesk")
            executable.write_bytes(b"stub")
            launcher = RustDeskLauncher(directory)
            with patch.dict(os.environ, {"TUNNEL_RUSTDESK_BIN": str(executable)}), \
                 patch("subprocess.Popen", side_effect=FakeProcess) as popen:
                result = launcher.connect("10.0.0.5", "key with spaces")
            self.assertTrue(result["running"])
            args = popen.call_args.args[0]
            self.assertEqual(args[1:4], ["--connect", "10.0.0.5", "--password"])
            self.assertEqual(args[4], "key with spaces")
            self.assertFalse(popen.call_args.kwargs.get("shell", False))
            launcher.close()

    def test_connect_allows_rustdesk_to_prompt_for_password(self):
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / ("rustdesk.exe" if os.name == "nt" else "rustdesk")
            executable.write_bytes(b"stub")
            launcher = RustDeskLauncher(directory)
            with patch.dict(os.environ, {"TUNNEL_RUSTDESK_BIN": str(executable)}), \
                 patch("subprocess.Popen", side_effect=FakeProcess) as popen:
                launcher.connect("10.0.0.5", "")
            self.assertEqual(popen.call_args.args[0][1:], ["--connect", "10.0.0.5"])
            launcher.close()

    def test_host_sets_permanent_password_without_manual_approval(self):
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / ("rustdesk.exe" if os.name == "nt" else "rustdesk")
            executable.write_bytes(b"stub")
            launcher = RustDeskLauncher(directory)
            with patch.dict(os.environ, {"TUNNEL_RUSTDESK_BIN": str(executable)}), \
                 patch("subprocess.Popen", side_effect=FakeProcess) as popen:
                result = launcher.host("shared key")
            self.assertFalse(result["running"])
            args = popen.call_args.args[0]
            self.assertEqual(args[-2:], ["--password", "shared key"])
            self.assertFalse(popen.call_args.kwargs.get("shell", False))
            launcher.close()

    def test_rejects_shell_metacharacters_in_target(self):
        with tempfile.TemporaryDirectory() as directory:
            launcher = RustDeskLauncher(directory)
            with self.assertRaises(RustDeskError):
                launcher.connect("10.0.0.5;rm -rf /", "secret")

    def test_rejects_rustdesk_id_to_keep_desktop_on_tunnel(self):
        with tempfile.TemporaryDirectory() as directory:
            launcher = RustDeskLauncher(directory)
            with self.assertRaisesRegex(RustDeskError, "虚拟 IP"):
                launcher.connect("123456789", None)


if __name__ == "__main__":
    unittest.main()
