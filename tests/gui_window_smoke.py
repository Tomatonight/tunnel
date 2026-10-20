"""Exercise the actual WebView window, bridge and TUN through UI button clicks."""
import argparse
import json
import logging
import os
from pathlib import Path
import secrets
import socket
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "gui"))
from controller import Controller
from main import Bridge, bundled_html

parser = argparse.ArgumentParser()
parser.add_argument("--binary", type=Path, default=ROOT / "build" / ("tunnel.exe" if os.name == "nt" else "tunnel"))
parser.add_argument("--visible", action="store_true")
parser.add_argument("--diagnostics", action="store_true")
parser.add_argument("--output", type=Path, help="Write a JSON test report")
args = parser.parse_args()


def main():
    import webview
    if args.diagnostics:
        logging.getLogger("pywebview").setLevel(logging.DEBUG)
    with tempfile.TemporaryDirectory(prefix="tunnel-window-test-") as directory:
        controller = Controller(args.binary, directory)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            address = "127.0.0.1:%s" % sock.getsockname()[1]
        config = json.dumps({"device_backend": "tun", "peers": [], "listen": {"enabled": True, "address": address,
            "bind_address": address, "networks": [{"tunnel": "198.18.253.0/30", "tunnel_ip": "198.18.253.1"}]}})
        # Leave a real legacy file on disk. The form must use the native parser's
        # migrated view without changing this file merely because it was opened.
        controller.path.write_text(config, encoding="utf-8")
        token = secrets.token_hex(32)
        window = webview.create_window("Tunnel UI smoke test", html=bundled_html(token), js_api=Bridge(controller, token),
                                       width=1180, height=820, hidden=not args.visible)
        window.events.closing += controller.close
        result = {"ok": False}

        def wait(predicate, label):
            end = time.monotonic() + 25
            while time.monotonic() < end:
                if predicate():
                    return
                time.sleep(.2)
            raise RuntimeError(label + ": " + json.dumps(controller.state(), ensure_ascii=False))

        def exercise():
            try:
                if not window.events.loaded.wait(60):
                    raise RuntimeError("WebView did not load the initial page within 60s")
                wait(lambda: window.evaluate_js("document.getElementById('local-endpoint').value") == address, "legacy form loaded")
                assert controller.path.read_text(encoding="utf-8") == config, "loading rewrote legacy file"
                wait(lambda: window.evaluate_js("!!document.getElementById('connection-button') && !document.getElementById('connection-button').disabled"), "bridge ready")
                window.evaluate_js("document.querySelector('[data-page=config]').click(); const input = document.querySelector('.network-cidr'); input.value = '198.18.253.2/30'; input.dispatchEvent(new Event('input', {bubbles:true})); document.getElementById('save-config').click()")
                def saved_new_form():
                    try:
                        saved = json.loads(controller.path.read_text(encoding="utf-8"))
                        return saved.get("address") == address and saved.get("networks") == ["198.18.253.2/30"]
                    except (OSError, ValueError):
                        return False
                wait(saved_new_form, "form save through native validation")
                wait(lambda: window.evaluate_js("!document.getElementById('connection-button').disabled"), "save completed")
                window.evaluate_js("document.getElementById('connection-button').click()")
                wait(lambda: controller.state()["phase"] == "running", "UI start")
                wait(lambda: window.evaluate_js("document.getElementById('phase-pill').dataset.phase") == "running", "running rendered")
                window.evaluate_js("document.getElementById('connection-button').click()")
                wait(lambda: controller.state()["phase"] == "stopped", "UI stop")
                wait(lambda: window.evaluate_js("document.getElementById('phase-pill').dataset.phase") == "stopped", "stopped rendered")
                result.update(ok=True, checks=["offline_html", "authenticated_bridge", "legacy_load_preserves_file",
                    "form_save_simple_config", "UI_start_real_TUN", "live_status_render", "UI_stop_cleanup"])
            except Exception as error:
                result["error"] = str(error)
            finally:
                controller.close()
                window.destroy()

        try:
            webview.start(exercise, http_server=False, private_mode=True)
        finally:
            controller.close()
        print(json.dumps(result, ensure_ascii=False, indent=2))
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
