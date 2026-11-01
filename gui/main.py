"""Offline desktop window for the tunnel core (Windows, Linux and macOS)."""
import argparse
import hmac
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import threading

from controller import Controller, MAX_CONFIG


def resources():
    if getattr(sys, "frozen", False):
        return Path(sys._MEIPASS)
    return Path(__file__).resolve().parent


def bundled_html(token):
    assets = resources() / "assets"
    html = (assets / "index.html").read_text(encoding="utf-8")
    html = html.replace('<meta charset="utf-8">', '<meta charset="utf-8">' +
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; ' +
        'script-src \'unsafe-inline\' \'unsafe-eval\'; style-src \'unsafe-inline\'; ' +
        'img-src data:; connect-src \'none\'; object-src \'none\'; base-uri \'none\'; ' +
        'form-action \'none\'; frame-src \'none\';">')
    css = (assets / "app.css").read_text(encoding="utf-8")
    script = (assets / "app.js").read_text(encoding="utf-8")
    # No local web server or management port. Only this initial page gets the token.
    html = html.replace('<link rel="stylesheet" href="app.css">', '<style>' + css + '</style>')
    html = html.replace('<link rel="stylesheet" href="remote.css">', '<style>' + (assets / "remote.css").read_text(encoding="utf-8") + '</style>')
    html = html.replace('<script src="app.js" defer></script>',
                        '<script>window.__TUNNEL_UI_TOKEN__=' + json.dumps(token) + ';</script>' +
                        '<script defer>' + script + '</script>')
    # Inline scripts must run after the DOM exists (defer has no effect on inline JS).
    if '<script defer>' in html:
        begin = html.index('<script>window.__TUNNEL_UI_TOKEN__=')
        end = html.index('</script>', html.index('<script defer>', begin)) + len('</script>')
        scripts = html[begin:end]
        html = html[:begin] + html[end:]
        html = html.replace('</body>', scripts + '</body>')
    if 'src="app.js"' in html or 'href="app.css"' in html:
        raise RuntimeError("UI assets could not be bundled")
    return html


def copy_text(text):
    if not isinstance(text, str) or len(text.encode("utf-8")) > 2 * MAX_CONFIG:
        raise ValueError("复制内容过大。")
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes
        user, kernel = ctypes.windll.user32, ctypes.windll.kernel32
        kernel.GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]
        kernel.GlobalAlloc.restype = wintypes.HGLOBAL
        kernel.GlobalLock.argtypes = [wintypes.HGLOBAL]
        kernel.GlobalLock.restype = ctypes.c_void_p
        kernel.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
        kernel.GlobalFree.argtypes = [wintypes.HGLOBAL]
        user.SetClipboardData.argtypes = [wintypes.UINT, wintypes.HANDLE]
        user.SetClipboardData.restype = wintypes.HANDLE
        if not user.OpenClipboard(None):
            raise ValueError("剪贴板暂时被占用，请重试。")
        handle = None
        try:
            data = (text + "\0").encode("utf-16-le")
            handle = kernel.GlobalAlloc(0x0002, len(data))
            pointer = kernel.GlobalLock(handle) if handle else None
            if not pointer:
                raise OSError("无法分配剪贴板内存")
            ctypes.memmove(pointer, data, len(data))
            kernel.GlobalUnlock(handle)
            if not user.EmptyClipboard() or not user.SetClipboardData(13, handle):
                raise OSError("无法写入剪贴板")
            handle = None  # Ownership transferred to Windows.
        finally:
            if handle:
                kernel.GlobalFree(handle)
            user.CloseClipboard()
    else:
        command = (["pbcopy"] if sys.platform == "darwin" else
                   ["wl-copy"] if shutil.which("wl-copy") else
                   ["xclip", "-selection", "clipboard"] if shutil.which("xclip") else None)
        if command is None:
            raise ValueError("系统缺少剪贴板工具，可直接选择日志文字复制。")
        subprocess.run(command, input=text.encode("utf-8"), check=True, timeout=5)


class Bridge:
    def __init__(self, controller, token):
        self._controller = controller
        self._token = token

    def request(self, message):
        try:
            if not isinstance(message, str) or len(message.encode("utf-8")) > 2 * MAX_CONFIG:
                raise ValueError("无效请求。")
            envelope = json.loads(message)
            token = envelope.get("token") if isinstance(envelope, dict) else None
            if not isinstance(token, str) or not hmac.compare_digest(token, self._token):
                raise ValueError("页面未获授权，请重新打开应用。")
            if envelope.get("action") == "copy_text":
                copy_text(envelope.get("payload", {}).get("text"))
                return json.dumps({"ok": True, "data": {"message": "已复制"}})
            return self._controller.request(message)
        except Exception as error:
            return json.dumps({"ok": False, "error": str(error)}, ensure_ascii=False)


def main():
    if "--remote-daemon" in sys.argv:
        from remote_desktop.daemon import main as daemon_main
        return daemon_main(sys.argv[sys.argv.index("--remote-daemon") + 1:])
    parser = argparse.ArgumentParser(description="Tunnel desktop UI")
    parser.add_argument("--binary", type=Path, help="Path to the native tunnel executable")
    parser.add_argument("--config-dir", type=Path, help="Private configuration directory")
    parser.add_argument("--check-ui", type=Path, metavar="REPORT", help="Check the WebView/bridge/core without connecting, write JSON and exit")
    args = parser.parse_args()
    frozen = getattr(sys, "frozen", False)
    base = Path(sys.executable).parent if frozen else Path(__file__).resolve().parent.parent
    native = "tunnel.exe" if os.name == "nt" else "tunnel"
    default_binary = base / native if frozen else base / "build" / native
    example = resources() / "default.json" if frozen else base / "config" / "default.json"
    controller = Controller(args.binary or default_binary, args.config_dir, example)
    token = secrets.token_hex(32)
    import webview
    window = webview.create_window("Tunnel", html=bundled_html(token), js_api=Bridge(controller, token),
                                   width=1180, height=820, min_size=(760, 580), background_color="#101820",
                                   text_select=True, hidden=bool(args.check_ui))
    window.events.closing += controller.close
    result = {}

    def check_ui():
        try:
            if not window.events.loaded.wait(60):
                raise RuntimeError("WebView did not load within 60 seconds")
            received = threading.Event()
            def completed(value):
                result.update(value if isinstance(value, dict) else {"ok": False, "error": str(value)})
                received.set()
            window.evaluate_js("""(async () => {
                const request = async (action, payload = {}) => {
                    const reply = JSON.parse(await window.pywebview.api.request(JSON.stringify({action, payload, token: window.__TUNNEL_UI_TOKEN__})));
                    if (!reply.ok) throw new Error(reply.error);
                    return reply.data;
                };
                try {
                    const state = await request('get_state');
                    const config = await request('load_config');
                    await request('validate_config', {text: config.text});
                    if (!document.getElementById('connection-button')) throw new Error('UI DOM missing');
                    if (!document.getElementById('remote-screen') || !document.getElementById('remote-access')) throw new Error('Remote desktop UI missing');
                    if (getComputedStyle(document.querySelector('.remote-content')).paddingLeft !== '24px') throw new Error('Remote stylesheet missing');
                    const documentConfig = JSON.parse(config.text); documentConfig.remote_desktop = {enabled: false};
                    const normalized = await request('normalize_config', {text: JSON.stringify(documentConfig)});
                    if (JSON.parse(normalized.text).remote_desktop.enabled !== false) throw new Error('Remote config normalization failed');
                    return {ok: true, platform: state.platform, checks: ['webview', 'bridge', 'config_load', 'core_validation', 'remote_desktop_dom', 'remote_css', 'remote_config_normalization']};
                } catch (error) { return {ok: false, error: String(error)}; }
            })()""", callback=completed)
            if not received.wait(25):
                raise RuntimeError("UI bridge timed out")
        except Exception as error:
            result.update(ok=False, error=str(error))
        finally:
            args.check_ui.parent.mkdir(parents=True, exist_ok=True)
            args.check_ui.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
            window.destroy()
    try:
        webview.start(check_ui if args.check_ui else None, http_server=False, private_mode=True)
    finally:
        controller.close()
    return 0 if not args.check_ui or result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
