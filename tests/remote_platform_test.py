"""No normal test injects input into the user's desktop.

Run with --live-capture for a read-only real desktop capture, or --xvfb for a
temporary isolated Linux X server with real capture/input verification.
"""
from __future__ import annotations

import argparse
import ctypes
import io
import math
import os
from pathlib import Path
import select
import subprocess
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from remote_desktop.platforms import DesktopBackend, DesktopError, InputError, _check_session, _WindowsInput


class FakeCapture:
    def __init__(self, width=1920, height=1080, left=-1920, top=20):
        self.monitors = [{}, {"left": left, "top": top, "width": width, "height": height}]
        self.closed = False

    def grab(self, monitor):
        class Shot:
            size = (monitor["width"], monitor["height"])
            bgra = b"\x33\x66\x99\x00" * (size[0] * size[1])
        return Shot()

    def close(self):
        self.closed = True


class FakeInput:
    def __init__(self):
        self.events = []
        self.fail_release = set()
        self.closed = False

    def move(self, x, y):
        self.events.append(("move", x, y))

    def key(self, key, down):
        if not down and key in self.fail_release:
            raise DesktopError("test release failure")
        self.events.append(("key", key, down))

    def button(self, button, down):
        self.events.append(("button", button, down))

    def wheel(self, dx, dy):
        self.events.append(("wheel", dx, dy))

    def close(self):
        self.closed = True


class BackendTest(unittest.TestCase):
    def setUp(self):
        self.capture = FakeCapture()
        self.native = FakeInput()
        self.backend = DesktopBackend(_capture=self.capture, _native=self.native, _platform="linux")

    def tearDown(self):
        self.native.fail_release.clear()
        self.backend.close()

    def test_jpeg_real_encoding_and_size(self):
        from PIL import Image
        result = self.backend.capture()
        self.assertEqual((result["width"], result["height"]), (1600, 900))
        self.assertEqual((result["source_width"], result["source_height"]), (1920, 1080))
        with Image.open(io.BytesIO(result["jpeg"])) as image:
            self.assertEqual(image.format, "JPEG")
            self.assertEqual(image.size, (1600, 900))
            self.assertLess(sum(abs(a - b) for a, b in zip(image.getpixel((800, 450)), (153, 102, 51))), 8)

    def test_capture_does_not_upscale(self):
        self.capture.monitors[1].update(width=128, height=96)
        result = self.backend.capture()
        self.assertEqual((result["width"], result["height"]), (128, 96))

    def test_mouse_coordinates_respect_monitor_offset(self):
        self.backend.input({"type": "mouse_move", "x": 0, "y": 0})
        self.backend.input({"type": "mouse_move", "x": 1, "y": 1})
        self.assertEqual(self.native.events, [("move", -1920, 20), ("move", -1, 1099)])

    def test_capture_refreshes_coordinates(self):
        self.capture.monitors[1].update(width=128, height=96, left=0, top=0)
        self.backend.capture()
        self.backend.input({"type": "mouse_move", "x": 1, "y": 1})
        self.assertEqual(self.native.events, [("move", 127, 95)])

    def test_rejects_bad_events_before_native_call(self):
        invalid = [None, [], {"type": "shell", "command": "whoami"},
                   {"type": "text", "text": "hello"},
                   {"type": "mouse_move", "x": -0.1, "y": 0},
                   {"type": "mouse_move", "x": 1.1, "y": 0},
                   {"type": "mouse_move", "x": math.nan, "y": 0},
                   {"type": "mouse_move", "x": math.inf, "y": 0},
                   {"type": "mouse_move", "x": 10 ** 1000, "y": 0},
                   {"type": "mouse_move", "x": True, "y": 0},
                   {"type": "mouse_move", "x": "0", "y": 0},
                   {"type": "mouse_button", "button": "side", "down": True},
                   {"type": "mouse_button", "button": [], "down": True},
                   {"type": "mouse_button", "button": "left", "down": 1},
                   {"type": "wheel", "dx": 11}, {"type": "wheel", "dy": 1.5},
                   {"type": "wheel", "dy": True},
                   {"type": "key", "key": "__dict__", "down": True},
                   {"type": "key", "key": "é", "down": True},
                   {"type": "key", "key": "KeyA", "down": "false"},
                   {"type": "key", "key": "a" * 200, "down": True},
                   {"type": "key", "key": ["A"], "down": True}]
        for event in invalid:
            with self.subTest(event=event), self.assertRaises(InputError):
                self.backend.input(event)
        self.assertEqual(self.native.events, [])

    def test_release_every_held_input_on_disconnect(self):
        self.backend.input({"type": "key", "key": "ControlLeft", "down": True})
        self.backend.input({"type": "key", "key": "a", "down": True})
        self.backend.input({"type": "mouse_button", "button": "left", "down": True})
        self.backend.release_all()
        self.assertIn(("key", "ControlLeft", False), self.native.events)
        self.assertIn(("key", "KeyA", False), self.native.events)
        self.assertIn(("button", "left", False), self.native.events)
        count = len(self.native.events)
        self.backend.release_all()
        self.assertEqual(len(self.native.events), count)

    def test_release_failure_does_not_skip_other_buttons(self):
        self.backend.input({"type": "key", "key": "KeyA", "down": True})
        self.backend.input({"type": "mouse_button", "button": "left", "down": True})
        self.native.fail_release.add("KeyA")
        with self.assertRaises(DesktopError):
            self.backend.release_all()
        self.assertIn(("button", "left", False), self.native.events)
        self.native.fail_release.clear()
        self.backend.release_all()
        self.assertIn(("key", "KeyA", False), self.native.events)

    def test_keyup_for_unheld_key_does_not_release_local_key(self):
        self.backend.input({"type": "key", "key": "ControlLeft", "down": False})
        self.backend.input({"type": "mouse_button", "button": "left", "down": False})
        self.assertEqual(self.native.events, [])

    def test_repeated_keydown_and_release(self):
        for _ in range(3):
            self.backend.input({"type": "key", "key": "Digit1", "down": True})
        self.backend.input({"type": "key", "key": "Digit1", "down": False})
        self.assertEqual(self.native.events, [("key", "Digit1", True)] * 3 + [("key", "Digit1", False)])

    def test_wheel_steps(self):
        self.backend.input({"type": "wheel", "dx": -10, "dy": 10})
        self.assertEqual(self.native.events, [("wheel", -10, 10)])

    def test_close_releases_and_is_idempotent(self):
        self.backend.input({"type": "key", "key": "ShiftLeft", "down": True})
        self.backend.close()
        self.backend.close()
        self.assertEqual(self.native.events[-1], ("key", "ShiftLeft", False))
        self.assertTrue(self.capture.closed and self.native.closed)
        with self.assertRaises(DesktopError):
            self.backend.capture()
        with self.assertRaises(DesktopError):
            self.backend.input({"type": "wheel", "dy": 1})

    def test_initialization_bounds(self):
        for options in ({"quality": 0}, {"quality": True}, {"max_width": 0}, {"max_height": 100000}, {"max_width": 1.0}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                DesktopBackend(**options, _capture=self.capture, _native=self.native)

    def test_missing_monitor(self):
        self.capture.monitors = [{}]
        with self.assertRaises(DesktopError):
            self.backend.capture()

    def test_reports_real_platform_limits(self):
        caps = self.backend.capabilities()
        self.assertTrue(caps["logged_in_session_only"])
        self.assertFalse(caps["secure_desktop"])
        self.assertFalse(caps["native_wayland"])
        self.assertFalse(caps["text"])

    def test_wayland_is_not_silently_treated_as_x11(self):
        for environ in ({"DISPLAY": ":0", "WAYLAND_DISPLAY": "wayland-0"},
                        {"DISPLAY": ":0", "XDG_SESSION_TYPE": "wayland"}):
            with self.assertRaisesRegex(DesktopError, "Wayland"):
                _check_session("linux", environ)
        with self.assertRaisesRegex(DesktopError, "DISPLAY"):
            _check_session("linux", {})
        _check_session("linux", {"DISPLAY": ":1", "XDG_SESSION_TYPE": "x11"})

    @unittest.skipUnless(sys.platform == "win32", "Windows ABI test")
    def test_windows_sendinput_abi_without_injecting_input(self):
        native = _WindowsInput()
        self.assertEqual(ctypes.sizeof(native.Input), 40 if ctypes.sizeof(ctypes.c_void_p) == 8 else 28)
        self.assertEqual(native.Input.data.offset, 8 if ctypes.sizeof(ctypes.c_void_p) == 8 else 4)
        captured = []
        native._send = lambda event: captured.append(event)
        native.key("ControlRight", True)
        native.key("ControlRight", False)
        native.button("left", True)
        native.wheel(0, -1)
        self.assertEqual(captured[0].ki.wVk, 0xA3)
        self.assertEqual(captured[0].ki.dwFlags, 1)
        self.assertEqual(captured[1].ki.dwFlags, 3)
        self.assertEqual(captured[2].mi.dwFlags, 2)
        self.assertEqual(captured[3].mi.mouseData, (-120) & 0xFFFFFFFF)


def live_capture():
    from PIL import Image
    backend = DesktopBackend()
    try:
        result = backend.capture()
        with Image.open(io.BytesIO(result["jpeg"])) as image:
            image.load()
            assert image.width == result["width"] and image.height == result["height"]
            assert image.width <= 1600 and image.height <= 900
        print("LIVE CAPTURE PASS", {k: v for k, v in result.items() if k != "jpeg"}, "jpeg_bytes=", len(result["jpeg"]))
    finally:
        backend.close()


def isolated_xvfb():
    if not sys.platform.startswith("linux"):
        raise RuntimeError("--xvfb is Linux-only")
    from PIL import Image
    read_fd, write_fd = os.pipe()
    process = subprocess.Popen(["Xvfb", "-screen", "0", "800x600x24", "-nolisten", "tcp", "-nolisten", "unix", "-displayfd", str(write_fd)],
                               pass_fds=(write_fd,), stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    os.close(write_fd)
    backend = None
    previous = {key: os.environ.get(key) for key in ("DISPLAY", "WAYLAND_DISPLAY", "XDG_SESSION_TYPE")}
    try:
        if not select.select([read_fd], [], [], 10)[0]:
            raise RuntimeError("Xvfb did not become ready")
        display = os.read(read_fd, 80).decode("ascii").strip()
        if not display.isdigit():
            raise RuntimeError("Xvfb failed to allocate a display")
        os.environ["DISPLAY"] = ":" + display
        os.environ.pop("WAYLAND_DISPLAY", None)
        os.environ["XDG_SESSION_TYPE"] = "x11"
        backend = DesktopBackend()
        native = backend._native
        x = native.x
        x.XDefaultRootWindow.argtypes = [ctypes.c_void_p]
        x.XDefaultRootWindow.restype = ctypes.c_ulong
        x.XSetWindowBackground.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong]
        x.XSetWindowBackground.restype = ctypes.c_int
        x.XClearWindow.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
        x.XClearWindow.restype = ctypes.c_int
        x.XSync.argtypes = [ctypes.c_void_p, ctypes.c_int]
        x.XSync.restype = ctypes.c_int
        root = x.XDefaultRootWindow(native.display)
        x.XSetWindowBackground(native.display, root, 0x224466)
        x.XClearWindow(native.display, root)
        x.XSync(native.display, 0)
        result = backend.capture()
        with Image.open(io.BytesIO(result["jpeg"])) as image:
            assert image.size == (800, 600)
            assert sum(abs(a - b) for a, b in zip(image.getpixel((400, 300)), (34, 68, 102))) < 8
        backend.input({"type": "mouse_move", "x": 0.5, "y": 0.5})
        backend.input({"type": "mouse_button", "button": "left", "down": True})
        backend.input({"type": "key", "key": "KeyA", "down": True})
        x.XSync(native.display, 0)
        x.XQueryPointer.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong), ctypes.POINTER(ctypes.c_ulong)] + [ctypes.POINTER(ctypes.c_int)] * 4 + [ctypes.POINTER(ctypes.c_uint)]
        x.XQueryPointer.restype = ctypes.c_int
        r, child = ctypes.c_ulong(), ctypes.c_ulong()
        rx, ry, wx, wy, mask = ctypes.c_int(), ctypes.c_int(), ctypes.c_int(), ctypes.c_int(), ctypes.c_uint()
        def pointer():
            assert x.XQueryPointer(native.display, root, ctypes.byref(r), ctypes.byref(child), ctypes.byref(rx), ctypes.byref(ry), ctypes.byref(wx), ctypes.byref(wy), ctypes.byref(mask))
            return rx.value, ry.value, mask.value
        px, py, buttons = pointer()
        assert (px, py) == (400, 300), (px, py)
        assert buttons & 256
        x.XQueryKeymap.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        x.XQueryKeymap.restype = ctypes.c_int
        def held_a():
            bitmap = (ctypes.c_uint8 * 32)()
            x.XQueryKeymap(native.display, bitmap)
            code = x.XKeysymToKeycode(native.display, x.XStringToKeysym(b"a"))
            return bool(bitmap[code // 8] & (1 << (code % 8)))
        assert held_a()
        backend.release_all()
        x.XSync(native.display, 0)
        assert not held_a()
        assert not pointer()[2] & 256
        print("XVFB PASS: actual JPEG color, pointer move, mouse press/release, key press/release, disconnect cleanup")
    finally:
        if backend is not None:
            backend.close()
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        os.close(read_fd)
        process.terminate()
        try:
            process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--live-capture", action="store_true")
    parser.add_argument("--xvfb", action="store_true")
    args, remaining = parser.parse_known_args()
    outcome = unittest.main(argv=[sys.argv[0]] + remaining, exit=False)
    if not outcome.result.wasSuccessful():
        raise SystemExit(1)
    if args.live_capture:
        live_capture()
    if args.xvfb:
        isolated_xvfb()
