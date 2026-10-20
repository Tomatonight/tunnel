"""Desktop capture and bounded input for the interactive user session.

This module never starts a network listener. Callers must authenticate/authorize
before calling input(), and must call release_all() when a session disconnects.
Windows login/UAC desktops and native Wayland sessions need separate backends;
this backend reports those limitations instead of claiming unattended support.
"""
from __future__ import annotations

import ctypes
import ctypes.util
import io
import math
import os
import sys
import threading
from typing import Any


class DesktopError(RuntimeError):
    """A desktop prerequisite or native desktop operation failed."""


class InputError(ValueError):
    """The remote input event is invalid or unsupported."""


_COMMON_KEYS = {
    "Enter", "Escape", "Backspace", "Tab", "Space", "Delete", "Insert",
    "Home", "End", "PageUp", "PageDown", "ArrowLeft", "ArrowRight", "ArrowUp",
    "ArrowDown", "ShiftLeft", "ShiftRight", "ControlLeft", "ControlRight",
    "AltLeft", "AltRight", "MetaLeft", "MetaRight", "CapsLock", "NumLock",
    "ScrollLock", "PrintScreen", "Pause", "Minus", "Equal", "BracketLeft",
    "BracketRight", "Backslash", "Semicolon", "Quote", "Backquote", "Comma",
    "Period", "Slash",
}
_KEYS = frozenset(_COMMON_KEYS | {f"Key{chr(c)}" for c in range(65, 91)} |
                  {f"Digit{c}" for c in range(10)} | {f"F{c}" for c in range(1, 13)})
_ALIASES = {
    " ": "Space", "Esc": "Escape", "Control": "ControlLeft", "Shift": "ShiftLeft",
    "Alt": "AltLeft", "Meta": "MetaLeft", "OS": "MetaLeft", "Left": "ArrowLeft",
    "Right": "ArrowRight", "Up": "ArrowUp", "Down": "ArrowDown",
    "-": "Minus", "=": "Equal", "[": "BracketLeft", "]": "BracketRight",
    "\\": "Backslash", ";": "Semicolon", "'": "Quote", "`": "Backquote",
    ",": "Comma", ".": "Period", "/": "Slash",
}


def _key_name(value: Any) -> str:
    if not isinstance(value, str) or len(value) > 32:
        raise InputError("key must be a supported browser KeyboardEvent.code")
    if len(value) == 1 and value.isascii() and value.isalpha():
        value = "Key" + value.upper()
    elif len(value) == 1 and value in "0123456789":
        value = "Digit" + value
    value = _ALIASES.get(value, value)
    if value not in _KEYS:
        raise InputError("unsupported key: " + repr(value))
    return value


def _normalized(value: Any, name: str) -> float:
    if type(value) not in (int, float) or not 0 <= value <= 1 or not math.isfinite(value):
        raise InputError(name + " must be a finite number between 0 and 1")
    return float(value)


def _boolean(value: Any, name: str) -> bool:
    if type(value) is not bool:
        raise InputError(name + " must be a boolean")
    return value


def _wheel(value: Any) -> int:
    if type(value) is not int or not -10 <= value <= 10:
        raise InputError("wheel deltas must be integer steps between -10 and 10")
    return value


def _check_session(platform: str, environ: Any = None) -> None:
    environ = os.environ if environ is None else environ
    if platform.startswith("linux"):
        if environ.get("WAYLAND_DISPLAY") or environ.get("XDG_SESSION_TYPE", "").lower() == "wayland":
            raise DesktopError("Native Wayland capture/control is not supported by this backend; use an X11 session. Xwayland is not a full-desktop substitute.")
        if not environ.get("DISPLAY"):
            raise DesktopError("An interactive X11 desktop and DISPLAY are required; a headless service cannot capture the user's desktop.")
    elif platform not in ("win32", "darwin"):
        raise DesktopError("Unsupported desktop platform: " + platform)


def _set_windows_dpi() -> None:
    """Use physical pixels on each calling thread; don't truncate HANDLEs."""
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    try:
        fn = user32.SetThreadDpiAwarenessContext
        fn.argtypes = [ctypes.c_void_p]
        fn.restype = ctypes.c_void_p
        fn(ctypes.c_void_p(-4))  # DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2
    except AttributeError:
        try:
            fn = ctypes.WinDLL("shcore").SetProcessDpiAwareness
            fn.argtypes = [ctypes.c_int]
            fn.restype = ctypes.c_long
            fn(2)
        except (AttributeError, OSError):
            user32.SetProcessDPIAware()


class _WindowsInput:
    def __init__(self) -> None:
        _set_windows_dpi()
        self.api = ctypes.WinDLL("user32", use_last_error=True)
        # Windows LONG/DWORD are always 32 bits; ULONG_PTR follows pointer width.
        class Mouse(ctypes.Structure):
            _fields_ = [("dx", ctypes.c_int32), ("dy", ctypes.c_int32),
                        ("mouseData", ctypes.c_uint32), ("dwFlags", ctypes.c_uint32),
                        ("time", ctypes.c_uint32), ("dwExtraInfo", ctypes.c_size_t)]
        class Keyboard(ctypes.Structure):
            _fields_ = [("wVk", ctypes.c_uint16), ("wScan", ctypes.c_uint16),
                        ("dwFlags", ctypes.c_uint32), ("time", ctypes.c_uint32),
                        ("dwExtraInfo", ctypes.c_size_t)]
        class Hardware(ctypes.Structure):
            _fields_ = [("uMsg", ctypes.c_uint32), ("wParamL", ctypes.c_uint16),
                        ("wParamH", ctypes.c_uint16)]
        class Data(ctypes.Union):
            _fields_ = [("mi", Mouse), ("ki", Keyboard), ("hi", Hardware)]
        class Input(ctypes.Structure):
            _anonymous_ = ("data",)
            _fields_ = [("type", ctypes.c_uint32), ("data", Data)]
        self.Input, self.Mouse, self.Keyboard = Input, Mouse, Keyboard
        self.api.SendInput.argtypes = [ctypes.c_uint32, ctypes.POINTER(Input), ctypes.c_int]
        self.api.SendInput.restype = ctypes.c_uint32
        self.api.SetCursorPos.argtypes = [ctypes.c_int, ctypes.c_int]
        self.api.SetCursorPos.restype = ctypes.c_int
        self.api.MapVirtualKeyW.argtypes = [ctypes.c_uint32, ctypes.c_uint32]
        self.api.MapVirtualKeyW.restype = ctypes.c_uint32

    def _send(self, event: Any) -> None:
        if self.api.SendInput(1, ctypes.byref(event), ctypes.sizeof(self.Input)) != 1:
            raise DesktopError("Windows rejected input (desktop unavailable or UIPI/elevation restriction); error " + str(ctypes.get_last_error()))

    def move(self, x: int, y: int) -> None:
        _set_windows_dpi()
        if not self.api.SetCursorPos(x, y):
            raise DesktopError("Windows rejected pointer movement: " + str(ctypes.get_last_error()))

    def button(self, button: str, down: bool) -> None:
        flags = {"left": (0x0002, 0x0004), "right": (0x0008, 0x0010), "middle": (0x0020, 0x0040)}
        ev = self.Input(type=0)
        ev.mi = self.Mouse(0, 0, 0, flags[button][0 if down else 1], 0, 0)
        self._send(ev)

    def wheel(self, dx: int, dy: int) -> None:
        for delta, flag in ((dy, 0x0800), (dx, 0x1000)):
            if delta:
                ev = self.Input(type=0)
                ev.mi = self.Mouse(0, 0, (delta * 120) & 0xFFFFFFFF, flag, 0, 0)
                self._send(ev)

    def key(self, key: str, down: bool) -> None:
        keys = {
            "Enter": 0x0D, "Escape": 0x1B, "Backspace": 8, "Tab": 9, "Space": 0x20,
            "Delete": 0x2E, "Insert": 0x2D, "Home": 0x24, "End": 0x23,
            "PageUp": 0x21, "PageDown": 0x22, "ArrowLeft": 0x25, "ArrowUp": 0x26,
            "ArrowRight": 0x27, "ArrowDown": 0x28, "ShiftLeft": 0xA0,
            "ShiftRight": 0xA1, "ControlLeft": 0xA2, "ControlRight": 0xA3,
            "AltLeft": 0xA4, "AltRight": 0xA5, "MetaLeft": 0x5B, "MetaRight": 0x5C,
            "CapsLock": 0x14, "NumLock": 0x90, "ScrollLock": 0x91,
            "PrintScreen": 0x2C, "Pause": 0x13, "Minus": 0xBD, "Equal": 0xBB,
            "BracketLeft": 0xDB, "BracketRight": 0xDD, "Backslash": 0xDC,
            "Semicolon": 0xBA, "Quote": 0xDE, "Backquote": 0xC0,
            "Comma": 0xBC, "Period": 0xBE, "Slash": 0xBF,
        }
        vk = (ord(key[3:]) if key.startswith("Key") else ord(key[5:])
              if key.startswith("Digit") else 0x6F + int(key[1:])
              if key.startswith("F") and key[1:].isdigit() else keys[key])
        extended = key in {"ControlRight", "AltRight", "MetaLeft", "MetaRight",
                           "Delete", "Insert", "Home", "End", "PageUp", "PageDown",
                           "ArrowLeft", "ArrowRight", "ArrowUp", "ArrowDown", "NumLock", "PrintScreen"}
        ev = self.Input(type=1)
        ev.ki = self.Keyboard(vk, self.api.MapVirtualKeyW(vk, 0),
                              (0 if down else 2) | (1 if extended else 0), 0, 0)
        self._send(ev)

    def close(self) -> None:
        pass


class _X11Input:
    def __init__(self) -> None:
        try:
            self.x = ctypes.CDLL(ctypes.util.find_library("X11") or "libX11.so.6")
            self.xt = ctypes.CDLL(ctypes.util.find_library("Xtst") or "libXtst.so.6")
        except OSError as exc:
            raise DesktopError("X11 input requires libX11 and libXtst") from exc
        self.x.XInitThreads.argtypes = []
        self.x.XInitThreads.restype = ctypes.c_int
        self.x.XInitThreads()
        self.x.XOpenDisplay.argtypes = [ctypes.c_char_p]
        self.x.XOpenDisplay.restype = ctypes.c_void_p
        self.x.XCloseDisplay.argtypes = [ctypes.c_void_p]
        self.x.XCloseDisplay.restype = ctypes.c_int
        self.x.XFlush.argtypes = [ctypes.c_void_p]
        self.x.XFlush.restype = ctypes.c_int
        self.x.XStringToKeysym.argtypes = [ctypes.c_char_p]
        self.x.XStringToKeysym.restype = ctypes.c_ulong
        self.x.XKeysymToKeycode.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
        self.x.XKeysymToKeycode.restype = ctypes.c_uint8
        self.xt.XTestQueryExtension.argtypes = [ctypes.c_void_p] + [ctypes.POINTER(ctypes.c_int)] * 4
        self.xt.XTestQueryExtension.restype = ctypes.c_int
        self.xt.XTestFakeMotionEvent.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_ulong]
        self.xt.XTestFakeMotionEvent.restype = ctypes.c_int
        self.xt.XTestFakeButtonEvent.argtypes = [ctypes.c_void_p, ctypes.c_uint, ctypes.c_int, ctypes.c_ulong]
        self.xt.XTestFakeButtonEvent.restype = ctypes.c_int
        self.xt.XTestFakeKeyEvent.argtypes = [ctypes.c_void_p, ctypes.c_uint, ctypes.c_int, ctypes.c_ulong]
        self.xt.XTestFakeKeyEvent.restype = ctypes.c_int
        self.display = self.x.XOpenDisplay(None)
        if not self.display:
            raise DesktopError("Cannot open DISPLAY; run the desktop helper as the logged-in desktop user with X11 authorization")
        values = [ctypes.c_int() for _ in range(4)]
        if not self.xt.XTestQueryExtension(self.display, *(ctypes.byref(v) for v in values)):
            self.close()
            raise DesktopError("The X11 server does not provide the XTEST input extension")

    def _flush(self, ok: int) -> None:
        if not ok:
            raise DesktopError("X11 rejected the input event")
        self.x.XFlush(self.display)

    def move(self, x: int, y: int) -> None:
        self._flush(self.xt.XTestFakeMotionEvent(self.display, -1, x, y, 0))

    def button(self, button: str, down: bool) -> None:
        self._flush(self.xt.XTestFakeButtonEvent(self.display, {"left": 1, "middle": 2, "right": 3}[button], int(down), 0))

    def wheel(self, dx: int, dy: int) -> None:
        for delta, positive, negative in ((dy, 4, 5), (dx, 7, 6)):
            for _ in range(abs(delta)):
                button = positive if delta > 0 else negative
                self._flush(self.xt.XTestFakeButtonEvent(self.display, button, 1, 0))
                self._flush(self.xt.XTestFakeButtonEvent(self.display, button, 0, 0))

    def key(self, key: str, down: bool) -> None:
        symbols = {
            "Enter": "Return", "Escape": "Escape", "Backspace": "BackSpace",
            "Tab": "Tab", "Space": "space", "Delete": "Delete", "Insert": "Insert",
            "Home": "Home", "End": "End", "PageUp": "Prior", "PageDown": "Next",
            "ArrowLeft": "Left", "ArrowRight": "Right", "ArrowUp": "Up", "ArrowDown": "Down",
            "ShiftLeft": "Shift_L", "ShiftRight": "Shift_R", "ControlLeft": "Control_L",
            "ControlRight": "Control_R", "AltLeft": "Alt_L", "AltRight": "Alt_R",
            "MetaLeft": "Super_L", "MetaRight": "Super_R", "CapsLock": "Caps_Lock",
            "NumLock": "Num_Lock", "ScrollLock": "Scroll_Lock", "PrintScreen": "Print",
            "Pause": "Pause", "Minus": "minus", "Equal": "equal", "BracketLeft": "bracketleft",
            "BracketRight": "bracketright", "Backslash": "backslash", "Semicolon": "semicolon",
            "Quote": "apostrophe", "Backquote": "grave", "Comma": "comma", "Period": "period", "Slash": "slash",
        }
        symbol = (key[3:].lower() if key.startswith("Key") else key[5:]
                  if key.startswith("Digit") else key if key.startswith("F") else symbols[key])
        code = self.x.XKeysymToKeycode(self.display, self.x.XStringToKeysym(symbol.encode("ascii")))
        if not code:
            raise InputError("The current X11 keyboard layout does not provide " + key)
        self._flush(self.xt.XTestFakeKeyEvent(self.display, code, int(down), 0))

    def close(self) -> None:
        if self.display:
            self.x.XCloseDisplay(self.display)
            self.display = None


class _MacInput:
    def __init__(self) -> None:
        self.cg = ctypes.CDLL("/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics")
        self.cf = ctypes.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
        self.ax = ctypes.CDLL("/System/Library/Frameworks/ApplicationServices.framework/ApplicationServices")
        self.ax.AXIsProcessTrusted.argtypes = []
        self.ax.AXIsProcessTrusted.restype = ctypes.c_bool
        if not self.ax.AXIsProcessTrusted():
            raise DesktopError("macOS Accessibility permission is required for this desktop helper; enable it in System Settings > Privacy & Security")
        if hasattr(self.cg, "CGPreflightScreenCaptureAccess"):
            self.cg.CGPreflightScreenCaptureAccess.argtypes = []
            self.cg.CGPreflightScreenCaptureAccess.restype = ctypes.c_bool
            if not self.cg.CGPreflightScreenCaptureAccess():
                raise DesktopError("macOS Screen Recording permission is required for this desktop helper; enable it in System Settings > Privacy & Security")
        class Point(ctypes.Structure):
            _fields_ = [("x", ctypes.c_double), ("y", ctypes.c_double)]
        self.Point = Point
        self.cg.CGEventCreate.argtypes = [ctypes.c_void_p]
        self.cg.CGEventCreate.restype = ctypes.c_void_p
        self.cg.CGEventGetLocation.argtypes = [ctypes.c_void_p]
        self.cg.CGEventGetLocation.restype = Point
        self.cg.CGEventCreateMouseEvent.argtypes = [ctypes.c_void_p, ctypes.c_uint32, Point, ctypes.c_uint32]
        self.cg.CGEventCreateMouseEvent.restype = ctypes.c_void_p
        self.cg.CGEventCreateKeyboardEvent.argtypes = [ctypes.c_void_p, ctypes.c_uint16, ctypes.c_bool]
        self.cg.CGEventCreateKeyboardEvent.restype = ctypes.c_void_p
        self.cg.CGEventCreateScrollWheelEvent.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32]
        self.cg.CGEventCreateScrollWheelEvent.restype = ctypes.c_void_p
        self.cg.CGEventSetFlags.argtypes = [ctypes.c_void_p, ctypes.c_uint64]
        self.cg.CGEventSetFlags.restype = None
        self.cg.CGEventPost.argtypes = [ctypes.c_uint32, ctypes.c_void_p]
        self.cg.CGEventPost.restype = None
        self.cf.CFRelease.argtypes = [ctypes.c_void_p]
        self.cf.CFRelease.restype = None
        self.buttons: set[str] = set()
        self.modifiers: set[str] = set()

    def _post(self, event: Any) -> None:
        if not event:
            raise DesktopError("macOS could not create an input event")
        try:
            flags = 0
            for prefix, flag in (("Shift", 1 << 17), ("Control", 1 << 18), ("Alt", 1 << 19), ("Meta", 1 << 20)):
                if any(key.startswith(prefix) for key in self.modifiers):
                    flags |= flag
            self.cg.CGEventSetFlags(event, flags)
            self.cg.CGEventPost(0, event)  # kCGHIDEventTap
        finally:
            self.cf.CFRelease(event)

    def _position(self) -> Any:
        event = self.cg.CGEventCreate(None)
        if not event:
            raise DesktopError("macOS could not query pointer location")
        try:
            return self.cg.CGEventGetLocation(event)
        finally:
            self.cf.CFRelease(event)

    def move(self, x: int, y: int) -> None:
        button = "left" if "left" in self.buttons else "right" if "right" in self.buttons else "middle" if "middle" in self.buttons else None
        kind = {"left": 6, "right": 7, "middle": 27, None: 5}[button]
        self._post(self.cg.CGEventCreateMouseEvent(None, kind, self.Point(x, y), {"left": 0, "right": 1, "middle": 2, None: 0}[button]))

    def button(self, button: str, down: bool) -> None:
        kind = {"left": (1, 2), "right": (3, 4), "middle": (25, 26)}[button][0 if down else 1]
        self._post(self.cg.CGEventCreateMouseEvent(None, kind, self._position(), {"left": 0, "right": 1, "middle": 2}[button]))
        self.buttons.add(button) if down else self.buttons.discard(button)

    def wheel(self, dx: int, dy: int) -> None:
        # Fixed arguments declared above; variadic arguments must be explicitly typed on arm64.
        self._post(self.cg.CGEventCreateScrollWheelEvent(None, 1, 2, ctypes.c_int32(dy), ctypes.c_int32(dx)))

    def key(self, key: str, down: bool) -> None:
        codes = {
            "KeyA": 0, "KeyS": 1, "KeyD": 2, "KeyF": 3, "KeyH": 4, "KeyG": 5,
            "KeyZ": 6, "KeyX": 7, "KeyC": 8, "KeyV": 9, "KeyB": 11, "KeyQ": 12,
            "KeyW": 13, "KeyE": 14, "KeyR": 15, "KeyY": 16, "KeyT": 17,
            "Digit1": 18, "Digit2": 19, "Digit3": 20, "Digit4": 21, "Digit6": 22,
            "Digit5": 23, "Equal": 24, "Digit9": 25, "Digit7": 26, "Minus": 27,
            "Digit8": 28, "Digit0": 29, "BracketRight": 30, "KeyO": 31, "KeyU": 32,
            "BracketLeft": 33, "KeyI": 34, "KeyP": 35, "Enter": 36, "KeyL": 37,
            "KeyJ": 38, "Quote": 39, "KeyK": 40, "Semicolon": 41, "Backslash": 42,
            "Comma": 43, "Slash": 44, "KeyN": 45, "KeyM": 46, "Period": 47,
            "Tab": 48, "Space": 49, "Backquote": 50, "Backspace": 51, "Escape": 53,
            "MetaRight": 54, "MetaLeft": 55, "ShiftLeft": 56, "CapsLock": 57,
            "AltLeft": 58, "ControlLeft": 59, "ShiftRight": 60, "AltRight": 61,
            "ControlRight": 62, "NumLock": 71, "F5": 96, "F6": 97, "F7": 98,
            "F3": 99, "F8": 100, "F9": 101, "F11": 103, "F10": 109,
            "F12": 111, "Home": 115, "PageUp": 116, "Delete": 117, "F4": 118,
            "End": 119, "F2": 120, "PageDown": 121, "F1": 122,
            "ArrowLeft": 123, "ArrowRight": 124, "ArrowDown": 125, "ArrowUp": 126,
        }
        if key not in codes:
            raise InputError("This key is not supported on macOS: " + key)
        previous = set(self.modifiers)
        self.modifiers.add(key) if down else self.modifiers.discard(key)
        try:
            self._post(self.cg.CGEventCreateKeyboardEvent(None, codes[key], down))
        except Exception:
            self.modifiers = previous
            raise

    def close(self) -> None:
        pass


class DesktopBackend:
    """Single-monitor JPEG capture and input, serialized across calling threads.

    An instance belongs to one controlling session. Releasing its input must not
    release keys held by another controller, so the host must allow one controller
    at a time. `_capture`/`_native` are dependency injection seams for isolated tests.
    """

    def __init__(self, max_width: int = 1600, max_height: int = 900, quality: int = 65,
                 *, _capture: Any = None, _native: Any = None, _platform: str | None = None) -> None:
        if type(max_width) is not int or type(max_height) is not int or not 64 <= max_width <= 3840 or not 64 <= max_height <= 2160:
            raise ValueError("capture bounds must be integers within 64..3840 by 64..2160")
        if type(quality) is not int or not 20 <= quality <= 90:
            raise ValueError("JPEG quality must be an integer between 20 and 90")
        self.platform = _platform or sys.platform
        self.max_width, self.max_height, self.quality = max_width, max_height, quality
        self._lock = threading.RLock()
        self._closed = False
        self._held_keys: set[str] = set()
        self._held_buttons: set[str] = set()
        self._capture, self._native = _capture, _native
        try:
            from PIL import Image
            self._image = Image
        except ImportError as exc:
            raise DesktopError("Screen capture requires Pillow; install remote_desktop/requirements.txt") from exc
        if self._capture is None or self._native is None:
            _check_session(self.platform)
        try:
            if self._native is None:
                self._native = (_WindowsInput() if self.platform == "win32" else
                                _MacInput() if self.platform == "darwin" else _X11Input())
            if self._capture is None:
                try:
                    import mss
                    import importlib.metadata
                    version = tuple(int(v) for v in importlib.metadata.version("mss").split(".")[:2])
                    if version < (10, 2):
                        raise DesktopError("mss >= 10.2 is required for capture across worker threads")
                    self._capture = mss.MSS()
                except ImportError as exc:
                    raise DesktopError("Screen capture requires mss; install remote_desktop/requirements.txt") from exc
            self._refresh_monitor()
        except Exception:
            if self._capture is not None:
                self._capture.close()
            if self._native is not None:
                self._native.close()
            raise

    def _refresh_monitor(self) -> None:
        # Refresh display configuration at each frame, including after sleep.
        if hasattr(self._capture, "_monitors"):
            self._capture._monitors = None
        monitors = self._capture.monitors
        if len(monitors) < 2:
            raise DesktopError("No interactive display is available")
        monitor = monitors[1]
        for candidate in monitors[1:]:
            primary = getattr(candidate, "is_primary", None)
            if primary is True or (isinstance(candidate, dict) and candidate.get("is_primary") is True):
                monitor = candidate
                break
        self._monitor = {key: int(getattr(monitor, key) if hasattr(monitor, key) else monitor[key])
                         for key in ("left", "top", "width", "height")}
        if not 1 <= self._monitor["width"] <= 32768 or not 1 <= self._monitor["height"] <= 32768:
            raise DesktopError("Invalid monitor dimensions")

    def _require_open(self) -> None:
        if self._closed:
            raise DesktopError("Desktop backend is closed")

    def capture(self) -> dict[str, Any]:
        with self._lock:
            self._require_open()
            if self.platform == "win32":
                _set_windows_dpi()
            self._refresh_monitor()
            try:
                shot = self._capture.grab(self._monitor)
                frame = self._image.frombytes("RGB", tuple(shot.size), bytes(shot.bgra), "raw", "BGRX")
                frame.thumbnail((self.max_width, self.max_height), self._image.Resampling.LANCZOS)
                encoded = io.BytesIO()
                frame.save(encoded, format="JPEG", quality=self.quality)
                return {"jpeg": encoded.getvalue(), "width": frame.width, "height": frame.height,
                        "source_width": self._monitor["width"], "source_height": self._monitor["height"]}
            except DesktopError:
                raise
            except Exception as exc:
                raise DesktopError("Desktop capture failed: " + str(exc)) from exc

    def input(self, event: dict[str, Any]) -> None:
        with self._lock:
            self._require_open()
            if not isinstance(event, dict) or len(event) > 8:
                raise InputError("input must be a small event object")
            kind = event.get("type")
            if kind == "mouse_move":
                x, y = _normalized(event.get("x"), "x"), _normalized(event.get("y"), "y")
                self._native.move(self._monitor["left"] + round(x * (self._monitor["width"] - 1)),
                                  self._monitor["top"] + round(y * (self._monitor["height"] - 1)))
            elif kind == "mouse_button":
                button = event.get("button")
                if not isinstance(button, str) or button not in ("left", "middle", "right"):
                    raise InputError("button must be left, middle or right")
                down = _boolean(event.get("down"), "down")
                if down or button in self._held_buttons:
                    self._native.button(button, down)
                    self._held_buttons.add(button) if down else self._held_buttons.discard(button)
            elif kind == "wheel":
                self._native.wheel(_wheel(event.get("dx", 0)), _wheel(event.get("dy", 0)))
            elif kind == "key":
                key, down = _key_name(event.get("key")), _boolean(event.get("down"), "down")
                if down or key in self._held_keys:
                    self._native.key(key, down)
                    self._held_keys.add(key) if down else self._held_keys.discard(key)
            elif kind == "text":
                raise InputError("Text/IME injection is not supported; use keyboard events")
            else:
                raise InputError("unsupported input event type")

    def release_all(self) -> None:
        """Try every release even if one OS call fails; retain failed state for retry."""
        with self._lock:
            errors = []
            for key in tuple(self._held_keys):
                try:
                    self._native.key(key, False)
                    self._held_keys.discard(key)
                except Exception as exc:
                    errors.append(str(exc))
            for button in tuple(self._held_buttons):
                try:
                    self._native.button(button, False)
                    self._held_buttons.discard(button)
                except Exception as exc:
                    errors.append(str(exc))
            if errors:
                raise DesktopError("Could not release all remote input: " + "; ".join(errors))

    def capabilities(self) -> dict[str, Any]:
        return {"platform": self.platform, "capture": True, "mouse": True, "keyboard": True,
                "text": False, "single_screen": True, "codec": "jpeg", "max_width": self.max_width,
                "max_height": self.max_height, "quality": self.quality,
                "logged_in_session_only": True, "secure_desktop": False, "native_wayland": False,
                "source_width": self._monitor["width"], "source_height": self._monitor["height"]}

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            try:
                self.release_all()
            finally:
                self._closed = True
                try:
                    self._capture.close()
                finally:
                    self._native.close()
