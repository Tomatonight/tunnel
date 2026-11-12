"""Small RFB 3.8 server used by the Tunnel remote desktop gateway.

The gateway keeps authentication and peer authorization in :mod:`runtime`.
This module translates an already-authorized byte stream into the RFB
protocol expected by noVNC.  Frames use Tight JPEG encoding.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import socket
import struct
import threading
import time
from urllib.parse import parse_qs, urlsplit
from typing import Callable, Optional

RFB_VERSION = b"RFB 003.008\n"
TIGHT_ENCODING = 7
EXTENDED_DESKTOP_SIZE = -308
# Tight's JPEG selector occupies the high nibble of the control byte.  The
# low nibble is reserved for zlib stream resets.
TIGHT_JPEG = 0x90
# noVNC sends the next FramebufferUpdateRequest as soon as the previous
# response is decoded.  Keep the capture cadence bounded even when the
# browser or network causes duplicate requests to arrive faster than the
# desktop can change.
FRAME_INTERVAL = 1.0 / 60.0


def _read_exact(sock, size: int) -> bytes:
    if size < 0 or size > 16 * 1024 * 1024:
        raise ValueError("Invalid RFB message size")
    result = bytearray()
    while len(result) < size:
        chunk = sock.recv(size - len(result))
        if not chunk:
            raise EOFError("RFB connection closed")
        result.extend(chunk)
    return bytes(result)


def _compact_length(size: int) -> bytes:
    if not 0 <= size < 1 << 22:
        raise ValueError("RFB rectangle is too large")
    first = size & 0x7f
    size >>= 7
    if not size:
        return bytes((first,))
    first |= 0x80
    second = size & 0x7f
    size >>= 7
    if not size:
        return bytes((first, second))
    return bytes((first, second | 0x80, size & 0xff))


def _key_name(keysym: int) -> Optional[str]:
    special = {
        0xff08: "Backspace", 0xff09: "Tab", 0xff0d: "Enter", 0xff1b: "Escape",
        0xff50: "Home", 0xff51: "ArrowLeft", 0xff52: "ArrowUp",
        0xff53: "ArrowRight", 0xff54: "ArrowDown", 0xff55: "PageUp",
        0xff56: "PageDown", 0xff57: "End", 0xffff: "Delete",
        0xffbe: "F1", 0xffbf: "F2", 0xffc0: "F3", 0xffc1: "F4",
        0xffc2: "F5", 0xffc3: "F6", 0xffc4: "F7", 0xffc5: "F8",
        0xffc6: "F9", 0xffc7: "F10", 0xffc8: "F11", 0xffc9: "F12",
        0xffe1: "ShiftLeft", 0xffe2: "ShiftRight", 0xffe3: "ControlLeft",
        0xffe4: "ControlRight", 0xffe5: "CapsLock", 0xffe7: "MetaLeft",
        0xffe8: "MetaRight", 0xffe9: "AltLeft", 0xffea: "AltRight",
        0xff13: "Pause", 0xff14: "ScrollLock", 0xff61: "PrintScreen",
        0xff7f: "NumLock", 0x20: "Space",
    }
    if keysym in special:
        return special[keysym]
    if 0x41 <= keysym <= 0x5a:
        return "Key" + chr(keysym)
    if 0x61 <= keysym <= 0x7a:
        return "Key" + chr(keysym - 0x20)
    if 0x30 <= keysym <= 0x39:
        return "Digit" + chr(keysym)
    return {
        0x2d: "Minus", 0x3d: "Equal", 0x5b: "BracketLeft", 0x5d: "BracketRight",
        0x5c: "Backslash", 0x3b: "Semicolon", 0x27: "Quote", 0x60: "Backquote",
        0x2c: "Comma", 0x2e: "Period", 0x2f: "Slash",
    }.get(keysym)


class WebSocketStream:
    """Turn one RFC 6455 binary WebSocket into a socket-like stream."""

    def __init__(self, sock):
        self.sock = sock
        self.pending = bytearray()
        self.raw_pending = bytearray()
        self.closed = False
        self.send_lock = threading.Lock()

    def handshake(self, expected_path=None, expected_token=None):
        request = bytearray()
        while b"\r\n\r\n" not in request:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise EOFError("WebSocket handshake closed")
            request.extend(chunk)
            if len(request) > 64 * 1024:
                raise ValueError("WebSocket handshake too large")
        header_end = request.index(b"\r\n\r\n") + 4
        self.raw_pending.extend(request[header_end:])
        lines = bytes(request[:header_end]).split(b"\r\n")
        parts = lines[0].decode("latin1").split(" ")
        if len(parts) != 3 or parts[0] != "GET":
            raise ValueError("Invalid WebSocket request")
        target = urlsplit(parts[1])
        if expected_path is not None and target.path != expected_path:
            raise ValueError("Invalid WebSocket path")
        if expected_token is not None and parse_qs(target.query).get("token", [None])[0] != expected_token:
            raise ValueError("Invalid WebSocket token")
        headers = {}
        for line in lines[1:]:
            if not line:
                break
            if b":" in line:
                name, value = line.split(b":", 1)
                headers[name.decode("latin1").strip().lower()] = value.decode("latin1").strip()
        key = headers.get("sec-websocket-key")
        if not key or headers.get("upgrade", "").lower() != "websocket":
            raise ValueError("Invalid WebSocket handshake")
        accept = base64.b64encode(hashlib.sha1(
            (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")
        ).digest()).decode("ascii")
        protocols = [item.strip() for item in headers.get("sec-websocket-protocol", "").split(",")]
        selected = "\r\nSec-WebSocket-Protocol: binary" if "binary" in protocols else ""
        response = ("HTTP/1.1 101 Switching Protocols\r\n"
                    "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                    "Sec-WebSocket-Accept: " + accept + selected + "\r\n\r\n").encode("ascii")
        self.sock.sendall(response)

    def _read_raw(self, size):
        if self.raw_pending:
            data = bytes(self.raw_pending[:size])
            del self.raw_pending[:size]
            if len(data) == size:
                return data
            return data + _read_exact(self.sock, size - len(data))
        return _read_exact(self.sock, size)

    def _frame(self):
        first, second = self._read_raw(2)
        opcode = first & 0x0f
        length = second & 0x7f
        masked = bool(second & 0x80)
        if length == 126:
            length = struct.unpack("!H", self._read_raw(2))[0]
        elif length == 127:
            length = struct.unpack("!Q", self._read_raw(8))[0]
        if length > 16 * 1024 * 1024:
            raise ValueError("WebSocket frame too large")
        mask = self._read_raw(4) if masked else b""
        payload = bytearray(self._read_raw(length))
        if masked:
            for index in range(length):
                payload[index] ^= mask[index % 4]
        return bool(first & 0x80), opcode, bytes(payload)

    def recv(self, size: int) -> bytes:
        while len(self.pending) < size and not self.closed:
            fin, opcode, payload = self._frame()
            if not fin:
                raise ValueError("Fragmented WebSocket frames are unsupported")
            if opcode == 0x8:
                self.closed = True
                self.send_frame(b"", 0x8)
                break
            if opcode == 0x9:
                self.send_frame(payload, 0xA)
                continue
            if opcode != 0x2:
                raise ValueError("Expected a binary WebSocket frame")
            self.pending.extend(payload)
        data = bytes(self.pending[:size])
        del self.pending[:size]
        return data

    def recv_message(self):
        """Read one complete WebSocket application message.

        Browser clients normally send binary RFB data in one frame, but the
        bridge accepts continuation frames and handles ping/pong/close
        control frames so a slow or large clipboard message cannot corrupt
        the byte stream.
        """
        parts = []
        message_opcode = None
        while not self.closed:
            fin, opcode, payload = self._frame()
            if opcode == 0x8:
                self.closed = True
                try:
                    self.send_frame(payload[:125], 0x8)
                except OSError:
                    pass
                return None, b""
            if opcode == 0x9:
                self.send_frame(payload, 0xA)
                continue
            if opcode == 0xA:
                continue
            if opcode == 0x0:
                if message_opcode is None:
                    raise ValueError("Unexpected WebSocket continuation")
            elif opcode in (0x1, 0x2):
                if message_opcode is not None:
                    raise ValueError("WebSocket message is already in progress")
                message_opcode = opcode
            else:
                raise ValueError("Unsupported WebSocket opcode")
            parts.append(payload)
            if fin:
                return message_opcode, b"".join(parts)
        return None, b""

    def send_frame(self, payload: bytes, opcode: int = 0x2):
        length = len(payload)
        if length < 126:
            header = bytes((0x80 | opcode, length))
        elif length < 65536:
            header = bytes((0x80 | opcode, 126)) + struct.pack("!H", length)
        else:
            header = bytes((0x80 | opcode, 127)) + struct.pack("!Q", length)
        with self.send_lock:
            self.sock.sendall(header + payload)

    def sendall(self, data: bytes):
        self.send_frame(data)

    def close(self):
        self.closed = True
        try:
            self.send_frame(b"", 0x8)
        except OSError:
            pass


def close_socket(sock):
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except (OSError, AttributeError):
        pass
    try:
        sock.close()
    except (OSError, AttributeError):
        pass


class WebSocketBridge:
    """Loopback noVNC WebSocket endpoint for an authenticated RFB stream."""

    def __init__(self, tunnel_sock, stop_event):
        self.tunnel_sock = tunnel_sock
        self.stop_event = stop_event
        self.token = secrets.token_urlsafe(24)
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.listener.settimeout(0.5)
        self.error = None
        self.connected = threading.Event()
        self.thread = threading.Thread(target=self._run, name="tunnel-vnc-websocket", daemon=True)

    @property
    def url(self):
        return "ws://127.0.0.1:%d/vnc/%s" % (self.listener.getsockname()[1], self.token)

    def start(self):
        self.thread.start()
        return self.url

    def _run(self):
        client = None
        try:
            while not self.stop_event.is_set():
                try:
                    client, _ = self.listener.accept()
                except socket.timeout:
                    continue
                client.settimeout(2)
                stream = WebSocketStream(client)
                stream.handshake(expected_path="/vnc/" + self.token)
                self.connected.set()
                self._relay(stream)
                return
        except Exception as error:
            if not self.stop_event.is_set():
                self.error = str(error)
        finally:
            self.stop_event.set()
            close_socket(client)
            close_socket(self.listener)

    def _relay(self, stream):
        self.tunnel_sock.settimeout(1)
        stream.sock.settimeout(1)
        errors = []

        def browser_to_tunnel():
            try:
                while not self.stop_event.is_set():
                    try:
                        opcode, payload = stream.recv_message()
                    except socket.timeout:
                        continue
                    if opcode is None:
                        return
                    if opcode != 0x2:
                        raise ValueError("noVNC must use binary WebSocket frames")
                    if payload:
                        self.tunnel_sock.sendall(payload)
            except Exception as error:
                errors.append(error)
            finally:
                self.stop_event.set()

        def tunnel_to_browser():
            try:
                while not self.stop_event.is_set():
                    try:
                        payload = self.tunnel_sock.recv(64 * 1024)
                    except socket.timeout:
                        continue
                    if not payload:
                        return
                    stream.send_frame(payload)
            except Exception as error:
                errors.append(error)
            finally:
                self.stop_event.set()

        outbound = threading.Thread(target=browser_to_tunnel, daemon=True)
        inbound = threading.Thread(target=tunnel_to_browser, daemon=True)
        outbound.start(); inbound.start()
        while outbound.is_alive() and inbound.is_alive() and not self.stop_event.wait(0.1):
            pass
        self.stop_event.set()
        close_socket(self.tunnel_sock)
        close_socket(stream.sock)
        outbound.join(2); inbound.join(2)


class RfbSession:
    """Serve one authorized RFB connection using a DesktopBackend."""

    def __init__(self, sock, backend_factory: Callable[[], object], *, server_name="Tunnel Desktop", allow_input=True):
        self.sock = sock
        self.backend_factory = backend_factory
        self.server_name = server_name[:256]
        self.backend = None
        self.width = 0
        self.height = 0
        self.button_mask = 0
        self.allow_input = bool(allow_input)
        self._frame = None
        self._frame_at = 0.0
        self._frame_sent = False
        self._force_next_frame = False
        # Advertise the resize capability with the first update. noVNC can
        # then send SetDesktopSize whenever its window or fullscreen viewport
        # changes.
        self._size_update_pending = True
        self._size_update_x = 0
        self._size_update_y = 0

    def _send_server_init(self):
        # Capture once during the handshake and retain it for the first
        # framebuffer request.  This avoids a second full-screen capture
        # immediately after noVNC receives ServerInit.
        frame, _fresh = self._capture_frame(force=True)
        self.width, self.height = frame["width"], frame["height"]
        pixel_format = struct.pack("!BBBBHHHBBB3x", 32, 24, 0, 1,
                                   255, 255, 255, 16, 8, 0)
        name = self.server_name.encode("utf-8")
        self.sock.sendall(struct.pack("!HH", self.width, self.height) +
                          pixel_format + struct.pack("!I", len(name)) + name)
        return frame

    def _capture_frame(self, *, force=False):
        """Return the latest frame, capturing at most once per refresh tick."""
        now = time.monotonic()
        force = force or self._force_next_frame
        if not force and self._frame is not None and now - self._frame_at < FRAME_INTERVAL:
            return self._frame, False
        self._force_next_frame = False
        self._frame = self.backend.capture()
        self._frame_at = time.monotonic()
        size = (self._frame["width"], self._frame["height"])
        if self.width and size != (self.width, self.height):
            self._size_update_pending = True
        self.width, self.height = size
        return self._frame, True

    def _send_empty_update(self):
        # A zero-rectangle incremental update is a valid RFB response and
        # prevents resending an unchanged multi-megabyte JPEG while the
        # refresh interval has not elapsed.
        self.sock.sendall(struct.pack("!BBH", 0, 0, 0))

    def _send_frame(self, frame):
        width, height, jpeg = frame["width"], frame["height"], frame["jpeg"]
        rectangles = []
        if self._size_update_pending:
            # ExtendedDesktopSize layout/resize response. x=0 advertises the
            # initial layout; x=1,y=0 acknowledges SetDesktopSize success.
            rectangles.append(struct.pack("!HHHHI", self._size_update_x, self._size_update_y,
                                          width, height, EXTENDED_DESKTOP_SIZE & 0xffffffff) +
                              struct.pack("!B3xIHHHHI", 1, 0, 0, 0, width, height, 0))
        rectangle = struct.pack("!HHHHI", 0, 0, width, height, TIGHT_ENCODING)
        rectangle += bytes((TIGHT_JPEG,)) + _compact_length(len(jpeg)) + jpeg
        rectangles.append(rectangle)
        self.sock.sendall(struct.pack("!BBH", 0, 0, len(rectangles)) + b"".join(rectangles))
        self._size_update_pending = False

    def _set_desktop_size(self, width: int, height: int) -> None:
        """Apply a noVNC viewport request to the next captured frame."""
        width = max(64, min(3840, int(width)))
        height = max(64, min(2160, int(height)))
        setter = getattr(self.backend, "set_capture_bounds", None)
        if setter is not None:
            setter(width, height)
        self._force_next_frame = True
        self._size_update_pending = True
        # noVNC uses x=1,y=0 as the successful response to its resize request;
        # x=0 is reserved for the initial screen-layout advertisement.
        self._size_update_x, self._size_update_y = 1, 0

    def _input_key(self, keysym: int, down: bool):
        if not self.allow_input:
            return
        key = _key_name(keysym)
        if key:
            self.backend.input({"type": "key", "key": key, "down": down})

    def _input_pointer(self, mask: int, x: int, y: int):
        if not self.allow_input:
            return
        x = max(0, min(self.width - 1, x))
        y = max(0, min(self.height - 1, y))
        self.backend.input({"type": "mouse_move",
                            "x": x / max(1, self.width - 1),
                            "y": y / max(1, self.height - 1)})
        previous = self.button_mask
        for bit, button in ((1, "left"), (2, "middle"), (4, "right")):
            if bool(mask & bit) != bool(previous & bit):
                self.backend.input({"type": "mouse_button", "button": button,
                                    "down": bool(mask & bit)})
        if mask & 8:
            self.backend.input({"type": "wheel", "dx": 0, "dy": 1})
        elif mask & 16:
            self.backend.input({"type": "wheel", "dx": 0, "dy": -1})
        self.button_mask = mask & 0x07

    def serve(self):
        self.sock.sendall(RFB_VERSION)
        client_version = _read_exact(self.sock, 12)
        if not client_version.startswith(b"RFB 003."):
            raise ValueError("Unsupported RFB protocol version")
        self.sock.sendall(bytes((1, 1)))  # one security type, None
        if _read_exact(self.sock, 1) != b"\x01":
            raise ValueError("RFB authentication was rejected")
        self.sock.sendall(struct.pack("!I", 0))
        _read_exact(self.sock, 1)  # ClientInit shared flag
        self.backend = self.backend_factory()
        self._send_server_init()
        while True:
            message_type = _read_exact(self.sock, 1)[0]
            if message_type == 0:
                _read_exact(self.sock, 3 + 16)
            elif message_type == 2:
                _read_exact(self.sock, 1)
                count = struct.unpack("!H", _read_exact(self.sock, 2))[0]
                _read_exact(self.sock, count * 4)
            elif message_type == 3:
                incremental, _x, _y, width, height = struct.unpack(
                    "!BHHHH", _read_exact(self.sock, 9))
                if width and height:
                    frame, fresh = self._capture_frame()
                    if frame is not None and (not incremental or fresh or not self._frame_sent):
                        self._send_frame(frame)
                        self._frame_sent = True
                    else:
                        self._send_empty_update()
            elif message_type == 4:
                down = bool(_read_exact(self.sock, 1)[0])
                _read_exact(self.sock, 2)
                self._input_key(struct.unpack("!I", _read_exact(self.sock, 4))[0], down)
            elif message_type == 5:
                mask, x, y = struct.unpack("!BHH", _read_exact(self.sock, 5))
                self._input_pointer(mask, x, y)
            elif message_type == 6:
                _read_exact(self.sock, 3)
                length = struct.unpack("!I", _read_exact(self.sock, 4))[0]
                if length > 1024 * 1024:
                    raise ValueError("RFB clipboard message too large")
                _read_exact(self.sock, length)
            elif message_type == 251:  # SetDesktopSize
                _read_exact(self.sock, 1)
                width, height = struct.unpack("!HH", _read_exact(self.sock, 4))
                screens = _read_exact(self.sock, 1)[0]
                _read_exact(self.sock, 1)
                if screens > 16:
                    raise ValueError("Too many RFB screens")
                _read_exact(self.sock, screens * 16)
                if not width or not height:
                    raise ValueError("Invalid RFB desktop size")
                self._set_desktop_size(width, height)
            else:
                raise ValueError("Unsupported RFB client message")

    def close(self):
        if self.backend:
            try:
                self.backend.release_all()
            finally:
                self.backend.close()


def serve_websocket(sock, backend_factory, *, server_name="Tunnel Desktop"):
    """Perform a WebSocket handshake and serve a noVNC connection."""
    stream = WebSocketStream(sock)
    stream.handshake()
    session = RfbSession(stream, backend_factory, server_name=server_name)
    try:
        session.serve()
    finally:
        session.close()
        stream.close()
