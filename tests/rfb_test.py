import socket
import struct
from pathlib import Path
import sys
import threading
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from remote_desktop.rfb import RfbSession, WebSocketStream, _compact_length, _key_name


class Backend:
    def __init__(self):
        self.events = []
        self.closed = False
        self.size = (2304, 1440)

    def capture(self):
        # Common high-resolution desktop dimensions must pass through RFB
        # without an artificial 2048-pixel width cap.
        return {"jpeg": b"\xff\xd8test\xff\xd9", "width": self.size[0], "height": self.size[1]}

    def set_capture_bounds(self, width, height):
        self.size = (width, height)

    def input(self, event):
        self.events.append(event)

    def release_all(self):
        pass

    def close(self):
        self.closed = True


def recv_exact(sock, size):
    result = bytearray()
    while len(result) < size:
        result.extend(sock.recv(size - len(result)))
    return bytes(result)


class RfbTests(unittest.TestCase):
    def test_compact_lengths(self):
        self.assertEqual(_compact_length(0), b"\x00")
        self.assertEqual(_compact_length(127), b"\x7f")
        self.assertEqual(_compact_length(128), b"\x80\x01")
        self.assertEqual(_compact_length(16384), b"\x80\x80\x01")

    def test_key_mapping(self):
        self.assertEqual(_key_name(ord("A")), "KeyA")
        self.assertEqual(_key_name(0xff51), "ArrowLeft")
        self.assertEqual(_key_name(0xff0d), "Enter")
        self.assertIsNone(_key_name(0x1008ff12))

    def test_websocket_handshake_token_and_subprotocol(self):
        server, client = socket.socketpair()
        errors = []

        def run():
            try:
                WebSocketStream(server).handshake(expected_path="/vnc", expected_token="abc")
            except Exception as error:
                errors.append(error)

        thread = threading.Thread(target=run)
        thread.start()
        client.sendall(
            b"GET /vnc?token=abc HTTP/1.1\r\n"
            b"Host: localhost\r\nUpgrade: websocket\r\n"
            b"Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
        )
        response = bytearray()
        while b"\r\n\r\n" not in response:
            response.extend(client.recv(4096))
        self.assertIn(b"101 Switching Protocols", response)
        self.assertNotIn(b"Sec-WebSocket-Protocol", response)
        client.close()
        server.close()
        thread.join(2)
        self.assertFalse(errors)

    def test_rfb_handshake_tight_frame_and_input(self):
        server, client = socket.socketpair()
        client.settimeout(3)
        backend = Backend()
        errors = []
        session = RfbSession(server, lambda: backend)

        def run():
            try:
                session.serve()
            except EOFError:
                pass
            except Exception as error:
                errors.append(error)
            finally:
                session.close()

        thread = threading.Thread(target=run)
        thread.start()
        self.assertEqual(recv_exact(client, 12), b"RFB 003.008\n")
        client.sendall(b"RFB 003.008\n")
        self.assertEqual(recv_exact(client, 2), b"\x01\x01")
        client.sendall(b"\x01")
        self.assertEqual(recv_exact(client, 4), b"\x00\x00\x00\x00")
        client.sendall(b"\x01")

        width, height = struct.unpack("!HH", recv_exact(client, 4))
        self.assertEqual((width, height), (2304, 1440))
        recv_exact(client, 16)
        name_length = struct.unpack("!I", recv_exact(client, 4))[0]
        self.assertEqual(recv_exact(client, name_length), b"Tunnel Desktop")

        client.sendall(b"\x02\x00\x00\x01\x00\x00\x00\x07")
        client.sendall(struct.pack("!BBBBI", 4, 1, 0, 0, ord("A")))
        client.sendall(struct.pack("!BBHH", 5, 0, 20, 30))
        client.sendall(struct.pack("!BBHHHH", 3, 0, 0, 0, 2304, 1440))

        self.assertEqual(recv_exact(client, 1), b"\x00")
        recv_exact(client, 3)
        x, y, w, h, encoding = struct.unpack("!HHHHI", recv_exact(client, 12))
        self.assertEqual((x, y, w, h, encoding), (0, 0, 2304, 1440, 0xfffffecc))
        screen_count = recv_exact(client, 1)[0]
        self.assertEqual(screen_count, 1)
        recv_exact(client, 3 + 16)
        x, y, w, h, encoding = struct.unpack("!HHHHI", recv_exact(client, 12))
        self.assertEqual((x, y, w, h, encoding), (0, 0, 2304, 1440, 7))
        self.assertEqual(recv_exact(client, 1), b"\x90")
        size = recv_exact(client, 1)[0]
        self.assertEqual(recv_exact(client, size), b"\xff\xd8test\xff\xd9")

        # A noVNC resize request changes the capture bound and is acknowledged
        # with a new ExtendedDesktopSize pseudo-rectangle.
        client.sendall(struct.pack("!BBHHBBIHHHHI", 251, 0, 1200, 800, 1, 0,
                                   0, 0, 0, 1200, 800, 0))
        client.sendall(struct.pack("!BBHHHH", 3, 1, 0, 0, 1200, 800))
        self.assertEqual(recv_exact(client, 1), b"\x00")
        recv_exact(client, 3)
        x, y, w, h, encoding = struct.unpack("!HHHHI", recv_exact(client, 12))
        self.assertEqual((x, y, w, h, encoding), (1, 0, 1200, 800, 0xfffffecc))
        self.assertEqual(recv_exact(client, 1), b"\x01")
        recv_exact(client, 3 + 16)
        x, y, w, h, encoding = struct.unpack("!HHHHI", recv_exact(client, 12))
        self.assertEqual((x, y, w, h, encoding), (0, 0, 1200, 800, 7))
        self.assertEqual(recv_exact(client, 1), b"\x90")
        size = recv_exact(client, 1)[0]
        self.assertEqual(recv_exact(client, size), b"\xff\xd8test\xff\xd9")

        self.assertIn({"type": "key", "key": "KeyA", "down": True}, backend.events)
        self.assertIn({"type": "mouse_move", "x": 20 / 2303, "y": 30 / 1439}, backend.events)
        client.close()
        thread.join(2)
        server.close()
        self.assertFalse(thread.is_alive())
        self.assertFalse(errors)
        self.assertTrue(backend.closed)


if __name__ == "__main__":
    unittest.main()
