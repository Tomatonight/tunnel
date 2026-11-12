import socket
import struct
import sys
import unittest
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from remote_runtime_test import DesktopTests, NETWORK, wait_for


def recv_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise EOFError("connection closed")
        data.extend(chunk)
    return bytes(data)


def ws_frame(payload):
    mask = b"test"
    length = len(payload)
    if length < 126:
        header = bytes((0x82, length | 0x80))
    else:
        header = bytes((0x82, 126 | 0x80)) + struct.pack("!H", length)
    encoded = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
    return header + mask + encoded


def ws_payload(sock):
    first, second = recv_exact(sock, 2)
    length = second & 0x7f
    if length == 126:
        length = struct.unpack("!H", recv_exact(sock, 2))[0]
    elif length == 127:
        length = struct.unpack("!Q", recv_exact(sock, 8))[0]
    return first & 0x0f, recv_exact(sock, length)


class RemoteVncTests(DesktopTests):
    def test_rfb_gateway_handshake_frame_and_input(self):
        result = self.client.request("remote_vnc_connect", {
            "address": self.server_core.ip, "tunnel": NETWORK,
            "port": self.port, "permission": "control", "shared_key": self.config["shared_key"]})
        result = wait_for(lambda: self.client.request("remote_state")["viewer"]
                          if self.client.request("remote_state")["viewer"].get("ws_url") else None)
        parts = urlsplit(result["ws_url"])
        sock = socket.create_connection((parts.hostname, parts.port), timeout=3)
        request = (
            "GET " + parts.path + " HTTP/1.1\r\n"
            "Host: " + parts.hostname + "\r\n"
            "Upgrade: websocket\r\nConnection: Upgrade\r\n"
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
        ).encode("ascii")
        sock.sendall(request)
        response = bytearray()
        while b"\r\n\r\n" not in response:
            response.extend(sock.recv(4096))
        self.assertIn(b"101 Switching Protocols", response)

        opcode, version = ws_payload(sock)
        self.assertEqual((opcode, version), (2, b"RFB 003.008\n"))
        sock.sendall(ws_frame(b"RFB 003.008\n"))
        opcode, security = ws_payload(sock)
        self.assertEqual((opcode, security), (2, b"\x01\x01"))
        sock.sendall(ws_frame(b"\x01"))
        self.assertEqual(ws_payload(sock)[1], b"\x00\x00\x00\x00")
        sock.sendall(ws_frame(b"\x01"))
        server_init = ws_payload(sock)[1]
        width, height = struct.unpack("!HH", server_init[:4])
        self.assertEqual((width, height), (64, 32))
        name_length = struct.unpack("!I", server_init[20:24])[0]
        self.assertEqual(server_init[24:24 + name_length], self.server.identity.name.encode())

        sock.sendall(ws_frame(b"\x02\x00\x00\x01\x00\x00\x00\x07"))
        sock.sendall(ws_frame(struct.pack("!BBBBI", 4, 1, 0, 0, ord("A"))))
        sock.sendall(ws_frame(struct.pack("!BBHH", 5, 0, 16, 8)))
        sock.sendall(ws_frame(struct.pack("!BBHHHH", 3, 0, 0, 0, 64, 32)))
        opcode, update = ws_payload(sock)
        self.assertEqual(opcode, 2)
        self.assertEqual(update[:4], b"\x00\x00\x00\x02")
        x, y, w, h, encoding = struct.unpack("!HHHHI", update[4:16])
        self.assertEqual((x, y, w, h, encoding), (0, 0, 64, 32, 0xfffffecc))
        self.assertEqual(update[16], 1)
        tight_offset = 36
        x, y, w, h, encoding = struct.unpack("!HHHHI", update[tight_offset:tight_offset + 12])
        self.assertEqual((x, y, w, h, encoding), (0, 0, 64, 32, 7))
        self.assertEqual(update[tight_offset + 12], 0x90)
        offset, jpeg_size, shift = tight_offset + 13, 0, 0
        while True:
            byte = update[offset]; offset += 1
            jpeg_size |= (byte & 0x7f) << shift
            if not byte & 0x80:
                break
            shift += 7
        jpeg = update[offset:offset + jpeg_size]
        self.assertGreater(jpeg_size, 20)
        self.assertEqual(jpeg[:2], b"\xff\xd8")
        self.assertEqual(jpeg[-2:], b"\xff\xd9")
        wait_for(lambda: self.backends and self.backends[0].events)
        self.assertIn({"type": "key", "key": "KeyA", "down": True}, self.backends[0].events)
        sock.close()


if __name__ == "__main__":
    unittest.main()
