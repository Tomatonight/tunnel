#!/usr/bin/env python3
"""Exercise the trusted local JSON bridge through a real child process.

Uses an allocator-only configuration, so it needs neither administrator rights
nor a TUN. Network membership/signature tests live in remote_control_tests.
"""
import argparse
import json
import os
from pathlib import Path
import queue
import socket
import subprocess
import tempfile
import threading
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="build/tunnel.exe" if os.name == "nt" else "build-wsl/tunnel")
    args = parser.parse_args()
    binary = Path(args.binary).resolve(strict=True)
    checks = 0
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    with tempfile.TemporaryDirectory(prefix="tunnel-rpc-") as folder:
        folder = Path(folder)
        config = folder / "config.json"
        config.write_text(json.dumps({"address_server": {
            "address": f"127.0.0.1:{port}", "bind_address": f"127.0.0.1:{port}",
            "state_file": str(folder / "leases.json"), "shared_key": "test-only-private-allocator-key",
            "networks": ["10.88.0.0/24"]}}), encoding="utf-8")
        status = folder / "status.json"
        kwargs = {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {}
        process = subprocess.Popen([str(binary), str(config), "--stdio-control", "--status-file", str(status)],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)
        replies = queue.Queue()
        errors = []

        def read_replies():
            for line in iter(process.stdout.readline, b""):
                if line.startswith(b"TUNNEL_RPC "):
                    replies.put(json.loads(line[len(b"TUNNEL_RPC "):]))
                else:
                    replies.put(RuntimeError("unexpected stdout: " + line.decode(errors="replace")))

        def read_errors():
            for line in iter(process.stderr.readline, b""):
                errors.append(line.decode(errors="replace"))

        readers = [threading.Thread(target=read_replies, daemon=True), threading.Thread(target=read_errors, daemon=True)]
        for reader in readers:
            reader.start()

        def send(text):
            process.stdin.write(text.encode("utf-8"))
            process.stdin.flush()

        def response():
            value = replies.get(timeout=8)
            if isinstance(value, Exception):
                raise value
            return value

        def rpc(value):
            send(json.dumps(value, ensure_ascii=True) + "\n")
            return response()

        try:
            # Partial commands must not block the single protocol event loop.
            send('{"id":"fragmented",')
            deadline = time.monotonic() + 8
            while not status.exists() and time.monotonic() < deadline:
                if process.poll() is not None:
                    raise AssertionError("core exited: " + "".join(errors))
                time.sleep(.05)
            assert status.exists()
            checks += 1
            if os.name != "nt" and Path(f"/proc/{process.pid}/task").exists():
                assert len(list(Path(f"/proc/{process.pid}/task").iterdir())) == 1
                checks += 1
            send('"method":"remote_info"}\r\n')
            info = response()
            assert info["id"] == "fragmented" and info["ok"] and info["result"]["networks"] == []
            assert info["result"]["remote_desktop"]["enabled"] is False
            checks += 2
            failed = rpc({"id": 2, "method": "remote_sign", "network": "10.88.0.0/24", "payload": "aa"})
            assert failed == {"id": 2, "ok": False, "error": "inactive_network"}
            checks += 1
            send('{"id":3,"id":4,"method":"remote_info"}\n')
            assert response()["error"] == "invalid_request"
            checks += 1
            assert rpc({"id": 5, "method": "unexpected"}) == {"id": 5, "ok": False, "error": "unknown_method"}
            checks += 1
            send("x" * 18000 + "STOP\n")
            assert rpc({"id": 6, "method": "remote_info"})["id"] == 6
            checks += 1
            send('{"id":60,"method":"remote_info","junk":"' + "x" * 18000 + '"}\n')
            assert response() == {"id": None, "ok": False, "error": "request_too_large"}
            checks += 1
            send(' \t{"id":61,"method":"remote_info"}\n')
            assert response()["id"] == 61
            checks += 1
            send('{"id":7,"method":"remote_info","nested":' + "[" * 16 + "0" + "]" * 16 + "}\n")
            assert response()["error"] == "invalid_request"
            checks += 1
            send('{"id":8,"method":"remote_info"}\n{"id":9,"method":"remote_info"}\n')
            assert [response()["id"], response()["id"]] == [8, 9]
            checks += 1
            assert rpc({"id": "中文设备", "method": "remote_info"})["id"] == "中文设备"
            checks += 1
            send("STOP\n")
            assert process.wait(timeout=8) == 0
            checks += 1
            for reader in readers:
                reader.join(timeout=2)
            assert "test-only-private-allocator-key" not in "".join(errors)
            assert json.loads(status.read_text(encoding="utf-8"))["running"] is False
            checks += 2
        finally:
            if process.stdin and not process.stdin.closed:
                process.stdin.close()
            if process.poll() is None:
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            for reader in readers:
                reader.join(timeout=2)
            process.stdout.close()
            process.stderr.close()
    print(f"Remote stdio tests: {checks} checks passed")


if __name__ == "__main__":
    main()
