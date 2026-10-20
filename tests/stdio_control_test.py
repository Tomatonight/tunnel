#!/usr/bin/env python3
"""Real-TUN lifecycle tests for the optional parent stdin control pipe.

Linux/WSL: sudo python3 tests/stdio_control_test.py --binary build-wsl/tunnel
Windows: administrator Python tests/stdio_control_test.py --binary build/tunnel.exe
Linux operations stay inside one newly created network namespace. Windows uses
a temporary Wintun adapter and checks that its narrow test subnet is unused.
No peers, extra control listener, host default route or firewall rule are added.
"""
import argparse
import ctypes
import ipaddress
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time


def run(*args, check=True):
    options = {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {}
    result = subprocess.run(list(map(str, args)), capture_output=True, text=True,
                            timeout=20, **options)
    if check and result.returncode:
        raise RuntimeError(f"command failed: {args}\n{result.stdout}\n{result.stderr}")
    return result


def main():
    windows = os.name == "nt"
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="build/tunnel.exe" if windows else "build-wsl/tunnel")
    parser.add_argument("--work", default="build/stdio-tests" if windows else "build-wsl/stdio-tests")
    args = parser.parse_args()
    if (windows and not ctypes.windll.shell32.IsUserAnAdmin()) or (not windows and os.geteuid()):
        raise SystemExit("This real-TUN test requires administrator/root privileges.")
    binary = Path(args.binary).resolve(strict=True)
    work = Path(args.work).resolve()
    work.mkdir(parents=True, exist_ok=True)
    namespace = "tc" + str(os.getpid())
    adapter = "TnlCtl" + str(os.getpid()) if windows else "overlay0"
    subnet = ipaddress.IPv4Network((int(ipaddress.IPv4Address("198.19.0.0")) + 4 * (os.getpid() % 16384), 30))
    if windows:
        routes = json.loads(run("powershell.exe", "-NoProfile", "-Command",
            "ConvertTo-Json -Compress -InputObject @(Get-NetRoute -AddressFamily IPv4 | Select-Object -ExpandProperty DestinationPrefix)").stdout)
        for prefix in routes:
            existing = ipaddress.IPv4Network(prefix, strict=False)
            if existing.prefixlen and existing.overlaps(subnet):
                raise SystemExit(f"Test subnet {subnet} overlaps an existing route {prefix}; no changes made.")
    config = work / "config.json"
    # Reserve a loopback port while choosing it; this node has no peers/listener.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    config.write_text(json.dumps({"device_backend": "tun", "tun_mtu": 1280, "transport_mtu": 1500,
        "listen": {"enabled": False, "address": f"127.0.0.1:{port}",
                   "bind_address": f"127.0.0.1:{port}",
                   "networks": [{"tunnel": str(subnet), "tunnel_ip": str(subnet.network_address + 1)}]},
        "peers": []}), encoding="utf-8")
    made_namespace = False
    active = None
    passed = []

    def adapter_exists():
        if windows:
            return run("powershell.exe", "-NoProfile", "-Command",
                f"if (Get-NetAdapter -Name '{adapter}' -ErrorAction SilentlyContinue) {{ exit 0 }} else {{ exit 1 }}",
                check=False).returncode == 0
        return run("ip", "-n", namespace, "link", "show", "dev", adapter, check=False).returncode == 0

    def state(path):
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError, PermissionError):
            return {}

    def wait(predicate, label, process=None, timeout=15):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if predicate():
                return
            if process is not None and process.poll() is not None:
                raise AssertionError(f"process exited {process.returncode} while waiting for {label}")
            time.sleep(.05)
        raise AssertionError("timeout: " + label)

    def scenario(label, action, controlled=True):
        nonlocal active
        status = work / (label + ".status.json")
        status.unlink(missing_ok=True)
        log_path = work / (label + ".log")
        command = [str(binary), str(config), "--tun-name", adapter,
                   "--status-file", str(status), "--run-for", "20" if controlled else ("15" if windows else "3")]
        if controlled:
            command.append("--stdio-control")
        if not windows:
            command = ["ip", "netns", "exec", namespace] + command
        options = {"creationflags": subprocess.CREATE_NO_WINDOW} if windows else {}
        with log_path.open("wb", buffering=0) as log:
            active = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=log, stderr=log, **options)
            wait(lambda: state(status).get("running") is True, label + " startup", active)
            assert adapter_exists(), "real TUN adapter was not created"
            if not windows:
                assert len(list(Path(f"/proc/{active.pid}/task").iterdir())) == 1, "unexpected extra protocol thread"
            action(active, status)
            # Windows Get-NetAdapter can spend several seconds initializing
            # CIM; do not let that exhaust the disabled-control deadline.
            code = active.wait(timeout=20 if not controlled and windows else 8)
            if active.stdin and not active.stdin.closed:
                active.stdin.close()
            assert code == 0, log_path.read_text(encoding="utf-8", errors="replace")
            assert state(status).get("running") is False, "final status was not updated"
            wait(lambda: not adapter_exists(), label + " adapter cleanup")
            active = None
        passed.append(label)
        print("PASS:", label, flush=True)
        return log_path.read_text(encoding="utf-8", errors="replace")

    def fragmented_stop(process, status):
        process.stdin.write(b"ST")
        process.stdin.flush()
        old = status.stat().st_mtime_ns
        wait(lambda: status.stat().st_mtime_ns != old, "event loop during partial command", process)
        assert process.poll() is None, "partial command stopped the process"
        process.stdin.write(b"OP\n")
        process.stdin.flush()

    def lowercase_stop(process, _):
        process.stdin.write(b"stop\r\n")
        process.stdin.flush()

    def close_pipe(process, _):
        process.stdin.close()

    def invalid_commands(process, status):
        # STOP embedded in an overlong line must not be accepted, and malformed
        # bytes must not poison parsing of a later, valid complete command.
        process.stdin.write(b"X" * 8192 + b"STOP\nSTOPJUNK\n\xffbroken\n\n")
        process.stdin.flush()
        time.sleep(.9)
        assert process.poll() is None, "invalid command stopped the process"
        old = status.stat().st_mtime_ns
        wait(lambda: status.stat().st_mtime_ns != old, "monitor after invalid input", process)
        process.stdin.write(b"STOP\n")
        process.stdin.flush()

    def disabled(process, _):
        process.stdin.write(b"STOP\n")
        process.stdin.flush()
        process.stdin.close()
        time.sleep(.7)
        assert process.poll() is None, "stdin was consumed without --stdio-control"

    try:
        if not windows:
            run("ip", "netns", "add", namespace)
            made_namespace = True
            run("ip", "-n", namespace, "link", "set", "lo", "up")
        scenario("fragmented_stop_clean_exit", fragmented_stop)
        scenario("lowercase_crlf_stop_clean_exit", lowercase_stop)
        scenario("parent_pipe_eof_clean_exit", close_pipe)
        logs = scenario("invalid_and_oversized_commands_are_bounded", invalid_commands)
        assert "invalid command" in logs, "invalid command feedback missing"
        assert logs.count("invalid command") <= 4, "invalid input caused unbounded log output"
        scenario("disabled_control_ignores_stdin", disabled, controlled=False)
        report = {"platform": sys.platform, "passed": passed, "count": len(passed)}
    except Exception as error:
        report = {"platform": sys.platform, "passed": passed, "error": str(error)}
        raise
    finally:
        if active and active.poll() is None:
            if active.stdin and not active.stdin.closed:
                active.stdin.close()
            try:
                active.wait(timeout=5)
            except subprocess.TimeoutExpired:
                active.terminate()
                try:
                    active.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    active.kill()
                    active.wait(timeout=5)
        if made_namespace:
            run("ip", "netns", "delete", namespace)
        (work / "results.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"All {len(passed)} stdin control tests passed.", flush=True)


if __name__ == "__main__":
    main()
