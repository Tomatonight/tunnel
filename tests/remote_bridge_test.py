#!/usr/bin/env python3
"""Exercise CoreBridge with real small OS pipes and concurrent callers.

Only Popen's executable command is substituted. The child, stdin/stdout pipes,
JSON encoder, bridge reader, queues and locks are real. A hard cleanup path kills
the child before joining threads, so regressions cannot hang the test process.
"""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import queue
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock


def fake_core(mode, expected, marker):
    """An intentionally backpressured core used only by this test process."""
    marker = Path(marker)

    def reply(request):
        payload = request.get("payload", "")
        result = {"ticket": request.get("ticket"),
                  "digest": hashlib.sha256(payload.encode("utf-8")).hexdigest(),
                  "padding": "R" * 4096}
        message = {"id": request["id"], "ok": True, "result": result}
        sys.stdout.write("TUNNEL_RPC " + json.dumps(message, separators=(",", ":")) + "\n")
        sys.stdout.flush()

    # Let simultaneous writers fill the small stdin pipe before the first
    # large response. The old shared map/write lock then reliably deadlocks.
    if mode == "echo":
        time.sleep(.15)
    buffered = []
    for line in sys.stdin:
        if line.strip() == "STOP":
            break
        request = json.loads(line)
        if mode in ("batch", "hold") and len(buffered) < expected:
            buffered.append(request)
            if len(buffered) < expected:
                continue
            marker.with_suffix(".ready").write_text(str(expected), encoding="utf-8")
            while not marker.with_suffix(".release").exists():
                time.sleep(.01)
            for pending in buffered:
                reply(pending)
            mode = "echo"
        else:
            reply(request)
        # Keep both directions busy without relying on high CPU load.
        time.sleep(.001)
    return 0


if len(sys.argv) > 1 and sys.argv[1] == "--fake-core":
    raise SystemExit(fake_core(sys.argv[2], int(sys.argv[3]), sys.argv[4]))

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from remote_desktop.core import CoreBridge
import remote_desktop.core as bridge_module

PIPE_OBSERVATIONS = []


def configure_small_pipes(process):
    if os.name == "nt":
        import msvcrt
        from ctypes import wintypes
        query = ctypes.WinDLL("kernel32", use_last_error=True).GetNamedPipeInfo
        query.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD),
                          ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD),
                          ctypes.POINTER(wintypes.DWORD)]
        query.restype = wintypes.BOOL
        result = {}
        for name, stream in (("stdin", process.stdin), ("stdout", process.stdout)):
            output_size = wintypes.DWORD()
            input_size = wintypes.DWORD()
            if not query(msvcrt.get_osfhandle(stream.fileno()), None,
                         ctypes.byref(output_size), ctypes.byref(input_size), None):
                raise ctypes.WinError(ctypes.get_last_error())
            result[name] = max(output_size.value, input_size.value)
        # Windows Popen uses real CreatePipe anonymous pipes, normally 4 KiB.
        if not all(0 < size <= 65536 for size in result.values()):
            raise AssertionError("Unexpectedly large or unknown Windows pipe size: " + repr(result))
    else:
        import fcntl
        result = {}
        for name, stream in (("stdin", process.stdin), ("stdout", process.stdout)):
            fcntl.fcntl(stream.fileno(), fcntl.F_SETPIPE_SZ, 4096)
            result[name] = fcntl.fcntl(stream.fileno(), fcntl.F_GETPIPE_SZ)
            if result[name] != 4096:
                raise AssertionError("Could not configure a 4 KiB test pipe")
    PIPE_OBSERVATIONS.append(result)


class Harness:
    def __init__(self, folder, mode="echo", expected=0):
        self.marker = Path(folder) / "child"
        self.threads = []
        actual_popen = subprocess.Popen

        def start_child(_command, **kwargs):
            process = actual_popen([sys.executable, "-u", str(Path(__file__).resolve()),
                                   "--fake-core", mode, str(expected), str(self.marker)], **kwargs)
            try:
                configure_small_pipes(process)
            except BaseException:
                process.kill()
                process.wait(timeout=3)
                process.stdin.close()
                process.stdout.close()
                raise
            return process

        with mock.patch.object(bridge_module.subprocess, "Popen", side_effect=start_child):
            self.bridge = CoreBridge(sys.executable, "unused.json", "unused-status.json", Path(folder) / "core.log")

    def worker(self, function):
        thread = threading.Thread(target=function, daemon=True)
        self.threads.append(thread)
        thread.start()
        return thread

    def wait(self, predicate, timeout=4):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return
            if self.bridge.process.poll() is not None:
                raise AssertionError("Fake core exited unexpectedly: " + repr(list(self.bridge.logs)))
            time.sleep(.01)
        raise AssertionError("Timed out waiting for child/bridge state")

    def join(self, timeout=15):
        deadline = time.monotonic() + timeout
        for thread in self.threads:
            thread.join(timeout=max(0, deadline - time.monotonic()))
        if any(thread.is_alive() for thread in self.threads):
            raise AssertionError("Concurrent bridge calls stalled under pipe backpressure")

    def cleanup(self):
        # Do not call CoreBridge.close() until writers have completed: this
        # deliberately handles the historical write/map-lock deadlock too.
        process = self.bridge.process
        if process.poll() is None:
            process.kill()
        process.wait(timeout=4)
        deadline = time.monotonic() + 4
        for thread in self.threads:
            thread.join(timeout=max(0, deadline - time.monotonic()))
        self.bridge.reader.join(timeout=2)
        alive = [thread for thread in self.threads if thread.is_alive()]
        if not alive:
            process.stdin.close()
        if not self.bridge.reader.is_alive():
            process.stdout.close()
        if alive or self.bridge.reader.is_alive():
            raise AssertionError("Bridge worker failed to exit after terminating its child")


class RemoteBridgeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="tunnel-bridge-")
        self.addCleanup(self.temporary.cleanup)

    def harness(self, mode="echo", expected=0):
        harness = Harness(self.temporary.name, mode, expected)
        self.addCleanup(harness.cleanup)
        return harness

    def launch_calls(self, harness, count, rounds=1, payload_size=4096):
        successes = queue.Queue()
        errors = queue.Queue()
        gate = threading.Barrier(count + 1, timeout=8)

        def worker(index):
            try:
                gate.wait()
                for turn in range(rounds):
                    ticket = index * rounds + turn
                    payload = (f"{ticket:08x}" * ((payload_size + 7) // 8))[:payload_size]
                    result = harness.bridge.call("remote_sign", ticket=ticket, payload=payload)
                    successes.put((ticket, payload, result))
            except BaseException as error:
                errors.put(error)

        for index in range(count):
            harness.worker(lambda index=index: worker(index))
        gate.wait()
        return successes, errors

    def assert_replies(self, successes, errors, expected):
        problems = []
        while not errors.empty():
            problems.append(repr(errors.get_nowait()))
        self.assertEqual(problems, [])
        self.assertEqual(successes.qsize(), expected)
        tickets = set()
        while not successes.empty():
            ticket, payload, result = successes.get_nowait()
            self.assertEqual(result["ticket"], ticket)
            self.assertEqual(result["digest"], hashlib.sha256(payload.encode("utf-8")).hexdigest())
            self.assertEqual(result["padding"], "R" * 4096)
            tickets.add(ticket)
        self.assertEqual(len(tickets), expected)

    def test_32_concurrent_large_requests_and_responses(self):
        harness = self.harness()
        successes, errors = self.launch_calls(harness, 32, rounds=4)
        harness.join(timeout=15)
        self.assert_replies(successes, errors, 128)
        self.assertEqual(harness.bridge.pending, {})
        # Graceful shutdown must still work after backpressure is drained.
        harness.bridge.close()
        self.assertEqual(harness.bridge.process.returncode, 0)
        self.assertFalse(harness.bridge.reader.is_alive())

    def test_pending_limit_is_32_and_recovers(self):
        harness = self.harness("batch", expected=32)
        successes, errors = self.launch_calls(harness, 32, payload_size=16)
        harness.wait(lambda: harness.marker.with_suffix(".ready").exists())
        with harness.bridge.lock:
            self.assertEqual(len(harness.bridge.pending), 32)
        rejected = queue.Queue()

        def overflow():
            try:
                harness.bridge.call("remote_info")
                rejected.put(None)
            except BaseException as error:
                rejected.put(error)

        probe = harness.worker(overflow)
        probe.join(timeout=1)
        self.assertFalse(probe.is_alive(), "Overflow call blocked instead of enforcing pending limit")
        error = rejected.get_nowait()
        self.assertIsInstance(error, RuntimeError)
        self.assertEqual(str(error), "Too many pending tunnel requests")
        with harness.bridge.lock:
            self.assertEqual(len(harness.bridge.pending), 32)
        harness.marker.with_suffix(".release").write_text("release", encoding="utf-8")
        harness.join(timeout=4)
        self.assert_replies(successes, errors, 32)
        self.assertEqual(harness.bridge.pending, {})
        after = harness.bridge.call("remote_info", ticket="after-limit", payload="ok")
        self.assertEqual(after["ticket"], "after-limit")

    def test_core_exit_promptly_wakes_pending_callers(self):
        harness = self.harness("hold", expected=8)
        successes, errors = self.launch_calls(harness, 8, payload_size=16)
        harness.wait(lambda: harness.marker.with_suffix(".ready").exists())
        with harness.bridge.lock:
            self.assertEqual(len(harness.bridge.pending), 8)
        started = time.monotonic()
        harness.bridge.process.terminate()
        harness.bridge.process.wait(timeout=3)
        harness.join(timeout=2)
        self.assertLess(time.monotonic() - started, 3, "Callers waited for the normal RPC timeout after EOF")
        self.assertEqual(successes.qsize(), 0)
        self.assertEqual(errors.qsize(), 8)
        while not errors.empty():
            error = errors.get_nowait()
            self.assertIsInstance(error, ValueError)
            self.assertEqual(str(error), "Tunnel core exited")
        self.assertEqual(harness.bridge.pending, {})
        with self.assertRaisesRegex(RuntimeError, "Tunnel core is not running"):
            harness.bridge.call("remote_info")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", default=("build" if os.name == "nt" else "build-wsl") + "/remote-bridge-tests.json")
    args = parser.parse_args()
    started = time.monotonic()
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(RemoteBridgeTests))
    report = {"platform": sys.platform, "tests": result.testsRun,
              "passed": result.testsRun - len(result.failures) - len(result.errors),
              "failures": len(result.failures), "errors": len(result.errors),
              "seconds": round(time.monotonic() - started, 3),
              "stress_workers": 32, "stress_rounds": 4, "stress_requests": 128,
              "request_payload_bytes": 4096, "response_padding_bytes": 4096,
              "pipe_capacities": PIPE_OBSERVATIONS,
              "checks": ["Concurrent bidirectional pipe backpressure, response integrity and request correlation",
                         "32 pending requests maximum, prompt excess rejection and recovery",
                         "Core EOF immediately wakes all pending callers and clears state"]}
    destination = Path(args.report)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
