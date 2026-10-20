"""TLS remote desktop with core-verified tunnel membership and device policy.

The protocol is pull based: at most one compressed frame is in flight. Input is
bounded and sent before capture; the tunnel loop never runs a desktop backend.
"""
import base64
from collections import deque
import hashlib
import ipaddress
import io
import secrets
import socket
import threading
import time

from .security import (Identity, DeviceStore, canonical, fingerprint, certificate_key,
                       client_context, receive, send)


def _nonce(value):
    if not isinstance(value, str) or len(value) != 64 or len(bytes.fromhex(value)) != 32:
        raise ValueError("Invalid desktop nonce")
    return value


def _identity(value):
    if (not isinstance(value, dict) or not isinstance(value.get("name"), str)
        or len(value["name"].encode("utf-8")) > 128 or any(ord(c) < 32 or ord(c) == 127 for c in value["name"])):
        raise ValueError("Invalid device identity")
    key = value.get("public_key", "")
    if not isinstance(key, str) or len(key) != 64:
        raise ValueError("Invalid device key")
    return {"name": value["name"], "public_key": key, "fingerprint": fingerprint(key)}


def _shutdown(sock):
    if sock:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            sock.close()
        except OSError:
            pass


def _revoke(session):
    # Call under Runtime.lock. A socket close alone cannot stop an input batch
    # which the worker already received and is waiting to execute.
    session["revoked"] = True
    _shutdown(session["socket"])


class Runtime:
    def __init__(self, core, directory, config, backend_factory=None):
        self.core = core
        self.identity = Identity(directory, config.get("device_name", ""))
        self.store = DeviceStore(directory)
        self.backend_factory = backend_factory
        self.lock = threading.RLock()
        self.config = {}
        self.policy_epoch = 0
        self.listeners = {}
        self.sessions = {}
        self.pending = {}
        self.viewer = None
        self.untrusted = {}
        self.events = deque(maxlen=200)
        self.stopping = threading.Event()
        self.gates = threading.BoundedSemaphore(16)
        self.workers = set()
        self.connections = {}
        self.info = {"networks": []}
        self.error = ""
        self.configure(config)
        self.monitor = threading.Thread(target=self._monitor, daemon=True)
        self.monitor.start()

    def log(self, message):
        with self.lock:
            self.events.append({"time": time.time(), "message": str(message)[:300]})

    def configure(self, config):
        if not isinstance(config, dict):
            raise ValueError("Invalid remote desktop configuration")
        allowed = {"enabled", "networks", "access", "unattended", "port", "device_name"}
        if set(config) - allowed:
            raise ValueError("Unknown remote desktop field")
        result = dict(enabled=False, networks=[], access="authorized_devices", unattended=False, port=47831, device_name="")
        result.update(config)
        if type(result["enabled"]) is not bool or type(result["unattended"]) is not bool:
            raise ValueError("Remote desktop flags must be booleans")
        if result["access"] not in ("authorized_devices", "all_tunnel_nodes"):
            raise ValueError("Invalid remote desktop access mode")
        if type(result["port"]) is not int or not 1 <= result["port"] <= 65535:
            raise ValueError("Invalid remote desktop port")
        if not isinstance(result["networks"], list) or len(result["networks"]) > 64:
            raise ValueError("Invalid remote desktop networks")
        for network in result["networks"]:
            if str(ipaddress.ip_network(network, strict=True)) != network:
                raise ValueError("Remote network must be canonical")
        if result["enabled"] and not result["networks"]:
            raise ValueError("Choose at least one desktop network")
        if (not isinstance(result["device_name"], str) or len(result["device_name"].encode("utf-8")) > 128
            or any(ord(c) < 32 or ord(c) == 127 for c in result["device_name"])):
            raise ValueError("Invalid device name")
        with self.lock:
            old = self.config
            self.config = result
            if result["device_name"]:
                self.identity.name = result["device_name"]
            if old != result:
                self.policy_epoch += 1
                # A policy change is immediate; reconnecting obtains a new,
                # explicitly checked grant, including changes to unattended.
                for session in list(self.sessions.values()):
                    _revoke(session)
                for pending in self.pending.values():
                    pending["rejected"] = True
                    pending["event"].set()
                for listener in self.listeners.values():
                    _shutdown(listener["socket"])
                self.listeners.clear()
        return {"message": "Remote desktop policy applied", "config": dict(result)}

    def _member(self, network):
        info = self.core.call("remote_info")
        for entry in info["networks"]:
            if entry["network"] == network:
                return info, entry
        raise ValueError("Tunnel network is not active")

    def _proof(self, network, transcript):
        return self.core.call("remote_sign", network=network, payload=canonical(transcript).hex())

    def _verify(self, network, proof, transcript, source_ip):
        if not isinstance(proof, dict) or proof.get("network") != network or proof.get("source_ip") != source_ip:
            raise ValueError("Desktop peer does not match tunnel address")
        result = self.core.call("remote_verify", network=network, node=proof.get("node", ""),
            source_ip=source_ip, payload=canonical(transcript).hex(), signature=proof.get("signature", ""))
        if not result.get("valid"):
            raise ValueError("Desktop peer is not a current authenticated tunnel member")

    def _monitor(self):
        while not self.stopping.is_set():
            try:
                info = self.core.call("remote_info")
                with self.lock:
                    self.info = info
                    active = {e["network"]: e["tunnel_ip"] for e in info["networks"]}
                    wanted = {(n, active[n], self.config["port"]) for n in self.config["networks"] if n in active} if self.config["enabled"] else set()
                    for key in set(self.listeners) - wanted:
                        _shutdown(self.listeners.pop(key)["socket"])
                    for session in list(self.sessions.values()):
                        if session["network"] not in active or session["network"] not in self.config["networks"]:
                            _revoke(session)
                    for key in wanted - set(self.listeners):
                        network, address, port = key
                        sock = socket.socket(socket.AF_INET6 if ":" in address else socket.AF_INET, socket.SOCK_STREAM)
                        try:
                            if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                                sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                            else:
                                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                            sock.bind((address, port))
                            sock.listen(8)
                            sock.settimeout(1)
                        except Exception:
                            sock.close()
                            raise
                        entry = {"socket": sock, "network": network}
                        self.listeners[key] = entry
                        threading.Thread(target=self._accept, args=(entry,), daemon=True).start()
                    self.error = ""
                    sessions = list(self.sessions.values())
                # Revalidate even when a controller stops polling while holding
                # keys. Do not wait for the eight-second TCP read timeout.
                for session in sessions:
                    if session["revoked"]:
                        continue
                    try:
                        self._verify(session["network"], session["member_proof"],
                                     session["member_transcript"], session["source_ip"])
                    except Exception:
                        with self.lock:
                            if self.sessions.get(session["session_id"]) is session:
                                _revoke(session)
            except Exception as error:
                with self.lock:
                    self.error = str(error)
                    # Fail closed when the core cannot confirm current membership.
                    for session in self.sessions.values():
                        _revoke(session)
                    for entry in self.listeners.values():
                        _shutdown(entry["socket"])
                    self.listeners.clear()
            self.stopping.wait(1)

    def _accept(self, entry):
        listener = entry["socket"]
        while not self.stopping.is_set():
            try:
                sock, address = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            if not self.gates.acquire(blocking=False):
                sock.close()
                continue
            thread = threading.Thread(target=self._serve, args=(sock, address[0], entry["network"]), daemon=True)
            with self.lock:
                if self.stopping.is_set():
                    sock.close()
                    self.gates.release()
                    return
                self.workers.add(thread)
                self.connections[thread] = sock
                try:
                    thread.start()
                except Exception:
                    self.workers.discard(thread)
                    self.connections.pop(thread, None)
                    sock.close()
                    self.gates.release()

    def _approval(self, sock, identity, network, requested):
        with self.lock:
            epoch = self.policy_epoch
            mode = self.config["access"]
            saved = self.store.get("devices", identity["fingerprint"])
            permitted = "control" if mode == "all_tunnel_nodes" else saved["permission"] if saved else None
            if permitted and self.config["unattended"]:
                return ("view" if requested == "view" else permitted), epoch
            if len(self.pending) >= 16:
                raise ValueError("Too many pending desktop requests")
            identifier = secrets.token_hex(12)
            pending = dict(identity, request_id=identifier, network=network, requested=requested,
                           event=threading.Event(), rejected=False, permission=None, epoch=epoch)
            self.pending[identifier] = pending
        self.log("Desktop approval requested: " + identity["fingerprint"][:16])
        try:
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline and not self.stopping.is_set():
                with self.lock:
                    if epoch != self.policy_epoch:
                        raise ValueError("Desktop authorization policy changed")
                send(sock, {"op": "pending", "request_id": identifier})
                if pending["event"].wait(2):
                    if pending["rejected"]:
                        raise ValueError("Desktop request rejected")
                    return ("view" if requested == "view" else pending["permission"]), epoch
            raise ValueError("Desktop approval timed out")
        finally:
            with self.lock:
                self.pending.pop(identifier, None)

    def _serve(self, raw, address, network):
        sock = raw
        backend = None
        identifier = None
        try:
            raw.settimeout(8)
            sock = self.identity.server_context().wrap_socket(raw, server_side=True, do_handshake_on_connect=False)
            with self.lock:
                self.connections[threading.current_thread()] = sock
                if self.stopping.is_set() or not self.config["enabled"] or network not in self.config["networks"]:
                    raise ValueError("Desktop service is stopping or disabled")
            sock.do_handshake()
            _, local = self._member(network)
            if sock.getsockname()[0] != local["tunnel_ip"]:
                raise ValueError("Desktop listener address is no longer active")
            hello = {"op": "hello", "version": 1, "network": network,
                     "nonce": secrets.token_hex(32), "identity": self.identity.info()}
            send(sock, hello)
            request = receive(sock, 16384)
            if request.get("op") != "hello" or request.get("version") != 1 or request.get("network") != network:
                raise ValueError("Incompatible desktop handshake")
            identity = _identity(request.get("identity"))
            requested = request.get("permission", "control")
            if requested not in ("view", "control"):
                raise ValueError("Invalid desktop permission")
            from cryptography.hazmat.primitives import serialization
            der = self.identity.cert.public_bytes(serialization.Encoding.DER)
            transcript = {"version": 1, "network": network, "server_nonce": hello["nonce"],
                          "client_nonce": _nonce(request.get("nonce")), "server_ip": local["tunnel_ip"],
                          "client_ip": address, "server_key": self.identity.public_key,
                          "client_key": identity["public_key"], "certificate": hashlib.sha256(der).hexdigest(),
                          "permission": requested}
            self._verify(network, request.get("proof"), transcript, address)
            Identity.verify(identity["public_key"], canonical(transcript), request.get("signature", ""))
            # Prove the actual server-side virtual endpoint before asking the
            # controller to pin this desktop device key.
            send(sock, {"op": "proof", "proof": self._proof(network, transcript)})
            decision = receive(sock, 4096)
            if decision.get("op") != "continue":
                return
            permission, epoch = self._approval(sock, identity, network, requested)
            self._member(network)
            self._verify(network, request["proof"], transcript, address)
            with self.lock:
                if self.stopping.is_set() or epoch != self.policy_epoch or not self.config["enabled"] or network not in self.config["networks"]:
                    raise ValueError("Remote desktop disabled for this network")
                if self.sessions:
                    raise ValueError("Desktop is busy with another controller")
                identifier = secrets.token_hex(12)
                session = dict(identity, session_id=identifier, network=network, permission=permission, socket=sock, revoked=False,
                    member_proof=request["proof"], member_transcript=transcript, source_ip=address)
                self.sessions[identifier] = session
            if self.backend_factory:
                backend = self.backend_factory()
            else:
                from .platforms import DesktopBackend
                backend = DesktopBackend()
            self.log("Desktop connected: " + identity["fingerprint"][:16] + " (" + permission + ")")
            send(sock, {"op": "ready", "session_id": identifier, "permission": permission, "capabilities": backend.capabilities()})
            checked = 0
            sequence = 0
            last_frame = 0
            while not self.stopping.is_set():
                message = receive(sock, 65536)
                if message.get("op") == "close":
                    break
                if message.get("op") != "poll":
                    raise ValueError("Unknown desktop operation")
                if time.monotonic() - checked > 1:
                    self._member(network)
                    self._verify(network, request["proof"], transcript, address)
                    checked = time.monotonic()
                events = message.get("events", [])
                if not isinstance(events, list) or len(events) > 128:
                    raise ValueError("Too many input events")
                with self.lock:
                    if self.sessions.get(identifier) is not session or session["revoked"]:
                        break
                    for event in events:
                        if not isinstance(event, dict):
                            raise ValueError("Invalid desktop input event")
                        if event.get("type") == "release_all":
                            backend.release_all()
                        elif session["permission"] == "control":
                            backend.input(event)
                        else:
                            raise ValueError("This desktop session is view-only")
                delay = 0.125 - (time.monotonic() - last_frame)
                if delay > 0:
                    self.stopping.wait(delay)
                frame = backend.capture()
                last_frame = time.monotonic()
                sequence += 1
                send(sock, {"op": "frame", "sequence": sequence,
                    "jpeg": base64.b64encode(frame["jpeg"]).decode("ascii"),
                    "width": frame["width"], "height": frame["height"], "permission": session["permission"]})
        except Exception as error:
            try:
                send(sock, {"op": "error", "error": str(error)[:300]})
            except Exception:
                pass
            self.log("Desktop connection ended: " + str(error))
        finally:
            if backend:
                try:
                    backend.release_all()
                except Exception as error:
                    self.log("Input release failed: " + str(error))
                try:
                    backend.close()
                except Exception as error:
                    self.log("Desktop backend cleanup failed: " + str(error))
            with self.lock:
                if identifier:
                    self.sessions.pop(identifier, None)
                self.workers.discard(threading.current_thread())
                self.connections.pop(threading.current_thread(), None)
            _shutdown(sock)
            self.gates.release()

    def _connect(self, viewer, address, network, port, permission):
        sock = None
        try:
            _, local = self._member(network)
            raw = socket.socket(socket.AF_INET6 if ":" in address else socket.AF_INET, socket.SOCK_STREAM)
            sock = raw
            with self.lock:
                viewer["socket"] = raw
                if viewer["stop"].is_set() or self.stopping.is_set():
                    raise ValueError("Desktop connection cancelled")
            raw.settimeout(8)
            raw.bind((local["tunnel_ip"], 0))
            raw.connect((address, port))
            sock = client_context().wrap_socket(raw, server_hostname=None, do_handshake_on_connect=False)
            with self.lock:
                viewer["socket"] = sock
                if viewer["stop"].is_set() or self.stopping.is_set():
                    raise ValueError("Desktop connection cancelled")
            sock.do_handshake()
            der = sock.getpeercert(binary_form=True)
            server_key = certificate_key(der)
            hello = receive(sock, 16384)
            identity = _identity(hello.get("identity"))
            if hello.get("op") != "hello" or hello.get("version") != 1 or hello.get("network") != network or identity["public_key"] != server_key:
                raise ValueError("Remote desktop certificate/identity mismatch")
            nonce = secrets.token_hex(32)
            transcript = {"version": 1, "network": network, "server_nonce": _nonce(hello.get("nonce")),
                          "client_nonce": nonce, "server_ip": address, "client_ip": local["tunnel_ip"],
                          "server_key": server_key, "client_key": self.identity.public_key,
                          "certificate": hashlib.sha256(der).hexdigest(), "permission": permission}
            send(sock, {"op": "hello", "version": 1, "network": network, "nonce": nonce,
                        "identity": self.identity.info(), "permission": permission,
                        "proof": self._proof(network, transcript), "signature": self.identity.sign(canonical(transcript))})
            proof = receive(sock, 16384)
            if proof.get("op") != "proof":
                raise ValueError(proof.get("error", "Missing desktop server proof"))
            self._verify(network, proof.get("proof"), transcript, address)
            with self.lock:
                if viewer["stop"].is_set() or self.stopping.is_set():
                    raise ValueError("Desktop connection cancelled")
                viewer["identity"] = identity
                if not self.store.get("hosts", identity["fingerprint"]):
                    self.untrusted[identity["fingerprint"]] = identity
                    if len(self.untrusted) > 16:
                        self.untrusted.pop(next(iter(self.untrusted)))
                    viewer["status"] = "trust_required"
                    send(sock, {"op": "cancel"})
                    return
            send(sock, {"op": "continue"})
            while not viewer["stop"].is_set():
                reply = receive(sock, 16384)
                if reply.get("op") == "pending":
                    viewer["status"] = "pending"
                    continue
                if reply.get("op") != "ready":
                    raise ValueError(reply.get("error", "Desktop rejected"))
                with self.lock:
                    if viewer["stop"].is_set() or self.stopping.is_set():
                        raise ValueError("Desktop connection cancelled")
                    viewer.update(status="connected", permission=reply["permission"], capabilities=reply["capabilities"])
                break
            checked = 0
            while not viewer["stop"].is_set():
                if time.monotonic() - checked > 1:
                    self._member(network)
                    self._verify(network, proof["proof"], transcript, address)
                    checked = time.monotonic()
                with self.lock:
                    events = list(viewer["events"])
                    viewer["events"].clear()
                send(sock, {"op": "poll", "events": events})
                reply = receive(sock)
                if reply.get("op") != "frame":
                    raise ValueError(reply.get("error", "Invalid desktop frame"))
                if (type(reply.get("width")) is not int or type(reply.get("height")) is not int
                    or not 1 <= reply["width"] <= 4096 or not 1 <= reply["height"] <= 4096
                    or not isinstance(reply.get("jpeg"), str)):
                    raise ValueError("Invalid remote desktop image")
                # Check encoded image dimensions too; untrusted metadata must
                # not trick the WebView into decoding an oversized JPEG.
                from PIL import Image
                picture = base64.b64decode(reply["jpeg"], validate=True)
                with Image.open(io.BytesIO(picture)) as image:
                    if image.format != "JPEG" or image.size != (reply["width"], reply["height"]):
                        raise ValueError("Remote image dimensions do not match")
                    image.verify()
                with self.lock:
                    viewer["frame"] = reply
            viewer["status"] = "disconnected"
        except Exception as error:
            viewer.update(status="error" if not viewer["stop"].is_set() else "disconnected", error=str(error)[:300])
        finally:
            _shutdown(sock)
            viewer["socket"] = None

    def _public_viewer(self):
        if not self.viewer:
            return None
        return {k: v for k, v in self.viewer.items() if k not in ("socket", "stop", "events", "frame", "thread")}

    def request(self, action, payload=None):
        payload = payload or {}
        with self.lock:
            if action == "remote_state":
                return {"identity": self.identity.info(), "config": dict(self.config),
                    "devices": self.store.list("devices"), "trusted_hosts": self.store.list("hosts"),
                    "pending": [{k: v for k, v in p.items() if k not in ("event", "rejected", "epoch")} for p in self.pending.values() if not p["rejected"] and not p["event"].is_set()],
                    "sessions": [{k: v for k, v in s.items() if k not in ("socket", "member_proof", "member_transcript")} for s in self.sessions.values()],
                    "viewer": self._public_viewer(), "error": self.error,
                    "listeners": [{"network": n, "address": a, "port": p} for n, a, p in self.listeners],
                    "logs": list(self.events)}
            if action == "remote_configure":
                return self.configure(payload["config"])
            if action == "remote_connect":
                if self.viewer and self.viewer["status"] in ("connecting", "pending", "connected"):
                    raise ValueError("Disconnect the current desktop first")
                address = str(ipaddress.ip_address(payload["address"]))
                network = str(ipaddress.ip_network(payload["tunnel"], strict=True))
                if ipaddress.ip_address(address) not in ipaddress.ip_network(network):
                    raise ValueError("Desktop address must belong to the selected tunnel")
                port = payload.get("port", 47831)
                permission = payload.get("permission", "control")
                if type(port) is not int or not 1 <= port <= 65535 or permission not in ("view", "control"):
                    raise ValueError("Invalid remote desktop connection")
                viewer = {"session_id": secrets.token_hex(12), "address": address, "network": network,
                    "status": "connecting", "permission": permission, "error": "", "socket": None,
                    "stop": threading.Event(), "events": deque(), "frame": None}
                self.viewer = viewer
                thread = threading.Thread(target=self._connect, args=(viewer, address, network, port, permission), daemon=True)
                viewer["thread"] = thread
                thread.start()
                return self._public_viewer()
            if action == "remote_trust":
                identity = self.untrusted.get(payload["fingerprint"])
                if not identity:
                    raise ValueError("No verified desktop identity awaiting trust")
                self.store.put("hosts", identity)
                return {"message": "Desktop identity saved"}
            if action == "remote_authorize":
                pending = self.pending.get(payload.get("request_id"))
                if (not pending or pending["rejected"] or pending["event"].is_set()
                    or pending["epoch"] != self.policy_epoch):
                    raise ValueError("Desktop approval request has expired")
                permission = payload.get("permission", "control")
                if permission not in ("view", "control") or type(payload.get("remember", False)) is not bool:
                    raise ValueError("Invalid desktop grant")
                if payload.get("remember", False):
                    self.store.put("devices", dict(_identity(pending), permission=permission))
                pending["permission"] = permission
                pending["event"].set()
                return {"message": "Desktop request approved"}
            if action == "remote_reject":
                pending = self.pending.get(payload.get("request_id"))
                if pending:
                    pending["rejected"] = True
                    pending["event"].set()
                return {"message": "Desktop request rejected"}
            if action == "remote_revoke":
                key = payload["fingerprint"]
                self.store.remove("devices", key)
                # Prevent a previously approved but not yet registered session
                # from racing a revocation. Existing unrelated sessions survive.
                self.policy_epoch += 1
                for pending in self.pending.values():
                    if pending["fingerprint"] == key:
                        pending["rejected"] = True
                        pending["event"].set()
                if self.config["access"] == "authorized_devices":
                    for session in self.sessions.values():
                        if session["fingerprint"] == key:
                            _revoke(session)
                return {"message": "Device authorization removed"}
            if action == "remote_terminate":
                pending = self.pending.get(payload.get("session_id"))
                if pending:
                    pending["rejected"] = True
                    pending["event"].set()
                session = self.sessions.get(payload.get("session_id"))
                if session:
                    _revoke(session)
                return {"message": "Desktop connection terminated"}
            if action in ("remote_frame", "remote_input", "remote_disconnect"):
                viewer = self.viewer
                if action == "remote_disconnect" and not viewer:
                    return {"message": "No outgoing desktop connection"}
                if not viewer or (payload.get("session_id") != viewer["session_id"] and not (action == "remote_disconnect" and not payload.get("session_id"))):
                    raise ValueError("Desktop session no longer exists")
                if action == "remote_disconnect":
                    viewer["stop"].set()
                    _shutdown(viewer["socket"])
                    viewer["status"] = "disconnected"
                    return {"message": "Desktop disconnected"}
                if action == "remote_frame":
                    frame = viewer["frame"]
                    result = self._public_viewer()
                    if frame and frame["sequence"] != payload.get("after"):
                        result.update(frame)
                    return result
                event = payload.get("event")
                if viewer["status"] != "connected":
                    raise ValueError("Desktop is not connected")
                if not isinstance(event, dict) or len(canonical(event)) > 1024:
                    raise ValueError("Invalid desktop input")
                if viewer["permission"] != "control" and event.get("type") != "release_all":
                    raise ValueError("Desktop is view-only")
                events = viewer["events"]
                if event.get("type") == "mouse_move" and events and events[-1].get("type") == "mouse_move":
                    events[-1] = event
                elif len(events) < 128:
                    events.append(event)
                else:
                    events.clear()
                    events.append({"type": "release_all"})
                    raise ValueError("Desktop input queue full; keys released")
                return {"ok": True}
            raise ValueError("Unknown remote desktop action")

    def close(self):
        self.stopping.set()
        with self.lock:
            for entry in self.listeners.values():
                _shutdown(entry["socket"])
            self.listeners.clear()
            for session in self.sessions.values():
                _revoke(session)
            for sock in self.connections.values():
                _shutdown(sock)
            for pending in self.pending.values():
                pending["rejected"] = True
                pending["event"].set()
            if self.viewer:
                self.viewer["stop"].set()
                _shutdown(self.viewer["socket"])
            workers = list(self.workers)
            if self.viewer and self.viewer.get("thread"):
                workers.append(self.viewer["thread"])
        deadline = time.monotonic() + 8
        for thread in workers:
            thread.join(timeout=max(0, deadline - time.monotonic()))
        self.monitor.join(timeout=max(0, deadline - time.monotonic()))
