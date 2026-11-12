"""TLS remote desktop with core-verified tunnel membership and device policy.

The protocol is pull based: at most one compressed frame is in flight. Input is
bounded and sent before capture; the tunnel loop never runs a desktop backend.
"""
import base64
from collections import deque
import hashlib
import hmac
import ipaddress
import secrets
import socket
import threading
import time

from .security import (Identity, DeviceStore, canonical, fingerprint, certificate_key,
                       client_context, receive, send)
from .rfb import RfbSession, WebSocketBridge, close_socket


# Pull one compressed frame at the display refresh cadence.  There is still
# only one frame in flight, so a slow link lowers the achieved FPS without
# building a stale frame backlog.
REMOTE_FPS = 60
FRAME_INTERVAL = 1.0 / REMOTE_FPS


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


def _low_latency(sock):
    """Disable Nagle buffering for the interactive desktop TCP stream."""
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except OSError:
        # Keep compatibility with test doubles and unusual socket providers;
        # the protocol remains correct if this hint is unavailable.
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
        allowed = {"enabled", "networks", "shared_key", "port", "device_name"}
        if set(config) - allowed:
            raise ValueError("Unknown remote desktop field")
        result = dict(enabled=False, networks=[], shared_key="",
                      port=47831, device_name="")
        result.update(config)
        if type(result["enabled"]) is not bool:
            raise ValueError("Remote desktop flags must be booleans")
        if not isinstance(result["shared_key"], str) or len(result["shared_key"].encode("utf-8")) > 4096:
            raise ValueError("Invalid remote desktop shared key")
        if result["enabled"] and not result["shared_key"]:
            raise ValueError("Remote desktop shared_key is required when enabled")
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
            # An empty name means "use the host name".  Recompute it on every
            # policy update so clearing a previously custom name takes effect
            # immediately instead of leaving stale identity text in handshakes.
            display_name = result["device_name"] or socket.gethostname()
            self.identity.name = display_name.encode("utf-8")[:128].decode("utf-8", errors="ignore")
            if old != result:
                self.policy_epoch += 1
                # A policy change is immediate; reconnecting obtains a new,
                # explicitly checked grant.
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

    def _backend_factory(self):
        if self.backend_factory:
            return self.backend_factory()
        from .platforms import DesktopBackend
        return DesktopBackend()

    def _rfb_backend_factory(self, viewport=None):
        if self.backend_factory:
            return self.backend_factory()
        from .platforms import DesktopBackend
        # The RFB path is already JPEG/Tight encoded by the backend. Keep
        # common 4K and 2560x1600 displays at native size: noVNC scales the
        # canvas, while avoiding an expensive pre-encode resize on every
        # frame. 4:2:0 at quality 85 keeps text sharp enough for control while
        # cutting JPEG CPU time and wire size versus 4:4:4/quality 90.
        max_width, max_height = 3840, 2160
        if isinstance(viewport, dict):
            if type(viewport.get("width")) is int:
                max_width = max(64, min(max_width, viewport["width"]))
            if type(viewport.get("height")) is int:
                max_height = max(64, min(max_height, viewport["height"]))
        backend = DesktopBackend(max_width=max_width, max_height=max_height,
                                 quality=85, subsampling=2)
        if isinstance(viewport, dict):
            # Make the initial ServerInit framebuffer match the controller's
            # first viewport. Later noVNC resize requests use the same setter.
            backend.set_capture_bounds(max_width, max_height)
        return backend

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

    def _approval(self, sock, identity, network, requested, presented_key=""):
        with self.lock:
            epoch = self.policy_epoch
            configured_key = self.config["shared_key"]
            if not configured_key or not isinstance(presented_key, str) or not hmac.compare_digest(presented_key, configured_key):
                raise ValueError("Remote desktop shared key rejected")
            # A valid remote desktop PSK is the complete authorization
            # decision; there is no approval or device-trust round trip.
            return ("view" if requested == "view" else "control"), epoch

    def _serve(self, raw, address, network):
        sock = raw
        backend = None
        identifier = None
        try:
            _low_latency(raw)
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
            protocol = request.get("protocol", "jpeg")
            if protocol not in ("jpeg", "rfb"):
                raise ValueError("Unsupported desktop protocol")
            presented_key = request.get("shared_key", "")
            if not isinstance(presented_key, str) or len(presented_key.encode("utf-8")) > 4096:
                raise ValueError("Invalid remote desktop shared key")
            from cryptography.hazmat.primitives import serialization
            der = self.identity.cert.public_bytes(serialization.Encoding.DER)
            transcript = {"version": 1, "network": network, "server_nonce": hello["nonce"],
                          "client_nonce": _nonce(request.get("nonce")), "server_ip": local["tunnel_ip"],
                          "client_ip": address, "server_key": self.identity.public_key,
                          "client_key": identity["public_key"], "certificate": hashlib.sha256(der).hexdigest(),
                          "permission": requested, "protocol": protocol}
            self._verify(network, request.get("proof"), transcript, address)
            Identity.verify(identity["public_key"], canonical(transcript), request.get("signature", ""))
            # Prove the actual server-side virtual endpoint before asking the
            # controller to pin this desktop device key.
            send(sock, {"op": "proof", "proof": self._proof(network, transcript)})
            decision = receive(sock, 4096)
            if decision.get("op") != "continue":
                return
            permission, epoch = self._approval(sock, identity, network, requested, presented_key)
            self._member(network)
            self._verify(network, request["proof"], transcript, address)
            with self.lock:
                if self.stopping.is_set() or epoch != self.policy_epoch or not self.config["enabled"] or network not in self.config["networks"]:
                    raise ValueError("Remote desktop disabled for this network")
                if self.sessions:
                    raise ValueError("Desktop is busy with another controller")
                identifier = secrets.token_hex(12)
                session = dict(identity, session_id=identifier, network=network, permission=permission, socket=sock, revoked=False,
                    protocol=protocol, member_proof=request["proof"], member_transcript=transcript, source_ip=address)
                self.sessions[identifier] = session
            self.log("Desktop connected: " + identity["fingerprint"][:16] + " (" + permission + ")")
            if protocol == "rfb":
                send(sock, {"op": "ready", "session_id": identifier, "permission": permission,
                            "protocol": "rfb", "capabilities": {"capture": True, "mouse": True,
                            "keyboard": permission == "control", "clipboard": False}})
                sock.settimeout(None)
                backend = self._rfb_backend_factory(request.get("viewport"))
                RfbSession(sock, lambda: backend, server_name=self.identity.name,
                           allow_input=permission == "control").serve()
                return
            backend = self._backend_factory()
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
                delay = FRAME_INTERVAL - (time.monotonic() - last_frame)
                if delay > 0:
                    self.stopping.wait(delay)
                frame = backend.capture()
                last_frame = time.monotonic()
                sequence += 1
                send(sock, {"op": "frame", "sequence": sequence,
                    "jpeg": base64.b64encode(frame["jpeg"]).decode("ascii"),
                    "width": frame["width"], "height": frame["height"], "permission": session["permission"]})
        except EOFError:
            # A browser closing the noVNC WebSocket is a normal end of a
            # desktop session. Keep it distinct from an authentication,
            # protocol, or capture failure in the activity log.
            self.log("Desktop connection closed")
        except (ConnectionResetError, BrokenPipeError, TimeoutError) as error:
            self.log("Desktop connection lost: " + str(error))
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

    def _connect(self, viewer, address, network, port, permission, protocol="jpeg", viewport=None, shared_key=""):
        sock = None
        try:
            _, local = self._member(network)
            raw = socket.socket(socket.AF_INET6 if ":" in address else socket.AF_INET, socket.SOCK_STREAM)
            sock = raw
            _low_latency(raw)
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
                          "certificate": hashlib.sha256(der).hexdigest(), "permission": permission,
                          "protocol": protocol}
            hello_message = {"op": "hello", "version": 1, "network": network, "nonce": nonce,
                        "identity": self.identity.info(), "permission": permission,
                        "protocol": protocol,
                        "proof": self._proof(network, transcript), "signature": self.identity.sign(canonical(transcript))}
            if protocol == "rfb" and isinstance(viewport, dict):
                hello_message["viewport"] = viewport
            if not isinstance(shared_key, str) or not shared_key:
                raise ValueError("Remote desktop shared key is required")
            hello_message["shared_key"] = shared_key
            send(sock, hello_message)
            proof = receive(sock, 16384)
            if proof.get("op") != "proof":
                raise ValueError(proof.get("error", "Missing desktop server proof"))
            self._verify(network, proof.get("proof"), transcript, address)
            with self.lock:
                if viewer["stop"].is_set() or self.stopping.is_set():
                    raise ValueError("Desktop connection cancelled")
                viewer["identity"] = identity
                # Tunnel membership plus the remote PSK is the complete
                # desktop authentication decision.
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
            if protocol == "rfb":
                bridge = WebSocketBridge(sock, viewer["stop"])
                with self.lock:
                    viewer["bridge"] = bridge
                    viewer["ws_url"] = bridge.start()
                    viewer["protocol"] = "rfb"
                bridge.thread.join()
                with self.lock:
                    if viewer["status"] == "connected":
                        viewer["status"] = "disconnected"
                return
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
                # Validate the bounded base64/JPEG envelope without parsing
                # the JPEG through Pillow on every frame. The desktop peer is
                # already authenticated, and the WebView performs the actual
                # image decode; a second image scan here added visible frame
                # latency on slower machines.
                picture = base64.b64decode(reply["jpeg"], validate=True)
                if len(picture) < 4 or picture[:2] != b"\xff\xd8" or picture[-2:] != b"\xff\xd9":
                    raise ValueError("Invalid remote JPEG image")
                with self.lock:
                    viewer["frame"] = reply
            viewer["status"] = "disconnected"
        except Exception as error:
            # Closing the socket is the normal path for an explicit
            # disconnect.  The worker can observe the resulting socket error
            # after the stop event is set; do not surface that expected
            # shutdown as a stale viewer error.
            if viewer["stop"].is_set() or self.stopping.is_set():
                viewer.update(status="disconnected", error="")
            else:
                viewer.update(status="error", error=str(error)[:300])
        finally:
            _shutdown(sock)
            viewer["socket"] = None

    def _public_viewer(self):
        if not self.viewer:
            return None
        # The PSK is needed only inside the TLS handshake.  Never echo it
        # through the local status RPC, where it could end up in GUI logs or
        # browser state snapshots.
        return {k: v for k, v in self.viewer.items() if k not in
                ("socket", "stop", "events", "frame", "thread", "bridge", "shared_key")}

    def _request_vnc_connect(self, payload):
        """Start or observe an RFB viewer and expose its loopback WebSocket."""
        session_id = payload.get("session_id")
        with self.lock:
            viewer = self.viewer
            if session_id:
                if not viewer or viewer.get("session_id") != session_id:
                    raise ValueError("Desktop session no longer exists")
            else:
                if viewer and viewer.get("status") in ("connecting", "pending", "connected"):
                    raise ValueError("Disconnect the current desktop first")
                if viewer:
                    viewer["stop"].set()
                    _shutdown(viewer.get("socket"))
                address = str(ipaddress.ip_address(payload["address"]))
                network = str(ipaddress.ip_network(payload["tunnel"], strict=True))
                if ipaddress.ip_address(address) not in ipaddress.ip_network(network):
                    raise ValueError("Desktop address must belong to the selected tunnel")
                port = payload.get("port", 47831)
                permission = payload.get("permission", "control")
                if type(port) is not int or not 1 <= port <= 65535 or permission not in ("view", "control"):
                    raise ValueError("Invalid remote desktop connection")
                shared_key = payload.get("shared_key", "")
                if not isinstance(shared_key, str) or not shared_key or len(shared_key.encode("utf-8")) > 4096:
                    raise ValueError("Remote desktop shared key is required")
                viewport = payload.get("viewport")
                if viewport is not None:
                    if (not isinstance(viewport, dict) or type(viewport.get("width")) is not int
                            or type(viewport.get("height")) is not int
                            or not 64 <= viewport["width"] <= 3840
                            or not 64 <= viewport["height"] <= 2160):
                        raise ValueError("Invalid remote desktop viewport")
                    viewport = {"width": viewport["width"], "height": viewport["height"]}
                viewer = {"session_id": secrets.token_hex(12), "address": address, "network": network,
                    "status": "connecting", "permission": permission, "protocol": "rfb", "error": "",
                    "socket": None, "bridge": None, "ws_url": "", "stop": threading.Event(),
                    "events": deque(), "frame": None, "viewport": viewport, "shared_key": shared_key}
                self.viewer = viewer
                thread = threading.Thread(target=self._connect, args=(viewer, address, network, port, permission, "rfb", viewport, shared_key), daemon=True)
                viewer["thread"] = thread
                thread.start()
        # Do not hold Runtime.lock while the handshake thread updates status.
        # A short wait makes the GUI receive trust/pending/ws_url in one call,
        # while slow links still report connecting and can be polled safely.
        # Return connecting/pending promptly; the GUI polls this session while
        # other local RPC requests (including approval) remain available.
        deadline = time.monotonic() + 1.5
        while time.monotonic() < deadline:
            with self.lock:
                status = viewer.get("status")
                if status != "connecting" and not (status == "connected" and not viewer.get("ws_url")):
                    break
            time.sleep(0.05)
        with self.lock:
            return self._public_viewer()

    def request(self, action, payload=None):
        payload = payload or {}
        if action == "remote_vnc_connect":
            return self._request_vnc_connect(payload)
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
                shared_key = payload.get("shared_key", "")
                if not isinstance(shared_key, str) or not shared_key or len(shared_key.encode("utf-8")) > 4096:
                    raise ValueError("Remote desktop shared key is required")
                viewer = {"session_id": secrets.token_hex(12), "address": address, "network": network,
                    "status": "connecting", "permission": permission, "error": "", "socket": None,
                    "stop": threading.Event(), "events": deque(), "frame": None, "shared_key": shared_key}
                self.viewer = viewer
                thread = threading.Thread(target=self._connect, args=(viewer, address, network, port, permission, "jpeg", None, shared_key), daemon=True)
                viewer["thread"] = thread
                thread.start()
                return self._public_viewer()
            if action in ("remote_trust", "remote_authorize", "remote_reject", "remote_revoke"):
                raise ValueError("Remote desktop uses pre-shared key authentication; approval is not supported")
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
                if viewer["status"] != "connected":
                    raise ValueError("Desktop is not connected")
                submitted = payload.get("events")
                if submitted is None:
                    submitted = [payload.get("event")]
                if not isinstance(submitted, list) or not submitted or len(submitted) > 32:
                    raise ValueError("Invalid desktop input batch")
                validated = []
                for event in submitted:
                    if not isinstance(event, dict) or len(canonical(event)) > 1024:
                        raise ValueError("Invalid desktop input")
                    if viewer["permission"] != "control" and event.get("type") != "release_all":
                        raise ValueError("Desktop is view-only")
                    validated.append(event)
                events = viewer["events"]
                for event in validated:
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
