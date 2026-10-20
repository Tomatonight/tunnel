"""Persistent device identities and bounded TLS application framing."""
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import ssl
import socket
import struct
import tempfile
import threading

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.x509.oid import NameOID

MAX_FRAME = 4 * 1024 * 1024


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def strict_json(data):
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError("Duplicate JSON key")
            value[key] = item
        return value
    return json.loads(data, object_pairs_hook=pairs, parse_constant=lambda s: (_ for _ in ()).throw(ValueError("Invalid number")))


def atomic_write(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, name = tempfile.mkstemp(prefix=".desktop-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


def fingerprint(public_key):
    return hashlib.sha256(bytes.fromhex(public_key)).hexdigest()


class Identity:
    def __init__(self, directory, name=""):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path = self.directory / "desktop-identity.pem"
        if not self.path.exists():
            key = Ed25519PrivateKey.generate()
            subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Tunnel Desktop")])
            now = datetime.now(timezone.utc)
            cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
                    .public_key(key.public_key()).serial_number(x509.random_serial_number())
                    .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=3650))
                    .sign(key, algorithm=None))
            atomic_write(self.path, key.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8, serialization.NoEncryption()) + cert.public_bytes(serialization.Encoding.PEM))
        data = self.path.read_bytes()
        self.key = serialization.load_pem_private_key(data, password=None)
        if not isinstance(self.key, Ed25519PrivateKey):
            raise ValueError("Unsupported desktop identity key")
        self.cert = x509.load_pem_x509_certificate(data[data.index(b"-----BEGIN CERTIFICATE-----"):])
        self.public_key = self.key.public_key().public_bytes_raw().hex()
        if self.cert.public_key().public_bytes_raw().hex() != self.public_key:
            raise ValueError("Desktop certificate does not match private key")
        self.fingerprint = fingerprint(self.public_key)
        self.name = (name or socket.gethostname()).encode("utf-8")[:128].decode("utf-8", errors="ignore")

    def info(self):
        return {"name": self.name, "public_key": self.public_key, "fingerprint": self.fingerprint}

    def sign(self, payload):
        return self.key.sign(b"Tunnel desktop device v1\n" + payload).hex()

    @staticmethod
    def verify(public_key, payload, signature):
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key)).verify(
            bytes.fromhex(signature), b"Tunnel desktop device v1\n" + payload)

    def server_context(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(self.path)
        context.num_tickets = 0
        return context


def client_context():
    # Trust is an exact persistent device key plus current core membership proof,
    # checked before screen/input exchange, rather than the public Web PKI.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    return context


def certificate_key(der):
    cert = x509.load_der_x509_certificate(der)
    key = cert.public_key()
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("Unsupported remote desktop identity")
    return key.public_bytes_raw().hex()


def _read(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise EOFError("Desktop connection closed")
        data.extend(chunk)
    return bytes(data)


def receive(sock, limit=MAX_FRAME):
    size = struct.unpack("!I", _read(sock, 4))[0]
    if size == 0 or size > limit:
        raise ValueError("Desktop frame exceeds limit")
    value = strict_json(_read(sock, size))
    if not isinstance(value, dict):
        raise ValueError("Expected desktop object")
    return value


def send(sock, value):
    data = canonical(value)
    if len(data) > MAX_FRAME:
        raise ValueError("Desktop frame exceeds limit")
    sock.sendall(struct.pack("!I", len(data)) + data)


class DeviceStore:
    def __init__(self, directory):
        self.path = Path(directory) / "desktop-devices.json"
        self.lock = threading.RLock()
        self.data = {"devices": {}, "hosts": {}}
        if self.path.exists():
            self.data = strict_json(self.path.read_bytes())
            if not isinstance(self.data, dict) or set(self.data) != {"devices", "hosts"}:
                raise ValueError("Invalid desktop device database")
            for group in self.data.values():
                if not isinstance(group, dict) or len(group) > 256:
                    raise ValueError("Invalid desktop device database")
                for key, value in group.items():
                    if not isinstance(value, dict) or fingerprint(value["public_key"]) != key:
                        raise ValueError("Invalid desktop device record")
                    if "permission" in value and value["permission"] not in ("view", "control"):
                        raise ValueError("Invalid desktop permission")

    def get(self, group, key):
        with self.lock:
            value = self.data[group].get(key)
            return dict(value) if value else None

    def list(self, group):
        with self.lock:
            return [dict(item) for item in self.data[group].values()]

    def put(self, group, value):
        with self.lock:
            key = fingerprint(value["public_key"])
            if key not in self.data[group] and len(self.data[group]) >= 256:
                raise ValueError("Desktop device limit reached")
            replacement = {name: dict(items) for name, items in self.data.items()}
            replacement[group][key] = dict(value, fingerprint=key)
            atomic_write(self.path, canonical(replacement))
            self.data = replacement

    def remove(self, group, key):
        with self.lock:
            replacement = {name: dict(items) for name, items in self.data.items()}
            replacement[group].pop(key, None)
            atomic_write(self.path, canonical(replacement))
            self.data = replacement
