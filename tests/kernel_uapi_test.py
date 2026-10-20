#!/usr/bin/env python3
"""Exercise the loaded tunnel_kmod ioctl ABI in an isolated network namespace.

Requires root/CAP_NET_ADMIN, iproute2, /dev/tunnel_kmod, and libcrypto.so.3.
No host interfaces, routes, or firewall rules are changed. The module remains
loaded; closing each private control fd removes only that test instance.
"""
import argparse
import ctypes as C
import errno
import fcntl
import glob
import ipaddress
import json
import os
from pathlib import Path
import platform
import select
import struct
import subprocess
import sys
import time


class Packed(C.Structure):
    _pack_ = 1


class Ip(Packed):
    _fields_ = [('family', C.c_uint8), ('data', C.c_uint8 * 16)]


class Endpoint(Packed):
    _fields_ = [('ip', Ip), ('port', C.c_uint16)]


class Network(Packed):
    _fields_ = [('address', Ip), ('prefix', C.c_uint8)]


class Keys(Packed):
    _fields_ = [('sid', C.c_uint8 * 16), ('send', C.c_uint8 * 32), ('receive', C.c_uint8 * 32)]


class Create(Packed):
    _fields_ = [('abi', C.c_uint32), ('mtu', C.c_uint32), ('transport_mtu', C.c_uint32),
               ('lease_ms', C.c_uint32), ('local', Endpoint), ('bind', Endpoint),
               ('name', C.c_char * 16), ('ifindex', C.c_uint32)]


class Blob(C.Structure):
    _fields_ = [('data', C.c_uint64), ('length', C.c_uint32), ('reserved', C.c_uint32)]


class Header(Packed):
    _fields_ = [(field, C.c_uint32) for field in ('abi', 'networks', 'peers', 'routes', 'ends', 'prefixes')]


class Net(Packed):
    _fields_ = [('network', Network), ('local_ip', Ip)]


class Peer(Packed):
    _fields_ = [('endpoint', Endpoint), ('keys', Keys), ('tcp', C.c_uint8),
               ('ready', C.c_uint8), ('networks', C.c_uint8 * 16)]


class Route(Packed):
    _fields_ = [('network', C.c_uint32), ('destination', Endpoint), ('ip', Ip),
               ('nhops', C.c_uint32), ('hops', C.c_uint32 * 32)]


class End(Packed):
    _fields_ = [('network', C.c_uint32), ('destination', Endpoint), ('keys', Keys), ('ready', C.c_uint8)]


class Prefix(Packed):
    _fields_ = [('network', C.c_uint32), ('prefix', Network), ('publisher', Endpoint), ('selected', C.c_uint8)]


class Event(Packed):
    _fields_ = [('kind', C.c_uint32), ('length', C.c_uint32), ('peer', Endpoint),
               ('network', Network), ('token', C.c_uint64)]


class Probe(Packed):
    _fields_ = [('peer', Endpoint), ('token', C.c_uint64)]


def ioc(direction, number, size=0):
    return (direction << 30) | (size << 16) | (ord('T') << 8) | number


CREATE = ioc(3, 0x90, C.sizeof(Create))
SNAPSHOT = ioc(1, 0x91, C.sizeof(Blob))
PROBE = ioc(1, 0x92, C.sizeof(Probe))
STATS = ioc(2, 0x93, 17 * 8)
RENEW = ioc(0, 0x94)


def ip(text):
    value = ipaddress.ip_address(text)
    return Ip(value.version, (C.c_uint8 * 16).from_buffer_copy(value.packed.ljust(16, b'\0')))


def endpoint(text, port):
    return Endpoint(ip(text), port)


def network(text):
    value = ipaddress.ip_network(text)
    return Network(ip(str(value.network_address)), value.prefixlen)


def ioctl(fd, command, value):
    result = bytearray(bytes(value))
    fcntl.ioctl(fd, command, result, True)
    return type(value).from_buffer_copy(result)


def state(nets=(), peers=(), routes=(), ends=(), prefixes=()):
    groups = (nets, peers, routes, ends, prefixes)
    return bytes(Header(1, *(len(group) for group in groups))) + b''.join(bytes(item) for group in groups for item in group)


def publish(fd, data, length=None, reserved=0):
    allocation = C.create_string_buffer(data)
    ioctl(fd, SNAPSHOT, Blob(C.addressof(allocation), len(data) if length is None else length, reserved))


def expect_error(call, allowed=(errno.EINVAL,)):
    try:
        call()
    except OSError as exc:
        assert exc.errno in allowed, (exc.errno, allowed, str(exc))
    else:
        raise AssertionError('invalid request was accepted')


def run(*arguments, check=True):
    return subprocess.run(list(map(str, arguments)), capture_output=True, text=True, check=check, timeout=10)


def crypto():
    candidates = ['libcrypto.so.3'] + glob.glob('/lib/*/libcrypto.so.3') + glob.glob('/usr/lib/*/libcrypto.so.3')
    for candidate in candidates:
        try:
            lib = C.CDLL(candidate)
            break
        except OSError:
            pass
    else:
        raise RuntimeError('libcrypto.so.3 is required for authenticated replay tests')
    lib.EVP_CIPHER_CTX_new.restype = C.c_void_p
    lib.EVP_CIPHER_CTX_free.argtypes = [C.c_void_p]
    lib.EVP_aes_256_gcm.restype = C.c_void_p
    lib.EVP_EncryptInit_ex.argtypes = [C.c_void_p, C.c_void_p, C.c_void_p, C.c_void_p, C.c_void_p]
    lib.EVP_EncryptUpdate.argtypes = [C.c_void_p, C.c_void_p, C.POINTER(C.c_int), C.c_void_p, C.c_int]
    lib.EVP_EncryptFinal_ex.argtypes = [C.c_void_p, C.c_void_p, C.POINTER(C.c_int)]
    lib.EVP_CIPHER_CTX_ctrl.argtypes = [C.c_void_p, C.c_int, C.c_int, C.c_void_p]

    def seal(key, sid, sequence, plain):
        header = b'TNL1' + bytes((1, 1)) + struct.pack('!H', len(plain)) + sid + struct.pack('!Q', sequence)
        nonce = b'\0' * 4 + struct.pack('!Q', sequence)
        ctx = lib.EVP_CIPHER_CTX_new()
        assert ctx
        try:
            assert lib.EVP_EncryptInit_ex(ctx, lib.EVP_aes_256_gcm(), None, key, nonce) == 1
            length = C.c_int()
            assert lib.EVP_EncryptUpdate(ctx, None, C.byref(length), header, len(header)) == 1
            out = C.create_string_buffer(len(plain) + 16)
            assert lib.EVP_EncryptUpdate(ctx, out, C.byref(length), plain, len(plain)) == 1
            used = length.value
            assert lib.EVP_EncryptFinal_ex(ctx, C.byref(out, used), C.byref(length)) == 1
            tag = C.create_string_buffer(16)
            assert lib.EVP_CIPHER_CTX_ctrl(ctx, 0x10, 16, tag) == 1
            return header + out.raw[:used + length.value] + tag.raw
        finally:
            lib.EVP_CIPHER_CTX_free(ctx)
    return seal


def exercise(report):
    opened = []

    def mark(name):
        report['checks'].append(name)
        print('PASS', name, flush=True)

    def new_fd():
        fd = os.open('/dev/tunnel_kmod', os.O_RDWR | os.O_NONBLOCK | os.O_CLOEXEC)
        opened.append(fd)
        return fd

    def create(fd, name, port=47291, lease=60000):
        config = Create(1, 1280, 1500, lease, endpoint('127.0.0.1', port), endpoint('127.0.0.1', port), name.encode(), 0)
        return ioctl(fd, CREATE, config)

    def stats(fd):
        output = bytearray(17 * 8)
        fcntl.ioctl(fd, STATS, output, True)
        return struct.unpack('=17Q', output)

    def read_event(fd):
        assert select.select([fd], [], [], 2)[0], 'event not available'
        data = os.read(fd, C.sizeof(Event) + 65536)
        event = Event.from_buffer_copy(data)
        packet = data[C.sizeof(Event):]
        assert event.length == len(packet)
        return event, packet

    try:
        run('ip', 'link', 'set', 'lo', 'up')
        fd = new_fd()
        expect_error(lambda: publish(fd, state()))
        for mtu, outer in ((0xfffffff0, 1500), (0xffffffff, 65535), (67, 1500), (1280, 1000), (1280, 65536)):
            bad = Create(1, mtu, outer, 60000, endpoint('127.0.0.1', 47291), endpoint('127.0.0.1', 47291), b'tkuapi0', 0)
            expect_error(lambda: ioctl(fd, CREATE, bad))
        mark('create_rejects_mtu_overflow_and_invalid_budgets')
        create(fd, 'tkuapi0')
        assert run('ip', 'link', 'show', 'dev', 'tkuapi0', check=False).returncode == 0
        expect_error(lambda: create(fd, 'tkuapi0'), (errno.EALREADY,))
        for counts in ((129, 0, 0, 0, 0), (0, 257, 0, 0, 0), (0, 0, 4097, 0, 0), (0, 0, 0, 257, 0), (0, 0, 0, 0, 4097), (1, 0, 0, 0, 0)):
            expect_error(lambda: publish(fd, bytes(Header(1, *counts))))
        expect_error(lambda: publish(fd, bytes(Header(2, 0, 0, 0, 0, 0))))
        expect_error(lambda: publish(fd, state(), reserved=1))
        expect_error(lambda: publish(fd, state(), length=1024 * 1024 + 1))
        expect_error(lambda: ioctl(fd, SNAPSHOT, Blob(1, 24, 0)), (errno.EFAULT,))
        mark('snapshot_rejects_bounds_lengths_abi_reserved_and_bad_pointer')
        net = Net(network('10.98.99.0/24'), ip('10.98.99.1'))
        invalid = Net(network('10.98.99.0/24'), ip('10.98.99.255'))
        expect_error(lambda: publish(fd, state(nets=[invalid])))
        invalid = Net(network('10.98.99.0/24'), ip('10.98.99.1')); invalid.network.prefix = 255
        expect_error(lambda: publish(fd, state(nets=[invalid])))
        invalid = Net(network('10.98.99.0/24'), ip('10.98.99.1')); invalid.local_ip.data[15] = 1
        expect_error(lambda: publish(fd, state(nets=[invalid])))
        expect_error(lambda: publish(fd, state(nets=[net, Net(network('10.98.0.0/16'), ip('10.98.0.1'))])))
        mark('snapshot_rejects_invalid_addresses_prefixes_and_overlap')
        keys = Keys((C.c_uint8 * 16)(*range(16)), (C.c_uint8 * 32)(*range(32)), (C.c_uint8 * 32)(*range(32, 64)))
        peer = Peer(endpoint('127.0.0.2', 47292), keys, 1, 1, (C.c_uint8 * 16)(1))
        good = state(nets=[net], peers=[peer])
        publish(fd, good)
        expect_error(lambda: publish(fd, state(nets=[net], peers=[peer, peer])))
        bad_peer = Peer.from_buffer_copy(bytes(peer)); bad_peer.networks[15] = 128
        expect_error(lambda: publish(fd, state(nets=[net], peers=[bad_peer])))
        bad_peer = Peer.from_buffer_copy(bytes(peer)); bad_peer.keys.send[0] ^= 1
        expect_error(lambda: publish(fd, state(nets=[net], peers=[bad_peer])), (errno.EKEYREJECTED,))
        route = Route(0, peer.endpoint, ip('10.98.99.2'), 1, (C.c_uint32 * 32)(1))
        expect_error(lambda: publish(fd, state(nets=[net], peers=[peer], routes=[route])))
        route.hops[0] = 0; route.nhops = 33
        expect_error(lambda: publish(fd, state(nets=[net], peers=[peer], routes=[route])))
        mark('snapshot_rejects_duplicate_session_changed_keys_bad_membership_and_hops')
        # Failed publications must not disturb the current session or counters.
        ioctl(fd, PROBE, Probe(peer.endpoint, 123))
        event, packet = read_event(fd)
        assert event.kind == 1 and struct.unpack('!Q', packet[24:32])[0] == 1
        publish(fd, good)
        ioctl(fd, PROBE, Probe(peer.endpoint, 124))
        event, packet = read_event(fd)
        assert event.kind == 1 and struct.unpack('!Q', packet[24:32])[0] == 2
        mark('atomic_snapshot_preserves_send_sequence_and_failed_update_keeps_old_state')
        seal = crypto()

        def inject(sequence, token, corrupt=False):
            record = seal(bytes(keys.receive), bytes(keys.sid), sequence, b'\x05' + struct.pack('!Q', token))
            if corrupt:
                record = record[:-1] + bytes((record[-1] ^ 1,))
            event = Event(1, len(record), peer.endpoint, Network(), 0)
            assert os.write(fd, bytes(event) + record) == C.sizeof(Event) + len(record)

        before = stats(fd)
        inject(1000000, 200, True)
        assert stats(fd)[10] == before[10] + 1
        inject(1, 201)
        event, packet = read_event(fd)
        assert event.kind == 3 and event.token == 201 and not packet
        assert stats(fd)[5] == before[5] + 1
        inject(1, 201)
        assert stats(fd)[11] == before[11] + 1
        publish(fd, good)
        inject(1, 201)
        assert stats(fd)[11] == before[11] + 2
        inject(2, 202)
        event, packet = read_event(fd)
        assert event.kind == 3 and event.token == 202
        mark('unauthenticated_record_cannot_advance_replay_and_snapshot_preserves_window')
        # Passing an open fd does not confer authority to alter its configuration.
        child = os.fork()
        if child == 0:
            try:
                os.setgid(65534); os.setuid(65534)
                expect_error(lambda: fcntl.ioctl(fd, RENEW), (errno.EPERM,))
                os._exit(0)
            except BaseException:
                os._exit(1)
        _, status = os.waitpid(child, 0)
        assert os.waitstatus_to_exitcode(status) == 0
        mark('configuration_ioctl_requires_namespace_admin_after_fd_transfer')
        lease_fd = new_fd(); create(lease_fd, 'tkuapilease', 47293, 1000)
        publish(lease_fd, state())
        time.sleep(1.25)
        expired_errors = (errno.ESTALE, errno.ETIME, errno.ENETDOWN, errno.EKEYEXPIRED)
        expect_error(lambda: fcntl.ioctl(lease_fd, RENEW), expired_errors)
        expect_error(lambda: publish(lease_fd, state()), expired_errors)
        mark('expired_control_lease_cannot_renew_or_republish_stale_snapshot')
        os.close(lease_fd); opened.remove(lease_fd)
        os.close(fd); opened.remove(fd)
        assert run('ip', 'link', 'show', 'dev', 'tkuapi0', check=False).returncode != 0
        assert run('ip', 'link', 'show', 'dev', 'tkuapilease', check=False).returncode != 0
        # Reusing the exact bind endpoint verifies socket release as well.
        again = new_fd(); create(again, 'tkuapiagain'); os.close(again); opened.remove(again)
        mark('control_fd_close_removes_device_and_releases_udp_bind')
    finally:
        for fd in opened:
            os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work', default='/tmp/tunnel-kernel-uapi-tests')
    parser.add_argument('--inside', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if platform.machine().lower() not in ('x86_64', 'amd64', 'aarch64', 'arm64', 'i686', 'i386', 'armv7l'):
        raise RuntimeError('ioctl encoding is tested only on Linux asm-generic ioctl architectures')
    work = Path(args.work).resolve(); work.mkdir(parents=True, exist_ok=True)
    if not args.inside:
        namespace = 'tkuapi-%d' % os.getpid()
        run('ip', 'netns', 'add', namespace)
        try:
            result = subprocess.run(['ip', 'netns', 'exec', namespace, sys.executable, str(Path(__file__).resolve()),
                '--inside', '--work', str(work)], timeout=45)
            return result.returncode
        finally:
            run('ip', 'netns', 'del', namespace, check=False)
    report = {'ok': False, 'checks': [], 'kernel': platform.release()}
    try:
        exercise(report)
        report['ok'] = True
    except BaseException as exc:
        report['error'] = repr(exc)
        import traceback
        traceback.print_exc()
    finally:
        (work / 'results.json').write_text(json.dumps(report, indent=2) + '\n')
        print('KERNEL_UAPI_RESULT', json.dumps(report), flush=True)
    return 0 if report['ok'] else 1


if __name__ == '__main__':
    sys.exit(main())
