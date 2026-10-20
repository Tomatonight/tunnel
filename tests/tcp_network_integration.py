#!/usr/bin/env python3
"""Real TCP/UDP mixed data paths, confined to fresh Linux network namespaces.

Run as Linux/WSL root with iproute2, nftables and ping installed:
  python3 tests/tcp_network_integration.py --binary build-wsl-reload/tunnel
No host interface, routing, sysctl or firewall settings are changed.
"""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import traceback


HELPER = r'''
import json, selectors, socket, sys
from pathlib import Path
mode = sys.argv[1]
if mode == 'serve':
    address4, address6, port, ready = sys.argv[2:]
    events = selectors.DefaultSelector()
    for family, address in ((socket.AF_INET, address4), (socket.AF_INET6, address6)):
        for protocol in ('tcp', 'udp'):
            s = socket.socket(family, socket.SOCK_STREAM if protocol == 'tcp' else socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if family == socket.AF_INET6:
                s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            s.bind((address, int(port)))
            if protocol == 'tcp': s.listen(8)
            events.register(s, selectors.EVENT_READ, protocol)
    Path(ready).write_text('ready')
    while True:
        for event, _ in events.select():
            s, protocol = event.fileobj, event.data
            if protocol == 'udp':
                data, remote = s.recvfrom(65535)
                s.sendto(data, remote)
            else:
                conn, remote = s.accept()
                try:
                    with conn:
                        conn.settimeout(10)
                        while True:
                            data = conn.recv(16384)
                            if not data: break
                            conn.sendall(data)
                except OSError: pass
elif mode == 'request':
    family, protocol, address, port, length = sys.argv[2:]
    family = socket.AF_INET6 if family == '6' else socket.AF_INET
    payload = bytes((i * 37 + 19) % 256 for i in range(int(length)))
    with socket.socket(family, socket.SOCK_STREAM if protocol == 'tcp' else socket.SOCK_DGRAM) as s:
        s.settimeout(10)
        s.connect((address, int(port)))
        s.sendall(payload)
        if protocol == 'tcp':
            s.shutdown(socket.SHUT_WR)
            response = bytearray()
            while len(response) < len(payload):
                part = s.recv(16384)
                if not part: break
                response.extend(part)
        else:
            response = s.recv(65535)
        assert response == payload, (len(response), len(payload))
    print(json.dumps({'protocol': protocol, 'bytes': len(payload), 'matched': True}))
else:
    raise RuntimeError('unknown helper mode')
'''


def run(*command, check=True, timeout=15, input=None):
    command = list(map(str, command))
    result = subprocess.run(command, input=input, text=True, capture_output=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f"command failed: {' '.join(command)}\n{result.stdout}\n{result.stderr}")
    return result


def wait(predicate, label, timeout=25):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(.1)
    raise AssertionError('timeout: ' + label)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', default='build-wsl-reload/tunnel')
    parser.add_argument('--work', default='build-wsl-reload/tcp-network-tests')
    args = parser.parse_args()
    if sys.platform != 'linux' or os.geteuid() != 0:
        raise SystemExit('Requires Linux/WSL root and network namespace privileges.')
    binary = Path(args.binary).resolve(strict=True)
    work = Path(args.work).resolve()
    work.mkdir(parents=True, exist_ok=True)
    helper = work / 'socket_helper.py'
    helper.write_text(HELPER, encoding='utf-8')
    prefix = 'ttcp' + str(os.getpid())
    spaces = {node: prefix + node.lower() for node in ('H', 'A', 'B', 'C')}
    endpoints = {node: f'192.0.2.{i + 1}:45000' for i, node in enumerate('ABC')}
    address4 = {node: f'10.97.0.{i + 1}' for i, node in enumerate('ABC')}
    address6 = {node: f'fd00:97::{i + 1}' for i, node in enumerate('ABC')}
    graph = {'A': ['B'], 'B': ['A', 'C'], 'C': ['B']}
    made, handles, helpers, passed, cleanup_errors = [], [], [], [], []
    processes, configurations = {}, {}
    result = {'ok': False, 'passed': passed, 'namespaces': spaces, 'cleanup_errors': cleanup_errors}

    def ns(node, *command, **kwargs):
        return run('ip', 'netns', 'exec', spaces[node], *command, **kwargs)

    def mark(label):
        passed.append(label)
        print('PASS:', label, flush=True)

    def state(node):
        process = processes.get(node)
        if process and process.poll() is not None:
            raise AssertionError(f'{node} exited unexpectedly ({process.returncode}): ' + (work / f'{node}.log').read_text()[-6000:])
        try:
            return json.loads((work / f'{node}.status.json').read_text(encoding='utf-8'))
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def route(node, destination, network='10.97.0.0/24'):
        return next((r for r in state(node).get('routes', [])
            if r['node'] == endpoints[destination] and r['network'] == network), None)

    def converged(mode='tcp'):
        for node in 'ABC':
            current = state(node)
            peers = current.get('peers', [])
            if len(peers) != len(graph[node]) or current.get('pending_connections', 1):
                return False
            for peer in peers:
                expected = mode if {node, next(n for n in 'ABC' if endpoints[n] == peer['node'])} == {'A', 'B'} else 'udp'
                if peer['state'] != 3 or peer.get('transport') != expected:
                    return False
        return all(route(src, dst, network) for src, dst in [('A', 'C'), ('C', 'A')]
            for network in ('10.97.0.0/24', 'fd00:97::/64'))

    def counters(node):
        values = state(node).get('counters', {})
        return values.get('peer_up', 0), values.get('peer_down', 0)

    def save(node):
        path = work / f'{node}.json'
        temporary = path.with_suffix('.new')
        temporary.write_text(json.dumps(configurations[node], indent=2), encoding='utf-8')
        run(binary, temporary, '--check')
        temporary.replace(path)

    def block_udp(enable):
        if not enable:
            ns('A', 'nft', 'delete', 'table', 'inet', 'tcp_encapsulation_test')
            return
        ns('A', 'nft', '-f', '-', input='''table inet tcp_encapsulation_test {
 chain incoming { type filter hook input priority 0; policy accept; iifname "eth0" meta l4proto udp counter drop; }
 chain outgoing { type filter hook output priority 0; policy accept; oifname "eth0" meta l4proto udp counter drop; }
}
''')

    def request(source, destination, protocol, ipv6=False, length=None):
        length = length or (65536 if protocol == 'tcp' else (1232 if ipv6 else 1252))
        address = address6[destination] if ipv6 else address4[destination]
        reply = ns(source, sys.executable, helper, 'request', '6' if ipv6 else '4', protocol,
            address, '36197', length, timeout=15)
        report = json.loads(reply.stdout)
        assert report['matched'] and report['bytes'] == length, report

    def ping(source, destination, ipv6=False, length=None, success=True):
        command = ['ping', '-6' if ipv6 else '-4', '-c', '1', '-W', '3']
        if length is not None:
            command += ['-M', 'do', '-s', str(length)]
        reply = ns(source, *command, address6[destination] if ipv6 else address4[destination], check=False, timeout=6)
        assert (reply.returncode == 0) == success, reply.stdout + reply.stderr

    try:
        existing = {line.split()[0] for line in run('ip', 'netns', 'list').stdout.splitlines()}
        assert not existing.intersection(spaces.values()), 'namespace name collision'
        for namespace in spaces.values():
            run('ip', 'netns', 'add', namespace)
            made.append(namespace)
            run('ip', '-n', namespace, 'link', 'set', 'lo', 'up')
        run('ip', '-n', spaces['H'], 'link', 'add', 'br0', 'type', 'bridge')
        run('ip', '-n', spaces['H'], 'link', 'set', 'br0', 'up')
        for index, node in enumerate('ABC'):
            left, right = f'p{index}', f'q{index}'
            run('ip', '-n', spaces['H'], 'link', 'add', left, 'type', 'veth', 'peer', 'name', right)
            run('ip', '-n', spaces['H'], 'link', 'set', right, 'netns', spaces[node])
            run('ip', '-n', spaces['H'], 'link', 'set', left, 'master', 'br0')
            run('ip', '-n', spaces['H'], 'link', 'set', left, 'up')
            run('ip', '-n', spaces[node], 'link', 'set', right, 'name', 'eth0')
            run('ip', '-n', spaces[node], 'address', 'add', f'192.0.2.{index + 1}/24', 'dev', 'eth0')
            run('ip', '-n', spaces[node], 'link', 'set', 'eth0', 'up')
        block_udp(True)
        # Confirm the namespace-local firewall really drops outer UDP before
        # drawing conclusions from a successful TCP encapsulated tunnel.
        ns('A', sys.executable, '-c', """import errno, socket
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    try:
        sock.sendto(b'blocked-test', ('192.0.2.2', 45000))
    except OSError as error:
        if error.errno not in (errno.EPERM, errno.EACCES):
            raise
""")
        rules = json.loads(ns('A', 'nft', '-j', 'list', 'table', 'inet', 'tcp_encapsulation_test').stdout)
        assert any(expr.get('counter', {}).get('packets', 0) > 0 for entry in rules['nftables']
            for expr in entry.get('rule', {}).get('expr', [])), rules
        mark('outer_udp_blocked_only_inside_node_a_namespace')
        for node in 'ABC':
            configurations[node] = {'device_backend': 'tun', 'address': endpoints[node], 'networks': [address4[node] + '/24', address6[node] + '/64'],
                'peers': [{'address': endpoints[peer], 'shared_key': 'tcp-netns-test-key',
                    'networks': ['10.97.0.0/24', 'fd00:97::/64']} for peer in graph[node]]}
            if node == 'A':
                configurations[node]['peers'][0]['transport'] = 'tcp'
            save(node)
            (work / f'{node}.status.json').unlink(missing_ok=True)
            log = (work / f'{node}.log').open('wb', buffering=0)
            handles.append(log)
            processes[node] = subprocess.Popen(['ip', 'netns', 'exec', spaces[node], str(binary), str(work / f'{node}.json'),
                '--tun-name', 'overlay0', '--status-file', str(work / f'{node}.status.json')], stdout=log, stderr=log)
        wait(converged, 'A TCP B UDP C convergence')
        mark('one_sided_tcp_selection_and_mixed_multihop_convergence')
        for node in 'ABC':
            process = processes[node]
            assert len(list(Path(f'/proc/{process.pid}/task').iterdir())) == 1
            udp_inodes = set()
            for table in ('udp', 'udp6'):
                for line in Path(f'/proc/{process.pid}/net/{table}').read_text().splitlines()[1:]:
                    udp_inodes.add(line.split()[9])
            links = [os.readlink(fd) for fd in Path(f'/proc/{process.pid}/fd').iterdir()]
            assert sum(link.startswith('socket:[') and link[8:-1] in udp_inodes for link in links) == 1
            assert links.count('/dev/net/tun') == 1
        mark('one_thread_one_udp_one_tun_preserved')
        for node in ('A', 'C'):
            ready = work / f'{node}.echo.ready'
            ready.unlink(missing_ok=True)
            log = (work / f'{node}.echo.log').open('wb', buffering=0)
            handles.append(log)
            process = subprocess.Popen(['ip', 'netns', 'exec', spaces[node], sys.executable, str(helper),
                'serve', address4[node], address6[node], '36197', str(ready)], stdout=log, stderr=log)
            helpers.append(process)
            wait(lambda: ready.exists() or process.poll() is not None, 'dual-stack echo helper ' + node)
            assert process.poll() is None, (work / f'{node}.echo.log').read_text()
        for source, destination in [('A', 'C'), ('C', 'A')]:
            for ipv6 in (False, True):
                ping(source, destination, ipv6)
                request(source, destination, 'tcp', ipv6)
                request(source, destination, 'udp', ipv6)
        mark('bidirectional_ipv4_ipv6_tcp_stream_udp_echo_and_icmp')
        ping('A', 'C', length=1252)
        ping('A', 'C', True, 1232)
        ping('A', 'C', length=1253, success=False)
        ping('A', 'C', True, 1233, success=False)
        mark('real_tun_1280_mtu_boundaries')
        assert state('A')['counters'].get('tcp_data_sent', 0) > 0
        assert state('A')['counters'].get('udp_data_sent', 0) == 0
        assert state('B')['counters'].get('tcp_data_received', 0) > 0
        assert state('B')['counters'].get('udp_data_sent', 0) > 0
        assert not state('B')['end_sessions'], 'transit must not terminate end-to-end sessions'
        mark('mixed_transport_counters_and_end_to_end_session_boundary')
        original = {node: (processes[node].pid, state(node)['public_key']) for node in 'ABC'}
        baseline = {node: counters(node) for node in 'ABC'}
        started = time.monotonic()
        wait(lambda: time.monotonic() - started >= 22, 'TCP heartbeat without outer UDP beyond 20s', 25)
        assert converged()
        assert {node: counters(node) for node in 'ABC'} == baseline
        request('A', 'C', 'tcp')
        mark('tcp_heartbeat_survives_udp_block_beyond_twenty_seconds')

        # A single peer's transport preference can be reloaded through SIGHUP.
        # B-C must retain its existing adjacency while A-B reconnects.
        block_udp(False)
        unaffected = counters('C')
        configurations['A']['peers'][0]['transport'] = 'udp'
        save('A')
        processes['A'].send_signal(signal.SIGHUP)
        wait(lambda: converged('udp'), 'TCP to UDP hot reload')
        assert counters('C') == unaffected
        request('A', 'C', 'tcp')
        request('C', 'A', 'udp', True)
        assert state('A')['counters'].get('udp_data_sent', 0) > 0
        mark('sighup_tcp_to_udp_preserves_other_adjacency')
        configurations['A']['peers'][0]['transport'] = 'tcp'
        save('A')
        processes['A'].send_signal(signal.SIGHUP)
        wait(converged, 'UDP to TCP hot reload')
        block_udp(True)
        request('A', 'C', 'udp')
        request('C', 'A', 'tcp', True)
        assert counters('C') == unaffected
        assert {node: (processes[node].pid, state(node)['public_key']) for node in 'ABC'} == original
        mark('sighup_back_to_tcp_same_pid_and_identity')
        result['ok'] = True
    except Exception as error:
        result['error'] = str(error)
        result['traceback'] = traceback.format_exc()
        print(result['traceback'], file=sys.stderr, flush=True)
    finally:
        for process in helpers + list(processes.values()):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            if process in processes.values() and process.returncode != 0:
                cleanup_errors.append(f'core PID {process.pid} exited {process.returncode}')
        for handle in handles:
            handle.close()
        for namespace in reversed(made):
            try:
                run('ip', 'netns', 'delete', namespace)
            except Exception as error:
                cleanup_errors.append(str(error))
        if cleanup_errors:
            result['ok'] = False
        (work / 'results.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result, indent=2), flush=True)
    return 0 if result['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
