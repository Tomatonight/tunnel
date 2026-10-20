#!/usr/bin/env python3
"""Privileged Linux integration tests, confined to newly created namespaces.

Usage: sudo python3 tests/network_integration.py --binary build-wsl/tunnel
Requires iproute2, iputils-ping and nftables. No host routes/firewall are changed.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time

HELPER = r'''
import json, socket, struct, sys, time
from pathlib import Path
mode, family, address, token, output, start_marker = sys.argv[1:]
def await_start():
    end = time.monotonic() + 15
    while not Path(start_marker).exists():
        if time.monotonic() >= end: raise RuntimeError('test start barrier timed out')
        time.sleep(.01)
v6 = family == '6'
if mode == 'capture':
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    s.settimeout(.1)
    Path(output + '.ready').write_text('ready')
    await_start()
    end = time.monotonic() + 3
    count = data = plain = 0
    while time.monotonic() < end:
        try: packet = s.recv(65535)
        except socket.timeout: continue
        if len(packet) > 42 and packet[12:14] == b'\x08\x00' and packet[23] == 17:
            count += 1
            data += len(packet) > 300
            plain += token.encode() in packet
    Path(output).write_text(json.dumps({'udp': count, 'data': data, 'plaintext': plain}))
    sys.exit(0)
s = socket.socket(socket.AF_INET6 if v6 else socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b'overlay0\0')
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
index = socket.if_nametoindex('overlay0')
multicast = address.startswith('239.') or address.startswith('ff')
if mode == 'listen':
    s.bind(('::' if v6 else '0.0.0.0', 36001))
    if multicast:
        if v6: s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, socket.inet_pton(socket.AF_INET6, address) + struct.pack('I', index))
        else: s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, socket.inet_aton(address) + b'\0' * 4 + struct.pack('i', index))
    s.settimeout(.1)
    Path(output + '.ready').write_text('ready')
    await_start()
    end = time.monotonic() + 2
    count = 0
    while time.monotonic() < end:
        try: data = s.recv(65535)
        except socket.timeout: continue
        if data == token.encode(): count += 1
    Path(output).write_text(json.dumps({'received': count}))
else:
    s.bind(('fd00:77::1' if v6 else '10.77.0.1', 0))
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    if v6:
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, index)
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, 0)
    else:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton('10.77.0.1'))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)
    s.sendto(token.encode(), (address, 36001, 0, index) if v6 else (address, 36001))
'''


def run(*args, check=True, timeout=15, input=None):
    result = subprocess.run(list(map(str, args)), input=input, text=True, capture_output=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f"command failed: {' '.join(map(str, args))}\n{result.stdout}\n{result.stderr}")
    return result


def wait(predicate, label, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(.05)
    raise AssertionError('timeout: ' + label)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', default='build-wsl/tunnel')
    parser.add_argument('--work', default='build-wsl/network-tests')
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit('Run with root/CAP_NET_ADMIN in Linux/WSL.')
    binary = Path(args.binary).resolve(strict=True)
    work = Path(args.work).resolve()
    work.mkdir(parents=True, exist_ok=True)
    helper = work / 'udp_helper.py'
    helper.write_text(HELPER)
    prefix = 'tt' + str(os.getpid())
    hub = prefix + 'h'
    names = [prefix + c for c in 'abcd']
    made = []
    processes = [None] * 4
    logs = []
    helpers = []
    passed = []
    shutdown_errors = []

    def mark(label):
        passed.append(label)
        print('PASS:', label, flush=True)

    def ns(index, *cmd, **kwargs):
        return run('ip', 'netns', 'exec', names[index], *cmd, **kwargs)

    def state(index):
        try:
            return json.loads((work / f'{index}.status.json').read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def route(index, destination=3, network='10.77.0.0/24'):
        return next((r for r in state(index).get('routes', []) if r['node'] == f'192.0.2.{destination+1}:45000' and r['network'] == network), None)

    def hops(index=0):
        return len((route(index) or {}).get('next_hops', []))

    def start(index):
        log = open(work / f'{index}.log', 'ab', buffering=0)
        logs.append(log)
        processes[index] = subprocess.Popen(['ip', 'netns', 'exec', names[index], str(binary),
            str(work / f'{index}.json'), '--tun-name', 'overlay0', '--status-file', str(work / f'{index}.status.json')], stdout=log, stderr=log)

    def stop(index):
        p = processes[index]
        if p and p.poll() is None:
            p.terminate()
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait(timeout=5)
        if p and p.returncode != 0:
            shutdown_errors.append(f'node {index} exited {p.returncode}')
        processes[index] = None

    def helper_process(namespace, mode, family, address, token, filename, start_marker):
        output = work / filename
        for path in (output, Path(str(output) + '.ready')):
            if path.exists():
                path.unlink()
        p = subprocess.Popen(['ip', 'netns', 'exec', namespace, sys.executable, str(helper), mode, str(family), address, token, str(output), str(start_marker)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        helpers.append(p)
        wait(lambda: Path(str(output) + '.ready').exists() or p.poll() is not None, 'UDP helper ready')
        if p.poll() is not None:
            raise RuntimeError(p.communicate()[1])
        return p, output

    def exchange(address, indices, label, v6=False, capture=False):
        token = 'tunnel-integration-' + label + '-' + 'X' * 256
        start_marker = work / (label + '.start')
        start_marker.unlink(missing_ok=True)
        watchers = [helper_process(names[i], 'listen', 6 if v6 else 4, address, token, f'{label}-{i}.json', start_marker) for i in indices]
        observer = helper_process(hub, 'capture', 4, address, token, f'{label}-capture.json', start_marker) if capture else None
        # Start receive/capture deadlines only after every subprocess has bound its socket.
        start_marker.write_text('start')
        ns(0, sys.executable, helper, 'send', '6' if v6 else '4', address, token, '-', start_marker)
        for p, output in watchers:
            _, error = p.communicate(timeout=5)
            assert p.returncode == 0, error
            assert json.loads(output.read_text())['received'] == 1, output.read_text()
        if observer:
            p, output = observer
            _, error = p.communicate(timeout=5)
            assert p.returncode == 0, error
            report = json.loads(output.read_text())
            assert report['data'] > 0 and report['plaintext'] == 0, report
        mark(label)

    def filtering(protocol):
        # This table exists only in B's newly created test namespace.
        ns(1, 'nft', 'delete', 'table', 'inet', 'tunnel_test', check=False)
        if protocol:
            script = f'''table inet tunnel_test {{
 chain incoming {{ type filter hook input priority 0; policy accept; ip saddr 192.0.2.1 meta l4proto {protocol} drop; }}
 chain outgoing {{ type filter hook output priority 0; policy accept; ip daddr 192.0.2.1 meta l4proto {protocol} drop; }}
}}
'''
            ns(1, 'nft', '-f', '-', input=script)

    try:
        existing = {line.split()[0] for line in run('ip', 'netns', 'list').stdout.splitlines()}
        assert not existing.intersection(names + [hub]), 'namespace name collision'
        for name in [hub] + names:
            run('ip', 'netns', 'add', name)
            made.append(name)
            run('ip', '-n', name, 'link', 'set', 'lo', 'up')
        run('ip', '-n', hub, 'link', 'add', 'br0', 'type', 'bridge')
        run('ip', '-n', hub, 'link', 'set', 'br0', 'up')
        for i, name in enumerate(names):
            left, right = prefix + f'l{i}', prefix + f'r{i}'
            run('ip', '-n', hub, 'link', 'add', left, 'type', 'veth', 'peer', 'name', right)
            run('ip', '-n', hub, 'link', 'set', right, 'netns', name)
            run('ip', '-n', hub, 'link', 'set', left, 'master', 'br0')
            run('ip', '-n', hub, 'link', 'set', left, 'up')
            run('ip', '-n', name, 'link', 'set', right, 'name', 'eth0')
            run('ip', '-n', name, 'address', 'add', f'192.0.2.{i+1}/24', 'dev', 'eth0')
            run('ip', '-n', name, 'link', 'set', 'eth0', 'up')
        graph = [[1, 2], [0, 3], [0, 3], [1, 2]]
        for i in range(4):
            networks = [{'tunnel': '10.77.0.0/24', 'tunnel_ip': f'10.77.0.{i+1}'}]
            if i != 2:
                networks += [{'tunnel': 'fd00:77::/64', 'tunnel_ip': f'fd00:77::{i+1}'},
                             {'tunnel': '10.78.0.0/24', 'tunnel_ip': f'10.78.0.{i+1}'}]
            config = {'tun_mtu': 1280, 'transport_mtu': 1500,
                'listen': {'enabled': True, 'address': f'192.0.2.{i+1}:45000', 'bind_address': '0.0.0.0:45000', 'networks': networks},
                'peers': [{'address': f'192.0.2.{p+1}:45000', 'shared_key': f'test-link-{min(i,p)}-{max(i,p)}', 'networks': networks} for p in graph[i]]}
            if i % 2 == 0:
                # Run new and legacy files in the same topology. A exercises explicit
                # multi-network permissions; C exercises the single-network default.
                config = {'address': f'192.0.2.{i+1}:45000',
                    'networks': [n['tunnel_ip'] + '/' + n['tunnel'].split('/')[1] for n in networks],
                    'peers': [{'address': f'192.0.2.{p+1}:45000', 'shared_key': f'test-link-{min(i,p)}-{max(i,p)}'} for p in graph[i]]}
                if len(networks) > 1:
                    for peer in config['peers']:
                        peer['networks'] = [n['tunnel'] for n in networks]
            config['device_backend'] = 'tun'
            (work / f'{i}.json').write_text(json.dumps(config))
            start(i)
        wait(lambda: hops() == 2, 'diamond ECMP convergence')
        mark('four_nodes_authenticated_and_ecmp')
        for p in processes:
            assert len(list(Path(f'/proc/{p.pid}/task').iterdir())) == 1
            udp_inodes = set()
            for table in ('udp', 'udp6'):
                for line in Path(f'/proc/{p.pid}/net/{table}').read_text().splitlines()[1:]:
                    udp_inodes.add(line.split()[9])
            links = [os.readlink(fd) for fd in Path(f'/proc/{p.pid}/fd').iterdir()]
            assert sum(link.startswith('socket:[') and link[8:-1] in udp_inodes for link in links) == 1, links
            assert links.count('/dev/net/tun') == 1, links
        mark('one_thread_one_udp_one_tun_per_process')
        ns(0, 'ping', '-c', '2', '-W', '2', '10.77.0.4')
        ns(3, 'ping', '-c', '2', '-W', '2', '10.77.0.1')
        mark('bidirectional_multihop_ipv4')
        ns(0, 'ping', '-6', '-c', '2', '-W', '2', 'fd00:77::4')
        ns(0, 'ping', '-c', '2', '-W', '2', '10.78.0.4')
        mark('multiple_addresses_ipv6_and_second_network')
        assert route(2, 3, 'fd00:77::/64') is None
        mark('network_membership_isolation')
        ns(0, 'ping', '-c', '1', '-W', '2', '-M', 'do', '-s', '1252', '10.77.0.4')
        ns(0, 'ping', '-6', '-c', '1', '-W', '2', '-M', 'do', '-s', '1232', 'fd00:77::4')
        assert ns(0, 'ping', '-c', '1', '-W', '1', '-M', 'do', '-s', '1253', '10.77.0.4', check=False).returncode != 0
        mark('mtu_1280_boundary_and_oversize_rejection')
        exchange('10.77.0.4', [3], 'encrypted_udp_payload_on_underlay', capture=True)
        exchange('10.77.0.255', [1, 2, 3], 'broadcast_rpf_one_delivery')
        ns(0, 'ip', 'route', 'add', '239.77.0.9/32', 'dev', 'overlay0')
        exchange('239.77.0.9', [1, 2, 3], 'ipv4_multicast_rpf_one_delivery')
        ns(0, 'ip', '-6', 'route', 'add', 'ff05::123/128', 'dev', 'overlay0')
        exchange('ff05::123', [1, 3], 'ipv6_multicast_membership_boundary', v6=True)
        original_key = state(3)['public_key']
        session = next(s['id'] for s in state(0)['end_sessions'] if s['network'] == '10.77.0.0/24' and s['node'] == '192.0.2.4:45000')
        filtering('udp')
        failure_started = time.monotonic()
        wait(lambda: hops() == 1 and route(0)['next_hops'] == ['192.0.2.3:45000'], 'UDP-only failure withdrawal', 30)
        assert time.monotonic() - failure_started >= 14, 'UDP adjacency withdrawn before 20s inactivity threshold'
        ns(0, 'ping', '-c', '2', '-W', '2', '10.77.0.4')
        assert route(0)['key'] == original_key
        assert any(s['id'] == session for s in state(0)['end_sessions'])
        mark('udp_failure_ecmp_failover_preserves_e2e_key')
        filtering(None)
        wait(lambda: hops() == 2, 'UDP restored reconnect', 25)
        filtering('tcp')
        failure_started = time.monotonic()
        wait(lambda: hops() == 1, 'TCP-only failure withdrawal', 30)
        assert time.monotonic() - failure_started >= 14, 'TCP adjacency withdrawn before 20s inactivity threshold'
        ns(0, 'ping', '-c', '1', '-W', '2', '10.77.0.4')
        mark('tcp_failure_with_healthy_udp_withdraws_peer')
        filtering(None)
        wait(lambda: hops() == 2, 'TCP restored reconnect', 25)
        stop(3)
        wait(lambda: route(0) is None, 'all destination paths withdrawn')
        assert not any(s['node'] == '192.0.2.4:45000' for s in state(0).get('end_sessions', []))
        assert ns(3, 'ip', 'link', 'show', 'overlay0', check=False).returncode != 0
        mark('last_path_withdrawal_and_tun_cleanup')
        start(3)
        wait(lambda: hops() == 2 and route(0)['key'] != original_key, 'restarted destination publishes new key', 25)
        ns(0, 'ping', '-c', '2', '-W', '2', '10.77.0.4')
        mark('node_restart_new_key_and_session_recovery')
        result = {'passed': passed, 'count': len(passed), 'ok': True,
                  'config_formats': ['simplified', 'legacy', 'simplified', 'legacy']}
    except Exception as error:
        result = {'passed': passed, 'count': len(passed), 'ok': False, 'error': str(error)}
        for i in range(4):
            log = work / f'{i}.log'
            if log.exists():
                print(f'node {i} log:\n' + log.read_text(errors='replace')[-5000:], file=sys.stderr)
        raise
    finally:
        for p in helpers:
            if p.poll() is None:
                p.terminate()
                p.wait(timeout=5)
        for i in range(4):
            stop(i)
        for file in logs:
            file.close()
        for name in reversed(made):
            run('ip', 'netns', 'delete', name, check=False)
        if 'result' in locals():
            if shutdown_errors:
                result['ok'] = False
                result['shutdown_errors'] = shutdown_errors
            (work / 'results.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    if not result['ok']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
