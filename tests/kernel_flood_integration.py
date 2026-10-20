#!/usr/bin/env python3
"""IPv6 outer UDP and flood RPF on a cyclic kernel/kernel/TUN topology."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import traceback
from tcp_network_integration import HELPER, run, wait

FLOOD = r'''
import json, selectors, socket, struct, sys, time
from pathlib import Path
mode, local4, output = sys.argv[1:4]
interface = socket.if_nametoindex('overlay0')
if mode == 'receive':
    events = selectors.DefaultSelector()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('', 36200))
    s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
        socket.inet_aton('239.98.0.1') + socket.inet_aton(local4))
    events.register(s, selectors.EVENT_READ)
    v6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    v6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    v6.bind(('::', 36200))
    v6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP,
        socket.inet_pton(socket.AF_INET6, 'ff05::98') + struct.pack('@I', interface))
    events.register(v6, selectors.EVENT_READ)
    Path(output + '.ready').write_text('ready')
    while True:
        for event, _ in events.select():
            data, source = event.fileobj.recvfrom(4096)
            with Path(output).open('a') as f:
                f.write(json.dumps({'token': data.decode(), 'source': source[0]}) + '\n')
elif mode == 'send':
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind((local4, 0))
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local4))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 16)
        s.sendto(b'broadcast4', ('10.99.0.255', 36200))
        s.sendto(b'multicast4', ('239.98.0.1', 36200))
    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, interface)
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 16)
        s.sendto(b'multicast6', ('ff05::98', 36200, 0, interface))
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True)
    parser.add_argument('--work', required=True)
    args = parser.parse_args()
    binary, work = Path(args.binary).resolve(), Path(args.work).resolve()
    work.mkdir(parents=True, exist_ok=True)
    (work / 'echo.py').write_text(HELPER)
    (work / 'flood.py').write_text(FLOOD)
    spaces = {node: 'tkf' + str(os.getpid()) + node.lower() for node in 'HABC'}
    made, cores, helpers, handles, passed = [], {}, [], [], []
    report = {'ok': False, 'passed': passed, 'cleanup_errors': []}

    def ns(node, *command, **kwargs):
        return run('ip', 'netns', 'exec', spaces[node], *command, **kwargs)

    def mark(label):
        passed.append(label)
        print('PASS:', label, flush=True)

    def state(node):
        if cores[node].poll() is not None:
            raise AssertionError(node + ' exited: ' + (work / (node + '.log')).read_text()[-6000:])
        try:
            return json.loads((work / (node + '.status')).read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    try:
        for node in 'HABC':
            run('ip', 'netns', 'add', spaces[node])
            made.append(spaces[node])
            ns(node, 'ip', 'link', 'set', 'lo', 'up')
        ns('H', 'ip', 'link', 'add', 'br0', 'type', 'bridge')
        ns('H', 'ip', 'link', 'set', 'br0', 'up')
        for index, node in enumerate('ABC', 1):
            left, right = 'p' + node, 'q' + node
            ns('H', 'ip', 'link', 'add', left, 'type', 'veth', 'peer', 'name', right)
            ns('H', 'ip', 'link', 'set', right, 'netns', spaces[node])
            ns('H', 'ip', 'link', 'set', left, 'master', 'br0')
            ns('H', 'ip', 'link', 'set', left, 'up')
            ns(node, 'ip', 'link', 'set', right, 'name', 'eth0')
            ns(node, 'ip', '-6', 'address', 'add', f'fd00:192::{index}/64', 'dev', 'eth0', 'nodad')
            ns(node, 'ip', 'link', 'set', 'eth0', 'up')
            cfg = {'address': f'[fd00:192::{index}]:45299',
                'networks': [f'10.99.0.{index}/24', f'fd00:99::{index}/64'],
                'peers': [{'address': f'[fd00:192::{peer + 1}]:45299', 'shared_key': 'kernel-flood-test-key',
                    'networks': ['10.99.0.0/24', 'fd00:99::/64']}
                    for peer in range(3) if peer + 1 != index]}
            cfg['device_backend'] = 'kernel' if node in 'AB' else 'tun'
            config = work / (node + '.json')
            config.write_text(json.dumps(cfg))
            log = (work / (node + '.log')).open('wb', buffering=0)
            handles.append(log)
            cores[node] = subprocess.Popen(['ip', 'netns', 'exec', spaces[node], str(binary), str(config),
                '--tun-name', 'overlay0', '--status-file', str(work / (node + '.status'))], stdout=log, stderr=log)
        def converged():
            return all(len(state(n).get('peers', [])) == 2 and all(p['state'] == 3 for p in state(n)['peers']) for n in 'ABC')
        wait(converged, 'IPv6 outer cyclic topology', 90)
        mark('ipv6_outer_udp_kernel_and_tun_adjacencies')
        ready = work / 'echo.ready'
        log = (work / 'echo.log').open('wb', buffering=0)
        handles.append(log)
        helpers.append(subprocess.Popen(['ip', 'netns', 'exec', spaces['A'], sys.executable, str(work / 'echo.py'),
            'serve', '10.99.0.1', 'fd00:99::1', '36199', str(ready)], stdout=log, stderr=log))
        wait(ready.exists, 'echo server', 30)
        for source in ('B', 'C'):
            for ipv6 in (False, True):
                address = 'fd00:99::1' if ipv6 else '10.99.0.1'
                wait(lambda: ns(source, 'ping', '-6' if ipv6 else '-4', '-c', '1', '-W', '1', address,
                    check=False).returncode == 0, 'E2E over outer UDP6', 30)
                for protocol in ('tcp', 'udp'):
                    response = ns(source, sys.executable, work / 'echo.py', 'request', '6' if ipv6 else '4',
                        protocol, address, '36199', 16384 if protocol == 'tcp' else 1200, timeout=30)
                    assert json.loads(response.stdout)['matched']
        mark('ipv4_ipv6_payloads_over_real_outer_udp6')
        for index, node in enumerate('AB', 1):
            output = work / (node + '.flood')
            log = (work / (node + '.flood.log')).open('wb', buffering=0)
            handles.append(log)
            helpers.append(subprocess.Popen(['ip', 'netns', 'exec', spaces[node], sys.executable,
                str(work / 'flood.py'), 'receive', f'10.99.0.{index}', str(output)], stdout=log, stderr=log))
            wait(lambda: Path(str(output) + '.ready').exists(), 'multicast listener', 20)
        ns('C', sys.executable, work / 'flood.py', 'send', '10.99.0.3', 'unused')
        def received():
            for node in 'AB':
                path = work / (node + '.flood')
                if not path.exists():
                    return False
                tokens = [json.loads(line)['token'] for line in path.read_text().splitlines()]
                if set(tokens) != {'broadcast4', 'multicast4', 'multicast6'}:
                    return False
            return True
        wait(received, 'IPv4 broadcast and IPv4/IPv6 multicast', 20)
        time.sleep(2)
        for node in 'AB':
            tokens = [json.loads(line)['token'] for line in (work / (node + '.flood')).read_text().splitlines()]
            assert len(tokens) == 3, (node, tokens)
            assert state(node)['counters']['kernel_rpf_drop'] > 0, state(node)['counters']
        mark('cyclic_broadcast_multicast_delivered_once_with_wrong_peer_rpf_drop')
        report['ok'] = True
    except Exception as error:
        report.update(error=str(error), traceback=traceback.format_exc())
        print(report['traceback'], flush=True)
        for path in work.glob('*'):
            if path.suffix in ('.log', '.status', '.flood'):
                print('DIAGNOSTIC', path.name, path.read_text(errors='replace')[-12000:], flush=True)
    finally:
        for process in helpers + list(cores.values()):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            if process in cores.values() and process.returncode:
                report['cleanup_errors'].append('core exit ' + str(process.returncode))
        for handle in handles:
            handle.close()
        for namespace in reversed(made):
            result = run('ip', 'netns', 'delete', namespace, check=False)
            if result.returncode:
                report['cleanup_errors'].append(result.stderr)
        if report['cleanup_errors']:
            report['ok'] = False
        (work / 'results.json').write_text(json.dumps(report, indent=2))
        print(json.dumps(report), flush=True)
    return 0 if report['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
