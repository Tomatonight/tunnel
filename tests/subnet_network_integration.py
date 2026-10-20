#!/usr/bin/env python3
"""Real subnet routing/NAT tests in fresh, isolated Linux network namespaces.

Requires root, iproute2, ping, nftables and an already-built native core.
Topology: C -- R -- A/B, with A and B attached to the same separate LAN H.
All addresses, forwarding settings and firewall rules belong to test namespaces.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import traceback


HELPER = r'''
import json, selectors, socket, sys, time
from pathlib import Path
mode, family, address, port, output = sys.argv[1:6]
af = socket.AF_INET6 if family == '6' else socket.AF_INET
port = int(port)
if mode == 'request':
    protocol, source, token = sys.argv[6:9]
    try:
        with socket.socket(af, socket.SOCK_STREAM if protocol == 'tcp' else socket.SOCK_DGRAM) as s:
            s.settimeout(3)
            s.bind((source, 0))
            s.connect((address, port))
            s.sendall(token.encode())
            response = json.loads(s.recv(65535).decode())
            if response['token'] != token:
                raise RuntimeError('unexpected echo token')
            print(json.dumps(response), flush=True)
    except Exception as error:
        print(json.dumps({'error': str(error)}), flush=True)
        sys.exit(2)
    sys.exit(0)

events = selectors.DefaultSelector()
log = Path(output)
def record(protocol, source, token=''):
    value = {'protocol': protocol, 'source': source, 'token': token}
    with log.open('a', encoding='utf-8') as stream:
        stream.write(json.dumps(value) + '\n')
    return json.dumps(value).encode()
for protocol in ('tcp', 'udp'):
    s = socket.socket(af, socket.SOCK_STREAM if protocol == 'tcp' else socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((address, port))
    if protocol == 'tcp': s.listen(16)
    events.register(s, selectors.EVENT_READ, protocol)
icmp = socket.socket(af, socket.SOCK_RAW, socket.IPPROTO_ICMPV6 if af == socket.AF_INET6 else socket.IPPROTO_ICMP)
icmp.bind((address, 0))
events.register(icmp, selectors.EVENT_READ, 'icmp')
Path(output + '.ready').write_text('ready')
while True:
    for event, _ in events.select(.5):
        s, protocol = event.fileobj, event.data
        if protocol == 'tcp':
            conn, remote = s.accept()
            try:
                with conn:
                    conn.settimeout(2)
                    data = conn.recv(65535)
                    if data: conn.sendall(record(protocol, remote[0], data.decode()))
            except (OSError, UnicodeError): pass
        elif protocol == 'udp':
            data, remote = s.recvfrom(65535)
            s.sendto(record(protocol, remote[0], data.decode()), remote)
        else:
            data, remote = s.recvfrom(65535)
            offset = 0 if af == socket.AF_INET6 else (data[0] & 15) * 4
            if len(data) > offset and data[offset] == (128 if af == socket.AF_INET6 else 8):
                record('icmp', remote[0])
'''


def run(*args, check=True, timeout=15, input=None):
    command = list(map(str, args))
    result = subprocess.run(command, input=input, text=True, capture_output=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f"command failed: {' '.join(command)}\n{result.stdout}\n{result.stderr}")
    return result


def wait(predicate, label, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(.1)
    if not predicate():
        raise AssertionError('timeout: ' + label)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', default='build-wsl/tunnel')
    parser.add_argument('--device-backend', choices=('tun', 'kernel'), default='tun')
    parser.add_argument('--work', default='build-wsl/subnet-network-tests')
    parser.add_argument('--ipv4-only', action='store_true', help='Explicitly skip the optional IPv6 routed and SNAT phases')
    args = parser.parse_args()
    if sys.platform != 'linux' or os.geteuid() != 0:
        raise SystemExit('Requires Linux/WSL root and network namespace privileges.')
    binary = Path(args.binary).resolve(strict=True)
    work = Path(args.work).resolve()
    work.mkdir(parents=True, exist_ok=True)
    helper = work / 'subnet_socket_helper.py'
    helper.write_text(HELPER, encoding='utf-8')
    prefix = 'tsn' + str(os.getpid())
    spaces = {node: prefix + suffix for node, suffix in [('hub', 'h'), ('C', 'c'), ('R', 'r'), ('A', 'a'), ('B', 'b'), ('H', 'l')]}
    transport = {'C': '192.0.2.1', 'R': '192.0.2.2', 'A': '192.0.2.3', 'B': '192.0.2.4'}
    endpoints = {node: address + ':45000' for node, address in transport.items()}
    virtual = {'C': '10.90.0.1', 'R': '10.90.0.2', 'A': '10.90.0.3', 'B': '10.90.0.4'}
    lan = {'A': '10.91.0.1', 'B': '10.91.0.2', 'H': '10.91.0.100'}
    virtual6 = {'C': 'fd00:90::1', 'R': 'fd00:90::2', 'A': 'fd00:90::3', 'B': 'fd00:90::4'}
    lan6 = {'A': 'fd00:91::1', 'B': 'fd00:91::2', 'H': 'fd00:91::100'}
    tunnel, subnet = '10.90.0.0/24', '10.91.0.0/24'
    tunnel6, subnet6 = 'fd00:90::/64', 'fd00:91::/64'
    made, log_handles, helper_processes, passed, shutdown_errors = [], [], [], [], []
    processes, configurations, seen_status, baselines = {}, {}, set(), {}
    result = {'ok': False, 'passed': passed, 'namespaces': spaces}

    def ns(node, *command, **kwargs):
        return run('ip', 'netns', 'exec', spaces[node], *command, **kwargs)

    def mark(label):
        passed.append(label)
        print('PASS:', label, flush=True)

    def state(node):
        last_error = None
        for _ in range(5):
            try:
                value = json.loads((work / f'{node}.status.json').read_text(encoding='utf-8'))
                seen_status.add(node)
                return value
            except FileNotFoundError as error:
                if node not in seen_status:
                    return {}
                last_error = error
            except (OSError, ValueError) as error:
                last_error = error
            time.sleep(.02)
        raise AssertionError(f'cannot read {node} status: {last_error}')

    def selected(prefix=subnet):
        return next((route for route in state('C').get('subnet_routes', []) if route['prefix'] == prefix and route['state'] == 'active'), None)

    def local_active(node, prefix=subnet):
        return any(route['prefix'] == prefix and route['active'] for route in state(node).get('local_exports', []))

    def kernel_route(prefix=subnet, v6=False):
        routes = json.loads(ns('C', 'ip', '-6' if v6 else '-4', '-j', 'route', 'show', 'exact', prefix).stdout)
        return any(route.get('dst') == prefix and route.get('dev') == 'overlay0' for route in routes)

    def save(node):
        configurations[node]['device_backend'] = args.device_backend
        path = work / f'{node}.json'
        path.write_text(json.dumps(configurations[node], indent=2), encoding='utf-8')
        run(binary, path, '--check')

    def start(node):
        seen_status.discard(node)
        (work / f'{node}.status.json').unlink(missing_ok=True)
        log = open(work / f'{node}.log', 'ab', buffering=0)
        log_handles.append(log)
        processes[node] = subprocess.Popen(['ip', 'netns', 'exec', spaces[node], str(binary), str(work / f'{node}.json'),
            '--status-file', str(work / f'{node}.status.json'), '--tun-name', 'overlay0', '--stdio-control'],
            stdin=subprocess.PIPE, stdout=log, stderr=log)

    def stop(node):
        process = processes.pop(node, None)
        if not process:
            return
        if process.poll() is None:
            try:
                process.stdin.write(b'STOP\n')
                process.stdin.flush()
                process.wait(8)
            except (BrokenPipeError, subprocess.TimeoutExpired):
                process.kill()
                process.wait(5)
        try:
            process.stdin.close()
        except OSError:
            pass
        if process.returncode != 0:
            shutdown_errors.append(f'{node}: exit {process.returncode}')

    def attach(node, bridge, interface, index, address):
        left, right = f'p{index}', f'q{index}'
        run('ip', '-n', spaces['hub'], 'link', 'add', left, 'type', 'veth', 'peer', 'name', right)
        run('ip', '-n', spaces['hub'], 'link', 'set', right, 'netns', spaces[node])
        run('ip', '-n', spaces['hub'], 'link', 'set', left, 'master', bridge)
        run('ip', '-n', spaces['hub'], 'link', 'set', left, 'up')
        run('ip', '-n', spaces[node], 'link', 'set', right, 'name', interface)
        run('ip', '-n', spaces[node], 'address', 'add', address + '/24', 'dev', interface)
        run('ip', '-n', spaces[node], 'link', 'set', interface, 'up')

    def serve(node, address, port, label, v6=False):
        output = work / (label + '.jsonl')
        output.write_text('', encoding='utf-8')
        Path(str(output) + '.ready').unlink(missing_ok=True)
        log = open(work / (label + '.log'), 'ab', buffering=0)
        log_handles.append(log)
        process = subprocess.Popen(['ip', 'netns', 'exec', spaces[node], sys.executable, str(helper), 'serve',
            '6' if v6 else '4', address, str(port), str(output)], stdout=log, stderr=log)
        helper_processes.append(process)
        wait(lambda: Path(str(output) + '.ready').exists(), 'socket helper ' + label, 10)
        return output

    def records(path):
        # Ignore only a currently incomplete final append, never complete malformed lines.
        content = path.read_text(encoding='utf-8')
        return [json.loads(line) for line in content.splitlines() if line and (line.endswith('}') or content.endswith('\n'))]

    def request(node, protocol, destination, source, port=36010, v6=False, should_succeed=True):
        last = None
        for attempt in range(4 if should_succeed else 1):
            token = f'{prefix}-{node}-{protocol}-{time.monotonic_ns()}-{attempt}'
            last = ns(node, sys.executable, helper, 'request', '6' if v6 else '4', destination, port, '-', protocol, source, token, check=False, timeout=15)
            if not should_succeed:
                assert last.returncode != 0, f'unsolicited {protocol} reached client: {last.stdout}'
                return
            if last.returncode == 0:
                return json.loads(last.stdout)
        raise AssertionError(f'{protocol} failed: {last.stdout} {last.stderr}')

    def ping(node, destination, source=None, v6=False, should_succeed=True):
        command = ['ping', '-6' if v6 else '-4', '-c', '1', '-W', '2']
        if source:
            command += ['-I', source]
        for _ in range(4 if should_succeed else 1):
            reply = ns(node, *command, destination, check=False, timeout=4)
            if reply.returncode == 0:
                if not should_succeed:
                    raise AssertionError('unsolicited ICMP echo reached client')
                return
        if should_succeed:
            raise AssertionError(f'ICMP failed: {reply.stdout} {reply.stderr}')

    def verify_protocols(expected_source, output, v6=False, automatic_source=False):
        host, source = (lan6['H'], virtual6['C']) if v6 else (lan['H'], virtual['C'])
        if automatic_source:
            source = '::' if v6 else '0.0.0.0'
        for protocol in ('tcp', 'udp'):
            response = request('C', protocol, host, source, v6=v6)
            assert response['source'] == expected_source, (protocol, response, expected_source)
        before = len(records(output))
        ping('C', host, None if automatic_source else source, v6)
        wait(lambda: any(record['protocol'] == 'icmp' and record['source'] == expected_source for record in records(output)[before:]), 'observed ICMP source')

    def reject_lan_initiation(client_log):
        before = len(records(client_log))
        for protocol in ('tcp', 'udp'):
            request('H', protocol, virtual['C'], lan['H'], port=36011, should_succeed=False)
        ping('H', virtual['C'], lan['H'], should_succeed=False)
        assert len(records(client_log)) == before, 'LAN-originated traffic was delivered to the client'

    try:
        existing = {line.split()[0] for line in run('ip', 'netns', 'list').stdout.splitlines()}
        assert not existing.intersection(spaces.values())
        for name in spaces.values():
            run('ip', 'netns', 'add', name)
            made.append(name)
            run('ip', '-n', name, 'link', 'set', 'lo', 'up')
        for bridge in ('transport0', 'lan0'):
            run('ip', '-n', spaces['hub'], 'link', 'add', bridge, 'type', 'bridge')
            run('ip', '-n', spaces['hub'], 'link', 'set', bridge, 'up')
        for index, node in enumerate(('C', 'R', 'A', 'B')):
            attach(node, 'transport0', 'eth0', index, transport[node])
        for index, node in enumerate(('A', 'B', 'H'), 4):
            attach(node, 'lan0', 'lan0', index, lan[node])
        ipv6 = not args.ipv4_only and ns('H', 'sysctl', '-n', 'net.ipv6.conf.all.disable_ipv6', check=False).returncode == 0
        if ipv6:
            for node in ('A', 'B', 'H'):
                ns(node, 'sysctl', '-w', 'net.ipv6.conf.all.disable_ipv6=0')
                ns(node, 'ip', '-6', 'address', 'add', lan6[node] + '/64', 'dev', 'lan0', 'nodad')
            # Older kernels lack per-interface force_forwarding. Make the routed
            # IPv6 prerequisite explicit inside our gateway namespaces only;
            # record 1 below as the baseline that shutdown must preserve.
            for node in ('A', 'B'):
                ns(node, 'sysctl', '-w', 'net.ipv6.conf.all.forwarding=1')
        else:
            result['ipv6_skip_reason'] = 'explicit --ipv4-only' if args.ipv4_only else 'IPv6 sysctl unavailable'
        for node in ('A', 'B'):
            baselines[node] = {'nft': ns(node, 'nft', 'list', 'ruleset').stdout,
                'ipv4_forwarding': ns(node, 'sysctl', '-n', 'net.ipv4.ip_forward').stdout.strip(),
                'lan_ipv4_forwarding': ns(node, 'sysctl', '-n', 'net.ipv4.conf.lan0.forwarding').stdout.strip()}
            if ipv6:
                baselines[node]['ipv6_forwarding'] = ns(node, 'sysctl', '-n', 'net.ipv6.conf.all.forwarding').stdout.strip()
        networks = [tunnel] + ([tunnel6] if ipv6 else [])
        for node in ('C', 'R', 'A', 'B'):
            adjacent = ('C', 'A', 'B') if node == 'R' else ('R',)
            config = {'address': endpoints[node], 'networks': [virtual[node] + '/24'] + ([virtual6[node] + '/64'] if ipv6 else []),
                'listen': {'enabled': node == 'R'}, 'peers': [{'address': endpoints[other], 'shared_key': 'test-subnet-pair-' + '-'.join(sorted((node, other))), 'networks': networks} for other in adjacent]}
            if node in ('A', 'B'):
                config['advertise_routes'] = [{'tunnel': tunnel, 'prefix': subnet, 'snat': True}]
            configurations[node] = config
            save(node)
        for node in ('R', 'C', 'A', 'B'):
            start(node)
        wait(lambda: local_active('A') and local_active('B') and selected() and kernel_route(), 'both gateways publish and client installs subnet route')
        wait(lambda: {endpoints['A'], endpoints['B']} <= {route['node'] for route in state('C').get('routes', []) if route['network'] == tunnel}, 'both indirect gateways reachable through relay')
        # Node reachability can arrive before that node's later prefix update.
        # Both gateways have equal distance here; wait for the documented
        # endpoint tie-break to converge instead of sampling a transient B.
        wait(lambda: selected() and selected()['gateway'] == endpoints['A'], 'equal-distance primary election converges to lower endpoint')
        gateway = next(node for node in ('A', 'B') if endpoints[node] == selected()['gateway'])
        backup = 'B' if gateway == 'A' else 'A'
        result['initial_gateway'] = gateway
        mark('two_gateways_publish_one_prefix_through_relay')
        host_log = serve('H', lan['H'], 36010, 'host-ipv4')
        client_log = serve('C', virtual['C'], 36011, 'client-inbound')
        verify_protocols(lan[gateway], host_log)
        mark('snat_tcp_udp_icmp_reach_lan_with_gateway_source_address')
        ns('H', 'ip', 'route', 'replace', tunnel, 'via', lan[gateway], 'dev', 'lan0')
        reject_lan_initiation(client_log)
        mark('lan_cannot_initiate_tcp_udp_or_icmp_to_client')
        stop(gateway)
        wait(lambda: selected() and selected()['gateway'] == endpoints[backup] and kernel_route(), 'backup selected after primary shutdown')
        verify_protocols(lan[backup], host_log)
        mark('gateway_failover_restores_new_tcp_udp_icmp_sessions')
        stop(backup)
        wait(lambda: not selected() and not kernel_route(), 'subnet route withdrawn after all gateways stop')
        ping('C', virtual['R'], virtual['C'])
        mark('all_gateways_down_withdraws_subnet_without_breaking_overlay')
        for node in ('A', 'B'):
            assert ns(node, 'nft', 'list', 'ruleset').stdout == baselines[node]['nft'], node + ' leaked firewall rules'
            assert ns(node, 'sysctl', '-n', 'net.ipv4.ip_forward').stdout.strip() == baselines[node]['ipv4_forwarding'], node + ' leaked forwarding setting'
            assert ns(node, 'sysctl', '-n', 'net.ipv4.conf.lan0.forwarding').stdout.strip() == baselines[node]['lan_ipv4_forwarding'], node + ' leaked LAN forwarding setting'
        mark('stopped_gateways_restore_firewall_and_forwarding_settings')
        configurations['A']['advertise_routes'] = [{'tunnel': tunnel, 'prefix': subnet}]
        if ipv6:
            configurations['A']['advertise_routes'].append({'tunnel': tunnel6, 'prefix': subnet6})
        save('A')
        ns('H', 'ip', 'route', 'replace', tunnel, 'via', lan['A'], 'dev', 'lan0')
        if ipv6:
            ns('H', 'ip', '-6', 'route', 'replace', tunnel6, 'via', lan6['A'], 'dev', 'lan0')
        start('A')
        wait(lambda: local_active('A') and selected() and selected()['gateway'] == endpoints['A'] and kernel_route(), 'routed gateway restarted without SNAT')
        verify_protocols(virtual['C'], host_log, automatic_source=True)
        reject_lan_initiation(client_log)
        mark('without_snat_automatic_route_source_is_virtual_ip_and_lan_initiation_is_blocked')
        if ipv6:
            host6_log = serve('H', lan6['H'], 36010, 'host-ipv6', True)
            wait(lambda: local_active('A', subnet6) and selected(subnet6) and kernel_route(subnet6, True), 'IPv6 exported prefix installed')
            verify_protocols(virtual6['C'], host6_log, True, automatic_source=True)
            mark('ipv6_routed_tcp_udp_icmp_automatically_select_virtual_source')
        stop('A')
        wait(lambda: not kernel_route() and (not ipv6 or not kernel_route(subnet6, True)), 'routed prefixes removed on shutdown')
        if ipv6:
            # Keep IPv4 routed and change only the existing IPv6 publication.
            # The client leaves its source unspecified; H must observe the
            # address selected by kernel masquerade on A's actual LAN egress.
            next(route for route in configurations['A']['advertise_routes'] if route['prefix'] == subnet6)['snat'] = True
            save('A')
            start('A')
            wait(lambda: local_active('A', subnet6) and selected(subnet6)
                and selected(subnet6)['gateway'] == endpoints['A'] and kernel_route(subnet6, True), 'IPv6 SNAT gateway restarted')
            verify_protocols(lan6['A'], host6_log, True, automatic_source=True)
            mark('ipv6_snat_tcp_udp_icmp_use_gateway_lan_source')
            stop('A')
            wait(lambda: not kernel_route() and not kernel_route(subnet6, True), 'IPv4 and IPv6 SNAT prefixes removed on shutdown')
        assert ns('A', 'nft', 'list', 'ruleset').stdout == baselines['A']['nft']
        assert ns('A', 'sysctl', '-n', 'net.ipv4.ip_forward').stdout.strip() == baselines['A']['ipv4_forwarding']
        assert ns('A', 'sysctl', '-n', 'net.ipv4.conf.lan0.forwarding').stdout.strip() == baselines['A']['lan_ipv4_forwarding']
        if ipv6:
            assert ns('A', 'sysctl', '-n', 'net.ipv6.conf.all.forwarding').stdout.strip() == baselines['A']['ipv6_forwarding']
        mark('routed_ipv4_ipv6_withdrawal_and_system_cleanup')
        result['ok'] = True
    except Exception as error:
        result['error'] = str(error)
        result['traceback'] = traceback.format_exc()
        result['failure_states'] = {}
        result['kernel_states'] = {}
        for node in ('C', 'A', 'H'):
            if spaces[node] in made:
                result['kernel_states'][node] = {}
                for label, command in [('addresses', ('ip', '-j', 'address')), ('ipv6_routes', ('ip', '-6', '-j', 'route')),
                        ('ipv6_neighbors', ('ip', '-6', '-j', 'neighbor')), ('firewall', ('nft', 'list', 'ruleset')),
                        ('ipv6_forwarding', ('sysctl', 'net.ipv6.conf.all.forwarding', 'net.ipv6.conf.default.forwarding', 'net.ipv6.conf.overlay0.forwarding', 'net.ipv6.conf.lan0.forwarding')),
                        ('ipv6_counters', ('cat', '/proc/net/snmp6'))]:
                    snapshot = ns(node, *command, check=False)
                    result['kernel_states'][node][label] = snapshot.stdout + snapshot.stderr
        for node in processes:
            try:
                result['failure_states'][node] = state(node)
            except Exception as read_error:
                result['failure_states'][node] = {'read_error': str(read_error)}
        print('FAIL:', error, flush=True)
        print(result['traceback'], flush=True)
    finally:
        for node in list(processes):
            stop(node)
        for process in helper_processes:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(3)
        for name in reversed(made):
            deleted = run('ip', 'netns', 'del', name, check=False)
            if deleted.returncode:
                shutdown_errors.append(name + ': ' + deleted.stderr.strip())
        listed = run('ip', 'netns', 'list', check=False)
        if listed.returncode:
            shutdown_errors.append('cannot verify namespace cleanup: ' + listed.stderr.strip())
        else:
            remaining = {line.split()[0] for line in listed.stdout.splitlines()}
            result['remaining_test_namespaces'] = sorted(remaining.intersection(made))
            if result['remaining_test_namespaces']:
                shutdown_errors.append('test namespaces remain after cleanup')
        for handle in log_handles:
            handle.close()
        if shutdown_errors:
            result['ok'] = False
            result['shutdown_errors'] = shutdown_errors
        result['count'] = len(passed)
        (work / 'results.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result, indent=2), flush=True)
    return 0 if result['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
