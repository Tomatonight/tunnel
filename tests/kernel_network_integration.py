#!/usr/bin/env python3
"""Real Linux net_device/TUN interoperability test, preferably in kernel_vm.py.

The module is loaded only in the explicitly selected guest/host. Tests use fresh
network namespaces; they never change an existing interface or firewall rule.
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

from tcp_network_integration import HELPER, run, wait


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True)
    parser.add_argument('--module', required=True)
    parser.add_argument('--work', default='/tmp/tunnel-kernel-tests')
    parser.add_argument('--smoke', action='store_true')
    parser.add_argument('--suite', choices=('all', 'main', 'extras', 'flood', 'subnet'), default='all')
    args = parser.parse_args()
    work = Path(args.work).resolve()
    work.mkdir(parents=True, exist_ok=True)
    binary = Path(args.binary).resolve(strict=True)
    helper = work / 'socket_helper.py'
    helper.write_text(HELPER)
    passed, cleanup_errors, made, processes, helpers, handles = [], [], [], {}, [], []
    report = dict(ok=False, passed=passed, cleanup_errors=cleanup_errors)
    prefix = 'tk' + str(os.getpid())
    spaces = {node: prefix + node.lower() for node in 'HABC'}
    endpoints = {node: f'192.0.2.{index + 1}:45000' for index, node in enumerate('ABC')}
    address4 = {node: f'10.98.0.{index + 1}' for index, node in enumerate('ABC')}
    address6 = {node: f'fd00:98::{index + 1}' for index, node in enumerate('ABC')}
    graph = {'A': ['B'], 'B': ['A', 'C'], 'C': ['B']}
    configurations = {}
    loaded = False

    def mark(name):
        passed.append(name)
        print('PASS:', name, flush=True)

    def ns(node, *args, **kwargs):
        return run('ip', 'netns', 'exec', spaces[node], *args, **kwargs)

    def state(node):
        process = processes[node]
        if process.poll() is not None:
            raise AssertionError(node + ' exited: ' + (work / (node + '.log')).read_text()[-10000:])
        try:
            return json.loads((work / (node + '.status.json')).read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def route(node, destination, network):
        return next((r for r in state(node).get('routes', [])
            if r['node'] == endpoints[destination] and r['network'] == network), None)

    def converged(transport='tcp'):
        for node in 'ABC':
            current = state(node)
            peers = current.get('peers', [])
            if len(peers) != len(graph[node]) or current.get('pending_connections', 1):
                return False
            for peer in peers:
                expected = transport if {endpoints[node], peer['node']} == {endpoints['B'], endpoints['C']} else 'udp'
                if peer['state'] != 3 or peer.get('transport') != expected:
                    return False
        return all(route(src, dst, network) for src, dst in [('A', 'C'), ('C', 'A')]
            for network in ('10.98.0.0/24', 'fd00:98::/64'))

    def request(source, destination, protocol='tcp', ipv6=False):
        length = 32768 if protocol == 'tcp' else (1232 if ipv6 else 1252)
        result = ns(source, sys.executable, helper, 'request', '6' if ipv6 else '4', protocol,
            address6[destination] if ipv6 else address4[destination], '36198', length, timeout=30)
        assert json.loads(result.stdout)['matched']

    def ping(source, destination, ipv6=False, length=None, success=True):
        command = ['ping', '-6' if ipv6 else '-4', '-c', '2', '-W', '3']
        if length is not None:
            command += ['-M', 'do', '-s', str(length)]
        result = ns(source, *command, address6[destination] if ipv6 else address4[destination], check=False, timeout=15)
        assert (result.returncode == 0) == success, result.stdout + result.stderr

    try:
        assert sys.platform == 'linux' and os.geteuid() == 0
        run(binary, '--help')
        run('ip', 'netns', 'add', spaces['H'])
        made.append(spaces['H'])
        run('ip', '-n', spaces['H'], 'link', 'set', 'lo', 'up')
        mark('guest_boot_python_libraries_and_network_namespaces')
        if args.smoke:
            report['ok'] = True
            return 0
        minimal = work / 'missing-module.json'
        minimal.write_text(json.dumps({'address': '127.0.0.1:45298', 'networks': ['10.98.1.1/24']}))
        assert not Path('/dev/tunnel_kmod').exists(), 'run missing-module check before module is loaded'
        for options in ([], ['--device-backend', 'kernel']):
            result = run(binary, minimal, *options, '--run-for', '1', check=False, timeout=20)
            assert result.returncode != 0 and ('module' in result.stderr.lower() or 'tunnel_kmod' in result.stderr), result.stdout + result.stderr
        mark('default_and_explicit_kernel_fail_clearly_without_module')
        invalid = run(binary, minimal, '--device-backend', 'invalid', '--check', check=False)
        assert invalid.returncode != 0
        normalized = json.loads(run(binary, minimal, '--normalize-config').stdout)
        assert normalized.get('device_backend', 'kernel') == 'kernel'
        assert 'device backend kernel' in run(binary, minimal, '--check').stdout
        explicit_tun = json.loads(run(binary, minimal, '--device-backend', 'tun', '--normalize-config').stdout)
        assert explicit_tun.get('device_backend') == 'tun', 'explicit TUN selection must survive serialization'
        mark('linux_defaults_to_kernel_and_explicit_tun_is_preserved')
        run('insmod', Path(args.module).resolve(strict=True))
        loaded = True
        wait(lambda: Path('/dev/tunnel_kmod').exists(), 'module character device', 10)
        mark('module_load_and_character_device')
        abi = run(sys.executable, Path(__file__).with_name('kernel_uapi_test.py'), '--work', work / 'uapi',
            check=False, timeout=90)
        print(abi.stdout, abi.stderr, flush=True)
        assert abi.returncode == 0, 'kernel ioctl/crypto ABI regression failed'
        mark('kernel_ioctl_crypto_replay_and_lifecycle_regression')
        if args.suite not in ('all', 'main'):
            selected = ('flood', 'subnet') if args.suite == 'extras' else (args.suite,)
            for part in selected:
                script = 'kernel_flood_integration.py' if part == 'flood' else 'subnet_network_integration.py'
                command = [sys.executable, Path(__file__).with_name(script), '--binary', binary, '--work', work / part]
                if part == 'subnet':
                    command += ['--device-backend', 'kernel']
                result = run(*command, check=False, timeout=300)
                print(result.stdout, result.stderr, flush=True)
                assert result.returncode == 0, part + ' regression failed'
                report[part] = json.loads((work / part / 'results.json').read_text())
                mark(part + '_regression')
            report['ok'] = True
            return 0
        for node in 'ABC':
            run('ip', 'netns', 'add', spaces[node])
            made.append(spaces[node])
            run('ip', '-n', spaces[node], 'link', 'set', 'lo', 'up')
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
        for node in 'ABC':
            cfg = {'address': endpoints[node], 'networks': [address4[node] + '/24', address6[node] + '/64'],
                'peers': [{'address': endpoints[peer], 'shared_key': 'kernel-integration-test-key',
                    'networks': ['10.98.0.0/24', 'fd00:98::/64']} for peer in graph[node]]}
            if node == 'B':
                cfg['device_backend'] = 'kernel'
                next(p for p in cfg['peers'] if p['address'] == endpoints['C'])['transport'] = 'tcp'
            elif node == 'C':
                cfg['device_backend'] = 'tun'
            configurations[node] = cfg
            config_path = work / (node + '.json')
            config_path.write_text(json.dumps(cfg))
            command = ['ip', 'netns', 'exec', spaces[node], str(binary), str(config_path),
                '--tun-name', 'overlay0', '--status-file', str(work / (node + '.status.json'))]
            log = (work / (node + '.log')).open('wb', buffering=0)
            handles.append(log)
            processes[node] = subprocess.Popen(command, stdout=log, stderr=log)
        wait(converged, 'kernel A UDP kernel B TCP TUN C adjacency/routes', 90)
        assert state('A')['device_backend'] == 'kernel'
        assert state('B')['device_backend'] == 'kernel'
        assert state('C')['device_backend'] == 'tun'
        mark('default_kernel_and_explicit_tun_mixed_transport_convergence')
        for node in 'ABC':
            fds = [os.readlink(fd) for fd in Path(f'/proc/{processes[node].pid}/fd').iterdir()]
            if node in 'AB':
                assert '/dev/net/tun' not in fds and '/dev/tunnel_kmod' in fds, fds
            else:
                assert '/dev/net/tun' in fds, fds
        mark('kernel_backend_owns_no_tun_fd')
        for node in ('A', 'C'):
            ready = work / (node + '.ready')
            log = (work / (node + '.echo.log')).open('wb', buffering=0)
            handles.append(log)
            process = subprocess.Popen(['ip', 'netns', 'exec', spaces[node], sys.executable, str(helper),
                'serve', address4[node], address6[node], '36198', str(ready)], stdout=log, stderr=log)
            helpers.append(process)
            wait(lambda: ready.exists() or process.poll() is not None, 'echo helper ' + node, 30)
            assert process.poll() is None
        # The first packet can be dropped while E2E keys are negotiated by design.
        for source, destination in [('A', 'C'), ('C', 'A')]:
            for ipv6 in (False, True):
                warm = lambda: ns(source, 'ping', '-6' if ipv6 else '-4', '-c', '1', '-W', '1',
                    address6[destination] if ipv6 else address4[destination], check=False, timeout=5).returncode == 0
                wait(warm, 'E2E warmup ' + source + destination, 30)
                ping(source, destination, ipv6)
                request(source, destination, 'tcp', ipv6)
                request(source, destination, 'udp', ipv6)
        mark('bidirectional_dual_stack_encrypted_tcp_udp_icmp_through_kernel_transit')
        ping('A', 'C', length=1252)
        ping('A', 'C', True, 1232)
        ping('A', 'C', length=1253, success=False)
        ping('A', 'C', True, 1233, success=False)
        mark('net_device_mtu_boundaries')
        time.sleep(1)
        assert state('A')['counters']['kernel_tx_packets'] > 0
        assert state('A')['counters']['kernel_rx_packets'] > 0
        assert state('B')['counters']['kernel_forwarded'] > 0
        assert state('B')['counters'].get('tcp_data_sent', 0) > 0
        assert not state('B')['end_sessions'], 'transit must not terminate endpoint encryption'
        mark('kernel_dataplane_counters_and_end_to_end_transit_boundary')
        # Switching B-C to UDP exercises wire compatibility with the original
        # TUN implementation as well as mixed TLS/UDP datapath state replacement.
        original = {node: (processes[node].pid, state(node)['public_key']) for node in 'ABC'}
        next(p for p in configurations['B']['peers'] if p['address'] == endpoints['C'])['transport'] = 'udp'
        (work / 'B.json').write_text(json.dumps(configurations['B']))
        processes['B'].send_signal(signal.SIGHUP)
        wait(lambda: converged('udp'), 'hot reload TCP to UDP with kernel data path', 90)
        for source, destination in [('A', 'C'), ('C', 'A')]:
            for ipv6 in (False, True):
                request(source, destination, 'tcp', ipv6)
                request(source, destination, 'udp', ipv6)
        assert {node: (processes[node].pid, state(node)['public_key']) for node in 'ABC'} == original
        mark('kernel_to_tun_udp_wire_compatibility_and_peer_hot_reload')
        # A stopped control process cannot service TUN reads or encrypt a packet.
        # Shorter than its lease, kernel A must still answer already-established
        # UDP tunnel traffic entirely within the kernel.
        processes['A'].send_signal(signal.SIGSTOP)
        try:
            for ipv6 in (False, True):
                reply = ns('C', 'ping', '-6' if ipv6 else '-4', '-c', '1', '-W', '2',
                    address6['A'] if ipv6 else address4['A'], check=False, timeout=5)
                assert reply.returncode == 0, reply.stdout + reply.stderr
        finally:
            processes['A'].send_signal(signal.SIGCONT)
        mark('udp_data_continues_in_kernel_while_userspace_control_is_stopped')
        for backend in ('tun', 'kernel'):
            if backend == 'kernel':
                # Removing the explicit choice must restore Linux's default
                # during a live reload, as well as on a fresh startup.
                configurations['B'].pop('device_backend', None)
            else:
                configurations['B']['device_backend'] = backend
            (work / 'B.json').write_text(json.dumps(configurations['B']))
            processes['B'].send_signal(signal.SIGHUP)
            wait(lambda: state('B').get('device_backend') == backend and converged('udp'),
                'live backend switch to ' + backend, 90)
            fds = [os.readlink(fd) for fd in Path(f'/proc/{processes["B"].pid}/fd').iterdir()]
            assert ('/dev/net/tun' in fds) == (backend == 'tun'), fds
            assert ('/dev/tunnel_kmod' in fds) == (backend == 'kernel'), fds
            for ipv6 in (False, True):
                request('A', 'C', 'tcp', ipv6)
                request('C', 'A', 'udp', ipv6)
            assert {node: (processes[node].pid, state(node)['public_key']) for node in 'ABC'} == original
        mark('explicit_tun_then_default_kernel_hot_reload_preserves_identity_and_dual_stack')
        # Fail-closed: removing a peer must stop forwarding, rather than keeping
        # a stale route/session in the kernel snapshot.
        configurations['B']['peers'] = [p for p in configurations['B']['peers'] if p['address'] != endpoints['C']]
        (work / 'B.json').write_text(json.dumps(configurations['B']))
        processes['B'].send_signal(signal.SIGHUP)
        wait(lambda: not route('A', 'C', '10.98.0.0/24'), 'withdrawal removes imported kernel route', 30)
        ping('A', 'C', success=False)
        mark('peer_removal_withdraws_kernel_forwarding')
        if args.suite == 'all':
            flood = run(sys.executable, Path(__file__).with_name('kernel_flood_integration.py'),
                '--binary', binary, '--work', work / 'flood', check=False, timeout=180)
            print(flood.stdout, flood.stderr, flush=True)
            assert flood.returncode == 0, 'kernel outer IPv6 and flood RPF regression failed'
            report['flood'] = json.loads((work / 'flood' / 'results.json').read_text())
            mark('outer_ipv6_and_cyclic_broadcast_multicast_rpf_regression')
            subnet = run(sys.executable, Path(__file__).with_name('subnet_network_integration.py'),
                '--binary', binary, '--device-backend', 'kernel', '--work', work / 'subnet', check=False, timeout=300)
            print(subnet.stdout, subnet.stderr, flush=True)
            assert subnet.returncode == 0, 'kernel subnet route/NAT regression failed'
            report['subnet'] = json.loads((work / 'subnet' / 'results.json').read_text())
            mark('kernel_subnet_route_snat_failover_ipv4_ipv6_regression')
        report['ok'] = True
    except Exception as error:
        report['error'] = str(error)
        report['traceback'] = traceback.format_exc()
        print(report['traceback'], flush=True)
        for node in processes:
            for suffix in ('.log', '.status.json'):
                path = work / (node + suffix)
                if path.exists():
                    print('DIAGNOSTIC', path.name, path.read_text(errors='replace')[-18000:], flush=True)
    finally:
        for process in helpers + list(processes.values()):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            if process in processes.values() and process.returncode != 0:
                cleanup_errors.append('core exit ' + str(process.returncode))
        for node in processes:
            result = ns(node, 'ip', 'link', 'show', 'overlay0', check=False)
            if result.returncode == 0:
                cleanup_errors.append(node + ' left overlay0 after owner fd closed')
        for handle in handles:
            handle.close()
        for space in reversed(made):
            result = run('ip', 'netns', 'delete', space, check=False)
            if result.returncode:
                cleanup_errors.append(result.stderr)
        if loaded:
            result = run('rmmod', 'tunnel_kmod', check=False)
            if result.returncode:
                cleanup_errors.append(result.stderr)
        if not cleanup_errors and processes:
            mark('normal_exit_interface_namespace_and_module_cleanup')
        if cleanup_errors:
            report['ok'] = False
        (work / 'results.json').write_text(json.dumps(report, indent=2))
        print('TUNNEL_KERNEL_RESULT:' + json.dumps(report), flush=True)
    return 0 if report['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
