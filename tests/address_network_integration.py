#!/usr/bin/env python3
"""Real allocation/TUN lifecycle tests, confined to fresh Linux net namespaces."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import time
import traceback


def run(*args, check=True, timeout=15, input=None):
    result = subprocess.run(list(map(str, args)), input=input, text=True, capture_output=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f"command failed: {' '.join(map(str, args))}\n{result.stdout}\n{result.stderr}")
    return result


def wait(predicate, label, timeout=25):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return
        time.sleep(.1)
    # File I/O or scheduling can cross the deadline after the previous poll.
    if predicate():
        return
    raise AssertionError('timeout: ' + label)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', default='build-wsl/tunnel')
    parser.add_argument('--work', default='build-wsl/address-network-tests')
    parser.add_argument('--auth-mode', choices=['shared', 'per-node'], default='shared')
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit('Requires root/CAP_NET_ADMIN in Linux/WSL.')
    binary = Path(args.binary).resolve(strict=True)
    work = Path(args.work).resolve()
    work.mkdir(parents=True, exist_ok=True)
    prefix = 'ta' + str(os.getpid())
    hub, names = prefix + 'h', [prefix + c for c in 'abc']
    made, handles, passed, shutdown_errors = [], [], [], []
    processes = {}
    seen_status = set()
    service = '192.0.2.254:45001'
    managed = ['10.77.0.0/30', 'fd00:77::/125']
    all_networks = ['10.88.0.0/24'] + managed

    def mark(label):
        passed.append(label)
        print('PASS:', label, flush=True)

    def command(node, *args, **kwargs):
        return run('ip', 'netns', 'exec', hub if node == 'server' else names[node], *args, **kwargs)

    def state(node):
        # A transient read failure is not evidence of revoked membership.
        # Only an initial, not-yet-created status file means "not started".
        error = None
        for _ in range(5):
            try:
                value = json.loads((work / f'{node}.status.json').read_text())
                seen_status.add(node)
                return value
            except FileNotFoundError as failure:
                if node not in seen_status:
                    return {}
                error = failure
            except (OSError, ValueError) as failure:
                error = failure
            time.sleep(.02)
        raise AssertionError(f'cannot read status for {node}: {error}')

    def ip(node, network):
        return next((n['ip'] for n in state(node).get('networks', []) if n['network'] == network and n['active']), '')

    def route(node, target, network):
        return next((r for r in state(node).get('routes', []) if r['node'] == f'192.0.2.{target+1}:45000' and r['network'] == network), None)

    def tun_addresses(node):
        data = json.loads(command(node, 'ip', '-j', 'address', 'show', 'dev', 'overlay0').stdout)
        return {address['local'] for interface in data for address in interface.get('addr_info', [])}

    def ping(node, destination, v6=False):
        # Status snapshots and reverse paths need not converge simultaneously.
        # Verify eventual connectivity, including the bounded E2E TLS retry.
        for _ in range(3):
            reply = command(node, 'ping', '-6' if v6 else '-4', '-c', '1', '-W', '3', destination, check=False)
            if reply.returncode == 0:
                return reply
        raise AssertionError(f'ping {node} -> {destination} failed: {reply.stdout} {reply.stderr}')

    def start(node):
        seen_status.discard(node)
        (work / f'{node}.status.json').unlink(missing_ok=True)
        log = open(work / f'{node}.log', 'ab', buffering=0)
        handles.append(log)
        cmd = ['ip', 'netns', 'exec', hub if node == 'server' else names[node], str(binary),
               str(work / f'{node}.json'), '--status-file', str(work / f'{node}.status.json')]
        if node != 'server':
            cmd += ['--tun-name', 'overlay0']
        processes[node] = subprocess.Popen(cmd, stdout=log, stderr=log)

    def stop(node):
        process = processes.pop(node, None)
        if not process:
            return
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(6)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(5)
        if process.returncode != 0:
            shutdown_errors.append(f'{node}: exit {process.returncode}')

    result = {'ok': False, 'passed': passed, 'auth_mode': args.auth_mode}
    try:
        existing = {line.split()[0] for line in run('ip', 'netns', 'list').stdout.splitlines()}
        assert not existing.intersection(names + [hub])
        for name in [hub] + names:
            run('ip', 'netns', 'add', name)
            made.append(name)
            run('ip', '-n', name, 'link', 'set', 'lo', 'up')
        run('ip', '-n', hub, 'link', 'add', 'br0', 'type', 'bridge')
        run('ip', '-n', hub, 'address', 'add', '192.0.2.254/24', 'dev', 'br0')
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
        graph = [[1], [0, 2], [1]]
        def key_for(i):
            return 'test-shared-allocation-key' if args.auth_mode == 'shared' else f'test-allocation-client-{i}'
        for i in range(3):
            config = {'device_backend': 'tun', 'address': f'192.0.2.{i+1}:45000', 'networks': [f'10.88.0.{i+1}/24'],
                'address_clients': [{'address': service, 'shared_key': key_for(i), 'networks': managed}],
                'peers': [{'address': f'192.0.2.{p+1}:45000', 'shared_key': f'test-pair-{min(i,p)}-{max(i,p)}', 'networks': all_networks} for p in graph[i]]}
            (work / f'{i}.json').write_text(json.dumps(config))
        server = {'address_server': {'address': service, 'state_file': 'leases.json', 'reclaim_after': 2,
            'networks': managed, 'clients': [{'address': f'192.0.2.{i+1}:45000', 'shared_key': f'test-allocation-client-{i}', 'networks': managed} for i in range(3)]}}
        if args.auth_mode == 'shared':
            del server['address_server']['clients']
            server['address_server']['shared_key'] = key_for(0)
        # Isolate reruns from previously generated bindings without touching user data.
        server['address_server']['state_file'] = f'leases-{prefix}.json'
        (work / 'server.json').write_text(json.dumps(server))
        exported = json.loads(run(binary, work / 'server.json', '--export-client', '192.0.2.1:45000').stdout)
        assert exported['address'] == '192.0.2.1:45000'
        assert set(exported['address_clients'][0]['networks']) == set(managed)
        assert exported['address_clients'][0]['shared_key'] == key_for(0)
        mark('export_authorized_client_configuration')
        start(0); start(1)
        wait(lambda: route(0, 1, '10.88.0.0/24'), 'static adjacency before server startup')
        ping(0, '10.88.0.2')
        assert not ip(0, managed[0]) and not ip(0, managed[1])
        assert '10.88.0.1' in tun_addresses(0)
        mark('static_network_operates_while_allocation_is_pending')
        start('server')
        wait(lambda: route(0, 1, managed[0]) and route(0, 1, managed[1]), 'dual stack allocation')
        a4, b4 = ip(0, managed[0]), ip(1, managed[0])
        a6, b6 = ip(0, managed[1]), ip(1, managed[1])
        assert a4 != b4 and a6 != b6
        assert {a4, a6, '10.88.0.1'} <= tun_addresses(0)
        ping(0, b4); ping(1, a6, True)
        mark('independent_ipv4_ipv6_pools_and_real_tun_addresses')
        start(2)
        wait(lambda: ip(2, managed[1]) and route(0, 2, managed[1]), 'partial allocation and multihop route')
        assert not ip(2, managed[0])
        errors = state(2)['address_service']['clients'][0]['errors']
        assert any(e['network'] == managed[0] for e in errors)
        ping(2, b6, True); ping(0, ip(2, managed[1]), True)
        mark('exhausted_ipv4_pool_does_not_block_ipv6_pool_or_multihop_traffic')
        server_process = processes['server']
        fds = [os.readlink(fd) for fd in Path(f'/proc/{server_process.pid}/fd').iterdir()]
        udp_inodes = {line.split()[9] for table in ('udp', 'udp6') for line in Path(f'/proc/{server_process.pid}/net/{table}').read_text().splitlines()[1:]}
        assert '/dev/net/tun' not in fds
        assert not any(fd.startswith('socket:[') and fd[8:-1] in udp_inodes for fd in fds)
        assert len(list(Path(f'/proc/{server_process.pid}/task').iterdir())) == 1
        mark('standalone_server_has_no_tun_or_udp_and_one_thread')
        ping(0, '10.88.0.2')
        wait(lambda: any(s['network'] == '10.88.0.0/24' and s['ready'] for s in state(0).get('end_sessions', [])), 'static session status')
        static_session = next(s['id'] for s in state(0)['end_sessions'] if s['network'] == '10.88.0.0/24')
        peer_up = state(0)['counters']['peer_up']
        stop('server')
        wait(lambda: not ip(0, managed[0]) and not ip(1, managed[1]), 'managed withdrawal after server close')
        assert not route(0, 1, managed[0]) and a4 not in tun_addresses(0) and a6 not in tun_addresses(0)
        ping(0, '10.88.0.2')
        assert state(0)['counters']['peer_up'] == peer_up
        assert any(s['id'] == static_session for s in state(0)['end_sessions'])
        mark('server_close_removes_only_managed_addresses_routes_and_sessions')
        start('server')
        wait(lambda: route(0, 1, managed[0]) and route(0, 1, managed[1]), 'allocator restart')
        assert ip(0, managed[0]) == a4 and ip(1, managed[0]) == b4 and ip(0, managed[1]) == a6
        assert any(s['id'] == static_session for s in state(0)['end_sessions'])
        ping(0, b4)
        mark('server_restart_retains_bindings_and_static_peer_session')
        rules = '''table inet allocation_test {
 chain out {
  type filter hook output priority 0; policy accept;
  ip daddr 192.0.2.254 tcp dport 45001 drop
 }
 chain in {
  type filter hook input priority 0; policy accept;
  ip saddr 192.0.2.254 tcp sport 45001 drop
 }
}
'''
        command(0, 'nft', '-f', '-', input=rules)
        failure_started = time.monotonic()
        wait(lambda: not ip(0, managed[0]) and not route(1, 0, managed[0]), '20 second service timeout', 30)
        assert time.monotonic() - failure_started >= 14
        assert ip(1, managed[0]) == b4
        ping(0, '10.88.0.2')
        assert any(s['id'] == static_session for s in state(0)['end_sessions'])
        mark('service_blackhole_20s_timeout_is_scoped_to_affected_node_and_tunnels')
        command(0, 'nft', 'delete', 'table', 'inet', 'allocation_test')
        wait(lambda: route(0, 1, managed[0]) and route(0, 2, managed[1]), 'automatic service reconnection and multihop resync')
        assert ip(0, managed[0]) == a4
        ping(0, b4)
        ping(0, ip(2, managed[1]), True)
        mark('automatic_reconnect_restores_original_ip_and_indirect_routes')
        stop(0)
        def offline_binding():
            return next((lease for lease in state('server').get('address_service', {}).get('server', {}).get('leases', [])
                         if lease['node'] == '192.0.2.1:45000' and lease['network'] == managed[0] and not lease['online']), None)
        wait(offline_binding, 'allocator observes the old node disconnecting')
        reclaim_at = offline_binding()['reclaim_at']
        # Base the wait on the authoritative persisted deadline, then allow
        # renewal/status publication. Closing a process alone does not prove
        # that the server has processed its TCP disconnect yet.
        reclaim_budget = max(20, (reclaim_at - time.time() * 1000) / 1000 + 20)
        assert reclaim_budget <= 90, f'unexpected reclaim deadline: {reclaim_at}'
        result['reclaim_wait_budget_seconds'] = round(reclaim_budget, 2)
        # Reclaim must wait for the last signed grant plus its guard, even when
        # the configured offline hold time is only two seconds.
        time.sleep(3)
        assert not ip(2, managed[0])
        mark('old_signed_grant_lifetime_prevents_premature_address_reuse')
        wait(lambda: ip(2, managed[0]), 'expired offline lease reclamation', reclaim_budget)
        assert time.time() * 1000 >= reclaim_at, 'address reused before the persisted safety deadline'
        assert ip(2, managed[0]) == a4 and ip(1, managed[0]) == b4, f'reclaimed assignment: C={ip(2, managed[0])}, expected={a4}; B={ip(1, managed[0])}, expected={b4}'
        ping(2, b4)
        mark('offline_address_reclaimed_and_reassigned_without_disturbing_online_node')
        start(0)
        wait(lambda: ip(0, managed[1]) and route(0, 1, '10.88.0.0/24'), 'old node rejoining after reclamation')
        assert not ip(0, managed[0]) and a4 not in tun_addresses(0)
        assert ip(2, managed[0]) == a4
        ping(0, '10.88.0.2')
        mark('rejoining_node_cannot_reuse_an_address_reassigned_to_another_node')
        result['ok'] = True
    except Exception as error:
        result['error'] = str(error)
        result['traceback'] = traceback.format_exc()
        result['failure_states'] = {}
        for node in processes:
            try:
                result['failure_states'][str(node)] = state(node)
            except Exception as read_error:
                result['failure_states'][str(node)] = {'read_error': str(read_error)}
        print('FAIL:', error, flush=True)
        print(result['traceback'], flush=True)
    finally:
        for node in list(processes):
            stop(node)
        for name in reversed(made):
            run('ip', 'netns', 'del', name, check=False)
        for handle in handles:
            handle.close()
        if shutdown_errors:
            result['ok'] = False
            result['shutdown_errors'] = shutdown_errors
        result['count'] = len(passed)
        (work / 'results.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2), flush=True)
    return 0 if result['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
