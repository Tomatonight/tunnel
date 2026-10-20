"""Real TUN/Wintun rebuild and rollback in one native process (admin/root)."""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from remote_desktop.core import CoreBridge


def addresses():
    if os.name == 'nt':
        output = subprocess.check_output(['powershell.exe', '-NoProfile', '-Command',
            'Get-NetIPAddress -AddressFamily IPv4 | Select-Object -ExpandProperty IPAddress'], text=True)
        return set(output.split())
    output = json.loads(subprocess.check_output(['ip', '-j', '-4', 'address']))
    return {address['local'] for interface in output for address in interface['addr_info']}


def eventually(predicate):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(.25)
    raise AssertionError('OS device state did not settle')


def mtu(address):
    if os.name == 'nt':
        return int(subprocess.check_output(['powershell.exe', '-NoProfile', '-Command',
            "Get-NetIPInterface -AddressFamily IPv4 -InterfaceIndex (Get-NetIPAddress -IPAddress '" + address +
            "').InterfaceIndex | Select-Object -ExpandProperty NlMtu"], text=True).strip())
    interfaces = json.loads(subprocess.check_output(['ip', '-j', '-4', 'address']))
    return next(item['mtu'] for item in interfaces if any(entry['local'] == address for entry in item['addr_info']))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    first, second = '10.253.247.1', '10.253.246.1'
    assert first not in addresses() and second not in addresses(), 'Test addresses already in use'
    with tempfile.TemporaryDirectory(prefix='tunnel-reload-device-') as folder:
        folder = Path(folder)
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0))
            port = reservation.getsockname()[1]
        config = {'device_backend': 'tun', 'address': f'127.0.0.1:{port}', 'networks': [first + '/30'],
            'listen': {'bind_address': f'127.0.0.1:{port}'}, 'peers': []}
        path = folder / 'config.json'
        path.write_text(json.dumps(config))
        core = CoreBridge(binary, path, folder / 'status.json', folder / 'core.log')
        checks = []

        def apply(value):
            path.write_text(json.dumps(value))
            return core.call('config_apply', path=str(path))

        try:
            original = core.call('remote_info')
            identity = original['public_key']
            pid = core.process.pid
            eventually(lambda: first in addresses())
            config['tun_mtu'] = 1300
            assert apply(config)['mode'] == 'rebuild'
            assert core.call('config_get')['tun_mtu'] == 1300
            assert core.call('remote_info')['public_key'] == identity
            assert core.process.pid == pid and core.process.poll() is None
            assert mtu(first) == 1300
            checks.append('real_mtu_rebuild_same_pid_and_identity')
            config['networks'] = [second + '/30']
            assert apply(config)['ok']
            eventually(lambda: second in addresses() and first not in addresses())
            checks.append('real_address_and_route_replacement')
            with socket.socket() as blocked:
                blocked.bind(('127.0.0.1', 0))
                blocked.listen(1)
                rejected = json.loads(json.dumps(config))
                rejected['listen']['bind_address'] = '127.0.0.1:' + str(blocked.getsockname()[1])
                result = apply(rejected)
                assert not result['ok'] and result['rolled_back'] and result['running'], result
                eventually(lambda: second in addresses())
            assert core.call('config_get')['listen']['bind_address'] == config['listen']['bind_address']
            checks.append('real_bind_failure_restores_device')
            server = {'address_server': {'address': f'127.0.0.1:{port}', 'bind_address': f'127.0.0.1:{port}',
                'shared_key': 'reload-device-test-only-key', 'networks': ['10.253.245.0/24'],
                'state_file': str(folder / 'leases.json')}}
            assert apply(server)['ok']
            eventually(lambda: second not in addresses())
            assert core.call('remote_info')['networks'] == []
            assert apply(config)['ok']
            eventually(lambda: second in addresses())
            assert core.call('remote_info')['public_key'] == identity
            checks.append('overlay_server_overlay_transition')
        finally:
            core.close()
    eventually(lambda: first not in addresses() and second not in addresses())
    print(json.dumps({'passed': len(checks), 'checks': checks}, indent=2))


if __name__ == '__main__':
    main()
