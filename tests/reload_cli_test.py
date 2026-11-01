"""Real native core + authenticated host + CLI reload tests, without a TUN."""
import argparse
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from remote_desktop.host import BackgroundHost


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def eventually(predicate, timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(.1)
    raise AssertionError('Condition did not become true within timeout')


def listening(port):
    with socket.socket() as sock:
        sock.settimeout(.3)
        return sock.connect_ex(('127.0.0.1', port)) == 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    checks = []
    with tempfile.TemporaryDirectory(prefix='tunnel-reload-cli-') as folder:
        folder = Path(folder)
        profile = folder / 'profile'
        secret = 'reload-test-only-key-123456789012345'
        port = free_port()
        document = {'address_server': {'address': f'127.0.0.1:{port}', 'bind_address': f'127.0.0.1:{port}',
            'shared_key': secret, 'networks': ['10.79.0.0/24'], 'state_file': str(folder / 'leases.json')}}
        source = folder / 'source.json'
        source.write_text(json.dumps(document))
        host = BackgroundHost(binary, profile)

        def cli(*arguments, ok=True, directory=profile):
            result = subprocess.run([sys.executable, str(ROOT / 'tools' / 'tunnel_cli.py'), '--binary', str(binary),
                '--config-dir', str(directory), *arguments], capture_output=True, text=True, encoding='utf-8', timeout=180)
            if ok:
                assert result.returncode == 0, (arguments, result.stderr)
                return json.loads(result.stdout)
            assert result.returncode != 0, arguments
            return json.loads(result.stderr)

        try:
            cli('start', '--config', str(source))
            initial = host.status()
            assert initial['running'] and listening(port)
            core_pid = initial['core_pid']
            checks.append('cli_background_start')
            shown = cli('config', 'show')
            assert shown['address_server']['shared_key'] == '<hidden>' and secret not in json.dumps(shown)
            assert cli('config', 'show', '--show-secrets')['address_server']['shared_key'] == secret
            checks.append('default_secret_redaction')
            result = cli('config', 'set', '/address_server/reclaim_after', '120')
            assert host.status()['core_pid'] == core_pid
            assert cli('config', 'show', '--running')['address_server']['reclaim_after'] == 120
            assert listening(port)
            checks.append('same_pid_live_configuration')
            original = (profile / 'configure.json').read_bytes()
            cli('config', 'set', '/tun_mtu', '12', ok=False)
            assert (profile / 'configure.json').read_bytes() == original
            assert cli('config', 'show', '--running')['address_server']['reclaim_after'] == 120
            checks.append('invalid_configuration_keeps_file_and_runtime')
            with socket.socket() as blocker:
                blocker.bind(('127.0.0.1', 0))
                blocker.listen(1)
                occupied = blocker.getsockname()[1]
                rejected = json.loads(original)
                rejected['address_server'].update(address=f'127.0.0.1:{occupied}', bind_address=f'127.0.0.1:{occupied}')
                source.write_text(json.dumps(rejected))
                cli('config', 'apply', str(source), ok=False)
                assert (profile / 'configure.json').read_bytes() == original
                assert host.status()['core_pid'] == core_pid and listening(port)
            checks.append('bind_failure_restores_previous_server')
            edited = json.loads(original)
            edited['address_server']['reclaim_after'] = 180
            (profile / 'configure.json').write_text(json.dumps(edited))
            cli('config', 'reload')
            assert cli('config', 'show', '--running')['address_server']['reclaim_after'] == 180
            checks.append('reload_external_file_edits')
            offline = folder / 'offline'
            cli('init', '--address', '127.0.0.1:57001', '--network', '10.77.0.1/24', directory=offline)
            key = folder / 'key.txt'
            key.write_text(secret)
            cli('peer', 'add', '127.0.0.1:57002', '--key-file', str(key), directory=offline)
            cli('network', 'add', '10.78.0.1/24', directory=offline)
            saved = cli('config', 'show', directory=offline)
            assert saved['peers'][0]['networks'] == ['10.77.0.0/24']
            cli('peer', 'remove', '127.0.0.1:57002', directory=offline)
            assert not cli('config', 'show', directory=offline).get('peers')
            checks.append('offline_init_peer_edits_and_network_permissions')
        finally:
            host.stop()
        assert not host.is_running()
        checks.append('graceful_cli_host_cleanup')

        # Standalone core observes atomic file replacements and POSIX SIGHUP.
        for watch in (True, False) if os.name != 'nt' else (True,):
            first, second = free_port(), free_port()
            while second == first:
                second = free_port()
            standalone = dict(document)
            standalone['address_server'] = dict(document['address_server'], address=f'127.0.0.1:{first}',
                bind_address=f'127.0.0.1:{first}', state_file=str(folder / f'watch-{watch}.leases.json'))
            path = folder / f'watch-{watch}.json'
            path.write_text(json.dumps(standalone))
            leases = Path(standalone['address_server']['state_file'])
            leases.write_text(json.dumps({'version': 1, 'server': f'127.0.0.1:{first}', 'leases': [{
                'network': '10.79.0.0/24', 'node': '127.0.0.1:59001', 'ip': '10.79.0.44',
                'offline_at': int(time.time() * 1000), 'proof_until': int(time.time() * 1000) + 60000}]}))
            child = subprocess.Popen([str(binary), str(path), *(['--watch-config'] if watch else [])],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            output = []
            reader = threading.Thread(target=lambda: output.extend(iter(child.stdout.readline, b'')), daemon=True)
            reader.start()
            try:
                eventually(lambda: listening(first))
                if watch:
                    path.write_text('{invalid')
                    eventually(lambda: any(b'configuration reload failed' in line for line in output))
                    assert listening(first) and child.poll() is None
                standalone['address_server'].update(address=f'127.0.0.1:{second}', bind_address=f'127.0.0.1:{second}')
                temporary = path.with_suffix('.tmp')
                temporary.write_text(json.dumps(standalone))
                temporary.replace(path)
                if not watch:
                    os.kill(child.pid, signal.SIGHUP)
                eventually(lambda: listening(second))
                assert not listening(first) and child.poll() is None
                persisted = json.loads(leases.read_text())
                assert persisted['server'] == f'127.0.0.1:{second}' and persisted['leases'][0]['ip'] == '10.79.0.44'
                checks.append('standalone_file_watch' if watch else 'posix_sighup')
            except Exception:
                print(b''.join(output).decode('utf-8', errors='replace'), file=sys.stderr)
                raise
            finally:
                child.terminate()
                child.wait(timeout=15)
                reader.join(timeout=2)
                child.stdout.close()
    print(json.dumps({'passed': len(checks), 'checks': checks}, indent=2))


if __name__ == '__main__':
    main()
