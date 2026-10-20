"""Smoke-test the distributable console executable and its detached host."""
import argparse
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from remote_desktop.host import BackgroundHost


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--executable', type=Path, default=ROOT / 'build/gui/TunnelUI/TunnelCtl.exe')
    args = parser.parse_args()
    executable = args.executable.resolve(strict=True)
    binary = executable.parent / 'tunnel.exe'
    with tempfile.TemporaryDirectory(prefix='tunnel-console-package-') as folder:
        folder = Path(folder)
        profile = folder / 'profile'
        host = BackgroundHost(binary, profile)

        def call(*command, success=True):
            result = subprocess.run([str(executable), '--config-dir', str(profile), *command],
                capture_output=True, text=True, encoding='utf-8', timeout=90)
            assert (result.returncode == 0) == success, (command, result.stdout, result.stderr)
            return json.loads(result.stdout if success else result.stderr)

        with socket.socket() as reserved:
            reserved.bind(('127.0.0.1', 0))
            port = reserved.getsockname()[1]
        document = {'address_server': {'address': f'127.0.0.1:{port}',
            'bind_address': f'127.0.0.1:{port}', 'shared_key': 'package-test-only-secret',
            'networks': ['10.253.244.0/24'], 'state_file': str(folder / 'leases.json')}}
        source = folder / 'node.json'
        source.write_text(json.dumps(document), encoding='utf-8-sig')
        try:
            call('config', 'apply', str(source))
            original = (profile / 'configure.json').read_bytes()
            source.write_text('{"address_server":{},"address_server":' + json.dumps(document['address_server']) + '}')
            call('config', 'apply', str(source), success=False)
            assert (profile / 'configure.json').read_bytes() == original
            call('start')
            pid = host.status()['core_pid']
            result = call('config', 'set', '/address_server/reclaim_after', '120')
            assert result['applied'] and result['mode'] == 'rebuild'
            assert host.status()['core_pid'] == pid
            current = call('config', 'show', '--running')
            assert current['address_server']['reclaim_after'] == 120
            assert current['address_server']['shared_key'] == '<hidden>'
            call('stop')
            assert not host.is_running()
        finally:
            host.stop()
    print(json.dumps({'passed': 6, 'checks': ['utf8_bom_import', 'duplicate_keys_rejected',
        'console_starts_detached_frozen_host', 'live_apply_same_core_pid', 'running_secret_redaction', 'console_stop']}))


if __name__ == '__main__':
    main()
