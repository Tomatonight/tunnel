"""Exercise CLI transport editing against native configuration validation; no TUN."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, help='Native core path; required for source CLI, optional beside a packaged executable')
    parser.add_argument('--executable', type=Path, help='Packaged TunnelCtl executable; omit to test the source CLI')
    args = parser.parse_args()
    if args.binary is None and args.executable is None:
        parser.error('--binary is required when --executable is omitted')
    executable = args.executable.resolve(strict=True) if args.executable else None
    if args.binary is not None:
        binary = args.binary.resolve(strict=True)
        command = ([str(executable)] if executable else [sys.executable, str(ROOT / 'tools' / 'tunnel_cli.py')]) + ['--binary', str(binary)]
    else:
        # Exercise the packaged CLI's default sibling-core discovery as well.
        (executable.parent / ('tunnel.exe' if sys.platform == 'win32' else 'tunnel')).resolve(strict=True)
        command = [str(executable)]
    checks = []
    with tempfile.TemporaryDirectory(prefix='tunnel-cli-transport-') as folder:
        folder = Path(folder)
        profile = folder / 'profile'
        secret = 'test-transport-psk-1234567890123456'
        key = folder / 'key.txt'
        key.write_text(secret, encoding='utf-8')

        def cli(*arguments, ok=True, directory=profile):
            result = subprocess.run([*command, '--config-dir', str(directory), *arguments], capture_output=True, text=True,
                encoding='utf-8', timeout=60 if executable else 30)
            assert secret not in result.stdout + result.stderr, 'CLI exposed the peer PSK'
            assert (result.returncode == 0) == ok, (arguments, result.stdout, result.stderr)
            return json.loads(result.stdout) if ok else result.stderr

        cli('init', '--bind-address', '192.0.2.1:65535', '--network', '10.91.0.1/24')
        cli('peer', 'add', '192.0.2.2:65535', '--key-file', str(key), '--transport', 'tcp')
        peers = cli('config', 'show')['peers']
        assert 'transport' not in peers[0] and peers[0]['shared_key'] == '<hidden>'
        checks.append('peer_add_tcp_uses_canonical_default_without_exposing_psk')

        duplicate = cli('peer', 'add', '192.0.2.2', '--key-file', str(key), ok=False)
        assert 'already exists' in duplicate
        cli('peer', 'remove', '192.0.2.2')
        assert not cli('config', 'show').get('peers', [])
        cli('peer', 'add', '192.0.2.2', '--key-file', str(key), '--transport', 'tcp')
        assert cli('config', 'show')['peers'][0]['endpoint'] == '192.0.2.2:65535'
        checks.append('peer_commands_normalize_default_port_for_duplicate_and_remove')

        cli('peer', 'add', '192.0.2.3:65535', '--key-file', str(key))
        cli('peer', 'add', '192.0.2.4:65535', '--key-file', str(key), '--transport', 'udp')
        peers = cli('config', 'show')['peers']
        assert 'transport' not in peers[0] and 'transport' not in peers[1]
        assert peers[2]['transport'] == 'udp'
        checks.append('default_tcp_and_explicit_udp_are_canonicalized')

        before = (profile / 'configure.json').read_bytes()
        error = cli('peer', 'add', '192.0.2.5:65535', '--key-file', str(key), '--transport', 'quic', ok=False)
        assert 'invalid choice' in error and (profile / 'configure.json').read_bytes() == before
        checks.append('unknown_transport_rejected_before_configuration_changes')

        cli('config', 'set', '/peers/1/transport', 'udp', '--string')
        assert cli('config', 'show')['peers'][1]['transport'] == 'udp'
        checks.append('existing_peer_can_switch_to_udp')
        cli('config', 'set', '/peers/1/transport', 'tcp', '--string')
        assert 'transport' not in cli('config', 'show')['peers'][1]
        checks.append('switching_back_to_tcp_restores_minimal_configuration')

        before = (profile / 'configure.json').read_bytes()
        cli('config', 'set', '/peers/0/transport', 'quic', '--string', ok=False)
        assert (profile / 'configure.json').read_bytes() == before
        checks.append('native_validation_rejects_unknown_transport_without_overwriting_file')

        outbound = folder / 'outbound-only'
        cli('init', '--no-listen', '--network', '10.92.0.1/24', directory=outbound)
        assert cli('config', 'show', directory=outbound)['listen'] == {'enabled': False}
        checks.append('no_listen_init_omits_local_bind_address')
    print(json.dumps({'passed': len(checks), 'checks': checks}, indent=2))


if __name__ == '__main__':
    main()
