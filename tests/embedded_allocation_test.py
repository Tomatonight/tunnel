#!/usr/bin/env python3
"""Exercise a real node hosting and using its own allocator, in a fresh netns."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', default='build-wsl/tunnel')
    parser.add_argument('--output', default='build-wsl/embedded-allocation-result.json')
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit('Requires root/CAP_NET_ADMIN.')
    binary = Path(args.binary).resolve(strict=True)
    namespace = 'te' + str(os.getpid())
    result = {'ok': False, 'namespace': namespace}
    process = None
    created = False
    try:
        subprocess.run(['ip', 'netns', 'add', namespace], check=True)
        created = True
        subprocess.run(['ip', '-n', namespace, 'link', 'set', 'lo', 'up'], check=True)
        with tempfile.TemporaryDirectory(prefix='tunnel-embedded-') as directory:
            root = Path(directory)
            pools = ['10.66.0.0/24', 'fd00:66::/64']
            local, server, secret = '127.0.0.1:45100', '127.0.0.1:45101', 'test-only-self-allocation'
            config = {'device_backend': 'tun', 'address': local,
                'address_server': {'address': server, 'networks': pools, 'shared_key': secret},
                'address_clients': [{'address': server, 'shared_key': secret, 'networks': pools}]}
            path, status = root / 'node.json', root / 'status.json'
            path.write_text(json.dumps(config))
            with (root / 'node.log').open('w+') as log:
                try:
                    process = subprocess.Popen(['ip', 'netns', 'exec', namespace, str(binary), str(path),
                                                '--status-file', str(status)], stdout=log, stderr=log)
                    end = time.monotonic() + 20
                    while True:
                        assert process.poll() is None, 'embedded node exited early'
                        state = json.loads(status.read_text()) if status.exists() else {}
                        if len([n for n in state.get('networks', []) if n['active']]) == 2:
                            break
                        assert time.monotonic() < end, 'embedded allocation timed out'
                        time.sleep(.1)
                    assert state['address_service']['server']['running']
                    addresses = json.loads(subprocess.check_output(['ip', '-n', namespace, '-j', 'address',
                                                                    'show', 'dev', state['device']], text=True))
                    assigned = {item['local'] for entry in addresses for item in entry.get('addr_info', [])}
                    assert {'10.66.0.1', 'fd00:66::1'} <= assigned
                    assert len(list(Path(f'/proc/{process.pid}/task').iterdir())) == 1
                    assert json.loads((root / 'address-leases.json').read_text())['leases']
                    result.update(ok=True, checks=['node_and_allocator_in_one_loop', 'self_authenticated_allocation',
                                                  'real_dual_stack_tun_addresses', 'persistent_self_binding'])
                finally:
                    if process and process.poll() is None:
                        process.terminate()
                        try:
                            process.wait(10)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait()
                    log.seek(0)
                    result['log'] = log.read()
                    if process and process.returncode != 0:
                        result.update(ok=False, exit_code=process.returncode)
    except Exception as error:
        result.update(ok=False, error=str(error))
    finally:
        if created:
            subprocess.run(['ip', 'netns', 'del', namespace], check=True)
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2), flush=True)
    return 0 if result['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
