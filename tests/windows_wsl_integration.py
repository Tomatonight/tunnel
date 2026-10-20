#!/usr/bin/env python3
"""Administrator-only Windows Wintun <-> WSL TUN interoperation smoke test.
Requires the verified official AMD64 Wintun DLL beside the Windows core binary.
Creates only a temporary adapter and two narrow test networks, then closes them.
"""
import argparse
import ctypes
import ipaddress
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time


def main():
    root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--transport', choices=('udp', 'tcp'), default='udp')
    parser.add_argument('--windows-binary', type=Path, default=root / 'build' / 'tunnel.exe')
    parser.add_argument('--linux-binary', help='WSL absolute path, or a Windows/repository path converted with wslpath')
    parser.add_argument('--work', type=Path, default=root / 'build' / 'windows-wsl-tests')
    parser.add_argument('--ipv4-prefix', help='Temporary IPv4 /30; defaults to 10.253.248.0/30 for TCP, 198.18.252.0/30 for UDP')
    args = parser.parse_args()
    try:
        ipv4_prefix = ipaddress.ip_network(args.ipv4_prefix or ('10.253.248.0/30' if args.transport == 'tcp' else '198.18.252.0/30'))
        if ipv4_prefix.version != 4 or ipv4_prefix.prefixlen != 30:
            raise ValueError('the IPv4 test prefix must be a canonical /30 network')
    except ValueError as error:
        parser.error(str(error))
    if os.name != 'nt' or not ctypes.windll.shell32.IsUserAnAdmin():
        raise SystemExit('Run using Windows Python in an administrator session.')
    windows_binary = args.windows_binary.resolve(strict=True)
    work = args.work.resolve()
    work.mkdir(parents=True, exist_ok=True)
    hidden = subprocess.CREATE_NO_WINDOW
    def wsl(*args):
        return subprocess.check_output(['wsl.exe', '-d', 'Ubuntu', '--exec', *args], creationflags=hidden, timeout=20).decode('utf-8')
    gateway = json.loads(wsl('ip', '-j', 'route', 'show', 'default'))[0]['gateway']
    address = next(a['local'] for a in json.loads(wsl('ip', '-j', '-4', 'address', 'show', 'dev', 'eth0'))[0]['addr_info'] if a['family'] == 'inet')
    linux_root = wsl('wslpath', '-u', str(root)).strip()
    linux_work = wsl('wslpath', '-u', str(work)).strip()
    if args.linux_binary is None:
        linux_binary = linux_root + '/build-wsl/tunnel'
    elif args.linux_binary.startswith('/'):
        linux_binary = args.linux_binary
    else:
        linux_binary = wsl('wslpath', '-u', str(Path(args.linux_binary).resolve(strict=True))).strip()
    wsl('test', '-x', linux_binary)
    with socket.socket() as reservation:
        reservation.bind((gateway, 0))
        port = reservation.getsockname()[1]
    alias = 'TnlTest' + str(os.getpid())
    linux_name = 'twt' + str(os.getpid())
    public = [gateway, address]
    v4 = [str(ip) for ip in ipv4_prefix.hosts()]
    v6 = ['fd53:42:7ef0::1', 'fd53:42:7ef0::2']
    for i in range(2):
        networks = [{'tunnel': str(ipv4_prefix), 'tunnel_ip': v4[i]}, {'tunnel': 'fd53:42:7ef0::/64', 'tunnel_ip': v6[i]}]
        config = {'device_backend': 'tun', 'tun_mtu': 1280, 'transport_mtu': 1500,
            'listen': {'enabled': i == 1, 'address': f'{public[i]}:{port}', 'bind_address': f'{public[i]}:{port}', 'networks': networks},
            'peers': [{'address': f'{public[1-i]}:{port}', 'shared_key': 'windows-linux-integration-only-key', 'networks': networks}]}
        if args.transport != 'udp':
            config['peers'][0]['transport'] = args.transport
        (work / f'{i}.json').write_text(json.dumps(config))
    echo = work / 'echo.py'
    echo.write_text('''import json, select, socket, sys, time
from pathlib import Path
servers=[]
for family, address in [(socket.AF_INET, sys.argv[1]), (socket.AF_INET6, sys.argv[2])]:
    server=socket.socket(family, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((address, 36002)); server.listen(2); servers.append(server)
Path(sys.argv[3]).write_text('ready')
for _ in range(2):
    readable,_,_=select.select(servers,[],[],30)
    if not readable: raise RuntimeError('echo timeout')
    connection,_=readable[0].accept(); connection.settimeout(10)
    with connection:
        payload=b''
        while len(payload)<1024:
            block=connection.recv(1024-len(payload))
            if not block: raise RuntimeError('unexpected EOF')
            payload+=block
        connection.sendall(payload)
for server in servers: server.close()
''')
    processes = []
    files = []
    checks = []
    def wait(predicate, label, seconds=20):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            if predicate():
                return
            for p in processes[:2]:
                if p.poll() is not None:
                    raise RuntimeError(f'tunnel exited {p.returncode}: {label}')
            time.sleep(.1)
        raise RuntimeError('timeout: ' + label)
    def state(i):
        try:
            return json.loads((work / f'{i}.status.json').read_text())
        except (OSError, json.JSONDecodeError):
            # Windows can briefly deny access while the core atomically replaces
            # its status snapshot; polling should retry rather than fail the VPN.
            return {}
    try:
        for i in range(2):
            (work / f'{i}.status.json').unlink(missing_ok=True)
        for i in range(2):
            log = open(work / f'{i}.log', 'wb', buffering=0)
            files.append(log)
            cmd = ([str(windows_binary), str(work / '0.json'), '--tun-name', alias, '--status-file', str(work / '0.status.json')] if i == 0 else
                ['wsl.exe', '-d', 'Ubuntu', '-u', 'root', '--exec', linux_binary, linux_work + '/1.json', '--tun-name', linux_name, '--status-file', linux_work + '/1.status.json'])
            # Leave room for slow WSL/Python startup and status-file contention,
            # while still bounding both cores if the test runner is interrupted.
            processes.append(subprocess.Popen(cmd + ['--run-for', '90'], stdout=log, stderr=log, creationflags=hidden))
        wait(lambda: all(any(p.get('state') == 3 and p.get('transport') == args.transport for p in state(i).get('peers', [])) for i in range(2)),
            f'Windows/Linux authentication and negotiated {args.transport} data transport (both binaries must report peer transport)')
        checks.append(f'windows_linux_tls_and_{args.transport}_data_authentication')
        # Simulate a monitoring reader that does not permit atomic replacement.
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
        kernel.CreateFileW.restype = ctypes.c_void_p
        kernel.CloseHandle.argtypes = [ctypes.c_void_p]
        handle = kernel.CreateFileW(str(work / '0.status.json'), 0x80000000, 1, None, 3, 0, None)
        assert handle != ctypes.c_void_p(-1).value
        try:
            time.sleep(1)
            assert processes[0].poll() is None, 'monitoring lock stopped the VPN'
        finally:
            kernel.CloseHandle(handle)
        checks.append('status_file_lock_does_not_interrupt_vpn')
        ready = work / 'echo.ready'
        if ready.exists():
            ready.unlink()
        processes.append(subprocess.Popen(['wsl.exe', '-d', 'Ubuntu', '--exec', 'python3', linux_work + '/echo.py', v4[1], v6[1], linux_work + '/echo.ready'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, creationflags=hidden))
        wait(ready.exists, 'echo server')
        for family, target, label in [(socket.AF_INET, v4[1], 'wintun_ipv4_tcp_echo'), (socket.AF_INET6, v6[1], 'wintun_ipv6_tcp_echo')]:
            with socket.socket(family, socket.SOCK_STREAM) as client:
                client.settimeout(10)
                client.connect((target, 36002))
                payload = bytes(range(256)) * 4
                client.sendall(payload)
                received = b''
                while len(received) < len(payload):
                    block = client.recv(1024)
                    if not block:
                        break
                    received += block
                assert received == payload
            checks.append(label + '_over_' + args.transport)
        for family, size, destination in [('-4', '1252', v4[1]), ('-6', '1232', v6[1])]:
            cmd = ['ping.exe', family, '-n', '1', '-w', '3000', '-l', size]
            if family == '-4':
                cmd.append('-f')
            p = subprocess.run(cmd + [destination], capture_output=True, creationflags=hidden, timeout=6)
            assert p.returncode == 0, p.stdout.decode(errors='replace')
            checks.append('wintun_mtu_1280_ipv' + family[1:] + '_over_' + args.transport)
        if args.transport == 'tcp':
            wait(lambda: all(state(i).get('counters', {}).get('tcp_data_sent', 0) > 0 and
                state(i).get('counters', {}).get('tcp_data_received', 0) > 0 for i in range(2)), 'TCP encapsulated data counters')
            assert all(state(i).get('counters', {}).get('udp_data_sent', 0) == 0 and
                state(i).get('counters', {}).get('udp_data_received', 0) == 0 for i in range(2)), 'TCP-only test used UDP data encapsulation'
            checks.append('tcp_encapsulated_data_without_udp_data')
        # Graceful --run-for shutdown also exercises both platform cleanup paths.
        for p in processes[:2]:
            assert p.wait(timeout=95) == 0
        checks.append('graceful_platform_shutdown')
        query = subprocess.run(['powershell.exe', '-NoProfile', '-Command', f"Get-NetAdapter -Name '{alias}' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name"], capture_output=True, creationflags=hidden, timeout=10)
        assert not query.stdout.strip(), 'Wintun adapter remains after close'
        checks.append('wintun_adapter_cleanup')
        result = {'ok': True, 'transport': args.transport, 'ipv4_prefix': str(ipv4_prefix), 'count': len(checks), 'passed': checks}
    except Exception as error:
        result = {'ok': False, 'transport': args.transport, 'ipv4_prefix': str(ipv4_prefix), 'count': len(checks), 'passed': checks, 'error': repr(error)}
        raise
    finally:
        # Normal completion exits on its own. On error stop only our child processes.
        for p in processes:
            if p.poll() is None:
                p.terminate()
                p.wait(timeout=10)
        for file in files:
            file.close()
        (work / 'results.json').write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps(result, indent=2), flush=True)
        if not result['ok']:
            for i in range(2):
                print((work / f'{i}.log').read_text(errors='replace'))


if __name__ == '__main__':
    main()
