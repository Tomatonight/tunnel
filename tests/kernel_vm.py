#!/usr/bin/env python3
"""Build an isolated initramfs and test the optional Linux kernel backend.

This does not load a module into, reboot, or change networking on the host.
Required host packages: qemu-system-x86, busybox-static, cpio, iproute2, nftables,
iputils-ping, Python 3, and a kernel image/modules matching the compiled module.
Keep --work outside the source tree, e.g. /home/tunnel-kernel-tests/vm.
"""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile


def run(*args, **kwargs):
    return subprocess.run(list(map(str, args)), check=True, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True)
    parser.add_argument('--module')
    parser.add_argument('--kernel', required=True)
    parser.add_argument('--modules-root', default='/')
    parser.add_argument('--release', required=True)
    parser.add_argument('--work', default='/home/tunnel-kernel-tests/vm')
    parser.add_argument('--timeout', type=int, default=900)
    parser.add_argument('--smoke', action='store_true', help='boot Python, crypto libraries and network namespace prerequisites only')
    parser.add_argument('--suite', choices=('all', 'main', 'extras', 'flood', 'subnet'), default='all')
    args = parser.parse_args()
    work = Path(args.work).resolve()
    work.mkdir(parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix='root-', dir=work))
    deps_seen = set()

    def copy(source, destination=None):
        source = Path(source)
        target = root / str(destination or source).lstrip('/')
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        return target

    def deps(source):
        source = Path(source).resolve()
        if source in deps_seen:
            return
        deps_seen.add(source)
        result = subprocess.run(['ldd', str(source)], text=True, capture_output=True)
        for candidate in re.findall(r'(/[^\s()]+)', result.stdout):
            if Path(candidate).is_file():
                copy(candidate)

    try:
        for folder in ('dev', 'proc', 'sys', 'tmp', 'run', 'etc', 'bin', 'sbin', 'test', 'modules'):
            (root / folder).mkdir(parents=True, exist_ok=True)
        copy(shutil.which('busybox'), '/bin/busybox')
        for app in ('sh', 'mount', 'mkdir', 'mknod', 'poweroff', 'insmod', 'rmmod', 'dmesg', 'cat', 'ip', 'sleep', 'ls', 'chmod', 'echo', 'uname', 'sysctl'):
            (root / 'bin' / app).symlink_to('busybox')
        for name in ('ip', 'nft', 'ping', 'python3'):
            source = shutil.which(name)
            if not source:
                raise RuntimeError('Missing host executable: ' + name)
            target = root / 'bin' / name
            if target.is_symlink():
                target.unlink()
            copy(source, '/bin/' + name)
            deps(source)
        python_lib = Path('/usr/lib') / ('python%d.%d' % sys.version_info[:2])
        shutil.copytree(python_lib, root / python_lib.relative_to('/'),
            ignore=shutil.ignore_patterns('__pycache__', 'test', 'tests', 'ensurepip', 'idlelib', 'tkinter'))
        for extension in python_lib.glob('lib-dynload/*.so'):
            deps(extension)
        # Python's dynamically loaded extension libraries need their dependencies.
        staged_binary = copy(args.binary, '/test/tunnel')
        artifact_hashes = {'binary_sha256': hashlib.sha256(staged_binary.read_bytes()).hexdigest()}
        deps(args.binary)
        base = Path(__file__).resolve().parent
        copy(base / 'kernel_network_integration.py', '/test/kernel_network_integration.py')
        copy(base / 'tcp_network_integration.py', '/test/tcp_network_integration.py')
        copy(base / 'kernel_uapi_test.py', '/test/kernel_uapi_test.py')
        copy(base / 'subnet_network_integration.py', '/test/subnet_network_integration.py')
        copy(base / 'kernel_flood_integration.py', '/test/kernel_flood_integration.py')
        if args.module:
            staged_module = copy(args.module, '/test/tunnel_kmod.ko')
            artifact_hashes['module_sha256'] = hashlib.sha256(staged_module.read_bytes()).hexdigest()

        # Resolve dependencies against the supplied kernel tree, not the running
        # WSL kernel. Store uncompressed modules so busybox insmod is sufficient.
        module_paths = []
        for name in ('tun', 'veth', 'bridge', 'udp_tunnel', 'ip6_udp_tunnel', 'nf_tables', 'nft_counter', 'nft_chain_nat', 'nf_conntrack', 'nft_ct', 'nft_masq', 'aesni_intel', 'gcm'):
            result = subprocess.run(['modprobe', '--show-depends', '-d', args.modules_root,
                '-S', args.release, name], text=True, capture_output=True)
            if result.returncode:
                print('Optional module:', name, result.stderr.strip())
                continue
            for line in result.stdout.splitlines():
                if line.startswith('insmod '):
                    source = Path(line.split()[1])
                    if source not in module_paths:
                        module_paths.append(source)
        module_commands = []
        for index, source in enumerate(module_paths):
            target = root / 'modules' / ('%03d.ko' % index)
            if source.suffix == '.zst':
                with target.open('wb') as out:
                    run('zstd', '-d', '-c', source, stdout=out)
            elif source.suffix == '.xz':
                import lzma
                target.write_bytes(lzma.decompress(source.read_bytes()))
            elif source.suffix == '.gz':
                target.write_bytes(gzip.decompress(source.read_bytes()))
            else:
                shutil.copy2(source, target)
            module_commands.append('insmod /modules/' + target.name + ' || echo MODULE_LOAD_WARNING_' + source.name)
        (root / 'etc' / 'passwd').write_text('root:x:0:0:root:/root:/bin/sh\n')
        (root / 'etc' / 'group').write_text('root:x:0:\n')
        (root / 'etc' / 'nsswitch.conf').write_text('hosts: files\npasswd: files\ngroup: files\n')
        (root / 'etc' / 'hosts').write_text('127.0.0.1 localhost\n::1 localhost\n')
        init = root / 'init'
        mode = ' --smoke' if args.smoke else ' --suite ' + args.suite
        init.write_text('#!/bin/sh\n'
            'export PATH=/bin:/sbin\n'
            'export PYTHONDONTWRITEBYTECODE=1\n'
            'mount -t proc proc /proc\nmount -t sysfs sysfs /sys\n'
            'mount -t devtmpfs devtmpfs /dev\nmkdir -p /dev/net /run/netns /tmp\n'
            'mount -t tmpfs tmpfs /run\nmount -t tmpfs tmpfs /tmp\n'
            'mkdir -p /run/netns\nmount --make-rshared /\n'
            + '\n'.join(module_commands) + '\n'
            '/bin/python3 /test/kernel_network_integration.py --binary /test/tunnel --module /test/tunnel_kmod.ko --work /tmp/kernel-tests' + mode + '\n'
            'echo TUNNEL_KERNEL_GUEST_EXIT:$?\ndmesg | tail -n 30\npoweroff -f\n')
        (root / 'bin' / 'tail').symlink_to('busybox')
        init.chmod(0o755)
        archive = work / 'initramfs.cpio.gz'
        names = b'.\0' + b''.join(str(p.relative_to(root)).encode() + b'\0' for p in sorted(root.rglob('*')))
        packed = subprocess.run(['cpio', '--null', '-o', '--format=newc'], cwd=root, input=names,
            capture_output=True, check=True)
        with gzip.open(archive, 'wb', compresslevel=1) as out:
            out.write(packed.stdout)
        log_path = work / 'console.log'
        command = ['qemu-system-x86_64', '-machine', 'q35,accel=tcg', '-cpu', 'max',
            '-m', '1024', '-smp', '2', '-nodefaults', '-no-reboot', '-nographic',
            '-serial', 'stdio', '-monitor', 'none', '-kernel', str(Path(args.kernel).resolve()),
            '-initrd', str(archive), '-append', 'console=ttyS0 rdinit=/init panic=-1 loglevel=4']
        print('Starting isolated guest:', args.release, flush=True)
        try:
            with log_path.open('w') as log:
                result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=args.timeout)
        except subprocess.TimeoutExpired:
            print(log_path.read_text(errors='replace')[-16000:])
            raise RuntimeError('QEMU test timed out; see ' + str(log_path))
        console = log_path.read_text(errors='replace')
        print(console[-24000:])
        matches = re.findall(r'TUNNEL_KERNEL_RESULT:(\{[^\r\n]+\})', console)
        if not matches:
            raise RuntimeError('Guest produced no test result; see ' + str(log_path))
        report = json.loads(matches[-1])
        abi = re.findall(r'KERNEL_UAPI_RESULT (\{[^\r\n]+\})', console)
        if abi:
            report['uapi'] = json.loads(abi[-1])
        report.update(artifact_hashes)
        report.update(kernel_release=args.release, qemu_exit=result.returncode, console=str(log_path))
        (work / 'results.json').write_text(json.dumps(report, indent=2))
        return 0 if report['ok'] and result.returncode == 0 else 1
    finally:
        # This is a newly created, resolved child of the explicit --work path.
        if root.parent == work and root.name.startswith('root-'):
            shutil.rmtree(root)


if __name__ == '__main__':
    raise SystemExit(main())
