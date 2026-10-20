#!/usr/bin/env python3
"""Build the optional Linux module without leaving intermediate files in source.

Example: python3 tools/build_kernel.py --headers /lib/modules/$(uname -r)/build
Requires the target kernel's configured headers, make and a matching compiler.
The module is not installed or loaded automatically.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import struct
import subprocess
import tempfile


def allocated_sections(path):
    """Hash every loadable ELF section, including modversions and code/data."""
    data = path.read_bytes()
    if data[:4] != b'\x7fELF' or data[4] not in (1, 2) or data[5] not in (1, 2):
        raise RuntimeError('Unsupported module ELF format')
    endian = '<' if data[5] == 1 else '>'
    if data[4] == 2:
        offset = struct.unpack_from(endian + 'Q', data, 40)[0]
        entry_size, count, names_index = struct.unpack_from(endian + 'HHH', data, 58)
        layout = endian + 'IIQQQQIIQQ'
    else:
        offset = struct.unpack_from(endian + 'I', data, 32)[0]
        entry_size, count, names_index = struct.unpack_from(endian + 'HHH', data, 46)
        layout = endian + 'IIIIIIIIII'
    sections = [struct.unpack_from(layout, data, offset + i * entry_size) for i in range(count)]
    names_section = sections[names_index]
    names = data[names_section[4]:names_section[4] + names_section[5]]
    result = {}
    for section in sections:
        if section[2] & 2:  # SHF_ALLOC; SHT_NOBITS has no file contents.
            name = names[section[0]:].split(b'\0', 1)[0].decode()
            content = data[section[4]:section[4] + section[5]] if section[1] != 8 else b''
            result[name] = {'type': section[1], 'flags': section[2], 'size': section[5],
                'sha256': hashlib.sha256(content).hexdigest()}
    return result


def capture_btf_tool(directory, name, executable, base_option):
    """Observe Kbuild's real flags while leaving its initial build unchanged."""
    executable = shutil.which(str(executable))
    if not executable:
        raise RuntimeError('Required BTF tool not found: ' + name)
    capture = directory / (name + '-invocation.json')
    wrapper = directory / (name + '-capture')
    wrapper.write_text('#!/usr/bin/env python3\n'
        'import json, os, sys\n'
        'from pathlib import Path\n'
        'args = sys.argv[1:]\n'
        'if ' + repr(base_option) + ' in args:\n'
        '    Path(' + repr(str(capture)) + ').write_text(json.dumps({"arguments": args, "cwd": os.getcwd()}))\n'
        'os.execv(' + repr(executable) + ', [' + repr(executable) + '] + args)\n')
    wrapper.chmod(0o755)
    return {'wrapper': wrapper, 'capture': capture, 'executable': executable, 'option': base_option}


def regenerate_btf(module, requested_base, base_snapshot, tools):
    """Rebuild optional debug BTF against the explicitly selected target base."""
    modprobe = shutil.which('modprobe') or '/usr/sbin/modprobe'
    objcopy = shutil.which(os.environ.get('OBJCOPY', 'objcopy'))
    if not objcopy:
        raise RuntimeError('objcopy is required with --btf-base')
    for tool in tools:
        if not tool['capture'].is_file():
            raise RuntimeError('Kbuild did not generate split BTF. --btf-base requires a prepared '
                'kernel tree with vmlinux, BTF enabled, pahole and resolve_btfids.')
    original_sections = allocated_sections(module)
    original_versions = subprocess.check_output([modprobe, '--show-modversions', str(module)], text=True)
    original_hash = hashlib.sha256(module.read_bytes()).hexdigest()
    subprocess.run([objcopy, '--remove-section=.BTF', '--remove-section=.BTF.ext',
        '--remove-section=.BTF.base', str(module)], check=True)
    environment = os.environ.copy()
    environment['LLVM_OBJCOPY'] = objcopy
    recorded = []
    for tool in tools:
        invocation = json.loads(tool['capture'].read_text())
        arguments = invocation['arguments']
        base_index = arguments.index(tool['option']) + 1
        arguments[base_index] = str(base_snapshot)
        subprocess.run([tool['executable'], *arguments], check=True, env=environment, cwd=invocation['cwd'])
        recorded.append({'tool': tool['executable'], 'arguments': arguments, 'cwd': invocation['cwd']})
    final_sections = allocated_sections(module)
    final_versions = subprocess.check_output([modprobe, '--show-modversions', str(module)], text=True)
    if original_sections != final_sections or original_versions != final_versions:
        raise RuntimeError('BTF regeneration changed allocated sections or import CRCs; refusing output')
    return {'base': str(requested_base), 'base_sha256': hashlib.sha256(base_snapshot.read_bytes()).hexdigest(),
        'original_module_sha256': original_hash, 'allocated_sections_identical': True,
        'allocated_sections': original_sections, 'imported_crc_metadata_identical': True,
        'original_imported_crc_metadata': original_versions, 'commands': recorded}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--headers', default='/lib/modules/' + platform.release() + '/build')
    parser.add_argument('--output', default='build/kernel')
    parser.add_argument('--jobs', type=int, default=min(os.cpu_count() or 1, 8))
    parser.add_argument('--cc', help='Optional compiler, e.g. gcc-13')
    parser.add_argument('--btf-base', type=Path, help='Explicit target kernel BTF file; regenerate '
        'optional module BTF without changing code or import CRCs. Use /sys/kernel/btf/vmlinux '
        'only when building for the currently running kernel.')
    args = parser.parse_args()
    if platform.system() != 'Linux':
        raise SystemExit('Build this module on Linux against the target Linux kernel headers.')
    headers = Path(args.headers).resolve()
    if not (headers / 'Makefile').is_file() or not (headers / 'include/generated/autoconf.h').is_file():
        raise SystemExit('Configured target kernel headers not found at ' + str(headers) +
            '. Install headers matching uname -r, or select a prepared tree with --headers. WSL often does not ship build headers.')
    btf_base = args.btf_base.resolve(strict=True) if args.btf_base else None
    source = Path(__file__).resolve().parent.parent / 'kernel'
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='tunnel-kmod-') as directory:
        build = Path(directory)
        inputs = [source / 'Makefile', *(p for p in source.glob('*.c') if not p.name.endswith('.mod.c')), *source.glob('*.h')]
        for path in inputs:
            shutil.copy2(path, build / path.name)
        command = ['make', '-C', str(build), 'KDIR=' + str(headers), '-j' + str(max(1, args.jobs))]
        if args.cc:
            command += ['CC=' + args.cc]
        btf_tools = []
        if btf_base:
            base_snapshot = build / 'target-vmlinux.btf'
            base_snapshot.write_bytes(btf_base.read_bytes())
            btf_tools = [capture_btf_tool(build, 'pahole', os.environ.get('PAHOLE', 'pahole'), '--btf_base'),
                capture_btf_tool(build, 'resolve_btfids',
                    headers / 'tools/bpf/resolve_btfids/resolve_btfids', '-b')]
            command += ['PAHOLE=' + str(btf_tools[0]['wrapper']),
                'RESOLVE_BTFIDS=' + str(btf_tools[1]['wrapper'])]
        subprocess.run(command, check=True)
        module = build / 'tunnel_kmod.ko'
        btf_report = regenerate_btf(module, btf_base, base_snapshot, btf_tools) if btf_base else None
        shutil.copy2(module, output / module.name)
        # Distro header-only trees may report the base source version for
        # `make kernelrelease`; vermagic records the actual generated target ABI.
        modinfo = shutil.which('modinfo') or '/usr/sbin/modinfo'
        release = subprocess.check_output([modinfo, '-F', 'vermagic', str(module)], text=True).split()[0]
        report = {'kernel_release': release, 'headers': str(headers), 'module': module.name,
            'module_sha256': hashlib.sha256(module.read_bytes()).hexdigest(),
            'source_sha256': {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs}}
        if btf_report:
            report['btf'] = btf_report
        (output / 'build-info.json').write_text(json.dumps(report, indent=2) + '\n')
    print('Built:', output / 'tunnel_kmod.ko')
    print('Target kernel:', release)
    print('Load only on that target kernel after checking its module signing policy.')


if __name__ == '__main__':
    main()
