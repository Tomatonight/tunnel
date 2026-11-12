"""Configure and manage Tunnel without opening a desktop window."""
import argparse
import getpass
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import sys

# Keep direct execution (`python tools/tunnel_cli.py`) equivalent to
# `python -m tools.tunnel_cli` by adding the repository root to sys.path.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from gui.controller import Controller
from remote_desktop.security import strict_json


def redact(value):
    if isinstance(value, dict):
        return {key: '<hidden>' if key == 'shared_key' else redact(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


def pointer(document, path, value=None, remove=False):
    if not path.startswith('/') or path == '/':
        raise ValueError('Use a JSON pointer, for example /tun_mtu or /peers/0/endpoint')
    parts = path[1:].split('/')
    for part in parts:
        import re
        if re.search(r'~(?![01])', part):
            raise ValueError('Invalid JSON pointer escape')
    parts = [part.replace('~1', '/').replace('~0', '~') for part in parts]
    current = document
    for part in parts[:-1]:
        if isinstance(current, dict):
            if part not in current and not remove:
                current[part] = {}
            current = current[part]
        elif isinstance(current, list):
            if not part.isdecimal():
                raise ValueError('Array index must be a nonnegative integer')
            current = current[int(part)]
        else:
            raise ValueError('Configuration path crosses a scalar value')
    key = parts[-1]
    if isinstance(current, dict):
        if remove:
            del current[key]
        else:
            current[key] = value
    elif isinstance(current, list):
        if key == '-' and not remove:
            current.append(value)
        elif key.isdecimal():
            index = int(key)
            if remove:
                del current[index]
            else:
                current[index] = value
        else:
            raise ValueError('Invalid array index')
    else:
        raise ValueError('Configuration path does not name an object or array entry')


def network_refs(document):
    refs = [str(ipaddress.ip_interface(item).network) for item in document.get('networks', [])]
    for client in document.get('address_clients', []):
        refs.extend(client.get('networks', []))
    return list(dict.fromkeys(refs))


def canonical_endpoint(value):
    """Parse a CLI endpoint using the core's fixed default transport port."""
    text = str(value).strip()
    if not text:
        raise ValueError('Endpoint must be a nonempty IP address')
    if text.startswith('['):
        closing = text.find(']')
        if closing <= 1 or (len(text) > closing + 1 and text[closing + 1] != ':'):
            raise ValueError('Invalid endpoint; use IP[:PORT] or [IPv6]:PORT')
        host = text[1:closing]
        port_text = text[closing + 2:] if len(text) > closing + 1 else '65535'
    elif text.count(':') == 0:
        host, port_text = text, '65535'
    elif text.count(':') == 1:
        host, port_text = text.rsplit(':', 1)
    else:
        host, port_text = text, '65535'
    try:
        address = ipaddress.ip_address(host)
        port = int(port_text)
    except (ValueError, TypeError):
        raise ValueError('Invalid endpoint; use IP[:PORT] or [IPv6]:PORT') from None
    if not 1 <= port <= 65535:
        raise ValueError('Endpoint port must be between 1 and 65535')
    if address.is_unspecified or address.is_multicast:
        raise ValueError('Peer endpoint must be a unicast IP address')
    return f'[{address}]:{port}' if address.version == 6 else f'{address}:{port}'


def freeze_network_permissions(document):
    """Adding an address must not silently give existing peers a new network."""
    refs = network_refs(document)
    for peer in document.get('peers', []):
        peer.setdefault('networks', list(refs))
    listen = document.setdefault('listen', {})
    listen.setdefault('networks', list(refs))


def main(argv=None):
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments and arguments[0] == '--remote-daemon':
        from remote_desktop.daemon import main as daemon_main
        return daemon_main(arguments[1:])
    parser = argparse.ArgumentParser(description=__doc__)
    base = Path(sys.executable).parent if getattr(sys, 'frozen', False) else ROOT / 'build'
    parser.add_argument('--binary', type=Path, default=base / ('tunnel.exe' if os.name == 'nt' else 'tunnel'))
    parser.add_argument('--config-dir', type=Path, help='Configuration directory (default: the application/project directory)')
    commands = parser.add_subparsers(dest='command', required=True)
    initialize = commands.add_parser('init', help='Create a new profile; does not start it')
    bind = initialize.add_mutually_exclusive_group()
    bind.add_argument('--bind-address', help='Local tunnel IP (default port 65535); may be IP:PORT, 0.0.0.0:PORT or [::]:PORT')
    bind.add_argument('--no-listen', action='store_true', help='Disable inbound listening; omit the local bind address')
    initialize.add_argument('--network', action='append', required=True, help='Local tunnel IP/prefix; repeat for several networks')
    start = commands.add_parser('start', help='Start core and optional desktop service in the background')
    start.add_argument('--config', type=Path, help='Import this complete JSON configuration before starting')
    commands.add_parser('stop', help='Stop this profile and release its interfaces')
    commands.add_parser('status', help='Show current connection and backend state')
    config = commands.add_parser('config', help='View, edit, validate or hot-apply configuration')
    settings = config.add_subparsers(dest='operation', required=True)
    show = settings.add_parser('show')
    show.add_argument('--running', action='store_true', help='Read the active backend configuration')
    show.add_argument('--show-secrets', action='store_true', help='Explicitly include PSKs in output')
    check = settings.add_parser('check')
    check.add_argument('file', nargs='?', type=Path)
    apply = settings.add_parser('apply', help='Validate, apply and save a complete JSON file')
    apply.add_argument('file', type=Path)
    settings.add_parser('reload', help='Apply edits made to this profile configure.json')
    set_value = settings.add_parser('set', help='Set a JSON pointer to a JSON value, and apply')
    set_value.add_argument('path')
    set_value.add_argument('value')
    set_value.add_argument('--string', action='store_true', help='Treat VALUE as a literal string')
    unset = settings.add_parser('unset', help='Remove an optional field, and apply')
    unset.add_argument('path')
    peers = commands.add_parser('peer').add_subparsers(dest='operation', required=True)
    add = peers.add_parser('add', help='Add a peer; prompts for its PSK unless --key-file is supplied')
    add.add_argument('address', help='Peer IP (default port 65535), or IP:PORT')
    add.add_argument('--key-file', type=Path)
    add.add_argument('--network', action='append', help='Allowed canonical tunnel network; repeat as needed')
    add.add_argument('--transport', choices=('udp', 'tcp'), default='tcp', help='Data encapsulation preference; TCP by default, or UDP when explicitly selected')
    remove = peers.add_parser('remove')
    remove.add_argument('address', help='Peer IP (default port 65535), or IP:PORT')
    networks = commands.add_parser('network').add_subparsers(dest='operation', required=True)
    add = networks.add_parser('add', help='Add a static local IP/prefix; existing peer permissions stay unchanged')
    add.add_argument('address')
    remove = networks.add_parser('remove', help='Remove a static IP/prefix; dependent permissions must first be changed')
    remove.add_argument('address')
    args = parser.parse_args(arguments)
    if args.command == 'init' and not args.bind_address and not args.no_listen:
        parser.error('init requires --bind-address or --no-listen')
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, 'reconfigure'):
            stream.reconfigure(encoding='utf-8')

    def emit(value):
        print(json.dumps(value, ensure_ascii=False, indent=2))

    try:
        controller = Controller(args.binary, args.config_dir)
        expected_revision = hashlib.sha256(controller.path.read_bytes()).hexdigest() if controller.path.exists() else None

        def request(action, **payload):
            reply = json.loads(controller.request(json.dumps({'action': action, 'payload': payload}, ensure_ascii=False)))
            if not reply.get('ok'):
                raise ValueError(reply.get('error', 'Operation failed'))
            return reply['data']

        def read_document():
            nonlocal expected_revision
            # Do not create a sample or guess addresses on a CLI read operation.
            if not controller.path.exists():
                raise ValueError('No configuration in this profile; use init or start --config FILE')
            data = controller.path.read_bytes()
            expected_revision = hashlib.sha256(data).hexdigest()
            raw = data.decode('utf-8-sig')
            return json.loads(request('normalize_config', text=raw)['text'])

        def save(document):
            text = document if isinstance(document, str) else json.dumps(document, ensure_ascii=False)
            reply = request('save_config', text=text, expected_sha256=expected_revision)
            emit({key: item for key, item in reply.items() if key != 'text'})

        if args.command == 'init':
            if controller.path.exists():
                raise ValueError('Profile already has a configuration; use config apply FILE to replace it')
            listen = {'enabled': False} if args.no_listen else {'bind_address': args.bind_address}
            save({'listen': listen, 'networks': args.network, 'peers': []})
        elif args.command == 'start':
            text = args.config.read_text(encoding='utf-8-sig') if args.config else json.dumps(read_document())
            emit(request('start', text=text))
        elif args.command == 'stop':
            emit(request('stop'))
        elif args.command == 'status':
            emit(request('get_state'))
        elif args.command == 'config':
            if args.operation == 'show':
                document = controller._background.request('get_config')['config'] if args.running else read_document()
                emit(document if args.show_secrets else redact(document))
            elif args.operation == 'check':
                text = args.file.read_text(encoding='utf-8-sig') if args.file else json.dumps(read_document())
                emit(request('validate_config', text=text))
            elif args.operation == 'apply':
                save(args.file.read_text(encoding='utf-8-sig'))
            elif args.operation == 'reload':
                save(read_document())
            else:
                document = read_document()
                if args.operation == 'set':
                    value = args.value if args.string else strict_json(args.value)
                    pointer(document, args.path, value)
                else:
                    pointer(document, args.path, remove=True)
                save(document)
        elif args.command == 'peer':
            document = read_document()
            peers = document.setdefault('peers', [])
            endpoint = canonical_endpoint(args.address)
            matches = [item for item in peers if canonical_endpoint(item['endpoint']) == endpoint]
            if args.operation == 'add':
                if matches:
                    raise ValueError('Peer already exists; use config set to update it')
                secret = args.key_file.read_text(encoding='utf-8').rstrip('\r\n') if args.key_file else getpass.getpass('Peer PSK: ')
                entry = {'endpoint': endpoint, 'shared_key': secret}
                if args.transport != 'tcp':
                    entry['transport'] = args.transport
                if args.network:
                    entry['networks'] = args.network
                peers.append(entry)
            else:
                if not matches:
                    raise ValueError('Peer was not found')
                document['peers'] = [item for item in peers if canonical_endpoint(item['endpoint']) != endpoint]
            save(document)
        elif args.command == 'network':
            document = read_document()
            address = str(ipaddress.ip_interface(args.address))
            networks = document.setdefault('networks', [])
            if args.operation == 'add':
                if address in networks:
                    raise ValueError('Static address already exists')
                freeze_network_permissions(document)
                networks.append(address)
            else:
                if address not in networks:
                    raise ValueError('Static address was not found')
                freeze_network_permissions(document)
                networks.remove(address)
            save(document)
        # Deliberately do not close Controller: CLI commands must leave a
        # running background service alive, even when desktop hosting is off.
        return 0
    except Exception as error:
        print(json.dumps({'ok': False, 'error': str(error)}, ensure_ascii=False), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
