"""Failure atomicity for the GUI/CLI host's configuration commit."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from remote_desktop.daemon import ConfigurationManager
from tools.tunnel_cli import freeze_network_permissions, pointer, redact


class ManagerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / 'config.json'
        self.old = {'address': '127.0.0.1:51001', 'networks': ['10.77.0.1/24'], 'peers': []}
        self.path.write_text(json.dumps(self.old))
        self.original = self.path.read_bytes()
        self.active = copy.deepcopy(self.old)
        self.core = Mock()
        self.core.call.side_effect = self.apply_core
        self.runtime = Mock()
        self.manager = ConfigurationManager(self.core, self.runtime, self.path, self.old, copy.deepcopy)

    def tearDown(self):
        self.temp.cleanup()

    def apply_core(self, method, **params):
        self.assertEqual(method, 'config_apply')
        candidate = Path(params['path'])
        self.assertTrue(candidate.is_file())
        self.active = json.loads(candidate.read_text())
        return {'ok': True, 'mode': 'rebuild', 'interrupted': True, 'running': True}

    def test_success_commits_after_core_and_cleans_private_candidate(self):
        changed = dict(self.old, tun_mtu=1300)
        self.assertEqual(self.manager.apply(changed)['mode'], 'rebuild')
        self.assertEqual(json.loads(self.path.read_bytes()), changed)
        self.assertEqual(self.active, changed)
        self.assertFalse(list(self.path.parent.glob('.reload-*')))

    def test_validation_failure_does_not_touch_runtime_or_file(self):
        self.manager.normalize = Mock(side_effect=ValueError('invalid configuration'))
        with self.assertRaisesRegex(ValueError, 'invalid'):
            self.manager.apply({})
        self.core.call.assert_not_called()
        self.assertEqual(self.path.read_bytes(), self.original)

    def test_core_rejection_does_not_apply_desktop_or_write_file(self):
        self.core.call.side_effect = None
        self.core.call.return_value = {'ok': False, 'error': 'bind failed', 'rolled_back': True}
        with self.assertRaisesRegex(ValueError, 'bind failed'):
            self.manager.apply(dict(self.old, tun_mtu=1300))
        self.runtime.configure.assert_not_called()
        self.assertEqual(self.path.read_bytes(), self.original)
        self.assertFalse(list(self.path.parent.glob('.reload-*')))

    def test_disk_failure_rolls_back_live_configuration(self):
        with patch('remote_desktop.daemon.atomic_write', side_effect=OSError('disk full')):
            with self.assertRaisesRegex(ValueError, 'previous configuration restored'):
                self.manager.apply(dict(self.old, tun_mtu=1300))
        self.assertEqual(self.active, self.old)
        self.assertEqual(self.path.read_bytes(), self.original)
        self.assertEqual(self.manager.document, self.old)

    def test_remote_apply_failure_rolls_back_core(self):
        self.runtime.configure.side_effect = [ValueError('desktop failed'), None]
        with self.assertRaisesRegex(ValueError, 'previous configuration restored'):
            self.manager.apply(dict(self.old, tun_mtu=1300))
        self.assertEqual(self.active, self.old)
        self.assertEqual(self.path.read_bytes(), self.original)

    def test_rollback_failure_is_explicit(self):
        self.core.call.side_effect = [dict(ok=True, mode='rebuild'), dict(ok=False, error='device lost')]
        self.runtime.configure.side_effect = ValueError('desktop failed')
        with self.assertRaisesRegex(ValueError, 'rollback failed.*device lost'):
            self.manager.apply(dict(self.old, tun_mtu=1300))
        self.assertEqual(self.path.read_bytes(), self.original)

    def test_pointer_and_redaction_do_not_change_other_fields(self):
        doc = {'peers': [{'address': '127.0.0.1:51200', 'shared_key': 'secret'}], 'a/b': {'~c': 1}}
        pointer(doc, '/a~1b/~0c', 2)
        pointer(doc, '/peers/0/address', '127.0.0.1:51201')
        self.assertEqual(doc['a/b']['~c'], 2)
        self.assertEqual(redact(doc)['peers'][0]['shared_key'], '<hidden>')
        self.assertEqual(doc['peers'][0]['shared_key'], 'secret')
        with self.assertRaises(ValueError):
            pointer(doc, '/peers/-1/address', 'bad')

    def test_new_network_keeps_existing_peer_permissions(self):
        doc = dict(self.old, peers=[{'address': '127.0.0.1:51200', 'shared_key': 'secret'}])
        freeze_network_permissions(doc)
        doc['networks'].append('10.78.0.1/24')
        self.assertEqual(doc['peers'][0]['networks'], ['10.77.0.0/24'])
        self.assertEqual(doc['listen']['networks'], ['10.77.0.0/24'])


if __name__ == '__main__':
    unittest.main()
