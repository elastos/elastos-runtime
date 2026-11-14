#!/usr/bin/env python3
"""Receipt guards for the installed two-Home journey; no Runtime or browser mocks."""
import copy
import json
from pathlib import Path
import runpy
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
JOURNEY = runpy.run_path(str(ROOT / 'scripts/ci-installed-journeys.py'))


class TwoHomeReceiptTests(unittest.TestCase):
    def identity(self):
        return {'candidate':'c'*40, 'source_tree':'d'*40, 'installed_runtime_sha256':'a'*64,
                'source_components_sha256':'b'*64, 'installation_receipt_sha256':'e'*64}

    def receipt(self):
        identity = self.identity()
        return {**identity, 'fixture_removed':True,
                'homes':[{'home':name, 'installed_runtime_sha256':identity['installed_runtime_sha256']}
                         for name in ('a','b','community')],
                'process_cleanup':[{'status':'passed', 'after':{'runtime':0}} for _ in range(5)],
                'transport':{'carrier_network':'direct','mdns':False},
                'results':{name:'passed' for name in ('community_post','direct_received','sender_delivered',
                                                     'offline_pending','restart_delivery')},
                'negative_controls':{name:{'assertion_rejected':True, 'api_state':'pending', 'ui_detail':'Sending'}
                                     for name in ('community_post','direct_received','sender_delivered')}}

    def test_acceptance_refuses_stale_identity_unchecked_failure_controls_or_surviving_processes(self):
        valid = self.receipt()
        check = JOURNEY['two_home_receipt_valid']
        self.assertTrue(check(valid, self.identity()))
        for key in self.identity():
            changed = copy.deepcopy(valid)
            changed[key] = 'stale'
            self.assertFalse(check(changed, self.identity()), key)
        for key, value in [('fixture_removed',False), ('homes',[]), ('process_cleanup',[])]:
            changed = copy.deepcopy(valid)
            changed[key] = value
            self.assertFalse(check(changed, self.identity()), key)
        for field in ('results','negative_controls'):
            for name in valid[field]:
                changed = copy.deepcopy(valid)
                del changed[field][name]
                self.assertFalse(check(changed, self.identity()), name)
        changed = copy.deepcopy(valid)
        changed['process_cleanup'][0]['after']['runtime'] = 1
        self.assertFalse(check(changed, self.identity()))
        changed = copy.deepcopy(valid)
        changed['negative_controls']['sender_delivered']['api_state'] = 'receipt_settled'
        self.assertFalse(check(changed, self.identity()))
        changed = copy.deepcopy(valid)
        changed['homes'][1]['home'] = 'a'
        self.assertFalse(check(changed, self.identity()))

    def test_source_identity_rejects_changed_runtime_and_browser_asset_before_launch(self):
        identify = JOURNEY['installed_message_identity']
        with tempfile.TemporaryDirectory() as temporary:
            data = Path(temporary)
            (data/'bin').mkdir()
            (data/'receipts').mkdir()
            runtime = data/'bin/elastos'
            runtime.write_bytes(b'fixture runtime')
            manifest = {'capsules':{}}
            for name in ('home','home-gui','people','inbox','chat-room'):
                directory = data/'capsules'/name
                directory.mkdir(parents=True)
                (directory/'index.html').write_text('fixture page')
                manifest['capsules'][name] = {'entrypoint':'index.html',
                    'entrypoint_sha256':'sha256:'+JOURNEY['digest'](directory/'index.html'),
                    'browser_assets':[{'path':'index.html','sha256':'sha256:'+JOURNEY['digest'](directory/'index.html')}]}
            (data/'components.json').write_text(json.dumps(manifest))
            (data/'receipts/source-home-capsules.json').write_text('{}')
            sha = 'sha256:'+JOURNEY['digest'](runtime)
            receipt = {'source':{'commit':'c'*40,'tree':'d'*40,'clean':True},
                       'runtime':{'built_sha256':sha,'installed_sha256':sha,'parity':True},
                       'components_sha256':'sha256:'+JOURNEY['digest'](data/'components.json'),
                       'source_home_capsule_metadata_receipt_sha256':'sha256:'+JOURNEY['digest'](data/'receipts/source-home-capsules.json')}
            (data/'receipts/source-home-installation.json').write_text(json.dumps(receipt))
            def observe():
                with mock.patch.object(identify.__globals__['subprocess'], 'check_output', side_effect=['c'*40,'d'*40]):
                    return identify(data)
            self.assertEqual(observe()['candidate'], 'c'*40)
            (data/'capsules/chat-room/index.html').write_text('stale UI')
            with self.assertRaises(AssertionError):
                observe()
            (data/'capsules/chat-room/index.html').write_text('fixture page')
            runtime.write_bytes(b'stale binary')
            with self.assertRaises(AssertionError):
                observe()


if __name__ == '__main__':
    unittest.main()
