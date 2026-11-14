#!/usr/bin/env python3
"""Receipt guards for the installed two-Home journey; no Runtime or browser mocks."""
import copy
import json
from pathlib import Path
import runpy
import os
import stat
import subprocess
import sys
import time
import signal
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
JOURNEY = runpy.run_path(str(ROOT / 'scripts/ci-installed-journeys.py'))


class TwoHomeReceiptTests(unittest.TestCase):
    def test_fresh_home_and_data_are_private_with_the_operator_umask(self):
        fresh = JOURNEY['fresh_fixture']
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary).resolve()/'source'
            data = home/'.local/share/elastos'
            data.mkdir(parents=True)
            (data/'components.json').write_text('{}')
            prior = os.umask(0o022)
            try:
                with mock.patch.dict(fresh.__globals__, {'engine_paths':lambda _: (None,None,None,data/'missing-engine')}):
                    destination = Path(temporary).resolve()/'fresh'
                    copied = fresh(home,data,destination,include_engine=False)
                self.assertEqual(stat.S_IMODE(destination.stat().st_mode),0o700)
                self.assertEqual(stat.S_IMODE(copied.stat().st_mode),0o700)
            finally:
                os.umask(prior)

    def test_source_home_jobs_run_and_require_the_message_receipt(self):
        source = (ROOT/'.github/workflows/ci.yml').read_text()
        linux = source.split('\n  source-home-linux:\n',1)[1].split('\n  source-home-',1)[0]
        self.assertLess(linux.index('run: scripts/ci-installed-journeys.sh model-repair'),
                        linux.index('run: scripts/ci-installed-journeys.sh two-home-messages'))
        for job in ('source-home-linux', 'source-home-macos'):
            block = source.split('\n  '+job+':\n', 1)[1].split('\n  source-home-', 1)[0]
            self.assertIn('run: scripts/ci-installed-journeys.sh two-home-messages', block)
            summary = block.split('name: summarize installed model journey', 1)[1]
            self.assertIn("CI_TWO_HOME_MESSAGES: 'true'", summary)
            self.assertNotIn('continue-on-error:', block.split('name: installed two-Home Community',1)[1].split('      - name:',1)[0])

    def identity(self):
        return {'candidate':'c'*40, 'source_tree':'d'*40, 'installed_runtime_sha256':'a'*64,
                'source_components_sha256':'b'*64, 'installation_receipt_sha256':'e'*64}

    def receipt(self):
        identity = self.identity()
        return {**identity, 'status':'passed', 'fixture_removed':True, 'network_arrangement':'same-host',
                'homes':[{'home':name, 'installed_runtime_sha256':identity['installed_runtime_sha256'],
                          'carrier_bind_address':f'127.0.0.1:{1025+index}'}
                         for index,name in enumerate(('a','b','community'))],
                'process_cleanup':[{'status':'passed', 'after':{'runtime':0}} for _ in range(5)],
                'browser_cross_home_http_requests':0,
                'direct_endpoint_observations':[{'home':name,'ticket_addresses':[{'Ip':f'127.0.0.1:{1025+index}'}]}
                    for index,name in ((2,'community'),(2,'community'),(0,'a'),(1,'b'),(1,'b'))],
                'results':{name:'passed' for name in ('community_post','direct_received','sender_delivered',
                                                     'offline_pending','restart_delivery')},
                'negative_controls':{name:{'assertion_rejected':True, 'api_state':'pending', 'ui_detail':'Sending'}
                                     for name in ('sender_delivered',)}}

    def test_acceptance_refuses_stale_identity_unchecked_failure_controls_or_surviving_processes(self):
        valid = self.receipt()
        check = JOURNEY['two_home_receipt_valid']
        self.assertTrue(check(valid, self.identity()))
        for key in self.identity():
            changed = copy.deepcopy(valid)
            changed[key] = 'stale'
            self.assertFalse(check(changed, self.identity()), key)
        for key, value in [('status','failed'), ('failure',{'phase':'late failure'}), ('browser_failure','failed'),
                           ('fixture_removed',False), ('homes',[]), ('process_cleanup',[]),
                           ('browser_cross_home_http_requests',1), ('direct_endpoint_observations',[])]:
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

    def test_network_arrangement_and_each_observed_ticket_must_match_configuration(self):
        check = JOURNEY['two_home_receipt_valid']
        valid = self.receipt()
        changed = copy.deepcopy(valid)
        changed['network_arrangement'] = 'two-nat'
        self.assertFalse(check(changed, self.identity()))
        self.assertFalse(check(valid, self.identity(), 'two-nat'))
        for index in range(5):
            for address in ({'Relay':'https://relay.invalid'}, {'Ip':'192.0.2.1:1234'}, {'Ip':'127.0.0.1:1234'}):
                changed = copy.deepcopy(valid)
                changed['direct_endpoint_observations'][index]['ticket_addresses'] = [address]
                self.assertFalse(check(changed, self.identity()), (index, address))
        changed = copy.deepcopy(valid)
        changed['homes'][0]['carrier_bind_address'] = '192.0.2.1:1234'
        self.assertFalse(check(changed, self.identity()))

    def test_fixture_removal_refuses_nested_home_process(self):
        remove = JOURNEY['remove_message_fixture']
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()/'fixture'
            root.mkdir()
            row = {'command':str(root/'b/data/bin/elastos')+' gateway'}
            with mock.patch.dict(remove.__globals__, {'process_rows':lambda: {123:row}}):
                with self.assertRaises(AssertionError):
                    remove(root)
            self.assertTrue(root.exists())
            with mock.patch.dict(remove.__globals__, {'process_rows':lambda: {}}):
                remove(root)
            self.assertFalse(root.exists())

    def test_failed_stop_and_disk_check_finish_other_stops_remove_keys_and_write_failure_receipt(self):
        finish = JOURNEY['finish_message_fixture']
        for disk_fails in (False, True):
            with self.subTest(disk_fails=disk_fails), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()/'fixture'
                root.mkdir()
                (root/'authority.key').write_text('disposable test key')
                evidence = Path(temporary).resolve()/'evidence'
                evidence.mkdir()
                stopped = []
                children = {'a':mock.Mock(pid=101), 'b':mock.Mock(pid=102), 'community':mock.Mock(pid=103)}
                def stop(name):
                    stopped.append(name)
                    if name == 'a':
                        raise RuntimeError('injected stop failure')
                    del children[name]
                def disk(_):
                    if disk_fails:
                        raise RuntimeError('injected disk failure')
                    return {'free':123}
                fallback = mock.Mock()
                with mock.patch.dict(finish.__globals__, {'process_rows':lambda: {},
                        'stop_message_processes':fallback, 'require_disk_space':disk}):
                    with self.assertRaisesRegex(RuntimeError, 'cleanup failed'):
                        finish(root, root, evidence, {'status':'passed'}, children,
                               {name:(root,root) for name in children}, stop, None, {}, time.monotonic())
                self.assertEqual(stopped, ['a','b','community'])
                fallback.assert_called_once()
                self.assertFalse(root.exists())
                receipt = json.loads((evidence/'installed-journeys.json').read_text())
                self.assertEqual(receipt['status'], 'failed')
                self.assertTrue(receipt['fixture_removed'])
                self.assertEqual(len(receipt['cleanup_failures']), 2 if disk_fails else 1)
                self.assertNotIn('disposable test key', json.dumps(receipt))

    def test_work_deadline_interrupts_a_hung_phase_and_restores_the_timer(self):
        before = signal.getsignal(signal.SIGALRM)
        with self.assertRaises(TimeoutError):
            with JOURNEY['message_timeout'](.05):
                time.sleep(1)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0,0))
        self.assertEqual(signal.getsignal(signal.SIGALRM), before)

    def test_sigkill_fallback_stops_a_detached_browser_after_node_exits(self):
        stop = JOURNEY['stop_message_processes']
        with tempfile.TemporaryDirectory() as temporary:
            pidfile = Path(temporary).resolve()/'browser.pid'
            marker = '--two-home-fixture='+str(Path(temporary).resolve())
            termfile = Path(temporary).resolve()/'term-observed'
            detached_code = ('import os,signal,sys,time; from pathlib import Path; '
                             'signal.signal(signal.SIGTERM,lambda *_: Path(sys.argv[3]).write_text("TERM")); '
                             'Path(sys.argv[2]).write_text(str(os.getpid())); time.sleep(60)')
            parent_code = ('import subprocess,sys,time; from pathlib import Path\n'
                           'subprocess.Popen([sys.executable,"-c",sys.argv[2],sys.argv[3],sys.argv[1],sys.argv[4]],start_new_session=True)\n'
                           'while not Path(sys.argv[1]).exists(): time.sleep(.01)')
            parent = subprocess.Popen([sys.executable,'-c',parent_code,str(pidfile),detached_code,marker,str(termfile)])
            detached = None
            try:
                parent.wait(timeout=5)
                detached = int(pidfile.read_text())
                # Node has already exited; the fixture marker identifies Chromium.
                with JOURNEY['message_timeout'](10):
                    stop(parent, {}, marker, grace=.2, killed=2)
                self.assertTrue(termfile.exists(), 'detached browser received TERM and required KILL')
                rows = JOURNEY['process_rows']()
                self.assertTrue(detached not in rows or rows[detached]['command'].endswith(' <defunct>'))
            finally:
                if detached:
                    try:
                        os.kill(detached, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                if parent.poll() is None:
                    parent.kill()
                parent.wait()

    def test_source_identity_rejects_changed_runtime_and_browser_asset_before_launch(self):
        identify = JOURNEY['installed_message_identity']
        with tempfile.TemporaryDirectory() as temporary:
            data = Path(temporary).resolve()
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
