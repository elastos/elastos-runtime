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

    # The journey's contract, spelled out here so a changed table cannot move the test with it.
    TRANSITIONS = {'start':('community','a','b'), 'node_restart':('community','a','b'),
                   'fresh_home':('community','a','b','c'), 'restart_b':('community','a','b','c')}

    def transitions(self):
        rows = {}
        for name, homes in self.TRANSITIONS.items():
            members = [home for home in homes if home != 'community']
            rows[name] = {'homes':{home:{'alive':True, 'peer_count':1} for home in homes},
                          'community':[{'from':sender, 'to':receiver, 'sent':f'{name} post from {sender}',
                                        'received':f'{name} post from {sender}'}
                                       for sender in members for receiver in members if sender != receiver],
                          'direct':{'from':'a', 'to':'b', 'sent':name+' direct', 'received':name+' direct'}}
        return rows

    def receipt(self):
        identity = self.identity()
        return {**identity, 'node_identity':identity, 'status':'passed', 'fixture_removed':True,
                'network_arrangement':'same-host',
                'homes':[{'home':name, 'installed_runtime_sha256':identity['installed_runtime_sha256'],
                          'carrier_bind_address':f'127.0.0.1:{1025+index}'}
                         for index,name in enumerate(('a','b','c','community'))],
                'process_cleanup':[{'status':'passed', 'after':{'runtime':0}} for _ in range(7)],
                'browser_cross_home_http_requests':0,
                'direct_endpoint_observations':[{'home':name,'ticket_addresses':[{'Ip':f'127.0.0.1:{1025+index}'}]}
                    for index,name in ((3,'community'),(3,'community'),(0,'a'),(1,'b'),(3,'community'),(2,'c'),(1,'b'))],
                'transitions':self.transitions(),
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
                           ('browser_cross_home_http_requests',1), ('direct_endpoint_observations',[]),
                           ('transitions',{})]:
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

    def test_acceptance_binds_the_node_and_each_home_to_its_own_build(self):
        check = JOURNEY['two_home_receipt_valid']
        homes, node = self.identity(), {**self.identity(), 'candidate':'f'*40, 'installed_runtime_sha256':'9'*64}
        mixed = self.receipt()
        mixed['node_identity'] = node
        next(home for home in mixed['homes'] if home['home'] == 'community')['installed_runtime_sha256'] = '9'*64
        self.assertTrue(check(mixed, homes, node_identity=node))
        self.assertFalse(check(mixed, homes), 'a same-version acceptance refuses another node build')
        self.assertFalse(check(self.receipt(), homes, node_identity=node), 'the named node build did not run')
        for name in ('community', 'a'):
            changed = copy.deepcopy(mixed)
            row = next(home for home in changed['homes'] if home['home'] == name)
            row['installed_runtime_sha256'] = ('a' if name == 'community' else '9')*64
            self.assertFalse(check(changed, homes, node_identity=node), name+' ran the other build')
        changed = self.receipt()
        del changed['node_identity']
        self.assertFalse(check(changed, homes))

    def test_acceptance_requires_positive_evidence_after_every_transition(self):
        check = JOURNEY['two_home_receipt_valid']
        valid = self.receipt()
        def refused(label, change):
            changed = copy.deepcopy(valid)
            change(changed['transitions'])
            self.assertFalse(check(changed, self.identity()), label)
        for name, homes in self.TRANSITIONS.items():
            refused(name+' is missing', lambda rows: rows.pop(name))
            for home in homes:
                refused(f'{home} is missing at {name}', lambda rows: rows[name]['homes'].pop(home))
                for alive in (False, None, 'true'):
                    refused(f'{home} alive={alive!r} at {name}',
                            lambda rows: rows[name]['homes'][home].update(alive=alive))
                for count in (0, None, True, '1'):
                    refused(f'{home} peer_count={count!r} at {name}',
                            lambda rows: rows[name]['homes'][home].update(peer_count=count))
                refused(f'{home} reports no peer count at {name}', lambda rows: rows[name]['homes'][home].pop('peer_count'))
            for index, post in enumerate(valid['transitions'][name]['community']):
                pair = f"{post['from']} to {post['to']} at {name}"
                refused(pair+' is missing', lambda rows: rows[name]['community'].pop(index))
                refused(pair+' arrived as a prefix',
                        lambda rows: rows[name]['community'][index].update(received=post['sent'][:-1]))
                refused(pair+' has no text', lambda rows: rows[name]['community'][index].update(sent='', received=''))
                if len(homes) > 3:
                    refused(pair+' is a second post from its sender', lambda rows: rows[name]['community'][index].update(
                        sent='second post', received='second post'))
            refused('a post is counted twice at '+name,
                    lambda rows: rows[name]['community'].__setitem__(1, rows[name]['community'][0]))
            refused('direct is missing at '+name, lambda rows: rows[name].pop('direct'))
            refused('direct arrived as a prefix at '+name, lambda rows: rows[name]['direct'].update(received=name+' direc'))
            refused('direct has no recipient at '+name, lambda rows: rows[name]['direct'].update(to='a'))
        def repost(rows):
            for post in rows['node_restart']['community']:
                post['sent'] = post['received'] = 'start post from '+post['from']
        refused('a post from before the node restart counts after it', repost)
        refused('a direct message from before the node restart counts after it',
                lambda rows: rows['node_restart']['direct'].update(sent='start direct', received='start direct'))

    def test_transition_homes_record_an_exited_process_and_wait_for_a_late_peer_count(self):
        observe = JOURNEY['transition_homes']
        transition = JOURNEY['Transition']('node_restart', 'restart_community', ('community', 'a'))
        running, exited = mock.Mock(**{'poll.return_value':None}), mock.Mock(**{'poll.return_value':1})
        late = {'community':iter([None, 0, 2]), 'a':iter([1])}
        with mock.patch.object(observe.__globals__['time'], 'sleep'):
            self.assertEqual(observe(transition, {'community':running, 'a':running}, lambda name: next(late[name])),
                             {'community':{'alive':True, 'peer_count':2}, 'a':{'alive':True, 'peer_count':1}})
        self.assertEqual(observe(transition, {'community':exited, 'a':running}, lambda name: 1)['community'],
                         {'alive':False, 'peer_count':None})
        self.assertEqual(observe(transition, {'a':running}, lambda name: 1)['community'],
                         {'alive':False, 'peer_count':None})
        for count in (None, 0):
            self.assertEqual(observe(transition, {'community':running, 'a':running}, lambda name: count, budget=0)['a'],
                             {'alive':True, 'peer_count':count})

    def test_peer_count_comes_from_the_home_status_command_and_an_absent_count_stays_absent(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary).resolve()
            (home/'bin').mkdir()
            runtime = home/'bin/elastos'
            runtime.write_text('#!/bin/sh\n[ "$*" = "home --status --json" ] || exit 2\ncat "$HOME/status.json"\n')
            runtime.chmod(0o700)
            owner = JOURNEY['Owner'](home, home, '', '', None)
            environment = {'PATH':os.environ['PATH'], 'HOME':str(home)}
            for status, expected in (({'runtime':{'running':True, 'peer_count':2}}, 2),
                                     ({'runtime':{'running':True, 'peer_count':0}}, 0),
                                     ({'runtime':{'running':True}}, None)):
                (home/'status.json').write_text(json.dumps(status))
                self.assertEqual(JOURNEY['home_peer_count'](owner, environment), expected)

    def test_network_arrangement_and_each_observed_ticket_must_match_configuration(self):
        check = JOURNEY['two_home_receipt_valid']
        valid = self.receipt()
        changed = copy.deepcopy(valid)
        changed['network_arrangement'] = 'two-nat'
        self.assertFalse(check(changed, self.identity()))
        self.assertFalse(check(valid, self.identity(), 'two-nat'))
        for index in range(len(valid['direct_endpoint_observations'])):
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
                               {name:JOURNEY['Owner'](root, root, '', '', None) for name in children},
                               stop, None, {}, time.monotonic())
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
        with self.assertRaises(JOURNEY['MessageDeadline']):
            with JOURNEY['message_timeout'](.05):
                time.sleep(1)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0,0))
        self.assertEqual(signal.getsignal(signal.SIGALRM), before)

    def test_deadline_cannot_be_swallowed_by_an_oserror_handler(self):
        swallowed = []
        with self.assertRaises(BaseException) as raised:
            with JOURNEY['message_timeout'](.05):
                try:
                    time.sleep(.2)
                except OSError:
                    swallowed.append(True)
        self.assertFalse(swallowed)
        self.assertNotIsInstance(raised.exception, OSError)

    def test_signal_census_cost_does_not_grow_with_process_count(self):
        stop = JOURNEY['stop_message_processes']
        counts = []
        for count in (2,20):
            rows = {pid:{'ppid':0,'start':'fixture birth','command':'fixture child'}
                    for pid in range(100,100+count)}
            census = mock.Mock(return_value=rows)
            with mock.patch.dict(stop.__globals__, {'process_rows':census}), mock.patch.object(os,'kill'):
                with self.assertRaises(AssertionError):
                    stop(mock.Mock(pid=100), rows.copy(), grace=0, killed=0)
            counts.append(census.call_count)
        self.assertEqual(counts[0], counts[1])
        self.assertLessEqual(counts[0], 4)

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

    def installed_data(self, data, commit, tree):
        (data/'bin').mkdir(parents=True)
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
        receipt = {'source':{'commit':commit,'tree':tree,'clean':True},
                   'runtime':{'built_sha256':sha,'installed_sha256':sha,'parity':True},
                   'components_sha256':'sha256:'+JOURNEY['digest'](data/'components.json'),
                   'source_home_capsule_metadata_receipt_sha256':'sha256:'+JOURNEY['digest'](data/'receipts/source-home-capsules.json')}
        (data/'receipts/source-home-installation.json').write_text(json.dumps(receipt))
        return runtime

    def test_an_installed_build_is_bound_to_its_own_checkout(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo, home = Path(temporary).resolve()/'released', Path(temporary).resolve()/'home'
            repo.mkdir()
            git = lambda *arguments: subprocess.check_output(['git', *arguments], cwd=repo, text=True).strip()
            git('init', '--quiet')
            git('-c', 'user.name=fixture', '-c', 'user.email=fixture@example.invalid', '-c', 'commit.gpgsign=false',
                'commit', '--quiet', '--allow-empty', '--message', 'released fixture')
            self.installed_data(home/'data', git('rev-parse', 'HEAD'), git('rev-parse', 'HEAD^{tree}'))
            build = JOURNEY['installed_build']('released', home, home/'data', repo)
            self.assertEqual((build.name, build.home, build.data, build.repo), ('released', home, home/'data', repo))
            self.assertEqual(build.identity['candidate'], git('rev-parse', 'HEAD'))
            with self.assertRaises(AssertionError):
                JOURNEY['installed_build']('candidate', home, home/'data')

    def test_source_identity_rejects_changed_runtime_and_browser_asset_before_launch(self):
        identify = JOURNEY['installed_message_identity']
        with tempfile.TemporaryDirectory() as temporary:
            data = Path(temporary).resolve()/'data'
            runtime = self.installed_data(data, 'c'*40, 'd'*40)
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
