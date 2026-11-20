#!/usr/bin/env python3
"""Receipt guards for the installed two-Home journey; no Runtime or browser mocks."""
import contextlib
import copy
import io
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
                        linux.index('scripts/ci-installed-journeys.sh two-home-messages'))
        for job in ('source-home-linux', 'source-home-macos'):
            block = source.split('\n  '+job+':\n', 1)[1].split('\n  source-home-', 1)[0]
            self.assertIn('scripts/ci-installed-journeys.sh two-home-messages', block)
            summary = block.split('name: summarize installed model journey', 1)[1]
            self.assertIn("CI_TWO_HOME_MESSAGES: 'true'", summary)
            self.assertNotIn('continue-on-error:', block.split('name: installed two-Home Community',1)[1].split('      - name:',1)[0])

    def test_matrix_entry_reaches_its_first_external_step_and_cleans_the_fixture(self):
        import types
        import shutil
        function = JOURNEY['two_home_message_matrix']
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            removed = []
            def cleanup(path):
                self.assertEqual(path.parent, root)
                self.assertTrue(path.name.startswith('carrier-journey-'))
                removed.append(path)
                shutil.rmtree(path)
            helpers = {'require_disk_space': mock.Mock(), 'remove_message_fixture': cleanup}
            with mock.patch.dict(function.__globals__, {
                    'runpy': types.SimpleNamespace(run_path=lambda _: helpers)}),                     mock.patch.object(Path, 'home', return_value=root),                     mock.patch.object(JOURNEY['subprocess'], 'run', side_effect=RuntimeError('stop before external build')) as run:
                with self.assertRaisesRegex(RuntimeError, 'stop before external build'):
                    function([], platform="linux")
                self.assertEqual(run.call_args.args[0][:2], ['openssl', 'req'])
            self.assertEqual(len(removed), 1)
            self.assertFalse(removed[0].exists())

    def test_network_matrix_scope_stays_with_the_existing_x64_job(self):
        source = (ROOT / '.github/workflows/ci.yml').read_text()
        for job, enabled in [('source-home-linux', 'true'), ('source-home-linux-arm64', 'false')]:
            block = source.split('\n  ' + job + ':\n', 1)[1].split('\n  source-home-', 1)[0]
            self.assertIn("CI_TWO_HOME_NETWORK_MATRIX: '" + enabled + "'", block)
        shell = (ROOT / 'scripts/ci-installed-journeys.sh').read_text()
        self.assertIn('if [[ "${CI_TWO_HOME_NETWORK_MATRIX:-false}" == true ]]', shell)
        self.assertIn('matrix_required = os.environ.get("CI_TWO_HOME_NETWORK_MATRIX") == "true"', shell)
        matrix = shell.split('    two-home-messages)', 1)[1].split('    home)', 1)[0]
        self.assertLess(matrix.index('scripts/test-behaviour.sh inputs'), matrix.index('--two-home-matrix'))
        self.assertIn('export NODE_PATH=', matrix)
        self.assertIn('export BROWSER_OPERATOR_PLAYWRIGHT_CORE=', matrix)

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
            rows[name] = {'homes':{home:{'alive':True, 'carrier_ticket_length':120} for home in homes},
                          'community':[{'from':sender, 'to':receiver, 'sent':f'{name} post from {sender}',
                                        'received':f'{name} post from {sender}'}
                                       for sender in members for receiver in members if sender != receiver],
                          'direct':{'from':'a', 'to':'b', 'sent':name+' direct', 'received':name+' direct'},
                          'reverse':{'sent':name+' answer', 'received':name+' answer'}}
        return rows

    def receipt(self, identity=None, node=None):
        identity = identity or self.identity()
        node = node or identity
        return {**identity, 'node_identity':node, 'status':'passed', 'fixture_removed':True,
                'network_arrangement':'same-host',
                'homes':[{'home':name, 'carrier_bind_address':f'127.0.0.1:{1025+index}',
                          'installed_runtime_sha256':(node if name == 'community' else identity)['installed_runtime_sha256']}
                         for index,name in enumerate(('a','b','c','community'))],
                'process_cleanup':[{'status':'passed', 'after':{'runtime':0}} for _ in range(7)],
                'browser_cross_home_http_requests':0,
                'direct_endpoint_observations':[{'home':name,'endpoint_id':{'community':'0','a':'a','b':'b','c':'c'}[name]*64,'ticket_addresses':[{'Ip':f'127.0.0.1:{1025+index}'}]}
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
                           ('process_cleanup',valid['process_cleanup'][:5]),
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
        mixed = self.receipt(homes, node)
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
                for length in (0, None, True, '120', 16385):
                    refused(f'{home} carrier_ticket_length={length!r} at {name}',
                            lambda rows: rows[name]['homes'][home].update(carrier_ticket_length=length))
                refused(f'{home} reports no Carrier observation at {name}',
                        lambda rows: rows[name]['homes'][home].pop('carrier_ticket_length'))
            for index, post in enumerate(valid['transitions'][name]['community']):
                pair = f"{post['from']} to {post['to']} at {name}"
                refused(pair+' is missing', lambda rows: rows[name]['community'].pop(index))
                refused(pair+' arrived as a prefix',
                        lambda rows: rows[name]['community'][index].update(received=post['sent'][:-1]))
                refused(pair+' has no text', lambda rows: rows[name]['community'][index].update(sent='', received=''))
                if len(homes) > 3:
                    refused(pair+' is a second post from its sender', lambda rows: rows[name]['community'][index].update(
                        sent='second post', received='second post'))
            refused('one post stands in for another at '+name,
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

    def test_transition_homes_observe_only_a_live_home_and_record_an_exited_one(self):
        observe = JOURNEY['transition_homes']
        transition = JOURNEY['Transition']('node_restart', 'restart_community', ('community', 'a'))
        running, exited = mock.Mock(**{'poll.return_value':None}), mock.Mock(**{'poll.return_value':1})
        self.assertEqual(observe(transition, {'community':running, 'a':running}, lambda name: len(name)),
                         {'community':{'alive':True, 'carrier_ticket_length':9},
                          'a':{'alive':True, 'carrier_ticket_length':1}})
        def refuse(name):
            if name == 'community':
                raise AssertionError('an exited Home was asked for a ticket')
            return 1
        self.assertEqual(observe(transition, {'community':exited, 'a':running}, refuse)['community'],
                         {'alive':False, 'carrier_ticket_length':None})
        self.assertEqual(observe(transition, {'a':running}, refuse)['community'],
                         {'alive':False, 'carrier_ticket_length':None})

    def test_the_carrier_observation_uses_the_homes_own_secret_at_shell_scope_and_bounds_the_ticket(self):
        with tempfile.TemporaryDirectory() as temporary:
            data = Path(temporary).resolve()
            (data/'gateway-runtime-coords.json').write_text(json.dumps(
                {'api_url':'http://127.0.0.1:1/', 'attach_secret':'fixture-secret'}))
            owner = JOURNEY['Owner'](data, data, '', '', None)
            posts = []
            def post_json(url, body, token=None):
                posts.append((url, body, token))
                return {'token':'fixture-token'} if url.endswith('/attach') else {'data':{'ticket':ticket}}
            with mock.patch.dict(JOURNEY['carrier_ticket'].__globals__, {'post_json':post_json}):
                ticket = 'T'*120
                self.assertEqual(JOURNEY['carrier_ticket'](owner), ticket)
                self.assertEqual(posts, [('http://127.0.0.1:1/api/auth/attach',
                                          {'secret':'fixture-secret', 'scope':'shell'}, None),
                                         ('http://127.0.0.1:1/api/provider/peer/get_ticket', {}, 'fixture-token')])
                for ticket in ('', 'T'*(JOURNEY['TICKET_MAX_LENGTH']+1)):
                    with self.assertRaises(AssertionError):
                        JOURNEY['carrier_ticket'](owner)

    def drive(self, outcome):
        """Run the mixed-version driver over a stand-in journey that saves a valid receipt unless ``outcome`` interferes."""
        driver = runpy.run_path(str(ROOT/'scripts/gossip-mixed-version-journey.py'))
        journey = driver['JOURNEY']
        identities = {'released':{**self.identity(), 'candidate':'1'*40, 'installed_runtime_sha256':'2'*64},
                      'candidate':self.identity()}
        calls = []
        def stand_in(homes, evidence, fixture_root, node_build):
            calls.append((node_build.name, homes.name, evidence.name, fixture_root.name))
            evidence.mkdir()
            receipt = self.receipt(homes.identity, node_build.identity)
            error = outcome(len(calls), receipt, fixture_root, journey)
            (evidence/'installed-journeys.json').write_text(json.dumps(receipt))
            if error:
                raise error
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            arguments = [argument for build in identities for part in ('home', 'data', 'repo')
                         for argument in (f'--{build}-{part}', str(root/build/part))]
            raised = None
            with mock.patch.dict(journey, {'two_home_messages':stand_in, 'installed_build':lambda name, *paths:
                    journey['InstalledBuild'](name, *paths, identities[name])}), contextlib.redirect_stdout(io.StringIO()):
                try:
                    driver['main']([*arguments, '--evidence', str(root/'evidence'), '--fixture-root', str(root/'fixtures')])
                except BaseException as error:
                    raised = error
            return raised, json.loads((root/'evidence/mixed-version-journey.json').read_text()), calls

    def test_mixed_version_driver_runs_every_pairing_into_its_own_evidence_and_fixture(self):
        raised, receipt, calls = self.drive(lambda *_: None)
        self.assertEqual(raised.code, 0)
        names = ['node-released-homes-released', 'node-released-homes-candidate',
                 'node-candidate-homes-released', 'node-candidate-homes-candidate']
        self.assertEqual(calls, [('released','released',names[0],names[0]), ('released','candidate',names[1],names[1]),
                                 ('candidate','released',names[2],names[2]), ('candidate','candidate',names[3],names[3])])
        self.assertEqual((receipt['status'], receipt['fixture_root_removed']), ('passed', True))
        self.assertEqual([row['arrangement'] for row in receipt['arrangements']], names)
        for row, (node, homes, *_) in zip(receipt['arrangements'], calls):
            self.assertEqual((row['status'], row['node']['build'], row['homes']['build']), ('passed', node, homes))
            self.assertEqual(row['node']['installed_runtime_sha256'], ('2' if node == 'released' else 'a')*64)
            self.assertEqual(row['homes']['installed_runtime_sha256'], ('2' if homes == 'released' else 'a')*64)
            self.assertEqual(row['journey']['transitions'], self.transitions())

    def test_mixed_version_driver_fails_on_a_failed_cleanup_an_unproven_receipt_or_a_leftover_fixture(self):
        def deadline(index, receipt, _root, journey):
            if index == 1:
                receipt.update(failure={'phase':'two_home_messages'})
                return journey['MessageDeadline']('two-Home phase deadline')
        def failed_cleanup(index, receipt, _root, _journey):
            if index == 2:
                receipt.update(status='failed', cleanup_failures=[{'phase':'stop_a'}])
                return RuntimeError('two-Home cleanup failed; see installed journey receipt')
        def no_carrier(index, receipt, _root, _journey):
            if index == 3:
                receipt['transitions']['node_restart']['homes']['a']['carrier_ticket_length'] = 0
        def raised_after_its_receipt(index, _receipt, _root, _journey):
            if index == 4:
                return RuntimeError('late failure')
        def leftover(index, _receipt, root, _journey):
            if index == 4:
                (root/'a').mkdir(parents=True)
        for outcome, failed, removed in ((deadline, ['node-released-homes-released'], True),
                                         (failed_cleanup, ['node-released-homes-candidate'], True),
                                         (no_carrier, ['node-candidate-homes-released'], True),
                                         (raised_after_its_receipt, ['node-candidate-homes-candidate'], True),
                                         (leftover, [], False)):
            with self.subTest(outcome=outcome.__name__):
                raised, receipt, calls = self.drive(outcome)
                self.assertEqual(raised.code, 1)
                self.assertEqual(len(calls), 4, 'the other arrangements stay observable')
                self.assertEqual((receipt['status'], receipt['fixture_root_removed']), ('failed', removed))
                self.assertEqual([row['arrangement'] for row in receipt['arrangements'] if row['status'] != 'passed'], failed)

    def test_mixed_version_driver_stops_on_sigterm_and_keeps_a_failed_receipt(self):
        def terminated(index, _receipt, _root, _journey):
            if index == 2:
                os.kill(os.getpid(), signal.SIGTERM)
                time.sleep(1)
        ignored = []
        operator = lambda *_: ignored.append(True)
        previous = signal.signal(signal.SIGTERM, operator)
        try:
            raised, receipt, calls = self.drive(terminated)
            self.assertIs(signal.getsignal(signal.SIGTERM), operator)
        finally:
            signal.signal(signal.SIGTERM, previous)
        self.assertEqual((type(raised).__name__, ignored, len(calls)), ('MessageTermination', [], 2))
        self.assertEqual((receipt['status'], len(receipt['arrangements'])), ('failed', 1))

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

    def test_promotion_receipt_needs_observed_relay_then_direct_and_failure_proof(self):
        row = self.receipt()
        row['network_arrangement'] = 'relay-to-direct'
        for home in row['homes']:
            host = {'community':'203.0.113.1', 'a':'10.0.1.2', 'b':'10.0.2.2', 'c':'10.0.2.2'}[home['home']]
            home['carrier_bind_address'] = host + ':' + home['carrier_bind_address'].rsplit(':', 1)[1]
        for observed in row['direct_endpoint_observations']:
            observed['ticket_addresses'] = [{'Relay':'https://203.0.113.1:8443/'}]
        row.update(promotion_candidates={'a':'a'*64,'b':'b'*64}, meeting_point={'origin':'https://203.0.113.1:8443/', 'spki_sha256':['a'*64]}, route_observations=['relay', 'direct'], all_carrier_paths_blocked=True, discovery_packets=12,
                   delivery_warning_count=2,
                   visible_failure={'reason':'peer_unreachable', 'ui_detail':'Unconfirmed',
                                    'elapsed_ms':65000, 'retry_same_message':True, 'b_alive':True, 'b_health':200, 'dropped_packets':12})
        row['results']['visible_failure'] = 'passed'
        row['results']['network_recovery'] = 'passed'
        check = JOURNEY['two_home_receipt_valid']
        self.assertTrue(check(row, self.identity(), 'relay-to-direct'))
        changed = copy.deepcopy(row)
        changed['promotion_candidates'] = {}
        self.assertFalse(check(changed, self.identity(), 'relay-to-direct'))
        changed = copy.deepcopy(row)
        changed['promotion_candidates']['a'] = 'other'
        self.assertFalse(check(changed, self.identity(), 'relay-to-direct'))
        changed = copy.deepcopy(row)
        changed['direct_endpoint_observations'][0]['ticket_addresses'] = [{'Relay':'https://foreign.invalid/'}]
        self.assertFalse(check(changed, self.identity(), 'relay-to-direct'))
        for routes in (['relay'], ['direct'], ['direct', 'relay']):
            changed = copy.deepcopy(row)
            changed['route_observations'] = routes
            self.assertFalse(check(changed, self.identity(), 'relay-to-direct'))
        for key, value in [('all_carrier_paths_blocked',False), ('delivery_warning_count',0),
                           ('delivery_warning_count',3), ('visible_failure',{})]:
            changed = copy.deepcopy(row)
            changed[key] = value
            self.assertFalse(check(changed, self.identity(), 'relay-to-direct'))

    def test_each_reverse_exchange_is_required_and_exact(self):
        for name in self.TRANSITIONS:
            for reverse in ({}, {'sent':'answer', 'received':'other'}):
                row = self.receipt()
                row['transitions'][name]['reverse'] = reverse
                self.assertFalse(JOURNEY['two_home_receipt_valid'](row, self.identity()))

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

    def test_sigterm_during_the_journey_reaches_its_cleanup_and_restores_the_handler(self):
        with tempfile.TemporaryDirectory() as temporary:
            home, root, evidence = (Path(temporary).resolve()/name for name in ('home', 'fixture', 'evidence'))
            (home/'data').mkdir(parents=True)
            build = JOURNEY['InstalledBuild']('home', home, home/'data', home, self.identity())
            def terminated_while_staging(*_arguments, **_options):
                os.kill(os.getpid(), signal.SIGTERM)
                time.sleep(1)
                raise RuntimeError('SIGTERM did not interrupt the journey')
            ignored = []
            operator = lambda *_: ignored.append(True)
            previous = signal.signal(signal.SIGTERM, operator)
            try:
                with mock.patch.dict(JOURNEY['finish_message_fixture'].__globals__, {
                        'fresh_fixture':terminated_while_staging, 'require_disk_space':lambda *_: {}}):
                    with self.assertRaises(JOURNEY['MessageTermination']):
                        JOURNEY['two_home_messages'](build, evidence, fixture_root=root)
                self.assertIs(signal.getsignal(signal.SIGTERM), operator)
            finally:
                signal.signal(signal.SIGTERM, previous)
            self.assertFalse(ignored)
            self.assertFalse(root.exists())
            receipt = json.loads((evidence/'installed-journeys.json').read_text())
            self.assertTrue(receipt['fixture_removed'])
            self.assertEqual(receipt['failure']['phase'], 'two_home_messages')
            self.assertFalse(JOURNEY['two_home_receipt_valid'](receipt, self.identity()))

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


INSTALL = runpy.run_path(str(ROOT / "scripts/install-source-home-runtime.py"))
NETWORK = runpy.run_path(str(ROOT / "scripts/ci-two-nat-network.py"))

class FixtureManifestTests(unittest.TestCase):
    def test_model_holder_keeps_its_original_http_owner(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            data = home / "data"
            data.mkdir()
            (data / "gateway-runtime-coords.json").write_text(json.dumps({
                "api_url": "http://localhost:1234", "attach_secret": "disposable-fixture"}))
            child = mock.Mock()
            post = mock.Mock(side_effect=[{"token": "fixture-token"}, {"data": {"ticket": "fixture-ticket"}}])
            owner = JOURNEY["start_holder"]
            with mock.patch.dict(owner.__globals__, {"wait_healthy": mock.Mock(), "post_json": post}), \
                    mock.patch.object(JOURNEY["subprocess"], "Popen", return_value=child), \
                    mock.patch.object(JOURNEY["subprocess"], "check_output", return_value='{"did":"did:fixture:holder"}'), \
                    mock.patch.object(JOURNEY["subprocess"], "run"):
                started, receipt = owner(home, data, home / "consumer", {})
            self.assertIs(started, child)
            self.assertEqual(receipt["holder_did"], "did:fixture:holder")
            self.assertEqual(post.call_args_list, [
                mock.call("http://localhost:1234/api/auth/attach", {"secret": "disposable-fixture", "scope": "shell"}),
                mock.call("http://localhost:1234/api/provider/peer/get_ticket", {}, "fixture-token")])

    def test_success_requires_a_bounded_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "receipt.json"
            with self.assertRaisesRegex(RuntimeError, "no receipt"):
                JOURNEY["require_message_receipt"](path)
            path.write_text('{"status":"passed"}')
            self.assertEqual(JOURNEY["require_message_receipt"](path), {"status":"passed"})
            path.write_bytes(b"x" * (1024 * 1024 + 1))
            with self.assertRaisesRegex(RuntimeError, "exceeds its bound"):
                JOURNEY["require_message_receipt"](path)

    def test_management_socket_is_opened_inside_the_home_namespace_with_secret_on_stdin(self):
        topology = NETWORK["MessageNetwork"].__new__(NETWORK["MessageNetwork"])
        topology.names = {"a": "fixture-home-a"}
        with mock.patch.object(NETWORK["subprocess"], "run", return_value=mock.Mock(stdout='{"token":"fixture"}')) as run:
            self.assertEqual(topology.http_json("a", "http://localhost/api/auth/attach",
                                                {"secret":"disposable-fixture-input"}), {"token":"fixture"})
        arguments, = run.call_args.args
        self.assertEqual(arguments[:4], ["ip", "netns", "exec", "fixture-home-a"])
        self.assertNotIn("disposable-fixture-input", " ".join(arguments))
        self.assertEqual(json.loads(run.call_args.kwargs["input"])["body"], {"secret":"disposable-fixture-input"})
        self.assertEqual(run.call_args.kwargs["timeout"], 65)

    def test_runtime_input_preserves_bytes_and_passes_the_single_link_artifact_gate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            built = root / "cargo-output"
            built.write_bytes(b"checksum fixture only; never executed")
            built.chmod(0o755)
            os.link(built, root / "cargo-deps-twin")
            with self.assertRaises(INSTALL["InstallError"]):
                INSTALL["hash_file"](built, 1024, executable=True, trusted_runtime=True)
            staged = JOURNEY["stage_runtime_input"](built, root / "runtime-input")
            self.assertEqual(staged.stat().st_nlink, 1)
            self.assertEqual(stat.S_IMODE(staged.stat().st_mode), 0o700)
            self.assertEqual(staged.read_bytes(), built.read_bytes())
            INSTALL["hash_file"](staged, 1024, executable=True, trusted_runtime=True)

    def test_fixture_contains_only_copied_apps_and_passes_the_shared_source_validator(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            data = root / "data"
            (data / "bin").mkdir(parents=True)
            binary = root / "checksum-input"
            binary.write_bytes(b"fixture for hashing only; this is never executed")
            JOURNEY["prepare_assets"](ROOT, data, binary)
            manifest = json.loads((data / "components.json").read_text())
            self.assertEqual(set(manifest["capsules"]), set(JOURNEY["MESSAGE_CAPSULES"]))
            INSTALL["validate_source_components"](manifest, "linux-amd64")
            # A stray source capsule from the full catalogue reopens the gap.
            manifest["capsules"]["uninstalled"] = {
                "entrypoint_sha256": "sha256:" + "a" * 64, "sha256": "", "cid": ""}
            manifest["external"]["uninstalled"] = {
                "platforms": {"linux-amd64": {"checksum": "sha256:" + "b" * 64}}}
            with self.assertRaises(INSTALL["InstallError"]):
                INSTALL["validate_source_components"](manifest, "linux-amd64")


if __name__ == '__main__':
    unittest.main()
