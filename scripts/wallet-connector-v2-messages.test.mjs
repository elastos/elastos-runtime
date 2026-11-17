import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { messageDecision, queryValid, identityDecision, summarySiteDecision, wireKeys, wireTypes, nestedKeys,
  closeValid, handoffValid, settlementValid, selectedResultDecision } from './wallet-extension-test/message-contract.mjs';

const fixture = JSON.parse(await readFile(new URL('./fixtures/wallet-connector-v2-messages.json', import.meta.url), 'utf8'));
test('n2_v2_message_fixtures_shared: pinned text and every exact-key example', async () => {
  assert.match(fixture.$comment, /N1 and N2.*have not yet had their human security review/);
  for (const [path, digest] of Object.entries(fixture.contracts)) {
    const bytes = await readFile(new URL(`../${path}`, import.meta.url));
    assert.equal(createHash('sha256').update(bytes).digest('hex'), digest,
      `${path} changed: review fixture shapes against the new text before updating its digest`);
  }
  const text = await readFile(new URL('../docs/HOME_SHELL_HOST_CONTRACT.md', import.meta.url), 'utf8');
  const spans = {
    hello: ['exact keys are `type`,', '.\n`documentNonce`'],
    ready: ['with exactly `type`,', '. Generation'],
    effect: ['Exact keys: `type`,', '. Effect IDs'],
    result: ['11 keys: `type`,', '. `outcome:null`'],
    state: ['exact keys are type,', '. Normally'],
    navigation: ['keys `type,schema,requestId,documentNonce,ok,reason`', '. Successful'],
  };
  for (const [kind, [start, end]] of Object.entries(spans)) {
    const offset = text.indexOf(start, text.indexOf(`\`home:${wireTypes[kind]}\``, text.indexOf('### Injected wallet connector effects')));
    assert.ok(offset >= 0, `${kind} key declaration in the written contract`);
    const stop = text.indexOf(end, offset);
    assert.ok(stop > offset, `${kind} declaration end`);
    const declaration = text.slice(offset, stop);
    const keys = declaration.slice(declaration.indexOf('type')).replaceAll('`', '').replace(/\s/g, '').split(',');
    assert.deepEqual(keys.sort(), [...wireKeys[kind]].sort(), `${kind} exact keys come from the text`);
  }
  for (const [kind, type] of Object.entries(wireTypes)) {
    const instances = fixture.messages.filter((x) => x.message.type === `home:${type}`);
    assert.ok(instances.some((x) => x.valid), `${kind} valid instance`);
    assert.ok(instances.some((x) => !x.valid), `${kind} invalid instance`);
    for (const instance of instances.filter((x) => x.valid)) assert.deepEqual(Object.keys(instance.message).sort(), [...wireKeys[kind]].sort(), instance.id);
  }
  const snapshotStart = text.indexOf('Snapshot keys are exactly ');
  assert.ok(snapshotStart >= 0);
  const snapshotEnd = text.indexOf('. Empty facts', snapshotStart);
  assert.ok(snapshotEnd > snapshotStart);
  const snapshotKeys = [...text.slice(snapshotStart, snapshotEnd).matchAll(/`([^`]+)`/g)].flatMap((m) => m[1].split(','));
  assert.deepEqual([...nestedKeys.snapshot].sort(), snapshotKeys.sort(), 'Snapshot keys come from the written contract');
  for (const row of fixture.messages.filter((r) => r.valid && r.message.snapshot))
    assert.deepEqual(Object.keys(row.message.snapshot).sort(), [...snapshotKeys].sort(), row.id);
  for (const row of fixture.messages) {
    const decision = messageDecision(row.message);
    assert.equal(decision, row.receiver, row.id);
    assert.equal(decision === 'accept', row.valid, row.id);
  }
  assert.equal(new Set(fixture.messages.map((x) => x.id)).size, fixture.messages.length);
  assert.ok(fixture.messages.some((r) => !Object.values(wireTypes).some((type) => r.message.type === `home:${type}`)
    && r.receiver === 'ignore' && !r.valid), 'Unknown top-level type has an explicit invalid example');
});
test('stage, dispatch and outcome coverage uses the same packets', () => {
  for (const stage of fixture.stages) assert.ok(fixture.messages.some((x) => x.valid && x.message.stage === stage), stage);
  for (const outcome of fixture.outcomes) assert.ok(fixture.messages.some((x) => x.valid && x.message.outcome === outcome), outcome);
  for (const dispatch of fixture.dispatch) assert.ok(fixture.messages.some((x) => x.valid && x.message.dispatch === dispatch), dispatch);
  assert.equal(fixture.messages.find((x) => x.message.outcome === 'extensions_unavailable').producible, false);
});
test('n1 query rows include routes, selectors and near misses', () => {
  for (const row of fixture.n1Queries) assert.equal(queryValid(row), row.valid, row.id);
});
test('n4 wire identity additions have the specified actor, type and bound', () => {
  for (const row of fixture.n4IdentityFields) assert.equal(identityDecision(row), row.expect, row.id);
});
test('n7 private summaries keep site text within the allowed audience', () => {
  for (const row of fixture.n7PrivateSummaries) assert.equal(summarySiteDecision(row), row.expect, row.id);
});
test('nullable safety and each no-hash receipt use the current draft semantics', () => {
  for (const paymentPending of [true, false, null]) assert.ok(fixture.messages.some((row) => row.valid
    && row.message.snapshot?.paymentPending === paymentPending), `safety ${paymentPending}`);
  for (const result of ['declined', 'refused', 'failed']) for (const receipt of ['recorded', 'recording_failed']) {
    assert.ok(fixture.messages.some((row) => row.valid && row.message.settled?.result === result
      && row.message.settled.receipt === receipt), `${result}/${receipt}`);
  }
  assert.ok(fixture.messages.some((row) => row.valid && row.message.dispatch === 'unknown'
    && row.message.stage === 'verifying' && row.message.outcome === 'failed'));
});
test('old Home source provenance and unchanged six-key draft; joined compatibility remains gated', async () => {
  const p = fixture.oldHomeSource;
  assert.equal(p.tag, 'v2.0.1');
  assert.equal(p.tagObject, '97cb28d2aaeba72f799d18d7e9d1902955f92bd1');
  assert.equal(p.commit, 'bde18c7bae6564db934cd406c1070b32499473ec');
  assert.equal(p.path, 'capsules/home/browser/home-wallet-connector-host.js');
  assert.equal(p.fixturePath, 'scripts/fixtures/wallet-home-v2.0.1-host.js.txt');
  const source = await readFile(new URL(`../${p.fixturePath}`, import.meta.url));
  assert.equal(createHash('sha256').update(source).digest('hex'), p.sha256);
  assert.equal(p.productProof, false, 'Joined Runtime test remains with its owning lane after human review');
  for (const row of fixture.handoffs) {
    assert.equal(handoffValid(row.message), row.valid, row.id);
    if (row.valid) assert.equal(Object.keys(row.message).length, 6);
  }
  assert.ok(fixture.handoffs.some((row) => !row.valid && 'external_result_deadline_at' in row.message));
});
test('NB1 draft has exactly the proposed producers, operation data and acknowledgements', () => {
  assert.match(fixture.settlementProposal, /human security review/);
  assert.deepEqual(fixture.callSettlements.filter((row) => row.valid).map((row) => row.body.outcome).sort(),
    ['not_approved', 'not_authorized', 'unresolved']);
  for (const row of fixture.callSettlements) assert.equal(settlementValid(row), row.valid, row.id);
});
test('draft hash and signer fields reject arrays before operation correlation', () => {
  for (const key of ['payload_hash', 'signer']) {
    const row = structuredClone(fixture.callSettlements.find((row) => row.valid));
    row.body[key] = [row.body[key]];
    row.runtimeOperation.data[key] = row.body[key];
    assert.equal(settlementValid(row), false, key);
  }
});
test('selected-result reads preserve the existing route and canonical selector', () => {
  for (const row of fixture.selectedResultReads) assert.equal(selectedResultDecision(row), row.expect, row.id);
});
test('own close has no destination fields; only trusted delivery selects Accounts', () => {
  for (const row of fixture.n1CloseMessages) assert.equal(closeValid(row.message), row.valid, row.id);
  for (const connector of ['wallet-metamask', 'wallet-unisat', 'wallet-walletconnect']) {
    assert.ok(fixture.n1Queries.some((row) => row.source === connector && row.query.tab === 'accounts' && !row.valid));
  }
});
