import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { messageDecision, queryValid, identityDecision, summarySiteDecision, wireKeys, wireTypes } from './wallet-extension-test/message-contract.mjs';

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
    state: ['exact keys are `type`,', '. Normally'],
    navigation: ['keys `type,schema,requestId,documentNonce,ok,reason`', '. Successful'],
  };
  for (const [kind, [start, end]] of Object.entries(spans)) {
    const offset = text.indexOf(start, text.indexOf(`\`home:${wireTypes[kind]}\``, text.indexOf('### Injected wallet connector effects')));
    assert.ok(offset >= 0, `${kind} key declaration in the written contract`);
    const stop = text.indexOf(end, offset);
    assert.ok(stop > offset, `${kind} declaration end`);
    const keys = [...text.slice(offset, stop).matchAll(/`([^`]+)`/g)].flatMap((m) => m[1].split(','));
    assert.deepEqual(keys.sort(), [...wireKeys[kind]].sort(), `${kind} exact keys come from the text`);
  }
  for (const [kind, type] of Object.entries(wireTypes)) {
    const instances = fixture.messages.filter((x) => x.message.type === `home:${type}`);
    assert.ok(instances.some((x) => x.valid), `${kind} valid instance`);
    assert.ok(instances.some((x) => !x.valid), `${kind} invalid instance`);
    for (const instance of instances.filter((x) => x.valid)) assert.deepEqual(Object.keys(instance.message).sort(), [...wireKeys[kind]].sort(), instance.id);
  }
  for (const row of fixture.messages) {
    const decision = messageDecision(row.message);
    assert.equal(decision, row.receiver, row.id);
    assert.equal(decision === 'accept', row.valid, row.id);
  }
  assert.equal(new Set(fixture.messages.map((x) => x.id)).size, fixture.messages.length);
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
