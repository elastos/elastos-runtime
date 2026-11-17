import test from 'node:test';
import assert from 'node:assert/strict';
import { installScriptedExtension, replayInput } from './wallet-extension-test/index.mjs';
import { readFile } from 'node:fs/promises';
import { recordedActionPins, validateScenarios } from './wallet-extension-test/recording-source.mjs';
import { scenarios } from './wallet-extension-test/scenarios.mjs';
import { messageDecision } from './wallet-extension-test/message-contract.mjs';
import { importRecordings } from './wallet-extension-test/import-recordings.mjs';

async function setup(scenario, id) {
  const input = await replayInput(scenario);
  const page = new EventTarget(); page.CustomEvent = CustomEvent;
  const replay = installScriptedExtension(input, page);
  let provider = id === 'legacy' ? page.ethereum : id === 'unisat' ? page.unisat : null;
  page.addEventListener('eip6963:announceProvider', ({ detail }) => { if (detail.info.rdns === id) provider = detail.provider; });
  page.dispatchEvent(new Event('eip6963:requestProvider')); await replay.advance(1000);
  return { input, replay, provider };
}

for (const [id, scenario, member] of [
  ['legacy', 'rabby-legacy-chooser', 'enable'],
  ['legacy', 'rabby-legacy-chooser', 'send'],
  ['unisat', 'unisat-before-access', '_request'],
  ['io.metamask', 'metamask-before-access', 'enable'],
  ['io.metamask', 'metamask-before-access', 'isConnected'],
  ['io.metamask', 'metamask-before-access', 'once'],
]) {
  test(`F3 residual: caught ${id}.${member} call leaves a violation`, async () => {
    const { replay, provider } = await setup(scenario, id);
    try { provider[member](); } catch { /* Same catch as product code. */ }
    assert.equal(replay.violations.length, 1);
    assert.throws(() => replay.assertNoViolations(), /violations/);
    replay.dispose();
  });
}

test('F3 residual: legacy isConnected returns its recorded true value', async () => {
  const { input, replay, provider } = await setup('rabby-legacy-chooser', 'legacy');
  const observation = input.fixture.cases.find((c) => c.id === 'R2-BOTH-legacy-shape').snapshots.find((s) => s.observation).observation;
  assert.equal(provider.isConnected(), observation.isConnected);
  assert.equal(observation.isConnected, true);
  replay.assertNoViolations(); replay.dispose();
});

for (const [id, scenario, member] of [
  ['legacy', 'rabby-legacy-chooser', '_state'],
  ['unisat', 'unisat-before-access', '_request'],
  ['io.rabby', 'metamask-and-rabby', 'enable'],
  ['unisat', 'unisat-before-access', 'getBalance'],
  ['unisat', 'unisat-before-access', 'initialize'],
]) {
  test(`F3 residual: unsupported ${id}.${member} read leaves a violation`, async () => {
    const { replay, provider } = await setup(scenario, id);
    try { void provider[member]; } catch { /* Product may catch the read itself. */ }
    assert.equal(replay.violations.length, 1);
    assert.throws(() => replay.assertNoViolations(), /violations/);
    replay.dispose();
  });
}

for (const [id, scenario] of [['legacy', 'rabby-legacy-chooser'], ['unisat', 'unisat-before-access'], ['io.metamask', 'metamask-before-access'], ['io.rabby', 'metamask-and-rabby']]) {
  for (const operation of ['on', 'removeListener']) test(`${operation === 'on' ? 'N-e: invalid subscription' : 'F3 residual: unrecorded unsubscribe'} ${id} leaves a violation`, async () => {
    const { replay, provider } = await setup(scenario, id);
    try { provider[operation]('accountsChanged', operation === 'on' ? null : () => {}); } catch {}
    assert.equal(replay.violations.length, 1);
    assert.throws(() => replay.assertNoViolations(), /violations/);
    replay.dispose();
  });
}

test('F3 residual: descriptors inspect recorded names without using unknown members', async () => {
  const { input, replay, provider } = await setup('unisat-before-access', 'unisat');
  const descriptors = Object.getOwnPropertyDescriptors(provider);
  assert.deepEqual(Object.keys(provider).sort(), [...input.fixture.surfaces.unisat.keys].sort());
  assert.equal(typeof descriptors._request.get, 'function');
  assert.equal('_request' in provider, true, 'The recorded inventory proves presence, without a reply');
  assert.equal('getAccounts' in provider, true);
  replay.assertNoViolations();
  assert.equal(await Promise.resolve(provider), provider);
  replay.assertNoViolations(); replay.dispose();
});

test('F3 residual: replacing an unknown getter with undefined fails the surface check', async () => {
  const { replay, provider } = await setup('unisat-before-access', 'unisat');
  Object.defineProperty(provider, '_request', { value: undefined });
  assert.throws(() => replay.assertNoViolations(), /descriptors differ/);
  replay.dispose();
});

for (const mutation of ['approval-value', 'approval-phase', 'unlock-phase']) {
  test(`N-c: recorded action evidence rejects ${mutation}`, async () => {
    const { fixture } = await replayInput('metamask-connect-late');
    const pin = JSON.parse(await readFile(new URL('./wallet-extension-test/recording-pin.json', import.meta.url)));
    const entry = fixture.cases.find((c) => c.id === (mutation === 'unlock-phase' ? 'US-12-locked-sign-repeat' : 'MM-2-ignore'));
    if (mutation === 'approval-value') entry.snapshots.at(-1).call.value = [];
    if (mutation === 'approval-phase') entry.snapshots.at(-1).phase = 'not approved';
    if (mutation === 'unlock-phase') entry.snapshots.at(-1).phase = 'unlock unavailable; no unlock occurred';
    assert.throws(() => validateScenarios(fixture, scenarios, pin.actions), /recorded action evidence/);
  });
}

test('N-f: UUID format follows the version-neutral contract', async () => {
  const fixture = JSON.parse(await readFile(new URL('./fixtures/wallet-connector-v2-messages.json', import.meta.url)));
  for (const type of ['home:wallet-connector-hello', 'home:open-target-result']) {
    const message = structuredClone(fixture.messages.find((row) => row.valid && row.message.type === type).message);
    message.documentNonce = '01890f18-c312-7e26-8d6c-111111111111';
    if (type === 'home:open-target-result') message.requestId = message.documentNonce;
    assert.equal(messageDecision(message), 'accept');
    message.documentNonce = 'not-a-uuid';
    assert.notEqual(messageDecision(message), 'accept');
  }
});

test('R3 importer refuses an unlock plan with no recorded unlock evidence', async () => {
  const { fixture } = await replayInput('metamask-sign-approved');
  const raw = { cases: fixture.cases, provenance: { product_commit: fixture.source.productCommit,
    extensions: fixture.source.extensions }, round2: { extensions: [] } };
  const plan = scenarios['metamask-sign-approved'].calls[0], original = plan.unlock;
  try {
    plan.unlock = true;
    assert.throws(() => importRecordings(Buffer.from(JSON.stringify(raw))), /unlock evidence missing/);
  } finally { plan.unlock = original; }
});

for (const phase of [undefined, 'unlock unavailable; no unlock occurred']) {
  test(`R3 validation refuses re-pinned unlock with phase ${phase}`, async () => {
    const { fixture } = await replayInput('unisat-sign-late');
    const entry = fixture.cases.find((c) => c.id === 'US-12-locked-sign-repeat');
    for (const snapshot of entry.snapshots) snapshot.phase = phase;
    const pins = recordedActionPins(fixture.cases, scenarios);
    assert.throws(() => validateScenarios(fixture, scenarios, pins), /unlock evidence missing/);
  });
}

for (const [id, scenario, member, operation] of [
  ['io.metamask', 'metamask-before-access', 'enable', 'in'],
  ['unisat', 'unisat-before-access', 'request', 'in'],
  ['legacy', 'rabby-legacy-chooser', 'chainId', 'set'],
  ['unisat', 'unisat-before-access', '_request', 'set'],
  ['io.metamask', 'metamask-before-access', 'enable', 'set'],
]) {
  test(`R3 caught ${id}.${member} ${operation} leaves a violation`, async () => {
    const { replay, provider } = await setup(scenario, id);
    try {
      if (operation === 'in') void (member in provider);
      else provider[member] = '0x1';
    } catch { /* Product catches leave the control evidence intact. */ }
    assert.equal(replay.violations.length, 1);
    assert.throws(() => replay.assertNoViolations(), /violations/);
    replay.dispose();
  });
}

for (const [id, scenario] of [['legacy', 'rabby-legacy-chooser'], ['unisat', 'unisat-before-access']]) {
  test(`R3 surface check catches non-enumerable ${id} member`, async () => {
    const { replay, provider } = await setup(scenario, id);
    Object.defineProperty(provider, 'extraHiddenMember', { value: true });
    assert.throws(() => replay.assertNoViolations(), /own keys differ/);
    replay.dispose();
  });
}
