import test from 'node:test';
import assert from 'node:assert/strict';
import { installScriptedExtension, replayInput } from './wallet-extension-test/index.mjs';

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
  for (const operation of ['on', 'removeListener']) test(`N-e: invalid ${id}.${operation} listener leaves a violation`, async () => {
    const { replay, provider } = await setup(scenario, id);
    try { provider[operation]('accountsChanged', null); } catch {}
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
