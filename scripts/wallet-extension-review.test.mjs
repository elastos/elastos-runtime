import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, writeFile, cp, mkdtemp, rm, mkdir, lstat, realpath } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { spawnSync } from 'node:child_process';
import { installScriptedExtension, replayInput } from './wallet-extension-test/index.mjs';
import { finalCall, validateScenarios } from './wallet-extension-test/recording-source.mjs';
import { importRecordings } from './wallet-extension-test/import-recordings.mjs';

const fixtureUrl = new URL('./fixtures/wallet-extension-replay.json', import.meta.url);
for (const mutation of ['error-code', 'pending-answer', 'swapped-errors', 'decline-approval', 'whitespace']) {
  test(`F1 default run rejects file mutation: ${mutation}`, async (t) => {
    const scratch = await mkdtemp(join(await realpath(tmpdir()), 'wallet-review-'));
    const identity = await lstat(scratch);
    try {
      await mkdir(join(scratch, 'scripts/fixtures'), { recursive: true });
      await cp(new URL('./wallet-extension-test/', import.meta.url), join(scratch, 'scripts/wallet-extension-test'), { recursive: true });
      await cp(new URL('./wallet-extension-replay.test.mjs', import.meta.url), join(scratch, 'scripts/wallet-extension-replay.test.mjs'));
      const fixture = JSON.parse(await readFile(fixtureUrl, 'utf8'));
      const get = (id) => finalCall(fixture.cases.find((c) => c.id === id));
      if (mutation === 'error-code') get('MM-4-second-connect').error.code = 4001;
      if (mutation === 'pending-answer') Object.assign(get('R2-DISABLED-old-mm-request'), { state: 'fulfilled', value: [], elapsed_ms: 300 });
      if (mutation === 'swapped-errors') {
        const a = get('MM-2-reject'), b = get('MM-5-sign-reject');
        [a.error, b.error] = [b.error, a.error];
      }
      if (mutation === 'decline-approval') {
        const path = join(scratch, 'scripts/wallet-extension-test/scenarios.mjs');
        await writeFile(path, (await readFile(path, 'utf8')).replace("call('MM-2-reject', 'declines')", "call('MM-2-ignore', 'declines')"));
      }
      await writeFile(join(scratch, 'scripts/fixtures/wallet-extension-replay.json'), `${JSON.stringify(fixture, null, 2)}\n${mutation === 'whitespace' ? '\n' : ''}`);
      const env = { ...process.env }; delete env.WALLET_EXTENSION_RAW; delete env.NODE_TEST_CONTEXT;
      const run = spawnSync(process.execPath, ['--test', 'scripts/wallet-extension-replay.test.mjs'], { cwd: scratch, env, encoding: 'utf8', timeout: 30000 });
      assert.equal(run.error, undefined);
      assert.match(run.stdout + run.stderr, /recording parity:/, 'Child must execute the default tests');
      assert.equal(run.status, 1, `${mutation} escaped the default run`);
      const expected = mutation === 'decline-approval' ? /Scenario mapping integrity failure/ : /Replay fixture integrity failure/;
      assert.match(run.stdout + run.stderr, expected, 'Independent pin must detect the mutation');
      t.diagnostic(`${mutation}: mutated default run exits ${run.status}; independent pin rejects it`);
    } finally {
      for (let path = scratch; ; path = dirname(path)) {
        const stat = await lstat(path); assert.equal(stat.isSymbolicLink(), false);
        if (path === dirname(path)) break;
      }
      const current = await lstat(scratch);
      assert.equal(current.dev, identity.dev); assert.equal(current.ino, identity.ino);
      await rm(scratch, { recursive: true, force: true });
    }
  });
}

test('F2 UniSat account action emits the account read after the switch', async () => {
  const input = await replayInput('unisat-switch-account');
  const page = new EventTarget(); page.CustomEvent = CustomEvent;
  const replay = installScriptedExtension(input, page);
  const values = []; page.unisat.on('accountsChanged', (v) => values.push(v));
  replay.person('switches account');
  assert.deepEqual(values.at(-1), finalCall(input.fixture.cases.find((c) => c.id === 'US-12-after-switch-accounts')).value);
  replay.assertNoViolations();
  replay.dispose();
});

test('F3 caught provider exceptions leave a visible violation', async () => {
  const input = await replayInput('unisat-before-access');
  const page = new EventTarget(); page.CustomEvent = CustomEvent;
  const replay = installScriptedExtension(input, page);
  try { page.unisat.getChain(); } catch { /* Product code may catch this. */ }
  assert.ok(replay.violations?.length > 0);
  assert.throws(() => replay.assertNoViolations(), /violations/);
  replay.dispose();
});

for (const [name, scenario, call] of [
  ['missing EVM argument', 'metamask-before-access', (provider) => provider.request()],
  ['null EVM argument', 'metamask-before-access', (provider) => provider.request(null)],
  ['symbol EVM method', 'metamask-before-access', (provider) => provider.request({ method: Symbol('invalid') })],
  ['unserializable EVM parameters', 'metamask-before-access', (provider) => provider.request({ method: 'eth_accounts', params: [1n] })],
  ['unserializable UniSat parameters', 'unisat-before-access', (provider) => provider.getAccounts(1n)],
]) {
  test(`F3 public entry records ${name} before product code catches it`, async () => {
    const input = await replayInput(scenario);
    const page = new EventTarget(); page.CustomEvent = CustomEvent;
    const replay = installScriptedExtension(input, page);
    let provider = page.unisat;
    if (!provider) {
      page.addEventListener('eip6963:announceProvider', ({ detail }) => provider = detail.provider);
      page.dispatchEvent(new Event('eip6963:requestProvider')); await replay.advance(1000);
    }
    try { call(provider); } catch { /* Product code may catch an entry error too. */ }
    assert.equal(replay.violations.length, 1);
    assert.throws(() => replay.assertNoViolations(), /violations/);
    replay.dispose();
  });
}

test('F4 UniSat has no EIP-1193 request member', async () => {
  const input = await replayInput('unisat-before-access');
  const page = new EventTarget(); page.CustomEvent = CustomEvent;
  const replay = installScriptedExtension(input, page);
  assert.equal('request' in page.unisat, false);
  const inventory = input.fixture.surfaces.unisat;
  assert.deepEqual(Object.keys(page.unisat).sort(), [...inventory.keys].sort());
  const descriptors = Object.getOwnPropertyDescriptors(page.unisat);
  assert.deepEqual(Object.keys(descriptors).filter((key) => typeof descriptors[key].value === 'function').sort(), [...inventory.methods].sort());
  replay.assertNoViolations();
  replay.dispose();
});

for (const mutation of ['extra', 'missing', 'wrong-method-type']) {
  test(`F4 surface check catches ${mutation} member`, async () => {
    const input = await replayInput('unisat-before-access');
    const page = new EventTarget(); page.CustomEvent = CustomEvent;
    const replay = installScriptedExtension(input, page);
    if (mutation === 'extra') page.unisat.request = () => {};
    if (mutation === 'missing') delete page.unisat.getAccounts;
    if (mutation === 'wrong-method-type') page.unisat.getAccounts = undefined;
    assert.throws(() => replay.assertNoViolations(), /differ from recording/);
    replay.dispose();
  });
}

test('N9 every scenario action is checked against its raw outcome and selected event', async () => {
  const { fixture } = await replayInput('unisat-switch-account');
  const { scenarios } = await import('./wallet-extension-test/scenarios.mjs');
  validateScenarios(fixture, scenarios);
  const wrong = structuredClone(scenarios);
  wrong['unisat-switch-account'].events[0].indices = [7];
  assert.throws(() => validateScenarios(fixture, wrong), /action event differs/);
  const approval = structuredClone(scenarios);
  approval['metamask-connect-declined'].calls[0].id = 'MM-2-ignore';
  assert.throws(() => validateScenarios(fixture, approval), /decline\/close must reject/);
});

test('N1 legacy events reach window.ethereum and retain their recorded payload', async () => {
  const input = await replayInput('rabby-legacy-chooser');
  const page = new EventTarget(); page.CustomEvent = CustomEvent;
  const replay = installScriptedExtension(input, page);
  const events = []; page.ethereum.on('accountsChanged', (value) => events.push(value));
  const call = finalCall(input.fixture.cases.find((c) => c.id === 'R2-BOTH-legacy-fresh-events'));
  page.ethereum.request({ method: call.method, params: call.params });
  replay.person('approves'); await replay.advance(call.elapsed_ms + 1);
  assert.deepEqual(events, [call.value]);
  replay.assertNoViolations(); replay.dispose();
});

test('N1 importer rejects an unmapped provider', async () => {
  const { fixture } = await replayInput('unisat-before-access');
  const raw = { ...fixture, provenance: { product_commit: '', extensions: [] }, round2: { extensions: [] } };
  raw.cases[0].snapshots[0].events = [{ provider: 'unmapped-wallet', name: 'accountsChanged', payload: [] }];
  assert.throws(() => importRecordings(Buffer.from(JSON.stringify(raw))), /Unmapped recorded provider/);
});

test('N2 second connect cannot report busy after the first connect answered', async () => {
  const input = await replayInput('metamask-second-connect');
  const page = new EventTarget(); page.CustomEvent = CustomEvent;
  const replay = installScriptedExtension(input, page);
  let provider; page.addEventListener('eip6963:announceProvider', ({ detail }) => provider = detail.provider);
  page.dispatchEvent(new Event('eip6963:requestProvider')); await replay.advance(1000);
  const first = finalCall(input.fixture.cases.find((c) => c.id === 'MM-2-ignore'));
  provider.request({ method: first.method, params: first.params });
  replay.person('approves'); await replay.advance(first.elapsed_ms + 1);
  assert.throws(() => provider.request({ method: first.method, params: first.params }), /must still be pending/);
  assert.equal(replay.violations.length, 1);
  replay.dispose();
});

test('N4 round-1 legacy flags and announced-object identity stay unclaimed', async () => {
  const input = await replayInput('metamask-before-access');
  const page = new EventTarget(); page.CustomEvent = CustomEvent;
  const replay = installScriptedExtension(input, page);
  assert.equal(Object.hasOwn(page.ethereum, 'isMetaMask'), false);
  let provider; page.addEventListener('eip6963:announceProvider', ({ detail }) => provider = detail.provider);
  page.dispatchEvent(new Event('eip6963:requestProvider')); await replay.advance(1000);
  assert.equal(Object.hasOwn(provider, 'isMetaMask'), false);
  replay.assertNoViolations(); replay.dispose();
});
