import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { runInNewContext } from 'node:vm';
import { createHash } from 'node:crypto';
import { installScriptedExtension, replayInput, scenarios } from './wallet-extension-test/index.mjs';
import { finalCall } from './wallet-extension-test/recording-source.mjs';
import { importRecordings } from './wallet-extension-test/import-recordings.mjs';

function pageSurface() {
  const page = new EventTarget();
  page.CustomEvent = CustomEvent;
  return page;
}
const canon = (id) => id === 'metamask' ? 'io.metamask' : id;
test('every recorded-provider silent read has a scenario and an original reply', async () => {
  const { fixture } = await replayInput('metamask-silent-check');
  const methods = new Set(Object.values(scenarios).flatMap((s) => s.calls.map((plan) => {
    const call = finalCall(fixture.cases.find((c) => c.id === plan.id));
    return `${canon(call.target || call.kind)}:${call.method}`;
  })));
  for (const method of ['io.metamask:eth_accounts', 'io.metamask:eth_chainId',
    'unisat:getAccounts', 'unisat:getChain', 'unisat:getNetwork']) {
    assert.ok(methods.has(method), `Missing recorded silent read: ${method}`);
  }
});
function errorShape(error) {
  return { constructor: error.constructor.name, code: error.code, message: error.message,
    data: error.data ?? null, own_properties: Object.getOwnPropertyNames(error) };
}
function assertReply(actual, call) {
  assert.equal(actual.state, call.state);
  if (call.state === 'fulfilled') assert.deepEqual(actual.value, call.value);
  if (call.state === 'rejected') assert.deepEqual(actual.error, call.error);
}

for (const name of Object.keys(scenarios)) {
  test(`recording parity: ${name}`, async () => {
    const input = await replayInput(name);
    const page = pageSurface();
    const replay = installScriptedExtension(input, page);
    const announcements = [];
    const providers = new Map();
    const observedEvents = [];
    function listen(id, provider) {
      if (providers.has(id)) return;
      providers.set(id, provider);
      for (const event of ['connect', 'disconnect', 'accountsChanged', 'chainChanged', 'networkChanged']) {
        provider.on(event, (payload) => observedEvents.push({ provider: id, name: event, payload }));
      }
    }
    page.addEventListener('eip6963:announceProvider', ({ detail }) => {
      announcements.push(detail.info); listen(detail.info.rdns, detail.provider);
    });
    if (page.ethereum) listen(page.ethereum.isRabby ? 'legacy' : 'io.metamask', page.ethereum);
    if (page.unisat) listen('unisat', page.unisat);
    page.dispatchEvent(new Event('eip6963:requestProvider'));
    await replay.advance(1000);
    const discovery = input.fixture.cases.find((c) => c.id === input.spec.discovery).snapshots.find((s) => s.observation)?.observation || {};
    assert.deepEqual(announcements, (discovery.new_announcements || discovery.announcements || []).map((a) => a.info));
    if (discovery.ethereum?.isRabby) {
      assert.equal(page.ethereum.isMetaMask, true);
      for (const p of providers.values()) if (p !== page.ethereum) assert.notEqual(p, page.ethereum);
    }
    const outputs = new Map();
    for (const plan of input.spec.calls) {
      const entry = input.fixture.cases.find((c) => c.id === plan.id);
      const call = finalCall(entry);
      const id = canon(call.target || call.kind);
      const provider = providers.get(id);
      assert.ok(provider, `Provider for ${plan.id}`);
      outputs.set(plan.id, { state: 'pending' });
      const promise = id === 'unisat' ? provider[call.method](...call.params) : provider.request({ method: call.method, params: call.params });
      promise.then((value) => outputs.set(plan.id, { state: 'fulfilled', value }), (error) => outputs.set(plan.id, { state: 'rejected', error: errorShape(error) }));
    }
    replay.person('does nothing');
    // Even a day of virtual waiting cannot approve a prompt or settle an unanswered call.
    await replay.advance(86_400_000);
    for (const plan of input.spec.calls) if (plan.action) assert.equal(outputs.get(plan.id).state, 'pending');
    for (const event of input.spec.events) replay.person(event.action, event.id);
    for (const plan of input.spec.calls) {
      if (plan.unlock) {
        assert.throws(() => replay.person(plan.action, plan.id), /Unlock/);
        replay.person('unlocks', plan.id);
      }
      if (plan.action) replay.person(plan.action, plan.id);
      if (input.spec.calls.some((later) => later.after === plan.id)) await replay.advance(86_400_000);
    }
    await replay.advance(86_400_000);
    for (const plan of input.spec.calls) {
      const call = finalCall(input.fixture.cases.find((c) => c.id === plan.id));
      assertReply(outputs.get(plan.id), call);
    }
    const expectedEvents = [];
    // Check public callbacks too, independently of the replay's transcript.
    for (const event of input.spec.events) {
      const entry = input.fixture.cases.find((c) => c.id === event.id);
      for (const e of entry.snapshots.filter((s) => s.call).at(-1).events.slice(-event.last)) {
        expectedEvents.push({ provider: canon(e.provider), name: e.name, payload: e.payload });
      }
    }
    const callEvents = input.spec.calls.flatMap((plan) => {
      const s = input.fixture.cases.find((c) => c.id === plan.id).snapshots.filter((s) => s.call).at(-1);
      // Pending-only observations contain no promised future behavior.
      return s.call.state === 'pending' ? [] : (s.events || []).filter((e) => e.since_call_ms >= 0 && e.since_call_ms <= s.call.elapsed_ms)
        .map((e) => ({ ...e, action: Boolean(plan.action) }));
    }).sort((a, b) => Number(a.action) - Number(b.action) || a.since_call_ms - b.since_call_ms);
    for (const e of callEvents) expectedEvents.push({ provider: canon(e.provider), name: e.name, payload: e.payload });
    assert.deepEqual(observedEvents, expectedEvents.filter((e) => providers.has(e.provider)));
    for (const id of providers.keys()) {
      const p = providers.get(id);
      assert.throws(() => p.request({ method: 'unrecorded_rpc', params: [] }), /Unrecorded wallet call/);
    }
    replay.dispose();
    assert.equal(page.__walletReplay, undefined);
  });
}

test('page init function works without imported closures', async () => {
  const input = await replayInput('metamask-before-access');
  const page = pageSurface();
  runInNewContext(`(${installScriptedExtension.toString()})(input, page)`, { input, page, structuredClone });
  const promise = page.ethereum.request({ method: 'eth_accounts' });
  await page.__walletReplay.advance(100);
  assert.deepEqual(await promise, []);
  page.__walletReplay.dispose();
});

test('queued transaction answers keep the second prompt pending after the first hash', async () => {
  const input = await replayInput('metamask-transactions-queued');
  const page = pageSurface();
  const replay = installScriptedExtension(input, page);
  const providers = new Map();
  page.addEventListener('eip6963:announceProvider', ({ detail }) => providers.set(detail.info.rdns, detail.provider));
  page.dispatchEvent(new Event('eip6963:requestProvider'));
  await replay.advance(1000);
  const first = finalCall(input.fixture.cases.find((c) => c.id === 'R2-MM-queue-first'));
  const second = finalCall(input.fixture.cases.find((c) => c.id === 'R2-MM-queue-second'));
  const provider = providers.get('io.metamask');
  // The order of object keys changes no JSON value.
  const params = first.params.map((v) => Object.fromEntries(Object.entries(v).reverse()));
  let hash, error;
  provider.request({ method: first.method, params }).then((v) => hash = v);
  provider.request({ method: second.method, params: second.params }).catch((e) => error = e);
  assert.throws(() => replay.person('declines', 'R2-MM-queue-second'), /earlier queued/);
  replay.person('approves', 'R2-MM-queue-first');
  await replay.advance(first.elapsed_ms + 1);
  assert.equal(hash, first.value);
  assert.equal(error, undefined);
  assert.equal(replay.requests[1].state, 'pending');
  replay.person('declines', 'R2-MM-queue-second');
  await replay.advance(second.elapsed_ms + 1);
  assert.deepEqual(errorShape(error), second.error);
  replay.dispose();
});

test('UniSat second approval settles only its own call; the first stays pending', async () => {
  const input = await replayInput('unisat-two-calls');
  const page = pageSurface();
  const replay = installScriptedExtension(input, page);
  let first = 'pending', second = 'pending';
  page.unisat.requestAccounts().then((v) => first = v);
  page.unisat.requestAccounts().then((v) => second = v);
  replay.person('approves', 'US-10-repeat-second');
  await replay.advance(120_000);
  assert.equal(first, 'pending');
  assert.deepEqual(second, finalCall(input.fixture.cases.find((c) => c.id === 'US-10-repeat-second')).value);
  assert.equal(replay.requests[0].state, 'pending');
  replay.dispose();
});

test('native close and side-panel close retain their distinct recorded results', async () => {
  const input = await replayInput('metamask-side-panel-close');
  const page = pageSurface();
  const replay = installScriptedExtension(input, page);
  let provider;
  page.addEventListener('eip6963:announceProvider', ({ detail }) => { if (detail.info.rdns === 'io.metamask') provider = detail.provider; });
  page.dispatchEvent(new Event('eip6963:requestProvider'));
  await replay.advance(1000);
  const expected = finalCall(input.fixture.cases.find((c) => c.id === 'R2-MM-native-connect-close'));
  let answer = 'pending';
  provider.request({ method: expected.method, params: expected.params }).then((v) => answer = v);
  replay.person('closes side panel');
  await replay.advance(100_000);
  assert.equal(answer, 'pending');
  replay.person('approves');
  await replay.advance(expected.elapsed_ms + 1);
  assert.deepEqual(answer, expected.value);
  replay.dispose();
});

test('real_transaction_hash_and_late_receipt_recording: three independent receipts', async () => {
  const { fixture } = await replayInput('metamask-transaction-receipt');
  for (const [send, receipt, independent] of [
    ['R2-MM-send-after-reconnect', 'R2-MM-receipt-confirm', 'R2-MM-independent-confirm'],
    ['R2-MM-send-late75', 'R2-MM-receipt-late75', 'R2-MM-independent-late75'],
    ['R2-MM-queue-first', 'R2-MM-receipt-queue-first', 'R2-MM-independent-queue'],
  ]) {
    const get = (id) => fixture.cases.find((c) => c.id === id);
    const hash = finalCall(get(send)).value;
    const r = finalCall(get(receipt));
    assert.equal(r.params[0], hash);
    assert.equal(r.value.transactionHash, hash);
    assert.equal(r.value.status, '0x1');
    assert.deepEqual(r.value, get(independent).snapshots[0].observation.receipt);
  }
  const late = finalCall(fixture.cases.find((c) => c.id === 'R2-MM-send-late75'));
  assert.ok(late.elapsed_ms > 100_000);
});

async function runMutant(name, mutate) {
  const original = await replayInput(name);
  const input = structuredClone(original);
  mutate(input);
  input.spec.calls = [input.spec.calls.at(-1)];
  const page = pageSurface();
  const replay = installScriptedExtension(input, page);
  const plan = input.spec.calls.at(-1);
  const expectedEntry = original.fixture.cases.find((c) => c.id === plan.id);
  const expected = finalCall(expectedEntry);
  const observedEvents = [];
  const provider = page.unisat;
  for (const name of ['accountsChanged', 'networkChanged']) provider.on(name, (payload) => observedEvents.push({ name, payload }));
  let actual = { state: 'pending' };
  provider[expected.method](...expected.params).then((value) => actual = { state: 'fulfilled', value },
    (error) => actual = { state: 'rejected', error: errorShape(error) });
  if (plan.unlock) replay.person('unlocks', plan.id);
  replay.person(plan.action, plan.id);
  await replay.advance(1_000_000);
  try {
    assertReply(actual, expected);
    assert.deepEqual(observedEvents, expectedEntry.snapshots.at(-1).events
      .filter((e) => e.since_call_ms >= 0 && e.since_call_ms <= expected.elapsed_ms).map(({ name, payload }) => ({ name, payload })));
  } finally { replay.dispose(); }
}

test('parity check fails on a replay with a changed reply; passes on the original', async () => {
  await assert.rejects(runMutant('unisat-locked-connect', (input) => {
    finalCall(input.fixture.cases.find((c) => c.id === 'R2-US-locked-connect-clean')).value = [];
  }), assert.AssertionError);
  await runMutant('unisat-locked-connect', () => {});
});
test('parity check fails on a replay with a changed error shape; passes on the original', async () => {
  await assert.rejects(runMutant('unisat-connect-declined', (input) => {
    finalCall(input.fixture.cases.find((c) => c.id === 'US-10-reject')).error.own_properties.push('data');
  }), assert.AssertionError);
  await runMutant('unisat-connect-declined', () => {});
});
test('parity check fails on a replay with swapped event payloads; passes on the original', async () => {
  await assert.rejects(runMutant('unisat-locked-connect', (input) => {
    const events = input.fixture.cases.find((c) => c.id === 'R2-US-locked-connect-clean').snapshots.at(-1).events;
    // Keep clocks, swap the observed payload order.
    [events[0].name, events[1].name] = [events[1].name, events[0].name];
    [events[0].payload, events[1].payload] = [events[1].payload, events[0].payload];
  }), assert.AssertionError);
  await runMutant('unisat-locked-connect', () => {});
});

test('original 160-case raw file matches every imported excerpt and pinned digest', { skip: !process.env.WALLET_EXTENSION_RAW }, async () => {
  const bytes = await readFile(process.env.WALLET_EXTENSION_RAW);
  const { fixture } = await replayInput('metamask-before-access');
  assert.equal(createHash('sha256').update(bytes).digest('hex'), fixture.source.sha256);
  assert.deepEqual(importRecordings(bytes), fixture);
  const raw = JSON.parse(bytes);
  assert.equal(raw.cases.length, 160);
  // Compare all response values, error shapes and event histories directly to raw input.
  for (const c of fixture.cases) {
    const source = raw.cases.find((r) => r.id === c.id);
    assert.deepEqual(c.snapshots.map((s) => s.call), source.snapshots.map((s) => s.call));
    assert.deepEqual(c.snapshots.map((s) => s.events), source.snapshots.map((s) => s.events));
  }
});
