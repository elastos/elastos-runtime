import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';
import { spawnSync } from 'node:child_process';

if (!vm.SourceTextModule) {
  test('passive wallet event host checks', () => {
    const result = spawnSync(process.execPath, ['--experimental-vm-modules', '--test', import.meta.filename], { encoding: 'utf8', timeout: 20000 });
    assert.equal(result.status, 0, result.stdout + result.stderr);
  });
}

// Load the complete host module; replace only its network dependency.
async function hostFixture(kind) {
  const listeners = new Map(), messages = [], calls = [], windowListeners = new Map();
  const provider = { on(name, callback) { listeners.set(name, callback); },
    request(call) { calls.push(call); return new Promise(() => {}); },
    requestAccounts() { calls.push('requestAccounts'); return new Promise(() => {}); },
    getAccounts() {}, getNetwork() {}, signMessage() {} };
  const source = await readFile(new URL('../capsules/home/browser/home-wallet-connector-host.js', import.meta.url), 'utf8');
  const window = { unisat: provider,
    addEventListener(name, callback) { windowListeners.set(name, callback); }, dispatchEvent() {} };
  const context = vm.createContext({ window, Event, Set, Map, WeakSet, Number, Object });
  const module = new vm.SourceTextModule(source, { context });
  await module.link(async () => {
    const dependency = new vm.SyntheticModule(['fetchJson'], function () {
      this.setExport('fetchJson', () => { throw Error('unexpected Runtime call'); });
    }, { context });
    return dependency;
  });
  await module.evaluate();
  windowListeners.get('eip6963:announceProvider')({ detail: { info: { rdns: 'io.metamask', uuid: 'test' }, provider } });
  const connectorId = `wallet-${kind}`;
  const frame = { postMessage(data) { messages.push(data); } };
  const lifetime = { retired: false, generation: 'document-1' };
  const admitted = { kind: 'app-frame', targetId: connectorId, homeToken: 'test-token', source: frame,
    clipboardState: lifetime, walletEffectState: { inFlight: false, requestIds: new Set() } };
  const data = { type: 'home:wallet-connector-effect', schema: 'elastos.home.wallet-connector-effect/v1',
    requestId: 'test:1', connectorId, connectorToken: 'test-token', action: { kind: 'link' } };
  const invoke = (sender = frame, ctx = admitted, packet = data) => module.namespace.handleHomeWalletConnectorEffect({ source: sender }, ctx, packet);
  return { listeners, messages, calls, frame, admitted, data, invoke, lifetime };
}

if (vm.SourceTextModule) for (const kind of ['metamask', 'unisat']) {
  test(`${kind}: only admitted recipient gets passive bounded notifications; no provider calls from events`, async () => {
    const f = await hostFixture(kind);
    f.invoke();
    assert.equal(f.calls.length, 1);
    const address = kind === 'metamask' ? '0x' + '1'.repeat(40) : 'bc1q' + 'a'.repeat(38);
    const before = f.calls.length;
    f.listeners.get('accountsChanged')([address]);
    assert.equal(f.messages.length, 1);
    assert.deepEqual(JSON.parse(JSON.stringify(f.messages[0])), { type: 'home:wallet-connector-event', connectorId: `wallet-${kind}`, event: 'accountsChanged', value: [address] });
    for (const bad of [[address.repeat(100)], Array(9).fill(address), [null], 'address', ['<script>']]) f.listeners.get('accountsChanged')(bad);
    assert.equal(f.messages.length, 1);
    const network = kind === 'metamask' ? 'chainChanged' : 'networkChanged';
    f.listeners.get(network)(kind === 'metamask' ? '0x1' : 'livenet');
    f.listeners.get(network)('x'.repeat(10000));
    f.listeners.get(network)({ secret: 'discard' });
    assert.equal(f.messages.length, 2);
    f.listeners.get('disconnect')({ secret: 'discard' });
    assert.equal(f.messages.at(-1).value, null);
    assert.equal(f.calls.length, before);
    f.lifetime.retired = true;
    f.listeners.get('accountsChanged')([]);
    assert.equal(f.messages.length, 3);
  });
  test(`${kind}: another frame cannot register, receive or trigger events`, async () => {
    const f = await hostFixture(kind);
    const foreign = [];
    const other = { postMessage(packet) { foreign.push(packet); } };
    f.invoke(other, { ...f.admitted, targetId: 'notes' });
    assert.equal(f.calls.length, 0);
    f.invoke();
    f.invoke(other, { ...f.admitted, targetId: 'notes' }, { type: 'home:wallet-connector-event', event: 'accountsChanged', value: [] });
    f.listeners.get('accountsChanged')([]);
    assert.equal(f.messages.filter(x => x.type === 'home:wallet-connector-event').length, 1);
    assert.equal(foreign.filter(x => x.type === 'home:wallet-connector-event').length, 0);
    f.lifetime.generation = 'new-document';
    f.listeners.get('accountsChanged')([]);
    assert.equal(f.messages.filter(x => x.type === 'home:wallet-connector-event').length, 1);
  });
  test(`${kind}: old window can ignore extra notifications; missing lifetime leaves v1 effects usable`, async () => {
    const f = await hostFixture(kind);
    f.invoke(f.frame, { ...f.admitted, clipboardState: undefined });
    assert.equal(f.calls.length, 1);
    f.listeners.get('accountsChanged')([]);
    assert.equal(f.messages.length, 0);
  });
}

if (vm.SourceTextModule) for (const kind of ['metamask', 'unisat']) test(`${kind}: a different source with the same connector cannot subscribe`, async () => {
  const f = await hostFixture(kind), foreign = [];
  f.invoke({postMessage(data){foreign.push(data);}});
  f.listeners.get('accountsChanged')([]);
  assert.equal(f.messages.filter(x=>x.type==='home:wallet-connector-event').length,0);
  assert.equal(foreign.filter(x=>x.type==='home:wallet-connector-event').length,0);
});
