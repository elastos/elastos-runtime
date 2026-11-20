import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';
import { spawnSync } from 'node:child_process';

if (!vm.SourceTextModule) {
  test('passive wallet event host checks', t => {
    const env = { ...process.env }; delete env.NODE_TEST_CONTEXT;
    const result = spawnSync(process.execPath, ['--experimental-vm-modules', '--test-reporter=tap', '--test', import.meta.filename], { env, encoding: 'utf8', timeout: 20000 });
    assert.equal(result.error, undefined);
    assert.match(result.stdout, /# tests 10/, 'child must execute every host test');
    assert.match(result.stdout, /# fail 0/);
    assert.equal(result.status, 0, result.stdout + result.stderr);
    t.diagnostic('Child executed 10 host tests: 10 passed, 0 failed, 0 skipped.');
  });
}

// Load the complete host module; replace only its network dependency.
async function hostFixture(kind, mutate = s => s) {
  const listeners = new Map(), messages = [], calls = [], windowListeners = new Map();
  const provider = { on(name, callback) { listeners.set(name, callback); },
    request(call) { calls.push(call); return new Promise(() => {}); },
    requestAccounts() { calls.push('requestAccounts'); return new Promise(() => {}); },
    getAccounts() { calls.push('getAccounts'); }, getNetwork() { calls.push('getNetwork'); }, signMessage() { calls.push('signMessage'); } };
  const source = await readFile(new URL('../capsules/home/browser/home-wallet-connector-host.js', import.meta.url), 'utf8');
  const window = { unisat: provider,
    addEventListener(name, callback) { windowListeners.set(name, callback); }, dispatchEvent() {} };
  const context = vm.createContext({ window, Event, Set, Map, WeakSet, Number, Object });
  const module = new vm.SourceTextModule(mutate(source), { context });
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
    if (kind === 'metamask') f.listeners.get(network)('0x' + '1'.repeat(17));
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

if (vm.SourceTextModule) for (const kind of ['metamask','unisat']) test(`${kind}: review forwarder breaks K04 K05 K06 K13 K15 fail the guard`, async t => {
  for (const [id, mutate, check] of [
    ['K04',s=>s.replace('if (recipient.lifetime.retired || recipient.lifetime.generation !== recipient.generation','if (false'), async f=>{f.invoke();f.lifetime.retired=true;f.listeners.get('accountsChanged')([]);assert.equal(f.messages.length,0);}],
    ['K05',s=>s.replace('event.source !== context.source','false'), async f=>{const foreign=[];f.invoke({postMessage(packet){foreign.push(packet);}});f.listeners.get('accountsChanged')([]);assert.equal(foreign.length,0);}],
    ['K06',s=>s.replace('value.length > 8','value.length > 800'), async f=>{f.invoke();f.listeners.get('accountsChanged')(Array(9).fill(kind==='metamask'?'0x'+'1'.repeat(40):'bc1q'+'a'.repeat(38)));assert.equal(f.messages.length,0);}],
    ...(kind==='metamask'?[['K13',s=>s.replace('{1,16}', '{1,}'),async f=>{f.invoke();f.listeners.get('chainChanged')('0x'+'1'.repeat(17));assert.equal(f.messages.length,0);}]]:[]),
    ['K15',s=>s.replace('if (walletEventProviders.get(connectorId) !== provider) return;',"if (walletEventProviders.get(connectorId) !== provider) return; provider.request({method:'eth_accounts'});"),async f=>{f.invoke();const n=f.calls.length;f.listeners.get('accountsChanged')([]);assert.equal(f.calls.length,n);}],
  ]) {
    const source=await readFile(new URL('../capsules/home/browser/home-wallet-connector-host.js',import.meta.url),'utf8');assert.notEqual(mutate(source),source,id);
    await check(await hostFixture(kind));
    await assert.rejects(check(await hostFixture(kind,mutate)),{code:'ERR_ASSERTION'},id);
    t.diagnostic(id+': break caught');
  }
});
