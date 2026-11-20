import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';
import { spawnSync } from 'node:child_process';
import { connectionView, viewText } from '../capsules/_shared/wallet-connection-view.mjs';

if (!vm.SourceTextModule) {
  test('compatible browser wallet host checks', (t) => {
    const env = { ...process.env }; delete env.NODE_TEST_CONTEXT;
    const result = spawnSync(process.execPath, ['--experimental-vm-modules', '--test-reporter=tap', '--test', import.meta.filename], { env, encoding: 'utf8', timeout: 60000 });
    assert.equal(result.error, undefined);
    assert.match(result.stdout, /# tests 9/);
    assert.match(result.stdout, /# fail 0/);
    assert.equal(result.status, 0, result.stdout + result.stderr);
    t.diagnostic('Child executed host wallet compatibility tests.');
  });
}

async function hostWithProviders(announcements) {
  const calls = [];
  const providers = new Map();
  for (const [index, spec] of announcements.entries()) {
    const provider = spec.provider ?? {
      request(call) { calls.push({ rdns: spec.rdns, call }); return Promise.resolve(spec.reply?.(call) ?? []); },
      on() {},
    };
    providers.set(index, provider);
  }
  const source = await readFile(new URL('../capsules/home/browser/home-wallet-connector-host.js', import.meta.url), 'utf8');
  const windowListeners = new Map();
  const window = {
    addEventListener(name, cb) { windowListeners.set(name, cb); },
    dispatchEvent() { announce(); },
  };
  const context = vm.createContext({
    window, Event, Set, Map, WeakSet, Number, Object, TextEncoder, crypto, setTimeout, clearTimeout,
  });
  context.fetchJson = async () => { throw new Error('network'); };
  const module = new vm.SourceTextModule(source, { context });
  await module.link(async () => {
    const dependency = new vm.SyntheticModule(['fetchJson'], function () {
      this.setExport('fetchJson', context.fetchJson);
    }, { context });
    return dependency;
  });
  await module.evaluate();
  function announce() {
  for (const [index, spec] of announcements.entries()) {
    windowListeners.get('eip6963:announceProvider')({
      detail: {
        info: { rdns: spec.rdns, uuid: spec.uuid, name: spec.name ?? spec.rdns },
        provider: providers.get(index),
      },
    });
  }
  }
  announce();
  return { module, calls, providers, window };
}

async function legacyHost(announcements, legacy) {
  const h = await hostWithProviders(announcements);
  h.window.ethereum = legacy;
  return h;
}

if (vm.SourceTextModule) test('announced Rabby alone is selected for link without walletUuid', async () => {
  const address = '0x' + '2'.repeat(40);
  const { module, calls } = await hostWithProviders([{
    rdns: 'io.rabby', uuid: 'rabby-1', name: 'Rabby Wallet',
    reply: (call) => (call.method === 'eth_requestAccounts' ? [address] : call.method === 'eth_chainId' ? '0x1' : null),
  }]);
  const frame = { postMessage() {} };
  const admitted = {
    kind: 'app-frame', targetId: 'wallet-metamask', homeToken: 'token', source: frame,
    clipboardState: { retired: false, generation: 'g1' },
    walletEffectState: { inFlight: false, requestIds: new Set() },
  };
  const data = {
    type: 'home:wallet-connector-effect', schema: 'elastos.home.wallet-connector-effect/v1',
    requestId: 'req:1', connectorId: 'wallet-metamask', connectorToken: 'token', action: { kind: 'link' },
  };
  module.namespace.handleHomeWalletConnectorEffect({ source: frame }, admitted, data);
  await new Promise((resolve) => setTimeout(resolve, 0));
  const accountCalls = calls.filter((entry) => entry.call.method === 'eth_requestAccounts');
  assert.equal(accountCalls.length, 1);
  assert.equal(accountCalls[0].rdns, 'io.rabby');
});

if (vm.SourceTextModule) test('MetaMask wins when MetaMask and Rabby are both announced', async () => {
  const { module, calls } = await hostWithProviders([
    { rdns: 'io.metamask', uuid: 'mm-1', name: 'MetaMask', reply: () => [] },
    { rdns: 'io.rabby', uuid: 'rabby-1', name: 'Rabby Wallet', reply: () => [] },
  ]);
  const frame = { postMessage() {} };
  const admitted = {
    kind: 'app-frame', targetId: 'wallet-metamask', homeToken: 'token', source: frame,
    clipboardState: { retired: false, generation: 'g1' },
    walletEffectState: { inFlight: false, requestIds: new Set() },
  };
  module.namespace.handleHomeWalletConnectorEffect({ source: frame }, admitted, {
    type: 'home:wallet-connector-effect', schema: 'elastos.home.wallet-connector-effect/v1',
    requestId: 'req:2', connectorId: 'wallet-metamask', connectorToken: 'token', action: { kind: 'link' },
  });
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(calls.length, 1);
  assert.equal(calls[0].rdns, 'io.metamask');
});

if (vm.SourceTextModule) test('two non-MetaMask wallets require an explicit walletChoiceId', async () => {
  const { module, calls } = await hostWithProviders([
    { rdns: 'io.rabby', uuid: 'rabby-1', name: 'Rabby Wallet', reply: () => [] },
    { rdns: 'com.brave.wallet', uuid: 'brave-1', name: 'Brave Wallet', reply: () => [] },
  ]);
  const frame = { postMessage() {} };
  const messages = [];
  const admitted = {
    kind: 'app-frame', targetId: 'wallet-metamask', homeToken: 'token',
    source: { postMessage(data) { messages.push(data); } },
    clipboardState: { retired: false, generation: 'g1' },
    walletEffectState: { inFlight: false, requestIds: new Set() },
  };
  module.namespace.handleHomeWalletConnectorEffect({ source: admitted.source }, admitted, {
    type: 'home:wallet-connector-effect', schema: 'elastos.home.wallet-connector-effect/v1',
    requestId: 'req:3', connectorId: 'wallet-metamask', connectorToken: 'token', action: { kind: 'link' },
  });
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(calls.length, 0);
  const choicePayload = messages.at(-1);
  assert.match(choicePayload?.error, /Choose a browser wallet/);
  assert.equal(choicePayload?.walletChoices?.length, 2);
  const braveChoice = choicePayload.walletChoices.find((row) => row.name === 'Brave Wallet');
  assert.ok(braveChoice?.id);

  module.namespace.handleHomeWalletConnectorEffect({ source: admitted.source }, admitted, {
    type: 'home:wallet-connector-effect', schema: 'elastos.home.wallet-connector-effect/v1',
    requestId: 'req:4', connectorId: 'wallet-metamask', connectorToken: 'token',
    action: { kind: 'link', walletChoiceId: braveChoice.id },
  });
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(calls.length, 1);
  assert.equal(calls[0].rdns, 'com.brave.wallet');
});

if (vm.SourceTextModule) test('conflicting duplicate rdns announcements drop only that wallet', async () => {
  const conflicted = {
    request(call) { return Promise.resolve([]); },
    on() {},
  };
  const { module, calls } = await hostWithProviders([
    {
      rdns: 'io.metamask', uuid: 'mm-1', name: 'MetaMask',
      reply: (call) => (call.method === 'eth_requestAccounts' ? ['0x' + '1'.repeat(40)] : call.method === 'eth_chainId' ? '0x1' : '0x' + 'ab'.repeat(65)),
    },
    { rdns: 'io.rabby', uuid: 'r1', name: 'Rabby', provider: conflicted },
    { rdns: 'io.rabby.alt', uuid: 'r2', name: 'Rabby alt', provider: conflicted },
  ]);
  const frame = { postMessage() {} };
  module.namespace.handleHomeWalletConnectorEffect({ source: frame }, {
    kind: 'app-frame', targetId: 'wallet-metamask', homeToken: 'token', source: frame,
    clipboardState: { retired: false, generation: 'g1' },
    walletEffectState: { inFlight: false, requestIds: new Set() },
  }, {
    type: 'home:wallet-connector-effect', schema: 'elastos.home.wallet-connector-effect/v1',
    requestId: 'req:conflict', connectorId: 'wallet-metamask', connectorToken: 'token', action: { kind: 'link' },
  });
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(calls.filter((entry) => entry.call.method === 'eth_requestAccounts').length, 1);
  assert.equal(calls[0].rdns, 'io.metamask');
});

if (vm.SourceTextModule) test('legacy shared-slot provider is not announced and is not used', async () => {
  const legacyCalls = [];
  const legacy = { request(call) { legacyCalls.push(call); return Promise.resolve([]); }, isMetaMask: true, on() {} };
  const { module, calls } = await legacyHost([], legacy);
  const frame = { postMessage() {} };
  const messages = [];
  module.namespace.handleHomeWalletConnectorEffect({ source: frame }, {
    kind: 'app-frame', targetId: 'wallet-metamask', homeToken: 'token', source: { postMessage(d) { messages.push(d); } },
    clipboardState: { retired: false, generation: 'g1' },
    walletEffectState: { inFlight: false, requestIds: new Set() },
  }, {
    type: 'home:wallet-connector-effect', schema: 'elastos.home.wallet-connector-effect/v1',
    requestId: 'req:5', connectorId: 'wallet-metamask', connectorToken: 'token', action: { kind: 'link' },
  });
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(legacyCalls.length, 0);
  assert.equal(calls.length, 0);
});

test('wallet names with markup characters are rejected at the view boundary', () => {
  const view = connectionView({
    window: 'metamask',
    stage: 'extension-wait',
    provider: {
      providerId: 'io.rabby', displayName: 'Rabby Wallet', alternatives: [], availability: 'found',
      firstAccount: null, requiredAccountAvailable: null, network: null, networkIssue: null,
      access: 'unknown', busy: false, paymentPending: null,
    },
    waitSeconds: 30,
  });
  assert.throws(() => connectionView({
    window: 'metamask', stage: 'extension-choose-wallet',
    walletChoices: [{ id: 'x', name: '<evil>', icon: null }],
  }), /closed wallet choice/);
  assert.equal(view.title, 'MetaMask');
  assert.doesNotMatch(viewText(view.notice), /MetaMask or Brave/);
});
async function send(h, action={kind:'link'}, context) {
  const messages=[];
  context ||= {kind:'app-frame',targetId:'wallet-metamask',homeToken:'token',source:{postMessage(data){messages.push(data);}},clipboardState:{retired:false,generation:'g1'},walletEffectState:{inFlight:false,requestIds:new Set()}};
  h.module.namespace.handleHomeWalletConnectorEffect({source:context.source},context,{
    type:'home:wallet-connector-effect',schema:'elastos.home.wallet-connector-effect/v1',requestId:'req:'+crypto.randomUUID(),connectorId:context.targetId,connectorToken:context.homeToken,action,
  });
  await new Promise(resolve=>setTimeout(resolve,5));
  return {reply:messages.at(-1),context};
}
if(vm.SourceTextModule) test('fresh discovery deduplicates before cap and drops cross-object identities only',async()=>{
  for(const collision of ['uuid','rdns','object']) {
    const common={request(){return Promise.resolve([]);}};
    const a={rdns:'io.first',uuid:'first',name:'First',...(collision==='object'?{provider:common}:{})};
    const b={rdns:collision==='rdns'?'io.first':'io.second',uuid:collision==='uuid'?'first':'second',name:'Second',...(collision==='object'?{provider:common}:{})};
    const h=await hostWithProviders([a,b,{rdns:'io.other',uuid:'other',name:'Other'}]);
    await send(h);assert.equal(h.calls[0].rdns,'io.other');
  }
  const specs=Array.from({length:32},(_,i)=>({rdns:'io.wallet'+i,uuid:'w'+i,name:'Wallet '+i}));
  const shared={request(){return Promise.resolve([]);}};
  const duplicate={rdns:'io.wallet0',uuid:'w0',name:'Wallet 0',provider:shared};
  const h=await hostWithProviders([...Array(33).fill(duplicate),...specs.slice(1)]);const {reply}=await send(h);assert.equal(reply.walletChoices.length,32);
  specs.push({rdns:'io.extra',uuid:'extra',name:'Extra'});
  const overflow=await hostWithProviders(specs);assert.match((await send(overflow)).reply.error,/ambiguous/);assert.equal(overflow.calls.length,0);
});
if(vm.SourceTextModule) test('choice handles are one-use and bound to frame lifetime, with disappeared-wallet recovery',async()=>{
  const specs=[{rdns:'io.first',uuid:'first',name:'First'},{rdns:'io.second',uuid:'second',name:'Second'}];
  const h=await hostWithProviders(specs);const offer=await send(h);const id=offer.reply.walletChoices[0].id;
  assert.match((await send(h,{kind:'link',walletChoiceId:id})).reply.error,/not available/);
  offer.context.clipboardState.generation='g2';
  await send(h,{kind:'link',walletChoiceId:id},offer.context);assert.equal(h.calls.length,0);
  const fresh=await send(h);specs.length=0;
  await send(h,{kind:'link',walletChoiceId:fresh.reply.walletChoices[0].id},fresh.context);assert.equal(h.calls.length,0);
});
if(vm.SourceTextModule) test('approval probes at most eight wallets in parallel and stops after a bounded wait',async()=>{
  let started=0;
  const specs=Array.from({length:10},(_,i)=>({rdns:'io.wallet'+i,uuid:'w'+i,name:'Wallet '+i,provider:{request(){started++;return new Promise(()=>{});}}}));
  const h=await hostWithProviders(specs),messages=[];
  const context={kind:'app-frame',targetId:'wallet-metamask',homeToken:'token',source:{postMessage(d){messages.push(d);}},clipboardState:{retired:false,generation:'g'},walletEffectState:{inFlight:false,requestIds:new Set()}};
  await send(h,{kind:'approve',approvalRequestId:'pending',linkedAddress:'0x'+'1'.repeat(40)},context);
  assert.equal(started,8);await new Promise(resolve=>setTimeout(resolve,1100));
  assert.equal(messages.length,1);assert.match(messages[0].error,/cannot confirm access/);
});
