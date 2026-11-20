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
    assert.match(result.stdout, /# tests 5/);
    assert.match(result.stdout, /# fail 0/);
    assert.equal(result.status, 0, result.stdout + result.stderr);
    t.diagnostic('Child executed host wallet compatibility tests.');
  });
}

async function hostWithProviders(announcements) {
  const calls = [];
  const providers = new Map();
  for (const spec of announcements) {
    const provider = {
      request(call) { calls.push({ rdns: spec.rdns, call }); return Promise.resolve(spec.reply?.(call) ?? []); },
      on() {},
    };
    providers.set(spec.rdns, provider);
  }
  const source = await readFile(new URL('../capsules/home/browser/home-wallet-connector-host.js', import.meta.url), 'utf8');
  const windowListeners = new Map();
  const window = {
    addEventListener(name, cb) { windowListeners.set(name, cb); },
    dispatchEvent() {},
  };
  const context = vm.createContext({
    window, Event, Set, Map, WeakSet, Number, Object, TextEncoder,
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
  for (const spec of announcements) {
    windowListeners.get('eip6963:announceProvider')({
      detail: {
        info: { rdns: spec.rdns, uuid: spec.uuid, name: spec.name ?? spec.rdns },
        provider: providers.get(spec.rdns),
      },
    });
  }
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

if (vm.SourceTextModule) test('two non-MetaMask wallets require an explicit walletUuid', async () => {
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
  assert.match(messages.at(-1)?.error, /Choose a browser wallet/);

  module.namespace.handleHomeWalletConnectorEffect({ source: admitted.source }, admitted, {
    type: 'home:wallet-connector-effect', schema: 'elastos.home.wallet-connector-effect/v1',
    requestId: 'req:4', connectorId: 'wallet-metamask', connectorToken: 'token',
    action: { kind: 'link', walletUuid: 'brave-1' },
  });
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(calls.length, 1);
  assert.equal(calls[0].rdns, 'com.brave.wallet');
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
  assert.equal(view.title, 'Rabby Wallet');
  assert.doesNotMatch(viewText(view.notice), /MetaMask or Brave/);
});