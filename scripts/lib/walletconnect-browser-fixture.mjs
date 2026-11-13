import { connectWalletConnectEvm } from './wc-sdk.js';
window.methods = []; window.nativeUrls = []; window.proposalReady = false;
window.runtimeTrace = [];
window.keys = Object.create(null); window.cancelled = false; window.failed = false;
class RelaySocket {
  constructor(url) {
    window.nativeUrls.push(url); this.readyState = 0;
    queueMicrotask(() => { this.readyState = 1; this.onopen?.(); });
  }
  send(raw) {
    const message = JSON.parse(raw);
    if (message.token) {
      queueMicrotask(() => this.onmessage?.({ data: '{"ready":true}' })); return;
    }
    if (!message.method) return;
    window.methods.push(message.method);
    if (message.method === 'wc_proposeSession') {
      window.proposalReady = /^[a-f0-9]{64}$/.test(message.params?.pairingTopic)
        && typeof message.params?.sessionProposal === 'string'
        && message.params.sessionProposal.length > 0;
    }
    const result = message.method.endsWith('batchSubscribe') ? message.params.topics.map((_, i) => 'sub-' + i)
      : message.method.endsWith('subscribe') ? 'fixture-subscription' : true;
    queueMicrotask(() => this.onmessage?.({ data: JSON.stringify({ jsonrpc:'2.0', id:message.id, result }) }));
  }
  close() { this.readyState = 3; this.onclose?.(); }
}
globalThis.WebSocket = RelaySocket;
const api = async (path, input) => {
  if (path === 'relay-admission') return { token:'fixture-admission' };
  if (path !== 'storage') throw new Error('unexpected Runtime resource');
  if (input) {
    const { key, value } = JSON.parse(input.body);
    window.runtimeTrace.push({ key, operation: value === null ? "removeItem" : "setItem" });
    if (value === null) delete window.keys[key]; else window.keys[key] = value;
  }
  return structuredClone(window.keys);
};
window.pending = connectWalletConnectEvm({
  contextKey:'principal-fixture', projectId:'fixture-project-id', chains:[1], api,
  relayUrl:location.origin.replace(/^http/, 'ws') + '/relay',
  runtimeUrl:location.origin + '/api/apps/wallet-walletconnect',
  metadata:{name:'Isolated Runtime fixture', description:'WalletConnect test', url:location.origin, icons:[]},
}).catch(error => { window.cancelled = error.message === 'Wallet connection cancelled.'; window.failed = !window.cancelled; });
