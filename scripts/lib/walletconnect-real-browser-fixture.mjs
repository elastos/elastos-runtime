// Playwright provisions private options; production routes receive only this
// capsule's launch token. This preflight stops at the first resource refusal.
import { installWalletConnectStorage } from './walletconnect-storage.mjs';
window.storageTrace = [];
installWalletConnectStorage(window, entry => {
  if (window.storageTrace.length < 128) window.storageTrace.push({
    store:entry.store, operation:entry.operation, refused:!!entry.refused,
    protocol:/wc@2:|keychain/i.test(entry.key || ''),
  });
});
window.runtimeTrace = [];
window.phase = 'options';
const options = await window.walletConnectTestOptions();
const origin = new URL(import.meta.url).origin;
const api = async (resource, input = {}) => {
  const trace = {resource, status:'request'};
  if (window.runtimeTrace.length < 128) window.runtimeTrace.push(trace);
  const response = await fetch(`${origin}/api/apps/wallet-walletconnect/${resource}`, {
    ...input, headers: { 'content-type':'application/json', 'x-elastos-home-token':options.connector },
  });
  trace.status = response.status;
  if (!response.ok) {
    window.refusal ??= { resource, status:response.status };
    throw new Error('Runtime refused the connector resource');
  }
  const values = await response.json();
  if (resource === 'storage') {
    // Private test-wallet handoff: the URI is reconstructed from the exact
    // Runtime-persisted pairing and keychain, and stays in process memory.
    const pairings = Object.entries(values).find(([key]) => key.endsWith('//pairing'))?.[1];
    const keys = Object.entries(values).find(([key]) => key.endsWith('//keychain'))?.[1];
    const pairing = Array.isArray(pairings) ? pairings.find(value => !value.active) : undefined;
    const keychain = typeof keys === 'string' ? JSON.parse(keys) : keys;
    const symKey = pairing && (Array.isArray(keychain) ? new Map(keychain).get(pairing.topic) : keychain?.[pairing.topic]);
    if (pairing && typeof symKey === 'string') {
      const params = new URLSearchParams({symKey, 'relay-protocol':pairing.relay.protocol,
        expiryTimestamp:String(pairing.expiry), methods:'[wc_sessionPropose]'});
      window.pairingUri = `wc:${pairing.topic}@2?${params}`;
    }
  }
  return values;
};
try {
  window.phase = 'import';
  const { connectWalletConnectEvm } = await import('./vendor/reown-appkit.js');
  window.phase = 'connect';
  window.provider = await connectWalletConnectEvm({
    contextKey:'wallet-walletconnect', projectId:options.projectId, chains:[1], api,
    runtimeUrl:`${origin}/api/apps/wallet-walletconnect`,
    relayUrl:`${origin.replace(/^http/, 'ws')}/api/apps/wallet-walletconnect/relay`,
    metadata:{name:'Isolated recovery test', description:'Throwaway test wallet', url:origin, icons:[]},
  });
  window.phase = 'connected';
} catch (error) {
  window.errorName = ['Error','TypeError','SecurityError'].includes(error.name) ? error.name : 'Error';
  window.failed = true;
}
