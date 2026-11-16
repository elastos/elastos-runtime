// A real pinned provider pairs with the test's SignClient wallet over a local relay.
import { createWalletConnectClient } from './walletconnect-client.mjs';
const keys = Object.create(null);
window.requests = [];
const api = async (path, input) => {
  if (path === 'wallet/config') return {walletconnect:{project_id:'fixture-project',storage_revision:'"0"'}};
  if (path === 'internet') return {status:'granted'};
  if (path === 'relay-admission') return {token:'fixture-admission'};
  if (path === 'storage') {
    if (input?.method === 'DELETE') { for (const key of Object.keys(keys)) delete keys[key]; }
    else if (input?.body) { const {key,value} = JSON.parse(input.body); if (value === null) delete keys[key]; else keys[key] = value; }
    return structuredClone(keys);
  }
  if (path.endsWith('/challenge')) { window.challenge = JSON.parse(input.body); return {message:'Test Home ownership',expires_at:Math.floor(Date.now()/1000)+600}; }
  if (path.endsWith('/verify')) return {};
  throw new Error('Unexpected fixture resource');
};
const client = createWalletConnectClient({api,origin:location.origin,loadAdapter:async () => {
  const adapter = await import('./vendor/reown-appkit.js');
  return {...adapter,connectWalletConnectEvm:async options => {
    // The pairing URI stays inside this isolated, disposable test.
    const observer = setInterval(async () => {
      const pairing = Object.entries(keys).find(([key]) => key.endsWith('//pairing'))?.[1]?.find(p => !p.active);
      const raw = Object.entries(keys).find(([key]) => key.endsWith('//keychain'))?.[1];
      const keychain = typeof raw === 'string' ? JSON.parse(raw) : raw;
      const symKey = pairing && (Array.isArray(keychain) ? new Map(keychain).get(pairing.topic) : keychain?.[pairing.topic]);
      if (symKey && !window.pairingSent) {
        window.pairingSent = true;
        await window.pairTestWallet(`wc:${pairing.topic}@2?symKey=${symKey}&relay-protocol=irn&expiryTimestamp=${pairing.expiry}`);
      }
    }, 50);
    try { window.provider = await adapter.connectWalletConnectEvm(options); return window.provider; }
    finally { clearInterval(observer); }
  }};
}});
window.done = client.effect({kind:'link'}).then(result => { window.result = result; }, error => { window.error = error.message; });
window.relink = () => client.effect({kind:'link'});
window.cleanup = () => client.effect({kind:'disconnect'});
