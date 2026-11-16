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
  if (path === 'wallet/approvals') return {approval_requests:[{request_id:'fixture-sign',status:'pending',address:'0x'+'12'.repeat(20),chain_namespace:'eip155:8453',intent:'browser_personal_sign',expires_at:Math.floor(Date.now()/1000)+600}]};
  if (path.endsWith('/approve')) return {handoff:{request_id:'fixture-sign',payload_hash:'0x'+'34'.repeat(32),signer:'0x'+'12'.repeat(20),intent:'browser_personal_sign',signature_type:'personal_sign',message:'Fixture signing request'},binding:{payload_hash:'0x'+'34'.repeat(32),chain_namespace:'eip155:8453',expires_at:Math.floor(Date.now()/1000)+600}};
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
window.done = client.effect(new URLSearchParams(location.search).get('action') === 'approve' ? {kind:'approve',approvalRequestId:'fixture-sign'} : {kind:'link'}).then(result => { window.result = result; }, error => { window.error = error.message; window.errorTone = error.tone; });
window.relink = () => client.effect({kind:'link'});
window.cleanup = () => client.effect({kind:'disconnect'});
