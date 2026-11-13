// This module runs only in the connector's opaque frame. Runtime owns approval authority.
export function createWalletConnectClient({ api, origin, loadAdapter = () => import(`./vendor/reown-appkit.js?instance=${crypto.randomUUID()}`), clearMemory = () => {} }) {
  let provider, adapter, activeRevision, sessionApi, generation = 0;
  const address = async () => {
    const accounts = await provider.request({method:'eth_accounts'});
    const value = accounts?.[0];
    if (!/^0x[0-9a-fA-F]{40}$/.test(value || '')) throw new Error('Select an account in your phone wallet.');
    return value;
  };
  const chain = async () => {
    const value = await provider.request({method:'eth_chainId'});
    if (!/^0x[0-9a-fA-F]+$/.test(value || '')) throw new Error('Wallet returned an invalid chain.');
    return `eip155:${Number.parseInt(value,16)}`;
  };
  const same = (a,b) => String(a).toLowerCase() === String(b).toLowerCase();
  const signData = message => /^0[xX](?:[0-9a-fA-F]{2})*$/.test(message) ? '0x'+message.slice(2)
    : '0x'+[...new TextEncoder().encode(message)].map(b=>b.toString(16).padStart(2,'0')).join('');
  const retireAdapter = async () => {
    let timer;
    try {
      await Promise.race([
        Promise.resolve().then(()=>adapter?.disconnectWalletConnectEvm({api:sessionApi})),
        new Promise(resolve=>{timer=setTimeout(resolve,5000);}),
      ]);
    } catch {} finally { clearTimeout(timer); }
  };
  const connect = async () => {
    const config = await api('wallet/config');
    const permission = await api('internet');
    if (permission.status !== 'granted') throw new Error('Allow WalletConnect internet access in Inbox, then connect again.');
    if (activeRevision !== undefined && activeRevision !== config.walletconnect.storage_revision) {
      await retireAdapter();
      provider = undefined; adapter = undefined; clearMemory();
    }
    activeRevision = config.walletconnect.storage_revision;
    const revision = activeRevision;
    sessionApi = (resource, init={}) => api(resource, ['storage','relay-admission'].includes(resource)
      ? {...init,headers:{...init.headers,'if-match':revision}} : init);
    adapter ??= await loadAdapter();
    const current = await adapter.connectWalletConnectEvm({
      contextKey:'wallet-walletconnect', projectId:config.walletconnect.project_id, chains:[1,20,8453,11155111], api:sessionApi,
      runtimeUrl:`${origin}/api/apps/wallet-walletconnect`, relayUrl:`${origin.replace(/^http/,'ws')}/api/apps/wallet-walletconnect/relay`,
      metadata:{name:'ElastOS Home',description:'Runtime wallet approval',url:origin,icons:[]},
    });
    if (current !== provider) {
      provider = current;
      for (const name of ['accountsChanged','chainChanged','disconnect']) provider.on(name,()=>generation++);
    }
    return provider;
  };
  const disconnect = async () => {
    generation++;
    try { await retireAdapter(); }
    finally {
      provider = undefined; adapter = undefined; activeRevision = undefined; clearMemory();
      await api('storage',{method:'DELETE'});
    }
    return {status:'disconnected'};
  };
  return { async effect(action) {
    if (action.kind === 'disconnect') return disconnect();
    if (action.kind === 'status') {
      const permission = await api('internet');
      if (permission.status !== 'granted' && provider) await disconnect();
      return {status:provider?.connected && provider.session?.expiry > Date.now()/1000
        && provider.signer?.client.core.relayer.connected ? 'connected':'disconnected',revision:generation};
    }
    await connect();
    const revision = generation;
    const signer = await address(), namespace = await chain();
    if (action.kind === 'link') {
      const challenge = await api('/api/auth/evm/challenge',{method:'POST',body:JSON.stringify({address:signer,chain_id:Number(namespace.split(':')[1])})});
      const check = async () => {
        if (!same(await address(),signer) || await chain() !== namespace || generation !== revision
          || !Number.isSafeInteger(challenge.expires_at) || challenge.expires_at <= Date.now()/1000) throw new Error('Wallet changed or the challenge expired. Connect again.');
      };
      await check();
      const signature = await provider.request({method:'personal_sign',params:[signData(challenge.message),signer]});
      await check();
      await api('/api/auth/evm/verify',{method:'POST',body:JSON.stringify({message:challenge.message,signature})});
      return {status:'linked'};
    }
    if (action.kind !== 'approve') throw new Error('Unsupported wallet request.');
    const path = `wallet/approvals/${encodeURIComponent(action.approvalRequestId)}`;
    const requests = (await api('wallet/approvals')).approval_requests || [];
    const review = requests.find(r=>r.request_id === action.approvalRequestId);
    if (!review || review.status !== 'pending' || !same(review.address,signer) || review.chain_namespace !== namespace) throw new Error('Select the requested account and network in your phone wallet, then review again.');
    const ttl = review.expires_at - Math.ceil(Date.now()/1000);
    if (!Number.isSafeInteger(review.expires_at) || ttl <= 0 || review.intent === 'transaction_intent' && ttl < 300) throw new Error('Wallet request expires soon. Request a fresh review.');
    const supported = ['auth_challenge','browser_personal_sign','browser_typed_data_sign','capability_grant','credential','publish_envelope','protected_content_rights_signature','transaction_intent','revocation'];
    if (!supported.includes(review.intent)) throw new Error('This request type is unavailable in WalletConnect. Reject it in Wallet.');
    if (review.intent === 'browser_typed_data_sign' && !provider.session?.namespaces?.eip155?.methods?.includes('eth_signTypedData_v4'))
      throw new Error('Typed data signing is unavailable in this pairing. Reject this request in Wallet or use another linked account.');
    const {handoff,binding} = await api(`${path}/approve`,{method:'POST',body:'{}'});
    if (!handoff || !binding || handoff.request_id !== action.approvalRequestId
      || handoff.payload_hash !== binding.payload_hash || !same(handoff.signer,signer)
      || binding.chain_namespace !== namespace || !/^0x[0-9a-fA-F]{64}$/.test(handoff.payload_hash || '')) throw new Error('Runtime returned an invalid wallet binding.');
    const check = async () => {
      if (!same(await address(),signer) || await chain() !== namespace || generation !== revision
        || !Number.isSafeInteger(binding.expires_at) || binding.expires_at <= Date.now()/1000) throw new Error('Wallet request changed or expired. Request a new review.');
      return Math.min(600,Math.max(binding.expires_at-Math.ceil(Date.now()/1000),300));
    };
    const expiry = await check();
    if (handoff.intent === 'transaction_intent') {
      const transaction = handoff.transaction;
      if (!transaction || !same(transaction.from,signer) || `eip155:${Number.parseInt(transaction.chainId,16)}` !== namespace) throw new Error('Runtime returned an invalid transaction.');
      const hash = await provider.request({method:'eth_sendTransaction',params:[transaction]},expiry);
      if (typeof hash !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(hash)) throw new Error('Wallet returned an invalid transaction hash. The wallet may have sent it. Check your wallet before sending again.');
      // A returned hash is retained even if the account, network or expiry changed while sending.
      try { await api(`${path}/complete`,{method:'POST',body:JSON.stringify({payload_hash:handoff.payload_hash,signer,transaction_hash:hash})}); }
      catch { throw new Error(`Wallet returned transaction hash ${hash}. Runtime could not confirm it. Keep this hash and check it before sending again.`); }
      return {status:'completed',effect:'transaction'};
    }
    if (handoff.signature_type !== 'personal_sign' || typeof handoff.message !== 'string') throw new Error('Runtime returned an invalid signature request.');
    const method = handoff.intent === 'browser_typed_data_sign' ? 'eth_signTypedData_v4' : 'personal_sign';
    const signature = await provider.request({method,params:method === 'eth_signTypedData_v4' ? [signer,handoff.message] : [signData(handoff.message),signer]},expiry);
    await check();
    await api(`${path}/complete`,{method:'POST',body:JSON.stringify({payload_hash:handoff.payload_hash,signer,signature,signature_type:method === 'eth_signTypedData_v4' ? 'eip712' : 'personal_sign'})});
    return {status:'completed',effect:'signature'};
  }};
}
