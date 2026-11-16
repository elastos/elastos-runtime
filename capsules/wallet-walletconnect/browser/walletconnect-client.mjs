const networks = new Map([[1,'Ethereum'],[20,'Elastos Smart Chain'],[8453,'Base'],[11155111,'Sepolia test network']]);
const noSupportedNetwork = 'Your wallet did not approve a network this Home supports. Select Connect wallet and choose Ethereum, Elastos Smart Chain, Base or Sepolia in your phone wallet.';
const connectionFailed = 'The wallet connection failed. Select Connect wallet to try again.';
const approvedNetworks = provider => {
  const namespace = provider.session?.namespaces?.eip155;
  return new Set([...(namespace?.accounts || []).map(account => account.split(':').slice(0,2).join(':'))]);
};
// This module runs only in the connector's opaque frame. Runtime owns approval authority.
export function createWalletConnectClient({ api, origin, loadAdapter = () => import(`./vendor/reown-appkit.js?instance=${crypto.randomUUID()}`), clearMemory = () => {} }) {
  let provider, adapter, activeRevision, sessionApi, projectId, pairing, generation = 0;
  const sdkError = (error, linking = false) => {
    console.error('WalletConnect SDK:', String(error?.message || error).split(projectId || '\0').join('[project]'));
    if ([4001,5000,5001,5002,5003].includes(Number(error?.code))) return Object.assign(new Error(linking
      ? 'You declined the connection in your phone wallet. Select Connect wallet to try again.'
      : 'You declined this in your phone wallet. Nothing was signed or sent.'), {tone:'muted'});
    if (error?.message === 'Request expired. Please try again.') return Object.assign(new Error('Your phone wallet did not answer in time. Nothing was signed or sent. Select the request again to retry.'), {tone:'muted'});
    const message = ['Wallet connection cancelled.','The QR code expired. Select Connect wallet for a new one.','Internet access for WalletConnect was turned off. Select Connect wallet to ask again.'].includes(error?.message) ? error.message : connectionFailed;
    return Object.assign(new Error(message), {tone:message.startsWith('The QR code expired.') || message.startsWith('Internet access for WalletConnect was turned off.') ? 'muted' : 'error'});
  };
  const requireNetwork = namespace => {
    if (!approvedNetworks(provider).has(namespace)) {
      const name = networks.get(Number(namespace.split(':')[1])) || `an unsupported network (${namespace.split(':')[1]})`;
      throw new Error(`This request is for ${name}, which your wallet did not approve. Select Disconnect, then Connect wallet, and approve ${name} in your phone wallet.`);
    }
  };
  const request = async (input, expiry, linking = false) => {
    requireNetwork(`eip155:${provider.chainId}`);
    try { return await provider.request(input, expiry); }
    catch (error) { throw sdkError(error, linking); }
  };
  const address = async () => {
    const accounts = await request({method:'eth_accounts'});
    const value = accounts?.[0];
    if (!/^0x[0-9a-fA-F]{40}$/.test(value || '')) throw new Error('Select an account in your phone wallet.');
    return value;
  };
  const chain = async () => {
    const value = await request({method:'eth_chainId'});
    // The pinned WalletConnect provider returns a number; EIP-1193 wallets use hex.
    const id = typeof value === 'number' ? value
      : typeof value === 'string' && /^0x[0-9a-fA-F]+$/.test(value) ? Number(value) : NaN;
    if (!Number.isSafeInteger(id) || id <= 0) throw new Error('Wallet returned an invalid chain.');
    return `eip155:${id}`;
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
    if (permission.status !== 'granted') throw Object.assign(new Error('WalletConnect needs internet access. Answer the request in Inbox. If it is no longer there, select Connect wallet to ask again.'), {tone:'muted'});
    if (activeRevision !== undefined && activeRevision !== config.walletconnect.storage_revision) {
      await retireAdapter();
      provider = undefined; adapter = undefined; clearMemory();
    }
    activeRevision = config.walletconnect.storage_revision;
    const revision = activeRevision;
    sessionApi = (resource, init={}) => api(resource, ['storage','relay-admission'].includes(resource)
      ? {...init,headers:{...init.headers,'if-match':revision}} : init);
    projectId = config.walletconnect.project_id;
    let current;
    const attempt = pairing = new AbortController();
    try {
      adapter ??= await loadAdapter();
      current = await adapter.connectWalletConnectEvm({
      signal:attempt.signal, contextKey:'wallet-walletconnect', projectId:config.walletconnect.project_id, chains:[1,20,8453,11155111], api:sessionApi,
      runtimeUrl:`${origin}/api/apps/wallet-walletconnect`, relayUrl:`${origin.replace(/^http/,'ws')}/api/apps/wallet-walletconnect/relay`,
      metadata:{name:'ElastOS Home',description:'Approve requests from your ElastOS Home',url:origin,icons:[]},
    });
      attempt.signal.throwIfAborted();
    } catch (error) { throw sdkError(error, true); }
    finally { if (pairing === attempt) pairing = undefined; }
    const approved = approvedNetworks(current);
    const supported = [...networks.keys()].filter(id => approved.has(`eip155:${id}`));
    if (!supported.length) { await disconnect(); throw new Error(noSupportedNetwork); }
    try { if (!supported.includes(current.chainId)) current.signer.setDefaultChain(`eip155:${supported[0]}`); }
    catch (error) { throw sdkError(error, true); }
    if (current !== provider) {
      provider = current;
      for (const name of ['accountsChanged','chainChanged','disconnect']) provider.on(name,()=>generation++);
    }
    return provider;
  };
  const disconnect = async () => {
    generation++;
    pairing?.abort(new Error('Internet access for WalletConnect was turned off. Select Connect wallet to ask again.'));
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
      if (permission.status !== 'granted' && (provider || pairing)) await disconnect();
      return {status:provider?.connected && provider.session?.expiry > Date.now()/1000
        && provider.signer?.client.core.relayer.connected ? 'connected':'disconnected',revision:generation,permission};
    }
    await connect();
    const revision = generation;
    const signer = await address(), namespace = await chain();
    if (action.kind === 'link') {
      const challenge = await api('/api/auth/evm/challenge',{method:'POST',body:JSON.stringify({address:signer,chain_id:Number(namespace.split(':')[1])})});
      const check = async () => {
        if (!same(await address(),signer) || await chain() !== namespace || generation !== revision
          || !Number.isSafeInteger(challenge.expires_at) || challenge.expires_at <= Date.now()/1000) throw new Error('Wallet changed or the challenge expired. Select Connect wallet to try again.');
      };
      await check();
      const signature = await request({method:'personal_sign',params:[signData(challenge.message),signer]}, undefined, true);
      await check();
      await api('/api/auth/evm/verify',{method:'POST',body:JSON.stringify({message:challenge.message,signature})});
      return {status:'linked'};
    }
    if (action.kind !== 'approve') throw new Error('Unsupported wallet request.');
    const path = `wallet/approvals/${encodeURIComponent(action.approvalRequestId)}`;
    const requests = (await api('wallet/approvals')).approval_requests || [];
    const review = requests.find(r=>r.request_id === action.approvalRequestId);
    if (review) requireNetwork(review.chain_namespace);
    if (!review || review.status !== 'pending' || !same(review.address,signer) || review.chain_namespace !== namespace) throw new Error('Select the requested account and network in your phone wallet, then review again.');
    const ttl = review.expires_at - Math.ceil(Date.now()/1000);
    if (!Number.isSafeInteger(review.expires_at) || ttl <= 0 || review.intent === 'transaction_intent' && ttl < 300) throw new Error('Wallet request expires soon. Request a fresh review.');
    const supported = ['auth_challenge','browser_personal_sign','browser_typed_data_sign','capability_grant','credential','publish_envelope','protected_content_rights_signature','transaction_intent','revocation'];
    if (!supported.includes(review.intent)) throw new Error('This request type is unavailable in WalletConnect. Reject it in Wallet.');
    if (review.intent === 'browser_typed_data_sign')
      throw new Error('Typed data signing is unavailable in this connector. Reject this request in Wallet or use another linked account.');
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
      if (transaction) requireNetwork(`eip155:${Number.parseInt(transaction.chainId,16)}`);
      if (!transaction || !same(transaction.from,signer) || `eip155:${Number.parseInt(transaction.chainId,16)}` !== namespace) throw new Error('Runtime returned an invalid transaction.');
      const hash = await request({method:'eth_sendTransaction',params:[transaction]},expiry);
      if (typeof hash !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(hash)) throw new Error('Wallet returned an invalid transaction hash. The wallet may have sent it. Check your wallet before sending again.');
      // A returned hash is retained even if the account, network or expiry changed while sending.
      let receipt;
      try { receipt = await api(`${path}/complete`,{method:'POST',body:JSON.stringify({payload_hash:handoff.payload_hash,signer,transaction_hash:hash})}); }
      catch { throw new Error(`Wallet returned transaction hash ${hash}. Runtime could not confirm it. Keep this hash and check it before sending again.`); }
      return {status:receipt.receipt_status || 'completed',effect:'transaction',message:receipt.receipt_status === 'sent_after_dismissal' ? 'Request dismissed. Transaction sent from wallet.' : 'Transaction sent.'};
    }
    if (handoff.signature_type !== 'personal_sign' || typeof handoff.message !== 'string') throw new Error('Runtime returned an invalid signature request.');
    const method = 'personal_sign';
    const signature = await request({method,params:[signData(handoff.message),signer]},expiry);
    await check();
    await api(`${path}/complete`,{method:'POST',body:JSON.stringify({payload_hash:handoff.payload_hash,signer,signature,signature_type:'personal_sign'})});
    return {status:'completed',effect:'signature'};
  }};
}
