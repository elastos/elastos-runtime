const networks = new Map([[1,'Ethereum'],[20,'Elastos Smart Chain'],[8453,'Base'],[11155111,'Sepolia test network']]);
const noSupportedNetwork = 'Your wallet did not approve a network this Home supports. Select Connect wallet and choose Ethereum, Elastos Smart Chain, Base or Sepolia in your wallet.';
const unavailableNetwork = id => `WalletConnect in this Home does not offer network ${id}.`;
// Shared with capsule and SDK journey tests so copy has one source.
export const walletConnectMessages = {
  proposalDeclined: 'Your wallet declined the connection request. Select Connect wallet to try again.',
  ownershipDeclined: 'Your wallet declined the ownership signature. Select Connect wallet to try again.',
  linkTimeout: 'Your wallet did not answer in time. Select Connect wallet to try again.',
  linkError: 'Home could not connect your wallet. Select Connect wallet to try again.',
  signatureDeclined: 'Your wallet declined this signature request. Ask the app to send a new request.',
  signatureTimeout: 'Your wallet did not answer in time. Ask the app to send a new signature request.',
  signatureError: 'Home could not finish this signature request. Ask the app to send a new request.',
  transactionDeclined: 'Your wallet declined this transaction. Check your wallet and Activity in Wallet before you send again.',
  transactionTimeout: 'Your wallet did not answer in time. Check your wallet and Activity in Wallet before you send again.',
  transactionError: 'Home could not confirm this transaction. Check your wallet and Activity in Wallet before you send again.',
  consumed: 'This request is no longer available for review here. Check your wallet and Activity in Wallet before you ask the app for a new request.',
  transactionRecovery: 'Check your wallet and Activity in Wallet before you send again.',
  unsupportedNetwork: id => `${unavailableNetwork(id)} Open Wallet to check your requests and activity.`,
  pendingUnsupportedNetwork: id => `${unavailableNetwork(id)} Reject this request in Wallet.`,
  unapprovedNetwork: name => `This wallet connection has no approved account on ${name}. Select Connect wallet for a new QR code and choose the requested account and network.`,
  cancelled: 'Wallet connection cancelled.',
};
export const isWalletConnectNetwork = namespace => networks.has(Number(String(namespace).split(':')[1]));
const approvedNetworks = provider => {
  const namespace = provider.session?.namespaces?.eip155;
  return new Set([...(namespace?.accounts || []).map(account => account.split(':').slice(0,2).join(':'))]);
};
// This module runs only in the connector's opaque frame. Runtime owns approval authority.
export function createWalletConnectClient({ api, origin, copyLink, pairingView, onPhase = () => {}, loadAdapter = () => import(`./vendor/reown-appkit.js?instance=${crypto.randomUUID()}`), clearMemory = () => {} }) {
  let provider, adapter, activeRevision, sessionApi, projectId, pairing, operation, restoring, restoreAttempt, retiring, cleanupPromise, latestPermission, cleanupRequired = false, removed = false, hadSession = false, sessionExpiry = 0, generation = 0, operationContext, operationDispatched = false, observedAccounts;
  const stopped = 'Home stopped waiting for your wallet. Select Connect wallet for a new QR code.';
  const removedMessage = 'Your wallet removed this connection. Select Connect wallet for a new QR code.';
  const muted = message => Object.assign(new Error(message), {tone:'muted'});
  const waitFor = async (promise, signal) => {
    if (!signal) return promise;
    if (signal.aborted) { Promise.resolve(promise).catch(() => {}); throw signal.reason; }
    let abort;
    try { return await Promise.race([promise,new Promise((_,reject)=>{abort=()=>reject(signal.reason);signal.addEventListener('abort',abort,{once:true});})]); }
    finally { signal.removeEventListener('abort',abort); }
  };
  const sdkError = (error, context = 'proposal') => {
    console.error('WalletConnect SDK:', context, typeof error?.code === 'number' ? error.code : 'local');
    const linking = ['proposal','ownership'].includes(context);
    const prefix = linking ? 'link' : context;
    const localError = error?.code === undefined;
    if ([4001,5000,5001,5002,5003].includes(Number(error?.code))) return Object.assign(new Error(
      walletConnectMessages[`${context}Declined`]), {tone:'muted'});
    // The pinned SDK creates an Error for its deadline; wallet replies are JSON objects.
    if (error instanceof Error && error.code === 6 && error.message === 'Request expired. Please try again.') return Object.assign(new Error(walletConnectMessages[`${prefix}Timeout`]), {tone:'muted'});
    const message = localError && [walletConnectMessages.cancelled,'The QR code expired. Select Connect wallet for a new one.','Internet access for WalletConnect was turned off. Select Connect wallet to ask again.'].includes(error?.message) ? error.message : walletConnectMessages[`${prefix}Error`];
    return Object.assign(new Error(message), {tone:'muted'});
  };
  const requireNetwork = namespace => {
    const id = namespace.split(':')[1];
    if (!isWalletConnectNetwork(namespace)) throw Object.assign(new Error(walletConnectMessages.unsupportedNetwork(id)), {tone:'muted'});
    if (!approvedNetworks(provider).has(namespace)) {
      const name = networks.get(Number(id));
      throw Object.assign(new Error(walletConnectMessages.unapprovedNetwork(name)), {tone:'muted',freshConnection:true});
    }
  };
  const request = async (input, expiry, context = 'signature', signal) => {
    signal?.throwIfAborted();
    requireNetwork(`eip155:${provider.chainId}`);
    try { return await waitFor(provider.request(input, expiry),signal); }
    catch (error) { if (signal?.aborted) throw signal.reason; throw sdkError(error, context); }
  };
  const address = async signal => {
    const accounts = await request({method:'eth_accounts'},undefined,'signature',signal);
    const value = accounts?.[0];
    // eth_accounts can retain the approved namespace after a wallet notification.
    // A fresh action must match the account this window can currently display.
    const shownAccounts=observedAccounts ?? provider.accounts;
    if (Array.isArray(shownAccounts) && (!shownAccounts[0] || String(shownAccounts[0]).toLowerCase() !== String(value).toLowerCase()))
      throw muted('Select an account in your wallet.');
    if (!/^0x[0-9a-fA-F]{40}$/.test(value || '')) throw new Error('Select an account in your wallet.');
    return value;
  };
  const chain = async signal => {
    const value = await request({method:'eth_chainId'},undefined,'signature',signal);
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
    if (retiring) return retiring;
    const current = adapter, oldApi = sessionApi;
    const task = (async()=>{
      let timer;
      try {
        await Promise.race([
          Promise.resolve().then(()=>current?.disconnectWalletConnectEvm({api:oldApi})),
          new Promise(resolve=>{timer=setTimeout(resolve,5000);}),
        ]);
      } catch {} finally { clearTimeout(timer); }
    })();
    retiring = task;
    try { await task; } finally { if (retiring === task) retiring = undefined; }
  };
  const clearStored = async () => {
    if (cleanupPromise) return cleanupPromise;
    const task = (async()=>{
      try { await api('storage',{method:'DELETE'}); }
      catch (error) {
        if (error.message === 'This wallet window expired. Close it and open WalletConnect again.') throw error;
        throw muted('Home could not clear this connection. Select Connect wallet to try again.');
      }
      provider = undefined; observedAccounts = undefined; adapter = undefined; activeRevision = undefined; sessionApi = undefined;
      cleanupRequired = false; hadSession = false; sessionExpiry = 0; clearMemory();
    })();
    cleanupPromise = task;
    try { await task; } finally { if (cleanupPromise === task) cleanupPromise = undefined; }
  };
  const reset = async (reason = muted(stopped), keepAttempt) => {
    generation++;
    if (operation !== keepAttempt) operation?.abort(reason);
    restoreAttempt?.abort(reason);
    if (pairing !== keepAttempt) pairing?.abort(reason);
    provider = undefined;
    cleanupRequired = true;
    await retireAdapter();
    await clearStored();
    return {status:'disconnected'};
  };
  const prepare = async signal => {
    if (cleanupRequired) await waitFor(clearStored(),signal);
    const config = await waitFor(api('wallet/config'),signal);
    const permission = await waitFor(api('internet'),signal);
    latestPermission = permission;
    if (permission.status !== 'granted') throw muted('WalletConnect needs internet access. An admin of this Home can allow it in Inbox. Then select Connect wallet.');
    if (activeRevision !== undefined && activeRevision !== config.walletconnect.storage_revision) {
      provider = undefined;
      await waitFor(retireAdapter(),signal);
      adapter = undefined; clearMemory();
    }
    signal?.throwIfAborted();
    activeRevision = config.walletconnect.storage_revision;
    const revision = activeRevision;
    sessionApi = (resource, init={}) => api(resource, ['storage','relay-admission'].includes(resource)
      ? {...init,headers:{...init.headers,'if-match':revision}} : init);
    projectId = config.walletconnect.project_id;
    return {
      signal, contextKey:'wallet-walletconnect', projectId, chains:[1,20,8453,11155111], api:sessionApi,
      runtimeUrl:`${origin}/api/apps/wallet-walletconnect`, relayUrl:`${origin.replace(/^http/,'ws')}/api/apps/wallet-walletconnect/relay`,
      metadata:{name:'ElastOS Home',description:'Approve requests from your ElastOS Home',url:origin,icons:[]},
      copyLink,onPhase,
    };
  };
  const load = async signal => {
    if (!adapter) {
      const loaded = await waitFor(loadAdapter(),signal);
      signal?.throwIfAborted();
      if (pairingView) {
        const {connectWithView} = await import('./walletconnect-pairing.mjs');
        signal?.throwIfAborted();
        adapter = {...loaded, connectWalletConnectEvm:options => connectWithView(loaded, options, pairingView)};
      } else adapter = loaded;
    }
    return adapter;
  };
  // SDK events carry current display facts before an unrelated Home read returns.
  const connectionFacts = () => {
    let currentSession=provider?.session;
    if (currentSession?.topic && provider.signer?.client?.session?.get) {
      try { currentSession=provider.signer.client.session.get(currentSession.topic); } catch {}
    }
    if (currentSession) sessionExpiry = currentSession.expiry;
    // EthereumProvider.connected is relay connectivity, not session existence.
    // A valid wallet session remains the display identity during reconnect.
    const session = currentSession && sessionExpiry > Date.now()/1000 ? currentSession : undefined;
    const namespace = session?.namespaces?.eip155;
    const accounts = namespace?.accounts || [];
    const selected = accounts.find(value=>value.startsWith(`eip155:${provider.chainId}:`)) || accounts[0];
    const activeAddress = Array.isArray(observedAccounts) ? observedAccounts[0] : Array.isArray(provider?.accounts) ? provider.accounts[0] : selected?.split(':')[2];
    const activeChain = provider?.chainId ? `eip155:${provider.chainId}` : selected?.split(':').slice(0,2).join(':');
    return {status:session ? 'connected':'disconnected',revision:generation,removed,
      expired:hadSession && sessionExpiry <= Date.now()/1000,cleanupRequired,relayConnected:provider?.signer?.client?.core?.relayer?.connected ?? null,
      session:session ? {name:String(session.peer?.metadata?.name || 'your wallet').replace(/[\u0000-\u001f\u007f]/g,'').slice(0,80),
        chain:activeChain,address:typeof activeAddress === 'string' && /^0x[0-9a-fA-F]{40}$/.test(activeAddress) ? activeAddress : undefined} : undefined};
  };
  const changed = detail => onPhase('changed',{...detail,connection:connectionFacts()});
  const adopt = current => {
    if (current !== provider) {
      provider = current;
      observedAccounts=Array.isArray(current.accounts) ? [...current.accounts.slice(0,8)] : undefined;
      const facts=()=>`${current.chainId}:${observedAccounts === undefined ? 'unknown' : String(observedAccounts[0] || '').toLowerCase()}`;
      let selection=facts();
      const permitsProof=()=>{const ns=current.session?.namespaces?.eip155;return Boolean(ns?.accounts?.some(value=>same(value,`eip155:${current.chainId}:${observedAccounts?.[0]}`))) && (!Array.isArray(ns.methods) || ns.methods.includes('personal_sign'));};
      let proofAllowed=permitsProof();
      for (const name of ['accountsChanged','chainChanged','session_update']) current.on(name,()=>{
        if (provider !== current) return;
        if (name === 'accountsChanged') observedAccounts=Array.isArray(current.accounts) ? [...current.accounts.slice(0,8)] : [];
        else {
          const approved=(current.session?.namespaces?.eip155?.accounts || []).filter(value=>typeof value === 'string' && value.startsWith(`eip155:${current.chainId}:`)).slice(0,8).map(value=>value.split(':')[2]);
          if ((name === 'session_update' || approved.length) && !approved.some(value=>same(value,observedAccounts?.[0]))) observedAccounts=approved;
        }
        const selectionChanged=selection !== facts();selection=facts();
        const authorityChanged=proofAllowed !== permitsProof();proofAllowed=permitsProof();
        if (selectionChanged || authorityChanged) generation++;
        if ((selectionChanged || authorityChanged) && operationDispatched && operationContext !== 'transaction_intent') operation?.abort(muted(operationContext === 'link'
          ? 'Wallet changed or the challenge expired. Select Connect wallet to try again.' : walletConnectMessages.consumed));
        changed({event:name,selectionChanged});
      });
      const relayer = current.signer?.client?.core?.relayer;
      // The SignClient session store owns expiry. UniversalProvider keeps a
      // separate session snapshot and does not refresh it on session_extend.
      current.signer?.client?.on?.('session_extend',event=>{
        if (provider === current && event.topic === current.session?.topic) changed({event:'session_extend'});
      });
      // @walletconnect/core 2.23.9 RELAYER_EVENTS, not its provider's event names.
      for (const name of ['connect','disconnect']) relayer?.on?.(`relayer_${name}`,()=>{
        if (provider === current) changed({event:`relay_${name}`});
      });
      current.on('disconnect',()=>{
        if (provider !== current) return;
        generation++; removed = sessionExpiry > Date.now()/1000;
        operation?.abort(Object.assign(muted(removed ? removedMessage : 'This phone connection expired. Select Connect wallet for a new QR code.'),{walletRemoved:removed}));
        changed();
      });
    }
    if (current.session) { hadSession = true; sessionExpiry = current.session.expiry; }
    return current;
  };
  const connect = async attempt => {
    const signal = attempt.signal;
    const options = await prepare(signal);
    const currentAdapter = await load(signal);
    pairing = attempt;
    let current;
    try { current = await waitFor(currentAdapter.connectWalletConnectEvm(options),signal); }
    catch (error) { if (signal.aborted) throw signal.reason; throw sdkError(error,'proposal'); }
    finally { if (pairing === attempt) pairing = undefined; }
    signal.throwIfAborted();
    const approved = approvedNetworks(current);
    const supported = [...networks.keys()].filter(id => approved.has(`eip155:${id}`));
    if (!supported.length) { await reset(muted(noSupportedNetwork),attempt); throw new Error(noSupportedNetwork); }
    try { if (!supported.includes(current.chainId)) current.signer.setDefaultChain(`eip155:${supported[0]}`); }
    catch (error) { throw sdkError(error,'proposal'); }
    return adopt(current);
  };
  const status = async () => {
    const observedGeneration = generation;
    let read,permissionFresh=true;
    try { read=await api('internet'); }
    catch(error) {if (latestPermission?.status !== 'granted' || !provider) throw error;read=latestPermission;permissionFresh=false;}
    const permission = observedGeneration !== generation && latestPermission ? latestPermission : read;
    latestPermission = permission;
    if (permission.status !== 'granted' && (provider || pairing || operation || adapter)) {
      const clearing = reset(muted('Internet access for WalletConnect was turned off. Select Connect wallet to ask again.'));
      // Home's permission reply is a display fact; SDK retirement can take longer.
      onPhase('permission',permission);
      await clearing;
    }
    if (permission.status === 'granted' && !operation && !provider && !cleanupRequired && !restoring) {
      const attempt = restoreAttempt = new AbortController();
      restoring = (async()=>{
        const options = await prepare(attempt.signal);
        const stored = await waitFor(sessionApi('storage'),attempt.signal);
        const sessions = Object.entries(stored).find(([key])=>key.endsWith('//session'))?.[1];
        const saved = Array.isArray(sessions) ? sessions.find(session=>session.expiry > Date.now()/1000) : undefined;
        if (!saved) {
          const expired = Array.isArray(sessions) && sessions.find(session=>Number.isSafeInteger(session.expiry) && session.expiry <= Date.now()/1000);
          if (expired) { hadSession = true; sessionExpiry = expired.expiry; }
          return;
        }
        hadSession = true; sessionExpiry = saved.expiry;
        const currentAdapter = await load(attempt.signal);
        if (!currentAdapter.restoreWalletConnectEvm) return;
        const current = await waitFor(currentAdapter.restoreWalletConnectEvm(options),attempt.signal);
        attempt.signal.throwIfAborted();
        adopt(current);
        if (!current.session) removed = sessionExpiry > Date.now()/1000;
      })();
      try { await restoring; } catch (error) { if (!attempt.signal.aborted) throw error; }
      finally { if (restoreAttempt === attempt) { restoring = undefined; restoreAttempt = undefined; } }
    }
    return {...connectionFacts(),permission,permissionFresh};
  };
  return { async effect(action) {
    if (action.kind === 'disconnect' || action.kind === 'cancel') return reset();
    if (action.kind === 'status') return status();
    if (operation && !operation.signal.aborted) throw new Error('A wallet request is already active.');
    const attempt = new AbortController();
    generation++;
    operation = attempt;
    operationContext = action.kind;
    operationDispatched = false;
    const signal = attempt.signal;
    try {
    // Reuse waits for the adapter that owns the saved session. Only reset()
    // retires it; aborting restore here can disconnect Review's own provider.
    if (!(action.kind === 'link' && action.fresh) && restoring) await waitFor(restoring,signal);
    removed = false;
    if (action.kind === 'link' && action.fresh) await reset(muted(stopped),attempt);
    signal.throwIfAborted();
    await connect(attempt);
    signal.throwIfAborted();
    const revision = generation;
    const signer = await address(signal), namespace = await chain(signal);
    if (action.kind === 'link') {
      const challenge = await api('/api/auth/evm/challenge',{method:'POST',body:JSON.stringify({address:signer,chain_id:Number(namespace.split(':')[1])})});
      const check = async () => {
        signal.throwIfAborted();
        if (generation !== revision || !same(await address(signal),signer) || await chain(signal) !== namespace
          || !Number.isSafeInteger(challenge.expires_at) || challenge.expires_at <= Date.now()/1000) throw new Error('Wallet changed or the challenge expired. Select Connect wallet to try again.');
      };
      await check();
      operationDispatched = true;
      onPhase('ownership',{expiresAt:challenge.expires_at,address:signer,chain:namespace,name:String(provider.session?.peer?.metadata?.name || 'your wallet').replace(/[\u0000-\u001f\u007f]/g,'').slice(0,80)});
      const signature = await request({method:'personal_sign',params:[signData(challenge.message),signer]}, 300, 'ownership',signal);
      await check();
      await api('/api/auth/evm/verify',{method:'POST',body:JSON.stringify({message:challenge.message,signature})});
      return {status:'linked'};
    }
    if (action.kind !== 'approve') throw new Error('Unsupported wallet request.');
    const path = `wallet/approvals/${encodeURIComponent(action.approvalRequestId)}`;
    const requests = (await api('wallet/approvals')).approval_requests || [];
    const review = requests.find(r=>r.request_id === action.approvalRequestId);
    operationContext = review?.intent;
    if (!review || review.status !== 'pending') throw Object.assign(new Error(walletConnectMessages.consumed), {tone:'muted'});
    requireNetwork(review.chain_namespace);
    if (!same(review.address,signer) || review.chain_namespace !== namespace) throw new Error('Select the requested account and network in your wallet, then review again.');
    const ttl = review.expires_at - Math.ceil(Date.now()/1000);
    if (!Number.isSafeInteger(review.expires_at) || ttl <= 0 || review.intent === 'transaction_intent' && ttl < 300) throw new Error('Wallet request expires soon. Request a fresh review.');
    const supported = ['auth_challenge','browser_personal_sign','browser_typed_data_sign','capability_grant','credential','publish_envelope','protected_content_rights_signature','transaction_intent','revocation'];
    if (!supported.includes(review.intent)) throw new Error('This request type is unavailable in WalletConnect. Reject it in Wallet.');
    if (review.intent === 'browser_typed_data_sign')
      throw new Error('Typed data signing is unavailable in this connector. Reject this request in Wallet or use another account in Wallet.');
    const {handoff,binding} = await api(`${path}/approve`,{method:'POST',body:'{}'});
    if (!handoff || !binding || handoff.request_id !== action.approvalRequestId
      || handoff.payload_hash !== binding.payload_hash || !same(handoff.signer,signer)
      || binding.chain_namespace !== namespace || !/^0x[0-9a-fA-F]{64}$/.test(handoff.payload_hash || '')) throw new Error('Runtime returned an invalid wallet binding.');
    const check = async () => {
      signal.throwIfAborted();
      if (generation !== revision || !same(await address(signal),signer) || await chain(signal) !== namespace
        || !Number.isSafeInteger(binding.expires_at) || binding.expires_at <= Date.now()/1000) throw Object.assign(new Error(walletConnectMessages.consumed), {tone:'muted'});
      return Math.min(600,Math.max(binding.expires_at-Math.ceil(Date.now()/1000),300));
    };
    const expiry = await check();
    if (handoff.intent === 'transaction_intent') {
      const transaction = handoff.transaction;
      if (transaction) requireNetwork(`eip155:${Number.parseInt(transaction.chainId,16)}`);
      if (!transaction || !same(transaction.from,signer) || `eip155:${Number.parseInt(transaction.chainId,16)}` !== namespace) throw new Error('Runtime returned an invalid transaction.');
      operationDispatched = true;
      onPhase('transaction',{expiresAt:Math.floor(Date.now()/1000)+expiry,name:String(provider.session?.peer?.metadata?.name || 'your wallet').replace(/[\u0000-\u001f\u007f]/g,'').slice(0,80)});
      const hash = await request({method:'eth_sendTransaction',params:[transaction]},expiry,'transaction',signal);
      if (typeof hash !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(hash)) throw new Error('Wallet returned an invalid transaction hash. The wallet may have sent it. Check your wallet before sending again.');
      // A returned hash is retained even if the account, network or expiry changed while sending.
      let receipt;
      try { receipt = await api(`${path}/complete`,{method:'POST',body:JSON.stringify({payload_hash:handoff.payload_hash,signer,transaction_hash:hash})}); }
      catch { throw Object.assign(new Error(`Wallet returned transaction hash ${hash}. Runtime could not confirm it. Keep this hash and check it before sending again.`),{transactionHash:hash}); }
      return {status:receipt.receipt_status || 'completed',effect:'transaction',message:receipt.receipt_status === 'sent_after_dismissal' ? 'Request dismissed. Transaction sent from wallet.' : 'Transaction sent.'};
    }
    if (handoff.signature_type !== 'personal_sign' || typeof handoff.message !== 'string') throw new Error('Runtime returned an invalid signature request.');
    operationDispatched = true;
    onPhase('signature',{expiresAt:Math.floor(Date.now()/1000)+expiry,name:String(provider.session?.peer?.metadata?.name || 'your wallet').replace(/[\u0000-\u001f\u007f]/g,'').slice(0,80)});
    const method = 'personal_sign';
    const signature = await request({method,params:[signData(handoff.message),signer]},expiry,'signature',signal);
    await check();
    try { await api(`${path}/complete`,{method:'POST',body:JSON.stringify({payload_hash:handoff.payload_hash,signer,signature,signature_type:'personal_sign'})}); }
    catch (error) { if (error.message === 'This wallet window expired. Close it and open WalletConnect again.') throw error; throw Object.assign(new Error(walletConnectMessages.signatureError), {tone:'muted'}); }
    return {status:'completed',effect:'signature'};
    } finally { if (operation === attempt) operation = undefined; }
  }};
}
