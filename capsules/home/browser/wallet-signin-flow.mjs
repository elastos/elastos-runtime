// Home owns ceremonies. Signatures, secrets and retry bodies live in this tab only.
export function walletBrowserSecret() {
  return [...crypto.getRandomValues(new Uint8Array(32))].map(b=>b.toString(16).padStart(2,'0')).join('');
}
export function walletSigninOriginAllowed(value) {
  const url=new URL(value),host=url.hostname;
  return url.protocol==='https:' || url.protocol==='http:' && (host==='localhost' || host==='[::1]' || /^127\.(?:\d{1,3}\.){2}\d{1,3}$/.test(host));
}
export const connectorName = id => ({metamask:'MetaMask',walletconnect:'WalletConnect',unisat:'UniSat'})[id] || 'Wallet';
export const walletNetwork = wallet => wallet.connector === 'unisat'
  ? (wallet.network === 'bitcoin' ? 'Bitcoin' : `Bitcoin ${wallet.network}`)
  : ({20:'Elastos Smart Chain',8453:'Base',1:'Ethereum'})[wallet.chain_id] || `Network ${wallet.chain_id}`;
export const shortWalletAddress = value => value.length > 22 ? `${value.slice(0,10)}…${value.slice(-8)}` : value;
export function walletSigninError(error, action) {
  if(error?.code === 'expired') return 'This request expired. Close the old request in your wallet, then try again.';
  if(error?.code === 'changed') return 'Your wallet is using a different account or network. Try again.';
  if(error?.code === 'missing') return 'Home could not find this wallet. Open a browser with the wallet installed, or choose another wallet.';
  if(error?.code === 'network') return 'Use Elastos Smart Chain or Base with WalletConnect.';
  if(error?.code === 'bitcoin-network') return 'Switch UniSat to Bitcoin mainnet, then try again.';
  if(error?.code === 'disconnected') return 'The connection to your wallet ended. Try again.';
  if([4001,5000,5001,5002,5003].includes(Number(error?.code))) return 'Your wallet declined the request. Try again or choose another wallet.';
  if(error?.status === 429) return 'Home is busy. Try again in a moment.';
  if(error?.status === 409) return action === 'signin' ? 'This wallet cannot sign in to this Home. Use your passkey or choose another wallet.' : 'Home could not make this change. Refresh the list, then check the wallet and try again.';
  if(error?.status === 403) return action === 'signin' ? 'This wallet cannot sign in to this Home. Use your passkey or choose another wallet.' : 'Home could not approve this change. Use your own passkey and try again.';
  if(error?.status === 503) return 'The wallet connection is unavailable. Try again.';
  return action === 'signin' ? 'Home could not sign you in. Check the connection to Home, then try again.' : 'Home could not change this wallet. Check the connection to Home, then try again.';
}
const fault = code => Object.assign(new Error(code),{code});
export function createWalletSigninFlow({api,select,approve,render,onComplete=()=>{},randomSecret=walletBrowserSecret,now=()=>Date.now()/1000}) {
  let state={stage:'closed'}, run, timer;
  function show(stage, extra={}) { state={...state,...extra,stage,expiresAt:run?.deadline};render(state); }
  function live(current) { return run===current && !current.controller.signal.aborted; }
  function assertLive(current) {
    if(!live(current)) throw fault('cancelled');
    if(now()>=current.deadline) throw fault('expired');
  }
  function stopLocal(current) { current.controller.abort();current.wallet?.close?.(); }
  async function clear(current) {
    if(!current) return;
    stopLocal(current);
    await Promise.allSettled([...current.ceremonies].map(([ceremony_id,browser_secret])=>api('/api/auth/wallet/cancel',{ceremony_id,browser_secret})));
  }
  function deadline(current, expires) {
    if(!Number.isFinite(expires) || expires<=now()) throw fault('expired');
    current.deadline=Math.min(current.deadline,expires);clearTimeout(timer);
    timer=setTimeout(()=>{
      if(!live(current))return;
      show('error',{message:walletSigninError(fault('expired'),state.action)});
      run=null;void clear(current);
    },Math.max(0,(current.deadline-now())*1000));
  }
  async function begin(current,path,body) {
    const secret=current.secret;
    const result=await api(path,{...body,browser_secret:secret});
    if(typeof result?.ceremony_id!=='string' || !result.ceremony_id || result.ceremony_id.length>256) throw fault('invalid');
    current.ceremonies.set(result.ceremony_id,secret);
    if(!live(current)) { await clear(current);throw fault('cancelled'); }
    deadline(current,result.expires_at);
    return result;
  }
  async function prepare(current,connector) {
    show('connecting',{connector});
    try {
      const method=state.method;
      let ceremony;
      if(state.action!=='signin' && state.action!=='add') {
        ceremony=await begin(current,'/api/auth/wallet-methods/begin',{action:state.action,method_id:method.method_id});
        current.target=method;
      }
      if(['signin','add','enable'].includes(state.action)) {
        let transport=ceremony;
        if(connector==='walletconnect' && !transport) transport=await begin(current,'/api/auth/wallet/signin/begin',{connector,address:'',chain_id:20,network:''});
        current.wallet=await select(connector,{
          signal:current.controller.signal,transport,
          pairing:pairing=>{if(live(current))show('pairing',{pairing});},
          choices:choices=>{if(live(current))show('wallet-choice',{choices});},
          changed:(code='changed')=>{
            if(!live(current))return;
            // A dispatched proof may already be committed. Keep its exact retry body.
            if(current.completion){current.wallet?.close?.();current.wallet=null;return;}
            show('error',{message:walletSigninError(fault(code),state.action)});run=null;clearTimeout(timer);void clear(current);
          },
        });
        assertLive(current);
        const wallet=current.wallet;
        const identity={connector,address:wallet.address,chain_id:wallet.chain_id,network:wallet.network};
        if(method && ((connector==='unisat'?wallet.address!==method.address:wallet.address.toLowerCase()!==method.address.toLowerCase()) || wallet.chain_id!==method.chain_id || wallet.network!==method.network)) throw fault('changed');
        current.target=method || identity;
        if(state.action==='signin') {
          ceremony=connector==='walletconnect'
            ? await api('/api/auth/wallet/signin/select',{ceremony_id:transport.ceremony_id,browser_secret:current.secret,address:wallet.address,chain_id:wallet.chain_id})
            : await begin(current,'/api/auth/wallet/signin/begin',identity);
          if(connector==='walletconnect') { ceremony={...transport,...ceremony};deadline(current,ceremony.expires_at); }
        } else if(state.action==='add') {
          if(connector==='walletconnect')current.secret=randomSecret();
          ceremony=await begin(current,'/api/auth/wallet-methods/begin',{action:'add',...identity});
        }
      }
      assertLive(current);
      if(!ceremony || typeof ceremony.message!=='string' || ceremony.message.length>32768 || ['signin','add','enable'].includes(state.action)&&!ceremony.message) throw fault('invalid');
      if(state.action!=='signin') {
        const approval=ceremony.approval, request=approval?.request;
        if(approval?.operation!=='auth.wallet.method' || request?.ceremony_id!==ceremony.ceremony_id || request?.action!==state.action
          || typeof request.account_id!=='string' || !request.account_id || typeof request.method_id!=='string' || !request.method_id
          || state.accountId && request.account_id!==state.accountId
          || state.action!=='add' && request.method_id!==state.method.method_id) throw fault('invalid');
      }
      current.ceremony=ceremony;
      show('review',{wallet:{...current.target,displayName:current.wallet?.name},message:'',signingMessage:ceremony.message,approvalNotice:typeof ceremony.approval?.notice==='string'?ceremony.approval.notice.slice(0,4096):''});
    } catch(error) { fail(current,error); }
  }
  function fail(current,error) {
    if(!live(current))return;
    show('error',{message:walletSigninError(error,state.action),refresh:error?.status===409 && state.action!=='signin'});
    run=null;clearTimeout(timer);void clear(current);
  }
  async function complete(current) {
    assertLive(current);show('completing');
    try {
      const result=await api(state.action==='signin'?'/api/auth/wallet/signin/complete':'/api/auth/wallet-methods/complete',JSON.parse(current.completion));
      if(!live(current))return;
      if(state.action==='signin' ? !result?.app_token || !result?.session_id || !result?.principal_id || !result?.proof_binding_id
        : result?.status!==(state.action==='remove'?'removed':'complete') || result?.method_id!==current.ceremony.approval.request.method_id
          || state.action!=='remove' && result.sign_in_enabled!==(state.action==='enable')) throw fault('invalid');
      clearTimeout(timer);run=null;stopLocal(current);
      // Runtime keeps the completed method/session; cancel ends temporary transport.
      void clear(current);
      show('done',{result});await onComplete(result,state.action);
    } catch(error) {
      if(!live(current))return;
      if(error?.status && error.status<500)fail(current,error);
      else show('unknown',{message:state.action==='signin'?'Home has not confirmed sign-in. Check again with this same request.':'Home has not confirmed the change. Check again before starting another request.'});
    }
  }
  return {
    get state(){return state;},
    async start({action='signin',method=null,account='',accountId='',token='' }={}) {
      const previous=run;run=null;clearTimeout(timer);void clear(previous);
      const current=run={secret:randomSecret(),controller:new AbortController(),ceremonies:new Map(),deadline:now()+180};
      state={stage:'choice',action,method,account,accountId,token};show('choice');deadline(current,current.deadline);
      if(method && live(current)) await prepare(current,method.connector);
    },
    async choose(connector) { if(run && state.stage==='choice' && ['metamask','walletconnect','unisat'].includes(connector))await prepare(run,connector); },
    async confirm() {
      const current=run;if(!current || state.stage!=='review')return;
      try {
        assertLive(current);
        if(['signin','add','enable'].includes(state.action)) {
          show('signing');await current.wallet.check();assertLive(current);
          current.proof=await current.wallet.sign(current.ceremony.message);assertLive(current);await current.wallet.check();assertLive(current);
        }
        if(state.action==='signin') {
          current.completion=JSON.stringify({ceremony_id:current.ceremony.ceremony_id,browser_secret:current.secret,...current.proof});
          await complete(current);
        } else if(['disable','remove'].includes(state.action)) await this.approve();
        else show('approval');
      } catch(error) { fail(current,error); }
    },
    async approve() {
      const current=run;if(!current || !['review','signing','approval'].includes(state.stage))return;
      try {
        assertLive(current);show('passkey');
        const step_up_token=await approve(current.ceremony.approval,{signal:current.controller.signal});assertLive(current);
        if(current.wallet) {
          try {await current.wallet.check();assertLive(current);}
          catch(error){fail(current,error);return;}
        }
        current.completion=JSON.stringify({ceremony_id:current.ceremony.ceremony_id,browser_secret:current.secret,...current.proof,step_up_token});
        await complete(current);
      } catch(error) {
        if(!live(current))return;
        if(error?.code==='expired')fail(current,error);
        else show('approval',{message:'Home could not confirm your passkey. Use passkey to try again, or cancel.'});
      }
    },
    async retry() { if(run && state.stage==='unknown')try{await complete(run);}catch(error){fail(run,error);} },
    async cancel() { const current=run;run=null;clearTimeout(timer);show('closed');await clear(current); },
  };
}
