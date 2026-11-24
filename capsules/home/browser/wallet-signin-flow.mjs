// Home owns ceremonies. Signatures, secrets and retry bodies live in this tab only.
export function walletBrowserSecret() {
  return [...crypto.getRandomValues(new Uint8Array(32))].map(b=>b.toString(16).padStart(2,'0')).join('');
}
export function walletSigninOriginAllowed(value) {
  const url=new URL(value),host=url.hostname;
  return url.protocol==='https:' || url.protocol==='http:' && (host==='localhost' || host==='[::1]' || /^127\.(?:\d{1,3}\.){2}\d{1,3}$/.test(host));
}
export const connectorName = id => ({metamask:'MetaMask',walletconnect:'Phone wallet',unisat:'UniSat'})[id] || 'Wallet';
export const walletNetwork = wallet => wallet.connector === 'unisat'
  ? (wallet.network === 'bitcoin' ? 'Bitcoin' : `Bitcoin ${wallet.network}`)
  : ({20:'Elastos Smart Chain',8453:'Base',1:'Ethereum',11155111:'Sepolia'})[wallet.chain_id] || `Network ${wallet.chain_id}`;
export const shortWalletAddress = value => value.length > 16 ? `${value.slice(0,6)}…${value.slice(-4)}` : value;
export function walletSigninError(error, action) {
  if(error?.code === 'status-unavailable')return 'Home could not check wallet sign-in; check the connection, then try again.';
  if(error?.code === 'already-added')return 'Choose another account because this wallet already signs in to this Home.';
  if(error?.code === 'expired') return 'Close the expired request in your wallet, then select Try again.';
  if(error?.code === 'changed') return 'Your wallet is using a different account or network; select Try again.';
  if(error?.code === 'wallet-unavailable') return 'Open the wallet with this account, then try again.';
  if(error?.code === 'permission') return 'Allow phone wallet internet access in Inbox, then try again.';
  if(error?.code === 'missing') return 'Choose another wallet or use a browser with this wallet installed.';
  if(error?.code === 'network') return 'Use Elastos Smart Chain or Base with your phone wallet.';
  if(error?.code === 'bitcoin-network') return 'Switch UniSat to Bitcoin mainnet, then try again.';
  if(error?.code === 'disconnected') return 'The connection to your wallet ended; select Try again.';
  if([4001,5000,5001,5002,5003].includes(Number(error?.code))) return 'Your wallet declined the request; select Try again or choose another wallet.';
  if(error?.status === 429) return 'Home is busy; select Try again in a moment.';
  if(error?.status === 409) return action === 'signin' ? 'Use your passkey or choose another wallet because this wallet cannot sign in to this Home.' : 'Home could not make this change; choose your wallet again.';
  if(error?.status === 403) return action === 'signin' ? 'Use your passkey or choose another wallet because this wallet cannot sign in to this Home.' : 'Home could not approve this change; use your own passkey and try again.';
  if(error?.status === 503) return 'The wallet connection is unavailable; select Try again.';
  return action === 'signin' ? 'Check the connection to Home, then select Try again to sign in.' : 'Check the connection to Home, then select Try again to change this wallet.';
}
const fault = code => Object.assign(new Error(code),{code});
export function createWalletSigninFlow({api,select,approve,render,onComplete=()=>{},randomSecret=walletBrowserSecret,now=()=>Date.now()/1000}) {
  let state={stage:'closed'}, run, timer, controls;
  function show(stage, extra={}) { state={...state,message:'',...extra,stage,expiresAt:run?.deadline};render(state); }
  function live(current) { return run===current && !current.controller.signal.aborted; }
  function assertLive(current) {
    if(!live(current)) throw fault('cancelled');
    if((current.effect==='open'||state.action==='signin') && now()>=current.deadline) throw fault('expired');
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
      if(state.action!=='signin' && current.effect!=='open') {
        if(current.effect==='unknown')void reconcile(current);
        return;
      }
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
      if(['signin','add'].includes(state.action)) {
        let transport=ceremony;
        if(connector==='walletconnect' && !transport && !state.delegateWalletConnect) transport=await begin(current,['add'].includes(state.action)?'/api/auth/wallet-methods/begin':'/api/auth/wallet/signin/begin',{
          ...(['add'].includes(state.action)?{action:state.action}:{}),connector,address:'',chain_id:20,network:'',allow_temporary_internet:true,
        });
        current.wallet=await select(connector,{
          signal:current.controller.signal,transport,method,providerId:state.providerId,action:state.action,
          pairing:pairing=>{if(live(current))show('pairing',{pairing});},
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
        if(connector==='walletconnect' && transport && ['signin','add'].includes(state.action)) {
          const selected=await api('/api/auth/wallet/signin/select',{ceremony_id:transport.ceremony_id,browser_secret:current.secret,address:wallet.address,chain_id:wallet.chain_id});
          assertLive(current);
          if(selected.ceremony_id!==transport.ceremony_id)throw fault('invalid');
          ceremony={...transport,...selected};deadline(current,ceremony.expires_at);
        } else if(state.action==='signin') {
          ceremony=await begin(current,'/api/auth/wallet/signin/begin',identity);
        } else if(['add'].includes(state.action)) {
          ceremony=await begin(current,'/api/auth/wallet-methods/begin',{action:state.action,...identity,...(connector==='walletconnect'?{allow_temporary_internet:true}:{})});
        }
      }
      assertLive(current);
      if(!ceremony || typeof ceremony.message!=='string' || ceremony.message.length>32768 || ['signin','add'].includes(state.action)&&!ceremony.message) throw fault('invalid');
      if(state.action!=='signin') {
        const approval=ceremony.approval, request=approval?.request;
        if(approval?.operation!=='auth.wallet.method' || request?.ceremony_id!==ceremony.ceremony_id || request?.action!==state.action
          || typeof request.account_id!=='string' || !request.account_id || typeof request.method_id!=='string' || !request.method_id
          || state.accountId && request.account_id!==state.accountId
          || !['add'].includes(state.action) && request.method_id!==state.method.method_id) throw fault('invalid');
      }
      current.ceremony=ceremony;
      show('review',{wallet:{...current.target,displayName:current.wallet?.name},message:'',signingMessage:ceremony.message,approvalNotice:state.action!=='signin'&&typeof ceremony.approval?.notice==='string'?ceremony.approval.notice.slice(0,4096):''});
      if(state.automatic)await controls.confirm();
    } catch(error) { fail(current,error); }
  }
  function fail(current,error) {
    if(!live(current))return;
    show('error',{message:walletSigninError(error,state.action),refresh:error?.status===409 && state.action!=='signin'});
    run=null;clearTimeout(timer);void clear(current);
  }
  function unknown(current) {
    current.effect='unknown';if(state.action!=='signin')clearTimeout(timer);
    show('unknown',{message:state.action==='signin'?'Home has not confirmed sign-in; select Check again.':'Home has not confirmed the change; select Check again.'});
  }
  async function reconcile(current) {
    if(!live(current) || current.effect==='dispatched' || current.reading)return;
    current.reading=true;
    try {
      const list=await api('/api/auth/wallet-methods');
      if(!live(current))return;
      const request=current.ceremony.approval.request;
      if(list?.account_id!==request.account_id || !Array.isArray(list.methods) || list.methods.length>256)throw fault('invalid');
      const method=list.methods.find(m=>m.method_id===request.method_id);
      const applied=state.action==='add'?method?.sign_in_enabled===true:!method;
      if(applied) {
        const result={status:state.action==='remove'?'removed':'complete',method_id:request.method_id,sign_in_enabled:state.action==='add'};
        current.effect='done';void current.wallet?.complete?.().catch(()=>{});clearTimeout(timer);run=null;stopLocal(current);
        show('done',{result});await onComplete(result,state.action);
      } else if(Array.isArray(list.open_changes) && list.open_changes.length<=64
        && list.open_changes.every(id=>typeof id==='string'&&id.length<=256)
        && !list.open_changes.includes(current.ceremony.ceremony_id)) {
        current.effect='not-applied';clearTimeout(timer);run=null;stopLocal(current);
        show('error',{message:'Home did not save this change.'});
      } else unknown(current);
    } catch { if(live(current))unknown(current); }
    finally {current.reading=false;}
  }
  async function complete(current) {
    assertLive(current);show('completing');current.effect='dispatched';
    try {
      const result=await api(state.action==='signin'?'/api/auth/wallet/signin/complete':'/api/auth/wallet-methods/complete',JSON.parse(current.completion));
      if(!live(current))return;
      if(state.action!=='signin') {current.effect='unknown';await reconcile(current);return;}
      if(!result?.app_token || !result?.session_id || !result?.principal_id || !result?.proof_binding_id) throw fault('invalid');
      void current.wallet?.complete?.().catch(()=>{});clearTimeout(timer);run=null;stopLocal(current);
      // Runtime retires the transport. Cancel would revoke the confirmed session.
      show('done',{result});await onComplete(result,state.action);
    } catch(error) {
      if(!live(current))return;
      if(state.action!=='signin') {
        current.effect='unknown';await reconcile(current);
      } else if(error?.status && error.status<500)fail(current,error);
      else unknown(current);
    }
  }
  return controls={
    get state(){return state;},
    async start({action='signin',method=null,account='',accountId='',token='',automatic=false,delegateWalletConnect=false,providerId='' }={}) {
      if(!['signin','add','remove'].includes(action))throw fault('invalid');
      if(run && run.effect!=='open' && state.action!=='signin')throw fault('busy');
      const previous=run;run=null;clearTimeout(timer);void clear(previous);
      const current=run={secret:randomSecret(),controller:new AbortController(),ceremonies:new Map(),deadline:now()+180,effect:'open'};
      state={stage:'choice',action,method,account,accountId,token,automatic,delegateWalletConnect,providerId,walletconnectAvailable:action==='signin'?null:true};show('choice');deadline(current,current.deadline);
      if(action==='signin') {
        let available=null;
        try {const status=await api('/api/auth/passkey/status');available=typeof status?.walletconnect_signin_available==='boolean'?status.walletconnect_signin_available:null;}catch{}
        if(!live(current))return;
        state={...state,walletconnectAvailable:available};
        if(state.stage==='choice')show('choice');
      }
      if(method && live(current))await prepare(current,method.connector);
    },
    async choose(connector) {
      if(!run || state.stage!=='choice' || !['metamask','walletconnect','unisat'].includes(connector))return;
      if(connector==='walletconnect') {
        if(state.walletconnectAvailable!==true){fail(run,state.walletconnectAvailable===null?fault('status-unavailable'):{status:403});return;}
        await prepare(run,connector);
      } else await prepare(run,connector);
    },
    async confirm() {
      const current=run;if(!current || state.stage!=='review')return;
      try {
        assertLive(current);
        if(['signin','add'].includes(state.action)) {
          show('signing');await current.wallet.check();assertLive(current);
          current.proof=await current.wallet.sign(current.ceremony.message);assertLive(current);await current.wallet.check();assertLive(current);
        }
        if(state.action==='signin') {
          current.completion=JSON.stringify({ceremony_id:current.ceremony.ceremony_id,browser_secret:current.secret,...current.proof});
          await complete(current);
        } else if(state.action==='remove') {show('approval');await this.approve();}
        else {show('approval');if(state.automatic)await controls.approve();}
      } catch(error) { fail(current,error); }
    },
    async approve() {
      const current=run;if(!current || state.stage!=='approval')return;
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
        else show('approval',{message:'Home could not confirm your passkey; select Use passkey or Cancel.'});
      }
    },
    async retry() { if(run && state.stage==='unknown')try{if(state.action==='signin')await complete(run);else await reconcile(run);}catch(error){fail(run,error);} },
    async cancel() { if(run && state.action!=='signin' && run.effect!=='open')return;const current=run;run=null;clearTimeout(timer);show('closed');await clear(current); },
  };
}
