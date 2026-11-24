// Home ends management before the requesting capsule stops waiting.
export const walletSigninRequestTimeoutMs=420000;
export async function readWalletSigninMethods(token,{origin}={}) {
  if(origin) {
    const result=await requestWalletSigninChange({action:'list',token,origin});
    if(result?.status!=='complete'||typeof result.account_id!=='string'||!Array.isArray(result.methods))throw new Error('Home could not load sign-in methods.');
    return result;
  }
  const response=await fetch('/api/auth/wallet-methods',{cache:'no-store',signal:AbortSignal.timeout(15000),headers:{'x-elastos-home-token':token}});
  if(!response.ok)throw new Error('Home could not load sign-in methods.');
  const result=await response.json();
  if(typeof result.account_id!=='string'||!Array.isArray(result.methods)||result.methods.length>256)throw new Error('Home could not load sign-in methods.');
  return result;
}
export function requestWalletSigninChange({action,methodId='',token,origin,loadConnected}) {
  if(window.top===window || !token || !origin)return Promise.reject(new Error('Open this app from Home to change wallet sign-in.'));
  const requestId=crypto.randomUUID();
  return new Promise((resolve,reject)=>{
    const timeout=setTimeout(()=>{window.removeEventListener('message',receive);resolve({status:'unknown'});},walletSigninRequestTimeoutMs);
    const receive=event=>{
      if(event.source!==window.top||event.origin!==origin||event.data?.requestId!==requestId)return;
      if(event.data.type==='home:wallet-signin-accounts-request' && action==='add' && typeof loadConnected==='function'
        && Object.keys(event.data).length===2 && event.ports?.length===1) {
        const port=event.ports[0];
        Promise.resolve().then(loadConnected).then(accounts=>port.postMessage({accounts}),()=>port.postMessage({failed:true})).finally(()=>port.close());
        return;
      }
      if(event.data?.type!=='home:wallet-signin-result')return;
      clearTimeout(timeout);window.removeEventListener('message',receive);resolve(event.data.result);
    };
    window.addEventListener('message',receive);
    window.top.postMessage({type:'home:wallet-signin-request',requestId,homeToken:token,action,methodId},origin);
  });
}
function text(tag,value,className) {const el=document.createElement(tag);el.textContent=value;if(className)el.className=className;return el;}
export function walletSigninControls(method,{onAction,buttonClass=''}) {
  const controls=text('div','','signin-method-controls');
  const remove=text('button','Remove',buttonClass);remove.type='button';remove.onclick=()=>onAction('remove',method.method_id);controls.append(remove);
  return controls;
}

export function watchWalletSigninMethods(refresh,origin) {
  window.addEventListener('focus',()=>void refresh());
  document.addEventListener('visibilitychange',()=>{if(document.visibilityState==='visible')void refresh();});
  window.addEventListener('message',event=>{
    if(event.source===window.top && event.origin===origin && event.data?.type==='home:wallet-signin-changed' && Object.keys(event.data).length===1)void refresh();
  });
}

export function connectedWalletSigninMethods(accounts,methods) {
  const result=methods.map(method=>({...method,paymentConnected:false}));
  for(const account of accounts) {
    const connector=({'wallet-metamask':'metamask','wallet-walletconnect':'walletconnect','wallet-unisat':'unisat'})[account.connector_id];
    if(!connector || typeof account.address!=='string' || ['managed_evm','managed_btc_p2wpkh'].includes(account.proof_type))continue;
    const chain_id=connector==='unisat'?0:Number(account.chain_namespace?.split(':')[1]);
    if(connector!=='unisat' && (!Number.isSafeInteger(chain_id)||chain_id<=0))continue;
    const network=connector==='unisat'?'bitcoin':'';
    const existing=result.find(row=>(connector==='unisat'?row.address===account.address:row.address.toLowerCase()===account.address.toLowerCase())&&row.chain_id===chain_id&&row.network===network);
    if(existing){existing.paymentConnected=true;continue;}
    const displayName=typeof account.wallet_display_name==='string'&&account.wallet_display_name.length<=80&&!/[\p{Cc}\p{Cf}]/u.test(account.wallet_display_name)?account.wallet_display_name:undefined;
    const providerId=typeof account.provider_id==='string'&&account.provider_id.length<=128&&/^[a-z0-9]+(?:\.[a-z0-9-]+)+$/.test(account.provider_id)?account.provider_id:undefined;
    result.push({connector,address:account.address,chain_id,network,...(displayName?{displayName}:{}),...(providerId?{providerId}:{}),sign_in_enabled:false,method_id:`payment:${account.account_id}`,paymentOnly:true,paymentConnected:true,last_used_at:null});
  }
  return result;
}

// System reads its own accounts. Home receives data through a request-bound port.
export function requestConnectedSigninWallets(source,requestId,{timeoutMs=15000}={}) {
  return new Promise((resolve,reject)=>{
    const channel=new MessageChannel();
    const finish=(error,accounts)=>{clearTimeout(timeout);channel.port1.close();channel.port2.close();error?reject(error):resolve(accounts);};
    const timeout=setTimeout(()=>finish(new Error('System could not load your wallets.')),timeoutMs);
    channel.port1.onmessage=event=>{
      const accounts=event.data?.accounts;
      if(!Array.isArray(accounts)||accounts.length>256)return finish(new Error('System could not load your wallets.'));
      finish(null,accounts);
    };
    source.postMessage({type:'home:wallet-signin-accounts-request',requestId},'*',[channel.port2]);
  });
}
