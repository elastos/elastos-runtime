import {connectorName,walletNetwork,shortWalletAddress} from './wallet-signin-flow.mjs';
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
export function requestWalletSigninChange({action,methodId='',wallet,token,origin}) {
  if(window.top===window || !token || !origin)return Promise.reject(new Error('Open this app from Home to change wallet sign-in.'));
  const requestId=crypto.randomUUID();
  return new Promise((resolve,reject)=>{
    const timeout=setTimeout(()=>{window.removeEventListener('message',receive);reject(new Error('Home stopped waiting. Refresh the sign-in methods before trying again.'));},200000);
    const receive=event=>{
      if(event.source!==window.top||event.origin!==origin||event.data?.type!=='home:wallet-signin-result'||event.data.requestId!==requestId)return;
      clearTimeout(timeout);window.removeEventListener('message',receive);resolve(event.data.result);
    };
    window.addEventListener('message',receive);
    window.top.postMessage({type:'home:wallet-signin-request',requestId,homeToken:token,action,methodId,...(wallet?{wallet:{connector:wallet.connector,address:wallet.address,chain_id:wallet.chain_id,network:wallet.network}}:{})},origin);
  });
}
function text(tag,value,className) {const el=document.createElement(tag);el.textContent=value;if(className)el.className=className;return el;}
function used(at) {return at?new Date(at*1000).toLocaleString():'Not used yet';}
export function walletSigninControls(method,{canManage,onAction,buttonClass=''}) {
  const controls=text('div','','signin-method-controls');
  if(method.paymentOnly) {
    const add=text('button','Add wallet',buttonClass);add.type='button';add.disabled=!canManage;add.onclick=()=>onAction('add',method.method_id);controls.append(add);
    if(!canManage)controls.append(text('small','Only an Admin can add a wallet.','signin-method-note'));
  } else {
    controls.append(text('small','Signs in','signin-method-note'));
    const remove=text('button','Remove',buttonClass);remove.type='button';remove.onclick=()=>onAction('remove',method.method_id);controls.append(remove);
  }
  return controls;
}
export function renderWalletSigninCards(mount,methods,options) {
  mount.replaceChildren();
  if(!methods.length)mount.append(text('p','Add a wallet in System, Accounts to use it for sign-in.','signin-method-note'));
  for(const method of methods) {
    const card=text('div','','signin-method-card');card.dataset.walletMethod=method.method_id;
    card.append(text('strong',connectorName(method.connector)),text('p',`${shortWalletAddress(method.address)} · ${walletNetwork(method)}`,'signin-method-note'),text('p',`Last used: ${used(method.last_used_at)}`,'signin-method-note'),walletSigninControls(method,options));card.title=method.address;mount.append(card);
  }
}

export function watchWalletSigninMethods(refresh,origin) {
  document.addEventListener('visibilitychange',()=>{if(document.visibilityState==='visible')void refresh();});
  window.addEventListener('message',event=>{
    if(event.source===window.top && event.origin===origin && event.data?.type==='home:wallet-signin-changed' && Object.keys(event.data).length===1)void refresh();
  });
}

export function connectedWalletSigninMethods(accounts,methods) {
  const result=[...methods];
  for(const account of accounts) {
    const connector=({'wallet-metamask':'metamask','wallet-walletconnect':'walletconnect','wallet-unisat':'unisat'})[account.connector_id];
    if(!connector || typeof account.address!=='string')continue;
    const chain_id=connector==='unisat'?0:Number(account.chain_namespace?.split(':')[1]);
    if(connector!=='unisat' && (!Number.isSafeInteger(chain_id)||chain_id<=0))continue;
    const network=connector==='unisat'?'bitcoin':'';
    if(result.some(row=>(connector==='unisat'?row.address===account.address:row.address.toLowerCase()===account.address.toLowerCase())&&row.chain_id===chain_id&&row.network===network))continue;
    result.push({connector,address:account.address,chain_id,network,sign_in_enabled:false,method_id:`payment:${account.account_id}`,paymentOnly:true,last_used_at:null});
  }
  return result;
}
