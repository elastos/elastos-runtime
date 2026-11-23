import { signinBrowserWallets } from './home-wallet-connector-host.js?v=home-wallpaper-20261030b';
const fault = code => Object.assign(new Error(code),{code});
function abortable(promise,signal) {
  if(signal.aborted) {Promise.resolve(promise).catch(()=>{});return Promise.reject(fault('cancelled'));}
  let abort;
  return Promise.race([promise,new Promise((_,reject)=>{abort=()=>reject(fault('cancelled'));signal.addEventListener('abort',abort,{once:true});})])
    .finally(()=>signal.removeEventListener('abort',abort));
}
const hexMessage = text => '0x'+[...new TextEncoder().encode(text)].map(b=>b.toString(16).padStart(2,'0')).join('');
export async function selectSigninWallet(connector,options) {
  if(connector==='walletconnect') return selectWalletConnect(options);
  const {signal,changed}=options;
  let provider,name;
  if(connector==='metamask') {
    const entries=signinBrowserWallets();
    if(!entries.length)throw fault('missing');
    let preferred=entries.find(entry=>entry.rdns===(options.providerId||options.method?.providerId||'io.metamask'));
    if((options.providerId||options.method?.providerId)&&!preferred)throw fault('missing');
    if(options.method&&!options.method.providerId) {
      let accountsVisible=false;
      const matches=await abortable(Promise.all(entries.map(async entry=>{
        let timer;
        try {
          const [accounts,chain]=await Promise.race([Promise.all([entry.provider.request({method:'eth_accounts'}),entry.provider.request({method:'eth_chainId'})]),new Promise((_,reject)=>{timer=setTimeout(()=>reject(fault('missing')),1000);})]);
          if(Array.isArray(accounts)&&accounts.length)accountsVisible=true;
          return typeof accounts?.[0]==='string'&&accounts[0].toLowerCase()===options.method.address.toLowerCase()&&Number(chain)===options.method.chain_id?entry:null;
        }catch{return null;}finally{clearTimeout(timer);}
      })),signal);
      preferred=matches.find(entry=>entry?.rdns==='io.metamask')||matches.find(Boolean);
      if(!preferred&&entries.length>1)throw fault(accountsVisible?'changed':'wallet-unavailable');
    }
    const entry=preferred || (entries.length===1 ? entries[0] : null);
    if(!entry)throw fault('changed');
    provider=entry.provider;name=entry.name;
  } else {provider=window.unisat;name="UniSat";}
  if(!provider || connector==='unisat' && ['requestAccounts','getAccounts','getNetwork','signMessage'].some(key=>typeof provider[key]!=='function'))throw fault('missing');
  const request=(method,params)=>abortable(Promise.resolve().then(()=>provider.request({method,...(params?{params}:{})})),signal);
  const accounts=connector==='unisat' ? await abortable(provider.requestAccounts(),signal) : await request('eth_requestAccounts');
  const address=accounts?.[0];
  if(typeof address!=='string' || !(connector==='unisat'?/^(bc1|[13])[A-Za-z0-9]{20,100}$/:/^0x[0-9a-fA-F]{40}$/).test(address)) throw fault('changed');
  const network=connector==='unisat' ? await abortable(provider.getNetwork(),signal) : '';
  if(connector==='unisat' && network!=='livenet')throw fault('bitcoin-network');
  const chain_id=connector==='unisat' ? 0 : Number(await request('eth_chainId'));
  if(connector!=='unisat' && (!Number.isSafeInteger(chain_id)||chain_id<=0))throw fault('changed');
  const listeners=[];
  for(const event of ['accountsChanged',connector==='unisat'?'networkChanged':'chainChanged','disconnect']) {
    const listener=value=>{
      const same=event==='accountsChanged'
        ? typeof value?.[0]==='string' && (connector==='unisat'?value[0]===address:value[0].toLowerCase()===address.toLowerCase())
        : event==='chainChanged'?Number(value)===chain_id:event==='networkChanged'?value===network:false;
      if(!same)changed(event==='disconnect'?'disconnected':'changed');
    };
    provider.on?.(event,listener);listeners.push([event,listener]);
  }
  const close=()=>{for(const [event,listener]of listeners)provider.removeListener?.(event,listener);};
  signal.addEventListener('abort',close,{once:true});
  return {connector,address,chain_id,network:connector==='unisat'?'bitcoin':network,name,
    async check(){
      signal.throwIfAborted();
      const current=connector==='unisat' ? await abortable(provider.getAccounts(),signal) : await request('eth_accounts');
      const net=connector==='unisat'?await abortable(provider.getNetwork(),signal):Number(await request('eth_chainId'));
      if(typeof current?.[0]!=='string' || (connector==='unisat'?current[0]!==address:current[0].toLowerCase()!==address.toLowerCase()) || net!==(connector==='unisat'?network:chain_id))throw fault('changed');
    },
    async sign(message){
      let signature,signature_type='personal_sign',public_key='';
      if(connector==='unisat') {
        const simple=/^bc1/i.test(address);
        signature_type=simple?'bip322_simple':'bitcoin_signed_message';
        if(!simple) {
          if(typeof provider.getPublicKey!=='function')throw fault('missing');
          public_key=await abortable(provider.getPublicKey(),signal);
        }
        signature=await abortable(provider.signMessage(message,simple?'bip322-simple':'ecdsa'),signal);
      } else signature=await request('personal_sign',[hexMessage(message),address]);
      if(typeof signature!=='string'||!signature||signature.length>16384||typeof public_key!=='string'||public_key.length>4096)throw fault('invalid');
      return {signature,signature_type,public_key};
    },close};
}

function selectWalletConnect({signal,transport,pairing,changed}) {
  return new Promise((resolve,reject)=>{
    const frame=document.createElement('iframe');frame.hidden=true;frame.setAttribute('sandbox','allow-scripts');frame.title='WalletConnect';
    const origin=location.origin;
    frame.src=`/apps/wallet-walletconnect/signin-transport.html?home_origin=${encodeURIComponent(origin)}`;
    let selected=false,sequence=0;const pending=new Map();
    const close=()=>{window.removeEventListener('message',receive);signal.removeEventListener('abort',abort);frame.remove();for(const job of pending.values())job.reject(fault('cancelled'));pending.clear();};
    const abort=()=>{close();reject(fault('cancelled'));};
    const send=(operation,body={})=>new Promise((resolve,reject)=>{
      const id=String(++sequence);pending.set(id,{resolve,reject});frame.contentWindow.postMessage({type:'wallet-signin-transport',id,operation,...body},'*');
    });
    const receive=event=>{
      if(event.source!==frame.contentWindow || event.origin!=='null' || event.data?.type!=='wallet-signin-transport-result')return;
      const data=event.data;
      if(data.event==='ready') {
        send('connect',{transport}).then(wallet=>{
          selected=true;
          resolve({...wallet,check:()=>send('check'),sign:message=>send('sign',{message}),close});
        },error=>{close();reject(error);});
      } else if(data.event==='pairing' && typeof data.qr==='string' && /^data:image\/png;base64,/.test(data.qr) && data.qr.length<262144 && typeof data.uri==='string' && data.uri.startsWith('wc:') && data.uri.length<16384) pairing({qr:data.qr,uri:data.uri});
      else if(data.event==='changed') {if(selected)changed(data.code==='disconnected'?'disconnected':'changed');else {close();reject(fault('changed'));}}
      else {
        const job=pending.get(data.id);if(!job)return;pending.delete(data.id);
        if(data.error)job.reject(Object.assign(new Error('WalletConnect request failed'),{code:data.code,status:data.status}));else job.resolve(data.result);
      }
    };
    window.addEventListener('message',receive);signal.addEventListener('abort',abort,{once:true});document.body.append(frame);
    if(signal.aborted)abort();
  });
}
