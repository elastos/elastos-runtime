// One opaque document owns one temporary SDK and its Runtime transport.
import { connectWithView } from './walletconnect-pairing.mjs';
const homeOrigin=new URLSearchParams(location.search).get('home_origin');
let provider,adapter,identity,connecting=false;
const fault=code=>Object.assign(new Error(code),{code});
const reply=body=>parent.postMessage({type:'wallet-signin-transport-result',...body},homeOrigin);
const readIdentity=async()=>{
  const accounts=await provider.request({method:'eth_accounts'});
  const chain_id=Number(await provider.request({method:'eth_chainId'}));
  const address=accounts?.[0];
  if(typeof address!=='string' || !/^0x[0-9a-fA-F]{40}$/.test(address))throw fault('changed');
  if(![20,8453].includes(chain_id))throw fault('network');
  return {connector:'walletconnect',address,chain_id,network:''};
};
const check=async()=>{
  const current=await readIdentity();
  if(current.address.toLowerCase()!==identity.address.toLowerCase() || current.chain_id!==identity.chain_id)throw fault('changed');
};
async function connect(transport) {
  if(connecting || provider)throw fault('invalid');connecting=true;
  if(typeof transport?.attempt_token!=='string' || typeof transport.instance_id!=='string' || typeof transport.storage_revision!=='string')throw fault('invalid');
  const api=async(resource,init={})=>{
    if(!['wallet/config','storage','relay-admission'].includes(resource))throw fault('invalid');
    const response=await fetch(`${homeOrigin}/api/apps/wallet-walletconnect/${resource}`,{
      ...init,signal:AbortSignal.timeout(15000),headers:{'content-type':'application/json','x-elastos-wallet-attempt':transport.attempt_token,'x-elastos-wallet-instance':transport.instance_id,
        ...(['storage','relay-admission'].includes(resource)?{'if-match':transport.storage_revision}:{}),...init.headers},
    });
    if(!response.ok)throw Object.assign(new Error('Runtime transport refused'),{status:response.status});
    return response.json();
  };
  transportExpiry=Math.min(Date.now()/1000+180,transport.expires_at);
  const config=await api('wallet/config');
  adapter=await import('../vendor/reown-appkit.js');
  provider=await connectWithView(adapter,{
    contextKey:`signin-${crypto.randomUUID()}`,projectId:config.walletconnect.project_id,chains:[20,8453],api,
    runtimeUrl:`${homeOrigin}/api/apps/wallet-walletconnect`,relayUrl:`${homeOrigin.replace(/^http/,'ws')}/api/apps/wallet-walletconnect/relay`,
    metadata:{name:'ElastOS Home',description:'Sign in to your Home',url:homeOrigin,icons:[]},
  },{show:(qr,actions,uri)=>{
    reply({event:'pairing',qr,uri});
  },hide(){} });
  identity=await readIdentity();
  for(const name of ['accountsChanged','chainChanged','disconnect','session_delete'])provider.on(name,value=>{
    const same=name==='accountsChanged'?typeof value?.[0]==='string'&&value[0].toLowerCase()===identity.address.toLowerCase():name==='chainChanged'?Number(value)===identity.chain_id:false;
    if(!same)reply({event:'changed',code:['disconnect','session_delete'].includes(name)?'disconnected':'changed'});
  });
  return identity;
}
addEventListener('message',async event=>{
  if(event.source!==parent || event.origin!==homeOrigin || event.data?.type!=='wallet-signin-transport')return;
  const {id,operation,message,transport}=event.data;
  if(typeof id!=='string'||id.length>128)return;
  try {
    let result;
    if(operation==='connect')result=await connect(transport);
    else if(operation==='check') {await check();result={};}
    else if(operation==='sign' && typeof message==='string' && message.length<=32768) {
      await check();
      const data='0x'+[...new TextEncoder().encode(message)].map(b=>b.toString(16).padStart(2,'0')).join('');
      const signature=await provider.request({method:'personal_sign',params:[data,identity.address]},Math.max(1,Math.min(180,Math.ceil(transportExpiry-Date.now()/1000))));
      await check();if(typeof signature!=='string'||signature.length>16384)throw fault('invalid');
      result={signature,signature_type:'personal_sign',public_key:''};
    } else throw fault('invalid');
    reply({id,result});
  } catch(error) {reply({id,error:true,code:error.code,status:error.status});}
});
let transportExpiry=Date.now()/1000+180;
if(homeOrigin && parent!==window)reply({event:'ready'});
