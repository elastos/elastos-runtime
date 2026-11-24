// One opaque document owns one temporary SDK and its Runtime transport.
import { walletConnectPeerName } from './walletconnect-client.mjs';
import { connectWithView } from './walletconnect-pairing.mjs';
import { createSigninTransportApi } from './signin-transport-api.mjs';
import { installWalletConnectStorage } from './walletconnect-storage.mjs';
const clearMemory = installWalletConnectStorage(window);
addEventListener('pagehide', clearMemory, {once:true});
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
  const name=walletConnectPeerName(provider.session?.peer?.metadata?.name);
  return {connector:'walletconnect',address,chain_id,network:'',...(name?{name}:{})};
};
const check=async()=>{
  const current=await readIdentity();
  if(current.address.toLowerCase()!==identity.address.toLowerCase() || current.chain_id!==identity.chain_id)throw fault('changed');
};
async function connect(transport) {
  if(connecting || provider)throw fault('invalid');connecting=true;
  if(typeof transport?.attempt_token!=='string' || typeof transport.instance_id!=='string' || (!Number.isSafeInteger(transport.storage_revision)||transport.storage_revision<0))throw fault('invalid');
  const api=createSigninTransportApi(homeOrigin,transport);
  const config=await api('wallet/config');
  adapter=await import('./vendor/reown-appkit.js');
  provider=await connectWithView(adapter,{
    contextKey:`signin-${crypto.randomUUID()}`,projectId:config.walletconnect.project_id,chains:[20,8453],api,authenticationOnly:true,
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
      // The SDK accepts request expiry from 300 seconds; use that minimum. Runtime and
      // the Home flow enforce the shorter ceremony deadline and retire this frame.
      const signature=await provider.request({method:'personal_sign',params:[data,identity.address]},300);
      await check();if(typeof signature!=='string'||signature.length>16384)throw fault('invalid');
      result={signature,signature_type:'personal_sign',public_key:''};
    } else throw fault('invalid');
    reply({id,result});
  } catch(error) {reply({id,error:true,code:error.code,status:error.status});}
});
if(homeOrigin && parent!==window)reply({event:'ready'});
