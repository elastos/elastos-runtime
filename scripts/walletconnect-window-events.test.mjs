import test from 'node:test';
import assert from 'node:assert/strict';
import {EventEmitter} from 'node:events';
import {createWalletConnectClient} from '../capsules/wallet-walletconnect/browser/walletconnect-client.mjs';
const address='0x'+'12'.repeat(20),other='0x'+'34'.repeat(20);
async function fixture(state){
 const relayer=Object.assign(new EventEmitter(),{connected:true});
 const provider=Object.assign(new EventEmitter(),{chainId:8453,accounts:[address],connected:true,
  session:{expiry:Math.floor(Date.now()/1000)+3600,peer:{metadata:{name:'Event test wallet'}},namespaces:{eip155:{accounts:[`eip155:8453:${address}`,`eip155:1:${address}`]}}},
  signer:{client:{core:{relayer}}}});
 let hold=false,reply,started,verified=0,completed=0;
 let reached=new Promise(resolve=>{started=resolve;});
 provider.request=async({method})=>{
  if(method==='eth_accounts')return provider.accounts;
  if(method==='eth_chainId')return provider.chainId;
  if(hold){started();return new Promise(resolve=>{reply=resolve;});}
  return '0x'+'ab'.repeat(65);
 };
 const api=async(path)=>{
  if(path==='internet')return {status:'granted'};
  if(path==='wallet/config')return {walletconnect:{project_id:'fixture-project',storage_revision:'"0"'}};
  if(path==='storage')return {};
  if(path.endsWith('/challenge'))return {message:'Event proof',expires_at:Math.floor(Date.now()/1000)+300};
  if(path.endsWith('/verify')){verified++;return {};}
  if(path==='wallet/approvals')return {approval_requests:[{request_id:'event-request',status:'pending',address,chain_namespace:'eip155:8453',intent:'credential',expires_at:Math.floor(Date.now()/1000)+600}]};
  if(path.endsWith('/approve'))return {handoff:{request_id:'event-request',payload_hash:'0x'+'45'.repeat(32),signer:address,intent:'credential',signature_type:'personal_sign',message:'Event message'},binding:{payload_hash:'0x'+'45'.repeat(32),chain_namespace:'eip155:8453',expires_at:Math.floor(Date.now()/1000)+600}};
  if(path.endsWith('/complete')){completed++;return {};}
  throw Error('Unexpected API');
 };
 const phases=[];
 const client=createWalletConnectClient({api,origin:'http://localhost',onPhase:(phase,detail)=>phases.push({phase,event:detail?.event}),loadAdapter:async()=>({connectWalletConnectEvm:async()=>provider,disconnectWalletConnectEvm:async()=>{}})});
 await client.effect({kind:'link'});
 let pending;
 if(state==='ownership'||state==='signature'){
  hold=true;pending=client.effect(state==='ownership'?{kind:'link'}:{kind:'approve',approvalRequestId:'event-request'}).then(result=>({result}),error=>({error:error.message}));await reached;
 }
 if(state==='result')await client.effect({kind:'approve',approvalRequestId:'event-request'});
 return {client,provider,relayer,phases,get verified(){return verified;},get completed(){return completed;},async answer(){reply?.('0x'+'ab'.repeat(65));return pending?await pending:null;}};
}
for(const state of ['idle','ownership','signature','result'])for(const event of ['accountsChanged','emptyAccounts','chainChanged','unsupportedChain','session_update','disconnect','expiry','relay_drop_return'])test(`wallet ${event} is observed in ${state}`,async()=>{
 const r=await fixture(state),before={verified:r.verified,completed:r.completed};
 if(event==='accountsChanged'||event==='emptyAccounts'){r.provider.accounts=event==='emptyAccounts'?[]:[other];r.provider.emit('accountsChanged',r.provider.accounts);}
 if(event==='chainChanged'||event==='unsupportedChain'){r.provider.chainId=event==='chainChanged'?1:137;r.provider.emit('chainChanged','0x'+r.provider.chainId.toString(16));}
 if(event==='session_update')r.provider.emit('session_update',{});
 if(event==='disconnect'){r.provider.connected=false;r.provider.emit('disconnect',{});}
 if(event==='expiry'){r.provider.session.expiry=Math.floor(Date.now()/1000)-1;await r.client.effect({kind:'status'});r.provider.connected=false;r.provider.emit('disconnect',{});}
 if(event==='relay_drop_return'){r.relayer.connected=false;r.relayer.emit('disconnect');assert.equal((await r.client.effect({kind:'status'})).relayConnected,false);r.relayer.connected=true;r.relayer.emit('connect');}
 const status=await r.client.effect({kind:'status'});
 if(event==='accountsChanged')assert.equal(status.session.address,other);
 if(event==='emptyAccounts')assert.equal(status.session.address,undefined,'old namespace account is withheld');
 if(event==='chainChanged'||event==='unsupportedChain')assert.equal(status.session.chain,`eip155:${r.provider.chainId}`);
 if(event==='disconnect')assert.equal(status.removed,true);
 if(event==='expiry')assert.equal(status.expired,true);
 if(event==='relay_drop_return'){assert.equal(status.relayConnected,true);assert.ok(r.phases.some(p=>p.event==='relay_disconnect'));assert.ok(r.phases.some(p=>p.event==='relay_connect'));}
 else assert.ok(r.phases.some(p=>p.phase==='changed'),'wallet event prompts a fresh display read');
 const result=await r.answer();
 if(result && event!=='relay_drop_return'){
  assert.ok(result.error,'a changed signer/session cannot complete an in-flight proof');
  assert.deepEqual({verified:r.verified,completed:r.completed},before,'no stale-account proof is recorded');
 }
 if(event==='emptyAccounts')await assert.rejects(r.client.effect({kind:'link'}),/Select an account/);
});
