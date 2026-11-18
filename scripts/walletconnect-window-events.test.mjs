import test from 'node:test';
import assert from 'node:assert/strict';
import {EventEmitter} from 'node:events';
import {spawnSync} from 'node:child_process';
import {observeWindowErrors,staleSessionMessage} from './lib/walletconnect-phone-window-fixture.mjs';
import {walletConnectFixtureRequire} from './lib/walletconnect-relay-fixture.mjs';
const {RELAYER_EVENTS}=walletConnectFixtureRequire('@walletconnect/core');
import {createWalletConnectClient} from '../capsules/wallet-walletconnect/browser/walletconnect-client.mjs';
const address='0x'+'12'.repeat(20),other='0x'+'34'.repeat(20);
test('a stopped Home read owns the promise it already started',()=>{
 const result=spawnSync(process.execPath,['--input-type=module','-e',`
  import assert from 'node:assert/strict';
  import {createWalletConnectClient} from './capsules/wallet-walletconnect/browser/walletconnect-client.mjs';
  const unhandled=[];process.on('unhandledRejection',error=>unhandled.push(error.message));
  let client;
  client=createWalletConnectClient({origin:'http://localhost',api:resource=>{
   if(resource==='wallet/config'){
    client.effect({kind:'cancel'}).catch(error=>unhandled.push(error.message));
    return Promise.reject(new Error('Stopped Home read'));
   }
   if(resource==='storage')return {};
   throw new Error('Unexpected Home read');
  }});
  await assert.rejects(client.effect({kind:'link'}),/Home stopped waiting/);
  await new Promise(resolve=>setTimeout(resolve,25));
  assert.deepEqual(unhandled,[],'Stop owns the rejected read without changing its stop result');
 `],{cwd:new URL('..',import.meta.url),encoding:'utf8',timeout:5000});
 assert.equal(result.status,0,result.stderr||result.error?.message);
});
async function fixture(state){
 const relayer=Object.assign(new EventEmitter(),{connected:true});
 const provider=Object.assign(new EventEmitter(),{chainId:8453,accounts:[address],connected:true,
  session:{expiry:Math.floor(Date.now()/1000)+3600,peer:{metadata:{name:'Event test wallet'}},namespaces:{eip155:{accounts:[`eip155:8453:${address}`,`eip155:1:${address}`]}}},
  signer:{client:{core:{relayer}}}});
 Object.defineProperty(provider,'connected',{get:()=>relayer.connected && Boolean(provider.session)});
 let hold=false,reply,started,verified=0,completed=0,internetFailed=false;
 let reached=new Promise(resolve=>{started=resolve;});
 provider.request=async({method})=>{
  if(method==='eth_accounts')return provider.accounts;
  if(method==='eth_chainId')return provider.chainId;
  if(hold){started();return new Promise(resolve=>{reply=resolve;});}
  return '0x'+'ab'.repeat(65);
 };
 const api=async(path)=>{
  if(path==='internet'){if(internetFailed)throw new Error('Home is unavailable');return {status:'granted'};}
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
 return {client,provider,relayer,phases,failInternet(){internetFailed=true;},get verified(){return verified;},get completed(){return completed;},async answer(){reply?.('0x'+'ab'.repeat(65));return pending?await pending:null;}};
}
for(const state of ['idle','ownership','signature','result'])for(const event of ['accountsChanged','emptyAccounts','chainChanged','unsupportedChain','session_update','disconnect','expiry','relay_drop_return'])test(`wallet ${event} is observed in ${state}`,async()=>{
 const r=await fixture(state),before={verified:r.verified,completed:r.completed};
 if(event==='accountsChanged'||event==='emptyAccounts'){r.provider.accounts=event==='emptyAccounts'?[]:[other];r.provider.emit('accountsChanged',r.provider.accounts);}
 if(event==='chainChanged'||event==='unsupportedChain'){r.provider.chainId=event==='chainChanged'?1:137;r.provider.emit('chainChanged','0x'+r.provider.chainId.toString(16));}
 if(event==='session_update')r.provider.emit('session_update',{});
 if(event==='disconnect'){r.provider.session=undefined;r.provider.emit('disconnect',{});}
 if(event==='expiry'){r.provider.session.expiry=Math.floor(Date.now()/1000)-1;await r.client.effect({kind:'status'});r.provider.emit('disconnect',{});}
 if(event==='relay_drop_return'){r.relayer.connected=false;r.relayer.emit(RELAYER_EVENTS.disconnect);const dropped=await r.client.effect({kind:'status'});assert.equal(dropped.relayConnected,false);assert.equal(dropped.session.address,address,'relay loss retains the actual wallet session');r.relayer.connected=true;r.relayer.emit(RELAYER_EVENTS.connect);}
 const status=await r.client.effect({kind:'status'});
 if(event==='accountsChanged')assert.equal(status.session.address,other);
 if(event==='emptyAccounts')assert.equal(status.session.address,undefined,'old namespace account is withheld');
 if(event==='chainChanged'||event==='unsupportedChain')assert.equal(status.session.chain,`eip155:${r.provider.chainId}`);
 if(event==='disconnect')assert.equal(status.removed,true);
 if(event==='expiry')assert.equal(status.expired,true);
 if(event==='relay_drop_return'){assert.equal(status.relayConnected,true);assert.ok(r.phases.some(p=>p.event==='relay_disconnect'));assert.ok(r.phases.some(p=>p.event==='relay_connect'));}
 else assert.ok(r.phases.some(p=>p.phase==='changed'),'wallet event prompts a fresh display read');
 const result=await r.answer();
 if(result && event!=='relay_drop_return' && event!=='session_update'){
  assert.ok(result.error,'a changed signer/session cannot complete an in-flight proof');
  assert.deepEqual({verified:r.verified,completed:r.completed},before,'no stale-account proof is recorded');
 }
 if(result && event==='session_update')assert.equal(result.error,undefined,'a no-op session update keeps the current request valid');
 if(event==='emptyAccounts')await assert.rejects(r.client.effect({kind:'link'}),/Select an account/);
});

for(const state of ['idle','ownership','signature','result'])test(`session extension uses the SDK store in ${state}`,async()=>{
 const r=await fixture(state),snapshot=r.provider.session;
 snapshot.topic='extension-test';snapshot.expiry=Math.floor(Date.now()/1000)-1;
 const client=Object.assign(new EventEmitter(),{core:{relayer:r.relayer},session:{get:topic=>{assert.equal(topic,snapshot.topic);return {...snapshot,expiry:Math.floor(Date.now()/1000)+3600};}}});
 // The store read also covers an extension which arrived before this status read.
 r.provider.signer.client=client;
 const status=await r.client.effect({kind:'status'});
 assert.equal(status.status,'connected');assert.equal(status.expired,false);
 assert.equal(snapshot.expiry< Date.now()/1000,true,'the provider snapshot remains stale');
 const answer=await r.answer();if(answer)assert.equal(answer.error,undefined,'an expiry extension leaves the current signer intact');
});
for(const state of ['ownership','signature'])test(`removing personal_sign permission stops a pending ${state}`,async()=>{
 const r=await fixture(state),before={verified:r.verified,completed:r.completed};r.provider.session.namespaces.eip155.methods=[];r.provider.emit('session_update',{});const answer=await r.answer();assert.ok(answer.error);assert.deepEqual({verified:r.verified,completed:r.completed},before);
});
test('cached permission is marked stale while current wallet facts still refresh',async()=>{
 const r=await fixture('idle');r.failInternet();r.provider.accounts=[other];r.provider.emit('accountsChanged',[other]);const status=await r.client.effect({kind:'status'});assert.equal(status.permissionFresh,false);assert.equal(status.permission.status,'granted');assert.equal(status.session.address,other);
});
test('a failed permission read starts no saved-session restore without a provider',async()=>{
 const r=await fixture('idle');await r.client.effect({kind:'disconnect'});r.failInternet();await assert.rejects(r.client.effect({kind:'status'}),/Home is unavailable/);
});
for(const ending of ['removed','expired'])test(`known wallet ${ending} facts survive a failed Home permission read`,async()=>{
 const r=await fixture('idle');
 if(ending==='expired'){r.provider.session.expiry=Math.floor(Date.now()/1000)-1;await r.client.effect({kind:'status'});}
 r.provider.session=undefined;r.provider.emit('disconnect',{});r.failInternet();
 const status=await r.client.effect({kind:'status'});assert.equal(status.permissionFresh,false);assert.equal(status.session,undefined);assert.equal(status[ending],true);
});

const fenceError=()=>Object.assign(new Error(staleSessionMessage),{stack:'Error\n at fetchJson (http://127.0.0.1/apps/wallet-walletconnect/wallet-walletconnect.js:1:1)'});
const oldWrite=()=>({path:'/api/apps/wallet-walletconnect/storage',method:'POST',revision:'"0"',status:409});
test('the common page-error guard consumes only one actual retired storage POST',()=>{
 const page=new EventEmitter(),state={calls:[oldWrite()],revision:1},{errors,sdkFences}=observeWindowErrors(page,{state});
 page.emit('pageerror',fenceError());assert.deepEqual(errors,[]);assert.equal(sdkFences.length,1);assert.equal(state.calls[0].observedRejection,true);
 page.emit('pageerror',fenceError());assert.deepEqual(errors,[staleSessionMessage],'a second error needs a second actual rejected write');
});
for(const [name,change] of [
 ['no rejected write',state=>{state.calls=[];}],
 ['a GET',state=>{state.calls[0].method='GET';}],
 ['the current revision',state=>{state.calls[0].revision='"1"';}],
 ['a missing revision',state=>{delete state.calls[0].revision;}],
])test(`the common page-error guard fails ${name}`,()=>{
 const page=new EventEmitter(),state={calls:[oldWrite()],revision:1};change(state);const {errors,sdkFences}=observeWindowErrors(page,{state});
 page.emit('pageerror',fenceError());assert.deepEqual(errors,[staleSessionMessage]);assert.equal(sdkFences.length,0);
});
test('the common page-error guard fails unexpected window script errors despite a stale write',()=>{
 const page=new EventEmitter(),state={calls:[oldWrite()],revision:1},{errors,sdkFences}=observeWindowErrors(page,{state});
 page.emit('pageerror',new Error('Unexpected script error'));const wrongStack=fenceError();wrongStack.stack='at anotherFrame (http://127.0.0.1/apps/home/home.js:1:1)';page.emit('pageerror',wrongStack);
 assert.deepEqual(errors,['Unexpected script error',staleSessionMessage]);assert.equal(sdkFences.length,0);
});

// Await the final sequential test before --test-force-exit can finish this module.
await test('SDK persist rejection needs a real retired storage POST',()=>{
 const page=new EventEmitter(),state={calls:[oldWrite()],revision:1},{errors,sdkFences}=observeWindowErrors(page,{state});
 const error=fenceError();error.stack='persist@http://127.0.0.1/apps/wallet-walletconnect/vendor/reown-appkit.js:1:1';page.emit('pageerror',error);
 assert.deepEqual(errors,[]);assert.equal(sdkFences.length,1);
});
