import test,{afterEach} from 'node:test';
import assert from 'node:assert/strict';
import {signinOptions,saveSigninOptions,readSigninOptions,saveSigninChoice,readSigninChoice} from '../capsules/home/browser/wallet-signin-options.mjs';
import {handleWalletSigninRequest} from '../capsules/home/browser/wallet-signin-host.mjs';
import {createWalletConnectClient} from '../capsules/wallet-walletconnect/browser/walletconnect-client.mjs';
const {createWalletSigninFlow}=await import(process.env.SIGNIN_FLOW_MODULE||'../capsules/home/browser/wallet-signin-flow.mjs');
const wallet={connector:'metamask',address:'0x'+'12'.repeat(20),chain_id:20,network:'',paymentOnly:true};
const flows=[];afterEach(async()=>{for(const flow of flows)await flow.cancel();flows.length=0;});
function ceremony({lost=false,change=false,connector='metamask'}={}) {
  const calls=[],states=[];let completes=0;
  const method={...wallet,connector};
  const flow=createWalletSigninFlow({
    randomSecret:()=> 'a'.repeat(64),
    api:async(path,body)=>{
      calls.push({path,body});
      if(path.endsWith('/begin'))return {ceremony_id:'one',message:'Use this wallet to sign in to this Home for Alex',expires_at:Date.now()/1000+120,approval:{operation:'auth.wallet.method',request:{ceremony_id:'one',action:body.action,account_id:'alex',method_id:'new-method'}}};
      if(path.endsWith('/complete')){if(lost&&completes++===0)throw new TypeError('lost reply');return {status:'complete',method_id:'new-method',sign_in_enabled:true};}
      return {};
    },
    select:async(_connector,options)=>{calls.push({select:options});return {...method,check:async()=>{if(change)throw Object.assign(new Error('changed'),{code:'changed'});},sign:async message=>{calls.push({signature:message});return {signature:'proof',signature_type:'personal_sign',public_key:''};},close(){}};},
    approve:async approval=>{calls.push({approval});return 'step-up';},render:state=>states.push(state),
  });flows.push(flow);return {flow,calls,states,method};
}
test('a connected wallet adds sign-in with one signature and one passkey approval',async()=>{
  const f=ceremony();await f.flow.start({action:'add_signin',method:f.method,automatic:true,accountId:'alex'});
  assert.equal(f.states.at(-1).stage,'done');
  assert.equal(f.calls.filter(c=>c.signature).length,1);assert.equal(f.calls.filter(c=>c.approval).length,1);
  const begin=f.calls.find(c=>c.path?.endsWith('/begin'));assert.equal(begin.body.action,'add_signin');assert.equal(begin.body.method_id,undefined);assert.equal(begin.body.address,wallet.address);
  assert.equal(f.calls.find(c=>c.approval).approval.request.action,'add_signin');
  assert(!f.calls.some(c=>c.path?.endsWith('/cancel')));
});
test('a lost add_signin reply retries the same proof and approval',async()=>{
  const f=ceremony({lost:true});await f.flow.start({action:'add_signin',method:f.method,automatic:true});
  assert.equal(f.states.at(-1).stage,'unknown');await f.flow.retry();assert.equal(f.states.at(-1).stage,'done');
  assert.deepEqual(f.calls.filter(c=>c.path?.endsWith('/complete')).map(c=>c.body),Array(2).fill(f.calls.find(c=>c.path?.endsWith('/complete')).body));
  assert.equal(f.calls.filter(c=>c.signature).length,1);assert.equal(f.calls.filter(c=>c.approval).length,1);
});
test('wallet changes stop the new automatic flow before signing or passkey approval',async()=>{
  const f=ceremony({change:true});await f.flow.start({action:'add_signin',method:f.method,automatic:true});
  assert.equal(f.states.at(-1).stage,'error');assert.equal(f.calls.filter(c=>c.signature||c.approval).length,0);
});
test('connected WalletConnect reuses its admitted window and existing permission without another Home prompt',async()=>{
  const f=ceremony({connector:'walletconnect'});await f.flow.start({action:'add_signin',method:f.method,automatic:true,delegateWalletConnect:true});
  assert.equal(f.states.at(-1).stage,'done');assert(!f.states.some(state=>state.stage==='internet-notice'));assert.equal(f.calls.find(c=>c.select).select.transport,undefined);
  assert.equal(f.calls.filter(c=>c.signature).length,1);assert.equal(f.calls.filter(c=>c.approval).length,1);
});
test('browser options retain enabled identities and drop every secret and payment-only wallet',()=>{
  const values=new Map(),storage={getItem:key=>values.get(key),setItem:(key,value)=>values.set(key,value),removeItem:key=>values.delete(key)};
  const enabled={...wallet,sign_in_enabled:true,browser_secret:'secret',signature:'secret',app_token:'secret'};
  saveSigninOptions([enabled,{...enabled,address:'0x'+'34'.repeat(20),sign_in_enabled:false}],storage);
  assert.deepEqual(readSigninOptions(storage),signinOptions([enabled]));assert.equal(readSigninOptions(storage).length,1);assert(!JSON.stringify([...values]).includes('secret'));
  saveSigninChoice('passkey',storage);assert.equal(readSigninChoice(storage),'passkey');saveSigninChoice('',storage);assert.equal(readSigninChoice(storage),'');
  saveSigninOptions(Array(257).fill(enabled),storage);assert.deepEqual(readSigninOptions(storage),[]);
});
test('opaque app storage refusal leaves method rendering usable',()=>{
  const blocked={getItem(){throw new Error('opaque origin');},setItem(){throw new Error('opaque origin');}};
  assert.doesNotThrow(()=>saveSigninOptions([wallet],blocked));assert.deepEqual(readSigninOptions(blocked),[]);
});
test('Home reads connected wallets through the requesting System launch, then checks methods with Home authority',async()=>{
  let options;const calls=[],source={postMessage(){}},context={kind:'app-frame',targetId:'system',source,homeToken:'system-token'};
  const data={type:'home:wallet-signin-request',requestId:'one',homeToken:'system-token',action:'add_signin',methodId:''};
  handleWalletSigninRequest({source,data},context,{authorityToken:()=> 'home-token',current:()=>true,changed(){},manage:async value=>{options=value;return {status:'cancelled'};},api:async(path,body,token)=>{
    calls.push({path,token});
    if(path.endsWith('/passkeys'))return {passkeys:[{principal_id:'alex',role:'admin'}]};
    if(path.endsWith('/system/summary'))return {wallet_accounts:{accounts:[{account_id:'connected',connector_id:'wallet-metamask',address:wallet.address,chain_namespace:'eip155:20'}]}};
    return {account_id:'alex',methods:[]};
  }});
  await new Promise(resolve=>setImmediate(resolve));const connected=await options.loadConnected();assert.equal(connected[0].address,wallet.address);
  assert(calls.some(c=>c.path.endsWith('/system/summary')&&c.token==='system-token'));
  assert(calls.filter(c=>c.path.includes('/auth/')).every(c=>c.token==='home-token'));
});
test('WalletConnect signs in through its restored session and keeps payments connected',async()=>{
  const calls=[];let connects=0,disconnects=0,permission='granted';
  const provider={chainId:20,accounts:[wallet.address],session:{expiry:Date.now()/1000+600,namespaces:{eip155:{chains:['eip155:20'],accounts:[`eip155:20:${wallet.address}`],methods:['personal_sign']}}},on(){},request:async input=>{calls.push(input);return input.method==='eth_accounts'?[wallet.address]:input.method==='eth_chainId'?20:'proof';}};
  const client=createWalletConnectClient({origin:'http://localhost',api:async path=>path==='wallet/config'?{walletconnect:{project_id:'fixture',storage_revision:'"0"'}}:path==='internet'?{status:permission}:path==='storage'?{'wc//session':[{expiry:Date.now()/1000+600}]}:{},loadAdapter:async()=>({restoreWalletConnectEvm:async()=>provider,connectWalletConnectEvm:async()=>{connects++;return provider;},disconnectWalletConnectEvm:async()=>{disconnects++;}})});
  await client.effect({kind:'status'});const selected=await client.effect({kind:'signin-select'});assert.equal(selected.address,wallet.address);
  const result=await client.effect({kind:'signin',message:'Runtime sign-in',address:wallet.address,chain_id:20});
  assert.equal(result.signature_type,'personal_sign');assert.equal(calls.filter(c=>c.method==='personal_sign').length,1);assert.equal(connects,0);
  await client.effect({kind:'stop-signin'});assert.equal(disconnects,0);assert.equal((await client.effect({kind:'status'})).status,'connected');
  permission='off';await assert.rejects(client.effect({kind:'signin',message:'Runtime sign-in',address:wallet.address,chain_id:20}),/internet access/i);assert.equal(calls.filter(c=>c.method==='personal_sign').length,1);
});

test('default opaque storage getters are contained inside the browser hint boundary',()=>{
  const previous=Object.getOwnPropertyDescriptor(globalThis,'localStorage');
  Object.defineProperty(globalThis,'localStorage',{configurable:true,get(){throw new Error('Opaque origin');}});
  try {assert.doesNotThrow(()=>saveSigninOptions([wallet]));assert.deepEqual(readSigninOptions(),[]);assert.equal(readSigninChoice(),'');assert.doesNotThrow(()=>saveSigninChoice('passkey'));}
  finally {if(previous)Object.defineProperty(globalThis,'localStorage',previous);else delete globalThis.localStorage;}
});

import {connectionView,reduceSummary,viewText} from '../capsules/_shared/wallet-connection-view.mjs';
test('the shared phone wait presents Home sign-in without disconnecting the payment session',()=>{
  const summary=reduceSummary({request_id:'signin',capsule_id:'home',requesting_app_name:'Home',intent:'auth_challenge',address:wallet.address,status:'pending',reason:'Sign in',expires_at:180},{connector:'wallet-walletconnect'});
  const view=connectionView({window:'walletconnect',stage:'request-phone',purpose:'home-signin',summary,supportedActions:['stop-waiting']});
  assert.match(viewText(view.status),/sign in to this Home/);assert.doesNotMatch(viewText(view.notice),/disconnect/);assert.equal(view.wait,null);
  assert.throws(()=>connectionView({window:'walletconnect',stage:'request-phone',purpose:'home-signin',summary:{...summary,actor:'browser'}}),/Home sign-in presentation/);
  assert.throws(()=>connectionView({window:'walletconnect',stage:'linked',purpose:'home-signin'}),/closed connection purpose/);
});

import {selectConnectedWalletConnect} from '../capsules/home/browser/wallet-signin-connector.mjs';
test('the Home signer bridge accepts only its current admitted connector and returns a closed proof',async()=>{
  const listen=new EventTarget(),controller=new AbortController(),sent=[];let active=true;
  const emit=(data,source,origin='null')=>listen.dispatchEvent(Object.assign(new Event('message'),{data,source,origin}));
  const source={postMessage(data){
    sent.push(data);if(data.operation==='stop')return;
    const result=data.operation==='select'?{...wallet,connector:'walletconnect'}:data.operation==='sign'?{signature:'proof',signature_type:'personal_sign',public_key:'',browser_secret:'forged'}:{};
    queueMicrotask(()=>{
      const response={type:'home:wallet-signin-effect-result',homeToken:'connector',requestId:data.requestId,result};
      emit({...response,result:{signature:'spoof'}},{});emit({...response,result:{signature:'spoof'}},source,'https://foreign.example');emit({...response,homeToken:'wrong'},source);emit(response,source);
    });
  }};
  const selected=await selectConnectedWalletConnect({signal:controller.signal,method:wallet},{listen,open:async()=>({source,homeToken:'connector'}),current:()=>active});
  await selected.check();assert.deepEqual(await selected.sign('Runtime message'),{signature:'proof',signature_type:'personal_sign',public_key:''});
  active=false;await assert.rejects(selected.check(),/window changed/);controller.abort();assert(!sent.some(data=>Object.hasOwn(data,'browser_secret')));
});
test('Runtime method refresh retains the connected provider display hint without accepting extra fields',()=>{
  const values=new Map(),storage={getItem:key=>values.get(key),setItem:(key,value)=>values.set(key,value)};
  saveSigninOptions([{...wallet,sign_in_enabled:true,providerId:'com.brave.wallet',displayName:'Brave Wallet',signature:'private'}],storage);
  saveSigninOptions([{...wallet,sign_in_enabled:true}],storage);
  const [saved]=readSigninOptions(storage);assert.equal(saved.providerId,'com.brave.wallet');assert.equal(saved.displayName,'Brave Wallet');assert(!Object.hasOwn(saved,'signature'));
  saveSigninOptions([],storage);assert.deepEqual(readSigninOptions(storage),[]);
});
test('browser choices follow wallet identity across EVM checksum casing and preserve the selected connection',()=>{
  const values=new Map(),storage={getItem:key=>values.get(key),setItem:(key,value)=>values.set(key,value)};
  const address='0x'+'ab'.repeat(20);
  saveSigninOptions([{...wallet,address,sign_in_enabled:true,providerId:'io.metamask',displayName:'MetaMask'}],storage);
  saveSigninOptions([{...wallet,address:'0x'+address.slice(2).toUpperCase(),connector:'walletconnect',sign_in_enabled:true}],storage,{preferProvided:true});
  saveSigninOptions([{...wallet,address,sign_in_enabled:true}],storage);
  const [saved]=readSigninOptions(storage);assert.equal(saved.connector,'walletconnect');assert.equal(saved.providerId,undefined);assert.equal(saved.displayName,undefined);
});
