import test, {afterEach} from 'node:test';
import assert from 'node:assert/strict';
import { createWalletSigninFlow as createProductFlow, walletSigninOriginAllowed } from '../capsules/home/browser/wallet-signin-flow.mjs';
const activeFlows=new Set();
const createWalletSigninFlow=options=>{const flow=createProductFlow(options);activeFlows.add(flow);return flow;};
afterEach(async()=>{await Promise.all([...activeFlows].map(flow=>flow.cancel()));activeFlows.clear();});

const method = {method_id:'wallet:one',connector:'metamask',address:'0x'+'12'.repeat(20),chain_id:20,network:'',sign_in_enabled:true};
function fixture({lost=false,passkeyRetry=false}={}) {
  const calls=[], states=[]; let completeCalls=0,approvalCalls=0,lastAction,notifyChange;
  const flow=createWalletSigninFlow({
    randomSecret:()=> 'a'.repeat(64),
    api:async(path,body)=>{
      calls.push({path,body:structuredClone(body)});
      if(path.endsWith('/begin')) {lastAction=body.action;return {ceremony_id:'ceremony',message:'exact Home message',expires_at:Date.now()/1000+120,approval:{operation:'auth.wallet.method',request:{ceremony_id:'ceremony',action:body.action,account_id:'principal:alex',method_id:method.method_id}}};}
      if(path.endsWith('/complete')) { if(lost && completeCalls++===0) throw new TypeError('lost reply'); return {status:lastAction==='remove'?'removed':'complete',method_id:method.method_id,sign_in_enabled:lastAction==='add'}; }
      return {};
    },
    select:async(_connector,options)=>{notifyChange=options.changed;return {...method,check:async()=>{},sign:async message=>{calls.push({sign:message});return {signature:'proof',signature_type:'personal_sign',public_key:''};},close(){}};},
    approve:async approval=>{calls.push({approve:approval});if(passkeyRetry&&approvalCalls++===0)throw new Error('cancelled');return 'step-up';},
    render:state=>states.push(state),
  });
  return {flow,calls,states,change:code=>notifyChange?.(code)};
}
test('add reviews before signature, then requests exact passkey approval',async()=>{
  const f=fixture();await f.flow.start({action:'add',method,account:'Alex'});
  assert.equal(f.states.at(-1).stage,'review');assert.equal(f.calls.filter(c=>c.sign).length,0);
  await f.flow.confirm();assert.equal(f.states.at(-1).stage,'approval');assert.equal(f.calls.filter(c=>c.approve).length,0);
  await f.flow.approve();assert.equal(f.states.at(-1).stage,'done');
  assert.equal(f.calls.find(c=>c.sign).sign,'exact Home message');
  assert.deepEqual(f.calls.find(c=>c.approve).approve,{operation:'auth.wallet.method',request:{ceremony_id:'ceremony',action:'add',account_id:'principal:alex',method_id:method.method_id}});
  assert.equal(f.calls.find(c=>c.path?.endsWith('/complete')).body.step_up_token,'step-up');
  assert(!f.calls.some(c=>c.path?.endsWith('/cancel')),'confirmed completion preserves its result');
  await f.flow.cancel();assert(!f.calls.some(c=>c.path?.endsWith('/cancel')),'closing a confirmed result preserves it');
});
test('uncertain completion retries identical proof without signing or approving again',async()=>{
  const f=fixture({lost:true});await f.flow.start({action:'add',method});await f.flow.confirm();await f.flow.approve();
  assert.equal(f.states.at(-1).stage,'unknown');await f.flow.retry();
  const sent=f.calls.filter(c=>c.path?.endsWith('/complete'));assert.equal(sent.length,2);assert.deepEqual(sent[0],sent[1]);
  assert.equal(f.calls.filter(c=>c.sign).length,1);assert.equal(f.calls.filter(c=>c.approve).length,1);assert.equal(f.states.at(-1).message,'');
});

test('remove uses a passkey without asking the wallet to sign',async()=>{
  for(const action of ['remove']) {
    const f=fixture();await f.flow.start({action,method});await f.flow.confirm();
    assert.equal(f.calls.filter(c=>c.sign).length,0);
    assert.equal(f.calls.filter(c=>c.approve).length,1);
    assert.equal(f.calls.find(c=>c.path?.endsWith('/complete')).body.signature,undefined);
  }
});
test('Cancel during a slow begin cancels the late ceremony and shows no review',async()=>{
  let release;const calls=[],states=[];
  const flow=createWalletSigninFlow({randomSecret:()=> 'b'.repeat(64),api:async(path,body)=>{
    calls.push({path,body});
    if(path.endsWith('/begin'))return new Promise(resolve=>{release=()=>resolve({ceremony_id:'late',message:'message',expires_at:Date.now()/1000+120});});
    return {};
  },select:async()=>({...method,close(){}}),approve:async()=>'',render:state=>states.push(state)});
  await flow.start();const choosing=flow.choose('metamask');await Promise.resolve();await Promise.resolve();
  await flow.cancel();release();await choosing;
  assert.equal(states.at(-1).stage,'closed');
  assert(calls.some(c=>c.path.endsWith('/cancel')&&c.body.ceremony_id==='late'));
});
test('changing the wallet before signing sends no completion',async()=>{
  const states=[],calls=[];
  const flow=createWalletSigninFlow({api:async(path,body)=>{calls.push(path);return {ceremony_id:'one',message:'message',expires_at:Date.now()/1000+120};},select:async()=>({...method,check:async()=>{throw Object.assign(new Error('changed'),{code:'changed'});},close(){},sign:()=>{throw new Error('must not sign');}}),approve:()=>{},render:s=>states.push(s)});
  await flow.start();await flow.choose('metamask');await flow.confirm();
  assert.equal(states.at(-1).stage,'error');assert.match(states.at(-1).message,/different account/);assert(!calls.some(path=>path.endsWith('/complete')));
});
test('unknown completion stays uncertain on transport failure, then expires',async()=>{
  let clock=100;const states=[];
  const flow=createWalletSigninFlow({now:()=>clock,api:async path=>{
    if(path.endsWith('/begin'))return {ceremony_id:'one',message:'message',expires_at:110};
    if(path.endsWith('/complete'))throw new TypeError('connection lost');
    return {};
  },select:async()=>({...method,check:async()=>{},sign:async()=>({signature:'proof',signature_type:'personal_sign',public_key:''}),close(){}}),approve:()=>{},render:s=>states.push(s)});
  await flow.start();await flow.choose('metamask');await flow.confirm();assert.equal(states.at(-1).stage,'unknown');
  clock=111;await flow.retry();assert.equal(states.at(-1).stage,'error');assert.match(states.at(-1).message,/expired/);
});
test('a refused completion clears the request and requires a new signer choice',async()=>{
  const states=[];
  const flow=createWalletSigninFlow({api:async path=>{
    if(path.endsWith('/begin'))return {ceremony_id:'one',message:'message',expires_at:Date.now()/1000+120};
    if(path.endsWith('/complete'))throw Object.assign(new Error('refused'),{status:403});
    return {};
  },select:async()=>({...method,check:async()=>{},sign:async()=>({signature:'proof'}),close(){}}),approve:()=>{},render:s=>states.push(s)});
  await flow.start();await flow.choose('metamask');await flow.confirm();assert.equal(states.at(-1).stage,'error');
  await flow.start();assert.equal(states.at(-1).stage,'choice');await flow.cancel();
});

import {connectedWalletSigninMethods} from '../capsules/home/browser/wallet-signin-methods.mjs';
import {handleWalletSigninRequest} from '../capsules/home/browser/wallet-signin-host.mjs';
test('payment links start off and the same address and network shares one sign-in record',()=>{
  const accounts=[{account_id:'payment',connector_id:'wallet-walletconnect',address:method.address.toUpperCase(),chain_namespace:'eip155:20'}];
  assert.equal(connectedWalletSigninMethods(accounts,[method]).length,1);
  const [candidate]=connectedWalletSigninMethods(accounts,[]);assert.equal(candidate.sign_in_enabled,false);assert.equal(candidate.paymentOnly,true);
  assert.equal(connectedWalletSigninMethods([{...accounts[0],chain_namespace:'eip155:8453'}],[method]).length,2,'network distinguishes wallet records');
});
test('Home accepts method intents only from the bound System or Wallet frame',async()=>{
  const source={postMessage(){}},context={kind:'app-frame',targetId:'system',source,homeToken:'launch'};
  const data={type:'home:wallet-signin-request',requestId:'one',homeToken:'launch',action:'remove',methodId:method.method_id};
  let reads=0,managed=0;
  const options={authorityToken:()=> 'home-authority',api:async (path,_body,token)=>{assert.equal(token,'home-authority');reads++;return path.endsWith('/passkeys')?{passkeys:[{principal_id:'principal:one',display_name:'Alex'}]}:{account_id:'principal:one',methods:[method]};},manage:async input=>{managed++;assert.equal(input.token,'home-authority');assert.equal(input.method,method);return {status:'complete'};},current:()=>true,changed(){}};
  for(const invalid of [{...context,targetId:'browser'},{...context,source:{}},{...context,homeToken:'other'}])handleWalletSigninRequest({source,data},invalid,options);
  assert.equal(reads,0);assert.equal(managed,0);
  handleWalletSigninRequest({source,data},context,options);await new Promise(resolve=>setImmediate(resolve));
  assert.equal(reads,2);assert.equal(managed,1);
});

test('every method action checks the approval against the reviewed ceremony and account',async()=>{
  for(const action of ['add','remove'])for(const mismatch of ['action','account_id','ceremony_id','method_id']) {
    const states=[];let signs=0;
    const request={action,account_id:'principal:alex',ceremony_id:'one',method_id:method.method_id};request[mismatch]=action==='add'&&mismatch==='method_id'?'':'different';
    const flow=createWalletSigninFlow({api:async path=>path.endsWith('/begin')?{ceremony_id:'one',message:'exact message',expires_at:Date.now()/1000+120,approval:{operation:'auth.wallet.method',request}}:{},
      select:async()=>({...method,close(){},sign(){signs++;}}),approve:()=>{throw new Error('must not approve');},render:s=>states.push(s)});
    await flow.start({action,method:action==='add'?null:method,accountId:'principal:alex'});if(action==='add')await flow.choose('metamask');
    assert.equal(states.at(-1).stage,'error',`${action} refuses a different ${mismatch}`);assert.equal(signs,0);
  }
});

test('WalletConnect Add pairs in the signed-in ceremony and selects its exact approval',async()=>{
  const calls=[],states=[];
  const flow=createWalletSigninFlow({randomSecret:()=> 'a'.repeat(64),
    api:async(path,body)=>{
      calls.push({path,body});
      if(path.endsWith('/begin') || path.endsWith('/select'))return {ceremony_id:'addition',message:path.endsWith('/select')?'Add this wallet':'',expires_at:Date.now()/1000+120,
        approval:{operation:'auth.wallet.method',request:{ceremony_id:'addition',action:'add',account_id:'principal:alex',method_id:'new',address:body.address}}};
      return {};
    },select:async(_connector,{transport})=>{assert.equal(transport.ceremony_id,'addition');return {...method,connector:'walletconnect',close(){}};},approve(){},render:s=>states.push(s)});
  await flow.start({action:'add',accountId:'principal:alex'});await flow.choose('walletconnect');
  assert.equal(states.at(-1).stage,'internet-notice');assert.equal(calls.length,0,'consent precedes transport');
  await flow.connect();assert.equal(states.at(-1).stage,'review');
  assert.deepEqual(calls.map(c=>c.path),['/api/auth/wallet-methods/begin','/api/auth/wallet/signin/select']);
  assert.equal(calls[0].body.address,'');assert.equal(calls[0].body.action,'add');assert.equal(calls[0].body.allow_temporary_internet,true);
  assert.equal(calls[1].body.address,method.address);assert.equal(calls[1].body.browser_secret,calls[0].body.browser_secret);
  await flow.cancel();assert.equal(calls.at(-1).body.ceremony_id,'addition');
});

test('signed-out WalletConnect requires an enabled compatible method and internet consent',async()=>{
  for(const available of [true,false]) {
    const calls=[],states=[];
    const flow=createWalletSigninFlow({api:async(path,body)=>{calls.push({path,body});return path.endsWith('/status')?{walletconnect_signin_available:available}:{ceremony_id:'signin',message:'',expires_at:Date.now()/1000+120};},
      select:async()=>({...method,connector:'walletconnect',close(){}}),approve(){},render:s=>states.push(s)});
    await flow.start();assert.equal(states.at(-1).walletconnectAvailable,available);await flow.choose('walletconnect');
    assert.equal(states.at(-1).stage,available?'internet-notice':'choice');assert.equal(calls.filter(c=>c.path.endsWith('/begin')).length,0);
    await flow.cancel();assert.equal(calls.filter(c=>c.path.endsWith('/begin')).length,0,'Cancel grants no temporary transport');
  }
});

test('Bitcoin method selection keeps address case while EVM accepts checksum case',async()=>{
  for(const connector of ['unisat','metamask']) {
    const wallet={...method,connector,address:connector==='unisat'?'1A'+'b'.repeat(30):'0x'+'ab'.repeat(20),chain_id:connector==='unisat'?0:20,network:connector==='unisat'?'bitcoin':''};
    const states=[];
    const flow=createWalletSigninFlow({api:async path=>path.endsWith('/begin')?{ceremony_id:'one',message:'message',expires_at:Date.now()/1000+120,approval:{operation:'auth.wallet.method',request:{ceremony_id:'one',action:'add',account_id:'principal:alex',method_id:method.method_id}}}:{},
      select:async()=>({...wallet,address:wallet.address.toLowerCase(),close(){}}),approve(){},render:s=>states.push(s)});
    await flow.start({action:'add',method:wallet});assert.equal(states.at(-1).stage,connector==='unisat'?'error':'review');await flow.cancel();
  }
});

test('wallet sign-in uses HTTPS outside numeric loopback and localhost',()=>{
  for(const origin of ['https://home.example','http://localhost:8090','http://127.0.0.1:8090','http://127.42.0.1:8090','http://[::1]:8090'])assert(walletSigninOriginAllowed(origin),origin);
  for(const origin of ['http://home.example','http://127.example','http://192.168.1.2:8090'])assert.equal(walletSigninOriginAllowed(origin),false,origin);
});

test('an account change after dispatch keeps the uncertain result retryable',async()=>{
  const f=fixture({lost:true});await f.flow.start({action:'add',method});await f.flow.confirm();await f.flow.approve();
  assert.equal(f.states.at(-1).stage,'unknown');f.change('changed');assert.equal(f.states.at(-1).stage,'unknown');await f.flow.retry();
  assert.equal(f.states.at(-1).stage,'done');
  const sent=f.calls.filter(c=>c.path?.endsWith('/complete'));assert.deepEqual(sent[0].body,sent[1].body);assert.equal(f.calls.filter(c=>c.sign).length,1);
});

test('Wallet reads only its own method list through Home authority',async()=>{
  const replies=[],source={postMessage:message=>replies.push(message)},context={kind:'app-frame',targetId:'wallet',source,homeToken:'wallet-launch'};
  const data={type:'home:wallet-signin-request',requestId:'list',homeToken:'wallet-launch',action:'list',methodId:''};
  handleWalletSigninRequest({source,data},context,{authorityToken:()=> 'home-launch',api:async(path,_body,token)=>{
    assert.equal(token,'home-launch');return path.endsWith('/passkeys')?{passkeys:[{principal_id:'other',role:'admin'},{principal_id:'principal:alex',role:'guest'}]}:{account_id:'principal:alex',methods:[method]};
  },manage:()=>{throw new Error('list does not change authority');},current:()=>true,changed(){}});
  await new Promise(resolve=>setImmediate(resolve));
  assert.deepEqual(replies[0].result,{status:'complete',account_id:'principal:alex',methods:[method],can_manage:false});
  assert(!Object.hasOwn(replies[0].result,'passkeys'));assert(!JSON.stringify(replies).includes('home-launch'));
});

test('a changed Home authority retires pending Wallet method requests',async()=>{
  const replies=[],source={postMessage:message=>replies.push(message)},context={kind:'app-frame',targetId:'wallet',source,homeToken:'wallet-launch'};
  let authority='home-one',release;
  const data={type:'home:wallet-signin-request',requestId:'retired',homeToken:'wallet-launch',action:'remove',methodId:method.method_id};
  handleWalletSigninRequest({source,data},context,{authorityToken:()=>authority,api:path=>path.endsWith('/passkeys')?Promise.resolve({passkeys:[]}):new Promise(resolve=>{release=resolve;}),manage:()=>{throw new Error('retired Home cannot start approval');},current:()=>true,changed(){}});
  authority='home-two';release({account_id:'principal:alex',methods:[method]});await new Promise(resolve=>setImmediate(resolve));assert.deepEqual(replies,[]);
});

test('signed-out sign-in ignores method-change approval notices',async()=>{
  const states=[];
  const flow=createWalletSigninFlow({api:async()=>({ceremony_id:'one',message:'sign in',expires_at:Date.now()/1000+120,approval:{notice:'Confirm this method change with your passkey.'}}),select:async()=>({...method,close(){}}),approve:()=>{throw new Error('signin uses the wallet');},render:s=>states.push(s)});
  await flow.start();await flow.choose('metamask');assert.equal(states.at(-1).stage,'review');assert.equal(states.at(-1).approvalNotice,'');
});

test('successful passkey retry replaces its earlier refusal message',async()=>{
  const f=fixture({passkeyRetry:true});await f.flow.start({action:'add',method});await f.flow.confirm();await f.flow.approve();
  assert.equal(f.states.at(-1).stage,'approval');assert.match(f.states.at(-1).message,/could not confirm/);
  await f.flow.approve();assert.equal(f.states.at(-1).stage,'done');assert.equal(f.states.at(-1).message,'');
});

test('method refresh preserves control focus and refreshes when the page returns',async()=>{
  const previousWindow=globalThis.window,previousDocument=globalThis.document;
  const fakeWindow=new EventTarget(),fakeDocument=new EventTarget();fakeDocument.visibilityState='visible';fakeWindow.top={};
  globalThis.window=fakeWindow;globalThis.document=fakeDocument;
  try {
    const {watchWalletSigninMethods}=await import('../capsules/home/browser/wallet-signin-methods.mjs');let refreshed=0;
    watchWalletSigninMethods(()=>{refreshed++;},'https://home.example');
    fakeWindow.dispatchEvent(new Event('focus'));assert.equal(refreshed,0);
    fakeDocument.dispatchEvent(new Event('visibilitychange'));assert.equal(refreshed,1);
    fakeDocument.visibilityState='hidden';fakeDocument.dispatchEvent(new Event('visibilitychange'));assert.equal(refreshed,1);
    fakeWindow.dispatchEvent(Object.assign(new Event('message'),{source:fakeWindow.top,origin:'https://home.example',data:{type:'home:wallet-signin-changed'}}));assert.equal(refreshed,2);
  } finally {globalThis.window=previousWindow;globalThis.document=previousDocument;}
});

test('a late WalletConnect availability reply keeps an active browser-wallet review',async()=>{
  let releaseStatus;
  const states=[];
  const flow=createWalletSigninFlow({api:async path=>path.endsWith('/status')?await new Promise(resolve=>releaseStatus=resolve):{ceremony_id:'one',message:'Sign in',expires_at:Date.now()/1000+120},
    select:async()=>({...method,close(){}}),approve(){},render:s=>states.push(s)});
  const starting=flow.start();
  await flow.choose('metamask');assert.equal(states.at(-1).stage,'review');
  releaseStatus({walletconnect_signin_available:true});await starting;
  assert.equal(flow.state.stage,'review');assert.equal(states.at(-1).stage,'review');
});

import {signinFixture,sampleMethod} from './lib/wallet-signin-fixture.mjs';
test('confirmed sign-in keeps the session usable after closing and starting another flow',async()=>{
  const server=await signinFixture();
  try {
    const api=async(path,body)=>{
      const response=await fetch(server.origin+path,{method:body?'POST':'GET',headers:{'content-type':'application/json'},...(body?{body:JSON.stringify(body)}:{})});
      assert.equal(response.status,200);return response.json();
    };
    const flow=createWalletSigninFlow({api,select:async()=>({...sampleMethod('metamask',true),check:async()=>{},sign:async()=>({signature:'fixture-signature'}),close(){}}),approve(){},render(){}});
    await flow.start();await flow.choose('metamask');await flow.confirm();assert.equal(flow.state.stage,'done');
    await flow.cancel();await flow.start();await flow.cancel();
    const response=await fetch(server.origin+'/api/auth/sessions/refresh');
    assert.equal(response.status,200,'the completed session remains usable');
    assert(!server.state.calls.some(c=>c.path==='/api/auth/wallet/cancel'));
  } finally {await server.close();}
});
test('fixture cancel revokes a completed sign-in session, matching Runtime',async()=>{
  const server=await signinFixture();
  try {
    const post=async(path,body)=>(await fetch(server.origin+path,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)})).json();
    const browser_secret='a'.repeat(64),wallet=sampleMethod('metamask',true);
    const begin=await post('/api/auth/wallet/signin/begin',{...wallet,browser_secret});
    await post('/api/auth/wallet/signin/complete',{ceremony_id:begin.ceremony_id,browser_secret,signature:'fixture-signature'});
    assert.equal((await fetch(server.origin+'/api/auth/sessions/refresh')).status,200);
    await post('/api/auth/wallet/cancel',{ceremony_id:begin.ceremony_id,browser_secret});
    assert.equal((await fetch(server.origin+'/api/auth/sessions/refresh')).status,403);
  } finally {await server.close();}
});

import {walletSigninControls} from '../capsules/home/browser/wallet-signin-methods.mjs';
test('Guests retain Remove and only Admins can Add connected payment wallets',()=>{
  const previous=globalThis.document;
  globalThis.document={createElement:tag=>({tag,children:[],setAttribute(){},append(...nodes){this.children.push(...nodes);}})};
  try {
    for(const canManage of [true,false]) {
      const actions=[],controls=walletSigninControls(method,{canManage,onAction:(...args)=>actions.push(args)});
      const [status,remove]=controls.children;
      assert.equal(status.textContent,'Signs in');assert.equal(Boolean(remove.disabled),false);
      remove.onclick();assert.deepEqual(actions,[['remove',method.method_id]]);
      const payment=walletSigninControls({...method,paymentOnly:true},{canManage,onAction:(...args)=>actions.push(args)});
      assert.equal(Boolean(payment.children[0].disabled),!canManage);
      payment.children[0].onclick();assert.deepEqual(actions.at(-1),['add',method.method_id]);
    }
  } finally {globalThis.document=previous;}
});
test('payment Add starts with the selected wallet and validates the bound frame intent',async()=>{
  for(const invalid of ['', 'network', 'source', 'extra', 'action']) {
    const replies=[],managed=[],source={postMessage:message=>replies.push(message)},context={kind:'app-frame',targetId:invalid==='source'?'system':'wallet',source,homeToken:'wallet-launch'};
    const wallet={connector:'metamask',address:method.address,chain_id:20,network:''};
    if(invalid==='network')wallet.network='bitcoin';if(invalid==='extra')wallet.authority='untrusted';
    handleWalletSigninRequest({source,data:{type:'home:wallet-signin-request',requestId:'add',homeToken:'wallet-launch',action:invalid==='action'?'enable':'add',methodId:'',wallet}},context,{
      authorityToken:()=> 'home',current:()=>true,changed(){},api:async path=>path.endsWith('/passkeys')?{passkeys:[]}:{account_id:'principal:alex',methods:[]},
      manage:async input=>{managed.push(input);return {status:'complete'};},
    });
    await new Promise(resolve=>setImmediate(resolve));
    assert.equal(managed.length,invalid?0:1);
    if(!invalid){assert.deepEqual(managed[0].method,wallet);assert.equal(managed[0].action,'add');assert.equal(replies[0].result.status,'complete');}
  }
});
test('Cancel and expiry revoke a committed but uncertain sign-in',async()=>{
  for(const action of ['cancel','expire']) {
    const server=await signinFixture();let clock=Date.now()/1000,cancelled;
    try {
      const api=async(path,body)=>{
        const request=fetch(server.origin+path,{method:body?'POST':'GET',headers:{'content-type':'application/json'},...(body?{body:JSON.stringify(body)}:{})});
        if(path.endsWith('/cancel'))cancelled=request;
        const response=await request;const result=await response.json();
        if(path.endsWith('/complete'))throw new TypeError('lost confirmation');return result;
      };
      const flow=createWalletSigninFlow({now:()=>clock,api,select:async()=>({...sampleMethod('metamask',true),check:async()=>{},sign:async()=>({signature:'fixture-signature'}),close(){}}),approve(){},render(){}});
      await flow.start();await flow.choose('metamask');await flow.confirm();assert.equal(flow.state.stage,'unknown');
      assert.equal((await fetch(server.origin+'/api/auth/sessions/refresh')).status,200,'the lost reply still committed');
      if(action==='cancel')await flow.cancel();else {clock+=181;await flow.retry();assert.equal(flow.state.stage,'error');}
      await cancelled;
      assert.equal((await fetch(server.origin+'/api/auth/sessions/refresh')).status,403,action+' revokes the uncertain result');
    } finally {await server.close();}
  }
});

test('the flow refuses retired method actions before it requests authority',async()=>{
  const f=fixture();
  for(const action of ['add_signin','enable','disable']) {
    await assert.rejects(f.flow.start({action,method}),/invalid/);
  }
  assert.deepEqual(f.calls,[]);
});
