import test, {afterEach} from 'node:test';
import assert from 'node:assert/strict';
import { createWalletSigninFlow as createProductFlow, walletSigninOriginAllowed } from '../capsules/home/browser/wallet-signin-flow.mjs';
const activeFlows=new Set();
const createWalletSigninFlow=options=>{const flow=createProductFlow(options);activeFlows.add(flow);return flow;};
afterEach(async()=>{await Promise.all([...activeFlows].map(flow=>flow.cancel()));activeFlows.clear();});

const method = {method_id:'wallet:one',connector:'metamask',address:'0x'+'12'.repeat(20),chain_id:20,network:'',sign_in_enabled:true};
function fixture({lost=false,passkeyRetry=false}={}) {
  const calls=[], states=[]; let completeCalls=0,approvalCalls=0,lastAction,notifyChange,committed=false,reads=0;
  const flow=createWalletSigninFlow({
    randomSecret:()=> 'a'.repeat(64),
    api:async(path,body)=>{
      calls.push({path,body:structuredClone(body)});
      if(path.endsWith('/begin')) {lastAction=body.action;return {ceremony_id:'ceremony',message:'exact Home message',expires_at:Date.now()/1000+120,approval:{operation:'auth.wallet.method',request:{ceremony_id:'ceremony',action:body.action,account_id:'principal:alex',method_id:method.method_id}}};}
      if(path==='/api/auth/wallet-methods') {reads++;if(lost&&reads===1)throw new TypeError('lost status');return {account_id:'principal:alex',methods:committed&&lastAction!=='remove'?[method]:[]};}
      if(path.endsWith('/complete')) { committed=true;if(lost && completeCalls++===0) throw new TypeError('lost reply'); return {status:lastAction==='remove'?'removed':'complete',method_id:method.method_id,sign_in_enabled:lastAction==='add'}; }
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
test('uncertain completion reads methods without signing or approving again',async()=>{
  const f=fixture({lost:true});await f.flow.start({action:'add',method});await f.flow.confirm();await f.flow.approve();
  assert.equal(f.states.at(-1).stage,'unknown');await f.flow.retry();
  const sent=f.calls.filter(c=>c.path?.endsWith('/complete'));assert.equal(sent.length,1);assert(f.calls.some(c=>c.path==='/api/auth/wallet-methods'));
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
test('Home accepts method intents only from the bound System frame',async()=>{
  const source={postMessage(){}},context={kind:'app-frame',targetId:'system',source,homeToken:'launch'};
  const data={type:'home:wallet-signin-request',requestId:'one',homeToken:'launch',action:'remove',methodId:method.method_id};
  let reads=0,managed=0;
  const options={authorityToken:()=> 'home-authority',api:async (path,_body,token)=>{assert.equal(token,'home-authority');reads++;return path.endsWith('/passkeys')?{passkeys:[{principal_id:'principal:one',display_name:'Alex'}]}:{account_id:'principal:one',methods:[method]};},manage:async input=>{managed++;assert.equal(input.token,'home-authority');assert.equal(input.method,method);return {status:'complete'};},current:()=>true,changed(){}};
  for(const invalid of [{...context,targetId:'browser'},{...context,source:{}},{...context,homeToken:'other'}])handleWalletSigninRequest({source,data},invalid,options);
  assert.equal(reads,0);assert.equal(managed,0);
  handleWalletSigninRequest({source,data},context,options);await new Promise(resolve=>setImmediate(resolve));
  assert.equal(reads,2,'read methods and passkeys with Home authority');assert.equal(managed,1);
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
  assert.equal(states.at(-1).stage,'review');
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
    assert.equal(calls.filter(c=>c.path.endsWith('/begin')).length,available?1:0);
    if(available)assert.equal(calls.find(c=>c.path.endsWith('/begin')).body.allow_temporary_internet,true);
    else assert.equal(states.at(-1).stage,'error');
    await flow.cancel();
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
  const sent=f.calls.filter(c=>c.path?.endsWith('/complete'));assert.equal(sent.length,1);assert.equal(f.calls.filter(c=>c.sign).length,1);
});

test('System reads its own method list through Home authority',async()=>{
  const replies=[],source={postMessage:message=>replies.push(message)},context={kind:'app-frame',targetId:'system',source,homeToken:'wallet-launch'};
  const data={type:'home:wallet-signin-request',requestId:'list',homeToken:'wallet-launch',action:'list',methodId:''};
  handleWalletSigninRequest({source,data},context,{authorityToken:()=> 'home-launch',api:async(path,_body,token)=>{
    assert.equal(token,'home-launch');return path.endsWith('/passkeys')?{passkeys:[{principal_id:'other',role:'admin'},{principal_id:'principal:alex',role:'guest'}]}:{account_id:'principal:alex',methods:[method]};
  },manage:()=>{throw new Error('list does not change authority');},current:()=>true,changed(){}});
  await new Promise(resolve=>setImmediate(resolve));
  assert.deepEqual(replies[0].result,{status:'complete',account_id:'principal:alex',methods:[method],can_manage:false});
  assert(!Object.hasOwn(replies[0].result,'passkeys'));assert(!JSON.stringify(replies).includes('home-launch'));
});

test('a changed Home authority retires pending System method requests',async()=>{
  const replies=[],source={postMessage:message=>replies.push(message)},context={kind:'app-frame',targetId:'system',source,homeToken:'wallet-launch'};
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
    fakeWindow.dispatchEvent(new Event('focus'));assert.equal(refreshed,1);
    fakeDocument.dispatchEvent(new Event('visibilitychange'));assert.equal(refreshed,2);
    fakeDocument.visibilityState='hidden';fakeDocument.dispatchEvent(new Event('visibilitychange'));assert.equal(refreshed,2);
    fakeWindow.dispatchEvent(Object.assign(new Event('message'),{source:fakeWindow.top,origin:'https://home.example',data:{type:'home:wallet-signin-changed'}}));assert.equal(refreshed,3);
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
test('Every account has one Remove control for its wallet method',()=>{
  const previous=globalThis.document;
  globalThis.document={createElement:tag=>({tag,children:[],setAttribute(){},append(...nodes){this.children.push(...nodes);}})};
  try {
    for(const canManage of [true,false]) {
      const actions=[],controls=walletSigninControls(method,{canManage,onAction:(...args)=>actions.push(args)});
      const [remove]=controls.children;
      assert.equal(controls.children.length,1);assert.equal(Boolean(remove.disabled),false);
      remove.onclick();assert.deepEqual(actions,[['remove',method.method_id]]);
    }
  } finally {globalThis.document=previous;}
});
test('Wallet frames and unsolicited wallet identities cannot change sign-in methods',async()=>{
 let managed=0;const source={postMessage(){}};
 for(const targetId of ['wallet','system'])handleWalletSigninRequest({source,data:{type:'home:wallet-signin-request',requestId:'add',homeToken:'launch',action:'add',methodId:'',wallet:method}},{kind:'app-frame',targetId,source,homeToken:'launch'},{manage(){managed++;},api(){throw new Error('untrusted intent');}});
 await new Promise(resolve=>setImmediate(resolve));assert.equal(managed,0);
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

// Connected-wallet reuse and signed-out surface contract.
{
const {default:test,afterEach}=await import('node:test');
const {default:assert}=await import('node:assert/strict');
const {saveSigninChoice,readSigninChoice,availableSigninOptions}=await import(process.env.SIGNIN_OPTIONS_MODULE||'../capsules/home/browser/wallet-signin-options.mjs');
const {handleWalletSigninRequest}=await import('../capsules/home/browser/wallet-signin-host.mjs');
const {createWalletConnectClient}=await import('../capsules/wallet-walletconnect/browser/walletconnect-client.mjs');
const {createWalletSigninFlow}=await import(process.env.SIGNIN_FLOW_MODULE||'../capsules/home/browser/wallet-signin-flow.mjs');
const wallet={connector:'metamask',address:'0x'+'12'.repeat(20),chain_id:20,network:'',paymentOnly:true};
const flows=[];afterEach(async()=>{for(const flow of flows)await flow.cancel();flows.length=0;});
function ceremony({lost=false,change=false,connector='metamask'}={}) {
  const calls=[],states=[];let completes=0,reads=0;
  const method={...wallet,connector};
  const flow=createWalletSigninFlow({
    randomSecret:()=> 'a'.repeat(64),
    api:async(path,body)=>{
      calls.push({path,body});
      if(path.endsWith('/begin'))return {ceremony_id:'one',message:'Use this wallet to sign in to this Home for Alex',expires_at:Date.now()/1000+120,approval:{operation:'auth.wallet.method',request:{ceremony_id:'one',action:body.action,account_id:'alex',method_id:'new-method'}}};
      if(path==='/api/auth/wallet-methods'){if(lost&&reads++===0)throw new TypeError('lost status');return {account_id:'alex',methods:[{method_id:'new-method',sign_in_enabled:true}]};}
      if(path.endsWith('/complete')){if(lost&&completes++===0)throw new TypeError('lost reply');return {status:'complete',method_id:'new-method',sign_in_enabled:true};}
      return {};
    },
    select:async(_connector,options)=>{calls.push({select:options});return {...method,check:async()=>{if(change)throw Object.assign(new Error('changed'),{code:'changed'});},sign:async message=>{calls.push({signature:message});return {signature:'proof',signature_type:'personal_sign',public_key:''};},close(){}};},
    approve:async approval=>{calls.push({approval});return 'step-up';},render:state=>states.push(state),
  });flows.push(flow);return {flow,calls,states,method};
}
test('a connected wallet adds sign-in with one signature and one passkey approval',async()=>{
  const f=ceremony();await f.flow.start({action:'add',method:f.method,automatic:true,accountId:'alex'});
  assert.equal(f.states.at(-1).stage,'done');
  assert.equal(f.calls.filter(c=>c.signature).length,1);assert.equal(f.calls.filter(c=>c.approval).length,1);
  const begin=f.calls.find(c=>c.path?.endsWith('/begin'));assert.equal(begin.body.action,'add');assert.equal(begin.body.method_id,undefined);assert.equal(begin.body.address,wallet.address);
  assert.equal(f.calls.find(c=>c.approval).approval.request.action,'add');
  assert(!f.calls.some(c=>c.path?.endsWith('/cancel')));
});
test('a lost add reply checks the saved method without another proof or approval',async()=>{
  const f=ceremony({lost:true});await f.flow.start({action:'add',method:f.method,automatic:true});
  assert.equal(f.states.at(-1).stage,'unknown');await f.flow.retry();assert.equal(f.states.at(-1).stage,'done');
  assert.equal(f.calls.filter(c=>c.path?.endsWith('/complete')).length,1);
  assert.equal(f.calls.filter(c=>c.signature).length,1);assert.equal(f.calls.filter(c=>c.approval).length,1);
});
test('wallet changes stop the new automatic flow before signing or passkey approval',async()=>{
  const f=ceremony({change:true});await f.flow.start({action:'add',method:f.method,automatic:true});
  assert.equal(f.states.at(-1).stage,'error');assert.equal(f.calls.filter(c=>c.signature||c.approval).length,0);
});
test('connected WalletConnect reuses its admitted window and existing permission without another Home prompt',async()=>{
  const f=ceremony({connector:'walletconnect'});await f.flow.start({action:'add',method:f.method,automatic:true,delegateWalletConnect:true});
  assert.equal(f.states.at(-1).stage,'done');assert(!f.states.some(state=>state.stage==='internet-notice'));assert.equal(f.calls.find(c=>c.select).select.transport,undefined);
  assert.equal(f.calls.filter(c=>c.signature).length,1);assert.equal(f.calls.filter(c=>c.approval).length,1);
});




test('Home reads connected wallets through the requesting System launch, then checks methods with Home authority',async()=>{
  let options;const calls=[],source={postMessage(data,_origin,ports){if(data.type==='home:wallet-signin-accounts-request'){ports[0].postMessage({accounts:[{account_id:'connected',connector_id:'wallet-metamask',address:wallet.address,chain_namespace:'eip155:20'}]});ports[0].close();}}},context={kind:'app-frame',targetId:'system',source,homeToken:'system-token'};
  const data={type:'home:wallet-signin-request',requestId:'one',homeToken:'system-token',action:'add',methodId:''};
  handleWalletSigninRequest({source,data},context,{authorityToken:()=> 'home-token',current:()=>true,changed(){},manage:async value=>{options=value;return {status:'cancelled'};},api:async(path,body,token)=>{
    calls.push({path,token});
    if(path.endsWith('/passkeys'))return {passkeys:[{principal_id:'alex',role:'admin'}]};
    if(path.endsWith('/system/summary'))throw new Error('Home cannot read System authority');
    return {account_id:'alex',methods:[]};
  }});
  await new Promise(resolve=>setImmediate(resolve));const connected=await options.loadConnected();assert.equal(connected[0].address,wallet.address);
  assert(!calls.some(c=>c.path.endsWith('/system/summary')));
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
  permission='off';await assert.rejects(client.effect({kind:'signin',message:'Runtime sign-in',address:wallet.address,chain_id:20}),{code:'permission'});assert.equal(calls.filter(c=>c.method==='personal_sign').length,1);
});

const {connectionView,reduceSummary,viewText}=await import('../capsules/_shared/wallet-connection-view.mjs');

test('the shared phone wait presents Home sign-in without disconnecting the payment session',()=>{
  const summary=reduceSummary({connector_id:'wallet-walletconnect',request_id:'signin',capsule_id:'home',requesting_app_name:'Home',intent:'auth_challenge',address:wallet.address,status:'pending',reason:'Sign in',expires_at:180},{connector:'wallet-walletconnect'});
  const view=connectionView({window:'walletconnect',stage:'request-phone',purpose:'home-signin',summary,supportedActions:['stop-waiting']});
  assert.match(viewText(view.status),/Continue in Phone wallet/);assert.doesNotMatch(viewText(view.notice),/disconnect/);assert.equal(view.wait,null);
  assert.throws(()=>connectionView({window:'walletconnect',stage:'request-phone',purpose:'home-signin',summary:{...summary,actor:'browser'}}),/Home sign-in presentation/);
  assert.throws(()=>connectionView({window:'walletconnect',stage:'linked',purpose:'home-signin'}),/closed connection purpose/);
});

const {selectConnectedWalletConnect}=await import('../capsules/home/browser/wallet-signin-connector.mjs');
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




test('closing the admitted phone window ends a pending signature without waiting for ceremony expiry',async t=>{
  t.mock.timers.enable({apis:['setInterval']});
  const listen=new EventTarget(),controller=new AbortController(),sent=[];
  const source={closed:false,postMessage(data){sent.push(data);if(data.operation==='select')queueMicrotask(()=>listen.dispatchEvent(Object.assign(new Event('message'),{source,origin:'null',data:{type:'home:wallet-signin-effect-result',homeToken:'connector',requestId:data.requestId,result:{...wallet,connector:'walletconnect'}}})));}};
  const selected=await selectConnectedWalletConnect({signal:controller.signal,method:wallet},{listen,open:async()=>({source,homeToken:'connector'}),current:()=>!source.closed});
  const pending=selected.sign('Runtime message');const ended=assert.rejects(pending,{code:'disconnected'});
  source.closed=true;t.mock.timers.tick(250);await ended;
  assert.equal(sent.filter(data=>data.operation==='sign').length,1);controller.abort();
});

test('a revoked WalletConnect option offers an error instead of an empty choice screen',async()=>{
  const states=[],paths=[];
  const flow=createWalletSigninFlow({api:async path=>{paths.push(path);return {walletconnect_signin_available:false};},select:async()=>{throw new Error('relay must remain unused');},approve:async()=>{},render:s=>states.push(s)});flows.push(flow);
  await flow.start({action:'signin',automatic:true});await flow.choose('walletconnect');
  assert.equal(states.at(-1).stage,'error');assert.match(states.at(-1).message,/Use your passkey/);assert.deepEqual(paths,['/api/auth/passkey/status']);
});

test('Runtime connector choices work in a fresh browser and on a desktop surface',()=>{
  const runtime=['metamask','unisat','walletconnect'];
  assert.deepEqual(availableSigninOptions(runtime,{providers:[{rdns:'io.metamask'}],unisatAvailable:true,walletconnectAvailable:true}).map(m=>m.connector),runtime);
  const extensions=availableSigninOptions(['metamask'],{providers:[{rdns:'io.rabby',name:'Rabby Wallet'},{rdns:'com.brave.wallet',name:'Brave Wallet'}]});
  assert.deepEqual(extensions.map(m=>m.providerId),['io.rabby','com.brave.wallet']);
  assert.deepEqual(availableSigninOptions(runtime,{walletconnectAvailable:true}).map(m=>m.connector),['walletconnect']);
  assert.deepEqual(availableSigninOptions(['metamask'],{walletconnectAvailable:true}),[]);
});
test('the browser stores only a closed remembered connector choice',()=>{
 const values=new Map();
 const storage={getItem:k=>values.get(k),setItem:(k,v)=>values.set(k,v),removeItem:k=>values.delete(k)};
 saveSigninChoice('metamask',storage);assert.equal(readSigninChoice(storage),'metamask');
 saveSigninChoice('metamask:com.brave.wallet',storage);assert.equal(readSigninChoice(storage),'metamask:com.brave.wallet');
 saveSigninChoice('0x'+'12'.repeat(20),storage);assert.equal(readSigninChoice(storage),'');
});

}

test('MetaMask enrollment keeps phone relay admission off until a phone method exists',async()=>{
 const server=await signinFixture();server.state.methods=[sampleMethod('metamask')];
 try {
  const status=await (await fetch(server.origin+'/api/auth/passkey/status')).json();
  assert.deepEqual(status.wallet_signin_connectors,['metamask']);assert.equal(status.walletconnect_signin_available,false);
  const result=await fetch(server.origin+'/api/auth/wallet/signin/begin',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({connector:'walletconnect',address:'',chain_id:20,browser_secret:'a'.repeat(64),allow_temporary_internet:true})});
  assert.equal(result.status,403);
 }finally {await server.close();}
});

import {openWalletSigninEntry} from '../capsules/home/browser/wallet-signin-window.mjs';
import {homeGuiReply} from '../capsules/home-gui/browser/home-gui-authority.js';
test("New wallet binds Desktop's exact visible window token while a hidden rail exists",async()=>{
 const listen=new EventTarget(),desktop={},sent=[],rail={targetId:'wallet',source:{postMessage(){throw new Error('hidden rail selected');}}},wallet={targetId:'wallet',source:{closed:false,postMessage:data=>sent.push(data)}};
 const contexts=new Map([['rail-token',rail],['window-token',wallet]]);
 const emit=(data,source=desktop,origin='null')=>listen.dispatchEvent(Object.assign(new Event('message'),{data,source,origin}));
 const result=await openWalletSigninEntry({listen,source:()=>desktop,desktopToken:()=>'desktop-token',context:key=>contexts.get(key),post:message=>{
  const reply=homeGuiReply({type:'home:wallet-connect-entry-ready',requestId:message.requestId,walletToken:'window-token'},'desktop-token');
  queueMicrotask(()=>{emit({...reply,walletToken:'rail-token'},{});emit({...reply,walletToken:'rail-token'},desktop,'https://foreign.example');emit({...reply,requestId:'wrong',walletToken:'rail-token'});emit(reply);});return true;
 }});
 assert.deepEqual(sent,[{type:'elastos.wallet.connect-entry/v1'}]);assert(result.isOpen());contexts.delete('window-token');assert.equal(result.isOpen(),false);
});
test('New wallet refuses a token for another app and cleans up a missing Desktop reply',async()=>{
 const listen=new EventTarget(),desktop={};
 await assert.rejects(openWalletSigninEntry({listen,source:()=>desktop,desktopToken:()=>'desktop-token',context:()=>({targetId:'system',source:{}}),post:message=>{queueMicrotask(()=>listen.dispatchEvent(Object.assign(new Event('message'),{source:desktop,origin:'null',data:homeGuiReply({type:'home:wallet-connect-entry-ready',requestId:message.requestId,walletToken:'wrong-app'},'desktop-token')})));return true;}}),/Wallet window changed/);
 await assert.rejects(openWalletSigninEntry({listen,source:()=>desktop,desktopToken:()=>'desktop-token',context:()=>null,post:()=>true,timeoutMs:1}),/Wallet did not open/);
});

test('Home-managed EVM and Bitcoin accounts are excluded even with an external connector id',()=>{
  for(const proof_type of ['managed_evm','managed_btc_p2wpkh'])for(const connector_id of ['wallet-metamask','wallet-unisat','wallet-walletconnect']) {
    assert.deepEqual(connectedWalletSigninMethods([{account_id:'managed',connector_id,address:method.address,chain_namespace:'eip155:20',proof_type}],[]),[]);
  }
});

const {selectConnectedExtension}=await import('../capsules/home/browser/wallet-signin-connector.mjs');
test('extension sign-in waits for its bound connector review and then signs the Runtime message once',async()=>{
  const listen=new EventTarget(),controller=new AbortController(),sent=[],signed=[];let reply,stops=0,changed=0;
  const emit=(data,source,origin='null')=>listen.dispatchEvent(Object.assign(new Event('message'),{data,source,origin}));
  const source={postMessage(data){sent.push(data);if(data.operation==='review')reply=()=>emit({type:'home:wallet-signin-effect-result',homeToken:'connector',requestId:data.requestId,result:{approved:true}},source);else if(data.operation==='finish')queueMicrotask(()=>emit({type:'home:wallet-signin-effect-result',homeToken:'connector',requestId:data.requestId,result:{}},source));}};
  const signer=await selectConnectedExtension('metamask',{signal:controller.signal,changed(){changed++;}},{listen,open:async()=>({homeToken:'connector',source}),current:()=>true,select:async()=>({...method,name:'MetaMask',check:async()=>{},sign:async message=>{signed.push(message);return {signature:'proof'};},close(){stops++;}})});
  try {
    const pending=signer.sign('Runtime exact message');await Promise.resolve();assert.deepEqual(signed,[]);
    const data={type:'home:wallet-signin-effect-result',homeToken:'connector',requestId:sent[0].requestId,result:{approved:true}};
    emit(data,{});emit(data,source,'https://foreign.example');emit({...data,homeToken:'other'},source);emit({...data,requestId:'other'},source);await Promise.resolve();assert.deepEqual(signed,[]);
    reply();assert.deepEqual(await pending,{signature:'proof'});assert.deepEqual(signed,['Runtime exact message']);
    emit({...data,error:true},source);assert.equal(changed,0,'a second answer to a consumed review has no authority');assert.equal(stops,0);
    assert.deepEqual(sent.map(x=>x.operation),['review','finish']);assert(!sent.some(x=>'browser_secret' in x||'step_up_token' in x));
  }finally{controller.abort();assert.equal(stops,1);}
});

test('closing the extension connector rejects its pending review before any provider signature',async t=>{
  t.mock.timers.enable({apis:['setInterval']});
  const controller=new AbortController(),listen=new EventTarget();let active=true,signed=0,changed=0;
  const signer=await selectConnectedExtension('unisat',{signal:controller.signal,changed(){changed++;}},{listen,open:async()=>({homeToken:'connector',source:{postMessage(){}}}),current:()=>active,select:async()=>({...method,check:async()=>{},sign:async()=>{signed++;},close(){}})});
  const pending=assert.rejects(signer.sign('Runtime message'),{code:'disconnected'});active=false;t.mock.timers.tick(250);await pending;assert.equal(signed,0);assert.equal(changed,1);controller.abort();
});
