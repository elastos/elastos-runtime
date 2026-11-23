import test, {afterEach} from 'node:test';
import assert from 'node:assert/strict';
import { createWalletSigninFlow as createProductFlow, walletSigninOriginAllowed } from '../capsules/home/browser/wallet-signin-flow.mjs';
const activeFlows=new Set();
const createWalletSigninFlow=options=>{const flow=createProductFlow(options);activeFlows.add(flow);return flow;};
afterEach(async()=>{await Promise.all([...activeFlows].map(flow=>flow.cancel()));activeFlows.clear();});

const method = {method_id:'wallet:one',connector:'metamask',address:'0x'+'12'.repeat(20),chain_id:20,network:'',sign_in_enabled:false};
function fixture({lost=false}={}) {
  const calls=[], states=[]; let completeCalls=0,lastAction;
  const flow=createWalletSigninFlow({
    randomSecret:()=> 'a'.repeat(64),
    api:async(path,body)=>{
      calls.push({path,body:structuredClone(body)});
      if(path.endsWith('/begin')) {lastAction=body.action;return {ceremony_id:'ceremony',message:'exact Home message',expires_at:Date.now()/1000+120,approval:{operation:'auth.wallet.method',request:{ceremony_id:'ceremony',action:body.action,account_id:'principal:alex',method_id:method.method_id}}};}
      if(path.endsWith('/complete')) { if(lost && completeCalls++===0) throw new TypeError('lost reply'); return {status:lastAction==='remove'?'removed':'complete',method_id:method.method_id,sign_in_enabled:lastAction==='enable'}; }
      return {};
    },
    select:async()=>({...method,check:async()=>{},sign:async message=>{calls.push({sign:message});return {signature:'proof',signature_type:'personal_sign',public_key:''};},close(){}}),
    approve:async approval=>{calls.push({approve:approval});return 'step-up';},
    render:state=>states.push(state),
  });
  return {flow,calls,states};
}
test('enable reviews before signature, then requests exact passkey approval',async()=>{
  const f=fixture();await f.flow.start({action:'enable',method,account:'Alex'});
  assert.equal(f.states.at(-1).stage,'review');assert.equal(f.calls.filter(c=>c.sign).length,0);
  await f.flow.confirm();assert.equal(f.states.at(-1).stage,'approval');assert.equal(f.calls.filter(c=>c.approve).length,0);
  await f.flow.approve();assert.equal(f.states.at(-1).stage,'done');
  assert.equal(f.calls.find(c=>c.sign).sign,'exact Home message');
  assert.deepEqual(f.calls.find(c=>c.approve).approve,{operation:'auth.wallet.method',request:{ceremony_id:'ceremony',action:'enable',account_id:'principal:alex',method_id:method.method_id}});
  assert.equal(f.calls.find(c=>c.path?.endsWith('/complete')).body.step_up_token,'step-up');
});
test('uncertain completion retries identical proof without signing or approving again',async()=>{
  const f=fixture({lost:true});await f.flow.start({action:'enable',method});await f.flow.confirm();await f.flow.approve();
  assert.equal(f.states.at(-1).stage,'unknown');await f.flow.retry();
  const sent=f.calls.filter(c=>c.path?.endsWith('/complete'));assert.equal(sent.length,2);assert.deepEqual(sent[0],sent[1]);
  assert.equal(f.calls.filter(c=>c.sign).length,1);assert.equal(f.calls.filter(c=>c.approve).length,1);
});

test('disable and remove use passkeys without asking the wallet to sign',async()=>{
  for(const action of ['disable','remove']) {
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
  const data={type:'home:wallet-signin-request',requestId:'one',homeToken:'launch',action:'enable',methodId:method.method_id};
  let reads=0,managed=0;
  const options={api:async path=>{reads++;return path.endsWith('/passkeys')?{passkeys:[{principal_id:'principal:one',display_name:'Alex'}]}:{account_id:'principal:one',methods:[method]};},manage:async input=>{managed++;assert.equal(input.method,method);return {status:'complete'};},current:()=>true,changed(){}};
  for(const invalid of [{...context,targetId:'browser'},{...context,source:{}},{...context,homeToken:'other'}])handleWalletSigninRequest({source,data},invalid,options);
  assert.equal(reads,0);assert.equal(managed,0);
  handleWalletSigninRequest({source,data},context,options);await new Promise(resolve=>setImmediate(resolve));
  assert.equal(reads,2);assert.equal(managed,1);
});

test('every method action checks the approval against the reviewed ceremony and account',async()=>{
  for(const action of ['add','enable','disable','remove'])for(const mismatch of ['action','account_id','ceremony_id','method_id']) {
    if(action==='add' && mismatch==='method_id')continue;
    const states=[];let signs=0;
    const request={action,account_id:'principal:alex',ceremony_id:'one',method_id:method.method_id};request[mismatch]='different';
    const flow=createWalletSigninFlow({api:async path=>path.endsWith('/begin')?{ceremony_id:'one',message:'exact message',expires_at:Date.now()/1000+120,approval:{operation:'auth.wallet.method',request}}:{},
      select:async()=>({...method,close(){},sign(){signs++;}}),approve:()=>{throw new Error('must not approve');},render:s=>states.push(s)});
    await flow.start({action,method:action==='add'?null:method,accountId:'principal:alex'});if(action==='add')await flow.choose('metamask');
    assert.equal(states.at(-1).stage,'error',`${action} refuses a different ${mismatch}`);assert.equal(signs,0);
  }
});

test('WalletConnect pairing and Add wallet each have their own browser secret',async()=>{
  const calls=[];let serial=0;
  const flow=createWalletSigninFlow({randomSecret:()=>String(++serial).padStart(64,'0'),
    api:async(path,body)=>{calls.push({path,body});if(path.endsWith('/begin')) {
      const ceremony_id=path.includes('/wallet-methods/')?'addition':'pairing';
      return {ceremony_id,message:'message',expires_at:Date.now()/1000+120,approval:{operation:'auth.wallet.method',request:{ceremony_id,action:'add',account_id:'principal:alex',method_id:'new'}}};
    }return {};},select:async()=>({...method,connector:'walletconnect',close(){}}),approve:()=>{},render(){}});
  await flow.start({action:'add'});await flow.choose('walletconnect');
  const begins=calls.filter(c=>c.path.endsWith('/begin'));await flow.cancel();assert.equal(begins.length,2);assert.notEqual(begins[0].body.browser_secret,begins[1].body.browser_secret);
  for(const begin of begins){const id=begin.path.includes('/wallet-methods/')?'addition':'pairing';assert(calls.some(c=>c.path.endsWith('/cancel')&&c.body.ceremony_id===id&&c.body.browser_secret===begin.body.browser_secret));}
});

test('Bitcoin method selection keeps address case while EVM accepts checksum case',async()=>{
  for(const connector of ['unisat','metamask']) {
    const wallet={...method,connector,address:connector==='unisat'?'1A'+'b'.repeat(30):'0x'+'ab'.repeat(20),chain_id:connector==='unisat'?0:20,network:connector==='unisat'?'livenet':''};
    const states=[];
    const flow=createWalletSigninFlow({api:async path=>path.endsWith('/begin')?{ceremony_id:'one',message:'message',expires_at:Date.now()/1000+120,approval:{operation:'auth.wallet.method',request:{ceremony_id:'one',action:'enable',account_id:'principal:alex',method_id:method.method_id}}}:{},
      select:async()=>({...wallet,address:wallet.address.toLowerCase(),close(){}}),approve(){},render:s=>states.push(s)});
    await flow.start({action:'enable',method:wallet});assert.equal(states.at(-1).stage,connector==='unisat'?'error':'review');await flow.cancel();
  }
});

test('wallet sign-in uses HTTPS outside numeric loopback and localhost',()=>{
  for(const origin of ['https://home.example','http://localhost:8090','http://127.0.0.1:8090','http://127.42.0.1:8090','http://[::1]:8090'])assert(walletSigninOriginAllowed(origin),origin);
  for(const origin of ['http://home.example','http://127.example','http://192.168.1.2:8090'])assert.equal(walletSigninOriginAllowed(origin),false,origin);
});
