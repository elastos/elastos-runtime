import test from 'node:test';
import assert from 'node:assert/strict';
import {createWalletSigninFlow,walletSigninError} from '../capsules/home/browser/wallet-signin-flow.mjs';
const method={method_id:'m',connector:'metamask',address:'0x'+'12'.repeat(20),chain_id:20,network:'',sign_in_enabled:true};
function fixture(t,{action='add',refused=0,applied=false}={}) {
  t.mock.timers.enable({apis:['setTimeout']});
  let open=true,reads=0,complete=0;const calls=[],states=[];
  const flow=createWalletSigninFlow({now:()=>1000,randomSecret:()=> 'a'.repeat(64),render:s=>states.push(s),approve:async()=> 'step',select:async()=>({...method,check:async()=>{},sign:async()=>({signature:'proof'}),close(){}}),api:async(path,body)=>{
    calls.push(path);
    if(path.endsWith('/begin'))return {ceremony_id:'c',message:'Runtime message',expires_at:1180,approval:{operation:'auth.wallet.method',request:{ceremony_id:'c',action,account_id:'a',method_id:'m'}}};
    if(path.endsWith('/complete')){complete++;if(refused)throw {status:refused};throw new TypeError('reply lost');}
    if(path.endsWith('/cancel')){open=false;return {};}
    if(path==='/api/auth/wallet-methods'){reads++;return {account_id:'a',methods:applied?[method]:[],open_changes:open?['c']:[]};}
    return {};
  }});
  return {flow,calls,states,get reads(){return reads;},get complete(){return complete;},apply(){applied=true;open=false;},keepMethod(){applied=true;},retire(){open=false;},async start(){await flow.start({action,method,automatic:true,accountId:'a',sessionMethodId:'m'});}};
}
for(const action of ['add','remove'])for(const status of [403,409])test(`round3 ${action} ${status} retires refusal immediately`,async t=>{
  const f=fixture(t,{action,refused:status});if(action==='remove')f.apply();await f.start();
  assert.equal(f.flow.state.stage,'error');assert.match(f.flow.state.message,/Home could not/);
  assert(f.calls.some(p=>p.endsWith('/cancel')));assert.equal(f.reads,1);
  assert.doesNotMatch(f.flow.state.message,/Check again/);
});
test('round3 unknown automatically reads until committed without resending proof',async t=>{
  const f=fixture(t);await f.start();assert.equal(f.flow.state.stage,'unknown');f.apply();
  t.mock.timers.tick(2000);await new Promise(setImmediate);
  assert.equal(f.flow.state.stage,'done');assert.equal(f.complete,1);assert.equal(f.reads,2);
});
test('round3 unknown automatically ends as NotApplied when Runtime retires the action',async t=>{
  const f=fixture(t);await f.start();f.retire();t.mock.timers.tick(2000);await new Promise(setImmediate);
  assert.equal(f.flow.state.stage,'error');assert.match(f.flow.state.message,/did not save/);assert.equal(f.complete,1);
});

test('round3 ending the current wallet session clears an uncertain removal',async t=>{
 const f=fixture(t,{action:'remove'});f.keepMethod();await f.start();assert.equal(f.flow.state.stage,'unknown');
 assert.equal(await f.flow.sessionEnded(),true);assert.equal(f.flow.state.stage,'done');
});
test('round3 another wallet change cannot use session end as a receipt',async t=>{
 const f=fixture(t);await f.start();assert.equal(await f.flow.sessionEnded(),false);assert.equal(f.flow.state.stage,'unknown');
});

import {reduceSummary,connectionView,viewText} from '../capsules/_shared/wallet-connection-view.mjs';
test('round3 Browser generated request copy uses plain actions and keeps real message text',()=>{
 for(const [intent,reason] of [['browser_personal_sign','Browser page requests personal_sign'],['transaction_intent','Browser page requests eth_sendTransaction on eip-mainnet']]){
  const input={request_id:'r',connector_id:'wallet-metamask',capsule_id:'browser',requesting_origin:'https://example.org',requesting_app_name:'Browser',intent,reason,status:'pending',address:method.address,expires_at:1800000600};
  assert.equal(reduceSummary(input,{connector:'wallet-metamask'}).detail,'');
  assert.equal(reduceSummary({...input,reason:'My exact message'},{connector:'wallet-metamask'}).detail,'My exact message');
 }
 const summary=reduceSummary({request_id:'t',connector_id:'wallet-walletconnect',capsule_id:'browser',intent:'transaction_intent',requesting_origin:'https://example.org',requesting_app_name:'Browser',status:'approved',address:method.address,expires_at:1800000600},{connector:'wallet-walletconnect'});
 const v=connectionView({window:'walletconnect',stage:'transaction-cancelled',summary,localSafety:null,supportedActions:['close-window']});
 const text=viewText(v.notice);assert.doesNotMatch(text,/Close this window|window controls/);assert.match(text,/Check.*wallet|Check.*Activity/i);
});

import {handleWalletSigninRequest} from '../capsules/home/browser/wallet-signin-host.mjs';
test('round3 closing a caller is distinct from ending its Home session',async()=>{
 let caller=true,session=true,options;const source={postMessage(){}};
 const data={type:'home:wallet-signin-request',requestId:'r',homeToken:'system',action:'remove',methodId:'m'};
 handleWalletSigninRequest({source,data},{source,kind:'app-frame',targetId:'system',homeToken:'system'},{api:async path=>path.endsWith('/wallet-methods')?{account_id:'a',methods:[method]}:{passkeys:[]},manage:async input=>{options=input;return {status:'cancelled'};},authorityToken:()=> 'owner',authorityCurrent:()=>()=>session,sessionMethodId:()=> 'm',current:()=>caller,changed(){}});
 await new Promise(setImmediate);assert.equal(options.sessionMethodId,'m');caller=false;assert.equal(options.isCurrent(),false);assert.equal(options.sessionCurrent(),true);session=false;assert.equal(options.sessionCurrent(),false);
});

test('round3 a payment blocks phone add with its real next step',()=>{
 assert.equal(walletSigninError({code:'payment-pending'},'add'),'Finish or check the payment in Wallet, then select Try again.');
});
