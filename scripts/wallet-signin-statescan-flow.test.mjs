import test from 'node:test';
import assert from 'node:assert/strict';
import {createWalletSigninFlow} from '../capsules/home/browser/wallet-signin-flow.mjs';

function harness({action='add',completeFails=1,statusThrows=false}={}) {
  const calls=[],states=[];let clock=1000,completes=0,committed=false,approvals=0;
  const wallet={address:'0x'+'11'.repeat(20),chain_id:20,network:'',name:'MetaMask',check:async()=>{},sign:async()=>({signature:'0xsig',signature_type:'personal_sign',public_key:''}),close(){}};
  const api=async(path,body)=>{
    calls.push(path);
    if(path==='/api/auth/passkey/status'){if(statusThrows)throw Object.assign(new Error('net'),{});return {walletconnect_signin_available:true};}
    if(path.endsWith('/begin'))return {ceremony_id:'wallet:1',expires_at:clock+180,message:'Sign',approval:{operation:'auth.wallet.method',notice:'',request:{ceremony_id:'wallet:1',action,account_id:'acct',method_id:'m1'}}};
    if(path.endsWith('/complete')){completes++;committed=true;if(completes<=completeFails)throw Object.assign(new Error('lost'),{status:502});return action==='signin'?{app_token:'t',session_id:'s',principal_id:'p',proof_binding_id:'b'}:{status:'complete',method_id:'m1',sign_in_enabled:true};}
    if(path.endsWith('/cancel'))return {status:'cancelled'};
    throw new Error('unexpected '+path);
  };
  const flow=createWalletSigninFlow({api,select:async()=>wallet,approve:async()=>{approvals++;return 'step';},render:s=>states.push({...s}),now:()=>clock});
  return {flow,calls,states,advance:s=>{clock+=s;},get committed(){return committed;},get approvals(){return approvals;}};
}

test('TRACE A: add committed, response lost -> unknown; deadline then tells the person to try again and cancels',async t=>{
  t.mock.timers.enable({apis:['setTimeout']});
  const h=harness({action:'add',completeFails:99});
  await h.flow.start({action:'add',accountId:'acct',automatic:true});
  await h.flow.choose('metamask');
  assert.equal(h.flow.state.stage,'unknown');assert.equal(h.committed,true);
  h.advance(181);t.mock.timers.tick(181000);await new Promise(r=>setImmediate(r));
  console.log('after deadline:',h.flow.state.stage,'|',h.flow.state.message,'| calls:',h.calls.join(','));
  // Desired explicit model: OutcomeUnknown is left only by a reconciling read, never by a timer to "try again".
  assert.equal(h.flow.state.stage,'unknown','unknown outcome must stay pending');assert(!h.calls.some(path=>path.endsWith('/cancel')));
});

test('TRACE B: approve() is accepted in review for add, before any wallet proof exists',async t=>{
  const h=harness({action:'add',completeFails:0});t.after(()=>h.flow.cancel());
  await h.flow.start({action:'add',accountId:'acct',automatic:false});
  await h.flow.choose('metamask');
  assert.equal(h.flow.state.stage,'review');
  await h.flow.approve();
  console.log('approve-from-review: approvals',h.approvals,'stage',h.flow.state.stage,'calls',h.calls.join(','));
  assert.equal(h.approvals,0,'passkey prompt must not run before the wallet signed');
});

test('TRACE C: sign-in status read fails -> WalletConnect choice reports the wallet cannot sign in',async t=>{
  const h=harness({action:'signin',statusThrows:true});t.after(()=>h.flow.cancel());
  await h.flow.start({action:'signin'});
  await h.flow.choose('walletconnect');
  console.log('status-unknown:',h.flow.state.stage,'|',h.flow.state.message);
  assert.doesNotMatch(h.flow.state.message,/cannot sign in to this Home/);
});

test('TRACE D: cancel while the add completion is in flight',async()=>{
  const calls=[];let release;const gate=new Promise(r=>release=r);let clock=1000;
  const wallet={address:'0x'+'11'.repeat(20),chain_id:20,network:'',check:async()=>{},sign:async()=>({signature:'0xsig',signature_type:'personal_sign',public_key:''}),close(){}};
  const completed=[];
  const flow=createWalletSigninFlow({now:()=>clock,render(){},select:async()=>wallet,approve:async()=>'step',onComplete:r=>completed.push(r),api:async(path)=>{calls.push(path);
    if(path.endsWith('/begin'))return {ceremony_id:'wallet:1',expires_at:clock+180,message:'Sign',approval:{operation:'auth.wallet.method',request:{ceremony_id:'wallet:1',action:'add',account_id:'acct',method_id:'m1'}}};
    if(path==='/api/auth/wallet-methods')return {account_id:'acct',methods:[{method_id:'m1',sign_in_enabled:true}]};
    if(path.endsWith('/complete')){await gate;return {status:'complete',method_id:'m1',sign_in_enabled:true};}
    return {};}});
  await flow.start({action:'add',accountId:'acct',automatic:true});
  const running=flow.choose('metamask');await new Promise(r=>setImmediate(r));
  assert.equal(flow.state.stage,'completing');
  await flow.cancel();release();await running;
  console.log('cancel-in-completing: stage',flow.state.stage,'onComplete calls',completed.length,'calls',calls.join(','));
  assert.equal(completed.length,1,'a committed add must be reported as complete, not cancelled');
});

for(const action of ['add','remove']) {
  for(const applied of [true,false])test(`${action}: a lost reply settles only from the bound method list (${applied?'Done':'NotApplied'})`,async()=>{
    let clock=1000,readsFail=true,appliedOnHome=false;const calls=[],completed=[];
    const method={method_id:'m1',connector:'metamask',address:'0x'+'11'.repeat(20),chain_id:20,network:'',sign_in_enabled:true};
    const flow=createWalletSigninFlow({now:()=>clock,render(){},select:async()=>({...method,check:async()=>{},sign:async()=>({signature:'proof'}),close(){}}),approve:async()=>'step',onComplete:result=>completed.push(result),api:async(path)=>{
      calls.push(path);
      if(path.endsWith('/begin'))return {ceremony_id:'one',expires_at:1180,message:action==='add'?'Add':'',approval:{operation:'auth.wallet.method',request:{ceremony_id:'one',action,account_id:'acct',method_id:'m1'}}};
      if(path.endsWith('/complete')){appliedOnHome=applied;throw new TypeError('reply lost');}
      if(path==='/api/auth/wallet-methods'){
        if(readsFail)throw new TypeError('status unavailable');
        return {account_id:'acct',open_changes:clock<1180?['one']:[],methods:(action==='add'?appliedOnHome:!appliedOnHome)?[method]:[]};
      }
      return {};
    }});
    await flow.start({action,method,automatic:true,accountId:'acct'});
    assert.equal(flow.state.stage,'unknown');
    await flow.cancel();assert.equal(flow.state.stage,'unknown');
    await assert.rejects(flow.start({action:'add'}),{code:'busy'});
    readsFail=false;await flow.retry();
    if(!applied){assert.equal(flow.state.stage,'unknown');clock=1181;await flow.retry();}
    assert.equal(flow.state.stage,applied?'done':'error');assert.equal(completed.length,applied?1:0);
    assert.equal(calls.filter(p=>p.endsWith('/complete')).length,1);
    assert.equal(calls.filter(p=>p.endsWith('/cancel')).length,0);
    if(!applied)assert.equal(flow.state.message,'Home did not save this change.');
  });
}

test('a method list for another account leaves the saved change unknown',async t=>{
  t.mock.timers.enable({apis:['setTimeout']});
  let clock=1000;
  const h=createWalletSigninFlow({now:()=>clock,render(){},approve:async()=>'step',select:async()=>({address:'0x'+'11'.repeat(20),chain_id:20,network:'',check:async()=>{},sign:async()=>({signature:'proof'}),close(){}}),api:async path=>{
    if(path.endsWith('/begin'))return {ceremony_id:'one',expires_at:1180,message:'Add',approval:{operation:'auth.wallet.method',request:{ceremony_id:'one',action:'add',account_id:'acct',method_id:'m1'}}};
    if(path==='/api/auth/wallet-methods')return {account_id:'another-account',methods:[{method_id:'m1',sign_in_enabled:true}]};
    return {status:'complete',method_id:'m1',sign_in_enabled:true};
  }});
  await h.start({action:'add',automatic:true,accountId:'acct'});await h.choose('metamask');
  assert.equal(h.state.stage,'unknown');clock=1181;await h.retry();assert.equal(h.state.stage,'unknown');
});

test('a changed browser clock cannot retire a change that Runtime still has open',async()=>{
  let browserClock=1000,runtimeOpen=true;
  const flow=createWalletSigninFlow({now:()=>browserClock,render(){},approve:async()=>'step',select:async()=>({address:'0x'+'11'.repeat(20),chain_id:20,network:'',check:async()=>{},sign:async()=>({signature:'proof'}),close(){}}),api:async path=>{
    if(path.endsWith('/begin'))return {ceremony_id:'one',expires_at:1180,message:'Add',approval:{operation:'auth.wallet.method',request:{ceremony_id:'one',action:'add',account_id:'acct',method_id:'m1'}}};
    if(path==='/api/auth/wallet-methods')return {account_id:'acct',open_changes:runtimeOpen?['one']:[],methods:[]};
    throw new TypeError('lost reply');
  }});
  await flow.start({action:'add',automatic:true,accountId:'acct'});await flow.choose('metamask');browserClock=2000;
  await flow.retry();assert.equal(flow.state.stage,'unknown');runtimeOpen=false;await flow.retry();assert.equal(flow.state.stage,'error');
});

test('a malformed sign-in status read reports an unavailable check',async()=>{
  const flow=createWalletSigninFlow({render(){},select(){throw new Error('status was not checked');},approve(){},api:async()=>({})});
  await flow.start({action:'signin'});await flow.choose('walletconnect');
  assert.match(flow.state.message,/could not check wallet sign-in/);assert.doesNotMatch(flow.state.message,/cannot sign in to this Home/);
});
