import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {selectConnectedWalletConnect,openWalletSigninChooser} from '../capsules/home/browser/wallet-signin-connector.mjs';
const identity={connector:'walletconnect',address:'0x'+'12'.repeat(20),chain_id:20,network:''};
for(const action of ['add','signin'])for(const connector of ['walletconnect'])test(`Home sends ${connector} ${action} action and completes only its matching request`,async()=>{
  const listen=new EventTarget(),controller=new AbortController(),sent=[];
  const source={postMessage(data){sent.push(data);if(data.operation==='stop')return;queueMicrotask(()=>listen.dispatchEvent(Object.assign(new Event('message'),{source,origin:'null',data:{type:'home:wallet-signin-effect-result',homeToken:'connector',requestId:data.requestId,result:data.operation==='select'?identity:data.operation==='review'?{approved:true}:data.operation==='sign'?{signature:'proof',signature_type:'personal_sign',public_key:''}:{}}})));}};
  const options={signal:controller.signal,action,changed(){}};
  const deps={listen,open:async()=>({source,homeToken:'connector'}),current:()=>true,select:async()=>({...identity,connector,check:async()=>{},sign:async()=>({signature:'proof'}),close(){}})};
  const wallet=await selectConnectedWalletConnect(options,deps);
  try {
    await wallet.sign('Runtime sentence');
    const request=sent.find(d=>d.operation===(connector==='walletconnect'?'sign':'review'));
    assert.equal(request.action,action);
    await wallet.complete();
    const complete=sent.find(d=>d.operation==='complete');
    assert.equal(complete.reviewRequestId,request.requestId);
    assert.equal(sent.filter(d=>d.operation==='complete').length,1);
  } finally {controller.abort();}
});

test('Home refuses chooser Cancel during completing and unknown, including a lost window',async t=>{
  t.mock.timers.enable({apis:['setInterval']});
  const listen=new EventTarget(),sent=[],actions=[];let active=true;
  const source={postMessage:d=>sent.push(d)},context={source,homeToken:'wallet'};
  const chooser=await openWalletSigninChooser({listen,open:async()=>context,current:()=>active,focus(){},onAction:a=>actions.push(a)});
  try {
    for(const stage of ['completing','unknown']) {
      active=true;chooser.render({stage});
      listen.dispatchEvent(Object.assign(new Event('message'),{source,origin:'null',data:{type:'home:wallet-signin-chooser-action',homeToken:'wallet',requestId:sent.at(-1).requestId,action:'cancel'}}));
      active=false;t.mock.timers.tick(250);
      assert.deepEqual(actions,[],stage);
    }
  } finally {chooser.close();}
});

test('Home copies use the canonical connector view and its action completion screen',()=>{
  for(const asset of ['wallet-connection-view.mjs','wallet-connection-screens.mjs'])assert.equal(readFileSync('capsules/home/browser/'+asset,'utf8'),readFileSync('capsules/_shared/'+asset,'utf8'));
});

import {connectionView,stageNames,viewText,reduceSummary} from '../capsules/_shared/wallet-connection-view.mjs';
import {shared} from './wallet-connection-view-fixtures.mjs';
test('joined wallet screens use WalletConnect and direct connection words',()=>{
  for(const window of ['walletconnect'])for(const stage of stageNames[window]) {
    const view=connectionView({window,stage,waitSeconds:300,localSafety:false,qrData:'data:image/png;base64,'+readFileSync('scripts/fixtures/wallet-connection-view-qr.png').toString('base64'),summary:reduceSummary({...shared.n7PrivateSummaries.find(r=>r.id==='site-wallet-metamask').summary,connector_id:'wallet-'+window},{connector:'wallet-'+window})});
    const text=[view.title,view.status,view.notice,view.afterNote,...view.actions.map(a=>a.label)].map(value=>typeof value==='string'?value:viewText(value)).join(' ');
    assert.doesNotMatch(text,/Phone wallet|\b[Ll]inked\b|From app:/,window+'/'+stage);
  }
  assert.doesNotMatch(readFileSync('elastos/crates/elastos-auth/src/wallet_signin/vectors.json','utf8'),/urn:elastos:/);
});


import {createWalletSigninFlow} from '../capsules/home/browser/wallet-signin-flow.mjs';
test('Runtime confirmation owns connector completion, including a lost reply',async()=>{
  let committed=false,unavailable=true,completed=0;
  const method={...identity,method_id:'wallet:fixture',sign_in_enabled:true};
  const flow=createWalletSigninFlow({
    api:async(path,body)=>{
      if(path.endsWith('/begin'))return {ceremony_id:'ceremony',message:'Runtime sentence',expires_at:Date.now()/1000+120,approval:{operation:'auth.wallet.method',request:{ceremony_id:'ceremony',action:'add',account_id:'account',method_id:method.method_id}}};
      if(path.endsWith('/complete')){committed=true;throw new TypeError('lost reply');}
      if(path==='/api/auth/wallet-methods'){if(unavailable)throw new TypeError('lost read');return {account_id:'account',methods:committed?[method]:[]};}
      return {};
    },
    select:async()=>({...method,check:async()=>{},sign:async()=>({signature:'proof'}),complete:async()=>{completed++;},close(){}}),
    approve:async()=> 'fixture-step-up',render(){},
  });
  try {
    await flow.start({action:'add',method,delegateWalletConnect:true});await flow.confirm();
    assert.equal(completed,0,'signature alone does not confirm Add');
    await flow.approve();assert.equal(flow.state.stage,'unknown');assert.equal(completed,0);
    unavailable=false;await flow.retry();assert.equal(flow.state.stage,'done');assert.equal(completed,1);
  } finally {await flow.cancel();}
});

test('a lost connector display acknowledgement has a bounded wait',async t=>{
  t.mock.timers.enable({apis:['setTimeout']});
  const listen=new EventTarget(),controller=new AbortController();
  const source={postMessage(data){if(data.operation==='complete'||data.operation==='stop')return;queueMicrotask(()=>listen.dispatchEvent(Object.assign(new Event('message'),{source,origin:'null',data:{type:'home:wallet-signin-effect-result',homeToken:'connector',requestId:data.requestId,result:data.operation==='select'?identity:{signature:'proof',signature_type:'personal_sign',public_key:''}}})));}};
  const wallet=await selectConnectedWalletConnect({signal:controller.signal},{listen,open:async()=>({source,homeToken:'connector'}),current:()=>true});
  try {
    await wallet.sign('Runtime sentence');
    const pending=assert.rejects(wallet.complete(),/display did not answer/);
    t.mock.timers.tick(1500);await pending;
  } finally {controller.abort();}
});

test('connector display cannot delay or cancel a confirmed sign-in',async()=>{
  let showComplete,releaseDisplay;const displayStarted=new Promise(resolve=>showComplete=resolve),calls=[];
  const flow=createWalletSigninFlow({
    api:async(path,body)=>{calls.push(path);if(path.endsWith('/begin'))return {ceremony_id:'ceremony',message:'Runtime sentence',expires_at:Date.now()/1000+120};if(path.endsWith('/complete'))return {app_token:'fixture',session_id:'session',principal_id:'principal',proof_binding_id:'proof'};return {};},
    select:async()=>({...identity,check:async()=>{},sign:async()=>({signature:'proof'}),complete:()=>{showComplete();return new Promise(resolve=>releaseDisplay=resolve);},close(){}}),
    approve:async()=>{},render(){},
  });
  let pending;
  try {
    await flow.start({action:'signin',method:identity,delegateWalletConnect:true});pending=flow.confirm();await displayStarted;
    assert.equal(flow.state.stage,'done');
    await flow.cancel();assert(!calls.some(path=>path.endsWith('/cancel')));
  } finally {releaseDisplay?.();await pending;await flow.cancel();}
});
