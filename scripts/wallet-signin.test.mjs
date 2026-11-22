import test from 'node:test';
import assert from 'node:assert/strict';
import { createWalletSigninFlow } from '../capsules/home/browser/wallet-signin-flow.mjs';

const method = {method_id:'wallet:one',connector:'metamask',address:'0x'+'12'.repeat(20),chain_id:20,network:'',sign_in_enabled:false};
function fixture({lost=false}={}) {
  const calls=[], states=[]; let completeCalls=0;
  const flow=createWalletSigninFlow({
    randomSecret:()=> 'a'.repeat(64),
    api:async(path,body)=>{
      calls.push({path,body:structuredClone(body)});
      if(path.endsWith('/begin')) return {ceremony_id:'ceremony',message:'exact Home message',expires_at:Date.now()/1000+120,approval:{operation:'auth.wallet.method',request:{ceremony_id:'ceremony'}}};
      if(path.endsWith('/complete')) { if(lost && completeCalls++===0) throw new TypeError('lost reply'); return {status:'complete',sign_in_enabled:true}; }
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
  assert.deepEqual(f.calls.find(c=>c.approve).approve,{operation:'auth.wallet.method',request:{ceremony_id:'ceremony'}});
  assert.equal(f.calls.find(c=>c.path?.endsWith('/complete')).body.step_up_token,'step-up');
});
test('uncertain completion retries identical proof without signing or approving again',async()=>{
  const f=fixture({lost:true});await f.flow.start({action:'enable',method});await f.flow.confirm();await f.flow.approve();
  assert.equal(f.states.at(-1).stage,'unknown');await f.flow.retry();
  const sent=f.calls.filter(c=>c.path?.endsWith('/complete'));assert.equal(sent.length,2);assert.deepEqual(sent[0],sent[1]);
  assert.equal(f.calls.filter(c=>c.sign).length,1);assert.equal(f.calls.filter(c=>c.approve).length,1);
});
