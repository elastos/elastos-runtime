import assert from 'node:assert/strict';
import test from 'node:test';
globalThis.document={querySelector:()=>null};
const home=await import('../capsules/home/browser/shell-core.js');
delete globalThis.document;
const session={principal_id:'alice',session_id:'one',proof_binding_id:'passkey:one'};
test('Home session check survives token renewal and rejects a replacement or cleared session',()=>{
 home.setHomeAuthorityToken('original',session);
 const current=home.createHomeAuthorityCheck();
 home.setHomeAuthorityToken('renewed',session);assert.equal(current(),true);
 home.setHomeAuthorityToken('different',{...session,session_id:'two'});assert.equal(current(),false);
 home.setHomeAuthorityToken('again',session);assert.equal(current(),false,'returning to the old identity cannot restore a retired flow');
 const next=home.createHomeAuthorityCheck();home.clearHomeAuthorityToken();assert.equal(next(),false);
});

test('System receives only the current Home result and sends zero client inventory rows',async()=>{
 const {requestWalletSigninChange}=await import('../capsules/home/browser/wallet-signin-methods.mjs');
 const listen=new EventTarget();let request,settled=false;
 const top={postMessage(data){request=data;}};globalThis.window=Object.assign(listen,{top});
 const emit=(data,{source=top,origin='http://localhost:8093'}={})=>listen.dispatchEvent(Object.assign(new Event('message'),{data,source,origin}));
 try {
  const pending=requestWalletSigninChange({action:'add',token:'system-token',origin:'http://localhost:8093'}).then(value=>{settled=true;return value;});
  const result={type:'home:wallet-signin-result',requestId:request.requestId,result:{status:'cancelled'}};
  emit(result,{source:{}});emit(result,{origin:'https://other.example'});emit({...result,requestId:'retired'});
  await Promise.resolve();assert.equal(settled,false);assert.deepEqual(Object.keys(request).sort(),['action','homeToken','methodId','requestId','type']);
  emit(result);assert.deepEqual(await pending,{status:'cancelled'});
 }finally{delete globalThis.window;}
});
