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

test('System connected-wallet callback accepts only the current Home request and parent',async()=>{
 const {requestWalletSigninChange,requestConnectedSigninWallets}=await import('../capsules/home/browser/wallet-signin-methods.mjs');
 const listen=new EventTarget();let reads=0,request;
 const top={postMessage(data){request=data;}};
 globalThis.window=Object.assign(listen,{top});
 const emit=(data,{source=top,origin='http://localhost:8093',ports=[]}={})=>listen.dispatchEvent(Object.assign(new Event('message'),{data,source,origin,ports}));
 try{
  const pending=requestWalletSigninChange({action:'add',token:'system-token',origin:'http://localhost:8093',loadConnected:async()=>{reads++;return [{address:'owned'}];}});
  const data={type:'home:wallet-signin-accounts-request',requestId:request.requestId};
  for(const options of [{source:{}},{origin:'https://other.example'}])emit(data,options);
  emit({...data,requestId:'retired'});emit({...data,extra:true});assert.equal(reads,0);
  const accounts=await requestConnectedSigninWallets({postMessage(message,_target,ports){emit(message,{ports});}},request.requestId);
  assert.deepEqual(accounts,[{address:'owned'}]);assert.equal(reads,1);
  emit({type:'home:wallet-signin-result',requestId:request.requestId,result:{status:'cancelled'}});
  assert.deepEqual(await pending,{status:'cancelled'});
  await assert.rejects(requestConnectedSigninWallets({postMessage(){}},'expired',{timeoutMs:1}),/could not load/);
 }finally{delete globalThis.window;}
});
