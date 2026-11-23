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
