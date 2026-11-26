import test from 'node:test';
import assert from 'node:assert/strict';
import {readSigninChoice,saveSigninChoice} from '../capsules/home/browser/wallet-signin-options.mjs';

const oldKey='elastos.signin.choice.v1', newKey='elastos.home.signin-choice';
const storage=()=>{const values=new Map();return {values,getItem:key=>values.get(key)??null,setItem:(key,value)=>values.set(key,value),removeItem:key=>values.delete(key)};};
for(const [old,value] of [['passkey','passkey'],['metamask','wallet-metamask'],['metamask:io.rabby','wallet-metamask:io.rabby'],['unisat','wallet-unisat'],['walletconnect','wallet-walletconnect']]) {
  test(`stored sign-in choice migrates ${old} with Undo reader safety`,()=>{
    const s=storage();s.setItem(oldKey,old);
    assert.equal(readSigninChoice(s),value);
    assert.equal(s.getItem(newKey),value);
    assert.equal(s.getItem(oldKey),old);
    saveSigninChoice(value,s);
    assert.equal(s.getItem(newKey),value);
    assert.equal(s.getItem(oldKey),old);
    // rc.1 changes and clears its own key during Undo.
    s.setItem(oldKey,'passkey');assert.equal(readSigninChoice(s),'passkey');
    s.removeItem(oldKey);assert.equal(readSigninChoice(s),'');
    assert.equal(s.getItem(newKey),null);
  });
}
test('stored sign-in choice rejects wallet addresses and malformed connector ids',()=>{
  const s=storage();
  for(const bad of ['wallet-metamask:0x'+'12'.repeat(20),'wallet-unknown','0x'+'12'.repeat(20)]) {
    saveSigninChoice(bad,s);assert.equal(readSigninChoice(s),'');
    assert.equal(s.getItem(oldKey),null);assert.equal(s.getItem(newKey),null);
  }
});
