import test from 'node:test';
import assert from 'node:assert/strict';
import {readSigninChoice,saveSigninChoice} from '../capsules/home/browser/wallet-signin-options.mjs';

const oldKey='elastos.signin.choice.v1', newKey='elastos.home.signin-choice';
const storage=()=>{const values=new Map();return {values,getItem:key=>values.get(key)??null,setItem:(key,value)=>values.set(key,value),removeItem:key=>values.delete(key)};};
for(const [old,value] of [['passkey','passkey'],['metamask','wallet-metamask'],['metamask:io.rabby','wallet-metamask:io.rabby'],['unisat','wallet-unisat'],['walletconnect','wallet-walletconnect']]) {
  test(`stored sign-in choice uses one key for ${old} and Undo`,()=>{
    const s=storage();s.setItem(oldKey,old);
    assert.equal(readSigninChoice(s),old);
    assert.equal(s.getItem(newKey),null);
    assert.equal(s.getItem(oldKey),old);
    saveSigninChoice(value,s);
    assert.equal(s.getItem(newKey),null);
    assert.equal(s.getItem(oldKey),old);
    assert.deepEqual([...s.values.keys()],[oldKey]);
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

// The Undo witness executes the production reader, message builder and verifier.
// Keep it bound to the original source rather than a rewritten test reader.
test('the rc.1 Undo witness keeps its pinned production implementation',async()=>{
  const {readFile}=await import('node:fs/promises');
  const {createHash}=await import('node:crypto');
  const source=await readFile(new URL('../elastos/crates/elastos-server/tests/fixtures/wallet_signin_rc1.rs',import.meta.url),'utf8');
  const production=source.split('\n').slice(3).join('\n');
  assert.equal(createHash('sha256').update(production).digest('hex'),'ac90eb6babc378822d2f073fcc7efd1e495b6a4a336a8e20f56e606ca3c9662a');
});

test('reading a remembered sign-in choice only reads its single stored key',()=>{
  const s={getItem:key=>{assert.equal(key,oldKey);return 'metamask';},
    setItem:()=>assert.fail('a read wrote a shadow key'),
    removeItem:()=>assert.fail('a read removed a shadow key')};
  assert.equal(readSigninChoice(s),'metamask');
});

test('Home and System load the current sign-in module graph after an update',async()=>{
  const {readFile,readdir}=await import('node:fs/promises');
  const home=new URL('../capsules/home/browser/',import.meta.url);
  const modules=(await readdir(home)).filter(name=>/^wallet-signin.*\.mjs$/.test(name));
  const sources=await Promise.all([...modules.map(name=>new URL(name,home)),
    new URL('shell-auth.js',home),new URL('home-shell-host.js',home),
    new URL('../capsules/system/browser/system.js',import.meta.url),
    new URL('lib/wallet-signin-fixture.mjs',import.meta.url),
    new URL('../capsules/wallet/browser/wallet.js',import.meta.url)
  ].map(path=>readFile(path,'utf8')));
  let imports=0;
  for(const source of sources)for(const match of source.matchAll(/from\s+['"]([^'"]*wallet-signin[^'"]*\.mjs[^'"]*)['"]/g)){
    imports++;assert.match(match[1],/\?v=wallet-signin-2$/);
  }
  assert.ok(imports>10);
  const homePage=await readFile(new URL('index.html',home),'utf8');
  const host=await readFile(new URL('home-shell-host.js',home),'utf8');
  const systemPage=await readFile(new URL('../capsules/system/browser/index.html',import.meta.url),'utf8');
  assert.match(homePage,/home-shell-host\.js\?v=wallet-signin-2/);
  assert.match(host,/shell-auth\.js\?v=wallet-signin-2/);
  assert.match(systemPage,/system\.js\?v=wallet-signin-2/);
});

test('the browser fixture replaces the current Home entry module',async()=>{
  const {signinFixture}=await import('./lib/wallet-signin-fixture.mjs');
  const fixture=await signinFixture();
  try{
    const page=await (await fetch(fixture.origin+'/home/')).text();
    assert.match(page,/src="\/fixture-host\.mjs"/);
    assert.doesNotMatch(page,/src="\.\/home-shell-host\.js/);
  }finally{await fixture.close();}
});
