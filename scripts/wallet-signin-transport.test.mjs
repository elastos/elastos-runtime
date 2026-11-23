import test from 'node:test';
import assert from 'node:assert/strict';
import {createSigninTransportApi} from '../capsules/wallet-walletconnect/browser/signin-transport-api.mjs';
const transport={attempt_token:'fixture-attempt',instance_id:'fixture-instance',storage_revision:0};
test('attempt storage follows ETags and serializes writes with relay admission',async()=>{
  const calls=[];let revision=0,release;
  const api=createSigninTransportApi('https://home.example',transport,async(url,init)=>{
    calls.push({url,headers:init.headers});assert.equal(init.headers['if-match'],`"${revision}"`);
    if(init.method==='POST'&&url.endsWith('/storage')) {
      if(revision===0)await new Promise(resolve=>release=resolve);
      revision++;
    }
    return new Response('{}',{headers:{etag:`"${revision}"`}});
  });
  await api('storage');
  const first=api('storage',{method:'POST'}),second=api('storage',{method:'POST'}),admission=api('relay-admission',{method:'POST'});
  await new Promise(resolve=>setImmediate(resolve));assert.equal(calls.length,2,'later requests wait for the first write');
  release();await Promise.all([first,second,admission]);
  assert.deepEqual(calls.map(c=>c.headers['if-match']),['"0"','"0"','"1"','"2"']);
  assert(calls.every(c=>c.headers['x-elastos-wallet-attempt']===transport.attempt_token&&!c.headers.Authorization));
});
test('attempt storage refuses missing malformed unsafe or older ETags',async()=>{
  for(const etag of ['', '1', '"-1"','"9007199254740992"','"0"']) {
    const api=createSigninTransportApi('https://home.example',{...transport,storage_revision:1},async()=>new Response('{}',{headers:etag?{etag}:{}}));
    await assert.rejects(api('storage'),/Invalid wallet storage revision/);
  }
});
