import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync,readdirSync } from 'node:fs';
import { join } from 'node:path';
import { exerciseWalletConnect,transactionHash } from './lib/walletconnect-capsule-fixture.mjs';
const sent = r=>r.calls.filter(c=>c.method==='eth_sendTransaction');
const completed = r=>r.routes.filter(c=>c.path.endsWith('/complete'));
test('opaque capsule sends the exact Runtime transaction once',async()=>{const r=await exerciseWalletConnect();assert.equal(r.error,undefined);assert.equal(sent(r).length,1);assert.equal(completed(r).length,1);});
for(const scenario of ['wrong-account','wrong-chain','expired','approved'])test(`capsule refuses ${scenario} before sending`,async()=>{const r=await exerciseWalletConnect(scenario);assert.equal(typeof r.error,'string');assert.equal(sent(r).length,0);assert.equal(completed(r).length,0);});
for(const scenario of ['account-change-during-send','chain-change-during-send','expired-during-send'])test(`capsule preserves the returned hash after ${scenario}`,async()=>{const r=await exerciseWalletConnect(scenario);assert.equal(r.error,undefined);assert.equal(completed(r).length,1);assert.equal(JSON.parse(completed(r)[0].input.body).transaction_hash,transactionHash);});
test('completion refusal retains the returned transaction hash',async()=>{const r=await exerciseWalletConnect('completion-refused');assert.ok(r.error.includes(transactionHash));assert.match(r.error,/check it before sending again/);});
test('wallet chosen text is refused as a transaction hash',async()=>{const r=await exerciseWalletConnect('invalid-hash');assert.match(r.error,/invalid transaction hash/);assert.doesNotMatch(r.error,/fake recovery website/);assert.equal(completed(r).length,0);});
for(const change of ['account-change-during-send','chain-change-during-send','expired-during-send'])test(`unused signature stops after ${change}`,async()=>{const r=await exerciseWalletConnect(`signature-${change}`);assert.equal(typeof r.error,'string');assert.equal(completed(r).length,0);});
for(const [scenario,expiry] of [['signature-short',300],['long-request',600]])test(`capsule bounds the SDK timeout for ${scenario}`,async()=>{const r=await exerciseWalletConnect(scenario);assert.equal(r.error,undefined);assert.equal(r.calls.find(c=>['personal_sign','eth_sendTransaction'].includes(c.method)).expiry,expiry);});
for(const [scenario,data] of [['link','0x52756e74696d65206f776e6572736869702070726f6f6620c2b72066697874757265'],['link-uppercase-hex','0x4142'],['link-odd-hex','0x3078313233']])test(`capsule signs the exact ownership DATA for ${scenario}`,async()=>{const r=await exerciseWalletConnect(scenario);assert.equal(r.error,undefined);assert.equal(r.calls.find(c=>c.method==='personal_sign').params[0],data);});
test('disconnect clears Runtime storage and memory while retaining linked accounts',async()=>{const r=await exerciseWalletConnect('disconnect');assert.equal(r.result.status,'disconnected');assert.equal(r.memoryCleared,true);assert.ok(r.routes.some(c=>c.path==='storage'&&c.input.method==='DELETE'));assert.ok(!r.routes.some(c=>c.path.includes('accounts')));});
test('Home capsules contain no WalletConnect SDK import or signer',()=>{
  const scan=path=>{for(const e of readdirSync(path,{withFileTypes:true})){const p=join(path,e.name);if(e.isDirectory())scan(p);else if(/\.[cm]?js$/.test(e.name))assert.doesNotMatch(readFileSync(p,'utf8'),/connectWalletConnectEvm|@walletconnect\/|import\s*\([^)]*reown-appkit/);}};
  for(const e of readdirSync('capsules',{withFileTypes:true}))if(e.isDirectory()&&e.name.startsWith('home'))scan(join('capsules',e.name));
});

test('typed data uses EIP-712 and preserves the exact Runtime message',async()=>{const r=await exerciseWalletConnect('typed');assert.equal(r.error,undefined);const call=r.calls.find(c=>c.method==='eth_signTypedData_v4');assert.equal(call.params[1],'Runtime approval fixture');assert.equal(JSON.parse(completed(r)[0].input.body).signature_type,'eip712');});
for(const scenario of ['typed-unavailable','unsupported']) test(`${scenario} remains pending instead of consuming an approval`,async()=>{const r=await exerciseWalletConnect(scenario);assert.equal(typeof r.error,'string');assert.equal(r.routes.filter(c=>c.path.endsWith('/approve')).length,0);assert.equal(completed(r).length,0);});
test('a reset creates a fresh SDK API while old SDK writes keep their stale revision',async()=>{
  const {createWalletConnectClient}=await import('../capsules/wallet-walletconnect/browser/walletconnect-client.mjs');
  let revision='"0"',loads=0,disconnects=0;const sessions=[];
  const signer=`0x${'12'.repeat(20)}`;
  const provider={on(){},request:async({method})=>method==='eth_accounts'?[signer]:method==='eth_chainId'?'0x14':'fixture-signature'};
  const api=async(path,input)=>{
    if(path==='wallet/config')return {walletconnect:{project_id:'fixture-project',storage_revision:revision}};
    if(path==='internet')return {status:'granted'};
    if(path==='storage'){if(input.headers['if-match']!==revision)throw new Error('stale SDK');return {};}
    if(path.endsWith('/challenge'))return {message:'fixture',expires_at:Date.now()/1000+600|0};
    if(path.endsWith('/verify'))return {};
    throw new Error('Unexpected resource');
  };
  const client=createWalletConnectClient({api,origin:'http://localhost',loadAdapter:async()=>{loads++;return {
    connectWalletConnectEvm:async options=>{sessions.push(options.api);return provider;},disconnectWalletConnectEvm:async()=>{disconnects++;},
  };}});
  await client.effect({kind:'link'});revision='"1"';await client.effect({kind:'link'});
  assert.equal(loads,2);assert.equal(disconnects,1);
  await assert.rejects(sessions[0]('storage',{method:'POST'}),/stale SDK/);
  assert.deepEqual(await sessions[1]('storage',{method:'POST'}),{});
});

test('protected-content rights signs the exact Runtime hex handoff with personal_sign',async()=>{
  const r=await exerciseWalletConnect('protected-content');assert.equal(r.error,undefined);
  assert.deepEqual(r.calls.find(c=>c.method==='personal_sign').params.slice(0,1),['0x414243']);
  assert.equal(JSON.parse(completed(r)[0].input.body).signature_type,'personal_sign');
});
test('a stalled old SDK disconnect cannot block a new storage generation',async t=>{
  t.mock.timers.enable({apis:['setTimeout']});
  const {createWalletConnectClient}=await import('../capsules/wallet-walletconnect/browser/walletconnect-client.mjs');
  let revision='"0"',loads=0;const signer=`0x${'12'.repeat(20)}`;
  const provider={on(){},request:async({method})=>method==='eth_accounts'?[signer]:method==='eth_chainId'?'0x14':'fixture'};
  const api=async path=>path==='wallet/config'?{walletconnect:{project_id:'fixture',storage_revision:revision}}:
    path==='internet'?{status:'granted'}:path.endsWith('/challenge')?{message:'fixture',expires_at:Date.now()/1000+600|0}:{};
  const client=createWalletConnectClient({api,origin:'http://localhost',loadAdapter:async()=>{loads++;return {
    connectWalletConnectEvm:async()=>provider,disconnectWalletConnectEvm:()=>new Promise(()=>{}),
  };}});
  await client.effect({kind:'link'});revision='"1"';const pending=client.effect({kind:'link'});
  for(let i=0;i<10;i++)await Promise.resolve();assert.equal(loads,1);
  t.mock.timers.tick(5000);assert.deepEqual(await pending,{status:'linked'});assert.equal(loads,2);
});
