import { historicalTestSource } from './lib/historical-test-source.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync,readdirSync } from 'node:fs';
import { join } from 'node:path';
import { exerciseWalletConnect,transactionHash,address } from './lib/walletconnect-capsule-fixture.mjs';
import {createWalletConnectClient,walletConnectMessages as messages} from '../capsules/wallet-walletconnect/browser/walletconnect-client.mjs';
const sent = r=>r.calls.filter(c=>c.method==='eth_sendTransaction');
const completed = r=>r.routes.filter(c=>c.path.endsWith('/complete')&&!JSON.parse(c.input.body).declined);
test('opaque capsule sends the exact Runtime transaction once',async()=>{const r=await exerciseWalletConnect();assert.equal(r.error,undefined);assert.equal(sent(r).length,1);assert.equal(completed(r).length,1);});
for(const scenario of ['wrong-account','wrong-chain','expired','approved'])test(`capsule refuses ${scenario} before sending`,async()=>{const r=await exerciseWalletConnect(scenario);assert.equal(typeof r.error,'string');assert.equal(sent(r).length,0);assert.equal(completed(r).length,0);});
for(const scenario of ['account-change-during-send','chain-change-during-send','expired-during-send'])test(`capsule preserves the returned hash after ${scenario}`,async()=>{const r=await exerciseWalletConnect(scenario);assert.equal(r.error,undefined);assert.equal(completed(r).length,1);assert.equal(JSON.parse(completed(r)[0].input.body).transaction_hash,transactionHash);});
test('completion refusal retains the returned transaction hash',async()=>{const r=await exerciseWalletConnect('completion-refused');assert.ok(r.error.includes(transactionHash));assert.match(r.error,/check it before sending again/);});
test('wallet chosen text is refused as a transaction hash',async()=>{const r=await exerciseWalletConnect('invalid-hash');assert.match(r.error,/invalid transaction hash/);assert.doesNotMatch(r.error,/fake recovery website/);assert.equal(completed(r).length,0);});
for(const change of ['account-change-during-send','chain-change-during-send','expired-during-send'])test(`unused signature stops after ${change}`,async()=>{const r=await exerciseWalletConnect(`signature-${change}`);assert.equal(typeof r.error,'string');assert.equal(completed(r).length,0);});
for(const [scenario,expiry] of [['signature-short',300],['long-request',600]])test(`capsule bounds the SDK timeout for ${scenario}`,async()=>{const r=await exerciseWalletConnect(scenario);assert.equal(r.error,undefined);assert.equal(r.calls.find(c=>['personal_sign','eth_sendTransaction'].includes(c.method)).expiry,expiry);});
for(const [scenario,data] of [['link','0x52756e74696d65206f776e6572736869702070726f6f6620c2b72066697874757265'],['link-uppercase-hex','0x4142'],['link-odd-hex','0x3078313233']])test(`capsule signs the exact ownership DATA for ${scenario}`,async()=>{const r=await exerciseWalletConnect(scenario);assert.equal(r.error,undefined);assert.equal(r.calls.find(c=>c.method==='personal_sign').params[0],data);});
test('disconnect clears Runtime storage and memory while retaining connected accounts',async()=>{const r=await exerciseWalletConnect('disconnect');assert.equal(r.result.status,'disconnected');assert.equal(r.memoryCleared,true);assert.ok(r.routes.some(c=>c.path==='storage'&&c.input.method==='DELETE'));assert.ok(!r.routes.some(c=>c.path.includes('accounts')));});
test('Home capsules contain no WalletConnect SDK import or signer',()=>{
  const scan=path=>{for(const e of readdirSync(path,{withFileTypes:true})){const p=join(path,e.name);if(e.isDirectory())scan(p);else if(/\.[cm]?js$/.test(e.name))assert.doesNotMatch(readFileSync(p,'utf8'),/connectWalletConnectEvm|@walletconnect\/|import\s*\([^)]*reown-appkit/);}};
  for(const e of readdirSync('capsules',{withFileTypes:true}))if(e.isDirectory()&&e.name.startsWith('home'))scan(join('capsules',e.name));
});

for(const scenario of ['typed','typed-unavailable','unsupported']) test(`${scenario} remains pending instead of consuming an approval`,async()=>{const r=await exerciseWalletConnect(scenario);assert.equal(typeof r.error,'string');assert.equal(r.routes.filter(c=>c.path.endsWith('/approve')).length,0);assert.equal(completed(r).length,0);assert.equal(r.calls.filter(c=>c.method==='eth_signTypedData_v4').length,0);});
test('a reset creates a fresh SDK API while old SDK writes keep their stale revision',async()=>{
  const {createWalletConnectClient}=await import('../capsules/wallet-walletconnect/browser/walletconnect-client.mjs');
  let revision='"0"',loads=0,disconnects=0;const sessions=[];
  const signer=`0x${'12'.repeat(20)}`;
  const provider={chainId:20,session:{namespaces:{eip155:{chains:['eip155:20'],accounts:[`eip155:20:${signer}`]}}},on(){},request:async({method})=>method==='eth_accounts'?[signer]:method==='eth_chainId'?'0x14':'fixture-signature'};
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
  const provider={chainId:20,session:{namespaces:{eip155:{chains:['eip155:20'],accounts:[`eip155:20:${signer}`]}}},on(){},request:async({method})=>method==='eth_accounts'?[signer]:method==='eth_chainId'?'0x14':'fixture'};
  const api=async path=>path==='wallet/config'?{walletconnect:{project_id:'fixture',storage_revision:revision}}:
    path==='internet'?{status:'granted'}:path.endsWith('/challenge')?{message:'fixture',expires_at:Date.now()/1000+600|0}:{};
  const client=createWalletConnectClient({api,origin:'http://localhost',loadAdapter:async()=>{loads++;return {
    connectWalletConnectEvm:async()=>provider,disconnectWalletConnectEvm:()=>new Promise(()=>{}),
  };}});
  await client.effect({kind:'link'});revision='"1"';const pending=client.effect({kind:'link'});
  for(let i=0;i<10;i++)await Promise.resolve();assert.equal(loads,1);
  t.mock.timers.tick(5000);assert.deepEqual(await pending,{status:'linked'});assert.equal(loads,2);
});

for(const scenario of ['numeric-chain','numeric-chain-link'])test(`capsule accepts the pinned SDK numeric chain for ${scenario}`,async()=>{const r=await exerciseWalletConnect(scenario);assert.equal(r.error,undefined);assert.equal(r.result.status,scenario.endsWith('link')?'linked':'completed');});
for(const value of [0,-1,1.5,9007199254740992,'20','0x0','0x20000000000000',null])test(`capsule refuses invalid chain ${JSON.stringify(value)} before authority changes`,async()=>{const r=await exerciseWalletConnect('invalid-chain:'+JSON.stringify(value));assert.match(r.error,/invalid chain/);assert.equal(r.routes.filter(c=>c.path.endsWith('/approve')||c.path.endsWith('/verify')).length,0);});

test('late send reports dismissal without claiming completion',async()=>{
  const r=await exerciseWalletConnect('dismissed-during-send');
  assert.equal(r.error,undefined);
  assert.equal(r.result.status,'sent_after_dismissal');
  assert.equal(r.result.message,'Request dismissed. Your wallet reported this transaction as sent.');
  const doc=readFileSync(new URL('../docs/WALLET_PROVIDER.md',import.meta.url),'utf8').replace(/\s+/g,' ');
  assert(doc.includes(r.result.message),'the documented late receipt quotes the actual wallet result');
  assert.equal(completed(r).length,1);
});


test('an unapproved request network stops before the phone and before handoff',async()=>{
  const r=await exerciseWalletConnect('unapproved-network');
  assert.equal(r.error,messages.unapprovedNetwork('Base'));
  assert.equal(sent(r).length,0);assert.equal(r.routes.filter(call=>call.path.endsWith('/approve')).length,0);
});
test('an unknown SDK error stays in the console and gives a safe recovery message',async t=>{
  const logs=[];t.mock.method(console,'error',(...args)=>logs.push(args));
  const r=await exerciseWalletConnect('sdk-unknown');
  assert.equal(r.error,messages.transactionError);
  assert.deepEqual(logs,[['WalletConnect SDK:','transaction','local']]);
});

for (const scope of ['signature','transaction','link','proposal']) for (const code of [4001,5000,5001,5002,5003]) test(`${scope} phone decline ${code} is muted and true`,async()=>{
  const r=await exerciseWalletConnect(`${scope}-phone-declined:${code}`);
  assert.equal(r.error,messages[`${scope==='link'?'ownership':scope}Declined`]);
  assert.equal(r.tone,'muted');assert.equal(completed(r).length,0);
  const declined=r.routes.filter(c=>c.path.endsWith('/complete')&&JSON.parse(c.input.body).declined);
  assert.equal(declined.length,['signature','transaction'].includes(scope)?1:0);
  if(declined.length){assert.equal(r.status,'rejected');const body=JSON.parse(declined[0].input.body);assert.equal(body.signature,undefined);assert.equal(body.transaction_hash,undefined);}
});
for (const scope of ['signature','transaction','link','proposal']) for (const [ending,key] of [['expired','Timeout'],['error:-32000','Error'],['error:5100','Error']]) test(`${scope} phone ${ending} gives a working next step`,async()=>{
  const r=await exerciseWalletConnect(`${scope}-phone-${ending}`);
  assert.equal(r.error,scope==='proposal'&&ending==='expired'?'The QR code expired. Select Connect wallet for a new one.':messages[`${['link','proposal'].includes(scope)?'link':scope}${key}`]);
  assert.equal(r.tone,'muted');assert.equal(completed(r).length,0);
});
for (const scope of ['signature','transaction']) for (const ending of ['declined:4001','expired','error:-32000','error:5100']) test(`${scope} second Review after ${ending} cannot dispatch again`,async()=>{
  const r=await exerciseWalletConnect(`${scope}-phone-${ending}`);
  assert.equal(r.status,ending.startsWith('declined')?'rejected':'approved');assert.equal(r.secondError,messages.consumed);
  assert.equal(r.routes.filter(c=>c.path.endsWith('/approve')).length,1);
  assert.equal(r.calls.filter(c=>['personal_sign','eth_sendTransaction'].includes(c.method)).length,1);
});
for (const [scenario,name] of [['listed-without-account','Ethereum'],['unknown-network',null]]) test(`${scenario} stops before handoff`,async()=>{
  const r=await exerciseWalletConnect(scenario);
  if(name)assert.equal(r.error,messages.unapprovedNetwork('Ethereum'));
  else assert.equal(r.error,messages.unsupportedNetwork('137'));
  assert.equal(sent(r).length,0);assert.equal(r.routes.filter(c=>c.path.endsWith('/approve')).length,0);
});

test('a network change after handoff cannot offer rejection of a consumed signature',async()=>{
  const r=await exerciseWalletConnect('signature-unsupported-chain-after-sign');
  assert.equal(r.status,'approved');assert.equal(completed(r).length,0);
  assert.equal(r.calls.filter(c=>c.method==='personal_sign').length,1);
  assert.doesNotMatch(r.error,/Reject|approve.*phone|review again/i);
  assert.equal(r.tone,'muted');
});

for (const scope of ['signature','transaction','link','proposal']) for (const code of [-32000,5100,6]) for (const alias of ['expired-text','cancelled-text']) test(`coded wallet errors stay contextual: ${scope} ${code} ${alias}`,async()=>{
  const r=await exerciseWalletConnect(`${scope}-phone-error:${code}:${alias}`);
  assert.equal(r.error,messages[`${['link','proposal'].includes(scope)?'link':scope}Error`]);
  assert.equal(r.tone,'muted');assert.equal(completed(r).length,0);
  if(['signature','transaction'].includes(scope)){assert.equal(r.status,'approved');assert.equal(r.secondError,messages.consumed);}
});

for(const scope of ['signature','transaction','link','proposal'])test(`uncoded wallet expiry-text replies stay contextual: ${scope}`,async()=>{
  const r=await exerciseWalletConnect(`${scope}-phone-error:uncoded:expired-text`);
  assert.equal(r.error,messages[`${['link','proposal'].includes(scope)?'link':scope}Error`]);
});
for(const change of ['account-change-during-send','approved-chain-change-during-send','expired-during-send'])test(`consumed signature recovery after ${change} asks for a new request`,async()=>{
  const r=await exerciseWalletConnect(`signature-${change}`);
  assert.equal(r.error,messages.consumed);
});
test('consumed signature completion failure asks the app for a new request',async()=>{
  const r=await exerciseWalletConnect('signature-completion-refused');
  assert.equal(r.error,messages.signatureError);
});

test('round18 ownership asks for the five-minute challenge deadline',async()=>{
  const r=await exerciseWalletConnect('link');assert.equal(r.error,undefined);
  assert.equal(r.calls.find(c=>c.method==='personal_sign').expiry,300);
});
test('round18 signature completion preserves the expired-window recovery',async()=>{
  const r=await exerciseWalletConnect('signature-completion-window-expired');
  assert.equal(r.error,'This wallet window expired. Close it and open WalletConnect again.');
});

for(const connector of ['wallet-metamask',undefined])test(`duplicate identity uses the WalletConnect method even in an overbroad API response: ${connector||'legacy MetaMask'}`,async()=>{
 // Deliberately overbroad input tests the client guard; the production endpoint is connector-scoped.
 const clientFactory=process.env.WALLETCONNECT_METHOD_GUARD_BEFORE==='1'?(await import('data:text/javascript;base64,'+Buffer.from(historicalTestSource('03fe8a186:capsules/wallet-walletconnect/browser/walletconnect-client.mjs')).toString('base64'))).createWalletConnectClient:createWalletConnectClient;
 const r=await exerciseWalletConnect('link',{addAccount:true,clientFactory,savedAccounts:[{address,chain_namespace:'eip155:20',connector_id:connector,proof_type:'siwe'}]});
 assert.equal(r.error,undefined);assert.equal(r.result.status,'linked');assert.equal(r.calls.filter(c=>c.method==='personal_sign').length,1);
});
