import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {dirname} from 'node:path';
import {walletConnectFixtureRequire} from './lib/walletconnect-relay-fixture.mjs';
import {windowPresentation, walletConnectView, errorStage} from '../capsules/wallet-walletconnect/browser/walletconnect-window-state.mjs';
import {walletConnectMessages as messages} from '../capsules/wallet-walletconnect/browser/walletconnect-client.mjs';
const now=1800000000,address='0x'+'12'.repeat(20);
const account={address,chain_namespace:'eip155:8453'};
const session={address,chain:'eip155:8453',name:'Scripted phone wallet'};
const request={request_id:'request-1',connector_id:'wallet-walletconnect',capsule_id:'browser',requesting_origin:'https://example.test',reason:'Test message',status:'pending',intent:'credential',proof_type:'siwe',address,chain_namespace:'eip155:8453',expires_at:now+600};
const initial={permission:'granted',connection:{session},accounts:[account]};
const cases=[
 ['nothing-saved',{}],['nothing-saved',{permission:'off',connection:{}}],['internet-ready',{permission:'granted'}],
 ['internet-pending',{permission:'requested',pending:{}}],['internet-refused',{permission:'refused'}],['internet-off',{permission:'revoked',connection:{}}],
 ['guest-access',{ownerNeeded:true,permission:'off'}],['window-expired',{expired:true}],
 ['preparing-qr',{busy:true,phase:'starting'}],['qr-shown',{qrData:'data:image/png;base64,AAAA'}],
 ['link-wait',{...initial,busy:true,phase:'ownership'}],
 ['saved-unlinked',{...initial,accounts:[]}],['linked',initial],
 ['wallet-removed',{connection:{removed:true}}],['connection-expired',{connection:{expired:true}}],
 ['request-waiting',{...initial,requests:[request]}],['request-multiple',{...initial,requests:[request,{...request,request_id:'request-2'}]}],
 ['request-phone',{...initial,busy:true,phase:'signature',activeRequest:request}],
 ['transaction-phone',{...initial,busy:true,phase:'transaction',activeRequest:{...request,intent:'transaction_intent'}}],
 ['request-unsendable',{...initial,requests:[{...request,intent:'browser_typed_data_sign'}]}],
 ['request-expired',{...initial,requests:[{...request,expires_at:now-1}]}],
 ['transaction-deadline',{...initial,requests:[{...request,intent:'transaction_intent',expires_at:now+250}]}],
 ['transaction-waiting',{...initial,requests:[{...request,intent:'transaction_intent'}]}],
 ['transaction-reopened',{...initial,requests:[{...request,intent:'transaction_intent',status:'approved'}]}],
 ['request-waiting',{permission:'granted',requests:[request]}],
 ['request-internet-off',{connection:{},permission:'revoked',requests:[request]}],
 ['request-internet-pending',{permission:'requested',pending:{},requests:[request]}],
 ['request-wallet-removed',{connection:{removed:true},requests:[request]}],
 ['request-connection-expired',{connection:{expired:true},requests:[request]}],
 ['disconnecting',{...initial,busy:true,phase:'disconnecting'}],
 ...['disconnected','link-declined','link-timeout','link-cancelled','link-error','qr-cancelled','qr-expired','connection-declined'].map(outcome=>[outcome,{...initial,outcome}]),
 ...['request-declined','request-timeout','request-done','request-cancelled','transaction-declined','transaction-timeout','transaction-cancelled','transaction-wallet-error','transaction-done'].map(outcome=>[outcome,{...initial,activeRequest:request,outcome}]),
];
for (const [expected,state] of cases) test(`live controller facts map to ${expected}`,()=>{
 const p=windowPresentation(state,now);assert.equal(p.input.stage,expected);
 const view=walletConnectView(p);assert.equal(view.stage,expected);
 if(['link-wait','request-phone','transaction-phone'].includes(expected)){assert.ok(view.actions.some(a=>a.id==='stop-waiting'));assert.ok(view.actions.every(a=>a.id!=='cancel'));}
});
test('wallet changed account is shown as unlinked, never silently adopted',()=>{
 const p=windowPresentation({...initial,connection:{session:{...session,address:'0x'+'34'.repeat(20)}}},now);
 assert.equal(p.input.stage,'saved-unlinked');assert.equal(p.input.account.accounts[0].address,'0x'+'34'.repeat(20));
 assert.equal(initial.accounts.length,1);
});
test('unsupported current wallet network is named',()=>{assert.match(windowPresentation({...initial,connection:{session:{...session,chain:'eip155:137'}}},now).input.account.accounts[0].networks[0],/Unsupported network.*137/);});
for(const [key,stage,kind] of [['proposalDeclined','connection-declined','link'],['ownershipDeclined','link-declined','link'],['linkTimeout','link-timeout','link'],['signatureDeclined','request-declined','approve'],['signatureTimeout','request-timeout','approve'],['transactionDeclined','transaction-declined','approve'],['transactionTimeout','transaction-timeout','approve']])test(`real client ${key} maps to ${stage}`,()=>assert.equal(errorStage(new Error(messages[key]),{kind},'signature'),stage));

for(const key of ['signatureError','consumed'])test(`consumed ${key} keeps Home uncertainty separate from wallet refusal`,()=>assert.equal(errorStage(new Error(messages[key]),{kind:'approve'},'signature'),'request-unavailable'));

test('account confirmation discards a latent request address after a wallet update',()=>{
 const next='0x'+'34'.repeat(20);
 const p=windowPresentation({...initial,connection:{session:{...session,address:next}},walletChanged:true,outcome:'request-unavailable',activeRequest:request},now);
 const view=walletConnectView(p);assert.equal(view.stage,'saved-unlinked');assert.equal(view.request,null);assert.equal(view.account.accounts[0].address,next);
});
test('linking with another request pending still confirms the wallet-selected account',()=>{
 const next='0x'+'34'.repeat(20);
 const view=walletConnectView(windowPresentation({...initial,connection:{session:{...session,address:next}},busy:true,phase:'ownership',requests:[request]},now));
 assert.equal(view.stage,'link-wait');assert.equal(view.request,null);assert.equal(view.account.accounts[0].address,next);
});

test('a proof being checked keeps its bound account after the wallet changes',()=>{
 const next='0x'+'34'.repeat(20);const view=walletConnectView(windowPresentation({...initial,connection:{session:{...session,address:next}},proofAccount:session,busy:true,checking:true,effectPhase:'ownership',phase:'checking'},now));
 assert.equal(view.account.accounts[0].address,address);assert.equal(view.account.accounts[0].networks[0],'Base');
});

for(const blocked of [{status:'approved',intent:'transaction_intent'},{intent:'browser_typed_data_sign'},{chain_namespace:'eip155:137'},{expires_at:now-1}])test(`blocked first request leaves a valid request reachable: ${JSON.stringify(blocked)}`,()=>{
 const view=walletConnectView(windowPresentation({...initial,requests:[{...request,...blocked},{...request,request_id:'valid'}]},now));
 assert.equal(view.stage,'request-multiple');assert.equal(view.request.id,'valid');assert.ok(view.actions.some(row=>row.id==='send-request'));
});
for(const permission of ['revoked','refused','requested'])for(const intent of ['credential','transaction_intent'])test(`sent ${intent} retains consumed state when permission is ${permission}`,()=>{
 const sent={...request,status:'approved',intent};const view=walletConnectView(windowPresentation({...initial,permission,activeRequest:sent,dispatchedRequestId:sent.request_id},now));
 assert.equal(view.stage,intent==='transaction_intent'?'transaction-wallet-error':'request-unavailable');assert.ok(view.actions.every(row=>row.id!=='send-request'));
});
for(const intent of ['credential','transaction_intent'])test(`expiry of a sent ${intent} never asks for resending`,()=>{
 const sent={...request,status:'approved',intent};const view=walletConnectView(windowPresentation({...initial,connection:{expired:true},activeRequest:sent,dispatchedRequestId:sent.request_id},now));
 assert.equal(view.stage,intent==='transaction_intent'?'transaction-wallet-error':'request-unavailable');assert.ok(view.actions.every(row=>row.id!=='send-request'));
});
test('dispatch identity belongs only to the actual sent request',()=>{
 const view=walletConnectView(windowPresentation({...initial,connection:{removed:true},activeRequest:{...request,request_id:'not-sent'},dispatchedRequestId:'earlier'},now));assert.equal(view.stage,'request-wallet-removed');
});
test('a previous challenge deadline cannot shorten a later request',()=>{
 const view=walletConnectView(windowPresentation({...initial,requests:[request],deadline:now+1},now));assert.equal(view.wait,'Time left: 10:00');
});
test('an unrelated request cannot shorten the ownership challenge',()=>{
 const view=walletConnectView(windowPresentation({...initial,busy:true,phase:'ownership',requests:[{...request,expires_at:now+1}],deadline:now+300},now));assert.equal(view.wait,'Time left: 5:00');
});
test('the QR renderer reproduces from the existing locked graph',async()=>{
 const require=walletConnectFixtureRequire,{build}=require('esbuild');
 assert.equal(require('esbuild/package.json').version,'0.28.0');assert.equal(require('qrcode/package.json').version,'1.5.4');
 const locked=await readFile(new URL('./walletconnect/package-lock.json',import.meta.url));assert.equal(createHash('sha256').update(locked).digest('hex'),'a12af83d3f92729c8bf06ff21505973a68c01d9fe08e157d837adc6c4b08833d');
 const result=await build({entryPoints:[require.resolve('qrcode/lib/browser.js')],absWorkingDir:dirname(require.resolve('qrcode/package.json')),bundle:true,write:false,format:'esm',platform:'browser',target:'es2022',minify:true});
 const shipped=await readFile(new URL('../capsules/wallet-walletconnect/browser/qrcode.mjs',import.meta.url),'utf8');assert.equal(result.outputFiles[0].text,shipped.slice(shipped.indexOf('\n')+1));
});
for(const left of [50,1500])test(`a sent request shows the bounded wallet wait for ${left}s approval lifetime`,()=>{
 const view=walletConnectView(windowPresentation({...initial,busy:true,phase:'signature',activeRequest:{...request,expires_at:now+left},deadline:now+(left<300?300:600)},now));assert.equal(view.wait,left<300?'Time left: 5:00':'Time left: 10:00');
});
for(const outcome of ['request-declined','transaction-declined'])for(const ended of [{permission:'revoked'},{connection:{removed:true}},{connection:{expired:true}}])test(`known ${outcome} survives ${JSON.stringify(ended)}`,()=>{
 const view=walletConnectView(windowPresentation({...initial,...ended,activeRequest:{...request,status:'approved',intent:outcome.startsWith('transaction')?'transaction_intent':'credential'},dispatchedRequestId:request.request_id,outcome},now));assert.equal(view.stage,outcome);
});
test('disconnect failure stays on a non-request recovery screen',()=>assert.equal(errorStage(new Error('Could not clear connection'),{kind:'disconnect'},'disconnecting'),'link-error'));
test('a transaction consumed elsewhere retains unknown-result recovery',()=>assert.equal(errorStage(new Error(messages.consumed),{kind:'approve',intent:'transaction_intent'},'starting'),'transaction-wallet-error'));
for(const phase of ['starting','signature','idle'])test(`Home failure in ${phase} never claims the wallet failed to sign`,()=>assert.equal(errorStage(new Error('Runtime returned an invalid signature request.'),{kind:'approve'},phase),'request-unavailable'));
test('an unsent expired request is not offered a connection-and-resend recovery',()=>assert.equal(windowPresentation({...initial,connection:{expired:true},requests:[{...request,expires_at:now-1}]},now).input.stage,'request-expired'));

for(const [ending,extra,expected] of [
 ['deadline',{},'transaction-reopened'],
 ['wallet removal',{connection:{removed:true}},'transaction-wallet-removed'],
 ['session expiry',{connection:{expired:true}},'transaction-wallet-error'],
 ['access loss',{permission:'revoked'},'transaction-wallet-error'],
])test(`approved transaction reopened after ${ending} keeps unknown-result recovery`,()=>{
 const row={...request,intent:'transaction_intent',status:'approved',expires_at:now-1};
 const view=walletConnectView(windowPresentation({...initial,...extra,requests:[row]},now));
 assert.equal(view.stage,expected);assert.ok(view.actions.every(action=>!['send-request','start-over','connect'].includes(action.id)));
 assert.match(view.notice.map(part=>part.text).join(''),/Check .*wallet.*before sending again/);
});
