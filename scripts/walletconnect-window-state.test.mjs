import test from 'node:test';
import assert from 'node:assert/strict';
import {windowPresentation, errorStage} from '../capsules/wallet-walletconnect/browser/walletconnect-window-state.mjs';
import {reduceConnection} from '../capsules/wallet-walletconnect/browser/wallet-connection-view.mjs';
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
 ...['request-declined','request-timeout','request-done','request-cancelled','request-wallet-error','transaction-declined','transaction-timeout','transaction-cancelled','transaction-wallet-error','transaction-done'].map(outcome=>[outcome,{...initial,activeRequest:request,outcome}]),
];
for (const [expected,state] of cases) test(`live controller facts map to ${expected}`,()=>{
 const p=windowPresentation(state,now);assert.equal(p.input.stage,expected);
 const view=reduceConnection(p.input,{summary:p.request,otherSummaries:p.otherRequests,nowSeconds:now});assert.equal(view.stage,expected);
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
