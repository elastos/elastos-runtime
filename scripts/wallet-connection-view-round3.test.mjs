import test from 'node:test';
import assert from 'node:assert/strict';
import {connectionView,reduceConnection,renderConnection,viewText} from '../capsules/_shared/wallet-connection-view.mjs';
import {screens} from '../capsules/_shared/wallet-connection-screens.mjs';
import {states,shared,fixtureView} from './wallet-connection-view-fixtures.mjs';
import {ruleFailures} from './lib/wallet-connection-view-rules.mjs';
const packet=id=>shared.messages.find(r=>r.id===id).message;
const seed=shared.n7PrivateSummaries.find(r=>r.id==='site-wallet-metamask').summary;
const deepFreeze=value=>{if(value&&typeof value==='object'){Object.values(value).forEach(deepFreeze);Object.freeze(value);}return value;};

test('B5: W986 unavailable message and transaction preserve exact recovery and never offer Send',()=>{
  for(const intent of ['browser_personal_sign','transaction_intent']){
    const v=reduceConnection({window:'metamask',stage:intent==='transaction_intent'?'transaction-waiting':'request-waiting',waitSeconds:300},{message:packet('outcome-request_unavailable'),summary:{...seed,intent},nowSeconds:1800000001});
    assert.equal(v.stage,'request-unavailable');assert.match(viewText(v.status),/new request/);
    assert.equal(viewText(v.notice),'');assert(!v.actions.some(a=>a.id==='send-request'));assert.equal(v.focus,'outcome');assert.equal(v.wait,null);
  }
});

test('F2: refusal keeps its app-return notice with the real unknown-safety packet',()=>{
 const v=reduceConnection({window:'metamask',stage:'request-waiting',waitSeconds:300},{message:packet('outcome-request_not_authorized'),summary:seed,nowSeconds:1800000001});
 assert.equal(viewText(v.notice),'To try again, go back to the app and start a new request.');
 const labelled=reduceConnection({window:'metamask',stage:'request-waiting',waitSeconds:300},{message:packet('outcome-request_not_authorized'),summary:{...seed,requesting_app_name:'Browser'},nowSeconds:1800000001});assert.equal(viewText(labelled.notice),'To try again, go back to Browser and start a new request.');
});

test('B7: nested genuine actions and label parts resist changes after factory checks',()=>{
 const view=connectionView({window:'metamask',stage:'ready'});
 assert(Object.isFrozen(view.actions[0]));assert(Object.isFrozen(view.actions[0].label[0]));
 assert.throws(()=>{view.actions[0].id='send-request';},TypeError);
 assert.throws(()=>{view.actions[0].label[0].text='Approve';},TypeError);
});

test('B8: a deeply frozen forged view still fails renderer provenance',()=>{
 const forged=deepFreeze(structuredClone(connectionView({window:'metamask',stage:'ready'})));
 assert(Object.isFrozen(forged.actions[0].label[0]));assert.throws(()=>renderConnection({},forged),/connectionView/);
});

test('screen definitions are deeply frozen and test copies stay independent',()=>{
 assert(Object.isFrozen(screens));assert(Object.isFrozen(screens.metamask.ready.primary));
 assert.throws(()=>{screens.metamask.ready.primary.label='Approve';},TypeError);
 const copy=structuredClone(screens);copy.metamask.ready.primary.label='A test-only control';
 assert.notEqual(copy.metamask.ready.primary.label,screens.metamask.ready.primary.label);
});

test('start-over oracle independently requires a new QR code sentence',()=>{
 const row=states.find(r=>r.designState==='walletconnect/link-busy'),v=fixtureView(row);
 assert.match(viewText(v.notice),/new QR code/);
 const broken={...v,notice:[{kind:'copy',text:'Try again.'}]};
 assert(ruleFailures(broken,{row,shared}).includes('sentence'));
});

test('B5 B7 B8: deliberately weakened product code fails the independent checks',async t=>{
 const {withTestView}=await import('./lib/wallet-connection-test-module.mjs');
 const broken=[
  {name:'B5 transaction unavailable keeps Send',from:"if(request && message?.outcome==='request_unavailable')",to:"if(request && !request.transaction && message?.outcome==='request_unavailable')",check:module=>{const v=module.reduceConnection({window:'metamask',stage:'transaction-waiting',waitSeconds:300},{message:packet('outcome-request_unavailable'),summary:{...seed,intent:'transaction_intent'},nowSeconds:1800000001});assert.equal(v.stage,'request-unavailable');assert(!v.actions.some(a=>a.id==='send-request'));}},
  {name:'B7 shallow factory freeze',from:'Object.values(value).forEach(freeze); ',to:'',check:module=>{const v=module.connectionView({window:'metamask',stage:'ready'});assert.throws(()=>{v.actions[0].label[0].text='Approve';},TypeError);}},
  {name:'B8 any frozen object accepted',from:'requireValue(renderedViews.has(view),',to:'requireValue(Object.isFrozen(view),',check:module=>{const v=deepFreeze(structuredClone(module.connectionView({window:'metamask',stage:'ready'})));assert.throws(()=>module.renderConnection({},v),/connectionView/);}},
 ];
 for(const m of broken)await t.test(m.name,async()=>withTestView({mutateSource:source=>{assert(source.includes(m.from));return source.replace(m.from,m.to);}},async module=>{assert.throws(()=>m.check(module),assert.AssertionError,m.name+' escaped');t.diagnostic(m.name+': independent assertion failed as required');}));
});

test('F2: every stage has an unknown-safety fixture, with a contract-owned recovery expectation',async t=>{
 const {unknownSafetyStates,contractStates}=await import('./wallet-connection-view-fixtures.mjs');
 const allowed={walletconnect:['link-busy','request-busy'],metamask:['extension-busy','link-busy','request-busy'],unisat:['extension-busy','link-busy','request-busy'],panel:[]};
 assert.equal(unknownSafetyStates.length,states.length+contractStates.length);
 for(const row of unknownSafetyStates)await t.test(row.caseId+' H754 busy / H767 uncertainty / H779 conservative safety',()=>{
  const v=fixtureView(row),expected=allowed[row.window].includes(row.stage),text=viewText(v.notice);
  assert.equal(text.includes('Home cannot tell'),expected,row.caseId);
  assert.doesNotMatch(text,/reload/i);if(row.window==='metamask')assert.doesNotMatch(text,/QR code|also available/,'H779 unknown safety offers no alternative in its copy');assert(!v.actions.some(a=>a.id==='use-walletconnect'));
  if(expected){assert.equal(v.actions.find(a=>a.primary)?.quiet,false,'primary Close has primary styling');assert.match(text,/Activity in Wallet/);assert.equal(v.actions.find(a=>a.primary)?.id,'close-window');assert.equal(v.focus,'close-window');}
  if(row.stage==='request-unavailable'){assert.match(viewText(v.status),/new request/);assert.equal(text,'');}
  if(row.stage==='request-access-error')assert.equal(text,'To try again, go back to Browser and start a new request.');
  if(row.stage==='account-unavailable')assert.match(text,row.window==='metamask'?/Manage connected accounts/:/Choose the required account/);
  if(row.stage==='extension-missing'){assert.match(text,/Close this window/);assert.match(text,/Open Home in a browser/);assert.match(text,/Wallet/);assert.doesNotMatch(text,/QR code/,'H779 unknown safety offers no alternative connector');}
 });
});

test('computed transaction facts have a closed display projection separate from app-authored reason',()=>{
 const display={amount:'0.01',asset:'ETH',destination:'0x1122334455667788990011223344556677889900',network:'Base'};
 const row=states.find(r=>r.designState==='walletconnect/transaction-declined');assert.equal(row.summaryInput.reason,'');assert.deepEqual(row.local.transactionDisplay,{amount:'0.01',asset:'ETH',destination:'0x8bC4…391a',network:'Base'});
 const summary={id:'r',app:'Browser',actor:'browser',title:'Send transaction',transaction:true,detail:'Words the app wrote',site:'https://shop.example',address:null,status:'pending',expiresAt:null};
 const view=connectionView({window:'walletconnect',stage:'transaction-waiting',summary,transactionDisplay:display,localSafety:false,waitSeconds:300});
 assert.equal(view.request.detail,'Words the app wrote');assert.deepEqual(view.transactionDisplay,display);assert.notEqual(view.transactionDisplay,display);
 assert.throws(()=>connectionView({window:'walletconnect',stage:'transaction-waiting',summary,transactionDisplay:{...display,html:'owned'},localSafety:false,waitSeconds:300}),/closed computed/);
});

test('temporary proof folders are removed after success and an uncaught failure',async()=>{
 const {temporaryProof}=await import('./lib/wallet-connection-browser-fixture.mjs');
 const {existsSync}=await import('node:fs');const {spawnSync}=await import('node:child_process');
 const proof=await temporaryProof('wallet-proof-cleanup-');assert(existsSync(proof.path));await proof.cleanup();assert(!existsSync(proof.path));
 const helper=new URL('./lib/wallet-connection-browser-fixture.mjs',import.meta.url).href;
 const child=spawnSync(process.execPath,['--input-type=module','-e',`const {temporaryProof}=await import(process.argv[1]);const proof=await temporaryProof('wallet-proof-failure-');console.log(proof.path);throw new Error('deliberate failure');`,helper],{encoding:'utf8',timeout:5000});
 assert.equal(child.status,1);assert(!existsSync(child.stdout.trim()),'exit cleanup removes the failed run folder');
});

test('H779: alternative advice fails the rule even when its controls are withheld',async()=>{
 const {unknownSafetyStates}=await import('./wallet-connection-view-fixtures.mjs');
 for(const stage of ['ready-multiple','extension-missing','extensions-unavailable','other-ethereum-wallet']){
  const row=unknownSafetyStates.find(r=>r.window==='metamask'&&r.stage===stage),v=fixtureView(row);
  assert(!ruleFailures(v,{row,shared}).includes('payment'));
  const broken={...v,notice:[{kind:'copy',text:stage==='ready-multiple'?'Another wallet is also available.':'Connect a wallet app with a QR code.'}]};
  assert(ruleFailures(broken,{row,shared}).includes('payment'),stage+': passive alternative advice escaped');
 }
});
