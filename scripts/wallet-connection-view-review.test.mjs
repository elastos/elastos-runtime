import {withTestView} from './lib/wallet-connection-test-module.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import { connectionView, renderConnection, reduceConnection, viewText } from '../capsules/_shared/wallet-connection-view.mjs';
import { fixtureView, states, shared } from './wallet-connection-view-fixtures.mjs';
import { ruleFailures } from './lib/wallet-connection-view-rules.mjs';
const state = name => states.find(r=>r.designState===name);
const packet = id => shared.messages.find(r=>r.id===id).message;
const summary = shared.n7PrivateSummaries.find(r=>r.id==='site-wallet-metamask').summary;

test('F3: the designed typed-data fixture carries typed data and renders its own title',()=>{
  const row=state('metamask/request-typed-data');
  assert.equal(row.summaryInput.intent,'browser_typed_data_sign');
  assert.equal(fixtureView(row).request.title,'Sign typed data');
});

test('8: earlier-session request has the contract sentence and loses Send',()=>{
  const v=reduceConnection({window:'metamask',stage:'request-waiting',waitSeconds:300},{message:packet('outcome-request_unavailable'),summary,nowSeconds:1800000001});
  assert.equal(viewText(v.status),'This request is unavailable. Return to the app and ask for a new request.');
  assert(!v.actions.some(a=>a.id==='send-request'));assert.equal(v.wait,null);assert.equal(v.focus,'outcome');
});

test('8: message answers select receipt stages before rendering',()=>{
  for(const [id,stage] of [['outcome-declined','request-declined'],['outcome-request_not_authorized','request-access-error'],['settled-answered','request-done']]){
    const v=reduceConnection({window:'metamask',stage:'request-waiting',waitSeconds:300},{message:packet(id),summary,nowSeconds:1800000001});
    assert.equal(v.stage,stage,id);assert.equal(v.focus,'outcome');assert.equal(v.wait,null);assert(!v.actions.some(a=>a.id==='send-request'));
  }
});

test('8: unknown cross-window safety states uncertainty and names Wallet activity',()=>{
  const v=fixtureView({...state('metamask/extension-busy'),safety:'state-payment-none'});
  assert.match(viewText(v.notice),/cannot tell/i);assert.match(viewText(v.notice),/Wallet activity/);assert.doesNotMatch(viewText(v.notice),/reload/i);
});

test('9: renderer rejects forged and copied views before touching the document',()=>{
  const valid=connectionView({window:'metamask',stage:'ready'});
  for(const view of [{...valid,qrData:'https://attacker.invalid/image'},structuredClone(valid)])assert.throws(()=>renderConnection({},view),/connectionView/);
  assert(Object.isFrozen(valid));assert(Object.isFrozen(valid.actions));
});

test('10: answered-receipt oracle keeps focus even when product flags lie',()=>{
  const row=state('metamask/request-done'),v=fixtureView(row);
  const broken={...v,answered:false,focus:'open-request-app'};
  assert(ruleFailures(broken,{row,shared}).includes('answered'));
});

test('10: error-stage payment and account/request alternative guards have exercising inputs',()=>{
  const errorRow=structuredClone(state('walletconnect/link-error'));
  errorRow.summaryInput=state('walletconnect/transaction-waiting').summaryInput;
  const error=fixtureView(errorRow);
  assert(error.paymentRisk,'error fixture must carry unresolved payment safety');
  const request=fixtureView({...state('metamask/request-waiting'),alternative:'extension-walletconnect-wallet-metamask'});
  const account=fixtureView({...state('metamask/site-access-ended'),alternative:'extension-walletconnect-wallet-metamask'});
  for(const [row,v]of [[state('metamask/request-waiting'),request],[state('metamask/site-access-ended'),account]]){
    assert(!v.actions.some(a=>a.id==='use-walletconnect'));
    assert(ruleFailures({...v,actions:[...v.actions,{id:'use-walletconnect',label:[],primary:false}]},{row,shared}).includes('capability'));
  }
});

test('10: real guards filter injected reload and connector offers on error, request and account screens',async()=>{
  const {fixtureArguments}=await import('./wallet-connection-view-fixtures.mjs');
  const error={...state('metamask/link-error'),summaryInput:state('metamask/transaction-waiting').summaryInput};
  await withTestView({editScreens:s=>{s.metamask['link-error'].notice='If the wallet will not open, use the browser Reload control.';}},async module=>{
    const view=module.reduceConnection(...fixtureArguments(error));assert.doesNotMatch(viewText(view.notice),/reload/i);assert.deepEqual(ruleFailures(view,{row:error,shared}),[]);
  });
  for(const name of ['request-waiting','linked','site-access-ended'])await withTestView({editScreens:s=>{s.metamask[name].secondary=[...(s.metamask[name].secondary||[]),{id:'use-walletconnect',label:'WalletConnect',quiet:true}];}},async module=>{
    assert(!module.reduceConnection(...fixtureArguments(state('metamask/'+name))).actions.some(a=>a.id==='use-walletconnect'),name);
  });
});

test('6: known app labels are local copy and absent labels use a sentence-safe fallback',async()=>{
  const {reduceSummary}=await import('../capsules/_shared/wallet-connection-view.mjs');
  for(const [capsule_id,app]of [['browser','Browser'],['notes','Notes'],['unknown-capsule','Requesting app']]){assert.equal(reduceSummary({...summary,capsule_id,requesting_app_name:app},{connector:'wallet-metamask'}).app,app);assert.equal(reduceSummary({...summary,capsule_id,requesting_app_name:undefined},{connector:'wallet-metamask'}).app,'Requesting app');}
});

test('10: independent oracles detect real source mutations',async t=>{
 const {fixtureArguments,pictures}=await import('./wallet-connection-view-fixtures.mjs');
 const mutations=[
  {name:'answered request-done loses outcome focus',from:'request-(done|declined',to:'request-(declined',row:state('metamask/request-done'),rule:'answered'},
  {name:'error-stage payment guard removed',from:'timeout|cancelled|reopened|error|removed',to:'timeout|cancelled|reopened|removed',row:{...state('metamask/link-error'),summaryInput:state('metamask/transaction-waiting').summaryInput},injectReload:true,rule:'payment'},
  {name:'request connector guard removed',from:' || requestScreen || ',to:' || false || ',requestOnly:true,row:state('metamask/request-waiting'),injectAlternative:true,rule:'capability'},
  {name:'account connector guard removed',from:'screen.account || screen.selectedAccount || ',to:'',row:state('metamask/site-access-ended'),injectAlternative:true,rule:'capability'},
 ];
 for(const m of mutations)await t.test(m.name,async()=>withTestView({
  mutateSource:source=>{assert.equal(source.split(m.from).length,2,'mutation must target exactly one guard');return source.replace(m.from,m.to);},
  editScreens:s=>{const screen=s[m.row.window][m.row.stage];if(m.requestOnly){screen.account=false;screen.selectedAccount=false;}if(m.injectReload)screen.notice='If the wallet will not open, use the browser Reload control.';if(m.injectAlternative)screen.secondary=[...(screen.secondary||[]),{id:'use-walletconnect',label:'WalletConnect',quiet:true}];},
 },async module=>{
  const view=module.reduceConnection(...fixtureArguments(m.row));const failures=ruleFailures(view,{row:m.row,shared,expected:pictures.find(p=>p.window===m.row.window&&p.stage===m.row.stage)});
  assert(failures.includes(m.rule),m.name+' escaped');t.diagnostic(m.name+': caught by '+m.rule);
 }));
});

test('9: freezing a returned view preserves caller-owned result mutability',()=>{
  const walletResult={disposition:null,receipt:null};
  const input={window:'metamask',stage:'ready',walletResult};
  const view=connectionView(input);
  assert.notEqual(view.walletResult,walletResult);assert(Object.isFrozen(view.walletResult));
  assert.equal(Object.isFrozen(walletResult),false);assert.equal(Object.isFrozen(input),false);
});
