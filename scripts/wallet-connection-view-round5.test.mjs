import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync,existsSync} from 'node:fs';
import {titleSources as sourceFixture,rustTitlePath as rustPath,assertTitleSources,assertTitleSourceBlobs} from './lib/wallet-connection-title-oracle.mjs';
import {writeFile} from 'node:fs/promises';
import * as product from '../capsules/_shared/wallet-connection-view.mjs';
import {shared,states,fixtureArguments} from './wallet-connection-view-fixtures.mjs';
const round4Source=JSON.parse(readFileSync(new URL('./fixtures/wallet-connection-round4-source.json',import.meta.url))).source;
import {approvalArguments,approvalCatalog} from './lib/wallet-connection-approval-cases.mjs';
import {withTestView} from './lib/wallet-connection-test-module.mjs';
import {browserFixture,playwright,temporaryProof} from './lib/wallet-connection-browser-fixture.mjs';
const seed=shared.n7PrivateSummaries.find(r=>r.id==='site-wallet-metamask').summary;
// Provisional boundary variants derive from the untouched shared personal-sign seed.
// Foundation examples are needed for rejected/approved_at, other kinds and signer changes.
const raw=(window,patch={})=>({...seed,connector_id:'wallet-'+window,request_id:'r5-'+window,...patch});
const reduce=(window,patch={},input={},api=product)=>api.reduceConnection({window,stage:'request-waiting',waitSeconds:300,...input},{summary:raw(window,patch),nowSeconds:1800000001});
const words=v=>product.viewText(v.notice);
function busyGuard(api=product){for(const window of ['metamask','unisat','walletconnect'])for(const stage of ['extension-busy','link-busy','request-busy']){
 if(!api.stageNames[window].includes(stage))continue;
 for(const transaction of [false,true])for(const supportedActions of [undefined,...Array.from({length:8},(_,mask)=>['close-window','check-access','check-status'].filter((_,i)=>mask&(1<<i)))]){
  const v=reduce(window,transaction?{intent:'transaction_intent'}:{}, {stage,localSafety:null,waitSeconds:300,supportedActions},api);const notice=api.viewText(v.notice);
  if(transaction&&stage==='request-busy'){assert.match(notice,/The transaction may still be waiting/);assert.doesNotMatch(notice,/another window/);}else{assert.match(notice,/An operation may still be waiting/);assert.match(notice,/Home cannot tell whether another window has payment work/);}
  assert.match(notice,/Wallet activity/);assert.doesNotMatch(notice,/reload/i);
 }
}}
test('R5 F-B: every unknown busy notice survives every supported-action subset',()=>busyGuard());
test('R5: later capability adaptation preserves link-error and unsafe-retry recovery once',()=>{
 for(const window of ['metamask','unisat','walletconnect'])for(const stage of ['link-error','account-changed','account-unavailable-unknown'])for(const supportedActions of [[],['close-window'],['check-access']]){
  const v=product.connectionView({window,stage,localSafety:null,supportedActions});const text=words(v);assert.match(text,/Wallet activity/);assert.equal((text.match(/Close this window/g)||[]).length,1);assert.doesNotMatch(text,/Open .* to check its account and connection/);
 }
});
function rejectedGuard(api=product){for(const window of ['walletconnect','metamask','unisat'])for(const transaction of [false,true]){
 const intent=transaction?'transaction_intent':'browser_personal_sign';const rejected=reduce(window,{status:'rejected',intent},{},api);assert.equal(rejected.stage,'request-rejected');assert.equal(rejected.request.status,'rejected');assert.equal(rejected.focus,'outcome');assert(!rejected.actions.some(a=>a.id==='send-request'));
 const dismissed=reduce(window,{status:'rejected',intent,approved_at:1800000000},{},api);assert.equal(dismissed.stage,'request-dismissed');assert.equal(dismissed.request.status,'dismissed');assert.equal(dismissed.focus,'outcome');assert(!dismissed.actions.some(a=>a.id==='send-request'));assert.match(api.viewText(dismissed.status),/dismissed/i);
}}
test('R5 K1: rejected and dismissed Runtime records never become expiry or a Send',()=>rejectedGuard());
function accountGuard(api=product){const address='0x'+'11'.repeat(20),current='0x'+'99'.repeat(20);const v=reduce('metamask',{address},{account:{name:'MetaMask',mark:'metamask',connection:null,accounts:[{address:current,networks:['Base']}]},currentSelection:{address:current,network:'Ethereum'}},api);assert.equal(v.account.accounts[0].address,address);assert.deepEqual(v.account.accounts[0].networks,['Base']);assert.equal(v.currentSelection.address,current);assert.equal(v.currentSelection.network,'Ethereum');assert(v.requiredAccount);}
test('R5 K6: required signer address and network survive current wallet selection',()=>accountGuard());
function nameGuard(api=product){for(const capsule_id of ['browser','notes','constructor'])assert.equal(api.reduceSummary(raw('metamask',{capsule_id,requesting_app_name:'Actual app label'}),{connector:'wallet-metamask'}).app,'Actual app label');}
test('R5 K8: a present app label wins over every actor ID',()=>nameGuard());
function queueGuard(api=product){for(const window of ['walletconnect','metamask','unisat']){
 const selected=raw(window),other=[raw(window,{request_id:'reject',status:'rejected',intent:'transaction_intent'}),raw(window,{request_id:'dismiss',status:'rejected',approved_at:1800000000,intent:'transaction_intent'}),raw(window,{request_id:'recover',status:'approved',intent:'transaction_intent'})];
 const v=api.reduceConnection({window,stage:'request-list'},{summary:selected,otherSummaries:other,nowSeconds:1800000001});assert.equal(v.queueCount,4);assert.equal(v.queuePendingCount,1);assert.equal(v.queueRecoveryCount,1);assert.equal(v.queueRejectedCount,1);assert.equal(v.queueDismissedCount,1);assert.equal(v.queueOtherCount,0);assert.equal(v.choices.length,4);
}}
test('R5 K21: rejected and dismissed transactions have their own queue counts',()=>queueGuard());
const titleGuard=(api=product,sources=sourceFixture.files)=>assertTitleSources(intent=>api.reduceSummary(raw('metamask',{intent}),{connector:'wallet-metamask'}).title,sources);
test('R5: canonical titles equal both raw integration sources including the unknown kind',async()=>{
 assertTitleSourceBlobs();await titleGuard();
 const broken=structuredClone(sourceFixture.files);broken[rustPath].source=broken[rustPath].source.replace('Wallet approval request','Wrong unknown title');await assert.rejects(()=>titleGuard(product,broken),/Wallet and Inbox/);
});
function commonGuard(api=product){for(const stage of ['request-expired','request-wallet-error']){const models=['metamask','unisat'].map(window=>reduce(window,{requesting_app_name:'Browser'}, {stage},api));assert.equal(api.viewText(models[0].notice),api.viewText(models[1].notice));assert.equal(api.viewText(models[0].notice),'To try again, return to Browser and make a new request.');}}
test('R5: extension recovery uses one common sentence',()=>commonGuard());
function neutralGuard(api=product){
 for(const window of ['metamask','unisat'])for(const stage of ['extension-missing','extensions-unavailable','link-wait']){const v=api.connectionView({window,stage,waitSeconds:300});assert.doesNotMatch([api.viewText(v.status),api.viewText(v.notice),v.title].join(' '),/Enable|MetaMask|UniSat/);}
 const provider=shared.messages.find(r=>r.id==='state-com.brave.wallet').message.snapshot;const v=api.connectionView({window:'metamask',stage:'link-wait',provider,waitSeconds:300});assert.equal(v.title,'Brave Wallet');assert.match(api.viewText(v.status)+api.viewText(v.notice),/Brave Wallet/);assert.doesNotMatch(api.viewText(v.status)+api.viewText(v.notice),/MetaMask/);
}
test('R5: absent or unidentified extensions use neutral copy and verified Brave keeps its name',()=>neutralGuard());
const proof=await temporaryProof('wallet-view-r5-',process.env.WALLET_VIEW_PROOF_DIR),receipts=[];test.after(async()=>{try{await writeFile(proof.path+'/round5.json',JSON.stringify(receipts,null,2)+'\n');}finally{await proof.cleanup();}});
async function variant(engine,mutate,run){const f=await browserFixture(engine,{width:320,height:182});try{
 if(mutate){const source=readFileSync(new URL('../capsules/_shared/wallet-connection-view.mjs',import.meta.url),'utf8'),changed=mutate(source);assert.notEqual(changed,source,'browser source break applies');await f.context.route('**/wallet-connection-view.mjs',route=>route.fulfill({contentType:'text/javascript',body:changed}));}
 return await run(f);
 }finally{await f.close();}}
async function labelGuard(f){const args=fixtureArguments(states.find(r=>r.designState==='metamask/request-waiting'),{compact:true});await f.page.evaluate(async args=>{const m=await import('/capsules/_shared/wallet-connection-view.mjs');m.mountConnection(document.querySelector('#mount'),m.reduceConnection(...args));},args);assert.equal(await f.page.locator('.connection-site-row > span').textContent(),'Site reported by Browser');}
async function focusGuard(f,engine,capture=false){await f.page.evaluate(()=>document.fonts.ready);const args=approvalArguments(approvalCatalog.stages.find(r=>r.window==='metamask'&&r.stage==='request-waiting'));args[1].summary={...args[1].summary,expires_at:null};
 const mount=args=>f.page.evaluate(async args=>{const m=await import('/capsules/_shared/wallet-connection-view.mjs');window.m=m.mountConnection(document.querySelector('#mount'),m.reduceConnection(...args),window.m);return{focus:document.activeElement.dataset.focus||document.activeElement.dataset.action||document.activeElement.tagName,top:window.m.root.scrollTop};},args);
 await mount(args);await f.page.locator('[data-action="send-request"]').focus();await f.page.evaluate(()=>{document.querySelector('main').scrollTop=40;});assert.equal(await f.page.locator('main').evaluate(e=>e.scrollTop),40,'the before position exists');args[1].summary.status='approved';const got=await mount(args);assert.equal(got.focus,'outcome');assert.equal(got.top,40);const box=await f.page.locator('[data-focus="outcome"]').boundingBox();assert(box.y>=0&&box.y+box.height<=182,'replacement focus stays visible');if(capture)await f.page.screenshot({path:proof.path+'/approved-focus-'+engine+'.png'});return got;
}
for(const engine of ['chromium','webkit']){const skip=engine==='webkit'&&!existsSync(playwright.webkit.executablePath())&&!process.env.ELASTOS_PLAYWRIGHT_MODULE?'WebKit required in test-elastos content-sandbox job':false;
 test('R5 K14: exact site label excludes its punctuation in '+engine,{skip},async()=>{
 await variant(engine,null,labelGuard);await assert.rejects(()=>variant(engine,s=>s.replace("el('span','Site reported by Browser')","el('span','Site reported by Browser:')"),labelGuard),assert.AssertionError);receipts.push({engine,case:'K14',result:'PASS / product colon break CAUGHT'});
 });
 test('R5 P1: an approved same-card request keeps scroll and focuses its outcome in '+engine,{skip},async()=>{
 const got=await variant(engine,null,f=>focusGuard(f,engine,true));
 for(const mutate of [s=>s.replace('||target(view.focus,view.focusKey)',''),()=>round4Source])await assert.rejects(()=>variant(engine,mutate,f=>focusGuard(f,engine)),assert.AssertionError);
 receipts.push({engine,case:'P1',...got,result:'PASS / product fallback break and pinned old product CAUGHT'});
 });
 test('R5: Runtime resolution and neutral extension cards render literally in '+engine,{skip},async()=>variant(engine,null,async f=>{
 for(const window of ['metamask','unisat','walletconnect'])for(const dismissed of [false,true]){
  const args=[{window,stage:'request-waiting',compact:true,showNextRequests:true},{summary:raw(window,{status:'rejected',...(dismissed?{approved_at:1800000000}:{}),intent:'transaction_intent'}),otherSummaries:[raw(window,{request_id:'dismissed-in-queue',status:'rejected',approved_at:1800000000,intent:'transaction_intent'})],nowSeconds:1800000001}];
  const got=await f.page.evaluate(async args=>{const m=await import('/capsules/_shared/wallet-connection-view.mjs');window.m?.dispose();const v=m.reduceConnection(...args);window.m=m.mountConnection(document.querySelector('#mount'),v);return {stage:v.stage,text:window.m.root.innerText,focus:document.activeElement.dataset.focus};},args);assert.equal(got.stage,dismissed?'request-dismissed':'request-rejected');assert.equal(got.focus,'outcome');assert.match(got.text,/1 dismissed request/);assert.doesNotMatch(got.text,/to review/);assert.equal(await f.page.locator('[data-action="send-request"]').count(),0);const feedback=await f.page.locator('.connection-feedback').boundingBox();assert(feedback.y>=0&&feedback.y+feedback.height<=182,'outcome and exits fit the compact frame');await f.page.screenshot({path:proof.path+`/${window}-${got.stage}-${engine}.png`});receipts.push({engine,case:window+'/'+got.stage,result:'PASS'});
 }
 for(const window of ['metamask','unisat']){const got=await f.page.evaluate(async kind=>{const m=await import('/capsules/_shared/wallet-connection-view.mjs');window.m?.dispose();window.m=m.mountConnection(document.querySelector('#mount'),m.connectionView({window:kind,stage:'extension-missing',compact:true,supportedActions:['close-window']}));return window.m.root.innerText;},window);assert.doesNotMatch(got,/Enable|MetaMask|UniSat/);await f.page.screenshot({path:proof.path+`/${window}-neutral-absence-${engine}.png`});}
 }));
}

// Each guard below executes a whole, deliberately broken product module.
test('R5: direct guards reject every escaped source break',async t=>{
 const mutations=[
  ['F-B safety priority',s=>s.replace('let effectiveNotice = safetyNotice ?? notice;','let effectiveNotice = notice;'),busyGuard],
  ['K1 rejected becomes expired',s=>s.replace("?'request-dismissed':'request-rejected'","?'request-dismissed':'request-expired'"),rejectedGuard],
  ['Runtime approval time lost',s=>s.replace("summary.status==='rejected'&&Number.isSafeInteger(summary.approved_at)","false&&summary.status==='rejected'&&Number.isSafeInteger(summary.approved_at)"),rejectedGuard],
  ['K6 live selection replaces signer',s=>s.replace('const account = accountDisplay(input.account, window, requestScreen?summary:null);','const account = accountDisplay(input.account, window, requestScreen?summary:null);if(account&&currentSelection){account.accounts[0].address=currentSelection.address;account.accounts[0].networks=[currentSelection.network];}'),accountGuard],
  ['K8 actor map replaces app label',s=>s.replace("? summary.requesting_app_name : 'Requesting app'","? ({browser:'Browser',notes:'Notes'}[summary.capsule_id]||summary.requesting_app_name) : 'Requesting app'"),nameGuard],
  ['K21 rejected transaction becomes recovery',s=>s.replace("queued.filter(r=>r.status==='approved'&&r.transaction)","queued.filter(r=>['approved','rejected'].includes(r.status)&&r.transaction)"),queueGuard],
  ['unknown title diverges',s=>s.replace("requestTitles[summary.intent]:'Wallet approval request'","requestTitles[summary.intent]:'Approval request'"),titleGuard],
 ];
 for(const[name,mutate,guard]of mutations)await t.test(name,()=>withTestView({mutateSource:source=>{const changed=mutate(source);assert.notEqual(changed,source,'source break applies');return changed;}},async api=>{await assert.rejects(async()=>guard(api),assert.AssertionError);t.diagnostic(name+': CAUGHT');}));
});

test('R5: corrected F-B guard rejects the pinned round-four product notice',()=>withTestView({mutateSource:()=>round4Source},api=>assert.throws(()=>busyGuard(api),assert.AssertionError)));

test('R5: capability copy cannot replace a returned transaction recovery or its save failure',()=>{
 for(const window of ['metamask','walletconnect'])for(const supportedActions of [[],['close-window'],['check-access']]){
  const summary=product.reduceSummary(raw(window,{intent:'transaction_intent'}),{connector:'wallet-'+window});
  const v=product.connectionView({window,stage:'transaction-timeout',summary,walletResult:{disposition:'answered',receipt:'recording_failed'},supportedActions});assert.match(product.viewText(v.status),/returned a transaction result/);assert.match(words(v),/Wallet activity before sending again/);assert.doesNotMatch(words(v),/still be waiting|account and connection/);
  const refused=product.connectionView({window,stage:'transaction-declined',summary,walletResult:{disposition:'declined',receipt:'recording_failed'},supportedActions});assert.match(words(refused),/Home cannot save that answer/);
 }
});
test('R5: a dismissed record retains a subsequently supplied known transaction result',()=>{
 const v=product.reduceConnection({window:'metamask',stage:'transaction-wallet-error'},{summary:raw('metamask',{intent:'transaction_intent',status:'rejected',approved_at:1800000000}),message:shared.messages.find(r=>r.id==='settled-answered').message,nowSeconds:1800000001});assert.equal(v.stage,'transaction-done');assert.equal(v.request.status,'dismissed');assert.match(product.viewText(v.status),/Transaction sent/);
});

test('R5: common recovery and neutral-identity guards reject broken screen definitions',async()=>{
 for(const [editScreens,guard]of [[s=>{s.unisat['request-wallet-error'].notice='Start a different request.';},commonGuard],[s=>{s.unisat['extension-missing'].notice='Enable UniSat in this browser.';},neutralGuard]])await withTestView({editScreens},api=>assert.throws(()=>guard(api),assert.AssertionError));
 await withTestView({mutateSource:s=>s.replace("'com.brave.wallet': 'Brave Wallet'","'com.brave.wallet': 'MetaMask'")},api=>assert.throws(()=>neutralGuard(api),assert.AssertionError));
});
