import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync,existsSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {writeFile} from 'node:fs/promises';
import * as product from '../capsules/_shared/wallet-connection-view.mjs';
import {shared,states,fixtureArguments} from './wallet-connection-view-fixtures.mjs';
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
 for(const supportedActions of [undefined,[],['close-window'],['check-access'],['check-access','close-window']]){
  const v=api.connectionView({window,stage,localSafety:null,waitSeconds:300,supportedActions});const notice=api.viewText(v.notice);
  assert.match(notice,/An operation may still be waiting/);assert.match(notice,/Home cannot tell whether another window has payment work/);assert.match(notice,/Wallet activity/);assert.doesNotMatch(notice,/reload/i);
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
function accountGuard(api=product){const address='0x'+'11'.repeat(20),current='0x'+'99'.repeat(20);const v=reduce('metamask',{address},{account:{name:'MetaMask',mark:'metamask',connection:null,accounts:[{address,networks:['Base']}]},currentSelection:{address:current,network:'Ethereum'}},api);assert.equal(v.account.accounts[0].address,address);assert.deepEqual(v.account.accounts[0].networks,['Base']);assert.equal(v.currentSelection.address,current);assert.equal(v.currentSelection.network,'Ethereum');assert(v.requiredAccount);}
test('R5 K6: required signer address and network survive current wallet selection',()=>accountGuard());
function nameGuard(api=product){for(const capsule_id of ['browser','notes','constructor'])assert.equal(api.reduceSummary(raw('metamask',{capsule_id,requesting_app_name:'Actual app label'}),{connector:'wallet-metamask'}).app,'Actual app label');}
test('R5 K8: a present app label wins over every actor ID',()=>nameGuard());
function queueGuard(api=product){for(const window of ['walletconnect','metamask','unisat']){
 const selected=raw(window),other=[raw(window,{request_id:'reject',status:'rejected',intent:'transaction_intent'}),raw(window,{request_id:'dismiss',status:'rejected',approved_at:1800000000,intent:'transaction_intent'}),raw(window,{request_id:'recover',status:'approved',intent:'transaction_intent'})];
 const v=api.reduceConnection({window,stage:'request-list'},{summary:selected,otherSummaries:other,nowSeconds:1800000001});assert.equal(v.queueCount,4);assert.equal(v.queuePendingCount,1);assert.equal(v.queueRecoveryCount,1);assert.equal(v.queueRejectedCount,1);assert.equal(v.queueDismissedCount,1);assert.equal(v.queueOtherCount,0);assert.equal(v.choices.length,4);
}}
test('R5 K21: rejected and dismissed transactions have their own queue counts',()=>queueGuard());
const sourceFixture=JSON.parse(readFileSync(new URL('./fixtures/wallet-connection-title-sources.json',import.meta.url)));
const rustPath='elastos/crates/elastos-server/src/api/gateway_inbox.rs',walletPath='capsules/wallet/browser/wallet-format.js';
function rustTitles(source){const body=source.match(/fn wallet_approval_title\(intent: &str\) -> String \{([\s\S]*?)\n\}/)?.[1];assert(body,'read the actual Rust title function');const pairs=[...body.matchAll(/("[a-z_]+"|_)\s*=>\s*"([^"]+)"\.to_string\(\)/g)].map(m=>[m[1]==='_'?'unknown_kind':JSON.parse(m[1]),m[2]]);assert.equal(pairs.length,11);return Object.fromEntries(pairs);}
async function titleGuard(api=product,sources=sourceFixture.files){const rust=rustTitles(sources[rustPath].source);const wallet=await import('data:text/javascript;base64,'+Buffer.from(sources[walletPath].source).toString('base64'));
 for(const[intent,title]of Object.entries(rust)){assert.equal(wallet.requestTitle({intent}),title,'Wallet and Inbox source title: '+intent);assert.equal(api.reduceSummary(raw('metamask',{intent}),{connector:'wallet-metamask'}).title,title,'shared view title: '+intent);}
}
test('R5: canonical titles equal both raw integration sources including the unknown kind',async()=>{
 assert.equal(sourceFixture.commit.slice(0,9),'ac08f5942');for(const{source,blob}of Object.values(sourceFixture.files))assert.equal(createHash('sha1').update('blob '+Buffer.byteLength(source)+'\0').update(source).digest('hex'),blob);await titleGuard();
 const broken=structuredClone(sourceFixture.files);broken[rustPath].source=broken[rustPath].source.replace('Wallet approval request','Wrong unknown title');await assert.rejects(()=>titleGuard(product,broken),/Wallet and Inbox/);
});
test('R5: extension recovery uses one common sentence',()=>{for(const stage of ['request-expired','request-wallet-error']){const models=['metamask','unisat'].map(window=>reduce(window,{}, {stage}));assert.equal(words(models[0]),words(models[1]));assert.equal(words(models[0]),'To try again, return to Browser and make a new request.');}});
test('R5: absent or unidentified extensions use neutral copy and verified Brave keeps its name',()=>{
 for(const window of ['metamask','unisat'])for(const stage of ['extension-missing','extensions-unavailable','link-wait']){const v=product.connectionView({window,stage,waitSeconds:300});assert.doesNotMatch([product.viewText(v.status),words(v),v.title].join(' '),/Enable|MetaMask|UniSat/);}
 const provider=structuredClone(shared.messages.find(r=>r.id==='state-io.metamask').message.snapshot);provider.providerId='com.brave.wallet';provider.availability='found';const v=product.connectionView({window:'metamask',stage:'link-wait',provider,waitSeconds:300});assert.equal(v.title,'Brave Wallet');assert.match(product.viewText(v.status)+words(v),/Brave Wallet/);assert.doesNotMatch(product.viewText(v.status)+words(v),/MetaMask/);
});
const proof=await temporaryProof('wallet-view-r5-',process.env.WALLET_VIEW_PROOF_DIR),receipts=[];test.after(async()=>{try{await writeFile(proof.path+'/round5.json',JSON.stringify(receipts,null,2)+'\n');}finally{await proof.cleanup();}});
for(const engine of ['chromium','webkit']){const skip=engine==='webkit'&&!existsSync(playwright.webkit.executablePath())&&!process.env.ELASTOS_PLAYWRIGHT_MODULE?'WebKit required in test-elastos content-sandbox job':false;
 test('R5 K14: exact site label excludes its punctuation in '+engine,{skip},async()=>{const f=await browserFixture(engine,{width:320,height:182});try{const args=fixtureArguments(states.find(r=>r.designState==='metamask/request-waiting'),{compact:true});await f.page.evaluate(async args=>{const m=await import('/capsules/_shared/wallet-connection-view.mjs');m.mountConnection(document.querySelector('#mount'),m.reduceConnection(...args));},args);const label=f.page.locator('.connection-site-row > span');assert.equal(await label.textContent(),'Site reported by Browser');await label.evaluate(e=>e.textContent+=':');await assert.rejects(async()=>assert.equal(await label.textContent(),'Site reported by Browser'),assert.AssertionError);receipts.push({engine,case:'K14',result:'PASS / colon break caught'});}finally{await f.close();}});
 test('R5 P1: an approved same-card request keeps scroll and focuses its outcome in '+engine,{skip},async()=>{const f=await browserFixture(engine,{width:320,height:182});try{await f.page.evaluate(()=>document.fonts.ready);const args=fixtureArguments(states.find(r=>r.designState==='metamask/request-waiting'),{compact:true});args[1].summary={...args[1].summary,expires_at:null};
 const mount=args=>f.page.evaluate(async args=>{const m=await import('/capsules/_shared/wallet-connection-view.mjs');window.m=m.mountConnection(document.querySelector('#mount'),m.reduceConnection(...args),window.m);return{focus:document.activeElement.dataset.focus||document.activeElement.dataset.action||document.activeElement.tagName,top:window.m.root.scrollTop};},args);
 await mount(args);await f.page.locator('[data-action="send-request"]').focus();await f.page.evaluate(()=>{document.querySelector('main').scrollTop=40;});args[1].summary.status='approved';const got=await mount(args);assert.equal(got.focus,'outcome');assert.equal(got.top,40);await f.page.screenshot({path:proof.path+'/approved-focus-'+engine+'.png'});receipts.push({engine,case:'P1',...got,result:'PASS'});
 }finally{await f.close();}});
}
