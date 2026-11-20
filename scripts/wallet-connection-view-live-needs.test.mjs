import {canonicalRequestTitles} from './lib/wallet-connection-title-oracle.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync,existsSync} from 'node:fs';
import {writeFile} from 'node:fs/promises';
import {connectionView,reduceConnection,reduceSummary,connectionKey,viewText,connectionActionIds,stageNames} from '../capsules/_shared/wallet-connection-view.mjs';
import {shared,states,contractStates,fixtureArguments} from './wallet-connection-view-fixtures.mjs';
import {browserFixture,playwright,temporaryProof} from './lib/wallet-connection-browser-fixture.mjs';
const live=JSON.parse(readFileSync(new URL('./fixtures/wallet-connection-live-view-states.json',import.meta.url))).states;
const seed=shared.n7PrivateSummaries.find(r=>r.id==='site-wallet-metamask').summary;
const source=id=>shared.messages.find(r=>r.id===id).message;
const projection=(patch={})=>reduceSummary({...seed,...patch},{connector:'wallet-metamask'});
const account={name:'MetaMask',mark:'metamask',connection:null,accounts:[{address:'0x1122334455667788990011223344556677889900',networks:['Base']}]};
test('live needs: all added stages have named window-local production fixtures',async t=>{
 for(const row of live)await t.test(row.window+'/'+row.stage,()=>{assert(stageNames[row.window].includes(row.stage));const v=connectionView({window:row.window,stage:row.stage});assert.equal(v.stage,row.stage);});
});
test('live needs: a supported-action projection withholds authority and keeps manual recovery',()=>{
 for(const row of states){
  const args=fixtureArguments(row),original=reduceConnection(...args);args[0].supportedActions=[];
  const v=reduceConnection(...args);assert.deepEqual(v.actions,[],row.designState);assert.equal(viewText(v.status),viewText(original.status));if(row.window==='walletconnect'&&row.stage==='disconnecting')assert.equal(viewText(v.notice),'Keep this window open until disconnecting finishes.');else assert.match(viewText(v.notice),/Home’s window controls/);
 }
 assert(!connectionView({window:'unisat',stage:'ready',supportedActions:['use-walletconnect']}).actions.length,'an allow-list cannot invent a compatible connector');
 assert.throws(()=>connectionView({window:'metamask',stage:'ready',supportedActions:['invented-route']}),/closed supported actions/);
 assert.throws(()=>connectionView({window:'metamask',stage:'ready',supportedActions:['connect','connect']}),/closed supported actions/);
});
test('live needs: stopped recovery retains the unanswered operation without a dead Check again instruction',()=>{
 for(const window of ['walletconnect','metamask','unisat'])for(const stage of ['request-timeout','request-cancelled']){
  const args=fixtureArguments(states.find(r=>r.window===window&&r.stage===stage));args[0].supportedActions=['close-window'];const v=reduceConnection(...args),copy=viewText(v.notice);
  assert.doesNotMatch(copy,/Check again|Check access|Check status/);assert.match(copy,/may still be waiting|later answer/);assert(v.actions.every(a=>a.id==='close-window'));
 }
});
test('live needs: request kind titles and expired status use Runtime vocabulary',async()=>{
 const titles={...canonicalRequestTitles,new_unknown_intent:canonicalRequestTitles.unknown_kind};
 for(const [intent,title]of Object.entries(titles))assert.equal(projection({intent}).title,title);
 for(const word of ['constructor','__proto__','toString']){assert.equal(projection({intent:word}).title,'Review request');assert.equal(projection({capsule_id:word,requesting_app_name:undefined}).app,'Requesting app');}
 const {withTestView}=await import('./lib/wallet-connection-test-module.mjs');
 await withTestView({mutateSource:source=>source.replace("title: Object.hasOwn(requestTitles,summary.intent)?requestTitles[summary.intent]:'Review request'","title: requestTitles[summary.intent]||'Review request'")},module=>{assert.throws(()=>assert.equal(module.reduceSummary({...seed,intent:'constructor'},{connector:'wallet-metamask'}).title,'Review request'),assert.AssertionError,'inherited dictionary lookup must fail the vocabulary oracle');});
 const view=reduceConnection({window:'metamask',stage:'request-waiting'},{summary:{...seed,status:'expired'},nowSeconds:1800000001});assert.equal(view.stage,'request-expired');assert.equal(view.request.status,'expired');assert(!view.actions.some(a=>a.id==='send-request'));
});
test('live needs: connection notices preserve a recorded transaction and its required account',()=>{
 const row=states.find(r=>r.designState==='metamask/transaction-done'),args=fixtureArguments(row),original=reduceConnection(...args);
 for(const connectionNotice of ['account-changed','network-changed','transport-unavailable','connection-removed','connection-expired','provider-unavailable']){
  args[0]={...args[0],connectionNotice,currentSelection:{address:'0x9999999999999999999999999999999999999999',network:'Ethereum'},localReturn:true};const v=reduceConnection(...args);
  assert.equal(viewText(v.status),viewText(original.status));assert.deepEqual(v.walletResult,original.walletResult);assert.equal(v.request.id,original.request.id);assert(v.connectionNotice.length);assert(v.requiredAccount);assert(v.actions.some(a=>a.id==='back-to-connection'));assert.equal(v.focus,'outcome');
 }
 assert.throws(()=>connectionView({window:'metamask',stage:'ready',connectionNotice:'raw wallet text'}),/closed connection notice/);
 assert.throws(()=>connectionView({window:'metamask',stage:'ready',currentSelection:{address:'a',network:'b',html:'c'}}),/closed current selection/);
});
test('live needs: full picker and account display keep a fourth and ninth row reachable',()=>{
 const summary=projection(),otherRequests=Array.from({length:20},(_,i)=>({...summary,id:'request-'+i}));
 const view=connectionView({window:'metamask',stage:'request-list',summary,otherRequests});assert.equal(view.choices.length,21);assert.equal(view.choices.at(-1).id,'request-19');
 const many={...account,accounts:Array.from({length:20},(_,i)=>({address:'0x'+String(i).padStart(40,'0'),networks:['Base']}))};assert.equal(connectionView({window:'metamask',stage:'linked',account:many}).account.accounts.length,20);
 assert.throws(()=>connectionView({window:'metamask',stage:'linked',account:{...many,accounts:Array(101).fill(many.accounts[0])}}),/account rows/);
});
test('live needs: clipboard feedback is closed local copy and QR keys respect supplied capabilities',()=>{
 const args=fixtureArguments(states.find(r=>r.stage==='qr-shown'));
 for(const copyFeedback of ['link-copied','address-copied','copy-failed']){args[0].copyFeedback=copyFeedback;assert(reduceConnection(...args).copyFeedback.length);}
 args[0].supportedActions=['copy-link'];const view=reduceConnection(...args);assert.equal(connectionKey(view,{key:'Escape'}),null);assert.equal(connectionKey(view,{key:'Tab',action:'copy-link'}).focus,'copy-link');
 args[0].supportedActions=['cancel'];const cancelOnly=reduceConnection(...args);assert.equal(cancelOnly.focus,'cancel');assert.equal(connectionKey(cancelOnly,{key:'Tab'}).focus,'cancel');
 assert.throws(()=>connectionView({window:'metamask',stage:'ready',copyFeedback:'wallet wrote this'}),/closed copy feedback/);
});

test('late needs: latent summaries cannot replace a linking account or its card identity',async()=>{
 const actual='0x9999999999999999999999999999999999999999';
 for(const status of ['pending','approved','expired'])for(const stage of ['saved-unlinked','link-wait']){
  const input={window:'walletconnect',stage,account:{...account,name:'A real wallet',connection:'WalletConnect',accounts:[{address:actual,networks:['Base']}]},localSafety:false,waitSeconds:300};
  const v=reduceConnection(input,{summary:{...seed,connector_id:'wallet-walletconnect',status,address:account.accounts[0].address},nowSeconds:1800000001});
  assert.equal(v.stage,stage);assert.equal(v.account.accounts[0].address,actual);assert.equal(v.requestId,null);
 }
 const {withTestView}=await import('./lib/wallet-connection-test-module.mjs');await withTestView({mutateSource:source=>source.replace('accountDisplay(input.account, window, requestScreen?summary:null)','accountDisplay(input.account, window, summary)')},module=>{const v=module.connectionView({window:'walletconnect',stage:'saved-unlinked',summary:projection(),account:{...account,accounts:[{address:actual,networks:['Base']}]},localSafety:false});assert.throws(()=>assert.equal(v.account.accounts[0].address,actual),assert.AssertionError,'latent-address substitution must fail');});
});
test('late needs: reconnecting is secondary fixed copy in idle, wait and result states',()=>{
 for(const stage of ['linked','link-wait','request-phone','transaction-done']){
  const args=fixtureArguments(states.find(r=>r.window==='walletconnect'&&r.stage===stage)),before=reduceConnection(...args);args[0].connectionNotice='transport-reconnecting';const v=reduceConnection(...args);
  assert.equal(viewText(v.connectionNotice),'WalletConnect is reconnecting.');assert.equal(viewText(v.status),viewText(before.status));assert.deepEqual(v.walletResult,before.walletResult);assert.equal(v.wait,before.wait);
 }
});
test('late needs: completion-failure hash is display only, full and closed',()=>{
 const args=fixtureArguments(states.find(r=>r.designState==='walletconnect/transaction-wallet-error')),before=reduceConnection(...args),hash='0x'+'ab'.repeat(32);args[0].transactionHash=hash;const v=reduceConnection(...args);
 assert.equal(v.transactionHash,hash);assert.deepEqual(v.walletResult,before.walletResult);assert.equal(viewText(v.status),viewText(before.status));assert(v.paymentRisk);assert(!v.actions.some(a=>['send-request','connect','start-over','use-walletconnect'].includes(a.id)));
 for(const transactionHash of ['0x12','<img src=x>',{toString:()=>hash}])assert.throws(()=>reduceConnection({...args[0],transactionHash},args[1]),/transaction hash/);
 assert.throws(()=>connectionView({window:'walletconnect',stage:'transaction-waiting',summary:v.request,transactionHash:hash,localSafety:false,waitSeconds:300}),/transaction hash/);
});
test('late needs: the local next-request queue is opt-in and preserves its outcome',()=>{
 for(const stage of ['transaction-done','transaction-wallet-error']){
  const args=fixtureArguments(states.find(r=>r.designState==='metamask/'+stage)),before=reduceConnection(...args);args[0].showNextRequests=true;args[1].otherSummaries=[{...seed,request_id:'next-request'}];const v=reduceConnection(...args);
  assert.equal(before.queueCount,0);assert.equal(v.queueCount,1);assert.equal(viewText(v.status),viewText(before.status));assert.deepEqual(v.walletResult,before.walletResult);
 }
});
test('late needs: missing catalog labels use Requesting app for every actor ID',()=>{
 for(const capsule_id of ['browser','notes','another-app'])assert.equal(projection({capsule_id,requesting_app_name:undefined}).app,'Requesting app');
 assert.equal(projection({capsule_id:'browser',requesting_app_name:'Browser'}).app,'Browser');
});

test('final needs: Home response checking keeps its local stop and never claims a recorded result',()=>{
 const plain=connectionView({window:'walletconnect',stage:'checking-response'});assert.equal(plain.request,null);assert.equal(plain.focus,'stop-waiting');assert.match(viewText(plain.status),/Home is checking the answer/);assert.equal(plain.walletResult.disposition,null);
 const args=fixtureArguments(states.find(r=>r.designState==='walletconnect/request-phone'));args[0].stage='checking-response';args[0].localReturn=true;args[0].showNextRequests=true;const v=reduceConnection(...args);assert(v.request);assert(!v.actions.some(a=>a.id==='back-to-connection'));assert.equal(v.queueCount,0);assert.match(viewText(v.notice),/Home may still record/);
 const doneArgs=fixtureArguments(states.find(r=>r.designState==='walletconnect/request-done'));const done=reduceConnection(...doneArgs);assert.equal(done.stage,'request-done');
});
test('final needs: blocked and terminal cards retain their outcome with a local picker exit',()=>{
 for(const window of ['walletconnect','metamask','unisat'])for(const stage of ['request-expired','request-unsendable','request-declined','request-wallet-error','request-unavailable']){
  const row=[...states,...contractStates].find(r=>r.window===window&&r.stage===stage);assert(row,window+'/'+stage);const args=fixtureArguments(row),before=reduceConnection(...args);args[0].localReturn=true;args[0].showNextRequests=true;args[1].otherSummaries=[{...seed,connector_id:'wallet-'+window,request_id:'another-request'}];const v=reduceConnection(...args);
  assert.equal(viewText(v.status),viewText(before.status));assert(v.actions.some(a=>a.id==='back-to-connection'),window+'/'+stage);assert.equal(v.queueCount,1);
 }
});
test('final needs: network-only notices keep the proof wait without inventing an account',()=>{
 for(const window of ['walletconnect','metamask','unisat'])for(const connectionNotice of ['network-unknown','network-unsupported']){
  const before=connectionView({window,stage:'link-wait',waitSeconds:30});const v=connectionView({window,stage:'link-wait',waitSeconds:30,connectionNotice});assert.equal(v.account,null);assert.equal(viewText(v.status),viewText(before.status));assert.equal(v.wait,before.wait);assert(v.connectionNotice.length);assert.deepEqual(v.actions,before.actions);
 }
});
test('new WC needs: read and cleanup failures keep their existing recovery actions',()=>{
 const read=connectionView({window:'walletconnect',stage:'home-read-unavailable'});assert.match(viewText(read.status),/Home could not load the wallet details/);assert.equal(read.focus,'refresh-status');assert(read.actions.some(a=>a.id==='refresh-status'));
 const cleanup=connectionView({window:'walletconnect',stage:'disconnect-error'});assert.match(viewText(cleanup.status),/Home could not finish disconnecting/);assert.equal(cleanup.focus,'disconnect');assert(cleanup.actions.some(a=>a.id==='disconnect'));
 const empty=connectionView({window:'walletconnect',stage:'account-unavailable-unknown',localSafety:false});assert.match(viewText(empty.status),/not showing an account/);assert.doesNotMatch(viewText(empty.notice),/Confirm this account/);assert.equal(empty.actions.find(a=>a.primary).id,'start-over');
 const unknown=connectionView({window:'walletconnect',stage:'account-unavailable-unknown',localSafety:null});assert(!unknown.actions.some(a=>a.id==='start-over'));assert.equal(unknown.focus,'close-window');
});
test('new WC needs: approved transaction recovery is separate from pending queue work',async()=>{
 const selected=projection(),pending=projection({request_id:'pending-other'}),recovery=projection({request_id:'approved-tx',intent:'transaction_intent',status:'approved'});
 const input={window:'metamask',stage:'request-list',summary:selected,otherRequests:[pending,recovery]},v=connectionView(input);
 assert.equal(v.queueCount,3);assert.equal(v.queuePendingCount,2);assert.equal(v.queueRecoveryCount,1);assert.equal(v.queueOtherCount,0);assert.equal(v.choices.length,3);assert.equal(v.choices.at(-1).id,'approved-tx');
 const {withTestView}=await import('./lib/wallet-connection-test-module.mjs');
 await withTestView({mutateSource:source=>source.replace("queued.filter(r=>r.status==='pending').length","queued.length")},module=>{assert.throws(()=>assert.equal(module.connectionView(input).queuePendingCount,2),assert.AssertionError,'legacy counting of approved records as pending must fail');});
});

const proof=await temporaryProof('wallet-live-view-',process.env.WALLET_VIEW_PROOF_DIR);const receipts=[];
test.after(async()=>{try{await writeFile(proof.path+'/live-needs.json',JSON.stringify(receipts,null,2)+'\n');}finally{await proof.cleanup();}});
for(const engine of ['chromium','webkit'])test('live needs: rendering and QR card containment in '+engine,{skip:engine==='webkit'&&!existsSync(playwright.webkit.executablePath())&&!process.env.ELASTOS_PLAYWRIGHT_MODULE?'WebKit runs in content-sandbox CI':false},async()=>{
 const f=await browserFixture(engine,{width:480,height:560});
 const mount=async args=>f.page.evaluate(async args=>{const m=await import('/capsules/_shared/wallet-connection-view.mjs');window.mounted?.dispose();window.mounted=m.mountConnection(document.querySelector('#mount'),m.reduceConnection(...args));await document.fonts.ready;},args);
 try{
  for(const row of live){await mount([{window:row.window,stage:row.stage,supportedActions:['close-window','refresh-status','connect','send-message','start-over','cancel']}]);assert((await f.page.locator('main').innerText()).length);if(process.env.WALLET_VIEW_CAPTURE==='1')await f.page.screenshot({path:proof.path+`/local-${row.window}-${row.stage}-${engine}.png`});}
  // Capability filtering covers model actions plus renderer-only account/picker/panel controls.
  for(const row of [...states,...live]){
   const args=row.local?fixtureArguments(row):[{window:row.window,stage:row.stage}];args[0].supportedActions=[];await mount(args);assert.equal(await f.page.locator('button').count(),0,row.window+'/'+row.stage);
  }
  const approvalArgs=fixtureArguments(states.find(r=>r.designState==='metamask/request-waiting'));approvalArgs[0].supportedActions=['send-request'];await mount(approvalArgs);assert.equal(await f.page.evaluate(()=>document.activeElement.dataset.focus),'dismissal');assert.equal(await f.page.locator('button').count(),1);assert.match(await f.page.locator('.connection-card-start').innerText(),/Home’s window controls/);
  const qrArgs=fixtureArguments(states.find(r=>r.stage==='qr-shown'));qrArgs[0].copyFeedback='copy-failed';await mount(qrArgs);
  const box=await f.page.evaluate(()=>{const card=document.querySelector('.connection-dialog').getBoundingClientRect(),qr=document.querySelector('.connection-qr').getBoundingClientRect();return {card:{top:card.top,bottom:card.bottom},qr:{width:qr.width,height:qr.height},controls:[...document.querySelectorAll('button')].map(b=>({top:b.getBoundingClientRect().top,bottom:b.getBoundingClientRect().bottom})),feedback:document.querySelector('.connection-copy-feedback')?.textContent};});
  assert.equal(box.feedback,'Could not copy. Try again.');assert(box.qr.width>=128,'normal QR does not use compact 56px sizing');assert(box.controls.every(b=>b.top>=box.card.top&&b.bottom<=box.card.bottom&&b.bottom<=560),'QR border encloses both controls within the viewport');await f.page.screenshot({path:proof.path+'/qr-contained-'+engine+'.png'});
  await f.page.setViewportSize({width:320,height:182});const summary=projection(),otherRequests=Array.from({length:20},(_,i)=>({...summary,id:'extra-'+i}));
  await f.page.evaluate(async({summary,otherRequests})=>{const m=await import('/capsules/_shared/wallet-connection-view.mjs');window.mounted?.dispose();window.mounted=m.mountConnection(document.querySelector('#mount'),m.connectionView({window:'metamask',stage:'request-list',summary,otherRequests,compact:true}));},{summary,otherRequests});
  const last=f.page.locator('[data-focus-key="select-request:extra-19"]');await last.scrollIntoViewIfNeeded();await last.click();assert(await last.isVisible());
  const queueArgs=fixtureArguments(states.find(r=>r.designState==='metamask/transaction-done'));queueArgs[0].showNextRequests=true;queueArgs[1].otherSummaries=[{...seed,request_id:'one-next'}];await mount(queueArgs);assert.equal(await f.page.locator('.connection-queue h2').textContent(),'1 other request waiting');
  queueArgs[1].otherSummaries.push({...seed,request_id:'approved-tx',intent:'transaction_intent',status:'approved'});await mount(queueArgs);assert.equal(await f.page.locator('.connection-queue h2').textContent(),'1 other request waiting');assert.equal(await f.page.locator('.connection-queue p').textContent(),'1 transaction to review');assert.equal(await f.page.locator('[data-action="view-requests"]').count(),1);await f.page.screenshot({path:proof.path+'/mixed-recovery-queue-'+engine+'.png'});
  const checkArgs=fixtureArguments(states.find(r=>r.designState==='walletconnect/request-phone'),{compact:true});checkArgs[0].stage='checking-response';checkArgs[0].account=undefined;checkArgs[0].connectionNotice='network-unknown';await mount(checkArgs);assert.equal(await f.page.locator('.connection-request-account').count(),0);assert(await f.page.locator('[data-action="stop-waiting"]').isVisible());await f.page.screenshot({path:proof.path+'/checking-network-only-'+engine+'.png'});
  const many={...account,accounts:Array.from({length:20},(_,i)=>({address:'0x'+String(i).padStart(40,'0'),networks:['Base']}))};
  await f.page.evaluate(async account=>{const m=await import('/capsules/_shared/wallet-connection-view.mjs');window.mounted?.dispose();window.mounted=m.mountConnection(document.querySelector('#mount'),m.connectionView({window:'metamask',stage:'linked',account,compact:true,supportedActions:['copy-address']}));},many);
  for(const index of [8,19]){const b=f.page.locator(`[data-focus-key="copy-address:${many.accounts[index].address}"]`);await b.scrollIntoViewIfNeeded();await b.click();const r=await b.boundingBox();assert(r.y>=0&&r.y+r.height<=182,'ninth and last account controls stay reachable');}
  const hashArgs=fixtureArguments(states.find(r=>r.designState==='walletconnect/transaction-wallet-error'),{compact:true});hashArgs[0].transactionHash='0x'+'ab'.repeat(32);await mount(hashArgs);
  const hash=f.page.locator('.connection-hash');assert.equal(await hash.textContent(),hashArgs[0].transactionHash);assert.equal(await hash.evaluate(e=>(getComputedStyle(e).userSelect||getComputedStyle(e).webkitUserSelect)),'text');assert.equal(await f.page.locator('a').count(),0);
  assert.equal(await hash.evaluate(e=>{const range=document.createRange();range.selectNodeContents(e);const s=getSelection();s.removeAllRanges();s.addRange(range);return s.toString();}),hashArgs[0].transactionHash);await hash.scrollIntoViewIfNeeded();await f.page.screenshot({path:proof.path+'/completion-failure-hash-'+engine+'.png'});
  receipts.push({engine,stages:live.length,supportedActionPaths:states.length+live.length,pickerRows:21,qr:box,result:'PASS'});
 }finally{await f.close();}
});
