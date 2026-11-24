import {windowTestOptions} from './lib/walletconnect-window-resources.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import {writeFile} from 'node:fs/promises';
import {browserFixture,playwright,temporaryProof} from './lib/wallet-connection-browser-fixture.mjs';
import {approvalArguments,approvalCatalog,reviewOrigin} from './lib/wallet-connection-approval-cases.mjs';
import {observeApproval,assertApprovalGeometry,assertApprovalPaint,assertEverySiteLinePaint,approvalIds} from './lib/wallet-connection-approval-oracle.mjs';
import {reduceConnection,connectionView,viewText} from '../capsules/_shared/wallet-connection-view.mjs';
import {states,fixtureArguments} from './wallet-connection-view-fixtures.mjs';
const proof=await temporaryProof('wallet-view-round4-',process.env.WALLET_VIEW_PROOF_DIR);
const evidence=[];
test.after(async()=>{try{await writeFile(proof.path+'/round4.json',JSON.stringify(evidence,null,2)+'\n');}finally{await proof.cleanup();}});
const requestRow=window=>approvalCatalog.stages.find(r=>r.window===window&&r.stage==='request-waiting');
async function mount(page,args){return page.evaluate(async args=>{
 const api=await import('/capsules/_shared/wallet-connection-view.mjs');
 const view=api.reduceConnection(...args);window.connectionMount=api.mountConnection(document.querySelector('#mount'),view,window.connectionMount);
 return {stage:view.stage,requestId:view.requestId,actions:view.actions.map(a=>a.id)};
},args);}
async function bottom(page){await page.evaluate(()=>{const root=document.querySelector('main');root.scrollTop=root.scrollHeight;});}
async function check(page,{paint=true,captureFailure=true}={}){const o=await observeApproval(page);assertApprovalGeometry(o);if(paint)await assertEverySiteLinePaint(page,{captureFailure});return o;}

// H:772-775: an unanswered operation may still be waiting; closing does not cancel it.
test('R4: current transaction busy copy keeps its own pending-wallet sentence once',()=>{
 for(const window of ['walletconnect','metamask']){
  const row=states.find(r=>r.window===window&&r.stage==='request-busy'),args=fixtureArguments(row);
  args[1].summary={...args[1].summary,intent:'transaction_intent'};
  if(window==='walletconnect')args[0].localSafety=null;
  else args[1].safetyMessage=undefined;
  const view=reduceConnection(...args),notice=viewText(view.notice);
  assert.equal((notice.match(/may still be waiting in/g)||[]).length,1);
  assert(!notice.includes('another window'),'the transaction is in this window');
  assert(notice.includes('Activity in Wallet'));
 }
});
test('R4: unknown link-error withholds Connect pending contract-owner retry decision',()=>{
 for(const window of ['walletconnect','metamask','unisat']){
  const row=states.find(r=>r.window===window&&r.stage==='link-error'),args=fixtureArguments(row);
  if(window==='walletconnect')args[0].localSafety=null;else args[1].safetyMessage=undefined;
  const view=reduceConnection(...args);assert(!view.actions.some(a=>approvalIds.includes(a.id)));assert.equal(view.focus,'close-window');
 }
});
test('R4: factory restores only the same request in the same stage on an approval card',()=>{
 const args=approvalArguments(requestRow('metamask')),view=reduceConnection(...args);
 const previous={window:view.window,stage:view.stage,requestId:view.requestId,action:'send-request',key:'send-request'};
 assert.equal(connectionView({...args[0],summary:view.request,provider:args[1].message.snapshot,previousFocus:previous}).focus,'send-request');
 for(const patch of [{requestId:'another-request'},{stage:'request-multiple'},{window:'unisat'}])assert.equal(connectionView({...args[0],summary:view.request,provider:args[1].message.snapshot,previousFocus:{...previous,...patch}}).focus,'close-window');
});
test('R4: request context is a bounded projection of a connector-owned summary',()=>{
 const row=approvalCatalog.stages.find(r=>r.kind==='context'),args=approvalArguments(row),view=reduceConnection(...args);
 assert.equal(view.request,null);assert.equal(view.context.site,reviewOrigin);assert.equal(view.context.id,args[1].contextSummary.request_id);
 assert.throws(()=>connectionView({...args[0],requestContext:{...view.context,freeText:'anything'}}),/closed request context/);
 assert.throws(()=>connectionView({...args[0],requestContext:{...view.context,site:'javascript:alert(1)'}}),/closed request context/);
});
test('R4: timeout notices have no trailing whitespace',()=>{
 for(const row of states.filter(r=>r.stage==='request-timeout')){
  const text=viewText(reduceConnection(...fixtureArguments(row)).notice);assert.equal(text,text.trim());
 }
});

for(const engine of ['chromium','webkit']){
 const skip=windowTestOptions(engine).skip;
 test(`R4 F-A: caller-owned redraw continuity in ${engine} at 320x182`,{skip,timeout:120000},async t=>{
  const f=await browserFixture(engine,{width:320,height:182});
  try{
   await f.page.evaluate(()=>document.fonts.ready);const args=approvalArguments(requestRow('metamask'));args[1].summary.expires_at=null;args[1].summary.reason='A long app reason. '.repeat(30);
   await mount(f.page,args);assert.equal(await f.page.evaluate(()=>document.activeElement.dataset.action),'close-window');
   const send=f.page.locator('[data-action="send-request"]');await send.focus();await assertApprovalPaint(f.page,await observeApproval(f.page));
   const initial=await f.page.evaluate(()=>{window.originalFocus=document.activeElement;return {top:document.querySelector('main').scrollTop};});
   args[0].waitSeconds=89;args[1].summary={...args[1].summary,expires_at:null};await mount(f.page,args);
   const after=await f.page.evaluate(()=>({same:document.activeElement===window.originalFocus,action:document.activeElement.dataset.action,top:document.querySelector('main').scrollTop}));
   assert(after.same,'timer redraw preserves the focused DOM node for assistive technology');assert.equal(after.action,'send-request');assert.equal(after.top,initial.top);await check(f.page);
   await f.page.evaluate(()=>{document.querySelector('main').scrollTop=57;});args[0].waitSeconds=88;await mount(f.page,args);assert.equal(await f.page.evaluate(()=>document.querySelector('main').scrollTop),57,'partial scroll survives timer redraw exactly');
   // A changed visible summary requires replacement, but the same card preserves logical focus/scroll.
   args[1].summary.reason='A changed app reason. '.repeat(30);await mount(f.page,args);assert.equal(await f.page.evaluate(()=>document.activeElement.dataset.action),'send-request');assert.equal(await f.page.evaluate(()=>document.querySelector('main').scrollTop),57);
   for(const key of ['Enter','Space']){await f.page.evaluate(()=>{document.querySelector('main').scrollTop=57;});await f.page.keyboard.press(key);const o=await observeApproval(f.page);assertApprovalGeometry(o);assert(o.visible.length,'keyboard activation reveals approval after manual scrolling');await assertApprovalPaint(f.page,o);}
   args[1].summary.request_id+='-next';await mount(f.page,args);assert.equal(await f.page.evaluate(()=>document.activeElement.dataset.action),'close-window');assert.equal(await f.page.evaluate(()=>document.querySelector('main').scrollTop),0);
   await bottom(f.page);args[0].stage='request-multiple';await mount(f.page,args);assert.equal(await f.page.evaluate(()=>document.activeElement.dataset.action),'close-window');assert.equal(await f.page.evaluate(()=>document.querySelector('main').scrollTop),0);
   await send.focus();await check(f.page);await f.page.screenshot({path:proof.path+`/redraw-send-${engine}.png`});
   await t.test('a forced redraw reset fails continuity',async()=>{
    const before=await f.page.evaluate(()=>({action:document.activeElement.dataset.action,top:document.querySelector('main').scrollTop}));
    await f.page.evaluate(()=>{document.querySelector('.connection-approve-actions [data-action=close-window]').focus({preventScroll:true});document.querySelector('main').scrollTop=0;});
    const broken=await f.page.evaluate(()=>({action:document.activeElement.dataset.action,top:document.querySelector('main').scrollTop}));
    assert.throws(()=>assert.deepEqual(broken,before),assert.AssertionError,'forced opening reset must fail the continuity oracle');
   });
   evidence.push({engine,case:'F-A',initial,after,result:'PASS'});
  }finally{await f.close();}
 });
 test(`R4: every approving stage has immediate site flow and painted lines in ${engine}`,{skip,timeout:600000},async t=>{
  const f=await browserFixture(engine,{width:320,height:182});
  try{
   await f.page.evaluate(()=>document.fonts.ready);
   for(const row of approvalCatalog.stages)await t.test(`${row.window}/${row.stage}`,async()=>{
    for(const [width,height]of (process.env.WALLET_VIEW_BROWSER_SMOKE==='1'?[[320,182]]:[[320,182],[480,522]])){
     await f.page.setViewportSize({width,height});const args=approvalArguments(row,{compact:width===320});const model=await mount(f.page,args);
     assert.equal(model.stage,row.stage,'the fixture exercises its named stage');
     if(row.window==='metamask'&&['request-unsendable','link-error'].includes(row.stage)){
      assert(!model.actions.some(a=>approvalIds.includes(a)));assert(model.actions.includes('refresh-status'));assert(model.actions.includes('close-window'));
      evidence.push({engine,case:row.window+'/'+row.stage,width,height,kind:'compatible-wallet check without approval',result:'PASS'});continue;
     }
     if(row.approving===false){
      assert(!model.actions.some(a=>approvalIds.includes(a)),'empty-account QR recovery grants no approval');assert(model.actions.includes('start-over'));
      assert.equal(await f.page.locator('.connection-site').textContent(),reviewOrigin);
      evidence.push({engine,case:row.window+'/'+row.stage,width,height,kind:'non-approving fresh-QR recovery',result:'PASS'});continue;
     }
     assert(model.actions.some(a=>approvalIds.includes(a)));
     const opening=await observeApproval(f.page);assert.equal(opening.scrollTop,0);assertApprovalGeometry(opening);
     await assertEverySiteLinePaint(f.page);await bottom(f.page);const end=await check(f.page);assert(end.visible.length);
     evidence.push({engine,case:row.window+'/'+row.stage,width,height,kind:args[1].summary?.intent||'context',contrast:end.contrast,lines:end.lines.length,result:'PASS'});
    }
   });
   // A transaction-specific relocation cannot hide behind message-only coverage.
   for(const window of ['walletconnect','metamask','unisat']){
    await f.page.setViewportSize({width:320,height:182});await mount(f.page,approvalArguments(requestRow(window),{transaction:true}));await bottom(f.page);await check(f.page);
   }
  }finally{await f.close();}
 });
 test(`R4: all five review-predicted escapes and the 8px limit fail in ${engine}`,{skip,timeout:180000},async t=>{
  const f=await browserFixture(engine,{width:320,height:182});
  try{
   await f.page.evaluate(()=>document.fonts.ready);
   for(const mutation of ['app between site and approval','3px site','7 percent site','all but final line clipped','transaction site above reason','gap over 8px'])await t.test(mutation,async()=>{
    await f.page.evaluate(()=>{window.connectionMount?.dispose();window.connectionMount=null;});
    await mount(f.page,approvalArguments(requestRow('metamask'),{transaction:mutation==='transaction site above reason'}));await bottom(f.page);await check(f.page);
    await f.page.evaluate(m=>{
     const root=document.querySelector('main'),site=root.querySelector('.connection-site'),unit=root.querySelector('.connection-approval-unit');
     if(m==='app between site and approval'){const name=document.createElement('span');name.textContent='App name';name.className='connection-app';site.parentElement.append(name);}
     if(m==='3px site')site.querySelector('.connection-host-end').style.fontSize='3px';
     if(m==='7 percent site')site.style.color='rgba(245,247,250,.07)';
     if(m==='all but final line clipped'){site.style.display='block';site.style.clipPath='inset(calc(100% - 1.5em) 0 0 0)';}
     if(m==='transaction site above reason')root.querySelector('.connection-identity').prepend(site.parentElement);
     if(m==='gap over 8px')unit.firstElementChild.style.marginBottom='12px';
    },mutation);
    if(mutation==='all but final line clipped'){await bottom(f.page);await assertApprovalPaint(f.page,await observeApproval(f.page),{captureFailure:false});}
    await assert.rejects(()=>check(f.page,{captureFailure:false}),undefined,mutation+' must fail the independent acceptance oracle');
    evidence.push({engine,break:mutation,result:'CAUGHT'});
   });
  }finally{await f.close();}
 });
 test(`R4: native scrolling, whole labels and site contrast in ${engine}`,{skip,timeout:120000},async()=>{
  const f=await browserFixture(engine,{width:320,height:182});
  try{
   await f.page.evaluate(()=>document.fonts.ready);await mount(f.page,approvalArguments(requestRow('metamask')));
   assert(await f.page.locator('main').evaluate(r=>r.scrollHeight>r.clientHeight),'long approval scrolls as one card');
   await bottom(f.page);await check(f.page);
   await f.page.setViewportSize({width:480,height:1200});await mount(f.page,approvalArguments(requestRow('metamask'),{origin:'https://example.com',compact:false}));assert.equal(await f.page.locator('main').evaluate(r=>r.scrollHeight>r.clientHeight),false,'short approval fits without scrolling');
   for(const theme of ['dark','light']){
    await f.page.evaluate(theme=>{document.documentElement.dataset.elTheme=theme;},theme);const o=await observeApproval(f.page);assertApprovalGeometry(o);evidence.push({engine,theme,contrast:o.contrast,result:'PASS'});
   }
   for(const width of [160,280,320,360,390,480]){
    await f.page.setViewportSize({width,height:182});await mount(f.page,approvalArguments(requestRow('metamask')));const o=await observeApproval(f.page);assert(o.lines.every(l=>!l.text.startsWith('.')),'a dot cannot begin a site line');
   }
   // Receipt images: one approving card per connector, each with a full look-alike origin.
   await f.page.evaluate(()=>{document.documentElement.dataset.elTheme='dark';});
   for(const window of ['walletconnect','metamask','unisat'])for(const [width,height]of [[320,182],[360,596],[480,522]])for(const [label,origin]of [['135',reviewOrigin],['lookalike','https://accounts.example.com.secure-login-verify-session.attacker-domain.net'],['253','https://'+('a'.repeat(63)+'.').repeat(3)+'a'.repeat(61)]]){
    await f.page.setViewportSize({width,height});await mount(f.page,approvalArguments(requestRow(window),{origin,compact:width===320}));await bottom(f.page);
    await f.page.screenshot({path:proof.path+`/r4-${window}-${label}-${width}x${height}-${engine}-end.png`});
    await f.page.evaluate(()=>{document.querySelector('main').scrollTop=0;});
    await f.page.screenshot({path:proof.path+`/r4-${window}-${label}-${width}x${height}-${engine}-start.png`});
   }
  }finally{await f.close();}
 });
}
