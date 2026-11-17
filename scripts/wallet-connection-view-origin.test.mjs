import test,{describe} from 'node:test';
import assert from 'node:assert/strict';
import {existsSync} from 'node:fs';
import {writeFile} from 'node:fs/promises';
import {browserFixture,playwright,temporaryProof} from './lib/wallet-connection-browser-fixture.mjs';
import {observeApproval,assertApprovalGeometry,assertApprovalPaint,approvalIds} from './lib/wallet-connection-approval-oracle.mjs';
import {states,fixtureArguments} from './wallet-connection-view-fixtures.mjs';

// Playwright 1.60 waits for document.fonts by default; this suite must capture the fallback paint before releasing the font route.
const previousFontWait=process.env.PW_TEST_SCREENSHOT_NO_FONTS_READY;process.env.PW_TEST_SCREENSHOT_NO_FONTS_READY='1';
test.after(()=>{if(previousFontWait===undefined)delete process.env.PW_TEST_SCREENSHOT_NO_FONTS_READY;else process.env.PW_TEST_SCREENSHOT_NO_FONTS_READY=previousFontWait;});
const exact='accounts.example.com.secure-login-verify-session.signin-confirmation-required.wallet-authorization.account-recovery.attacker-domain.net';
const lookalike='accounts.example.com.secure-login-verify-session.attacker-domain.net';
function host(length){if(length<=63)return 'a'.repeat(length);const tail='.attacker-domain.net';let prefix='';while(length-tail.length-prefix.length>63)prefix+='a'.repeat(63)+'.';return prefix+'a'.repeat(length-tail.length-prefix.length)+tail;}
const origins=[...[1,63,87,89,118,135,253].map(n=>'https://'+host(n)), 'https://'+exact,'https://'+lookalike,'https://'+host(499)+':4444'];
assert.equal(exact.length,135);assert.equal(origins.at(-1).length,512);
const sizes=[[320,182],[360,596],[480,522],[390,844]];
const ciSmoke=process.env.WALLET_VIEW_BROWSER_SMOKE==='1';
const requested=process.env.WALLET_VIEW_PROOF_DIR;
const proof=await temporaryProof('wallet-view-origin-',requested);
test.after(async()=>proof.cleanup());

async function mount(page,{window='metamask',origin=origins[7],long=true,compact=true,unnamed=false}={}){
 const row=structuredClone(states.find(r=>r.window===window&&r.stage==='request-waiting'));
 const args=fixtureArguments(row,{compact});
 args[0].account.name=long?'W'.repeat(40):row.local.account.name;
 args[1].summary={...args[1].summary,capsule_id:unnamed?'unlabelled-app':'browser',requesting_app_name:unnamed?undefined:long?'A'.repeat(128):'Browser',requesting_origin:origin,reason:long?'R'.repeat(2048):'Sign in to the app.'};
 return page.evaluate(async args=>{
  const {reduceConnection,renderConnection}=await import('/capsules/_shared/wallet-connection-view.mjs');
  const view=reduceConnection(...args),mount=document.querySelector('#mount');mount.replaceChildren(renderConnection(document,view));
  const root=mount.firstChild;root.scrollTop=0;window.approvalActivations=[];
  root.addEventListener('click',event=>{const button=event.target.closest('button');if(!button||!['send-request','connect','restore-access','send-message','finish'].includes(button.dataset.action))return;
   const site=root.querySelector('.connection-site'),walker=document.createTreeWalker(site,NodeFilter.SHOW_TEXT);let node,last;while(node=walker.nextNode())if(node.length)last=node;
   const range=document.createRange();range.setStart(last,last.length-1);range.setEnd(last,last.length);const box=range.getBoundingClientRect(),lines=[];const text=document.createTreeWalker(site,NodeFilter.SHOW_TEXT);while(text.nextNode())for(let i=0;i<text.currentNode.length;i++){const part=document.createRange();part.setStart(text.currentNode,i);part.setEnd(text.currentNode,i+1);const r=part.getBoundingClientRect();if(Math.abs(r.top-box.top)<1)lines.push(r);}
   const top=Math.min(...lines.map(r=>r.top)),bottom=Math.max(...lines.map(r=>r.bottom));
   window.approvalActivations.push({id:button.dataset.action,visible:top>=0&&bottom<=innerHeight,top,bottom,scrollTop:root.scrollTop});
  });return {stage:view.stage,focus:view.focus};
 },args);
}
async function check(page,{paint=true}={}){const o=await observeApproval(page);assertApprovalGeometry(o);if(paint&&o.visible.length)await assertApprovalPaint(page,o);return o;}
async function sweep(page){
 let o=await check(page);assert.equal(o.scrollTop,0,'opening position is card start');assert(o.topExit&&o.cue==='More below.','visible top dismissal and more cue');
 const top=await page.locator('.connection-card-start').boundingBox();assert(top.y>=0&&top.y+top.height<=o.height,'top exit is reachable before the site');
 // Measure opening first, then every CSS-pixel scroll position in the range.
 // Only positions with an intersecting approving control require paint captures.
 const samples=await page.evaluate(async ids=>{
  const root=document.querySelector('main'),site=root.querySelector('.connection-site');const walker=document.createTreeWalker(site,NodeFilter.SHOW_TEXT);let node,last;while(node=walker.nextNode())if(node.length)last=node;
  const range=document.createRange();range.setStart(last,last.length-1);range.setEnd(last,last.length);const max=root.scrollHeight-root.clientHeight,visible=[];
  for(let y=0;y<=max;y++){ root.scrollTop=y;const end=range.getBoundingClientRect();const buttons=[...root.querySelectorAll('button')].filter(b=>ids.includes(b.dataset.action));
   for(const b of buttons){const box=b.getBoundingClientRect();if(box.bottom>0&&box.top<innerHeight){if(end.top<-.5||end.bottom>innerHeight+.5||box.top<end.bottom-.5||box.top-end.bottom>30)throw new Error('approval visible without final site line at scroll '+y);visible.push(y);}}
  }return {max,visible:[...new Set(visible)]};
 },approvalIds);
 assert(samples.visible.length,'approving control is reachable');
 // Every sampled paint position (16px steps plus both intersection edges) gets a standalone pixel reference; geometry above checks every CSS pixel.
 const positions=samples.visible.filter((y,i)=>i===0||i===samples.visible.length-1||y%16===0);
 for(const y of new Set(positions)){await page.evaluate(y=>{document.querySelector('main').scrollTop=y;},y);await check(page);}
 return {...samples,paintedScrollPositions:[...new Set(positions)]};
}
async function activate(page,resize){
 if(resize)await page.setViewportSize(resize);
 const button=page.locator('[data-action="send-request"]');await button.scrollIntoViewIfNeeded();await check(page);await button.click();await check(page,{paint:false});
 for(const key of ['Enter','Space']){
  await page.evaluate(()=>{document.querySelector('main').scrollTop=0;document.activeElement?.blur();});
  // Native Tab traversal, without a scripted scroll or focus on the approving control.
  await page.locator('.connection-card-start [data-action="close-window"]').focus();
  for(let n=0;n<20;n++){await page.keyboard.press('Tab');if(await button.evaluate(e=>e===document.activeElement))break;}
  assert(await button.evaluate(e=>e===document.activeElement),'Tab reaches approval');await check(page);await page.keyboard.press(key);await check(page,{paint:false});
 }
 const events=await page.evaluate(()=>window.approvalActivations);assert.equal(events.length,3);assert(events.every(e=>e.visible),'site final line visible at pointer, Enter and Space activation');
 return events;
}
describe('structural approval access and paint',{concurrency:false,timeout:360000},()=>{
for(const engine of ['chromium','webkit']){
 const optional=engine==='webkit'&&!existsSync(playwright.webkit.executablePath())&&!process.env.ELASTOS_PLAYWRIGHT_MODULE;
 test(`F1: full origins and fixed feedback in ${engine}`,{skip:optional?'WebKit required in content-sandbox CI':false,timeout:175000},async t=>{
  const receipts=[];
  const runScale=async scale=>{
   // At 200% effective browser zoom, a physical window contains half as many CSS pixels.
   const f=await browserFixture(engine,{width:320/scale,height:182/scale,scale,delayFont:true});
   try{
    for(const window of ['metamask','walletconnect','unisat'])for(const [width,height]of sizes)for(const i of (ciSmoke?[7,9]:origins.map((_,i)=>i))){
     if(t.signal.aborted)throw new Error('approval matrix cancelled');
     try {
     await f.page.setViewportSize({width:Math.floor(width/scale),height:Math.floor(height/scale)});
     const delayedFamily=await f.prepareFont();
     await mount(f.page,{window,origin:origins[i],compact:scale===2||width<=360});
     const fontBefore=await f.page.evaluate(family=>[...document.fonts].find(f=>f.family===family)?.status,delayedFamily);assert(fontBefore&&fontBefore!=='loaded','font response is withheld through fallback paint');
     const opening=await check(f.page);assert.equal(opening.origin,origins[i]);assert.equal(opening.scrollTop,0);
     const measured=await sweep(f.page);
     if(requested&&scale===1&&width!==390&&[6,7,8].includes(i)){await f.page.screenshot({path:`${proof.path}/${window}-approval-${i===6?'253':i===7?'135':'lookalike'}-${width}x${height}-end-${engine}.png`});await f.page.evaluate(()=>{document.querySelector('main').scrollTop=0;});await f.page.screenshot({path:`${proof.path}/${window}-approval-${i===6?'253':i===7?'135':'lookalike'}-${width}x${height}-start-${engine}.png`});}
     await f.releaseFont();const fontAfter=await f.page.evaluate(family=>[...document.fonts].find(f=>f.family===family)?.status,delayedFamily);assert.equal(fontAfter,'loaded','real web font arrives after fallback paint');await check(f.page,{paint:false});
     const events=await activate(f.page,{width:Math.floor((width===320?360:320)/scale),height:Math.floor((height===182?596:182)/scale)});
     receipts.push({window,width,height,scale,origin:origins[i],fontBefore,fontAfter,...measured,events});
     }catch(error){error.stack=`${engine}/${window}/${width}x${height}/zoom${scale}/origin${origins[i].length}:\n${error.stack}`;throw error;}
    }
   }finally{await f.close();}
  };
  if(engine==='chromium')await Promise.all([1,2].map(runScale));else for(const scale of [1,2])await runScale(scale);
  const f=await browserFixture(engine);try{await mount(f.page,{unnamed:true,long:false,compact:false});assert.equal(await f.page.locator('.connection-app').textContent(),'Requesting app');if(requested)await f.page.screenshot({path:`${proof.path}/unnamed-app-${engine}.png`});}finally{await f.close();}
  assert.equal(receipts.length,ciSmoke?48:240);
  await writeFile(`${proof.path}/approval-${engine}.json`,JSON.stringify(receipts,null,2)+'\n');
 });
 test(`F1: six independent layout and paint breaks fail in ${engine}`,{skip:optional?'WebKit required in content-sandbox CI':false},async t=>{
  const f=await browserFixture(engine,{width:320,height:182});
  try{
   await f.page.evaluate(()=>document.fonts.ready);
   for(const mutation of ['O2 clip-path','O4 site above reason','opacity zero','overlay','pinned approval','ellipsis'])await t.test(mutation,async()=>{
    await mount(f.page,{long:false});await f.page.evaluate(()=>document.fonts.ready);
    await f.page.evaluate(()=>{const root=document.querySelector('main');root.scrollTop=root.scrollHeight;});await check(f.page);
    await f.page.evaluate(mutation=>{
     const root=document.querySelector('main'),site=root.querySelector('.connection-site');
     if(mutation==='O2 clip-path')site.style.clipPath='inset(0 0 calc(100% - 1em) 0)';
     if(mutation==='O4 site above reason')root.querySelector('.connection-identity').prepend(site.parentElement);
     if(mutation==='opacity zero')site.style.opacity='0';
     if(mutation==='overlay'){const e=document.createElement('div'),r=site.getBoundingClientRect();e.style.cssText=`position:fixed;left:${r.left}px;top:${r.top}px;width:${r.width}px;height:${r.height}px;background:#16181d;z-index:99999`;root.append(e);}
     if(mutation==='pinned approval'){root.scrollTop=0;root.querySelector('.connection-approve-actions').style.cssText='position:fixed;bottom:0;left:0;right:0';}
     if(mutation==='ellipsis')site.style.cssText='white-space:nowrap;overflow:hidden;text-overflow:ellipsis';
    },mutation);
    await assert.rejects(async()=>{if(['O2 clip-path','opacity zero','overlay'].includes(mutation))await assertApprovalPaint(f.page,await observeApproval(f.page),{captureFailure:false});else await check(f.page);},undefined,mutation+' escaped independent oracle');
   });
  }finally{await f.close();}
 });
}

});
