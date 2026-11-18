import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {existsSync} from 'node:fs';
import {requireProductSmokePlaywright} from './product-smoke-browser.mjs';
import {fixture} from './lib/wallet-extension-window-fixture.mjs';
const playwright=requireProductSmokePlaywright();
const recordings=JSON.parse(await readFile(new URL('./fixtures/wallet-extension-replay.json',import.meta.url),'utf8'));
const recordedReject=recordings.cases.find(c=>c.id==='MM-7-known-reject').snapshots.find(s=>s.call?.error).call.error;
assert.equal(recordedReject.code,4001);assert.equal(recordedReject.constructor,'Object');
const skip=engine=>engine==='webkit'&&!existsSync(playwright.webkit.executablePath())?'WebKit required on Mac; Linux acceptance uses Chromium':false;
for(const engine of ['chromium','webkit']) {
  test(`${engine} MetaMask: recorded plain-object switch rejection stays honestly unclassified by v1`,{skip:skip(engine)},async()=>{
    const browser=await playwright[engine].launch({headless:true});try{const f=await fixture(browser,'metamask',{saved:true,requests:'transaction'});try{
      await f.state('transaction-waiting');await f.top.evaluate(()=>testState.refuseSwitch='reject');
      await f.action('send-request').click();await f.state('transaction-wallet-error');
      assert.match(await f.frame.locator('body').innerText(),/transaction may have been sent/);
      assert.equal(await f.top.evaluate(()=>testState.calls.filter(c=>c.method==='eth_sendTransaction').length),0);
      assert.equal(await f.top.evaluate(()=>testState.requests[0].status),'approved');
      assert.equal(await f.action('send-request').count(),0);await f.assertShared();
    }finally{await f.close();}}finally{await browser.close();}
  });
  test(`${engine} MetaMask: post-broadcast completion failure keeps payment uncertainty`,{skip:skip(engine)},async()=>{
    const browser=await playwright[engine].launch({headless:true});try{const f=await fixture(browser,'metamask',{saved:true,requests:'transaction'});try{
      await f.state('transaction-waiting');await f.top.evaluate(()=>{const send=runtimeFetch;window.runtimeFetch=(url,init)=>url.endsWith('/complete')?Promise.reject(Error('fixture recording failed')):send(url,init);});
      await f.action('send-request').click();await f.state('transaction-wallet-error');
      assert.equal(await f.top.evaluate(()=>testState.calls.filter(c=>c.method==='eth_sendTransaction').length),1);
      assert.equal(await f.top.evaluate(()=>testState.receipts.length),0);
      assert.match(await f.frame.locator('body').innerText(),/transaction may have been sent/);
      assert.equal(await f.action('send-request').count(),0);await f.assertShared();
    }finally{await f.close();}}finally{await browser.close();}
  });
  for(const kind of ['metamask','unisat'])test(`${engine} ${kind}: refusal isolates the app name and does not rewrite its live region`,{skip:skip(engine)},async()=>{
    const browser=await playwright[engine].launch({headless:true});try{const f=await fixture(browser,kind,{saved:true,requests:true});try{
      await f.state('request-waiting');const app='Owner \u202Eapp';
      await f.top.evaluate(({app,kind})=>{Object.assign(testState.requests[0],{capsule_id:'fixture-app',requesting_app_name:app,requesting_origin:null});testState.walletAddress=kind==='metamask'?'0x'+'2'.repeat(40):'bc1q'+'b'.repeat(38);},{app,kind});
      await f.frame.evaluate(()=>dispatchEvent(new Event('focus')));
      await f.frame.waitForFunction(app=>document.querySelector('.connection-app')?.textContent===app,app);
      await f.action('send-request').click();await f.state('request-consumed');
      const value=f.frame.locator('.connection-notice bdi').last();assert.equal(await value.textContent(),app);assert.equal(await value.getAttribute('dir'),'auto');
      assert.equal(await value.evaluate(e=>getComputedStyle(e).unicodeBidi),'isolate');
      await f.frame.evaluate(()=>{window.copyNode=document.querySelector('.connection-status');window.copyMutations=0;new MutationObserver(records=>copyMutations+=records.length).observe(document.querySelector('.connection-status'),{childList:true,subtree:true,characterData:true});});
      await f.top.clock.runFor(2100);assert.equal(await f.frame.evaluate(()=>copyMutations),0);assert.equal(await f.frame.evaluate(()=>copyNode===document.querySelector('.connection-status')),true);
    }finally{await f.close();}}finally{await browser.close();}
  });
}
