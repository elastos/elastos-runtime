import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { requireProductSmokePlaywright } from './product-smoke-browser.mjs';
import { fixture } from './lib/wallet-extension-window-fixture.mjs';
const playwright=requireProductSmokePlaywright();

// Primary contract: wallet-provider/src/approval.rs:486-490 consumes Pending;
// :362 excludes Approved from ListApprovals(false). Home calls handoff before
// its signer check (home-wallet-connector-host.js:291-312 at the pinned base).
async function oneUse(f,kind) {
  await f.top.evaluate(value=>testState.walletAddress=value,kind==='metamask'?'0x'+'2'.repeat(40):'bc1q'+'b'.repeat(38));
  await f.action('send-request').click();
  await f.frame.waitForFunction(()=>document.querySelector('main').dataset.state!=='request-extension',null,{timeout:3000});
  assert.equal(await f.top.evaluate(()=>testState.requests[0]?.status),'approved');
  await f.state('request-unavailable');
  assert.equal(await f.action('send-request').count(),0,'a consumed request cannot offer a dead retry');
  assert.equal(await f.top.evaluate(()=>testState.receipts.length),0);
  await f.top.evaluate(()=>testState.walletAddress=testState.address);
  const result=await f.frame.evaluate(kind=>new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>{removeEventListener('message',receive);reject(Error('one-use reply timeout'));},3000);
    function receive(event){if(event.source===window.top&&event.origin==='http://extensions.test'&&event.data?.requestId==='one-use:retry'){clearTimeout(timer);removeEventListener('message',receive);resolve(event.data);}}
    addEventListener('message',receive);
    window.top.postMessage({type:'home:wallet-connector-effect',schema:'elastos.home.wallet-connector-effect/v1',requestId:'one-use:retry',connectorId:'wallet-'+kind,connectorToken:'fixture-token',action:{kind:'approve',approvalRequestId:'approval-1'}},'http://extensions.test');
  }),kind);
  assert.match(result.error,/not found|not pending/);
  const record=await f.top.evaluate(()=>({status:testState.requests[0].status,receipts:testState.receipts.length,calls:testState.calls}));
  assert.equal(record.status,'approved');assert.equal(record.receipts,0);
  assert.equal(record.calls.filter(c=>['personal_sign','signMessage','eth_sendTransaction'].includes(c.method)).length,0);
}
for(const engine of ['chromium','webkit'])for(const kind of ['metamask','unisat'])test(`${engine} ${kind}: pinned Home one-use handoff is not a retryable pending request`,{timeout:15000,skip:engine==='webkit'&&!existsSync(playwright.webkit.executablePath())?'WebKit required for explicit Mac acceptance':false},async t=>{
  const browser=await playwright[engine].launch({headless:true});
  try{
    const good=await fixture(browser,kind,{saved:true,requests:true,oldHost:true});try{await oneUse(good,kind);}finally{await good.close();}
    const bad=await fixture(browser,kind,{saved:true,requests:true,oldHost:true});try{
      await bad.top.evaluate(()=>{const send=runtimeFetch;window.runtimeFetch=async(url,init)=>{const result=await send(url,init);if(url.endsWith('/handoff'))testState.requests[0].status='pending';return result;};});
      await assert.rejects(oneUse(bad,kind),error=>error.code==='ERR_ASSERTION'||error.name==='TimeoutError','the former reusable-handoff double must fail');
      t.diagnostic('one-use Runtime model passed; former pending-after-handoff model failed');
    }finally{await bad.close();}
  }finally{await browser.close();}
});
