import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { requireProductSmokePlaywright } from './product-smoke-browser.mjs';
import { fixture } from './lib/wallet-extension-window-fixture.mjs';
const playwright=requireProductSmokePlaywright();

// Primary contract: wallet-provider/src/approval.rs:486-490 consumes Pending;
// :362 excludes Approved from ListApprovals(false). Home calls handoff before
// its signer check (home-wallet-connector-host.js:291-312 at the pinned base).
async function refuse(f,kind) {
  await f.top.evaluate(value=>testState.walletAddress=value,kind==='metamask'?'0x'+'2'.repeat(40):'bc1q'+'b'.repeat(38));
  await f.action('send-request').click();
  await f.frame.waitForFunction(()=>document.querySelector('main').dataset.state!=='request-extension',null,{timeout:3000});
}
async function consumed(f,kind) {
  await f.state('request-unavailable');
  assert.equal(await f.action('send-request').count(),0,'a consumed request cannot offer a dead retry');
  assert.equal(await f.top.evaluate(()=>testState.requests[0]?.status),'approved');
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
for(const engine of ['chromium','webkit'])for(const kind of ['metamask','unisat'])test(`${engine} ${kind}: pinned Home one-use handoff is not a retryable pending request`,{timeout:30000,skip:engine==='webkit'&&!existsSync(playwright.webkit.executablePath())?'WebKit required for explicit Mac acceptance':false},async t=>{
  const browser=await playwright[engine].launch({headless:true});
  try{
    for(const oldHost of [true,false]) {
      const good=await fixture(browser,kind,{saved:true,requests:true,oldHost});try{await refuse(good,kind);await consumed(good,kind);}finally{await good.close();}
      const bad=await fixture(browser,kind,{saved:true,requests:true,oldHost,pictures:false});try{
        await bad.top.evaluate(()=>{const send=runtimeFetch;window.runtimeFetch=async(url,init)=>{const result=await send(url,init);if(url.endsWith('/handoff'))testState.requests[0].status='pending';return result;};});
        await refuse(bad,kind);await bad.state('request-unsendable');
        await bad.frame.waitForFunction(()=>!document.querySelector('[data-action="send-request"]').disabled,null,{timeout:3000});
        await assert.rejects(consumed(bad,kind),error=>/locator.waitFor: Timeout/.test(error.message)&&/request-unavailable/.test(error.message),'the former reusable-handoff model must fail the same UI oracle');
        t.diagnostic(`${oldHost?'pinned':'current'} Home: consumed request hidden; broken pending model shows an enabled retry and fails the UI oracle`);
      }finally{await bad.close();}
    }
  }finally{await browser.close();}
});

async function failedRead(f,kind,failure=503) {
  await f.state('request-waiting');
  const fail=route=>route.fulfill(failure===503?{status:503,json:{error:'fixture read error'}}:{json:{available:false,approval_requests:[]}});
  await f.context.route('**/approvals',fail);
  await refuse(f,kind);await f.state('link-error');
  const consumedAtRuntime=await f.top.evaluate(()=>testState.requests[0].status==='approved');
  await f.frame.evaluate(()=>{window.returnSeen=false;addEventListener('message',function watch(e){if(e.data?.type==='home:wallet-connector-event'){returnSeen=true;removeEventListener('message',watch);}});});
  await f.top.evaluate(()=>{testState.walletAddress=testState.address;emitWallet('accountsChanged',[testState.address]);});
  await f.frame.waitForFunction(()=>returnSeen);
  await f.state('link-error');assert.equal(await f.action('send-request').count(),0);
  await f.context.unroute('**/approvals',fail);await f.action('connect').click();
  await f.state(consumedAtRuntime?'request-unavailable':'request-waiting');
  assert.equal(await f.top.evaluate(()=>testState.effects.length),1,'retry only repeats Home reads');
}
for(const engine of ['chromium','webkit'])for(const kind of ['metamask','unisat'])test(`${engine} ${kind}: wallet events cannot revive Send after a failed pending-list verification`,{timeout:30000,skip:engine==='webkit'&&!existsSync(playwright.webkit.executablePath())?'WebKit required for explicit Mac acceptance':false},async()=>{
  const browser=await playwright[engine].launch({headless:true});try{
    for(const failure of [503,200]) {
      const good=await fixture(browser,kind,{saved:true,requests:true});try{await failedRead(good,kind,failure);}finally{await good.close();}
      const bad=await fixture(browser,kind,{saved:true,requests:true,mutate:source=>{const broken=source.replace('pendingVerificationRequired = true;','pendingVerificationRequired = false;');assert.notEqual(broken,source);return broken;}});try{
        await assert.rejects(failedRead(bad,kind,failure),error=>error.code==='ERR_ASSERTION'||/locator.waitFor: Timeout/.test(error.message),'missing verification hold must fail');
      }finally{await bad.close();}
    }
  }finally{await browser.close();}
});

for(const engine of ['chromium','webkit'])for(const kind of ['metamask','unisat'])test(`${engine} ${kind}: verifying a refusal keeps Send disabled and follows wallet corrections`,{timeout:30000,skip:engine==='webkit'&&!existsSync(playwright.webkit.executablePath())?'WebKit required for explicit Mac acceptance':false},async()=>{
  const browser=await playwright[engine].launch({headless:true});try{
    for(const fault of ['account','network']) {
      const transaction=kind==='metamask';
      const f=await fixture(browser,kind,{saved:true,requests:transaction?'transaction':true,pictureContext:'pending-list response held; Runtime has already consumed the handoff'});
      let release;
      try {
        await f.state(transaction?'transaction-waiting':'request-waiting');
        const gate=new Promise(resolve=>release=resolve);
        await f.context.route('**/approvals',async route=>{await gate;await route.fulfill({json:{approval_requests:[]}});});
        await f.top.evaluate(({kind,fault})=>{
          if(fault==='account')testState.walletAddress=kind==='metamask'?'0x'+'2'.repeat(40):'bc1q'+'b'.repeat(38);
          else if(kind==='metamask')testState.refuseSwitch=true;
          else testState.network='testnet';
        },{kind,fault});
        await f.action('send-request').click();
        await f.state(fault==='account'?'request-unsendable':kind==='metamask'?'request-network-declined':'request-network-testnet');
        assert.equal(await f.action('send-request').isDisabled(),true);
        assert.equal(await f.top.evaluate(()=>testState.requests[0].status),'approved');
        if(fault==='account') {
          await f.frame.evaluate(()=>{window.corrected=false;addEventListener('message',function watch(e){if(e.data?.type==='home:wallet-connector-event'){corrected=true;removeEventListener('message',watch);}});});
          await f.top.evaluate(()=>{testState.walletAddress=testState.address;emitWallet('accountsChanged',[testState.address]);});
          await f.frame.waitForFunction(()=>corrected);await f.state(transaction?'transaction-waiting':'request-waiting');
          assert.equal(await f.action('send-request').isDisabled(),true,'the wallet correction alone cannot prove pending status');
          assert.doesNotMatch(await f.frame.locator('body').innerText(),/not providing.*account/i);
        }
        assert.equal(await f.top.evaluate(()=>testState.effects.length),1);
        release();await f.state('request-unavailable');assert.equal(await f.action('send-request').count(),0);
        assert.equal(await f.top.evaluate(()=>testState.receipts.length),0);
      }finally{release?.();await f.close();}
    }
  }finally{await browser.close();}
});
