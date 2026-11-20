import {windowTestOptions} from './lib/walletconnect-window-resources.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import { requireProductSmokePlaywright } from './product-smoke-browser.mjs';
import { fixture } from './lib/wallet-extension-window-fixture.mjs';
const playwright=requireProductSmokePlaywright();

// Primary contract: wallet-provider/src/approval.rs:486-490 consumes Pending;
// :362 excludes Approved from ListApprovals(false). Home calls handoff before
// its signer check (home-wallet-connector-host.js:291-312 at the pinned base).
async function refuse(f,kind) {
  await f.top.evaluate(value=>testState.accountDuringHandoff=value,kind==='metamask'?'0x'+'2'.repeat(40):'bc1q'+'b'.repeat(38));
  await f.action('send-request').click();
  await f.frame.waitForFunction(()=>document.querySelector('main').dataset.state!=='request-extension',null,{timeout:3000});
}
async function consumed(f,kind,oldHost=false) {
  await f.state('request-consumed');
  assert.equal(await f.action('send-request').count(),0,'a consumed request cannot offer a dead retry');
  assert.equal(await f.top.evaluate(()=>testState.requests[0]?.status),'approved');
  assert.equal(await f.top.evaluate(()=>testState.receipts.length),0);
  await f.top.evaluate(()=>testState.walletAddress=testState.address);
  const result=await f.frame.evaluate(({kind,oldHost})=>new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>{removeEventListener('message',receive);reject(Error('one-use reply timeout'));},3000);
    function receive(event){if(event.source===window.top&&event.origin==='https://extensions.test'&&event.data?.requestId==='one-use:retry'){clearTimeout(timer);removeEventListener('message',receive);resolve(event.data);}}
    addEventListener('message',receive);
    window.top.postMessage({type:'home:wallet-connector-effect',schema:'elastos.home.wallet-connector-effect/v1',requestId:'one-use:retry',connectorId:'wallet-'+kind,connectorToken:'fixture-token',action:{kind:'approve',approvalRequestId:'approval-1',...(!oldHost&&kind==='metamask'?{linkedAddress:'0x'+'1'.repeat(40)}:{})}},'https://extensions.test');
  }),{kind,oldHost});
  assert.match(result.error,/not found|not pending/);
  const record=await f.top.evaluate(()=>({status:testState.requests[0].status,receipts:testState.receipts.length,calls:testState.calls}));
  assert.equal(record.status,'approved');assert.equal(record.receipts,0);
  assert.equal(record.calls.filter(c=>['personal_sign','signMessage','eth_sendTransaction'].includes(c.method)).length,0);
}
for(const engine of ['chromium','webkit'])for(const kind of ['metamask','unisat'])test(`${engine} ${kind}: pinned Home one-use handoff is not a retryable pending request`,{timeout:30000,skip:windowTestOptions(engine).skip},async t=>{
  const browser=await playwright[engine].launch({headless:true});
  try{
    const oldAction = source => source.replace(", ...(kind === 'metamask' ? {linkedAddress:selected.address} : {})", '');
    for(const oldHost of [true,false]) {
      const good=await fixture(browser,kind,{saved:true,requests:true,oldHost,mutate:oldHost?oldAction:undefined});try{await refuse(good,kind);await consumed(good,kind,oldHost);}finally{await good.close();}
      const bad=await fixture(browser,kind,{saved:true,requests:true,oldHost,pictures:false,mutate:oldHost?oldAction:undefined});try{
        await bad.top.evaluate(()=>{const send=runtimeFetch;window.runtimeFetch=async(url,init)=>{const result=await send(url,init);if(url.endsWith('/handoff'))testState.requests[0].status='pending';return result;};});
        await refuse(bad,kind);
        await assert.rejects(consumed(bad,kind,oldHost),error=>error.code==='ERR_ASSERTION'&&/approved/.test(error.message),'the former reusable-handoff model must fail the primary status oracle');
        t.diagnostic(`${oldHost?'pinned':'current'} Home: consumed cause retained; broken pending model fails the primary status oracle`);
      }finally{await bad.close();}
    }
  }finally{await browser.close();}
});

async function failedRead(f,kind,failure=503) {
  await f.state('request-waiting');
  const fail=route=>route.fulfill(failure===503?{status:503,json:{error:'fixture read error'}}:{json:{available:false,approval_requests:[]}});
  await f.context.route('**/approvals',fail);
  await refuse(f,kind);await f.state('request-consumed');
  const text=await f.frame.locator('body').innerText();
  await f.top.evaluate(()=>{testState.walletAddress=testState.address;emitWallet('accountsChanged',[testState.address]);});
  await f.frame.evaluate(()=>dispatchEvent(new Event('focus')));
  await f.state('request-consumed');assert.equal(await f.action('send-request').count(),0);
  assert.equal(await f.frame.locator('body').innerText(),text);
  await f.context.unroute('**/approvals',fail);await f.frame.evaluate(()=>dispatchEvent(new Event('focus')));
  await f.state('request-consumed');
  assert.equal(await f.top.evaluate(()=>testState.effects.length),1,'reads never repeat the consumed effect');
}
for(const engine of ['chromium','webkit'])for(const kind of ['metamask','unisat'])test(`${engine} ${kind}: failed reads and wallet events retain the consumed cause`,{timeout:30000,skip:windowTestOptions(engine).skip},async()=>{
  const browser=await playwright[engine].launch({headless:true});try{
    for(const failure of [503,200]) {
      const good=await fixture(browser,kind,{saved:true,requests:true});try{await failedRead(good,kind,failure);}finally{await good.close();}
    }
  }finally{await browser.close();}
});

for(const engine of ['chromium','webkit'])for(const kind of ['metamask','unisat'])test(`${engine} ${kind}: refusal is final before the pending-list answer and keeps its instructions`,{timeout:30000,skip:windowTestOptions(engine).skip},async()=>{
  const browser=await playwright[engine].launch({headless:true});try{
    for(const fault of ['account','network']) {
      const transaction=kind==='metamask';
      const f=await fixture(browser,kind,{saved:true,requests:transaction?'transaction':true});
      let release,readFinished;
      const finished=new Promise(resolve=>readFinished=resolve);
      try {
        await f.state(transaction?'transaction-waiting':'request-waiting');
        const gate=new Promise(resolve=>release=resolve);
        await f.context.route('**/approvals',async route=>{await gate;await route.fulfill({json:{approval_requests:[]}});readFinished();});
        await f.top.evaluate(({kind,fault})=>{
          if(fault==='account')testState.accountDuringHandoff=kind==='metamask'?'0x'+'2'.repeat(40):'bc1q'+'b'.repeat(38);
          else if(kind==='metamask')testState.refuseSwitch=true;
          else testState.network='testnet';
        },{kind,fault});
        await f.action('send-request').click();await f.state('request-consumed');
        const text=await f.frame.locator('body').innerText();
        assert.match(text,/This request can no longer be sent/);assert.match(text,/and (?:start|make) a new request/);assert.doesNotMatch(text,/try again|unknown/i);
        assert.equal(await f.action('send-request').count(),0);
        assert.equal(await f.top.evaluate(()=>testState.requests[0].status),'approved');
        await f.top.evaluate(()=>testState.walletAddress=testState.address);
        const beforeRead=await f.frame.evaluate(()=>window.__windowReadsFinished||0);release();await finished;await f.frame.waitForFunction(before=>(window.__windowReadsFinished||0)>before,beforeRead);await f.state('request-consumed');
        await f.top.evaluate(()=>emitWallet('accountsChanged',[testState.address]));
        await f.state('request-consumed');
        assert.equal(await f.frame.locator('body').innerText(),text);
        assert.equal(await f.top.evaluate(()=>testState.receipts.length),0);
      }finally{release?.();await f.close();}
    }
  }finally{await browser.close();}
});
