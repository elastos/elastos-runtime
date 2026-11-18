import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { requireProductSmokePlaywright } from './product-smoke-browser.mjs';
import { fixture as baseFixture } from './lib/wallet-extension-window-fixture.mjs';
const breaks = {
  K17:s=>s.replace('const root = renderConnection(document, view);',"const root = renderConnection(document, view); root.append(document.createElement('button'));"),
  K02:s=>s.replace('approvalRequestId: selected.id })','approvalRequestId: requests[0].request_id })'),
  K07:s=>s.replace('data.value.length > 8','data.value.length > 800'),
  K12:s=>s.replace('const sameFact = lastView?.stage === view.stage && lastView?.request?.id === view.request?.id;','const sameFact = false;'),
  K14:s=>s.replace("event.source !== window.top || event.origin !== homeOrigin || data?.type !== 'home:wallet-connector-event'","data?.type !== 'home:wallet-connector-event'"),
  B1:s=>s.replace("if (preflightFailure) { stage = preflightFailure; draw(); return; }",''),
  saved:s=>s.replace('const rows = address ? row ? [row] : [] : candidates;', 'const rows = address ? row ? [row] : [] : [];'),
  read:s=>s.replace("action === 'connect' && readFailed","false"),
  disconnect:s=>s.replace('if (data.value.length) disconnected = false;',''),
  'read-event':s=>s.replace('stage = chooseStage(); readFailed = false;', 'stage = chooseStage();'),
  removed:s=>s.replace("if (selected.status === 'pending') { stage = 'request-unavailable'; fixedOutcome = true; }","if (stage === 'request-waiting') { stage = 'request-unavailable'; fixedOutcome = true; }"),
  network:s=>s.replace('if (selected && requestNetworks.has(selected.id)) return [networkName(requestNetworks.get(selected.id))];',''),
};
const fixture = (browser,kind,options={}) => baseFixture(browser,kind,{...options,mutate:process.env.EXTENSION_WINDOW_BREAK ? source=>{
  const mutate=breaks[process.env.EXTENSION_WINDOW_BREAK];assert(mutate,'known break');const broken=mutate(source);assert.notEqual(broken,source,'break applies');return broken;
}:options.mutate});
const playwright = requireProductSmokePlaywright();
const engineSkip = engine => engine === 'webkit' && !existsSync(playwright.webkit.executablePath()) ? 'WebKit input is required for the explicit Mac acceptance run.' : false;
const other = kind => kind === 'metamask' ? '0x'+'2'.repeat(40) : 'bc1q'+'b'.repeat(38);

async function preflight(f, kind, fault, type) {
  await f.state(type === 'transaction' ? 'transaction-waiting' : type === 'typed' ? 'request-typed-data' : 'request-waiting');
  await f.top.evaluate(({fault,other}) => {
    if(fault==='account')testState.walletAddress=other;
    if(fault==='network')testState.network='testnet';
    if(fault==='switch')testState.refuseSwitch=true;
  }, {fault,other:other(kind)});
  await f.action('send-request').click();
  await f.state(fault === 'account' ? 'request-unsendable' : kind === 'unisat' ? 'request-network-testnet' : 'request-network-declined');
  const text=await f.frame.locator('body').innerText();
  assert.match(text, fault==='account' ? /account this request needs/ : kind==='unisat' ? /Bitcoin mainnet/ : /network/);
  assert.doesNotMatch(text,/result unknown|return to|Start a new request/i);
  if(kind==='unisat' && fault==='account') assert.doesNotMatch(text,/Connect wallet/);
  await f.assertShared();
  const first=await f.top.evaluate(()=>({receipts:testState.receipts,requests:testState.requests,calls:testState.calls}));
  assert.equal(first.receipts.length,0);
  assert.equal(first.requests.length,1,'Runtime request remains pending');
  assert.equal(first.requests[0].status,'pending');
  assert.equal(first.calls.filter(c=>['personal_sign','eth_signTypedData_v4','signMessage','eth_sendTransaction'].includes(c.method)).length,0,'Home refused before signing');
  assert.equal(await f.action('send-request').count(),1,'same Send stays available without an event');
  assert.equal(await f.action('connect').count(),0,'a pending approval never starts a new ownership proof');
  await f.top.evaluate(()=>{testState.walletAddress=testState.address;testState.network='livenet';testState.refuseSwitch=false;});
  await f.action('send-request').click();
  await f.state(type==='transaction'?'transaction-done':'request-done');
  const final=await f.top.evaluate(()=>({receipts:testState.receipts,requests:testState.requests,effects:testState.effects,calls:testState.calls}));
  assert.equal(final.receipts.length,1);assert.equal(final.requests.length,0);
  assert.deepEqual(final.effects.map(e=>e.action),Array(2).fill({kind:'approve',approvalRequestId:'approval-1'}));
  assert.equal(final.calls.filter(c=>['personal_sign','eth_signTypedData_v4','signMessage','eth_sendTransaction'].includes(c.method)).length,1,'signed or sent once');
}

async function keepSecondCopy(f,kind) {
      await f.state('linked');await f.action('copy-address').nth(1).focus();
      const key=await f.frame.evaluate(()=>document.activeElement.dataset.focusKey);
      await f.context.route('**/accounts',route=>route.fulfill({json:{accounts:[{address:kind==='metamask'?'0x'+'1'.repeat(40):'bc1q'+'a'.repeat(38),connector_id:'wallet-'+kind,chain_namespace:kind==='metamask'?'eip155:20':'bip122:000000000019d6689c085ae165831e93'},{address:other(kind),connector_id:'wallet-'+kind,chain_namespace:kind==='metamask'?'eip155:20':'bip122:000000000019d6689c085ae165831e93'},{address:kind==='metamask'?'0x'+'3'.repeat(40):'bc1q'+'c'.repeat(38),connector_id:'wallet-'+kind,chain_namespace:kind==='metamask'?'eip155:20':'bip122:000000000019d6689c085ae165831e93'}]}}));
      await f.frame.evaluate(()=>dispatchEvent(new Event('focus')));
      await f.frame.waitForFunction(()=>{if(document.querySelectorAll('[data-action="copy-address"]').length===3)return true;dispatchEvent(new Event('focus'));return false;},null,{timeout:3000});
      assert.equal(await f.frame.evaluate(()=>document.activeElement.dataset.focusKey),key);
}

for(const engine of ['chromium','webkit'])for(const kind of ['metamask','unisat']) {
  for(const [type,fault] of (kind==='metamask' ? [[true,'account'],['typed','account'],['transaction','account'],['transaction','switch']] : [[true,'account'],[true,'network']])) {
    test(`${engine} ${kind}: first Send ${type}/${fault} recovers in the same pending request`,{timeout:20000,skip:engineSkip(engine)},async()=>{
      const browser=await playwright[engine].launch({headless:true});
      try { const f=await fixture(browser,kind,{saved:true,requests:type});try{await preflight(f,kind,fault,type);}finally{await f.close();} }finally{await browser.close();}
    });
  }
  test(`${engine} ${kind}: saved Home accounts have Copy without a new signature`,{skip:engineSkip(engine)},async()=>{
    const browser=await playwright[engine].launch({headless:true});
    try{const f=await fixture(browser,kind,{saved:true,extraHomeAccount:true});try{
      await f.state('linked');await f.assertShared();assert.equal(await f.action('copy-address').count(),2);
      await f.action('copy-address').first().click();await f.top.waitForFunction(()=>testState.copies.length===1);
      assert.equal(await f.top.evaluate(()=>testState.effects.length),0);
      assert.equal(await f.top.evaluate(()=>testState.receipts.length),0);
    }finally{await f.close();}}finally{await browser.close();}
  });
  test(`${engine} ${kind}: Try again after a Home read repeats only the read`,{skip:engineSkip(engine)},async()=>{
    const browser=await playwright[engine].launch({headless:true});
    try{const f=await fixture(browser,kind,{readFailure:503});try{
      await f.state('link-error');const before=f.reads.length;
      let retries=0;await f.context.route('**/api/**',route=>{retries++;return route.fulfill({json:route.request().url().endsWith('/accounts')?{accounts:[]}:{approval_requests:[]}});});
      await f.action('connect').click();await f.state('ready');
      assert.equal(retries,2);assert.equal(f.reads.length,before);assert.equal(await f.top.evaluate(()=>testState.effects.length),0);assert.equal(await f.top.evaluate(()=>testState.calls.length),0);
    }finally{await f.close();}}finally{await browser.close();}
  });
  test(`${engine} ${kind}: same account returning clears disconnect without a proof`,{skip:engineSkip(engine)},async()=>{
    const browser=await playwright[engine].launch({headless:true});
    try{const f=await fixture(browser,kind);try{
      await f.action('connect').click();await f.state('linked');
      await f.top.evaluate(()=>emitWallet('disconnect',{}));await f.state('account-unavailable');
      await f.top.evaluate(()=>emitWallet('accountsChanged',[testState.address]));await f.state('linked');
      assert.equal(await f.top.evaluate(()=>testState.receipts.length),1);
    }finally{await f.close();}}finally{await browser.close();}
  });
  test(`${engine} ${kind}: account changes during linking can be retried`,{skip:engineSkip(engine)},async()=>{
    const browser=await playwright[engine].launch({headless:true});
    try{const f=await fixture(browser,kind);try{
      await f.top.evaluate(value=>testState.accountDuringChallenge=value,other(kind));
      await f.action('connect').click();await f.state('account-unavailable');
      assert.equal(await f.top.evaluate(()=>testState.receipts.length),0);
      await f.top.evaluate(()=>{testState.accountDuringChallenge=null;testState.walletAddress=testState.address;});
      await f.action('connect').click();await f.state('linked');assert.equal(await f.top.evaluate(()=>testState.receipts.length),1);
    }finally{await f.close();}}finally{await browser.close();}
  });
  test(`${engine} ${kind}: foreign frames and oversized window events are ignored`,{skip:engineSkip(engine)},async()=>{
    const browser=await playwright[engine].launch({headless:true});
    try{const f=await fixture(browser,kind);try{
      await f.action('connect').click();await f.state('linked');
      for(const value of [Array(9).fill(other(kind)),['<script>']]) {
        await f.top.evaluate(({kind,value})=>document.querySelector('iframe').contentWindow.postMessage({type:'home:wallet-connector-event',connectorId:'wallet-'+kind,event:'accountsChanged',value},'*'),{kind,value});
        await f.frame.evaluate(()=>new Promise(resolve=>setTimeout(resolve,30)));await f.state('linked');
      }
      await f.top.evaluate(kind=>{
        const sibling=document.createElement('iframe');document.body.append(sibling);
        sibling.contentWindow.eval(`parent.document.querySelector('iframe').contentWindow.postMessage(${JSON.stringify({type:'home:wallet-connector-event',connectorId:'wallet-'+kind,event:'accountsChanged',value:[]})},'*')`);
      },kind);
      await f.frame.evaluate(()=>new Promise(resolve=>setTimeout(resolve,30)));await f.state('linked');
      assert.equal(await f.action('copy-address').count(),1);
    }finally{await f.close();}}finally{await browser.close();}
  });
  test(`${engine} ${kind}: selecting second pending request sends that request`,{skip:engineSkip(engine)},async()=>{
    const browser=await playwright[engine].launch({headless:true});
    try{const f=await fixture(browser,kind,{saved:true,requests:'multiple'});try{
      await f.state('request-list');await f.frame.locator('[data-focus-key="select-request:approval-2"]').click();await f.state('request-multiple');
      await f.action('send-request').click();await f.state('request-next');
      assert.equal(await f.top.evaluate(()=>testState.effects[0].action.approvalRequestId),'approval-2');
      assert.deepEqual(await f.top.evaluate(()=>testState.requests.map(r=>r.request_id)),['approval-1']);
    }finally{await f.close();}}finally{await browser.close();}
  });
  test(`${engine} ${kind}: changed markup keeps the focused Copy control`,{skip:engineSkip(engine)},async()=>{
    const browser=await playwright[engine].launch({headless:true});
    try{const f=await fixture(browser,kind,{saved:true,extraHomeAccount:true});try{
      await keepSecondCopy(f,kind);
    }finally{await f.close();}}finally{await browser.close();}
  });
}
for(const engine of ['chromium','webkit'])test(`${engine} UniSat: wrong network while linking names Bitcoin mainnet and retries`,{skip:engineSkip(engine)},async()=>{
  const browser=await playwright[engine].launch({headless:true});try{const f=await fixture(browser,'unisat');try{
    await f.top.evaluate(()=>testState.network='testnet');await f.action('connect').click();await f.state('network-changed');
    assert.match(await f.frame.locator('body').innerText(),/Bitcoin mainnet/);assert.equal(await f.top.evaluate(()=>testState.receipts.length),0);
    await f.top.evaluate(()=>testState.network='livenet');await f.action('connect').click();await f.state('linked');assert.equal(await f.top.evaluate(()=>testState.receipts.length),1);
  }finally{await f.close();}}finally{await browser.close();}
});
for(const engine of ['chromium','webkit'])test(`${engine} MetaMask: signer shows request network before and after wallet event`,{skip:engineSkip(engine)},async()=>{
  const browser=await playwright[engine].launch({headless:true});try{const f=await fixture(browser,'metamask',{saved:true,requests:'transaction'});try{
    await f.state('transaction-waiting');assert.match(await f.frame.locator('.connection-request-account').innerText(),/Elastos Smart Chain/);
    await f.top.evaluate(()=>testState.refuseSwitch=true);await f.action('send-request').click();await f.state('request-network-declined');
    await f.top.evaluate(()=>emitWallet('chainChanged','0x1'));
    assert.match(await f.frame.locator('.connection-request-account').innerText(),/Elastos Smart Chain/);
  }finally{await f.close();}}finally{await browser.close();}
});

for(const engine of ['chromium','webkit'])test(`${engine} UniSat: preflight recovery cannot hide expiry`,{skip:engineSkip(engine)},async()=>{
  const browser=await playwright[engine].launch({headless:true});try{const f=await fixture(browser,'unisat',{saved:true,requests:true});try{
    await f.top.evaluate(()=>testState.network='testnet');await f.action('send-request').click();await f.state('request-network-testnet');
    await f.top.clock.runFor(301000);await f.state('request-expired');assert.match(await f.frame.locator('body').innerText(),/This request expired/);
    assert.equal(await f.action('send-request').count(),0);assert.equal(await f.top.evaluate(()=>testState.receipts.length),0);
  }finally{await f.close();}}finally{await browser.close();}
});

async function delivered(f, run) {
  await f.frame.evaluate(()=>{window.fixEventSeen=false;addEventListener('message',function watch(e){if(e.data?.type==='home:wallet-connector-event'){window.fixEventSeen=true;removeEventListener('message',watch);}});});
  await run();await f.frame.waitForFunction(()=>fixEventSeen);
}
async function rejectBadEvent(f,kind,foreign) {
  await f.action('connect').click();await f.state('linked');
  await delivered(f,()=>f.top.evaluate(({kind,foreign,value})=>{
    const packet={type:'home:wallet-connector-event',connectorId:'wallet-'+kind,event:'accountsChanged',value};
    if(!foreign)document.querySelector('iframe').contentWindow.postMessage(packet,'*');
    else {const sibling=document.createElement('iframe');document.body.append(sibling);sibling.contentWindow.eval(`parent.document.querySelector('iframe').contentWindow.postMessage(${JSON.stringify(packet)},'*')`);}
  },{kind,foreign,value:foreign?[]:Array(9).fill(other(kind))}));
  assert.equal(await f.frame.locator('main').getAttribute('data-state'),'linked');
}
async function disappeared(f,kind) {
  await f.top.evaluate(value=>testState.walletAddress=value,other(kind));await f.action('send-request').click();await f.state('request-unsendable');
  await f.top.evaluate(()=>testState.requests=[]);await f.frame.evaluate(()=>dispatchEvent(new Event('focus')));await f.state('request-unavailable');
  assert.equal(await f.action('send-request').count(),0);
}
for(const engine of ['chromium','webkit'])for(const kind of ['metamask','unisat'])test(`${engine} ${kind}: suite catches escaped review breaks and fix regressions`,{timeout:180000,skip:engineSkip(engine)},async t=>{
  const browser=await playwright[engine].launch({headless:true});
  try {
    const cases=[
      ['K02',{saved:true,requests:'multiple'},async f=>{await f.state('request-list');await f.frame.locator('[data-focus-key="select-request:approval-2"]').click();await f.action('send-request').click();await f.top.waitForFunction(()=>testState.receipts.length===1);assert.equal(await f.top.evaluate(()=>testState.effects[0].action.approvalRequestId),'approval-2');}],
      ['K07',{},f=>rejectBadEvent(f,kind,false)],
      ['K14',{},f=>rejectBadEvent(f,kind,true)],
      ['K12',{saved:true,extraHomeAccount:true},f=>keepSecondCopy(f,kind)],
      ['K17',{saved:true},async f=>{await f.state('linked');await f.assertShared();}],
      ['B1',{saved:true,requests:true},f=>preflight(f,kind,'account',true)],
      ['saved',{saved:true},async f=>{await f.state('linked');assert.equal(await f.action('copy-address').count(),1);}],
      ['disconnect',{},async f=>{await f.action('connect').click();await f.state('linked');await f.top.evaluate(()=>emitWallet('disconnect',{}));await f.state('account-unavailable');await f.top.evaluate(()=>emitWallet('accountsChanged',[testState.address]));await f.state('linked');}],
      ['read',{readFailure:503},async f=>{await f.state('link-error');let n=0;await f.context.route('**/api/**',r=>{n++;return r.fulfill({json:r.request().url().endsWith('/accounts')?{accounts:[]}:{approval_requests:[]}});});await f.action('connect').click();await f.state('ready');assert.equal(n,2);assert.equal(await f.top.evaluate(()=>testState.effects.length),0);}],
      ['removed',{saved:true,requests:true},f=>disappeared(f,kind)],
      ['read-event',{},async f=>{
        await f.action('connect').click();await f.state('linked');
        await f.context.route('**/api/**',r=>r.fulfill({status:503,json:{error:'fixture read error'}}));
        await f.frame.evaluate(()=>dispatchEvent(new Event('focus')));await f.state('link-error');
        await delivered(f,()=>f.top.evaluate(value=>emitWallet('accountsChanged',[value]),other(kind)));await f.state('account-unavailable');
        await f.top.evaluate(()=>testState.mode='pending');await f.action('connect').click();
        await f.top.waitForFunction(()=>testState.effects.length===2,null,{timeout:1000});assert.equal(await f.top.evaluate(()=>testState.effects[1].action.kind),'link');
      }],
      ...(kind==='metamask'?[['network',{saved:true,requests:'transaction'},async f=>{await f.state('transaction-waiting');assert.match(await f.frame.locator('.connection-request-account').innerText(),/Elastos Smart Chain/);}]]:[]),
    ];
    for(const [id,options,oracle] of cases) {
      const good=await baseFixture(browser,kind,options);try{await oracle(good);}finally{await good.close();}
      const bad=await baseFixture(browser,kind,{...options,mutate:source=>{const broken=breaks[id](source);assert.notEqual(broken,source,id+' applies');return broken;}});
      try {await assert.rejects(oracle(bad),e=>e.code==='ERR_ASSERTION'||/(?:locator.waitFor|page.waitForFunction): Timeout/.test(e.message),id+' must fail its live oracle');}finally{await bad.close();}
      t.diagnostic(id+': clean oracle passed; deliberate break failed');
    }
  }finally{await browser.close();}
});
