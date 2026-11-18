import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { requireProductSmokePlaywright } from './product-smoke-browser.mjs';
import { fixture as baseFixture } from './lib/wallet-extension-window-fixture.mjs';
const breaks = {
  K17:s=>s.replace('const root = presentation.root;',"const root = presentation.root; root.append(document.createElement('button'));"),
  K02:s=>s.replace('approvalRequestId: selected.id })','approvalRequestId: requests[0].request_id })'),
  K07:s=>s.replace('data.value.length > 8','data.value.length > 800'),
  K12:s=>s.replace('mountConnection(mount, view, presentation)', 'mountConnection(mount, view, null)'),
  K14:s=>s.replace("event.source !== window.top || event.origin !== homeOrigin || data?.type !== 'home:wallet-connector-event'","data?.type !== 'home:wallet-connector-event'"),
  B1:s=>s.replace("[wallet[0].toUpperCase()+wallet.slice(1), ` was using a different ${refusal.cause}. This request needed ${refusal.cause} `, {value:needed}, '.']", "['This request is unavailable.']"),
  X1:s=>s.replace("root.dataset.extensionFeedback = 'consumed';", "root.dataset.extensionFeedback = 'consumed'; root.querySelector('.connection-actions').append(renderConnection(document, connectionView({window:kind,stage:'request-waiting',summary:selected,account:accountView(),waitSeconds:remaining(),supportedActions:['send-request']})).querySelector('button'));"),
  X2:s=>s.replace("if (!next) { draw(); return; }", "if (!next) { refusal = null; stage = 'request-unavailable'; draw(); return; }"),
  X3:s=>s.replace("'Switch to the linked account before approving.', ", ""),
  saved:s=>s.replace('const rows = address ? row ? [row] : [] : candidates;', 'const rows = address ? row ? [row] : [] : [];'),
  read:s=>s.replace("action === 'refresh-status') void refresh()","action === 'refresh-status') void perform({kind:'link'})"),
  disconnect:s=>s.replace('if (data.value.length) disconnected = false;',''),
  'link-request':s=>s.replace('if (next?.id !== selected?.id) preflightFailure = null;',''),
  'read-event':s=>s.replace('stage = chooseStage(); }', "stage = 'wallet-unavailable'; }"),
  removed:s=>s.replace("if (selected.status === 'pending') { stage = 'request-unavailable'; fixedOutcome = true; }","if (stage === 'request-waiting') { stage = 'request-unavailable'; fixedOutcome = true; }"),
  network:s=>s.replace('if (selected && requestNetworks.has(selected.id)) return [networkName(requestNetworks.get(selected.id))];',''),
};
const fixture = (browser,kind,options={}) => baseFixture(browser,kind,{...options,mutate:process.env.EXTENSION_WINDOW_BREAK ? source=>{
  const mutate=breaks[process.env.EXTENSION_WINDOW_BREAK];assert(mutate,'known break');const broken=mutate(source);assert.notEqual(broken,source,'break applies');return broken;
}:options.mutate});
const playwright = requireProductSmokePlaywright();
const engineSkip = engine => engine === 'webkit' && !existsSync(playwright.webkit.executablePath()) ? 'WebKit input is required for the explicit Mac acceptance run.' : false;
const other = kind => kind === 'metamask' ? '0x'+'2'.repeat(40) : 'bc1q'+'b'.repeat(38);

async function assertReadAfter(f,before) {
  for(let i=0;i<100&&f.completedReads.length<before+2;i++) {
    await f.frame.evaluate(()=>dispatchEvent(new Event('focus')));
    await new Promise(resolve=>setTimeout(resolve,10));
  }
  assert(f.completedReads.length>=before+2,'both Home reads must finish');
  await f.frame.evaluate(()=>new Promise(resolve=>queueMicrotask(resolve)));
}

async function preflight(f, kind, fault, type) {
  await f.state(type === 'transaction' ? 'transaction-waiting' : type === 'typed' ? 'request-typed-data' : 'request-waiting');
  await f.top.evaluate(({fault,other}) => {
    if(fault==='account')testState.walletAddress=other;
    if(fault==='network')testState.network='testnet';
    if(fault==='switch')testState.refuseSwitch=true;
  }, {fault,other:other(kind)});
  await f.action('send-request').click();
  await f.state('request-consumed');
  const text=await f.frame.locator('body').innerText();
  assert.match(text, /was using a different/);
  assert.match(text, fault==='account' ? new RegExp('account '+(kind==='metamask'?'0x'+'1'.repeat(40):'bc1q'+'a'.repeat(38))) : kind==='unisat' ? /Bitcoin/ : /Elastos Smart Chain/);
  assert.match(text,/This request can no longer be sent/);
  assert.match(text,/After switching, return to .* and make a new request/);
  assert.doesNotMatch(text,/try again|result unknown/i);
  assert.equal(await f.action('send-request').count(),0);
  assert.equal(await f.action('connect').count(),0);
  await f.assertShared();
  const first=await f.top.evaluate(()=>({receipts:testState.receipts,requests:testState.requests,calls:testState.calls}));
  assert.equal(first.receipts.length,0);
  assert.equal(first.requests[0].status,'approved');
  assert.equal(first.calls.filter(c=>['personal_sign','eth_signTypedData_v4','signMessage','eth_sendTransaction'].includes(c.method)).length,0,'Home refused before signing');
  await f.top.evaluate(()=>{testState.walletAddress=testState.address;testState.network='livenet';testState.refuseSwitch=false;});
  const beforeRead=f.completedReads.length;
  await f.frame.evaluate(()=>dispatchEvent(new Event('focus')));
  await assertReadAfter(f,beforeRead);
  await f.state('request-consumed');
  assert.equal(await f.frame.locator('body').innerText(),text,'the cause stays after the wallet correction and a completed read');
  await f.top.evaluate(kind=>emitWallet(kind==='unisat'?'networkChanged':'chainChanged',kind==='unisat'?'livenet':'0x14'),kind);
  await f.top.clock.runFor(301000);await f.state('request-consumed');
  assert.equal(await f.frame.locator('body').innerText(),text,'expiry and wallet events keep the refusal');
  await f.top.evaluate(()=>{testState.requests.push({...testState.requests[0],request_id:'approval-new',status:'pending',expires_at:Math.floor(Date.now()/1000)+300});});
  await f.frame.evaluate(()=>dispatchEvent(new Event('focus')));
  await f.state(type==='transaction'?'transaction-waiting':type==='typed'?'request-typed-data':'request-waiting');
  await f.action('send-request').click();await f.state(type==='transaction'?'transaction-done':'request-done');
  assert.equal(await f.top.evaluate(()=>testState.receipts.length),1,'new request signs once after correction');
  assert.equal(await f.top.evaluate(()=>testState.calls.filter(c=>['personal_sign','eth_signTypedData_v4','signMessage','eth_sendTransaction'].includes(c.method)).length),1);

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
    test(`${engine} ${kind}: first Send ${type}/${fault} retains the consumed cause and accepts a new request`,{timeout:20000,skip:engineSkip(engine)},async()=>{
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
      await f.state('wallet-unavailable');const before=f.reads.length;
      let retries=0;await f.context.route('**/api/**',route=>{retries++;return route.fulfill({json:route.request().url().endsWith('/accounts')?{accounts:[]}:{approval_requests:[]}});});
      await f.action('refresh-status').click();await f.state('ready');
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
    await f.top.evaluate(()=>testState.refuseSwitch=true);await f.action('send-request').click();await f.state('request-consumed');
    await f.top.evaluate(()=>emitWallet('chainChanged','0x1'));
    assert.match(await f.frame.locator('.connection-request-account').innerText(),/Elastos Smart Chain/);
  }finally{await f.close();}}finally{await browser.close();}
});

for(const engine of ['chromium','webkit'])test(`${engine} UniSat: consumed refusal survives expiry`,{skip:engineSkip(engine)},async()=>{
  const browser=await playwright[engine].launch({headless:true});try{const f=await fixture(browser,'unisat',{saved:true,requests:true});try{
    await f.top.evaluate(()=>testState.network='testnet');await f.action('send-request').click();await f.state('request-consumed');
    await f.top.clock.runFor(301000);await f.state('request-consumed');assert.match(await f.frame.locator('body').innerText(),/This request can no longer be sent/);
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
      ['X1',{saved:true,requests:true},f=>preflight(f,kind,'account',true)],
      ['X2',{saved:true,requests:true},f=>preflight(f,kind,'account',true)],
      ...(kind==='metamask'?[['X3',{saved:true,requests:true},f=>preflight(f,kind,'account',true)]]:[]),
      ['saved',{saved:true},async f=>{await f.state('linked');assert.equal(await f.action('copy-address').count(),1);}],
      ['disconnect',{},async f=>{await f.action('connect').click();await f.state('linked');await f.top.evaluate(()=>emitWallet('disconnect',{}));await f.state('account-unavailable');await f.top.evaluate(()=>emitWallet('accountsChanged',[testState.address]));await f.state('linked');}],
      ['read',{readFailure:503},async f=>{await f.state('wallet-unavailable');let n=0;await f.context.route('**/api/**',r=>{n++;return r.fulfill({json:r.request().url().endsWith('/accounts')?{accounts:[]}:{approval_requests:[]}});});await f.action('refresh-status').click();await f.state('ready');assert.equal(n,2);assert.equal(await f.top.evaluate(()=>testState.effects.length),0);}],

      ['link-request',{},async f=>{
        await f.top.evaluate(value=>testState.accountDuringChallenge=value,other(kind));
        await f.action('connect').click();await f.state('account-unavailable');
        await f.top.evaluate(kind=>{
          testState.accountDuringChallenge=null;testState.walletAddress=testState.address;testState.linked=true;
          testState.requests=[{request_id:'arrived',capsule_id:'browser',connector_id:'wallet-'+kind,intent:kind==='metamask'?'browser_personal_sign':'bitcoin_bip322_proof',proof_type:kind==='metamask'?'siwe':'bip322_simple',address:testState.address,chain_namespace:kind==='metamask'?'eip155:1':'bip122:000000000019d6689c085ae165831e93',status:'pending',reason:'Arrived after link failure',expires_at:Math.floor(Date.now()/1000)+300}];
        },kind);
        await f.frame.evaluate(()=>dispatchEvent(new Event('focus')));await f.state('request-waiting');
        await f.action('send-request').click();await f.state('request-done');assert.equal(await f.top.evaluate(()=>testState.receipts.length),1);
        assert.deepEqual(await f.top.evaluate(()=>testState.effects.map(e=>e.action.kind)),['link','approve']);
      }],
      ['read-event',{},async f=>{
        await f.action('connect').click();await f.state('linked');
        await f.context.route('**/api/**',r=>r.fulfill({status:503,json:{error:'fixture read error'}}));
        await f.frame.evaluate(()=>dispatchEvent(new Event('focus')));await f.state('wallet-unavailable');
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

for(const engine of ['chromium','webkit'])for(const kind of ['metamask','unisat'])test(`${engine} ${kind}: r5 provider identity, absence and rejected/dismissed summaries`,{timeout:30000,skip:engineSkip(engine)},async()=>{
  const browser=await playwright[engine].launch({headless:true});
  try {
    const f=await fixture(browser,kind,{saved:true,requests:true});try{
      await f.state('request-waiting');await f.action('send-request').click();await f.state('request-done');
      assert.equal(await f.frame.locator('h1').innerText(),kind==='metamask'?'Browser wallet':'UniSat');
      assert.match(await f.frame.locator('.connection-heading img').getAttribute('src'),new RegExp('connection-'+(kind==='metamask'?'wallet':kind)));
      // Existing response schema permits these statuses. This is a projection
      // check: today's pending-only Runtime endpoint normally omits them.
      for(const [status,approved_at,state] of [['rejected',null,'request-rejected'],['rejected',1,'request-dismissed']]) {
        await f.context.route('**/approvals',route=>route.fulfill({json:{approval_requests:[{request_id:'record-'+state,capsule_id:'browser',connector_id:'wallet-'+kind,intent:kind==='metamask'?'browser_personal_sign':'bitcoin_bip322_proof',proof_type:kind==='metamask'?'siwe':'bip322_simple',address:kind==='metamask'?'0x'+'1'.repeat(40):'bc1q'+'a'.repeat(38),chain_namespace:kind==='metamask'?'eip155:1':'bip122:000000000019d6689c085ae165831e93',reason:'Recorded result',status,approved_at,expires_at:1}]}}));
        // Open a fresh window on the existing record; completed local outcomes
        // intentionally do not turn into unrelated rejected records.
        const url=new URL(f.frame.url());url.searchParams.set('record',state);await f.frame.goto(url.href);await f.state(state);
        assert.match(await f.frame.locator('body').innerText(),state==='request-rejected'?/This request was rejected\./:/This request was dismissed\./);
        assert.equal(await f.action('send-request').count(),0);await f.assertShared();
        await f.context.unroute('**/approvals');
      }
    }finally{await f.close();}
  }finally{await browser.close();}
});

for(const engine of ['chromium','webkit'])for(const kind of ['metamask','unisat'])test(`${engine} ${kind}: an already queued request cannot erase the consumed cause`,{timeout:15000,skip:engineSkip(engine)},async()=>{
  const browser=await playwright[engine].launch({headless:true});try{const f=await fixture(browser,kind,{saved:true,requests:'multiple'});try{
    await f.state('request-list');await f.frame.locator('[data-focus-key="select-request:approval-1"]').click();await f.state('request-multiple');
    await f.top.evaluate(value=>testState.walletAddress=value,other(kind));await f.action('send-request').click();await f.state('request-consumed');
    const text=await f.frame.locator('body').innerText();
    await f.frame.evaluate(()=>dispatchEvent(new Event('focus')));await f.state('request-consumed');assert.equal(await f.frame.locator('body').innerText(),text);
    assert.equal(await f.top.evaluate(()=>testState.requests.filter(r=>r.status==='pending').length),1);
  }finally{await f.close();}}finally{await browser.close();}
});
