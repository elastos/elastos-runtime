import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { requireProductSmokePlaywright } from './product-smoke-browser.mjs';
const playwright = requireProductSmokePlaywright();
const engineSkip = engine => engine === 'webkit' && !existsSync(playwright.webkit.executablePath()) ? 'Install WebKit for the explicit acceptance run; behaviour inputs provide Chromium.' : false;
const A = '0x' + '1'.repeat(40), B = '0x' + '2'.repeat(40);
const U = 'bc1q' + 'a'.repeat(38), V = 'bc1q' + 'b'.repeat(38);

import { fixture } from './lib/wallet-extension-window-fixture.mjs';

for (const engine of ['chromium', 'webkit']) for (const kind of ['metamask', 'unisat']) {
  test(`${engine} ${kind}: live shared window links, signs, redraws and returns actual receipts`, { timeout: 50000, skip: engineSkip(engine) }, async () => {
    const browser = await playwright[engine].launch({ headless: true });
    try {
      const f = await fixture(browser, kind);
      try {
        await f.state('ready'); await f.action('connect').click(); await f.state('linked');
        assert.equal(await f.top.evaluate(() => testState.receipts.length), 1);
        await f.action('copy-address').click();
        await f.top.waitForFunction(() => testState.copies.length === 1);
        assert.equal(await f.top.evaluate(() => testState.copies[0]), kind === 'metamask' ? A : U);
        assert.equal(await f.frame.locator('body > :not(#connection-root):not(script)').count(), 0);
        assert.equal(await f.frame.locator('#connection-root > main').count(), 1);
        await f.top.evaluate(() => emitWallet('accountsChanged', []));
        await f.state('account-unavailable');
        await f.action('connect').click(); await f.state('linked');
        assert.equal(await f.top.evaluate(() => testState.receipts.length), 2);
      } finally { await f.close(); }
      const g = await fixture(browser, kind, { saved: true, requests: true });
      try {
        await g.state('request-waiting');
        await g.action('send-request').focus();
        await g.frame.evaluate(() => window.scrollTo(0, 150));
        const position = await g.frame.evaluate(() => ({ key: document.activeElement.dataset.focusKey, y: scrollY }));
        await g.top.clock.runFor(2000);
        assert.deepEqual(await g.frame.evaluate(() => ({ key: document.activeElement.dataset.focusKey, y: scrollY })), position);
        await g.action('send-request').click(); await g.state('request-done');
        assert.equal(await g.top.evaluate(() => testState.receipts.length), 1);
        assert.equal(await g.top.evaluate(() => testState.effects[0].action.kind), 'approve');
        assert.equal(await g.top.evaluate(() => testState.requests.length), 0);
        assert.equal(await g.action('send-request').count(), 0);
        await g.top.evaluate(kind => emitWallet(kind === 'metamask' ? 'chainChanged' : 'networkChanged', kind === 'metamask' ? '0x1' : 'livenet'), kind);
        await g.state('request-done');
        assert.equal(await g.action('send-request').count(), 0, 'a network event cannot revive a consumed request');
      } finally { await g.close(); }
    } finally { await browser.close(); }
  });

  test(`${engine} ${kind}: wallet silence, stop, answer, timeout and account events`, { timeout: 50000, skip: engineSkip(engine) }, async () => {
    const browser = await playwright[engine].launch({ headless: true });
    try {
      const f = await fixture(browser, kind, { saved: true, requests: true });
      try {
        await f.top.evaluate(() => { testState.mode = 'pending'; });
        await f.action('send-request').click(); await f.state('request-extension');
        assert.equal(await f.frame.getByRole('button', { name: 'Cancel', exact: true }).count(), 0);
        await f.action('stop-waiting').click(); await f.state('request-cancelled');
        await f.top.evaluate(() => { const p = testState.pending.shift(); p.resolve(p.result); });
        await f.state('request-done');
        assert.equal(await f.top.evaluate(() => testState.receipts.length), 1);
        await f.top.evaluate(() => emitWallet('accountsChanged', []));
        await f.state('account-unavailable');
        assert.equal(await f.action('send-request').count(), 0);
      } finally { await f.close(); }
      const g = await fixture(browser, kind);
      try {
        await g.top.evaluate(() => { testState.mode = 'pending'; });
        await g.action('connect').click(); await g.state('extension-wait');
        await g.top.clock.runFor(61000); await g.state('extension-timeout');
        assert.equal(await g.frame.getByRole('button', { name: 'Cancel', exact: true }).count(), 0);
        assert.equal(await g.top.evaluate(() => testState.effects.length), 1);
      } finally { await g.close(); }
      const h = await fixture(browser, kind, { saved: true });
      try {
        await h.state('ready');
        assert.equal(await h.frame.locator('.connection-account').count(), 0, 'stored Home data does not prove current extension access');
        await h.action('connect').click(); await h.state('linked');
        await h.action('copy-address').click();
        assert.equal(await h.top.evaluate(() => testState.receipts.length), 1);
        await h.top.evaluate(value => emitWallet('accountsChanged', [value]), kind === 'metamask' ? B : V);
        await h.state('account-unavailable');
        assert.equal(await h.action('connect').count(), 1);
        if (kind === 'unisat') {
          await h.top.evaluate(() => emitWallet('accountsChanged', [testState.address]));
          await h.top.evaluate(() => emitWallet('networkChanged', 'testnet')); await h.state('network-changed');
        }
      } finally { await h.close(); }
    } finally { await browser.close(); }
  });

  test(`${engine} ${kind}: recorded decline, closed prompt, missing extension and stalled provider`, { timeout: 50000, skip: engineSkip(engine) }, async () => {
    const browser = await playwright[engine].launch({ headless: true });
    try {
      for (const [recording, person] of [[`${kind}-connect-declined`, 'declines'], [`${kind}-native-connect-close`, 'closes the prompt']]) {
        const f = await fixture(browser, kind, { recording });
        try {
          await f.action('connect').click(); await f.state('extension-wait');
          await f.top.waitForFunction(() => __walletReplay.requests.length === 1);
          await f.top.clock.runFor(Math.min(60001, Math.ceil(f.peerElapsed)));
          await f.top.evaluate(person => { __walletReplay.person(person); return __walletReplay.advance(200000); }, person);
          await f.state(f.peerElapsed > 60000 ? 'extension-timeout' : 'link-error');
          assert.equal(await f.top.evaluate(() => testState.receipts.length), 0);
        } finally { await f.close(); }
      }
      const missing = await fixture(browser, kind, { recording: 'private-no-extension' });
      try { await missing.action('connect').click(); await missing.state('extension-missing'); } finally { await missing.close(); }
      const silent = await fixture(browser, kind, { recording: kind === 'metamask' ? 'metamask-disabled-stale' : 'unisat-connect-pending' });
      try {
        await silent.action('connect').click(); await silent.state('extension-wait');
        await silent.top.clock.runFor(61000); await silent.state('extension-timeout');
        assert.equal(await silent.top.evaluate(() => __walletReplay.requests.length), 1);
      } finally { await silent.close(); }
    } finally { await browser.close(); }
  });
}

test('both extension packages carry one presenter and existing v1 actions only', async () => {
  const mm = await readFile('capsules/wallet-metamask/browser/extension-window.mjs', 'utf8');
  assert.equal(mm, await readFile('capsules/wallet-unisat/browser/extension-window.mjs', 'utf8'));
  assert.match(mm, /renderConnection\(document, view\)/);
  assert.doesNotMatch(mm, /localStorage|sessionStorage|eth_requestAccounts|eth_sendTransaction|wallet-connector\/.*\/v2|home:open-target/);
});

for (const engine of ['chromium', 'webkit']) for (const kind of ['metamask', 'unisat']) {
  test(`${engine} ${kind}: keyboard, fit, saved link, refusal and request expiry`, { timeout: 50000, skip: engineSkip(engine) }, async () => {
    const browser = await playwright[engine].launch({ headless: true });
    try {
      const f = await fixture(browser, kind, { saved: true, requests: true });
      try {
        await f.state('request-waiting');
        assert.equal(await f.frame.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
        const expected = await f.frame.locator('button:not(:disabled)').evaluateAll(nodes => nodes.map(n => n.dataset.focusKey));
        await f.frame.locator('button').first().focus();
        const visited = new Set();
        for (let i = 0; i < expected.length * 3 + 3; i++) {
          const key = await f.frame.evaluate(() => document.activeElement?.dataset.focusKey);
          if (key) visited.add(key);
          await f.top.keyboard.press('Tab');
        }
        for (const key of expected) assert(visited.has(key), `Tab reaches ${key}`);
        await f.top.evaluate(() => { testState.mode = 'decline'; });
        await f.action('send-request').click(); await f.state('request-wallet-error');
        assert.equal(await f.top.evaluate(() => testState.receipts.length), 0);
      } finally { await f.close(); }
      const g = await fixture(browser, kind, { saved: true, requests: true });
      try {
        await g.state('request-waiting');
        await g.top.clock.runFor(301000); await g.state('request-expired');
        assert.equal(await g.action('send-request').count(), 0);
        assert.equal(await g.top.evaluate(() => testState.effects.length), 0);
      } finally { await g.close(); }
    } finally { await browser.close(); }
  });
}

test('live-window regression oracle rejects five deliberate breaks', { timeout: 50000 }, async () => {
  const browser = await playwright.chromium.launch({ headless: true });
  try {
    const mutations = [
      ['state mapped wrong', s => s.replace("let stage = 'ready'", "let stage = 'link-error'").replace("return accounts.length && linkObserved ? 'linked' : 'ready';", "return accounts.length && linkObserved ? 'linked' : 'link-error';"), async f => {
        // Snapshot the first controller paint before any asynchronous refresh.
        assert.equal(await f.frame.locator('main').getAttribute('data-state'), 'ready');
      }],
      ['control wired wrong', s => s.replace("void perform({ kind: 'approve', approvalRequestId: selected.id })", "void perform({ kind: 'link' })"), async f => {
        await f.action('send-request').click();
        await f.top.waitForFunction(() => testState.effects.length > 0);
        assert.equal(await f.top.evaluate(() => testState.effects[0].action.kind), 'approve');
      }],
      ['Cancel after dispatch', s => s.replace('const markup = root.outerHTML', "for (const b of root.querySelectorAll('[data-action=stop-waiting]')) b.textContent = 'Cancel';\n    const markup = root.outerHTML"), async f => {
        await f.top.evaluate(() => { testState.mode = 'pending'; });
        await f.action('send-request').click(); await f.state('request-extension');
        assert.equal(await f.frame.getByRole('button', { name: 'Cancel', exact: true }).count(), 0);
      }],
      ['stale wait after answer', s => s.replace("stage = result.effect === 'transaction' ? 'transaction-done' : 'request-done';", "stage = result.effect === 'transaction' ? 'transaction-done' : 'request-extension';"), async f => {
        await f.action('send-request').click(); await f.state('request-done');
      }],
      ['draw outside shared view', s => s.replace('const root = renderConnection(document, view);', "const root = renderConnection(document, view); root.append(document.createElement('aside'));"), async f => {
        assert.equal(await f.frame.locator('main aside').count(), 0);
      }],
    ];
    for (const [name, mutate, oracle] of mutations) {
      const source = await readFile('capsules/wallet-metamask/browser/extension-window.mjs', 'utf8');
      assert.notEqual(mutate(source), source, name + ' mutation applies');
      const f = await fixture(browser, 'metamask', { saved: name !== 'state mapped wrong', requests: name !== 'state mapped wrong', mutate });
      try { await assert.rejects(oracle(f), undefined, name + ' must fail the live oracle'); }
      finally { await f.context.close(); }
    }
  } finally { await browser.close(); }
});

for (const kind of ['metamask', 'unisat']) test(`${kind}: actual old Home with new window, actual old window with new Home`, { timeout: 40000 }, async () => {
  const browser = await playwright.chromium.launch({ headless: true });
  try {
    const modern = await fixture(browser, kind, { oldHost: true });
    try { await modern.action('connect').click(); await modern.state('linked'); }
    finally { await modern.close(); }
    const legacy = await fixture(browser, kind, { oldWindow: true });
    try {
      await legacy.frame.locator('#wallet-connect').click();
      await legacy.frame.locator('#wallet-status').filter({hasText:'Approval method added.'}).waitFor();
      await legacy.top.evaluate(value => emitWallet('accountsChanged', [value]), kind === 'metamask' ? B : V);
      assert.equal(await legacy.top.evaluate(() => testState.receipts.length), 1);
      assert.equal(await legacy.frame.locator('#wallet-status').innerText(), 'Approval method added.');
    }finally{await legacy.close();}
  }finally{await browser.close();}
});

for (const kind of ['metamask', 'unisat']) test(`${kind}: a failed Home read is distinct from expired authority`, async () => {
  const browser = await playwright.chromium.launch({ headless: true });
  try {
    for (const [status, state] of [[503, 'link-error'], [403, 'window-expired']]) {
      const f = await fixture(browser, kind, { readFailure: status });
      try { await f.state(state); assert.equal(await f.top.evaluate(() => testState.effects.length), 0); }
      finally { await f.close(); }
    }
  } finally { await browser.close(); }
});

for (const engine of ['chromium', 'webkit']) for (const kind of ['metamask', 'unisat']) test(`${engine} ${kind}: wallet events preserve an active link and an acknowledged result`, { timeout: 50000, skip: engineSkip(engine) }, async () => {
  const browser = await playwright[engine].launch({ headless:true });
  const changed = kind === 'metamask' ? B : V;
  try {
    const f = await fixture(browser, kind, {saved:true});
    try {
      await f.top.evaluate(()=>{testState.mode='pending';});
      await f.action('connect').click(); await f.state('extension-wait');
      await f.top.waitForFunction(()=>testState.pending.length>0);
      await f.top.evaluate(value=>emitWallet('accountsChanged',[value]),changed);
      await f.state('extension-wait');
      assert.equal(await f.action('stop-waiting').count(),1);
      await f.top.evaluate(value=>{testState.mode='approve';testState.address=value;testState.pending.shift().resolve([value]);},changed);
      await f.state('linked');
      assert.equal(await f.top.evaluate(()=>testState.receipts.length),1);
      await f.top.evaluate(()=>emitWallet('disconnect',{code:4900}));
      await f.state('link-error');
      assert.doesNotMatch(await f.frame.locator('body').innerText(),/not sharing/i);
    }finally{await f.close();}
    const g = await fixture(browser,kind,{saved:true,requests:true});
    try {
      await g.top.evaluate(()=>{testState.mode='pending';});
      await g.action('send-request').click();await g.state('request-extension');
      await g.top.waitForFunction(()=>testState.pending.length>0);
      await g.top.evaluate(value=>emitWallet('accountsChanged',[value]),changed);
      await g.state('request-extension');
      assert.equal(await g.action('stop-waiting').count(),1);
      assert.equal(await g.frame.locator('.connection-request-account').count(),0,'changed current account is not shown as the signer');
      await g.top.evaluate(()=>{const pending=testState.pending.shift();pending.resolve(pending.result);});
      await g.state('request-done');
      assert.equal(await g.top.evaluate(()=>testState.receipts.length),1);
      assert.equal(await g.action('send-request').count(),0);
      await g.top.evaluate(()=>emitWallet('disconnect',{}));await g.state('request-done');
      assert.equal(await g.frame.locator('.connection-request-account').count(),0);
    }finally{await g.close();}
  }finally{await browser.close();}
});

for (const kind of ['metamask','unisat']) test(`${kind}: local picker, stopped link, missing launch and no Home wallet`, {timeout:40000}, async()=>{
  const browser=await playwright.chromium.launch({headless:true});
  try{
    const list=await fixture(browser,kind,{saved:true,requests:'multiple'});
    try{
      await list.state('request-list');
      await list.frame.locator('[data-focus-key="select-request:approval-2"]').click();await list.state('request-multiple');
      assert.equal(await list.frame.locator('.connection-request[data-request-id="approval-2"]').count(),1);
      await list.action('view-requests').click();await list.state('request-list');
      assert.equal(await list.top.evaluate(()=>testState.effects.length),0);
    }finally{await list.close();}
    const stopped=await fixture(browser,kind);
    try{
      await stopped.top.evaluate(()=>{testState.mode='pending';});
      await stopped.action('connect').click();await stopped.state('extension-wait');
      await stopped.action('stop-waiting').click();await stopped.state('extension-cancelled');
      assert.doesNotMatch(await stopped.frame.locator('body').innerText(),/check again/i);
      await stopped.action('close-window').click();await stopped.top.waitForFunction(()=>testState.closed);
    }finally{await stopped.close();}
    const missing=await fixture(browser,kind,{launch:false});
    try{await missing.state('window-expired');assert.equal(await missing.frame.locator('button').count(),0);}
    finally{await missing.close();}
    const home=await fixture(browser,kind,{noHomeWallet:true});
    try{await home.action('connect').click();await home.state('link-error');assert.equal(await home.top.evaluate(()=>testState.receipts.length),0);}
    finally{await home.close();}
    const stale=await fixture(browser,kind,{requests:true,saved:true});
    try{
      await stale.state('request-waiting');await stale.top.evaluate(()=>{testState.requests=[];});
      await stale.frame.evaluate(()=>window.dispatchEvent(new Event('focus')));await stale.state('request-unavailable');
      assert.equal(await stale.action('send-request').count(),0);
    }finally{await stale.close();}
  }finally{await browser.close();}
});

test('MetaMask: typed data and transaction wait, stop, failure, timeout and changed-account result', {timeout:50000}, async()=>{
  const browser=await playwright.chromium.launch({headless:true});
  try{
    const typed=await fixture(browser,'metamask',{saved:true,requests:'typed'});
    try{
      await typed.state('request-typed-data');await typed.action('send-request').click();await typed.state('request-done');
      assert.equal(await typed.top.evaluate(()=>testState.receipts[0].signature_type),'eip712');
    }finally{await typed.close();}
    for(const mode of ['approve','decline','stop','timeout']){
      const f=await fixture(browser,'metamask',{saved:true,requests:'transaction'});
      try{
        await f.state('transaction-waiting');
        await f.top.evaluate(mode=>{testState.mode=mode==='approve'||mode==='stop'||mode==='timeout'?'pending':'decline';},mode);
        await f.action('send-request').click();
        if(mode==='decline'){await f.state('transaction-wallet-error');continue;}
        await f.state('transaction-extension');
        await f.top.waitForFunction(()=>testState.pending.length>0);
        if(mode==='timeout'){await f.top.clock.runFor(61000);await f.state('transaction-timeout');continue;}
        if(mode==='stop'){await f.action('stop-waiting').click();await f.state('transaction-cancelled');}
        await f.top.evaluate(value=>{emitWallet('accountsChanged',[value]);const pending=testState.pending.shift();pending.resolve(pending.result);},B);
        await f.state('transaction-done');
        assert.equal(await f.top.evaluate(()=>testState.receipts.length),1);
        assert.equal(await f.frame.locator('.connection-request-account').count(),0);
      }finally{await f.close();}
    }
  }finally{await browser.close();}
});
