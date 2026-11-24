import {windowTestOptions} from './lib/walletconnect-window-resources.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { requireProductSmokePlaywright } from './product-smoke-browser.mjs';
const playwright = requireProductSmokePlaywright();
const engineSkip = engine => windowTestOptions(engine).skip;
const A = '0x' + '1'.repeat(40), B = '0x' + '2'.repeat(40);
const U = 'bc1q' + 'a'.repeat(38), V = 'bc1q' + 'b'.repeat(38);

import { fixture } from './lib/wallet-extension-window-fixture.mjs';

async function secondRequest(f) {
  await f.state('request-list');
  await f.frame.locator('[data-focus-key="select-request:approval-1"]').click();
  await f.state('request-multiple'); await f.action('send-request').click(); await f.state('request-next');
  await f.action('view-requests').click(); await f.state('request-list');
  await f.frame.locator('[data-focus-key="select-request:approval-2"]').click(); await f.state('request-waiting');
}

async function peerEvent(f, name, value) {
  await f.frame.evaluate(() => {
    const observe = event => {
      if (event.data?.type !== 'home:wallet-connector-event') return;
      removeEventListener('message', observe); console.debug('extension-fixture:wallet-event');
    };
    addEventListener('message', observe);
  });
  const observed = f.top.waitForEvent('console', { predicate: message => message.text() === 'extension-fixture:wallet-event', timeout: 3000 });
  await Promise.all([observed, f.top.evaluate(({ name, value }) => emitWallet(name, value), { name, value })]);
}

async function overdueEvent(f, name, value) {
  const instant = await f.top.evaluate(() => Date.now());
  await f.top.clock.pauseAt(new Date(instant + 10000));
  try {
    await f.top.clock.setSystemTime(new Date(instant + 301000));
    await peerEvent(f, name, value);
    return await f.frame.evaluate(() => document.querySelector('main').dataset.state);
  } finally { await f.top.clock.resume(); }
}

for (const engine of ['chromium', 'webkit']) for (const kind of ['metamask', 'unisat']) {
  test(`${engine} ${kind}: each passive event during linked, account-proof, signature and result states`, { timeout: 120000, skip: engineSkip(engine) }, async () => {
    const browser = await playwright[engine].launch({ headless: true });
    try {
      for (const phase of ['linked', 'proof', 'signature', 'result']) {
        for (const name of ['accountsChanged', kind === 'metamask' ? 'chainChanged' : 'networkChanged', 'disconnect']) {
          const f = await fixture(browser, kind, { saved: ['signature', 'result'].includes(phase), requests: ['signature', 'result'].includes(phase) });
          try {
            const waitState = state => f.frame.locator(`main[data-state="${state}"]`).waitFor({ timeout: 3000 });
            const signingMethod = kind === 'metamask' ? 'personal_sign' : 'signMessage';
            if (['proof', 'signature'].includes(phase)) {
              // Pause the real signing RPC, after account discovery and Home's
              // challenge/handoff. An account chooser is a different wait.
              await f.top.evaluate(method => Object.defineProperty(testState, 'mode', {
                configurable: true,
                get() { return testState.calls.at(-1)?.method === method ? 'pending' : 'approve'; },
              }), signingMethod);
            }
            await waitState(['signature', 'result'].includes(phase) ? 'request-waiting' : 'ready');
            await f.action(['signature', 'result'].includes(phase) ? 'send-request' : 'connect').click();
            const expected = ({ linked: 'linked', proof: 'extension-wait', signature: 'request-extension', result: 'request-done' })[phase];
            await waitState(expected);
            if (['proof', 'signature'].includes(phase)) await f.top.waitForFunction(method => testState.pending.some(p => p.method === method), signingMethod);
            await f.frame.evaluate(() => {
              window.eventProbe = [];
              addEventListener('message', event => {
                if (event.data?.type === 'home:wallet-connector-event') eventProbe.push(event.data);
              });
            });
            const before = await f.top.evaluate(() => ({ calls: testState.calls.length, runtime: testState.runtimeCalls.length, effects: testState.effects.length, receipts: testState.receipts.length }));
            const focusBefore = await f.frame.evaluate(() => ({ key: document.activeElement?.dataset.focusKey || document.activeElement?.dataset.focus, y: scrollY }));
            if (phase === 'result') assert.equal(focusBefore.key, 'outcome', 'positive control: the completed result owns focus');
            const value = name === 'accountsChanged' ? [kind === 'metamask' ? B : V]
              : name === 'disconnect' ? { code: 4900 } : kind === 'metamask' ? '0x14' : 'testnet';
            await f.top.evaluate(({ name, value }) => emitWallet(name, value), { name, value });
            // Observe the real Home forwarder, rather than injecting a window
            // packet or merely waiting for an already-visible state.
            await f.frame.waitForFunction(() => eventProbe.length === 1);
            assert.deepEqual(await f.frame.evaluate(() => eventProbe[0]), {
              type: 'home:wallet-connector-event', connectorId: `wallet-${kind}`, event: name, value: name === 'disconnect' ? null : value,
            });
            await waitState(phase !== 'linked' ? expected : name === 'accountsChanged' ? 'account-unavailable'
              : name === 'disconnect' ? 'account-unavailable' : kind === 'unisat' ? 'network-changed' : 'linked');
            assert.deepEqual(await f.top.evaluate(() => ({ calls: testState.calls.length, runtime: testState.runtimeCalls.length, effects: testState.effects.length, receipts: testState.receipts.length })), before, `${phase}/${name}: notification is passive`);
            if (phase !== 'linked') assert.deepEqual(await f.frame.evaluate(() => ({ key: document.activeElement?.dataset.focusKey || document.activeElement?.dataset.focus, y: scrollY })), focusBefore, `${phase}/${name}: redraw retains focus and scroll`);
            if (['proof', 'signature'].includes(phase)) assert.equal(await f.action('stop-waiting').count(), 1);
            if (['signature', 'result'].includes(phase) && ['accountsChanged', 'disconnect'].includes(name)) assert.equal(await f.frame.locator('.connection-request-account').count(), 0);
            if (phase === 'result') assert.equal(await f.action('send-request').count(), 0);
            if (name.includes('Changed') && name !== 'accountsChanged' && phase === 'linked') assert.match(await f.frame.locator('body').innerText(), kind === 'metamask' ? /Elastos Smart Chain/ : /test network.*unsupported|Bitcoin test network/i);
            if (phase === 'linked' && name === 'accountsChanged' || phase === 'result' && name.includes('Changed') && name !== 'accountsChanged') {
              await f.top.evaluate(() => { const input = document.createElement('input'); input.id = 'other-control'; document.body.append(input); input.focus(); });
              assert.equal(await f.frame.evaluate(() => document.hasFocus()), false);
              await f.top.evaluate(({ phase, kind }) => emitWallet(phase === 'linked' ? 'accountsChanged' : kind === 'metamask' ? 'chainChanged' : 'networkChanged', phase === 'linked' ? [testState.address] : kind === 'metamask' ? '0x1' : 'livenet'), { phase, kind });
              await f.frame.waitForFunction(() => eventProbe.length === 2);
              await waitState(phase === 'linked' ? 'linked' : 'request-done');
              assert.equal(await f.top.evaluate(() => document.activeElement?.id), 'other-control', 'passive redraw keeps the other Home control active');
              assert.deepEqual(await f.top.evaluate(() => ({ calls: testState.calls.length, runtime: testState.runtimeCalls.length, effects: testState.effects.length, receipts: testState.receipts.length })), before);
            }
            if (['proof', 'signature'].includes(phase)) {
              await f.top.evaluate(() => {
                Object.defineProperty(testState, 'mode', { configurable: true, writable: true, value: 'approve' });
                const pending = testState.pending.shift(); pending.resolve(pending.result);
              });
              await waitState(phase === 'signature' ? 'request-done' : ['accountsChanged', 'disconnect'].includes(name) ? 'account-unavailable'
                : kind === 'unisat' ? 'network-changed' : 'linked');
              assert.equal(await f.top.evaluate(() => testState.receipts.length), 1, 'a real accepted proof/result is retained after the event');
              if (phase === 'proof' && name === 'disconnect') assert.doesNotMatch(await f.frame.locator('body').innerText(), /Could not connect|Permissions|Choose the required account/);
              if (phase === 'signature') assert.equal(await f.action('send-request').count(), 0);
            }
            assert.deepEqual(f.errors, []);
          } finally { await f.close(); }
        }
      }
    } finally { await browser.close(); }
  });
}

for (const engine of ['chromium', 'webkit']) for (const kind of ['metamask', 'unisat']) {
  test(`${engine} ${kind}: live shared window links, signs, redraws and returns actual receipts`, { timeout: 50000, skip: engineSkip(engine) }, async () => {
    const browser = await playwright[engine].launch({ headless: true });
    try {
      const f = await fixture(browser, kind);
      try {
        await f.state('ready'); await f.action('connect').focus(); await f.top.keyboard.press('Enter'); await f.state('linked');
        assert.equal(await f.top.evaluate(() => testState.receipts.length), 1);
        await f.action('copy-address').focus(); await f.top.keyboard.press('Space');
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
        await g.top.keyboard.press('Enter'); await g.state('request-done');
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
        await f.action('stop-waiting').focus(); await f.top.keyboard.press('Enter'); await f.state('request-cancelled');
        assert.doesNotMatch(await f.frame.locator('body').innerText(), /ignore a later answer/);
        assert.match(await f.frame.locator('body').innerText(), /Check your wallet and Activity in Wallet/);
        await f.top.waitForFunction(() => testState.pending.length > 0);
        await f.top.evaluate(() => { const p = testState.pending.shift(); p.resolve(p.result); });
        await f.state('request-done');
        assert.equal(await f.top.evaluate(() => testState.receipts.length), 1);
        await f.top.evaluate(() => emitWallet('accountsChanged', []));
        await f.state('request-done');
        assert.equal(await f.frame.locator('.connection-request-account').count(), 0);
        assert.equal(await f.action('send-request').count(), 0);
      } finally { await f.close(); }
      const g = await fixture(browser, kind);
      try {
        await g.top.evaluate(() => { testState.mode = 'pending'; });
        await g.action('connect').click(); await g.state('extension-wait');
        await g.top.clock.runFor(61000); await g.state('extension-timeout');
        assert.doesNotMatch(await g.frame.locator('body').innerText(), /ignore a later answer/);
        assert.equal(await g.frame.getByRole('button', { name: 'Cancel', exact: true }).count(), 0);
        assert.equal(await g.top.evaluate(() => testState.effects.length), 1);
      } finally { await g.close(); }
      const h = await fixture(browser, kind);
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
          await h.top.evaluate(() => emitWallet('networkChanged', 'unknown')); await h.state('network-unknown');
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
          await f.state(f.peerElapsed > 60000 ? 'extension-timeout' : 'link-declined');
          assert.equal(await f.top.evaluate(() => testState.receipts.length), 0);
        } finally { await f.close(); }
      }
      const missing = await fixture(browser, kind, { recording: 'private-no-extension' });
      try { await missing.action('connect').click(); await missing.state('extension-missing'); assert.doesNotMatch(await missing.frame.locator('body').innerText(), /enable|reload/i, 'absence cannot prove extensions can run in this window'); } finally { await missing.close(); }
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
  assert.match(mm, /postMessage\(\{type:'home:open-target',target:'wallet',homeToken:frameHomeToken\},homeOrigin\)/);
  assert.equal((mm.match(/home:open-target/g)||[]).length,1,'one fixed Wallet recovery message');
  assert.match(mm, /mountConnection\(mount, view, presentation\)/);
  assert.doesNotMatch(mm, /localStorage|sessionStorage|eth_requestAccounts|eth_sendTransaction|wallet-connector\/.*\/v2/);
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
        await f.action('send-request').click(); await f.state('request-declined');
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

test('fixture close retires an in-flight Home read', { timeout: 10000 }, async () => {
  const browser = await playwright.chromium.launch({ headless: true });
  try {
    const f = await fixture(browser, 'metamask');
    await f.state('ready');
    const entered = Promise.withResolvers(), finished = Promise.withResolvers();
    const closed = f.context.waitForEvent('close');
    const evaluate = f.top.evaluate.bind(f.top);
    // Hold the real /api/ handler at its page read until teardown closes the
    // context. This fixes the race ordering without a timer or a retry.
    f.top.evaluate = async (...args) => {
      entered.resolve();
      await closed;
      try { return await evaluate(...args); }
      finally { finished.resolve(); }
    };
    await f.frame.evaluate(() => { void fetch('https://extensions.test/api/fixture-close').catch(() => {}); });
    await entered.promise;
    await f.close();
    await finished.promise;
  } finally { await browser.close(); }
});

test('live-window regression oracle rejects deliberate breaks', { timeout: 50000 }, async () => {
  const browser = await playwright.chromium.launch({ headless: true });
  try {
    const mutations = [
      ['state mapped wrong', s => s.replace("let stage = 'ready'", "let stage = 'link-error'").replace("return accountView() ? 'linked' : 'ready';", "return accountView() ? 'linked' : 'link-error';"), async f => {
        // Snapshot the first controller paint before any asynchronous refresh.
        assert.equal(await f.frame.locator('main').getAttribute('data-state'), 'ready');
      }],
      ['control wired wrong', s => s.replace("void perform({ kind: 'approve', approvalRequestId: selected.id, ...(kind === 'metamask' ? {linkedAddress:selected.address} : {}) })", "void perform({ kind: 'link' })"), async f => {
        await f.action('send-request').click();
        await f.top.waitForFunction(() => testState.effects.length > 0);
        assert.equal(await f.top.evaluate(() => testState.effects[0].action.kind), 'approve');
      }],
      ['Cancel after dispatch', s => s.replace('const root = presentation.root;', "const root = presentation.root; for (const b of root.querySelectorAll('[data-action=stop-waiting]')) b.textContent = 'Cancel';"), async f => {
        await f.top.evaluate(() => { testState.mode = 'pending'; });
        await f.action('send-request').click(); await f.state('request-extension');
        assert.equal(await f.frame.getByRole('button', { name: 'Cancel', exact: true }).count(), 0);
      }],
      ['stale wait after answer', s => s.replace("const viewStage = refusal ? 'request-dismissed' : stage;", "const viewStage = refusal ? 'request-dismissed' : stage === 'request-done' ? 'request-extension' : stage;"), async f => {
        await f.action('send-request').click(); await f.state('request-done');
      }],
      ['draw outside shared view', s => s.replace('const root = presentation.root;', "const root = presentation.root; root.append(document.createElement('aside'));"), async f => {
        await f.assertShared();
      }],
      ['accepted proof after disconnect', s => s.replace("if (disconnected) return linkObserved ? 'account-unavailable' : 'link-error';", "if (disconnected) return 'link-error';"), async f => {
        await f.top.evaluate(() => Object.defineProperty(testState, 'mode', {
          configurable: true, get() { return testState.calls.at(-1)?.method === 'personal_sign' ? 'pending' : 'approve'; },
        }));
        await f.action('connect').click(); await f.state('extension-wait');
        await f.top.waitForFunction(() => testState.pending.some(p => p.method === 'personal_sign'));
        await f.top.evaluate(() => {
          emitWallet('disconnect', { code: 4900 });
          Object.defineProperty(testState, 'mode', { configurable: true, value: 'approve' });
          const pending = testState.pending.shift(); pending.resolve(pending.result);
        });
        await f.top.waitForFunction(() => testState.receipts.length === 1);
        await f.state('account-unavailable');
      }],
      ['inactive window revived', s => s.replace("if (stage === 'window-expired') fixedOutcome = true;", ''), async f => {
        await f.action('connect').click(); await f.state('linked');
        await f.context.route('**/api/**', route => route.fulfill({ status: 403, json: { error: 'authority ended' } }));
        await f.frame.evaluate(() => {
          window.expiryEventSeen = false;
          addEventListener('message', e => { if (e.data?.type === 'home:wallet-connector-event') expiryEventSeen = true; });
          dispatchEvent(new Event('focus'));
        });
        await f.state('window-expired');
        await f.top.evaluate(() => emitWallet('chainChanged', '0x14'));
        await f.frame.waitForFunction(() => expiryEventSeen);
        await f.state('window-expired');
      }],
      ['wrong linked signer', s => s.replace('&& !(walletEventAddress && selected && sameAccount(walletEventAddress, selected.address))', '&& true'), async f => {
        await secondRequest(f); await peerEvent(f, 'accountsChanged', [B]); await f.state('account-unavailable');
        assert.equal(await f.action('send-request').count(),0);
      }],
      ['expiry hidden by wallet state', s => s.replace('if (!operation && !uncertain && !fixedOutcome && isRequestExpired())', "if (!operation && !uncertain && !fixedOutcome && isRequestExpired() && ['request-waiting', 'request-typed-data', 'transaction-waiting', 'request-list'].includes(stage))"), async f => {
        await secondRequest(f); await f.top.evaluate(value=>testState.walletAddress=value,B);
        await f.action('send-request').click();await f.state('request-unsendable');
        await f.top.clock.runFor(301000); await f.state('request-expired');
      }],
      ['overdue event before timer', s => s.replace('function isRequestExpired() {', 'function isRequestExpired() { return false;'), async f => {
        await secondRequest(f); assert.equal(await overdueEvent(f, 'accountsChanged', [B]), 'request-expired');
      }],
      ['outcome focus lost', s => s.replace("root.querySelector('.connection-actions')?.append(close);", "root.querySelector('.connection-actions')?.append(close); close.focus();"), async f => {
        await f.action('send-request').click(); await f.state('request-done');
        assert.equal(await f.frame.evaluate(() => document.activeElement?.dataset.focus), 'outcome');
        await peerEvent(f, 'accountsChanged', [B]);
        assert.equal(await f.frame.evaluate(() => document.activeElement?.dataset.focus), 'outcome');
      }],
      ['background focus stolen', s => s.replace('presentation = mountConnection(mount, view, presentation);',"presentation = mountConnection(mount, view, presentation); mount.querySelector('button')?.focus();"), async f => {
        await f.action('connect').click(); await f.state('linked');
        await f.top.evaluate(() => { const input = document.createElement('input'); input.id = 'other-control'; document.body.append(input); input.focus(); });
        await peerEvent(f, 'accountsChanged', [B]);
        assert.equal(await f.top.evaluate(() => document.activeElement?.id), 'other-control');
      }],
    ];
    for (const [name, mutate, oracle] of mutations) {
      const source = await readFile('capsules/wallet-metamask/browser/extension-window.mjs', 'utf8');
      assert.notEqual(mutate(source), source, name + ' mutation applies');
      const requestPair = ['wrong linked signer', 'expiry hidden by wallet state', 'overdue event before timer'].includes(name);
      const f = await fixture(browser, 'metamask', { saved: !['state mapped wrong', 'accepted proof after disconnect', 'inactive window revived', 'background focus stolen'].includes(name), requests: requestPair ? 'multiple' : !['state mapped wrong', 'accepted proof after disconnect', 'inactive window revived', 'background focus stolen'].includes(name), extraHomeAccount: requestPair, mutate });
      try { await assert.rejects(oracle(f), undefined, name + ' must fail the live oracle'); }
      finally { await f.close(); }
    }
  } finally { await browser.close(); }
});

for (const kind of ['metamask', 'unisat']) test(`${kind}: new window with pinned Home and retired-window result contract`, { timeout: 40000 }, async () => {
  const browser = await playwright.chromium.launch({ headless: true });
  try {
    const modern = await fixture(browser, kind, { oldHost: true });
    try { await modern.action('connect').click(); await modern.state('linked');
      if(kind==='metamask') {assert.equal(await modern.frame.locator('.connection-account-name').innerText(),'Your wallet');assert.equal(await modern.frame.locator('img').count(),0);} }
    finally { await modern.close(); }
    const legacy = await fixture(browser, kind, { oldWindow: true });
    try {
      await legacy.frame.locator('#wallet-connect').click();
      const expected = kind === 'metamask' ? 'Home returned an invalid wallet result.' : 'Approval method added.';
      await legacy.frame.locator('#wallet-status').filter({hasText:expected}).waitFor();
      await legacy.top.evaluate(value => emitWallet('accountsChanged', [value]), kind === 'metamask' ? B : V);
      assert.equal(await legacy.top.evaluate(() => testState.receipts.length), 1);
      assert.equal(await legacy.frame.locator('#wallet-status').innerText(), expected);
    }finally{await legacy.close();}
  }finally{await browser.close();}
});

for (const kind of ['metamask', 'unisat']) test(`${kind}: a failed Home read is distinct from expired authority`, async () => {
  const browser = await playwright.chromium.launch({ headless: true });
  try {
    for (const [status, state] of [[503, 'wallet-unavailable'], [403, 'window-expired']]) {
      const f = await fixture(browser, kind, { readFailure: status });
      try { await f.state(state); assert.equal(await f.top.evaluate(() => testState.effects.length), 0); }
      finally { await f.close(); }
    }
  } finally { await browser.close(); }
});

for (const engine of ['chromium', 'webkit']) for (const kind of ['metamask', 'unisat']) test(`${engine} ${kind}: passive events cannot revive an inactive window`, { timeout: 50000, skip: engineSkip(engine) }, async () => {
  const browser = await playwright[engine].launch({ headless: true });
  try {
    for (const status of [401, 403]) {
      const f = await fixture(browser, kind);
      try {
        await f.action('connect').click(); await f.state('linked');
        await f.context.route('**/api/**', route => route.fulfill({ status, json: { error: 'authority ended' } }));
        await f.frame.evaluate(() => {
          window.expiryEvents = 0;
          addEventListener('message', e => { if (e.data?.type === 'home:wallet-connector-event') expiryEvents++; });
          dispatchEvent(new Event('focus'));
        });
        await f.state('window-expired');
        let count = 0;
        for (const [name, value] of [['accountsChanged', [kind === 'metamask' ? B : V]], [kind === 'metamask' ? 'chainChanged' : 'networkChanged', kind === 'metamask' ? '0x14' : 'testnet'], ['disconnect', {}]]) {
          await f.top.evaluate(({ name, value }) => emitWallet(name, value), { name, value });
          await f.frame.waitForFunction(n => expiryEvents === n, ++count);
          await f.state('window-expired');
          assert.equal(await f.action('connect').count(), 0);
          assert.equal(await f.action('send-request').count(), 0);
        }
        assert.equal(await f.top.evaluate(() => testState.effects.length), 1);
        await f.action('close-window').focus(); await f.top.keyboard.press('Enter');
        await f.top.waitForFunction(() => testState.closed === true);
        assert.deepEqual(f.errors, []);
      } finally { await f.close(); }
    }
  } finally { await browser.close(); }
});

for (const engine of ['chromium', 'webkit']) for (const kind of ['metamask', 'unisat']) test(`${engine} ${kind}: another connected account cannot satisfy the selected request or hide its expiry`, { timeout: 50000, skip: engineSkip(engine) }, async () => {
  const browser = await playwright[engine].launch({ headless: true });
  try {
    for (const mode of ['recover', 'timer', 'event']) {
      const f = await fixture(browser, kind, { saved: true, requests: 'multiple', extraHomeAccount: true });
      try {
        await secondRequest(f);
        if (mode === 'event') {
          assert.equal(await overdueEvent(f, 'accountsChanged', [kind === 'metamask' ? B : V]), 'request-expired');
          await f.state('request-expired');
        } else {
          await peerEvent(f, 'accountsChanged', [kind === 'metamask' ? B : V]); await f.state('account-unavailable');
          assert.equal(await f.action('send-request').count(), 0);
          assert.equal(await f.top.evaluate(() => testState.effects.length), 1);
          if (mode === 'recover') {
            await peerEvent(f, 'accountsChanged', [kind === 'metamask' ? A : U]); await f.state('request-waiting');
            assert.equal(await f.top.evaluate(() => testState.effects.length), 1);
            await f.action('send-request').click(); await f.state('request-done');
            assert.equal(await f.top.evaluate(() => testState.receipts.length), 2);
            assert.equal(await f.top.evaluate(() => testState.effects.at(-1).action.approvalRequestId), 'approval-2');
            continue;
          }
          await f.top.clock.runFor(301000); await f.state('request-expired');
        }
        await peerEvent(f, 'accountsChanged', [kind === 'metamask' ? A : U]);
        await f.state('request-expired');
        assert.equal(await f.action('send-request').count(), 0);
        assert.equal(await f.top.evaluate(() => testState.effects.length), 1);
        assert.deepEqual(f.errors, []);
      } finally { await f.close(); }
    }
  } finally { await browser.close(); }
});

for (const engine of ['chromium', 'webkit']) for (const kind of ['metamask', 'unisat']) test(`${engine} ${kind}: wallet events preserve an active link and an acknowledged result`, { timeout: 50000, skip: engineSkip(engine) }, async () => {
  const browser = await playwright[engine].launch({ headless:true });
  const changed = kind === 'metamask' ? B : V;
  try {
    const f = await fixture(browser, kind);
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
      await f.state('account-unavailable');
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

for (const engine of ['chromium','webkit']) for (const kind of ['metamask','unisat']) test(`${engine} ${kind}: local picker, stopped link, missing launch and no Home wallet`, {timeout:40000,skip:engineSkip(engine)}, async()=>{
  const browser=await playwright[engine].launch({headless:true});
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
      await stopped.action('close-window').focus(); await stopped.top.keyboard.press('Enter');await stopped.top.waitForFunction(()=>testState.closed);
    }finally{await stopped.close();}
    const missing=await fixture(browser,kind,{launch:false});
    try{await missing.state('window-expired');assert.equal(await missing.frame.locator('button').count(),0);}
    finally{await missing.close();}
    const home=await fixture(browser,kind,{noHomeWallet:true});
    try{await home.action('connect').click();await home.state('link-error');assert.equal(await home.top.evaluate(()=>testState.receipts.length),0);}
    finally{await home.close();}
    const timed=await fixture(browser,kind,{requests:true,saved:true});
    try{
      await timed.top.evaluate(()=>{testState.mode='pending';});
      await timed.action('send-request').click();await timed.state('request-extension');
      await timed.top.clock.runFor(61000);await timed.state('request-timeout');
      assert.doesNotMatch(await timed.frame.locator('body').innerText(),/check again/i);
    }finally{await timed.close();}
    const stale=await fixture(browser,kind,{requests:true,saved:true});
    try{
      await stale.state('request-waiting');await stale.top.evaluate(()=>{testState.requests=[];});
      await stale.frame.evaluate(()=>window.dispatchEvent(new Event('focus')));await stale.state('request-unavailable');
      await stale.top.evaluate(kind=>document.querySelector('iframe').contentWindow.postMessage({type:'home:wallet-connector-event',connectorId:'wallet-'+kind,event:kind==='metamask'?'chainChanged':'networkChanged',value:kind==='metamask'?'0x1':'livenet'},'*'),kind);await stale.state('request-unavailable');
      assert.equal(await stale.action('send-request').count(),0);
    }finally{await stale.close();}
  }finally{await browser.close();}
});

for (const engine of ['chromium','webkit']) test(`${engine} MetaMask: typed data and transaction wait, stop, failure, timeout and changed-account result`, {timeout:50000,skip:engineSkip(engine)}, async()=>{
  const browser=await playwright[engine].launch({headless:true});
  try{
    const typed=await fixture(browser,'metamask',{saved:true,requests:'typed'});
    try{
      await typed.state('request-typed-data');await typed.action('send-request').click();await typed.state('request-done');
      assert.equal(await typed.top.evaluate(()=>testState.receipts[0].signature_type),'eip712');
    }finally{await typed.close();}
    // A presentation label can change without changing the signing method.
    const relabel=source=>source.replace('if (selected) return requests.length > 1', "if (selected) selected.title = 'Sign a message';\n    if (selected) return requests.length > 1");
    const renamed=await fixture(browser,'metamask',{saved:true,requests:'typed',mutate:relabel});
    try{
      await renamed.state('request-typed-data');await renamed.action('send-request').click();await renamed.state('request-done');
      assert.equal(await renamed.top.evaluate(()=>testState.receipts[0].signature_type),'eip712','intent owns signing after the heading changes');
    }finally{await renamed.close();}
    const sentenceDriven=await fixture(browser,'metamask',{saved:true,requests:'typed',mutate:source=>relabel(source).replace("requests.find(request => request.request_id === selected.id)?.intent === 'browser_typed_data_sign'", "selected.title === 'Sign typed data'")});
    try{await sentenceDriven.state('request-waiting');assert.notEqual(await sentenceDriven.frame.locator('main').getAttribute('data-state'),'request-typed-data','the former sentence comparison loses the typed-data state');}
    finally{await sentenceDriven.close();}
    for(const mode of ['approve','decline','stop','timeout']){
      const f=await fixture(browser,'metamask',{saved:true,requests:'transaction'});
      try{
        await f.state('transaction-waiting');
        await f.top.evaluate(mode=>{testState.mode=mode==='approve'||mode==='stop'||mode==='timeout'?'pending':'decline';},mode);
        await f.action('send-request').click();
        if(mode==='decline'){
          await f.state('transaction-declined');
          assert.doesNotMatch(await f.frame.locator('body').innerText(), /Home does not know if the transaction was sent/);
          await f.top.evaluate(value=>{emitWallet('chainChanged','0x1');emitWallet('accountsChanged',[value]);},B);
          await f.state('transaction-declined');assert.equal(await f.action('send-request').count(),0);continue;
        }
        await f.state('transaction-extension');
        await f.top.waitForFunction(()=>testState.pending.length>0);
        if(mode==='timeout'){await f.top.clock.runFor(61000);await f.state('transaction-timeout');assert.equal(await f.action('close-window').count(),1);await f.top.evaluate(value=>emitWallet('accountsChanged',[value]),B);await f.state('transaction-timeout');assert.equal(await f.frame.locator('.connection-request-account').count(),0);continue;}
        if(mode==='stop'){await f.action('stop-waiting').click();await f.state('transaction-cancelled');assert.equal(await f.action('close-window').count(),1);}
        await f.top.evaluate(value=>{emitWallet('accountsChanged',[value]);const pending=testState.pending.shift();pending.resolve(pending.result);},B);
        await f.state('transaction-done');
        assert.equal(await f.top.evaluate(()=>testState.receipts.length),1);
        assert.equal(await f.frame.locator('.connection-request-account').count(),0);
      }finally{await f.close();}
    }
  }finally{await browser.close();}
});

for (const engine of ['chromium','webkit']) for (const kind of ['metamask','unisat']) test(`${engine} ${kind}: another pending message remains reachable after a signed result`, {timeout:40000,skip:engineSkip(engine)}, async()=>{
  const browser=await playwright[engine].launch({headless:true});
  try{
    const f=await fixture(browser,kind,{saved:true,requests:'multiple'});
    try{
      await f.state('request-list');await f.frame.locator('[data-focus-key="select-request:approval-1"]').click();await f.state('request-multiple');
      await f.action('send-request').click();await f.state('request-next');
      assert.equal(await f.top.evaluate(()=>testState.receipts.length),1);
      await f.action('view-requests').focus();await f.top.keyboard.press('Space');await f.state('request-list');
      assert.equal(await f.frame.locator('[data-focus-key="select-request:approval-1"]').count(),0);
      await f.frame.locator('[data-focus-key="select-request:approval-2"]').focus();await f.top.keyboard.press('Enter');await f.state('request-waiting');
      await f.action('send-request').click();await f.state('request-done');
      assert.equal(await f.top.evaluate(()=>testState.receipts.length),2);
      assert.deepEqual(await f.top.evaluate(()=>testState.effects.map(e=>e.action.approvalRequestId)),['approval-1','approval-2']);
      assert.equal(await f.top.evaluate(()=>testState.requests.length),0);
    }finally{await f.close();}
  }finally{await browser.close();}
});

for (const engine of ['chromium','webkit']) test(`${engine} UniSat: recorded lock and unlock keep one existing account prompt`, {timeout:30000,skip:engineSkip(engine)}, async()=>{
  const browser=await playwright[engine].launch({headless:true});
  try{
    const f=await fixture(browser,'unisat',{recording:'unisat-locked-connect'});
    try{
      // Reproduce the recording's initial page probe; this is harness setup,
      // not an added product RPC or a claim that an empty list identifies lock.
      await f.top.evaluate(()=>{window.lockProbe=unisat.getAccounts();});
      await f.top.evaluate(()=>__walletReplay.advance(100));
      assert.deepEqual(await f.top.evaluate(()=>window.lockProbe),[]);
      await f.action('connect').click();await f.state('extension-wait');
      await f.top.waitForFunction(()=>__walletReplay.requests.length===2);
      await f.top.evaluate(()=>{__walletReplay.person('unlocks');return __walletReplay.advance(1000);});
      await f.state('extension-wait');
      assert.equal(await f.top.evaluate(()=>__walletReplay.requests.filter(r=>r.method==='requestAccounts').length),1);
      await f.action('stop-waiting').click();await f.state('extension-cancelled');
      assert.equal(await f.top.evaluate(()=>testState.receipts.length),0);
    }finally{await f.close();}
  }finally{await browser.close();}
});

for(const engine of ['chromium','webkit']) for(const kind of ['metamask','unisat']) test(`${engine} ${kind}: a Home completion error does not claim the wallet failed to sign`, {timeout:30000,skip:engineSkip(engine)}, async()=>{
  const browser=await playwright[engine].launch({headless:true});
  try{
    const f=await fixture(browser,kind,{saved:true,requests:true});
    try{
      await f.top.evaluate(()=>{const send=window.runtimeFetch;window.runtimeFetch=(url,init)=>url.endsWith('/complete')?Promise.reject(Error('Fixture result recording failed')):send(url,init);});
      await f.action('send-request').click();await f.state('request-wallet-error');
      assert.equal(await f.top.evaluate(()=>testState.calls.some(c=>['personal_sign','signMessage'].includes(c.method))),true);
      assert.doesNotMatch(await f.frame.locator('body').innerText(),/could not sign/i);
      assert.doesNotMatch(await f.frame.locator('body').innerText(),/return to|result unknown/i);
      assert.equal(await f.action('send-request').count(),0);
    }finally{await f.close();}
  }finally{await browser.close();}
});

for(const engine of ['chromium','webkit']) for(const kind of ['metamask','unisat']) test(`${engine} ${kind}: a send always shows its Runtime-bound signer even when the account list lags`, {timeout:30000,skip:engineSkip(engine)}, async()=>{
  const browser=await playwright[engine].launch({headless:true});
  try{
    const f=await fixture(browser,kind,{requests:true,saved:false});
    try{
      await f.state('request-waiting');
      const signer=kind==='metamask'?'0x1111':'bc1qaaaa';
      assert.match(await f.frame.locator('.connection-request-account').innerText(),new RegExp(signer));
      await f.action('send-request').click();await f.state('request-done');
      assert.equal(await f.top.evaluate(()=>testState.receipts.length),1);
    }finally{await f.close();}
    const invalid=await fixture(browser,kind,{requests:true});
    try{
      await invalid.state('request-waiting');await invalid.top.evaluate(()=>{testState.requests[0].address='';});
      await invalid.frame.evaluate(()=>window.dispatchEvent(new Event('focus')));await invalid.state('request-unavailable');
      assert.equal(await invalid.action('send-request').count(),0);
      assert.equal(await invalid.top.evaluate(()=>testState.effects.length),0);
    }finally{await invalid.close();}
  }finally{await browser.close();}
});
