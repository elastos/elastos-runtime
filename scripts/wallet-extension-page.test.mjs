import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { installScriptedExtension, replayInput } from './wallet-extension-test/index.mjs';

const require = createRequire(import.meta.url);
const { chromium } = require(process.env.BROWSER_OPERATOR_PLAYWRIGHT_CORE
  || join(homedir(), '.cache/elastos-runtime/behaviour/core/node_modules/playwright-core'));

test('headless page installs the scripted provider before its first page script', async () => {
  const browser = await chromium.launch({ headless: true });
  try {
    const page = await browser.newPage();
    await page.addInitScript(installScriptedExtension, await replayInput('metamask-before-access'));
    await page.goto('data:text/html,<script>window.sawWalletAtBoot=typeof ethereum; addEventListener("eip6963:announceProvider",e=>window.wallet=e.detail.provider); dispatchEvent(new Event("eip6963:requestProvider"));</script>');
    assert.equal(await page.evaluate(() => sawWalletAtBoot), 'object');
    await page.evaluate(() => __walletReplay.advance(1000));
    await page.evaluate(() => { window.accounts = wallet.request({ method: 'eth_accounts' }); });
    await page.evaluate(() => __walletReplay.advance(100));
    assert.deepEqual(await page.evaluate(() => accounts), []);
    assert.deepEqual(await page.evaluate(() => __walletReplay.requests.map(({ method, params, state }) => ({ method, params, state }))),
      [{ method: 'eth_accounts', params: [], state: 'fulfilled' }]);
    await page.evaluate(() => __walletReplay.assertNoViolations());
  } finally { await browser.close(); }
});

test('caught page errors remain visible to the test through the control helper', async () => {
  const browser = await chromium.launch({ headless: true });
  try {
    const page = await browser.newPage();
    await page.addInitScript(installScriptedExtension, await replayInput('unisat-before-access'));
    await page.goto('data:text/html,<script>try { unisat.getChain(); } catch { window.productRecovered = true; }</script>');
    assert.equal(await page.evaluate(() => productRecovered), true);
    assert.equal(await page.evaluate(() => __walletReplay.violations.length), 1);
    await assert.rejects(page.evaluate(() => __walletReplay.assertNoViolations()), /Wallet replay violations/);
  } finally { await browser.close(); }
});

test('headless UniSat waits through unlock and approval, with recorded public event order', async () => {
  const browser = await chromium.launch({ headless: true });
  try {
    const page = await browser.newPage();
    await page.addInitScript(installScriptedExtension, await replayInput('unisat-locked-connect'));
    await page.goto('data:text/html,<script>window.events=[]; unisat.on("accountsChanged",v=>events.push(["accountsChanged",v])); unisat.on("networkChanged",v=>events.push(["networkChanged",v])); window.boot=unisat.getAccounts();</script>');
    await page.evaluate(() => __walletReplay.advance(100));
    assert.deepEqual(await page.evaluate(() => boot), []);
    await page.evaluate(() => { window.result = 'pending'; unisat.requestAccounts().then((v) => result = v); });
    await page.evaluate(() => __walletReplay.advance(70_000));
    assert.equal(await page.evaluate(() => result), 'pending');
    await page.evaluate(() => __walletReplay.person('unlocks'));
    assert.equal(await page.evaluate(() => result), 'pending');
    await page.evaluate(() => __walletReplay.person('approves'));
    await page.evaluate(() => __walletReplay.advance(1000));
    assert.deepEqual(await page.evaluate(() => result), ['bc1qcwnwu8vq8y66tr7a3mwn3j5p4yxz8prpukfnuv']);
    assert.deepEqual(await page.evaluate(() => events), [
      ['accountsChanged', ['bc1qcwnwu8vq8y66tr7a3mwn3j5p4yxz8prpukfnuv']], ['networkChanged', 'livenet'],
    ]);
    await page.evaluate(() => __walletReplay.assertNoViolations());
  } finally { await browser.close(); }
});
