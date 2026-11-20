import { windowTestOptions } from './lib/walletconnect-window-resources.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import { requireProductSmokePlaywright } from './product-smoke-browser.mjs';
import { fixture } from './lib/wallet-extension-window-fixture.mjs';

const playwright = requireProductSmokePlaywright();
const engineSkip = (engine) => windowTestOptions(engine).skip;

for (const engine of ['chromium']) {
  test(`${engine} metamask: Home-issued picker for two alt wallets announced in Home only`, { timeout: 60000, skip: engineSkip(engine) }, async () => {
    const browser = await playwright[engine].launch({ headless: true });
    try {
      const f = await fixture(browser, 'metamask', { dualAlt: true });
      try {
        await f.top.evaluate(() => window.dispatchEvent(new Event('eip6963:requestProvider')));
        await f.frame.locator('main[data-state="ready"] [data-action="connect"]').click();
        await f.frame.locator('main[data-state="extension-choose-wallet"]').waitFor({ timeout: 15000 });
        const names = await f.frame.locator('.connection-wallet-choice h2').allTextContents();
        assert.deepEqual(names.sort(), ['Brave Wallet', 'Rabby Wallet']);
        const choiceKey = await f.frame.locator('.connection-wallet-choice', { hasText: 'Brave Wallet' })
          .locator('[data-action="select-wallet"]').getAttribute('data-focus-key');
        assert.match(choiceKey, /^select-wallet:wchoice-/);
        await f.frame.locator(`[data-focus-key="${choiceKey}"]`).click();
        await f.frame.locator('main[data-state="extension-wait"],main[data-state="linked"]').waitFor({ timeout: 5000 });
        const action = await f.top.evaluate(() => testState.effects.at(-1)?.action);
        assert.equal(action?.walletChoiceId, choiceKey.slice('select-wallet:'.length));
        assert.equal((await f.top.evaluate(() => testState.calls.find((row) => row.wallet === 'brave')?.method)), 'eth_requestAccounts');
      } finally {
        await f.close();
      }
    } finally {
      await browser.close();
    }
  });
}