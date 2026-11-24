import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir } from 'node:fs/promises';
import { chromium, startSystemFixtureServer, jsonResponse, makeAppearanceRecord, makeSystemSummary } from './system-uiux-fixture.mjs';
import { productSmokeLaunchOptions } from './product-smoke-browser.mjs';

for (const summaryFails of [false, true]) test(`password Kit keeps Profile confirmation and updates setup in place (summary failure ${summaryFails})`, { timeout: 30000 }, async () => {
  let exported = false, summaryReads = 0;
  const server = await startSystemFixtureServer({
    title: 'Recovery download regression',
    hostScript: `addEventListener('message', event => {
      if (event.data?.type === 'elastos.home.passkey-step-up.request/v1') event.source.postMessage({
        type: 'elastos.home.passkey-step-up.result/v1', requestId: event.data.requestId, stepUpToken: 'fixture-step-up'
      }, '*');
    });`,
    onApiRequest: async ({ request, response, url }) => {
      if (url.pathname === '/api/apps/system/summary') {
        summaryReads++;
        if (exported && summaryFails) { jsonResponse(response, {}, 503); return true; }
        const summary = makeSystemSummary(makeAppearanceRecord());
        summary.identity.profile_readiness.status = exported ? 'ready' : 'setup_required';
        summary.identity.profile_setup_display_name = 'Fixture Profile';
        jsonResponse(response, summary); return true;
      }
      if (url.pathname === '/api/auth/recovery/status') {
        jsonResponse(response, { principal_id: 'person:fixture', localhost_root: 'localhost://fixture', recovery_configured: true,
          recovery_download_available: true, protection_configured: true }); return true;
      }
      if (url.pathname === '/api/auth/recovery/full-export') {
        let body = ''; for await (const part of request) body += part;
        const input = JSON.parse(body);
        assert.equal(input.download_password, 'fixture password');
        assert.equal(input.profile_display_name, 'Fixture Profile');
        exported = true;
        // The Rust package round-trip regression proves this metadata belongs to the encrypted Kit.
        jsonResponse(response, { schema: 'elastos.full-recovery-bundle.package/v1', principal_id: 'person:fixture',
          included: { people_identity: true }, protection: { cipher: 'aes-256-gcm' } }); return true;
      }
      return false;
    },
  });
  const browser = await chromium.launch({ headless: true, ...productSmokeLaunchOptions() });
  try {
    const page = await browser.newPage({ viewport: { width: 1050, height: 900 } });
    // Exercise the full System module and real event handlers, with fixture authority responses.
    await page.route('**/fixture?*', async route => {
      const response = await route.fetch();
      await route.fulfill({ response, body: (await response.text()).replace('sandbox="allow-forms', 'sandbox="allow-downloads allow-forms') });
    });
    await page.goto(`${server.baseUrl}/fixture?settings=security`);
    const frame = page.frameLocator('#system-frame');
    await frame.locator('#recovery-profile-setup').waitFor({ state: 'visible' });
    await frame.locator('#recovery-password').fill('fixture password');
    const download = page.waitForEvent('download');
    await frame.locator('#recovery-download').click();
    await download;
    const note = frame.locator('[data-field="recovery-note"]');
    await note.filter({ hasText: 'It includes your Profile.' }).waitFor({ timeout: 5000 });
    await frame.locator('#recovery-profile-setup').waitFor({ state: 'hidden', timeout: 5000 });
    assert.match(await note.textContent(), /Store it offline\. It includes your Profile\./);
    assert.doesNotMatch(await note.textContent(), /Refresh System/);
    assert(summaryReads >= 2, 'System refreshes setup state without a page refresh');
    assert.equal(await frame.locator('#recovery-password').inputValue(), '');
    if (process.env.PRODUCT_FAULT_PICTURES) {
      await mkdir(process.env.PRODUCT_FAULT_PICTURES, { recursive: true });
      await page.screenshot({ path: `${process.env.PRODUCT_FAULT_PICTURES}/99-recovery-${summaryFails ? 'summary-unavailable' : 'ready'}.png` });
      await page.setViewportSize({ width: 390, height: 844 });
      await note.scrollIntoViewIfNeeded();
      await page.screenshot({ path: `${process.env.PRODUCT_FAULT_PICTURES}/99-recovery-phone-${summaryFails ? 'summary-unavailable' : 'ready'}.png` });
    }
  } finally { await browser.close(); await server.close(); }
});
