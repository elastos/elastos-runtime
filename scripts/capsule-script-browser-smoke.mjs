#!/usr/bin/env node
// Run against the source Home served by content_sandbox_browser_capsule_scripts.
// Documents and headers come from the product gateway, with no route fulfillment.
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { importProductSmokePlaywright, productSmokeLaunchOptions } from './product-smoke-browser.mjs';

const playwright = await importProductSmokePlaywright();
const origin = process.env.ELASTOS_CAPSULE_SCRIPT_URL;
const token = process.env.ELASTOS_CAPSULE_SCRIPT_TOKEN;
assert.ok(origin && token, 'the Rust source Home supplies its URL and disposable session');
const engines = (process.env.ELASTOS_CAPSULE_SCRIPT_ENGINES || 'chromium,webkit').split(',');
const failures = [];
let foreignRequests = 0;
const foreign = createServer((_request, response) => {
  foreignRequests++;
  response.writeHead(200, {
    'content-type': 'text/javascript',
    'access-control-allow-origin': '*',
    'cross-origin-resource-policy': 'cross-origin',
  });
  response.end('globalThis.foreignScriptExecuted = true;');
});
await new Promise(resolve => foreign.listen(0, '127.0.0.1', resolve));
const foreignUrl = `http://127.0.0.1:${foreign.address().port}/foreign.js`;
try {
  for (const engine of engines) {
    assert.ok(['chromium', 'webkit'].includes(engine), `supported engine: ${engine}`);
    const browser = await playwright[engine].launch({ headless: true,
      ...(engine === 'chromium' ? productSmokeLaunchOptions() : {}) });
    try {
      const context = await browser.newContext({ viewport: { width: 1280, height: 900 } });
      context.setDefaultTimeout(10_000);
      context.setDefaultNavigationTimeout(15_000);
      await context.addCookies([{
        name: process.env.ELASTOS_CAPSULE_SCRIPT_COOKIE_NAME,
        value: token, url: origin, httpOnly: false, sameSite: 'Lax',
      }]);
      // Positive control: this origin really serves an executable script.
      const control = await context.newPage();
      await control.goto(`${origin}/healthz`);
      await control.addScriptTag({ url: foreignUrl });
      assert.equal(await control.evaluate(() => globalThis.foreignScriptExecuted), true);
      await control.close();
      const page = await context.newPage();
      const policies = new Map();
      page.on('response', response => {
        if (response.request().resourceType() === 'document') {
          policies.set(new URL(response.url()).pathname, response.headers()['content-security-policy']);
        }
      });
      const host = await page.goto(`${origin}/home/`, { waitUntil: 'domcontentloaded' });
      assert.equal(host.status(), 200);
      assert.equal(host.headers()['content-security-policy'], "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' blob: data:; connect-src 'self'; frame-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");
      for (const app of ['home-gui', 'documents', 'library']) {
        try {
          if (app !== 'home-gui') {
            const route = await page.evaluate(async ({ app, token, origin }) => {
              const response = await fetch('/api/apps/home/launch', {
                method: 'POST', signal: AbortSignal.timeout(10_000),
                headers: { 'content-type': 'application/json', 'x-elastos-home-token': token },
                body: JSON.stringify({ target: app, query: { home_origin: origin } }),
              });
              if (!response.ok) throw new Error(`launch ${app}: HTTP ${response.status}`);
              return (await response.json()).route;
            }, { app, token, origin });
            // Mount under the real host even if the GUI cannot boot. This lets
            // a failing engine report all three apps rather than just the GUI.
            await page.evaluate(({ app, route }) => {
              const iframe = document.createElement('iframe');
              iframe.id = `script-check-${app}`;
              iframe.style = 'position:fixed;inset:0;width:100%;height:100%;z-index:2147483647';
              iframe.setAttribute('sandbox', 'allow-scripts allow-forms allow-downloads');
              iframe.src = route;
              document.body.append(iframe);
            }, { app, route });
          }
          await page.waitForFunction(app => [...document.querySelectorAll('iframe')]
            .some(frame => frame.src.includes(`/apps/${app}/`)), app);
          const frame = await page.waitForEvent('framenavigated', {
            predicate: frame => new URL(frame.url()).pathname === `/apps/${app}/`, timeout: 1000,
          }).catch(() => page.frames().find(frame => frame.url().includes(`/apps/${app}/`)));
          assert.ok(frame, `${app}: product frame exists`);
          await frame.waitForLoadState('domcontentloaded');
          assert.equal(await frame.evaluate(() => self.origin), 'null', `${app}: opaque origin`);
          const policy = policies.get(`/apps/${app}/`);
          assert.ok(policy?.startsWith('sandbox allow-scripts allow-forms allow-downloads; '), `${app}: real sandbox header`);
          assert.ok(!policy.includes('allow-same-origin'), `${app}: sandbox keeps origin isolation`);
          // Observe a CSP violation as well as the absence of script effects.
          // CORS, COEP or an unavailable server alone cannot satisfy this check.
          const before = foreignRequests;
          const blocked = await frame.evaluate(url => new Promise(resolve => {
            const timer = setTimeout(() => resolve(null), 5000);
            document.addEventListener('securitypolicyviolation', event => {
              if (event.blockedURI === url && event.effectiveDirective.startsWith('script-src')) {
                clearTimeout(timer);
                resolve({ directive: event.effectiveDirective, executed: !!globalThis.foreignScriptExecuted });
              }
            });
            const script = document.createElement('script');
            script.src = url;
            document.body.append(script);
          }), foreignUrl);
          assert.ok(blocked, `${app}: foreign script refused by script-src`);
          assert.equal(blocked.executed, false);
          assert.equal(foreignRequests, before, `${app}: foreign server received no script request`);
          await frame.waitForFunction(app => {
            if (app === 'home-gui') return document.body.dataset.homeStatus === 'ready' && !!document.querySelector('#desktop');
            if (app === 'documents') return !!document.querySelector('#documents-shell') && !document.querySelector('#documents-shell').classList.contains('hidden');
            return typeof window.__libraryPerf === 'object' && !!document.querySelector('#library-shell') && !document.querySelector('#library-shell').classList.contains('hidden');
          }, app);
          if (app === 'documents') {
            await frame.locator('#new-document').click();
            await frame.locator('#title-input').waitFor({ state: 'visible' });
          }
          assert.equal(await frame.evaluate(() => self.origin), 'null');
          console.log(`PASS ${engine} ${browser.version()} ${app}: scripts run; origin null; foreign script blocked`);
        } catch (error) {
          // Playwright errors can include frame URLs; keep launch tokens private.
          failures.push(`${engine} ${app}: ${String(error.message).replace(/home_token=[^\s"'&]+/g, 'home_token=<redacted>')}`);
          console.error(`FAIL ${engine} ${app}: script/isolation regression`);
        }
      }
      if (process.env.ELASTOS_CAPSULE_SCRIPT_SCREENSHOTS) {
        await mkdir(process.env.ELASTOS_CAPSULE_SCRIPT_SCREENSHOTS, { recursive: true });
        for (const width of [1280, 390]) {
          await page.setViewportSize({ width, height: 900 });
          await page.screenshot({ path: join(process.env.ELASTOS_CAPSULE_SCRIPT_SCREENSHOTS, `${engine}-${width}.png`) });
        }
      }
      await context.close();
    } finally {
      await browser.close();
    }
  }
} finally {
  await new Promise(resolve => foreign.close(resolve));
}
assert.deepEqual(failures, [], failures.join('\n'));
