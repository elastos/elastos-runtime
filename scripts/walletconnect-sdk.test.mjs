import assert from "node:assert/strict";
import test from "node:test";
import http from "node:http";
import { readFileSync, mkdirSync } from "node:fs";
import { createRequire } from "node:module";
const require = createRequire(new URL("../elastos/tools/browser-playwright-engine/package.json", import.meta.url));
const { chromium } = require("playwright");
const bundle = readFileSync(new URL("../capsules/wallet-walletconnect/vendor/reown-appkit.js", import.meta.url));

const fixture = readFileSync(new URL("./lib/walletconnect-browser-fixture.mjs", import.meta.url));

test("the locked SDK reaches QR through Home, stores its keys through Runtime, and cancels", { timeout: 45000 }, async () => {
  const server = http.createServer((req, res) => {
    res.setHeader("content-security-policy", "default-src 'self'; script-src 'self'; connect-src 'self'; frame-src 'self'; style-src 'self'");
    if (req.url === "/vendor/reown-appkit.js") { res.setHeader("content-type", "text/javascript"); res.end(bundle); }
    else if (req.url === "/fixture.js") { res.setHeader("content-type", "text/javascript"); res.end(fixture); }
    else { res.setHeader("content-type", "text/html"); res.end('<!doctype html><meta name="viewport" content="width=device-width"><script type="module" src="/fixture.js"></script>'); }
  });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  let browser;
  try {
    browser = await chromium.launch({ headless: true });
    for (const width of [1280, 390]) {
      const context = await browser.newContext({ viewport: { width, height: 800 } });
      // CSP remains the same Home-only network boundary used by the product.
      await context.route("**/*", route => new URL(route.request().url()).origin === origin ? route.continue() : route.abort());
      const page = await context.newPage();
      const pageErrors = [];
      page.on("pageerror", error => pageErrors.push(error.message));
      await page.goto(origin);
      try {
        await page.locator("dialog[open] canvas").waitFor({ timeout: 20000 });
      } catch (cause) {
        const state = await page.evaluate(() => ({ failed: window.failed, methods: window.methods,
          nativeOrigins: window.nativeUrls.map(url => new URL(url).origin) }));
        throw new Error(`SDK fixture did not reach QR: ${JSON.stringify({ pageErrors, state })}`, { cause });
      }
      try {
        await page.waitForFunction(() => window.proposalReady
          && Object.keys(window.keys).some(key => key.includes("keychain")), null, { timeout: 10000 });
      } catch (cause) {
        const state = await page.evaluate(() => ({ methods: window.methods, proposalReady: window.proposalReady, keyNames: Object.keys(window.keys),
          localKeyCount: localStorage.length, nativeOrigins: window.nativeUrls.map(url => new URL(url).origin) }));
        throw new Error(`SDK relay/storage not ready: ${JSON.stringify(state)}`, { cause });
      }
      const state = await page.evaluate(() => ({
        homeOnly: window.nativeUrls.length > 0 && window.nativeUrls.every(url => url === location.origin.replace(/^http/, "ws") + "/relay"),
        proposed: window.proposalReady,
        runtimeKeys: Object.keys(window.keys).some(key => key.includes("keychain")),
        localKeys: localStorage.length,
        canvas: document.querySelector("canvas").width,
        fits: document.querySelector("dialog").getBoundingClientRect().width <= innerWidth,
      }));
      assert.equal(state.homeOnly, true, "SDK sockets terminate at Home");
      assert.equal(state.proposed, true, "the pinned SDK publishes its pairing proposal through Home");
      assert.equal(state.runtimeKeys, true, "SDK keychain reaches the Runtime storage adapter");
      assert.equal(state.localKeys, 0);
      assert.ok(state.canvas > 0);
      assert.equal(state.fits, true);
      if (process.env.WALLETCONNECT_SCREENSHOTS) {
        mkdirSync(process.env.WALLETCONNECT_SCREENSHOTS, { recursive: true });
        await page.screenshot({ path: `${process.env.WALLETCONNECT_SCREENSHOTS}/qr-${width}.png` });
      }
      await page.getByRole("button", { name: "Cancel", exact: true }).click();
      await page.waitForFunction(() => window.cancelled);
      assert.equal(await page.locator("dialog").count(), 0);
      await context.close();
    }
  } finally {
    await browser?.close();
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  }
});
