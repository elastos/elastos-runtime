// The source gateway test supplies the documents, headers and pinned SDK.
import assert from "node:assert/strict";
import { mkdir, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { importProductSmokePlaywright } from "./product-smoke-browser.mjs";
import { exerciseStorage } from "./lib/walletconnect-storage-probe.mjs";

const origin = process.env.ELASTOS_WALLETCONNECT_SANDBOX_URL;
assert.ok(origin, "the source Runtime supplies the Home URL");
const evidence = process.env.WALLETCONNECT_SCREENSHOTS;
if (evidence) await mkdir(evidence, { recursive: true });
const expectedHash = "6cff318e63fa0b8c9cc7ee95ce92d5a5470df6cd742a8ad8c2033ce829bb1895";
const sdk = await fetch(`${origin}/apps/wallet-walletconnect/vendor/reown-appkit.js`);
assert.equal(sdk.status, 200);
assert.equal(createHash("sha256").update(Buffer.from(await sdk.arrayBuffer())).digest("hex"), expectedHash);
for (const path of ["capsule.json", "wallet-walletconnect.wasm", "vendor/package-lock.json", "vendor/other.js"]) {
  assert.equal((await fetch(`${origin}/apps/wallet-walletconnect/${path}`)).status, 404, path);
}
const result = { sdkSha256: expectedHash, runs: [] };
const failures = [];
const playwright = await importProductSmokePlaywright();
for (const engine of ["chromium", "webkit"]) {
  const browser = await playwright[engine].launch({ headless: true });
  try {
    for (const width of [1280, 390]) {
      const context = await browser.newContext({ viewport: { width, height: 850 } });
      const page = await context.newPage();
      const errors = [];
      page.on("pageerror", error => errors.push(error.message));
      // Block foreign traffic. Product CSP remains untouched.
      await context.route("**/*", route => new URL(route.request().url()).origin === origin ? route.continue() : route.abort());
      const run = { engine, version: browser.version(), width, errors };
      try {
        const home = await page.goto(`${origin}/apps/home/`);
        assert.equal(home.status(), 200);
        const doc = await fetch(`${origin}/apps/wallet-walletconnect/wc-frame.html`);
        run.headers = Object.fromEntries(doc.headers);
        assert.equal(run.headers["content-security-policy"], `sandbox allow-scripts allow-forms allow-downloads; default-src ${origin}; script-src 'self' 'wasm-unsafe-eval' ${origin}; style-src ${origin} 'unsafe-inline'; img-src ${origin} blob: data:; connect-src ${origin} ${origin.replace(/^http/, "ws")}; frame-src ${origin}; object-src 'none'; base-uri 'none'; form-action ${origin}`);
        await page.evaluate(url => {
          const frame = document.createElement("iframe");
          frame.setAttribute("sandbox", "allow-downloads allow-forms allow-modals allow-pointer-lock allow-scripts");
          frame.src = url;
          frame.style = "position:fixed;inset:0;width:100%;height:100%;z-index:999999";
          document.body.append(frame);
        }, `${origin}/apps/wallet-walletconnect/wc-frame.html`);
        const frame = page.frameLocator('iframe[src$="/wc-frame.html"]');
        await frame.locator("dialog[open] canvas").waitFor({ timeout: 20000 });
        const actualFrame = page.frames().find(f => f.url().endsWith("/wc-frame.html"));
        await actualFrame.waitForFunction(() => window.proposalReady && Object.keys(window.keys).some(key => key.includes("keychain")));
        run.state = await actualFrame.evaluate(() => {
          const canvas = document.querySelector("canvas");
          const pixels = canvas.getContext("2d").getImageData(0, 0, canvas.width, canvas.height).data;
          let black = 0, white = 0;
          for (let i = 0; i < pixels.length; i += 4) {
            if (pixels[i + 3] === 255) { if (pixels[i] < 10) black++; if (pixels[i] > 240) white++; }
          }
          return { origin: self.origin, crypto: !!crypto.subtle, failed: window.failed,
            runtimeTrace: window.runtimeTrace, storageTrace: window.storageTrace,
            proposal: window.proposalReady, canvas: canvas.width, black, white,
            fits: document.querySelector("dialog").getBoundingClientRect().width <= innerWidth };
        });
        assert.equal(run.state.origin, "null");
        assert.equal(run.state.crypto, true);
        assert.equal(run.state.failed, false);
        assert.ok(run.state.black && run.state.white);
        assert.equal(run.state.fits, true);
        assert.ok(run.state.runtimeTrace.some(t => t.key.includes("keychain")));
        assert.ok(run.state.storageTrace.every(t => !t.refused));
        if (evidence) await page.screenshot({ path: `${evidence}/${engine}-${width}.png` });
        run.native = await page.evaluate(exerciseStorage);
        run.memory = await actualFrame.evaluate(exerciseStorage);
        assert.deepEqual(run.memory, run.native);
        run.refusals = await actualFrame.evaluate(() => {
          const results = [];
          for (const name of ["localStorage", "sessionStorage"]) for (const write of [
            s => s.setItem("wc@2:core:0.3//keychain", "fixture"),
            s => { s["wc@2:client:0.3//session"] = "fixture"; },
            s => Object.defineProperty(s, "wc@2:core:0.3//pairing", { value: "fixture" }),
          ]) {
            try { write(window[name]); results.push("accepted"); }
            catch (error) { results.push(error.name); }
          }
          return results;
        });
        assert.deepEqual(run.refusals, Array(6).fill("SecurityError"));
        await frame.getByRole("button", { name: "Cancel", exact: true }).click();
        await actualFrame.waitForFunction(() => window.cancelled);
        assert.equal(await frame.locator("dialog").count(), 0);
        run.cancelled = true;
        console.log(`PASS ${engine} ${width}: opaque SDK, QR, Runtime writes, native Storage parity, protocol refusal, Cancel`);
      } catch (error) {
        run.failure = error.message;
        failures.push(`${engine} ${width}: ${error.message}`);
      } finally {
        result.runs.push(run);
        await context.close();
      }
    }
  } finally { await browser.close(); }
}
if (evidence) await writeFile(`${evidence}/step0b.json`, JSON.stringify(result, null, 2));
console.log(JSON.stringify(result));
assert.deepEqual(failures, []);
