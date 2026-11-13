import assert from "node:assert/strict";
import test from "node:test";
import http from "node:http";
import { readFileSync } from "node:fs";
import { requireProductSmokePlaywright } from "./product-smoke-browser.mjs";
import { exerciseStorage } from "./lib/walletconnect-storage-probe.mjs";

const shim = readFileSync(new URL("../capsules/wallet-walletconnect/browser/walletconnect-storage.mjs", import.meta.url));

for (const engine of ["chromium", "webkit"]) {
  test(`capsule memory Storage matches native ${engine} Storage`, { timeout: 45000 }, async () => {
    const server = http.createServer((req, res) => {
      res.setHeader("content-type", req.url === "/shim.mjs" ? "text/javascript" : "text/html");
      res.end(req.url === "/shim.mjs" ? shim : "<!doctype html><title>Storage comparison</title>");
    });
    await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
    let browser;
    try {
      browser = await requireProductSmokePlaywright()[engine].launch({ headless: true });
      const page = await browser.newPage();
      await page.goto(`http://127.0.0.1:${server.address().port}`);
      const native = await page.evaluate(exerciseStorage);
      await page.evaluate(async () => {
        const { installWalletConnectStorage } = await import("/shim.mjs");
        window.clearMemoryStorage = installWalletConnectStorage(window);
      });
      const memory = await page.evaluate(exerciseStorage);
      assert.deepEqual(memory, native);
      assert.deepEqual(await page.evaluate(() => {
        const errors = [];
        for (const name of ["localStorage", "sessionStorage"]) {
          for (const write of [
            s => s.setItem("wc@2:core:0.3//keychain", "fixture"),
            s => { s["wc@2:client:0.3//session"] = "fixture"; },
            s => Object.defineProperty(s, "wc@2:core:0.3//pairing", { value: "fixture" }),
          ]) {
            try { write(window[name]); errors.push("accepted"); }
            catch (error) { errors.push(error.name); }
          }
          window[name].setItem("wallet-choice", "fixture");
        }
        window.clearMemoryStorage();
        return { errors, lengths: [localStorage.length, sessionStorage.length] };
      }), { errors: Array(6).fill("SecurityError"), lengths: [0, 0] });
    } finally {
      await browser?.close();
      server.closeAllConnections();
      await new Promise(resolve => server.close(resolve));
    }
  });
}
