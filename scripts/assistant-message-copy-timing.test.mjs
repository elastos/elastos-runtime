import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";

const root = fileURLToPath(new URL("../", import.meta.url));

// Run the real smoke and product. Browser DOM faults check the observation
// contract without changing product source or its success text.
function runSmoke(mode, signal) {
  const script = `
    import assert from "node:assert/strict";
    import { chromium } from "./scripts/system-uiux-fixture.mjs";
    const launch = chromium.launch.bind(chromium);
    let exercised = false;
    chromium.launch = async (...args) => {
      const browser = await launch(...args);
      const newContext = browser.newContext.bind(browser);
      browser.newContext = async (...args) => {
        const context = await newContext(...args);
        const newPage = context.newPage.bind(context);
        context.newPage = async (...args) => {
          const page = await newPage(...args);
          const locator = page.locator.bind(page);
          page.locator = (...args) => {
            const found = locator(...args);
            if (args[0] === "#home-clipboard-allow") {
              const click = found.click.bind(found);
              found.click = async (...args) => {
                if (!exercised && ${JSON.stringify(mode)} === "pending-write") {
                  await page.evaluate(() => {
                    navigator.clipboard.writeText = () => new Promise(() => {});
                  });
                }
                await click(...args);
                if (exercised) return;
                exercised = true;
                const status = page.frameLocator("#gui").frameLocator("iframe")
                  .locator(".agent-msg").first().locator(".agent-copy-status");
                if (${JSON.stringify(mode)} === "expired-before-return") {
                  await status.waitFor({ state: "visible", timeout: 10000 });
                  await status.waitFor({ state: "detached", timeout: 10000 });
                  console.log("fault: feedback expired before click returned");
                } else if (${JSON.stringify(mode)} === "short-status") {
                  await status.waitFor({ state: "visible", timeout: 10000 });
                  await status.evaluate(node => setTimeout(() => node.remove(), 100));
                  console.log("fault: feedback removed after 100 ms");
                }
              };
            }
            return found;
          };
          return page;
        };
        return context;
      };
      return browser;
    };
    await import("./scripts/assistant-message-copy-browser-smoke.mjs");
    assert.equal(exercised, true);
  `;
  return new Promise(resolve => {
    execFile(process.execPath, ["--input-type=module", "-e", script], { cwd: root, signal }, (error, stdout, stderr) => {
      resolve({ code: error?.code ?? 0, stdout, stderr });
    });
  });
}

for (const mode of ["expired-before-return", "short-status", "pending-write"]) {
  test(`Copy smoke rejects ${mode}`, async t => {
    const result = await runSmoke(mode, t.signal);
    if (mode !== "pending-write") assert.match(result.stdout, /fault: feedback/);
    assert.equal(result.code, 1, result.stderr);
    assert.match(result.stderr, /Assistant message copy smoke failed at sent message/);
    assert.match(result.stderr, /Copy feedback failed/);
    assert.match(result.stderr, /"statusText":/);
    assert.match(result.stderr, mode === "pending-write" ? /"data-copy-pending":"1"/ : /"data-copy-pending":null/);
    assert.match(result.stderr, /"written":\["Why is the sky blue/);
    assert.match(result.stderr, /"button":\{/);
    assert.match(result.stderr, mode === "pending-write" ? /"state":"pending"/ : /"state":"fulfilled"/);
    assert.match(result.stderr, /"prompt":\{"hidden":true/);
  });
}
