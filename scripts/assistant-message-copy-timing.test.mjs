import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";

const root = fileURLToPath(new URL("../", import.meta.url));

// Run the real smoke and product. Only control when the driver's confirmation
// click returns, or remove the product's success report to check the smoke.
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
        if (${JSON.stringify(mode)} === "missing-status") {
          await context.route(/\\/apps\\/assistant\\/harness-host\\.js/, async route => {
            const response = await route.fetch();
            const source = await response.text();
            const body = source.replace('showCopyStatus(button, "Copied", true);', "/* success report withheld */");
            assert.notEqual(body, source, "fixture removes the success report");
            await route.fulfill({ response, body });
          });
        }
        const newPage = context.newPage.bind(context);
        context.newPage = async (...args) => {
          const page = await newPage(...args);
          const locator = page.locator.bind(page);
          page.locator = (...args) => {
            const found = locator(...args);
            if (args[0] === "#home-clipboard-allow") {
              const click = found.click.bind(found);
              found.click = async (...args) => {
                await click(...args);
                if (exercised) return;
                exercised = true;
                if (${JSON.stringify(mode)} === "delayed-driver") {
                  const status = page.frameLocator("#gui").frameLocator("iframe")
                    .locator(".agent-msg").first().locator(".agent-copy-status");
                  await status.filter({ hasText: "Copied" }).waitFor({ timeout: 10000 });
                  await status.waitFor({ state: "detached", timeout: 10000 });
                  console.log("driver resumed after visible Copied status expired");
                } else {
                  await page.waitForFunction(() => window.__home.written.length === 1, null, { timeout: 10000 });
                  assert.equal(await page.evaluate(() => navigator.clipboard.readText()),
                    await page.evaluate(() => window.__home.written[0]));
                  console.log("clipboard written with success report withheld");
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

test("Copy smoke observes visible success before a delayed driver resumes", async t => {
  const result = await runSmoke("delayed-driver", t.signal);
  assert.match(result.stdout, /driver resumed after visible Copied status expired/);
  assert.equal(result.code, 0, result.stderr);
  assert.match(result.stdout, /PASS Assistant Copy/);
});

test("Copy smoke fails when the clipboard is written but Copy never reports success", async t => {
  const result = await runSmoke("missing-status", t.signal);
  assert.match(result.stdout, /clipboard written with success report withheld/);
  assert.equal(result.code, 1, result.stderr);
  assert.match(result.stderr, /Assistant message copy smoke failed at sent message/);
  assert.match(result.stderr, /locator\.waitFor: Timeout 10000ms exceeded/);
});
