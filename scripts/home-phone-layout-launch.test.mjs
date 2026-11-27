import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

for (const [engine, smokeCase] of [
  ["chromium", ""], ["webkit", ""],
  ["chromium", "closed-stream"], ["webkit", "closed-stream"],
]) {
  test(`phone smoke ${smokeCase || "all"} leaves ${engine}'s executable selection with its owner`, () => {
    const directory = mkdtempSync(join(tmpdir(), "phone-layout-launch-"));
    try {
      const module = join(directory, "playwright.mjs");
      writeFileSync(module, `
        import assert from 'node:assert/strict';
        const engine = {
          name: () => ${JSON.stringify(engine)},
          executablePath: () => ${JSON.stringify(module)},
          async launch(options) {
            assert.equal(options.headless, true);
            ${engine === "webkit"
              ? "assert.equal(options.executablePath, undefined, 'shared WebKit wrapper owns its default executable'); assert.deepEqual(options.args, []);"
              : `assert.equal(options.executablePath, ${JSON.stringify(module)}); assert.ok(options.args.includes('--no-proxy-server'));`}
            throw new Error('PHONE_LAUNCH_OPTIONS_VERIFIED');
          },
        };
        export const chromium = engine;
        export const webkit = engine;
      `);
      const result = spawnSync(process.execPath, ["scripts/home-phone-layout-smoke.mjs"], {
        cwd: new URL("../", import.meta.url),
        env: { ...process.env, ELASTOS_PLAYWRIGHT_MODULE: module,
          ELASTOS_BROWSER_EXECUTABLE: module, HOME_PHONE_SMOKE_ENGINES: engine,
          HOME_PHONE_SMOKE_OUT: join(directory, "output"), HOME_PHONE_SMOKE_CASE: smokeCase || "" },
        encoding: "utf8", timeout: 10_000,
      });
      assert.equal(result.error, undefined);
      assert.equal(result.status, 1);
      assert.match(result.stderr, /PHONE_LAUNCH_OPTIONS_VERIFIED/);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });
}

test("phone smoke rejects an unknown case before starting a browser", () => {
  const result = spawnSync(process.execPath, ["scripts/home-phone-layout-smoke.mjs"], {
    cwd: new URL("../", import.meta.url),
    env: { ...process.env, HOME_PHONE_SMOKE_CASE: "unknown",
      ELASTOS_PLAYWRIGHT_MODULE: "/phone-case-validation/absent-playwright.mjs" },
    encoding: "utf8", timeout: 10_000,
  });
  assert.equal(result.error, undefined);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /unsupported phone smoke case unknown/);
});

for (const [smoke, failure, closeFails = false] of [
  ["phone", "Home GUI frame"], ["phone", "Home bootstrap"],
  ["wallet", "real Home GUI frame"], ["wallet", "real Home GUI frame", true],
]) {
  const failureMessage = `timed out waiting for ${failure}`;
  test(closeFails ? "wallet smoke reports browser close failure and releases its server"
    : `${smoke} smoke preserves ${failure} failure evidence without retrying`, () => {
    const directory = mkdtempSync(join(tmpdir(), "phone-layout-boot-"));
    try {
      const module = join(directory, "playwright.mjs");
      writeFileSync(module, `
        import assert from 'node:assert/strict';
        let contexts = 0;
        let pages = 0;
        const openContexts = new Set();
        const engine = {
          name: () => 'webkit',
          executablePath: () => ${JSON.stringify(module)},
          async launch() {
            const contextClosers = [];
            return {
              async newContext(options) {
                contexts += 1;
                const contextId = contexts;
                openContexts.add(contextId);
                console.log('BOOT_CONTEXT_CREATED');
                const close = async () => {
                  if (openContexts.delete(contextId)) console.log('BOOT_CONTEXT_CLOSED');
                };
                contextClosers.push(close);
                return {
                  async addInitScript() {},
                  async newPage() {
                    pages += 1;
                    throw new Error(${JSON.stringify(failureMessage)});
                  },
                  pages: () => [],
                  close,
                };
              },
              async close() {
                assert.equal(pages, contexts);
                for (const close of contextClosers) await close();
                assert.equal(openContexts.size, 0, 'browser close retires its contexts');
                ${closeFails ? "throw new Error('WALLET_BROWSER_CLOSE_FAILED');" : ""}
              },
            };
          },
        };
        export const chromium = engine;
        export const webkit = engine;
      `);
      const result = spawnSync(process.execPath, [smoke === "phone" ? "scripts/home-phone-layout-smoke.mjs" : "scripts/home-wallet-connector-launch-headless-smoke.mjs"], {
        cwd: new URL("../", import.meta.url),
        env: { ...process.env, ELASTOS_PLAYWRIGHT_MODULE: module,
          HOME_WALLET_CONNECTOR_ENGINE: "webkit", WALLET_CONNECT_RETURN: smoke === "wallet" ? "1" : "",
          HOME_PHONE_SMOKE_ENGINES: "webkit", HOME_PHONE_SMOKE_PROFILES: "phone-portrait",
          HOME_PHONE_SMOKE_CASE: "", HOME_PHONE_FRAME_TRACE: "", HOME_PHONE_SMOKE_OUT: join(directory, "output") },
        encoding: "utf8", timeout: 10_000,
      });
      assert.equal(result.error, undefined);
      assert.equal(result.status, 1, 'the first boot failure fails the smoke');
      assert.ok(result.stderr.includes(closeFails ? "WALLET_BROWSER_CLOSE_FAILED" : failureMessage), result.stderr);
      assert.doesNotMatch(result.stderr, /AssertionError/);
      assert.equal(result.stdout.match(/BOOT_CONTEXT_CREATED/g)?.length || 0, smoke === "phone" ? 1 : 2,
        "one cold context per profile, with no boot retry");
      assert.equal(result.stdout.match(/BOOT_CONTEXT_CLOSED/g)?.length || 0, smoke === "phone" ? 1 : 2,
        "close every context");
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });
}
