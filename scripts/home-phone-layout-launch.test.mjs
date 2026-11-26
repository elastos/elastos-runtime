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

for (const failure of ["Home GUI frame", "Home bootstrap"]) {
  test(`phone smoke replaces a stalled GUI context and preserves ${failure} failure evidence`, () => {
    const directory = mkdtempSync(join(tmpdir(), "phone-layout-boot-"));
    try {
      const module = join(directory, "playwright.mjs");
      writeFileSync(module, `
        import assert from 'node:assert/strict';
        let contexts = 0;
        let pages = 0;
        let closed = false;
        let firstOptions;
        const engine = {
          name: () => 'webkit',
          executablePath: () => ${JSON.stringify(module)},
          async launch() {
            return {
              async newContext(options) {
                contexts += 1;
                if (contexts === 1) firstOptions = options;
                else {
                  assert.equal(contexts, 2, 'one boot retry only');
                  assert.equal(closed, true, 'retire the failed context first');
                  assert.deepEqual(options, firstOptions, 'preserve the device profile');
                }
                const generation = contexts;
                return {
                  async newPage() {
                    pages += 1;
                    if (pages === 1) throw new Error('timed out waiting for ${failure}: FRAME_STATE_FIRST');
                    assert.equal(generation, 2, 'boot retry needs a fresh browser context');
                    throw new Error('timed out waiting for Home GUI frame: FRAME_STATE_SECOND');
                  },
                  pages: () => [],
                  async close() { closed = true; },
                };
              },
              async close() {
                assert.equal(contexts, ${failure === "Home GUI frame" ? 2 : 1});
                assert.equal(pages, ${failure === "Home GUI frame" ? 2 : 1});
                assert.equal(closed, true, 'close the final context');
              },
            };
          },
        };
        export const chromium = engine;
        export const webkit = engine;
      `);
      const result = spawnSync(process.execPath, ["scripts/home-phone-layout-smoke.mjs"], {
        cwd: new URL("../", import.meta.url),
        env: { ...process.env, ELASTOS_PLAYWRIGHT_MODULE: module,
          HOME_PHONE_SMOKE_ENGINES: "webkit", HOME_PHONE_SMOKE_PROFILES: "phone-portrait",
          HOME_PHONE_SMOKE_CASE: "", HOME_PHONE_FRAME_TRACE: "", HOME_PHONE_SMOKE_OUT: join(directory, "output") },
        encoding: "utf8", timeout: 10_000,
      });
      assert.equal(result.error, undefined);
      assert.equal(result.status, 1, 'a repeated boot failure still fails the smoke');
      assert.match(result.stderr, failure === "Home GUI frame" ? /FRAME_STATE_SECOND/ : /Home bootstrap: FRAME_STATE_FIRST/);
      assert.doesNotMatch(result.stderr, /AssertionError/);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });
}
