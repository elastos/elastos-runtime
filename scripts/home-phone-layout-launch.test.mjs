import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

for (const engine of ["chromium", "webkit"]) {
  test(`phone smoke leaves ${engine}'s executable selection with its owner`, () => {
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
          HOME_PHONE_SMOKE_OUT: join(directory, "output") },
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
