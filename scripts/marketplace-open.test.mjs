import test from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

for (const [kind, title] of [
  ["connectors", "Marketplace lists all three connectors with Wallet directions and no standalone Open"],
  ["assistant", "Marketplace Open shows Assistant on screen and preserves model handoff validation"],
]) {
  test(title, { timeout: 75000 }, async () => {
    const { stdout } = await promisify(execFile)(process.execPath,
      ["scripts/home-wallet-connector-launch-headless-smoke.mjs"], {
        env: { ...process.env, HOME_WALLET_CONNECTOR_ENGINE: "chromium", MARKETPLACE_OPEN_CASE: kind }, timeout: 70000,
      });
    assert.match(stdout, new RegExp(`\\[marketplace-open\\] PASS ${kind}`));
    process.stdout.write(stdout);
  });
}
