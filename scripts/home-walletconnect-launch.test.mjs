import test from "node:test";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

test("Wallet opens each connector in a separate bounded Home window and closes it", { timeout: 75000 }, async () => {
  await import("./home-wallet-connector-launch-headless-smoke.mjs");
});

test("Home forwards connector account hints to the kept-open Wallet in WebKit", {timeout:90000}, async () => {
  await promisify(execFile)(process.execPath, ["scripts/home-wallet-connector-launch-headless-smoke.mjs"], {
    env: {...process.env, HOME_WALLET_CONNECTOR_ENGINE:"webkit"}, timeout:85000,
  });
});
