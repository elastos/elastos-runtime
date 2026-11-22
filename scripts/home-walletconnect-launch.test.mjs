import {windowTestOptions} from './lib/walletconnect-window-resources.mjs';
import test from "node:test";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

test("Wallet opens each connector in a separate bounded Home window and closes it", { timeout: 75000 }, async () => {
  await import("./home-wallet-connector-launch-headless-smoke.mjs");
});

test("Home forwards connector account hints to the kept-open Wallet in WebKit", windowTestOptions('webkit',90000), async () => {
  await promisify(execFile)(process.execPath, ["scripts/home-wallet-connector-launch-headless-smoke.mjs"], {
    env: {...process.env, HOME_WALLET_CONNECTOR_ENGINE:"webkit"}, timeout:85000,
  });
});

for (const engine of ["chromium", "webkit"]) {
  test(`Wallet's phone Connect path keeps each connector in front in ${engine}`, windowTestOptions(engine,90000), async () => {
    const { stdout } = await promisify(execFile)(process.execPath, ["scripts/home-wallet-connector-launch-headless-smoke.mjs"], {
      env: {...process.env, HOME_WALLET_CONNECTOR_ENGINE:engine, WALLET_PHONE_OPEN:"1"}, timeout:85000,
    });
    process.stdout.write(stdout);
  });
}
