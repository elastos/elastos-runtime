import test from "node:test";

test("Wallet opens each connector in a separate bounded Home window and closes it", { timeout: 45000 }, async () => {
  await import("./home-wallet-connector-launch-headless-smoke.mjs");
});
