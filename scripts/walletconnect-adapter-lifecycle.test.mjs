import test from "node:test";
import assert from "node:assert/strict";
import { register } from "node:module";
register(new URL("./lib/walletconnect-adapter-loader.mjs", import.meta.url));

test("the real adapter resumes restored sessions and refreshes authority before reconnect or disconnect", async () => {
  let initialized = 0, opened = 0, closed = 0, disconnected = 0, paired = 0;
  const providers = [];
  let sdkOptions;
  globalThis.walletConnectSdkFixture = async options => {
    initialized++; sdkOptions = options;
    const provider = {
      connected: true, session: { topic: "restored-session", expiry: Math.floor(Date.now() / 1000) + 600 },
      signer: { client: { core: { relayer: {
        transportOpen: async () => { opened++; },
        transportClose: async () => { closed++; },
      } } } },
      connect: async () => {
        assert.ok(provider.session.expiry < Date.now() / 1000, "an unexpired restored session needs no new pairing");
        paired++;
        provider.session.expiry = Math.floor(Date.now() / 1000) + 600;
      },
      on() {}, removeListener() {},
      disconnect: async () => { disconnected++; },
    };
    providers.push(provider);return provider;
  };
  const { connectWalletConnectEvm, disconnectWalletConnectEvm } = await import("./walletconnect/adapter.mjs");
  const calls = [];
  const options = {
    contextKey: "principal-one", chains: [1], projectId: "fixture-project",
    relayUrl: "ws://home.test/relay", runtimeUrl: "http://home.test/api/apps/wallet-walletconnect",
    api: async (...args) => { calls.push(["old", ...args]);return {}; },
  };
  assert.equal(await connectWalletConnectEvm(options), providers[0]);
  assert.equal(initialized, 1);assert.equal(opened, 1);
  // A fresh launch for the same principal must update the API used by persisted Core.
  const api = async (...args) => { calls.push(["fresh", ...args]);return {}; };
  assert.equal(await connectWalletConnectEvm({ ...options, api }), providers[0]);
  await sdkOptions.storage.setItem("session", { topic: "same-pairing" });
  assert.equal(calls.at(-1)[0], "fresh");
  assert.equal(initialized, 1);assert.equal(opened, 2);
  await disconnectWalletConnectEvm({ api });
  assert.equal(disconnected, 1);assert.equal(closed, 1);
  assert.equal(calls.some(call => call[1].includes("account")), false, "disconnect leaves wallet-provider accounts intact");
  assert.equal(await connectWalletConnectEvm({ ...options, contextKey: "principal-two", api }), providers[1]);
  assert.equal(initialized, 2);
  assert.equal(paired, 0);
  providers[1].session.expiry = 1;
  let removed = 0;
  globalThis.document = {
    createElement: () => ({ append() {}, addEventListener() {}, remove() { removed++; } }),
    body: { append() {} },
  };
  await connectWalletConnectEvm({ ...options, contextKey: "principal-two", api });
  assert.equal(paired, 1, "an expired session requires a fresh phone pairing even when the relay is connected");
  assert.equal(removed, 1);
  delete globalThis.document;
  delete globalThis.walletConnectSdkFixture;
});
