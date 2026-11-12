import { test } from "node:test";
import assert from "node:assert/strict";
import { pathToFileURL } from "node:url";
import { resolve } from "node:path";

const address = `0x${"12".repeat(20)}`;
const payloadHash = `0x${"34".repeat(32)}`;
const signature = `0x${"ab".repeat(65)}`;
const linkMessage = "Runtime ownership proof · fixture";
const linkMessages = { "link-uppercase-hex": "0X4142", "link-odd-hex": "0x123" };
const transactionHash = `0x${"56".repeat(32)}`;
const origin = "http://localhost:61180";
const connector = "wallet-walletconnect";

async function fixture(scenario) {
  globalThis.document = { querySelector() { return null; } };
  globalThis.location = { origin };
  globalThis.window = { addEventListener() {}, dispatchEvent() {} };
  const { setHomeAuthorityToken } = await import("../capsules/home/browser/shell-core.js?v=home-wallpaper-20261030b");
  setHomeAuthorityToken("home-authority-fixture");
  const host = await import(`../capsules/home/browser/home-wallet-connector-host.js?fixture=${scenario}`);
  const calls = [];
  globalThis.__wcFixtureProvider = {
    connected: true, on() {},
    async request(input, expiry) {
      calls.push({ ...input, expiry });
      if (input.method === "eth_requestAccounts") return [address];
      if (input.method === "personal_sign") return signature;
      if (input.method === "eth_accounts") return [scenario === "wrong-account" ? `0x${"ab".repeat(20)}` : address];
      if (input.method === "eth_chainId") return scenario === "wrong-chain" ? "0x1" : "0x14";
      if (input.method === "eth_sendTransaction") return transactionHash;
      throw new Error(`Unexpected wallet call: ${input.method}`);
    },
  };
  const routes = [];
  globalThis.fetch = async (path, input) => {
    routes.push(path);
    assert.equal(input.headers["x-elastos-home-token"], "home-authority-fixture");
    let value;
    if (path.endsWith("host-config")) value = {
      projectId: "fixture-project", principal_id: "principal-fixture", internet: { status: "granted" },
      sdk_asset_path: pathToFileURL(resolve("scripts/lib/walletconnect-sdk-fixture.mjs")).href,
    };
    else if (path.endsWith("/evm/link/challenge")) value = {
      schema: "elastos.home.wallet-connector.effect.result/v1", action: "evm_link_challenge", connector_id: connector,
      challenge: { schema: "elastos.auth.challenge/v1", challenge_id: "challenge:fixture", message: linkMessages[scenario] || linkMessage, expires_at: Math.floor(Date.now() / 1000) + 600, resources: [] },
    };
    else if (path.endsWith("/evm/link/verify")) {
      const body = JSON.parse(input.body);
      assert.equal(body.message, linkMessages[scenario] || linkMessage); assert.equal(body.signature, signature);
      value = { schema: "elastos.home.wallet-connector.effect.result/v1", action: "evm_link_complete", connector_id: connector, status: "linked" };
    }
    else if (path.endsWith("/review")) value = { address, chain_namespace: "eip155:20", expires_at: Math.floor(Date.now() / 1000) + 600 };
    else if (path.endsWith("/handoff")) value = {
      schema: "elastos.home.wallet-connector.effect.result/v1", action: "approval_handoff",
      connector_id: connector, request_id: "approval:fixture", evm_chains: [],
      handoff: { schema: "elastos.wallet.webconnect_handoff/v1", request_id: "approval:fixture", intent: "transaction_intent",
        payload_hash: payloadHash, signer: address, status: "awaiting_wallet_transaction",
        transaction: { from: address, to: `0x${"78".repeat(20)}`, value: "0x1", data: "0x", gas: "0x5208", gasPrice: "0x1", nonce: "0x1", chainId: "0x14" },
      },
      binding: { principal_id: "principal-fixture", requested_by_actor: "documents", account_id: "account-fixture", chain_namespace: "eip155:20",
        payload_hash: payloadHash, expires_at: scenario === "expired" ? 1 : Math.floor(Date.now() / 1000) + 600 },
    };
    else if (path.endsWith("/complete")) {
      const body = JSON.parse(input.body);
      assert.equal(body.payload_hash, payloadHash);
      assert.equal(body.signer, address);
      assert.equal(body.transaction_hash, transactionHash);
      value = { schema: "elastos.home.wallet-connector.effect.result/v1", action: "approval_complete", connector_id: connector,
        request_id: "approval:fixture", status: "completed" };
    } else throw new Error(`Unexpected Runtime route: ${path}`);
    return { ok: true, json: async () => value };
  };
  let reply;
  const complete = new Promise(resolveReply => { reply = resolveReply; });
  const context = { kind: "app-frame", targetId: connector, homeToken: "connector-fixture", walletEffectState: { inFlight: false, requestIds: new Set() } };
  const data = { type: host.WALLET_CONNECTOR_EFFECT_TYPE, schema: host.WALLET_CONNECTOR_EFFECT_SCHEMA,
    requestId: "request:fixture", connectorId: scenario === "wrong-capsule" ? "wallet-metamask" : connector,
    connectorToken: "connector-fixture", action: scenario.startsWith("link") ? { kind: "link" } : { kind: "approve", approvalRequestId: "approval:fixture" } };
  if (scenario === "injected-payload") data.action.payload = { to: "attacker" };
  assert.equal(host.handleHomeWalletConnectorEffect({ source: { postMessage: reply } }, context, data), true);
  return { response: await complete, calls, routes };
}

test("trusted Home signs the exact Runtime transaction once", async () => {
  const result = await fixture("valid");
  assert.equal(result.response.error, undefined, result.response.error);
  assert.equal(result.calls.filter(c => c.method === "eth_sendTransaction").length, 1);
  assert.ok(result.calls.find(c => c.method === "eth_sendTransaction").expiry >= 300);
  assert.ok(result.calls.find(c => c.method === "eth_sendTransaction").expiry <= 600);
  assert.equal(result.calls.find(c => c.method === "eth_sendTransaction").params[0].to, `0x${"78".repeat(20)}`);
});
for (const scenario of ["wrong-account", "wrong-chain", "wrong-capsule", "expired", "injected-payload"]) {
  test(`trusted Home refuses ${scenario} before a signing effect`, async () => {
    const result = await fixture(scenario);
    assert.equal(typeof result.response.error, "string");
    assert.equal(result.calls.filter(c => c.method === "eth_sendTransaction").length, 0);
    assert.equal(result.routes.filter(p => p.endsWith("/complete")).length, 0);
  });
}

test("WalletConnect signs the exact UTF-8 ownership proof as EIP-1193 DATA", async () => {
  const result = await fixture("link");
  assert.equal(result.response.error, undefined, result.response.error);
  assert.equal(result.response.result.status, "linked");
  assert.deepEqual(result.calls.find(c => c.method === "personal_sign").params,
    ["0x" + Buffer.from(linkMessage, "utf8").toString("hex"), address]);
});

for (const [scenario, expected] of [["link-uppercase-hex", "0x4142"], ["link-odd-hex", "0x3078313233"]]) {
  test(`WalletConnect personal_sign matches wallet-provider bytes for ${scenario}`, async () => {
    const result = await fixture(scenario);
    assert.equal(result.response.error, undefined, result.response.error);
    assert.equal(result.calls.find(c => c.method === "personal_sign").params[0], expected);
  });
}
