import test from "node:test";
import assert from "node:assert/strict";
import { register } from "node:module";
register(new URL("./lib/walletconnect-connector-loader.mjs", import.meta.url));

class Element {
  children = []; dataset = {}; listeners = new Map(); textContent = "";
  addEventListener(type, fn) { this.listeners.set(type, fn); }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.children = children; }
  closest() { return this; }
}
let sequence = 0;
const tick = () => new Promise(resolve => setImmediate(resolve));
const transactionHash = `0x${"ab".repeat(32)}`;

async function fixture(kind) {
  const origin = "http://localhost:61183";
  const nodes = new Map(["wallet-connect", "wallet-disconnect", "wallet-connection", "wallet-status", "wallet-state", "wallet-accounts", "wallet-requests"].map(id => [`#${id}`, new Element()]));
  globalThis.document = { querySelector: selector => nodes.get(selector), createElement: () => new Element() };
  const events = new Map(); const timers = new Map(); let now = 0, timerId = 0, effect;
  const home = { postMessage(message) { if (message.type === "home:wallet-connector-effect") effect = message; } };
  globalThis.window = {
    location: { search: `?home_origin=${encodeURIComponent(origin)}`, hash: "#home_token=deadline-fixture", origin: "null" },
    top: home, parent: home, crypto: { randomUUID: () => `deadline-${++sequence}` },
    addEventListener(type, callback) { if (!events.has(type)) events.set(type, new Set()); events.get(type).add(callback); },
    removeEventListener(type, callback) { events.get(type)?.delete(callback); },
    setTimeout(fn, ms) { timers.set(++timerId, { fn, at: now + ms }); return timerId; },
    clearTimeout(id) { timers.delete(id); },
  };
  globalThis.fetch = async path => ({ ok: true, json: async () => path.endsWith("/accounts") ? { accounts: [] } : { approval_requests: [{
    request_id: "approval:deadline", status: "pending", intent: "transaction_intent", capsule_id: "documents", chain_namespace: "eip155:20",
    proof_type: "siwe", connector_id: "wallet-walletconnect", address: `0x${"12".repeat(20)}`,
  }] } });
  await import(`../capsules/wallet-walletconnect/browser/wallet-walletconnect.js?deadline=${++sequence}`);
  await tick();
  const root = nodes.get("#wallet-requests");
  const button = root.children[0].children.at(-1);
  const pending = kind === "link" ? nodes.get("#wallet-connect").listeners.get("click")()
    : root.listeners.get("click")({ target: button });
  assert.equal(effect.action.kind, kind);
  return {
    async advance(ms) {
      now += ms;
      for (const [id, timer] of [...timers]) if (timer.at <= now) { timers.delete(id); timer.fn(); }
      await tick();
    },
    async reply() {
      const data = { type: "home:wallet-connector-effect-result", schema: "elastos.home.wallet-connector-effect-result/v1",
        requestId: effect.requestId, connectorId: "wallet-walletconnect",
        ...(kind === "link" ? { result: { status: "linked" } } : { error: `Wallet returned transaction hash ${transactionHash}. Keep this hash and check it before sending again.` }),
      };
      for (const fn of [...events.get("message")]) fn({ source: home, origin, data });
      await pending;
    },
    pending, status: nodes.get("#wallet-status"),
  };
}

for (const kind of ["approve", "link"]) {
  test(`WalletConnect ${kind} still receives its Home reply after 180 seconds`, async () => {
    const f = await fixture(kind);
    await f.advance(181000);
    await f.reply();
    assert.ok(kind === "link" ? f.status.textContent === "Approval method added." : f.status.textContent.includes(transactionHash), f.status.textContent);
  });
}
test("an unresponsive Home effect has a bounded screen deadline", async () => {
  const f = await fixture("approve");
  await f.advance(811000); await f.pending;
  assert.equal(f.status.textContent, "Wallet request timed out.");
});
