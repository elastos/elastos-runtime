import test from "node:test";
import assert from "node:assert/strict";
import { createWalletRequests } from "../capsules/wallet/browser/wallet-requests.js";
import { activityTitle, activitySubtitle, activityIcon, pendingRequests } from "../capsules/wallet/browser/wallet-activity.js";

class Element {
  children = []; dataset = {}; hidden = false; textContent = "";
  classList = { toggle() {} };
  constructor(tagName) { this.tagName = tagName; }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.children = children; }
  closest(selector) {
    return selector === "[data-wallet-request-reject]" && this.dataset.walletRequestReject ? this : null;
  }
}
const descendants = node => [node, ...node.children.flatMap(descendants)];

test("Wallet dismisses earlier-session connector sends without another approval", async t => {
  const previous = globalThis.document;
  globalThis.document = { createElement: tag => new Element(tag) };
  t.after(() => { globalThis.document = previous; });
  for (const connector of ["wallet-walletconnect"]) {
    const now = Math.floor(Date.now() / 1000);
    const expires = now - 13 * 3600;
    let request = { request_id: "approval:abandoned", status: "approved", intent: "transaction_intent",
      connector_id: connector, capsule_id: "browser", address: `0x${"12".repeat(20)}`,
      approved_at: expires - 290, created_at: expires - 300, expires_at: expires, reason: "Send transaction" };
    const root = new Element("section"), panel = new Element("section"), calls = [], messages = [];
    let refuse = true;
    const requests = createWalletRequests({ requestsNode: root, requestsPanelNode: panel,
      shellHeaders: headers => ({ ...headers, "x-elastos-home-token": "fixture-current-session-wallet-token" }),
      fetchJson: async (path, input) => {
        calls.push({ path, input });
        if (refuse) throw new Error("Runtime refused dismissal");
        request = { ...request, status: "rejected" };
        return { receipt_status: "dismissed" };
      },
      notifyHomeSummaryChanged() {},
      openApprovalMethod() { assert.fail("dismissal opens no signer"); },
      requestPasskeyStepUp() { assert.fail("dismissal grants no new approval"); },
      showStatus: message => messages.push(message),
      refreshWalletState: async () => requests.renderRequests(requests.pendingWalletRequests([request])),
    });
    assert.deepEqual(requests.pendingWalletRequests([request]), [request], "an approved send remains actionable after its TTL");
    for (const other of [
      { ...request, status: "completed" }, { ...request, status: "rejected" },
      { ...request, intent: "browser_personal_sign" }, { ...request, connector_id: null },
    ]) assert.deepEqual(requests.pendingWalletRequests([other]), []);
    requests.renderRequests(requests.pendingWalletRequests([request]));
    const buttons = descendants(root).filter(node => node.tagName === "button");
    assert.deepEqual(buttons.map(button => button.textContent), ["Dismiss"], "approved sends offer dismissal without another send");
    assert(descendants(root).some(node => node.textContent.includes("does not cancel")));
    await requests.onRequestClick({ target: buttons[0] });
    assert.equal(root.children.length, 1, "a refused dismissal keeps its recovery card");
    assert.equal(buttons[0].disabled, false);
    refuse = false;
    await requests.onRequestClick({ target: buttons[0] });
    assert.equal(calls.length, 2);
    assert.equal(calls[1].path, "/api/apps/wallet/wallet/approvals/approval%3Aabandoned/reject");
    assert.equal(calls[1].input.method, "POST");
    assert.equal(calls[1].input.headers["x-elastos-home-token"], "fixture-current-session-wallet-token",
      "dismissal uses the current Wallet launch, including for an earlier-session send");
    assert.equal(root.children.length, 1, "the acknowledgement keeps the request identity after refresh");
    assert.equal(panel.hidden, false);
    assert.equal(requests.pendingWalletRequests([request]).length, 0, "the acknowledgement is outside the waiting count");
    assert.equal(descendants(root).filter(node => node.tagName === "button").length, 0);
    assert(!descendants(root).some(node => node.className === "wallet-request-time"));
    assert(descendants(root).some(node => node.textContent.startsWith("Request dismissed.")));
    assert.match(activityTitle(request), /Dismissed transaction request/);
    assert.equal(requests.requestsWithDecisions([])[0].status, "rejected");
    assert.equal(requests.requestsWithDecisions([{ ...request, status:"approved" }])[0].status, "rejected", "an old read cannot reopen the known decision");
    const positive = { ...request, status:"completed", transaction_hash:`0x${"a".repeat(64)}` };
    assert.deepEqual(requests.requestsWithDecisions([positive]), [positive], "a later recorded result keeps its canonical facts");
  }
});

test("only WalletConnect unfinished approved sends enter the request list and badge", () => {
  const approved = { status: "approved", intent: "transaction_intent", approved_at: 10 };
  for (const connector_id of ["wallet-metamask", "wallet-unisat", "wallet-walletconnect"]) {
    const request = { ...approved, connector_id };
    assert.equal(pendingRequests([request]).length, connector_id === "wallet-walletconnect" ? 1 : 0);
    assert.equal(pendingRequests([{ ...request, status: "pending" }]).length, 1);
  }
});

test("Activity distinguishes pending rejection, approved dismissal and a late wallet send", () => {
  const request = { status: "rejected", intent: "transaction_intent", connector_id: "wallet-walletconnect", capsule_id: "browser" };
  assert.match(activityTitle(request), /Rejected/);
  assert.match(activityTitle({ ...request, approved_at: 10 }), /Dismissed transaction request/);
  const late = { ...request, approved_at: 10, transaction_hash: `0x${"a".repeat(64)}` };
  assert.match(activityTitle(late), /Dismissed request. Your wallet reported this transaction as sent/);
  assert.equal(activityIcon(late), "✓");
  assert.equal(activityIcon({ ...request, approved_at: 10 }), "·");
  assert(activitySubtitle(late).includes(late.transaction_hash));
});

// The server may approve a pending card before its Reject click arrives.
for (const dismissed of [false, true]) test(`Wallet uses the current rejection result (dismissed=${dismissed})`, async () => {
  const messages = [];
  const requests = createWalletRequests({
    fetchJson: async () => ({ receipt_status: dismissed ? "dismissed" : null,
      note: "Fixture provider summary unavailable" }),
    shellHeaders: headers => headers,
    showStatus: message => messages.push(message),
    notifyHomeSummaryChanged() {}, refreshWalletState: async () => {},
  });
  const button = new Element("button");
  button.dataset.walletRequestReject = "approval:stale";
  await requests.onRequestClick({ target: button });
  assert.equal(messages.at(-1), dismissed
    ? "Request dismissed. This does not cancel a transaction in your wallet. Check your wallet before sending again."
    : "Request rejected.");
});

test("n3_reject_dismiss_acknowledgement: successful decision survives a failed refresh", async t => {
  const previous = globalThis.document;
  globalThis.document = { createElement: tag => new Element(tag) };
  t.after(() => { globalThis.document = previous; });
  const root = new Element("section");
  const request = { request_id:"request:refresh-failed", status:"pending", intent:"browser_personal_sign", capsule_id:"notes",
    reason:"Sign into Notes", address:"0xabc", expires_at:Math.floor(Date.now()/1000)+600 };
  const view = createWalletRequests({ requestsNode:root, fetchJson:async () => ({}), shellHeaders:headers => headers,
    notifyHomeSummaryChanged() {}, showStatus() {}, refreshWalletState:async () => { throw new Error("refresh unavailable"); } });
  view.renderRequests([request]);
  await view.onRequestClick({ target:descendants(root).find(node => node.dataset.walletRequestReject) });
  assert(descendants(root).some(node => node.textContent === "Request rejected."));
  assert(descendants(root).some(node => node.textContent === "Sign into Notes"));
  assert.equal(descendants(root).filter(node => node.tagName === "button").length, 0);
  assert(!descendants(root).some(node => node.className === "wallet-request-time"));
  assert.equal(view.pendingWalletRequests([request]).length, 0, "an older in-flight summary cannot count the acknowledged ID again");
});

test("n3_reject_dismiss_acknowledgement: consecutive decisions survive a stale read", async t => {
  const previous = globalThis.document;
  globalThis.document = { createElement: tag => new Element(tag) };
  t.after(() => { globalThis.document = previous; });
  const stale = ["first", "second"].map(request_id => ({ request_id, status:"pending", intent:"browser_personal_sign", connector_id:"wallet-metamask", reason:"Sign a message" }));
  const root = new Element("section");
  const requests = createWalletRequests({ requestsNode:root, shellHeaders:headers => headers,
    fetchJson:async () => ({}), notifyHomeSummaryChanged() {}, showStatus() {},
    refreshWalletState:async () => { throw new Error("read failed"); } });
  requests.renderRequests(stale);
  for (const id of ["first", "second"]) {
    const button = descendants(root).find(node => node.dataset.walletRequestReject === id);
    assert(button, `request ${id} can be rejected`);
    await requests.onRequestClick({ target:button });
  }
  assert.deepEqual(requests.requestsWithDecisions(stale).map(r => r.status), ["rejected", "rejected"]);
  assert.equal(requests.pendingWalletRequests(stale).length, 0, "neither known decision reopens in the count");
});
