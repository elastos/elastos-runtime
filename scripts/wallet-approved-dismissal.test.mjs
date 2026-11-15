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
    assert.equal(root.children.length, 0, "successful refresh removes the dismissed request");
    assert.equal(panel.hidden, true);
    assert(messages.some(message => message.startsWith("Request dismissed.")));
    assert.match(activityTitle(request), /Dismissed transaction request/);
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
  assert.match(activityTitle(late), /Sent from wallet after request was dismissed/);
  assert.equal(activityIcon(late), "✓");
  assert.equal(activityIcon({ ...request, approved_at: 10 }), "·");
  assert(activitySubtitle(late).includes(late.transaction_hash));
});
