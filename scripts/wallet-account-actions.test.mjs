import assert from "node:assert/strict";
import test from "node:test";
import { createWalletAccountActions } from "../capsules/wallet/browser/wallet-account-actions.js";

for (const [name, label, expected] of [
  ["Holiday wallet", "External account", "Holiday wallet"],
  ["Your wallet", "External account", "Your wallet"],
  [undefined, "Savings wallet", "Savings wallet"],
  [undefined, "External account", "Your wallet"],
]) {
  test(`default confirmation identifies the grouped address: ${expected} (${name})`, async () => {
    const first = { account_id: "esc", chain_namespace: "eip155:20", address: "0x1234", label,
      connector_id: "wallet-walletconnect" };
    const second = { ...first, account_id: "base", chain_namespace: "eip155:8453" };
    const view = { ...first, name, account_records: [first, second] };
    let rows, body, status, refreshed = 0;
    const actions = createWalletAccountActions({
      buildViewAccounts: () => [view], getSelectedAccountId: () => "esc",
      flowRow: (title, detail, action) => ({ title, detail, action }),
      openFlowModal: (_title, _detail, next) => { rows = next; },
      fetchJson: async (url, options) => { assert.equal(url, "/api/apps/wallet/wallet/default"); body = JSON.parse(options.body); },
      shellHeaders: headers => headers, closeModal() {},
      showStatus: (message, kind) => { status = { message, kind }; },
      refreshWalletState: async () => { refreshed++; },
    });
    await actions.onAccountClick({ target: { closest: () => ({ dataset: { walletAccountMenu: "esc" } }) }, stopPropagation() {} });
    await rows.find(row => row.title === "Use by default").action();
    await rows.find(row => row.title === "Base").action();
    assert.deepEqual(body, { account_id: "base", chain_namespace: "eip155:8453", intent: "transaction_intent" });
    assert.deepEqual(status, { message: `${expected} is now the default for transactions.`, kind: "success" });
    assert.equal(refreshed, 1);
  });
}
