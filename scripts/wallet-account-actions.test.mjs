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

for (const namespace of ['eip155:20', 'eip155:8453']) {
  test(`grouped recovery key keeps a wallet and network label for ${namespace}`, async () => {
    const records = ['eip155:20', 'eip155:8453'].map((chain_namespace, index) => ({
      account_id: `built-${index}`, chain_namespace, address: '0x1234', proof_type: 'managed_evm',
    }));
    const view = {...records[0], name: 'Home address', account_records: records};
    let rows, details;
    const savedDocument = globalThis.document;
    globalThis.document = {createElement: () => ({})};
    try {
      const actions = createWalletAccountActions({
        buildViewAccounts: () => [view], getSelectedAccountId: () => '',
        flowRow: (title, detail, action) => ({title, detail, action}),
        flowStaticRow: (label, value) => ({label, value}), modalButton: () => ({}),
        openFlowModal: (title, _subtitle, nodes) => {if (title === 'Recovery key' && nodes.some(n => n.label)) details = nodes; else rows = nodes;},
        requestPasskeyStepUp: async () => 'fixture-approval',
        fetchJson: async () => ({account_id:'fixture', chain_namespace:namespace, address:'0x1234'}),
        shellHeaders: headers => headers,
      });
      await actions.onAccountClick({target:{closest:()=>({dataset:{walletAccountMenu:view.account_id}})}, stopPropagation(){}});
      await rows.find(row => row.title === 'Recovery key').action();
      await rows.find(row => row.title === (namespace === 'eip155:20' ? 'ESC' : 'Base')).action();
      assert.equal(details.find(row => row.label === 'Network').value, namespace === 'eip155:20' ? 'ESC' : 'Base');
      assert.equal(typeof details.find(row => row.label === 'Wallet').value, 'string');
      assert(details.find(row => row.label === 'Wallet').value.length > 0);
      assert.equal(details.some(row => row.value === undefined || row.value === 'undefined'), false);
    } finally {globalThis.document = savedDocument;}
  });
}
