import assert from "node:assert/strict";
import test from "node:test";

class FakeElement {
  constructor(tagName) {
    this.tagName = tagName;
    this.children = [];
    this.className = "";
    this.dataset = {};
    this.listeners = {};
    this.textContent = "";
  }

  append(...nodes) {
    this.children.push(...nodes);
  }

  get firstChild() {
    return this.children[0];
  }

  addEventListener(type, listener) {
    this.listeners[type] = listener;
  }

  set innerHTML(_value) {
    throw new Error("Wallet network rows must render text, not HTML.");
  }
}

globalThis.document = { createElement: (tagName) => new FakeElement(tagName) };

const { createWalletAccountActions } = await import("./wallet-account-actions.js");
const { createWalletFlows } = await import("./wallet-flows.js");
const { publicWalletText } = await import("./wallet-render.js");
const {
  EVM_NETWORK_CHOICES,
  accountDefaultChainNamespace,
  accountDisplayChainNamespace,
} = await import("./wallet-network.js");

const ESC = "eip155:20";
const BASE = "eip155:8453";
const BITCOIN = "bip122:000000000019d6689c085ae165831e93";

function rowText(row) {
  const [title, subtitle] = row.firstChild.children;
  return { title: title.textContent, subtitle: subtitle.textContent };
}

function evmAccount(overrides = {}) {
  return {
    account_id: "acc-esc",
    account_ids: ["acc-esc"],
    account_records: [{ account_id: "acc-esc", chain_namespace: ESC, address: "0xabc", proof_type: "managed_evm" }],
    chain_namespace: ESC,
    display_chain_namespace: BASE,
    default_chain_namespace: "",
    network: "Base",
    address: "0x00000000000000000000000000000000000000aa",
    name: "Family",
    proof_type: "managed_evm",
    ...overrides,
  };
}

function bitcoinAccount() {
  return {
    account_id: "acc-btc",
    account_ids: ["acc-btc"],
    account_records: [{ account_id: "acc-btc", chain_namespace: BITCOIN }],
    chain_namespace: BITCOIN,
    display_chain_namespace: "",
    default_chain_namespace: "",
    network: "Bitcoin",
    address: "bc1qexample",
    name: "Savings",
    proof_type: "managed_btc_p2wpkh",
  };
}

function harness(accounts) {
  const { flowRow, flowStaticRow, modalButton } = createWalletFlows({ showStatus: () => {} });
  const modals = [];
  const requests = [];
  const statuses = [];
  let refreshes = 0;
  const actions = createWalletAccountActions({
    buildViewAccounts: () => accounts,
    clearAccountSelection: () => {},
    closeModal: () => {},
    copyText: async () => {},
    fetchJson: async (url, init) => {
      requests.push({ url, method: init.method, body: JSON.parse(init.body) });
      return {};
    },
    flowRow,
    flowStaticRow,
    getSelectedAccountId: () => "",
    modalButton,
    modalNode: null,
    notifyHomeSummaryChanged: () => {},
    openAccountDetail: () => {},
    openApprovalMethod: () => {},
    openFlowModal: (title, subtitle, rows) => modals.push({ title, subtitle, rows }),
    openInfoModal: () => {},
    refreshWalletState: async () => {
      refreshes += 1;
    },
    renderReceiveAddress: () => {},
    requestPasskeyStepUp: async () => "step-up",
    shellHeaders: (extra = {}) => extra,
    showStatus: (message, tone) => statuses.push({ message, tone }),
  });
  return { actions, modals, requests, statuses, refreshes: () => refreshes };
}

async function click(row) {
  row.listeners.click();
  await new Promise((resolve) => setImmediate(resolve));
}

function networkRow(modal) {
  return modal.rows.find((row) => rowText(row).title === "Network");
}

test("Base is the suggested first network and Elastos Smart Chain the alternative", () => {
  assert.deepEqual(
    EVM_NETWORK_CHOICES.map((choice) => [choice.chainNamespace, choice.label]),
    [[BASE, "Base"], [ESC, "Elastos Smart Chain"]],
  );
});

test("an EVM account shows the network where it is the transaction default, Base otherwise", () => {
  const records = [{ account_id: "acc-esc", chain_namespace: ESC, proof_type: "managed_evm" }];
  const defaultOn = (chainNamespace, accountId = "acc-esc", setAt = 1, intent = "transaction_intent") => ({
    account_id: accountId,
    chain_namespace: chainNamespace,
    intent,
    set_at: setAt,
  });
  assert.equal(accountDisplayChainNamespace(records, [defaultOn(ESC)]), ESC);
  assert.equal(accountDisplayChainNamespace(records, [defaultOn(BASE)]), BASE);
  assert.equal(accountDisplayChainNamespace(records, []), BASE);
  assert.equal(accountDisplayChainNamespace(records, [defaultOn(ESC, "acc-other")]), BASE);
  assert.equal(accountDisplayChainNamespace(records, [defaultOn(ESC, "acc-esc", 1, "browser_connect")]), BASE);
  assert.equal(accountDisplayChainNamespace(records, [defaultOn("eip155:1")]), BASE);
  assert.equal(
    accountDisplayChainNamespace(records, [defaultOn(BASE, "acc-esc", 1), defaultOn(ESC, "acc-esc", 2)]),
    ESC,
  );
  assert.equal(accountDisplayChainNamespace([{ account_id: "acc-btc", chain_namespace: BITCOIN }], []), "");
});

test("only externally owned EVM accounts choose a network", () => {
  const record = (proofType) => [{ account_id: "acc-esc", chain_namespace: ESC, proof_type: proofType }];
  const defaults = [{ account_id: "acc-esc", chain_namespace: ESC, intent: "transaction_intent", set_at: 1 }];
  assert.equal(accountDisplayChainNamespace(record("managed_evm"), []), BASE);
  assert.equal(accountDisplayChainNamespace(record("siwe"), []), BASE);
  // A contract account exists only on the chain it was deployed to.
  assert.equal(accountDisplayChainNamespace(record("siwe_erc1271"), []), "");
  assert.equal(accountDisplayChainNamespace(record("siwe_erc1271"), defaults), "");
  assert.equal(accountDefaultChainNamespace(record("siwe_erc1271"), defaults), "");
});

test("only the account holding the EVM transaction default has a current network", () => {
  const records = [{ account_id: "acc-esc", chain_namespace: ESC, proof_type: "managed_evm" }];
  const defaultOn = (chainNamespace, accountId, setAt) => ({
    account_id: accountId,
    chain_namespace: chainNamespace,
    intent: "transaction_intent",
    set_at: setAt,
  });
  assert.equal(accountDefaultChainNamespace(records, [defaultOn(ESC, "acc-esc", 1)]), ESC);
  assert.equal(accountDefaultChainNamespace(records, []), "");
  assert.equal(
    accountDefaultChainNamespace(records, [defaultOn(ESC, "acc-esc", 1), defaultOn(BASE, "acc-other", 2)]),
    "",
  );
});

test("the Account sheet shows a Network row for EVM accounts only", () => {
  const evm = harness([evmAccount()]);
  evm.actions.openAccountMenu("acc-esc");
  const row = networkRow(evm.modals.at(-1));
  assert.ok(row, "EVM accounts need a Network row");
  assert.deepEqual(rowText(row), { title: "Network", subtitle: "Base" });

  const bitcoin = harness([bitcoinAccount()]);
  bitcoin.actions.openAccountMenu("acc-btc");
  assert.equal(networkRow(bitcoin.modals.at(-1)), undefined);

  const contract = harness([evmAccount({
    proof_type: "siwe_erc1271",
    display_chain_namespace: "",
    network: "Elastos Smart Chain",
  })]);
  contract.actions.openAccountMenu("acc-esc");
  assert.equal(networkRow(contract.modals.at(-1)), undefined);
});

test("the network picker lists Base first and marks the current network", async () => {
  const { actions, modals } = harness([evmAccount({
    display_chain_namespace: ESC,
    default_chain_namespace: ESC,
    network: "Elastos Smart Chain",
  })]);
  actions.openAccountMenu("acc-esc");
  await click(networkRow(modals.at(-1)));
  const picker = modals.at(-1);
  assert.equal(picker.title, "Network");
  assert.deepEqual(picker.rows.map(rowText), [
    { title: "Base", subtitle: "Suggested" },
    { title: "Elastos Smart Chain", subtitle: "Current" },
  ]);
});

test("an account that only shows Base by suggestion has no current network", async () => {
  const { actions, modals } = harness([evmAccount()]);
  actions.openAccountMenu("acc-esc");
  await click(networkRow(modals.at(-1)));
  assert.deepEqual(modals.at(-1).rows.map(rowText), [
    { title: "Base", subtitle: "Suggested" },
    { title: "Elastos Smart Chain", subtitle: "EVM network" },
  ]);
});

test("choosing a network makes the account the transaction default on that chain", async () => {
  const { actions, modals, requests, statuses, refreshes } = harness([evmAccount()]);
  actions.openAccountMenu("acc-esc");
  await click(networkRow(modals.at(-1)));
  const esc = modals.at(-1).rows.find((row) => rowText(row).title === "Elastos Smart Chain");
  await click(esc);
  assert.deepEqual(requests, [{
    url: "/api/apps/wallet/wallet/default",
    method: "POST",
    body: { account_id: "acc-esc", chain_namespace: ESC, intent: "transaction_intent" },
  }]);
  assert.deepEqual(statuses.at(-1), {
    message: "Family is now the default on Elastos Smart Chain.",
    tone: "success",
  });
  assert.equal(refreshes(), 1);
});

test("a grouped card binds the default to its exact record on the chosen chain", async () => {
  const grouped = evmAccount({
    account_ids: ["acc-esc", "acc-base"],
    account_records: [
      { account_id: "acc-esc", chain_namespace: ESC },
      { account_id: "acc-base", chain_namespace: BASE },
    ],
  });
  const { actions, modals, requests } = harness([grouped]);
  actions.openAccountMenu("acc-esc");
  await click(networkRow(modals.at(-1)));
  await click(modals.at(-1).rows.find((row) => rowText(row).title === "Base"));
  assert.deepEqual(requests.at(-1).body, {
    account_id: "acc-base",
    chain_namespace: BASE,
    intent: "transaction_intent",
  });
});

test("network rows render account names and labels as text", async () => {
  const name = '<img src=x onerror="alert(1)">';
  const { actions, modals } = harness([evmAccount({ name })]);
  actions.openAccountMenu("acc-esc");
  await click(networkRow(modals.at(-1)));
  assert.equal(modals.at(-1).subtitle, name);
  assert.deepEqual(rowText(modals.at(-1).rows[0]), { title: "Base", subtitle: "Suggested" });
});

test("network refusals reach the person as plain text", () => {
  assert.equal(
    publicWalletText("request failed: 500 This account cannot sign on the requested network."),
    "This account cannot sign on the requested network.",
  );
  assert.equal(
    publicWalletText("request failed: 500 This transaction is for a different network than the one approved."),
    "This transaction is for a different network than the one approved.",
  );
  assert.equal(
    publicWalletText("request failed: 500 wallet approval authority no longer matches its managed account"),
    "Wallet action could not be completed.",
  );
});
