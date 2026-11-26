import assert from "node:assert/strict";
import test from "node:test";
import {
  normalizeWalletBridge,
  walletRuntimeRequestedAccount,
} from "./browser-selkies-control-service.mjs";

const account = {
  account_id: "wallet:eip155:20:0x1111111111111111111111111111111111111111",
  chain_namespace: "eip155:20",
  address: "0x1111111111111111111111111111111111111111",
  proof_type: "siwe",
};

test("website requests select the connector account after bridge normalization", () => {
  for (const connector_id of ["wallet-metamask", "wallet-walletconnect", "wallet-unisat"]) {
    const wallet = normalizeWalletBridge({ accounts: [{ ...account, connector_id }] });
    assert.equal(wallet.accounts[0].connector_id, connector_id);
    assert.equal(walletRuntimeRequestedAccount({ wallet }, {}).connector_id, connector_id);
    // Refresh and page creation can normalize the same bridge again.
    assert.deepEqual(normalizeWalletBridge(wallet), wallet);
  }
});

test("bridge normalization admits only connector identifiers", () => {
  for (const connector_id of [undefined, null, 42, {}, [], "", "wallet metamask", "../wallet", "wallet\n"]) {
    const wallet = normalizeWalletBridge({ accounts: [{ ...account, connector_id }] });
    assert.equal(wallet.accounts[0].connector_id, null);
    assert.equal(walletRuntimeRequestedAccount({ wallet }, {}, { required: false }), null);
  }
  const wallet = normalizeWalletBridge({ accounts: [{ ...account, proof_type: "managed_evm" }] });
  assert.equal(walletRuntimeRequestedAccount({ wallet }, {}).account_id, account.account_id);
});
