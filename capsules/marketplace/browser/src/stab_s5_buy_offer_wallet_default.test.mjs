import assert from "node:assert/strict";
import test from "node:test";

import { buyRefusalCopy, parseBuyOfferAnswer } from "./market-listing.js";

// STAB-REPRO S5 (red, no fix). Live 2026-11-17: both `buy_offer` presses
// (Home-6, 08:01:05Z and 08:01:24Z) were refused before any Wallet request
// because the Home has no Wallet account for Base. Runtime says so as data
// (`wallet_default`, the field Creator already reads), under the generic
// `library_error` code. This is that answer exactly as the producer pin
// `stab_s5_buy_offer_without_a_wallet_account_is_a_typed_wallet_default_refusal`
// (gateway_tests/stab_s5_buy_offer_no_wallet_account.rs) asserts it.
// (The live `detail` field is left out because the page never reads it.)
const NO_WALLET_ACCOUNT_ANSWER = {
  status: "error",
  code: "library_error",
  message: "Runtime custody purchase is denied before buy",
  wallet_default: {
    schema: "elastos.protected-content.wallet-default-unusable/v1",
    reason: "no_transaction_default_for_chain_namespace",
    chain_namespace: "eip155:8453",
  },
};

test("stab_s5: a buy refused for a missing Wallet account is not read as a failed purchase", () => {
  const outcome = parseBuyOfferAnswer(NO_WALLET_ACCOUNT_ANSWER);
  // Today this is { kind: "failed" }. `buyOffer` (marketplace.js) words that
  // as "The purchase did not finish." although nothing was attempted, and
  // the person is not told to add or choose a Wallet account for Base.
  assert.notEqual(outcome.kind, "failed", JSON.stringify(outcome));
});

test("stab_s5: the page has words for a buy refused for a missing Wallet account", () => {
  // Today buyRefusalCopy answers only `custody_elsewhere`, so this is null.
  assert.notEqual(buyRefusalCopy(NO_WALLET_ACCOUNT_ANSWER), null);
});
