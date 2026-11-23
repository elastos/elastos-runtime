// STAB-REPRO S3 on Home-6 (red, no fix): Home-6 has no Wallet account
// (gateway log: "Runtime custody wallet default account failed closed …
// no_transaction_default_for_chain_namespace … wallet_accounts_total=0",
// 07:44-08:01Z). The listing object then answers `available` +
// `access_unknown` with no `access_subject`; `cardAccessState` reads that as
// `no_account`, and `catalogCardControl` renders an enabled "Buy"
// (market-card.js `case "no_account"`). A Buy that has no account to pay
// with cannot work, and no access can be checked: the card should say a
// Wallet account is needed instead.

import assert from "node:assert/strict";
import test from "node:test";

import { cardAccessState } from "./market-access.js";
import { catalogCardControl } from "./market-card.js";

const LEDGER = `0x${"e".repeat(40)}`;

test("stab_s3 a card on a Home with no Wallet account does not offer Buy", () => {
  // The listing object Home-6 gets: no account to ask about.
  const access = cardAccessState({ accessState: "available", accessUnknown: true, accessSubject: null });
  assert.equal(access, "no_account", "precondition");
  const markup = catalogCardControl(
    { ledger: LEDGER, tokenId: "0x1", accessState: "available" },
    { key: `${LEDGER}|0x1`, size: "", access },
  );
  const label = (/<button[^>]*>([^<]*)<\/button>/u.exec(markup) || [])[1];
  assert.notEqual(label, "Buy", markup);
});
