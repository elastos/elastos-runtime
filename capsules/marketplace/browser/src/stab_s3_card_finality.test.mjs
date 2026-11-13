// STAB-REPRO S3 (red, no fix): while Base has not finalized a new item, its
// Explore card is labelled "Buy" for every account that does not hold a
// local copy -- including one the chain already grants it (a channel
// subscription). `catalogCardControl` picks the label from the catalog row's
// `accessState`, which for an item minted on another Home is always
// "available" (`mark_market_catalog_held`), and ignores the account's own
// access answer. On Base the finalized block trails the mint by ~20 min
// (Home-4 log 2026-11-17: finalized `unbound` 07:35:48..07:55:38Z, `latest`
// `has_access` throughout), so a freshly minted item says "Buy" all that time.

import assert from "node:assert/strict";
import test from "node:test";

import { catalogCardControl } from "./market-card.js";

const LEDGER = `0x${"e".repeat(40)}`;

function label(ctx) {
  const markup = catalogCardControl(
    { ledger: LEDGER, tokenId: "0x1", accessState: "available" },
    { key: `${LEDGER}|0x1`, size: "", ...ctx },
  );
  const match = /<button[^>]*>([^<]*)<\/button>/u.exec(markup);
  return match ? match[1] : markup;
}

test("stab_s3 a card awaiting finality does not offer Buy to an account the chain grants the item", () => {
  assert.notEqual(label({ finalityPending: true, access: "held" }), "Buy");
});

test("stab_s3 a card awaiting finality does not offer Buy while the account's access is not known", () => {
  assert.notEqual(label({ finalityPending: true, access: "pending" }), "Buy");
});
