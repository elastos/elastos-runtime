import assert from "node:assert/strict";
import test from "node:test";

import { catalogCardControl, formatBadge } from "./market-card.js";
import { CUSTODY_ELSEWHERE_COPY, NO_REACHABLE_HOLDER_COPY } from "./market-listing.js";

const LEDGER = `0x${"e".repeat(40)}`;
const KEY = `${LEDGER}|0x3e`;

function item(accessState = "available") {
  return { ledger: LEDGER, tokenId: "0x3e", accessState };
}

function render(listing, ctx = {}) {
  return catalogCardControl(listing, { key: KEY, size: "", ...ctx });
}

// Every element the markup opens, with its attributes and its text.
function elements(markup) {
  return [...markup.matchAll(/<(button|span)([^>]*)>([^<]*)<\/\1>/g)].map(([, tag, attrs, text]) => ({
    tag,
    text,
    action: attrs.match(/data-action="([^"]*)"/)?.[1] ?? null,
    disabled: /\sdisabled(\s|$|=)/.test(attrs),
    accessKey: attrs.match(/data-access-key="([^"]*)"/)?.[1] ?? null,
    title: attrs.match(/title="([^"]*)"/)?.[1] ?? null,
  }));
}

function only(markup) {
  const found = elements(markup);
  assert.equal(found.length, 1, markup);
  return found[0];
}

test("no answer yet is a disabled Checking… that names the card for the watch -- never Buy", () => {
  for (const access of ["checking", "pending"]) {
    const control = only(render(item(), { access }));
    assert.equal(control.text, "Checking…", String(access));
    assert.equal(control.disabled, true);
    assert.equal(control.action, null);
    assert.equal(control.accessKey, KEY.replace("|", "|"));
  }
});

// D5 (STAB-26): a read that failed is settled, not "Checking…".
test("a failed read is an enabled Try again that names the card for the watch -- never Buy", () => {
  const control = only(render(item(), { access: "retrying" }));
  assert.deepEqual([control.text, control.action, control.disabled], ["Try again", "retry-access", false]);
  assert.equal(control.accessKey, KEY);
});

test("no access for a known account is Buy", () => {
  const control = only(render(item(), { access: "available" }));
  assert.deepEqual([control.text, control.action, control.disabled], ["Buy", "buy-listing", false]);
});

// D5 (STAB-24): with no Wallet account there is nothing to buy with.
test("no wallet account to ask about is Add a Wallet account, never Buy", () => {
  const control = only(render(item(), { access: "no_account" }));
  assert.deepEqual([control.text, control.action, control.disabled], ["Add a Wallet account", "open-wallet", false]);
  assert.equal(control.accessKey, KEY);
});

test("access the chain grants is Open, which builds the copy and opens it", () => {
  const control = only(render(item(), { access: "held" }));
  assert.deepEqual([control.text, control.action, control.disabled], ["Open", "open-market-item", false]);
  const opening = only(render(item(), { access: "held", downloading: true }));
  assert.deepEqual([opening.text, opening.disabled], ["Opening…", true]);
  const foreign = only(render(item(), { access: "held", readability: "foreign" }));
  assert.deepEqual([foreign.tag, foreign.text], ["span", "Opens on ela.city"]);
});

// PR5 point 1: a granted item that no reachable Home serves, with no copy
// here, would only fail to open from its pool.
test("granted but served by no reachable Home is a disabled Unavailable that stays watched", () => {
  const control = only(render(item(), { access: "held", noHolder: true }));
  assert.deepEqual([control.text, control.action, control.disabled], ["Unavailable", null, true]);
  assert.equal(control.title, NO_REACHABLE_HOLDER_COPY);
  assert.equal(control.accessKey, KEY, "the watch rereads it on its TTL");
  // This Home's own copy of the exact item still opens: it needs no holder.
  const local = only(render(item(), { access: "held", noHolder: true, mint: "mint-1" }));
  assert.deepEqual([local.text, local.action, local.disabled], ["Open", "open-media", false]);
  // Without the hint the answer is unchanged.
  const served = only(render(item(), { access: "held", noHolder: false }));
  assert.deepEqual([served.text, served.action], ["Open", "open-market-item"]);
});

test("a settled unknown is an enabled View that opens the sheet, never Buy", () => {
  const control = only(render(item(), { access: "unknown" }));
  assert.deepEqual([control.text, control.action, control.disabled], ["View", "view-listing", false]);
});

test("an unavailable card says Unavailable, disabled, with nothing to press -- never View or Checking…", () => {
  const control = only(render(item(), { access: "unavailable" }));
  assert.deepEqual([control.text, control.disabled, control.action], ["Unavailable", true, null]);
  assert.equal(control.accessKey, KEY);
});

test("an item whose pool this Home cannot reach offers nothing to press, held or not", () => {
  for (const listing of [item(), item("purchased")]) {
    const found = elements(render(listing, { access: "elsewhere", readability: "verified", hasItem: true }));
    assert.equal(found[0].tag, "span");
    assert.equal(found[0].text, "Pool not reachable");
    assert.equal(found[0].title, CUSTODY_ELSEWHERE_COPY.replace(/’/g, "’"));
    assert.ok(!found.some((element) => ["buy-listing", "download-market-copy", "open-market-item"].includes(element.action)));
  }
});

test("a bought item not yet here offers Download copy, which says Downloading… while it runs", () => {
  const idle = elements(render(item("purchased"), { readability: "verified", hasItem: true }));
  assert.deepEqual(idle.map((element) => element.text), ["Download copy", "Details"]);
  const running = elements(render(item("purchased"), { readability: "verified", hasItem: true, downloading: true }));
  assert.equal(running[0].text, "Downloading…");
  assert.equal(running[0].disabled, true);
});

// D5 (STAB-25): the label is what the account's access says, never Buy for
// an account the chain grants the item.
test("an item Base has not finalized keeps its control disabled with no action", () => {
  for (const [access, text] of [["held", "Open"], ["available", "Buy"], ["pending", "Checking…"]]) {
    const control = only(render(item(), { finalityPending: true, access }));
    assert.deepEqual([control.text, control.disabled, control.action], [text, true, null], access);
  }
});

// PR5 point 2: a catalog item is told only its kind (`video/*`).
test("the format badge names a wildcard MIME's kind, and keeps concrete badges", () => {
  const badge = (mimeType) => formatBadge({ mimeType });
  assert.deepEqual(
    ["video/*", "image/*", "audio/*", "application/*", "*/*"].map(badge),
    ["VIDEO", "IMAGE", "AUDIO", "FILE", "FILE"],
  );
  assert.deepEqual(
    ["video/mp4", "video/quicktime", "audio/mpeg", "image/jpeg", "application/epub+zip", ""].map(badge),
    ["MP4", "MOV", "MP3", "JPG", "EPUB", "FILE"],
  );
});
