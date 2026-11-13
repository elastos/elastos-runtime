import assert from "node:assert/strict";
import test from "node:test";

import { catalogCardControl } from "./market-card.js";
import { CUSTODY_ELSEWHERE_COPY } from "./market-listing.js";

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
  for (const access of ["checking", "retrying", "pending"]) {
    const control = only(render(item(), { access }));
    assert.equal(control.text, "Checking…", String(access));
    assert.equal(control.disabled, true);
    assert.equal(control.action, null);
    assert.equal(control.accessKey, KEY.replace("|", "|"));
  }
});

test("no access, or no wallet account to ask about, is Buy", () => {
  for (const access of ["available", "no_account"]) {
    const control = only(render(item(), { access }));
    assert.deepEqual([control.text, control.action, control.disabled], ["Buy", "buy-listing", false], access);
  }
});

test("access the chain grants is Open, which builds the copy and opens it", () => {
  const control = only(render(item(), { access: "held" }));
  assert.deepEqual([control.text, control.action, control.disabled], ["Open", "open-market-item", false]);
  const opening = only(render(item(), { access: "held", downloading: true }));
  assert.deepEqual([opening.text, opening.disabled], ["Opening…", true]);
  const foreign = only(render(item(), { access: "held", readability: "foreign" }));
  assert.deepEqual([foreign.tag, foreign.text], ["span", "Opens on ela.city"]);
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

test("an item Base has not finalized keeps its control disabled with no action", () => {
  const control = only(render(item(), { finalityPending: true, access: "held" }));
  assert.deepEqual([control.text, control.disabled, control.action], ["Buy", true, null]);
});
