// STAB-IMPL WP-G: Explore cards for an item this Home holds, and Explore's
// market read over a long-open page.
//
// STAB-04 (J2-F1): a held catalog row opens in the viewer its kind names.
// STAB-27 (J2-F3): a local card the chain grants this account opens, by its
// own mint, instead of offering Buy.
// J2-F9: Explore reads the market again when it is looked at after its last
// read went stale.
//
// Drives the page's own functions, taken verbatim from marketplace.js (they
// live inside its closure), and the real card control.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { ACCESS_STATES, RUNTIME_CUSTODY_MINT_ID, viewerForListing } from "./listing.js";
import { listingReadOutcome } from "./market-access.js";
import { catalogCardControl } from "./market-card.js";

const here = (path) => fileURLToPath(new URL(path, import.meta.url));
const PAGE_JS = readFileSync(here("../marketplace.js"), "utf8");

function pageFunction(name) {
  const start = PAGE_JS.indexOf(`function ${name}(`);
  assert.ok(start >= 0, `marketplace.js defines ${name}`);
  let depth = 0;
  for (let i = PAGE_JS.indexOf("{", start); i < PAGE_JS.length; i += 1) {
    if (PAGE_JS[i] === "{") depth += 1;
    if (PAGE_JS[i] === "}" && --depth === 0) return PAGE_JS.slice(start, i + 1);
  }
  throw new Error(`unbalanced ${name}`);
}

// A page constant, exactly as written.
function pageConstant(name) {
  const match = PAGE_JS.match(new RegExp(`const ${name} = ([^;]+);`));
  assert.ok(match, `marketplace.js defines ${name}`);
  return new Function(`return ${match[1]};`)();
}

const MINT = "4c1e5a7d".padEnd(64, "0");
const LEDGER = `0x${"ab".repeat(20)}`;
const TOKEN = "0xad527f81";
const KEY = `${LEDGER}|${TOKEN}`;

// STAB-04. The catalog join names the kind of a held mint (`contentKind`),
// because the shelf leaves Granted and Asset listings out and the catalog row
// is then the page's only record of the item.
test("stab_04 a held catalog row opens in the viewer its kind names", () => {
  const posted = [];
  const state = { mediaListings: [], catalog: [] };
  const names = [
    "state", "viewerForListing", "RUNTIME_CUSTODY_MINT_ID", "ACCESS_STATES", "window",
    "homeParentOrigin", "homeToken", "showToast",
  ];
  const body = ["cidOrEmpty", "catalogMimeType", "catalogItemFromAnswer", "openMedia"]
    .map(pageFunction)
    .join("\n");
  const api = new Function(...names, `${body}\nreturn { catalogItemFromAnswer, openMedia };`)(
    state, viewerForListing, RUNTIME_CUSTODY_MINT_ID, ACCESS_STATES,
    { top: { postMessage: (message) => posted.push(message) } }, "https://home.local", "home-token",
    () => assert.fail("no toast"),
  );
  const row = (contentKind) => api.catalogItemFromAnswer({
    ledger: LEDGER, tokenId: TOKEN, mintId: MINT, accessState: "purchased", contentCategory: "video", contentKind,
  });

  state.catalog = [row("media")];
  api.openMedia(MINT);
  assert.equal(posted.at(-1).target, "elacity-player", "a held video opens in the Player");
  assert.deepEqual(posted.at(-1).query, { mint_id: MINT });

  state.catalog = [row("object")];
  api.openMedia(MINT);
  assert.equal(posted.at(-1).target, "elacity-reader", "a held object opens in the Reader");

  // A kind the page does not know is not passed on: the Reader says so.
  assert.equal(row("document").contentKind, "");
});

// STAB-27. A listing this Home holds that this person has not bought: the
// chain may still grant it (a channel subscription). The access watch answers
// for it, and the card acts on the listing's own mint.
const local = { ledger: LEDGER, tokenId: TOKEN, accessState: "available", mintId: MINT };
const control = (access) => catalogCardControl(local, { key: KEY, size: "", access, mint: MINT });

test("stab_27 a local card the chain grants this account opens by its mint", () => {
  const markup = control("held");
  assert.match(markup, /data-action="open-media"/, markup);
  assert.match(markup, new RegExp(`data-mint="${MINT}"`), markup);
  assert.match(markup, new RegExp(`data-access-key="${KEY.replace("|", "\\|")}"`), markup);
  assert.match(markup, />Open</, markup);
});

test("stab_27 a local card not answered yet says Checking…, never Buy", () => {
  for (const access of ["checking", "pending"]) {
    const markup = control(access);
    assert.match(markup, />Checking…</, `${access}: ${markup}`);
    assert.match(markup, /data-access-key=/, markup);
    assert.doesNotMatch(markup, />Buy</, markup);
  }
});

test("stab_27 a local card the chain does not grant keeps its own Buy, by its mint", () => {
  for (const access of ["available"]) {
    const markup = control(access);
    assert.match(markup, /data-action="buy-media"/, `${access}: ${markup}`);
    assert.match(markup, new RegExp(`data-mint="${MINT}"`), markup);
    assert.match(markup, /data-access-key=/, markup);
    assert.match(markup, />Buy</, markup);
  }
});

// J2-F9. Explore read the market once per page: a page left open never saw
// what was minted since unless the person pressed Refresh.
function tabData(stateOverrides) {
  const reads = [];
  const state = {
    destination: "media",
    mediaTab: "explore",
    catalogLoaded: true,
    catalogLoading: false,
    catalogReadAt: 0,
    shopsLoaded: true,
    shopsLoading: false,
    ...stateOverrides,
  };
  const ensure = new Function(
    "state", "loadCatalogItems", "loadShopsData", "render", "CATALOG_STALE_MS",
    `${pageFunction("ensureMediaTabData")}\nreturn ensureMediaTabData;`,
  )(
    state,
    (options) => {
      reads.push(options);
      return Promise.resolve();
    },
    () => Promise.resolve(),
    () => {},
    pageConstant("CATALOG_STALE_MS"),
  );
  return { ensure, reads, state };
}

test("j2_f9 Explore asks the market again when it is looked at after its read went stale", () => {
  const stale = pageConstant("CATALOG_STALE_MS");
  const fresh = tabData({ catalogReadAt: Date.now() });
  fresh.ensure();
  assert.equal(fresh.reads.length, 0, "a current read is not repeated");

  const old = tabData({ catalogReadAt: Date.now() - stale - 1 });
  old.ensure();
  assert.equal(old.reads.length, 1, "a stale read is asked again");

  const busy = tabData({ catalogReadAt: Date.now() - stale - 1, catalogLoading: true });
  busy.ensure();
  assert.equal(busy.reads.length, 0, "a read in flight is not doubled");
});

test("j2_f9 a page coming back into view asks what its surface needs", () => {
  const calls = [];
  const watch = (name) => ({ pause: () => calls.push(`${name}.pause`), resume: () => calls.push(`${name}.resume`) });
  const onVisibilityChange = new Function(
    "document", "finalityWatch", "accessWatch", "syncFinalityWatch", "ensureMediaTabData",
    `${pageFunction("onVisibilityChange")}\nreturn onVisibilityChange;`,
  );
  const visible = onVisibilityChange(
    { hidden: false }, watch("finality"), watch("access"), () => calls.push("sync"), () => calls.push("ensure"),
  );
  visible();
  assert.ok(calls.includes("ensure"), `back in sight, the surface's reads are checked: ${calls}`);

  calls.length = 0;
  const hidden = onVisibilityChange(
    { hidden: true }, watch("finality"), watch("access"), () => calls.push("sync"), () => calls.push("ensure"),
  );
  hidden();
  assert.deepEqual(calls, ["finality.pause", "access.pause"], "a hidden tab reads nothing");
});

// D5 (STAB-24, 26): the one wording rule holds for a local card too.
test("stab_d5 a local card with no Wallet account, or a failed read, never offers Buy", () => {
  const cases = [["no_account", "Add a Wallet account", "open-wallet"], ["retrying", "Try again", "retry-access"]];
  for (const [access, text, action] of cases) {
    const markup = catalogCardControl(
      { ledger: LEDGER, tokenId: TOKEN, accessState: "available" },
      { key: `${LEDGER}|${TOKEN}`, mint: MINT, access },
    );
    assert.match(markup, new RegExp(`data-action="${action}"[^>]*>${text}<`), `${access}: ${markup}`);
    assert.doesNotMatch(markup, />Buy</, `${access}: ${markup}`);
  }
});

// D4-A guard (ADV-19, DKMS-14): a row without a proven KID-to-item binding
// stays visible but never shows available or Open. The listing read answers
// such a row `unbound` (final) or `pending_finality` (waiting); neither
// renders Open or an enabled Buy, and the catalog row itself, with no KID
// and no answer yet, renders neither either.
test("guard_an_unbound_row_offers_neither_open_nor_an_enabled_buy", () => {
  const row = { ledger: LEDGER, tokenId: TOKEN, accessState: "available" };
  const key = `${LEDGER}|${TOKEN}`;
  assert.deepEqual(listingReadOutcome({ code: "unbound" }), { kind: "unavailable" });
  const controls = [undefined, MINT].flatMap((mint) => [
    catalogCardControl(row, { key, mint, access: "unavailable" }),
    catalogCardControl(row, { key, mint, access: "checking" }),
    catalogCardControl(row, { key, mint, finalityPending: true, access: "pending" }),
    catalogCardControl(row, { key, mint, finalityPending: true, access: "available" }),
  ]);
  for (const markup of controls) {
    assert.doesNotMatch(markup, />Open</, markup);
    const buy = /<button([^>]*)>Buy</u.exec(markup);
    assert.ok(!buy || /\bdisabled\b/u.test(buy[1]), `an enabled Buy on an unproven row: ${markup}`);
  }
});

// STAB-R1-F2: the real local-mint branch follows the same chain states.
test("a local mint offers Buy only for explicit available access", () => {
  const states = [
    ["unknown", "View", "view-listing"],
    ["unavailable", "Unavailable", null],
    ["elsewhere", "Pool not reachable", null],
    ["no_account", "Add a Wallet account", "open-wallet"],
    ["retrying", "Try again", "retry-access"],
    ["checking", "Checking…", null],
    ["pending", "Checking…", null],
    ["unrecognized", "Unavailable", null],
  ];
  for (const [access, label, action] of states) {
    const markup = control(access);
    assert.doesNotMatch(markup, />Buy<|>Open<|data-action="(?:buy-media|open-media)"/, `${access}: ${markup}`);
    assert.ok(markup.includes(`>${label}<`), `${access}: ${markup}`);
    if (action) assert.ok(markup.includes(`data-action="${action}"`), `${access}: ${markup}`);
    else assert.doesNotMatch(markup, /data-action=/, `${access}: ${markup}`);
    if (["unavailable", "unrecognized"].includes(access)) assert.match(markup, /\bdisabled\b/, markup);
  }
  assert.match(control("available"), /data-action="buy-media"[^>]*>Buy</);
  assert.match(control("held"), /data-action="open-media"[^>]*>Open</);
});
