// DEMO-ISSUES B: a pasted link whose folder is neither an item nor a listing
// package is answered `not_a_listing` (404). The page says so plainly and
// finally, never "The market couldn't be reached. Try again."
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { parseRuntimeCustodyListings, uint256Decimal } from "./listing.js";
import { createReadSlots } from "./market-access.js";

const PAGE = process.env.MARKETPLACE_PAGE_UNDER_TEST || new URL("../marketplace.js", import.meta.url);

/** The page's own `marketListingErrorMessage`, run as written. */
function marketListingErrorMessage() {
  const source = readFileSync(PAGE, "utf8");
  const start = source.indexOf("function marketListingErrorMessage(code)");
  assert.ok(start > 0, "marketListingErrorMessage is in marketplace.js");
  const end = source.indexOf("\n  }\n", start);
  const unreachable = source.match(/const MARKET_UNREACHABLE_COPY = ("[^"]*");/)[1];
  return new Function(`const MARKET_UNREACHABLE_COPY = ${unreachable}; return ${source.slice(start, end + 4)}`)();
}

test("a link that is not a listing is told so, finally", () => {
  const message = marketListingErrorMessage()("not_a_listing");
  assert.equal(message, "That link isn’t a listing.");
  assert.doesNotMatch(message, /try again|couldn’t be reached/i);
});

test("guard: a market that could not be read still says Try again", () => {
  assert.match(marketListingErrorMessage()("unavailable"), /Try again/);
});

// Exercise the page's actual click and fetch functions, without a browser or
// credentials. The action header joins diagnostics only; request bodies and
// existing Home-token authority stay unchanged.
function importActionHarness({ withoutUuid = false, failImport = false } = {}) {
  const source = readFileSync(PAGE, "utf8");
  const names = ["importListing", "readMarketListing", "requestMarketListing", "postObjectProvider"];
  const functions = names.map((name) => {
    const start = source.indexOf(`async function ${name}(`);
    assert.ok(start > 0, `${name} is in marketplace.js`);
    const end = source.indexOf("\n  }\n", start);
    assert.ok(end > start);
    return source.slice(start, end + 4);
  }).join("\n");
  const calls = [];
  const slotAdmissions = [];
  const marketReadSlots = createReadSlots(2);
  let ids = 0;
  const page = new Function("fetch", "crypto", "marketReadSlots", `
    const homeToken = "fixture-home-token";
    let importInFlight = false;
    const els = { importInput: { value: "" }, importSubmit: {
      disabled: false, setAttribute() {}, removeAttribute() {}
    } };
    const marketLinkFromInput = (value) => value;
    const legacyListingUriFromLink = (value) => value;
    const showToast = () => {};
    const publicError = (value) => value;
    const loadMediaData = async () => {};
    const render = () => {};
    ${functions}
    return { importListing, requestMarketListing, postObjectProvider };
  `)(async (route, init) => {
    calls.push({ route, init });
    const admitted = marketReadSlots.tryAcquire();
    slotAdmissions.push(admitted);
    if (admitted) marketReadSlots.release();
    if (failImport && route.endsWith("/import_runtime_custody")) throw new Error("unavailable");
    return { ok: true, json: async () => route === "/api/apps/marketplace/listing"
      ? { legacy_listing: true } : { status: "ok", data: {} } };
  }, withoutUuid ? {} : { randomUUID: () => `00000000-0000-4000-8000-${String(++ids).padStart(12, "0")}` }, marketReadSlots);
  return { ...page, calls, slotAdmissions, marketReadSlots };
}

test("one Add listing action joins lookup and legacy import, and the next click has a fresh ID", async () => {
  const page = importActionHarness();
  const link = `elastos://bafy${"a".repeat(55)}`;
  await page.importListing(link);
  await page.importListing(link);
  assert.deepEqual(page.calls.map(({ route }) => route), [
    "/api/apps/marketplace/listing", "/api/provider/object/import_runtime_custody",
    "/api/apps/marketplace/listing", "/api/provider/object/import_runtime_custody",
  ]);
  const ids = page.calls.map(({ init }) => init.headers["x-elastos-action-id"]);
  assert.match(ids[0] || "", /^[0-9a-f-]{36}$/);
  assert.equal(ids[0], ids[1]);
  assert.equal(ids[2], ids[3]);
  assert.notEqual(ids[0], ids[2]);
  for (const { init } of page.calls) {
    assert.equal(init.headers["x-elastos-home-token"], "fixture-home-token");
    assert.equal(init.headers["content-type"], "application/json");
  }
  assert.deepEqual(JSON.parse(page.calls[0].init.body), { start: { token_uri: link } });
  assert.deepEqual(JSON.parse(page.calls[1].init.body), { listing_uri: link });
});

test("unrelated listing reads and object operations omit the optional action header", async () => {
  const page = importActionHarness();
  await page.requestMarketListing({ item: { ledger: "fixture", token_id: "1" } });
  await page.postObjectProvider("list_runtime_custody", {});
  for (const { init } of page.calls) {
    assert.equal(Object.hasOwn(init.headers, "x-elastos-action-id"), false);
  }
});

test("Add listing defers card reads through legacy import and wakes them on success or failure", async () => {
  for (const failImport of [false, true]) {
    const { importListing, marketReadSlots, slotAdmissions } = importActionHarness({ failImport });
    assert.ok(marketReadSlots.tryAcquire(), "a card read is already in flight");
    let wakes = 0;
    marketReadSlots.onRelease(() => { wakes += 1; });

    await importListing(`elastos://bafy${"a".repeat(55)}`);

    assert.deepEqual(slotAdmissions, [false, false]);
    assert.equal(wakes, 1, "waiting cards are notified as soon as Add settles");
    assert.ok(marketReadSlots.tryAcquire());
    assert.equal(marketReadSlots.tryAcquire(), false, "Add does not release the in-flight card's slot");
    marketReadSlots.release();
    marketReadSlots.release();
  }
});


test("Add listing still carries a trace ID when randomUUID is unavailable", async () => {
  const page = importActionHarness({ withoutUuid: true });
  await page.importListing(`elastos://bafy${"a".repeat(55)}`);
  assert.equal(page.calls.length, 2);
  const ids = page.calls.map(({ init }) => init.headers["x-elastos-action-id"]);
  assert.match(ids[0] || "", /^[A-Za-z0-9-]{1,64}$/);
  assert.equal(ids[0], ids[1]);
});

test("successful Add reloads the real parser and Explore cards without hiding fetched or granted rows", async () => {
  const cid = `bafy${"a".repeat(55)}`;
  const row = {
    schema: "elastos.library.runtime-custody-listing/v1", mint_id: "ab".repeat(32),
    display_name: "Added clip.mp4", content_kind: "media", listing_uri: `elastos://${cid}`,
    metadata_cid: cid, mime_type: "video/mp4", codecs: "avc1.640028", quantity: "0x1", price: "0x0",
    pay_token: `0x${"0".repeat(40)}`, seller_address: `0x${"1".repeat(40)}`,
    chain_namespace: "eip155:8453", ledger: `0x${"2".repeat(40)}`, token_id: "0x1",
    published_at: null, purchase_in_flight: false, access_state: "purchased",
    availability: { schema: "elastos.library.runtime-custody-availability-summary/v1",
      status: "last_verified_fetch", checked_at: 1800000000, required_replicas: 1,
      observed_replicas: 0, receipt_digest: "", recheck_before_buy: true, recheck_before_open: true },
  };
  const payload = { schema: "elastos.library.runtime-custody-listings/v1", truncated: false,
    listings: [row, { ...row, mint_id: "cd".repeat(32), listing_uri: null, token_id: "0x2" }] };
  const source = readFileSync(PAGE, "utf8");
  const names = ["importListing", "readMarketListing", "requestMarketListing", "postObjectProvider",
    "loadMediaData", "showToast", "renderExploreSections", "exploreSourceItems", "filteredMediaListings",
    "sortExploreListings", "groupExploreListings", "exploreGroupFor", "exploreGroupId", "shelfNotice",
    "renderMediaCard", "cardStateName", "statusTag", "priceBlock", "mediaCardSubtitle",
    "cardActions", "cardSecondaryActions", "mediaActionButton", "buyStateNoteMarkup", "availabilitySummary"];
  const functions = names.map((name) => {
    let start = source.indexOf(`function ${name}(`);
    assert.ok(start > 0, name);
    if (source.slice(start - 6, start) === "async ") start -= 6;
    const end = source.indexOf("\n  }\n", start);
    return source.slice(start, end + 4);
  }).join("\n");
  const calls = [];
  // Only DOM plumbing, decoration and optional cover fetching are doubles.
  // Add, local reload, parsing, dedup, grouping, cards and action buttons run
  // the shipping functions. This is not a browser/remote playback test.
  const page = new Function("fetch", "parseRuntimeCustodyListings", "uint256Decimal", "marketReadSlots", `
    const homeToken = "fixture-home-token";
    const crypto = { randomUUID: () => "fixture-add-action" };
    const window = { setTimeout() { return 1; }, clearTimeout() {} };
    let importInFlight = false;
    const classes = new Set();
    const els = { importInput: { value: "fixture link" }, importSubmit: {
      disabled: false, setAttribute() {}, removeAttribute() {}
    }, storeSections: { innerHTML: "" }, toast: { textContent: "", classList: {
      add(name) { classes.add(name); }, remove(name) { classes.delete(name); },
      toggle(name, yes) { if (yes) classes.add(name); else classes.delete(name); }
    } } };
    const state = { mediaTab: "explore", catalogReady: true, catalogLoading: false,
      catalog: [{ mintId: "${row.mint_id}" }], mediaListings: [], mediaTruncated: false,
      mediaRejected: 0, search: "", exploreFilter: "all", exploreGroup: "", exploreSort: "newest" };
    const EXPLORE_GROUPS = [{ id: "videos", title: "Videos", shape: "wide", limit: 8, matches: () => true }];
    const EXPLORE_ROW_LIMIT = 8, MAX_RUNTIME_CUSTODY_LISTINGS = 128;
    const listingMetadata = new Map(), pendingDownloads = new Set(), pendingMediaBuys = new Map();
    const itemKey = (item) => item.mintId || item.catalogId || "";
    const marketLinkFromInput = (value) => value, legacyListingUriFromLink = (value) => value;
    const publicError = (value) => value, escapeHtml = (value) => String(value), escapeAttr = escapeHtml;
    const icons = { media: "" }, spriteIcon = () => "", formatBadge = () => "MP4";
    const ownedLabel = () => "Purchased", sellerByline = () => "Seller";
    const marketNotice = () => "", renderExploreChips = () => {}, bindAppActions = () => {};
    const requestListingMetadata = () => {}, emptyState = (title) => title;
    const render = () => renderExploreSections();
    ${functions}
    return { importListing, state, els, renderExploreSections, availabilitySummary };
  `)(async (route) => {
    calls.push(route);
    const data = route.endsWith("/listing") ? { legacy_listing: true }
      : { status: "ok", data: route.endsWith("list_runtime_custody") ? payload : { status: "verified" } };
    return { ok: true, json: async () => data };
  }, parseRuntimeCustodyListings, uint256Decimal, createReadSlots(2));
  await page.importListing(`elastos://${cid}`);
  assert.deepEqual(calls, ["/api/apps/marketplace/listing", "/api/provider/object/import_runtime_custody",
    "/api/provider/object/list_runtime_custody"]);
  assert.equal(page.els.toast.textContent, "Listing added.");
  assert.equal(page.els.importInput.value, "");
  assert.equal(page.state.mediaRejected, 0, "successful Runtime rows must not turn into the hidden-items notice");
  assert.equal(page.state.mediaListings.length, 2);
  assert.equal((page.els.storeSections.innerHTML.match(/<article /g) || []).length, 2, "the catalog copy is deduplicated");
  assert.match(page.els.storeSections.innerHTML, /data-action="open-media"/);
  assert.doesNotMatch(page.els.storeSections.innerHTML, /data-action="share-listing"|items? could not be read/);
  assert.equal(page.availabilitySummary(page.state.mediaListings[0].availability), "Manifest checked");
  page.state.mediaTab = "mine";
  page.renderExploreSections();
  assert.equal(page.els.storeSections.innerHTML, "No protected items yet", "My listings remains creator-only");
});
