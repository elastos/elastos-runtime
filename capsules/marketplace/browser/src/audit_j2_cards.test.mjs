// AUDIT-REPRO J2 (red, no fix): Explore cards on another Home.
//
// Drives the page's own functions, taken verbatim from marketplace.js (they
// live inside its closure), with the shapes Runtime really sends:
// `list_runtime_custody` (src/listing.js) and the catalog (`/catalog`, joined
// by `mark_held_market_catalog_items`).
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  ACCESS_STATES,
  RUNTIME_CUSTODY_MINT_ID,
  parseRuntimeCustodyListings,
  viewerForListing,
} from "./listing.js";
import { createAccessWatch, createReadSlots, listingReadOutcome } from "./market-access.js";

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

const escapeAttr = (value) => String(value).replace(/"/g, "&quot;");
const MINT = "9672d187".padEnd(64, "0");
const LEDGER = `0x${"ab".repeat(20)}`;
const TOKEN = "0xad527f81";

// The page's card and open functions over one shared state.
function cardPage({ mediaListings = [], catalog = [] } = {}) {
  const posted = [];
  const toasts = [];
  const state = { mediaTab: "explore", mediaListings, catalog };
  const fakeTop = { postMessage: (message, origin) => posted.push({ message, origin }) };
  const names = [
    "state", "pendingMediaBuys", "escapeAttr", "viewerForListing", "RUNTIME_CUSTODY_MINT_ID",
    "ACCESS_STATES", "window", "homeParentOrigin", "homeToken", "showToast", "catalogActionButton",
  ];
  const body = [
    "cidOrEmpty", "catalogMimeType", "catalogItemFromAnswer", "exploreSourceItems",
    "mediaActionButton", "openMedia", "openMintInViewer",
  ].map(pageFunction).join("\n");
  const api = new Function(
    ...names,
    `${body}\nreturn { catalogItemFromAnswer, exploreSourceItems, mediaActionButton, openMedia, openMintInViewer };`,
  )(
    state, new Map(), escapeAttr, viewerForListing, RUNTIME_CUSTODY_MINT_ID,
    ACCESS_STATES, { top: fakeTop }, "https://home.local", "home-token", (text) => toasts.push(text),
    (listing) => `<button data-action="catalog" data-ledger="${listing.ledger}">catalog</button>`,
  );
  return { api, state, posted, toasts };
}

// J2-F1. A channel-granted (or market-bought) item: Runtime holds a Granted
// (or Asset) listing for it. `list_runtime_custody` leaves those out
// (protected_content_runtime.rs:13175-13182; pinned green by
// gateway_tests/library.rs `shelf["data"]["listings"] == []`), while the
// catalog join names its mint with `accessState: "purchased"`
// (`runtime_custody_listing_chain_index`, same test: index[0].access_state ==
// "purchased"). That is exactly the catalog row below with an empty shelf.
test("audit_j2_f1 Open on a held channel-granted catalog item opens a viewer", () => {
  const page = cardPage();
  const row = page.api.catalogItemFromAnswer({
    ledger: LEDGER,
    tokenId: TOKEN,
    mintId: MINT,
    accessState: "purchased",
    displayName: "1717998-uhd_3840_2160_25fps",
    contentCategory: "video",
    price: "0",
  });
  page.state.catalog = [row];
  // Precondition: the card is on Explore and its main control is Open.
  const shown = page.api.exploreSourceItems();
  assert.equal(shown.length, 1);
  assert.equal(shown[0].catalogOnly, false, "a held mint is no longer catalog-only");
  const button = page.api.mediaActionButton(shown[0]);
  assert.match(button, /data-action="open-media"/);
  assert.match(button, new RegExp(`data-mint="${MINT}"`));
  assert.match(button, />Open</);

  // The click handler: `if (action === "open-media") openMedia(target.dataset.mint)`.
  page.api.openMedia(MINT);
  assert.equal(
    page.posted.length + page.toasts.length,
    1,
    "pressing Open on a held item must open a viewer (or say why), not return silently",
  );
});

// J2-F3. A listing added by "Add listing" / a Share link (Imported origin) on a
// Home whose account a channel grants the item: Runtime's shelf row is
// `access_state: "available"` (no purchase record; the chain is not asked,
// protected_content_runtime.rs:13399-13402) and names no ledger, so the page
// has nothing to key the chain's access watch on, and the card says Buy.
test("audit_j2_f3 a local card for an item the chain grants this account does not offer Buy", () => {
  const shelf = parseRuntimeCustodyListings({
    schema: "elastos.library.runtime-custody-listings/v1",
    truncated: false,
    listings: [{
      schema: "elastos.library.runtime-custody-listing/v1",
      mint_id: MINT,
      display_name: "1717998-uhd_3840_2160_25fps",
      content_kind: "media",
      listing_uri: "elastos://bafybeigvnnulsmbnexrvyspkzpem6qjcgsbu4zjkefisghju6vuo7c7rs4",
      metadata_cid: "QmX1KSGkt3fLX5GsuN7wVWrCj55PSnfbk4JJ2BTY2QRJ7F",
      mime_type: "video/mp4",
      codecs: "avc1.640028",
      quantity: "0x3e8",
      price: "0xf4240",
      pay_token: "0x0000000000000000000000000000000000000000",
      seller_address: "0xab5028bdbb0826ad6f1885478e421db677b0001a",
      // What the producer sends since STAB-27 (WP-D `runtime_custody_listing_summary`).
      chain_namespace: "eip155:8453",
      ledger: LEDGER,
      token_id: TOKEN,
      published_at: 1789656297,
      purchase_in_flight: false,
      availability: {
        schema: "elastos.library.runtime-custody-availability-summary/v1",
        status: "last_verified_receipt",
        checked_at: 1789656121,
        required_replicas: 3,
        observed_replicas: 3,
        receipt_digest: "357bc17ce614dda83ef2542c01f574c4db5571fe648e2e60eb9977c8b5f0c8ef",
        recheck_before_buy: true,
        recheck_before_open: true,
      },
      access_state: "available",
    }],
  });
  const local = shelf.listings[0];
  const page = cardPage({ mediaListings: [local] });
  const button = page.api.mediaActionButton(page.api.exploreSourceItems()[0]);
  assert.ok(
    local.ledger,
    `the shelf row must name its ledger so the chain's access watch can answer for it; button: ${button}`,
  );
  assert.doesNotMatch(button, />Buy</, "a channel subscriber is offered Buy");
});

// J2-F5. A card whose listing read answered a final `no_holder` (or ran out
// of retries) is `unavailable` for the life of the page: the Refresh control
// (`refreshMediaSurface`) reloads the shelf and the catalog but never tells
// the access watch, whose `needsRead` answers false for `unavailable`.
test("audit_j2_f5 Refresh asks again for a card that settled as unavailable", async () => {
  const KEY = `${LEDGER}|${TOKEN}`;
  let reads = 0;
  const watch = createAccessWatch({
    // What `readCatalogAccess` answers for a listing read refused `no_holder`.
    read: async () => {
      reads += 1;
      return listingReadOutcome({ code: "no_holder" });
    },
    waitsForFinality: () => false,
    onChange: () => {},
    slots: createReadSlots(4),
    now: () => Date.now(),
    setTimer: () => 0,
    clearTimer: () => {},
  });
  watch.show([KEY]);
  for (let i = 0; i < 10; i += 1) await new Promise((resolve) => setImmediate(resolve));
  assert.equal(reads, 1, "precondition: one read");
  assert.equal(watch.state(KEY), "unavailable", "precondition: settled final");

  // The page's own Refresh, then the render that shows the same cards again.
  const state = { mediaRefreshing: false, mediaTab: "explore", catalogLoaded: true, shopsLoaded: true };
  const refresh = new Function(
    "state", "loadMediaData", "loadCatalogItems", "loadPayTokens", "loadShopsData", "render", "showToast",
    "refreshSummary", "accessWatch",
    `async ${pageFunction("refreshMediaSurface")}\nreturn refreshMediaSurface;`,
  )(
    state, async () => {}, async () => {}, async () => {}, async () => {},
    () => watch.show([KEY]), () => {}, () => "", watch,
  );
  await refresh(null);
  for (let i = 0; i < 10; i += 1) await new Promise((resolve) => setImmediate(resolve));
  assert.equal(reads, 2, "an explicit Refresh must read the card's listing again");
});
