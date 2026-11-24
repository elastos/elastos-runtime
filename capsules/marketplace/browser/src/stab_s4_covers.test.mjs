// STAB-REPRO S4 (red, no fix): covers on Explore cards and in the offer sheet
// on Home-7, and cards that stay "Checking…".
//
// Drives the page's real code: `bindRasterIconFallbacks` and `offerSheetIcon`
// are taken verbatim from marketplace.js (they live inside its closure), the
// real `hydrateContentImages`, and the real access watch and card control.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { hydrateContentImages } from "./content-reads.js";
import { createAccessWatch, createReadSlots, listingReadOutcome, READ_DEADLINE_MS } from "./market-access.js";
import { catalogCardControl } from "./market-card.js";
import { FINALITY_CHECK_CONCURRENCY } from "./market-finality.js";

const here = (path) => fileURLToPath(new URL(path, import.meta.url));
const PAGE_JS = readFileSync(here("../marketplace.js"), "utf8");
const PAGE_CSS = readFileSync(here("../marketplace.css"), "utf8");

// One `function name(...) { ... }` from the page, exactly as written.
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

// The minimum DOM the fallback touches.
function element({ classes = [], dataset = {} } = {}) {
  const listeners = new Map();
  const list = new Set(classes);
  return {
    dataset: { ...dataset },
    hidden: false,
    complete: false,
    style: {},
    src: "",
    classList: {
      add: (name) => list.add(name),
      remove: (name) => list.delete(name),
      contains: (name) => list.has(name),
      toggle: (name, on) => (on ? list.add(name) : list.delete(name)),
    },
    classes: () => [...list],
    removeAttribute(name) {
      if (name === "data-cover") delete this.dataset.cover;
    },
    addEventListener(type, callback) {
      listeners.set(type, [...(listeners.get(type) || []), callback]);
    },
    dispatchEvent(event) {
      for (const callback of listeners.get(event.type) || []) callback(event);
    },
  };
}

const flush = async () => {
  for (let i = 0; i < 5; i += 1) await new Promise((resolve) => setImmediate(resolve));
};

// The offer sheet on Home-7: Runtime's `/listing` named the cover
// (`asset.cover_cid`), and `/content/<cover>` answers 404 there (see
// stab_s4_content_route_reads_a_cover_that_a_carrier_holder_serves), so the
// image fails and the sheet falls back. The fallback must still be a visible
// tile -- not a white glyph on no background, i.e. a blank white box.
test("stab_s4: the offer sheet's icon after its cover fails is not a blank white box", async () => {
  const { bindRasterIconFallbacks, offerSheetIcon } = new Function(
    "hydrateContentImages", "contentReader", "icons", "escapeAttr",
    `${pageFunction("bindRasterIconFallbacks")}\n${pageFunction("offerSheetIcon")}\n` +
      "return { bindRasterIconFallbacks, offerSheetIcon };",
  )(
    hydrateContentImages,
    // What the page's reader answers for a cover this Home cannot read.
    { readyImageUrl: () => undefined, imageUrl: async () => "" },
    { media: "<svg></svg>" },
    (value) => String(value),
  );
  const markup = offerSheetIcon({ asset: { coverCid: "QmQRymQvJvzZQmsWurAjabCFENe44BsRneqtrUnxd9hUhM" } });
  const containerClasses = markup.match(/^<span class="([^"]+)"/)[1].split(" ");
  const cid = markup.match(/data-content-cid="([^"]+)"/)[1];

  const container = element({ classes: containerClasses });
  const image = element({ dataset: { contentCid: cid } });
  const glyph = element();
  glyph.hidden = true;
  container.querySelector = (selector) => ({ ".app-icon-img": image, ".app-icon-glyph": glyph }[selector] || null);
  const root = {
    querySelectorAll: (selector) => ({
      ".app-icon-raster": [container],
      "img[data-content-cid]": [image],
    }[selector] || []),
  };
  bindRasterIconFallbacks(root);
  await flush();

  // The fallback ran: the glyph shows instead of the image.
  assert.equal(glyph.hidden, false, "precondition: the fallback replaced the failed cover");
  // `.app-icon svg { fill: white }`: the glyph is white, so the tile needs a
  // background of its own. The page's backgrounds are its `.gradient-*` classes.
  assert.match(PAGE_CSS, /\.app-icon svg \{[^}]*fill: white/);
  const backgrounds = [...PAGE_CSS.matchAll(/^\.(gradient-[a-z]+) \{ background:/gm)].map((m) => m[1]);
  const shown = container.classes();
  assert.ok(
    shown.some((name) => backgrounds.includes(name)),
    `the fallback tile has no background, so its white glyph is invisible on the white sheet: classes ${JSON.stringify(shown)}`,
  );
});

// A small fake clock for the access watch.
function clock() {
  let t = 1_700_000_000_000;
  let seq = 0;
  const timers = new Map();
  return {
    now: () => t,
    setTimer(cb, delay) { const id = ++seq; timers.set(id, { at: t + Math.max(0, delay), cb }); return id; },
    clearTimer(id) { timers.delete(id); },
    async advance(ms) {
      const end = t + ms;
      for (;;) {
        let next = null;
        for (const [id, x] of timers) if (x.at <= end && (!next || x.at < next[1].at)) next = [id, x];
        if (!next) break;
        timers.delete(next[0]);
        t = next[1].at;
        next[1].cb();
        await flush();
      }
      t = end;
      await flush();
    },
  };
}

const LEDGER = `0x${"a".repeat(40)}`;
const label = (watch, key) => {
  const [ledger, tokenId] = key.split("|");
  const html = catalogCardControl({ ledger, tokenId, accessState: "available" }, { key, access: watch.state(key) });
  return html.match(/>([^<>]+)<\/(button|span)>/)[1];
};

// A card whose listing read failed (Runtime answered `unavailable`: the market
// or chain could not be read in time) waits 15 s, 60 s, then 5 min to ask
// again -- and says "Checking…" the whole time, as if it were still asking.
test("stab_s4: a card whose listing read failed does not keep saying Checking…", async () => {
  const clk = clock();
  const key = `${LEDGER}|0x1`;
  const watch = createAccessWatch({
    read: async () => listingReadOutcome({ code: "unavailable" }),
    onChange: () => {},
    slots: createReadSlots(FINALITY_CHECK_CONCURRENCY),
    now: clk.now, setTimer: clk.setTimer, clearTimer: clk.clearTimer,
  });
  watch.show([key]);
  await clk.advance(1_000);
  assert.equal(watch.state(key), "retrying", "precondition: the read answered and failed");
  const seen = [];
  for (let s = 0; s < 6 * 60; s += 30) {
    seen.push(label(watch, key));
    await clk.advance(30_000);
  }
  const checking = seen.filter((text) => text === "Checking…").length * 30;
  assert.equal(
    checking,
    0,
    `after its read had already answered, the card still said "Checking…" for ${checking} s of the next 6 min`,
  );
});

// Every card's access read and every finality re-check share
// FINALITY_CHECK_CONCURRENCY (2) slots. A Home-7 listing read is a Carrier
// read of the folder (up to 20 s) plus chain reads, bounded at 30 s by
// MARKET_LISTING_DEADLINE; at that cost a shelf of 8 cards is still
// "Checking…" well past one read's deadline.
test("stab_s4: a shelf of 8 cards is answered within one read deadline", async () => {
  const clk = clock();
  const keys = Array.from({ length: 8 }, (_, i) => `${LEDGER}|0x${(i + 1).toString(16)}`);
  const watch = createAccessWatch({
    read: (key) => new Promise((resolve) => clk.setTimer(() => resolve(listingReadOutcome({
      listing: {
        item: { chainNamespace: "eip155:8453", ledger: LEDGER, token_id: key.split("|")[1] },
        asset: { readability: "verified" },
        accessState: "available",
        accessSubject: "S",
        custodyRoute: "resolved",
      },
    })), 30_000)),
    onChange: () => {},
    slots: createReadSlots(FINALITY_CHECK_CONCURRENCY),
    now: clk.now, setTimer: clk.setTimer, clearTimer: clk.clearTimer,
  });
  watch.show(keys);
  await clk.advance(READ_DEADLINE_MS);
  const still = keys.filter((key) => label(watch, key) === "Checking…");
  assert.deepEqual(
    still,
    [],
    `${still.length} of 8 cards still say "Checking…" ${READ_DEADLINE_MS / 1000} s after the shelf was shown`,
  );
});
