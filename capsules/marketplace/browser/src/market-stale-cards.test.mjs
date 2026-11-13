// A market read that never settles, a timer that fires early, and an access
// "pending" the finality watch let go of must never leave a card stuck. Drives
// the real access watch, finality watch and card markup, with the page's glue
// (readCatalogAccess, checkCatalogFinality, the render loop) in miniature, on
// a fake clock.
import assert from "node:assert/strict";
import test from "node:test";

const { createAccessWatch, createReadSlots, listingReadOutcome, READ_DEADLINE_MS } = await import("./market-access.js");
const {
  createFinalityWatch, finalityCheckResult, finalityCopy, FINALITY_CHECK_CONCURRENCY, PENDING_FINALITY_CODE,
} = await import("./market-finality.js");
const { catalogCardControl } = await import("./market-card.js");

const LEDGER = `0x${"a".repeat(40)}`;
const NEW = `${LEDGER}|0x1`;
const OLD = `${LEDGER}|0x2`;
const THIRD = `${LEDGER}|0x3`;

async function flush() {
  for (let i = 0; i < 10; i++) await new Promise((r) => setImmediate(r));
}

function clock({ driftEveryMs = 0 } = {}) {
  const start = 1_700_000_000_000;
  let t = start;
  let seq = 0;
  const timers = new Map();
  return {
    // `driftEveryMs`: the wall clock the watch reads loses 1 ms per that
    // much timer time (as Date.now() vs a monotonic timer can; Node fires a
    // 15 ms timer before Date.now() reaches its deadline ~1% of the time).
    now: () => t - (driftEveryMs ? Math.floor((t - start) / driftEveryMs) : 0),
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
    get t() { return t; },
  };
}

const elsewhereListing = (key) => {
  const [ledger, token_id] = key.split("|");
  return {
    item: { chainNamespace: "eip155:8453", ledger, token_id },
    asset: { readability: "verified" },
    accessState: "available",
    accessSubject: "S",
    custodyRoute: "unresolved",
  };
};

// `server(key, n)` answers the n-th read of key: a listing, an error, or "hang".
function page({ server, catalog, clk }) {
  const reads = [];
  const counts = new Map();
  const pendingNever = [];
  const slots = createReadSlots(FINALITY_CHECK_CONCURRENCY);
  const cards = new Map();
  let repaintQueued = false;

  async function request(key) {
    const n = (counts.get(key) || 0) + 1;
    counts.set(key, n);
    reads.push([key, n, clk.t]);
    const a = server(key, n);
    if (a === "hang") return new Promise((resolve) => pendingNever.push(resolve));
    if (a.error) throw Object.assign(new Error(a.error.code), a.error);
    return a.listing;
  }
  function noteReadability(listing, { access = true } = {}) {
    if (access) access_.note(`${listing.item.ledger}|${listing.item.token_id}`, listing);
  }
  const finality = createFinalityWatch({
    check: async (key) => {
      try { const l = await request(key); noteReadability(l); return { kind: "ready" }; }
      catch (e) { return finalityCheckResult(e); }
    },
    onChange: () => repaint(),
    onTick: () => tick(),
    setTimer: clk.setTimer, clearTimer: clk.clearTimer, now: clk.now, slots,
  });
  const access_ = createAccessWatch({
    read: async (key) => {
      try { const l = await request(key); noteReadability(l, { access: false }); return listingReadOutcome({ listing: l }); }
      catch (e) {
        if (e && e.code === PENDING_FINALITY_CODE && Number.isSafeInteger(e.readyAt)) {
          finality.markPending(key, e.readyAt); return { kind: "pending" };
        }
        return listingReadOutcome({ code: e && e.code });
      }
    },
    onChange: () => repaint(),
    waitsForFinality: (key) => finality.pendingReadyAt(key) !== null,
    slots, now: clk.now, setTimer: clk.setTimer, clearTimer: clk.clearTimer,
  });
  function repaint() {
    if (repaintQueued) return;
    repaintQueued = true;
    clk.setTimer(() => { repaintQueued = false; render(); }, 0);
  }
  function render() {
    const fin = [], acc = [];
    for (const key of catalog) {
      const [ledger, tokenId] = key.split("|");
      const ready = finality.pendingReadyAt(key);
      const html = catalogCardControl({ ledger, tokenId, accessState: "available" },
        { key, finalityPending: ready !== null, access: access_.state(key) });
      const note = ready !== null ? finalityCopy(ready, clk.t) : "";
      cards.set(key, { html, note });
      const f = html.match(/data-finality-key="([^"]*)"/); if (f) fin.push(f[1]);
      const a = html.match(/data-access-key="([^"]*)"/); if (a) acc.push(a[1]);
    }
    finality.show(fin);
    // The IntersectionObserver: every rendered access card is in view; its
    // callback lands a frame later.
    clk.setTimer(() => access_.show(acc), 16);
  }
  function tick() {
    for (const key of catalog) {
      const ready = finality.pendingReadyAt(key);
      if (ready !== null) cards.get(key).note = finalityCopy(ready, clk.t);
    }
  }
  const label = (key) => {
    const c = cards.get(key);
    const m = c.html.match(/>([^<>]+)<\/(button|span)>/);
    return `${m ? m[1] : "?"}${c.note ? ` [${c.note}]` : ""}`;
  };
  return { finality, access: access_, render, label, reads, pendingNever };
}

const pendingAt = (readyAt) => ({ error: { code: PENDING_FINALITY_CODE, readyAt } });
const unavailable = { error: { code: "unavailable" } };

const hang = "hang";

test("a stalled read frees its slot after the deadline, and later reads proceed", async () => {
  const clk = clock();
  const p = page({
    clk, catalog: [OLD, THIRD],
    server: (key, n) => (key === OLD && n === 1 ? hang : { listing: elsewhereListing(key) }),
  });
  p.render();
  await clk.advance(100);
  assert.equal(p.label(OLD), "Checking…");
  await clk.advance(READ_DEADLINE_MS + 16_000);
  assert.equal(p.label(OLD), "Pool not reachable", "the stalled card is retried and settles");
});

test("two stalled reads do not freeze the page", async () => {
  const clk = clock();
  const mintSecs = Math.floor(clk.t / 1000);
  const finalAtMs = clk.t + 10 * 60_000;
  const p = page({
    clk, catalog: [NEW, OLD, THIRD],
    server: (key, n) => {
      if (key === OLD && n === 1) return hang;
      if (key === NEW && n === 2) return hang;
      if (key === NEW && clk.t >= finalAtMs) return { listing: elsewhereListing(key) };
      if (key === NEW) return pendingAt(mintSecs + 20 * 60);
      return { listing: elsewhereListing(key) };
    },
  });
  p.finality.estimate(NEW, mintSecs + 20 * 60);
  p.render();
  await clk.advance(25 * 60_000);
  assert.equal(p.label(NEW), "Pool not reachable");
  assert.equal(p.label(OLD), "Pool not reachable");
  assert.equal(p.label(THIRD), "Pool not reachable");
});

test("a finality re-check that stalls is re-armed and the card settles without a reload", async () => {
  const clk = clock();
  const mintSecs = Math.floor(clk.t / 1000);
  const p = page({
    clk, catalog: [NEW],
    server: (key, n) => (n === 2 ? hang : n < 4 ? pendingAt(mintSecs + 20 * 60) : { listing: elsewhereListing(key) }),
  });
  p.finality.estimate(NEW, mintSecs + 20 * 60);
  p.render();
  await clk.advance(60 * 60_000);
  assert.equal(p.label(NEW), "Pool not reachable");
});

test("confirming to final flips the card to its settled state", async () => {
  const clk = clock();
  const mintSecs = Math.floor(clk.t / 1000);
  const finalAtMs = clk.t + 10 * 60_000;
  const p = page({
    clk, catalog: [NEW],
    server: (key) => (clk.t < finalAtMs ? pendingAt(mintSecs + 20 * 60) : { listing: elsewhereListing(key) }),
  });
  p.finality.estimate(NEW, mintSecs + 20 * 60);
  p.render();
  await clk.advance(0);
  assert.match(p.label(NEW), /Buy \[Confirming on Base/);
  await clk.advance(25 * 60_000);
  assert.equal(p.label(NEW), "Pool not reachable");
});

test("transient to settled: the failed read is retried and the card settles", async () => {
  const clk = clock();
  const p = page({ clk, catalog: [OLD], server: (key, n) => (n === 1 ? unavailable : { listing: elsewhereListing(key) }) });
  p.render();
  await clk.advance(100);
  assert.equal(p.label(OLD), "Checking…");
  await clk.advance(16_000);
  assert.equal(p.label(OLD), "Pool not reachable");
});

test("a listing no reachable Home serves settles as Unavailable at once and is not read again", async () => {
  const clk = clock();
  const p = page({ clk, catalog: [OLD], server: () => ({ error: { code: "no_holder" } }) });
  p.render();
  await clk.advance(100);
  assert.equal(p.label(OLD), "Unavailable");
  await clk.advance(60 * 60_000);
  assert.equal(p.label(OLD), "Unavailable");
  assert.equal(p.reads.filter(([key]) => key === OLD).length, 1);
});

test("a read that keeps failing settles as Unavailable once its retries are spent, never View", async () => {
  const clk = clock();
  const p = page({ clk, catalog: [OLD], server: () => unavailable });
  p.render();
  await clk.advance(100);
  assert.equal(p.label(OLD), "Checking…");
  await clk.advance(60 * 60_000);
  assert.equal(p.label(OLD), "Unavailable");
});

test("a retry timer that fires 1 ms before the wall clock says due still re-reads", async () => {
  const clk = clock({ driftEveryMs: 10_000 });
  const p = page({ clk, catalog: [OLD], server: (key, n) => (n === 1 ? unavailable : { listing: elsewhereListing(key) }) });
  p.render();
  await clk.advance(25 * 60_000);
  assert.equal(p.label(OLD), "Pool not reachable");
});

test("access pending is read again once the finality watch lets go without a listing", async () => {
  const clk = clock();
  const mintSecs = Math.floor(clk.t / 1000);
  const p = page({
    clk, catalog: [OLD],
    server: (key, n) => (n === 1 ? pendingAt(mintSecs + 60) : n === 2 ? { error: { code: "malformed" } } : { listing: elsewhereListing(key) }),
  });
  p.render();
  await clk.advance(25 * 60_000);
  assert.equal(p.label(OLD), "Pool not reachable");
});
