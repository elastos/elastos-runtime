import assert from "node:assert/strict";
import test from "node:test";

import { ACCESS_SETTLED_TTL_MS, cardAccessState, createAccessWatch, createReadSlots } from "./market-access.js";
import { catalogCardControl } from "./market-card.js";

const LEDGER = `0x${"e".repeat(40)}`;
const KEYS = [`${LEDGER}|0x1`, `${LEDGER}|0x2`, `${LEDGER}|0x3`];

async function flush() {
  for (let i = 0; i < 5; i++) {
    await new Promise((resolve) => setImmediate(resolve));
  }
}

// The page in miniature: cards rendered from the watch's answers, and the
// watch shown whatever keys the rendered cards name -- as the page does.
function page({ answers }) {
  let clock = 0;
  const reads = [];
  let account = "A";
  const html = new Map();
  const watch = createAccessWatch({
    read: async (key) => {
      reads.push(key);
      return {
        kind: "listing",
        listing: {
          item: { chainNamespace: "eip155:20" },
          accessState: answers[account][key] ? "purchased" : "available",
          accessSubject: `subject-${account}`,
        },
      };
    },
    onChange: () => render(),
    slots: createReadSlots(2),
    now: () => clock,
  });
  function render() {
    const shown = [];
    for (const key of KEYS) {
      const [ledger, tokenId] = key.split("|");
      const markup = catalogCardControl(
        { ledger, tokenId, accessState: "available" },
        { key, access: watch.state(key) },
      );
      html.set(key, markup);
      const named = markup.match(/data-access-key="([^"]*)"/);
      if (named) shown.push(named[1]);
    }
    watch.show(shown);
  }
  return {
    watch,
    reads,
    html,
    render,
    switchTo(next) { account = next; },
    advance(ms) { clock += ms; },
  };
}

const label = (markup) => markup.match(/>([^<]*)<\/(button|span)>/)[1];

test("settled cards are re-read and repainted when the account switches", async () => {
  const p = page({ answers: { A: { [KEYS[0]]: true }, B: { [KEYS[1]]: true } } });
  p.render();
  await flush();
  assert.deepEqual(KEYS.map((key) => label(p.html.get(key))), ["Open", "Buy", "Buy"]);
  assert.equal(p.reads.length, 3);

  p.switchTo("B");
  p.watch.resume();
  await flush();

  assert.deepEqual(KEYS.map((key) => label(p.html.get(key))), ["Buy", "Open", "Buy"]);
  // One probe, then the cards the new subject invalidated: no card is read
  // twice more than it needs.
  assert.equal(p.reads.length, 3 + 3);
});

test("a settled card is read again once its time-to-live has run out", async () => {
  const p = page({ answers: { A: { [KEYS[0]]: true } } });
  p.render();
  await flush();
  assert.equal(p.reads.length, 3);

  p.advance(ACCESS_SETTLED_TTL_MS - 1);
  p.render();
  await flush();
  assert.equal(p.reads.length, 3, "still fresh");

  p.advance(1);
  p.render();
  await flush();
  assert.equal(p.reads.length, 6);
});

test("every unheld card state names the card to the watch", () => {
  const item = { ledger: LEDGER, tokenId: "0x1", accessState: "available" };
  const ctxs = [
    { access: "checking" }, { access: "retrying" }, { access: "available" }, { access: "no_account" },
    { access: "held" }, { access: "held", readability: "foreign" },
    { access: "unknown" }, { access: "unavailable" }, { access: "elsewhere" },
  ];
  for (const ctx of ctxs) {
    const markup = catalogCardControl(item, { key: KEYS[0], ...ctx });
    assert.equal((markup.match(/data-access-key=/g) || []).length, 1, JSON.stringify(ctx));
  }
  for (const accessState of ["purchased", "creator"]) {
    for (const extra of [{}, { access: "elsewhere" }, { readability: "foreign" }, { readability: "verified", hasItem: true }, { readability: "verified" }]) {
      const markup = catalogCardControl({ ...item, accessState }, { key: KEYS[0], ...extra });
      assert.equal((markup.match(/data-access-key=/g) || []).length, 1, `${accessState} ${JSON.stringify(extra)}`);
    }
  }
});

test("a note that names no account does not reset the chain's subject", async () => {
  const p = page({ answers: { A: {} } });
  p.render();
  await flush();
  const before = p.reads.length;
  p.watch.note(KEYS[0], { item: { chainNamespace: "eip155:20" }, accessState: "available", custodyRoute: "unresolved" });
  p.render();
  await flush();
  assert.equal(p.reads.length, before);
  assert.notEqual(p.watch.state(KEYS[1]), "checking");
});

// Plan B T4.7: an item of any pool this Home can reach buys as usual; only an
// unresolved pool takes Buy away, before any payment.
test("card_disables_buy_only_for_unresolved_route", () => {
  const item = { ledger: LEDGER, tokenId: "0x1", accessState: "available" };
  const listing = (custodyRoute) => ({
    item: { chainNamespace: "eip155:20" },
    accessState: "available",
    accessSubject: "subject-A",
    ...(custodyRoute ? { custodyRoute } : {}),
  });
  for (const route of [undefined, "pool"]) {
    const access = cardAccessState(listing(route));
    assert.equal(access, "available", String(route));
    const markup = catalogCardControl(item, { key: KEYS[0], access });
    assert.match(markup, /data-action="buy-listing"/u, String(route));
    assert.doesNotMatch(markup, /\bdisabled\b/u, String(route));
  }
  const access = cardAccessState(listing("unresolved"));
  assert.equal(access, "elsewhere");
  const markup = catalogCardControl(item, { key: KEYS[0], access });
  assert.doesNotMatch(markup, /data-action="buy-listing"/u);
  assert.match(markup, />Pool not reachable</u);
  assert.match(markup, /Add the pool in Custody\./u);
});
