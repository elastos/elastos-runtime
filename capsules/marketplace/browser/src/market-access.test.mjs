import assert from "node:assert/strict";
import test from "node:test";

import {
  ACCESS_RETRY_BACKOFF_MS,
  ACCESS_SETTLED_TTL_MS,
  cardAccessState,
  createAccessWatch,
  createReadSlots,
  listingReadOutcome,
} from "./market-access.js";
import { FINALITY_CHECK_CONCURRENCY, createFinalityWatch } from "./market-finality.js";

async function flush() {
  for (let i = 0; i < 5; i++) {
    await new Promise((resolve) => setImmediate(resolve));
  }
}

// A read the test answers by hand, so it can hold reads in flight.
function heldReads() {
  const pending = [];
  return {
    pending,
    read: (key) => new Promise((resolve) => { pending.push({ key, resolve }); }),
    async answer(index, result) {
      pending[index].resolve(result);
      await flush();
    },
  };
}

function listing({ accessState = "available", accessUnknown, custodyRoute, accessSubject, chain } = {}) {
  const value = { accessState };
  if (chain) value.item = { chainNamespace: chain };
  if (accessUnknown) value.accessUnknown = true;
  if (custodyRoute) value.custodyRoute = custodyRoute;
  if (accessSubject) value.accessSubject = accessSubject;
  return value;
}

// Timers the test runs by hand.
function fakeTimers() {
  const timers = new Map();
  let next = 1;
  return {
    setTimer(callback, delay) {
      const id = next++;
      timers.set(id, { callback, delay });
      return id;
    },
    clearTimer(id) {
      timers.delete(id);
    },
    delays: () => [...timers.values()].map((timer) => timer.delay),
    async runAll() {
      const due = [...timers.entries()];
      timers.clear();
      for (const [, timer] of due) {
        timer.callback();
      }
      await flush();
    },
  };
}

function watchWith(read, { slots = createReadSlots(FINALITY_CHECK_CONCURRENCY), now = () => 0, timers = fakeTimers() } = {}) {
  const changed = [];
  const watch = createAccessWatch({
    read,
    onChange: (key) => changed.push(key),
    slots,
    now,
    setTimer: timers.setTimer,
    clearTimer: timers.clearTimer,
  });
  return { watch, changed, slots, timers };
}

test("a card's access state comes from the listing object alone", () => {
  assert.equal(cardAccessState(listing({ accessState: "purchased" })), "held");
  assert.equal(cardAccessState(listing({ accessState: "creator" })), "held");
  assert.equal(cardAccessState(listing({ accessState: "available" })), "available");
  // Unknown with an account named is the chain not saying; with none, this
  // Home has no account to ask about, and Buy is how one is set up.
  assert.equal(cardAccessState(listing({ accessUnknown: true, accessSubject: "aa".repeat(16) })), "unknown");
  assert.equal(cardAccessState(listing({ accessUnknown: true })), "no_account");
  // An item whose pool this Home cannot reach is neither bought nor opened
  // here, whatever access says; one of a reachable pool reads as usual.
  assert.equal(cardAccessState(listing({ accessState: "purchased", custodyRoute: "unresolved" })), "elsewhere");
  assert.equal(cardAccessState(listing({ accessState: "available", custodyRoute: "unresolved" })), "elsewhere");
  assert.equal(cardAccessState(listing({ accessState: "purchased", custodyRoute: "pool" })), "held");
  assert.equal(cardAccessState(listing({ accessState: "available", custodyRoute: "pool" })), "available");
});

test("only cards on screen are read, and an unread card is checking", async () => {
  const reads = heldReads();
  const { watch } = watchWith(reads.read);
  assert.equal(watch.state("a"), "checking");
  watch.show(["a"]);
  assert.deepEqual(reads.pending.map((entry) => entry.key), ["a"]);
  assert.equal(watch.state("b"), "checking", "a card not shown is never read");
  await reads.answer(0, { kind: "listing", listing: listing({ accessState: "purchased" }) });
  assert.equal(watch.state("a"), "held");
});

test("each answer is the card's state: held, available, unknown, pending, retrying, unavailable, elsewhere", async () => {
  const reads = heldReads();
  const { watch, changed } = watchWith(reads.read, { slots: createReadSlots(8) });
  const keys = ["held", "free", "unknown", "pending", "failed", "gone", "elsewhere"];
  watch.show(keys);
  await reads.answer(0, { kind: "listing", listing: listing({ accessState: "purchased" }) });
  await reads.answer(1, { kind: "listing", listing: listing() });
  await reads.answer(2, { kind: "listing", listing: listing({ accessUnknown: true, accessSubject: "aa".repeat(16) }) });
  await reads.answer(3, { kind: "pending" });
  await reads.answer(4, { kind: "retry" });
  await reads.answer(5, { kind: "unavailable" });
  await reads.answer(6, { kind: "listing", listing: listing({ custodyRoute: "unresolved" }) });
  assert.deepEqual(
    keys.map((key) => watch.state(key)),
    ["held", "available", "unknown", "pending", "retrying", "unavailable", "elsewhere"],
  );
  assert.deepEqual(changed, keys);
});

test("a read that throws leaves the card retrying, never available", async () => {
  const { watch } = watchWith(async () => { throw new Error("offline"); });
  watch.show(["a"]);
  await flush();
  assert.equal(watch.state("a"), "retrying");
});

test("one function reads every listing answer: final refusals are unavailable, anything else is retried", () => {
  const read = listing();
  assert.deepEqual(listingReadOutcome({ listing: read }), { kind: "listing", listing: read });
  for (const code of ["no_holder", "unbound", "asset_mismatch"]) {
    assert.deepEqual(listingReadOutcome({ code }), { kind: "unavailable" }, code);
  }
  assert.deepEqual(listingReadOutcome({ legacy: true }), { kind: "unavailable" }, "a legacy folder is no market item");
  for (const code of ["unavailable", "malformed", "", undefined]) {
    assert.deepEqual(listingReadOutcome({ code }), { kind: "retry" }, String(code));
  }
});

test("a typed unavailable is final: never read again, after its TTL or back in sight", async () => {
  let nowMs = 0;
  let count = 0;
  const { watch, timers } = watchWith(async () => {
    count += 1;
    return { kind: "unavailable" };
  }, { now: () => nowMs, slots: createReadSlots(8) });
  watch.show(["a"]);
  await flush();
  assert.equal(watch.state("a"), "unavailable");
  assert.deepEqual(timers.delays(), [], "no retry is scheduled");
  nowMs += ACCESS_SETTLED_TTL_MS;
  watch.show(["a"]);
  watch.pause();
  watch.resume();
  await flush();
  assert.equal(count, 1);
  assert.equal(watch.state("a"), "unavailable");
});

test("an answer is cached: showing the card again reads nothing", async () => {
  let count = 0;
  const { watch } = watchWith(async () => {
    count += 1;
    return { kind: "listing", listing: listing() };
  });
  watch.show(["a"]);
  await flush();
  watch.show([]);
  watch.show(["a"]);
  await flush();
  assert.equal(count, 1);
  assert.equal(watch.state("a"), "available");
});

test("a failed read is retried with backoff, then settles as unavailable -- never endlessly", async () => {
  let nowMs = 0;
  let count = 0;
  const { watch, timers } = watchWith(async () => {
    count += 1;
    return { kind: "retry" };
  }, { now: () => nowMs });
  watch.show(["a"]);
  await flush();
  assert.equal(count, 1);
  assert.equal(watch.state("a"), "retrying");
  for (const delay of ACCESS_RETRY_BACKOFF_MS) {
    assert.deepEqual(timers.delays(), [delay], "one retry, after the next delay");
    nowMs += delay;
    await timers.runAll();
  }
  assert.equal(count, 1 + ACCESS_RETRY_BACKOFF_MS.length);
  assert.equal(watch.state("a"), "unavailable", "the delays are spent: unavailable, settled");
  assert.deepEqual(timers.delays(), [], "nothing more is scheduled");
  watch.show(["a"]);
  await flush();
  assert.equal(count, 1 + ACCESS_RETRY_BACKOFF_MS.length, "a settled unavailable is not re-read");
});

test("View opens from the listing the card was read from, with no second read", async () => {
  let count = 0;
  const unknown = listing({ accessUnknown: true, accessSubject: "aa".repeat(16) });
  const { watch } = watchWith(async () => {
    count += 1;
    return { kind: "listing", listing: unknown };
  });
  watch.show(["a"]);
  await flush();
  assert.equal(watch.state("a"), "unknown");
  assert.equal(watch.listing("a"), unknown);
  assert.equal(count, 1);
  assert.equal(watch.listing("b"), null, "an unread card has no listing");
});

test("a settled answer is read again when shown after its TTL", async () => {
  let nowMs = 0;
  let count = 0;
  const { watch } = watchWith(async () => {
    count += 1;
    return { kind: "listing", listing: listing() };
  }, { now: () => nowMs });
  watch.show(["a"]);
  await flush();
  watch.show(["a"]);
  await flush();
  assert.equal(count, 1);
  nowMs += ACCESS_SETTLED_TTL_MS;
  watch.show(["a"]);
  await flush();
  assert.equal(count, 2);
  assert.equal(watch.state("a"), "available", "the old answer stands while the new one is read");
});

test("an answer the page already has -- from the sheet -- is the card's too", () => {
  const { watch } = watchWith(async () => { throw new Error("not asked"); });
  watch.note("a", listing({ accessState: "purchased" }));
  assert.equal(watch.state("a"), "held");
});

test("at most two reads run at once, shared with the finality watch", async () => {
  assert.equal(FINALITY_CHECK_CONCURRENCY, 2);
  const slots = createReadSlots(FINALITY_CHECK_CONCURRENCY);
  const reads = heldReads();
  const checks = [];
  const finality = createFinalityWatch({
    check: (key) => new Promise((resolve) => { checks.push({ key, resolve }); }),
    onChange: () => {},
    setTimer: () => 0,
    clearTimer: () => {},
    now: () => 1_800_000_000_000,
    slots,
  });
  finality.estimate("f", 1_800_000_000);
  finality.show(["f"]);
  const { watch } = watchWith(reads.read, { slots });
  watch.show(["a", "b", "c"]);
  assert.equal(checks.length + reads.pending.length, 2, "one finality check and one access read");
  assert.equal(reads.pending.length, 1);
  checks[0].resolve({ kind: "ready" });
  await flush();
  assert.equal(reads.pending.length, 2, "a freed slot goes to the next waiting read");
  await reads.answer(0, { kind: "listing", listing: listing() });
  await reads.answer(1, { kind: "listing", listing: listing() });
  assert.equal(reads.pending.length, 3);
});

test("a hidden tab reads nothing until it is back", async () => {
  const reads = heldReads();
  const { watch } = watchWith(reads.read);
  watch.pause();
  watch.show(["a"]);
  assert.equal(reads.pending.length, 0);
  watch.resume();
  assert.equal(reads.pending.length, 1);
});

test("a hidden-then-visible card leaves checking, and a retry due while hidden runs once back", async () => {
  const reads = heldReads();
  let nowMs = 0;
  const { watch, timers } = watchWith(reads.read, { now: () => nowMs });
  watch.pause();
  watch.show(["a"]);
  assert.equal(watch.state("a"), "checking");
  watch.resume();
  await reads.answer(0, { kind: "retry" });
  assert.equal(watch.state("a"), "retrying");

  // The retry falls due while the tab is hidden: it keeps its state, and
  // runs as soon as the tab is back.
  watch.pause();
  nowMs += ACCESS_RETRY_BACKOFF_MS[0];
  await timers.runAll();
  assert.equal(reads.pending.length, 1, "nothing is read while hidden");
  assert.equal(watch.state("a"), "retrying");
  watch.resume();
  assert.equal(reads.pending.length, 2);
  await reads.answer(1, { kind: "listing", listing: listing() });
  assert.equal(watch.state("a"), "available");
});

test("another wallet account invalidates that chain's answers, and the cards are read again", async () => {
  const base = "eip155:8453";
  let subject = "aa".repeat(16);
  let count = 0;
  const { watch } = watchWith(async (key) => {
    count += 1;
    return {
      kind: "listing",
      listing: listing({ accessState: key === "a" ? "purchased" : "available", accessSubject: subject, chain: base }),
    };
  }, { slots: createReadSlots(8) });
  watch.show(["a", "b"]);
  await flush();
  assert.equal(watch.state("a"), "held");
  assert.equal(count, 2);

  // The person switched account; the next answer the page sees says so.
  subject = "bb".repeat(16);
  watch.note("c", listing({ accessSubject: subject, chain: base }));
  assert.equal(watch.state("a"), "checking", "the other account's answers no longer count");
  assert.equal(watch.state("b"), "checking");
  assert.equal(watch.state("c"), "available", "the answer that told is kept");
  watch.show(["a", "b"]);
  await flush();
  assert.equal(count, 4, "every shown card is read again for the new account");
  assert.equal(watch.state("a"), "held");
});

test("two chains keep their own accounts: answers from one never evict the other's", async () => {
  let count = 0;
  const subjectOf = { a: "aa".repeat(16), b: "bb".repeat(16) };
  const chainOf = { a: "eip155:8453", b: "eip155:20" };
  const { watch } = watchWith(async (key) => {
    count += 1;
    return { kind: "listing", listing: listing({ accessSubject: subjectOf[key], chain: chainOf[key] }) };
  }, { slots: createReadSlots(8) });
  watch.show(["a", "b"]);
  await flush();
  for (let i = 0; i < 3; i++) {
    watch.show(["a", "b"]);
    await flush();
  }
  assert.equal(count, 2, "no read loop between the chains");
  assert.equal(watch.state("a"), "available");
  assert.equal(watch.state("b"), "available");
});

test("an answer from a read started before the switch never brings the old account back", async () => {
  const reads = heldReads();
  let nowMs = 0;
  const { watch } = watchWith(reads.read, { now: () => nowMs, slots: createReadSlots(8) });
  const base = "eip155:8453";
  watch.show(["old"]);
  nowMs = 10;
  watch.note("fresh", listing({ accessSubject: "bb".repeat(16), chain: base }));
  await reads.answer(0, { kind: "listing", listing: listing({ accessState: "purchased", accessSubject: "aa".repeat(16), chain: base }) });
  assert.equal(watch.state("fresh"), "available", "the newer account still counts");
  assert.equal(watch.state("old"), "checking", "the late answer is for an account no longer in use");
});

test("back in sight, one shown card is read again to notice an account switch", async () => {
  let count = 0;
  const { watch } = watchWith(async () => {
    count += 1;
    return { kind: "listing", listing: listing() };
  }, { slots: createReadSlots(8) });
  watch.show(["a", "b"]);
  await flush();
  assert.equal(count, 2);
  watch.pause();
  watch.resume();
  await flush();
  assert.equal(count, 3, "exactly one card is asked again");
});
