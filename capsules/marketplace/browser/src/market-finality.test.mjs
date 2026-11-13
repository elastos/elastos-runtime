import assert from "node:assert/strict";
import test from "node:test";

import {
  FINALITY_CHECK_CONCURRENCY,
  FINALITY_COPY_TICK_MS,
  FINALITY_EXPECTED_LAG_SECS,
  FINALITY_FIRST_RECHECK_FLOOR_MS,
  FINALITY_RECENT_WINDOW_SECS,
  FINALITY_RECHECK_LIMIT,
  FINALITY_RECHECK_MS,
  createFinalityWatch,
  estimatedReadyAt,
  finalityCheckResult,
  finalityCopy,
  pendingFinalityFromAnswer,
} from "./market-finality.js";

const NOW_SECS = 1_800_000_000;

// One clock and one timer queue the watch is given instead of the page's, so
// a test can say exactly which timers exist and run them.
function fakeClock() {
  let nowMs = NOW_SECS * 1000;
  let nextId = 1;
  const timers = new Map();
  return {
    now: () => nowMs,
    setTimer(callback, delay) {
      const id = nextId++;
      timers.set(id, { callback, at: nowMs + Math.max(0, delay), delay });
      return id;
    },
    clearTimer(id) {
      timers.delete(id);
    },
    timers,
    delays: () => [...timers.values()].map((timer) => timer.delay).sort((a, b) => a - b),
    async advance(ms) {
      nowMs += ms;
      const due = [...timers.entries()]
        .filter(([, timer]) => timer.at <= nowMs)
        .sort((a, b) => a[1].at - b[1].at);
      for (const [id, timer] of due) {
        timers.delete(id);
        timer.callback();
      }
      await flush();
    },
  };
}

async function flush() {
  for (let i = 0; i < 5; i++) {
    await new Promise((resolve) => setImmediate(resolve));
  }
}

function watchWith(clock, answers) {
  const asked = [];
  const changed = [];
  let ticks = 0;
  const watch = createFinalityWatch({
    check: async (key) => {
      asked.push(key);
      const answer = typeof answers === "function" ? answers(key, asked.length) : answers.shift();
      return answer || { kind: "wait" };
    },
    onChange: (key) => changed.push(key),
    onTick: () => { ticks += 1; },
    setTimer: clock.setTimer,
    clearTimer: clock.clearTimer,
    now: clock.now,
  });
  return { watch, asked, changed, ticks: () => ticks };
}

test("the copy counts whole minutes up, and says any moment once the time has passed", () => {
  const nowMs = NOW_SECS * 1000;
  assert.equal(finalityCopy(NOW_SECS + 125, nowMs), "Confirming on Base · ready in about 3 min");
  assert.equal(finalityCopy(NOW_SECS + 60, nowMs), "Confirming on Base · ready in about 1 min");
  assert.equal(finalityCopy(NOW_SECS + 1, nowMs), "Confirming on Base · ready in about 1 min");
  assert.equal(finalityCopy(NOW_SECS, nowMs), "Confirming on Base · ready any moment now");
  assert.equal(finalityCopy(NOW_SECS - 600, nowMs), "Confirming on Base · ready any moment now");
  assert.equal(finalityCopy(Number.NaN, nowMs), "Confirming on Base · ready any moment now");
});

test("only Runtime's exact pending answer is read as one", () => {
  assert.equal(pendingFinalityFromAnswer({ code: "pending_finality", ready_at: NOW_SECS }), NOW_SECS);
  for (const answer of [
    null,
    "pending_finality",
    {},
    { code: "unbound" },
    { code: "pending_finality" },
    { code: "pending_finality", ready_at: "1800000000" },
    { code: "pending_finality", ready_at: 1.5 },
    { code: "pending_finality", ready_at: 0 },
    { code: "pending_finality", ready_at: -5 },
    { code: "pending_finality", ready_at: Number.MAX_SAFE_INTEGER + 1 },
    { code: "pending_finality", ready_at: NOW_SECS, surprise: true },
  ]) {
    assert.equal(pendingFinalityFromAnswer(answer), null, JSON.stringify(answer));
  }
});

test("a listing read's failure says whether to keep waiting", () => {
  const pending = Object.assign(new Error("x"), { code: "pending_finality", readyAt: NOW_SECS });
  assert.deepEqual(finalityCheckResult(pending), { kind: "pending", readyAt: NOW_SECS });
  assert.deepEqual(finalityCheckResult(Object.assign(new Error("x"), { code: "unavailable" })), { kind: "wait" });
  // A fetch that never reached Runtime carries no code.
  assert.deepEqual(finalityCheckResult(new TypeError("Failed to fetch")), { kind: "wait" });
  for (const code of ["unbound", "asset_mismatch", "invalid_start", "malformed"]) {
    assert.deepEqual(finalityCheckResult(Object.assign(new Error("x"), { code })), { kind: "done" }, code);
  }
});

test("only an item the index published within the window is presumed not final", () => {
  assert.equal(estimatedReadyAt(NOW_SECS - 60, NOW_SECS), NOW_SECS - 60 + FINALITY_EXPECTED_LAG_SECS);
  assert.equal(estimatedReadyAt(NOW_SECS + 30, NOW_SECS), NOW_SECS + 30 + FINALITY_EXPECTED_LAG_SECS);
  assert.equal(estimatedReadyAt(NOW_SECS - FINALITY_RECENT_WINDOW_SECS, NOW_SECS), null);
  assert.equal(estimatedReadyAt(0, NOW_SECS), null);
  assert.equal(estimatedReadyAt(Number.NaN, NOW_SECS), null);
  assert.equal(estimatedReadyAt(NOW_SECS + FINALITY_RECENT_WINDOW_SECS + 1, NOW_SECS), null);
});

test("a pending item is re-checked once at ready_at and enabled when its listing loads", async () => {
  const clock = fakeClock();
  const { watch, asked, changed } = watchWith(clock, [{ kind: "ready" }]);
  watch.markPending("a|0x1", NOW_SECS + 300);
  assert.equal(watch.pendingReadyAt("a|0x1"), NOW_SECS + 300);
  // Not shown yet: nothing runs.
  assert.equal(clock.timers.size, 0);
  watch.show(["a|0x1"]);
  // One re-check at ready_at, and the copy's tick.
  assert.deepEqual(clock.delays(), [FINALITY_COPY_TICK_MS, 300_000]);
  await clock.advance(299_000);
  assert.deepEqual(asked, []);
  await clock.advance(1_000);
  assert.deepEqual(asked, ["a|0x1"]);
  assert.equal(watch.pendingReadyAt("a|0x1"), null);
  assert.deepEqual(changed, ["a|0x1"]);
  watch.show(["a|0x1"]);
  assert.equal(clock.timers.size, 0, "no timer outlives the wait");
});

test("a ready_at already past is re-checked after a short floor, never at once", () => {
  const clock = fakeClock();
  const { watch } = watchWith(clock, []);
  watch.markPending("a|0x1", NOW_SECS - 30);
  watch.show(["a|0x1"]);
  assert.deepEqual(clock.delays(), [FINALITY_FIRST_RECHECK_FLOOR_MS, FINALITY_COPY_TICK_MS].sort((a, b) => a - b));
});

test("still pending: every minute after, and the page stops asking after the limit", async () => {
  const clock = fakeClock();
  const { watch, asked, changed } = watchWith(clock, () => ({ kind: "pending", readyAt: NOW_SECS - 1 }));
  watch.markPending("a|0x1", NOW_SECS);
  watch.show(["a|0x1"]);
  await clock.advance(FINALITY_FIRST_RECHECK_FLOOR_MS);
  assert.equal(asked.length, 1);
  assert.equal(watch.pendingReadyAt("a|0x1"), NOW_SECS - 1);
  assert.ok(clock.delays().includes(FINALITY_RECHECK_MS), String(clock.delays()));
  for (let i = 1; i < FINALITY_RECHECK_LIMIT; i++) {
    await clock.advance(FINALITY_RECHECK_MS);
  }
  assert.equal(asked.length, FINALITY_RECHECK_LIMIT);
  // Bounded: the controls return, and pressing them asks again.
  assert.equal(watch.pendingReadyAt("a|0x1"), null);
  assert.equal(changed.at(-1), "a|0x1");
  watch.show(["a|0x1"]);
  assert.equal(clock.timers.size, 0);
  await clock.advance(10 * FINALITY_RECHECK_MS);
  assert.equal(asked.length, FINALITY_RECHECK_LIMIT);
});

test("after the first re-check, a still-pending item is read every minute", async () => {
  const clock = fakeClock();
  const { watch, asked } = watchWith(clock, () => ({ kind: "pending", readyAt: NOW_SECS + 3_600 }));
  watch.markPending("a|0x1", NOW_SECS + 15);
  watch.show(["a|0x1"]);
  await clock.advance(15_000);
  assert.equal(asked.length, 1);
  // The estimate moved an hour out; the card keeps showing it, and is still
  // read every minute rather than left until then.
  assert.equal(watch.pendingReadyAt("a|0x1"), NOW_SECS + 3_600);
  assert.ok(clock.delays().includes(FINALITY_RECHECK_MS), String(clock.delays()));
  await clock.advance(FINALITY_RECHECK_MS);
  assert.equal(asked.length, 2);
});

test("a card first viewed late waits for the index's estimate, not one lag past the head", async () => {
  const clock = fakeClock();
  // Published ten minutes ago: final in about ten more.
  const indexReadyAt = estimatedReadyAt(NOW_SECS - 600, NOW_SECS);
  assert.equal(indexReadyAt, NOW_SECS + 600);
  // Runtime counts from the head it read now: twenty more.
  const { watch, asked } = watchWith(clock, [
    { kind: "pending", readyAt: NOW_SECS + 1_200 },
    { kind: "ready" },
  ]);
  watch.estimate("k|0x1", indexReadyAt);
  watch.show(["k|0x1"]);
  await flush();
  assert.equal(asked.length, 1);
  assert.equal(watch.pendingReadyAt("k|0x1"), NOW_SECS + 600, "the copy shows the earlier estimate");
  assert.ok(clock.delays().includes(600_000), String(clock.delays()));
  await clock.advance(600_000);
  assert.equal(asked.length, 2);
  assert.equal(watch.pendingReadyAt("k|0x1"), null);
});

test("re-checks due together run a few at a time", async () => {
  const clock = fakeClock();
  const releases = [];
  const asked = [];
  const watch = createFinalityWatch({
    check: (key) => {
      asked.push(key);
      return new Promise((resolve) => releases.push(() => resolve({ kind: "ready" })));
    },
    onChange: () => {},
    setTimer: clock.setTimer,
    clearTimer: clock.clearTimer,
    now: clock.now,
  });
  const keys = ["k|0x1", "k|0x2", "k|0x3", "k|0x4", "k|0x5"];
  for (const key of keys) {
    watch.markPending(key, NOW_SECS + 60);
  }
  watch.show(keys);
  await clock.advance(60_000);
  assert.equal(asked.length, FINALITY_CHECK_CONCURRENCY);
  while (releases.length) {
    releases.shift()();
    await flush();
    assert.ok(releases.length <= FINALITY_CHECK_CONCURRENCY);
  }
  assert.deepEqual([...asked].sort(), keys);
});

test("a hidden tab pauses every re-check and resumes where it was", async () => {
  const clock = fakeClock();
  const { watch, asked, ticks } = watchWith(clock, [{ kind: "ready" }]);
  watch.markPending("a|0x1", NOW_SECS + 120);
  watch.show(["a|0x1"]);
  assert.equal(clock.timers.size, 2);
  watch.pause();
  assert.equal(clock.timers.size, 0, "no timer runs while the tab is hidden");
  // A paint while hidden arms nothing either.
  watch.show(["a|0x1"]);
  assert.equal(clock.timers.size, 0);
  await clock.advance(600_000);
  assert.deepEqual(asked, []);
  assert.equal(ticks(), 0);
  watch.resume();
  assert.ok(clock.delays().includes(0), String(clock.delays()));
  await clock.advance(0);
  assert.deepEqual(asked, ["a|0x1"]);
  assert.equal(watch.pendingReadyAt("a|0x1"), null);
});

test("an item no longer shown keeps no timer, and resumes where it was when shown again", async () => {
  const clock = fakeClock();
  const { watch, asked } = watchWith(clock, [{ kind: "ready" }]);
  watch.markPending("a|0x1", NOW_SECS + 120);
  watch.show(["a|0x1"]);
  assert.equal(clock.timers.size, 2);
  watch.show([]);
  assert.equal(clock.timers.size, 0, "no timers for items no longer shown");
  await clock.advance(300_000);
  assert.deepEqual(asked, []);
  // Still pending: what it waits for did not change while it was hidden.
  assert.equal(watch.pendingReadyAt("a|0x1"), NOW_SECS + 120);
  watch.show(["a|0x1"]);
  assert.ok(clock.delays().includes(0), String(clock.delays()));
  await clock.advance(0);
  assert.deepEqual(asked, ["a|0x1"]);
});

test("a check that could not reach the market keeps waiting; a definite answer ends the wait", async () => {
  const clock = fakeClock();
  const { watch, changed } = watchWith(clock, [{ kind: "wait" }, { kind: "done" }]);
  watch.markPending("a|0x1", NOW_SECS);
  watch.show(["a|0x1"]);
  await clock.advance(FINALITY_FIRST_RECHECK_FLOOR_MS);
  assert.equal(watch.pendingReadyAt("a|0x1"), NOW_SECS);
  await clock.advance(FINALITY_RECHECK_MS);
  assert.equal(watch.pendingReadyAt("a|0x1"), null);
  assert.equal(changed.at(-1), "a|0x1");
});

test("recent index items are checked lazily: only shown ones, a few at a time", async () => {
  const clock = fakeClock();
  const releases = [];
  const asked = [];
  const watch = createFinalityWatch({
    check: (key) => {
      asked.push(key);
      return new Promise((resolve) => releases.push(() => resolve({ kind: "ready" })));
    },
    onChange: () => {},
    setTimer: clock.setTimer,
    clearTimer: clock.clearTimer,
    now: clock.now,
  });
  const keys = ["k|0x1", "k|0x2", "k|0x3", "k|0x4", "k|0x5"];
  for (const key of keys) {
    watch.estimate(key, NOW_SECS + 900);
  }
  watch.estimate("hidden|0x9", NOW_SECS + 900);
  // Disabled from the start, before any check.
  assert.equal(watch.pendingReadyAt("k|0x1"), NOW_SECS + 900);
  watch.show(keys);
  await flush();
  assert.equal(asked.length, FINALITY_CHECK_CONCURRENCY);
  while (releases.length) {
    releases.shift()();
    await flush();
  }
  assert.deepEqual([...asked].sort(), [...keys].sort());
  assert.ok(!asked.includes("hidden|0x9"));
  for (const key of keys) {
    assert.equal(watch.pendingReadyAt(key), null);
  }
});

test("an item a check already cleared is not presumed pending again", async () => {
  const clock = fakeClock();
  const { watch } = watchWith(clock, [{ kind: "ready" }]);
  watch.estimate("k|0x1", NOW_SECS + 900);
  watch.show(["k|0x1"]);
  await flush();
  assert.equal(watch.pendingReadyAt("k|0x1"), null);
  watch.estimate("k|0x1", NOW_SECS + 900);
  assert.equal(watch.pendingReadyAt("k|0x1"), null);
  // A Runtime answer still marks it: that is a fact, not a guess.
  watch.markPending("k|0x1", NOW_SECS + 60);
  assert.equal(watch.pendingReadyAt("k|0x1"), NOW_SECS + 60);
});

test("the copy ticks only while a pending item is shown", async () => {
  const clock = fakeClock();
  const { watch, ticks } = watchWith(clock, []);
  watch.markPending("a|0x1", NOW_SECS + 3_600);
  watch.show(["a|0x1"]);
  await clock.advance(FINALITY_COPY_TICK_MS);
  await clock.advance(FINALITY_COPY_TICK_MS);
  assert.equal(ticks(), 2);
  watch.show([]);
  assert.equal(clock.timers.size, 0);
  await clock.advance(10 * FINALITY_COPY_TICK_MS);
  assert.equal(ticks(), 2);
});
