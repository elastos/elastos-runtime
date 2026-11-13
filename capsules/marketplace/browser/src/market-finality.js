// An item the market cannot sell yet because Base has not finalized it.
//
// Runtime decides every purchase and open on the finalized block, which on
// Base trails the head by about 15-20 minutes. A listing read of an item
// minted inside that window answers `pending_finality` with `ready_at` (unix
// seconds) instead of `unbound`. This module holds what the page does with
// that answer: the item's Buy and Open stay disabled with an honest
// estimate, the listing is read again when the item should be final and
// then every minute, and the controls return as soon as a read succeeds. Nothing here decides
// whether anything may be bought; it only decides when to ask Runtime again.
//
// The watch owns its timers and keeps them only for items on screen: the page
// tells it which items it shows after every paint, and a timer for anything
// else is cleared at once.

import { createReadSlots, withReadDeadline } from "./market-access.js";

export const PENDING_FINALITY_CODE = "pending_finality";
// After the first re-check, how often a still-pending item is read again.
export const FINALITY_RECHECK_MS = 60 * 1000;
// The first re-check never runs sooner than this, even when `ready_at` has
// already passed, so an answer cannot start a run of back-to-back reads.
export const FINALITY_FIRST_RECHECK_FLOOR_MS = 15 * 1000;
// How many reads the page makes by itself before it stops asking. The
// controls then return, and pressing one asks Runtime again.
export const FINALITY_RECHECK_LIMIT = 30;
// How often the copy's "about N min" is redrawn while an item waits.
export const FINALITY_COPY_TICK_MS = 30 * 1000;
// Runtime's RUNTIME_CUSTODY_EXPECTED_FINALITY_LAG_SECS: how long finality
// usually trails a confirmed mint on Base.
export const FINALITY_EXPECTED_LAG_SECS = 20 * 60;
// An item the index says was published this recently may not be final yet,
// so its card starts disabled until a read says otherwise.
export const FINALITY_RECENT_WINDOW_SECS = 30 * 60;
// How many listing reads the watch runs at once.
export const FINALITY_CHECK_CONCURRENCY = 2;

/**
 * What a person reads while the item waits. Minutes round up, so the wait
 * is never shown shorter than it is; a time that has passed says so.
 */
export function finalityCopy(readyAt, nowMs) {
  const remaining = Number(readyAt) - nowMs / 1000;
  if (!Number.isFinite(remaining) || remaining <= 0) {
    return "Confirming on Base · ready any moment now";
  }
  return `Confirming on Base · ready in about ${Math.ceil(remaining / 60)} min`;
}

/**
 * `ready_at` from Runtime's exact `{code: "pending_finality", ready_at}`
 * answer, or null for anything else -- including that code with any other
 * field, which is not the answer this page knows.
 */
export function pendingFinalityFromAnswer(answer) {
  if (!answer || typeof answer !== "object" || Array.isArray(answer)) {
    return null;
  }
  const keys = Object.keys(answer).sort();
  if (keys.length !== 2 || keys[0] !== "code" || keys[1] !== "ready_at") {
    return null;
  }
  if (answer.code !== PENDING_FINALITY_CODE) {
    return null;
  }
  return Number.isSafeInteger(answer.ready_at) && answer.ready_at > 0 ? answer.ready_at : null;
}

/**
 * What a failed listing read means for an item that waits: still pending
 * (with the new estimate), worth asking again (Runtime or the market could
 * not be reached), or done waiting (any other answer, which the controls
 * then give the person as they always have).
 */
export function finalityCheckResult(error) {
  const code = error && typeof error.code === "string" ? error.code : "";
  if (code === PENDING_FINALITY_CODE && Number.isSafeInteger(error.readyAt)) {
    return { kind: "pending", readyAt: error.readyAt };
  }
  if (!code || code === "unavailable") {
    return { kind: "wait" };
  }
  return { kind: "done" };
}

/**
 * When an item the index lists may become final, from the index's own
 * publish time, or null when it was published long enough ago (or the index
 * gave no usable time). Only a guess to start from: a read replaces it.
 */
export function estimatedReadyAt(publishedAt, nowSecs) {
  if (!Number.isSafeInteger(publishedAt) || publishedAt <= 0) {
    return null;
  }
  if (publishedAt <= nowSecs - FINALITY_RECENT_WINDOW_SECS || publishedAt > nowSecs + FINALITY_RECENT_WINDOW_SECS) {
    return null;
  }
  return publishedAt + FINALITY_EXPECTED_LAG_SECS;
}

/**
 * The page's one watch over items that wait for finality.
 *
 * `check(key)` reads the item's listing and resolves to `{kind: "ready"}`,
 * `{kind: "pending", readyAt}`, `{kind: "wait"}` or `{kind: "done"}`.
 * `onChange(key)` asks the page to repaint that item; `onTick()` to redraw
 * the copy. Timers come from `setTimer`/`clearTimer` and time from `now()`
 * (milliseconds), so a test can hold the clock.
 *
 * The first re-check is due at the earlier of Runtime's `ready_at` and the
 * index's own estimate: Runtime counts from the head it read, which for a
 * card first viewed late is up to one lag past the real mint. Every later
 * re-check follows a minute after the one before. At most
 * FINALITY_CHECK_CONCURRENCY reads run at once, whatever started them, and
 * nothing runs while the page is paused (its tab hidden). `slots`, when
 * given, is shared with the page's other market reads (`createReadSlots`),
 * so the bound holds across all of them.
 */
export function createFinalityWatch({
  check,
  onChange,
  onTick = () => {},
  setTimer,
  clearTimer,
  now,
  slots = createReadSlots(FINALITY_CHECK_CONCURRENCY),
}) {
  // key -> {readyAt, estimated, checks, rechecks, dueAt}. `estimated` is an
  // index guess no read has confirmed yet; `rechecks` counts the reads this
  // watch timed; `dueAt` is when the next one is due.
  const entries = new Map();
  // The index's estimate for an item, kept beside Runtime's answers.
  const hints = new Map();
  // Items a read has answered for. The index's guess never marks them again.
  const cleared = new Set();
  const timers = new Map();
  const inFlight = new Set();
  let shown = new Set();
  // Reads waiting for one of the FINALITY_CHECK_CONCURRENCY slots.
  let queue = [];
  let paused = false;
  slots.onRelease(() => pump());
  let tickTimer = null;

  function expectedAt(key, entry) {
    const hint = hints.get(key);
    return hint === undefined ? entry.readyAt : Math.min(entry.readyAt, hint);
  }

  function pendingReadyAt(key) {
    const entry = entries.get(key);
    return entry ? expectedAt(key, entry) : null;
  }

  // Runtime answered `pending_finality` for this item.
  function markPending(key, readyAt) {
    const previous = entries.get(key);
    cleared.delete(key);
    const confirmed = previous && !previous.estimated;
    entries.set(key, {
      readyAt,
      estimated: false,
      checks: confirmed ? previous.checks : 0,
      rechecks: confirmed ? previous.rechecks : 0,
      dueAt: null,
    });
    if (timers.has(key)) {
      clearTimer(timers.get(key));
      timers.delete(key);
    }
    if (shown.has(key)) {
      arm(key);
    }
    syncTick();
  }

  // The index suggests the item may not be final yet.
  function estimate(key, readyAt) {
    hints.set(key, readyAt);
    if (entries.has(key) || cleared.has(key)) {
      return;
    }
    entries.set(key, { readyAt, estimated: true, checks: 0, rechecks: 0, dueAt: null });
  }

  // The items on screen now. Anything else loses its timer.
  function show(keys) {
    shown = new Set(keys);
    for (const [key, timer] of [...timers]) {
      if (paused || !shown.has(key)) {
        clearTimer(timer);
        timers.delete(key);
      }
    }
    queue = queue.filter((key) => shown.has(key));
    for (const key of shown) {
      arm(key);
    }
    pump();
    syncTick();
  }

  // The tab went out of sight: no reads, no timers, until it is back.
  function pause() {
    paused = true;
    show(shown);
  }

  function resume() {
    paused = false;
    show(shown);
  }

  function arm(key) {
    const entry = entries.get(key);
    if (paused || !entry || timers.has(key) || inFlight.has(key) || queue.includes(key)) {
      return;
    }
    if (entry.estimated) {
      queue.push(key);
      return;
    }
    if (entry.dueAt === null) {
      entry.dueAt = now() + (entry.rechecks === 0
        ? Math.max(expectedAt(key, entry) * 1000 - now(), FINALITY_FIRST_RECHECK_FLOOR_MS)
        : FINALITY_RECHECK_MS);
    }
    timers.set(key, setTimer(() => {
      timers.delete(key);
      entry.rechecks += 1;
      queue.push(key);
      pump();
    }, Math.max(0, entry.dueAt - now())));
  }

  function pump() {
    while (!paused && queue.length) {
      const key = queue[0];
      if (!shown.has(key) || !entries.has(key) || inFlight.has(key)) {
        queue.shift();
        continue;
      }
      if (!slots.tryAcquire()) {
        return;
      }
      queue.shift();
      run(key).finally(() => slots.release());
    }
  }

  async function run(key) {
    inFlight.add(key);
    let result;
    try {
      result = await withReadDeadline(check(key), { kind: "wait" }, setTimer, clearTimer);
    } catch {
      result = { kind: "wait" };
    } finally {
      inFlight.delete(key);
    }
    const entry = entries.get(key);
    if (!entry) {
      return;
    }
    entry.checks += 1;
    entry.estimated = false;
    entry.dueAt = null;
    if (result && result.kind === "pending" && Number.isSafeInteger(result.readyAt)) {
      entry.readyAt = result.readyAt;
    }
    const waiting = result && (result.kind === "pending" || result.kind === "wait");
    if (!waiting || entry.checks >= FINALITY_RECHECK_LIMIT) {
      entries.delete(key);
      cleared.add(key);
    } else if (shown.has(key)) {
      arm(key);
    }
    syncTick();
    onChange(key);
  }

  function syncTick() {
    const waitingOnScreen = !paused && [...shown].some((key) => entries.has(key));
    if (waitingOnScreen && tickTimer === null) {
      tickTimer = setTimer(() => {
        tickTimer = null;
        onTick();
        syncTick();
      }, FINALITY_COPY_TICK_MS);
    } else if (!waitingOnScreen && tickTimer !== null) {
      clearTimer(tickTimer);
      tickTimer = null;
    }
  }

  return { pendingReadyAt, markPending, estimate, show, pause, resume };
}
