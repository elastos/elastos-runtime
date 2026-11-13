// What an Explore card offers, from the chain's own answer.
//
// The catalog knows only what this Home holds; an account the chain grants
// an item -- minted, bought anywhere, or a subscription -- would still be
// offered Buy. Each card on screen therefore reads the item's own listing
// object (`POST /api/apps/marketplace/listing`), whose `access_state` is
// Runtime's `hasAccessByContentId` read for this person's account. Reads are
// lazy, bounded, and cached per account: Runtime names the account only as
// an opaque `access_subject`, one per chain, and an answer is good only for
// the subject its chain answers with now.

/** How long a settled answer is trusted before a shown card asks again. */
export const ACCESS_SETTLED_TTL_MS = 5 * 60 * 1000;
/**
 * When a card whose read failed asks again: after each delay in turn. Once
 * they are spent the card settles as unavailable, like a final answer.
 */
export const ACCESS_RETRY_BACKOFF_MS = [15 * 1000, 60 * 1000, 5 * 60 * 1000];

/**
 * Listing refusals that are final for a card: no Home this one can reach
 * serves the item's document (`no_holder`), or the chain names no such item
 * on this market (`unbound`, `asset_mismatch`). Asking again soon gives the
 * same answer.
 */
const FINAL_LISTING_CODES = new Set(["no_holder", "unbound", "asset_mismatch"]);

/**
 * The one reading of a card's listing read, from what the page got back:
 * the parsed `listing`; a `legacy` folder, which is no market item; or a
 * refusal's `code`. `{kind: "listing", listing}`, `{kind: "unavailable"}`
 * for a final answer, or `{kind: "retry"}` for anything asking again may
 * change. Not final yet (`pending_finality`) belongs to the finality watch
 * and is answered before this.
 */
export function listingReadOutcome({ listing = null, legacy = false, code = "" } = {}) {
  if (listing) {
    return { kind: "listing", listing };
  }
  if (legacy || FINAL_LISTING_CODES.has(code)) {
    return { kind: "unavailable" };
  }
  return { kind: "retry" };
}

/**
 * How long a watch waits for one market read before it gives the slot and
 * the card back. Above the 35 s the page aborts a listing fetch at, so a
 * read that honours its own timeout is never cut off here.
 */
export const READ_DEADLINE_MS = 40 * 1000;

/**
 * Settles with `promise`, or with `fallback` once `READ_DEADLINE_MS` passes
 * or `promise` rejects. Whichever comes first wins; a late answer is dropped.
 */
export function withReadDeadline(promise, fallback, setTimer, clearTimer) {
  return new Promise((resolve) => {
    const timer = setTimer(() => resolve(fallback), READ_DEADLINE_MS);
    const settle = (value) => {
      clearTimer(timer);
      resolve(value);
    };
    Promise.resolve(promise).then(settle, () => settle(fallback));
  });
}

/**
 * The card's state from one parsed listing object:
 * `elsewhere` -- this Home cannot reach the item's pool (`custody_route`
 * `unresolved`), so it is neither bought nor opened here until the pool is
 * added in Custody; `held` -- the chain grants access (or this Home
 * minted it); `no_account` -- this Home has no wallet account to ask about,
 * so Buy leads to setting one up; `unknown` -- the chain could not say for
 * this account; `available` -- Buy.
 */
export function cardAccessState(listing) {
  if (listing.custodyRoute === "unresolved") {
    return "elsewhere";
  }
  if (listing.accessState === "purchased" || listing.accessState === "creator") {
    return "held";
  }
  if (listing.accessUnknown) {
    // Runtime names the account whenever it had one to ask about.
    return listing.accessSubject ? "unknown" : "no_account";
  }
  return "available";
}

/**
 * Slots shared by every watch that reads the market, so together they never
 * run more than `limit` reads at once. A released slot wakes every waiting
 * watch; each takes what it can.
 */
export function createReadSlots(limit) {
  let active = 0;
  const wakers = new Set();
  return {
    tryAcquire() {
      if (active >= limit) {
        return false;
      }
      active += 1;
      return true;
    },
    release() {
      active -= 1;
      for (const wake of [...wakers]) {
        wake();
      }
    },
    onRelease(wake) {
      wakers.add(wake);
    },
  };
}

/**
 * The page's one watch over card access, and the card's state machine:
 * `checking` until a card has an answer that is good for its chain's
 * current account; then the answer's state (`cardAccessState`), `pending`,
 * or `unavailable`, which is final; or `retrying` while a failed read waits
 * to be asked again, which becomes `unavailable` once the delays are spent.
 * A hidden tab or an off-screen card keeps its state, and a read that fell
 * due meanwhile runs once it is shown again.
 *
 * `read(key)` resolves to a `listingReadOutcome`, or `{kind: "pending"}`
 * (not final yet; the finality watch owns it). `onChange(key)` asks the page
 * to repaint. `listing(key)` is the listing a settled state was read from.
 * `waitsForFinality(key)` says whether the finality watch still holds a
 * `pending` key; once it does not, the key is read again.
 */
export function createAccessWatch({
  read,
  waitsForFinality = () => true,
  onChange,
  slots,
  now,
  setTimer = (callback, delay) => setTimeout(callback, delay),
  clearTimer = (timer) => clearTimeout(timer),
}) {
  // key -> {state, listing, at, chain, subject, failures, dueAt}
  const entries = new Map();
  // chain -> {subject, startedAt}: the account each chain answers for now,
  // as the most recently started read that told.
  const subjects = new Map();
  const inFlight = new Set();
  const retryTimers = new Map();
  let shown = new Set();
  let queue = [];
  let paused = false;
  slots.onRelease(() => pump());

  // An answer is good only for the account its chain answers for now. A
  // chain no read has named a subject for has nothing to contradict it.
  function valid(entry) {
    if (!entry.chain || !subjects.has(entry.chain)) {
      return true;
    }
    return subjects.get(entry.chain).subject === entry.subject;
  }

  function state(key) {
    const entry = entries.get(key);
    return entry && valid(entry) ? entry.state : "checking";
  }

  function listing(key) {
    const entry = entries.get(key);
    return entry && valid(entry) ? entry.listing : null;
  }

  // A state with no listing behind it: a failure, a final refusal, or not
  // final yet.
  function settle(key, state, failures = 0, dueAt = null) {
    entries.set(key, { state, listing: null, at: now(), chain: undefined, subject: null, failures, dueAt });
  }

  // An answer the page already has -- a sheet's read, a finality re-check --
  // is the card's answer too, so the card and the sheet never disagree.
  // `startedAt` is when the read that produced it began: an older read never
  // overrides the account a newer one named.
  function note(key, listing, startedAt = now()) {
    const chain = listing.item ? listing.item.chainNamespace : undefined;
    let subject = listing.accessSubject || null;
    // A listing built from an item alone (a refused download) names no
    // account and says nothing about one: it never resets the chain's
    // subject. A real read with no account to ask about is `accessUnknown`.
    const speaksForAccount = Boolean(listing.accessSubject || listing.accessUnknown);
    if (chain && speaksForAccount) {
      const current = subjects.get(chain);
      if (!current || startedAt >= current.startedAt) {
        subjects.set(chain, { subject, startedAt });
      }
    } else if (chain && subjects.has(chain)) {
      // It stands for the account the chain answers for now.
      subject = subjects.get(chain).subject;
    }
    entries.set(key, { state: cardAccessState(listing), listing, at: now(), chain, subject, failures: 0, dueAt: null });
    onChange(key);
  }

  function needsRead(key) {
    if (inFlight.has(key) || queue.includes(key)) {
      return false;
    }
    const entry = entries.get(key);
    if (!entry || !valid(entry)) {
      return true;
    }
    if (entry.state === "retrying") {
      return entry.dueAt !== null && now() >= entry.dueAt;
    }
    if (entry.state === "pending") {
      return !waitsForFinality(key);
    }
    if (entry.state === "unavailable") {
      return false;
    }
    return now() - entry.at >= ACCESS_SETTLED_TTL_MS;
  }

  function show(keys) {
    shown = new Set(keys);
    queue = queue.filter((key) => shown.has(key));
    for (const key of shown) {
      if (needsRead(key)) {
        queue.push(key);
      }
    }
    pump();
  }

  function pause() {
    paused = true;
  }

  // Back in sight. The person may have switched account in Wallet meanwhile,
  // and nothing on this page would say so: one shown card that has settled is
  // read again at once, and the subject it answers with tells every other card.
  function resume() {
    paused = false;
    const first = [...shown].find((key) => {
      const entry = entries.get(key);
      return entry && !inFlight.has(key) && entry.listing !== null;
    });
    if (first !== undefined) {
      entries.get(first).at = -Infinity;
    }
    show(shown);
  }

  function pump() {
    while (!paused && queue.length) {
      const key = queue[0];
      if (!shown.has(key) || inFlight.has(key)) {
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
    const startedAt = now();
    let result;
    try {
      result = await withReadDeadline(read(key), { kind: "retry" }, setTimer, clearTimer);
    } catch {
      result = { kind: "retry" };
    } finally {
      inFlight.delete(key);
    }
    if (result && result.kind === "listing" && result.listing) {
      note(key, result.listing, startedAt);
      return;
    }
    if (result && (result.kind === "pending" || result.kind === "unavailable")) {
      settle(key, result.kind);
      onChange(key);
      return;
    }
    failed(key);
  }

  // A read that failed is retried with backoff while the card is shown;
  // once the delays are spent the card settles as unavailable.
  function failed(key) {
    const previous = entries.get(key);
    const failures = (previous && previous.state === "retrying" ? previous.failures : 0) + 1;
    if (failures > ACCESS_RETRY_BACKOFF_MS.length) {
      settle(key, "unavailable", failures);
      onChange(key);
      return;
    }
    const delay = ACCESS_RETRY_BACKOFF_MS[failures - 1];
    settle(key, "retrying", failures, now() + delay);
    if (retryTimers.has(key)) {
      clearTimer(retryTimers.get(key));
    }
    retryTimers.set(key, setTimer(() => {
      retryTimers.delete(key);
      // The firing timer is the due signal; the wall clock may read a hair early.
      const due = entries.get(key);
      if (due && due.state === "retrying") {
        due.dueAt = Math.min(due.dueAt, now());
      }
      if (shown.has(key) && needsRead(key)) {
        queue.push(key);
        pump();
      }
    }, delay));
    onChange(key);
  }

  return { state, listing, note, show, pause, resume };
}
