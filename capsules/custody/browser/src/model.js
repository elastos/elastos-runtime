// The Custody app's pure model: the states.md wording, the check lines built
// from the Runtime's check results, and the small readers the app renders
// with. No DOM; custody.test.mjs pins it through custody.js.

export const DAY_MS = 86_400_000;
// The terms themselves come from `summary.term_presets_days`; only their
// words live here.
const TERM_LABELS = Object.freeze({
  182: "6 months",
  365: "1 year",
  730: "2 years",
});
export const DEFAULT_TERM_DAYS = 365;
const MAX_LABEL_BYTES = 64;
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

export const UNAVAILABLE_LINE = "Custody is temporarily unavailable. Runtime will retry.";
export const CHAIN_MISSING_LINE = "Turn on protected content for this Home. Runtime then installs the Base network.";
export const KEY_MISSING_LINE = "Create the pool signing key first.";
export const FIX_CHECKS_LINE = "Fix the failed checks first.";
export const INSTALL_FAILED_LINE = "The pool did not pass the Runtime check and was not installed. Nothing changed.";
export const RESTART_NEEDED_LINE = "This Home's node is set up but not started. Restart this Home to start it.";
export const TERMINAL_POOL_LINE = "This pool was formed from the terminal. Register its nodes with elastos node peer add.";
// A slot's request that never reached Runtime: nothing retries it on its own.
export const SLOT_UNAVAILABLE_LINE = "Custody is temporarily unavailable. Try again.";
export const HOLDS_CUSTODY_LINE = "This Home already holds a custody state, so it cannot offer custody.";
export const OFFER_UNREAD_LINE = "This Home could not read its custody offer. Try again.";
// #388 A1: only a WCI-operated host takes custody, pool or seal roles.
export const HOST_TRUST_REQUIRED_LINE = "This Home is not set up as a WCI-operated host.";
const MESSAGES_OFF_REFUSED_LINE = "Custody messages are off on this Home. Enable custody messages, then try again.";
const NO_PROFILE_LINE = "Save your Profile before you enable custody messages.";
const PASSKEY_FAILED_LINE = "Passkey verification failed.";
export const MESSAGES_ENABLE_OPERATION = "custody.messages.enable";
export const LOCAL_NODE_REMOVE_OPERATION = "custody.local_node.remove";
// Plan B T4.3: Add a pool, approved with the admin's passkey.
export const KNOWN_POOL_ADD_OPERATION = "custody.known_pool.add";
// Plan B T2.3: Stop serving one pool needs the admin's passkey.
export const SERVED_POOL_REMOVE_OPERATION = "custody.served_pool.remove";
// Plan B T2.3 (S2-A3): Confirm publisher for a served pool or this Home's own.
export const SERVED_POOL_CONFIRM_PUBLISHER_OPERATION = "custody.served_pool.confirm_publisher";
export const PUBLISHER_NOTE = "Sealed items for this pool are published under your profile.";
export const PUBLISHER_CONFIRMED_LINE = "Sealed items for this pool are now published under your profile.";
export const HOSTING_POOLS_LINE = "This Home keeps shares for the pools below. A pool owner asks this Home to join; you approve in Inbox.";
export const SERVING_ATTENTION_LINE = "A pool this Home served before this version needs attention: its consent is missing. Nothing was changed.";
export const KNOWN_POOLS_LINE = "Add a pool to mint into it, and to buy and play items that its nodes keep.";
export const NEEDS_UPDATE_LINE = "Needs an update: this contact's Home cannot receive custody requests yet.";
export const TERM_CHANGED_LINE = "A node agreed to a different term. Ask it again for this term.";
export const FIND_BUSY_LINE = "Asking your contacts…";
export const NO_OFFERS_LINE = "None of your contacts offers custody yet.";
export const NO_CONTACTS_LINE = "You have no contacts yet. Add contacts in People, then find nodes.";

// Sending a node request and finding nodes: refusals the owner can act on.
const NODE_REQUEST_REFUSAL_LINES = Object.freeze({
  already_requested: "You already asked this Home. Wait for its answer.",
  too_many_requests: "Too many open requests. Wait for some answers first.",
  pool_installed: "The pool is already installed.",
  no_signing_key: KEY_MISSING_LINE,
  messages_not_enabled: "Enable custody messages in Hosting first.",
  not_contact: "This Profile is not one of your contacts.",
  needs_update: NEEDS_UPDATE_LINE,
  bad_term: "Choose a pool term first.",
  term_changed: TERM_CHANGED_LINE,
});

// A node's own reasons for a decline. Any other code is this Home failing to
// deliver the request, never the node's decision.
const NODE_DECLINE_LINES = Object.freeze({
  not_offering: "No longer offers custody.",
  already_serving: "Already serves another pool owner.",
  not_admin: "Only that Home's admin can approve custody requests.",
  declined: "The node's admin declined.",
  expired: "The request expired before the node answered.",
});
const REQUEST_STATES = ["waiting", "approved", "declined", "expired"];
const FOUND_STATUSES = ["offering", "not_offering", "unreachable", "needs_update"];
// A request the node may still act on binds its Home and its term.
const LIVE_REQUEST_STATES = ["waiting", "approved"];

export const REFUSAL_LINES = Object.freeze({
  not_a_card: "This is not a node card. Ask the node operator for the text that starts with elastos-node-card.",
  newer_version: "This node card comes from a newer ElastOS. Update this Home, then try again.",
  changed: "This card was changed after the node made it. Ask the operator for a fresh copy.",
  unsupported: "This node uses a format this Home cannot read. Ask the operator to update their node.",
  ticket_mismatch: "This card's connection details belong to a different Home. Ask for a fresh card.",
  storage_without_id: "This card says the node keeps copies but has no storage ID. Ask for a fresh card.",
  bad_labels: "Run by or Location is empty, has extra spaces, or is longer than 64 characters.",
  local_card: "This card is for a node inside its owner's own Home. Use Include this Home on that Home instead.",
  own_card: "This is this Home's own card. Use Include this Home.",
});

// Fetching a card from its node: refusals with no states.md row. The node
// refuses for more than ownership (clock skew, a replayed request), so
// not_owner names no cause; the node's reason follows as "Reason: …".
export const FETCH_REFUSAL_LINES = Object.freeze({
  bad_address: "This is not a node address. Ask the node operator for the address their node host printed.",
  unreachable: "This Home could not reach the node. Check that the node is running, then try again.",
  not_owner: "The node did not give its card to this Home.",
  no_card: "The node has no node card yet. Ask the operator to set it up for custody, or to send its node card.",
});
const CARD_PREFIX = "elastos-node-card:";

// Card refusals the slot shows that states.md has no row for.
const SLOT_REFUSED_LINES = Object.freeze({
  local_node_missing: "This Home's node could not be found. Nothing changed.",
  local_node_unreadable: "This Home's node could not be read. Nothing changed.",
  local_node_no_keys: "This Home's node has no keys, so it cannot join a pool. Include this Home again to set it up.",
});
const CARD_REFUSED_LINE = "Runtime refused this card. Nothing changed.";

// Permanent refusals with no states.md row: what failed, then that nothing
// changed. The Runtime's detail follows as "Reason: …".
const REFUSED_LINES = Object.freeze({
  provision_failed: "Setting up this Home's node failed. Nothing changed.",
  local_node_unreadable: SLOT_REFUSED_LINES.local_node_unreadable,
  local_node_missing: SLOT_REFUSED_LINES.local_node_missing,
  register_failed: "Registering the node failed. Nothing changed.",
  no_card: "This Home has no node card for that member. Nothing changed.",
  no_pool: "This Home has no pool. Nothing changed.",
  unknown_share: "That share is not in the pool. Nothing changed.",
  bad_request: "Runtime refused the request. Nothing changed.",
  bad_slot: "Runtime refused a node slot. Nothing changed.",
  bad_term: "Runtime refused the pool term. Nothing changed.",
  pool_installed: "The pool is installed, so this Home's node stays. Nothing changed.",
  already_serving: "This Home serves another Home's pool. Nothing changed.",
  no_local_node: "This Home has no node to remove. Nothing changed.",
});
// A removal that stopped part way left this Home's node half removed.
const REMOVE_FAILED_LINE = "This Home's node could not be fully removed. Try again.";
const LOCAL_NODE_REMOVED_LINE = "This Home's node is removed. This Home can offer custody again.";
const REFUSED_LINE = "Runtime refused this action. Nothing changed.";

// The design names roles in this order; `ipfs` is "storage" in the UI.
const ROLE_WORDS = [
  ["custody", "custody"],
  ["chain", "chain"],
  ["ipfs", "storage"],
];

// Cards travel by chat and email, which wrap long lines. The Runtime parser
// strips ASCII whitespace too, so the duplicate check here sees what it sees.
export function normalizeCardText(text) {
  return typeof text === "string" ? text.replace(/[\t\n\f\r ]+/g, "") : "";
}

// What a slot was given: card text (the fallback), or else the node's
// address, which Runtime fetches the card from.
export function slotEntry(text) {
  const trimmed = readText(text);
  if (!trimmed) {
    return null;
  }
  const value = normalizeCardText(trimmed);
  return trimmed.startsWith(CARD_PREFIX) ? { card: value } : { address: value };
}

export function refusalLine(code, slot) {
  if (code === "duplicate") {
    return `This card is already in node ${slot}.`;
  }
  if (Object.hasOwn(REFUSAL_LINES, code)) {
    return REFUSAL_LINES[code];
  }
  return Object.hasOwn(SLOT_REFUSED_LINES, code) ? SLOT_REFUSED_LINES[code] : CARD_REFUSED_LINE;
}

export function slotCount(threshold) {
  const total = threshold?.total;
  return Number.isInteger(total) && total > 0 && total <= 255 ? total : 0;
}

// The rule as a plain sentence, for the check row. While slots are still
// empty a count would claim more than the cards prove, so it is left out.
export function checkTitle(id, threshold, filled) {
  const total = slotCount(threshold);
  const partial = filled < total;
  switch (id) {
    case "members":
      return `${total} members`;
    case "keys":
      return "Every node has its own keys";
    case "homes":
      return partial ? "Different Homes" : `${total} different Homes`;
    case "run_by":
      return partial ? "Different people run them" : `${total} different people run them`;
    case "location":
      return partial ? "Different places" : `${total} different places`;
    case "this_home":
      return "At most one slot is this Home";
    case "roles":
      return "Every node provides custody and chain";
    default:
      return "";
  }
}

// The states.md line for one check result, built from the names and detail
// the Runtime sent. `run_by` names Locations (the shared operator is the
// detail); every other rule names the Run by.
export function checkLine(result, threshold) {
  const total = slotCount(threshold);
  const names = arrayValue(result?.names).filter((name) => typeof name === "string" && name);
  const who = listWords(names);
  const detail = readText(result?.detail);
  const passed = result?.result === "pass";
  switch (result?.id) {
    case "members":
      return passed
        ? `${total} members`
        : `Add ${Math.max(total - names.length, 0)} more. A pool needs exactly ${total}.`;
    case "keys":
      return passed
        ? "Every node has its own keys"
        : `${who} use the same node keys. One card was copied from the other. Ask for fresh cards.`;
    case "homes":
      return passed
        ? `${total} different Homes`
        : `${who} are the same Home. A Home holds one share in a pool.`;
    case "run_by":
      return passed
        ? `${total} different people run them`
        : `${who} are both run by ${sentence(detail)} Swap one of them.`;
    case "location":
      return passed
        ? `${total} different places`
        : `${who} both run in ${sentence(detail)} Pools need different places.`;
    case "this_home":
      return passed ? "At most one slot is this Home" : "Only one slot can be this Home.";
    case "roles": {
      if (passed) {
        return "Every node provides custody and chain";
      }
      const missing = listWords(detail.split(",").map((role) => role.trim()).filter(Boolean));
      const verb = names.length > 1 ? "do" : "does";
      return `${who} ${verb} not provide ${missing}. Ask ${who} to set up the node with custody and chain.`;
    }
    case "copies":
      // The creator's Home serves the protected copy; pool members keep key
      // shares only until the pool redesign brings copies back.
      return COPIES_LINE;
    default:
      return "";
  }
}

export const COPIES_LINE = "Your Home serves the protected copy. Nodes keep key shares only.";

export function termEnd(startMs, termDays) {
  return startMs + termDays * DAY_MS;
}

export function formatDate(ms) {
  const date = new Date(ms);
  return `${date.getDate()} ${MONTHS[date.getMonth()]} ${date.getFullYear()}`;
}

export function termLabel(days) {
  return Object.hasOwn(TERM_LABELS, days) ? TERM_LABELS[days] : `${days} days`;
}

// The terms Runtime accepts, in its order.
export function termPresets(days) {
  return arrayValue(days).filter((day) => Number.isInteger(day) && day > 0);
}

// The term to select: the one chosen if Runtime still offers it, else the
// default, else Runtime's first.
export function termChoice(presets, chosen) {
  if (presets.length === 0 || presets.includes(chosen)) {
    return chosen;
  }
  return presets.includes(DEFAULT_TERM_DAYS) ? DEFAULT_TERM_DAYS : presets[0];
}

// The Runtime's label rule: 1..=64 UTF-8 bytes, no surrounding whitespace.
export function validLabel(value) {
  return typeof value === "string"
    && value.length > 0
    && value.trim() === value
    && new TextEncoder().encode(value).byteLength <= MAX_LABEL_BYTES;
}

export function rolesText(provides) {
  const roles = arrayValue(provides);
  const text = listWords(ROLE_WORDS.filter(([role]) => roles.includes(role)).map(([, word]) => word));
  return text ? text[0].toUpperCase() + text.slice(1) : "";
}

// Fingerprints arrive as "1A2B 3C4D … 4F2A 91C0"; a slot quotes the end.
export function fingerprintTail(fingerprint) {
  const groups = readText(fingerprint).split(/\s+/).filter(Boolean);
  return groups.length >= 2 ? groups.slice(-2).join(" ") : groups.join(" ");
}

export function middleTruncate(value, head = 12, tail = 8) {
  const text = readText(value);
  return text.length > head + tail + 1 ? `${text.slice(0, head)}…${text.slice(-tail)}` : text;
}

// The install body: one entry per share, in share order. Null until every
// slot holds a read card or this Home.
export function installSlots(slots) {
  const entries = arrayValue(slots).map((slot) => {
    if (slot?.kind === "home") {
      return { this_home: true };
    }
    if (slot?.kind === "card" && slot.text) {
      return { card: slot.text };
    }
    return null;
  });
  return entries.length > 0 && entries.every(Boolean) ? entries : null;
}

// What to say for a failed request. Coded refusals map to their states.md
// line, or a "Nothing changed." line where states.md has none; a Runtime
// `detail` is shown as "Reason: …"; plain text is shown as is. Only a network
// failure or an uncoded 5xx is transient and says Runtime will retry.
export function errorView(error) {
  const code = readText(error?.code);
  const detail = readText(error?.detail);
  const reason = detail ? `Reason: ${detail}` : "";
  switch (code) {
    case "already_installed":
      return { line: "This Home already has a pool. Nothing changed.", reason: "" };
    case "verify_failed":
      return {
        line: detail
          ? `The installed pool did not pass the Runtime check: ${detail.replace(/\.$/, "")}.`
          : "The installed pool did not pass the Runtime check.",
        reason: "",
      };
    case "install_failed":
      return { line: INSTALL_FAILED_LINE, reason };
    case "bad_labels":
      return { line: REFUSAL_LINES.bad_labels, reason: "" };
    case "no_signing_key":
      return { line: KEY_MISSING_LINE, reason: "" };
    case "checks_failed":
      return { line: FIX_CHECKS_LINE, reason: "" };
    case "protected_content_off":
      return { line: CHAIN_MISSING_LINE, reason: "" };
    case "term_changed":
      return { line: TERM_CHANGED_LINE, reason: "" };
    case "already_holds_custody":
      return { line: HOLDS_CUSTODY_LINE, reason: "" };
    case "host_trust_required":
      return { line: HOST_TRUST_REQUIRED_LINE, reason: "" };
    case "messages_not_enabled":
      return { line: MESSAGES_OFF_REFUSED_LINE, reason: "" };
    case "no_profile":
      return { line: NO_PROFILE_LINE, reason: "" };
    case "remove_failed":
      return { line: REMOVE_FAILED_LINE, reason };
    case "":
      break;
    default:
      return { line: Object.hasOwn(REFUSED_LINES, code) ? REFUSED_LINES[code] : REFUSED_LINE, reason };
  }
  const text = readText(error?.text);
  return { line: text || UNAVAILABLE_LINE, reason: "" };
}

// A refused fetch, as the slot shows it, or null when the failure is about
// the request rather than the node or its card (errorView words those). A
// fetched card is refused for the same reasons as a pasted one.
export function fetchRefusal(error) {
  const code = readText(error?.code);
  const detail = readText(error?.detail);
  const reason = detail ? `Reason: ${detail}` : "";
  if (Object.hasOwn(FETCH_REFUSAL_LINES, code)) {
    return { line: FETCH_REFUSAL_LINES[code], reason, retry: code !== "bad_address" };
  }
  if (Object.hasOwn(REFUSAL_LINES, code)) {
    return { line: refusalLine(code), reason, retry: false };
  }
  return null;
}

// The slot a failed card fetch or read leaves. The node's refusals show as
// refused. A bad address or a request that failed keeps the text in an empty
// slot to edit or send again; one that never reached Runtime offers Try again.
export function failedSlot(error, text, address = "") {
  const refused = address ? fetchRefusal(error) : null;
  if (refused && error?.code !== "bad_address") {
    return { kind: "refused", ...refused, address };
  }
  const unavailable = !refused && error?.unavailable === true;
  const line = refused?.line || (unavailable ? SLOT_UNAVAILABLE_LINE : errorView(error).line);
  return { kind: "empty", text, error: line, note: "", retry: unavailable };
}

// A failed Verify again: only the Runtime's verify_failed verdict marks the
// installed pool as failed. Any other refusal or an unreachable Runtime is a
// notice about the request, and leaves the last check as it was.
export function verifyFailure(error) {
  return error?.code === "verify_failed"
    ? { verify: { ok: false, view: errorView(error) }, notice: null }
    : { verify: null, notice: { tone: "danger", ...errorView(error) } };
}

// Live member health, from `pool/health`. The Runtime decides each state and
// the pool status; the numbers in every line come from its answer.
const HEALTH_STATUSES = Object.freeze({
  healthy: { word: "Healthy", tone: "ok" },
  at_risk: { word: "At risk", tone: "pending" },
  down: { word: "Down", tone: "danger" },
});
const MEMBER_STATES = Object.freeze({
  online: { word: "Online", tone: "ok" },
  not_answering: { word: "Not answering", tone: "danger" },
  different_node: { word: "Different node", tone: "danger" },
  refused: { word: "Refused", tone: "pending" },
});
// The only stable detail codes; any other detail is the node's own text.
const MEMBER_DETAIL_LINES = Object.freeze({
  no_address: "No address for this node on this Home.",
  not_running: "This Home's node is not running. Restart this Home to start it.",
});
const DIFFERENT_NODE_LINE = "This node answers with different keys than the pool expects.";
const MAX_DETAIL_CHARS = 200;
export const HEALTH_FAILED_LINE = "Node health could not be checked. Try again.";
export const HEALTH_CHECKING_LINE = "Checking each node. It takes a few seconds.";

// The health answer, or null when it is not one this app can show.
export function readHealth(value) {
  const health = objectValue(value);
  const { required, total, online } = health;
  // Without its time an answer cannot say when the nodes were checked.
  const checkedAt = health.checked_at;
  if (!Object.hasOwn(HEALTH_STATUSES, health.status)
    || ![required, total, online, checkedAt].every(Number.isInteger)
    || required < 1 || required > total || online < 0 || online > total || checkedAt <= 0) {
    return null;
  }
  return {
    status: health.status,
    online,
    required,
    total,
    checkedAt: checkedAt * 1000,
    members: arrayValue(health.members)
      .filter((member) => Number.isInteger(member?.share))
      .map((member) => ({ share: member.share, state: readText(member.state), detail: readText(member.detail) })),
  };
}

export function healthChip(status) {
  return HEALTH_STATUSES[status];
}

export function healthLine(health) {
  switch (health.status) {
    case "healthy":
      return `All ${health.total} nodes are online.`;
    case "at_risk": {
      // Refused and different-node members answered, but are not online.
      const missing = health.total - health.online;
      return `Releases work, with no spare. ${missing} of ${health.total} nodes ${missing === 1 ? "is" : "are"} not online.`;
    }
    default:
      return `Buyers cannot open content in this pool until ${health.required} ${health.required === 1 ? "node is" : "nodes are"} online.`;
  }
}

export function healthBanner(health) {
  if (health.status === "healthy") {
    return { tone: "ok", strong: "Pool active.", line: `Any ${health.required} of ${health.total} shares open your content.` };
  }
  return { tone: healthChip(health.status).tone, line: healthLine(health) };
}

// The one banner the Active view shows, highest first: a pool the Runtime
// refused, an ended term, a down pool, this Home's restart, an unregistered
// member, a term ending soon, then health. Only a fresh healthy answer shows
// the ok "Pool active." banner; a check that runs or failed never reads as
// healthy. Null when there is no pool.
export function activeBanner({
  problem = null,
  pool = false,
  termEndedAt = 0,
  health = null,
  checking = false,
  failed = false,
  restart = false,
  unregistered = "",
  termDaysLeft = null,
  threshold = {},
} = {}) {
  if (problem) {
    return { tone: "danger", ...problem };
  }
  if (!pool) {
    return null;
  }
  if (termEndedAt) {
    return { tone: "danger", line: `Pool term ended on ${formatDate(termEndedAt)}.` };
  }
  // A last-known down pool stays danger, even when the re-check failed.
  if (health?.status === "down") {
    return failed ? { ...healthBanner(health), line: staleLine(health) } : healthBanner(health);
  }
  if (restart) {
    return { tone: "pending", line: RESTART_NEEDED_LINE };
  }
  if (unregistered) {
    return { tone: "pending", line: `${unregistered} is not registered on this Home yet. Releases cannot reach it.` };
  }
  if (termDaysLeft !== null) {
    return { tone: "pending", line: `Pool term ends in ${termDaysLeft} days. Renewing comes in a later version.` };
  }
  if (!health) {
    if (failed) {
      return { tone: "pending", line: HEALTH_FAILED_LINE };
    }
    return { line: checking ? HEALTH_CHECKING_LINE : `Releases need ${threshold.required} of ${slotCount(threshold)} nodes online.` };
  }
  if (failed) {
    // The last answer, no longer confirmed: its line and time, never green.
    return { tone: "pending", line: staleLine(health) };
  }
  return healthBanner(health);
}

function staleLine(health) {
  return `${healthLine(health)} Last checked ${checkedText(health.checkedAt)}.`;
}

// When a check ran: the time today, else the date.
export function checkedText(ms) {
  const date = new Date(ms);
  if (date.toDateString() === new Date().toDateString()) {
    return `today, ${String(date.getHours()).padStart(2, "0")}:${String(date.getMinutes()).padStart(2, "0")}`;
  }
  return formatDate(ms);
}

// One member's dot, word and note. A state this app does not know reads as
// not answering, so it never claims a node is online.
export function memberHealth(member) {
  const state = Object.hasOwn(MEMBER_STATES, member.state) ? member.state : "not_answering";
  const detail = readText(member.detail);
  const reason = clipDetail(detail);
  let note = reason ? `Reason: ${reason}` : "";
  if (state === "different_node") {
    note = DIFFERENT_NODE_LINE;
  } else if (state === "online") {
    note = "";
  } else if (state === "not_answering" && Object.hasOwn(MEMBER_DETAIL_LINES, detail)) {
    note = MEMBER_DETAIL_LINES[detail];
  }
  return { presence: state, ...MEMBER_STATES[state], note };
}

// A node's reason is free text from another Home: keep it to one short line.
// Controls become word breaks, and bidi marks and overrides go, so the text
// cannot reorder the "Reason:" line it sits in.
const DETAIL_CONTROLS = /[\u0000-\u001F\u007F-\u009F]+/g;
const DETAIL_BIDI = /[\u200E\u200F\u202A-\u202E\u2066-\u2069]/g;

export function clipDetail(value) {
  const text = typeof value === "string" ? value.replace(DETAIL_BIDI, "").replace(DETAIL_CONTROLS, " ").replace(/ {2,}/g, " ") : "";
  const chars = [...text.trim()];
  return chars.length > MAX_DETAIL_CHARS ? `${chars.slice(0, MAX_DETAIL_CHARS - 1).join("")}…` : chars.join("");
}

// This Home as a node in another Home's pool, from `summary.serving`, or null
// when it serves none. Only a true provider_running reads as running, and a
// contact time that is not whole positive seconds reads as never.
export function readServing(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }
  const contact = value.last_owner_contact;
  return {
    ownerName: readText(value.owner_name),
    ownerDid: readText(value.owner_did),
    runBy: readText(value.run_by),
    location: readText(value.location),
    provides: arrayValue(value.provides),
    fingerprint: readText(value.fingerprint),
    fingerprintFull: readText(value.fingerprint_full),
    running: value.provider_running === true,
    // Running is not serving yet while the Chain plane trusts a stale issuer.
    needsRestart: value.needs_restart === true,
    lastContact: Number.isInteger(contact) && contact > 0 ? contact * 1000 : 0,
    pool: readServedPool(value.pool),
    // Plan B T2.3: the served pool's key, which Stop serving names.
    poolFingerprint: POOL_FINGERPRINT_HEX.test(readText(value.pool_fingerprint)) ? readText(value.pool_fingerprint) : "",
  };
}

const POOL_FINGERPRINT_HEX = /^[0-9a-f]{64}$/;
const SERVED_POOL_STATUSES = Object.freeze({
  waiting_for_pool: { tone: "pending", word: "Waiting for the owner's pool" },
  serving: { tone: "ok", word: "Serving" },
  needs_restart: { tone: "pending", word: "Restart this Home to serve this pool." },
  consent_ending: { tone: "pending", word: "Consent ends in under 7 days" },
});

// Plan B T2.3: the served pools from `custody/pools/served`, one per pool. An
// item without a pool key or a known status is dropped.
export function readServedPools(answer) {
  return arrayValue(answer)
    .filter((item) => POOL_FINGERPRINT_HEX.test(readText(item?.pool_fingerprint)) && Object.hasOwn(SERVED_POOL_STATUSES, item?.status))
    .map((item) => ({
      poolFingerprint: item.pool_fingerprint,
      ownerName: readText(item.owner_name),
      roles: arrayValue(item.roles).filter((role) => typeof role === "string"),
      status: item.status,
      termEnd: Number.isInteger(item.term_end) && item.term_end > 0 ? item.term_end * 1000 : 0,
      sharesHeld: Number.isInteger(item.shares_held) && item.shares_held >= 0 ? item.shares_held : null,
      publisherConfirmed: item.publisher_confirmed === true,
    }));
}

// This Home's own pool from `summary.own_pool` (S2-R3-F1), or null.
export function readOwnPool(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }
  const poolFingerprint = readText(value.pool_fingerprint);
  if (!POOL_FINGERPRINT_HEX.test(poolFingerprint)) {
    return null;
  }
  return { poolFingerprint, publisherConfirmed: value.publisher_confirmed === true };
}

// What Confirm publisher sends, and what the passkey approves: the pool again.
export function confirmPublisherRequest(poolFingerprint) {
  return { pool: poolFingerprint };
}

const CONFIRM_PUBLISHER_LINES = Object.freeze({
  unknown_pool: "This Home no longer holds that pool. Nothing changed.",
  bad_pool: "Runtime refused the pool. Nothing changed.",
});

export function confirmPublisherRefusalLine(code) {
  return CONFIRM_PUBLISHER_LINES[code] || "The publisher was not confirmed. Nothing changed.";
}

export function servedPoolStatusChip(status) {
  return SERVED_POOL_STATUSES[status] || null;
}

export function sharesHeldLine(count) {
  return count === 1 ? "Holds 1 share." : `Holds ${count} shares.`;
}

// What Stop serving sends, and what the passkey approves: the pool again.
export function stopServingRequest(poolFingerprint) {
  return { pool: poolFingerprint };
}

const STOP_SERVING_LINES = Object.freeze({
  unknown_pool: "This Home no longer serves that pool. Nothing changed.",
  bad_pool: "Runtime refused the pool. Nothing changed.",
  stop_failed: "The pool could not be fully stopped. Try again.",
});

export function stopServingRefusalLine(code) {
  return STOP_SERVING_LINES[code] || "Stop serving failed. Nothing changed.";
}

export const STOPPED_SERVING_LINE = "This Home no longer serves that pool. Its shares are set aside on this Home.";

export const POOL_WAITING_LINE = "Waiting for the owner to confirm the pool.";

// The signed pool a served node is in, from `summary.serving.pool`, or null
// until its owner confirms one. A share outside the threshold, or a time
// that is not whole positive seconds, reads as no pool.
export function readServedPool(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }
  const { share, total, required } = value;
  const whole = (number) => Number.isInteger(number) && number > 0;
  if (![share, total, required, value.pool_start, value.term_end].every(whole) || share > total || required > total) {
    return null;
  }
  return {
    share,
    total,
    required,
    poolStart: value.pool_start * 1000,
    termEnd: value.term_end * 1000,
    members: arrayValue(value.members)
      .filter((member) => Number.isInteger(member?.share))
      .map((member) => ({ share: member.share, runBy: readText(member.run_by), location: readText(member.location) })),
  };
}

export function servedPoolLine(pool) {
  return `Share ${pool.share} of ${pool.total} · ${pool.required} needed`;
}

const NOTICE_STATES = ["pending", "delivered", "refused", "skipped"];

// Who of the installed pool's members was told they are in it, from
// `summary.pool_notices`, or null when there is no set.
export function readPoolNotices(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }
  return {
    fingerprintFull: readText(value.fingerprint_full),
    members: arrayValue(value.members)
      .filter((member) => Number.isInteger(member?.share) && NOTICE_STATES.includes(member?.state))
      .map((member) => ({
        share: member.share,
        name: readText(member.recipient_name),
        state: member.state,
        code: readText(member.code),
      })),
  };
}

export const NOTICE_MESSAGES_OFF_LINE = "Waiting: custody messages are off on this Home";

// `messagesOff` is true only when the Hosting offer read says this Home's
// custody messages are off: its notices wait until they are on.
export function noticeLine({ state, code }, { messagesOff = false } = {}) {
  switch (state) {
    case "delivered":
      return { word: "Told", tone: "ok" };
    case "pending":
      return messagesOff
        ? {
          word: NOTICE_MESSAGES_OFF_LINE,
          tone: "pending",
          hint: NODE_REQUEST_REFUSAL_LINES.messages_not_enabled,
        }
        : { word: "Not told yet", tone: "pending" };
    case "refused":
      return { word: code ? `Could not tell (${code})` : "Could not tell", tone: "danger" };
    default:
      return code === "this_home" ? { word: "This Home", tone: "accent" } : { word: "Not a contact", tone: "" };
  }
}

// Notify members again, one request at a time: a press while one runs sends
// nothing and returns null.
export function notifyOnce(post) {
  let running = null;
  return () => {
    if (running) {
      return null;
    }
    running = (async () => {
      try {
        return { notices: readPoolNotices(await post({})) };
      } catch (error) {
        return { notice: errorView(error) };
      } finally {
        running = null;
      }
    })();
    return running;
  };
}

export function servingStatus({ running, needsRestart }) {
  if (!running) {
    return { tone: "pending", word: "Node not running. Restart this Home." };
  }
  return needsRestart
    ? { tone: "pending", word: "Restart this Home to finish serving." }
    : { tone: "ok", word: "Node running" };
}

// The Hosting offer, from `custody/offer`, or null when it is not one. Only
// a true flag reads as set. The labels stay as Runtime sent them: switching
// off sends them back unchanged.
export function readOffer(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }
  return {
    enabled: value.enabled === true,
    runBy: typeof value.run_by === "string" ? value.run_by : "",
    location: typeof value.location === "string" ? value.location : "",
    provides: arrayValue(value.provides),
    holdsCustody: value.holds_custody_state === true,
    messagesEnabled: value.messages_enabled === true,
  };
}

// What the offer switch sends, or null when an edited label is bad. Runtime
// checks the labels even when the offer goes off, so off sends the stored
// ones and leaves any edit behind.
export function offerBody(offer, draft, enabled) {
  if (!enabled) {
    return { enabled: false, run_by: offer.runBy, location: offer.location };
  }
  if (!validLabel(draft.runBy) || !validLabel(draft.location)) {
    return null;
  }
  return { enabled: true, run_by: draft.runBy, location: draft.location };
}

// Switches the offer through `post(body)`: the new offer, a bad label (never
// sent when it is caught here), or the refusal to show.
export async function switchOffer(post, offer, draft, enabled) {
  const body = offerBody(offer, draft, enabled);
  if (!body) {
    return { invalid: true };
  }
  try {
    return { offer: readOffer(await post(body)) };
  } catch (error) {
    return error?.code === "bad_labels" ? { invalid: true } : { notice: errorView(error) };
  }
}

// Enabling custody messages changes the admin's Profile, so the passkey comes
// first; a step-up that fails or is cancelled sends nothing.
export function enableMessages(stepUp, post) {
  return withStepUp(MESSAGES_ENABLE_OPERATION, stepUp, post);
}

// Removing this Home's node before install deletes its keys, so the passkey
// comes first, as for Include this Home. A node already gone clears the slot
// too; `note` says which.
export async function removeLocalNode(stepUp, remove) {
  let note = LOCAL_NODE_REMOVED_LINE;
  const outcome = await withStepUp(LOCAL_NODE_REMOVE_OPERATION, stepUp, async (body) => {
    try {
      await remove(body);
    } catch (error) {
      if (error?.code !== "no_local_node") {
        throw error;
      }
      note = errorView(error).line;
    }
  });
  return outcome.ok ? { ok: true, note } : outcome;
}

async function withStepUp(operation, stepUp, send) {
  let stepUpToken = "";
  try {
    stepUpToken = await stepUp(operation, {});
  } catch (error) {
    return { ok: false, line: readText(error?.message) || PASSKEY_FAILED_LINE, reason: "" };
  }
  try {
    await send({ step_up_token: stepUpToken });
    return { ok: true };
  } catch (error) {
    return { ok: false, ...errorView(error) };
  }
}

/* ---------- Find nodes: requests to contacts ---------- */

// The owner's sent requests from `summary.node_requests`, newest first. A
// record without an id or a known state is left out.
export function readNodeRequests(value) {
  return arrayValue(value)
    .filter((record) => readText(record?.request_id) && REQUEST_STATES.includes(record?.state))
    .map((record) => ({
      requestId: readText(record.request_id),
      profileDid: readText(record.recipient_profile_did),
      recipientHome: readText(record.recipient_home),
      name: readText(record.recipient_name),
      termDays: Number.isInteger(record.term_days) ? record.term_days : 0,
      createdAt: Number.isInteger(record.created_at) ? record.created_at : 0,
      state: record.state,
      code: readText(record.code),
      card: record.state === "approved" ? normalizeCardText(record.card) : "",
    }))
    .sort((left, right) => right.createdAt - left.createdAt);
}

// The contacts `nodes/find` answered with. A status this app does not know
// reads as not reachable, so it never offers Ask.
export function readFoundContacts(value) {
  return arrayValue(objectValue(value).contacts)
    .filter((contact) => readText(contact?.profile_did))
    .map((contact) => ({
      profileDid: readText(contact.profile_did),
      name: readText(contact.name),
      status: FOUND_STATUSES.includes(contact.status) ? contact.status : "unreachable",
      runBy: readText(contact.run_by),
      location: readText(contact.location),
      provides: arrayValue(contact.provides),
      request: REQUEST_STATES.includes(contact.request) ? contact.request : "",
    }));
}

export function requestErrorView(error) {
  const code = readText(error?.code);
  return Object.hasOwn(NODE_REQUEST_REFUSAL_LINES, code)
    ? { line: NODE_REQUEST_REFUSAL_LINES[code], reason: "" }
    : errorView(error);
}

// A slot bound to a sent request; its state comes from the record.
export function requestSlot(record) {
  return { kind: "request", requestId: record.requestId, record };
}

// The contact an approved node in a slot came from, which can be asked again
// for another term; "" for anything else. A waiting request answers first.
export function askAgainTarget(slot) {
  if (slot?.kind === "card" && slot.requestId) {
    return readText(slot.profileDid);
  }
  if (slot?.kind === "request" && slot.record?.state === "approved") {
    return readText(slot.record.profileDid);
  }
  return "";
}

// Where to bind a node asked again: the slot `asked` was in, or the slot that
// holds its request now (a summary can read the same approval into a new
// slot meanwhile); -1 when the owner removed it.
export function askAgainIndex(slots, index, asked) {
  const list = arrayValue(slots);
  if (list[index] === asked) {
    return index;
  }
  return asked?.requestId ? list.findIndex((slot) => slot?.requestId === asked.requestId) : -1;
}

// A read card's slot: `{card}` is what check and install send. `view` is the
// card as `node-cards/read` gave it; a card from an approval keeps the
// request it came from.
export function cardSlot(text, view, approval = {}) {
  return { kind: "card", text, card: objectValue(view), ...approval };
}

// What a slot filled from an approval carries while it is read and after.
export function approvalFields(record) {
  return {
    requestId: record.requestId,
    profileDid: record.profileDid,
    recipientHome: record.recipientHome,
    approvedBy: record.name,
    termDays: record.termDays,
  };
}

// The chip, line and action of a request: Cancel while it waits; Find another
// once it can no longer fill the slot.
export function requestStatus(record) {
  switch (record.state) {
    case "waiting":
      return { word: `Waiting for ${record.name}`, tone: "pending", line: "", action: "cancel" };
    case "approved":
      // An approval without a card cannot fill the slot; it can only be let go.
      return { word: `Approved by ${record.name}`, tone: "ok", line: "", action: record.card ? "" : "find-another" };
    case "declined":
      if (Object.hasOwn(NODE_DECLINE_LINES, record.code)) {
        return { word: "Declined", tone: "danger", line: NODE_DECLINE_LINES[record.code], action: "find-another" };
      }
      return {
        word: "Not sent",
        tone: "danger",
        line: record.code
          ? `This request could not be delivered (${record.code}).`
          : "This request could not be delivered.",
        action: "find-another",
      };
    default:
      return { word: "Expired", tone: "pending", line: "", action: "find-another" };
  }
}

// The request a slot holds or came from, while the node may still act on it.
function liveRequest(slot) {
  if (slot?.kind === "request") {
    return LIVE_REQUEST_STATES.includes(slot.record?.state) ? slot.record : null;
  }
  return slot?.requestId ? { recipientHome: slot.recipientHome, profileDid: slot.profileDid, termDays: slot.termDays } : null;
}

// The node Home a slot holds: a request's recipient, or a read card's node.
// A card's node is its sender's Home, so it matches `recipient_home`.
function slotHomes(slot) {
  return [liveRequest(slot)?.recipientHome, slot?.kind === "card" ? readText(slot.card?.home_id) : ""]
    .filter(Boolean);
}

// The share (1-based) a contact already fills, or 0. A pasted card counts
// when its node is a Home that contact's requests went to, or it is the
// card an approval from that contact carried.
export function slotForContact(slots, profileDid, records = []) {
  const theirs = records.filter((record) => record.profileDid === profileDid);
  const homes = new Set(theirs.map((record) => record.recipientHome).filter(Boolean));
  const index = arrayValue(slots).findIndex((slot) => {
    if (liveRequest(slot)?.profileDid === profileDid) {
      return true;
    }
    return slot?.kind === "card" && !slot.requestId
      && (slotHomes(slot).some((home) => homes.has(home))
        || theirs.some((record) => record.card && record.card === slot.text));
  });
  return index + 1;
}

// Waiting and approved requests no slot holds, each with the empty slot it
// fills: newest first, for the chosen term only, never a Home twice. An empty
// slot with typed text is the owner's, and released requests stay out.
export function restorePlacements(slots, records, termDays, released) {
  const homes = new Set();
  const bound = new Set();
  const cards = new Set();
  for (const slot of arrayValue(slots)) {
    for (const home of slotHomes(slot)) {
      homes.add(home);
    }
    if (slot?.requestId) {
      bound.add(slot.requestId);
    }
    if (slot?.text) {
      cards.add(slot.text);
    }
  }
  const free = arrayValue(slots)
    .map((slot, index) => (slot?.kind === "empty" && !readText(slot.text) && !slot.requestId ? index : -1))
    .filter((index) => index >= 0);
  const placements = [];
  for (const record of records) {
    if (!free.length) {
      break;
    }
    if (!LIVE_REQUEST_STATES.includes(record.state) || record.termDays !== termDays
      || bound.has(record.requestId) || released.has(record.requestId)
      || homes.has(record.recipientHome) || (record.card && cards.has(record.card))
      || (record.state === "approved" && !record.card)) {
      continue;
    }
    homes.add(record.recipientHome);
    placements.push({ index: free.shift(), record });
  }
  return placements;
}

// A slot's node agreed to, or was asked for, a term other than the chosen
// one: install would be refused, so it is refused before the passkey.
export function termMismatch(slots, termDays) {
  return arrayValue(slots).some((slot) => {
    const live = liveRequest(slot);
    return Boolean(live) && live.termDays !== termDays;
  });
}

export function termChangedLine(agreedDays, termDays) {
  return agreedDays && agreedDays !== termDays
    ? `This node agreed to ${termLabel(agreedDays)}. Ask again for the new term.`
    : "";
}

// Refresh the summary while a node may still answer and the owner can see it.
export function shouldPollRequests(slots, { shown, visible }) {
  return shown === true && visible === true
    && arrayValue(slots).some((slot) => slot?.kind === "request" && slot.record?.state === "waiting");
}

// How long until the next poll: one interval after the last summary began.
// Arming the poll again (a section, step or visibility change) never pushes
// the refresh back, and a view shown again after an interval refreshes now.
export function pollDelay(lastAt, now, interval) {
  return Math.min(interval, Math.max(0, lastAt + interval - now));
}

// A failed offer read. Nothing reads it again on its own, so the line asks
// for Try again; Runtime's reason or its plain-text refusal follows.
export function offerReadFailure(error) {
  const detail = readText(error?.detail);
  return { line: OFFER_UNREAD_LINE, reason: detail ? `Reason: ${detail}` : readText(error?.text) };
}

export function ownerContactLine(ms) {
  return ms > 0 ? `Last checked by the owner: ${checkedText(ms)}.` : "The owner has not checked this node yet.";
}

// `summary.local_node` mixes two nodes: `address` belongs to the node this
// Home serves for another owner, the rest to the Include this Home node. The
// include route answers for its node only, with a null address.
const INCLUDED_NODE_FIELDS = ["provisioned", "run_by", "location", "fingerprint", "running"];

export function mergeLocalNode(current, included) {
  const merged = { ...objectValue(current) };
  const answer = objectValue(included);
  for (const field of INCLUDED_NODE_FIELDS) {
    if (Object.hasOwn(answer, field)) {
      merged[field] = answer[field];
    }
  }
  return merged;
}

// A new Include this Home slot. Run by starts as this Home's Profile name
// when the summary carries one; it stays editable.
export function includeDraft(summary) {
  return {
    kind: "include",
    runBy: readText(objectValue(summary).local_profile_name),
    location: "",
    invalid: false,
    error: "",
    busy: false,
  };
}

// Home's clipboard purposes for Custody: one token such as a DID or a node
// address, or a whole fingerprint digest ("sha256:" and 64 hex).
export const COPY_IDENTIFIER = "custody.identifier";
export const COPY_FINGERPRINT = "custody.fingerprint";
// The owner's pool address, for another Home to add the pool.
export const COPY_POOL_ADDRESS = "custody.pool_address";

// What Runtime says when a pool was not added, in Custody's own words.
const KNOWN_POOL_REFUSALS = {
  bad_address: "This is not a pool address. Ask the pool owner to copy it from Custody › Pools.",
  pool_unreachable: "The pool did not answer. Check that its owner’s Home is online, then try again.",
  pool_invalid: "The pool’s answer could not be checked, so the pool was not added.",
  too_many_pools: "This Home already uses as many pools as it can.",
};

export function knownPoolRefusalLine(code) {
  const key = readText(code);
  return Object.hasOwn(KNOWN_POOL_REFUSALS, key)
    ? KNOWN_POOL_REFUSALS[key]
    : "The pool was not added. Try again.";
}

// The known pools as Runtime lists them; rows it cannot read are left out.
export function readKnownPools(answer) {
  return arrayValue(objectValue(answer).pools)
    .map((pool) => ({
      pool: readText(pool?.pool),
      address: readText(pool?.address),
      sequence: Number(pool?.sequence),
      members: Number(pool?.members),
      servers: Number(pool?.servers),
      expiresAt: Number(pool?.expires_at),
    }))
    .filter((pool) => pool.pool && pool.address && Number.isSafeInteger(pool.servers));
}

// Copies one value through Home's clipboard bridge. "fallback" means the
// bridge is missing or never answered, so the caller selects the value for a
// keyboard copy; "cancelled" means the person declined Home's prompt.
export async function copyThroughHome(clipboard, value, purpose) {
  if (!clipboard) {
    return "fallback";
  }
  try {
    await clipboard.writeText(value, { purpose });
    return "copied";
  } catch (error) {
    const code = readText(error?.code);
    if (code === "cancelled") {
      return "cancelled";
    }
    return !code || code === "unavailable" ? "fallback" : "failed";
  }
}

// A name such as "Iz." already ends the sentence.
function sentence(text) {
  return text.endsWith(".") ? text : `${text}.`;
}

export function listWords(words) {
  if (words.length <= 1) {
    return words.join("");
  }
  return `${words.slice(0, -1).join(", ")} and ${words[words.length - 1]}`;
}

export function arrayValue(value) {
  return Array.isArray(value) ? value : [];
}

export function objectValue(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : {};
}

export function readText(value) {
  return typeof value === "string" ? value.trim() : "";
}

export function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}
