import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { homeClipboardValidPayload } from "../../home/browser/home-clipboard-protocol.js";
import {
  COPY_FINGERPRINT,
  COPY_IDENTIFIER,
  COPY_POOL_ADDRESS,
  PUBLISHER_NOTE,
  SERVED_POOL_CONFIRM_PUBLISHER_OPERATION,
  KNOWN_POOL_ADD_OPERATION,
  KNOWN_POOLS_LINE,
  knownPoolRefusalLine,
  readKnownPools,
  LOCAL_NODE_REMOVE_OPERATION,
  MESSAGES_ENABLE_OPERATION,
  checkLine,
  activeBanner,
  approvalFields,
  askAgainIndex,
  askAgainTarget,
  cardSlot,
  checkTitle,
  clipDetail,
  copyThroughHome,
  createView,
  enableMessages,
  errorView,
  HOST_TRUST_REQUIRED_LINE,
  failedSlot,
  fetchRefusal,
  fingerprintTail,
  formatDate,
  healthBanner,
  healthChip,
  healthLine,
  includeDraft,
  installSlots,
  memberHealth,
  mergeLocalNode,
  ownerContactLine,
  readFoundContacts,
  readHealth,
  readNodeRequests,
  readServing,
  readServedPools,
  servedPoolStatusChip,
  sharesHeldLine,
  stopServingRequest,
  HOSTING_POOLS_LINE,
  middleTruncate,
  noticeLine,
  normalizeCardText,
  notifyOnce,
  offerBody,
  offerReadFailure,
  pollDelay,
  readOffer,
  readPoolNotices,
  readServedPool,
  refusalLine,
  removeLocalNode,
  requestErrorView,
  requestSlot,
  requestStatus,
  restorePlacements,
  rolesText,
  servingStatus,
  shouldPollRequests,
  slotCount,
  slotEntry,
  switchOffer,
  termChoice,
  termEnd,
  termLabel,
  termChangedLine,
  termMismatch,
  termPresets,
  validLabel,
  verifyFailure,
} from "./custody.js";

const THRESHOLD = { required: 2, total: 3 };

test("normalizeCardText strips wrapping whitespace from chat or email", () => {
  assert.equal(normalizeCardText(" elastos-node-card:v1:ab\ncd "), "elastos-node-card:v1:abcd");
  assert.equal(normalizeCardText("elastos-node-card:v1:a b\r\n\tc"), "elastos-node-card:v1:abc");
  assert.equal(normalizeCardText(undefined), "");
});

test("refusalLine maps every card refusal code to its states.md line", () => {
  const lines = {
    not_a_card: "This is not a node card. Ask the node operator for the text that starts with elastos-node-card.",
    newer_version: "This node card comes from a newer ElastOS. Update this Home, then try again.",
    changed: "This card was changed after the node made it. Ask the operator for a fresh copy.",
    unsupported: "This node uses a format this Home cannot read. Ask the operator to update their node.",
    ticket_mismatch: "This card's connection details belong to a different Home. Ask for a fresh card.",
    storage_without_id: "This card says the node keeps copies but has no storage ID. Ask for a fresh card.",
    bad_labels: "Run by or Location is empty, has extra spaces, or is longer than 64 characters.",
    local_card: "This card is for a node inside its owner's own Home. Use Include this Home on that Home instead.",
    own_card: "This is this Home's own card. Use Include this Home.",
  };
  for (const [code, line] of Object.entries(lines)) {
    assert.equal(refusalLine(code), line, code);
  }
  assert.equal(refusalLine("duplicate", 2), "This card is already in node 2.");
});

test("refusalLine names an unknown code without guessing a reason", () => {
  assert.equal(refusalLine("something_new"), "Runtime refused this card. Nothing changed.");
  assert.equal(refusalLine("local_node_missing"), "This Home's node could not be found. Nothing changed.");
  assert.equal(refusalLine("local_node_unreadable"), "This Home's node could not be read. Nothing changed.");
  assert.equal(refusalLine("local_node_no_keys"), "This Home's node has no keys, so it cannot join a pool. Include this Home again to set it up.");
});

test("checkLine builds the Location failure from the names the Runtime sent", () => {
  assert.equal(
    checkLine({ id: "location", result: "fail", names: ["Hetzner box", "home-paris"], detail: "fsn1" }, THRESHOLD),
    "Hetzner box and home-paris both run in fsn1. Pools need different places.",
  );
});

test("checkLine words every failed rule from states.md", () => {
  const fail = (id, names, detail = null) => checkLine({ id, result: "fail", names, detail }, THRESHOLD);
  assert.equal(fail("members", ["Alice"]), "Add 2 more. A pool needs exactly 3.");
  assert.equal(
    fail("keys", ["Alice", "Bob"]),
    "Alice and Bob use the same node keys. One card was copied from the other. Ask for fresh cards.",
  );
  assert.equal(fail("homes", ["Alice", "Bob"]), "Alice and Bob are the same Home. A Home holds one share in a pool.");
  assert.equal(
    fail("run_by", ["home-antananarivo", "hetzner-fsn1"], "Iz."),
    "home-antananarivo and hetzner-fsn1 are both run by Iz. Swap one of them.",
  );
  assert.equal(fail("this_home", ["Iz.", "Iz."]), "Only one slot can be this Home.");
  assert.equal(
    fail("roles", ["Ter"], "chain"),
    "Ter does not provide chain. Ask Ter to set up the node with custody and chain.",
  );
  assert.equal(
    fail("keys", ["Alice", "Bob", "Carol"]),
    "Alice, Bob and Carol use the same node keys. One card was copied from the other. Ask for fresh cards.",
  );
});

test("checkLine words passed rules and storage advice from the threshold", () => {
  const pass = (id, names = []) => checkLine({ id, result: "pass", names, detail: null }, THRESHOLD);
  assert.equal(pass("members", ["A", "B", "C"]), "3 members");
  assert.equal(pass("keys"), "Every node has its own keys");
  assert.equal(pass("homes"), "3 different Homes");
  assert.equal(pass("run_by"), "3 different people run them");
  assert.equal(pass("location"), "3 different places");
  assert.equal(pass("this_home"), "At most one slot is this Home");
  assert.equal(pass("roles"), "Every node provides custody and chain");
  assert.equal(pass("copies", ["McKaya", "Ter"]), "Your Home serves the protected copy. Nodes keep key shares only.");
  assert.equal(
    checkLine({ id: "copies", result: "advice", names: ["McKaya"], detail: null }, THRESHOLD),
    "Your Home serves the protected copy. Nodes keep key shares only.",
  );
});

test("checkTitle drops the count while slots are still empty", () => {
  assert.equal(checkTitle("homes", THRESHOLD, 2), "Different Homes");
  assert.equal(checkTitle("homes", THRESHOLD, 3), "3 different Homes");
  assert.equal(checkTitle("members", THRESHOLD, 2), "3 members");
});

test("slotCount reads the total from the threshold, never a constant", () => {
  assert.equal(slotCount({ required: 3, total: 5 }), 5);
  assert.equal(slotCount(THRESHOLD), 3);
  assert.equal(slotCount(null), 0);
  assert.equal(slotCount({ required: 2, total: "3" }), 0);
});

test("termEnd adds whole days to the start", () => {
  const start = Date.UTC(2026, 9, 23);
  assert.equal(termEnd(start, 365), Date.UTC(2027, 9, 23));
  assert.equal(termEnd(start, 182), start + 182 * 86_400_000);
  // formatDate shows the local date: local noon is that day in every zone.
  assert.equal(formatDate(new Date(2027, 9, 23, 12).getTime()), "23 Oct 2027");
  assert.equal(formatDate(new Date(2027, 8, 3, 12).getTime()), "3 Sep 2027");
});

test("termLabel names the three presets", () => {
  assert.equal(termLabel(182), "6 months");
  assert.equal(termLabel(365), "1 year");
  assert.equal(termLabel(730), "2 years");
  assert.equal(termLabel(90), "90 days");
});

test("the terms come from Runtime; the default is a year", () => {
  assert.deepEqual(termPresets([182, 365, 730]), [182, 365, 730]);
  assert.deepEqual(termPresets([182, "365", 0, -1, 1.5, null]), [182]);
  assert.deepEqual(termPresets(undefined), []);
  assert.equal(termChoice([182, 365, 730], 730), 730);
  assert.equal(termChoice([182, 365], 730), 365);
  assert.equal(termChoice([182, 730], 90), 182);
  assert.equal(termChoice([], 365), 365);

  const state = hostileState({ step: "review" });
  state.summary.term_presets_days = [182, 730];
  state.termDays = 182;
  const html = createView(state).poolsMarkup();
  const terms = [...html.matchAll(/data-action="term" data-days="(\d+)"/g)].map(([, days]) => Number(days));
  assert.deepEqual(terms, [182, 730]);
  assert.match(html, />6 months</);
  assert.match(html, />2 years</);
  assert.doesNotMatch(html, />1 year</);
});

test("Review lists the members full width, then the checks beside term and sign", () => {
  const card = (runBy, location) => ({
    run_by: runBy,
    location,
    home_id: "did:key:z6Mkky1234567890L78x6KxT",
    provides: ["chain", "custody"],
    fingerprint: "1A2B 3C4D 4F2A 91C0",
  });
  const state = hostileState({
    step: "review",
    slots: [
      { kind: "home", runBy: "Iz.", location: "home-antananarivo", restart: false },
      { kind: "card", text: "elastos-node-card:v1:aa", card: card("McKaya", "home-lisbon") },
      { kind: "card", text: "elastos-node-card:v1:bb", card: card("Ter", "home-paris") },
    ],
  });
  state.checks.results = state.checks.results.map((result) => ({ ...result, result: "pass", names: [] }));
  const html = createView(state).poolsMarkup();
  const members = html.indexOf("cp-review-members");
  const checks = html.indexOf('class="cp-checks"');
  const sign = html.indexOf('data-action="sign"');
  assert.ok(members >= 0 && members < checks && checks < sign, "members, then checks, then sign");
  assert.equal((html.match(/class="cp-row" role="listitem"/g) || []).length, 3);
  assert.doesNotMatch(html, /cp-quorum-slots|data-action="remove"/);
  // Before install, slots are nodes: the epoch numbers shares by node key.
  assert.match(html, /<h4 class="cp-row-title">This Home<\/h4>.*>Node 1<.*>Run by Iz\.<.*>home-antananarivo<.*>This Home</s);
  assert.match(html, /<h4 class="cp-row-title">McKaya<\/h4>.*>Node 2<.*>home-lisbon<.*>Custody and chain<.*>Card read</s);
  assert.doesNotMatch(html, />Share \d</);
  assert.match(html, /<code>did:key:z6Mk…8x6KxT<\/code>/);
  assert.match(html, /Confirm with McKaya that their card ends in <code>4F2A 91C0<\/code>\./);
  assert.match(html, /data-action="sign">Sign and install pool</);
});

test("validLabel accepts 1 to 64 UTF-8 bytes without surrounding whitespace", () => {
  assert.equal(validLabel("Iz."), true);
  assert.equal(validLabel("x".repeat(64)), true);
  assert.equal(validLabel(""), false);
  assert.equal(validLabel(" Iz."), false);
  assert.equal(validLabel("Iz.\n"), false);
  assert.equal(validLabel("x".repeat(65)), false);
  // 22 three-byte characters are 66 bytes.
  assert.equal(validLabel("€".repeat(22)), false);
  assert.equal(validLabel("€".repeat(21)), true);
  assert.equal(validLabel(42), false);
});

test("rolesText names roles in the design's order", () => {
  assert.equal(rolesText(["chain", "custody"]), "Custody and chain");
  assert.equal(rolesText(["chain", "custody", "ipfs"]), "Custody, chain and storage");
  assert.equal(rolesText(["chain"]), "Chain");
});

test("fingerprintTail quotes the last two groups", () => {
  assert.equal(fingerprintTail("1A2B 3C4D … 4F2A 91C0"), "4F2A 91C0");
  assert.equal(fingerprintTail(""), "");
});

test("middleTruncate keeps the first 12 and last 8 characters", () => {
  assert.equal(middleTruncate("did:key:z6Mkky1234567890L78x6KxT"), "did:key:z6Mk…L78x6KxT");
  assert.equal(middleTruncate("0x4be1"), "0x4be1");
  assert.equal(middleTruncate("did:key:z6Mkky1234567890L78x6KxT", 12, 6), "did:key:z6Mk…8x6KxT");
});

test("installSlots keeps the share order and sends this Home as a flag", () => {
  const slots = [
    { kind: "home" },
    { kind: "card", text: "elastos-node-card:v1:aa" },
    { kind: "card", text: "elastos-node-card:v1:bb" },
  ];
  assert.deepEqual(installSlots(slots), [
    { this_home: true },
    { card: "elastos-node-card:v1:aa" },
    { card: "elastos-node-card:v1:bb" },
  ]);
  assert.equal(installSlots([{ kind: "home" }, { kind: "empty" }]), null);
});

test("errorView branches on the code and shows the detail as the reason", () => {
  assert.deepEqual(errorView({ code: "already_installed", detail: null }), {
    line: "This Home already has a pool. Nothing changed.",
    reason: "",
  });
  assert.deepEqual(errorView({ code: "verify_failed", detail: "term ended" }), {
    line: "The installed pool did not pass the Runtime check: term ended.",
    reason: "",
  });
  assert.deepEqual(errorView({ code: "install_failed", detail: "route unreachable" }), {
    line: "The pool did not pass the Runtime check and was not installed. Nothing changed.",
    reason: "Reason: route unreachable",
  });
  assert.deepEqual(errorView({ code: "bad_labels", detail: null }).line,
    "Run by or Location is empty, has extra spaces, or is longer than 64 characters.");
  // Auth and step-up refusals arrive as plain text and are shown as sent.
  assert.deepEqual(errorView({ text: "admin passkey required" }), { line: "admin passkey required", reason: "" });
  assert.deepEqual(errorView({}), { line: "Custody is temporarily unavailable. Runtime will retry.", reason: "" });
});

test("errorView gives every permanent refusal its own line, never the retry line", () => {
  const unavailable = "Custody is temporarily unavailable. Runtime will retry.";
  const codes = [
    "provision_failed", "local_node_unreadable", "register_failed", "no_card", "no_pool",
    "unknown_share", "local_node_missing", "bad_request", "bad_slot", "bad_term", "pool_installed",
    "already_serving", "no_local_node", "something_new",
  ];
  const lines = new Set();
  for (const code of codes) {
    const view = errorView({ code, detail: "provider binary missing" });
    assert.notEqual(view.line, unavailable, code);
    assert.match(view.line, /\. Nothing changed\.$/, code);
    assert.equal(view.reason, "Reason: provider binary missing", code);
    assert.equal(errorView({ code, detail: null }).reason, "", code);
    lines.add(view.line);
  }
  // Each known code says what failed; only the unknown one shares a line.
  assert.equal(lines.size, codes.length);
  // A removal that stopped part way changed something: it asks to try again.
  assert.deepEqual(errorView({ code: "remove_failed", detail: "busy" }), {
    line: "This Home's node could not be fully removed. Try again.",
    reason: "Reason: busy",
  });
  assert.notEqual(refusalLine("local_node_missing"), unavailable);
  assert.notEqual(refusalLine("something_new"), unavailable);
});

test("errorView keeps the retry line for transient failures only", () => {
  const unavailable = "Custody is temporarily unavailable. Runtime will retry.";
  assert.equal(errorView({ unavailable: true }).line, unavailable);
  assert.equal(errorView({ code: "", text: "" }).line, unavailable);
});

test("slotEntry reads card text as a card and any other text as a node address", () => {
  assert.deepEqual(slotEntry(" elastos-node-card:v1:ab\ncd "), { card: "elastos-node-card:v1:abcd" });
  assert.deepEqual(slotEntry("\n  vqaaa2xbbbb\n"), { address: "vqaaa2xbbbb" });
  // Chat and email wrap a long address too; an address holds no whitespace.
  assert.deepEqual(slotEntry("vqaaa\n2xbbbb"), { address: "vqaaa2xbbbb" });
  // Only the exact card prefix makes a card.
  assert.deepEqual(slotEntry("Elastos-node-card:v1:ab"), { address: "Elastos-node-card:v1:ab" });
  assert.deepEqual(slotEntry("elastos-node-card"), { address: "elastos-node-card" });
  assert.equal(slotEntry("  \n "), null);
  assert.equal(slotEntry(undefined), null);
});

test("fetchRefusal gives each fetch refusal its own line and the node's reason", () => {
  const unavailable = "Custody is temporarily unavailable. Runtime will retry.";
  const lines = {
    bad_address: "This is not a node address. Ask the node operator for the address their node host printed.",
    unreachable: "This Home could not reach the node. Check that the node is running, then try again.",
    not_owner: "The node did not give its card to this Home.",
    no_card: "The node has no node card yet. Ask the operator to set it up for custody, or to send its node card.",
  };
  for (const [code, line] of Object.entries(lines)) {
    assert.deepEqual(fetchRefusal({ code, detail: "replayed request" }), {
      line,
      reason: "Reason: replayed request",
      retry: code !== "bad_address",
    }, code);
    assert.equal(fetchRefusal({ code, detail: null }).reason, "", code);
    assert.notEqual(line, unavailable, code);
  }
  // The node refuses for more than ownership (clock skew, replay), so the
  // line must not name a cause.
  assert.doesNotMatch(fetchRefusal({ code: "not_owner" }).line, /own|trust|issuer|pool/i);
  // A fetched card is refused for the same reasons as a pasted one.
  assert.deepEqual(fetchRefusal({ code: "own_card", detail: null }), {
    line: "This is this Home's own card. Use Include this Home.",
    reason: "",
    retry: false,
  });
  assert.equal(fetchRefusal({ code: "ticket_mismatch" }).line, refusalLine("ticket_mismatch"));
  // Anything else is not a slot refusal: the caller shows errorView.
  assert.equal(fetchRefusal({ unavailable: true }), null);
  assert.equal(fetchRefusal({ text: "admin passkey required" }), null);
  assert.equal(fetchRefusal({ code: "bad_request" }), null);
  // The register route's no_card keeps its own line.
  assert.equal(errorView({ code: "no_card" }).line, "This Home has no node card for that member. Nothing changed.");
});

test("an empty slot asks for the node's address, and a fetch reads as fetching", () => {
  const state = hostileState({ slots: [{ kind: "empty", text: "", error: "", note: "" }] });
  state.summary.threshold = { required: 1, total: 1 };
  const empty = createView(state).poolsMarkup();
  assert.match(empty, /Paste the node&#039;s address, or its node card\./);
  assert.match(empty, /placeholder="Node address"/);
  assert.match(empty, />Choose file</);

  state.slots = [{ kind: "reading", text: "vqaaa", address: "vqaaa", token: 1 }];
  assert.match(createView(state).poolsMarkup(), /Fetching the node card from the node…/);
  state.slots = [{ kind: "reading", text: "elastos-node-card:v1:aa", token: 1 }];
  assert.match(createView(state).poolsMarkup(), /Reading the node card…/);
});

test("a fetch refusal shows its reason and offers the fetch again", () => {
  const state = hostileState({ slots: [{ kind: "refused", line: "L", reason: "Reason: R", retry: true, address: "vqaaa" }] });
  state.summary.threshold = { required: 1, total: 1 };
  const html = createView(state).poolsMarkup();
  assert.match(html, /Reason: R/);
  assert.match(html, /data-action="retry-fetch"/);
  assert.match(html, /data-action="retry-card"/);
  // A bad address, or a pasted card, has nothing to fetch again.
  state.slots = [{ kind: "refused", line: "L", reason: "", retry: false, address: "vqaaa" }];
  assert.doesNotMatch(createView(state).poolsMarkup(), /retry-fetch/);
  state.slots = [{ kind: "refused", line: "L" }];
  assert.doesNotMatch(createView(state).poolsMarkup(), /retry-fetch|Reason/);
});

test("a failed fetch or read keeps the text, and only a request that never arrived offers Try again", () => {
  const unavailable = "Custody is temporarily unavailable. Runtime will retry.";
  const badAddress = failedSlot({ code: "bad_address", detail: null }, "vqaa", "vqaa");
  assert.deepEqual(badAddress, {
    kind: "empty",
    text: "vqaa",
    error: "This is not a node address. Ask the node operator for the address their node host printed.",
    note: "",
    retry: false,
  });
  // The node's own refusals stay refused, with their Try again.
  assert.deepEqual(failedSlot({ code: "unreachable", detail: "timed out" }, "vqaa", "vqaa"), {
    kind: "refused",
    line: "This Home could not reach the node. Check that the node is running, then try again.",
    reason: "Reason: timed out",
    retry: true,
    address: "vqaa",
  });
  for (const [text, address] of [["vqaa", "vqaa"], ["elastos-node-card:v1:aa", ""]]) {
    const slot = failedSlot({ unavailable: true }, text, address);
    assert.equal(slot.kind, "empty");
    assert.equal(slot.text, text);
    assert.equal(slot.retry, true);
    assert.equal(slot.error, "Custody is temporarily unavailable. Try again.");
    assert.notEqual(slot.error, unavailable);
  }
  const auth = failedSlot({ text: "admin passkey required" }, "vqaa", "vqaa");
  assert.equal(auth.error, "admin passkey required");
  assert.equal(auth.retry, false);

  const state = hostileState({ slots: [{ kind: "empty", text: "vqaa", error: "E", note: "", retry: true }] });
  state.summary.threshold = { required: 1, total: 1 };
  const html = createView(state).poolsMarkup();
  assert.match(html, /data-action="retry-read"/);
  assert.match(html, />vqaa<\/textarea>/);
  state.slots = [badAddress];
  assert.doesNotMatch(createView(state).poolsMarkup(), /retry-read/);
});

test("this Home's node that is not serving shows Restart needed, after a reload too", () => {
  const restartLine = "This Home's node is set up but not started. Restart this Home to start it.";
  const now = Date.now() / 1000;
  const state = hostileState({ step: "nodes", checks: null });
  state.summary.local_node = { provisioned: true, run_by: "Iz.", location: "Paris", running: false };
  assert.equal(createView(state).homeNeedsRestart(), true);
  // The slot was filled from the summary, with no include response.
  const nodes = createView(state).poolsMarkup();
  assert.match(nodes, /data-state="restart"/);
  assert.match(nodes, />Restart needed</);
  assert.doesNotMatch(nodes, /Restart now/);

  state.step = "active";
  state.summary.pool_installed = true;
  state.summary.pool = {
    members: [{ share: 1, run_by: "Iz.", this_home: true, registered: true, provides: [] }],
    term: { start: now - 86_400, end: now + 400 * 86_400, days: 365 },
    threshold: THRESHOLD,
    fingerprint: "AB",
    cards_kept: true,
  };
  assert.ok(createView(state).poolsMarkup().includes(escapeText(restartLine)));

  state.summary.local_node.running = true;
  assert.equal(createView(state).homeNeedsRestart(), false);
  assert.ok(!createView(state).poolsMarkup().includes(escapeText(restartLine)));
  state.step = "nodes";
  assert.doesNotMatch(createView(state).poolsMarkup(), /Restart needed/);
});

test("Register again shows only when the pool kept its members' cards", () => {
  const terminalLine = "This pool was formed from the terminal. Register its nodes with elastos node peer add.";
  const now = Date.now() / 1000;
  const state = hostileState({ step: "active" });
  state.summary.pool_installed = true;
  state.summary.pool = {
    members: [
      { share: 1, run_by: "Iz.", registered: true, provides: [] },
      { share: 2, run_by: "Ter", registered: false, provides: [] },
    ],
    term: { start: now - 86_400, end: now + 400 * 86_400, days: 365 },
    threshold: THRESHOLD,
    fingerprint: "AB",
    cards_kept: false,
  };
  let html = createView(state).poolsMarkup();
  assert.doesNotMatch(html, /data-action="register"/);
  assert.ok(html.includes(terminalLine));

  state.summary.pool.cards_kept = true;
  html = createView(state).poolsMarkup();
  assert.match(html, /data-action="register" data-share="2"/);
  assert.ok(!html.includes(terminalLine));
});

function escapeText(text) {
  return text.replaceAll("'", "&#039;");
}

/* ---------- Hosting: this Home as a node in another Home's pool ---------- */

const OWNER_DID = "did:key:z6MkownerAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAowner1";
const NODE_ADDRESS = "vqaaaanodeaddressbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbcccc";
// The whole digest the short "ABCD 1234 … 5678 9ABC" summarises.
const NODE_FINGERPRINT_FULL = `sha256:abcd1234${"0".repeat(48)}56789abc`;

function servingSummary(overrides = {}) {
  return {
    owner_did: OWNER_DID,
    owner_name: null,
    run_by: "Bob",
    location: "Porto",
    provides: ["chain", "custody", "ipfs"],
    fingerprint: "ABCD 1234 … 5678 9ABC",
    fingerprint_full: NODE_FINGERPRINT_FULL,
    provider_running: true,
    needs_restart: false,
    last_owner_contact: null,
    ...overrides,
  };
}

// Plan B T2.3: `summary.serving` is a list, one entry per served pool.
function hostingState(serving, address = null) {
  const state = hostileState({ section: "hosting" });
  state.summary.serving = serving === null ? [] : [serving];
  state.summary.local_node = { ...state.summary.local_node, address };
  return state;
}

test("readServing keeps what the Serving card shows and drops what it cannot trust", () => {
  for (const value of [null, undefined, [], "serving"]) {
    assert.equal(readServing(value), null, String(value));
  }
  assert.deepEqual(readServing(servingSummary({ last_owner_contact: 1_793_040_166 })), {
    ownerName: "",
    ownerDid: OWNER_DID,
    runBy: "Bob",
    location: "Porto",
    provides: ["chain", "custody", "ipfs"],
    fingerprint: "ABCD 1234 … 5678 9ABC",
    fingerprintFull: NODE_FINGERPRINT_FULL,
    running: true,
    needsRestart: false,
    lastContact: 1_793_040_166_000,
    pool: null,
    // Plan B T2.3: no pool key in this summary, so no Stop serving.
    poolFingerprint: "",
  });
  assert.equal(readServing(servingSummary({ pool_fingerprint: "d".repeat(64) })).poolFingerprint, "d".repeat(64));
  assert.equal(readServing(servingSummary({ pool_fingerprint: "sha256:abc" })).poolFingerprint, "");
  // Only a true needs_restart asks for a restart.
  assert.equal(readServing(servingSummary({ needs_restart: true })).needsRestart, true);
  for (const restart of [false, "true", 1, null, undefined]) {
    assert.equal(readServing(servingSummary({ needs_restart: restart })).needsRestart, false, String(restart));
  }
  // Only a true provider_running reads as running.
  for (const running of [false, "true", 1, null, undefined]) {
    assert.equal(readServing(servingSummary({ provider_running: running })).running, false, String(running));
  }
  // A contact time is whole positive seconds; anything else reads as never.
  for (const contact of [null, undefined, 0, -5, 1.5, "1793040166", Number.NaN]) {
    assert.equal(readServing(servingSummary({ last_owner_contact: contact })).lastContact, 0, String(contact));
  }
  assert.equal(readServing(servingSummary({ owner_name: " Iz. " })).ownerName, "Iz.");
  assert.deepEqual(readServing({}).provides, []);
});

test("servingStatus says whether the node runs, and the next step when it does not", () => {
  assert.deepEqual(servingStatus({ running: true, needsRestart: false }), { tone: "ok", word: "Node running" });
  assert.deepEqual(servingStatus({ running: false, needsRestart: true }), { tone: "pending", word: "Node not running. Restart this Home." });
  assert.deepEqual(servingStatus({ running: false, needsRestart: false }), { tone: "pending", word: "Node not running. Restart this Home." });
  // Running, but its Chain plane still trusts a stale issuer.
  assert.deepEqual(servingStatus({ running: true, needsRestart: true }), { tone: "pending", word: "Restart this Home to finish serving." });
});

test("the Serving card asks for a restart while the running node still needs one", () => {
  const html = createView(hostingState(servingSummary({ needs_restart: true }))).hostingMarkup();
  assert.match(html, /data-tone="pending">Restart this Home to finish serving\.</);
  assert.doesNotMatch(html, />Node running</);
});

test("ownerContactLine says when the owner last checked this node", () => {
  assert.equal(ownerContactLine(0), "The owner has not checked this node yet.");
  assert.match(ownerContactLine(Date.now()), /^Last checked by the owner: today, \d\d:\d\d\.$/);
  const pastSeconds = 1_700_000_000;
  assert.equal(ownerContactLine(pastSeconds * 1000), `Last checked by the owner: ${formatDate(pastSeconds * 1000)}.`);
});

test("mergeLocalNode takes the included node's fields and keeps the served node's address", () => {
  const summary = {
    provisioned: false, run_by: null, location: null, fingerprint: null, running: false, address: NODE_ADDRESS,
  };
  // The include route has no Carrier handle: its address is always null.
  const included = {
    provisioned: true, run_by: "Iz.", location: "Paris", fingerprint: "AB CD", running: false,
    address: null, needs_restart: true,
  };
  assert.deepEqual(mergeLocalNode(summary, included), {
    provisioned: true, run_by: "Iz.", location: "Paris", fingerprint: "AB CD", running: false, address: NODE_ADDRESS,
  });
  // A partial answer changes only what it carries.
  assert.deepEqual(mergeLocalNode(summary, { run_by: "Iz." }), { ...summary, run_by: "Iz." });
  assert.deepEqual(mergeLocalNode(undefined, included), {
    provisioned: true, run_by: "Iz.", location: "Paris", fingerprint: "AB CD", running: false,
  });
});

test("includeDraft prefills Run by with this Home's Profile name when the summary has one", () => {
  const empty = { kind: "include", runBy: "", location: "", invalid: false, error: "", busy: false };
  assert.deepEqual(includeDraft({}), empty);
  assert.deepEqual(includeDraft(null), empty);
  assert.deepEqual(includeDraft({ local_profile_name: 42 }), empty);
  assert.deepEqual(includeDraft({ local_profile_name: " Iz. " }), { ...empty, runBy: "Iz." });
});

test("Hosting shows the Serving card with this Home's node address", () => {
  const now = Math.floor(Date.now() / 1000);
  const html = createView(hostingState(servingSummary({ last_owner_contact: now }), NODE_ADDRESS)).hostingMarkup();
  // No People name: the owner's short DID, in a key field.
  assert.match(html, /This Home holds a key share for <span class="cp-key" title="did:key:z6Mkowner/);
  assert.ok(html.includes(`<code>${middleTruncate(OWNER_DID)}</code>`));
  assert.match(html, /<div class="cp-row-meta">.*>Run by Bob<.*>Porto<.*>Custody, chain and storage<.*data-tone="ok">Node running</s);
  // The short form shows; the whole digest is in the title and is what Copy sends.
  assert.ok(html.includes(`<dt>Fingerprint</dt><dd><span class="cp-key" title="${NODE_FINGERPRINT_FULL}" data-value="${NODE_FINGERPRINT_FULL}"><code>ABCD 1234 … 5678 9ABC</code>`));
  assert.match(html, /Last checked by the owner: today, \d\d:\d\d\./);
  assert.match(html, /The pool owner decides the pool and its term\. This Home sees its own share only\./);
  assert.ok(html.includes(`<dt>${escapeText("This Home's node address")}</dt>`));
  assert.ok(html.includes(`data-action="copy" data-value="${NODE_ADDRESS}"`));
  assert.match(html, /Send this to the pool owner\. Your node gives its card only to the Home it trusts\./);
  // The backend does not count releases yet.
  assert.doesNotMatch(html, /Releases served/);

  const named = createView(hostingState(servingSummary({ owner_name: "Iz.", provider_running: false }), NODE_ADDRESS)).hostingMarkup();
  assert.match(named, />This Home holds a key share for Iz\.<\/h2>/);
  assert.doesNotMatch(named, /title="did:key/);
  assert.match(named, /data-tone="pending">Node not running\. Restart this Home\.</);
  assert.match(named, /The owner has not checked this node yet\./);

  const unknown = createView(hostingState(servingSummary({ owner_did: null }))).hostingMarkup();
  assert.match(unknown, />This Home holds a key share for another Home<\/h2>/);
  assert.doesNotMatch(unknown, /node address/);
});

test("Hosting shows the node address alone, or nothing, without a served node", () => {
  const alone = createView(hostingState(null, NODE_ADDRESS)).hostingMarkup();
  assert.ok(alone.includes(`data-value="${NODE_ADDRESS}"`));
  assert.match(alone, /Send this to the pool owner\./);
  assert.doesNotMatch(alone, /holds a key share/);
  assert.equal(createView(hostingState(null)).hostingMarkup(), "");
  assert.equal(createView({ ...hostingState(null), summary: null }).hostingMarkup(), "");
});

test("the served pools sit below the Hosting note", () => {
  const html = readFileSync(new URL("./index.html", import.meta.url), "utf8");
  const node = html.indexOf('id="hosting-node"');
  assert.ok(node > html.indexOf(escapeText(HOSTING_POOLS_LINE)), "the served pools render below the note");
});

test("old_copy_is_gone", () => {
  const html = readFileSync(new URL("./index.html", import.meta.url), "utf8");
  assert.doesNotMatch(html, /In this version, nodes are set up outside the Custody app/);
  assert.doesNotMatch(html, /class="cp-howto"/);
  assert.doesNotMatch(html, /deploy\/custody-host/);
  assert.doesNotMatch(html, /Ask the pool owner for their Runtime issuer/);
  assert.ok(html.includes(escapeText(HOSTING_POOLS_LINE)));
  // The Include note stays.
  assert.match(html, /use <b>Include this Home<\/b> in Pools\./);
  // R3-D6 (user 2026-11-12 13:05): the unreachable node-Home note is gone.
  const view = readFileSync(new URL("./src/view.js", import.meta.url), "utf8");
  assert.doesNotMatch(view, /NODE_HOME_LINE|nodeHomeMarkup/);
  assert.doesNotMatch(view, /Forming your own pool on this Home comes in a later version/);
});

test("confirm_publisher_is_offered_only_when_missing", () => {
  const pool = "c".repeat(64);
  for (const [confirmed, offered] of [[false, true], [true, false]]) {
    const state = hostingState(null, NODE_ADDRESS);
    state.summary.serving = [servingSummary({ pool_fingerprint: pool })];
    state.servedPools = {
      items: readServedPools([
        { pool_fingerprint: pool, owner_name: "Ann", roles: ["custody"], status: "serving", term_end: 1_900_000_000, shares_held: 1, publisher_confirmed: confirmed },
      ]),
      failed: false,
    };
    const html = createView(state).hostingMarkup();
    assert.equal(
      new RegExp(`data-action="confirm-publisher" data-pool="${pool}"`).test(html),
      offered,
      String(confirmed),
    );
    assert.equal(html.includes(escapeText(PUBLISHER_NOTE)), offered, String(confirmed));
  }
  assert.equal(PUBLISHER_NOTE, "Sealed items for this pool are published under your profile.");
  assert.equal(SERVED_POOL_CONFIRM_PUBLISHER_OPERATION, "custody.served_pool.confirm_publisher");
});

test("own_pool_confirm_publisher_line_shows_only_when_unconfirmed", () => {
  const own = "d".repeat(64);
  const state = hostingState(null, NODE_ADDRESS);
  state.summary.own_pool = { pool_fingerprint: own, publisher_confirmed: false };
  const html = createView(state).hostingMarkup();
  assert.match(html, new RegExp(`data-action="confirm-publisher" data-pool="${own}"`));
  assert.ok(html.includes(escapeText(PUBLISHER_NOTE)));
  state.summary.own_pool = { pool_fingerprint: own, publisher_confirmed: true };
  assert.doesNotMatch(createView(state).hostingMarkup(), /data-action="confirm-publisher"/);
  // A malformed own pool shows nothing.
  state.summary.own_pool = { pool_fingerprint: "nothex", publisher_confirmed: false };
  assert.doesNotMatch(createView(state).hostingMarkup(), /data-action="confirm-publisher"/);
});

test("hosting_lists_one_card_per_pool", () => {
  const first = "a".repeat(64);
  const second = "b".repeat(64);
  const state = hostingState(null, NODE_ADDRESS);
  state.summary.serving = [
    servingSummary({ owner_name: "Iz.", pool_fingerprint: first }),
    servingSummary({ owner_name: "Ann", pool_fingerprint: second }),
    // Not a served node: no card.
    "serving",
  ];
  state.servedPools = {
    items: readServedPools([
      { pool_fingerprint: first, owner_name: "Iz.", roles: ["custody"], status: "consent_ending", term_end: 1_800_000_000, shares_held: 3 },
      { pool_fingerprint: second, owner_name: "Ann", roles: ["custody"], status: "waiting_for_pool", term_end: null, shares_held: 0 },
      { pool_fingerprint: "not-hex", status: "serving" },
      { pool_fingerprint: "c".repeat(64), status: "unknown" },
    ]),
    failed: false,
  };
  assert.equal(state.servedPools.items.length, 2);
  const html = createView(state).hostingMarkup();
  assert.equal(html.match(/data-action="stop-serving"/g).length, 2);
  assert.ok(html.includes(`data-pool="${first}"`));
  assert.ok(html.includes(`data-pool="${second}"`));
  assert.match(html, />This Home holds a key share for Iz\.<\/h2>/);
  assert.match(html, />This Home holds a key share for Ann<\/h2>/);
  assert.match(html, /data-tone="pending">Consent ends in under 7 days</);
  assert.match(html, /data-tone="pending">Waiting for the owner&#039;s pool</);
  assert.match(html, /Holds 3 shares\./);
  assert.match(html, /Holds 0 shares\./);
  // Before the list is read, a card shows the node's own status.
  const unread = { ...state, servedPools: { items: [], failed: true } };
  assert.match(createView(unread).hostingMarkup(), /data-tone="ok">Node running</);
  // A pool from before this version without consent is flagged.
  state.summary.serving_needs_attention = true;
  assert.match(createView(state).hostingMarkup(), /needs attention: its consent is missing/);
  assert.equal(stopServingRequest(first).pool, first);
  assert.deepEqual(servedPoolStatusChip("serving"), { tone: "ok", word: "Serving" });
  assert.equal(servedPoolStatusChip("other"), null);
  assert.equal(sharesHeldLine(1), "Holds 1 share.");
});

test("Pools on a Home that serves other pools still forms its own pool", () => {
  // Plan B T2.2 (removal approved 2026-11-12 10:35): a Home may own a pool
  // and serve others.
  const line = escapeText("This Home serves another Home's pool. Forming your own pool on this Home comes in a later version.");
  for (const step of ["prepare", "nodes", "review"]) {
    const state = hostileState({ step });
    state.summary.serving = [servingSummary()];
    const html = createView(state).poolsMarkup();
    assert.ok(!html.includes(line), step);
  }
  // Pools and Hosting read serving the same way: a value that is not a
  // served node shows neither the note nor the card.
  for (const serving of [[], "serving", 1]) {
    const state = hostileState({ step: "prepare" });
    state.summary.serving = serving;
    const view = createView(state);
    assert.ok(!view.poolsMarkup().includes(line), JSON.stringify(serving));
    assert.doesNotMatch(view.hostingMarkup(), /holds a key share/, JSON.stringify(serving));
  }
  // A pool this Home installed still shows as Active.
  const active = activeState();
  active.summary.serving = servingSummary();
  const html = createView(active).poolsMarkup();
  assert.ok(!html.includes(line));
  assert.match(html, /<h3 class="cp-group-label">Members<\/h3>/);
});

test("the Include this Home form explains each field and keeps Run by editable", () => {
  const state = hostileState({ slots: [includeDraft({ local_profile_name: "Iz." }), { kind: "empty", text: "", error: "", note: "" }] });
  state.summary.threshold = { required: 1, total: 2 };
  const html = createView(state).poolsMarkup();
  assert.match(html, /<input class="cp-input" id="run-by-0" [^>]*value="Iz\."[^>]*>/);
  assert.doesNotMatch(html, /id="run-by-0" [^>]*(readonly|disabled)/);
  assert.match(html, /aria-describedby="run-by-help-0"/);
  assert.match(html, /aria-describedby="location-help-0"/);
  assert.match(html, /<p class="cp-help" id="run-by-help-0">Who runs this machine\. Each node should be run by someone different\.<\/p>/);
  assert.match(html, /<p class="cp-help" id="location-help-0">Where this machine runs\. Each node should be in a different place\.<\/p>/);
});

/* ---------- Hosting: offering custody to contacts ---------- */

const PRIVACY_LINE = "Your contacts can see that this Home offers custody, with its Run by, Location and roles.";
const HOLDS_LINE = "This Home already holds a custody state, so it cannot offer custody.";
const MESSAGES_OFF_LINE = "Custody messages are off. Contacts cannot send this Home requests until you enable them.";

function offerView(overrides = {}) {
  return {
    enabled: false,
    run_by: "Bob",
    location: "Porto",
    provides: ["chain", "custody", "ipfs"],
    holds_custody_state: false,
    messages_enabled: true,
    ...overrides,
  };
}

function offerState(view, overrides = {}) {
  const state = hostingState(null);
  const offer = readOffer(view);
  state.offer = {
    view: offer,
    failed: null,
    runBy: offer?.runBy ?? "",
    location: offer?.location ?? "",
    edited: false,
    invalid: false,
    notice: null,
    busy: false,
    ...overrides,
  };
  return state;
}

function switchOf(html) {
  return html.match(/<button class="cp-switch"[^>]*>/)?.[0] || "";
}

test("readOffer keeps the offer view and reads only true as on", () => {
  for (const value of [null, undefined, [], "offer"]) {
    assert.equal(readOffer(value), null, String(value));
  }
  assert.deepEqual(readOffer(offerView()), {
    enabled: false,
    runBy: "Bob",
    location: "Porto",
    provides: ["chain", "custody", "ipfs"],
    holdsCustody: false,
    messagesEnabled: true,
  });
  for (const flag of ["true", 1, null, undefined]) {
    const offer = readOffer(offerView({ enabled: flag, holds_custody_state: flag, messages_enabled: flag }));
    assert.equal(offer.enabled, false, String(flag));
    assert.equal(offer.holdsCustody, false, String(flag));
    assert.equal(offer.messagesEnabled, false, String(flag));
  }
  // The stored labels go back to Runtime as they are.
  assert.equal(readOffer(offerView({ run_by: " Bob " })).runBy, " Bob ");
  assert.equal(readOffer(offerView({ run_by: 42 })).runBy, "");
});

test("Hosting offers custody with a switch, Run by, Location and roles", () => {
  const html = createView(offerState(offerView())).hostingMarkup();
  assert.match(switchOf(html), /role="switch"/);
  assert.match(switchOf(html), /aria-checked="false"/);
  assert.doesNotMatch(switchOf(html), /disabled/);
  assert.match(html, />Offer custody to my contacts</);
  assert.ok(html.includes(PRIVACY_LINE));
  assert.match(html, /<input class="cp-input" id="offer-run-by" [^>]*value="Bob"[^>]*>/);
  assert.match(html, /<input class="cp-input" id="offer-location" [^>]*value="Porto"[^>]*>/);
  assert.doesNotMatch(html, /id="offer-run-by" [^>]*disabled/);
  // The Run by help is the Include this Home explanation.
  assert.match(html, /aria-describedby="offer-run-by-help"/);
  assert.match(html, /<p class="cp-help" id="offer-run-by-help">Who runs this machine\. Each node should be run by someone different\.<\/p>/);
  assert.match(html, />Custody, chain and storage</);
  assert.doesNotMatch(html, /data-action="offer-messages"/);

  // On: the switch shows it, and the labels are what contacts see.
  const on = createView(offerState(offerView({ enabled: true }))).hostingMarkup();
  assert.match(switchOf(on), /aria-checked="true"/);
  assert.doesNotMatch(switchOf(on), /disabled/);
  assert.match(on, /id="offer-run-by" [^>]*disabled/);
  assert.ok(on.includes(PRIVACY_LINE));
});

test("a Home that holds a custody state can only turn the offer off", () => {
  const off = createView(offerState(offerView({ holds_custody_state: true }))).hostingMarkup();
  assert.match(switchOf(off), /disabled/);
  assert.ok(off.includes(HOLDS_LINE));
  const on = createView(offerState(offerView({ holds_custody_state: true, enabled: true }))).hostingMarkup();
  assert.match(switchOf(on), /aria-checked="true"/);
  assert.doesNotMatch(switchOf(on), /disabled/);
  assert.ok(!on.includes(HOLDS_LINE));
  // A Home that cannot offer has no use for custody messages.
  const silent = createView(offerState(offerView({ holds_custody_state: true, messages_enabled: false }))).hostingMarkup();
  assert.ok(!silent.includes(MESSAGES_OFF_LINE));
  assert.doesNotMatch(silent, /data-action="offer-messages"/);
  // One already on can still be reached by contacts, so the warning stays.
  const reachable = createView(offerState(offerView({ holds_custody_state: true, enabled: true, messages_enabled: false }))).hostingMarkup();
  assert.ok(reachable.includes(MESSAGES_OFF_LINE));
});

test("the offer card warns while custody messages are off, on or off", () => {
  for (const enabled of [false, true]) {
    const html = createView(offerState(offerView({ enabled, messages_enabled: false }))).hostingMarkup();
    assert.ok(html.includes(MESSAGES_OFF_LINE), String(enabled));
    assert.match(html, /<button class="cp-btn cp-btn-sm" type="button" data-action="offer-messages"[^>]*>Enable custody messages<\/button>/);
  }
  const busy = createView(offerState(offerView({ messages_enabled: false }), { busy: true })).hostingMarkup();
  assert.match(busy, /data-action="offer-messages"[^>]* disabled/);
  assert.match(switchOf(busy), /disabled/);
});

test("the offer card shows a bad label, a refusal, or a failed read inline", () => {
  const invalid = createView(offerState(offerView(), { runBy: " Bob", invalid: true })).hostingMarkup();
  assert.match(invalid, /id="offer-run-by" [^>]*aria-invalid="true"/);
  // Only the field whose label is bad is marked.
  assert.doesNotMatch(invalid, /id="offer-location" [^>]*aria-invalid/);
  const badLocation = createView(offerState(offerView(), { location: "", invalid: true })).hostingMarkup();
  assert.match(badLocation, /id="offer-location" [^>]*aria-invalid="true"/);
  assert.doesNotMatch(badLocation, /id="offer-run-by" [^>]*aria-invalid/);
  assert.ok(invalid.includes("Run by or Location is empty, has extra spaces, or is longer than 64 characters."));

  const refused = createView(offerState(offerView(), { notice: errorView({ code: "already_holds_custody" }) })).hostingMarkup();
  assert.ok(refused.includes(HOLDS_LINE));

  // A failed read keeps the Serving card out of it: the card says so alone.
  const failed = offerState(null, { failed: { line: "This Home could not read its custody offer. Try again.", reason: "" } });
  const html = createView(failed).hostingMarkup();
  assert.match(html, /This Home could not read its custody offer\. Try again\./);
  assert.match(html, /data-action="offer-reload"/);
  assert.doesNotMatch(html, /cp-switch/);
  // A read that fails later keeps the last offer, with the failure and Try again.
  const stale = createView(offerState(offerView(), { failed: offerReadFailure({ detail: "disk" }) })).hostingMarkup();
  assert.match(stale, /cp-switch/);
  assert.match(stale, /This Home could not read its custody offer\. Try again\./);
  assert.match(stale, /Reason: disk/);
  assert.match(stale, /data-action="offer-reload"/);
});

test("the offer card shows on a Home that serves other pools too", () => {
  // Plan B T2.2 (removal approved 2026-11-12 10:35): the offer stays on
  // below eight pools.
  const serving = offerState(offerView());
  serving.summary.serving = [servingSummary()];
  const html = createView(serving).hostingMarkup();
  assert.match(html, /holds a key share/);
  assert.match(html, /Offer custody to my contacts/);
  assert.ok(html.indexOf("cp-switch") < html.indexOf("holds a key share"));
  // Without a summary the card waits.
  assert.equal(createView({ ...offerState(offerView()), summary: null }).hostingMarkup(), "");
  // With the node address, the offer sits above it.
  const both = offerState(offerView());
  both.summary.local_node.address = NODE_ADDRESS;
  const markup = createView(both).hostingMarkup();
  assert.ok(markup.indexOf("cp-switch") >= 0 && markup.indexOf("cp-switch") < markup.indexOf(NODE_ADDRESS));
});

test("turning the offer off sends the stored labels unchanged", async () => {
  const stored = readOffer(offerView({ enabled: true }));
  // Edits in the fields never go out with off: Runtime checks the labels even then.
  assert.deepEqual(offerBody(stored, { runBy: "", location: " edited " }, false), {
    enabled: false, run_by: "Bob", location: "Porto",
  });
  const posted = [];
  const result = await switchOffer(async (body) => {
    posted.push(body);
    return offerView({ enabled: false });
  }, stored, { runBy: "Someone else", location: "" }, false);
  assert.deepEqual(posted, [{ enabled: false, run_by: "Bob", location: "Porto" }]);
  assert.equal(result.offer.enabled, false);
});

test("turning the offer on checks the labels before anything is sent", async () => {
  const stored = readOffer(offerView());
  for (const draft of [
    { runBy: "", location: "Porto" },
    { runBy: " Bob", location: "Porto" },
    { runBy: "Bob", location: "x".repeat(65) },
  ]) {
    assert.equal(offerBody(stored, draft, true), null, JSON.stringify(draft));
    let posts = 0;
    const result = await switchOffer(async () => {
      posts += 1;
      return offerView();
    }, stored, draft, true);
    assert.equal(posts, 0, JSON.stringify(draft));
    assert.deepEqual(result, { invalid: true });
  }
  const posted = [];
  const result = await switchOffer(async (body) => {
    posted.push(body);
    return offerView({ enabled: true, run_by: "Ann", location: "Lisbon" });
  }, stored, { runBy: "Ann", location: "Lisbon" }, true);
  assert.deepEqual(posted, [{ enabled: true, run_by: "Ann", location: "Lisbon" }]);
  assert.equal(result.offer.runBy, "Ann");
});

test("a refused offer switch says why", async () => {
  const stored = readOffer(offerView());
  const refuse = (error) => async () => {
    throw Object.assign(new Error(error.code || "x"), error);
  };
  assert.deepEqual(await switchOffer(refuse({ code: "bad_labels" }), stored, { runBy: "Bob", location: "Porto" }, true), { invalid: true });
  assert.deepEqual(
    await switchOffer(refuse({ code: "already_holds_custody", detail: "" }), stored, { runBy: "Bob", location: "Porto" }, true),
    { notice: { line: HOLDS_LINE, reason: "" } },
  );
});

test("Enable custody messages asks for the passkey before it sends anything", async () => {
  assert.equal(MESSAGES_ENABLE_OPERATION, "custody.messages.enable");
  const calls = [];
  const outcome = await enableMessages(
    async (operation, request) => {
      calls.push(["step-up", operation, request]);
      return "token-1";
    },
    async (body) => {
      calls.push(["post", body]);
      return { messages_enabled: true };
    },
  );
  assert.deepEqual(calls, [
    ["step-up", "custody.messages.enable", {}],
    ["post", { step_up_token: "token-1" }],
  ]);
  assert.deepEqual(outcome, { ok: true });

  let posts = 0;
  const cancelled = await enableMessages(
    async () => {
      throw new Error("Passkey verification failed.");
    },
    async () => {
      posts += 1;
    },
  );
  assert.equal(posts, 0);
  assert.deepEqual(cancelled, { ok: false, line: "Passkey verification failed.", reason: "" });

  const refused = await enableMessages(async () => "token-2", async () => {
    throw Object.assign(new Error("no_profile"), { code: "no_profile", detail: "" });
  });
  assert.deepEqual(refused, { ok: false, ...errorView({ code: "no_profile" }) });
});

test("Remove of this Home's node asks for the passkey before it deletes anything", async () => {
  assert.equal(LOCAL_NODE_REMOVE_OPERATION, "custody.local_node.remove");
  const calls = [];
  const outcome = await removeLocalNode(
    async (operation, request) => {
      calls.push(["step-up", operation, request]);
      return "token-1";
    },
    async (body) => {
      calls.push(["delete", body]);
      return { provisioned: false };
    },
  );
  assert.deepEqual(calls, [
    ["step-up", "custody.local_node.remove", {}],
    ["delete", { step_up_token: "token-1" }],
  ]);
  assert.deepEqual(outcome, { ok: true, note: "This Home's node is removed. This Home can offer custody again." });

  // Already gone: the slot clears and says so.
  const gone = await removeLocalNode(async () => "token-3", async () => {
    throw Object.assign(new Error("no_local_node"), { code: "no_local_node", detail: "" });
  });
  assert.deepEqual(gone, { ok: true, note: "This Home has no node to remove. Nothing changed." });

  let deletes = 0;
  const cancelled = await removeLocalNode(
    async () => {
      throw new Error("Passkey verification failed.");
    },
    async () => {
      deletes += 1;
    },
  );
  assert.equal(deletes, 0);
  assert.deepEqual(cancelled, { ok: false, line: "Passkey verification failed.", reason: "" });

  const refused = await removeLocalNode(async () => "token-2", async () => {
    throw Object.assign(new Error("pool_installed"), { code: "pool_installed", detail: "" });
  });
  assert.deepEqual(refused, { ok: false, ...errorView({ code: "pool_installed" }) });
});

test("this Home's slot shows its Remove refusal and holds Remove while it runs", () => {
  const state = hostileState();
  state.slots[0] = { kind: "home", runBy: "Iz.", location: "Paris", restart: false, busy: true, error: "" };
  const busy = createView(state).poolsMarkup();
  assert.match(busy, /data-action="remove" data-slot="0" disabled/);
  state.slots[0] = { ...state.slots[0], busy: false, error: errorView({ code: "pool_installed" }).line };
  const refused = createView(state).poolsMarkup();
  assert.doesNotMatch(refused, /data-action="remove" data-slot="0" disabled/);
  assert.ok(refused.includes(escapeText(errorView({ code: "pool_installed" }).line)));
});

test("askAgainIndex finds the slot the asked node is in now, or none", () => {
  const approved = readNodeRequests([nodeRequest({ state: "approved", card: CARD_ANN })])[0];
  const asked = approvedSlot(approved, { home_id: "did:key:z6MkAnnHome" });
  // Unchanged while the ask ran.
  assert.equal(askAgainIndex([emptySlot(), asked], 1, asked), 1);
  // Read again meanwhile: the same approval sits in a new slot object.
  const reread = approvedSlot(approved, { home_id: "did:key:z6MkAnnHome" });
  assert.equal(askAgainIndex([reread, emptySlot()], 1, asked), 0);
  // Removed meanwhile: no slot holds it.
  assert.equal(askAgainIndex([emptySlot(), emptySlot()], 1, asked), -1);
});

test("errorView words the offer refusals", () => {
  assert.deepEqual(errorView({ code: "already_holds_custody" }), { line: HOLDS_LINE, reason: "" });
  for (const code of ["messages_not_enabled", "no_profile"]) {
    const { line } = errorView({ code });
    assert.notEqual(line, "Runtime refused this action. Nothing changed.", code);
    assert.ok(line.length > 0 && line.length < 90, code);
  }
});

/* ---------- Pools: finding nodes among contacts ---------- */

const NEEDS_UPDATE_LINE = "Needs an update: this contact's Home cannot receive custody requests yet.";
const CARD_ANN = "elastos-node-card:v1:annannann";

function nodeRequest(overrides = {}) {
  return {
    request_id: "req-ann",
    request_sha256: `sha256:${"a".repeat(64)}`,
    recipient_profile_did: "did:key:z6MkAnnProfile",
    recipient_home: "did:key:z6MkAnnHome",
    recipient_name: "Ann",
    term_days: 365,
    created_at: 1_793_000_000,
    expires_at: 1_793_086_400,
    state: "waiting",
    ...overrides,
  };
}

// The card slot a read approval leaves, as readCardInto builds it.
function approvedSlot(record, view = {}) {
  return cardSlot(record.card, view, approvalFields(record));
}

function emptySlot() {
  return { kind: "empty", text: "", error: "", note: "" };
}

function finderState(contacts, finder = {}) {
  const state = hostileState({ step: "nodes", slots: [emptySlot(), emptySlot(), emptySlot()] });
  state.finder = {
    slot: 0,
    busy: false,
    contacts: contacts === null ? null : readFoundContacts({ contacts }),
    failed: null,
    asking: "",
    askError: null,
    ...finder,
  };
  return state;
}

function finderOf(html) {
  const start = html.indexOf('class="cp-card cp-card-raised cp-finder"');
  return start < 0 ? "" : html.slice(start);
}

test("readNodeRequests keeps well-formed records, newest first", () => {
  const older = nodeRequest({ request_id: "old", created_at: 1_792_000_000 });
  const records = readNodeRequests([older, nodeRequest(), null, { request_id: "x", state: "lost" }, "r"]);
  assert.deepEqual(records.map((record) => record.requestId), ["req-ann", "old"]);
  assert.deepEqual(records[0], {
    requestId: "req-ann",
    profileDid: "did:key:z6MkAnnProfile",
    recipientHome: "did:key:z6MkAnnHome",
    name: "Ann",
    termDays: 365,
    createdAt: 1_793_000_000,
    state: "waiting",
    code: "",
    card: "",
  });
  assert.deepEqual(readNodeRequests(undefined), []);
});

test("Each empty slot offers Find a node next to the paste path", () => {
  const state = finderState(null);
  state.finder = null;
  const html = createView(state).poolsMarkup();
  assert.match(html, /data-action="find-open" data-slot="0"[^>]*>Find a node</);
  assert.match(html, /data-action="find-open" data-slot="2"/);
  assert.match(html, /placeholder="Node address"/);
});

test("the finder lists contacts by status, and asks only those who offer", () => {
  const html = finderOf(createView(finderState([
    { profile_did: "did:key:ann", name: "Ann", status: "offering", run_by: "Ann R.", location: "Lisbon", provides: ["chain", "custody", "ipfs"] },
    { profile_did: "did:key:bob", name: "Bob", status: "not_offering" },
    { profile_did: "did:key:cy", name: "Cy", status: "unreachable" },
    { profile_did: "did:key:dee", name: "Dee", status: "needs_update" },
  ])).poolsMarkup());
  assert.match(html, />Ann</);
  assert.match(html, />Run by Ann R\.</);
  assert.match(html, />Lisbon</);
  assert.match(html, />Custody, chain and storage</);
  assert.match(html, /data-action="find-ask" data-profile="did:key:ann"[^>]*>Ask to be a node</);
  assert.equal((html.match(/data-action="find-ask"/g) || []).length, 1);
  assert.match(html, />Not offering custody</);
  assert.match(html, />Not reachable right now</);
  assert.ok(html.includes(escapeText(NEEDS_UPDATE_LINE)));
  assert.doesNotMatch(html, /None of your contacts offers custody yet/);
});

test("the finder says when no contact offers custody", () => {
  const html = finderOf(createView(finderState([{ profile_did: "did:key:bob", name: "Bob", status: "not_offering" }])).poolsMarkup());
  assert.match(html, /None of your contacts offers custody yet\./);
  assert.doesNotMatch(html, /People/);
});

test("the finder with no contacts points to People", () => {
  const html = finderOf(createView(finderState([])).poolsMarkup());
  assert.match(html, /You have no contacts yet\. Add contacts in People, then find nodes\./);
  assert.doesNotMatch(html, /None of your contacts offers custody/);
});

test("a contact that approved reads as approved with its node, never as not offering", () => {
  // A node that approved holds a custody state, so it no longer offers.
  const state = finderState([
    { profile_did: "did:key:z6MkAnnProfile", name: "Ann", status: "not_offering", request: "approved" },
  ], { slot: 1 });
  const record = nodeRequest({ state: "approved", card: CARD_ANN });
  state.summary.node_requests = [record];
  state.slots[0] = approvedSlot(readNodeRequests([record])[0], { home_id: "did:key:z6MkAnnHome" });
  const html = finderOf(createView(state).poolsMarkup());
  assert.match(html, />Approved · in node 1</);
  assert.doesNotMatch(html, /Not offering custody/);
  assert.doesNotMatch(html, /data-action="find-ask"/);
  // An approval no slot holds still reads as approved.
  state.slots[0] = emptySlot();
  const loose = finderOf(createView(state).poolsMarkup());
  assert.match(loose, />Approved</);
  assert.doesNotMatch(loose, /in node|Not offering custody/);
  // A contact that stopped offering after a decline still reads as not offering.
  state.finder.contacts = readFoundContacts({ contacts: [
    { profile_did: "did:key:z6MkAnnProfile", name: "Ann", status: "not_offering", request: "declined" },
  ] });
  assert.match(finderOf(createView(state).poolsMarkup()), />Not offering custody</);
});

test("the finder shows its busy state and blocks a second find", () => {
  const html = createView(finderState(null, { busy: true })).poolsMarkup();
  assert.match(finderOf(html), /Asking your contacts…/);
  assert.match(html, /data-action="find-open" data-slot="1"[^>]* disabled/);
});

test("a request in flight disables Ask, and a contact with a request shows its state", () => {
  const contacts = [
    { profile_did: "did:key:ann", name: "Ann", status: "offering", run_by: "Ann", location: "Lisbon", provides: ["custody"] },
    { profile_did: "did:key:eve", name: "Eve", status: "offering", run_by: "Eve", location: "Oslo", provides: ["custody"], request: "waiting" },
    { profile_did: "did:key:fay", name: "Fay", status: "offering", run_by: "Fay", location: "Rome", provides: ["custody"], request: "approved" },
    { profile_did: "did:key:gus", name: "Gus", status: "offering", run_by: "Gus", location: "Kyiv", provides: ["custody"], request: "declined" },
  ];
  const asking = finderOf(createView(finderState(contacts, { asking: "did:key:ann" })).poolsMarkup());
  assert.match(asking, /data-profile="did:key:ann"[^>]* disabled/);
  assert.match(asking, /data-profile="did:key:gus"[^>]* disabled/);
  const html = finderOf(createView(finderState(contacts)).poolsMarkup());
  assert.match(html, />Waiting for Eve</);
  assert.match(html, />Approved by Fay</);
  assert.doesNotMatch(html, /data-profile="did:key:(eve|fay)"/);
  // A decided request can be asked again.
  assert.match(html, /data-profile="did:key:gus"/);
});

test("a contact already filling another slot is not offered again", () => {
  const state = finderState([
    { profile_did: "did:key:z6MkAnnProfile", name: "Ann", status: "offering", run_by: "Ann", location: "Lisbon", provides: ["custody"] },
  ], { slot: 1 });
  state.slots[0] = requestSlot(readNodeRequests([nodeRequest()])[0]);
  const html = finderOf(createView(state).poolsMarkup());
  assert.match(html, />In node 1</);
  assert.doesNotMatch(html, /data-action="find-ask"/);
  // A pasted card whose node is that contact's Home fills a slot too.
  state.slots[0] = { kind: "card", text: "elastos-node-card:v1:pasted", card: { home_id: "did:key:z6MkAnnHome" } };
  state.summary.node_requests = [nodeRequest({ state: "declined", code: "declined" })];
  assert.match(finderOf(createView(state).poolsMarkup()), />In node 1</);
  // A declined slot holds nobody: that contact may be asked again.
  state.slots[0] = requestSlot(readNodeRequests([nodeRequest({ state: "declined", code: "declined" })])[0]);
  assert.match(finderOf(createView(state).poolsMarkup()), /data-action="find-ask"/);
});

test("a failed find or ask shows its refusal in the finder", () => {
  const failed = finderOf(createView(finderState(null, {
    failed: requestErrorView({ code: "messages_not_enabled" }),
  })).poolsMarkup());
  assert.match(failed, /Enable custody messages in Hosting first\./);
  assert.match(failed, /data-action="find-retry"/);
  const ask = finderOf(createView(finderState([], { askError: requestErrorView({ code: "already_requested" }) })).poolsMarkup());
  assert.match(ask, /You already asked this Home\. Wait for its answer\./);
});

test("every node request refusal has its own line", () => {
  const lines = {
    already_requested: "You already asked this Home. Wait for its answer.",
    too_many_requests: "Too many open requests. Wait for some answers first.",
    pool_installed: "The pool is already installed.",
    no_signing_key: "Create the pool signing key first.",
    messages_not_enabled: "Enable custody messages in Hosting first.",
    not_contact: "This Profile is not one of your contacts.",
    needs_update: NEEDS_UPDATE_LINE,
    bad_term: "Choose a pool term first.",
    term_changed: "A node agreed to a different term. Ask it again for this term.",
  };
  for (const [code, line] of Object.entries(lines)) {
    assert.deepEqual(requestErrorView({ code, detail: "" }), { line, reason: "" }, code);
  }
  // Install refuses a term the node did not agree to with the same line.
  assert.equal(errorView({ code: "term_changed" }).line, lines.term_changed);
  // Anything else reads as any other refusal.
  assert.deepEqual(requestErrorView({ text: "admin passkey required" }), errorView({ text: "admin passkey required" }));
});

test("requestStatus gives each request state its chip, line and action", () => {
  const status = (overrides) => requestStatus(readNodeRequests([nodeRequest(overrides)])[0]);
  assert.deepEqual(status({}), { word: "Waiting for Ann", tone: "pending", line: "", action: "cancel" });
  assert.deepEqual(status({ state: "approved", card: CARD_ANN }), { word: "Approved by Ann", tone: "ok", line: "", action: "" });
  // An approval without a card cannot fill the slot: it can only be let go.
  assert.deepEqual(status({ state: "approved" }), { word: "Approved by Ann", tone: "ok", line: "", action: "find-another" });
  assert.deepEqual(status({ state: "expired" }), { word: "Expired", tone: "pending", line: "", action: "find-another" });
  const declines = {
    not_offering: "No longer offers custody.",
    already_serving: "Already serves another pool owner.",
    not_admin: "Only that Home's admin can approve custody requests.",
    declined: "The node's admin declined.",
    expired: "The request expired before the node answered.",
  };
  for (const [code, line] of Object.entries(declines)) {
    assert.deepEqual(status({ state: "declined", code }), { word: "Declined", tone: "danger", line, action: "find-another" }, code);
  }
  // A decline without a code is not the node's decision either.
  for (const code of ["", undefined]) {
    assert.deepEqual(status({ state: "declined", code }), {
      word: "Not sent", tone: "danger", line: "This request could not be delivered.", action: "find-another",
    }, String(code));
  }
  // Any other code is this Home failing to send, never the node's decision.
  assert.deepEqual(status({ state: "declined", code: "unreachable" }), {
    word: "Not sent", tone: "danger", line: "This request could not be delivered (unreachable).", action: "find-another",
  });
});

test("a request slot shows its chip, the term asked for and its action", () => {
  const state = finderState(null);
  state.finder = null;
  const slotFor = (overrides) => requestSlot(readNodeRequests([nodeRequest(overrides)])[0]);
  state.slots[0] = slotFor({});
  let html = createView(state).poolsMarkup();
  assert.match(html, /data-tone="pending">Waiting for Ann</);
  assert.match(html, /Asked for 1 year/);
  assert.match(html, /data-action="request-release" data-slot="0"[^>]*>Cancel</);
  // A waiting slot is not filled: Review stays shut.
  assert.equal(createView(state).filledCount(), 0);

  state.slots[0] = slotFor({ state: "declined", code: "already_serving" });
  html = createView(state).poolsMarkup();
  assert.match(html, /data-tone="danger">Declined</);
  assert.match(html, /Already serves another pool owner\./);
  assert.match(html, /data-action="request-release" data-slot="0"[^>]*>Find another</);

  state.slots[0] = slotFor({ state: "declined", code: "send_failed" });
  html = createView(state).poolsMarkup();
  assert.match(html, />Not sent</);
  assert.match(html, /This request could not be delivered \(send_failed\)\./);
  assert.doesNotMatch(html, />Declined</);

  state.slots[0] = slotFor({ state: "expired" });
  assert.match(createView(state).poolsMarkup(), />Expired<.*>Find another</s);
});

test("an approved record fills the slot as a card that installs like a pasted one", () => {
  const record = readNodeRequests([nodeRequest({ state: "approved", card: ` ${CARD_ANN}\n` })])[0];
  const view = { run_by: "Ann R.", location: "Lisbon", provides: ["custody", "chain"], fingerprint: "AB12 CD34 EF56", home_id: "did:key:z6MkNode" };
  // readCardInto builds every card slot this way; an approval adds its request.
  const slot = cardSlot(CARD_ANN, view, approvalFields(record));
  assert.equal(record.card, CARD_ANN);
  assert.deepEqual(cardSlot(CARD_ANN, view), { kind: "card", text: CARD_ANN, card: view });
  assert.equal(slot.kind, "card");
  assert.equal(slot.text, CARD_ANN);
  assert.equal(slot.requestId, "req-ann");
  assert.equal(slot.recipientHome, "did:key:z6MkAnnHome");
  assert.equal(slot.termDays, 365);
  assert.deepEqual(installSlots([slot]), [{ card: CARD_ANN }]);
  const state = finderState(null);
  state.finder = null;
  state.slots[0] = slot;
  assert.equal(createView(state).slotInput(slot).card, CARD_ANN);
  const html = createView(state).poolsMarkup();
  assert.match(html, /data-tone="ok">Approved by Ann</);
  assert.match(html, />Ann R\.</);
  assert.match(html, /Asked for 1 year/);
});

test("restorePlacements refills unbound waiting and approved requests, newest first, same term only", () => {
  const records = readNodeRequests([
    nodeRequest({ request_id: "new", recipient_home: "home-b", created_at: 30 }),
    nodeRequest({ request_id: "mid", recipient_home: "home-c", created_at: 20, state: "approved", card: CARD_ANN }),
    nodeRequest({ request_id: "old", recipient_home: "home-d", created_at: 10 }),
    nodeRequest({ request_id: "two-year", recipient_home: "home-e", created_at: 40, term_days: 730 }),
    nodeRequest({ request_id: "declined", recipient_home: "home-f", created_at: 50, state: "declined", code: "declined" }),
    nodeRequest({ request_id: "expired", recipient_home: "home-g", created_at: 60, state: "expired" }),
    nodeRequest({ request_id: "bound", recipient_home: "home-a", created_at: 70 }),
    // A second record for a Home already in a slot never takes another.
    nodeRequest({ request_id: "dup", recipient_home: "home-a", created_at: 5 }),
  ]);
  const slots = [
    requestSlot(records.find((record) => record.requestId === "bound")),
    emptySlot(),
    { kind: "empty", text: "typed", error: "", note: "" },
    emptySlot(),
  ];
  const placements = restorePlacements(slots, records, 365, new Set());
  assert.deepEqual(placements.map(({ index, record }) => [index, record.requestId]), [[1, "new"], [3, "mid"]]);
  // A request the owner let go of stays out.
  assert.deepEqual(
    restorePlacements(slots, records, 365, new Set(["new"])).map(({ index, record }) => [index, record.requestId]),
    [[1, "mid"], [3, "old"]],
  );
  // An approved card already in a slot binds its Home.
  const filled = [approvedSlot(records.find((record) => record.requestId === "mid"), {}), emptySlot()];
  assert.deepEqual(restorePlacements(filled, records.filter((record) => record.requestId !== "new"), 365, new Set())
    .map(({ index, record }) => [index, record.requestId]), [[1, "bound"]]);
  assert.deepEqual(restorePlacements([emptySlot()], records, 730, new Set()).map(({ record }) => record.requestId), ["two-year"]);
  // A pasted card from the same Home, even as different text, holds that Home.
  const pasted = { kind: "card", text: "elastos-node-card:v1:other", card: { home_id: "home-b" } };
  assert.deepEqual(restorePlacements([pasted, emptySlot()], records.filter((record) => record.requestId === "new"), 365, new Set()), []);
});

test("a term change marks the request slots and blocks install", () => {
  const waiting = requestSlot(readNodeRequests([nodeRequest()])[0]);
  const approved = approvedSlot(readNodeRequests([nodeRequest({ request_id: "b", state: "approved", card: CARD_ANN })])[0], {});
  const declined = requestSlot(readNodeRequests([nodeRequest({ request_id: "c", state: "declined", code: "declined" })])[0]);
  const pasted = { kind: "card", text: "elastos-node-card:v1:pasted", card: {} };
  assert.equal(termMismatch([waiting, approved, declined, pasted], 365), false);
  assert.equal(termMismatch([waiting, pasted], 730), true);
  assert.equal(termMismatch([approved], 182), true);
  // Only a request the node may still act on binds the term.
  assert.equal(termMismatch([declined, pasted], 730), false);
  assert.equal(termChangedLine(365, 730), "This node agreed to 1 year. Ask again for the new term.");
  assert.equal(termChangedLine(365, 365), "");

  const state = finderState(null);
  state.finder = null;
  state.termDays = 730;
  state.slots[0] = waiting;
  state.slots[1] = approved;
  const html = createView(state).poolsMarkup();
  assert.equal((html.match(/This node agreed to 1 year\. Ask again for the new term\./g) || []).length, 2);
  // The approved node can be asked again for the new term; a waiting one
  // answers first.
  assert.match(html, /<button class="cp-btn cp-btn-sm" type="button" data-action="ask-again" data-slot="1">Ask again for 2 years<\/button>/);
  assert.doesNotMatch(html, /data-action="ask-again" data-slot="0"/);
  assert.equal(askAgainTarget(approved), "did:key:z6MkAnnProfile");
  for (const slot of [waiting, declined, pasted, emptySlot()]) {
    assert.equal(askAgainTarget(slot), "", JSON.stringify(slot));
  }
  state.termDays = 365;
  assert.doesNotMatch(createView(state).poolsMarkup(), /data-action="ask-again"/);
  // Before install, every slot names a node, not a share.
  state.termDays = 730;
  assert.match(html, /<span class="cp-slot-coord">Node 1<\/span>/);
  assert.doesNotMatch(html, /cp-slot-coord">Share/);
});

test("pollDelay counts from the last summary, so arming again never pushes a refresh back", () => {
  const interval = 10_000;
  // Armed again 3 s after a refresh: the refresh still comes 10 s after it.
  assert.equal(pollDelay(100_000, 103_000, interval), 7_000);
  // Shown again long after the last summary: refresh at once.
  assert.equal(pollDelay(100_000, 160_000, interval), 0);
  assert.equal(pollDelay(0, 160_000, interval), 0);
  // A clock that went back never waits longer than one interval.
  assert.equal(pollDelay(200_000, 100_000, interval), interval);
});

test("shouldPollRequests polls only for a waiting slot on a shown, visible setup view", () => {
  const waiting = requestSlot(readNodeRequests([nodeRequest()])[0]);
  const declined = requestSlot(readNodeRequests([nodeRequest({ state: "declined", code: "declined" })])[0]);
  assert.equal(shouldPollRequests([emptySlot(), waiting], { shown: true, visible: true }), true);
  assert.equal(shouldPollRequests([waiting], { shown: false, visible: true }), false);
  assert.equal(shouldPollRequests([waiting], { shown: true, visible: false }), false);
  assert.equal(shouldPollRequests([declined, emptySlot()], { shown: true, visible: true }), false);
});

test("the finder and request slots render remote text inert", () => {
  const contacts = [
    { profile_did: HOSTILE, name: HOSTILE, status: "offering", run_by: HOSTILE, location: HOSTILE, provides: ["custody", HOSTILE] },
    { profile_did: HOSTILE, name: HOSTILE, status: "offering", run_by: HOSTILE, location: HOSTILE, request: "waiting" },
    { profile_did: `${HOSTILE}2`, name: HOSTILE, status: "needs_update" },
    { profile_did: `${HOSTILE}3`, name: HOSTILE, status: HOSTILE },
  ];
  const state = finderState(contacts, { askError: { line: HOSTILE, reason: HOSTILE } });
  const hostile = (overrides) => requestSlot(readNodeRequests([nodeRequest({ recipient_name: HOSTILE, ...overrides })])[0]);
  state.slots[1] = hostile({});
  state.slots[2] = hostile({ request_id: "d", state: "declined", code: HOSTILE });
  state.termDays = 730;
  const html = createView(state).poolsMarkup();
  assertInert(html, "finder and request slots");
  assert.ok(!html.includes("<img"), "raw <img>");
  const approved = finderState(null, { failed: { line: HOSTILE, reason: HOSTILE } });
  approved.slots[1] = approvedSlot(readNodeRequests([nodeRequest({ recipient_name: HOSTILE, state: "approved", card: CARD_ANN })])[0], {
    run_by: HOSTILE, location: HOSTILE, provides: [HOSTILE], fingerprint: HOSTILE, home_id: HOSTILE,
  });
  assertInert(createView(approved).poolsMarkup(), "finder failure and approved card");
});

/* ---------- Member health ---------- */

// Checked now by default, so "today" holds in every time zone on any day.
function healthAnswer(status, online, members, threshold = THRESHOLD, checkedAt = Math.floor(Date.now() / 1000)) {
  return {
    status,
    online,
    required: threshold.required,
    total: threshold.total,
    checked_at: checkedAt,
    members,
  };
}

test("readHealth keeps a well-formed answer and refuses a malformed one", () => {
  const members = [
    { share: 1, state: "online", detail: null },
    { share: 2, state: "not_answering", detail: "no_address" },
  ];
  assert.deepEqual(readHealth(healthAnswer("at_risk", 2, members, THRESHOLD, 1_793_000_000)), {
    status: "at_risk",
    online: 2,
    required: 2,
    total: 3,
    checkedAt: 1_793_000_000_000,
    members: [
      { share: 1, state: "online", detail: "" },
      { share: 2, state: "not_answering", detail: "no_address" },
    ],
  });
  assert.equal(readHealth(null), null);
  assert.equal(readHealth(healthAnswer("fine", 3, [])), null);
  assert.equal(readHealth({ ...healthAnswer("healthy", 3, []), total: "3" }), null);
  assert.equal(readHealth({ ...healthAnswer("healthy", 3, []), online: 4 }), null);
  assert.equal(readHealth({ ...healthAnswer("healthy", 3, []), required: 4 }), null);
  // An answer without its time cannot say when it was checked.
  for (const checkedAt of [undefined, null, 0, -5, 1.5, "1793000000", Number.NaN]) {
    assert.equal(readHealth({ ...healthAnswer("healthy", 3, []), checked_at: checkedAt }), null, String(checkedAt));
  }
  // A member without a share number cannot be placed on a row.
  assert.deepEqual(readHealth(healthAnswer("down", 0, [{ state: "online" }, null])).members, []);
});

test("healthLine words each pool status from the answer's threshold", () => {
  assert.equal(healthLine(readHealth(healthAnswer("healthy", 3, []))), "All 3 nodes are online.");
  assert.equal(
    healthLine(readHealth(healthAnswer("at_risk", 2, []))),
    "Releases work, with no spare. 1 of 3 nodes is not online.",
  );
  assert.equal(
    healthLine(readHealth(healthAnswer("down", 1, []))),
    "Buyers cannot open content in this pool until 2 nodes are online.",
  );
  // Another threshold changes every number: none of them is a literal.
  const wide = { required: 3, total: 5 };
  assert.equal(healthLine(readHealth(healthAnswer("healthy", 5, [], wide))), "All 5 nodes are online.");
  assert.equal(
    healthLine(readHealth(healthAnswer("at_risk", 3, [], wide))),
    "Releases work, with no spare. 2 of 5 nodes are not online.",
  );
  assert.equal(
    healthLine(readHealth(healthAnswer("down", 2, [], wide))),
    "Buyers cannot open content in this pool until 3 nodes are online.",
  );
  // One missing node, and a threshold of one, read in the singular.
  const single = { required: 1, total: 3 };
  assert.equal(
    healthLine(readHealth(healthAnswer("at_risk", 2, [], single))),
    "Releases work, with no spare. 1 of 3 nodes is not online.",
  );
  assert.equal(
    healthLine(readHealth(healthAnswer("at_risk", 1, [], single))),
    "Releases work, with no spare. 2 of 3 nodes are not online.",
  );
  assert.equal(
    healthLine(readHealth(healthAnswer("down", 0, [], single))),
    "Buyers cannot open content in this pool until 1 node is online.",
  );
});

test("healthChip gives each pool status its word and tone", () => {
  assert.deepEqual(healthChip("healthy"), { word: "Healthy", tone: "ok" });
  assert.deepEqual(healthChip("at_risk"), { word: "At risk", tone: "pending" });
  assert.deepEqual(healthChip("down"), { word: "Down", tone: "danger" });
});

test("healthBanner follows the pool status", () => {
  const wide = { required: 3, total: 5 };
  assert.deepEqual(healthBanner(readHealth(healthAnswer("healthy", 5, [], wide))), {
    tone: "ok",
    strong: "Pool active.",
    line: "Any 3 of 5 shares open your content.",
  });
  assert.deepEqual(healthBanner(readHealth(healthAnswer("at_risk", 4, [], wide))), {
    tone: "pending",
    line: "Releases work, with no spare. 1 of 5 nodes is not online.",
  });
  assert.deepEqual(healthBanner(readHealth(healthAnswer("down", 0, [], wide))), {
    tone: "danger",
    line: "Buyers cannot open content in this pool until 3 nodes are online.",
  });
});

test("activeBanner picks one banner in the ruled order", () => {
  const healthy = readHealth(healthAnswer("healthy", 3, []));
  const atRisk = readHealth(healthAnswer("at_risk", 2, []));
  const down = readHealth(healthAnswer("down", 1, []));
  const problem = errorView({ code: "verify_failed", detail: "term ended" });
  const lines = {
    problem: "The installed pool did not pass the Runtime check: term ended.",
    ended: "Pool term ended on 23 Oct 2027.",
    down: "Buyers cannot open content in this pool until 2 nodes are online.",
    restart: "This Home's node is set up but not started. Restart this Home to start it.",
    unregistered: "Ter is not registered on this Home yet. Releases cannot reach it.",
    ending: "Pool term ends in 12 days. Renewing comes in a later version.",
    atRisk: "Releases work, with no spare. 1 of 3 nodes is not online.",
    healthy: "Any 2 of 3 shares open your content.",
  };
  // Every condition at once; drop the winner each time to reach the next.
  const all = {
    problem,
    pool: true,
    termEndedAt: new Date(2027, 9, 23, 12).getTime(),
    health: down,
    restart: true,
    unregistered: "Ter",
    termDaysLeft: 12,
    threshold: THRESHOLD,
  };
  const order = [
    [{}, "danger", lines.problem],
    [{ problem: null }, "danger", lines.ended],
    [{ problem: null, termEndedAt: 0 }, "danger", lines.down],
    [{ problem: null, termEndedAt: 0, health: atRisk }, "pending", lines.restart],
    [{ problem: null, termEndedAt: 0, health: atRisk, restart: false }, "pending", lines.unregistered],
    [{ problem: null, termEndedAt: 0, health: atRisk, restart: false, unregistered: "" }, "pending", lines.ending],
    [{ problem: null, termEndedAt: 0, health: atRisk, restart: false, unregistered: "", termDaysLeft: null }, "pending", lines.atRisk],
    [{ problem: null, termEndedAt: 0, health: healthy, restart: false, unregistered: "", termDaysLeft: null }, "ok", lines.healthy],
    // Without an answer and with no check under way, nothing claims health.
    [{ problem: null, termEndedAt: 0, health: null, restart: false, unregistered: "", termDaysLeft: null }, undefined, "Releases need 2 of 3 nodes online."],
  ];
  for (const [change, tone, line] of order) {
    const banner = activeBanner({ ...all, ...change });
    assert.equal(banner.tone, tone, line);
    assert.equal(banner.line, line);
  }
  assert.equal(activeBanner({ ...all, ...order[7][0] }).strong, "Pool active.");
  // Down outranks the pending banners; at risk yields to them.
  assert.equal(activeBanner({ pool: true, health: down, unregistered: "Ter", termDaysLeft: 3, threshold: THRESHOLD }).line, lines.down);
  assert.equal(activeBanner({ pool: true, health: atRisk, termDaysLeft: 12, threshold: THRESHOLD }).line, lines.ending);
  assert.equal(activeBanner({ pool: false, health: down }), null);
});

test("activeBanner shows ok only for a fresh healthy answer", () => {
  const healthy = readHealth(healthAnswer("healthy", 3, []));
  const atRisk = readHealth(healthAnswer("at_risk", 2, []));
  const down = readHealth(healthAnswer("down", 1, []));
  const base = { pool: true, threshold: THRESHOLD };
  const checkingLine = "Checking each node. It takes a few seconds.";
  const failedLine = "Node health could not be checked. Try again.";

  // First check running: neutral, no tone.
  assert.deepEqual(activeBanner({ ...base, checking: true }), { line: checkingLine });
  // First check failed: pending.
  assert.deepEqual(activeBanner({ ...base, failed: true }), { tone: "pending", line: failedLine });
  // A failed re-check keeps the last line, pending, with its time.
  const today = /^All 3 nodes are online\. Last checked today, \d\d:\d\d\.$/;
  const stale = activeBanner({ ...base, health: healthy, failed: true });
  assert.equal(stale.tone, "pending");
  assert.equal(stale.strong, undefined);
  assert.match(stale.line, today);
  assert.match(activeBanner({ ...base, health: atRisk, failed: true }).line, /^Releases work, with no spare\. 1 of 3 nodes is not online\. Last checked today, /);
  // A last-known down pool is never softened: danger, in the down slot.
  const staleDown = activeBanner({ ...base, health: down, failed: true });
  assert.equal(staleDown.tone, "danger");
  assert.match(staleDown.line, /^Buyers cannot open content in this pool until 2 nodes are online\. Last checked today, \d\d:\d\d\.$/);
  assert.equal(activeBanner({ ...base, health: down, failed: true, restart: true, unregistered: "Ter", termDaysLeft: 9 }).line, staleDown.line);
  assert.equal(activeBanner({ ...base, health: down, failed: true, termEndedAt: new Date(2027, 9, 23, 12).getTime() }).line,
    "Pool term ended on 23 Oct 2027.");
  const pastSeconds = 1_700_000_000;
  assert.equal(
    activeBanner({ ...base, health: readHealth(healthAnswer("healthy", 3, [], THRESHOLD, pastSeconds)), failed: true }).line,
    `All 3 nodes are online. Last checked ${formatDate(pastSeconds * 1000)}.`,
  );
  // Only the fresh healthy answer is ok.
  assert.equal(activeBanner({ ...base, health: healthy }).tone, "ok");
  for (const state of [{ checking: true }, { failed: true }, { health: healthy, failed: true }, {}]) {
    assert.notEqual(activeBanner({ ...base, ...state }).tone, "ok", JSON.stringify(state));
  }
  // A re-check under way keeps the last answer, so a down pool stays on top.
  assert.equal(activeBanner({ ...base, health: down, checking: true, restart: true }).tone, "danger");
  // The higher banners keep their place above these states.
  const restartLine = "This Home's node is set up but not started. Restart this Home to start it.";
  assert.equal(activeBanner({ ...base, checking: true, restart: true }).line, restartLine);
  assert.equal(activeBanner({ ...base, failed: true, unregistered: "Ter" }).line,
    "Ter is not registered on this Home yet. Releases cannot reach it.");
  assert.equal(activeBanner({ ...base, health: atRisk, failed: true, termDaysLeft: 9 }).line,
    "Pool term ends in 9 days. Renewing comes in a later version.");
  assert.equal(activeBanner({ ...base, failed: true, problem: { line: "P", reason: "" } }).line, "P");
});

test("memberHealth gives each member state a dot, a word and its note", () => {
  assert.deepEqual(memberHealth({ share: 1, state: "online", detail: "" }), {
    presence: "online", word: "Online", tone: "ok", note: "",
  });
  assert.deepEqual(memberHealth({ share: 2, state: "not_answering", detail: "no_address" }), {
    presence: "not_answering", word: "Not answering", tone: "danger", note: "No address for this node on this Home.",
  });
  assert.deepEqual(memberHealth({ share: 1, state: "not_answering", detail: "not_running" }), {
    presence: "not_answering", word: "Not answering", tone: "danger",
    note: "This Home's node is not running. Restart this Home to start it.",
  });
  assert.deepEqual(memberHealth({ share: 3, state: "not_answering", detail: "operator connection timed out" }), {
    presence: "not_answering", word: "Not answering", tone: "danger", note: "Reason: operator connection timed out",
  });
  assert.deepEqual(memberHealth({ share: 3, state: "not_answering", detail: "" }).note, "");
  assert.deepEqual(memberHealth({ share: 2, state: "different_node", detail: "" }), {
    presence: "different_node", word: "Different node", tone: "danger",
    note: "This node answers with different keys than the pool expects.",
  });
  assert.deepEqual(memberHealth({ share: 3, state: "refused", detail: "this node has no custody card" }), {
    presence: "refused", word: "Refused", tone: "pending", note: "Reason: this node has no custody card",
  });
  assert.equal(memberHealth({ share: 3, state: "refused", detail: "" }).note, "");
  // A state this app does not know claims nothing about the node.
  assert.deepEqual(memberHealth({ share: 3, state: "sleeping", detail: "zzz" }), {
    presence: "not_answering", word: "Not answering", tone: "danger", note: "Reason: zzz",
  });
});

test("clipDetail keeps a node's reason to about 200 characters", () => {
  assert.equal(clipDetail("short"), "short");
  assert.equal(clipDetail("x".repeat(200)), "x".repeat(200));
  const clipped = clipDetail("x".repeat(500));
  assert.equal([...clipped].length, 200);
  assert.ok(clipped.endsWith("…"));
  // A clip never splits a character in two.
  assert.ok(!clipDetail("😀".repeat(300)).includes("\uFFFD"));
  assert.equal([...clipDetail("😀".repeat(300))].length, 200);
  const long = memberHealth({ share: 3, state: "refused", detail: "y".repeat(1000) }).note;
  assert.equal(long, `Reason: ${"y".repeat(199)}…`);
});

test("clipDetail drops control and bidi characters from a node's reason", () => {
  // U+202E would show "Reason: evil" reversed after it.
  assert.equal(clipDetail("abc\u202Edcba"), "abcdcba");
  assert.equal(clipDetail("\u200Eleft\u200F \u202Aa\u202Bb\u202Cc\u202Dd \u2066e\u2067f\u2068g\u2069"), "left abcd efg");
  // Line breaks and other C0/C1 controls separate words as one space.
  assert.equal(clipDetail("timed out\r\n\tcaused by\u0000x\u007Fy\u0085z\u009F"), "timed out caused by x y z");
  assert.equal(clipDetail("ok reason"), "ok reason");
  // Stripped before the clip: the limit counts what is shown.
  assert.equal(clipDetail(`${"\u202E".repeat(300)}short`), "short");
  assert.equal(
    memberHealth({ share: 3, state: "refused", detail: "\u202Eno card\u202C" }).note,
    "Reason: no card",
  );
  // A reason of only controls says nothing: no empty "Reason:".
  assert.equal(memberHealth({ share: 3, state: "refused", detail: "\u202E\u0000\u2066" }).note, "");
});

function activeState(health = {}) {
  const now = Date.now() / 1000;
  const state = hostileState({ step: "active", verify: null, ...health });
  state.summary.pool_installed = true;
  state.summary.local_node = { provisioned: true, run_by: "Iz.", location: "Paris", running: true };
  state.summary.pool = {
    members: [
      { share: 1, run_by: "Iz.", location: "Paris", this_home: true, registered: true, provides: ["custody", "chain"] },
      { share: 2, run_by: "McKaya", location: "Lisbon", registered: true, provides: ["custody", "chain"] },
      { share: 3, run_by: "Ter", location: "Berlin", registered: true, provides: ["custody", "chain"] },
    ],
    term: { start: now - 86_400, end: now + 400 * 86_400, days: 365 },
    threshold: THRESHOLD,
    fingerprint: "AB",
    cards_kept: true,
  };
  return state;
}

const HEALTHY = readHealth(healthAnswer("healthy", 3, [
  { share: 1, state: "online", detail: null },
  { share: 2, state: "online", detail: null },
  { share: 3, state: "online", detail: null },
]));
const AT_RISK = readHealth(healthAnswer("at_risk", 2, [
  { share: 1, state: "online", detail: null },
  { share: 2, state: "online", detail: null },
  { share: 3, state: "not_answering", detail: "no_address" },
]));
const DOWN = readHealth(healthAnswer("down", 1, [
  { share: 1, state: "online", detail: null },
  { share: 2, state: "different_node", detail: null },
  { share: 3, state: "refused", detail: "this node has no custody card" },
]));

function bannerOf(html) {
  return html.match(/<p class="cp-banner"[^>]*>.*?<\/p>/)?.[0] || "";
}

test("the Active view shows health once a check answered, and no Health not measured", () => {
  const html = createView(activeState({ health: AT_RISK })).poolsMarkup();
  assert.doesNotMatch(html, /Health not measured/);
  assert.doesNotMatch(html, /Runtime does not check node health yet/);
  assert.doesNotMatch(html, /Storage peering/);
  assert.match(html, /<span class="cp-chip" data-tone="pending">At risk<\/span>/);
  assert.match(html, /Releases work, with no spare\. 1 of 3 nodes is not online\./);
  assert.match(html, /Checked today, \d\d:\d\d\./);
  assert.match(html, /data-action="check-health"[^>]*>Check nodes</);

  // An older answer shows its date.
  const pastSeconds = 1_700_000_000;
  const past = readHealth(healthAnswer("at_risk", 2, [], THRESHOLD, pastSeconds));
  const dated = createView(activeState({ health: past })).poolsMarkup();
  assert.ok(dated.includes(`Checked ${formatDate(pastSeconds * 1000)}.`));
  assert.doesNotMatch(dated, /Checked today/);
  const datedFailure = createView(activeState({ health: past, healthFailed: true })).poolsMarkup();
  assert.ok(datedFailure.includes(`Last checked ${formatDate(pastSeconds * 1000)}.`));

  const healthy = createView(activeState({ health: HEALTHY })).poolsMarkup();
  assert.match(healthy, /<span class="cp-chip" data-tone="ok">Healthy<\/span>/);
  assert.match(healthy, /All 3 nodes are online\./);
  const down = createView(activeState({ health: DOWN })).poolsMarkup();
  assert.match(down, /<span class="cp-chip" data-tone="danger">Down<\/span>/);
});

test("the Active banner follows health in the ruled order", () => {
  const banner = (overrides) => bannerOf(createView(activeState(overrides)).poolsMarkup());
  // Before the first answer, the banner claims nothing; only healthy is ok.
  assert.equal(banner({ health: null, healthChecking: true }), '<p class="cp-banner" role="status">Checking each node. It takes a few seconds.</p>');
  assert.match(banner({ health: null, healthFailed: true }), /data-tone="pending">Node health could not be checked\. Try again\.</);
  const staleHealthy = banner({ health: HEALTHY, healthFailed: true });
  assert.match(staleHealthy, /data-tone="pending">All 3 nodes are online\. Last checked today, \d\d:\d\d\.</);
  assert.doesNotMatch(staleHealthy, /data-tone="ok"|Pool active/);
  assert.match(banner({ health: HEALTHY }), /data-tone="ok"><strong>Pool active\.<\/strong> Any 2 of 3 shares open your content\./);
  assert.match(banner({ health: AT_RISK }), /data-tone="pending">Releases work, with no spare\. 1 of 3 nodes is not online\./);
  assert.match(banner({ health: DOWN }), /data-tone="danger">Buyers cannot open content in this pool until 2 nodes are online\./);

  // Down outranks this Home's restart; at risk yields to it.
  const restart = activeState({ health: DOWN });
  restart.summary.local_node.running = false;
  assert.match(bannerOf(createView(restart).poolsMarkup()), /data-tone="danger">Buyers cannot open content/);
  restart.health = AT_RISK;
  assert.match(bannerOf(createView(restart).poolsMarkup()), /not started\. Restart this Home/);

  const problem = activeState({
    health: HEALTHY,
    verify: { ok: false, view: errorView({ code: "verify_failed", detail: "term ended" }) },
  });
  assert.match(bannerOf(createView(problem).poolsMarkup()), /data-tone="danger">The installed pool did not pass the Runtime check: term ended\./);
});

test("each member row shows a presence dot and a word for its state", () => {
  const html = createView(activeState({ health: DOWN })).poolsMarkup();
  const rows = html.split('<div class="cp-row" role="listitem">').slice(1);
  assert.equal(rows.length, 3);
  assert.match(rows[0], /<span class="cp-avatar" aria-hidden="true" data-presence="online">/);
  assert.match(rows[0], /<span class="cp-chip" data-tone="ok">Online<\/span>/);
  assert.match(rows[1], /data-presence="different_node"/);
  assert.match(rows[1], /<span class="cp-chip" data-tone="danger">Different node<\/span>/);
  assert.match(rows[1], /This node answers with different keys than the pool expects\./);
  assert.match(rows[2], /data-presence="refused"/);
  assert.match(rows[2], /<span class="cp-chip" data-tone="pending">Refused<\/span>/);
  assert.match(rows[2], /Reason: this node has no custody card/);

  const missing = createView(activeState({ health: AT_RISK })).poolsMarkup();
  assert.match(missing, /<span class="cp-chip" data-tone="danger">Not answering<\/span>/);
  assert.match(missing, /No address for this node on this Home\./);

  // Before a check answers, rows carry no dot and no health word.
  const unchecked = createView(activeState({ health: null })).poolsMarkup();
  assert.doesNotMatch(unchecked, /data-presence/);
  assert.doesNotMatch(unchecked, />Online</);
});

test("a check in progress shows Checking and disables Check nodes", () => {
  const first = createView(activeState({ health: null, healthChecking: true })).poolsMarkup();
  assert.match(first, /<span class="cp-chip" data-tone="pending">Checking<\/span>/);
  assert.match(first, /Checking each node\. It takes a few seconds\./);
  assert.match(first, /data-action="check-health" disabled/);

  // A check again keeps the last result, greyed, while it runs.
  const again = createView(activeState({ health: DOWN, healthChecking: true })).poolsMarkup();
  assert.match(again, /<span class="cp-chip" data-tone="pending">Checking<\/span>/);
  assert.match(again, /<div class="cp-list" role="list" data-stale="true">/);
  assert.match(again, /data-presence="refused"/);
  assert.match(again, /<span class="cp-chip" data-tone="pending" data-stale="true">Refused<\/span>/);
  assert.match(createView(activeState({ health: DOWN })).poolsMarkup(), /<span class="cp-chip" data-tone="pending">Refused<\/span>/);
});

test("a failed check says so and keeps the last result greyed with its time", () => {
  const html = createView(activeState({ health: AT_RISK, healthFailed: true })).poolsMarkup();
  assert.match(html, /Node health could not be checked\. Try again\./);
  assert.match(html, /Last checked today, \d\d:\d\d\./);
  assert.match(html, /<span class="cp-chip" data-tone="pending" data-stale="true">At risk<\/span>/);
  assert.match(html, /<div class="cp-list" role="list" data-stale="true">/);
  assert.match(html, /data-action="check-health">Check nodes</);
  // The banner keeps the last known health.
  assert.match(bannerOf(html), /data-tone="pending">Releases work, with no spare\./);

  const never = createView(activeState({ health: null, healthFailed: true })).poolsMarkup();
  assert.match(never, /Node health could not be checked\. Try again\./);
  assert.doesNotMatch(never, /Last checked/);
  assert.doesNotMatch(never, /data-presence/);
});

/* ---------- Copy through Home's clipboard ---------- */

function fakeClipboard(outcome) {
  const writes = [];
  return {
    writes,
    writeText(text, options) {
      writes.push([text, options]);
      if (outcome === "ok") {
        return Promise.resolve(true);
      }
      const error = new Error(`clipboard ${outcome}`);
      if (outcome) {
        error.code = outcome;
      }
      return Promise.reject(error);
    },
  };
}

test("copyThroughHome writes through Home with the field's purpose", async () => {
  const clipboard = fakeClipboard("ok");
  assert.equal(await copyThroughHome(clipboard, NODE_ADDRESS, COPY_IDENTIFIER), "copied");
  assert.deepEqual(clipboard.writes, [[NODE_ADDRESS, { purpose: "custody.identifier" }]]);
  assert.equal(COPY_FINGERPRINT, "custody.fingerprint");
  // The person declined Home's prompt: nothing to say.
  assert.equal(await copyThroughHome(fakeClipboard("cancelled"), "x", COPY_IDENTIFIER), "cancelled");
  // Home answered and refused: brief failure feedback.
  for (const code of ["denied", "busy", "timeout", "retired", "malformed", "replay"]) {
    assert.equal(await copyThroughHome(fakeClipboard(code), "x", COPY_IDENTIFIER), "failed", code);
  }
  // No bridge, or one that never answered: select the value to copy by hand.
  assert.equal(await copyThroughHome(fakeClipboard("unavailable"), "x", COPY_IDENTIFIER), "fallback");
  assert.equal(await copyThroughHome(fakeClipboard(""), "x", COPY_IDENTIFIER), "fallback");
  assert.equal(await copyThroughHome(null, "x", COPY_IDENTIFIER), "fallback");
});

test("every Copy button carries the full value and a purpose Home accepts", () => {
  const issuer = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
  const homeId = "did:key:z6MkkyT3oUh7cr6Yv2zAnpZzWNj9aCzHFrXv1wM6L78x6KxT";
  const fingerprint = "1A2B 3C4D … 4F2A 91C0";
  const full = `sha256:1a2b3c4d${"e".repeat(48)}4f2a91c0`;
  const screens = (withFull) => {
    const fingerprintFull = withFull ? full : undefined;
    const card = { run_by: "McKaya", location: "Lisbon", home_id: homeId, provides: ["chain", "custody"], fingerprint };
    const base = () => {
      const state = hostileState({ step: "prepare" });
      state.summary.runtime_issuer = issuer;
      state.summary.signing_key = { present: true, fingerprint, fingerprint_full: fingerprintFull };
      return state;
    };
    const review = base();
    review.step = "review";
    review.slots = [
      { kind: "home", runBy: "Iz.", location: "Paris", restart: false },
      { kind: "card", text: "elastos-node-card:v1:aa", card },
      { kind: "card", text: "elastos-node-card:v1:bb", card: { ...card, run_by: "Ter" } },
    ];
    const sign = base();
    sign.step = "sign";
    sign.sign = { phase: "success", fingerprint, fingerprintFull: fingerprintFull || "" };
    const active = activeState();
    active.summary.pool.fingerprint = fingerprint;
    active.summary.pool.fingerprint_full = fingerprintFull;
    const serving = servingSummary({ owner_did: homeId, fingerprint, fingerprint_full: fingerprintFull });
    return [
      createView(base()).poolsMarkup(),
      createView(review).poolsMarkup(),
      createView(sign).poolsMarkup(),
      createView(active).poolsMarkup(),
      createView(hostingState(serving, NODE_ADDRESS)).hostingMarkup(),
    ].join("");
  };
  const buttonsOf = (html) => [...html.matchAll(/<button class="cp-copy" [^>]*>/g)].map(([button]) => ({
    value: button.match(/data-value="([^"]*)"/)?.[1],
    purpose: button.match(/data-purpose="([^"]*)"/)?.[1],
  }));
  const html = screens(true);
  const buttons = buttonsOf(html);
  const copied = buttons.map(({ value }) => value);
  for (const value of [issuer, homeId, full, NODE_ADDRESS]) {
    assert.ok(copied.includes(value), `copies the full ${value}`);
  }
  // The short fingerprint is shown, never copied.
  assert.ok(!copied.includes(fingerprint));
  assert.equal((html.match(/<code>1A2B 3C4D … 4F2A 91C0<\/code>/g) || []).length, 4);
  // Issuer and signing key; two Home IDs; the pool on Sign and Active; then
  // the owner, the node fingerprint and the address.
  assert.equal(buttons.length, 9);
  assert.equal(buttons.filter(({ purpose }) => purpose === COPY_FINGERPRINT).length, 4);
  for (const { value, purpose } of buttons) {
    assert.ok(homeClipboardValidPayload("custody", purpose, "write", value), `${purpose}: ${value}`);
  }

  // An older backend sends no full digest: the fingerprints show without Copy.
  const older = screens(false);
  const olderButtons = buttonsOf(older);
  assert.equal(olderButtons.length, 5);
  assert.ok(olderButtons.every(({ purpose }) => purpose === COPY_IDENTIFIER));
  assert.equal((older.match(/<code>1A2B 3C4D … 4F2A 91C0<\/code>/g) || []).length, 4);
});

/* ---------- Escaping: every remote string the screens render ---------- */

const HOSTILE = `<img src=x onerror=alert(1)>"><svg onload=1></div>O'Brien`;
const ESCAPED_IMG = "&lt;img src=x onerror=alert(1)&gt;";
const ALLOWED_TAGS = new Set([
  "aside", "b", "button", "code", "dd", "div", "dl", "dt", "h2", "h3", "h4", "input", "label",
  "li", "ol", "p", "section", "span", "strong", "textarea", "ul",
]);

function assertInert(html, label) {
  assert.ok(html.includes(ESCAPED_IMG), `${label}: hostile text was rendered (escaped)`);
  assert.ok(!html.includes("O'Brien"), `${label}: raw single quote`);
  const attributes = html.match(/="[^"]*"/g) || [];
  for (const attribute of attributes) {
    assert.ok(!/[<>]/.test(attribute), `${label}: markup inside attribute ${attribute}`);
  }
  assert.ok(!html.replace(/="[^"]*"/g, "").includes('"'), `${label}: stray double quote`);
  for (const [, name] of html.matchAll(/<\/?([a-zA-Z0-9-]+)/g)) {
    assert.ok(ALLOWED_TAGS.has(name.toLowerCase()), `${label}: unexpected <${name}>`);
  }
  const opened = (html.match(/<div\b/g) || []).length;
  const closed = (html.match(/<\/div>/g) || []).length;
  assert.equal(opened, closed, `${label}: div balance`);
}

function hostileState(overrides = {}) {
  const card = {
    run_by: HOSTILE,
    location: HOSTILE,
    home_id: `did:key:${HOSTILE}${HOSTILE}`,
    provides: ["chain", "custody", HOSTILE],
    fingerprint: `${HOSTILE} … ${HOSTILE} ${HOSTILE}`,
  };
  const state = {
    section: "pools",
    summary: {
      threshold: THRESHOLD,
      term_presets_days: [182, 365, 730],
      runtime_issuer: HOSTILE,
      signing_key: { present: true, fingerprint: HOSTILE, fingerprint_full: HOSTILE },
      chain: { ready: true, network: HOSTILE, proof_sources: 3 },
      local_node: { provisioned: true, run_by: HOSTILE, location: HOSTILE, fingerprint: HOSTILE },
      pool_installed: false,
      pool: null,
      pool_problem: null,
    },
    loadedAt: Date.UTC(2026, 9, 26),
    step: "nodes",
    slots: [
      { kind: "home", runBy: HOSTILE, location: HOSTILE, restart: false },
      { kind: "card", text: "elastos-node-card:v1:aa", card },
      { kind: "card", text: "elastos-node-card:v1:bb", card },
    ],
    checks: null,
    checking: false,
    termDays: 365,
    sign: null,
    notice: null,
    keyBusy: false,
    verify: null,
    verifying: false,
    health: null,
    healthChecking: false,
    healthFailed: false,
    registering: new Set(),
    ...overrides,
  };
  const results = ["members", "keys", "homes", "run_by", "location", "this_home", "roles", "copies"]
    .map((id) => ({ id, result: id === "copies" ? "advice" : "fail", names: [HOSTILE, HOSTILE], detail: HOSTILE }));
  state.checks = { key: createView(state).checkKey(), shares: [1, 2, 3], results };
  return state;
}

test("every screen renders remote text inert", () => {
  const html = (overrides) => createView(hostileState(overrides)).poolsMarkup();
  assertInert(html({ step: "prepare" }), "prepare");
  assertInert(html({ step: "prepare", notice: { tone: "danger", line: HOSTILE, reason: HOSTILE } }), "plain-text error");
  assertInert(html({ step: "nodes" }), "add nodes");
  assertInert(html({
    step: "nodes",
    slots: [
      { kind: "include", runBy: HOSTILE, location: HOSTILE, invalid: false, error: HOSTILE, busy: false },
      { kind: "empty", text: HOSTILE, error: HOSTILE, note: HOSTILE, retry: true },
      { kind: "refused", line: HOSTILE },
    ],
  }), "slot forms and refusals");
  const notServing = hostileState({ step: "nodes" });
  notServing.summary.local_node.running = false;
  assertInert(createView(notServing).poolsMarkup(), "this Home restart needed");
  for (const code of ["bad_address", "unreachable", "not_owner", "no_card", "own_card"]) {
    const refused = fetchRefusal({ code, detail: HOSTILE });
    assertInert(html({
      step: "nodes",
      slots: [
        { kind: "reading", text: HOSTILE, address: HOSTILE, token: 1 },
        { kind: "refused", ...refused, address: HOSTILE },
        { kind: "empty", text: HOSTILE, error: HOSTILE, note: "" },
      ],
    }), `fetch ${code}`);
  }
  const review = html({ step: "review" });
  assertInert(review, "review");
  // The member rows put the Home ID in a key field's attributes.
  assert.match(review, /data-value="did:key:&lt;img src=x onerror=alert\(1\)&gt;&quot;&gt;/);
  assertInert(html({
    step: "sign",
    sign: { phase: "registration", fingerprint: HOSTILE, fingerprintFull: HOSTILE, failed: [{ share: 2, ok: false, reason: HOSTILE }] },
  }), "sign registration");
  assertInert(html({ step: "sign", sign: { phase: "failed", reason: HOSTILE } }), "sign failed");
  assertInert(html({ step: "sign", sign: { phase: "stopped", view: { line: HOSTILE, reason: HOSTILE } } }), "sign stopped");
  assertInert(html({ step: "sign", sign: { phase: "cancelled", message: HOSTILE } }), "sign cancelled");

  const now = Date.now() / 1000;
  const member = (share, registered) => ({
    share, run_by: HOSTILE, location: HOSTILE, home_id: HOSTILE, provides: ["custody", HOSTILE],
    this_home: share === 1, registered,
  });
  const installed = (pool, problem) => ({
    step: "active",
    summary: {
      ...hostileState().summary,
      pool_installed: true,
      pool,
      pool_problem: problem,
    },
  });
  const pool = {
    members: [member(1, true), member(2, false), member(3, true)],
    term: { start: now - 86_400, end: now + 400 * 86_400, days: 365 },
    threshold: THRESHOLD,
    fingerprint: HOSTILE,
    fingerprint_full: HOSTILE,
    cards_kept: true,
  };
  assertInert(html(installed(pool, null)), "active members");
  assertInert(html(installed({ ...pool, cards_kept: false }, null)), "active terminal pool");
  const restart = installed({ ...pool, members: [member(1, true)] }, null);
  restart.summary.local_node = { ...restart.summary.local_node, running: false };
  assertInert(html(restart), "active restart needed");
  assertInert(html(installed(null, { code: "verify_failed", detail: HOSTILE })), "pool problem");

  // A node's reason is remote text from another Home.
  const hostileHealth = (status, online) => readHealth({
    status,
    online,
    required: THRESHOLD.required,
    total: THRESHOLD.total,
    checked_at: 1_793_000_000,
    members: [
      { share: 1, state: "refused", detail: HOSTILE },
      { share: 2, state: "not_answering", detail: HOSTILE },
      { share: 3, state: "different_node", detail: HOSTILE },
    ],
  });
  for (const [status, online] of [["healthy", 3], ["at_risk", 2], ["down", 0]]) {
    const health = hostileHealth(status, online);
    assertInert(html({ ...installed(pool, null), health }), `active health ${status}`);
    assertInert(html({ ...installed(pool, null), health, healthChecking: true }), `active health ${status} checking`);
    assertInert(html({ ...installed(pool, null), health, healthFailed: true }), `active health ${status} failed`);
  }
  assertInert(html({ ...installed(pool, null), healthChecking: true }), "active health first check");
  // The clipped reason is escaped too.
  const long = hostileHealth("down", 0);
  long.members[0].detail = HOSTILE.repeat(20);
  assertInert(html({ ...installed(pool, null), health: long }), "active health long reason");

  // Hosting: the owner's DID or name, the node's labels, fingerprint and
  // address all come from files and other Homes.
  const hostileServing = {
    owner_did: HOSTILE,
    owner_name: null,
    run_by: HOSTILE,
    location: HOSTILE,
    provides: ["custody", HOSTILE],
    fingerprint: HOSTILE,
    fingerprint_full: HOSTILE,
    provider_running: false,
    last_owner_contact: null,
  };
  const hosting = (serving, address) => createView(hostingState(serving, address)).hostingMarkup();
  const byDid = hosting(hostileServing, HOSTILE);
  assertInert(byDid, "hosting serving by owner DID");
  // The DID, fingerprint and address sit in key fields' attributes too.
  assert.equal((byDid.match(/data-value="&lt;img src=x onerror=alert\(1\)&gt;&quot;&gt;/g) || []).length, 6);
  assertInert(hosting({ ...hostileServing, owner_name: HOSTILE, provider_running: true, last_owner_contact: 1_793_000_000 }, HOSTILE),
    "hosting serving by owner name");
  assertInert(hosting(null, HOSTILE), "hosting address only");
  // The offer's labels are the admin's own, but Runtime sends them back.
  const hostileOffer = {
    enabled: false, run_by: HOSTILE, location: HOSTILE, provides: ["custody", HOSTILE],
    holds_custody_state: true, messages_enabled: false,
  };
  const offerHtml = createView(offerState(hostileOffer, {
    runBy: HOSTILE, location: HOSTILE, invalid: true, notice: { line: HOSTILE, reason: HOSTILE },
  })).hostingMarkup();
  assertInert(offerHtml, "hosting offer");
  assert.ok(!offerHtml.includes("<img"), "hosting offer: raw <img>");
  assertInert(createView(offerState(null, { failed: { line: HOSTILE, reason: HOSTILE } })).hostingMarkup(), "hosting offer unread");
  const nodeHome = hostileState({ step: "prepare", notice: { tone: "danger", line: HOSTILE, reason: HOSTILE } });
  nodeHome.summary.serving = hostileServing;
  assertInert(createView(nodeHome).poolsMarkup(), "pools on a node Home");
  assertInert(html({
    step: "nodes",
    slots: [includeDraft({ local_profile_name: HOSTILE }), { kind: "empty", text: "", error: "", note: "" }, { kind: "refused", line: HOSTILE }],
  }), "include form prefilled from the Profile name");
});

test("verifyFailure marks the pool failed only on the Runtime's verify_failed", () => {
  const failed = verifyFailure({ code: "verify_failed", detail: "term ended" });
  assert.deepEqual(failed.verify, {
    ok: false,
    view: { line: "The installed pool did not pass the Runtime check: term ended.", reason: "" },
  });
  assert.equal(failed.notice, null);
  for (const error of [
    { text: "admin passkey required" },
    { unavailable: true },
    { code: "no_pool", detail: null },
  ]) {
    const outcome = verifyFailure(error);
    assert.equal(outcome.verify, null);
    assert.equal(outcome.notice.tone, "danger");
    assert.equal(outcome.notice.line, errorView(error).line);
  }
});

/* ---------- Pool active: members told they are in the pool ---------- */

const POOL_END = 1_824_536_000;
const POOL_WAITING_LINE = "Waiting for the owner to confirm the pool.";

function servedPool(overrides = {}) {
  return {
    share: 2,
    total: 3,
    required: 2,
    pool_start: 1_793_000_000,
    term_end: POOL_END,
    members: [
      { share: 1, run_by: "Ann", location: "Lisbon" },
      { share: 2, run_by: "Bob", location: "Porto" },
      { share: 3, run_by: "Carol", location: "Kyiv" },
    ],
    ...overrides,
  };
}

test("readServedPool reads the pool a served node is in, or nothing", () => {
  assert.equal(readServing(servingSummary()).pool, null);
  for (const value of [null, undefined, [], "pool", {}, servedPool({ share: 0 }), servedPool({ share: 4 }), servedPool({ required: "2" }), servedPool({ term_end: -1 })]) {
    assert.equal(readServedPool(value), null, JSON.stringify(value));
  }
  assert.deepEqual(readServing(servingSummary({ pool: servedPool() })).pool, {
    share: 2,
    total: 3,
    required: 2,
    poolStart: 1_793_000_000_000,
    termEnd: POOL_END * 1000,
    members: [
      { share: 1, runBy: "Ann", location: "Lisbon" },
      { share: 2, runBy: "Bob", location: "Porto" },
      { share: 3, runBy: "Carol", location: "Kyiv" },
    ],
  });
});

test("the Serving card shows the pool once its owner confirms it", () => {
  const waiting = createView(hostingState(servingSummary())).hostingMarkup();
  assert.ok(waiting.includes(POOL_WAITING_LINE));
  assert.equal(waiting.split(POOL_WAITING_LINE).length, 2, "one line");

  const html = createView(hostingState(servingSummary({ pool: servedPool() }))).hostingMarkup();
  assert.ok(!html.includes(POOL_WAITING_LINE));
  assert.ok(html.includes("Share 2 of 3 · 2 needed"));
  assert.ok(html.includes(`Until ${formatDate(POOL_END * 1000)}`));
  for (const text of ["Ann", "Lisbon", "Bob", "Porto", "Carol", "Kyiv"]) {
    assert.ok(html.includes(text), text);
  }
  const hostile = servedPool({ members: [{ share: 1, run_by: HOSTILE, location: HOSTILE }] });
  assertInert(createView(hostingState(servingSummary({ pool: hostile }))).hostingMarkup(), "served pool");
});

test("noticeLine says whether each member was told", () => {
  const line = (state, code = "") => noticeLine({ share: 1, name: "", state, code });
  assert.deepEqual(line("delivered"), { word: "Told", tone: "ok" });
  assert.deepEqual(line("pending"), { word: "Not told yet", tone: "pending" });
  assert.deepEqual(line("refused", "not_member"), { word: "Could not tell (not_member)", tone: "danger" });
  assert.deepEqual(line("skipped", "this_home"), { word: "This Home", tone: "accent" });
  assert.deepEqual(line("skipped", "not_contact"), { word: "Not a contact", tone: "" });
});

test("a waiting notice says when this Home's custody messages are off", () => {
  const off = (state, code = "") =>
    noticeLine({ share: 1, name: "", state, code }, { messagesOff: true });
  assert.deepEqual(off("pending"), {
    word: "Waiting: custody messages are off on this Home",
    tone: "pending",
    hint: "Enable custody messages in Hosting first.",
  });
  // Every other state keeps its words.
  assert.deepEqual(off("delivered"), { word: "Told", tone: "ok" });
  assert.deepEqual(off("refused", "not_member"), { word: "Could not tell (not_member)", tone: "danger" });
  assert.deepEqual(off("skipped", "this_home"), { word: "This Home", tone: "accent" });
  assert.deepEqual(off("skipped", "not_contact"), { word: "Not a contact", tone: "" });
});

function poolNotices(members) {
  return { fingerprint_full: NODE_FINGERPRINT_FULL, members };
}

test("readPoolNotices keeps known states only", () => {
  assert.equal(readPoolNotices(null), null);
  assert.equal(readPoolNotices([]), null);
  assert.deepEqual(readPoolNotices(poolNotices([
    { share: 1, state: "skipped", code: "this_home" },
    { share: 2, recipient_name: " Bob ", state: "delivered" },
    { share: 3, state: HOSTILE },
    { share: "4", state: "pending" },
  ])), {
    fingerprintFull: NODE_FINGERPRINT_FULL,
    members: [
      { share: 1, name: "", state: "skipped", code: "this_home" },
      { share: 2, name: "Bob", state: "delivered", code: "" },
    ],
  });
});

test("the Active pool says who was told, and Notify members again waits while it runs", () => {
  const state = activeState();
  state.summary.pool_notices = poolNotices([
    { share: 1, state: "skipped", code: "this_home" },
    { share: 2, recipient_name: "McKaya", state: "delivered" },
    { share: 3, recipient_name: "Ter", state: "refused", code: "not_member" },
    { share: 4, recipient_name: "Una", state: "pending" },
    { share: 5, state: "skipped", code: "not_contact" },
  ]);
  const html = createView(state).poolsMarkup();
  for (const word of ["This Home", "Told", "Could not tell (not_member)", "Not told yet", "Not a contact"]) {
    assert.ok(html.includes(word), word);
  }
  assert.match(html, /<button class="cp-btn cp-btn-sm" type="button" data-action="notify-members">Notify members again<\/button>/);
  state.notifying = true;
  assert.match(createView(state).poolsMarkup(), /data-action="notify-members" disabled>Notify members again</);
  state.summary.pool_notices = poolNotices([{ share: 2, recipient_name: HOSTILE, state: "refused", code: HOSTILE }]);
  assertInert(createView(state).poolsMarkup(), "pool notices");
  // A pool without notices shows none, and no button.
  state.summary.pool_notices = null;
  assert.doesNotMatch(createView(state).poolsMarkup(), /notify-members/);
});

test("waiting notices name this Home's custody messages only when the offer read says they are off", () => {
  const state = activeState();
  state.summary.pool_notices = poolNotices([
    { share: 2, recipient_name: "McKaya", state: "delivered" },
    { share: 4, recipient_name: "Una", state: "pending" },
  ]);
  const waiting = "Waiting: custody messages are off on this Home";
  const hint = "Enable custody messages in Hosting first.";
  // Not read yet, or on: the usual words.
  for (const view of [null, readOffer({ enabled: false, messages_enabled: true })]) {
    state.offer = { view };
    const html = createView(state).poolsMarkup();
    assert.ok(html.includes("Not told yet"));
    assert.ok(!html.includes(waiting));
    assert.ok(!html.includes(hint));
  }
  state.offer = { view: readOffer({ enabled: false, messages_enabled: false }) };
  const html = createView(state).poolsMarkup();
  assert.ok(html.includes(waiting));
  assert.ok(html.includes(`<p class="cp-help">${hint}</p>`));
  assert.ok(html.includes("Told"));
  assert.ok(!html.includes("Not told yet"));
});

test("Notify members again sends one request at a time", async () => {
  let release;
  const gate = new Promise((resolve) => {
    release = resolve;
  });
  const posted = [];
  const notify = notifyOnce(async (body) => {
    posted.push(body);
    await gate;
    return poolNotices([{ share: 2, recipient_name: "Bob", state: "delivered" }]);
  });
  const first = notify();
  assert.equal(notify(), null, "a second press while one runs sends nothing");
  release();
  const result = await first;
  assert.deepEqual(posted, [{}]);
  assert.equal(result.notices.members[0].state, "delivered");
  const failing = notifyOnce(async () => {
    throw Object.assign(new Error("no_pool"), { code: "no_pool", detail: "" });
  });
  const failed = await failing();
  assert.ok(failed.notice.line);
  // Once it settled, the button sends again.
  assert.notEqual(notify(), null);
});

// ---------------------------------------------------------------------------
// Plan B T4.3: the pool address and the pools this Home uses.
// ---------------------------------------------------------------------------

const POOL_ADDRESS = `elastos-pool:${"AbC-_9".repeat(40)}`;

test("renders_known_pools_and_add_form", () => {
  const state = activeState();
  state.knownPools = {
    pools: readKnownPools({
      pools: [
        {
          pool: "did:key:z6MkPoolOneAbcdefghijklmnopqrstuvwx",
          address: POOL_ADDRESS,
          sequence: 3,
          members: 3,
          servers: 2,
          expires_at: Date.UTC(2027, 0, 15) / 1000,
          fetched_at: 1,
        },
        { pool: HOSTILE, address: HOSTILE, servers: 1, expires_at: 0 },
        { pool: "", address: "x", servers: 1 },
      ],
    }),
    failed: false,
  };
  state.poolAdd = { address: HOSTILE, busy: false, error: "", added: "" };
  const html = createView(state).poolsMarkup();
  const card = html.slice(html.indexOf('aria-labelledby="known-pools-title"'));
  assert.ok(card.length > 0, "the Pools screen ends with the pools this Home uses");
  assert.match(card, />Pools this Home uses</);
  assert.ok(card.includes(KNOWN_POOLS_LINE));
  assert.equal(KNOWN_POOLS_LINE, "Add a pool to mint into it, and to buy and play items that its nodes keep.");
  // Two readable pools; the row without a pool is left out.
  assert.equal((card.match(/class="cp-row" role="listitem"/g) || []).length, 2);
  assert.match(card, />2 servers</);
  assert.match(card, />1 server</);
  assert.match(card, /Until /);
  assert.match(card, /<label for="pool-address">Pool address<\/label><input class="cp-input" id="pool-address"/);
  assert.match(card, /data-field="pool-address"/);
  assert.match(card, /data-action="add-pool">Add a pool</);
  assert.ok(!card.includes(HOSTILE), "every value is escaped");

  // Before any pool: one line, and the form.
  state.knownPools = { pools: [], failed: false };
  state.poolAdd = { address: "", busy: true, error: "", added: "" };
  const empty = createView(state).poolsMarkup();
  assert.match(empty, /This Home uses no other pool yet\./);
  assert.match(empty, /data-action="add-pool" disabled>Add a pool</);
  state.knownPools = { pools: [], failed: true };
  assert.match(createView(state).poolsMarkup(), /could not be read/);

  // A Home without its own pool shows the card too.
  const preparing = hostileState({ step: "prepare" });
  assert.match(createView(preparing).poolsMarkup(), />Pools this Home uses</);
  assert.equal(KNOWN_POOL_ADD_OPERATION, "custody.known_pool.add");
});

test("copy_pool_address_from_owner_card", () => {
  const state = activeState();
  assert.doesNotMatch(createView(state).poolsMarkup(), /Pool address<\/dt>/);
  state.summary.pool_address = POOL_ADDRESS;
  const html = createView(state).poolsMarkup();
  assert.match(html, /<dt>Pool address<\/dt>/);
  const button = html.match(/<button class="cp-copy"[^>]*data-purpose="custody\.pool_address"[^>]*>/)?.[0] || "";
  assert.ok(button, "the owner card copies its pool address");
  assert.ok(button.includes(`data-value="${POOL_ADDRESS}"`), "Copy sends the whole address");
  assert.match(button, /aria-label="Copy pool address"/);
  assert.equal(COPY_POOL_ADDRESS, "custody.pool_address");
  // Home accepts this value for this purpose, and only a pool address.
  assert.ok(homeClipboardValidPayload("custody", COPY_POOL_ADDRESS, "write", POOL_ADDRESS));
  assert.equal(homeClipboardValidPayload("custody", COPY_POOL_ADDRESS, "write", "did:key:z6Mk"), false);
});

test("add_pool_refusal_codes_show_own_words", () => {
  const lines = ["bad_address", "pool_unreachable", "pool_invalid", "too_many_pools"].map(knownPoolRefusalLine);
  assert.equal(new Set(lines).size, 4, "each refusal has its own words");
  assert.match(lines[0], /not a pool address/);
  assert.match(lines[1], /did not answer/);
  assert.match(lines[2], /could not be checked/);
  assert.match(lines[3], /as many pools as it can/);
  for (const line of lines) {
    assert.doesNotMatch(line, /bad_address|pool_unreachable|pool_invalid|too_many_pools/);
  }
  assert.equal(knownPoolRefusalLine("teapot"), "The pool was not added. Try again.");
  assert.equal(knownPoolRefusalLine(undefined), "The pool was not added. Try again.");

  // The error shows under the form, with the address kept.
  const state = activeState();
  state.poolAdd = { address: "elastos-pool:abc", busy: false, error: lines[1], added: "" };
  const html = createView(state).poolsMarkup();
  assert.match(html, /role="alert">The pool did not answer\./);
  assert.match(html, /value="elastos-pool:abc" aria-invalid="true"/);
});

// #388 A1: an everyday Home takes no Hosting role; Custody says why.
test("host_trust_required maps to its custody copy", () => {
  assert.equal(HOST_TRUST_REQUIRED_LINE, "This Home is not set up as a WCI-operated host.");
  assert.deepEqual(errorView({ code: "host_trust_required", detail: "operator setting" }), {
    line: "This Home is not set up as a WCI-operated host.",
    reason: "",
  });
});
