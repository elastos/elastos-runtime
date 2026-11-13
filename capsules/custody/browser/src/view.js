// The Custody app's view: what the draft and summary mean (filled slots,
// fresh checks, whether Review may open) and the markup for every screen.
// No DOM and no requests, so custody.test.mjs can render each screen from a
// state object. Every value from the Runtime or a card passes escapeHtml.
import {
  CHAIN_MISSING_LINE,
  COPY_FINGERPRINT,
  COPY_IDENTIFIER,
  COPY_POOL_ADDRESS,
  DAY_MS,
  FIND_BUSY_LINE,
  FIX_CHECKS_LINE,
  HEALTH_CHECKING_LINE,
  HEALTH_FAILED_LINE,
  HOLDS_CUSTODY_LINE,
  INSTALL_FAILED_LINE,
  KEY_MISSING_LINE,
  KNOWN_POOLS_LINE,
  NEEDS_UPDATE_LINE,
  NO_CONTACTS_LINE,
  NO_OFFERS_LINE,
  POOL_WAITING_LINE,
  REFUSAL_LINES,
  TERMINAL_POOL_LINE,
  UNAVAILABLE_LINE,
  activeBanner,
  arrayValue,
  askAgainTarget,
  checkLine,
  checkTitle,
  checkedText,
  errorView,
  escapeHtml,
  fingerprintTail,
  formatDate,
  healthChip,
  healthLine,
  installSlots,
  memberHealth,
  middleTruncate,
  noticeLine,
  objectValue,
  ownerContactLine,
  readNodeRequests,
  readPoolNotices,
  readServing,
  readOwnPool,
  PUBLISHER_NOTE,
  servedPoolStatusChip,
  sharesHeldLine,
  SERVING_ATTENTION_LINE,
  readText,
  requestStatus,
  rolesText,
  servedPoolLine,
  servingStatus,
  slotCount,
  slotForContact,
  termChangedLine,
  termEnd,
  termLabel,
  termPresets,
  validLabel,
} from "./model.js?v=custody-20261113e";

const TERM_ENDING_DAYS = 30;
const ONE_POOL_LINE = "Content you published is bound to this pool’s nodes, so a second pool would leave it without keys. Replacing a pool comes in a later version.";
const RULE_CHECKS = ["members", "keys", "homes", "run_by", "location", "this_home", "roles", "copies"];
const RUN_BY_HELP = "Who runs this machine. Each node should be run by someone different.";
const LOCATION_HELP = "Where this machine runs. Each node should be in a different place.";
const SERVING_TITLE = "This Home holds a key share for";
const ADDRESS_LABEL = "This Home's node address";
const SEND_ADDRESS_LINE = "Send this to the pool owner. Your node gives its card only to the Home it trusts.";
const OWNER_DECIDES_LINE = "The pool owner decides the pool and its term. This Home sees its own share only.";
// v1 keeps one custody state per Home, and a node Home's state trusts the
// other owner.
// Find nodes: what each contact's status means for this pool.
const FOUND_STATUS_LINES = Object.freeze({
  not_offering: "Not offering custody",
  unreachable: "Not reachable right now",
  needs_update: NEEDS_UPDATE_LINE,
});
const OFFER_SWITCH_LABEL = "Offer custody to my contacts";
const OFFER_PRIVACY_LINE = "Your contacts can see that this Home offers custody, with its Run by, Location and roles.";
const MESSAGES_OFF_LINE = "Custody messages are off. Contacts cannot send this Home requests until you enable them.";

// The view reads `state` as the app holds it; it never changes it.
export function createView(state) {
  function prepareReady() {
    const summary = objectValue(state.summary);
    return summary.signing_key?.present === true && summary.chain?.ready === true;
  }

  // This Home's node is set up but its provider is not serving yet. Read from
  // the summary, so it survives a reload.
  function homeNeedsRestart() {
    const local = objectValue(state.summary?.local_node);
    return local.provisioned === true && local.running === false;
  }

  function slotNeedsRestart(slot) {
    return slot.kind === "home" && (slot.restart === true || homeNeedsRestart());
  }

  function homeSlotIndex() {
    return state.slots.findIndex((slot) => ["home", "include", "setup"].includes(slot.kind));
  }

  // What one slot sends to check and install, or null while it is not filled.
  function slotInput(slot) {
    if (slot.kind === "home") {
      return { this_home: true };
    }
    if (slot.kind === "card") {
      return { card: slot.text };
    }
    return null;
  }

  function filledCount() {
    return state.slots.filter((slot) => slotInput(slot)).length;
  }

  function checkKey() {
    return JSON.stringify(state.slots.map(slotInput));
  }

  function freshChecks() {
    return state.checks && state.checks.key === checkKey() && !state.checking ? state.checks.results : null;
  }

  function ruleResults() {
    const results = freshChecks() || [];
    return RULE_CHECKS.map((id) => results.find((result) => result?.id === id)).filter(Boolean);
  }

  // Failed rules shown as failures. While slots are empty the member count is
  // still to come, not a failure.
  function failedRules() {
    const partial = filledCount() < slotCount(state.summary?.threshold);
    return ruleResults().filter((result) => result.result === "fail" && !(partial && result.id === "members"));
  }

  function reviewReady() {
    return Boolean(installSlots(state.slots)) && Boolean(freshChecks()) && failedRules().length === 0;
  }

  // A slot named by a failed rule: names are Run by, or Locations for run_by.
  function slotFailsCheck(slot) {
    const runBy = slot.kind === "card" ? readText(slot.card?.run_by) : (slot.kind === "home" ? slot.runBy : "");
    const location = slot.kind === "card" ? readText(slot.card?.location) : (slot.kind === "home" ? slot.location : "");
    if (!runBy) {
      return false;
    }
    return failedRules().some((result) => result.id !== "members"
      && arrayValue(result.names).includes(result.id === "run_by" ? location : runBy));
  }

  function shareName(share) {
    const member = arrayValue(state.summary?.pool?.members).find((entry) => entry?.share === share);
    const slot = state.slots[share - 1];
    return readText(member?.run_by)
      || readText(slot?.card?.run_by)
      || (slot?.kind === "home" ? slot.runBy : "")
      || `Share ${share}`;
  }

  // Every Pools screen ends with the pools this Home uses (Plan B T4.3).
  function poolsMarkup() {
    const main = ownPoolMarkup();
    return state.summary ? `${main}${knownPoolsMarkup()}` : main;
  }

  function ownPoolMarkup() {
    const summary = state.summary;
    if (!summary) {
      return bannerMarkup(state.notice);
    }
    if (summary.pool_installed === true && state.step !== "sign") {
      return activeMarkup(summary);
    }
    switch (state.step) {
      case "nodes":
        return nodesMarkup(summary);
      case "review":
        return reviewMarkup(summary);
      case "sign":
        return signMarkup(summary);
      default:
        return prepareMarkup(summary);
    }
  }

  function bannerMarkup(banner) {
    if (!banner?.line) {
      return "";
    }
    const tone = banner.tone ? ` data-tone="${escapeHtml(banner.tone)}"` : "";
    const head = banner.strong ? `<strong>${escapeHtml(banner.strong)}</strong> ` : "";
    const reason = banner.reason ? `<span class="cp-banner-reason">${escapeHtml(banner.reason)}</span>` : "";
    return `<p class="cp-banner" role="status"${tone}>${head}${escapeHtml(banner.line)}${reason}</p>`;
  }

  function stepperMarkup(current, { blocked = false, subs = {} } = {}) {
    const steps = [
      ["prepare", "Prepare"],
      ["nodes", "Add nodes"],
      ["review", "Review"],
      ["sign", "Sign"],
      ["active", "Active"],
    ];
    const currentIndex = steps.findIndex(([id]) => id === current);
    return `<ol class="cp-steps" aria-label="Pool setup">${steps.map(([id, label], index) => {
      const stepState = index < currentIndex ? "done" : index > currentIndex ? "todo" : (blocked ? "blocked" : "current");
      const sub = subs[id] ? `<span class="cp-step-sub">${escapeHtml(subs[id])}</span>` : "";
      const aria = index === currentIndex ? ' aria-current="step"' : "";
      return `<li class="cp-step" data-state="${stepState}"${aria}><span class="cp-step-bar"></span><span class="cp-step-label">${escapeHtml(label)}</span>${sub}</li>`;
    }).join("")}</ol>`;
  }

  function stepSubs(summary) {
    const total = slotCount(summary.threshold);
    const failed = failedRules().length;
    return {
      prepare: summary.signing_key?.present === true ? "Key ready" : "Key not created",
      nodes: failed ? `${failed} check failed` : `${filledCount()} of ${total} filled`,
      review: reviewReady() ? "All checks passed" : "",
    };
  }

  // Copy always sends the full value; only the display is truncated. `copy`
  // is that value when it differs from the shown one, such as a fingerprint's
  // whole digest; without it there is no Copy, never a copy of the short form.
  function keyFieldMarkup(value, label, { tail = 8, purpose = COPY_IDENTIFIER, copy = value } = {}) {
    const text = readText(value);
    if (!text) {
      return "";
    }
    const full = readText(copy);
    const button = full
      ? `<button class="cp-copy" type="button" data-action="copy" data-value="${escapeHtml(full)}" data-purpose="${escapeHtml(purpose)}" aria-label="Copy ${escapeHtml(label)}"></button>`
      : "";
    return `<span class="cp-key" title="${escapeHtml(full || text)}"${full ? ` data-value="${escapeHtml(full)}"` : ""}><code>${escapeHtml(middleTruncate(text, 12, tail))}</code>${button}</span>`;
  }

  // A fingerprint shows its short form and copies its whole digest.
  function fingerprintFieldMarkup(short, full, label) {
    return keyFieldMarkup(short, label, { purpose: COPY_FINGERPRINT, copy: readText(full) });
  }

  function chipMarkup(text, tone = "", stale = false) {
    const toneAttr = tone ? ` data-tone="${escapeHtml(tone)}"` : "";
    return `<span class="cp-chip"${toneAttr}${stale ? ' data-stale="true"' : ""}>${escapeHtml(text)}</span>`;
  }

  function prepareMarkup(summary) {
    const threshold = objectValue(summary.threshold);
    const key = objectValue(summary.signing_key);
    const chain = objectValue(summary.chain);
    const keyReady = key.present === true;
    const chainReady = chain.ready === true;
    const help = !keyReady ? KEY_MISSING_LINE : (!chainReady ? CHAIN_MISSING_LINE : "");
    const keyRow = keyReady
      ? `<div class="cp-row"><div><p class="cp-prep-title">Pool signing key ${chipMarkup("Ready", "ok")}</p><p class="cp-prep-line">Kept on this Home only. Losing it blocks renewing the pool later.</p>${key.fingerprint ? `<p class="cp-prep-value">${fingerprintFieldMarkup(key.fingerprint, key.fingerprint_full, "pool signing key fingerprint")}</p>` : ""}</div><div></div></div>`
      : `<div class="cp-row"><div><p class="cp-prep-title">Pool signing key ${chipMarkup("Not created", "pending")}</p><p class="cp-prep-line">Signs your pool. It is kept on this Home only.</p></div><button class="cp-btn" type="button" data-action="create-key"${state.keyBusy ? " disabled" : ""}>Create pool signing key</button></div>`;
    const chainRow = chainReady
      ? `<div class="cp-row"><div><p class="cp-prep-title">Chain network ${chipMarkup(readText(chain.network) || "Base", "ok")}</p><p class="cp-prep-line">${escapeHtml(`${Number(chain.proof_sources) || 0} proof sources.`)}</p></div><div></div></div>`
      : `<div class="cp-row"><div><p class="cp-prep-title">Chain network ${chipMarkup("Not set up", "pending")}</p><p class="cp-prep-line">${escapeHtml(CHAIN_MISSING_LINE)}</p></div><div></div></div>`;
    return `${bannerMarkup(state.notice)}
      ${stepperMarkup("prepare", { subs: stepSubs(summary) })}
      <p class="cp-desc cp-lead">${escapeHtml(`Your pool is ${slotCount(threshold)} Homes that each keep one share of your content’s key. Any ${threshold.required} can open it for a buyer.`)}</p>
      <div class="cp-list cp-prep">
        <div class="cp-row"><div><p class="cp-prep-title">Runtime issuer</p><p class="cp-prep-line">Node operators enter this when they set up a node for your pool.</p><p class="cp-prep-value">${keyFieldMarkup(summary.runtime_issuer, "Runtime issuer")}</p></div><div></div></div>
        ${keyRow}
        ${chainRow}
      </div>
      <div class="cp-footer">${help ? `<p class="cp-help">${escapeHtml(help)}</p>` : ""}<button class="cp-btn" type="button" data-action="go" data-step="nodes"${prepareReady() ? "" : " disabled"}>Add nodes</button></div>`;
  }

  // Before install a slot is a node: the signed epoch numbers shares by node
  // key, so a slot's place is not its share.
  function slotMarkup(slot, index) {
    const coord = `<span class="cp-slot-coord">Node ${index + 1}</span>`;
    const top = (chip) => `<div class="cp-slot-top">${coord}${chip}</div>`;
    const failAttr = slotFailsCheck(slot) ? ' data-check="fail"' : "";
    const actions = (buttons) => (buttons ? `<div class="cp-slot-actions">${buttons}</div>` : "");
    const remove = `<button class="cp-btn cp-btn-sm" type="button" data-action="remove" data-slot="${index}"${slot.busy ? " disabled" : ""}>Remove</button>`;
    switch (slot.kind) {
      case "reading":
        return `<div class="cp-slot" data-state="reading">${top(chipMarkup("Reading", "pending"))}<p class="cp-slot-line">${slot.address ? "Fetching the node card from the node…" : "Reading the node card…"}</p></div>`;
      case "card": {
        const card = objectValue(slot.card);
        const runBy = readText(card.run_by);
        const homeId = readText(card.home_id);
        const termLine = slot.requestId ? termChangedLine(slot.termDays, state.termDays) : "";
        const asked = slot.requestId && slot.termDays ? `<p class="cp-slot-line">${escapeHtml(`Asked for ${termLabel(slot.termDays)}`)}</p>` : "";
        return `<div class="cp-slot" data-state="filled"${failAttr}>${top(cardChip(slot))}
          <p class="cp-slot-name">${escapeHtml(runBy)}</p>
          <p class="cp-slot-where">${escapeHtml([readText(card.location), rolesText(card.provides)].filter(Boolean).join(" · "))}</p>
          ${homeId ? `<p class="cp-slot-id">Home <code title="${escapeHtml(homeId)}">${escapeHtml(middleTruncate(homeId))}</code></p>` : ""}
          <p class="cp-slot-fp">Confirm with ${escapeHtml(runBy)} that their card ends in <code>${escapeHtml(fingerprintTail(card.fingerprint))}</code>.</p>
          ${asked}
          ${termLine ? `<p class="cp-slot-reason" role="alert">${escapeHtml(termLine)}</p>` : ""}
          ${actions(`${termLine ? askAgainMarkup(slot, index) : ""}${remove}`)}</div>`;
      }
      case "request": {
        // Bound to a request sent to a contact; the chip follows its record.
        const record = objectValue(slot.record);
        const status = requestStatus(record);
        const live = record.state === "waiting" || record.state === "approved";
        const termLine = live ? termChangedLine(record.termDays, state.termDays) : "";
        const release = status.action
          ? `<button class="cp-btn cp-btn-sm${status.action === "cancel" ? " cp-btn-quiet" : ""}" type="button" data-action="request-release" data-slot="${index}">${status.action === "cancel" ? "Cancel" : "Find another"}</button>`
          : "";
        return `<div class="cp-slot" data-state="${status.tone === "danger" ? "refused" : "reading"}">${top(chipMarkup(status.word, status.tone))}
          <p class="cp-slot-name">${escapeHtml(record.name)}</p>
          <p class="cp-slot-where">${escapeHtml(`Asked for ${termLabel(record.termDays)}`)}</p>
          ${status.line ? `<p class="cp-slot-reason">${escapeHtml(status.line)}</p>` : ""}
          ${termLine ? `<p class="cp-slot-reason" role="alert">${escapeHtml(termLine)}</p>` : ""}
          ${actions(`${termLine ? askAgainMarkup(slot, index) : ""}${release}`)}</div>`;
      }
      case "home": {
        const restart = slotNeedsRestart(slot);
        const chip = restart ? chipMarkup("Restart needed", "pending") : chipMarkup("This Home", "accent");
        const line = restart
          ? "This Home's node is set up. Restart this Home to start it. You can sign the pool first."
          : "Local route: only one slot can be this Home.";
        return `<div class="cp-slot" data-state="${restart ? "restart" : "local"}"${failAttr}>${top(chip)}
          <p class="cp-slot-name">This Home</p>
          <p class="cp-slot-where">${escapeHtml(`Run by ${slot.runBy} · ${slot.location} · Custody and chain`)}</p>
          <p class="cp-slot-line">${escapeHtml(line)}</p>
          ${slot.error ? `<p class="cp-slot-reason" role="alert">${escapeHtml(slot.error)}</p>` : ""}
          ${actions(remove)}</div>`;
      }
      case "setup":
        return `<div class="cp-slot" data-state="reading">${top(chipMarkup("Setting up", "pending"))}<p class="cp-slot-name">This Home</p><p class="cp-slot-line">Creating this Home's node keys. They stay on this Home.</p></div>`;
      case "include": {
        const invalid = slot.invalid ? ' aria-invalid="true"' : "";
        const busy = slot.busy ? " disabled" : "";
        const problem = slot.invalid ? REFUSAL_LINES.bad_labels : slot.error;
        return `<div class="cp-slot" data-state="local">${top(chipMarkup("This Home", "accent"))}
          <div class="cp-field"><label for="run-by-${index}">Run by</label><input class="cp-input" id="run-by-${index}" type="text" autocomplete="off" data-field="run_by" data-slot="${index}" data-focus="run_by-${index}" aria-describedby="run-by-help-${index}" value="${escapeHtml(slot.runBy)}"${invalid}${busy}><p class="cp-help" id="run-by-help-${index}">${escapeHtml(RUN_BY_HELP)}</p></div>
          <div class="cp-field"><label for="location-${index}">Location</label><input class="cp-input" id="location-${index}" type="text" autocomplete="off" data-field="location" data-slot="${index}" data-focus="location-${index}" aria-describedby="location-help-${index}" value="${escapeHtml(slot.location)}"${invalid}${busy}><p class="cp-help" id="location-help-${index}">${escapeHtml(LOCATION_HELP)}</p></div>
          ${problem ? `<p class="cp-slot-reason" role="alert">${escapeHtml(problem)}</p>` : ""}
          <div class="cp-slot-actions"><button class="cp-btn cp-btn-sm" type="button" data-action="include-confirm" data-slot="${index}"${busy}>Include this Home</button><button class="cp-btn cp-btn-sm cp-btn-quiet" type="button" data-action="include-cancel" data-slot="${index}"${busy}>Cancel</button></div></div>`;
      }
      case "refused": {
        // A node that was down or refused may answer later: fetch it again.
        const again = slot.retry === true && slot.address
          ? `<button class="cp-btn cp-btn-sm" type="button" data-action="retry-fetch" data-slot="${index}" data-focus="refetch-${index}">Try again</button>`
          : "";
        return `<div class="cp-slot" data-state="refused">${top(chipMarkup("Refused", "danger"))}<p class="cp-slot-reason">${escapeHtml(slot.line)}</p>${slot.reason ? `<p class="cp-slot-line">${escapeHtml(slot.reason)}</p>` : ""}${actions(`${again}<button class="cp-btn cp-btn-sm${again ? " cp-btn-quiet" : ""}" type="button" data-action="retry-card" data-slot="${index}" data-focus="retry-${index}">Try another card</button>`)}</div>`;
      }
      default: {
        // A request that never reached Runtime: send the kept text again.
        const again = slot.retry === true && readText(slot.text)
          ? `<button class="cp-btn cp-btn-sm" type="button" data-action="retry-read" data-slot="${index}" data-focus="reread-${index}">Try again</button>`
          : "";
        const include = homeSlotIndex() < 0
          ? `<button class="cp-btn cp-btn-sm cp-btn-quiet" type="button" data-action="include-open" data-slot="${index}">Include this Home</button>`
          : "";
        const find = `<button class="cp-btn cp-btn-sm cp-btn-quiet" type="button" data-action="find-open" data-slot="${index}"${state.finder?.busy ? " disabled" : ""}>Find a node</button>`;
        return `<div class="cp-slot" data-state="drop" data-slot="${index}">${coord}
          <p class="cp-slot-line">${escapeHtml(slot.note || "Paste the node's address, or its node card.")}</p>
          <textarea class="cp-paste" aria-label="Node address or node card for node ${index + 1}" placeholder="Node address" spellcheck="false" data-field="card" data-slot="${index}" data-focus="paste-${index}">${escapeHtml(slot.text)}</textarea>
          ${slot.error ? `<p class="cp-slot-reason" role="alert">${escapeHtml(slot.error)}</p>` : ""}
          <div class="cp-slot-actions">${again}<button class="cp-btn cp-btn-sm${again ? " cp-btn-quiet" : ""}" type="button" data-action="choose-file" data-slot="${index}">Choose file</button>${find}${include}</div></div>`;
      }
    }
  }

  // A node that approved another term can be asked again for this one.
  function askAgainMarkup(slot, index) {
    if (!askAgainTarget(slot)) {
      return "";
    }
    const busy = state.askingAgain?.has(index) ? " disabled" : "";
    return `<button class="cp-btn cp-btn-sm" type="button" data-action="ask-again" data-slot="${index}"${busy}>${escapeHtml(`Ask again for ${termLabel(state.termDays)}`)}</button>`;
  }

  // One Review row per node slot, in the Active member list's row markup.
  // Review opens only when every slot holds a read card or this Home.
  function reviewMemberMarkup(slot, index) {
    const failAttr = slotFailsCheck(slot) ? ' data-check="fail"' : "";
    const row = (name, chips, lines) => `<div class="cp-row" role="listitem"${failAttr}><span class="cp-avatar" aria-hidden="true">${escapeHtml(name.slice(0, 1).toUpperCase())}</span><div><h4 class="cp-row-title">${escapeHtml(name)}</h4><div class="cp-row-meta">${chipMarkup(`Node ${index + 1}`)}${chips}</div>${lines}</div></div>`;
    if (slot.kind === "card") {
      const card = objectValue(slot.card);
      const runBy = readText(card.run_by);
      const location = readText(card.location);
      const roles = rolesText(card.provides);
      const homeId = readText(card.home_id);
      const termLine = slot.requestId ? termChangedLine(slot.termDays, state.termDays) : "";
      return row(runBy, [
        location ? chipMarkup(location) : "",
        roles ? chipMarkup(roles) : "",
        cardChip(slot),
      ].join(""), `${homeId ? `<p class="cp-row-line cp-row-id">Home ${keyFieldMarkup(homeId, "Home ID", { tail: 6 })}</p>` : ""}
        <p class="cp-row-line">Confirm with ${escapeHtml(runBy)} that their card ends in <code>${escapeHtml(fingerprintTail(card.fingerprint))}</code>.</p>
        ${termLine ? `<p class="cp-row-note" data-tone="pending">${escapeHtml(termLine)}</p>` : ""}`);
    }
    if (slot.kind === "home") {
      const restart = slotNeedsRestart(slot);
      const line = restart
        ? "This Home's node is set up. Restart this Home to start it. You can sign the pool first."
        : "Local route: only one slot can be this Home.";
      return row("This Home", [
        chipMarkup(`Run by ${slot.runBy}`),
        chipMarkup(slot.location),
        chipMarkup("Custody and chain"),
        chipMarkup("This Home", "accent"),
        restart ? chipMarkup("Restart needed", "pending") : "",
      ].join(""), `<p class="cp-row-line">${escapeHtml(line)}</p>`);
    }
    return "";
  }

  function slotsMarkup() {
    return `<div class="cp-quorum-slots" data-slot-count="${state.slots.length}">${state.slots.map(slotMarkup).join("")}</div>${finderMarkup()}`;
  }

  // A card from an approval names who approved it; a pasted one says read.
  function cardChip(slot) {
    return slot.approvedBy ? chipMarkup(`Approved by ${slot.approvedBy}`, "ok") : chipMarkup("Card read", "ok");
  }

  // Find a node: the contacts the finder asked, for one empty slot at a time.
  function finderMarkup() {
    const finder = state.finder;
    if (!finder || state.slots[finder.slot]?.kind !== "empty") {
      return "";
    }
    const title = `Find node ${finder.slot + 1}`;
    const alert = (shown) => (shown?.line
      ? `<p class="cp-slot-reason" role="alert">${escapeHtml(shown.line)}</p>${shown.reason ? `<p class="cp-help">${escapeHtml(shown.reason)}</p>` : ""}`
      : "");
    let body = "";
    if (finder.busy) {
      body = `<p class="cp-help" role="status">${escapeHtml(FIND_BUSY_LINE)}</p>`;
    } else if (finder.failed) {
      body = `${alert(finder.failed)}<div><button class="cp-btn cp-btn-sm" type="button" data-action="find-retry">Try again</button></div>`;
    } else if (finder.contacts) {
      const records = readNodeRequests(state.summary?.node_requests);
      const contacts = arrayValue(finder.contacts);
      let none = "";
      if (!contacts.length) {
        none = NO_CONTACTS_LINE;
      } else if (!contacts.some((contact) => contact.status === "offering")) {
        none = NO_OFFERS_LINE;
      }
      none = none ? `<p class="cp-help">${escapeHtml(none)}</p>` : "";
      const rows = contacts.map((contact) => contactRowMarkup(contact, finder.slot + 1, records)).join("");
      body = `${none}${rows ? `<div class="cp-list" role="list">${rows}</div>` : ""}${alert(finder.askError)}`;
    }
    return `<section class="cp-card cp-card-raised cp-finder" aria-label="${escapeHtml(title)}">
        <div class="cp-card-head"><h3 class="cp-group-label">${escapeHtml(title)}</h3><button class="cp-btn cp-btn-sm cp-btn-quiet" type="button" data-action="find-close">Close</button></div>
        ${body}
      </section>`;
  }

  // One contact: an offering contact can be asked unless it already fills
  // another slot or has a request the node may still act on. A node that
  // approved holds a custody state and stops offering: it reads as approved.
  function contactRowMarkup(contact, share, records) {
    const name = contact.name || middleTruncate(contact.profileDid);
    let meta = "";
    let line = "";
    let action = "";
    if (contact.status === "offering") {
      const roles = rolesText(contact.provides);
      meta = [
        contact.runBy ? chipMarkup(`Run by ${contact.runBy}`) : "",
        contact.location ? chipMarkup(contact.location) : "",
        roles ? chipMarkup(roles) : "",
      ].join("");
      const filled = slotForContact(state.slots, contact.profileDid, records);
      if (filled && filled !== share) {
        action = chipMarkup(`In node ${filled}`);
      } else if (contact.request === "waiting" || contact.request === "approved") {
        const status = requestStatus({ state: contact.request, name });
        action = chipMarkup(status.word, status.tone);
      } else {
        action = `<button class="cp-btn cp-btn-sm" type="button" data-action="find-ask" data-profile="${escapeHtml(contact.profileDid)}"${state.finder?.asking ? " disabled" : ""}>Ask to be a node</button>`;
      }
    } else if (contact.request === "approved") {
      const filled = slotForContact(state.slots, contact.profileDid, records);
      action = chipMarkup(filled ? `Approved · in node ${filled}` : "Approved", "ok");
    } else {
      line = FOUND_STATUS_LINES[contact.status] || FOUND_STATUS_LINES.unreachable;
    }
    return `<div class="cp-row" role="listitem"><span class="cp-avatar" aria-hidden="true">${escapeHtml(name.slice(0, 1).toUpperCase())}</span><div><h4 class="cp-row-title">${escapeHtml(name)}</h4>${meta ? `<div class="cp-row-meta">${meta}</div>` : ""}${line ? `<p class="cp-row-line">${escapeHtml(line)}</p>` : ""}</div><div class="cp-row-actions">${action}</div></div>`;
  }

  function checksMarkup(threshold) {
    const filled = filledCount();
    const partial = filled < slotCount(threshold);
    return `<ul class="cp-checks">${ruleResults().map((result) => {
      let rowState = result.result === "pass" ? "pass" : "fail";
      let title = checkTitle(result.id, threshold, filled);
      let why = result.result === "pass" ? "" : checkLine(result, threshold);
      let word = result.result === "pass" ? "Passed" : "Failed";
      if (result.id === "copies") {
        title = checkLine(result, threshold);
        why = "";
        if (result.result !== "pass") {
          rowState = "wait";
          word = "Advice";
        }
      } else if (result.id === "members" && partial && result.result !== "pass") {
        rowState = "wait";
        word = `${Math.max(slotCount(threshold) - filled, 0)} to go`;
      }
      return `<li class="cp-check" data-state="${rowState}"><span class="cp-check-mark" aria-hidden="true"></span><div><p class="cp-check-text">${escapeHtml(title)}</p>${why ? `<p class="cp-check-why">${escapeHtml(why)}</p>` : ""}</div><span class="cp-check-state">${escapeHtml(word)}</span></li>`;
    }).join("")}</ul>`;
  }

  function nodesMarkup(summary) {
    const threshold = objectValue(summary.threshold);
    const total = slotCount(threshold);
    const filled = filledCount();
    const failed = failedRules().length;
    const banner = state.notice
      || (failed ? { tone: "danger", strong: `${failed} check failed.`, line: "Fix it before you review the pool." } : null)
      || (state.slots.some(slotNeedsRestart)
        ? { tone: "pending", strong: "This Home’s node is set up.", line: "Restart this Home to start it. You can sign the pool first." }
        : null);
    const checks = filled >= 2 && ruleResults().length
      ? `<div class="cp-section-head"><h3 class="cp-group-label">${filled < total ? "Checks so far" : "Checks"}</h3><span class="cp-count">${escapeHtml(`${filled} of ${total} filled`)}</span></div>${checksMarkup(threshold)}`
      : "";
    const help = filled < total
      ? `Fill all ${total} slots to review the pool.`
      : (failed ? FIX_CHECKS_LINE : "");
    return `${bannerMarkup(banner)}
      ${stepperMarkup("nodes", { blocked: failed > 0, subs: stepSubs(summary) })}
      <p class="cp-desc cp-lead">Paste the node address each operator sent you, or their node card. One slot can be this Home.</p>
      ${slotsMarkup()}
      <p class="cp-quorum-rule">${escapeHtml(`Any ${threshold.required} of ${total} shares open your content`)}</p>
      ${checks}
      <div class="cp-footer">${help ? `<p class="cp-help">${escapeHtml(help)}</p>` : ""}<button class="cp-btn cp-btn-quiet" type="button" data-action="go" data-step="prepare">Back</button><button class="cp-btn" type="button" data-action="go" data-step="review"${reviewReady() ? "" : " disabled"}>Review</button></div>`;
  }

  function reviewMarkup(summary) {
    const threshold = objectValue(summary.threshold);
    const total = slotCount(threshold);
    const ready = reviewReady();
    const remote = state.slots.filter((slot) => slot.kind === "card").length;
    const ends = formatDate(termEnd(Date.now(), state.termDays));
    return `${bannerMarkup(state.notice)}
      ${stepperMarkup("review", { subs: stepSubs(summary) })}
      <p class="cp-desc cp-lead">Check your pool, then sign it.</p>
      <div class="cp-list cp-review-members" role="list" aria-label="Members">${state.slots.map(reviewMemberMarkup).join("")}</div>
      <div class="cp-review-split">
        <div class="cp-stack">
          ${checksMarkup(threshold)}
          <div class="cp-footer"><button class="cp-btn cp-btn-quiet" type="button" data-action="go" data-step="nodes">Back</button></div>
        </div>
        <aside class="cp-stack">
          <section class="cp-card cp-card-raised">
            <div class="cp-field"><span class="cp-field-label" id="term-label">Pool term</span>
              <div class="cp-seg" role="radiogroup" aria-labelledby="term-label">${termPresets(summary.term_presets_days).map((days) => `<button type="button" role="radio" aria-checked="${days === state.termDays}" data-action="term" data-days="${days}" data-focus="term-${days}">${escapeHtml(termLabel(days))}</button>`).join("")}</div>
              <p class="cp-help">${escapeHtml(`Ends ${ends}.`)}</p></div>
            <div class="cp-field"><span class="cp-field-label">Rule</span><p class="cp-rule">${escapeHtml(`Any ${threshold.required} of ${total} shares open your content.`)}</p></div>
          </section>
          <section class="cp-card cp-card-raised">
            <p class="cp-group-label">What signing does</p>
            <ul class="cp-bullets"><li>Signs the pool with this Home’s pool signing key.</li><li>Installs it on this Home and checks it with the Runtime.</li><li>${escapeHtml(`Registers the ${remote} other nodes and their storage IDs.`)}</li></ul>
            <button class="cp-btn cp-btn-primary" type="button" data-action="sign"${ready ? "" : " disabled"}>Sign and install pool</button>
            <p class="cp-help">${escapeHtml(ready ? "Asks for your passkey." : FIX_CHECKS_LINE)}</p>
          </section>
        </aside>
      </div>`;
  }

  function signStepsMarkup(states, remote) {
    const labels = ["Sign the pool", "Install on this Home", "Check with the Runtime", `Register ${remote} nodes`];
    const words = { pass: "Done", fail: "Failed", wait: "Running" };
    return `<ul class="cp-checks">${labels.map((label, index) => {
      const [rowState, word] = Array.isArray(states[index]) ? states[index] : [states[index], words[states[index]] || ""];
      return `<li class="cp-check" data-state="${rowState}"><span class="cp-check-mark" aria-hidden="true"></span><div><p class="cp-check-text">${escapeHtml(label)}</p></div><span class="cp-check-state">${escapeHtml(word)}</span></li>`;
    }).join("")}</ul>`;
  }

  function signMarkup(summary) {
    const sign = objectValue(state.sign);
    const remote = state.slots.filter((slot) => slot.kind === "card").length;
    const subs = stepSubs(summary);
    const card = (title, chip, body, label = title) => `<section class="cp-card cp-card-raised cp-sign" aria-label="${escapeHtml(label)}"><div class="cp-card-head"><h2 class="cp-section-title cp-card-title">${escapeHtml(title)}</h2>${chip}</div>${body}</section>`;
    const fingerprint = sign.fingerprint
      ? `<dl class="cp-kv"><dt>Pool fingerprint</dt><dd>${fingerprintFieldMarkup(sign.fingerprint, sign.fingerprintFull, "pool fingerprint")}</dd></dl>`
      : "";
    const openPool = '<div class="cp-footer"><button class="cp-btn cp-btn-inverse" type="button" data-action="open-pool">Open pool</button></div>';
    const back = '<div class="cp-footer"><button class="cp-btn" type="button" data-action="go" data-step="review">Back to review</button></div>';
    const signAgain = `<div class="cp-footer"><button class="cp-btn cp-btn-quiet" type="button" data-action="go" data-step="review">Back to review</button><button class="cp-btn cp-btn-primary" type="button" data-action="sign"${reviewReady() ? "" : " disabled"}>Sign and install pool</button></div>`;
    let banner = state.notice;
    let body = "";
    let blocked = false;
    switch (sign.phase) {
      case "confirm":
        subs.sign = "Confirm";
        body = card("Signing your pool", chipMarkup("Confirm", "pending"),
          `<p class="cp-desc cp-lead">Confirm with your passkey to sign the pool.</p><div class="cp-footer"><button class="cp-btn cp-btn-quiet" type="button" data-action="sign-cancel">Cancel</button></div>`);
        break;
      case "progress":
        subs.sign = "Signing";
        body = card("Signing your pool", chipMarkup("Signing", "pending"),
          `${signStepsMarkup(["wait", "wait", "wait", "wait"].map((rowState) => [rowState, ""]), remote)}<p class="cp-help">Keep this window open. It takes a few seconds.</p>`);
        break;
      case "success":
        subs.sign = "Verified";
        banner = banner || { tone: "ok", strong: "Your pool is installed and verified." };
        body = card("Pool signed", chipMarkup("Verified", "ok"),
          `${signStepsMarkup(["pass", "pass", "pass", "pass"], remote)}${fingerprint}${openPool}`);
        break;
      case "registration": {
        subs.sign = "Installed";
        const failures = arrayValue(sign.failed).map((entry) => {
          const share = Number(entry?.share);
          const reason = readText(entry?.reason);
          const busy = state.registering.has(share) ? " disabled" : "";
          return `<div class="cp-row-flex cp-register"><p class="cp-desc">${escapeHtml(`Your pool is installed and verified. ${shareName(share)} was not registered: ${reason.replace(/\.$/, "")}.`)}</p><button class="cp-btn cp-btn-sm" type="button" data-action="register" data-share="${share}"${busy}>Register again</button></div>`;
        }).join("");
        body = card("Pool signed", chipMarkup("Installed", "pending"),
          `${signStepsMarkup(["pass", "pass", "pass", ["fail", "Failed"]], remote)}${failures}${fingerprint}${openPool}`);
        break;
      }
      case "failed":
        subs.sign = "Not installed";
        blocked = true;
        banner = banner || { tone: "danger", strong: "The pool was not installed.", line: "Nothing changed." };
        body = card("The Runtime check failed", chipMarkup("Not installed", "danger"),
          `${signStepsMarkup(["pass", ["todo", "Rolled back"], "fail", ["todo", "Skipped"]], remote)}<p class="cp-desc cp-lead">${escapeHtml(INSTALL_FAILED_LINE)}</p>${sign.reason ? `<p class="cp-reason">${escapeHtml(`Reason: ${sign.reason}`)}</p>` : ""}${back}`,
          "Not installed");
        break;
      case "already":
        subs.sign = "Not installed";
        body = card("Pool not signed", "",
          `<p class="cp-desc cp-lead">This Home already has a pool. Nothing changed.</p>${openPool}`);
        break;
      case "stopped": {
        const view = objectValue(sign.view);
        body = card("Pool not signed", "",
          `<p class="cp-desc cp-lead">${escapeHtml(view.line || UNAVAILABLE_LINE)}</p>${view.reason ? `<p class="cp-reason">${escapeHtml(view.reason)}</p>` : ""}${signAgain}`);
        break;
      }
      default:
        body = card("Pool not signed", "",
          `<p class="cp-desc cp-lead">Signing cancelled. Nothing changed.</p>${sign.message ? `<p class="cp-help">${escapeHtml(sign.message)}</p>` : ""}${signAgain}`);
    }
    return `${bannerMarkup(banner)}${stepperMarkup("sign", { blocked, subs })}${body}`;
  }

  function activeMarkup(summary) {
    const threshold = objectValue(summary.threshold);
    const total = slotCount(threshold);
    const pool = summary.pool && typeof summary.pool === "object" ? summary.pool : null;
    const members = arrayValue(pool?.members);
    const term = objectValue(pool?.term);
    const now = Date.now();
    const startMs = Number(term.start) * 1000;
    const endMs = Number(term.end) * 1000;
    const daysLeft = Math.ceil((endMs - now) / DAY_MS);
    const unregistered = members.filter((member) => member?.registered !== true);
    const cardsKept = pool?.cards_kept === true;
    const problem = state.verify?.ok === false
      ? state.verify.view
      : (summary.pool_problem ? errorView(summary.pool_problem) : null);
    const banner = state.notice || activeBanner({
      problem,
      pool: Boolean(pool),
      termEndedAt: daysLeft <= 0 ? endMs : 0,
      health: state.health,
      checking: state.healthChecking === true,
      failed: state.healthFailed === true,
      restart: homeNeedsRestart(),
      unregistered: unregistered.length ? readText(unregistered[0].run_by) || `Share ${unregistered[0].share}` : "",
      termDaysLeft: daysLeft <= TERM_ENDING_DAYS ? daysLeft : null,
      threshold,
    });
    const health = state.health;
    // A check that runs or failed leaves the last result on screen, greyed.
    const stale = Boolean(health) && (state.healthChecking === true || state.healthFailed === true);
    const rows = members.map((member) => {
      const share = Number(member?.share);
      const name = readText(member?.run_by) || `Share ${share}`;
      const registered = member?.registered === true;
      const busy = state.registering.has(share) ? " disabled" : "";
      const answer = health ? health.members.find((entry) => entry.share === share) : null;
      const presence = answer ? memberHealth(answer) : null;
      const chips = [
        chipMarkup(`Share ${share}`),
        readText(member?.location) ? chipMarkup(readText(member.location)) : "",
        rolesText(member?.provides) ? chipMarkup(rolesText(member.provides)) : "",
        member?.this_home === true ? chipMarkup("This Home", "accent") : "",
        registered ? "" : chipMarkup("Not registered", "pending"),
        presence ? chipMarkup(presence.word, presence.tone, stale) : "",
      ].join("");
      const healthNote = presence?.note ? `<p class="cp-row-note">${escapeHtml(presence.note)}</p>` : "";
      const note = registered ? "" : `<p class="cp-row-note" data-tone="pending">${escapeHtml(`${name} is not registered on this Home yet. Releases cannot reach it.`)}</p>`;
      // Without kept cards Register again can only answer no_card.
      const actions = registered || !cardsKept ? "" : `<button class="cp-btn cp-btn-sm" type="button" data-action="register" data-share="${share}"${busy}>Register again</button>`;
      const presenceAttr = presence ? ` data-presence="${escapeHtml(presence.presence)}"` : "";
      return `<div class="cp-row" role="listitem"><span class="cp-avatar" aria-hidden="true"${presenceAttr}>${escapeHtml(name.slice(0, 1).toUpperCase())}</span><div><h4 class="cp-row-title">${escapeHtml(name)}</h4><div class="cp-row-meta">${chips}</div></div><div class="cp-row-actions">${actions}</div>${note}${healthNote}</div>`;
    }).join("");
    const memberList = members.length
      ? `<div class="cp-section-head"><div class="cp-row-flex"><h3 class="cp-group-label">Members</h3>${healthChipMarkup(stale)}</div><span class="cp-count">${escapeHtml(`${members.length} members`)}</span></div>
        ${healthLineMarkup(threshold, total)}
        <div class="cp-list" role="list"${stale ? ' data-stale="true"' : ""}>${rows}</div>
        ${unregistered.length && !cardsKept ? `<p class="cp-help">${escapeHtml(TERMINAL_POOL_LINE)}</p>` : ""}`
      : "";
    const used = endMs > startMs ? Math.min(100, Math.max(1, Math.round(((now - startMs) / (endMs - startMs)) * 100))) : 100;
    const epochState = daysLeft <= 0 ? "expired" : (daysLeft <= TERM_ENDING_DAYS ? "renew" : "active");
    const epochTone = daysLeft <= 0 ? "danger" : (daysLeft <= TERM_ENDING_DAYS ? "pending" : "ok");
    const epoch = pool
      ? `<section class="cp-card cp-card-raised" aria-label="Pool term"><div class="cp-epoch" data-state="${epochState}"><div><p class="cp-eyebrow">Pool term ends</p><p class="cp-epoch-big">${escapeHtml(formatDate(endMs))}</p></div>${chipMarkup(`${Math.max(daysLeft, 0)} days`, epochTone)}<div class="cp-epoch-track"><span data-used="${used}"></span></div><p class="cp-epoch-facts"><span><b>${escapeHtml(termLabel(Number(term.days)))}</b> term</span><span><b>${escapeHtml(`${threshold.required} of ${total}`)}</b> to open</span></p></div></section>`
      : "";
    const checked = state.verify?.ok === true ? state.verify.at : state.loadedAt;
    const checkRow = problem
      ? `<dd class="cp-row-flex">${chipMarkup("Failed", "danger")}</dd>`
      : `<dd class="cp-row-flex">${chipMarkup("Passed", "ok")}<span class="cp-mute">${escapeHtml(checkedText(checked))}</span></dd>`;
    const details = `<section class="cp-card cp-card-raised"><dl class="cp-kv cp-kv-single">
        ${pool ? `<dt>Pool fingerprint</dt><dd>${fingerprintFieldMarkup(pool.fingerprint, pool.fingerprint_full, "pool fingerprint")}</dd><dt>Signed</dt><dd>${escapeHtml(`${formatDate(startMs)} by this Home’s pool signing key`)}</dd>` : ""}
        ${readText(summary.pool_address) ? `<dt>Pool address</dt><dd>${keyFieldMarkup(summary.pool_address, "pool address", { tail: 10, purpose: COPY_POOL_ADDRESS })}</dd>` : ""}
        <dt>Runtime check</dt>${checkRow}</dl>
        <button class="cp-btn" type="button" data-action="verify"${state.verifying ? " disabled" : ""}>Verify again</button>
        ${state.verify?.ok === true ? '<p class="cp-help" role="status">Checked just now. The installed pool passed the Runtime check.</p>' : ""}</section>`;
    return `${bannerMarkup(banner)}
      <div class="cp-grid-side">
        <div class="cp-stack">${memberList}${noticesMarkup(summary)}<p class="cp-note">${escapeHtml(ONE_POOL_LINE)}</p></div>
        <aside class="cp-stack">${epoch}${details}</aside>
      </div>`;
  }

  // The pools this Home uses to buy and play, and Add a pool.
  function knownPoolsMarkup() {
    const known = objectValue(state.knownPools);
    const add = objectValue(state.poolAdd);
    const pools = arrayValue(known.pools);
    const rows = pools.map((pool) => {
      const servers = Number(pool.servers);
      const chips = [
        chipMarkup(`${servers} ${servers === 1 ? "server" : "servers"}`),
        pool.expiresAt > 0 ? chipMarkup(`Until ${formatDate(pool.expiresAt * 1000)}`) : "",
      ].join("");
      return `<div class="cp-row" role="listitem"><div><h4 class="cp-row-title"><code>${escapeHtml(middleTruncate(readText(pool.pool), 12, 8))}</code></h4><div class="cp-row-meta">${chips}</div></div></div>`;
    }).join("");
    let list = '<p class="cp-help">This Home uses no other pool yet.</p>';
    if (pools.length) {
      list = `<div class="cp-list" role="list">${rows}</div>`;
    } else if (known.failed === true) {
      list = '<p class="cp-help" data-tone="danger">The pools this Home uses could not be read.</p>';
    }
    const busy = add.busy === true ? " disabled" : "";
    const error = add.error ? `<p class="cp-help" data-tone="danger" role="alert">${escapeHtml(add.error)}</p>` : "";
    const added = add.added ? `<p class="cp-help" role="status">${escapeHtml(add.added)}</p>` : "";
    return `<section class="cp-card cp-card-raised" aria-labelledby="known-pools-title">
        <h2 class="cp-section-title" id="known-pools-title">Pools this Home uses</h2>
        <p class="cp-desc">${escapeHtml(KNOWN_POOLS_LINE)}</p>
        ${list}
        <div class="cp-field"><label for="pool-address">Pool address</label><input class="cp-input" id="pool-address" type="text" autocomplete="off" spellcheck="false" data-field="pool-address" data-focus="pool-address" value="${escapeHtml(readText(add.address))}"${add.error ? ' aria-invalid="true"' : ""}${busy}></div>
        <div><button class="cp-btn" type="button" data-action="add-pool"${busy}>Add a pool</button></div>
        ${error}${added}
      </section>`;
  }

  // Who of the members was told they are in the pool, and Notify members
  // again. Empty until Runtime recorded whom to tell.
  function noticesMarkup(summary) {
    const notices = readPoolNotices(summary.pool_notices);
    if (!notices) {
      return "";
    }
    // Only a Hosting offer read that says so counts as messages off.
    const messagesOff = objectValue(state.offer).view?.messagesEnabled === false;
    const rows = notices.members.map((member) => {
      const line = noticeLine(member, { messagesOff });
      const title = member.name ? `Share ${member.share} · ${member.name}` : `Share ${member.share}`;
      const hint = line.hint ? `<p class="cp-help">${escapeHtml(line.hint)}</p>` : "";
      return `<div class="cp-row" role="listitem"><div><h4 class="cp-row-title">${escapeHtml(title)}</h4><div class="cp-row-meta">${chipMarkup(line.word, line.tone)}</div>${hint}</div></div>`;
    }).join("");
    const busy = state.notifying === true ? " disabled" : "";
    return `<div class="cp-section-head"><h3 class="cp-group-label">Told about the pool</h3></div>
        <div class="cp-list" role="list">${rows}</div>
        <div><button class="cp-btn cp-btn-sm" type="button" data-action="notify-members"${busy}>Notify members again</button></div>`;
  }

  // The signed pool this served node is in, once its owner confirmed it.
  function servedPoolMarkup(pool) {
    if (!pool) {
      return `<p class="cp-help">${escapeHtml(POOL_WAITING_LINE)}</p>`;
    }
    const rows = pool.members.map((member) => {
      const chips = [
        chipMarkup(`Share ${member.share}`),
        member.location ? chipMarkup(member.location) : "",
        member.share === pool.share ? chipMarkup("This Home", "accent") : "",
      ].join("");
      return `<div class="cp-row" role="listitem"><div><h4 class="cp-row-title">${escapeHtml(member.runBy || `Share ${member.share}`)}</h4><div class="cp-row-meta">${chips}</div></div></div>`;
    }).join("");
    return `<p class="cp-help">${escapeHtml(servedPoolLine(pool))}</p>
        <p class="cp-help">${escapeHtml(`Until ${formatDate(pool.termEnd)}`)}</p>
        <div class="cp-list" role="list">${rows}</div>`;
  }

  function healthChipMarkup(stale) {
    if (state.healthChecking === true) {
      return chipMarkup("Checking", "pending");
    }
    if (!state.health) {
      return "";
    }
    const chip = healthChip(state.health.status);
    return chipMarkup(chip.word, chip.tone, stale);
  }

  // The status line under Members, with the time of the result it describes,
  // and Check nodes. Each check writes an audit line on every node, so it
  // runs only when asked.
  function healthLineMarkup(threshold, total) {
    const health = state.health;
    let line = `<p class="cp-help" role="status">${escapeHtml(`Releases need ${threshold.required} of ${total} nodes online.`)}</p>`;
    if (state.healthChecking === true) {
      line = `<p class="cp-help" role="status">${escapeHtml(HEALTH_CHECKING_LINE)}</p>`;
    } else if (state.healthFailed === true) {
      const last = health ? ` <span class="cp-mute">${escapeHtml(`Last checked ${checkedText(health.checkedAt)}.`)}</span>` : "";
      line = `<p class="cp-help" role="status" data-tone="danger">${escapeHtml(HEALTH_FAILED_LINE)}${last}</p>`;
    } else if (health) {
      line = `<p class="cp-help" role="status">${escapeHtml(healthLine(health))} <span class="cp-mute">${escapeHtml(`Checked ${checkedText(health.checkedAt)}.`)}</span></p>`;
    }
    const busy = state.healthChecking === true ? " disabled" : "";
    return `<div class="cp-health cp-help-tight">${line}<button class="cp-btn cp-btn-sm" type="button" data-action="check-health"${busy}>Check nodes</button></div>`;
  }

  // Plan B T2.3: Hosting, below its note: the offer, then one card per pool
  // this Home serves, each with Stop serving. Empty before the summary.
  function hostingMarkup() {
    const summary = objectValue(state.summary);
    const servings = arrayValue(summary.serving).map(readServing).filter(Boolean);
    const address = readText(objectValue(summary.local_node).address);
    const addressRows = address
      ? `<dt>${escapeHtml(ADDRESS_LABEL)}</dt><dd>${keyFieldMarkup(address, ADDRESS_LABEL)}</dd>`
      : "";
    const sendLine = address ? `<p class="cp-help">${escapeHtml(SEND_ADDRESS_LINE)}</p>` : "";
    // The v1 orphans, by pool fingerprint (user 10:35); an older Runtime
    // answered a flag.
    const attentionList = summary.serving_needs_attention;
    const needsAttention = Array.isArray(attentionList) ? attentionList.length > 0 : attentionList === true;
    const attention = needsAttention
      ? `<p class="cp-slot-reason" role="alert">${escapeHtml(SERVING_ATTENTION_LINE)}</p>`
      : "";
    // S2-R3-F1: this Home's own pool asks for its publisher above the cards.
    const ownPool = readOwnPool(summary.own_pool);
    const ownPublisher = ownPool && !ownPool.publisherConfirmed
      ? `<section class="cp-card cp-card-raised cp-hosting" aria-label="Your pool's publisher"><p class="cp-help">${escapeHtml(PUBLISHER_NOTE)}</p>${confirmPublisherButton(ownPool.poolFingerprint)}</section>`
      : "";
    const stopped = state.hostingNotice ? bannerMarkup(state.hostingNotice) : "";
    // The offer stays on below eight pools (Plan B T2.2).
    const offer = state.summary ? offerMarkup() : "";
    if (!servings.length) {
      const node = address
        ? `<section class="cp-card cp-card-raised cp-hosting cp-serving" aria-label="This Home's node"><dl class="cp-kv">${addressRows}</dl>${sendLine}</section>`
        : "";
      return `${stopped}${attention}${ownPublisher}${offer}${node}`;
    }
    return `${stopped}${attention}${ownPublisher}${offer}<div class="cp-stack" role="list" aria-label="Served pools">${servings
      .map((serving) => servingCardMarkup(serving, addressRows, sendLine))
      .join("")}</div>`;
  }

  // One served pool: who it is for, its node, its status from
  // `custody/pools/served` once read, and Stop serving.
  function servingCardMarkup(serving, addressRows, sendLine) {
    // Name the person; without a People name the owner's DID goes in a key field.
    let owner = "another Home";
    if (serving.ownerName) {
      owner = escapeHtml(serving.ownerName);
    } else if (serving.ownerDid) {
      owner = keyFieldMarkup(serving.ownerDid, "pool owner's Runtime issuer");
    }
    const item = arrayValue(state.servedPools?.items)
      .find((entry) => serving.poolFingerprint && entry.poolFingerprint === serving.poolFingerprint);
    const status = (item && servedPoolStatusChip(item.status)) || servingStatus(serving);
    const roles = rolesText(serving.provides);
    const chips = [
      serving.runBy ? chipMarkup(`Run by ${serving.runBy}`) : "",
      serving.location ? chipMarkup(serving.location) : "",
      roles ? chipMarkup(roles) : "",
      chipMarkup(status.word, status.tone),
    ].join("");
    const fingerprint = serving.fingerprint
      ? `<dt>Fingerprint</dt><dd>${fingerprintFieldMarkup(serving.fingerprint, serving.fingerprintFull, "node fingerprint")}</dd>`
      : "";
    const shares = item && item.sharesHeld !== null
      ? `<p class="cp-help">${escapeHtml(sharesHeldLine(item.sharesHeld))}</p>`
      : "";
    const busy = state.stoppingPool === serving.poolFingerprint ? " disabled" : "";
    const stop = serving.poolFingerprint
      ? `<div><button class="cp-btn cp-btn-sm" type="button" data-action="stop-serving" data-pool="${escapeHtml(serving.poolFingerprint)}"${busy}>Stop serving</button></div>`
      : "";
    // Offered only while no publisher is kept for this pool (S2-A3).
    const publisher = item && !item.publisherConfirmed
      ? `<p class="cp-help">${escapeHtml(PUBLISHER_NOTE)}</p>${confirmPublisherButton(serving.poolFingerprint)}`
      : "";
    return `<section class="cp-card cp-card-raised cp-hosting cp-serving" role="listitem" aria-label="Serving">
        <div><h2 class="cp-section-title cp-card-title">${escapeHtml(SERVING_TITLE)} ${owner}</h2><div class="cp-row-meta">${chips}</div></div>
        ${fingerprint || addressRows ? `<dl class="cp-kv">${fingerprint}${addressRows}</dl>` : ""}
        ${sendLine}
        ${servedPoolMarkup(serving.pool)}
        ${shares}
        <p class="cp-help">${escapeHtml(ownerContactLine(serving.lastContact))}</p>
        <p class="cp-note">${escapeHtml(OWNER_DECIDES_LINE)}</p>
        ${publisher}
        ${stop}
      </section>`;
  }

  // Confirm publisher for one pool, behind the admin's passkey.
  function confirmPublisherButton(poolFingerprint) {
    const busy = state.confirmingPublisher === poolFingerprint ? " disabled" : "";
    return `<div><button class="cp-btn cp-btn-sm" type="button" data-action="confirm-publisher" data-pool="${escapeHtml(poolFingerprint)}"${busy}>Confirm publisher</button></div>`;
  }

  // The Hosting offer: a switch, the labels contacts see, and whether custody
  // messages can reach this Home. Empty until the offer is read or fails to.
  function offerMarkup() {
    const offer = objectValue(state.offer);
    const view = offer.view;
    const card = (body) => `<section class="cp-card cp-card-raised cp-hosting cp-offer" aria-label="Offer custody">${body}</section>`;
    const problem = (shown) => (shown?.line
      ? `<p class="cp-slot-reason" role="alert">${escapeHtml(shown.line)}</p>${shown.reason ? `<p class="cp-help">${escapeHtml(shown.reason)}</p>` : ""}`
      : "");
    const unread = offer.failed
      ? `${problem(offer.failed)}<div><button class="cp-btn cp-btn-sm" type="button" data-action="offer-reload">Try again</button></div>`
      : "";
    if (!view) {
      return unread ? card(unread) : "";
    }
    // Holding a custody state keeps the offer off; one already on may go off.
    const blocked = view.holdsCustody && !view.enabled;
    const busy = offer.busy === true;
    const switchOff = blocked || busy ? " disabled" : "";
    // The fields show what contacts see while the offer is on.
    const fieldsOff = view.enabled || blocked || busy ? " disabled" : "";
    const runBy = String(offer.runBy ?? "");
    const location = String(offer.location ?? "");
    // Mark the field whose label breaks the rule; a Runtime refusal of labels
    // that pass it here marks both.
    const runByBad = offer.invalid === true && !validLabel(runBy);
    const locationBad = offer.invalid === true && !validLabel(location);
    const bothBad = offer.invalid === true && !runByBad && !locationBad;
    const field = (id, label, key, value, help, bad) => `<div class="cp-field"><label for="${id}">${escapeHtml(label)}</label><input class="cp-input" id="${id}" type="text" autocomplete="off" data-field="${key}" data-focus="${id}" aria-describedby="${id}-help" value="${escapeHtml(value)}"${bad || bothBad ? ' aria-invalid="true"' : ""}${fieldsOff}><p class="cp-help" id="${id}-help">${escapeHtml(help)}</p></div>`;
    const roles = rolesText(view.provides);
    // A Home that cannot offer has no use for custody messages.
    const messages = view.messagesEnabled || blocked
      ? ""
      : `<div class="cp-stack cp-offer-messages"><p class="cp-help" data-tone="pending">${escapeHtml(MESSAGES_OFF_LINE)}</p><div><button class="cp-btn cp-btn-sm" type="button" data-action="offer-messages"${busy ? " disabled" : ""}>Enable custody messages</button></div></div>`;
    return card(`<div><button class="cp-switch" type="button" role="switch" aria-checked="${view.enabled}" aria-describedby="offer-privacy" data-action="offer-switch" data-focus="offer-switch"${switchOff}><span class="cp-switch-label">${escapeHtml(OFFER_SWITCH_LABEL)}</span><span class="cp-switch-track" aria-hidden="true"></span></button>
        <p class="cp-help" id="offer-privacy">${escapeHtml(OFFER_PRIVACY_LINE)}</p></div>
        ${blocked ? `<p class="cp-note">${escapeHtml(HOLDS_CUSTODY_LINE)}</p>` : ""}
        ${field("offer-run-by", "Run by", "offer_run_by", runBy, RUN_BY_HELP, runByBad)}
        ${field("offer-location", "Location", "offer_location", location, LOCATION_HELP, locationBad)}
        ${roles ? `<div class="cp-field"><span class="cp-field-label">Roles</span><p class="cp-rule">${escapeHtml(roles)}</p></div>` : ""}
        ${offer.invalid ? problem({ line: REFUSAL_LINES.bad_labels }) : ""}
        ${problem(offer.notice)}
        ${unread}
        ${messages}`);
  }

  return {
    prepareReady,
    homeNeedsRestart,
    homeSlotIndex,
    slotInput,
    filledCount,
    checkKey,
    freshChecks,
    ruleResults,
    failedRules,
    reviewReady,
    slotFailsCheck,
    shareName,
    poolsMarkup,
    hostingMarkup,
  };
}
