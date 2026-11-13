// Custody: a Home admin forms this Home's dKMS custody pool from node cards,
// fetched from each node by its address or pasted, then sees the installed
// pool.
//
// The Runtime owns every pool rule; this app keeps the draft in memory only
// and renders what the custody routes return. The threshold is data: the share
// slots, every count and the open rule come from `summary.threshold`.
// Refusals are read by their JSON `code`, never by the HTTP status. Auth and
// passkey step-up refusals arrive as plain text and are shown as sent.
// The wording and pure readers live in `src/model.js`; what the state means
// and the markup for each screen live in `src/view.js`.
import {
  DEFAULT_TERM_DAYS,
  OFFER_UNREAD_LINE,
  TERM_CHANGED_LINE,
  UNAVAILABLE_LINE,
  approvalFields,
  arrayValue,
  askAgainIndex,
  askAgainTarget,
  cardSlot,
  copyThroughHome,
  enableMessages,
  errorView,
  failedSlot,
  includeDraft,
  installSlots,
  KNOWN_POOL_ADD_OPERATION,
  SERVED_POOL_REMOVE_OPERATION,
  SERVED_POOL_CONFIRM_PUBLISHER_OPERATION,
  PUBLISHER_CONFIRMED_LINE,
  STOPPED_SERVING_LINE,
  confirmPublisherRefusalLine,
  confirmPublisherRequest,
  readServedPools,
  stopServingRefusalLine,
  stopServingRequest,
  knownPoolRefusalLine,
  mergeLocalNode,
  notifyOnce,
  objectValue,
  offerReadFailure,
  pollDelay,
  readFoundContacts,
  readHealth,
  readKnownPools,
  readNodeRequests,
  readOffer,
  readServing,
  readText,
  refusalLine,
  removeLocalNode,
  requestErrorView,
  requestSlot,
  restorePlacements,
  shouldPollRequests,
  slotCount,
  slotEntry,
  switchOffer,
  termChoice,
  termMismatch,
  termPresets,
  validLabel,
  verifyFailure,
} from "./src/model.js?v=custody-20261113e";
import { createView } from "./src/view.js?v=custody-20261113e";

export {
  COPY_FINGERPRINT,
  COPY_IDENTIFIER,
  COPY_POOL_ADDRESS,
  KNOWN_POOL_ADD_OPERATION,
  KNOWN_POOLS_LINE,
  HOSTING_POOLS_LINE,
  SERVED_POOL_REMOVE_OPERATION,
  SERVED_POOL_CONFIRM_PUBLISHER_OPERATION,
  PUBLISHER_NOTE,
  PUBLISHER_CONFIRMED_LINE,
  confirmPublisherRefusalLine,
  confirmPublisherRequest,
  readOwnPool,
  readServedPools,
  servedPoolStatusChip,
  sharesHeldLine,
  stopServingRefusalLine,
  stopServingRequest,
  LOCAL_NODE_REMOVE_OPERATION,
  MESSAGES_ENABLE_OPERATION,
  activeBanner,
  approvalFields,
  askAgainIndex,
  askAgainTarget,
  cardSlot,
  checkLine,
  checkTitle,
  checkedText,
  clipDetail,
  copyThroughHome,
  enableMessages,
  errorView,
  failedSlot,
  fetchRefusal,
  fingerprintTail,
  formatDate,
  healthBanner,
  healthChip,
  healthLine,
  includeDraft,
  installSlots,
  knownPoolRefusalLine,
  memberHealth,
  mergeLocalNode,
  middleTruncate,
  noticeLine,
  normalizeCardText,
  notifyOnce,
  offerBody,
  offerReadFailure,
  ownerContactLine,
  pollDelay,
  readFoundContacts,
  readHealth,
  readKnownPools,
  readNodeRequests,
  readOffer,
  readPoolNotices,
  readServedPool,
  readServing,
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
  termChangedLine,
  termChoice,
  termEnd,
  termLabel,
  termMismatch,
  termPresets,
  validLabel,
  verifyFailure,
  HOST_TRUST_REQUIRED_LINE,
} from "./src/model.js?v=custody-20261113e";
export { createView } from "./src/view.js?v=custody-20261113e";

const API = "/api/apps/custody";
// A card is about 4 KB; the parser refuses anything over 16 KiB anyway.
const MAX_CARD_FILE_BYTES = 64 * 1024;
const CARD_READ_DELAY_MS = 500;
const SUMMARY_RETRY_MS = [2_000, 5_000, 15_000, 30_000];
const COPIED_MS = 1_400;
// A node answers a request in its own time; the summary carries the answer.
const REQUEST_POLL_MS = 10_000;
const COPIED_LABEL = "Copied";
const COPY_FAILED_LABEL = "Copy failed. Try again.";
const FILE_UNREADABLE_LINE = "This Home could not read the file. Drop a .node-card file, or paste its text.";

/* ---------- App ---------- */

// `createClipboard({ homeOrigin, homeToken })` gives Home's clipboard client
// and `createNavigation(options)` Home's navigation client, which renews this
// frame's launch authority; main.js passes both, so this module stays
// importable without Home.
export function bootCustodyApp({ createClipboard = null, createNavigation = null } = {}) {
  const lockedShell = document.getElementById("locked-shell");
  const custodyShell = document.getElementById("custody-shell");
  const poolsNode = document.getElementById("pools");
  const hostingNode = document.getElementById("hosting-node");
  const pageTitle = document.querySelector(".cp-page-title");
  const fileInput = document.getElementById("card-file");
  const launchParams = new URLSearchParams(window.location.search);
  let homeToken = new URLSearchParams(window.location.hash.replace(/^#/, "")).get("home_token") || "";
  const homeParentOrigin = launchParams.get("home_origin") || "";
  const SECTION_TITLES = { pools: "Pools", hosting: "Hosting" };

  const state = {
    section: "pools",
    summary: null,
    loadedAt: 0,
    // prepare | nodes | review | sign; the Active view shows whenever a pool
    // is installed and no signing result is on screen.
    step: "prepare",
    slots: [],
    checks: null,
    checking: false,
    termDays: DEFAULT_TERM_DAYS,
    sign: null,
    notice: null,
    keyBusy: false,
    verify: null,
    verifying: false,
    // Notify members again is on its way.
    notifying: false,
    // The last health answer, kept on screen while a new check runs or after
    // one fails.
    health: null,
    healthChecking: false,
    healthFailed: false,
    registering: new Set(),
    // Find a node: the finder open on one empty slot, or null.
    finder: null,
    // Requests the owner let go of in a slot; they are not put back.
    releasedRequests: new Set(),
    // Slots whose node is being asked again for the current term.
    askingAgain: new Set(),
    // The Hosting offer as Runtime last sent it, and its edited labels.
    offer: {
      view: null,
      failed: null,
      runBy: "",
      location: "",
      edited: false,
      invalid: false,
      notice: null,
      busy: false,
    },
    // Plan B T4.3: the pools this Home uses, and the Add a pool form.
    knownPools: { pools: [], failed: false },
    // Plan B T2.3: Hosting's served pools, the pool being stopped, and the
    // last Stop serving outcome.
    servedPools: { items: [], failed: false },
    stoppingPool: "",
    hostingNotice: null,
    poolAdd: { address: "", busy: false, error: "", added: "" },
  };
  const view = createView(state);
  const notify = notifyOnce((body) => fetchJson(`${API}/pool/notify`, {
    method: "POST",
    body: JSON.stringify(body),
  }));
  let summaryGeneration = 0;
  let checkGeneration = 0;
  let readGeneration = 0;
  let signGeneration = 0;
  let healthGeneration = 0;
  let offerGeneration = 0;
  let summaryRetry = 0;
  let summaryRetryTimer = 0;
  let summaryLoading = false;
  // When the last summary read began; the poll counts from it.
  let summaryStartedAt = 0;
  let pollTimer = 0;
  let findGeneration = 0;
  let fileSlot = -1;
  const readTimers = new Map();
  const copyFlashes = new WeakMap();

  announceReady();
  bindNavigation();
  bindActions();
  if (!homeToken) {
    lockedShell?.classList.remove("hidden");
    custodyShell?.classList.add("hidden");
    return;
  }
  // This frame has no clipboard access of its own; Copy goes through Home.
  const homeClipboard = createClipboard ? createClipboard({ homeOrigin: homeParentOrigin, homeToken }) : null;
  // Home renews this frame's launch authority before it expires (#532):
  // requests, passkey steps and Copy all read the current token.
  createNavigation?.({ homeToken, homeOrigin: homeParentOrigin, target: "custody",
    onHomeToken(token) {
      homeClipboard?.setHomeToken(token);
      homeToken = token;
    },
  });
  lockedShell?.classList.add("hidden");
  custodyShell?.classList.remove("hidden");
  render();
  refreshSummary();

  function announceReady() {
    if (homeToken && homeParentOrigin && window.top !== window) {
      window.top.postMessage({ type: "home:app-ready", homeToken }, homeParentOrigin);
      window.top.postMessage({
        type: "home:menu-manifest",
        homeToken,
        menus: [
          { title: "File", items: [{ label: "Close Window", cmd: "__close-window" }] },
          { title: "View", items: [{ label: "Refresh", cmd: "refresh" }] },
        ],
      }, homeParentOrigin);
    }
  }

  function bindNavigation() {
    for (const button of document.querySelectorAll("[data-section-target]")) {
      button.addEventListener("click", () => activateSection(readText(button.dataset.sectionTarget)));
    }
    activateSection("pools");
  }

  function activateSection(targetId) {
    if (!SECTION_TITLES[targetId]) {
      return;
    }
    state.section = targetId;
    for (const item of document.querySelectorAll("[data-section-target]")) {
      if (readText(item.dataset.sectionTarget) === targetId) {
        item.setAttribute("aria-current", "page");
      } else {
        item.removeAttribute("aria-current");
      }
    }
    for (const section of document.querySelectorAll(".cp-section[id]")) {
      section.hidden = section.id !== targetId;
    }
    if (pageTitle) {
      pageTitle.textContent = SECTION_TITLES[targetId];
    }
    if (targetId === "hosting") {
      loadOffer();
      loadServedPools();
    }
    schedulePoll();
  }

  function bindActions() {
    document.addEventListener("click", (event) => {
      const target = event.target instanceof Element ? event.target.closest("[data-action]") : null;
      if (!(target instanceof HTMLButtonElement) || target.disabled) {
        return;
      }
      handleAction(target).catch((error) => {
        state.notice = { tone: "danger", ...errorView(error) };
        render();
      });
    });
    window.addEventListener("message", (event) => {
      if (event.origin !== "null" || event.source !== window.parent) {
        return;
      }
      const message = event.data;
      if (message?.type === "elastos:menu-command" && readText(message.cmd) === "refresh") {
        refreshSummary();
      }
    });
    document.addEventListener("visibilitychange", schedulePoll);
    hostingNode?.addEventListener("input", onHostingInput);
    poolsNode?.addEventListener("input", onPoolsInput);
    poolsNode?.addEventListener("paste", onPaste);
    poolsNode?.addEventListener("change", onPoolsChange);
    poolsNode?.addEventListener("dragover", onDragOver);
    poolsNode?.addEventListener("dragleave", onDragLeave);
    poolsNode?.addEventListener("drop", onDrop);
    fileInput?.addEventListener("change", () => {
      const file = fileInput.files?.[0];
      const index = fileSlot;
      fileInput.value = "";
      fileSlot = -1;
      if (file && index >= 0) {
        readCardFile(index, file);
      }
    });
  }

  async function handleAction(button) {
    const action = readText(button.dataset.action);
    const index = Number(button.dataset.slot);
    switch (action) {
      case "copy":
        return copyValue(button);
      case "create-key":
        return createSigningKey();
      case "go":
        return goToStep(readText(button.dataset.step));
      case "section":
        return activateSection(readText(button.dataset.section));
      case "choose-file":
        fileSlot = index;
        fileInput?.click();
        return undefined;
      case "include-open":
        return openIncludeForm(index);
      case "include-cancel":
        state.slots[index] = emptySlot();
        return render();
      case "include-confirm":
        return includeThisHome(index);
      case "remove":
        return removeSlot(index);
      case "retry-card":
        releaseRequest(state.slots[index]);
        state.slots[index] = emptySlot();
        slotsChanged();
        return focusSoon(`paste-${index}`);
      case "retry-fetch": {
        const address = readText(state.slots[index]?.address);
        if (state.slots[index]?.kind !== "refused" || !address) {
          return undefined;
        }
        state.slots[index] = emptySlot();
        return readCardInto(index, address);
      }
      case "retry-read": {
        const slot = state.slots[index];
        const text = slot?.kind === "empty" ? readText(slot.text) : "";
        return text ? readCardInto(index, text, approvalOf(slot)) : undefined;
      }
      case "term":
        state.termDays = Number(button.dataset.days) || DEFAULT_TERM_DAYS;
        return render();
      case "sign":
        return signPool();
      case "sign-cancel":
        signGeneration += 1;
        state.sign = { phase: "cancelled", message: "" };
        return render();
      case "find-open":
        return openFinder(index);
      case "find-retry":
        return state.finder ? openFinder(state.finder.slot) : undefined;
      case "find-close":
        findGeneration += 1;
        state.finder = null;
        return render();
      case "find-ask":
        return askContact(readText(button.dataset.profile));
      case "ask-again":
        return askAgain(index);
      case "request-release":
        if (state.slots[index]?.kind !== "request") {
          return undefined;
        }
        releaseRequest(state.slots[index]);
        state.slots[index] = emptySlot();
        slotsChanged();
        return schedulePoll();
      case "open-pool":
        state.finder = null;
        state.sign = null;
        state.notice = null;
        state.step = "prepare";
        state.slots = state.slots.map(() => emptySlot());
        state.checks = null;
        return refreshSummary();
      case "register":
        return registerMember(Number(button.dataset.share));
      case "verify":
        return verifyPool();
      case "notify-members":
        return notifyMembers();
      case "check-health":
        return checkHealth();
      case "offer-switch":
        return switchOfferTo(button.getAttribute("aria-checked") !== "true");
      case "offer-messages":
        return enableCustodyMessages();
      case "offer-reload":
        return loadOffer();
      case "add-pool":
        return addPool();
      case "stop-serving":
        return stopServing(readText(button.dataset.pool));
      case "confirm-publisher":
        return confirmPublisher(readText(button.dataset.pool));
      default:
        return undefined;
    }
  }

  /* ---------- Requests ---------- */

  async function fetchJson(path, options = {}) {
    const headers = new Headers(shellHeaders(options.headers));
    if (typeof options.body === "string") {
      headers.set("content-type", "application/json");
    }
    let response;
    try {
      response = await fetch(path, { ...options, headers, credentials: "same-origin" });
    } catch (_error) {
      throw Object.assign(new Error(UNAVAILABLE_LINE), { unavailable: true });
    }
    const text = await response.text();
    let payload = null;
    try {
      payload = text ? JSON.parse(text) : null;
    } catch (_error) {
      payload = null;
    }
    if (!response.ok) {
      const code = readText(payload?.code);
      const error = new Error(code || text || UNAVAILABLE_LINE);
      error.code = code;
      error.detail = code ? readText(payload?.detail) : "";
      // A 5xx carries no reason worth showing; Runtime logs it.
      error.text = code || response.status >= 500 ? "" : text.trim();
      error.unavailable = !code && !error.text;
      throw error;
    }
    return payload;
  }

  function shellHeaders(extra) {
    return Object.assign(
      homeToken.length > 0 ? { "x-elastos-home-token": homeToken } : {},
      extra || {},
    );
  }

  // Copied from System (capsules/system/browser/system.js): Home runs the
  // passkey ceremony for the launch it owns and returns a one-use token bound
  // to this exact operation and request.
  function requestHomePasskeyStepUp(homeToken, parentOrigin, operation, request) {
    if (!homeToken || window.top === window || !parentOrigin) {
      return Promise.reject(new Error("Open Custody from Home to verify your passkey."));
    }
    const requestId = window.crypto?.randomUUID?.()
      || `passkey-${Date.now()}-${Math.random().toString(16).slice(2)}`;
    return new Promise((resolve, reject) => {
      const timeout = window.setTimeout(() => {
        window.removeEventListener("message", onResult);
        reject(new Error("Passkey verification timed out."));
      }, 120_000);
      const onResult = (event) => {
        if (event.source !== window.top || event.origin !== parentOrigin) {
          return;
        }
        const result = event.data && typeof event.data === "object" ? event.data : null;
        if (
          result?.type !== "elastos.home.passkey-step-up.result/v1"
          || result.requestId !== requestId
        ) {
          return;
        }
        window.clearTimeout(timeout);
        window.removeEventListener("message", onResult);
        const stepUpToken = readText(result.stepUpToken);
        const expectedKeys = stepUpToken
          ? ["type", "requestId", "stepUpToken"]
          : ["type", "requestId", "error"];
        if (!hasExactKeys(result, expectedKeys)) {
          reject(new Error("Passkey verification returned an invalid result."));
          return;
        }
        if (stepUpToken) {
          resolve(stepUpToken);
          return;
        }
        reject(new Error(readText(result.error) || "Passkey verification failed."));
      };
      window.addEventListener("message", onResult);
      window.top.postMessage({
        type: "elastos.home.passkey-step-up.request/v1",
        requestId,
        homeToken,
        operation,
        request,
      }, parentOrigin);
    });
  }

  function hasExactKeys(value, expectedKeys) {
    if (!value || typeof value !== "object" || Array.isArray(value)) return false;
    const actual = Object.keys(value).sort();
    const expected = [...expectedKeys].sort();
    return actual.length === expected.length
      && actual.every((key, index) => key === expected[index]);
  }

  async function refreshSummary() {
    const generation = ++summaryGeneration;
    window.clearTimeout(summaryRetryTimer);
    summaryLoading = true;
    summaryStartedAt = Date.now();
    try {
      const summary = await fetchJson(`${API}/summary`);
      if (generation !== summaryGeneration) {
        return;
      }
      summaryRetry = 0;
      applySummary(objectValue(summary));
      loadKnownPools();
      if (state.notice?.retry) {
        state.notice = null;
      }
      if (state.section === "hosting") {
        loadOffer();
        loadServedPools();
      }
    } catch (error) {
      if (generation !== summaryGeneration) {
        return;
      }
      if (error.unavailable) {
        state.notice = { tone: "danger", line: UNAVAILABLE_LINE, reason: "", retry: true };
        const delay = SUMMARY_RETRY_MS[Math.min(summaryRetry, SUMMARY_RETRY_MS.length - 1)];
        summaryRetry += 1;
        summaryRetryTimer = window.setTimeout(refreshSummary, delay);
      } else {
        state.notice = { tone: "danger", ...errorView(error) };
      }
    }
    summaryLoading = false;
    render();
    schedulePoll();
  }

  function applySummary(summary) {
    state.summary = summary;
    state.loadedAt = Date.now();
    state.termDays = termChoice(termPresets(summary.term_presets_days), state.termDays);
    const total = slotCount(summary.threshold);
    if (state.slots.length !== total) {
      state.slots = Array.from({ length: total }, (_, index) => state.slots[index] || emptySlot());
      state.checks = null;
    }
    const wasActive = state.step === "active";
    if (summary.pool_installed === true && state.step !== "sign") {
      state.step = "active";
    } else if (summary.pool_installed !== true && state.step === "active") {
      state.step = "prepare";
    }
    if (state.step !== "active") {
      healthGeneration += 1;
      state.health = null;
      state.healthChecking = false;
      state.healthFailed = false;
    } else if (!wasActive && summary.pool) {
      // The Active view opened on a pool the Runtime accepted.
      checkHealth();
    }
    if (setupActive()) {
      syncRequestSlots(readNodeRequests(summary.node_requests));
    }
  }

  /* ---------- Find nodes ---------- */

  // The pool setup the owner fills slots in: no pool, not a node Home, no
  // signing on screen.
  function setupActive() {
    const summary = state.summary;
    return Boolean(summary) && summary.pool_installed !== true
      && !readServing(summary.serving) && state.step !== "sign" && state.step !== "active";
  }

  function pollDue() {
    return shouldPollRequests(state.slots, {
      shown: state.section === "pools" && setupActive(),
      visible: document.visibilityState === "visible",
    });
  }

  // Request slots take their record's latest state; an approval fills its
  // slot with the node's card. Then requests no slot holds come back into
  // empty slots, so a reload keeps them.
  function syncRequestSlots(records) {
    const byId = new Map(records.map((record) => [record.requestId, record]));
    state.slots.forEach((slot, index) => {
      if (slot.kind !== "request") {
        return;
      }
      slot.record = byId.get(slot.requestId) || slot.record;
      if (slot.record.state === "approved" && slot.record.card) {
        fillApproved(index, slot.record);
      }
    });
    for (const { index, record } of restorePlacements(state.slots, records, state.termDays, state.releasedRequests)) {
      if (record.state === "approved") {
        fillApproved(index, record);
      } else {
        state.slots[index] = requestSlot(record);
      }
    }
  }

  // The approved card is read like a pasted one, so the slot shows its Run
  // by, Location and fingerprint, and install sends it as `{card}`.
  function fillApproved(index, record) {
    state.slots[index] = emptySlot();
    readCardInto(index, record.card, approvalFields(record));
  }

  function approvalOf(slot) {
    return slot?.requestId
      ? {
        requestId: slot.requestId,
        profileDid: slot.profileDid,
        recipientHome: slot.recipientHome,
        approvedBy: slot.approvedBy,
        termDays: slot.termDays,
      }
      : {};
  }

  // A request let go of in a slot stays out of it; its record still blocks
  // asking that Home again until the node answers.
  function releaseRequest(slot) {
    if (slot?.requestId) {
      state.releasedRequests.add(slot.requestId);
    }
  }

  // One find per opening: it asks every contact's Home and can take a while.
  async function openFinder(index) {
    if (state.slots[index]?.kind !== "empty" || state.finder?.busy) {
      return;
    }
    const generation = ++findGeneration;
    const finder = { slot: index, busy: true, contacts: null, failed: null, asking: "", askError: null };
    state.finder = finder;
    render();
    try {
      finder.contacts = readFoundContacts(await fetchJson(`${API}/nodes/find`, { method: "POST", body: "{}" }));
    } catch (error) {
      finder.failed = requestErrorView(error);
    }
    if (generation !== findGeneration) {
      return;
    }
    finder.busy = false;
    render();
  }

  async function askContact(profileDid) {
    const finder = state.finder;
    const contact = arrayValue(finder?.contacts).find((entry) => entry.profileDid === profileDid);
    if (!contact || contact.status !== "offering" || finder.busy || finder.asking) {
      return;
    }
    const index = finder.slot;
    finder.asking = profileDid;
    finder.askError = null;
    render();
    let answer = null;
    let record = null;
    try {
      answer = await fetchJson(`${API}/node-requests`, {
        method: "POST",
        body: JSON.stringify({ profile_did: profileDid, term_days: state.termDays }),
      });
      record = readNodeRequests([answer])[0] || null;
      if (!record) {
        throw Object.assign(new Error(UNAVAILABLE_LINE), { unavailable: true });
      }
    } catch (error) {
      if (state.finder === finder) {
        finder.asking = "";
        finder.askError = requestErrorView(error);
        render();
      }
      return;
    }
    // Until the next summary carries it.
    if (state.summary) {
      state.summary.node_requests = [answer, ...arrayValue(state.summary.node_requests)];
    }
    if (state.finder === finder) {
      state.finder = null;
    }
    if (state.slots[index]?.kind === "empty" && !readText(state.slots[index].text)) {
      state.slots[index] = requestSlot(record);
    } else {
      // The slot was filled meanwhile: the request takes the next free one.
      syncRequestSlots(readNodeRequests(state.summary?.node_requests));
    }
    slotsChanged();
    schedulePoll();
  }

  // Ask the node in slot `index` again, for the term the owner chose now. The
  // slot then waits on the new request; the earlier one is let go.
  async function askAgain(index) {
    const slot = state.slots[index];
    const profileDid = askAgainTarget(slot);
    if (!profileDid || state.askingAgain.has(index)) {
      return;
    }
    state.askingAgain.add(index);
    state.notice = null;
    render();
    let answer = null;
    let record = null;
    try {
      answer = await fetchJson(`${API}/node-requests`, {
        method: "POST",
        body: JSON.stringify({ profile_did: profileDid, term_days: state.termDays }),
      });
      record = readNodeRequests([answer])[0] || null;
      if (!record) {
        throw Object.assign(new Error(UNAVAILABLE_LINE), { unavailable: true });
      }
    } catch (error) {
      state.notice = { tone: "danger", ...requestErrorView(error) };
    }
    state.askingAgain.delete(index);
    if (record) {
      if (state.summary) {
        state.summary.node_requests = [answer, ...arrayValue(state.summary.node_requests)];
      }
      // The slot may have changed during the ask; the new request still
      // binds, or it would block asking that Home again.
      const at = askAgainIndex(state.slots, index, slot);
      if (at >= 0) {
        releaseRequest(state.slots[at]);
        state.slots[at] = requestSlot(record);
      } else {
        syncRequestSlots(readNodeRequests(state.summary?.node_requests));
      }
      slotsChanged();
      schedulePoll();
      return;
    }
    render();
  }

  // Polls while a slot waits for a node, the owner sees the setup and the
  // page is visible; a refresh in flight is never doubled. Each refresh
  // comes one interval after the last summary, so coming back to the page or
  // to Pools refreshes at once instead of waiting a full interval again.
  function schedulePoll() {
    window.clearTimeout(pollTimer);
    if (!pollDue()) {
      return;
    }
    pollTimer = window.setTimeout(() => {
      // The view may have changed since, and a read in flight arms the
      // next poll when it ends.
      if (!pollDue() || summaryLoading) {
        return;
      }
      refreshSummary();
    }, pollDelay(summaryStartedAt, Date.now(), REQUEST_POLL_MS));
  }

  /* ---------- Prepare ---------- */

  async function createSigningKey() {
    state.keyBusy = true;
    state.notice = null;
    render();
    try {
      await fetchJson(`${API}/signing-key`, { method: "POST" });
    } catch (error) {
      // Another window created it first; the summary shows it as ready.
      if (error.code !== "key_exists") {
        const reason = readText(error.detail) || readText(error.text) || UNAVAILABLE_LINE.replace(/\.$/, "");
        state.notice = {
          tone: "danger",
          line: `Creating the pool signing key failed: ${reason.replace(/\.$/, "")}. Nothing changed.`,
          reason: "",
        };
      }
    } finally {
      state.keyBusy = false;
    }
    await refreshSummary();
  }

  function goToStep(step) {
    if (step === "nodes" && !view.prepareReady()) {
      return;
    }
    if (step === "review" && !view.reviewReady()) {
      return;
    }
    state.step = step;
    state.notice = null;
    render();
    schedulePoll();
    document.querySelector(".cp-content")?.scrollTo?.({ top: 0 });
  }

  /* ---------- Share slots ---------- */

  function emptySlot(extra = {}) {
    return { kind: "empty", text: "", error: "", note: "", ...extra };
  }

  function slotsChanged() {
    render();
    runChecks();
  }

  function onPoolsInput(event) {
    const target = event.target;
    if (!(target instanceof HTMLElement)) {
      return;
    }
    if (target.dataset.field === "pool-address") {
      state.poolAdd.address = target.value;
      state.poolAdd.error = "";
      state.poolAdd.added = "";
      return;
    }
    const index = Number(target.dataset.slot);
    const slot = state.slots[index];
    if (!slot) {
      return;
    }
    if (target.dataset.field === "card" && slot.kind === "empty") {
      slot.text = target.value;
      slot.error = "";
      slot.retry = false;
      window.clearTimeout(readTimers.get(index));
      readTimers.set(index, window.setTimeout(() => readCardInto(index, slot.text), CARD_READ_DELAY_MS));
    } else if (slot.kind === "include" && (target.dataset.field === "run_by" || target.dataset.field === "location")) {
      slot[target.dataset.field === "run_by" ? "runBy" : "location"] = target.value;
    }
  }

  function onPoolsChange(event) {
    const target = event.target;
    if (target instanceof HTMLTextAreaElement && target.dataset.field === "card") {
      const index = Number(target.dataset.slot);
      if (state.slots[index]?.kind === "empty") {
        readCardInto(index, target.value);
      }
    }
  }

  function onPaste(event) {
    const target = event.target;
    if (!(target instanceof HTMLTextAreaElement) || target.dataset.field !== "card") {
      return;
    }
    const text = event.clipboardData?.getData("text") || "";
    if (!text) {
      return;
    }
    event.preventDefault();
    readCardInto(Number(target.dataset.slot), text);
  }

  function dropSlot(event) {
    const slot = event.target instanceof Element ? event.target.closest(".cp-slot[data-state='drop']") : null;
    return slot instanceof HTMLElement ? slot : null;
  }

  function onDragOver(event) {
    const slot = dropSlot(event);
    if (!slot) {
      return;
    }
    event.preventDefault();
    if (event.dataTransfer) {
      event.dataTransfer.dropEffect = "copy";
    }
    slot.dataset.over = "true";
  }

  function onDragLeave(event) {
    const slot = dropSlot(event);
    if (slot && !(event.relatedTarget instanceof Node && slot.contains(event.relatedTarget))) {
      delete slot.dataset.over;
    }
  }

  function onDrop(event) {
    const slot = dropSlot(event);
    if (!slot) {
      return;
    }
    event.preventDefault();
    delete slot.dataset.over;
    const index = Number(slot.dataset.slot);
    const file = event.dataTransfer?.files?.[0];
    if (file) {
      readCardFile(index, file);
      return;
    }
    const text = event.dataTransfer?.getData("text/plain") || "";
    if (text) {
      readCardInto(index, text);
    }
  }

  async function readCardFile(index, file) {
    let text = "";
    try {
      if (file.size > MAX_CARD_FILE_BYTES) {
        throw new Error("too large");
      }
      text = await file.text();
    } catch (_error) {
      if (state.slots[index]?.kind === "empty") {
        state.slots[index] = emptySlot({ error: FILE_UNREADABLE_LINE });
        render();
      }
      return;
    }
    readCardInto(index, text);
  }

  // Card text is read as it is; any other text is the node's address, and
  // Runtime fetches the card from the node. `approval` is the request an
  // approved card came from; every slot the read leaves keeps it.
  async function readCardInto(index, rawText, approval = {}) {
    window.clearTimeout(readTimers.get(index));
    const current = state.slots[index];
    const entry = slotEntry(rawText);
    if (!current || current.kind !== "empty" || !entry) {
      return;
    }
    if (entry.address) {
      return fetchCardInto(index, entry.address);
    }
    const text = entry.card;
    if (refuseDuplicate(index, (slot) => slot.text === text, approval)) {
      return;
    }
    const token = ++readGeneration;
    state.slots[index] = { kind: "reading", text, token, ...approval };
    render();
    try {
      const read = objectValue(await fetchJson(`${API}/node-cards/read`, {
        method: "POST",
        body: JSON.stringify({ card: text }),
      }));
      if (state.slots[index]?.token !== token) {
        return;
      }
      state.slots[index] = readText(read.refused)
        ? { kind: "refused", line: refusalLine(readText(read.refused)), ...approval }
        : cardSlot(text, read, approval);
    } catch (error) {
      if (state.slots[index]?.token !== token) {
        return;
      }
      state.slots[index] = { ...failedSlot(error, text), ...approval };
    }
    slotsChanged();
  }

  async function fetchCardInto(index, address) {
    if (refuseDuplicate(index, (slot) => slot.address === address)) {
      return;
    }
    const token = ++readGeneration;
    state.slots[index] = { kind: "reading", text: "", address, token };
    render();
    try {
      const fetched = objectValue(await fetchJson(`${API}/node-cards/fetch`, {
        method: "POST",
        body: JSON.stringify({ address }),
      }));
      if (state.slots[index]?.token !== token) {
        return;
      }
      const text = slotEntry(fetched.card)?.card || "";
      if (text && refuseDuplicate(index, (slot) => slot.text === text)) {
        return;
      }
      // The same slot a pasted card makes: check and install send the text.
      state.slots[index] = text
        ? { kind: "card", text, card: objectValue(fetched.view), address }
        : emptySlot({ text: address, error: refusalLine("") });
    } catch (error) {
      if (state.slots[index]?.token !== token) {
        return;
      }
      state.slots[index] = failedSlot(error, address, address);
    }
    slotsChanged();
  }

  // Another slot already holds this card (or is reading it): refuse this one.
  function refuseDuplicate(index, same, approval = {}) {
    const duplicate = state.slots.findIndex((slot, other) => other !== index
      && (slot.kind === "card" || slot.kind === "reading") && same(slot));
    if (duplicate < 0) {
      return false;
    }
    state.slots[index] = { kind: "refused", line: refusalLine("duplicate", duplicate + 1), ...approval };
    slotsChanged();
    return true;
  }

  function openIncludeForm(index) {
    if (view.homeSlotIndex() >= 0 || state.slots[index]?.kind !== "empty") {
      return;
    }
    // A node set up earlier keeps its keys and labels; including it again
    // needs no new keys, so it fills the slot without a passkey. Whether it
    // still needs a restart comes from the summary.
    const local = objectValue(state.summary?.local_node);
    if (local.provisioned === true) {
      state.slots[index] = {
        kind: "home",
        runBy: readText(local.run_by),
        location: readText(local.location),
        restart: false,
      };
      slotsChanged();
      return;
    }
    state.slots[index] = includeDraft(state.summary);
    render();
    focusSoon(`run_by-${index}`);
  }

  async function includeThisHome(index) {
    const slot = state.slots[index];
    if (slot?.kind !== "include" || slot.busy) {
      return;
    }
    // A bad label never reaches the passkey prompt.
    if (!validLabel(slot.runBy) || !validLabel(slot.location)) {
      slot.invalid = true;
      slot.error = "";
      render();
      return;
    }
    const request = { run_by: slot.runBy, location: slot.location };
    slot.invalid = false;
    slot.error = "";
    slot.busy = true;
    render();
    let stepUpToken = "";
    try {
      stepUpToken = await requestHomePasskeyStepUp(
        homeToken,
        homeParentOrigin,
        "custody.local_node.include",
        request,
      );
    } catch (error) {
      if (state.slots[index] === slot) {
        slot.busy = false;
        slot.error = readText(error?.message) || "Passkey verification failed.";
        render();
      }
      return;
    }
    if (state.slots[index] !== slot) {
      return;
    }
    state.slots[index] = { kind: "setup" };
    render();
    try {
      const node = objectValue(await fetchJson(`${API}/local-node`, {
        method: "POST",
        body: JSON.stringify({ ...request, step_up_token: stepUpToken }),
      }));
      // An earlier node keeps its first labels; show the ones it has.
      state.slots[index] = {
        kind: "home",
        runBy: readText(node.run_by),
        location: readText(node.location),
        restart: node.needs_restart === true,
      };
      // Until the summary refreshes; the answer carries no node address.
      if (state.summary) {
        state.summary.local_node = mergeLocalNode(state.summary.local_node, node);
      }
      await refreshSummary();
    } catch (error) {
      const shown = errorView(error);
      state.slots[index] = {
        kind: "include",
        runBy: request.run_by,
        location: request.location,
        invalid: error.code === "bad_labels",
        error: error.code === "bad_labels" ? "" : [shown.line, shown.reason].filter(Boolean).join(" "),
        busy: false,
      };
    }
    slotsChanged();
  }

  function removeSlot(index) {
    const slot = state.slots[index];
    if (!slot || slot.busy) {
      return undefined;
    }
    if (slot.kind === "home" && objectValue(state.summary?.local_node).provisioned === true) {
      return removeThisHome(index);
    }
    releaseRequest(slot);
    state.slots[index] = emptySlot();
    slotsChanged();
    return undefined;
  }

  // Before install, removing this Home's slot deletes its node, so this Home
  // can offer custody to others again. Runtime keeps the node once a pool is
  // installed.
  async function removeThisHome(index) {
    const slot = state.slots[index];
    slot.busy = true;
    slot.error = "";
    render();
    const outcome = await removeLocalNode(
      (operation, request) => requestHomePasskeyStepUp(homeToken, homeParentOrigin, operation, request),
      (body) => fetchJson(`${API}/local-node`, { method: "DELETE", body: JSON.stringify(body) }),
    );
    if (state.slots[index] !== slot) {
      return refreshSummary();
    }
    if (!outcome.ok) {
      slot.busy = false;
      slot.error = [outcome.line, outcome.reason].filter(Boolean).join(" ");
      render();
      return undefined;
    }
    state.slots[index] = emptySlot({ note: outcome.note });
    slotsChanged();
    return refreshSummary();
  }

  async function runChecks() {
    const inputs = [];
    const shares = [];
    state.slots.forEach((slot, index) => {
      const input = view.slotInput(slot);
      if (input) {
        inputs.push(input);
        shares.push(index + 1);
      }
    });
    const key = view.checkKey();
    if (inputs.length < 2) {
      checkGeneration += 1;
      state.checks = null;
      state.checking = false;
      render();
      return;
    }
    if (state.checks?.key === key) {
      // The draft is back to what was checked: an older request in flight
      // must not land after this, or leave Review waiting on it.
      checkGeneration += 1;
      state.checking = false;
      render();
      return;
    }
    const generation = ++checkGeneration;
    state.checking = true;
    render();
    try {
      const response = objectValue(await fetchJson(`${API}/pool/check`, {
        method: "POST",
        body: JSON.stringify({ slots: inputs }),
      }));
      if (generation !== checkGeneration) {
        return;
      }
      state.checks = { key, shares, results: arrayValue(response.checks) };
      state.checking = false;
      if (applySlotRefusals()) {
        slotsChanged();
        return;
      }
    } catch (error) {
      if (generation !== checkGeneration) {
        return;
      }
      state.checks = null;
      state.checking = false;
      state.notice = { tone: "danger", ...errorView(error) };
    }
    render();
  }

  // Card-level failures the check found (a card that became this Home's own,
  // a copy of another slot) belong in the slot, as the read would show them.
  function applySlotRefusals() {
    let changed = false;
    const { shares, results } = state.checks;
    const shareAt = (position) => shares[Number(position) - 1];
    for (const result of results) {
      if (result?.result !== "fail") {
        continue;
      }
      const names = arrayValue(result.names);
      if (result.id === "card") {
        const share = shareAt(names[0]);
        if (share) {
          state.slots[share - 1] = { kind: "refused", line: refusalLine(readText(result.detail)) };
          changed = true;
        }
        // This Home's node lost its keys: the summary then shows no node, so
        // Include sets it up again instead of reusing it.
        if (result.detail === "local_node_no_keys") {
          refreshSummary();
        }
      } else if (result.id === "duplicate") {
        const first = shareAt(names[0]);
        const share = shareAt(names[1]);
        if (first && share) {
          state.slots[share - 1] = { kind: "refused", line: refusalLine("duplicate", first) };
          changed = true;
        }
      }
    }
    return changed;
  }

  /* ---------- Sign ---------- */

  async function signPool() {
    const slots = installSlots(state.slots);
    if (!slots || !view.reviewReady()) {
      return;
    }
    // Runtime would refuse it too; this keeps the passkey out of it.
    if (termMismatch(state.slots, state.termDays)) {
      state.notice = { tone: "danger", line: TERM_CHANGED_LINE, reason: "" };
      render();
      return;
    }
    const request = { slots, term_days: state.termDays };
    const generation = ++signGeneration;
    state.step = "sign";
    state.notice = null;
    state.sign = { phase: "confirm" };
    render();
    let stepUpToken = "";
    try {
      stepUpToken = await requestHomePasskeyStepUp(homeToken, homeParentOrigin, "custody.pool.install", request);
    } catch (error) {
      if (generation === signGeneration) {
        state.sign = { phase: "cancelled", message: readText(error?.message) };
        render();
      }
      return;
    }
    if (generation !== signGeneration) {
      return;
    }
    state.sign = { phase: "progress" };
    render();
    try {
      const result = objectValue(await fetchJson(`${API}/pool`, {
        method: "POST",
        body: JSON.stringify({ ...request, step_up_token: stepUpToken }),
      }));
      const failed = arrayValue(result.registered).filter((entry) => entry?.ok !== true);
      state.sign = {
        phase: failed.length ? "registration" : "success",
        fingerprint: readText(result.fingerprint),
        fingerprintFull: readText(result.fingerprint_full),
        failed,
      };
    } catch (error) {
      if (error.code === "install_failed") {
        state.sign = { phase: "failed", reason: readText(error.detail) };
      } else if (error.code === "already_installed") {
        state.sign = { phase: "already" };
      } else {
        state.sign = { phase: "stopped", view: errorView(error) };
        if (error.code === "checks_failed") {
          state.checks = null;
          runChecks();
        }
      }
    }
    await refreshSummary();
  }

  async function registerMember(share) {
    if (!Number.isInteger(share) || state.registering.has(share)) {
      return;
    }
    state.registering.add(share);
    state.notice = null;
    render();
    try {
      await fetchJson(`${API}/pool/members/${share}/register`, { method: "POST" });
      if (state.sign?.failed) {
        state.sign.failed = state.sign.failed.filter((entry) => entry?.share !== share);
        if (state.sign.phase === "registration" && state.sign.failed.length === 0) {
          state.sign.phase = "success";
        }
      }
    } catch (error) {
      const shown = errorView(error);
      state.notice = {
        tone: "pending",
        line: `${view.shareName(share)} is not registered on this Home yet. Releases cannot reach it.`,
        reason: shown.reason || (error.code ? "" : shown.line),
      };
    } finally {
      state.registering.delete(share);
    }
    await refreshSummary();
  }

  /* ---------- Active ---------- */

  // Tells every member not yet told again; a second press while one runs
  // sends nothing.
  // Plan B T4.3: the pools this Home uses. A failed read keeps the last list.
  async function loadKnownPools() {
    try {
      state.knownPools = { pools: readKnownPools(await fetchJson(`${API}/pools/known`)), failed: false };
    } catch (_error) {
      state.knownPools = { ...state.knownPools, failed: true };
    }
    render();
  }

  // Add a pool: the admin's passkey approves exactly this address, then
  // Runtime asks the pool and keeps its signed descriptor.
  async function addPool() {
    const address = readText(state.poolAdd.address);
    if (!address || state.poolAdd.busy) {
      return;
    }
    const request = { address };
    state.poolAdd = { address, busy: true, error: "", added: "" };
    render();
    let stepUpToken = "";
    try {
      stepUpToken = await requestHomePasskeyStepUp(homeToken, homeParentOrigin, KNOWN_POOL_ADD_OPERATION, request);
    } catch (error) {
      state.poolAdd = { address, busy: false, error: readText(error?.message) || "Passkey verification failed.", added: "" };
      render();
      return;
    }
    try {
      await fetchJson(`${API}/pools/known`, {
        method: "POST",
        body: JSON.stringify({ ...request, step_up_token: stepUpToken }),
      });
      state.poolAdd = { address: "", busy: false, error: "", added: "The pool was added." };
      await loadKnownPools();
    } catch (error) {
      state.poolAdd = { address, busy: false, error: knownPoolRefusalLine(error?.code), added: "" };
      render();
    }
  }

  async function notifyMembers() {
    const sent = notify();
    if (!sent) {
      return;
    }
    state.notifying = true;
    render();
    const result = await sent;
    state.notifying = false;
    if (result.notices && state.summary) {
      state.summary.pool_notices = {
        fingerprint_full: result.notices.fingerprintFull,
        members: result.notices.members.map((member) => ({
          share: member.share,
          recipient_name: member.name,
          state: member.state,
          code: member.code,
        })),
      };
    }
    state.notice = result.notice ? { tone: "danger", ...result.notice } : null;
    render();
  }

  async function verifyPool() {
    state.verifying = true;
    state.notice = null;
    render();
    try {
      const result = objectValue(await fetchJson(`${API}/pool/verify`, { method: "POST" }));
      const checkedAt = Number(result.checked_at);
      state.verify = { ok: true, at: Number.isFinite(checkedAt) ? checkedAt * 1000 : Date.now() };
    } catch (error) {
      const failure = verifyFailure(error);
      state.verify = failure.verify || state.verify;
      state.notice = failure.notice;
    } finally {
      state.verifying = false;
    }
    if (state.verify?.ok === true) {
      // A passing check clears a pool_problem the last summary carried.
      await refreshSummary();
      if (state.step === "active" && state.summary?.pool) {
        checkHealth();
      }
      return;
    }
    render();
  }

  // Asks every member's node over Carrier. Each check writes an audit line on
  // every node, so it runs when Active opens, after Verify again and on Check
  // nodes, and never on a timer.
  async function checkHealth() {
    const generation = ++healthGeneration;
    state.healthChecking = true;
    render();
    let health = null;
    try {
      health = readHealth(await fetchJson(`${API}/pool/health`));
    } catch (_error) {
      health = null;
    }
    if (generation !== healthGeneration) {
      return;
    }
    // A failed check keeps the last answer, shown greyed with its time.
    state.health = health || state.health;
    state.healthFailed = !health;
    state.healthChecking = false;
    render();
  }

  /* ---------- Served pools (Plan B T2.3) ---------- */

  // A failed read keeps the last list; the cards show without a status.
  async function loadServedPools() {
    if (!homeToken) {
      return;
    }
    try {
      state.servedPools = { items: readServedPools(await fetchJson(`${API}/pools/served`)), failed: false };
    } catch (_error) {
      state.servedPools = { ...state.servedPools, failed: true };
    }
    render();
  }

  // Stop serving one pool: the admin's passkey approves exactly that pool,
  // then Runtime sets its root aside. A press while one runs sends nothing.
  async function stopServing(pool) {
    if (!pool || state.stoppingPool) {
      return;
    }
    const request = stopServingRequest(pool);
    state.stoppingPool = pool;
    state.hostingNotice = null;
    render();
    let stepUpToken = "";
    try {
      stepUpToken = await requestHomePasskeyStepUp(homeToken, homeParentOrigin, SERVED_POOL_REMOVE_OPERATION, request);
    } catch (error) {
      state.stoppingPool = "";
      state.hostingNotice = { tone: "danger", line: readText(error?.message) || "Passkey verification failed.", reason: "" };
      render();
      return;
    }
    try {
      await fetchJson(`${API}/pools/served/${pool}`, {
        method: "DELETE",
        body: JSON.stringify({ ...request, step_up_token: stepUpToken }),
      });
      state.hostingNotice = { tone: "ok", line: STOPPED_SERVING_LINE, reason: "" };
    } catch (error) {
      state.hostingNotice = { tone: "danger", line: stopServingRefusalLine(error?.code), reason: "" };
    }
    state.stoppingPool = "";
    await refreshSummary();
    await loadServedPools();
  }

  // Confirm publisher for one pool (S2-A3, S2-R3-F1): the admin's passkey
  // approves exactly that pool, then Runtime keeps this admin's profile as
  // its publisher. A press while one runs sends nothing.
  async function confirmPublisher(pool) {
    if (!pool || state.confirmingPublisher) {
      return;
    }
    const request = confirmPublisherRequest(pool);
    state.confirmingPublisher = pool;
    state.hostingNotice = null;
    render();
    let stepUpToken = "";
    try {
      stepUpToken = await requestHomePasskeyStepUp(
        homeToken,
        homeParentOrigin,
        SERVED_POOL_CONFIRM_PUBLISHER_OPERATION,
        request,
      );
    } catch (error) {
      state.confirmingPublisher = "";
      state.hostingNotice = { tone: "danger", line: readText(error?.message) || "Passkey verification failed.", reason: "" };
      render();
      return;
    }
    try {
      await fetchJson(`${API}/pools/served/${pool}/publisher`, {
        method: "POST",
        body: JSON.stringify({ ...request, step_up_token: stepUpToken }),
      });
      state.hostingNotice = { tone: "ok", line: PUBLISHER_CONFIRMED_LINE, reason: "" };
    } catch (error) {
      state.hostingNotice = { tone: "danger", line: confirmPublisherRefusalLine(error?.code), reason: "" };
    }
    state.confirmingPublisher = "";
    await refreshSummary();
    await loadServedPools();
  }

  /* ---------- Hosting offer ---------- */

  // Read when Hosting opens and after each summary, never per render. Plan B
  // T2.2: a Home that serves pools keeps its offer below eight.
  async function loadOffer() {
    if (!homeToken) {
      return;
    }
    const generation = ++offerGeneration;
    let offer = null;
    let failed = null;
    try {
      offer = readOffer(await fetchJson(`${API}/offer`));
      failed = offer ? null : { line: OFFER_UNREAD_LINE, reason: "" };
    } catch (error) {
      failed = offerReadFailure(error);
    }
    if (generation !== offerGeneration) {
      return;
    }
    applyOffer(offer, failed);
    render();
  }

  // A failed read keeps the last offer on screen, with the failure above
  // Try again. The fields follow Runtime until the person edits them.
  function applyOffer(offer, failed = null) {
    const current = state.offer;
    current.view = offer || current.view;
    current.failed = offer ? null : failed;
    if (offer && !current.edited) {
      current.runBy = offer.runBy;
      current.location = offer.location;
    }
  }

  function onHostingInput(event) {
    const target = event.target;
    if (!(target instanceof HTMLInputElement)) {
      return;
    }
    const field = target.dataset.field;
    if (field === "offer_run_by" || field === "offer_location") {
      state.offer[field === "offer_run_by" ? "runBy" : "location"] = target.value;
      state.offer.edited = true;
      // An edit answers the bad-label line; the switch checks again.
      if (state.offer.invalid) {
        state.offer.invalid = false;
        render();
      }
    }
  }

  async function switchOfferTo(enabled) {
    const offer = state.offer;
    if (!offer.view || offer.busy) {
      return;
    }
    offer.busy = true;
    offer.invalid = false;
    offer.notice = null;
    render();
    // Busy lasts through any follow-up read, so the switch cannot run twice.
    try {
      const result = await switchOffer(
        (body) => fetchJson(`${API}/offer`, { method: "POST", body: JSON.stringify(body) }),
        offer.view,
        offer,
        enabled,
      );
      offer.invalid = result.invalid === true;
      offer.notice = result.notice || null;
      if (result.offer) {
        // A read that started before this answer would bring back the old offer.
        offerGeneration += 1;
        offer.edited = false;
        applyOffer(result.offer);
      } else if (!result.invalid && !result.notice) {
        await loadOffer();
      }
    } finally {
      offer.busy = false;
    }
    render();
    // The switch was disabled while busy, which drops its focus.
    if (offer.invalid || document.activeElement === document.body) {
      hostingNode?.querySelector(`[data-focus="${offer.invalid ? "offer-run-by" : "offer-switch"}"]`)?.focus();
    }
  }

  async function enableCustodyMessages() {
    const offer = state.offer;
    if (!offer.view || offer.busy) {
      return;
    }
    offer.busy = true;
    offer.notice = null;
    render();
    // Busy lasts through the follow-up read, so a second step-up cannot start.
    try {
      const outcome = await enableMessages(
        (operation, request) => requestHomePasskeyStepUp(homeToken, homeParentOrigin, operation, request),
        (body) => fetchJson(`${API}/messages/enable`, { method: "POST", body: JSON.stringify(body) }),
      );
      if (outcome.ok) {
        await loadOffer();
      } else {
        offer.notice = { line: outcome.line, reason: outcome.reason };
      }
    } finally {
      offer.busy = false;
    }
    render();
  }

  async function copyValue(button) {
    const value = readText(button.dataset.value);
    const purpose = readText(button.dataset.purpose);
    if (!value || !purpose || button.dataset.copying === "true") {
      return;
    }
    button.dataset.copying = "true";
    const outcome = await copyThroughHome(homeClipboard, value, purpose);
    delete button.dataset.copying;
    if (outcome === "copied" || outcome === "failed") {
      flashCopy(button, outcome === "copied" ? "true" : "failed");
    } else if (outcome === "fallback") {
      // No bridge to Home: show the whole value selected, so the person can
      // copy it with the keyboard.
      const code = button.parentElement?.querySelector("code");
      if (code) {
        code.textContent = value;
        const range = document.createRange();
        range.selectNodeContents(code);
        const selection = window.getSelection();
        selection?.removeAllRanges();
        selection?.addRange(range);
      }
    }
  }

  // A copy during the flash restarts it and keeps the button's own label.
  function flashCopy(button, copied) {
    const flash = copyFlashes.get(button) || { label: button.getAttribute("aria-label") || "", timer: 0 };
    window.clearTimeout(flash.timer);
    button.dataset.copied = copied;
    button.title = copied === "true" ? COPIED_LABEL : COPY_FAILED_LABEL;
    button.setAttribute("aria-label", button.title);
    flash.timer = window.setTimeout(() => {
      copyFlashes.delete(button);
      delete button.dataset.copied;
      button.removeAttribute("title");
      button.setAttribute("aria-label", flash.label);
    }, COPIED_MS);
    copyFlashes.set(button, flash);
  }

  /* ---------- Render ---------- */

  function focusSoon(key) {
    window.requestAnimationFrame(() => {
      poolsNode?.querySelector(`[data-focus="${key}"]`)?.focus();
    });
  }

  function render() {
    if (hostingNode) {
      // Hosting has fields too: a render while typing keeps the caret.
      renderKeepingFocus(hostingNode, view.hostingMarkup());
      hostingNode.hidden = hostingNode.innerHTML === "";
    }
    if (!poolsNode) {
      return;
    }
    renderKeepingFocus(poolsNode, view.poolsMarkup());
    // CSP keeps inline styles out of markup; layout numbers go through CSSOM.
    for (const grid of poolsNode.querySelectorAll("[data-slot-count]")) {
      grid.style.setProperty("--cp-slots", grid.dataset.slotCount);
    }
    for (const track of poolsNode.querySelectorAll("[data-used]")) {
      track.style.width = `${track.dataset.used}%`;
    }
  }

  function renderKeepingFocus(node, markup) {
    const active = document.activeElement instanceof HTMLElement && node.contains(document.activeElement)
      ? document.activeElement
      : null;
    const focusKey = active?.dataset.focus || "";
    const selection = active && "selectionStart" in active
      ? [active.selectionStart, active.selectionEnd]
      : null;
    node.innerHTML = markup;
    if (!focusKey) {
      return;
    }
    const next = node.querySelector(`[data-focus="${focusKey}"]`);
    if (next instanceof HTMLElement) {
      next.focus();
      if (selection && "setSelectionRange" in next) {
        try {
          next.setSelectionRange(selection[0], selection[1]);
        } catch (_error) {
          // Not every focusable control keeps a selection.
        }
      }
    }
  }

}
