    const INBOX_SAFETY_REFRESH_MS = 5 * 60 * 1000;
    const launchParams = new URLSearchParams(window.location.search);
    const homeParentOrigin = launchParams.get("home_origin") || "";
    const requestedNotificationId = launchParams.get("notification_id") || "";
    const presentation = launchParams.get("presentation") === "rail" ? "rail" : "window";
    document.documentElement.dataset.inboxPresentation = presentation;

    const state = {
      homeToken: new URLSearchParams(window.location.hash.replace(/^#/, "")).get("home_token") || "",
      entries: [],
      refreshInFlight: null,
      filter: "all",
      requestedSelectionId: requestedNotificationId.trim(),
      selectedId: requestedNotificationId.trim(),
    };

    const elements = {
      lockedShell: document.getElementById("locked-shell"),
      inboxShell: document.getElementById("inbox-shell"),
      statusText: document.getElementById("status-text"),
      pendingCount: document.getElementById("pending-count"),
      reviewCount: document.getElementById("review-count"),
      refresh: document.getElementById("refresh"),
      entryRows: document.getElementById("entry-rows"),
      entryDetail: document.getElementById("entry-detail"),
      entrySplit: document.getElementById("entry-split"),
      emptyState: document.getElementById("empty-state"),
      emptyTitle: document.getElementById("empty-title"),
      listTitle: document.getElementById("list-title"),
      filterButtons: [...document.querySelectorAll(".summary-card[data-filter]")],
    };

    configureInboxWindowSelection();
    announceHomeChrome();

    function configureInboxWindowSelection() {
      if (presentation !== "window" || !state.homeToken || window.parent === window.top) return;
      const homeToken = state.homeToken;
      const documentNonce = window.crypto.randomUUID();
      let active = true;
      let busy = false;
      let lastSequence = 0;
      window.addEventListener("pagehide", () => {
        active = false;
        window.parent.postMessage({ type: "home:app-unloading", homeToken, documentNonce }, "*");
      }, { once: true });
      window.addEventListener("message", async (event) => {
        const data = event.data;
        if (!active || event.source !== window.parent || event.origin !== "null"
          || homeToken !== state.homeToken || !data || data.homeToken !== homeToken
          || typeof data.requestId !== "string" || !/^[a-zA-Z0-9-]{1,64}$/.test(data.requestId)) return;
        if (data.type === "elastos.inbox.window-ready.request/v1"
          && hasExactKeys(data, ["type", "homeToken", "requestId"])) {
          window.parent.postMessage({ type: "elastos.inbox.window-ready.result/v1",
            homeToken, documentNonce, requestId: data.requestId }, "*");
          return;
        }
        if (data.type !== "elastos:inbox-chrome-command" || data.cmd !== "select-notification"
          || !hasExactKeys(data, ["type", "cmd", "homeToken", "requestId", "documentNonce", "sequence", "expiresAt", "query"])
          || data.documentNonce !== documentNonce || !Number.isSafeInteger(data.sequence)
          || data.sequence <= lastSequence || !Number.isSafeInteger(data.expiresAt)
          || data.expiresAt <= Date.now() || data.expiresAt > Date.now() + 15000) return;
        lastSequence = data.sequence;
        const current = () => active && homeToken === state.homeToken && Date.now() < data.expiresAt;
        let ok = false;
        let failureCopy = "Finish the current review, then open this request again.";
        if (!busy && !elements.refresh.disabled && data.query && typeof data.query === "object"
          && !Array.isArray(data.query) && hasExactKeys(data.query, ["notification_id"])
          && typeof data.query.notification_id === "string" && /^[a-zA-Z0-9:._-]{1,256}$/.test(data.query.notification_id)) {
          busy = true;
          try {
            const payload = await api("/api/apps/inbox/summary");
            if (current() && !elements.refresh.disabled) {
              state.entries = inboxEntries(payload);
              state.requestedSelectionId = data.query.notification_id;
              state.selectedId = "";
              setFilter("all");
              ok = true;
            }
          } catch (_error) {
            failureCopy = "Could not open this request. Refresh Inbox and try again.";
          } finally { busy = false; }
        }
        if (current() && !ok) setStatus(failureCopy);
        if (active) window.parent.postMessage({ type: "elastos.inbox.window.result/v1",
          homeToken, documentNonce, requestId: data.requestId, ok }, "*");
      });
      window.parent.postMessage({ type: "home:app-ready", homeToken, documentNonce }, "*");
    }

    function showLocked() {
      elements.lockedShell.classList.remove("hidden");
      elements.inboxShell.classList.add("hidden");
    }

    function showInbox() {
      elements.lockedShell.classList.add("hidden");
      elements.inboxShell.classList.remove("hidden");
    }

    function setStatus(text) {
      const message = String(text || "").trim();
      elements.statusText.textContent = message
        ? publicInboxText(message, "Inbox action could not be completed.")
        : "";
    }

    function publicInboxText(value, fallback) {
      const text = String(value || "").trim();
      if (!text || /\b(runtime mirror|projection|schema|derived facts?|capsules?|providers?|capabilit(?:y|ies)|affordances?|authority boundary|provider boundary|gate preview|runtime-owned|launch token|hostcall|request failed|failed to fetch|unauthorized|forbidden|[45]\d\d)\b|engine_[a-z_]+/i.test(text)) {
        return fallback;
      }
      return text;
    }

    function inboxEntryText(entry, field, fallback) {
      if (isCustodyRequest(entry)) {
        const request = custodyStepUpRequest(entry);
        if (!request) return field === "title" ? "Custody request" : fallback;
        if (field === "title") {
          return entry.kind === "custody_node_approving" || entry.kind === "custody_node_resumable"
            ? `Finish approving ${request.owner_name}'s custody request`
            : entry.kind === "custody_node_incomplete"
            ? `Approving ${request.owner_name}'s custody request could not finish`
            : entry.kind === "custody_node_taken"
            ? `${request.owner_name}'s custody request can no longer be approved`
            : request.owner_name + " asks this Home to hold custody";
        }
        return `${request.term_days} days, run by ${request.run_by} in ${request.location}`;
      }
      const text = String(entry[field] || "").trim();
      if (entry.kind === "browser_internet_decision" && field === "body") {
        const date = new Date(entry.created_at * 1000).toLocaleString(undefined, {dateStyle: "medium", timeStyle: "short"});
        return `${text.replace(/\.$/, "")} on ${date}.`;
      }
      // Contact and service copy contains names chosen by people, which can
      // include words used in technical messages. Render those names as text.
      const namedRequest = entry.kind === "contact_request"
        || entry.kind === "service_access_request"
        || entry.kind === "service_access_grant"
        || entry.kind === "hosted_route_decision"
        || entry.kind === "hosted_route_history";
      return namedRequest ? text || fallback : publicInboxText(text, fallback);
    }

    function notifyHome() {
      if (homeParentOrigin && window.top && window.top !== window) {
        window.top.postMessage({
          type: "home:refresh-summary",
          homeToken: state.homeToken,
        }, homeParentOrigin);
      }
    }

    function notifyRailChrome() {
      if (presentation !== "rail" || window.parent === window) {
        return;
      }
      const unreadPending = state.entries.filter((entry) => entry && (!entry.read || entry.kind === "hosted_route_decision")).length;
      window.parent.postMessage({
        type: "inbox:pending-count",
        count: unreadPending,
      }, "*");
    }

    function runtimeEventIsRelevant(event) {
      const kind = String(event && event.kind || "");
      const scope = String(event && event.scope || "");
      return scope === "inbox" || scope === "wallet" || kind.startsWith("inbox.") || kind.startsWith("wallet.");
    }

    function onRuntimeEvents(event) {
      if (event.origin !== homeParentOrigin || event.source !== window.top) {
        return;
      }
      const message = event.data || {};
      if (message.type !== "elastos:runtime-events" || !Array.isArray(message.events)) {
        return;
      }
      if (message.events.some(runtimeEventIsRelevant)) {
        requestInboxRefresh().catch(() => {});
      }
    }

    function announceHomeChrome() {
      if (!state.homeToken || !homeParentOrigin || window.top === window) {
        return;
      }
      window.top.postMessage({
        type: "home:app-ready",
        homeToken: state.homeToken,
      }, homeParentOrigin);
      window.top.postMessage({
        type: "home:menu-manifest",
        homeToken: state.homeToken,
        menus: [
          {
            title: "File",
            items: [
              { label: "Refresh", cmd: "refresh" },
              { label: "Close Window", cmd: "__close-window" },
            ],
          },
          {
            title: "View",
            items: [
              { label: "All", cmd: "filter-all" },
              { label: "Needs Review", cmd: "filter-review" },
            ],
          },
        ],
      }, homeParentOrigin);
    }

    function isTrustedHomeParentEvent(event) {
      return event.origin === "null" && event.source === window.parent;
    }

    function handleMenuCommand(cmd) {
      switch (cmd) {
        case "refresh":
          triggerRefresh().catch(() => {});
          return;
        case "filter-all":
          setFilter("all");
          return;
        case "filter-review":
          setFilter("review");
          return;
        default:
      }
    }

    window.addEventListener("message", (event) => {
      if (!isTrustedHomeParentEvent(event)) {
        return;
      }
      const message = event.data || {};
      if (message.type === "elastos:inbox-chrome-command" && message.cmd === "refresh") {
        triggerRefresh().catch(() => {});
        return;
      }
      if (message.type === "elastos:menu-command" && typeof message.cmd === "string") {
        handleMenuCommand(message.cmd);
      }
    });

    async function api(path, options) {
      const request = Object.assign({ method: "GET" }, options || {});
      request.headers = Object.assign({}, request.headers || {}, {
        "x-elastos-home-token": state.homeToken,
      });
      if (request.body && !request.headers["content-type"]) {
        request.headers["content-type"] = "application/json";
      }
      const response = await fetch(path, request);
      if (!response.ok) {
        const text = await response.text();
        const { code, detail } = refusal(text);
        const error = new Error(code
          ? refusalText(code, detail)
          : publicInboxText(text, "Inbox could not complete the request."));
        error.status = response.status;
        error.code = code;
        throw error;
      }
      return response.json();
    }

    // A custody refusal answers {code, detail}; Inbox shows its own words for
    // the code and never the Runtime's detail, which may only pick the words.
    function refusal(text) {
      try {
        const body = JSON.parse(text);
        if (body && typeof body === "object" && typeof body.code === "string"
          && /^[a-z_]{1,32}$/.test(body.code)) {
          return { code: body.code, detail: typeof body.detail === "string" ? body.detail : "" };
        }
      } catch (_error) {
      }
      return { code: "", detail: "" };
    }

    function refusalText(code, detail) {
      switch (code) {
        case "changed":
          return "This request changed after it was shown. Review it again, then approve.";
        case "expired":
          return "This request has expired. Its owner can send it again.";
        case "not_pending":
          return detail === "approving"
            ? "This request is being approved. Finish approving it."
            : "This request was already decided.";
        case "messages_not_enabled":
          return "Enable custody messages in Custody before approving.";
        case "not_contact":
          return "This owner is no longer one of your contacts.";
        case "unknown_request":
          return "This request is no longer available.";
        case "already_serving":
          return "This Home already serves another owner. Decline this request.";
        case "not_offering":
          return "This Home is not offering custody. Turn on Offer custody in Custody first.";
        case "not_admin":
          return "Only this Home's admin can decide custody requests.";
        case "too_many_requests":
          return "Too many custody requests are waiting. Decide some, then try again.";
        case "provision_failed":
          return detail === "custody_state_incomplete"
            ? "This Home's custody setup did not finish and needs repair. Decline this request."
            : "This Home could not be set up as a custody node. Try again.";
        case "card_refused":
          return "This Home could not be set up as a custody node. Try again.";
        case "no_address":
          return "This Home is not reachable on its network yet. Try again in a moment.";
        case "messages_unavailable":
          return "Custody messages are not available on this Home.";
        case "no_profile":
          return "Save your Profile before deciding custody requests.";
        case "unavailable":
          return "This Home could not read its custody setup. Try again later.";
        case "protected_content_off":
          return "Turn on protected content for this Home before approving.";
        case "withdrawal_in_progress":
          return "Metadata sharing is still stopping. Try again when it has stopped.";
        case "public_metadata_off":
          return "Metadata sharing is not offered on this Home.";
        default:
          return "Inbox action could not be completed.";
      }
    }

    // A request whose approval began and did not finish stays, past its
    // expiry too: until it is approved again, or, when this Home's custody
    // state was left incomplete, until it is declined.
    // An approval that began and set nothing up yet can still be declined.
    const CUSTODY_REQUEST_KINDS = [
      "custody_node_request", "custody_node_approving", "custody_node_resumable",
      "custody_node_incomplete", "custody_node_taken",
    ];
    // Approving began and can no longer finish: setup stopped part way, or
    // this Home serves another owner now. Only Decline settles these.
    const CUSTODY_DECLINE_ONLY_KINDS = ["custody_node_incomplete", "custody_node_taken"];

    function isCustodyRequest(entry) {
      return Boolean(entry) && CUSTODY_REQUEST_KINDS.includes(entry.kind);
    }

    function custodyDeclineOnly(entry) {
      return CUSTODY_DECLINE_ONLY_KINDS.includes(entry.kind);
    }

    function custodyApprovalBegan(entry) {
      return entry.kind === "custody_node_approving" || entry.kind === "custody_node_resumable"
        || custodyDeclineOnly(entry);
    }

    const CUSTODY_REQUEST_FIELDS = [
      "request_id", "request_sha256", "owner_name", "owner_home",
      "term_days", "run_by", "location", "expires_at",
    ];

    // The exact request the admin's passkey approves, as the Runtime rebuilt
    // it from its own record. The card shows these fields and nothing else,
    // so an entry without a well-formed one offers no approval.
    function custodyStepUpRequest(entry) {
      const request = entry && entry.step_up_request;
      if (!request || typeof request !== "object" || Array.isArray(request)
        || !hasExactKeys(request, CUSTODY_REQUEST_FIELDS)
        || typeof request.request_id !== "string" || !/^[0-9a-f]{32}$/.test(request.request_id)
        || !Number.isSafeInteger(request.term_days) || request.term_days <= 0
        || !Number.isSafeInteger(request.expires_at) || request.expires_at <= 0
        || ["request_sha256", "owner_name", "owner_home", "run_by", "location"]
          .some((field) => typeof request[field] !== "string" || !request[field].trim())
        || entry.action_ref?.action_id !== (custodyDeclineOnly(entry)
          ? "custody-decline-request:" : "custody-approve-request:") + request.request_id) {
        return null;
      }
      return request;
    }

    function custodyExpiry(request) {
      return new Intl.DateTimeFormat([], { dateStyle: "medium", timeStyle: "short" })
        .format(new Date(request.expires_at * 1000));
    }

    // OPEN-LOOP F1 (ADV-14): approving is one consent to both duties of a
    // pool node, so every card that offers Approve names them.
    const CUSTODY_NODE_DUTIES = "This Home will hold a key share and keep a copy of this pool's files.";

    // An approval that began is past its request's expiry by design, so its
    // card does not show that date.
    function createCustodyFacts(request, showExpiry, approvable) {
      const list = document.createElement("div");
      list.className = "entry-facts";
      if (approvable) {
        const duties = document.createElement("p");
        duties.className = "entry-fact-note";
        duties.textContent = CUSTODY_NODE_DUTIES;
        list.append(duties);
      }
      const fact = (label, value) => {
        const row = document.createElement("div");
        row.className = "entry-fact";
        const name = document.createElement("span");
        name.className = "entry-fact-label";
        name.textContent = label;
        const text = document.createElement("span");
        text.className = "entry-fact-value";
        text.textContent = value;
        row.append(name, text);
        return row;
      };
      const details = document.createElement("details");
      details.className = "entry-fact-details";
      const summary = document.createElement("summary");
      summary.textContent = "Details";
      details.append(summary, fact("Owner's Home: ", request.owner_home));
      list.append(
        fact("Owner: ", request.owner_name),
        fact("Term: ", request.term_days + " days"),
        fact("Run by: ", request.run_by),
        fact("Location: ", request.location),
        ...(showExpiry ? [fact("Expires: ", custodyExpiry(request))] : []),
        details,
      );
      return list;
    }

    async function requestPasskeyStepUp(operation, request) {
      if (!state.homeToken || window.top === window || !homeParentOrigin) {
        throw new Error("Open Inbox from Home to verify your passkey.");
      }
      const requestId = window.crypto?.randomUUID?.()
        || `passkey-${Date.now()}-${Math.random().toString(16).slice(2)}`;
      return new Promise((resolve, reject) => {
        const timeout = window.setTimeout(() => {
          window.removeEventListener("message", onResult);
          reject(new Error("Passkey verification timed out."));
        }, 120_000);
        const onResult = (event) => {
          if (event.source !== window.top || event.origin !== homeParentOrigin) {
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
          const stepUpToken = typeof result.stepUpToken === "string"
            ? result.stepUpToken.trim()
            : "";
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
          reject(new Error(typeof result.error === "string" && result.error.trim()
            ? result.error.trim()
            : "Passkey verification failed."));
        };
        window.addEventListener("message", onResult);
        window.top.postMessage({
          type: "elastos.home.passkey-step-up.request/v1",
          requestId,
          homeToken: state.homeToken,
          operation,
          request,
        }, homeParentOrigin);
      });
    }

    function hasExactKeys(value, expectedKeys) {
      const actual = Object.keys(value).sort();
      const expected = expectedKeys.slice().sort();
      return actual.length === expected.length
        && actual.every((key, index) => key === expected[index]);
    }

    async function inboxAction(actionId, fields = {}) {
      return api("/api/apps/inbox/actions", {
        method: "POST",
        body: JSON.stringify(Object.assign({ action_id: actionId }, fields)),
      });
    }

    async function loadInbox() {
      const payload = await api("/api/apps/inbox/summary");
      state.entries = inboxEntries(payload);
      renderInbox();
      markVisibleRead();
      notifyHome();
    }

    function inboxEntries(payload) {
      const entries = Array.isArray(payload.notifications?.entries) ? payload.notifications.entries.slice() : [];
      const routes = Array.isArray(payload.hosted_routes) ? payload.hosted_routes : [];
      for (const route of routes) {
        if (!route || !/^[a-zA-Z0-9:-]{1,128}$/.test(route.id || "")
          || !["pending", "approved", "denied", "ended", "expired"].includes(route.status)) continue;
        const status = route.status[0].toUpperCase() + route.status.slice(1);
        const expires = route.connection && route.expires_at === 0
          ? "Until End or configuration change" : Number.isSafeInteger(route.expires_at)
          ? new Date(route.expires_at * 1000).toLocaleString() : "Unavailable";
        const actionId = route.status === "pending" ? `model-egress-approve:${route.id}`
          : route.status === "approved" ? `model-egress-end:${route.id}` : "";
        entries.push({
          id: `external-http-request:${route.id}`,
          kind: route.status === "pending" ? "hosted_route_decision" : "hosted_route_history",
          source_app: String(route.offer_id || "").startsWith("validation:") ? "system" : "assistant",
          title: `${route.provider || "Hosted model"} ${route.connection ? "connection" : "route"} · ${status}`,
          body: route.connection
            ? `Provider: ${route.provider || "Hosted model"}\nApproved HTTPS origin: ${route.origin || ""}\nRuntime may check the key and send configured Assistant model prompts to its pinned provider routes at this origin. Runtime checks each route and effect before dispatch. The key stays on this Home.\nRecipient: ${route.recipient || ""}\nPayer: ${route.payer || ""}\nExpires: ${expires}`
            : `Provider: ${route.provider || "Hosted model"}\nRoute: ${route.method || ""} ${route.origin || ""}${route.path || ""}\nExact URL SHA-256: ${route.url_sha256 || ""}\nOrigin: ${route.origin || ""}\nRecipient: ${route.recipient || ""}\nPayer: ${route.payer || ""}\nPurpose: ${route.purpose || ""}\nExpires: ${expires}`,
          severity: route.status === "pending" ? "attention" : "info",
          read: true,
          created_at: route.requested_at,
          action_ref: actionId ? { app: "inbox", action_id: actionId } : null,
        });
      }
      return entries.sort((a, b) => (b.created_at || 0) - (a.created_at || 0));
    }

    function requestInboxRefresh() {
      if (state.refreshInFlight) {
        return state.refreshInFlight;
      }
      state.refreshInFlight = loadInbox()
        .catch((error) => {
          setStatus(error.message || "Could not refresh inbox.");
          throw error;
        })
        .finally(() => {
          state.refreshInFlight = null;
        });
      return state.refreshInFlight;
    }

    function filteredEntries() {
      if (state.filter === "review") {
        return state.entries.filter((entry) => entry && entry.severity === "attention");
      }
      return state.entries;
    }

    function setFilter(filter) {
      state.filter = filter === "review" ? "review" : "all";
      for (const button of elements.filterButtons) {
        const active = button.dataset.filter === state.filter;
        button.classList.toggle("active", active);
        button.setAttribute("aria-pressed", active ? "true" : "false");
      }
      elements.listTitle.textContent = state.filter === "review" ? "Needs Review" : "All";
      renderInbox();
    }

    function pendingRequestEntries() {
      return state.entries.filter((entry) => entry && entry.kind !== "service_access_grant" && entry.kind !== "hosted_route_history" && entry.kind !== "browser_internet_decision");
    }

    function renderInbox() {
      const entries = filteredEntries();
      const attentionCount = state.entries.filter((entry) => entry && entry.severity === "attention").length;
      const pendingCount = pendingRequestEntries().length;
      elements.pendingCount.textContent = String(pendingCount);
      // The list shows grants and route history too; the count is only pending requests.
      elements.filterButtons.find((button) => button.dataset.filter === "all")
        ?.setAttribute("aria-label", `All, ${pendingCount} pending ${pendingCount === 1 ? "request" : "requests"}`);
      elements.reviewCount.textContent = String(attentionCount);
      const requestedSelectionPresent = state.requestedSelectionId
        && entries.some((entry) => entryId(entry) === state.requestedSelectionId);
      const requestedSelectionMissing = state.requestedSelectionId
        && !requestedSelectionPresent;
      if (!entries.some((entry) => entry.id === state.selectedId)) {
        state.selectedId = requestedSelectionPresent
          ? state.requestedSelectionId
          : requestedSelectionMissing
          ? ""
          : entries.length ? entryId(entries[0]) : "";
      }
      elements.entryRows.replaceChildren();
      if (presentation === "rail") {
        for (const entry of entries) {
          elements.entryRows.appendChild(createRailCard(entry));
        }
        elements.entryDetail.replaceChildren();
      } else {
        for (const entry of entries) {
          elements.entryRows.appendChild(createRow(entry));
        }
        renderDetail(
          entries.find((entry) => entryId(entry) === state.selectedId) || null,
          requestedSelectionMissing,
        );
      }
      const empty = entries.length === 0;
      elements.emptyState.classList.toggle("hidden", !empty);
      elements.entrySplit.classList.toggle("hidden", empty);
      elements.emptyTitle.textContent =
        state.filter === "review" && state.entries.length !== 0
          ? "No requests need review"
          : "No requests";
      setStatus(pendingCount === 0 ? "" : `${pendingCount} pending.`);
      notifyRailChrome();
    }

    function entryId(entry) {
      return entry && typeof entry.id === "string" ? entry.id : "";
    }

    function createRow(entry) {
      const row = document.createElement("button");
      row.type = "button";
      row.className = "entry-row";
      row.setAttribute("role", "option");
      row.setAttribute("aria-selected", entryId(entry) === state.selectedId ? "true" : "false");
      row.classList.toggle("active", entryId(entry) === state.selectedId);
      row.classList.toggle("entry-row-unread", !entry.read);

      const top = document.createElement("div");
      top.className = "entry-row-top";
      const title = document.createElement("span");
      title.className = "entry-row-title";
      title.textContent = inboxEntryText(entry, "title", "Request");
      const time = document.createElement("span");
      time.className = "entry-row-time";
      time.textContent = entry.created_at ? formatInboxTime(entry.created_at) : "";
      top.append(title, time);

      const snippet = document.createElement("span");
      snippet.className = "entry-row-snippet";
      snippet.textContent = inboxEntryText(entry, "body", "This request needs your review.");

      row.append(top, snippet);
      row.addEventListener("click", () => {
        state.requestedSelectionId = "";
        state.selectedId = entryId(entry);
        renderInbox();
      });
      return row;
    }

    function createRailCard(entry) {
      const card = document.createElement("article");
      card.className = "entry-rail-card";
      if (!entry.read) {
        card.classList.add("entry-row-unread");
      }

      const top = document.createElement("div");
      top.className = "entry-row-top";
      const title = document.createElement("span");
      title.className = "entry-row-title";
      title.textContent = inboxEntryText(entry, "title", "Request");
      const time = document.createElement("span");
      time.className = "entry-row-time";
      time.textContent = entry.created_at ? formatInboxTime(entry.created_at) : "";
      top.append(title, time);

      const snippet = document.createElement("span");
      snippet.className = "entry-row-snippet";
      snippet.textContent = inboxEntryText(entry, "body", "This request needs your review.");

      const actions = document.createElement("div");
      actions.className = "entry-actions";
      fillEntryActions(actions, entry);

      card.append(top, snippet, actions);
      return card;
    }

    // META-PUBLIC A4: one Runtime-built card per public metadata state. Agree
    // asks the Home's passkey over exactly the request the card shows; Stop
    // sharing asks to confirm and needs no passkey; Try again repeats Stop.
    const PUBLIC_METADATA_KINDS = [
      "public_metadata_consent", "public_metadata_sharing", "public_metadata_paused",
      "public_metadata_stopping", "public_metadata_unreadable",
    ];
    const PUBLIC_METADATA_ENABLE = "public-metadata-enable";
    const PUBLIC_METADATA_STOP = "public-metadata-stop";

    function publicMetadataStepUpRequest(entry) {
      const request = entry && entry.step_up_request;
      if (entry?.passkey_approval !== true
        || entry.action_ref?.action_id !== PUBLIC_METADATA_ENABLE
        || !request || typeof request !== "object" || Array.isArray(request)
        || !hasExactKeys(request, ["wording_version", "wording_sha256"])
        || !Number.isInteger(request.wording_version)
        || typeof request.wording_sha256 !== "string"
        || !/^[0-9a-f]{64}$/.test(request.wording_sha256)) {
        return null;
      }
      return request;
    }

    async function agreePublicMetadata(button, request) {
      setButtonsDisabled(true);
      button.disabled = true;
      setStatus("Confirm with your passkey to turn on metadata sharing.");
      try {
        // The passkey signs exactly the object the card shows, and the
        // Runtime compares it with its own request before spending it.
        const stepUpToken = await requestPasskeyStepUp("creator.public_ipfs.enable", request);
        const outcome = await inboxAction(PUBLIC_METADATA_ENABLE, {
          step_up_token: stepUpToken,
          step_up_request: request,
        });
        await loadInbox();
        notifyHome();
        elements.statusText.textContent = typeof outcome?.message === "string" && outcome.message.trim()
          ? outcome.message.trim() : "Metadata sharing is on.";
      } catch (error) {
        if (error && error.code) {
          await loadInbox().catch(() => {});
        }
        throw error;
      } finally {
        setButtonsDisabled(false);
      }
    }

    function confirmPublicMetadataStop() {
      const dialog = document.querySelector("#public-metadata-confirm");
      return new Promise(resolve => {
        dialog.addEventListener("close", () => resolve(dialog.returnValue === "stop"), {once:true});
        dialog.showModal();dialog.querySelector('[value="cancel"]').focus();
      });
    }

    function fillPublicMetadataActions(actions, entry) {
      const actionId = entry.action_ref && entry.action_ref.action_id;
      if (entry.kind === "public_metadata_consent") {
        const request = publicMetadataStepUpRequest(entry);
        if (request) {
          actions.appendChild(createButton("Agree", (button) => agreePublicMetadata(button, request), "primary"));
        }
        return;
      }
      if (actionId !== PUBLIC_METADATA_STOP) {
        return;
      }
      if (entry.kind === "public_metadata_stopping") {
        actions.appendChild(createActionButton("Try again", PUBLIC_METADATA_STOP, "primary"));
        return;
      }
      actions.appendChild(createButton("Stop sharing", async () => {
        if (!await confirmPublicMetadataStop()) return;
        await runAction(PUBLIC_METADATA_STOP);
        notifyHome();
      }, "danger"));
    }

    function confirmBrowserInternetOff() {
      const dialog = document.querySelector("#browser-internet-confirm");
      return new Promise(resolve => {
        dialog.addEventListener("close", () => resolve(dialog.returnValue === "off"), {once:true});
        dialog.showModal();dialog.querySelector('[value="cancel"]').focus();
      });
    }

    async function allowBrowserInternet(actionId) {
      setButtonsDisabled(true);
      try {
        const current = actionId ? await api("/api/apps/browser/internet")
          : await api("/api/apps/browser/internet", {method:"POST",body:JSON.stringify({action:"request"})});
        const expected = "browser-internet-allow:" + current.request?.request_id;
        if (current.status !== "requested" || (actionId && actionId !== expected)) {
          throw new Error("This request has changed. Refresh Inbox and review the current request.");
        }
        const stepUpToken = await requestPasskeyStepUp("browser.internet.grant", current.request);
        await inboxAction(expected, {step_up_token:stepUpToken});
        setStatus("Browser can open websites.");await loadInbox();notifyHome();
        window.top.postMessage({type:"home:focus-browser",homeToken:state.homeToken},homeParentOrigin);
      } finally {setButtonsDisabled(false);}
    }

    function fillEntryActions(actions, entry) {
      const actionId = entry.action_ref && entry.action_ref.action_id;
      // A standing card: its state is the Runtime's, so no Open or Dismiss.
      if (PUBLIC_METADATA_KINDS.includes(entry.kind)) {
        fillPublicMetadataActions(actions, entry);
        return;
      }
      if (entry.kind === "browser_internet_decision") {
        if (actionId?.startsWith("browser-internet-turn-off:")) {
          actions.appendChild(createButton("Turn Off", async () => {
            if (!await confirmBrowserInternetOff()) return;
            setButtonsDisabled(true);
            try {
              const current = await api("/api/apps/browser/internet");
              const stepUpToken = current.stop_pending ? undefined : await requestPasskeyStepUp("browser.internet.revoke", current.request);
              await inboxAction(actionId, {step_up_token:stepUpToken});
              await loadInbox();notifyHome();
            } finally { setButtonsDisabled(false); }
          }, "danger"));
        } else if (actionId === "browser-internet-request") {
          actions.appendChild(createButton("Allow", () => allowBrowserInternet(), "primary"));
        }
        return;
      }
      // A request Inbox decides itself has no other app to open.
      if (entry.kind !== "browser_internet_request" && typeof entry.source_app === "string" && entry.source_app.trim() && entry.source_app.trim() !== "inbox") {
        // A direct-message notice opens its own conversation in Chat.
        const query = typeof actionId === "string" && actionId.startsWith("chat-open-direct:")
          ? { conversation_id: actionId.slice("chat-open-direct:".length) } : {};
        actions.appendChild(createButton("Open", () => openSource(entry.source_app, query)));
      }

      if (typeof actionId === "string" && actionId.startsWith("browser-internet-allow:")) {
        actions.appendChild(createActionButton("Don't Allow", actionId.replace("browser-internet-allow:", "browser-internet-deny:")));
        actions.appendChild(createButton("Allow", () => allowBrowserInternet(actionId), "primary"));
      } else if (typeof actionId === "string" && actionId.startsWith("room-approve-request:")) {
        actions.appendChild(createActionButton("Approve", actionId, "primary"));
        actions.appendChild(createActionButton("Deny", "room-deny-request:" + actionId.slice("room-approve-request:".length), "danger"));
      } else if (typeof actionId === "string" && actionId.startsWith("contact-accept-request:")) {
        actions.appendChild(createActionButton("Accept", actionId, "primary"));
        actions.appendChild(createActionButton("Decline", "contact-decline-request:" + actionId.slice("contact-accept-request:".length), "danger"));
      } else if (typeof actionId === "string" && actionId.startsWith("service-approve-request:")) {
        actions.appendChild(createActionButton("Approve", actionId, "primary"));
        actions.appendChild(createActionButton("Deny", "service-deny-request:" + actionId.slice("service-approve-request:".length), "danger"));
      } else if (typeof actionId === "string" && actionId.startsWith("service-deny-request:")) {
        actions.appendChild(createActionButton("Revoke access", actionId, "danger"));
      } else if (typeof actionId === "string" && actionId.startsWith("wallet-approve-request:")) {
        const requestId = actionId.slice("wallet-approve-request:".length);
        // Inbox signs only with a built-in wallet, after a passkey. Any other
        // account, such as an external wallet, is approved in Wallet.
        const passkeyApproval = entry.passkey_approval === true;
        if (passkeyApproval) {
          actions.appendChild(createButton("Approve", (button) => approveWalletRequest(button, requestId), "primary"));
        }
        actions.appendChild(createButton("Review in Wallet", () => openSource("wallet", { wallet_request: requestId }), passkeyApproval ? undefined : "primary"));
        actions.appendChild(createActionButton("Reject", "wallet-reject-request:" + actionId.slice("wallet-approve-request:".length), "danger"));
      } else if (typeof actionId === "string" && actionId.startsWith("wallet-review-request:")) {
        const requestId = actionId.slice("wallet-review-request:".length);
        actions.appendChild(createButton("Review in Wallet", () => openSource("wallet", { wallet_request: requestId }), "primary"));
      } else if (typeof actionId === "string" && actionId.startsWith("custody-approve-request:")) {
        const requestId = actionId.slice("custody-approve-request:".length);
        if (entry.passkey_approval === true && custodyStepUpRequest(entry)) {
          actions.appendChild(createButton("Approve", (button) => approveCustodyRequest(button, entry), "primary"));
        }
        // Approving may already have set this Home up; it can only be finished.
        if (entry.kind !== "custody_node_approving") {
          actions.appendChild(createActionButton("Decline", "custody-decline-request:" + requestId, "danger"));
        }
      } else if (typeof actionId === "string" && actionId.startsWith("custody-decline-request:")
        && custodyDeclineOnly(entry)) {
        // Approving can no longer finish: only declining settles it.
        actions.appendChild(createActionButton("Decline", actionId, "danger"));
      } else if (typeof actionId === "string" && actionId.startsWith("capability-approve-request:")) {
        actions.appendChild(createActionButton("Approve", actionId, "primary"));
        actions.appendChild(createActionButton("Deny", "capability-deny-request:" + actionId.slice("capability-approve-request:".length), "danger"));
      } else if (typeof actionId === "string" && actionId.startsWith("inspect-approve-request:")) {
        const requestId = actionId.slice("inspect-approve-request:".length);
        const approveButton = createButton("Approve", (button) => approveInspectRequest(button, requestId), "primary");
        approveButton.dataset.actionId = actionId;
        actions.appendChild(approveButton);
        actions.appendChild(createButton("Deny", () => denyInspectRequest(requestId), "danger"));
      } else if (typeof actionId === "string" && actionId.startsWith("model-egress-approve:")) {
        actions.appendChild(createActionButton("Approve", actionId, "primary"));
        actions.appendChild(createActionButton("Deny", "model-egress-deny:" + actionId.slice("model-egress-approve:".length), "danger"));
        actions.appendChild(createActionButton("End", "model-egress-end:" + actionId.slice("model-egress-approve:".length), "danger"));
      } else if (typeof actionId === "string" && actionId.startsWith("model-egress-end:")) {
        actions.appendChild(createActionButton("End", actionId, "danger"));
      } else if (typeof actionId === "string" && actionId.startsWith("hosted-http-approve:")) {
        actions.appendChild(createActionButton("Approve", actionId, "primary"));
        actions.appendChild(createActionButton("Deny", "hosted-http-deny:" + actionId.slice("hosted-http-approve:".length), "danger"));
      } else if (typeof actionId === "string" && actionId.startsWith("community-presence-always:")) {
        const request = actionId.slice("community-presence-always:".length);
        actions.appendChild(createActionButton("Always while Home is online", actionId, "primary"));
        actions.appendChild(createActionButton("Only while Community is open", "community-presence-open:" + request));
        actions.appendChild(createActionButton("Later", "community-presence-later:" + request));
        actions.appendChild(createActionButton("Never", "community-presence-never:" + request, "danger"));
      } else if (typeof actionId === "string" && actionId.includes("-http-approve:")) {
        // Every request to let this Home talk to an outside service is the
        // same decision, so it is matched by shape rather than by naming each
        // one: "<what>-http-approve:<source>" always pairs with
        // "<what>-http-deny:<source>". Naming them individually is why the
        // creator's channel-list request arrived with nothing to press.
        const denyId = actionId.replace("-http-approve:", "-http-deny:");
        actions.appendChild(createActionButton("Approve", actionId, "primary"));
        actions.appendChild(createActionButton("Reject", denyId, "danger"));
      }

      if (entry.kind !== "browser_internet_request" && entry.kind !== "wallet_approval_request" && entry.kind !== "capability_request" && entry.kind !== "inspect_action_request" && entry.kind !== "external_http_request" && entry.kind !== "hosted_route_decision" && entry.kind !== "hosted_route_history" && entry.kind !== "contact_request" && entry.kind !== "service_access_request" && entry.kind !== "service_access_grant" && entry.kind !== "community_presence_request" && !isCustodyRequest(entry)) {
        actions.appendChild(createActionButton("Dismiss", "notification-dismiss:" + entry.id));
      }
    }

    function renderDetail(entry, requestedSelectionMissing = false) {
      elements.entryDetail.replaceChildren();
      if (!entry) {
        const placeholder = document.createElement("div");
        placeholder.className = "entry-detail-placeholder";
        placeholder.textContent = requestedSelectionMissing
          ? "That request is no longer available. Select another request."
          : "Select a request";
        elements.entryDetail.appendChild(placeholder);
        return;
      }

      const titleRow = document.createElement("div");
      titleRow.className = "entry-title-row";
      const title = document.createElement("div");
      title.className = "entry-title";
      title.textContent = inboxEntryText(entry, "title", "Request");
      titleRow.appendChild(title);
      if (entry.severity === "attention") {
        const badge = document.createElement("span");
        badge.className = "entry-badge";
        badge.textContent = "Review";
        titleRow.appendChild(badge);
      }
      if (!entry.read) {
        const badge = document.createElement("span");
        badge.className = "entry-badge";
        badge.textContent = "New";
        titleRow.appendChild(badge);
      }

      const time = document.createElement("time");
      time.className = "entry-time";
      if (entry.created_at) {
        time.dateTime = new Date(entry.created_at * 1000).toISOString();
        time.textContent = formatInboxTime(entry.created_at);
      }

      const bodyText = inboxEntryText(entry, "body", "This request needs your review.");
      const custodyRequest = isCustodyRequest(entry) ? custodyStepUpRequest(entry) : null;
      const body = custodyRequest
        ? createCustodyFacts(custodyRequest, !custodyApprovalBegan(entry), !custodyDeclineOnly(entry))
        : entry.kind === "hosted_route_decision" || entry.kind === "hosted_route_history"
        ? createFactList(bodyText) : document.createElement("p");
      body.classList.add("entry-body");
      if (body.tagName === "P") body.textContent = bodyText;

      const actions = document.createElement("div");
      actions.className = "entry-actions";
      fillEntryActions(actions, entry);
      elements.entryDetail.append(titleRow, time, body, actions);
    }

    function createFactList(text) {
      const list = document.createElement("div");
      list.className = "entry-facts";
      for (const line of text.split("\n")) {
        const fact = /^([A-Z][A-Za-z0-9 -]{0,32}): (.*)$/.exec(line);
        if (!fact) {
          const note = document.createElement("p");
          note.className = "entry-fact-note";
          note.textContent = line;
          list.append(note);
          continue;
        }
        const row = document.createElement("div");
        row.className = "entry-fact";
        const label = document.createElement("span");
        label.className = "entry-fact-label";
        label.textContent = `${fact[1]}: `;
        const value = document.createElement("span");
        value.className = "entry-fact-value";
        value.textContent = fact[2];
        row.append(label, value);
        list.append(row);
      }
      return list;
    }

    function createButton(label, onClick, className) {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "entry-action" + (className ? " " + className : "");
      button.textContent = label;
      button.addEventListener("click", () => {
        Promise.resolve(onClick(button)).catch((error) => {
          setStatus(error.message || "Action failed.");
        });
      });
      return button;
    }

    function createActionButton(label, actionId, className) {
      const button = createButton(label, () => runAction(actionId), className);
      button.dataset.actionId = actionId;
      return button;
    }

    async function runAction(actionId) {
      setButtonsDisabled(true);
      try {
        await inboxAction(actionId);
        await loadInbox();
      } catch (error) {
        if (error && error.status === 503) {
          try {
            await loadInbox();
          } catch (_) {
          }
        }
        throw error;
      } finally {
        setButtonsDisabled(false);
      }
    }

    async function approveWalletRequest(button, requestId) {
      if (!requestId) {
        return;
      }
      setButtonsDisabled(true);
      button.disabled = true;
      setStatus("Confirm with your passkey to sign.");
      try {
        const stepUpToken = await requestPasskeyStepUp("wallet.approve", {
          request_id: requestId,
          reason: "Approved in Inbox",
        });
        await inboxAction("wallet-approve-request:" + requestId, {
          step_up_token: stepUpToken,
        });
        setStatus("Request signed.");
        await loadInbox();
        notifyHome();
      } finally {
        setButtonsDisabled(false);
      }
    }

    async function approveCustodyRequest(button, entry) {
      const request = custodyStepUpRequest(entry);
      if (!request) {
        return;
      }
      setButtonsDisabled(true);
      button.disabled = true;
      setStatus("Confirm with your passkey to approve this custody request.");
      try {
        // The passkey signs exactly the object the card shows, and the
        // Runtime compares it with its own record before spending it.
        const stepUpToken = await requestPasskeyStepUp("custody.node_request.approve", request);
        const outcome = await inboxAction("custody-approve-request:" + request.request_id, {
          step_up_token: stepUpToken,
          step_up_request: request,
        });
        await loadInbox();
        notifyHome();
        // Runtime's own copy; it names the owner, so it is shown as text.
        elements.statusText.textContent = typeof outcome?.message === "string" && outcome.message.trim()
          ? outcome.message.trim() : "Custody request approved.";
      } catch (error) {
        // A refused request shows as it now stands before the reason.
        if (error && error.code) {
          await loadInbox().catch(() => {});
        }
        throw error;
      } finally {
        setButtonsDisabled(false);
      }
    }

    async function approveInspectRequest(button, requestId) {
      if (!requestId) {
        return;
      }
      setButtonsDisabled(true);
      button.disabled = true;
      setStatus("Confirm with your passkey to approve this System action.");
      try {
        const stepUpToken = await requestPasskeyStepUp("inspect.approve", {
          request_id: requestId,
        });
        const outcome = await inboxAction("inspect-approve-request:" + requestId, {
          step_up_token: stepUpToken,
        });
        requireInspectActionResult(outcome, requestId, "completed");
        setStatus("System action approved.");
        await loadInbox();
        notifyHome();
      } finally {
        setButtonsDisabled(false);
      }
    }

    async function denyInspectRequest(requestId) {
      if (!requestId) {
        return;
      }
      setButtonsDisabled(true);
      try {
        const outcome = await inboxAction("inspect-deny-request:" + requestId);
        requireInspectActionResult(outcome, requestId, "denied");
        setStatus("System action denied.");
        await loadInbox();
        notifyHome();
      } finally {
        setButtonsDisabled(false);
      }
    }

    function requireInspectActionResult(outcome, requestId, expectedStatus) {
      const result = outcome && outcome.result;
      const binding = result && result.request_binding;
      if (
        !result ||
        result.schema !== "elastos.inspect.action-result/v1" ||
        result.status !== expectedStatus ||
        result.request_id !== requestId ||
        !binding ||
        binding.schema !== "elastos.esp.request-binding/v1" ||
        binding.request_id !== requestId ||
        typeof binding.principal !== "string" || !binding.principal ||
        typeof binding.capsule !== "string" || !binding.capsule ||
        binding.interface !== null ||
        typeof binding.method !== "string" || !binding.method ||
        !Array.isArray(binding.resources) ||
        typeof binding.sha256 !== "string" || !binding.sha256 ||
        typeof binding.bytes !== "number"
      ) {
        throw new Error("Runtime did not return the exact System action result.");
      }
      if (expectedStatus === "denied") {
        if (result.dispatch_result != null) {
          throw new Error("Denied System action returned an unexpected dispatch result.");
        }
        return result;
      }
      const dispatch = result.dispatch_result;
      const provider = dispatch && dispatch.provider_response;
      const transfer = provider && provider._runtime_transfer;
      if (
        !dispatch ||
        dispatch.schema !== "elastos.inspect.dispatch-result/v1" ||
        !sameInspectRequestBinding(dispatch.request_binding, binding) ||
        dispatch.id !== binding.capsule ||
        dispatch.operation !== binding.method ||
        !provider || provider.status !== "ok" ||
        !transfer ||
        transfer.schema !== "elastos.provider.transfer/v1" ||
        transfer.source !== "inspect" ||
        transfer.target !== dispatch.target ||
        transfer.op !== binding.method ||
        transfer.status !== "completed"
      ) {
        throw new Error("Runtime returned an unrelated System action result.");
      }
      return result;
    }

    function sameInspectRequestBinding(left, right) {
      return Boolean(
        left && right &&
        left.schema === right.schema &&
        left.request_id === right.request_id &&
        left.principal === right.principal &&
        left.capsule === right.capsule &&
        left.interface === right.interface &&
        left.method === right.method &&
        JSON.stringify(left.resources) === JSON.stringify(right.resources) &&
        left.sha256 === right.sha256 &&
        left.bytes === right.bytes &&
        left.truncated === right.truncated &&
        canonicalInboxJson(left.preview) === canonicalInboxJson(right.preview)
      );
    }

    function canonicalInboxJson(value) {
      if (Array.isArray(value)) {
        return "[" + value.map(canonicalInboxJson).join(",") + "]";
      }
      if (value && typeof value === "object") {
        return "{" + Object.keys(value).sort().map((key) =>
          JSON.stringify(key) + ":" + canonicalInboxJson(value[key])
        ).join(",") + "}";
      }
      return JSON.stringify(value);
    }

    function setButtonsDisabled(disabled) {
      for (const container of [elements.entryRows, elements.entryDetail]) {
        for (const button of container.querySelectorAll("button")) {
          button.disabled = disabled;
        }
      }
      elements.refresh.disabled = disabled;
    }

    function openSource(sourceApp, query = {}) {
      const target = typeof sourceApp === "string" ? sourceApp.trim() : "";
      if (!target || !homeParentOrigin || !window.top || window.top === window) {
        return;
      }
      window.top.postMessage({
        type: "home:open-target",
        target,
        query,
        homeToken: state.homeToken,
      }, homeParentOrigin);
    }

    function markVisibleRead() {
      const unreadIds = state.entries
        .filter((entry) => entry && entry.id && !entry.read
          && entry.kind !== "wallet_approval_request"
          && entry.kind !== "browser_internet_request"
          && entry.kind !== "contact_request" && entry.kind !== "service_access_request"
          && !isCustodyRequest(entry))
        .map((entry) => entry.id);
      if (unreadIds.length === 0) {
        return;
      }
      Promise.all(
        unreadIds.map((id) => inboxAction("notification-read:" + id).catch(() => null)),
      ).then(() => {
        const unreadIdSet = new Set(unreadIds);
        for (const entry of state.entries) {
          if (unreadIdSet.has(entry.id)) {
            entry.read = true;
          }
        }
        renderInbox();
        notifyHome();
      });
    }

    function formatInboxTime(createdAt) {
      const ageSeconds = Math.max(0, Math.floor(Date.now() / 1000) - Number(createdAt || 0));
      if (ageSeconds < 60) {
        return "just now";
      }
      if (ageSeconds < 3600) {
        return Math.floor(ageSeconds / 60) + "m ago";
      }
      if (ageSeconds < 86400) {
        return Math.floor(ageSeconds / 3600) + "h ago";
      }
      return new Intl.DateTimeFormat([], {
        month: "short",
        day: "numeric",
        hour: "numeric",
        minute: "2-digit",
      }).format(new Date(Number(createdAt) * 1000));
    }

    elements.refresh.addEventListener("click", () => {
      triggerRefresh().catch(() => {});
    });

    for (const button of elements.filterButtons) {
      button.addEventListener("click", () => {
        setFilter(button.dataset.filter);
      });
    }

    elements.entryRows.addEventListener("keydown", (event) => {
      if (presentation === "rail" || !["ArrowDown", "ArrowUp", "Home", "End"].includes(event.key)) {
        return;
      }
      const entries = filteredEntries();
      if (!entries.length) {
        return;
      }
      const currentIndex = entries.findIndex((entry) => entryId(entry) === state.selectedId);
      const index = currentIndex >= 0 ? currentIndex : 0;
      let next = index;
      if (event.key === "ArrowDown") {
        next = Math.min(entries.length - 1, index + 1);
      } else if (event.key === "ArrowUp") {
        next = Math.max(0, index - 1);
      } else if (event.key === "Home") {
        next = 0;
      } else {
        next = entries.length - 1;
      }
      if (next === index) {
        return;
      }
      event.preventDefault();
      state.requestedSelectionId = "";
      state.selectedId = entryId(entries[next]);
      renderInbox();
      const rows = elements.entryRows.querySelectorAll(".entry-row");
      rows[next]?.focus();
    });

    function triggerRefresh() {
      setButtonsDisabled(true);
      return requestInboxRefresh()
        .catch((error) => setStatus(error.message || "Could not refresh."))
        .finally(() => setButtonsDisabled(false));
    }

    if (!state.homeToken) {
      showLocked();
    } else {
      showInbox();
      requestInboxRefresh().catch(() => {});
      window.addEventListener("message", onRuntimeEvents);
      window.setInterval(() => {
        if (document.hidden) {
          return;
        }
        requestInboxRefresh().catch(() => {});
      }, INBOX_SAFETY_REFRESH_MS);
      document.addEventListener("visibilitychange", () => {
        if (document.hidden) {
          return;
        }
        requestInboxRefresh().catch(() => {});
      });
    }
