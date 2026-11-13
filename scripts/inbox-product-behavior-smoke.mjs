#!/usr/bin/env node

import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";

class FakeClassList {
  constructor(owner) {
    this.owner = owner;
  }

  add(name) {
    this.toggle(name, true);
  }

  remove(name) {
    this.toggle(name, false);
  }

  toggle(name, enabled) {
    const names = new Set(String(this.owner.className || "").split(/\s+/).filter(Boolean));
    enabled ? names.add(name) : names.delete(name);
    this.owner.className = [...names].join(" ");
  }
}

class FakeElement {
  constructor(tagName) {
    this.tagName = String(tagName).toUpperCase();
    this.children = [];
    this.className = "";
    this.classList = new FakeClassList(this);
    this.dataset = {};
    this.hidden = false;
    this.open = false;
    this.textContent = "";
    this.attributes = new Map();
    this.listeners = new Map();
    this.disabled = false;
    this.type = "";
  }

  append(...children) {
    this.children.push(...children);
  }

  appendChild(child) {
    this.children.push(child);
    return child;
  }

  replaceChildren(...children) {
    this.children = [...children];
  }

  addEventListener(type, callback) {
    const listeners = this.listeners.get(type) || [];
    listeners.push(callback);
    this.listeners.set(type, listeners);
  }

  setAttribute(name, value) {
    this.attributes.set(name, String(value));
  }

  getAttribute(name) {
    return this.attributes.get(name) || null;
  }

  querySelectorAll(selector) {
    const nodes = descendants(this).slice(1);
    if (selector === "button") {
      return nodes.filter((node) => node.tagName === "BUTTON");
    }
    if (selector === ".entry-row") {
      return nodes.filter((node) => String(node.className || "").split(/\s+/).includes("entry-row"));
    }
    return [];
  }

  focus() {}

  scrollIntoView() {}
}

function descendants(node) {
  return [node, ...(node.children || []).flatMap(descendants)];
}

function jsonResponse(payload) {
  return {
    ok: true,
    status: 200,
    async json() {
      return payload;
    },
    async text() {
      return JSON.stringify(payload);
    },
  };
}

function textResponse(status, text) {
  return {
    ok: false,
    status,
    async json() {
      throw new Error("error body is not json");
    },
    async text() {
      return text;
    },
  };
}

function plainJson(value) {
  return JSON.parse(JSON.stringify(value));
}

function inboxSummary() {
  const now = Math.floor(Date.now() / 1000);
  return {
    notifications: {
      attention_count: 1,
      unread_count: 0,
      entries: [
        {
          id: "entry-review",
          kind: "contact_request",
          title: "Review request",
          body: "Contact approval needs review",
          severity: "attention",
          read: true,
          created_at: now - 60,
          source_app: "people",
          action_ref: { action_id: "contact-accept-request:entry-review" },
        },
        {
          id: "entry-wallet",
          kind: "wallet_approval_request",
          title: "Wallet request",
          body: "Review wallet request",
          severity: "info",
          read: true,
          created_at: now - 3600,
          source_app: "wallet",
          action_ref: { action_id: "wallet-review-request:wallet-request-1" },
        },
      ],
    },
  };
}

// META-PUBLIC A4: consent and "Stop sharing metadata" cards. Agree asks the
// Home's passkey over exactly the shown request; Stop and Try again need none.
function publicMetadataEntry(kind, overrides = {}) {
  const request = { wording_version: 1, wording_sha256: "a".repeat(64) };
  const action = kind === "public_metadata_consent" ? "public-metadata-enable" : "public-metadata-stop";
  return {
    id: "public-metadata",
    source_app: "creator",
    kind,
    title: "Metadata sharing",
    body: "Publish your assets' metadata on IPFS",
    severity: "info",
    read: true,
    created_at: Math.floor(Date.now() / 1000) - 30,
    action_ref: { app: "inbox", action_id: action },
    ...(kind === "public_metadata_consent" ? { passkey_approval: true, step_up_request: request } : {}),
    ...overrides,
  };
}

async function runInboxPublicMetadataSmoke() {
  const inboxScript = extractInboxScript(
    fs.readFileSync(new URL("../capsules/inbox/browser/index.html", import.meta.url), "utf8"),
  );
  let summary = { notifications: { entries: [] } };
  const actions = [];
  let actionAnswer = () => jsonResponse({ message: "Metadata sharing is on." });
  const { context, nodes, topMessages, topFrame, dispatch } = inboxWindowContext(async (path, options = {}) => {
    if (path === "/api/apps/inbox/actions") {
      actions.push(JSON.parse(options.body));
      return actionAnswer();
    }
    return jsonResponse(summary);
  });
  vm.runInNewContext(inboxScript, context, { filename: "capsules/inbox/browser/inbox.js" });
  await settle();

  const labels = (entry) => {
    const row = new FakeElement("div");
    context.fillEntryActions(row, entry);
    return row.children.map((node) => node.textContent);
  };
  // One action per card, no Open and no Dismiss: the card is the state.
  assert.deepEqual(labels(publicMetadataEntry("public_metadata_consent")), ["Agree"]);
  for (const kind of ["public_metadata_sharing", "public_metadata_paused", "public_metadata_unreadable"]) {
    assert.deepEqual(labels(publicMetadataEntry(kind)), ["Stop sharing"], kind);
  }
  assert.deepEqual(labels(publicMetadataEntry("public_metadata_stopping")), ["Try again"]);
  // Agree only over a request with exactly its keys, bound to its action.
  const consent = publicMetadataEntry("public_metadata_consent");
  for (const broken of [
    { ...consent, passkey_approval: false },
    { ...consent, step_up_request: { ...consent.step_up_request, extra: 1 } },
    { ...consent, step_up_request: { wording_version: "1", wording_sha256: "a".repeat(64) } },
    { ...consent, action_ref: { app: "inbox", action_id: "public-metadata-stop" } },
  ]) {
    assert.deepEqual(labels(broken), [], JSON.stringify(broken));
  }

  summary = { notifications: { entries: [consent] } };
  dispatch({ origin: "null", source: topFrame, data: { type: "elastos:menu-command", cmd: "refresh" } });
  await settle();
  const agree = descendants(nodes.get("entry-detail"))
    .find((node) => node.tagName === "BUTTON" && node.textContent === "Agree");
  for (const callback of agree.listeners.get("click") || []) callback();
  await settle();
  const prompt = topMessages.filter((sent) => sent.message.type === "elastos.home.passkey-step-up.request/v1").at(-1);
  assert.deepEqual(plainJson(prompt), {
    message: {
      type: "elastos.home.passkey-step-up.request/v1",
      requestId: "inbox-fixture-document",
      homeToken: "inbox-test-token",
      operation: "creator.public_ipfs.enable",
      request: consent.step_up_request,
    },
    origin: "http://localhost:61180",
  });
  dispatch({
    origin: "http://localhost:61180",
    source: topFrame,
    data: { type: "elastos.home.passkey-step-up.result/v1", requestId: "inbox-fixture-document", stepUpToken: "step-up-pm" },
  });
  await settle();
  assert.deepEqual(plainJson(actions.at(-1)), {
    action_id: "public-metadata-enable",
    step_up_token: "step-up-pm",
    step_up_request: consent.step_up_request,
  });

  // Refusals show Inbox's words for their code.
  for (const [code, copy] of [
    ["changed", "This request changed after it was shown. Review it again, then approve."],
    ["withdrawal_in_progress", "Metadata sharing is still stopping. Try again when it has stopped."],
    ["public_metadata_off", "Metadata sharing is not offered on this Home."],
  ]) {
    actionAnswer = () => textResponse(409, JSON.stringify({ code, detail: "provider internals" }));
    for (const callback of agree.listeners.get("click") || []) callback();
    await settle();
    dispatch({
      origin: "http://localhost:61180",
      source: topFrame,
      data: { type: "elastos.home.passkey-step-up.result/v1", requestId: "inbox-fixture-document", stepUpToken: `step-up-${code}` },
    });
    await settle();
    assert.equal(nodes.get("status-text").textContent, copy, code);
  }
  assert(!actions.some((action) => String(action.action_id).startsWith("notification-dismiss:public-metadata")),
    "the standing card is never dismissed");
}

async function settle() {
  for (let attempt = 0; attempt < 8; attempt += 1) {
    await Promise.resolve();
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
}

function extractInboxScript(html) {
  assert.match(html, /<script src="\.\/inbox\.js(?:\?[^"\s]*)?"><\/script>/, "Inbox script reference not found");
  return fs.readFileSync(new URL("../capsules/inbox/browser/inbox.js", import.meta.url), "utf8");
}

async function runInboxHomeChromeSmoke() {
  const inbox = fs.readFileSync(new URL("../capsules/inbox/browser/index.html", import.meta.url), "utf8");
  const inboxScript = extractInboxScript(inbox);
  const topMessages = [];
  const parentMessages = [];
  const fetchCalls = [];
  const filterAll = new FakeElement("button");
  filterAll.className = "summary-card active";
  filterAll.dataset.filter = "all";
  const filterReview = new FakeElement("button");
  filterReview.className = "summary-card";
  filterReview.dataset.filter = "review";
  const nodes = new Map([
    ["locked-shell", new FakeElement("section")],
    ["inbox-shell", new FakeElement("section")],
    ["status-text", new FakeElement("p")],
    ["pending-count", new FakeElement("strong")],
    ["review-count", new FakeElement("strong")],
    ["refresh", new FakeElement("button")],
    ["entry-rows", new FakeElement("section")],
    ["entry-detail", new FakeElement("section")],
    ["entry-split", new FakeElement("div")],
    ["empty-state", new FakeElement("section")],
    ["empty-title", new FakeElement("h2")],
    ["list-title", new FakeElement("h1")],
  ]);
  const windowListeners = new Map();
  const documentListeners = new Map();
  const topFrame = {
    postMessage(message, origin) {
      topMessages.push({ message, origin });
    },
  };
  const parentFrame = {
    postMessage(message, origin) {
      parentMessages.push({ message, origin });
    },
  };
  const documentElement = { dataset: {} };
  const document = {
    hidden: false,
    documentElement,
    getElementById(id) {
      return nodes.get(id) || null;
    },
    querySelectorAll(selector) {
      if (selector === ".summary-card[data-filter]") {
        return [filterAll, filterReview];
      }
      return [];
    },
    addEventListener(type, callback) {
      documentListeners.set(type, callback);
    },
    createElement(tagName) {
      return new FakeElement(tagName);
    },
  };
  const context = {
    console,
    document,
    window: {
      crypto: { randomUUID: () => "inbox-fixture-document" },
      location: {
        search: "?home_origin=http%3A%2F%2Flocalhost%3A61180&presentation=rail",
        hash: "#home_token=inbox-test-token",
      },
      top: topFrame,
      parent: parentFrame,
      addEventListener(type, callback) {
        const listeners = windowListeners.get(type) || [];
        listeners.push(callback);
        windowListeners.set(type, listeners);
      },
      removeEventListener(type, callback) {
        const listeners = windowListeners.get(type) || [];
        windowListeners.set(type, listeners.filter((entry) => entry !== callback));
      },
      setInterval() {
        return 1;
      },
      setTimeout(callback) {
        callback();
        return 1;
      },
      clearTimeout() {},
    },
    URLSearchParams,
    Intl,
    Date,
    Promise,
    setTimeout,
    clearTimeout,
    fetch: async (path) => {
      fetchCalls.push(path);
      return jsonResponse(inboxSummary());
    },
  };

  vm.runInNewContext(inboxScript, context, {
    filename: "capsules/inbox/browser/inbox.js",
  });
  await settle();

  // Contact and service names remain visible even when they contain technical words.
  for (const kind of ["contact_request", "service_access_request", "service_access_grant"]) {
    for (const name of ["Model Capsule", "<b>Provider</b>"]) {
      const entry = { ...inboxSummary().notifications.entries[0], kind, title: `${name} requests access`, body: `${name} needs your review.` };
      context.renderDetail(entry);
      for (const view of [context.createRow(entry), context.createRailCard(entry), nodes.get("entry-detail")]) {
        const texts = descendants(view).map(node => node.textContent);
        assert(texts.includes(entry.title), "Named identity missing from Inbox view");
        assert(texts.includes(entry.body), "Named details missing from Inbox view");
        assert(!descendants(view).some(node => node.tagName === "B"), "Named identity became markup");
      }
    }
  }
  assert.equal(context.inboxEntryText({ kind: "contact_request", title: "" }, "title", "Request"), "Request");
  assert.equal(context.inboxEntryText({ kind: "external_http_request", body: "provider boundary failed" }, "body", "Review"), "Review");
  const route = {
    id: "model-egress-fixture", provider: "Venice", offer_id: "validation:venice",
    method: "GET", origin: "https://api.venice.ai", path: "/api/v1/models",
    url_sha256: "a".repeat(64), recipient: "api.venice.ai", payer: "this Home",
    purpose: "Load hosted model choices", requested_at: Math.floor(Date.now() / 1000),
    expires_at: Math.floor(Date.now() / 1000) + 600,
  };
  for (const [status, expectedAction] of [
    ["pending", "model-egress-approve:model-egress-fixture"],
    ["approved", "model-egress-end:model-egress-fixture"],
    ["denied", null],
    ["ended", null],
  ]) {
    const [entry] = context.inboxEntries({ notifications: { entries: [] }, hosted_routes: [{ ...route, status }] });
    assert.equal(entry.action_ref?.action_id || null, expectedAction);
    assert(entry.body.includes("Origin: https://api.venice.ai"));
    assert(entry.body.includes("Recipient: api.venice.ai"));
    assert(entry.body.includes("Payer: this Home"));
    assert(entry.body.includes("Expires:"));
    assert.equal(context.inboxEntryText(entry, "body", "Review"), entry.body);
    const actions = new FakeElement("div");
    context.fillEntryActions(actions, entry);
    const end = actions.children.find(node => node.dataset.actionId === "model-egress-end:model-egress-fixture");
    assert.equal(Boolean(end), status === "pending" || status === "approved");
    if (end) assert.equal(end.type, "button");
  }
  // Community presence: four answers, no Dismiss; the Runtime keeps the card
  // until the person decides.
  {
    const actions = new FakeElement("div");
    context.fillEntryActions(actions, {
      id: "community-presence-request:42", kind: "community_presence_request",
      source_app: "chat-room", title: "Show yourself in Community?", body: "",
      action_ref: { app: "inbox", action_id: "community-presence-always:42" },
    });
    const decisions = actions.children.filter(node => node.dataset.actionId).map(node => [node.textContent, node.dataset.actionId]);
    assert.deepEqual(decisions, [
      ["Always while Home is online", "community-presence-always:42"],
      ["Only while Community is open", "community-presence-open:42"],
      ["Later", "community-presence-later:42"],
      ["Never", "community-presence-never:42"],
    ]);
    assert(!actions.children.some(node => String(node.dataset.actionId || "").startsWith("notification-dismiss:")));
  }
  context.setStatus("unauthorized provider");
  assert.equal(nodes.get("status-text").textContent, "Inbox action could not be completed.");

  const menuManifest = topMessages.find((entry) => entry.message.type === "home:menu-manifest");
  assert.deepEqual(
    plainJson(topMessages.find((entry) => entry.message.type === "home:app-ready")),
    {
      message: { type: "home:app-ready", homeToken: "inbox-test-token" },
      origin: "http://localhost:61180",
    },
  );
  assert.deepEqual(plainJson(menuManifest), {
    message: {
      type: "home:menu-manifest",
      homeToken: "inbox-test-token",
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
    },
    origin: "http://localhost:61180",
  });
  assert.deepEqual(
    plainJson(parentMessages),
    [
      {
        message: {
          type: "inbox:pending-count",
          count: 0,
        },
        origin: "*",
      },
    ],
  );
  assert.equal(
    topMessages.some((entry) => entry.message.type === "inbox:pending-count"),
    false,
  );
  assert.equal(documentElement.dataset.inboxPresentation, "rail");
  assert.equal(fetchCalls.filter((path) => path === "/api/apps/inbox/summary").length, 1);

  for (const callback of windowListeners.get("message") || []) {
    callback({
      origin: "null",
      source: parentFrame,
      data: { type: "elastos:menu-command", cmd: "filter-review" },
    });
  }
  await settle();
  assert.equal(nodes.get("list-title").textContent, "Needs Review");
  assert.equal(nodes.get("entry-rows").children.length, 1);

  for (const callback of windowListeners.get("message") || []) {
    callback({
      origin: "null",
      source: parentFrame,
      data: { type: "elastos:menu-command", cmd: "refresh" },
    });
  }
  await settle();
  assert.equal(fetchCalls.filter((path) => path === "/api/apps/inbox/summary").length, 2);

  for (const callback of windowListeners.get("message") || []) {
    callback({
      origin: "null",
      source: parentFrame,
      data: { type: "elastos:inbox-chrome-command", cmd: "refresh" },
    });
  }
  await settle();
  assert.equal(fetchCalls.filter((path) => path === "/api/apps/inbox/summary").length, 3);

  for (const callback of windowListeners.get("message") || []) {
    callback({
      origin: "http://localhost:61180",
      source: parentFrame,
      data: { type: "elastos:menu-command", cmd: "refresh" },
    });
    callback({
      origin: "null",
      source: {},
      data: { type: "elastos:inbox-chrome-command", cmd: "refresh" },
    });
  }
  await settle();
  assert.equal(fetchCalls.filter((path) => path === "/api/apps/inbox/summary").length, 3);

  const originalFetch = context.fetch;
  context.fetch = async (path) => {
    fetchCalls.push(path);
    return jsonResponse({
      notifications: {
        attention_count: 0,
        unread_count: 0,
        entries: [
          {
            id: "entry-wallet",
            kind: "wallet_approval_request",
            title: "Wallet request",
            body: "Review wallet request",
            severity: "info",
            read: true,
            created_at: Math.floor(Date.now() / 1000) - 3600,
            source_app: "wallet",
            action_ref: { action_id: "wallet-review-request:wallet-request-1" },
          },
        ],
      },
    });
  };
  for (const callback of windowListeners.get("message") || []) {
    callback({
      origin: "null",
      source: parentFrame,
      data: { type: "elastos:menu-command", cmd: "refresh" },
    });
  }
  await settle();
  for (const callback of windowListeners.get("message") || []) {
    callback({
      origin: "null",
      source: parentFrame,
      data: { type: "elastos:menu-command", cmd: "filter-review" },
    });
  }
  await settle();
  assert.equal(nodes.get("empty-title").textContent, "No requests need review");
  context.fetch = originalFetch;

  const serviceActions = [];
  context.fetch = async (path, options = {}) => {
    if (path === "/api/apps/inbox/actions") {
      serviceActions.push(JSON.parse(options.body).action_id);
    }
    return jsonResponse({ notifications: { entries: [{
      id: "entry-service", kind: "service_access_request", title: "Browser Exit access",
      body: "A contact requests Browser Exit access.", severity: "attention", read: false,
      source_app: "inbox", action_ref: { app: "inbox", action_id: "service-approve-request:service-1" },
    }] } });
  };
  for (const callback of windowListeners.get("message") || []) {
    callback({ origin: "null", source: parentFrame,
      data: { type: "elastos:menu-command", cmd: "refresh" } });
  }
  await settle();
  const buttons = descendants(nodes.get("entry-rows")).filter(node => node.tagName === "BUTTON");
  // Services is hidden, so a service request offers no Open; Inbox decides it.
  assert.deepEqual(buttons.map(button => button.textContent), ["Approve", "Deny"]);
  assert.deepEqual(serviceActions, [], "Viewing a service request must preserve its pending state");
  for (const label of ["Approve", "Deny"]) {
    const button = descendants(nodes.get("entry-rows")).find(node => node.tagName === "BUTTON" && node.textContent === label);
    for (const callback of button.listeners.get("click") || []) callback();
    await settle();
  }
  assert.deepEqual(serviceActions, ["service-approve-request:service-1", "service-deny-request:service-1"]);

  // Inbox can only sign with a built-in wallet after a passkey, so Approve
  // appears only on a request the server marks as passkey-approvable. An
  // external wallet (MetaMask) request goes to Wallet instead.
  for (const [passkeyApproval, expected] of [
    [undefined, ["Review in Wallet", "Reject"]],
    [true, ["Approve", "Review in Wallet", "Reject"]],
  ]) {
    context.fetch = async () => jsonResponse({ notifications: { entries: [{
      id: "entry-wallet-approval", kind: "wallet_approval_request", title: "Wallet approval request",
      body: "runtime requests wallet approval for Open protected content.", severity: "attention", read: false,
      action_ref: { action_id: "wallet-approve-request:wallet-request-2" },
      ...(passkeyApproval === undefined ? {} : { passkey_approval: passkeyApproval }),
    }] } });
    for (const callback of windowListeners.get("message") || []) {
      callback({ origin: "null", source: parentFrame,
        data: { type: "elastos:menu-command", cmd: "refresh" } });
    }
    await settle();
    const walletButtons = descendants(nodes.get("entry-rows")).filter(node => node.tagName === "BUTTON");
    assert.deepEqual(walletButtons.map(button => button.textContent), expected,
      `wallet approval actions with passkey_approval=${passkeyApproval}`);
    assert(String(walletButtons[0].className).includes("primary"),
      `the first wallet approval action must be the primary one (passkey_approval=${passkeyApproval})`);
  }

  const grantActions = [];
  let grantRevoked = false;
  const grantEntry = {
    id: "entry-grant",
    kind: "service_access_grant",
    title: "Seed may use your AI model",
    body: "Seed may use Mac model. Revoke access to stop new runs and cancel open runs.",
    severity: "info",
    read: true,
    source_app: "inbox",
    action_ref: { action_id: "service-deny-request:grant-1" },
  };
  context.fetch = async (path, options = {}) => {
    fetchCalls.push(path);
    if (path === "/api/apps/inbox/actions") {
      grantActions.push(JSON.parse(options.body).action_id);
      grantRevoked = true;
      return textResponse(503, "service access request delivery failed");
    }
    return jsonResponse({
      notifications: {
        attention_count: 0,
        unread_count: 0,
        entries: grantRevoked ? [] : [grantEntry],
      },
    });
  };
  for (const callback of windowListeners.get("message") || []) {
    callback({ origin: "null", source: parentFrame,
      data: { type: "elastos:menu-command", cmd: "filter-all" } });
  }
  await settle();
  const summariesBeforeRevoke = fetchCalls.filter((path) => path === "/api/apps/inbox/summary").length;
  for (const callback of windowListeners.get("message") || []) {
    callback({ origin: "null", source: parentFrame,
      data: { type: "elastos:menu-command", cmd: "refresh" } });
  }
  await settle();
  assert.equal(nodes.get("pending-count").textContent, "0");
  // The All list holds a grant card; the count beside it names only pending requests.
  assert.equal(filterAll.getAttribute("aria-label"), "All, 0 pending requests");
  assert.equal(nodes.get("list-title").textContent, "All");
  assert.equal(nodes.get("review-count").textContent, "0");
  const grantButtons = descendants(nodes.get("entry-rows")).filter(node => node.tagName === "BUTTON");
  assert.deepEqual(grantButtons.map(button => button.textContent), ["Revoke access"]);
  assert.deepEqual(grantActions, [], "Viewing an approved grant must preserve its access");
  const revoke = grantButtons.find(button => button.textContent === "Revoke access");
  for (const callback of revoke.listeners.get("click") || []) callback();
  await settle();
  assert.deepEqual(grantActions, ["service-deny-request:grant-1"]);
  assert.ok(
    fetchCalls.filter((path) => path === "/api/apps/inbox/summary").length > summariesBeforeRevoke,
    "503 after a saved revoke must refresh Inbox summary",
  );
  assert.deepEqual(
    descendants(nodes.get("entry-rows")).filter(node => node.tagName === "BUTTON").map(button => button.textContent),
    [],
  );
  assert.equal(nodes.get("pending-count").textContent, "0");
  assert.equal(
    nodes.get("status-text").textContent,
    "service access request delivery failed",
  );

  context.fetch = async () => jsonResponse({ notifications: {
    attention_count: 1,
    unread_count: 1,
    entries: [
      {
        id: "entry-service",
        kind: "service_access_request",
        title: "Browser Exit access",
        body: "A contact requests Browser Exit access.",
        severity: "attention",
        read: false,
        source_app: "inbox",
        action_ref: { action_id: "service-approve-request:service-1" },
      },
      {
        id: "entry-grant",
        kind: "service_access_grant",
        title: "Seed may use your AI model",
        body: "Seed may use Mac model. Revoke access to stop new runs and cancel open runs.",
        severity: "info",
        read: true,
        source_app: "inbox",
        action_ref: { action_id: "service-deny-request:grant-1" },
      },
    ],
  } });
  for (const callback of windowListeners.get("message") || []) {
    callback({ origin: "null", source: parentFrame,
      data: { type: "elastos:menu-command", cmd: "refresh" } });
  }
  await settle();
  assert.equal(nodes.get("pending-count").textContent, "1");
  assert.equal(filterAll.getAttribute("aria-label"), "All, 1 pending request");
  assert.equal(nodes.get("review-count").textContent, "1");
}

async function runInboxLaunchSelectionSmoke() {
  const inbox = fs.readFileSync(new URL("../capsules/inbox/browser/index.html", import.meta.url), "utf8");
  const inboxScript = extractInboxScript(inbox);
  const nodes = new Map([
    ["locked-shell", new FakeElement("section")],
    ["inbox-shell", new FakeElement("section")],
    ["status-text", new FakeElement("p")],
    ["pending-count", new FakeElement("strong")],
    ["review-count", new FakeElement("strong")],
    ["refresh", new FakeElement("button")],
    ["entry-rows", new FakeElement("section")],
    ["entry-detail", new FakeElement("section")],
    ["entry-split", new FakeElement("div")],
    ["empty-state", new FakeElement("section")],
    ["empty-title", new FakeElement("h2")],
    ["list-title", new FakeElement("h1")],
  ]);
  const filterAll = new FakeElement("button");
  filterAll.className = "summary-card active";
  filterAll.dataset.filter = "all";
  const filterReview = new FakeElement("button");
  filterReview.className = "summary-card";
  filterReview.dataset.filter = "review";
  const document = {
    hidden: false,
    documentElement: { dataset: {} },
    getElementById(id) {
      return nodes.get(id) || null;
    },
    querySelectorAll(selector) {
      if (selector === ".summary-card[data-filter]") {
        return [filterAll, filterReview];
      }
      return [];
    },
    addEventListener() {},
    createElement(tagName) {
      return new FakeElement(tagName);
    },
  };
  const context = {
    console,
    document,
    window: {
      crypto: { randomUUID: () => "inbox-fixture-document" },
      location: {
        search: "?home_origin=http%3A%2F%2Flocalhost%3A61180&notification_id=entry-wallet",
        hash: "#home_token=inbox-test-token",
      },
      top: { postMessage() {} },
      parent: { postMessage() {} },
      addEventListener() {},
      removeEventListener() {},
      setInterval() {
        return 1;
      },
      setTimeout(callback) {
        callback();
        return 1;
      },
      clearTimeout() {},
    },
    URLSearchParams,
    Intl,
    Date,
    Promise,
    setTimeout,
    clearTimeout,
    fetch: async () => jsonResponse(inboxSummary()),
  };

  vm.runInNewContext(inboxScript, context, {
    filename: "capsules/inbox/browser/inbox.js",
  });
  await settle();

  assert.equal(nodes.get("entry-rows").children.length, 2);
  assert.equal(nodes.get("entry-rows").children[1].getAttribute("aria-selected"), "true");
  const detailText = descendants(nodes.get("entry-detail"))
    .map((node) => node.textContent || "")
    .join(" ");
  assert(detailText.includes("Wallet request"), "Inbox did not keep the requested notification selected", detailText);
}

async function runInboxMissingLaunchSelectionSmoke() {
  const inbox = fs.readFileSync(new URL("../capsules/inbox/browser/index.html", import.meta.url), "utf8");
  const inboxScript = extractInboxScript(inbox);
  const nodes = new Map([
    ["locked-shell", new FakeElement("section")],
    ["inbox-shell", new FakeElement("section")],
    ["status-text", new FakeElement("p")],
    ["pending-count", new FakeElement("strong")],
    ["review-count", new FakeElement("strong")],
    ["refresh", new FakeElement("button")],
    ["entry-rows", new FakeElement("section")],
    ["entry-detail", new FakeElement("section")],
    ["entry-split", new FakeElement("div")],
    ["empty-state", new FakeElement("section")],
    ["empty-title", new FakeElement("h2")],
    ["list-title", new FakeElement("h1")],
  ]);
  const filterAll = new FakeElement("button");
  filterAll.className = "summary-card active";
  filterAll.dataset.filter = "all";
  const filterReview = new FakeElement("button");
  filterReview.className = "summary-card";
  filterReview.dataset.filter = "review";
  const document = {
    hidden: false,
    documentElement: { dataset: {} },
    getElementById(id) {
      return nodes.get(id) || null;
    },
    querySelectorAll(selector) {
      if (selector === ".summary-card[data-filter]") {
        return [filterAll, filterReview];
      }
      return [];
    },
    addEventListener() {},
    createElement(tagName) {
      return new FakeElement(tagName);
    },
  };
  const context = {
    console,
    document,
    window: {
      crypto: { randomUUID: () => "inbox-fixture-document" },
      location: {
        search: "?home_origin=http%3A%2F%2Flocalhost%3A61180&notification_id=missing-entry",
        hash: "#home_token=inbox-test-token",
      },
      top: { postMessage() {} },
      parent: { postMessage() {} },
      addEventListener() {},
      removeEventListener() {},
      setInterval() {
        return 1;
      },
      setTimeout(callback) {
        callback();
        return 1;
      },
      clearTimeout() {},
    },
    URLSearchParams,
    Intl,
    Date,
    Promise,
    setTimeout,
    clearTimeout,
    fetch: async () => jsonResponse(inboxSummary()),
  };

  vm.runInNewContext(inboxScript, context, {
    filename: "capsules/inbox/browser/inbox.js",
  });
  await settle();

  const selectedRows = nodes.get("entry-rows").children
    .filter((row) => row.getAttribute("aria-selected") === "true");
  assert.equal(selectedRows.length, 0, "Inbox selected a different request after an explicit missing launch id");
  const detailText = descendants(nodes.get("entry-detail"))
    .map((node) => node.textContent || "")
    .join(" ");
  assert(detailText.includes("no longer available"), "Inbox did not show the explicit request as unavailable", detailText);
  assert.equal(
    descendants(nodes.get("entry-detail")).filter((node) => node.tagName === "BUTTON").length,
    0,
    "Inbox exposed actions for a missing explicit launch id",
  );
}

async function runInboxRemovedLaunchSelectionSmoke() {
  const inbox = fs.readFileSync(new URL("../capsules/inbox/browser/index.html", import.meta.url), "utf8");
  const inboxScript = extractInboxScript(inbox);
  const nodes = new Map([
    ["locked-shell", new FakeElement("section")],
    ["inbox-shell", new FakeElement("section")],
    ["status-text", new FakeElement("p")],
    ["pending-count", new FakeElement("strong")],
    ["review-count", new FakeElement("strong")],
    ["refresh", new FakeElement("button")],
    ["entry-rows", new FakeElement("section")],
    ["entry-detail", new FakeElement("section")],
    ["entry-split", new FakeElement("div")],
    ["empty-state", new FakeElement("section")],
    ["empty-title", new FakeElement("h2")],
    ["list-title", new FakeElement("h1")],
  ]);
  const filterAll = new FakeElement("button");
  filterAll.className = "summary-card active";
  filterAll.dataset.filter = "all";
  const filterReview = new FakeElement("button");
  filterReview.className = "summary-card";
  filterReview.dataset.filter = "review";
  let fetchCount = 0;
  const document = {
    hidden: false,
    documentElement: { dataset: {} },
    getElementById(id) {
      return nodes.get(id) || null;
    },
    querySelectorAll(selector) {
      if (selector === ".summary-card[data-filter]") {
        return [filterAll, filterReview];
      }
      return [];
    },
    addEventListener() {},
    createElement(tagName) {
      return new FakeElement(tagName);
    },
  };
  const context = {
    console,
    document,
    window: {
      crypto: { randomUUID: () => "inbox-fixture-document" },
      location: {
        search: "?home_origin=http%3A%2F%2Flocalhost%3A61180&notification_id=entry-wallet",
        hash: "#home_token=inbox-test-token",
      },
      top: { postMessage() {} },
      parent: { postMessage() {} },
      addEventListener() {},
      removeEventListener() {},
      setInterval() {
        return 1;
      },
      setTimeout(callback) {
        callback();
        return 1;
      },
      clearTimeout() {},
    },
    URLSearchParams,
    Intl,
    Date,
    Promise,
    setTimeout,
    clearTimeout,
    fetch: async () => {
      fetchCount += 1;
      if (fetchCount === 1) {
        return jsonResponse(inboxSummary());
      }
      const summary = inboxSummary();
      summary.notifications.entries = summary.notifications.entries.filter((entry) => entry.id !== "entry-wallet");
      return jsonResponse(summary);
    },
  };

  vm.runInNewContext(inboxScript, context, {
    filename: "capsules/inbox/browser/inbox.js",
  });
  await settle();
  await nodes.get("refresh").listeners.get("click")[0]();
  await settle();

  const selectedRows = nodes.get("entry-rows").children
    .filter((row) => row.getAttribute("aria-selected") === "true");
  assert.equal(selectedRows.length, 0, "Inbox selected a different request after the explicit request disappeared");
  const detailText = descendants(nodes.get("entry-detail"))
    .map((node) => node.textContent || "")
    .join(" ");
  assert(detailText.includes("no longer available"), "Inbox did not keep the vanished explicit request unavailable", detailText);
  assert.equal(
    descendants(nodes.get("entry-detail")).filter((node) => node.tagName === "BUTTON").length,
    0,
    "Inbox exposed actions after the explicit request disappeared on refresh",
  );
}

async function runInboxRequestedSelectionAppearsLaterSmoke() {
  const inbox = fs.readFileSync(new URL("../capsules/inbox/browser/index.html", import.meta.url), "utf8");
  const inboxScript = extractInboxScript(inbox);
  const nodes = new Map([
    ["locked-shell", new FakeElement("section")],
    ["inbox-shell", new FakeElement("section")],
    ["status-text", new FakeElement("p")],
    ["pending-count", new FakeElement("strong")],
    ["review-count", new FakeElement("strong")],
    ["refresh", new FakeElement("button")],
    ["entry-rows", new FakeElement("section")],
    ["entry-detail", new FakeElement("section")],
    ["entry-split", new FakeElement("div")],
    ["empty-state", new FakeElement("section")],
    ["empty-title", new FakeElement("h2")],
    ["list-title", new FakeElement("h1")],
  ]);
  const filterAll = new FakeElement("button");
  filterAll.className = "summary-card active";
  filterAll.dataset.filter = "all";
  const filterReview = new FakeElement("button");
  filterReview.className = "summary-card";
  filterReview.dataset.filter = "review";
  let fetchCount = 0;
  const document = {
    hidden: false,
    documentElement: { dataset: {} },
    getElementById(id) {
      return nodes.get(id) || null;
    },
    querySelectorAll(selector) {
      if (selector === ".summary-card[data-filter]") {
        return [filterAll, filterReview];
      }
      return [];
    },
    addEventListener() {},
    createElement(tagName) {
      return new FakeElement(tagName);
    },
  };
  const context = {
    console,
    document,
    window: {
      crypto: { randomUUID: () => "inbox-fixture-document" },
      location: {
        search: "?home_origin=http%3A%2F%2Flocalhost%3A61180&notification_id=entry-wallet",
        hash: "#home_token=inbox-test-token",
      },
      top: { postMessage() {} },
      parent: { postMessage() {} },
      addEventListener() {},
      removeEventListener() {},
      setInterval() {
        return 1;
      },
      setTimeout(callback) {
        callback();
        return 1;
      },
      clearTimeout() {},
    },
    URLSearchParams,
    Intl,
    Date,
    Promise,
    setTimeout,
    clearTimeout,
    fetch: async () => {
      fetchCount += 1;
      const summary = inboxSummary();
      if (fetchCount === 1) {
        summary.notifications.entries = [summary.notifications.entries[0]];
      }
      return jsonResponse(summary);
    },
  };

  vm.runInNewContext(inboxScript, context, {
    filename: "capsules/inbox/browser/inbox.js",
  });
  await settle();

  let selectedRows = nodes.get("entry-rows").children
    .filter((row) => row.getAttribute("aria-selected") === "true");
  assert.equal(selectedRows.length, 0, "Inbox selected the wrong request before the explicit request appeared");

  await nodes.get("refresh").listeners.get("click")[0]();
  await settle();

  selectedRows = nodes.get("entry-rows").children
    .filter((row) => row.getAttribute("aria-selected") === "true");
  assert.equal(selectedRows.length, 1);
  assert.equal(selectedRows[0], nodes.get("entry-rows").children[1], "Inbox did not reselect the requested request when it appeared");

  const keydown = nodes.get("entry-rows").listeners.get("keydown")[0];
  keydown({
    key: "ArrowUp",
    preventDefault() {},
  });
  await settle();
  selectedRows = nodes.get("entry-rows").children
    .filter((row) => row.getAttribute("aria-selected") === "true");
  assert.equal(selectedRows[0], nodes.get("entry-rows").children[0], "Keyboard selection did not clear the pinned request");
}

function custodyRequestEntry(overrides = {}) {
  const now = Math.floor(Date.now() / 1000);
  const request = {
    request_id: "1".repeat(32),
    request_sha256: `sha256:${"5e".repeat(32)}`,
    owner_name: "Olivia",
    owner_home: "did:key:z6MkOwnerHome",
    term_days: 365,
    run_by: "Nadia",
    location: "Porto",
    expires_at: now + 3600,
    ...overrides,
  };
  return {
    id: `custody-node-request:${request.request_id}`,
    source_app: "custody",
    kind: "custody_node_request",
    // The card never reads these: it shows the step-up request alone.
    title: "Server title",
    body: "Server body",
    severity: "attention",
    read: false,
    created_at: now - 30,
    passkey_approval: true,
    action_ref: { app: "inbox", action_id: `custody-approve-request:${request.request_id}` },
    step_up_request: request,
  };
}

function inboxWindowContext(fetchImpl) {
  const nodes = new Map([
    "locked-shell", "inbox-shell", "status-text", "pending-count", "review-count", "refresh",
    "entry-rows", "entry-detail", "entry-split", "empty-state", "empty-title", "list-title",
  ].map((id) => [id, new FakeElement(id === "refresh" ? "button" : "section")]));
  const windowListeners = new Map();
  const topMessages = [];
  const topFrame = { postMessage(message, origin) { topMessages.push({ message, origin }); } };
  const context = {
    console,
    document: {
      hidden: false,
      documentElement: { dataset: {} },
      getElementById(id) { return nodes.get(id) || null; },
      querySelectorAll() { return []; },
      addEventListener() {},
      createElement(tagName) { return new FakeElement(tagName); },
    },
    window: {
      crypto: { randomUUID: () => "inbox-fixture-document" },
      location: {
        search: "?home_origin=http%3A%2F%2Flocalhost%3A61180",
        hash: "#home_token=inbox-test-token",
      },
      top: topFrame,
      parent: topFrame,
      addEventListener(type, callback) {
        const listeners = windowListeners.get(type) || [];
        listeners.push(callback);
        windowListeners.set(type, listeners);
      },
      removeEventListener(type, callback) {
        windowListeners.set(type, (windowListeners.get(type) || []).filter((entry) => entry !== callback));
      },
      setInterval() { return 1; },
      // The passkey prompt waits for Home's answer, not for a timer.
      setTimeout() { return 1; },
      clearTimeout() {},
    },
    URLSearchParams,
    Intl,
    Date,
    Promise,
    setTimeout,
    clearTimeout,
    fetch: fetchImpl,
  };
  const dispatch = (event) => {
    for (const callback of windowListeners.get("message") || []) callback(event);
  };
  return { context, nodes, topMessages, topFrame, dispatch };
}

function factPairs(view) {
  return descendants(view)
    .filter((node) => node.className === "entry-fact")
    .map((row) => row.children.map((child) => child.textContent));
}

async function runInboxCustodyRequestSmoke() {
  const inboxScript = extractInboxScript(
    fs.readFileSync(new URL("../capsules/inbox/browser/index.html", import.meta.url), "utf8"),
  );
  let summary = { notifications: { entries: [] } };
  const actions = [];
  let actionAnswer = () => jsonResponse({ message: "Approved." });
  const { context, nodes, topMessages, topFrame, dispatch } = inboxWindowContext(async (path, options = {}) => {
    if (path === "/api/apps/inbox/actions") {
      actions.push(JSON.parse(options.body));
      return actionAnswer();
    }
    return jsonResponse(summary);
  });
  vm.runInNewContext(inboxScript, context, { filename: "capsules/inbox/browser/inbox.js" });
  await settle();

  // Hostile names and labels are text, everywhere the card appears.
  const hostile = custodyRequestEntry({
    owner_name: "<img src=x onerror=alert(1)>",
    run_by: "</span><script>alert(1)</script>",
    location: "provider schema 500 <b>Porto</b>",
    owner_home: "did:key:<i>z6Mk</i>",
  });
  const request = hostile.step_up_request;
  context.renderDetail(hostile);
  const expires = new Intl.DateTimeFormat([], { dateStyle: "medium", timeStyle: "short" })
    .format(new Date(request.expires_at * 1000));
  assert.deepEqual(factPairs(nodes.get("entry-detail")), [
    ["Owner: ", request.owner_name],
    ["Term: ", "365 days"],
    ["Run by: ", request.run_by],
    ["Location: ", request.location],
    ["Expires: ", expires],
    ["Owner's Home: ", request.owner_home],
  ]);
  const details = descendants(nodes.get("entry-detail")).find((node) => node.tagName === "DETAILS");
  assert.deepEqual(factPairs(details), [["Owner's Home: ", request.owner_home]], "the Home ID sits under Details");
  // OPEN-LOOP F1 (ADV-14): the one consent names both duties wherever Approve is offered.
  const CUSTODY_DUTIES = "This Home will hold a key share and keep a copy of this pool's files.";
  const namesDuties = () => descendants(nodes.get("entry-detail")).some((node) => node.textContent === CUSTODY_DUTIES);
  assert(namesDuties(), "the approval card does not name both duties");
  for (const view of [context.createRow(hostile), context.createRailCard(hostile), nodes.get("entry-detail")]) {
    const texts = descendants(view).map((node) => node.textContent);
    assert(texts.includes(`${request.owner_name} asks this Home to hold custody`), "owner name missing from the card");
    assert(!texts.some((text) => String(text).includes("Server")), "the card read fields beside its step-up request");
    assert(!descendants(view).some((node) => ["IMG", "SCRIPT", "B", "I"].includes(node.tagName)), "a name became markup");
    assert(!descendants(view).some((node) => Object.hasOwn(node, "innerHTML") || Object.hasOwn(node, "outerHTML")),
      "the card wrote markup");
  }

  // Approve needs a well-formed request bound to this action; Decline needs none.
  const labels = (entry) => {
    const row = new FakeElement("div");
    context.fillEntryActions(row, entry);
    return row.children.map((node) => [node.textContent, node.dataset.actionId || null]);
  };
  const declineId = `custody-decline-request:${request.request_id}`;
  assert.deepEqual(labels(hostile), [["Open", null], ["Approve", null], ["Decline", declineId]]);
  for (const broken of [
    { ...hostile, passkey_approval: false },
    { ...hostile, step_up_request: { ...request, extra: 1 } },
    { ...hostile, step_up_request: { ...request, term_days: "365" } },
    { ...hostile, action_ref: { app: "inbox", action_id: `custody-approve-request:${"2".repeat(32)}` } },
  ]) {
    assert.deepEqual(labels(broken).map(([label]) => label), ["Open", "Decline"]);
  }
  assert.equal(context.inboxEntryText({ ...hostile, step_up_request: null }, "title", "Request"), "Custody request");

  // An approval that did not finish can only be finished: Approve, no Decline,
  // still rendered from its step-up request alone.
  const finishing = { ...hostile, kind: "custody_node_approving" };
  assert.deepEqual(labels(finishing), [["Open", null], ["Approve", null]]);
  assert.equal(
    context.inboxEntryText(finishing, "title", "Request"),
    `Finish approving ${request.owner_name}'s custody request`,
  );
  context.renderDetail(finishing);
  const withoutExpiry = [
    ["Owner: ", request.owner_name],
    ["Term: ", "365 days"],
    ["Run by: ", request.run_by],
    ["Location: ", request.location],
    ["Owner's Home: ", request.owner_home],
  ];
  assert.deepEqual(factPairs(nodes.get("entry-detail")), withoutExpiry, "an approval that began hides its stale expiry");
  assert(!descendants(nodes.get("entry-detail")).some((node) => ["IMG", "SCRIPT", "B", "I"].includes(node.tagName)));
  assert(namesDuties(), "finishing an approval does not name both duties");

  // An approval that set nothing up yet can be finished or declined.
  const resumable = { ...hostile, kind: "custody_node_resumable" };
  assert.deepEqual(labels(resumable), [["Open", null], ["Approve", null], ["Decline", declineId]]);
  assert.equal(
    context.inboxEntryText(resumable, "title", "Request"),
    `Finish approving ${request.owner_name}'s custody request`,
  );
  context.renderDetail(resumable);
  assert.deepEqual(factPairs(nodes.get("entry-detail")), withoutExpiry, "an approval that began hides its stale expiry");
  assert(namesDuties(), "resuming an approval does not name both duties");

  // An approval that stopped part way can only be declined.
  const stopped = {
    ...hostile,
    kind: "custody_node_incomplete",
    action_ref: { app: "inbox", action_id: declineId },
  };
  assert.deepEqual(labels(stopped), [["Open", null], ["Decline", declineId]]);
  assert.equal(
    context.inboxEntryText(stopped, "title", "Request"),
    `Approving ${request.owner_name}'s custody request could not finish`,
  );
  context.renderDetail(stopped);
  assert.deepEqual(factPairs(nodes.get("entry-detail")), withoutExpiry);
  assert(!namesDuties(), "a card that only declines asks for no consent");
  // So can one on a Home that serves another owner now.
  const taken = { ...stopped, kind: "custody_node_taken" };
  assert.deepEqual(labels(taken), [["Open", null], ["Decline", declineId]]);
  assert.equal(
    context.inboxEntryText(taken, "title", "Request"),
    `${request.owner_name}'s custody request can no longer be approved`,
  );
  context.renderDetail(taken);
  assert.deepEqual(factPairs(nodes.get("entry-detail")), withoutExpiry);
  // Bound to its own action: an approve action on this card is not trusted.
  assert.equal(
    context.inboxEntryText({ ...stopped, action_ref: { app: "inbox", action_id: `custody-approve-request:${request.request_id}` } }, "title", "Request"),
    "Custody request",
  );

  // The passkey signs exactly the shown request, and Inbox sends it back unchanged.
  const entry = custodyRequestEntry();
  summary = { notifications: { entries: [entry] } };
  dispatch({ origin: "null", source: topFrame, data: { type: "elastos:menu-command", cmd: "refresh" } });
  await settle();
  const approveButton = () => descendants(nodes.get("entry-detail"))
    .find((node) => node.tagName === "BUTTON" && node.textContent === "Approve");
  const approveOnce = async (token) => {
    for (const callback of approveButton().listeners.get("click") || []) callback();
    await settle();
    const prompt = topMessages.filter((sent) => sent.message.type === "elastos.home.passkey-step-up.request/v1").at(-1);
    assert.deepEqual(plainJson(prompt), {
      message: {
        type: "elastos.home.passkey-step-up.request/v1",
        requestId: "inbox-fixture-document",
        homeToken: "inbox-test-token",
        operation: "custody.node_request.approve",
        request: entry.step_up_request,
      },
      origin: "http://localhost:61180",
    });
    dispatch({
      origin: "http://localhost:61180",
      source: topFrame,
      data: { type: "elastos.home.passkey-step-up.result/v1", requestId: "inbox-fixture-document", stepUpToken: token },
    });
    await settle();
  };
  actionAnswer = () => jsonResponse({ message: "Approved. This Home is now a custody node for <b>Olivia</b>." });
  await approveOnce("step-up-1");
  assert.deepEqual(plainJson(actions.at(-1)), {
    action_id: `custody-approve-request:${entry.step_up_request.request_id}`,
    step_up_token: "step-up-1",
    step_up_request: entry.step_up_request,
  });
  assert.equal(nodes.get("status-text").textContent, "Approved. This Home is now a custody node for <b>Olivia</b>.");

  // A refusal shows Inbox's words for its code, never the Runtime's detail.
  for (const [code, copy] of [
    ["changed", "This request changed after it was shown. Review it again, then approve."],
    ["expired", "This request has expired. Its owner can send it again."],
    ["already_serving", "This Home already serves another owner. Decline this request."],
    ["not_offering", "This Home is not offering custody. Turn on Offer custody in Custody first."],
    ["not_admin", "Only this Home's admin can decide custody requests."],
    ["too_many_requests", "Too many custody requests are waiting. Decide some, then try again."],
    ["something_new", "Inbox action could not be completed."],
    ["messages_not_enabled", "Enable custody messages in Custody before approving."],
    ["not_contact", "This owner is no longer one of your contacts."],
    ["not_pending", "This request was already decided."],
    ["provision_failed", "This Home could not be set up as a custody node. Try again."],
    ["unavailable", "This Home could not read its custody setup. Try again later."],
    ["protected_content_off", "Turn on protected content for this Home before approving."],
  ]) {
    actionAnswer = () => textResponse(409, JSON.stringify({ code, detail: "provider internals" }));
    await approveOnce(`step-up-${code}`);
    assert.equal(nodes.get("status-text").textContent, copy);
  }

  // An incomplete setup is told by its stable key, never by free text.
  actionAnswer = () => textResponse(409, JSON.stringify({ code: "provision_failed", detail: "custody_state_incomplete" }));
  await approveOnce("step-up-incomplete");
  assert.equal(
    nodes.get("status-text").textContent,
    "This Home's custody setup did not finish and needs repair. Decline this request.",
  );

  const clickDecline = async () => {
    const declineButton = descendants(nodes.get("entry-detail"))
      .find((node) => node.tagName === "BUTTON" && node.textContent === "Decline");
    for (const callback of declineButton.listeners.get("click") || []) callback();
    await settle();
  };
  // Declining a request that is being approved is refused with its own words.
  actionAnswer = () => textResponse(409, JSON.stringify({ code: "not_pending", detail: "approving" }));
  await clickDecline();
  assert.equal(nodes.get("status-text").textContent, "This request is being approved. Finish approving it.");
  actionAnswer = () => jsonResponse({ message: "Declined the custody request." });
  await clickDecline();
  assert.deepEqual(plainJson(actions.at(-1)), { action_id: declineId.replace(request.request_id, entry.step_up_request.request_id) });
  assert(!actions.some((action) => String(action.action_id).startsWith("notification-read:custody-node-request")),
    "showing a custody request does not mark it read");
}

await runInboxHomeChromeSmoke();
await runInboxCustodyRequestSmoke();
await runInboxPublicMetadataSmoke();
await runInboxLaunchSelectionSmoke();
await runInboxMissingLaunchSelectionSmoke();
await runInboxRemovedLaunchSelectionSmoke();
await runInboxRequestedSelectionAppearsLaterSmoke();
console.log("inbox-product-behavior-smoke: PASS");
