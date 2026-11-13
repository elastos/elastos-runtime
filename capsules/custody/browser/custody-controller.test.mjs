// The Custody controller against a fake DOM, Home and Runtime: the branches
// that live in bootCustodyApp rather than in the pure model and view.
import assert from "node:assert/strict";
import test from "node:test";

class Element {
  constructor() {
    this.dataset = {};
    this.innerHTML = "";
    this.hidden = false;
    this.disabled = false;
    this.style = { setProperty() {} };
    this.classList = { add() {}, remove() {} };
    this.listeners = new Map();
  }

  closest() {
    return this;
  }

  addEventListener(type, listener) {
    if (!this.listeners.has(type)) {
      this.listeners.set(type, []);
    }
    this.listeners.get(type).push(listener);
  }

  querySelector() {
    return null;
  }

  querySelectorAll() {
    return [];
  }

  contains() {
    return false;
  }

  getAttribute() {
    return null;
  }

  setAttribute() {}

  removeAttribute() {}

  focus() {}
}

class HTMLElement extends Element {}
class HTMLButtonElement extends HTMLElement {}
Object.assign(globalThis, {
  Element,
  HTMLElement,
  HTMLButtonElement,
  HTMLTextAreaElement: class extends HTMLElement {},
  HTMLInputElement: class extends HTMLElement {},
  Node: class {},
});

const { bootCustodyApp } = await import("./custody.js");

const HOME_ORIGIN = "https://home.test";
const ANN_CARD = "elastos-node-card:v1:annannann";

function record(overrides = {}) {
  return {
    request_id: "req-1",
    request_sha256: `sha256:${"a".repeat(64)}`,
    recipient_profile_did: "did:key:ann-profile",
    recipient_home: "did:key:ann-home",
    recipient_name: "Ann",
    term_days: 365,
    created_at: 1_793_000_000,
    expires_at: 1_793_086_400,
    state: "waiting",
    ...overrides,
  };
}

function summary(overrides = {}) {
  return {
    threshold: { required: 2, total: 3 },
    term_presets_days: [182, 365, 730],
    runtime_issuer: "0xissuer",
    signing_key: { present: true },
    chain: { ready: true, network: "Base", proof_sources: 3 },
    local_node: { provisioned: true, run_by: "Iz", location: "Paris", running: true },
    pool_installed: false,
    pool: null,
    node_requests: [],
    ...overrides,
  };
}

// One booted app: its fake document, window, timers, Home and routes.
// `routes[METHOD path]` answers `{status, body}`, or a promise of one.
function boot(routes, bootOptions = {}) {
  let clock = 1_800_000_000_000;
  const timers = [];
  let timerId = 0;
  const calls = [];
  // The Home token each request carried, apart from `calls` so the request
  // assertions above stay about method, path and body.
  const requestTokens = [];
  const stepUps = [];
  const documentListeners = new Map();
  const windowListeners = new Map();
  const nodes = {
    "locked-shell": new Element(),
    "custody-shell": new Element(),
    pools: new Element(),
    "hosting-node": new Element(),
    "card-file": new Element(),
  };
  const listen = (map) => (type, listener) => {
    if (!map.has(type)) {
      map.set(type, []);
    }
    map.get(type).push(listener);
  };
  const win = {
    location: { search: `?home_origin=${encodeURIComponent(HOME_ORIGIN)}`, hash: "#home_token=launch-token" },
    parent: {},
    addEventListener: listen(windowListeners),
    removeEventListener(type, listener) {
      windowListeners.set(type, (windowListeners.get(type) || []).filter((entry) => entry !== listener));
    },
    setTimeout(fn, delay = 0) {
      timerId += 1;
      timers.push({ id: timerId, fn, delay });
      return timerId;
    },
    clearTimeout(id) {
      const index = timers.findIndex((timer) => timer.id === id);
      if (index >= 0) {
        timers.splice(index, 1);
      }
    },
    requestAnimationFrame(fn) {
      fn();
    },
    crypto: { randomUUID: () => `step-up-${stepUps.length + 1}` },
  };
  win.top = {
    // Home answers every passkey step-up with a token named after it.
    postMessage(message) {
      if (message?.type !== "elastos.home.passkey-step-up.request/v1") {
        return;
      }
      stepUps.push({ operation: message.operation, request: message.request });
      queueMicrotask(() => {
        for (const listener of windowListeners.get("message") || []) {
          listener({
            source: win.top,
            origin: HOME_ORIGIN,
            data: {
              type: "elastos.home.passkey-step-up.result/v1",
              requestId: message.requestId,
              stepUpToken: `token-${message.operation}`,
            },
          });
        }
      });
    },
  };
  const doc = {
    visibilityState: "visible",
    activeElement: null,
    body: {},
    getElementById: (id) => nodes[id] || null,
    querySelector: () => null,
    querySelectorAll: () => [],
    addEventListener: listen(documentListeners),
  };
  globalThis.window = win;
  globalThis.document = doc;
  globalThis.fetch = async (path, options = {}) => {
    const method = options.method || "GET";
    const body = typeof options.body === "string" ? JSON.parse(options.body) : null;
    calls.push({ method, path, body });
    requestTokens.push({ path, token: new Headers(options.headers).get("x-elastos-home-token") });
    const route = routes[`${method} ${path}`];
    if (!route) {
      throw new Error(`no route for ${method} ${path}`);
    }
    const answer = await (typeof route === "function" ? route(body) : route);
    return {
      ok: answer.status < 400,
      status: answer.status,
      text: async () => JSON.stringify(answer.body),
    };
  };
  const realNow = Date.now;
  Date.now = () => clock;
  bootCustodyApp(bootOptions);
  return {
    calls,
    requestTokens,
    stepUps,
    timers,
    markup: () => nodes.pools.innerHTML,
    hostingMarkup: () => nodes["hosting-node"].innerHTML,
    tick(ms) {
      clock += ms;
    },
    // Runs the timers armed now; ones they arm wait for the next call.
    fireTimers() {
      for (const timer of timers.splice(0)) {
        timer.fn();
      }
    },
    click(action, data = {}) {
      const button = new HTMLButtonElement();
      button.dataset = { action, ...data };
      for (const listener of documentListeners.get("click") || []) {
        listener({ target: button });
      }
    },
    dispatch(type) {
      for (const listener of documentListeners.get(type) || []) {
        listener({});
      }
    },
    refresh() {
      for (const listener of windowListeners.get("message") || []) {
        listener({ source: win.parent, origin: "null", data: { type: "elastos:menu-command", cmd: "refresh" } });
      }
    },
    restore() {
      Date.now = realNow;
    },
  };
}

async function settle() {
  for (let round = 0; round < 30; round += 1) {
    await new Promise((resolve) => setImmediate(resolve));
  }
}

function deferred() {
  let resolve;
  const promise = new Promise((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

const ok = (body) => ({ status: 200, body });

test("A renewed Home token is used by the next request and by Copy", async () => {
  let navigation = null;
  const clipboards = [];
  const app = boot({ "GET /api/apps/custody/summary": () => ok(summary()) }, {
    createClipboard({ homeOrigin, homeToken }) {
      const clipboard = { homeOrigin, token: homeToken, setHomeToken(token) { this.token = token; } };
      clipboards.push(clipboard);
      return clipboard;
    },
    createNavigation(options) {
      navigation = options;
      return {};
    },
  });
  try {
    await settle();
    assert.equal(navigation.target, "custody");
    assert.equal(navigation.homeOrigin, HOME_ORIGIN);
    assert.equal(navigation.homeToken, "launch-token");
    navigation.onHomeToken("renewed-token");
    app.refresh();
    await settle();
    const summaries = app.requestTokens.filter((call) => call.path === "/api/apps/custody/summary");
    assert.ok(summaries.length >= 2, JSON.stringify(summaries));
    assert.equal(summaries[0].token, "launch-token");
    assert.equal(summaries.at(-1).token, "renewed-token");
    assert.equal(clipboards.length, 1);
    assert.equal(clipboards[0].token, "renewed-token");
  } finally {
    app.restore();
  }
});

test("Remove on this Home's provisioned node asks the passkey and deletes it", async () => {
  const app = boot({
    "GET /api/apps/custody/summary": () => ok(summary()),
    "DELETE /api/apps/custody/local-node": () => ok({ provisioned: false }),
  });
  try {
    await settle();
    app.click("go", { step: "nodes" });
    app.click("include-open", { slot: "0" });
    await settle();
    assert.match(app.markup(), /<p class="cp-slot-name">This Home<\/p>/);
    app.click("remove", { slot: "0" });
    await settle();
    assert.deepEqual(app.stepUps, [{ operation: "custody.local_node.remove", request: {} }]);
    assert.deepEqual(
      app.calls.filter((call) => call.method === "DELETE"),
      [{ method: "DELETE", path: "/api/apps/custody/local-node", body: { step_up_token: "token-custody.local_node.remove" } }],
    );
    assert.match(app.markup(), /This Home&#039;s node is removed\. This Home can offer custody again\./);
  } finally {
    app.restore();
  }
});

test("Remove on a this-Home slot whose node is gone only clears the slot", async () => {
  let current = summary();
  const app = boot({ "GET /api/apps/custody/summary": () => ok(current) });
  try {
    await settle();
    app.click("go", { step: "nodes" });
    app.click("include-open", { slot: "0" });
    await settle();
    current = summary({ local_node: { provisioned: false } });
    app.refresh();
    await settle();
    app.click("remove", { slot: "0" });
    await settle();
    assert.deepEqual(app.stepUps, []);
    assert.equal(app.calls.filter((call) => call.method === "DELETE").length, 0);
    assert.doesNotMatch(app.markup(), /<p class="cp-slot-name">This Home<\/p>/);
  } finally {
    app.restore();
  }
});

test("a node asked again binds its new request even when its slot was removed meanwhile", async () => {
  const asked = deferred();
  const approved = record({ state: "approved", card: ANN_CARD });
  const app = boot({
    "GET /api/apps/custody/summary": () => ok(summary({ local_node: { provisioned: false }, node_requests: [approved] })),
    "POST /api/apps/custody/node-cards/read": () => ok({
      run_by: "Ann",
      location: "Lisbon",
      home_id: "did:key:ann-home",
      provides: ["chain", "custody"],
      fingerprint: "AA BB CC DD",
    }),
    "POST /api/apps/custody/node-requests": () => asked.promise,
  });
  try {
    await settle();
    app.click("go", { step: "nodes" });
    assert.match(app.markup(), /Approved by Ann/);
    app.click("term", { days: "182" });
    await settle();
    assert.match(app.markup(), /data-action="ask-again" data-slot="0"/);
    app.click("ask-again", { slot: "0" });
    await settle();
    app.click("remove", { slot: "0" });
    await settle();
    asked.resolve(ok(record({ request_id: "req-2", term_days: 182, created_at: 1_793_000_100 })));
    await settle();
    assert.match(app.markup(), /Waiting for Ann/);
  } finally {
    app.restore();
  }
});

test("the request poll waits for a summary in flight instead of spinning", async () => {
  const slow = deferred();
  let reads = 0;
  const app = boot({
    "GET /api/apps/custody/summary": () => {
      reads += 1;
      return reads === 1 ? ok(summary({ node_requests: [record()] })) : slow.promise;
    },
  });
  try {
    await settle();
    app.click("go", { step: "nodes" });
    assert.match(app.markup(), /Waiting for Ann/);
    // The poll fires and its read hangs.
    app.tick(10_000);
    app.fireTimers();
    await settle();
    assert.equal(reads, 2);
    // Coming back after the interval arms the poll at once, while the read
    // still runs.
    app.tick(15_000);
    app.dispatch("visibilitychange");
    assert.deepEqual(app.timers.map((timer) => timer.delay), [0]);
    app.fireTimers();
    await settle();
    assert.deepEqual(app.timers, [], "nothing is armed while the read runs");
    assert.equal(reads, 2);
    // The read ends and arms the next poll.
    slow.resolve(ok(summary({ node_requests: [record()] })));
    await settle();
    assert.equal(app.timers.length, 1);
  } finally {
    app.restore();
  }
});

test("a this-Home slot refused for missing keys reads the summary again, so Include sets it up", async () => {
  const approved = record({ state: "approved", card: ANN_CARD });
  let summaries = 0;
  const app = boot({
    "GET /api/apps/custody/summary": () => {
      summaries += 1;
      return ok(summary({
        node_requests: [approved],
        local_node: summaries === 1 ? { provisioned: true, run_by: "Iz", location: "Paris", running: true } : { provisioned: false },
      }));
    },
    "POST /api/apps/custody/node-cards/read": () => ok({
      run_by: "Ann",
      location: "Lisbon",
      home_id: "did:key:ann-home",
      provides: ["chain", "custody"],
      fingerprint: "AA BB CC DD",
    }),
    "POST /api/apps/custody/pool/check": () => ok({
      checks: [{ id: "card", result: "fail", names: ["2"], detail: "local_node_no_keys" }],
    }),
  });
  try {
    await settle();
    app.click("go", { step: "nodes" });
    app.click("include-open", { slot: "1" });
    await settle();
    assert.match(app.markup(), /This Home&#039;s node has no keys/);
    assert.equal(summaries, 2);
    // Include now asks Runtime to set the node up, instead of reusing it.
    app.click("retry-card", { slot: "1" });
    app.click("include-open", { slot: "1" });
    await settle();
    assert.match(app.markup(), /data-action="include-confirm"/);
  } finally {
    app.restore();
  }
});

test("confirm_publisher_asks_for_passkey", async () => {
  const pool = "ef".repeat(32);
  let served = [{ pool_fingerprint: pool, owner_name: "Ann", roles: ["custody"], status: "serving", term_end: 1_900_000_000, shares_held: 2, publisher_confirmed: false }];
  const serving = {
    owner_name: "Ann", owner_did: "did:key:ann-home", run_by: "Iz", location: "Paris", provides: ["chain", "custody"],
    fingerprint: "AB", fingerprint_full: `sha256:${"c".repeat(64)}`, provider_running: true, needs_restart: false,
    last_owner_contact: null, pool: null, pool_fingerprint: pool,
  };
  const current = summary({ serving: [serving] });
  const app = boot({
    "GET /api/apps/custody/summary": () => ok(current),
    "GET /api/apps/custody/offer": () => ok({ enabled: false, run_by: "Iz", location: "Paris", provides: [], holds_custody_state: true, messages_enabled: true }),
    "GET /api/apps/custody/pools/served": () => ok(served),
    "GET /api/apps/custody/pools/known": () => ok([]),
    [`POST /api/apps/custody/pools/served/${pool}/publisher`]: () => {
      served = [{ ...served[0], publisher_confirmed: true }];
      return ok({ publisher_confirmed: true });
    },
  });
  try {
    await settle();
    app.click("section", { section: "hosting" });
    await settle();
    assert.match(app.hostingMarkup(), new RegExp(`data-action="confirm-publisher" data-pool="${pool}"`));
    app.click("confirm-publisher", { pool });
    await settle();
    assert.deepEqual(app.stepUps, [{ operation: "custody.served_pool.confirm_publisher", request: { pool } }]);
    assert.deepEqual(
      app.calls.filter((call) => call.method === "POST" && call.path.endsWith("/publisher")),
      [{ method: "POST", path: `/api/apps/custody/pools/served/${pool}/publisher`, body: { pool, step_up_token: "token-custody.served_pool.confirm_publisher" } }],
    );
    assert.doesNotMatch(app.hostingMarkup(), /data-action="confirm-publisher"/);
  } finally {
    app.restore();
  }
});

test("stop_serving_asks_for_passkey", async () => {
  const pool = "ab".repeat(32);
  let served = [{ pool_fingerprint: pool, owner_name: "Ann", roles: ["custody"], status: "serving", term_end: 1_900_000_000, shares_held: 2 }];
  const serving = {
    owner_name: "Ann", owner_did: "did:key:ann-home", run_by: "Iz", location: "Paris", provides: ["chain", "custody"],
    fingerprint: "AB", fingerprint_full: `sha256:${"c".repeat(64)}`, provider_running: true, needs_restart: false,
    last_owner_contact: null, pool: null, pool_fingerprint: pool,
  };
  let current = summary({ serving: [serving] });
  const app = boot({
    "GET /api/apps/custody/summary": () => ok(current),
    "GET /api/apps/custody/offer": () => ok({ enabled: false, run_by: "Iz", location: "Paris", provides: [], holds_custody_state: true, messages_enabled: true }),
    "GET /api/apps/custody/pools/served": () => ok(served),
    "GET /api/apps/custody/pools/known": () => ok([]),
    [`DELETE /api/apps/custody/pools/served/${pool}`]: () => {
      served = [];
      current = summary({ serving: [] });
      return ok({ stopped: true });
    },
  });
  try {
    await settle();
    app.click("section", { section: "hosting" });
    await settle();
    assert.match(app.hostingMarkup(), new RegExp(`data-action="stop-serving" data-pool="${pool}"`));
    app.click("stop-serving", { pool });
    await settle();
    assert.deepEqual(app.stepUps, [{ operation: "custody.served_pool.remove", request: { pool } }]);
    assert.deepEqual(
      app.calls.filter((call) => call.method === "DELETE"),
      [{ method: "DELETE", path: `/api/apps/custody/pools/served/${pool}`, body: { pool, step_up_token: "token-custody.served_pool.remove" } }],
    );
    const html = app.hostingMarkup();
    assert.match(html, /This Home no longer serves that pool\./);
    assert.doesNotMatch(html, /data-action="stop-serving"/);
  } finally {
    app.restore();
  }
});
