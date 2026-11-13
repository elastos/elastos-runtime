import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import vm from "node:vm";

const read = path => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
function fn(source, name) {
  const plain = source.indexOf(`function ${name}(`);
  assert.ok(plain >= 0, name);
  const start = source.slice(plain - 6, plain) === "async " ? plain - 6 : plain;
  return source.slice(start, source.indexOf("\n}", plain) + 2);
}
// A function nested in an app's boot closure, two spaces in.
function inner(source, name) {
  const plain = source.indexOf(`  function ${name}(`);
  const asyncStart = source.indexOf(`  async function ${name}(`);
  const start = asyncStart >= 0 ? asyncStart : plain;
  assert.ok(start >= 0, name);
  return source.slice(start, source.indexOf("\n  }\n", start) + 4);
}
function fixture() {
  const requests = [], clips = [];
  let options;
  const window = { location: { hash: "#home_token=old", search: "?home_origin=https://home.fixture" }, top: {},
    setTimeout, clearTimeout };
  const context = vm.createContext({ window, URLSearchParams, Headers, AbortController,
    document: { getElementById: () => ({}), querySelector: () => ({}) },
    createHomeNavigationClient(value) { options = value; return {}; },
    createHomeClipboardClient(value) {
      const clip = { token: value.homeToken, retired: false, start() {}, setHomeToken(token) { this.token = token; }, teardown() { this.retired = true; } };
      clips.push(clip); return clip;
    },
    fetch: async (path, options) => {
      requests.push({ path, token: new Headers(options.headers).get("x-elastos-home-token"), body: options.body });
      return { ok: true, status: 200, headers: new Headers({ "content-type": "application/json" }),
        text: async () => "{}", json: async () => ({}) };
    },
    sharedFileName: value => value || "", readText: value => value || "",
    DOCUMENTS_REQUEST_DEADLINE_MS: 1000,
  });
  return { context, requests, clips, renew() { assert.ok(options?.onHomeToken); options.onHomeToken("fresh"); } };
}

test("People requests and Clipboard use the replacement token", async () => {
  const f = fixture(), source = read("capsules/people/browser/people.js");
  vm.runInContext(source.slice(source.indexOf("const lockedShell"), source.indexOf("let localProfileId")), f.context);
  vm.runInContext(fn(source, "fetchJson"), f.context);
  await f.context.fetchJson("/people"); f.renew(); await f.context.fetchJson("/people");
  assert.deepEqual(f.requests.map(r => r.token), ["old", "fresh"]);
  assert.equal(f.clips.length, 1); assert.equal(f.clips[0].retired, false); assert.equal(f.clips[0].token, "fresh");
});

test("Documents keeps its draft and sends the next save with the replacement token", async () => {
  const f = fixture(), source = read("capsules/documents/browser/documents.js");
  vm.runInContext(source.slice(source.indexOf("const state"), source.indexOf("const DOCUMENTS_WINDOW_CLOSE_REQUEST_TYPE")), f.context);
  vm.runInContext(fn(source, "documentsApi"), f.context);
  vm.runInContext('state.dirty = true; state.current = { text: "Keep my edits" };', f.context);
  await f.context.documentsApi("/save", { method: "POST", body: "first revision" });
  f.renew();
  await f.context.documentsApi("/save", { method: "POST", body: "saved revision" });
  assert.deepEqual(f.requests.map(r => r.token), ["old", "fresh"]);
  assert.equal(f.requests[1].body, "saved revision");
  assert.equal(vm.runInContext("state.dirty && state.current.text", f.context), "Keep my edits");
});

test("Assistant requests and token listeners receive the replacement", async () => {
  const f = fixture(), source = read("capsules/assistant/browser/harness-host.js");
  vm.runInContext(source.slice(source.indexOf("let homeToken"), source.indexOf("/* ---- shell-core")).replaceAll("export ", ""), f.context);
  vm.runInContext(fn(source, "fetchJson"), f.context);
  f.context.homeOrigin = () => "https://home.fixture";
  vm.runInContext(fn(source, "getHomeGuiLaunchToken"), f.context);
  const app = read("capsules/assistant/browser/home-agent.js");
  vm.runInContext(app.slice(app.indexOf("const clipboardOptions"), app.indexOf("/* A copy Home")), f.context);
  let observed; f.context.onHomeTokenChanged(token => { observed = token; });
  await f.context.fetchJson("/assistant"); f.renew(); await f.context.fetchJson("/assistant");
  assert.deepEqual(f.requests.map(r => r.token), ["old", "fresh"]);
  assert.equal(observed, "fresh");
  assert.equal(f.clips[0].token, "fresh");
  assert.equal(f.clips[0].retired, false);
});

test("Library requests read the renewed state and replace Clipboard authority", async () => {
  const f = fixture(), source = read("capsules/library/browser/src/app.js");
  vm.runInContext('const state = { homeToken: "old", mode: "browse" }; const queryParams = new URLSearchParams(window.location.search);', f.context);
  vm.runInContext(read("capsules/library/browser/src/api.js").replaceAll("export ", ""), f.context);
  vm.runInContext(source.slice(source.indexOf('    const homeOrigin ='), source.indexOf('    const elements =')), f.context);
  await vm.runInContext('runtimeProviderApi("read", {})', f.context);
  f.renew();
  await vm.runInContext('runtimeProviderApi("write", { text: "saved" })', f.context);
  assert.deepEqual(f.requests.map(r => r.token), ["old", "fresh"]);
  assert.equal(f.clips.length, 1); assert.equal(f.clips[0].retired, false); assert.equal(f.clips[0].token, "fresh");
});

test("Creator requests read the renewed token", async () => {
  const f = fixture(), source = read("capsules/creator/browser/creator.js");
  f.context.connectHomeNavigation = f.context.createHomeNavigationClient;
  f.context.query = new URLSearchParams("?home_origin=https://home.fixture");
  const start = source.indexOf("  let homeToken =");
  vm.runInContext(source.slice(start, source.indexOf("\n  const els = {", start)), f.context);
  vm.runInContext(inner(source, "providerApiEnvelope"), f.context);
  await f.context.providerApiEnvelope("status", {}); f.renew(); await f.context.providerApiEnvelope("status", {});
  assert.deepEqual(f.requests.map(r => r.token), ["old", "fresh"]);
});

test("Marketplace requests and content reads use the replacement token", async () => {
  const f = fixture(), source = read("capsules/marketplace/browser/marketplace.js");
  const readers = [];
  f.context.createContentReader = ({ token }) => {
    const reader = { token, setToken(value) { this.token = value; } };
    readers.push(reader); return reader;
  };
  // An open model detail (marketplace.js `detailModels`) is renewed as well.
  f.context.detailModels = { token: "old", setToken(value) { this.token = value; } };
  const start = source.indexOf("  const params = new URLSearchParams(window.location.search);");
  vm.runInContext(source.slice(start, source.indexOf("\n  const state = {", start)), f.context);
  vm.runInContext(inner(source, "postObjectProvider"), f.context);
  await f.context.postObjectProvider("status", {}); f.renew(); await f.context.postObjectProvider("status", {});
  assert.deepEqual(f.requests.map(r => r.token), ["old", "fresh"]);
  assert.equal(readers.length, 1); assert.equal(readers[0].token, "fresh");
  assert.equal(f.context.detailModels.token, "fresh");
});

// Just enough DOM for the shared model controller's compact view.
class FakeNode {
  constructor(tag) {
    Object.assign(this, { tag, children: [], dataset: {}, listeners: {}, attributes: {}, hidden: false, disabled: false,
      textContent: "", className: "", classList: { add() {} } });
  }
  append(...nodes) { this.children.push(...nodes); }
  replaceChildren(...nodes) { this.children = [...nodes]; }
  setAttribute(name, value) { this.attributes[name] = value; }
  addEventListener(type, fn) { (this.listeners[type] ||= []).push(fn); }
  contains(node) { return node === this || this.children.some(child => child instanceof FakeNode && child.contains(node)); }
  querySelector() { return null; }
  cloneNode() { return new FakeNode(this.tag); }
  focus() {}
  all() { return [this, ...this.children.flatMap(child => child instanceof FakeNode ? child.all() : [])]; }
}

test("An open Marketplace model detail keeps its operation and sends the replacement token", async () => {
  const source = read("capsules/_shared/model-management.js");
  for (const copy of ["marketplace", "system"]) assert.equal(read(`capsules/${copy}/browser/model-management.js`), source);
  const cid = `bafybei${"a".repeat(52)}`;
  const preparation = { operation_id: "op-1", cid, state: "preparing", total_bytes: 1000, completed_bytes: 100,
    cancel_requested: false, admitted: false, activation_pending: false, failure_class: null };
  const operations = ["use", "status", "cancel", "retention", "reclaim"];
  const requests = [], timers = [];
  const answer = (path, body) => {
    if (path === "/api/capsules/catalog") return { schema: "elastos.capsules.catalog/v1", model_catalog_state: "verified",
      capsules: [{ source: "signed-model-catalog", cid, role: "content", installed: false, launchable: false,
        title: "Fixture model", publisher_did: "did:fixture:publisher", signature_state: "catalog-signature-verified",
        content_size_bytes: 1000, model_memory_fit: "fits",
        model_runtime: { admitted: false, kept: false, dispatch_ready: false, offer_id: null, preparation } }] };
    if (path === "/api/capsules/interfaces") return { interfaces: [{ capsule: "marketplace",
      interface: { id: "elastos.model", methods: operations.map(operation => ({ id: `content.${operation}`, operation,
        resource: "elastos://capsules/*", approval: "runtime_policy", risk: operation === "status" ? "read" : "write" })) },
      bindings: operations.map(operation => ({ method: `content.${operation}`, executable: true })) }] };
    const state = body.method === "content.cancel"
      ? { ...preparation, cancel_requested: true } : { ...preparation, completed_bytes: 500 };
    return { schema: "elastos.capsules.invoke-result/v1", status: "ok", capsule: body.capsule, interface: body.interface,
      method: body.method, request_id: body.request_id,
      output: { admitted: false, kept: false, dispatch_ready: false, offer_id: null, ...state } };
  };
  const fetch = async (path, init) => {
    const body = init.body ? JSON.parse(init.body) : null;
    requests.push({ path, token: init.headers["x-elastos-home-token"], method: body?.method, input: body?.input });
    return { ok: true, text: async () => JSON.stringify(answer(path, body)) };
  };
  const pageWindow = { addEventListener() {}, removeEventListener() {} };
  const context = vm.createContext({ window: pageWindow, fetch, AbortController,
    document: { hidden: false, activeElement: null, createElement: tag => new FakeNode(tag), createTextNode: value => value,
      addEventListener() {}, removeEventListener() {} },
    crypto: { randomUUID: () => `request-${requests.length}` },
    setTimeout: (fn, delay) => timers.push({ fn, delay, cleared: false }),
    clearTimeout: id => { if (timers[id - 1]) timers[id - 1].cleared = true; } });
  vm.runInContext(source, context);
  const flush = async () => { for (let i = 0; i < 20; i++) await new Promise(resolve => setImmediate(resolve)); };
  const root = new FakeNode("ul"), actionsRoot = new FakeNode("span");
  const models = pageWindow.ElastosModelManagement.create({ root, capsule: "marketplace", token: "old", cid, compact: true,
    actionsRoot, buttonClass: "secondary", primaryButtonClass: "primary", onReadyOpen() {} });
  models.setVisible(true);
  await flush();
  assert.deepEqual(requests.map(r => [r.path, r.token]),
    [["/api/capsules/catalog", "old"], ["/api/capsules/interfaces", "old"]]);

  // Home renews the frame while the detail stays open on a running Get.
  models.setToken("fresh");
  const poll = timers.filter(timer => !timer.cleared && timer.delay === 1500).at(-1);
  assert.ok(poll);
  poll.fn(); await flush();
  assert.deepEqual(requests.slice(2).map(r => [r.method, r.token, r.input.operation_id]),
    [["content.status", "fresh", "op-1"]]);
  const stop = actionsRoot.all().find(node => node.dataset.modelControl === "cancel");
  assert.ok(stop); assert.equal(stop.disabled, false);
  stop.listeners.click[0](); await flush();
  assert.deepEqual(requests.slice(3).map(r => [r.method, r.token, r.input.operation_id]),
    [["content.cancel", "fresh", "op-1"]]);
  // The operation continued in place: the catalog was read once.
  assert.equal(requests.filter(r => r.path === "/api/capsules/catalog").length, 1);
  models.destroy();
});

test("Only Home's exact proactive request reaches Browser's renewal adapter", () => {
  const source = read("capsules/browser/browser/browser.js");
  const start = source.indexOf('window.addEventListener("message", (event) => {');
  let receive, renewals = 0;
  const top = {};
  const context = vm.createContext({ window: { top, addEventListener(type, callback) { receive = callback; } },
    homeParentOrigin: "https://home.fixture", launchToken: "browser-old", requestHomeRelaunch() { renewals++; } });
  vm.runInContext(source.slice(start, source.indexOf("  if (isHomeBrowserWindowCloseRequest", start)) + "});", context);
  const data = { type: "elastos.home.authority.request/v1", homeToken: "browser-old" };
  receive({ data, source: {}, origin: "https://home.fixture" });
  receive({ data, source: top, origin: "https://evil.fixture" });
  receive({ data: { ...data, homeToken: "other" }, source: top, origin: "https://home.fixture" });
  assert.equal(renewals, 0);
  receive({ data, source: top, origin: "https://home.fixture" });
  assert.equal(renewals, 1);
});
