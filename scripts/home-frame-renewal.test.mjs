import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { registerHooks } from "node:module";
import { createHomeClipboardClient } from "../capsules/home/browser/home-clipboard-client.js";
import { createHomeClipboardHost, createHomeClipboardFrameState } from "../capsules/home/browser/home-clipboard-host.js";
import { handleWalletAppUse, retireWalletAppUse } from "../capsules/home/browser/wallet-app-use-host.mjs";
import { createHomeNavigationClient } from "../capsules/home/browser/home-navigation-client.js";

const homeOrigin = "https://home.fixture";
test.beforeEach(t => t.mock.timers.enable({ apis: ["Date"], now: 59_000 }));
const hostURL = new URL("../capsules/home/browser/home-shell-host.js", import.meta.url);
const hostImports = [...readFileSync(hostURL, "utf8").matchAll(/import\s*\{([^}]+)\}\s*from\s*["']([^"']+)["']/g)];
let fixtureNumber = 0;
async function fixture(target = "chat-room", enabled = true, { readyState = "" } = {}) {
  const listeners = new Map(), timers = new Map(), commands = [], launchQueries = [];
  let next = 0, receive, launches = 0, refreshed = 0, currentToken = "old-frame", holdPrepare = false;
  const authority = { signed_in: true, principal_id: "alice", proof_binding_id: "proof:alice" };
  const shell = {}, home = { location: { origin: homeOrigin, href: homeOrigin },
    setTimeout(fn) { timers.set(++next, fn); return next; }, clearTimeout(id) { timers.delete(id); },
    addEventListener(type, fn) { if (type === "message") receive = fn; },
  };
  const frame = { postMessage(data) { for (const fn of listeners.get("message") || []) fn({ data, source: home, origin: homeOrigin }); } };
  const windowRef = { top: home, parent: shell, crypto: { randomUUID: () => `request-${++next}` },
    setTimeout: home.setTimeout, clearTimeout: home.clearTimeout,
    addEventListener(type, fn) { if (!listeners.has(type)) listeners.set(type, new Set()); listeners.get(type).add(fn); },
    removeEventListener(type, fn) { listeners.get(type)?.delete(fn); },
    ...(readyState ? { document: { readyState } } : {}),
  };
  const message = (data, source = frame, origin = "null") => receive({ data, source, origin });
  home.postMessage = data => message(data);
  const old = { targetId: target, source: readyState ? null : frame, origin: "null", expiresAt: 60_000 };
  const shellState = { currentSummary: { authority }, activeShellRootTarget: "home-gui" };
  const receipt = command => message({ type: `home:frame-authority-${command.phase === "prepare" ? "renewed" : "committed"}`,
    homeToken: "shell-token", requestId: command.requestId, oldHomeToken: command.homeToken,
    freshHomeToken: "fresh-frame", ok: true }, shell);
  const clipboardHost = { handle: () => false, retireFrame() {}, resetFrame() {} };
  let booting = true;
  const dependencies = {
    shellState, activeShellFrame: { addEventListener() {}, contentWindow: shell, dataset: { route: "/apps/home-gui/#home_token=shell-token" } },
    activeShellRoot: { dataset: { target: "home-gui" } },
    HOME_GUI_SHELL_ID: "home-gui", SYSTEM_APP_ID: "system", HOME_SHELL_HOST_ID: "home-shell-host",
    homeActiveShellName: value => value,
    shellHostRecoveryHomeButton: null, shellHostRecoveryReloadButton: null, shellHostRecoverySignOutButton: null,
    createHomeClipboardPrompt: () => ({}), createHomeClipboardHost: () => clipboardHost,
    createHomeExternalLinkPrompt: () => ({ retire() {}, transfer() {} }),
    createHomeLinkStatus: () => ({ replay() {} }), bindKeyboardInsetRelay() {}, bindHomeUnlock() {},
    handleHomeWalletConnectorEffect: () => false, handleWalletAppUse, retireWalletAppUse, isHomeAuthError: () => false,
    refreshHomeSession: () => {
      // Leave startup pending. Each test drives session refresh itself.
      if (booting) { booting = false; return new Promise(() => {}); }
      refreshed++;
      return Promise.resolve();
    },
  };
  globalThis.window = home;
  globalThis.document = { body: { dataset: { homeAuthority: "signed" } }, querySelector: () => null };
  globalThis.__homeRenewalDependencies = dependencies;
  const url = `${hostURL.href}?renewal-fixture=${++fixtureNumber}`;
  // Import the complete host. Substitute its UI/network dependencies and expose
  // private controls only in this test loader; renewal helpers stay in scope.
  const hooks = registerHooks({
    resolve(specifier, options, nextResolve) {
      if (options.parentURL === url) {
        const declaration = hostImports.find(match => match[2] === specifier);
        assert.ok(declaration, `unexpected host dependency: ${specifier}`);
        const exports = declaration[1].split(",").map(name => name.trim()).filter(Boolean).map(name =>
          `export const ${name} = Object.hasOwn(globalThis.__homeRenewalDependencies, ${JSON.stringify(name)})
            ? globalThis.__homeRenewalDependencies[${JSON.stringify(name)}]
            : (() => { throw new Error("Unexpected dependency: ${name}"); });`).join("\n");
        return { shortCircuit: true, url: `data:text/javascript,${encodeURIComponent(exports)}#${fixtureNumber}` };
      }
      return nextResolve(specifier, options);
    },
    load(moduleURL, options, nextLoad) {
      const loaded = nextLoad(moduleURL, options);
      if (moduleURL !== url) return loaded;
      return { ...loaded, source: `${loaded.source}
        export { launchedAppContexts, pendingBrowserAuthorityRenewals, homeClipboardHost,
          refreshSignedHomeSession, retireLaunchedAppContext, openLibraryPicker,
          currentLibraryPicker, deliverMessageToHomeGuiTargetFrame, acceptLibraryPicker };
        export function configureFixture(overrides) {
          postToActiveShell = overrides.postToActiveShell;
          refreshShellSummary = overrides.refreshShellSummary;
          launchHomeTarget = overrides.launchHomeTarget;
        }
        export function setPickerLauncher(value) { openTargetFromHomeGui = value; }
      ` };
    },
  });
  let api;
  try { api = await import(url); }
  finally { hooks.deregister(); delete globalThis.__homeRenewalDependencies; }
  const frames = api.launchedAppContexts;
  frames.set("old-frame", old);
  api.configureFixture({
    postToActiveShell(command) {
      commands.push(command);
      if (command.command === "renew-frame-authority" && (!holdPrepare || command.phase === "commit")) queueMicrotask(() => receipt(command));
      return true;
    },
    refreshShellSummary: async () => shellState.currentSummary,
    launchHomeTarget: async (requested, query) => {
      launches++;
      launchQueries.push(query);
      if (!authority.signed_in) throw Object.assign(new Error("Sign in"), { status: 401 });
      frames.set("fresh-frame", { targetId: requested, source: null, origin: "null", parentOrigin: homeOrigin, expiresAt: 120_000 });
      return { target: requested, attach_kind: "iframe", expires_at: 120,
        route: `/apps/${requested}/#home_token=fresh-frame` };
    },
  });
  const context = { ...api };
  Object.defineProperties(context, {
    homeClipboardHost: { get: () => clipboardHost, set: value => Object.assign(clipboardHost, value) },
    openTargetFromHomeGui: { set: api.setPickerLauncher },
  });
  const client = createHomeNavigationClient({ homeToken: currentToken, homeOrigin, target, enabled, windowRef,
    onHomeToken(token) { currentToken = token; } });
  return { client, context, frames, message, receipt, commands, launchQueries, authority, frame, old, timers, home, windowRef,
    pageshow() { for (const fn of listeners.get("pageshow") || []) fn(); },
    hold() { holdPrepare = true; }, token: () => currentToken, launches: () => launches, refreshed: () => refreshed,
    close() { context.retireLaunchedAppContext("old-frame"); },
  };
}
const settle = async () => { for (let i = 0; i < 8; i++) await Promise.resolve(); };

const RENEWING_TARGETS = ["chat-room", "people", "documents", "assistant", "library",
  "creator", "custody", "marketplace", "elacity-player", "elacity-reader"];

for (const target of RENEWING_TARGETS) {
  test(`Home refresh replaces an expiring open ${target} frame authority`, async () => {
    const f = await fixture(target);
    await f.context.refreshSignedHomeSession(); await settle();
    assert.equal(f.refreshed(), 1);
    assert.equal(f.token(), "fresh-frame");
    assert.equal(f.frames.has("old-frame"), false);
    assert.equal(f.frames.get("fresh-frame").source, f.frame);
    assert.equal(f.launches(), 1);
    assert.equal(f.timers.size, 0);
  });
}

// Creator, Player and Reader load the navigation client with a dynamic import
// that usually resolves after the document's first pageshow.
for (const target of ["creator", "elacity-player", "elacity-reader"]) {
  test(`A ${target} navigation client attached after the page was shown is bound and renewed`, async () => {
    const f = await fixture(target, true, { readyState: "complete" });
    assert.equal(f.old.source, f.frame);
    await f.context.refreshSignedHomeSession(); await settle();
    assert.equal(f.token(), "fresh-frame");
    assert.equal(f.frames.has("old-frame"), false);
    assert.equal(f.frames.get("fresh-frame").source, f.frame);
    assert.equal(f.launches(), 1);
  });
}

test("A navigation client created while its page loads is bound by its pageshow", async () => {
  const f = await fixture("elacity-player", true, { readyState: "interactive" });
  assert.equal(f.old.source, null);
  // Home renews only frames it has bound.
  await f.context.refreshSignedHomeSession(); await settle();
  assert.equal(f.launches(), 0);
  assert.equal(f.token(), "old-frame");
  f.pageshow();
  assert.equal(f.old.source, f.frame);
  await f.context.refreshSignedHomeSession(); await settle();
  assert.equal(f.token(), "fresh-frame");
  assert.equal(f.launches(), 1);
});

test("A stolen frame token, wrong origin or another target cannot request renewal", async () => {
  const f = await fixture();
  const request = { type: "home:launch-target", homeToken: "old-frame", requestId: "renew-1", target: "chat-room", query: {} };
  f.message(request, {});
  f.message(request, f.frame, homeOrigin);
  f.message({ ...request, target: "documents" });
  await settle();
  assert.equal(f.launches(), 0);
  assert.equal(f.token(), "old-frame");
});

for (const target of RENEWING_TARGETS) {
  test(`${target} renewal refuses unexpected query keys and picker authority`, async () => {
    for (const query of [{ unexpected: "value" }, { pickerRequestId: "foreign-picker" }]) {
      const f = await fixture(target);
      f.client.setQuery(query);
      await assert.rejects(f.client.renewAuthority(), /could not reconnect/);
      assert.equal(f.launches(), 0);
      assert.equal(f.token(), "old-frame");
    }
  });
}

for (const [target, query] of [["chat-room", { conversation_id: "direct:fixture" }],
  ["documents", { doc: "did:fixture" }], ["documents", { objectUri: "library://fixture/file" }],
  ["library", { uri: "library://fixture/folder" }],
  ["elacity-player", { mint_id: "a".repeat(64) }], ["elacity-reader", { mint_id: "b".repeat(64) }]]) {
  test(`${target} renewal accepts its ${Object.keys(query)[0]} selector`, async () => {
    const f = await fixture(target);
    f.client.setQuery(query);
    await f.client.renewAuthority();
    assert.equal(f.token(), "fresh-frame");
    assert.deepEqual(JSON.parse(JSON.stringify(f.launchQueries[0])), query);
  });
}

for (const target of ["elacity-player", "elacity-reader"]) {
  test(`${target} renewal refuses a mint_id that is not a mint`, async () => {
    for (const mint_id of ["A".repeat(64), "a".repeat(63), `${"a".repeat(64)}/x`, ""]) {
      const f = await fixture(target);
      f.client.setQuery({ mint_id });
      await assert.rejects(f.client.renewAuthority(), /could not reconnect/);
      assert.equal(f.launches(), 0, mint_id);
      assert.equal(f.token(), "old-frame");
    }
  });
}

test("Home GUI renews the open window of every app Home renews, and of no other", async () => {
  function element() {
    const node = new Proxy({
      style: {},
      dataset: {},
      classList: { add() {}, remove() {}, toggle() {}, contains: () => false },
      hidden: false,
      textContent: "",
      innerHTML: "",
      className: "",
      value: "",
      children: [],
    }, {
      get(target, prop, receiver) {
        if (prop in target) return target[prop];
        if (typeof prop !== "string") return undefined;
        const method = () => receiver;
        target[prop] = method;
        return method;
      },
      set(target, prop, value) {
        target[prop] = value;
        return true;
      },
    });
    node.content = { cloneNode() { return element(); }, firstElementChild: node };
    node.querySelector = () => element();
    node.querySelectorAll = () => [];
    node.closest = () => node;
    node.appendChild = child => child;
    node.insertBefore = child => child;
    node.cloneNode = () => element();
    node.replaceChildren = () => {};
    return node;
  }
  const documentStub = {
    addEventListener() {},
    removeEventListener() {},
    body: element(),
    head: element(),
    documentElement: element(),
    querySelector() { return element(); },
    querySelectorAll() { return []; },
    getElementById() { return element(); },
    createElement() { return element(); },
    elementFromPoint() { return null; },
  };
  globalThis.document = documentStub;
  globalThis.window = globalThis;
  globalThis.location = { href: `${homeOrigin}/apps/home-gui/`, origin: homeOrigin };
  globalThis.addEventListener = globalThis.addEventListener || function () {};
  globalThis.removeEventListener = globalThis.removeEventListener || function () {};
  globalThis.matchMedia = () => ({ matches: false, addEventListener() {}, removeEventListener() {} });
  globalThis.innerWidth = 1280;
  globalThis.innerHeight = 800;
  globalThis.requestAnimationFrame = () => 0;
  globalThis.cancelAnimationFrame = () => {};
  globalThis.getComputedStyle = () => new Proxy({}, { get: () => () => "" });
  globalThis.fetch = async () => ({ ok: true, status: 200, text: async () => "<div></div>", json: async () => ({}) });
  globalThis.localStorage = { getItem: () => null, setItem() {}, removeItem() {} };
  globalThis.HTMLElement = globalThis.HTMLElement || class HTMLElement {};
  globalThis.MutationObserver = globalThis.MutationObserver || class { observe() {} disconnect() {} };
  globalThis.ResizeObserver = globalThis.ResizeObserver || class { observe() {} disconnect() {} };
  const gui = await import("../capsules/home-gui/browser/home-gui.js");
  const shell = await import("../capsules/home-gui/browser/shell-core.js?v=home-20261101d");
  for (const [target, renews] of [...RENEWING_TARGETS.map(target => [target, true]), ["wallet", false], ["browser", false]]) {
    const route = token => `/apps/${target}/?home_origin=${encodeURIComponent(homeOrigin)}#home_token=${token}`;
    const frame = { contentWindow: {}, src: route("old"), dataset: { route: route("old") }, getAttribute: () => route("old") };
    shell.shellState.windows.clear();
    shell.shellState.windows.set("window", {
      id: "window",
      targetId: target,
      node: { querySelector: () => frame },
      homeNavigation: null,
    });
    const launched = { target, attach_kind: "iframe", launch_status: "launched", route: route("fresh") };
    assert.equal(gui.renewHomeGuiFrameAuthority("old", launched, homeOrigin, false), renews, target);
  }
});

test("Home's own refused authority leaves the registered app unchanged", async () => {
  const f = await fixture(); f.authority.signed_in = false;
  await assert.rejects(f.client.renewAuthority(), /Sign in to Home/);
  assert.equal(f.token(), "old-frame");
  assert.equal(f.frames.has("fresh-frame"), false);
});

for (const invalidation of ["close", "principal", "sign-out"]) {
  test(`${invalidation} during renewal rejects late receipts`, async () => {
    const f = await fixture(); f.hold();
    const pending = f.client.renewAuthority();
    const rejected = assert.rejects(pending);
    assert.equal(f.client.renewAuthority(), pending);
    await settle();
    const command = f.commands.find(c => c.phase === "prepare");
    assert.ok(command);
    f.receipt({ ...command, requestId: "forged" });
    assert.equal(f.token(), "old-frame");
    if (invalidation === "close") f.close();
    if (invalidation === "principal") f.authority.principal_id = "bob";
    if (invalidation === "sign-out") f.authority.signed_in = false;
    f.receipt(command); await settle();
    for (const timer of [...f.timers.values()]) timer();
    await rejected;
    assert.equal(f.token(), "old-frame");
    assert.equal(f.frames.has("fresh-frame"), false);
  });
}

async function pickerFixture(renewTarget, openerTarget = "chat-room") {
  const f = await fixture(renewTarget, renewTarget !== "library");
  const opener = renewTarget === "library" ? { targetId: openerTarget, source: { postMessage(data) { delivered.push(data); } }, origin: "null" } : f.old;
  const delivered = [];
  if (opener === f.old) {
    const post = f.frame.postMessage;
    f.frame.postMessage = data => { delivered.push(data); post(data); };
  }
  const picker = renewTarget === "library" ? f.old : { targetId: "library", source: {}, origin: "null" };
  const openerToken = opener === f.old ? "old-frame" : "opener";
  const pickerToken = picker === f.old ? "old-frame" : "picker";
  f.frames.set(openerToken, opener); f.frames.set(pickerToken, picker);
  let record;
  if (openerTarget === "chat-room") {
    f.context.openTargetFromHomeGui = (target, { query }) => {
      assert.equal(target, "library");
      record = opener.pickerRequest;
      assert.equal(query.pickerRequestId, record.id);
      record.pickerToken = pickerToken;
      picker.pickerOwner = record;
    };
    f.context.openLibraryPicker({ homeToken: openerToken, source: opener.source, targetId: openerTarget },
      { requestId: "pick-request", documentNonce: "document-nonce", query: { mode: "attach", returnTarget: openerTarget } });
  } else {
    // Documents has no picker UI in this tree. Exercise association ownership
    // without adding a new Documents selection contract to a renewal fix.
    record = { id: "picker-id", requestId: "pick-request", documentNonce: "document-nonce",
      openerToken, opener, source: opener.source, pickerToken, phase: "ready" };
    opener.pickerRequest = record; picker.pickerOwner = record;
  }
  return { ...f, record, delivered, opener, picker };
}

test("Library renewal accepts only its own in-flight picker without acquiring picker authority", async () => {
  const f = await pickerFixture("library");
  f.client.setQuery({ pickerRequestId: f.record.id });
  await f.client.renewAuthority();
  assert.equal(f.token(), "fresh-frame");
  assert.deepEqual(JSON.parse(JSON.stringify(f.launchQueries[0])), {});
  assert.equal(f.frames.get("fresh-frame").pickerOwner, f.record);
});

for (const invalidation of ["foreign token", "retired", "foreign record"]) {
  test(`Library renewal refuses a picker with ${invalidation}`, async () => {
    const f = await pickerFixture("library");
    if (invalidation === "foreign token") f.record.pickerToken = "another-frame";
    if (invalidation === "retired") f.record.phase = "retired";
    if (invalidation === "foreign record") f.old.pickerOwner = { ...f.record };
    f.client.setQuery({ pickerRequestId: f.record.id });
    await assert.rejects(f.client.renewAuthority(), /could not reconnect/);
    assert.equal(f.launches(), 0);
  });
}

for (const target of ["chat-room", "library"]) {
  test(`Library selection survives renewal of the ${target} frame`, async () => {
    const f = await pickerFixture(target);
    await f.client.renewAuthority(); await settle();
    const fresh = f.frames.get("fresh-frame");
    assert.equal(f.context.currentLibraryPicker(f.record), true);
    if (target === "library") {
      assert.equal(f.record.pickerToken, "fresh-frame");
      assert.equal(fresh.pickerOwner, f.record);
      assert.equal(f.old.pickerOwner, null);
    } else {
      assert.equal(f.record.opener, fresh);
      assert.equal(f.record.openerToken, "fresh-frame");
      assert.equal(f.old.pickerRequest, null);
    }
    if (target === "library") {
      assert.equal(await f.context.deliverMessageToHomeGuiTargetFrame("chat-room", { type: "chat-room:attach-library-item" },
        { targetId: "library", homeToken: "old-frame", source: f.picker.source }, f.record.id), false);
    }
    const delivery = f.context.deliverMessageToHomeGuiTargetFrame("chat-room", { type: "chat-room:attach-library-item" },
      { targetId: "library", homeToken: f.record.pickerToken, source: f.picker.source }, f.record.id);
    const data = f.delivered.at(-1);
    assert.equal(data.pickerId, f.record.id);
    const reply = { ...data, type: "home:picker-accepted", accepted: true };
    assert.equal(f.context.acceptLibraryPicker({ homeToken: "old-frame", source: f.record.source }, reply), false);
    assert.equal(f.record.phase, "delivering");
    assert.equal(f.context.acceptLibraryPicker({ homeToken: f.record.openerToken, source: f.record.source }, reply), true);
    assert.equal(await delivery, true);
  });
}

for (const target of ["documents", "library"]) {
  test(`A Documents-owned picker record survives ${target} renewal`, async () => {
    const f = await pickerFixture(target, "documents");
    await f.client.renewAuthority(); await settle();
    assert.equal(f.context.currentLibraryPicker(f.record), true);
    assert.equal(f.record.phase, "ready");
    assert.equal(f.record.openerToken, target === "documents" ? "fresh-frame" : "opener");
    assert.equal(f.record.pickerToken, target === "library" ? "fresh-frame" : "picker");
  });
}

for (const target of ["chat-room", "library"]) for (const closed of ["opener", "picker"]) {
  test(`Closing ${closed} cancels the picker during ${target} renewal`, async () => {
    const f = await pickerFixture(target); f.hold();
    const pending = f.client.renewAuthority();
    const result = pending.catch(() => {});
    await settle();
    f.context.retireLaunchedAppContext(f.record[`${closed}Token`]);
    assert.equal(f.record.phase, "retired");
    const prepare = f.commands.find(command => command.phase === "prepare");
    f.receipt(prepare); await settle();
    for (const timer of [...f.timers.values()]) timer();
    await result;
    assert.equal(f.context.acceptLibraryPicker({ homeToken: f.record.openerToken, source: f.record.source }, {}), false);
    assert.equal(f.record.phase, "retired");
  });
}


test("Clipboard confirmation and replay state survive frame renewal", async () => {
  const f = await fixture("chat-room");
  let allow;
  const writes = [];
  const host = createHomeClipboardHost({
    clipboard: { writeText: async text => writes.push(text) },
    prompt: { request: () => new Promise(resolve => { allow = resolve; }), cancel() {} },
    cryptoRef: { randomUUID: () => "clipboard-generation" },
    setTimeoutFn: f.home.setTimeout, clearTimeoutFn: f.home.clearTimeout,
  });
  f.context.homeClipboardHost = host;
  f.old.clipboardState = createHomeClipboardFrameState();
  f.old.parentOrigin = homeOrigin;
  const client = createHomeClipboardClient({ targetId: "chat-room", homeOrigin, homeToken: "old-frame",
    targetWindow: f.home, sourceWindow: f.windowRef, cryptoRef: { randomUUID: () => "copy-request" },
    setTimeoutFn: f.home.setTimeout, clearTimeoutFn: f.home.clearTimeout });
  client.start();
  const state = f.old.clipboardState;
  const generation = state.generation;
  const copied = client.writeText("hello", { purpose: "profile.id" });
  await settle();
  assert.equal(typeof allow, "function");
  await f.client.renewAuthority();
  client.setHomeToken("fresh-frame");
  assert.equal(f.frames.get("fresh-frame").clipboardState, state);
  assert.equal(f.old.clipboardState, null);
  assert.equal(state.generation, generation);
  assert.equal(state.retired, false);
  assert.equal(state.inFlight.homeToken, "fresh-frame");
  assert.equal(state.replayIds.has("copy-request"), true);
  allow(true);
  assert.equal(await copied, true);
  assert.deepEqual(writes, ["hello"]);
  client.teardown();
});

test("Pending Browser requests move ownership and retain their GUI reply identity", async () => {
  const f = await fixture();
  const record = { requestId: "browser-request", oldHomeToken: "old-frame", frameToken: "old-frame", timeout: 0 };
  f.context.pendingBrowserAuthorityRenewals.set(record.requestId, record);
  await f.client.renewAuthority();
  assert.equal(f.context.pendingBrowserAuthorityRenewals.get(record.requestId), record);
  assert.equal(record.frameToken, "fresh-frame");
  assert.equal(record.oldHomeToken, "old-frame");
  f.context.retireLaunchedAppContext("fresh-frame");
  assert.equal(f.context.pendingBrowserAuthorityRenewals.size, 0);
});
