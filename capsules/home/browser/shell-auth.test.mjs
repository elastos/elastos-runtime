import assert from "node:assert/strict";
import test from "node:test";

// The real shell-auth module on a minimal page: lock face, card and buttons.
class FakeElement {
  constructor() {
    this.hidden = false;
    this.disabled = false;
    this.textContent = "";
    this.value = "";
    this.title = "";
    this.dataset = {};
    this.attributes = new Map();
    this.listeners = new Map();
    this.style = { setProperty() {}, removeProperty() {} };
    this.classList = { add() {}, remove() {}, toggle() {}, contains: () => false };
  }

  setAttribute(name, value) {
    this.attributes.set(name, String(value));
  }

  addEventListener(type, callback) {
    this.listeners.set(type, callback);
  }

  click() {
    this.listeners.get("click")?.({ target: this });
  }

  focus() {}
}

const elements = new Map();
const element = (selector) => {
  if (!elements.has(selector)) elements.set(selector, new FakeElement());
  return elements.get(selector);
};
globalThis.document = {
  body: { dataset: {} },
  querySelector: element,
  querySelectorAll: () => [],
  getElementById: (id) => element(`#${id}`),
};
globalThis.location = new URL("http://localhost:61180/home/");
globalThis.window = {
  PublicKeyCredential: function PublicKeyCredential() {},
  location: globalThis.location,
  sessionStorage: { getItem: () => null, setItem() {}, removeItem() {} },
  matchMedia: () => ({ matches: false }),
  setTimeout,
  clearTimeout,
  setInterval: () => 1,
  clearInterval() {},
  addEventListener() {},
  dispatchEvent() { return true; },
  dispatchEvent() { return true; },
  atob,
  btoa,
};

let credentials = {};
Object.defineProperty(globalThis, "navigator", {
  configurable: true,
  value: { credentials: { get: (...args) => credentials.get(...args), create: (...args) => credentials.create(...args) } },
});

let routes = {};
const requests = [];
globalThis.fetch = async (url, init = {}) => {
  requests.push({ url, body: init.body ? JSON.parse(init.body) : null });
  const route = routes[url];
  if (!route) throw new TypeError("Failed to fetch");
  const { status = 200, body = {}, retryAfter } = await route();
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: status === 403 ? "Forbidden" : "",
    headers: { get: name => name === "retry-after" ? retryAfter : null },
    text: async () => (typeof body === "string" ? body : JSON.stringify(body)),
    json: async () => body,
  };
};

const fakeCredential = () => ({
  id: "AQ",
  rawId: new Uint8Array([1]).buffer,
  type: "public-key",
  response: {
    clientDataJSON: new Uint8Array([2]).buffer,
    authenticatorData: new Uint8Array([3]).buffer,
    signature: new Uint8Array([4]).buffer,
    attestationObject: new Uint8Array([5]).buffer,
    userHandle: null,
  },
});

const settle = async () => {
  for (let i = 0; i < 20; i += 1) await new Promise((resolve) => setImmediate(resolve));
};

const {
  addAccountPasskey,
  bindHomeUnlock,
  recoveryImportIncompleteMessage,
  profileReadinessActionTarget,
  showHomeUnlock,
} = await import("./shell-auth.js");

routes["/api/auth/passkey/status"] = () => ({ body: { registered: true, guest_registration_enabled: false } });
await showHomeUnlock(() => {});
bindHomeUnlock();
const faceStatus = element("#home-unlock-face-status");

async function signInOnLockFace() {
  assert.equal(element(".home-unlock-face").hidden, false, "the lock face is the sign-in surface");
  assert.equal(element(".home-unlock-card").hidden, true);
  element("#home-unlock-person").click();
  await settle();
  assert.equal(faceStatus.hidden, false, "the failure is visible on the lock face");
  assert.doesNotMatch(faceStatus.textContent.replace(/\b\d+ seconds\b/g, ""), /\d{3}|request failed|enrollment|credential|Error/i);
  return faceStatus.textContent;
}

const begin = () => ({ body: { ceremony_id: "c1", options: { publicKey: { challenge: "AA" } } } });

test("a passkey Home rejects shows one plain reason and one next step on the lock face", async () => {
  routes["/api/auth/passkey/authenticate/begin"] = begin;
  routes["/api/auth/passkey/authenticate/complete"] = () => ({ status: 403, body: "owner enrollment unavailable" });
  credentials = { get: async () => fakeCredential() };
  assert.equal(
    await signInOnLockFace(),
    "Home did not accept this passkey. Use the passkey you created for this Home.",
  );
  assert.equal(faceStatus.dataset.tone, "error");
});

test("a cancelled passkey prompt says so and how to retry", async () => {
  routes["/api/auth/passkey/authenticate/begin"] = begin;
  credentials = { get: async () => null };
  assert.equal(await signInOnLockFace(), "No passkey was used. Select your account to try again.");
  assert.equal(faceStatus.dataset.tone, "muted");
});

test("a busy or unreachable Home is named, not shown as a status code", async () => {
  routes["/api/auth/passkey/authenticate/begin"] = () => ({ status: 429, body: "Passkey sign-in is busy." });
  assert.equal(await signInOnLockFace(), "Sign-in is busy. Try again in 300 seconds.");
  delete routes["/api/auth/passkey/authenticate/begin"];
  assert.equal(
    await signInOnLockFace(),
    "Home is not responding. Check that ElastOS is running, then try again.",
  );
});

test("passkey sign-in shows the server wait rounded up to whole seconds", async () => {
  routes["/api/auth/passkey/authenticate/begin"] = () => ({status:429,retryAfter:"181",body:"Busy"});
  assert.equal(await signInOnLockFace(), "Sign-in is busy. Try again in 181 seconds.");
});

test("adding a passkey takes a fresh approval first and carries the System launch", async () => {
  requests.length = 0;
  const calls = [];
  routes["/api/auth/passkey-step-up/begin"] = () => ({
    body: {
      schema: "elastos.auth.passkey-step-up.begin.result/v1",
      ceremony_id: "step-up-1",
      options: { publicKey: { challenge: "AA" } },
    },
  });
  routes["/api/auth/passkey-step-up/complete"] = () => ({
    body: { schema: "elastos.auth.passkey-step-up.complete.result/v1", step_up_token: "fresh-approval" },
  });
  routes["/api/auth/passkey/add/begin"] = () => ({
    body: {
      schema: "elastos.auth.passkey.add.begin/v1",
      ceremony_id: "add-1",
      options: { publicKey: { challenge: "AA", user: { id: "AQ", name: "Anders · ElastOS Home (localhost:8090)", displayName: "Anders · ElastOS Home (localhost:8090)" } } },
    },
  });
  routes["/api/auth/passkey/add/complete"] = () => ({
    body: { schema: "elastos.auth.passkey.add.result/v1", proof_binding_id: "proof:passkey:new", role: "admin" },
  });
  credentials = {
    get: async () => { calls.push("approve"); return fakeCredential(); },
    create: async ({ publicKey }) => {
      assert.equal(publicKey.user.name, "Anders · ElastOS Home (localhost:8090)");
      assert.equal(publicKey.user.displayName, publicKey.user.name);
      assert.deepEqual(new Uint8Array(publicKey.user.id), new Uint8Array([1]));
      calls.push("create");
      const credential = fakeCredential();
      credential.authenticatorAttachment = "cross-platform";
      credential.response.getTransports = () => ["hybrid", "internal"];
      return credential;
    },
  };
  assert.deepEqual(await addAccountPasskey("system-launch"), { role: "admin" });
  assert.deepEqual(calls, ["approve", "create"]);
  const byUrl = Object.fromEntries(requests.map((request) => [request.url, request.body]));
  assert.equal(byUrl["/api/auth/passkey-step-up/begin"].operation, "auth.passkey.add");
  assert.equal(byUrl["/api/auth/passkey-step-up/begin"].app_token, "system-launch");
  assert.equal(byUrl["/api/auth/passkey/add/begin"].step_up_token, "fresh-approval");
  assert.equal(byUrl["/api/auth/passkey/add/begin"].app_token, "system-launch");
  assert.equal(byUrl["/api/auth/passkey/add/complete"].ceremony_id, "add-1");
  assert.equal(byUrl["/api/auth/passkey/add/complete"].response.authenticatorAttachment, "cross-platform");
  assert.deepEqual(byUrl["/api/auth/passkey/add/complete"].response.response.transports, ["hybrid", "internal"]);
  assert.equal(byUrl["/api/auth/passkey/add/complete"].app_token, "system-launch");
});

test("a refused or cancelled passkey add is one plain sentence", async () => {
  credentials = {
    get: async () => fakeCredential(),
    create: async () => null,
  };
  await assert.rejects(addAccountPasskey("system-launch"), {
    message: "No new passkey was created. Select Add passkey to try again.",
  });
  routes["/api/auth/passkey/add/begin"] = () => ({ status: 403, body: "passkey step-up token has already been used" });
  await assert.rejects(addAccountPasskey("system-launch"), {
    message: "Home did not add the passkey. Select Add passkey to try again.",
  });
});

test("recovery says it worked when only the Home's recovery record is missing", () => {
  const imported = (wallet, people, audit) => ({
    schema: "elastos.full-recovery-bundle.import.response/v2",
    wallet_restore: { status: wallet },
    people_identity_restore: { status: people },
    runtime_audit: { status: audit },
  });
  assert.equal(recoveryImportIncompleteMessage(imported("complete", "restored", "complete")), "");
  const auditOnly = recoveryImportIncompleteMessage(imported("complete", "restored", "incomplete"));
  assert.match(auditOnly, /^Your account, Profile and Wallet were recovered\./);
  assert.doesNotMatch(auditOnly, /could not finish|failed|needs completion/i);
  assert.match(auditOnly, /Choose the same kit again to finish it\.$/);
  for (const response of [
    imported("incomplete", "restored", "complete"),
    imported("complete", "incomplete", "incomplete"),
  ]) {
    assert.equal(recoveryImportIncompleteMessage(response),
      "The root was recovered. Profile or Wallet recovery still needs completion. Choose the same kit again to retry safely.");
  }
  assert.match(recoveryImportIncompleteMessage(imported("complete", "absent", "complete")),
    /has no signed Profile or name/);
});


test("first-account and guest creation preserve Runtime's passkey label and user id", async () => {
  for (const guest of [false, true]) {
    routes["/api/auth/passkey/status"] = () => ({ body: { registered: guest, guest_registration_enabled: guest } });
    const storage = new Map();
    window.sessionStorage = {
      getItem: (key) => storage.get(key) || null,
      setItem: (key, value) => storage.set(key, value),
      removeItem: (key) => storage.delete(key),
    };
    await showHomeUnlock(() => {});
    if (guest) element("#home-unlock-create").click();
    element("#home-unlock-name").value = "Anders";
    const label = "Anders · ElastOS Home (localhost:61180)";
    routes["/api/auth/passkey/register/begin"] = () => ({ body: {
      schema: "elastos.auth.passkey.register.begin/v1", ceremony_id: "named-create",
      options: { publicKey: { challenge: "AA", user: { id: "AQ", name: label, displayName: label } } },
    } });
    let created;
    credentials = { create: async ({ publicKey }) => { created = publicKey.user; return null; } };
    element("#home-unlock-primary").click();
    await settle();
    assert.equal(created?.name, label, `guest=${guest}`);
    assert.equal(created.displayName, label);
    assert.deepEqual(new Uint8Array(created.id), new Uint8Array([1]));
  }
});

test("owner recovery preserves Runtime's passkey label and user id", async () => {
  routes["/api/auth/passkey/status"] = () => ({ body: { registered: true, guest_registration_enabled: false } });
  window.sessionStorage = { getItem: () => null, setItem() {}, removeItem() {} };
  await showHomeUnlock(() => {});
  element("#home-recover-owner").click();
  element("#home-owner-recovery-code").value = "fixture-code";
  const kit = JSON.stringify({ schema: "elastos.full-recovery-bundle/v1", people_identity: { profile_authority_bundle: {} } });
  element("#home-recovery-file").files = [{ size: kit.length, text: async () => kit }];
  await element("#home-recovery-file").listeners.get("change")();
  const label = "Account recovery · ElastOS Home (localhost:61180)";
  routes["/api/auth/owner-recovery/begin"] = () => ({ body: {
    schema: "elastos.auth.passkey.register.begin/v1", ceremony_id: "named-recovery",
    options: { publicKey: { challenge: "AA", user: { id: "AQ", name: label, displayName: label } } },
  } });
  let created;
  credentials = { create: async ({ publicKey }) => { created = publicKey.user; return null; } };
  element("#home-unlock-primary").click();
  await settle();
  assert.equal(created?.name, label);
  assert.equal(created.displayName, label);
  assert.deepEqual(new Uint8Array(created.id), new Uint8Array([1]));
});
test("wallet sign-in opens the account when the contract result has no enrollment metadata", () => {
  const response = {app_token:"home", session_id:"session", principal_id:"principal:alex", proof_binding_id:"wallet:one"};
  assert.equal(profileReadinessActionTarget(response, {walletSignin:true}), "");
  assert.equal(profileReadinessActionTarget({}), "system", "passkey enrollment keeps its Profile check");
  assert.equal(profileReadinessActionTarget({...response, profile_readiness:{schema:"elastos.profile.readiness/v1",status:"setup_required"}}, {walletSignin:true}), "system", "explicit Runtime readiness still owns setup");
  assert.equal(profileReadinessActionTarget({...response, profile_readiness:{schema:"elastos.profile.readiness/v1",status:"ready"}}, {walletSignin:true}), "");
});

test("Home has one Sign in entry and offers choices in its sign-in sheet", async () => {
  const {readFile} = await import("node:fs/promises");
  const markup = await readFile(new URL("./index.html", import.meta.url), "utf8");
  assert.doesNotMatch(markup, /Other options|data-home-signin-options/);
  routes["/api/auth/passkey/status"] = () => ({body:{registered:true,wallet_signin_available:true,wallet_signin_connectors:["wallet-metamask"]}});
  await showHomeUnlock(() => {});
  assert.equal(element("#home-unlock-person").disabled, false);
  routes["/api/auth/passkey/status"] = () => ({body:{registered:true}});
});

test("opening Home keeps wallet identities out of browser storage", async () => {
 const values=new Map();
 globalThis.localStorage={getItem:k=>values.get(k),setItem:(k,v)=>values.set(k,v),removeItem:k=>values.delete(k)};
 try {
  routes['/api/auth/passkey/status']=()=>({body:{registered:true}});
  await showHomeUnlock(()=>{});assert.deepEqual([...values.keys()],[]);
 } finally {delete globalThis.localStorage;}
});
