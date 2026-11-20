import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import vm from "node:vm";

const source = readFileSync(new URL("../capsules/system/browser/system.js", import.meta.url), "utf8");

function functionSource(name) {
  const start = source.search(new RegExp(`(?:async )?function ${name}\\(`));
  assert.ok(start >= 0, name);
  const end = source.indexOf("\n}", start);
  assert.ok(end > start, name);
  const body = source.slice(start, end + 2);
  assert.ok(body.includes(`function ${name}`), name);
  assert.equal(body.at(-1), "}");
  return body;
}

function arraySource(name) {
  const start = source.indexOf(`const ${name} = [`);
  if (start < 0) return "";
  const end = source.indexOf("\n];", start);
  assert.ok(end > start, name);
  return source.slice(start, end + 3);
}

function presentFunction(name) {
  return source.includes(`function ${name}(`) ? functionSource(name) : "";
}

const handlerSource = [
  arraySource("RECOVERY_KIT_SAVE_REFUSALS"),
  ...[
    "hasShellAccess",
    "fetchJson",
    "readText",
    "hasExactKeys",
    "shellHeaders",
    "publicSystemError",
    "recoveryKitSaveRefusal",
    "showRecoveryStatus",
    "showRecoveryNote",
    "setRecoveryButton",
    "clearRecoveryPending",
    "recoveryDownloadPassword",
    "exportFullRecoveryBundle",
    "requestPasskeyStepUp",
    "requestHomePasskeyStepUp",
    "configureRecoveryAccess",
    "onRecoveryDownload",
  ].map(presentFunction),
].join("\n");

const SIZE = "Home could not prepare your Recovery Kit: Documents/big.bin is not encrypted and is 17 MiB. Home encrypts existing files of up to 16 MiB in place. Move it out of /tmp/elastos-home/Documents and try again; once Home is running, upload it again in Library, which encrypts files of up to 100 MiB. After that, select Download Recovery Kit again; you will confirm with your passkey again.";
const COUNT = "Home could not prepare your Recovery Kit: 65 files in protected Home folders are not encrypted (first: Documents/00.txt); Home encrypts up to 64 in one run. Move some of them out of their folders and try again; then move them back and try again. After that, select Download Recovery Kit again; you will confirm with your passkey again.";
const TOTAL = "Home could not prepare your Recovery Kit: Unencrypted files in protected Home folders add up to more than 64 MiB (reached at Documents/part-4.bin); Home encrypts up to 64 MiB in one run. Move some of them out of their folders and try again; then move them back and try again. After that, select Download Recovery Kit again; you will confirm with your passkey again.";
const OTHER = "Home could not prepare your Recovery Kit: Documents/a.bin does not carry the label this Home writes on encrypted files. After that, select Download Recovery Kit again; you will confirm with your passkey again.";

function field() {
  return {
    hidden: true,
    textContent: "",
    value: "",
    readOnly: false,
    disabled: false,
    dataset: {},
    classList: { toggle() {} },
    focus() {},
    addEventListener() {},
  };
}

async function save(body) {
  const statusNode = field();
  const noteNode = field();
  const button = field();
  button.textContent = "Download Recovery Kit";
  button.hidden = false;
  const handlers = {};
  button.addEventListener = (type, fn) => { handlers[type] = fn; };
  const listeners = new Set();
  const top = {};
  const window = {
    top,
    crypto: { randomUUID: () => "11111111-1111-4111-8111-111111111111" },
    addEventListener(_type, fn) { listeners.add(fn); },
    removeEventListener(_type, fn) { listeners.delete(fn); },
    setTimeout() { return 1; },
    clearTimeout() {},
  };
  top.postMessage = (data) => {
    const event = {
      source: top,
      origin: "https://home.example",
      data: {
        type: "elastos.home.passkey-step-up.result/v1",
        requestId: data.requestId,
        stepUpToken: "fixture-step-up",
      },
    };
    for (const fn of listeners) fn(event);
  };
  const context = vm.createContext({
    apiHomeToken: "home-token",
    homeParentOrigin: "https://home.example",
    recoveryProfileStatus: "ready",
    recoveryProfileRequired: false,
    recoveryExportBusy: false,
    pendingRecoveryImport: null,
    recoveryDownloadButton: button,
    recoveryProfileName: field(),
    recoveryPasswordInput: { value: "" },
    recoveryStatusNode: statusNode,
    recoveryNoteNode: noteNode,
    recoveryPendingNode: field(),
    recoveryPendingTextNode: field(),
    recoveryAttachButton: field(),
    recoveryImportInput: field(),
    recoveryCancelButton: field(),
    onRecoveryImport() {},
    onRecoveryAttach() {},
    window,
    fetch: async (url) => {
      if (url === "/api/auth/recovery/status") {
        const text = JSON.stringify({
          principal_id: "person:fixture",
          localhost_root: "localhost://fixture",
        });
        return { ok: true, status: 200, statusText: "OK", text: async () => text, json: async () => JSON.parse(text) };
      }
      assert.equal(url, "/api/auth/recovery/full-export");
      return { ok: false, status: 409, statusText: "Conflict", text: async () => body, json: async () => { throw new Error("not json"); } };
    },
  });
  vm.runInContext(`${handlerSource}\nconfigureRecoveryAccess();`, context);
  assert.equal(typeof handlers.click, "function");
  await handlers.click();
  return {
    status: statusNode.textContent,
    statusHidden: statusNode.hidden,
    note: noteNode.textContent,
    noteHidden: noteNode.hidden,
    button: button.textContent,
  };
}

for (const [name, body] of [
  ["one file over the size limit", SIZE],
  ["too many files", COUNT],
  ["total too large", TOTAL],
]) {
  test(`Recovery Kit save shows the server refusal for ${name}`, async () => {
    const shown = await save(body);
    assert.equal(shown.status, "Not set");
    assert.equal(shown.statusHidden, false);
    assert.equal(shown.noteHidden, false);
    assert.equal(shown.note, body);
    assert.equal(shown.button, "Download Recovery Kit");
  });
}

test("another Recovery Kit refusal keeps the generic recovery note", async () => {
  const shown = await save(OTHER);
  assert.equal(shown.status, "Not set");
  assert.equal(shown.note, "Recovery action could not be completed.");
  assert.equal(shown.button, "Download Recovery Kit");
});
