import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import vm from "node:vm";

const source = readFileSync(new URL("../capsules/system/browser/system.js", import.meta.url), "utf8");
const controller = source.slice(
  source.indexOf("const RECOVERY_ROOT_CHECKED_SENTENCE"),
  source.indexOf("async function onRecoveryDownload("),
);

function render(status) {
  const shown = {};
  const context = vm.createContext({
    recoveryProfileStatus: "ready",
    recoveryProfileRequired: false,
    readText: value => typeof value === "string" ? value.trim() : "",
    showRecoveryStatus: (text, tone) => { shown.status = text; shown.statusTone = tone; },
    showRecoveryNote: (text, tone) => { shown.note = text; shown.noteTone = tone; },
    setRecoveryButton: (label, disabled) => { shown.button = label; shown.disabled = disabled; },
  });
  vm.runInContext(`${controller}\nsetRecoveryStatus(${JSON.stringify(status)});`, context);
  return shown;
}

const ready = { recovery_configured: true, recovery_download_available: true, protection_configured: true, required_actions: [] };
const checked = "No unencrypted file was found in your protected Home folders, and each file there is labelled for this Home's current key. Each file's contents are checked when you open it.";

test("an encrypted root states what start checked, and nothing more", () => {
  const shown = render({ ...ready, root_encrypted: true });
  assert.equal(shown.status, "");
  assert.ok(shown.note.startsWith(`${checked} Saves your Profile`), shown.note);
  assert.doesNotMatch(shown.note, /verified|authenticated|intact/);
  assert.equal(shown.button, "Download Recovery Kit");
  assert.ok(!render({ ...ready, root_encrypted: false }).note.includes(checked));
});

test("damaged files are named once with their action", () => {
  const action = "Documents/a.bin does not carry the label this Home writes on encrypted files.";
  const shown = render({
    ...ready,
    root_encrypted: true,
    objects_needing_attention: [{ path: "Documents/a.bin", problem: "label_unreadable", action }],
    objects_needing_attention_count: 3,
  });
  assert.equal(shown.status, "Needs attention");
  assert.equal(shown.note, `3 file(s) in your protected Home folders need attention: ${action} And 2 more.`);
  assert.equal(shown.button, "Download Recovery Kit");
  const one = render({
    ...ready,
    objects_needing_attention: [{ path: "Documents/a.bin", problem: "label_unreadable", action }],
    objects_needing_attention_count: 1,
  });
  assert.equal(one.note, `1 file(s) in your protected Home folders need attention: ${action}`);
});

test("a pending encryption step is explained", () => {
  const shown = render({ ...ready, root_encrypted: false, required_actions: ["finish_interrupted_principal_root_migration"] });
  assert.equal(shown.status, "Needs attention");
  assert.equal(shown.note, 'An earlier encryption step did not finish. Home will not start again until it is finished or undone. Reinstalling ElastOS does that and keeps your files. If the installer stops with "recovered an incomplete principal-root migration", run it once more.');
});

test("plaintext that arrived while Home runs is explained", () => {
  const encrypts = "Save your Recovery Kit and confirm with your passkey to encrypt them. One save takes at most 64 files and 64 MiB in total, each file up to 16 MiB. If more are waiting, move some out of your protected Home folders, save, then move them back and save again. Move a file over 16 MiB out and upload it again in Library (up to 100 MiB).";
  const shown = render({ ...ready, root_encrypted: false, required_actions: ["migrate_declared_plaintext_objects"] });
  assert.equal(shown.status, "Needs attention");
  assert.equal(shown.note, `Some files in your protected Home folders are not encrypted yet; until they are, Home will not start again. ${encrypts}`);
  assert.equal(shown.button, "Download Recovery Kit");
  // An unprotected root reports the same action; the start sentence is for protected roots only.
  const unprotected = render({ required_actions: ["migrate_declared_plaintext_objects"], protection_configured: false });
  assert.equal(unprotected.note, `Some files in your protected Home folders are not encrypted yet. ${encrypts}`);
});

test("a Home whose Profile needs backup still sees files needing attention", () => {
  const action = "Documents/a.bin does not carry the label this Home writes on encrypted files.";
  const shown = render({
    ...ready,
    required_actions: ["download_recovery_kit_with_profile"],
    objects_needing_attention: [{ path: "Documents/a.bin", problem: "label_unreadable", action }],
    objects_needing_attention_count: 1,
  });
  assert.equal(shown.status, "Profile needs backup");
  assert.equal(shown.note, `Save a new kit that includes your Profile. 1 file(s) in your protected Home folders need attention: ${action}`);
  assert.equal(shown.button, "Save complete Recovery Kit");
  assert.equal(render({ ...ready, required_actions: ["download_recovery_kit_with_profile"] }).note, "Save a new kit that includes your Profile.");
});
