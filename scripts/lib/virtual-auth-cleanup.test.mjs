import assert from "node:assert/strict";
import test from "node:test";
import { cleanupVirtualPasskey, shouldRetainVirtualAuthProfile, VIRTUAL_AUTH_PROFILE_CLEANUP_INSTRUCTION } from "./virtual-auth-cleanup.mjs";

test("first-owner cleanup keeps the passkey and its profile without calling removal", async () => {
  const created = { created: true, mode: "admin" };
  const cleanup = await cleanupVirtualPasskey(created, () => assert.fail("first owner reached removal"));
  assert.equal(cleanup.ok, true);
  assert.equal(cleanup.skipped, true);
  assert.equal(cleanup.retained, true);
  assert.match(cleanup.reason, /First owner passkey kept/);
  assert.equal(shouldRetainVirtualAuthProfile({ created, cleanup, credentialCount: 1 }), true);
  assert.match(VIRTUAL_AUTH_PROFILE_CLEANUP_INSTRUCTION, /add another admin passkey first/);
  assert.match(VIRTUAL_AUTH_PROFILE_CLEANUP_INSTRUCTION, /isolated test Home and its profile together/);
});

test("guest cleanup still removes its passkey and permits profile cleanup", async () => {
  let removals = 0;
  const created = { created: true, mode: "guest" };
  const cleanup = await cleanupVirtualPasskey(created, async () => { removals++; return { ok: true }; });
  assert.equal(removals, 1);
  assert.equal(shouldRetainVirtualAuthProfile({ created, cleanup, credentialCount: 1 }), false);
});

test("disabled or failed cleanup and uncertain credential persistence retain the profile", () => {
  for (const state of [
    { created: { created: true, mode: "admin" }, cleanup: { skipped: true } },
    { created: { created: true, mode: "guest" }, cleanup: { ok: false } },
    { created: { created: false }, credentialCount: 1 },
    { created: null, credentialSaveError: "fixture write failed" },
  ]) assert.equal(shouldRetainVirtualAuthProfile(state), true);
  assert.equal(shouldRetainVirtualAuthProfile({ created: null, credentialCount: 0 }), false);
});
