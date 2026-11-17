import test from "node:test";
import assert from "node:assert/strict";
import { runtimeView, permissionEntry, packets } from "./lib/wallet-runtime-browser.mjs";

test("n5_permission_entry_all_states: Inbox existing routes", async t => {
  for (const status of ["requested", "granted", "refused", "revoked", "expired", "cleanup"]) await t.test(status, async t => {
    const r = await runtimeView(t, "inbox", { entries: [permissionEntry(status)], permission: status });
    const labels = await r.frame.locator("#entry-detail button").allTextContents();
    assert.deepEqual(labels, status === "requested" ? ["Don't Allow", "Allow"] : status === "granted" ? ["Turn Off"] : status === "cleanup" ? ["Finish disconnecting"] : ["Allow"]);
    await r.capture(`inbox-internet-${({requested:"asked",granted:"allowed",revoked:"off",cleanup:"clearing"})[status] || status}-light-window.png`);
    assert.deepEqual(r.errors, []);
  });
});

test("n5_allow_after_refusal_off_expiry: current question and proof", async t => {
  for (const permission of ["refused", "revoked", "expired"]) await t.test(permission, async t => {
    const r = await runtimeView(t, "inbox", { permission, entries: [permissionEntry(permission)] });
    await r.frame.getByRole("button", { name: "Allow", exact: true }).click();
    await r.frame.getByRole("button", { name: "Turn Off", exact: true }).waitFor();
    assert.deepEqual(r.calls.filter(c => c.path.endsWith("/internet") && c.method === "POST").map(c => c.input), [{ action: "request" }]);
    assert.deepEqual(r.calls.find(c => c.path.endsWith("/actions")).input, { action_id: "walletconnect-internet-allow:consent:current", step_up_token: "fixture-proof" });
    assert.equal(r.state.permission, "granted");
    assert.deepEqual(r.errors, []);
  });
});

test("n5_inbox_action_by_kind_and_409: decision and conflict", async t => {
  await t.test("decision never offers Don't Allow", async t => {
    const entry = { ...permissionEntry("requested"), kind: "walletconnect_internet_decision" };
    const r = await runtimeView(t, "inbox", { entries: [entry], permission: "requested" });
    assert.equal(await r.frame.getByRole("button", { name: "Don't Allow", exact: true }).count(), 0);
  });
  await t.test("409 refreshes once and retains fixed wording", async t => {
    const r = await runtimeView(t, "inbox", { entries: [permissionEntry("requested")], permission: "requested", conflict: true });
    await r.frame.getByRole("button", { name: "Allow", exact: true }).click();
    await r.frame.locator("#status-text").filter({ hasText: "This request has changed. Refresh Inbox and review the current request." }).waitFor({ timeout: 3000 });
    assert.equal(r.calls.filter(c => c.path.endsWith("/actions")).length, 1);
    assert.equal(r.calls.filter(c => c.path.endsWith("/summary")).length, 2);
    assert.equal(r.state.permission, "requested");
  });
});

test("n3_reject_dismiss_acknowledgement: Wallet cards", async t => {
  for (const dismissed of [false, true]) await t.test(dismissed ? "Dismiss" : "Reject", async t => {
    const request = { ...packets.n7PrivateSummaries.find(f => f.id === "site-wallet").summary,
      status: dismissed ? "approved" : "pending", intent: dismissed ? "transaction_intent" : "browser_personal_sign",
      connector_id: dismissed ? "wallet-walletconnect" : "wallet-metamask", expires_at: Math.floor(Date.now() / 1000) + 600 };
    const r = await runtimeView(t, "wallet", { approvals: [request] });
    await r.frame.getByRole("button", { name: dismissed ? "Dismiss" : "Reject", exact: true }).click();
    const card = r.frame.locator(`[data-wallet-request-id="${request.request_id}"]`);
    await card.locator("[role=status]").waitFor({ timeout: 3000 });
    assert.match(await card.textContent(), dismissed ? /Request dismissed/ : /Request rejected/);
    assert.equal(await card.locator("button,.wallet-request-time").count(), 0);
    assert.equal(await card.getByText(request.reason, { exact: true }).count(), 1);
    await r.capture(`wallet-request-${dismissed ? "dismissed" : "rejected"}-light-window.png`);
    assert.deepEqual(r.errors, []);
  });
});
