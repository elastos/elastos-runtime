import test from "node:test";
import assert from "node:assert/strict";
import { runtimeView, permissionEntry, packets } from "./lib/wallet-runtime-browser.mjs";

const requestFixture = () => ({ ...packets.n7PrivateSummaries.find(f => f.id === "site-wallet").summary, created_at:Math.floor(Date.now()/1000),
  requesting_app_name:"Browser", chain_namespace: "eip155:20", expires_at: Math.floor(Date.now() / 1000) + 600 });

test("n5_permission_entry_all_states: Inbox existing routes", async t => {
  for (const status of ["requested", "granted", "refused", "revoked", "expired", "cleanup"]) await t.test(status, async t => {
    const r = await runtimeView(t, "inbox", { entries: [permissionEntry(status)], permission: status });
    const labels = await r.frame.locator("#entry-detail button").allTextContents();
    assert.deepEqual(labels, status === "requested" ? ["Don't allow", "Allow"] : status === "granted" ? ["Turn off internet access"] : status === "cleanup" ? ["Finish disconnecting"] : ["Allow"]);
    await r.capture(`inbox-internet-${({requested:"asked",granted:"allowed",revoked:"off",cleanup:"clearing"})[status] || status}-light-window.png`);
    assert.deepEqual(r.errors, []);
  });
});

test("n5_allow_after_refusal_off_expiry: current question and proof", async t => {
  for (const permission of ["refused", "revoked", "expired"]) await t.test(permission, async t => {
    const r = await runtimeView(t, "inbox", { permission, entries: [permissionEntry(permission)] });
    await r.frame.getByRole("button", { name: "Allow", exact: true }).click();
    await r.frame.getByRole("button", { name: "Turn off internet access", exact: true }).waitFor();
    assert.deepEqual(r.calls.filter(c => c.path.endsWith("/internet") && c.method === "POST").map(c => c.input), [{ action: "request" }]);
    assert.deepEqual(r.calls.find(c => c.path.endsWith("/actions")).input, { action_id: "walletconnect-internet-allow:consent:new", step_up_token: "fixture-proof" });
    assert.equal(r.state.permission, "granted");
    assert.deepEqual(r.errors, []);
  });
});

test("n5_inbox_action_by_kind_and_409: decision and conflict", async t => {
  await t.test("decision never offers Don't Allow", async t => {
    const entry = { ...permissionEntry("requested"), kind: "walletconnect_internet_decision" };
    const r = await runtimeView(t, "inbox", { entries: [entry], permission: "requested" });
    assert.equal(await r.frame.getByRole("button", { name: "Don't allow", exact: true }).count(), 0);
  });
  await t.test("409 refreshes once and retains fixed wording", async t => {
    const r = await runtimeView(t, "inbox", { entries: [permissionEntry("requested")], permission: "requested", conflict: true });
    await r.frame.getByRole("button", { name: "Allow", exact: true }).click();
    await r.frame.locator("#status-text").filter({ hasText: "Refresh Inbox and review the current request before trying again." }).waitFor({ timeout: 3000 });
    assert.equal(r.calls.filter(c => c.path.endsWith("/actions")).length, 1);
    assert.equal(r.calls.filter(c => c.path.endsWith("/summary")).length, 2);
    assert.equal(r.state.permission, "requested");
    await r.capture("inbox-internet-conflict-light-window.png");
  });
  await t.test("409 keeps fixed wording when its one refresh fails", async t => {
    const r = await runtimeView(t, "inbox", { entries:[permissionEntry("requested")], permission:"requested",
      conflict:true, summaryFailureAfterConflict:true });
    await r.frame.getByRole("button", { name:"Allow", exact:true }).click();
    await r.frame.locator("#refresh:enabled").waitFor();
    assert.equal(await r.frame.locator("#status-text").textContent(), "Refresh Inbox and review the current request before trying again.");
    assert.equal(r.calls.filter(c => c.path.endsWith("/actions")).length, 1);
    assert.equal(r.calls.filter(c => c.path.endsWith("/summary")).length, 2, "the failed refresh is attempted only once");
    assert.equal(r.state.permission, "requested");
    await r.capture("inbox-internet-conflict-refresh-failed-light-window.png");
    assert.deepEqual(r.errors, []);
  });
});

test("n3_reject_dismiss_acknowledgement: Wallet cards", async t => {
  for (const dismissed of [false, true]) for (const failedRefresh of [false, "transport", "unavailable"]) await t.test(`${dismissed ? "Dismiss" : "Reject"}${failedRefresh ? ` / ${failedRefresh}` : ""}`, async t => {
    const request = { ...requestFixture(),
      status: dismissed ? "approved" : "pending", intent: dismissed ? "transaction_intent" : "browser_personal_sign",
      approved_at: dismissed ? Math.floor(Date.now() / 1000) - 30 : null,
      connector_id: dismissed ? "wallet-walletconnect" : "wallet-metamask", expires_at: Math.floor(Date.now() / 1000) + 600 };
    const r = await runtimeView(t, "wallet", { approvals: [request], summaryFailureAfterDecision:failedRefresh });
    await r.frame.getByRole("button", { name: dismissed ? "Dismiss" : "Reject", exact: true }).click();
    const card = r.frame.locator(`[data-wallet-request-id="${request.request_id}"]`);
    await card.locator("[role=status]").waitFor({ timeout: 3000 });
    assert.match(await card.textContent(), dismissed ? /Request dismissed/ : /Request rejected/);
    assert.equal(await card.locator("button,.wallet-request-time").count(), 0);
    assert.equal(await card.getByText(request.reason, { exact: true }).count(), 1);
    const box = await card.boundingBox();
    assert(box.y >= 0 && box.y + box.height <= 682, "the whole answered card, including identity and outcome, remains in view");
    if (failedRefresh) await r.frame.locator("#wallet-status").filter({ hasText:"Wallet could not refresh other requests." }).waitFor();
    assert.equal(await r.frame.locator("#wallet-approvals-badge").isVisible(), false, "a known decision clears the badge even when the next read fails");
    const outcome = dismissed ? "dismissed" : "rejected";
    await r.capture(`wallet-request-${outcome}${failedRefresh ? `-${failedRefresh}` : ""}-light-window.png`);
    await r.frame.getByRole("button", { name:"Activity", exact:true }).click();
    await r.frame.locator("#wallet-activity-drawer .wallet-activity-row strong").filter({ hasText: dismissed ? "Dismissed transaction request" : "Rejected" }).waitFor();
    if (failedRefresh) await r.capture(`wallet-activity-${outcome}-${failedRefresh}-light-window.png`);
    assert.deepEqual(r.errors, []);
  });
});

test("n3_wallet_badge_counts_review_requests: real GUI module", async t => {
  const r = await runtimeView(t, "wallet");
  const count = await r.page.evaluate(async () => {
    document.body.innerHTML = '<button id="toolbar-wallet"></button><aside id="wallet-rail" hidden><iframe id="wallet-rail-frame"></iframe></aside>';
    const rail = await import("/apps/home-gui/shell-wallet-rail.js");
    rail.bindWalletRail();
    const entry = (action, kind = "wallet_approval_request") => ({ kind, action_ref: { action_id: action } });
    rail.syncWalletRailAvailability({ targets: [{ target: "wallet", title: "Wallet" }], notifications: { entries: [
      entry("wallet-approve-request:a"), entry("wallet-approve-request:a"), entry("wallet-review-request:a"),
      entry("wallet-review-request:b"), entry("wallet-review-request:account-access"),
      entry("wallet-review-request:"), entry("wallet-review-request:other", "contact_request"), entry("unrelated:c"),
    ] } });
    const value = document.querySelector(".toolbar-wallet-count")?.textContent;
    rail.retireWalletRail();
    return value;
  });
  assert.equal(count, "3");
  assert.deepEqual(r.errors, []);
});

test("n7_browser_site_projection_all_surfaces: Inbox and Wallet consumers", async t => {
  for (const app of ["inbox", "wallet"]) await t.test(app, async t => {
    for (const intent of ["browser_personal_sign", "browser_typed_data_sign", "transaction_intent"]) {
    const title = intent === "transaction_intent" ? "Send transaction" : intent === "browser_typed_data_sign" ? "Sign typed data" : "Sign a message";
    const request = { ...requestFixture(), intent, reason:title };
    const entry = { id: `wallet-approval-request:${request.request_id}`, source_app: request.capsule_id,
      kind: "wallet_approval_request", title, body: `${request.capsule_id} requests wallet approval for ${request.reason}.`, severity: "attention", read: true,
      requesting_origin: request.requesting_origin, action_ref: { action_id: `wallet-review-request:${request.request_id}` } };
    const r = await runtimeView(t, app, { approvals: [request], entries: [entry] });
    await r.frame.getByText("Site reported by Browser", { exact: true }).waitFor();
    const origin = r.frame.getByText(request.requesting_origin, { exact: true });
    assert.equal(await origin.count(), 1);
    assert.equal(await origin.evaluate(el => el.tagName), "SPAN");
    assert.equal(await origin.evaluate(el => el.dir), "auto");
    assert.equal(await origin.evaluate(el => getComputedStyle(el).unicodeBidi), "isolate");
    const state = intent === "transaction_intent" ? "transaction" : intent === "browser_typed_data_sign" ? "typed-data" : "request";
    await r.capture(`${app}-${state}-external-light-window.png`);
    const canonical = "https://shop_sub.example:8443";
    r.state.approvals[0].requesting_origin = canonical;
    r.state.entries[0].requesting_origin = canonical;
    await r.page.reload();
    await r.frame.getByText(canonical, { exact:true }).waitFor();
    assert.deepEqual(r.errors, []);
    }
  });
});

test("n7_site_absent_or_forged_origin: shared invalid summaries", async t => {
  const r = await runtimeView(t, "wallet");
  const outcomes = await r.frame.locator("body").evaluate(async (_, fixtures) => {
    const { createWalletRequests } = await import("./wallet-requests.js");
    const root = document.createElement("section"); document.body.append(root);
    const view = createWalletRequests({ requestsNode: root });
    return fixtures.filter(f => f.audience === "wallet").map(f => {
      view.renderRequests([f.summary]);
      return { id: f.id, actual: root.querySelectorAll(".wallet-request-origin").length, expected: f.expect === "show_site" ? 1 : 0,
        text: root.querySelector(".wallet-request-origin")?.textContent };
    });
  }, packets.n7PrivateSummaries);
  for (const result of outcomes) assert.equal(result.actual, result.expected, result.id);
  assert.equal(outcomes.find(r => r.id === "literal-idn").text, "https://xn--bcher-kva.example");
});

test("n7_account_access_uses_same_projection: one site and no review fallback", async t => {
  const request = { ...requestFixture(), intent: "browser_account_access", proof_type: "managed_evm", connector_id: null,
    reason: "Browser origin https://old.example requests access", review: { kind: "account_access", origin: "https://old.example",
      page_url: "https://old.example/private", permission: "eth_accounts", account_id: "account:fixture-1" } };
  const r = await runtimeView(t, "wallet", { approvals: [request] });
  const card = r.frame.locator(".wallet-request");
  await card.waitFor();
  assert.equal(await card.getByText("https://shop.example", { exact: true }).count(), 1);
  assert(!await card.textContent().then(text => text.includes("old.example")));
  await r.capture("wallet-account-access-light-window.png");
  await r.frame.locator("body").evaluate(async (_, request) => {
    const { createWalletRequests } = await import("./wallet-requests.js");
    const root = document.querySelector("#wallet-hero-pending");
    createWalletRequests({ requestsNode: root }).renderRequests([{ ...request, requesting_origin: undefined }]);
  }, request);
  assert.equal(await card.locator(".wallet-request-origin").count(), 0);
  await r.capture("wallet-account-access-no-site-light-window.png");
});

test("n4_metadata_bounds_and_text_rendering: real Wallet", async t => {
  const name = "Alice <svg/onload=alert(1)>";
  const account = { account_id: "account:fixture-1", chain_namespace: "eip155:20", address: requestFixture().address,
    connector_id: "wallet-walletconnect", proof_type: "siwe", wallet_display_name: name, wallet_mark: "wallet" };
  const r = await runtimeView(t, "wallet", { accounts: [account] });
  const label = r.frame.locator(".wallet-account .wallet-card-name");
  await label.filter({ hasText: name }).waitFor();
  assert.equal(await label.textContent(), name);
  assert((await r.frame.locator("#wallet-account-card").getAttribute("aria-label")).includes(name));
  assert((await r.frame.locator(".wallet-account [data-wallet-account-menu]").getAttribute("aria-label")).includes(name));
  assert.equal(await label.evaluate(el => el.dir), "auto");
  assert.equal(await label.evaluate(el => getComputedStyle(el).unicodeBidi), "isolate");
  const mark = r.frame.locator(".wallet-account .wallet-method-mark img");
  assert.match(await mark.getAttribute("src"), /icons\/icon-64.png$/);
  assert.equal(await mark.getAttribute("alt"), "");
  assert.equal(await r.frame.locator(".wallet-account svg[onload]").count(), 0);
  const linked = r.frame.locator(".wallet-method-account");
  assert.equal(await linked.locator("strong").textContent(), name);
  assert.equal(await linked.locator("strong").evaluate(el => el.dir), "auto");
  assert.match(await linked.locator("img").getAttribute("src"), /icons\/icon-64.png$/);
  await linked.getByRole("button", { name:"Remove", exact:true }).click();
  const confirmation = r.frame.getByRole("heading", { name:`Remove ${name}?`, exact:true });
  await confirmation.waitFor();
  assert.match(await r.frame.locator("#wallet-modal .wallet-modal-body").textContent(), /fed1/);
  assert.match(await r.frame.locator(".wallet-modal-header").textContent(), /Your wallet and funds stay unchanged/);
  assert.doesNotMatch(await r.frame.locator(".wallet-modal-header").textContent(), /recovery key/);
  assert.equal(await confirmation.textContent(), `Remove ${name}?`, "the confirmation names the same isolated display identity as its row");
  assert.equal(await confirmation.locator("bdi").textContent(), name);
  assert.equal(await confirmation.locator("bdi").evaluate(el=>el.dir), "auto");
  assert.equal(await confirmation.locator("bdi").evaluate(el=>getComputedStyle(el).unicodeBidi), "isolate");
  assert.equal(await r.frame.locator(".wallet-modal-header svg[onload]").count(), 0);
  await r.capture("wallet-account-remove-confirm-light-window.png");
  await r.frame.locator("#wallet-modal").getByRole("button", { name:"Cancel", exact:true }).click();
  await confirmation.waitFor({ state:"hidden" });
  await r.capture("wallet-linked-light-window.png");
  assert.deepEqual(r.errors, []);
  const builtin = await runtimeView(t, "wallet", { accounts:[{ ...account, account_id:"account:managed-fixture", proof_type:"managed_evm",
    connector_id:null, wallet_display_name:null, wallet_mark:null }] });
  await builtin.frame.locator(".wallet-method-account").getByRole("button", { name:"Remove", exact:true }).click();
  assert.match(await builtin.frame.locator(".wallet-modal-header").textContent(), /Built-in accounts require their Wallet recovery key/);
  assert.deepEqual(builtin.errors, []);
});

test("n4_old_record_and_reopened_window: legacy Wallet fallback", async t => {
  const account = { account_id: "account:fixture-1", chain_namespace: "eip155:20", address: requestFixture().address,
    connector_id: "wallet-metamask", proof_type: "siwe" };
  const r = await runtimeView(t, "wallet", { accounts: [account] });
  await r.frame.locator(".wallet-account .wallet-card-name").filter({ hasText: "Your wallet" }).waitFor();
  await r.page.reload();
  await r.frame.locator(".wallet-account .wallet-card-name").filter({ hasText: "Your wallet" }).waitFor();
  assert.match(await r.frame.locator(".wallet-method-account img").getAttribute("src"), /icons\/icon-64.png$/);
  await r.capture("wallet-linked-unknown-light-window.png");
  assert.deepEqual(r.errors, []);
});

test("n5_cleanup_blocks_allow_until_complete: Inbox cases", async t => {
  for (const initial of ["cleanup", "granted"]) await t.test(initial === "cleanup" ? "already pending cleanup" : "failure after granted Turn Off", async t => {
    const r = await runtimeView(t, "inbox", { permission:initial, cleanupFailure:true, entries:[permissionEntry(initial)],
      accounts:[{ account_id:"account:kept" }] });
    await r.frame.getByRole("button", { name:initial === "cleanup" ? "Finish disconnecting" : "Turn off internet access", exact:true }).click();
    await r.frame.locator('dialog[open] button[value="off"]').click();
    await r.frame.locator("#status-text").filter({ hasText:"cleanup could not finish" }).waitFor();
    assert.equal(await r.frame.locator("#status-text").textContent(), "cleanup could not finish", "Runtime failures are plain text");
    assert.equal(await r.frame.getByRole("button", { name:"Finish disconnecting", exact:true }).count(), 1, "failed Turn Off shows the current persisted cleanup phase");
    assert.equal(await r.frame.getByRole("button", { name:"Allow", exact:true }).count(), 0);
    await r.capture(`inbox-internet-cleanup-failed${initial === "granted" ? "-after-turn-off" : ""}-light-window.png`);
    r.state.cleanupFailure = false;
    await r.frame.getByRole("button", { name:"Finish disconnecting", exact:true }).click();
    await r.frame.locator('dialog[open] button[value="off"]').click();
    await r.frame.getByRole("button", { name:"Allow", exact:true }).waitFor();
    assert.equal(r.state.accounts.length, 1);
    const actions = r.calls.filter(c => c.path === "/api/apps/inbox/actions");
    assert.equal(actions.length, 2);
    assert.equal(actions.filter(c => c.input.step_up_token).length, initial === "granted" ? 1 : 0, "cleanup retry keeps the existing proof rule");
    assert.deepEqual(r.errors, []);
  });
});

test("n4_pending_requests_current_session_only: stale cards and counts", async t => {
  await t.test("Wallet", async t => {
  const r = await runtimeView(t, "wallet", { approvals: [], requestId: "request:previous-session" });
  await r.frame.locator("#wallet-status").filter({ hasText: "This request is unavailable. Return to the app and ask for a new request." }).waitFor();
  assert.equal(await r.frame.locator(".wallet-request").count(), 0);
  assert.equal(await r.frame.locator("#wallet-approvals-badge").isVisible(), false);
  assert.equal(r.calls.filter(c => c.method === "POST" && /approve|handoff|complete/.test(c.path)).length, 0);
  await r.capture("wallet-request-unavailable-light-window.png");
  });
  await t.test("Inbox", async t => {
    const r = await runtimeView(t, "inbox", { entries:[], notificationId:"wallet-approval-request:previous-session" });
    await r.frame.locator("#status-text").filter({ hasText:"This request is unavailable. Return to the app and make a new request." }).waitFor();
    assert.equal(await r.frame.locator("#pending-count").textContent(), "0");
    assert.equal(await r.frame.locator("#entry-detail button").count(), 0);
    assert.equal(r.calls.filter(c => c.method === "POST" && /approve|handoff|complete/.test(c.path)).length, 0);
    await r.capture("inbox-request-unavailable-light-window.png");
  });
});

test("n3_external_inbox_review_action: presentation before navigation review", async t => {
  const request = requestFixture();
  const entry = { id: `wallet-approval-request:${request.request_id}`, source_app: "browser", kind: "wallet_approval_request",
    title: "Sign a message", body: "Browser requests a signature.", severity: "attention", read: true,
    action_ref: { action_id: `wallet-review-request:${request.request_id}` } };
  const r = await runtimeView(t, "inbox", { entries: [entry] });
  await r.frame.getByRole("button", { name: "Review in Wallet", exact: true }).waitFor();
  assert.deepEqual(await r.frame.locator("#entry-detail button").allTextContents(), ["Review in Wallet"]);
  assert.equal(r.calls.filter(c => c.path.endsWith("/actions")).length, 0);
});

test("n3_requester_provenance_without_site_invention: Wallet card", async t => {
  const request = { ...requestFixture(), capsule_id: "notes", requesting_app_name:"Notes", requesting_origin: undefined, reason: "Home asks for https://forged.example" };
  const r = await runtimeView(t, "wallet", { approvals: [request] });
  const card = r.frame.locator(".wallet-request");
  await card.waitFor();
  assert.equal(await card.locator(".wallet-request-main > span").textContent(), `Notes · ${request.address.slice(0, 6)}…${request.address.slice(-4)} · Elastos Smart Chain`);
  assert.equal(await card.locator(".wallet-request-origin").count(), 0);
  await r.capture("wallet-request-no-site-light-window.png");
});

test("n3_reject_dismiss_acknowledgement: Inbox decision and count", async t => {
  const request = requestFixture();
  const entry = { id:`wallet-approval-request:${request.request_id}`, source_app:"browser", kind:"wallet_approval_request",
    title:"Sign a message", body:"Sign into the app.", read:true, severity:"attention", requesting_origin:request.requesting_origin,
    action_ref:{ action_id:`wallet-approve-request:${request.request_id}` } };
  const r = await runtimeView(t, "inbox", { entries:[entry] });
  await r.frame.getByRole("button", { name:"Reject", exact:true }).click();
  const result = r.frame.locator('#entry-detail [role="status"]');
  await result.waitFor();
  assert.equal(await result.textContent(), "Request rejected.");
  assert.equal(await r.frame.locator("#entry-detail button").count(), 0);
  assert.equal(await r.frame.locator("#pending-count").textContent(), "0");
  assert.equal(await r.frame.getByText("Sign into the app.", { exact:true }).count(), 1);
  await r.frame.getByRole("button", { name:"Refresh", exact:true }).click();
  await result.waitFor();
  assert.equal(await r.frame.locator("#entry-detail button").count(), 0);
  await r.capture("inbox-request-rejected-light-window.png");
});

test("n3_reject_dismiss_acknowledgement: Inbox consecutive decisions and stale list", async t => {
  const request = requestFixture();
  const entries = ["first", "second"].map(id => ({ id:`wallet-approval-request:${id}`, source_app:"browser", kind:"wallet_approval_request",
    title:"Sign a message", body:`Sign message ${id}.`, read:true, severity:"attention", requesting_origin:request.requesting_origin,
    action_ref:{ action_id:`wallet-approve-request:${id}` } }));
  const r = await runtimeView(t, "inbox", { entries });
  for (const id of ["first", "second"]) {
    await r.frame.locator(".entry-row").filter({ hasText:`Sign message ${id}.` }).click();
    await r.frame.getByRole("button", { name:"Reject", exact:true }).click();
    await r.frame.locator('#entry-detail [role="status"]').waitFor();
  }
  r.state.entries = entries;
  await r.frame.getByRole("button", { name:"Refresh", exact:true }).click();
  await r.frame.locator("#refresh:enabled").waitFor();
  assert.equal(await r.frame.locator("#pending-count").textContent(), "0", "a stale list cannot reopen either confirmed decision");
  assert.equal(await r.frame.locator(".entry-row").count(), 0, "neither answered request returns to the pending list");
  assert.equal(await r.frame.locator('#entry-detail [role="status"]').textContent(), "Request rejected.");
  assert.equal(await r.frame.getByText("Sign message second.", { exact:true }).count(), 1, "the last acknowledgement keeps the selected request's identity");
  assert.deepEqual(r.errors, []);
});
