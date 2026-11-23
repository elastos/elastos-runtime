import test from "node:test";
import assert from "node:assert/strict";
import { chromium, jsonResponse, makeAppearanceRecord, makeSystemSummary, startSystemFixtureServer } from "./system-uiux-fixture.mjs";

test("System wallet sessions approve the exact Guest and Community choices before writing", async () => {
  let walletSession = true, role = "admin", enabled = false, mode = "hidden";
  const writes = [];
  const server = await startSystemFixtureServer({
    title: "Wallet session approvals",
    hostScript: `window.approvals = []; window.refuseApproval = false;
      window.addEventListener("message", event => {
        if (event.source !== document.querySelector("iframe").contentWindow || event.data?.type !== "elastos.home.passkey-step-up.request/v1") return;
        window.approvals.push(event.data);
        event.source.postMessage({type:"elastos.home.passkey-step-up.result/v1", requestId:event.data.requestId,
          ...(window.refuseApproval ? {error:"Passkey verification cancelled."} : {stepUpToken:"exact-choice-approval"})}, "*");
      });`,
    async onApiRequest({ request, response, url }) {
      if (url.pathname === "/api/apps/system/summary") {
        const summary = makeSystemSummary(makeAppearanceRecord(), {proofBindingId: walletSession ? "proof:signin-wallet:one" : "proof:passkey:one"});
        summary.access = {...summary.access, role, guest_registration_enabled:enabled};
        jsonResponse(response, summary); return true;
      }
      if (url.pathname === "/api/apps/system/community") {
        jsonResponse(response, {schema:"elastos.community-membership/v1", configured:true, joined:true}); return true;
      }
      if (url.pathname === "/api/apps/system/community/presence" || url.pathname === "/api/apps/system/access/guest-registration") {
        if (request.method === "POST") {
          let raw = ""; for await (const chunk of request) raw += chunk;
          const body = JSON.parse(raw);
          writes.push({path:url.pathname, body, token:request.headers["x-elastos-step-up-token"], home:request.headers["x-elastos-home-token"]});
          if ("enabled" in body) enabled = body.enabled; else mode = body.mode;
        }
        jsonResponse(response, url.pathname.endsWith("presence")
          ? {schema:"elastos.community-presence/v1", configured:true, joined:true, community_presence:mode}
          : {role, guest_registration_enabled:enabled}); return true;
      }
      return false;
    },
  });
  const browser = await chromium.launch({headless:true});
  try {
    const page = await browser.newPage(); page.setDefaultTimeout(5000);
    async function open() {
      await page.goto(`${server.baseUrl}/fixture?settings=security`);
      const frame = await page.locator("#system-frame").elementHandle().then(h => h.contentFrame());
      await frame.waitForFunction(() => !document.querySelector('[data-presence-mode="always"]').disabled);
      return frame;
    }
    let frame = await open();
    await frame.locator("#guest-registration").check({force:true});
    await frame.waitForFunction(() => document.querySelector('[data-field="guest-registration-status"]').textContent === "Guest creation on.");
    assert.equal(writes.at(-1).token, "exact-choice-approval");
    assert.deepEqual(writes.at(-1).body, {enabled:true});
    assert.equal(writes.at(-1).home, "system-token");
    assert.deepEqual(await page.evaluate(() => window.approvals.map(a => [a.operation,a.request])), [["auth.account.guest-registration",{enabled:true}]]);
    for (const choice of ["always", "while_open", "hidden"]) {
      await frame.locator(`[data-presence-mode="${choice}"]`).click();
      await frame.waitForFunction(choice => document.querySelector(`[data-presence-mode="${choice}"]`).getAttribute("aria-checked") === "true" && !document.querySelector(`[data-presence-mode="${choice}"]`).disabled, choice);
      assert.deepEqual(writes.at(-1).body, {mode:choice});
      assert.equal(writes.at(-1).token, choice === "hidden" ? undefined : "exact-choice-approval");
    }
    assert.deepEqual(await page.evaluate(() => window.approvals.slice(1).map(a => [a.operation,a.request])), [
      ["community.presence.grant",{mode:"always"}], ["community.presence.grant",{mode:"while_open"}],
    ]);
    await page.evaluate(() => window.refuseApproval = true);
    const before = writes.length;
    await frame.locator("#guest-registration").uncheck({force:true});
    await frame.waitForFunction(() => !document.querySelector("#guest-registration").disabled);
    assert.equal(await frame.locator("#guest-registration").isChecked(), true);
    await frame.locator('[data-presence-mode="always"]').click();
    await frame.locator('[data-field="community-presence-status"]').waitFor({state:"visible"});
    assert.equal(await frame.locator('[data-presence-mode="hidden"]').getAttribute("aria-checked"), "true");
    assert.equal(writes.length, before, "cancelled passkey approval sends neither write");
    role = "guest"; frame = await open();
    await frame.locator('[data-presence-mode="always"]').click();
    await frame.waitForFunction(() => !document.querySelector('[data-presence-mode="always"]').disabled);
    assert.equal(writes.at(-1).token, "exact-choice-approval", "Guest approves his own presence");
    assert.equal(await frame.locator("#guest-registration").isDisabled(), true);
    role = "admin"; walletSession = false; frame = await open();
    await frame.locator("#guest-registration").uncheck({force:true});
    await frame.waitForFunction(() => !document.querySelector("#guest-registration").disabled);
    await frame.locator('[data-presence-mode="while_open"]').click();
    await frame.waitForFunction(() => !document.querySelector('[data-presence-mode="while_open"]').disabled);
    assert.equal(writes.at(-1).token, undefined);
    assert.equal(await page.evaluate(() => window.approvals.length), 0, "passkey sessions keep their existing approval policy");
    assert.deepEqual(server.requestFailures, []);
  } finally { await browser.close(); await server.close(); }
});
