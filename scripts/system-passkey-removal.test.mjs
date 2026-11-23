import assert from "node:assert/strict";
import test from "node:test";
import { mkdir } from "node:fs/promises";
import { join } from "node:path";
import { chromium, jsonResponse, textResponse, makeAppearanceRecord, makeSystemSummary, startSystemFixtureServer } from "./system-uiux-fixture.mjs";
import { productSmokeLaunchOptions } from "./product-smoke-browser.mjs";

const explanation = "Add another admin passkey before removing this one.";
const owner = { principal_id: "alex", proof_binding_id: "proof:passkey:alex", display_name: "Alex", role: "admin", current: true,
  last_used_at: Date.UTC(2026, 10, 22, 16, 5) / 1000 };
const guest = { principal_id: "sam", proof_binding_id: "proof:passkey:sam", display_name: "Sam", role: "guest", current: false };

async function fixture(run) {
  let passkeys = [owner], role = "admin", theme = "light", failure = null, afterFailurePasskeys = null;
  let listReads = 0;
  const writes = [];
  const server = await startSystemFixtureServer({
    title: "Passkey removal",
    async onApiRequest({ request, response, url }) {
      if (url.pathname === "/api/apps/system/summary") {
        const summary = makeSystemSummary(makeAppearanceRecord({ theme }));
        summary.access.role = role;
        jsonResponse(response, summary);
        return true;
      }
      if (url.pathname === "/api/auth/wallet-methods") {
        jsonResponse(response, { account_id: passkeys.find(key => key.current)?.principal_id || owner.principal_id, methods: [] });
        return true;
      }
      if (url.pathname === "/api/auth/passkeys") {
        listReads++;
        jsonResponse(response, { passkeys });
        return true;
      }
      if (/\/(revoke|promote-admin|demote-guest)$/.test(url.pathname)) {
        writes.push({ path: url.pathname, method: request.method, token: request.headers["x-elastos-home-token"] });
        if (failure) {
          if (afterFailurePasskeys) passkeys = afterFailurePasskeys;
          textResponse(response, failure.body, failure.status);
        }
        else {
          passkeys = passkeys.filter(passkey => !url.pathname.includes(encodeURIComponent(passkey.proof_binding_id)));
          jsonResponse(response, { status: "revoked" });
        }
        return true;
      }
      return false;
    },
  });
  const browser = await chromium.launch({ headless: true, ...productSmokeLaunchOptions() });
  try {
    const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
    page.setDefaultTimeout(5000);
    const errors = [];
    const consoleErrors = [];
    page.on("console", message => {
      if (message.type() === "error") consoleErrors.push(message.text());
    });
    page.on("pageerror", error => errors.push(error.message));
    const open = async (keys, options = {}) => {
      passkeys = keys.map(key => ({ ...key }));
      role = options.role || "admin";
      theme = options.theme || "light";
      failure = options.failure || null;
      afterFailurePasskeys = options.afterFailurePasskeys || null;
      await page.goto(`${server.baseUrl}/fixture?settings=account`);
      const frame = await page.locator("#system-frame").elementHandle().then(handle => handle.contentFrame());
      await frame.waitForSelector(".account-row");
      return frame;
    };
    await run({ page, open, writes, consoleErrors, listReads: () => listReads });
    assert.deepEqual(errors, []);
    assert.deepEqual(server.requestFailures, []);
  } finally {
    await browser.close();
    await server.close();
  }
}

async function screenshot(page, name) {
  const directory = process.env.LAST_ADMIN_SCREENSHOT_DIR;
  if (!directory) return;
  await mkdir(directory, { recursive: true });
  await page.screenshot({ path: join(directory, `${name}.png`) });
}

test("System protects the last admin with or without guests, in both themes and widths", async () => {
  await fixture(async ({ page, open, writes }) => {
    for (const theme of ["light", "dark"]) {
      for (const width of [1280, 390]) {
        await page.setViewportSize({ width, height: 900 });
        let frame = await open([owner], { theme });
        const remove = frame.locator(".passkey-remove");
        assert.equal(await remove.isDisabled(), true);
        assert.equal(await remove.getAttribute("title"), explanation);
        const note = frame.getByText(explanation, { exact: true });
        assert.equal(await note.isVisible(), true);
        assert.equal(await remove.getAttribute("aria-describedby"), await note.getAttribute("id"));
        const bounds = await note.boundingBox();
        assert.ok(bounds.x >= 0 && bounds.x + bounds.width <= width);
        // A synthetic click on a disabled control also has no effect.
        await remove.dispatchEvent("click");
        assert.equal(writes.length, 0);
        frame = await open([owner, guest], { theme });
        assert.equal(await frame.locator(".account-row").first().locator(".passkey-remove").isDisabled(), true);
        assert.equal(await frame.locator(".account-row").last().locator(".passkey-remove").isEnabled(), true);
        // A retained revoked admin cannot enable Remove.
        frame = await open([owner, { ...guest, role: "admin", revoked_at: 123 }], { theme });
        assert.equal(await frame.locator(".account-row").count(), 1);
        assert.equal(await frame.locator(".passkey-remove").isDisabled(), true);
      }
    }
  });
});

test("every allowed removal asks first and returns focus after Cancel or Escape", async () => {
  await fixture(async ({ page, open, writes }) => {
    for (const theme of ["light", "dark"]) {
      for (const width of [1280, 390]) {
        await page.setViewportSize({ width, height: 900 });
        const frame = await open([owner, guest], { theme });
        const remove = frame.locator(".account-row").last().locator(".passkey-remove");
        const before = writes.length;
        await remove.click();
        const dialog = frame.getByRole("dialog", { name: "Remove passkey?", exact: true });
        await dialog.waitFor({ timeout: 1500 });
        assert.equal(writes.length, before);
        assert.match(await dialog.textContent(), /Remove the passkey for Sam from this Home\?/);
        assert.match(await dialog.textContent(), /All windows signed in with this passkey will be signed out\./);
        assert.match(await dialog.textContent(), /If a copy remains on their device, security key or in their password manager, they can delete it there\./);
        assert.equal(await dialog.getByRole("button", { name: "Cancel", exact: true }).evaluate(node => node === document.activeElement), true);
        const bounds = await dialog.boundingBox();
        assert.ok(bounds.x >= 0 && bounds.x + bounds.width <= width);
        await screenshot(page, `confirmation-${theme}-${width}`);
        await page.keyboard.press("Enter");
        await dialog.waitFor({ state: "hidden" });
        assert.equal(writes.length, before, "Enter takes the default Cancel action");
        assert.equal(await remove.evaluate(node => node === document.activeElement), true);
        await remove.click();
        await page.keyboard.press("Escape");
        await dialog.waitFor({ state: "hidden" });
        assert.equal(writes.length, before);
        assert.equal(await remove.evaluate(node => node === document.activeElement), true);
        await remove.click();
        await dialog.getByRole("button", { name: "Cancel", exact: true }).click();
        assert.equal(writes.length, before);
        assert.equal(await remove.evaluate(node => node === document.activeElement), true);
        await remove.click();
        await dialog.getByRole("button", { name: "Remove passkey", exact: true }).click();
        await frame.waitForFunction(() => document.querySelectorAll(".account-row").length === 1);
        assert.deepEqual(writes.at(-1), { path: "/api/auth/passkeys/proof%3Apasskey%3Asam/revoke", method: "POST", token: "system-token" });
        assert.equal(writes.length, before + 1);
      }
    }
    // The same confirmation protects a guest leaving and an owner replacing a key.
    for (const role of ["guest", "admin"]) {
      const current = { ...owner, role };
      const keys = [current, { ...current, proof_binding_id: "proof:passkey:replacement", current: false }];
      const frame = await open(keys, { role });
      const before = writes.length;
      await frame.locator(".passkey-remove").first().click();
      const dialog = frame.getByRole("dialog");
      await dialog.waitFor();
      assert.match(await dialog.textContent(), /Remove your passkey from this Home\?/);
      assert.equal(writes.length, before);
      await dialog.getByRole("button", { name: "Remove passkey", exact: true }).click();
      await frame.waitForFunction(() => document.querySelector('[data-field="passkey-status"]').textContent === "Removed. Open Home to sign in.");
      assert.equal(writes.length, before + 1);
    }
  });
});

test("confirmation uses own and unnamed wording for device and hardware passkeys", async () => {
  await fixture(async ({ page, open, writes }) => {
    for (const theme of ["light", "dark"]) {
      for (const width of [1280, 390]) {
        await page.setViewportSize({ width, height: 900 });
        for (const state of ["current", "own-other", "unnamed"]) {
          const other = state === "unnamed" ? { ...guest, display_name: "" }
            : { ...owner, proof_binding_id: "proof:passkey:other", current: false };
          const frame = await open([owner, other], { theme });
          const remove = frame.locator(".passkey-remove").nth(state === "current" ? 0 : 1);
          await remove.click();
          const dialog = frame.getByRole("dialog");
          await dialog.waitFor();
          assert.equal(await dialog.locator('[data-field="passkey-remove-person"]').textContent(),
            state === "unnamed" ? "Remove this passkey from this Home?" : "Remove your passkey from this Home?");
          assert.equal(await dialog.locator('[data-field="passkey-remove-current"]').isVisible(), state === "current");
          assert.match(await dialog.textContent(), state === "unnamed"
            ? /their device, security key or in their password manager/ : /your device, security key or in your password manager/);
          assert.doesNotMatch(await dialog.textContent(), /for Account|that person/);
          if (state !== "own-other") await screenshot(page, `confirmation-${state}-${theme}-${width}`);
          await dialog.getByRole("button", { name: "Cancel", exact: true }).click();
          assert.equal(await remove.evaluate(node => node === document.activeElement), true);
        }
      }
    }
    assert.equal(writes.length, 0);
  });
});

test("only the removal 409 shows its sentence and refreshes the stale list", async () => {
  await fixture(async ({ page, open, writes, listReads }) => {
    const otherOwnKey = { ...owner, proof_binding_id: "proof:passkey:replacement", current: false };
    let frame = await open([owner, otherOwnKey], {
      failure: { status: 409, body: explanation }, afterFailurePasskeys: [owner],
    });
    const before = listReads();
    await frame.locator(".passkey-remove").first().click();
    await frame.getByRole("dialog").getByRole("button", { name: "Remove passkey", exact: true }).click();
    await frame.waitForFunction(message => document.querySelector('[data-field="passkey-status"]').textContent === message
      && document.querySelectorAll(".account-row").length === 1 && document.querySelector(".passkey-remove").disabled, explanation);
    assert.ok(listReads() > before);
    assert.equal(writes.length, 1);
    for (const status of [403, 409, 500]) {
      for (const action of ["remove", "promote", "demote"]) {
        const target = { ...guest, role: action === "demote" ? "admin" : "guest" };
        frame = await open([owner, target], { failure: { status, body: "private-server-detail /private/fixture-state" } });
        const readsBefore = listReads();
        const refreshed = status === 409 ? page.waitForResponse(response => response.url().endsWith("/api/auth/passkeys")) : null;
        await frame.locator(`.passkey-${action}`).last().click();
        if (action === "remove") await frame.getByRole("dialog").getByRole("button", { name: "Remove passkey", exact: true }).click();
        await frame.waitForFunction(() => document.querySelector('[data-field="passkey-status"]').textContent === "Account action could not be completed.");
        assert.doesNotMatch(await frame.locator('[data-field="passkey-status"]').textContent(), /private-server-detail|fixture-state/);
        if (refreshed) {
          await refreshed;
          assert.ok(listReads() > readsBefore);
        }
      }
    }
  });
});


test("System opens passkey removal with Cancel focused and no cross-origin autofocus error", async () => {
  await fixture(async ({ page, open, writes, consoleErrors }) => {
    const frame = await open([owner, guest]);
    assert.equal(await frame.evaluate(() => window.origin), "null");
    await frame.locator(".account-row").last().locator(".passkey-remove").click();
    const cancel = frame.getByRole("dialog").getByRole("button", { name: "Cancel", exact: true });
    assert.equal(await cancel.evaluate(button => button === document.activeElement), true);
    await cancel.click();
    assert.equal(await frame.getByRole("dialog").count(), 0);
    assert.equal(writes.length, 0);
    assert.deepEqual(consoleErrors.filter(message => /autofocus/i.test(message)), []);
  });
});


test("System distinguishes two passkeys and identifies this window at desktop and phone widths", async () => {
  await fixture(async ({ page, open, writes }) => {
    const created = Date.UTC(2026, 10, 22, 14, 5) / 1000;
    const second = { ...owner, proof_binding_id: "proof:passkey:backup", current: false,
      created_at: created + 3600, added_from: "Chrome on Android" };
    for (const width of [1280, 390]) {
      await page.setViewportSize({ width, height: 900 });
      let frame = await open([{ ...owner, created_at: created, added_from: "Safari on Mac" }, second]);
      const rows = frame.locator(".account-row");
      assert.equal(await rows.count(), 2);
      assert.match(await rows.nth(0).locator(".passkey-added").textContent(), /^Added .+ in Safari on Mac$/);
      assert.match(await rows.nth(1).locator(".passkey-added").textContent(), /^Added .+ in Chrome on Android$/);
      assert.equal(await rows.nth(0).locator(".passkey-current").textContent(), "This window signed in with this passkey");
      assert.notEqual(await rows.nth(0).locator(".account-used").textContent(), "Not used yet");
      assert.equal(await rows.nth(1).locator(".passkey-current").count(), 0);
      assert.equal(await frame.getByText("Your browser will offer where to save the passkey, including a phone or tablet.", { exact: true }).isVisible(), true);
      for (const label of await frame.locator(".passkey-added, .passkey-current").all()) {
        const bounds = await label.boundingBox();
        assert.ok(bounds.x >= 0 && bounds.x + bounds.width <= width);
        assert.equal(await label.evaluate(node => node.scrollWidth <= node.clientWidth), true);
      }
      await screenshot(page, `passkey-names-${width}`);
      // Two additions from the same browser within a minute remain distinct.
      frame = await open([{ ...owner, created_at: created, added_from: "Safari on Mac" },
        { ...second, created_at: created + 1, added_from: "Safari on Mac" }]);
      const labels = await frame.locator(".passkey-added").allTextContents();
      assert.notEqual(labels[0], labels[1]);
      // Old credentials retain their creation date, and the marker follows the session.
      frame = await open([{ ...owner, created_at: created, current: false }, { ...second, current: true }]);
      assert.match(await frame.locator(".passkey-added").first().textContent(), /^Added /);
      assert.doesNotMatch(await frame.locator(".passkey-added").first().textContent(), / in /);
      assert.equal(await frame.locator(".account-row").nth(1).locator(".passkey-current").count(), 1);
    }
    assert.equal(writes.length, 0);
  });
});
