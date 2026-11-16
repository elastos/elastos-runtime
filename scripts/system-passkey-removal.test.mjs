import assert from "node:assert/strict";
import test from "node:test";
import { mkdir } from "node:fs/promises";
import { join } from "node:path";
import { chromium, jsonResponse, textResponse, makeAppearanceRecord, makeSystemSummary, startSystemFixtureServer } from "./system-uiux-fixture.mjs";
import { productSmokeLaunchOptions } from "./product-smoke-browser.mjs";

const explanation = "Add another admin passkey before removing this one.";
const owner = { principal_id: "alex", proof_binding_id: "proof:passkey:alex", display_name: "Alex", role: "admin", current: true };
const guest = { principal_id: "sam", proof_binding_id: "proof:passkey:sam", display_name: "Sam", role: "guest", current: false };

async function fixture(run) {
  let passkeys = [owner], role = "admin", theme = "light", refuse = false;
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
      if (url.pathname === "/api/auth/passkeys") {
        jsonResponse(response, { passkeys });
        return true;
      }
      if (url.pathname.endsWith("/revoke")) {
        writes.push({ path: url.pathname, method: request.method, token: request.headers["x-elastos-home-token"] });
        if (refuse) textResponse(response, explanation, 409);
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
    page.on("pageerror", error => errors.push(error.message));
    const open = async (keys, options = {}) => {
      passkeys = keys.map(key => ({ ...key }));
      role = options.role || "admin";
      theme = options.theme || "light";
      refuse = options.refuse || false;
      await page.goto(`${server.baseUrl}/fixture?settings=account`);
      const frame = await page.locator("#system-frame").elementHandle().then(handle => handle.contentFrame());
      await frame.waitForSelector(".account-row");
      return frame;
    };
    await run({ page, open, writes });
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
        await screenshot(page, `protected-${theme}-${width}`);
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

test("every allowed removal asks first, defaults to Cancel, and shows failures", async () => {
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
        assert.match(await dialog.textContent(), /password manager until they delete it there\./);
        assert.equal(await dialog.getByRole("button", { name: "Cancel", exact: true }).evaluate(node => node === document.activeElement), true);
        const bounds = await dialog.boundingBox();
        assert.ok(bounds.x >= 0 && bounds.x + bounds.width <= width);
        await screenshot(page, `confirmation-${theme}-${width}`);
        await page.keyboard.press("Enter");
        await dialog.waitFor({ state: "hidden" });
        assert.equal(writes.length, before, "Enter takes the default Cancel action");
        await remove.click();
        await page.keyboard.press("Escape");
        await dialog.waitFor({ state: "hidden" });
        assert.equal(writes.length, before);
        await remove.click();
        await dialog.getByRole("button", { name: "Cancel", exact: true }).click();
        assert.equal(writes.length, before);
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
      const keys = role === "guest" ? [current] : [current, { ...owner, proof_binding_id: "proof:passkey:replacement", current: false }];
      const frame = await open(keys, { role });
      const before = writes.length;
      await frame.locator(".passkey-remove").first().click();
      const dialog = frame.getByRole("dialog");
      await dialog.waitFor();
      assert.match(await dialog.textContent(), /passkey for Alex/);
      assert.equal(writes.length, before);
      await dialog.getByRole("button", { name: "Remove passkey", exact: true }).click();
      await frame.waitForFunction(() => document.querySelector('[data-field="passkey-status"]').textContent === "Removed. Open Home to sign in.");
      assert.equal(writes.length, before + 1);
    }
    const frame = await open([owner, guest], { refuse: true });
    await frame.locator(".passkey-remove").last().click();
    await frame.getByRole("dialog").getByRole("button", { name: "Remove passkey", exact: true }).click();
    await frame.waitForFunction(message => document.querySelector('[data-field="passkey-status"]').textContent === message, explanation);
    assert.equal(await frame.locator(".account-row").count(), 2);
    assert.equal(await frame.locator(".passkey-remove").last().isEnabled(), true);
  });
});
