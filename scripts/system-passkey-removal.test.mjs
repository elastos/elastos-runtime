import assert from "node:assert/strict";
import test from "node:test";
import { mkdir } from "node:fs/promises";
import { join } from "node:path";
import { jsonResponse, textResponse, makeAppearanceRecord, makeSystemSummary, startSystemFixtureServer } from "./system-uiux-fixture.mjs";
import { productSmokeLaunchOptions, requireProductSmokePlaywright } from "./product-smoke-browser.mjs";
import { windowTestOptions } from "./lib/walletconnect-window-resources.mjs";

const explanation = "Add another admin passkey first.";
const disabledExplanation = "Add another admin passkey first.";
const owner = { principal_id: "alex", proof_binding_id: "proof:passkey:alex", display_name: "Alex", role: "admin", current: true,
  last_used_at: Date.UTC(2026, 10, 22, 16, 5) / 1000 };
const guest = { principal_id: "sam", proof_binding_id: "proof:passkey:sam", display_name: "Sam", role: "guest", current: false };

const guestBackup={...guest,proof_binding_id:'proof:passkey:sam-backup'};

async function fixture(run, engine = "chromium") {
  let passkeys = [owner], role = "admin", theme = "light", failure = null, afterFailurePasskeys = null;
  let methods = [];
  let listReads = 0;
  const writes = [];
  const server = await startSystemFixtureServer({
    title: "Passkey removal",
    async onApiRequest({ request, response, url }) {
      if (url.pathname === "/api/apps/system/summary") {
        const summary = makeSystemSummary(makeAppearanceRecord({ theme }));
        summary.access.role = role;
        summary.authority.proof_binding_id = passkeys.find(key => key.current)?.proof_binding_id || owner.proof_binding_id;
        jsonResponse(response, summary);
        return true;
      }
      if (url.pathname === "/api/apps/wallet/wallet/inventory") {
        jsonResponse(response, {schema:'elastos.wallet.inventory/v1',account_id:passkeys.find(key=>key.current)?.principal_id||owner.principal_id,entries:methods.map(method=>({inventory_id:`eip155:${method.chain_id}:${method.address}`,address:method.address,chain_namespace:`eip155:${method.chain_id}`,accounts:[],sign_in:method}))});return true;
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
  const browser = await requireProductSmokePlaywright()[engine].launch({ headless: true, ...(engine === "chromium" ? productSmokeLaunchOptions() : {}) });
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
      methods = options.methods || [];
      theme = options.theme || "light";
      failure = options.failure || null;
      afterFailurePasskeys = options.afterFailurePasskeys || null;
      await page.goto(`${server.baseUrl}/fixture?settings=account`);
      await page.bringToFront();
      const frame = await page.locator("#system-frame").elementHandle().then(handle => handle.contentFrame());
      await frame.waitForSelector(".account-row");
      await frame.evaluate(() => document.fonts.ready);
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

async function waitForRemoveFocus(frame, remove) {
  const proofBindingId = await remove.getAttribute("data-passkey-revoke");
  // Refreshes replace the controls. Resolve the same passkey on every poll.
  await frame.waitForFunction(id => {
    const button = [...document.querySelectorAll(".passkey-remove")]
      .find(node => node.dataset.passkeyRevoke === id);
    return Boolean(button) && button === document.activeElement;
  }, proofBindingId);
}

async function screenshot(page, name, directory = process.env.LAST_ADMIN_SCREENSHOT_DIR) {
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
        assert.equal(await remove.getAttribute("title"), disabledExplanation);
        const note = frame.getByText(disabledExplanation, { exact: true });
        assert.equal(await note.isVisible(), true);
        assert.equal(await remove.getAttribute("aria-describedby"), await note.getAttribute("id"));
        const bounds = await note.boundingBox();
        assert.ok(bounds.x >= 0 && bounds.x + bounds.width <= width);
        // A synthetic click on a disabled control also has no effect.
        await remove.dispatchEvent("click");
        assert.equal(writes.length, 0);
        frame = await open([owner, guestBackup, guest], { theme });
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
        const frame = await open([owner, guestBackup, guest], { theme });
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
        await waitForRemoveFocus(frame, remove);
        await remove.click();
        await dialog.waitFor();
        await page.keyboard.press("Escape");
        await dialog.waitFor({ state: "hidden" });
        assert.equal(writes.length, before);
        await waitForRemoveFocus(frame, remove);
        await remove.click();
        await dialog.waitFor();
        await dialog.getByRole("button", { name: "Cancel", exact: true }).click();
        assert.equal(writes.length, before);
        await waitForRemoveFocus(frame, remove);
        await remove.click();
        await dialog.waitFor();
        await dialog.getByRole("button", { name: "Remove passkey", exact: true }).click();
        await frame.waitForFunction(() => document.querySelectorAll(".account-row").length === 2);
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

test("removal focus assertion follows a refreshed control and rejects lost focus", async () => {
  await fixture(async ({ page, open, writes }) => {
    const frame = await open([owner, guestBackup, guest]);
    const remove = frame.locator(".account-row").last().locator(".passkey-remove");
    await remove.click();
    const dialog = frame.getByRole("dialog");
    await dialog.waitFor();
    const original = await remove.elementHandle();
    // Start polling while Cancel has focus, then replace the opener through
    // the real focus-triggered refresh before closing the dialog.
    const restoredFocus = waitForRemoveFocus(frame, remove);
    await frame.evaluate(() => new Promise(resolve => requestAnimationFrame(resolve)));
    await frame.evaluate(() => window.dispatchEvent(new Event("focus")));
    await frame.waitForFunction(node => !node.isConnected, original);
    await page.keyboard.press("Enter");
    await dialog.waitFor({ state: "hidden" });
    await restoredFocus;
    await assert.rejects(
      frame.waitForFunction(node => node === document.activeElement, original, { timeout: 100 }),
      /Timeout 100ms exceeded/,
    );
    await original.dispose();

    // A present, enabled Remove is insufficient: it must have actual focus.
    await remove.evaluate(node => node.blur());
    page.setDefaultTimeout(100);
    try {
      await assert.rejects(waitForRemoveFocus(frame, remove), /Timeout 100ms exceeded/);
    } finally {
      page.setDefaultTimeout(5000);
    }
    assert.equal(writes.length, 0);
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
          const frame = await open([owner, ...(state==='unnamed'?[{...guestBackup,display_name:''}]:[]), other], { theme });
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
          await waitForRemoveFocus(frame, remove);
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
        frame = await open([owner, ...(action==='remove'?[guestBackup]:[]), target], { failure: { status, body: "private-server-detail /private/fixture-state" } });
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
    const frame = await open([owner, guestBackup, guest]);
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
      created_at: created + 3600, added_from: "Saved on a phone or tablet (added from Safari on Mac or iPad)" };
    for (const width of [1280, 390]) {
      await page.setViewportSize({ width, height: 900 });
      let frame = await open([{ ...owner, created_at: created, added_from: "Apple Passwords (added from Safari on Mac or iPad)" }, second]);
      const rows = frame.locator(".account-row");
      assert.equal(await rows.count(), 2);
      assert.equal(await rows.nth(0).locator(".passkey-name").textContent(), "Apple Passwords");
      assert.match(await rows.nth(0).locator(".account-name-wrap").getAttribute("title"), /added from Safari on Mac or iPad/);
      assert.equal(await rows.nth(1).locator(".passkey-name").textContent(), "Saved on a phone or tablet");
      assert.equal(await rows.nth(0).locator(".passkey-current").textContent(), "Current passkey");
      assert.notEqual(await rows.nth(0).locator(".account-used").textContent(), "Not used yet");
      assert.equal(await rows.nth(1).locator(".passkey-current").count(), 0);
      assert.equal(await frame.locator("#passkey-add-help").count(), 0);
      for (const label of await frame.locator(".passkey-added, .passkey-current").all()) {
        const bounds = await label.boundingBox();
        assert.ok(bounds.x >= 0 && bounds.x + bounds.width <= width);
        assert.equal(await label.evaluate(node => node.scrollWidth <= node.clientWidth), true);
      }
      await screenshot(page, `passkey-names-${width}`);
      // Two additions from the same browser within a minute remain distinct.
      frame = await open([{ ...owner, created_at: created, added_from: "Apple Passwords (added from Safari on Mac or iPad)" },
        { ...second, created_at: created + 1, added_from: "Apple Passwords (added from Safari on Mac or iPad)" }]);
      const labels = await frame.locator(".passkey-name").allTextContents();
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


for (const engine of ["chromium", "webkit"]) test(`Accounts groups methods beneath their owner with equal add controls in both themes and widths in ${engine}`, windowTestOptions(engine, 30000), async () => {
  const tabKey = engine === "webkit" && process.platform === "darwin" ? "Alt+Tab" : "Tab";
  const previousKey = engine === "webkit" && process.platform === "darwin" ? "Alt+Shift+Tab" : "Shift+Tab";
  await fixture(async ({ page, open, writes }) => {
    const created = Date.UTC(2026, 10, 23, 13, 3) / 1000;
    const key = { ...owner, created_at: created, last_used_at: created + 240, added_from: "Device passkey (added from Chrome on Mac or iPad)" };
    const backup = { ...key, current: false, proof_binding_id: "proof:passkey:backup" };
    const wallet = { method_id: "wallet:metamask", connector: "metamask", address: "0x1234567890123456789012345678901234567890", chain_id: 20, network: "", sign_in_enabled: true, last_used_at: created };
    for (const theme of ["light", "dark"]) for (const width of [1280, 390]) {
      await page.setViewportSize({ width, height: 900 });
      for (const [state, keys, options] of [
        ["admin-one-passkey", [key], {}],
        ["admin-two-passkeys-wallet", [key, backup], { methods: [wallet] }],
        ["guest", [{ ...key, role: "guest" }], { role: "guest" }],
      ]) {
        const frame = await open(keys, { theme, ...options });
        const block = frame.locator(".account-block");
        assert.equal(await block.count(), 1);
        assert.equal(await block.locator(".account-header h2").textContent(), "Alex");
        assert.equal(await block.locator(".account-row").count(), keys.length);
        assert.equal(await block.locator(".passkey-current").count(), 1);
        assert.equal(await frame.locator("#passkey-add-help").count(), 0);
        assert.equal(await block.getByText("Signs in", {exact:true}).count(), 0);
        for (const action of await block.locator('.passkey-remove, .account-remove').all()) {
          const style=await action.evaluate(node=>{const s=getComputedStyle(node);return {background:s.backgroundColor,border:s.borderTopColor,height:node.getBoundingClientRect().height,padding:s.padding};});
          assert.notEqual(style.background,"rgba(0, 0, 0, 0)","passkey and account actions keep the approved button surface");
          assert.notEqual(style.border,"rgba(0, 0, 0, 0)","passkey and account actions have a visible boundary");
          assert.ok(style.height>=44);
          assert.equal(style.padding,"8px 12px","all destructive actions use the same padding");
        }
        const add = frame.locator("#passkey-add, #wallet-signin-add");
        if (options.role === "guest") {assert.equal(await frame.locator(".account-add-actions button:visible").count(),0);assert.equal(await frame.locator(".system-signin-wallets").getByRole("button",{name:"Add wallet",exact:true}).count(),0);}
        else {
          const boxes = await Promise.all((await add.all()).map(button => button.boundingBox()));
          assert.ok(boxes.every(box=>box&&box.height>=44));
        }
        assert.equal(await frame.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
        for (const note of await frame.locator(".passkey-removal-note").all()) {
          const button = frame.locator(`[aria-describedby="${await note.getAttribute("id")}"]`);
          assert.equal(await button.isDisabled(), true);
          assert.equal(await note.evaluate(node => node.parentElement.contains(node.parentElement.querySelector("button"))), true);
        }
        if (options.methods) {
          const walletRow = block.locator("[data-wallet-method]");
          assert.equal(await walletRow.getByRole("button").count(), 1);
          assert.equal(await walletRow.getByRole("switch").count(), 0);
          assert.equal(await walletRow.getByRole("button", { name: "Remove from sign-in", exact: true }).count(), 1);
          const walletSize = await walletRow.getByRole("button", { name: "Remove from sign-in", exact: true }).boundingBox();
          const passkeySize = await block.locator(".passkey-remove").first().boundingBox();
          assert(walletSize.width > passkeySize.width, "Remove from sign-in retains its full action label");
          assert(Math.abs(walletSize.height - passkeySize.height) <= 1, `wallet and passkey Remove use the same height: ${JSON.stringify({walletSize,passkeySize,theme,width})}`);
          assert.equal(await block.getByRole("button", { name: "Remove account", exact: true }).count(), 0);
          assert.equal(new Set(await block.locator(".passkey-name").allTextContents()).size, 2);
          const remove = block.locator(".passkey-remove").first();
          await page.bringToFront();
          await remove.press(tabKey);
          await page.keyboard.press(previousKey);
          const focused = await frame.waitForFunction(id=>{
            const node=[...document.querySelectorAll('[data-passkey-revoke]')].find(button=>button.dataset.passkeyRevoke===id);
            if(node!==document.activeElement||!node.matches(':focus-visible'))return false;
            const style=getComputedStyle(node);
            return parseFloat(style.outlineWidth)>=2&&{width:style.outlineWidth,style:style.outlineStyle};
          },key.proof_binding_id);
          // Keep the measurement from the focused frame, before another window can take focus.
          const focus = await focused.jsonValue();
          await focused.dispose();
          assert.notEqual(focus.style, "none");
          assert.ok(parseFloat(focus.width) >= 2);
          await remove.evaluate(node => node.blur());
        }
        await frame.evaluate(() => document.fonts.ready);
        const background = await frame.locator("body").evaluate(node => getComputedStyle(node).backgroundColor);
        const brightness = background.match(/\d+/g).slice(0, 3).map(Number).reduce((sum, value) => sum + value, 0) / 3;
        assert.equal(brightness < 128, theme === "dark", "the rendered theme matches the capture name");
        const notes = frame.locator(".account-actions:has(.passkey-removal-note)");
        for (const actions of await notes.all()) assert.ok((await actions.boundingBox()).width >= 176);
        await screenshot(page, `${state}-${theme}-${width}`, process.env.ACCOUNTS_SCREENSHOT_DIR);
      }
      const frame = await open([key, backup, guestBackup, guest], { theme, methods: [wallet] });
      assert.equal(await frame.locator(".account-block").count(), 2);
      assert.equal(await frame.locator(".account-block").first().locator("[data-wallet-method]").count(), 1);
      assert.equal(await frame.locator(".account-block").last().locator("[data-wallet-method]").count(), 0);
      assert.equal(await frame.locator(".account-header .passkey-promote").count(), 1);
    }
    assert.equal(writes.length, 0);
  }, engine);
});
