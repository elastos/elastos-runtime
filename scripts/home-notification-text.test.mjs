import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { once } from "node:events";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { extname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { requireProductSmokePlaywright, productSmokeLaunchOptions } from "./product-smoke-browser.mjs";

const root = fileURLToPath(new URL("../", import.meta.url));
const entry = {
  id: "contact-request:readable", kind: "contact_request", read: true,
  title: "A contact request with a name that needs more than one line to read",
  body: "Jordan wants to connect so you can share messages and files. Open People to review this request and choose whether to connect. Keep this final sentence visible too.",
};

// Import the real capsule modules and template. Only Runtime data is a fixture.
const shell = `<!doctype html><meta name="viewport" content="width=device-width, initial-scale=1">
  <script src="/apps/home-gui/elastos-theme.js"></script>
  <link rel="stylesheet" href="/apps/home-gui/elastos-ui.css">
  <body data-home-shell="desktop"><div class="home-gui-shell"></div>
  <script type="module">
    const core = await import('/apps/home-gui/shell-core.js?v=home-20261101d');
    await core.ensureHomeGuiDom();
    const formFactor = await import('/apps/home-gui/shell-form-factor.js?v=home-20261101d');
    formFactor.syncFormFactor();
    for (const node of document.querySelectorAll('[data-home-gui-hidden-by-host]')) {
      node.hidden = false; node.inert = false;
    }
    core.shellState.currentSummary = {
      authority: { signed_in: true }, targets: [{ target: 'system' }, { target: 'inbox' }],
      identity: {
        profile_readiness: { schema: 'elastos.profile.readiness/v1', status: 'ready' },
        recovery_readiness: { schema: 'elastos.recovery.readiness/v1', status: 'setup_required' }
      }
    };
    const notifications = await import('/apps/home-gui/shell-notifications.js?v=home-20261101d');
    const setup = await import('/apps/home-gui/shell-setup-sheet.js?v=home-20261101d');
    notifications.bindNotificationCenter();
    setup.bindSetupSheet(); setup.showSetupSheet();
    window.fixture = { notifications, core,
      surface: await import('/apps/home-gui/shell-surface.js?v=home-20261101d') };
  </script>`;

// Set a ref to capture and confirm the original clipping beside the fix.
const compareRef = process.env.NOTIFICATION_TEXT_COMPARE_REF || null;
for (const sourceRef of compareRef ? [compareRef, null] : [null]) {
  for (const viewport of [{ width: 1440, height: 900 }, { width: 390, height: 844 }]) {
    test(`notification text is complete at ${viewport.width}x${viewport.height} (${sourceRef || "working tree"})`, { timeout: 60000 }, async (t) => {
      const server = createServer((req, res) => {
        const url = new URL(req.url, "http://fixture");
        res.setHeader("cache-control", "no-store");
        if (url.pathname === "/") {
          res.setHeader("content-type", "text/html"); res.end(shell); return;
        }
        if (url.pathname.startsWith("/api/")) {
          res.setHeader("content-type", "application/json");
          res.end(JSON.stringify({ notifications: { entries: [entry] } })); return;
        }
        const match = /^\/apps\/(home-gui|inbox)\/(.*)$/.exec(url.pathname);
        const base = match && resolve(root, `capsules/${match[1]}/browser`);
        const path = base && resolve(base, match[2] || "index.html");
        if (!path || !path.startsWith(`${base}/`)) { res.writeHead(404); res.end(); return; }
        try {
          res.setHeader("content-type", ({ ".js": "text/javascript", ".css": "text/css", ".html": "text/html", ".svg": "image/svg+xml" })[extname(path)] || "application/octet-stream");
          res.end(sourceRef
            ? execFileSync("git", ["show", `${sourceRef}:${path.slice(root.length)}`], { cwd: root, stdio: ["ignore", "pipe", "ignore"] })
            : readFileSync(path));
        } catch { res.writeHead(404); res.end(); }
      });
      server.listen(0, "127.0.0.1"); await once(server, "listening");
      t.after(() => { server.closeAllConnections(); server.close(); });
      const { chromium } = requireProductSmokePlaywright();
      const browser = await chromium.launch({ headless: true, ...productSmokeLaunchOptions() });
      t.after(() => browser.close());
      const page = await browser.newPage({ viewport, reducedMotion: "reduce", isMobile: viewport.width < 600, hasTouch: viewport.width < 600 });
      const errors = [];
      page.on("pageerror", (error) => errors.push(error.message));
      const origin = `http://127.0.0.1:${server.address().port}`;
      const results = [];
      const out = process.env.NOTIFICATION_TEXT_OUT
        ? resolve(process.env.NOTIFICATION_TEXT_OUT, sourceRef ? "before" : "after") : null;
      if (out) mkdirSync(out, { recursive: true });
      async function capture(name, selector) {
        const nodes = page.locator(selector);
        await nodes.first().waitFor({ state: "visible" });
        await nodes.last().scrollIntoViewIfNeeded();
        await page.screenshot(out ? { path: `${out}/${viewport.width}-${name}.png` } : {});
        results.push(...await nodes.evaluateAll((elements) => elements.map((node) => {
          const style = getComputedStyle(node);
          const range = document.createRange(); range.selectNodeContents(node);
          const text = range.getBoundingClientRect();
          const box = node.getBoundingClientRect();
          return { text: node.textContent, selector: node.className,
            clipped: node.scrollHeight > node.clientHeight + 1 || node.scrollWidth > node.clientWidth + 1
              || text.bottom > box.bottom + 1 || text.right > box.right + 1,
            clamp: style.webkitLineClamp, whiteSpace: style.whiteSpace,
            client: [node.clientWidth, node.clientHeight], scroll: [node.scrollWidth, node.scrollHeight],
            box: [box.right, box.bottom], textBox: [text.right, text.bottom] };
        })));
        assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), `${name}: viewport fits`);
      }
      await page.goto(origin);
      await page.waitForFunction(() => Boolean(window.fixture));
      await page.locator("#setup-sheet-later").click();
      await page.locator("#clock").click();
      assert.equal(await page.locator(".notification-center-item-title").textContent(), "Save your Recovery Kit");
      await capture("recovery", ".notification-center-item-title, .notification-center-item-body");
      await page.locator(".notification-center-item").click();
      await page.locator("#setup-sheet-later").waitFor({ state: "visible" });
      await page.locator("#setup-sheet-later").click();
      await page.evaluate((entry) => window.fixture.notifications.recordNotifications({ notifications: { entries: [entry] } }), entry);
      await page.locator("#clock").click();
      await capture("history", ".notification-center-item-title, .notification-center-item-body");
      await page.locator("#clock").click();
      await page.evaluate(() => window.fixture.surface.maybeShowInboxRequestToast(
        { notifications: { entries: [] } },
        { targets: [{ target: 'inbox' }], notifications: { entries: [{ id: 'toast', kind: 'community_presence_request', action_ref: { action_id: 'review' } }] } }
      ));
      await capture("toast", "#home-notification-title, #home-notification-body");
      await page.locator("#home-notification-dismiss").click();
      assert(await page.locator("#home-notification-toast").isHidden(), "toast can be dismissed");
      for (const presentation of ["rail", "window"]) {
        await page.goto(`${origin}/apps/inbox/?presentation=${presentation}#home_token=fixture`);
        await capture(`inbox-${presentation}`, ".entry-row-title, .entry-row-snippet");
        if (presentation === "window") assert.equal(await page.locator(".entry-body").textContent(), entry.body);
      }
      assert.deepEqual(errors, [], "real capsule modules run without errors");
      if (out) writeFileSync(`${out}/${viewport.width}-measurements.json`, JSON.stringify(results, null, 2));
      const cut = results.filter((result) => result.clipped || result.clamp !== "none" || result.whiteSpace === "nowrap");
      if (sourceRef) assert(cut.some((result) => result.clipped), "comparison source reproduces clipped text");
      else assert.deepEqual(cut, [], "all notification text wraps without clipping or clamping");
    });
  }
}
