import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire, registerHooks } from "node:module";
import test from "node:test";
import { requireProductSmokePlaywright, productSmokeLaunchOptions, playwrightCoreDir } from "./product-smoke-browser.mjs";

// Import the complete smoke with its CLI entry disabled, as in the host tests.
// Keep its helpers and their dependencies together instead of extracting code.
const smokeURL = new URL("./home-passkey-virtual-auth-smoke.mjs", import.meta.url).href;
const playwrightPath = createRequire(import.meta.url).resolve(playwrightCoreDir());
const previousProfile = process.env.HOME_VIRTUAL_AUTH_PROFILE;
process.env.HOME_VIRTUAL_AUTH_PROFILE = "unused-signed-out-test-profile";
const hooks = registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier === "playwright") {
      return nextResolve(playwrightPath, context);
    }
    return nextResolve(specifier, context);
  },
  load(url, context, nextLoad) {
    const loaded = nextLoad(url, context);
    if (url !== smokeURL) return loaded;
    assert.ok(String(loaded.source).includes("try { await main(); }"));
    return { ...loaded, source: String(loaded.source).replace("try { await main(); }", "try { /* CLI disabled in fixture */ }")
      + "\nexport { homeState, assertSignedOutShell };\n" };
  },
});
const { homeState, assertSignedOutShell } = await import(smokeURL);
hooks.deregister();
if (previousProfile === undefined) delete process.env.HOME_VIRTUAL_AUTH_PROFILE;
else process.env.HOME_VIRTUAL_AUTH_PROFILE = previousProfile;

test("passkey smoke accepts empty signed-out documents and rejects a mounted shell in Chromium", { timeout: 30_000 }, async () => {
  const browser = await requireProductSmokePlaywright().chromium.launch({ headless: true, ...productSmokeLaunchOptions() });
  try {
    const page = await browser.newPage();
    const errors = [], launches = [];
    page.on("pageerror", error => errors.push(error.message));
    await page.route("**/*", async route => {
      const url = new URL(route.request().url());
      assert.equal(url.origin, "https://signed-out.test");
      if (url.pathname === "/apps/home-gui/wallpaper.webp") return route.fulfill({ contentType: "image/webp",
        body: readFileSync(new URL("../capsules/home-gui/browser/wallpaper.webp", import.meta.url)) });
      if (url.pathname === "/api/auth/sessions/refresh") return route.fulfill({ status: 401, json: { error: "sign in required" } });
      if (url.pathname === "/api/apps/home/summary") return route.fulfill({ json: { authority: { signed_in: false }, targets: [] } });
      if (url.pathname === "/api/auth/passkey/status") return route.fulfill({ json: { registered: true } });
      if (url.pathname.startsWith("/api/")) {
        launches.push(url.pathname);
        return route.fulfill({ status: 500, json: { error: "unexpected request" } });
      }
      assert.ok(url.pathname.startsWith("/apps/home/"), url.pathname);
      const path = url.pathname.slice("/apps/home/".length);
      assert.ok(!path.includes(".."));
      const contentType = path.endsWith(".js") || path.endsWith(".mjs") ? "text/javascript"
        : path.endsWith(".css") ? "text/css" : path.endsWith(".html") ? "text/html"
        : path.endsWith(".svg") ? "image/svg+xml" : "application/octet-stream";
      return route.fulfill({ contentType, body: readFileSync(new URL(`../capsules/home/browser/${path}`, import.meta.url)) });
    });
    await page.goto("https://signed-out.test/apps/home/index.html");
    await page.waitForFunction(() => document.body.dataset.homeStatus === "ready" && document.body.dataset.homeGui === "dormant");
    const iframe = page.locator("#active-shell-frame");
    assert.equal(await iframe.getAttribute("src"), null, "cold signed-out host keeps src absent");
    for (const source of [null, "", "about:blank"]) {
      await iframe.evaluate((element, value) => {
        if (value === null) element.removeAttribute("src");
        else element.setAttribute("src", value);
      }, source);
      await assertSignedOutShell(page, await homeState(page));
    }
    assert.deepEqual(launches, [], "signed-out Home launches no shell");
    assert.deepEqual(errors, []);

    await iframe.evaluate(element => { element.dataset.route = "/apps/home-gui/#home_token=stale"; });
    let state = await homeState(page);
    await assert.rejects(() => assertSignedOutShell(page, state), /remained mounted/);
    await iframe.evaluate(element => { element.dataset.route = ""; element.srcdoc = "<script>setInterval(() => {}, 10)</script>"; });
    state = await homeState(page);
    await assert.rejects(() => assertSignedOutShell(page, state), /remained mounted/);
    await iframe.evaluate(element => element.removeAttribute("srcdoc"));
    state = await homeState(page);
    await assertSignedOutShell(page, state);
    const frame = await (await iframe.elementHandle()).contentFrame();
    await frame.evaluate(() => { document.body.textContent = "shell still mounted"; });
    await assert.rejects(() => assertSignedOutShell(page, state), /Timeout/);
  } finally {
    await browser.close();
  }
});
