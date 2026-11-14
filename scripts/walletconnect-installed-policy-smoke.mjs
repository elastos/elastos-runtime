#!/usr/bin/env node
// Exercise default installation through the signed Home, Wallet and Marketplace APIs.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { createWriteStream } from "node:fs";
import { access, chmod, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import { dirname, join, resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { importProductSmokePlaywright, productSmokeLaunchOptions } from "./product-smoke-browser.mjs";

const [binary, dataArgument, homeArgument] = process.argv.slice(2);
assert(binary && dataArgument && homeArgument, "runtime, isolated data and Home required");
const data = resolve(dataArgument), home = resolve(homeArgument);
const capsule = join(data, "capsules/wallet-walletconnect");
for (const file of ["capsule.json", "browser/index.html", "vendor/adapter.json", "vendor/reown-appkit.js"]) {
  await access(join(capsule, file));
}
const config = join(data, "ElastOS/SystemServices/WalletConnect/config.json");
await assert.rejects(access(config), { code: "ENOENT" }, "default Home has no operator project");
await assert.rejects(access(join(capsule, "vendor/connector.json")), { code: "ENOENT" });
const listener = createServer();
await new Promise(resolve => listener.listen(0, "127.0.0.1", resolve));
const port = listener.address().port;
await new Promise(resolve => listener.close(resolve));
const base = `http://localhost:${port}`;
const env = { ...process.env, HOME: home, XDG_DATA_HOME: dirname(data), ELASTOS_DATA_DIR: data,
  ELASTOS_COLLABORATION_STARTUP_MODE: "isolated" };
delete env.ELASTOS_WALLETCONNECT_PROJECT_FILE;
delete env.ELASTOS_WALLETCONNECT_PROJECT_ID;
const log = createWriteStream(join(home, "walletconnect-installed-policy.log"), { mode: 0o600 });
const runtime = spawn(binary, ["serve", "--addr", `127.0.0.1:${port}`], { env, stdio: ["ignore", log, log] });
const stopped = new Promise(resolve => runtime.once("exit", resolve));
let browser;
const project = join(home, "walletconnect-test-project");
try {
  const deadline = Date.now() + 60000;
  for (;;) {
    assert(runtime.exitCode === null, "owned Runtime remains running");
    try { if ((await fetch(`${base}/api/health`, { signal: AbortSignal.timeout(1000) })).ok) break; } catch {}
    assert(Date.now() < deadline, "owned Runtime reaches health readiness");
    await delay(100);
  }
  const { chromium } = await importProductSmokePlaywright();
  browser = await chromium.launch({ headless: true, ...productSmokeLaunchOptions() });
  const context = await browser.newContext();
  const page = await context.newPage();
  let homeToken;
  page.on("request", request => {
    if (request.frame() === page.mainFrame() && new URL(request.url()).pathname === "/api/apps/home/launch") {
      homeToken = request.headers()["x-elastos-home-token"];
    }
  });
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", { options: {
    protocol: "ctap2", transport: "internal", hasResidentKey: true,
    hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true,
  } });
  assert((await page.goto(`${base}/home/`)).ok());
  await page.locator("#home-unlock-name").fill("Connector install fixture");
  const registered = page.waitForResponse(response => response.url().endsWith("/api/auth/passkey/register/complete"));
  await page.locator("#home-unlock-primary").click();
  assert((await registered).ok(), "isolated owner registers through Home");
  await page.frameLocator("#active-shell-frame").locator("#desktop").waitFor({ state: "visible", timeout: 60000 });
  assert(homeToken, "Home carries its signed launch authority");
  async function api(path, token, body, frame = page) {
    return frame.evaluate(async ({ path, token, body }) => {
      const response = await fetch(path, {
        method: body ? "POST" : "GET",
        headers: { "content-type": "application/json", "x-elastos-home-token": token },
        body: body ? JSON.stringify(body) : undefined, signal: AbortSignal.timeout(30000),
      });
      return { status: response.status, body: await response.json() };
    }, { path, token, body });
  }
  async function launch(target) {
    return api("/api/apps/home/launch", homeToken, { target, query: { home_origin: base } });
  }
  async function appToken(target) {
    const response = await launch(target);
    assert.equal(response.status, 200, `${target} launches`);
    const token = new URLSearchParams(new URL(response.body.route, base).hash.slice(1)).get("home_token");
    assert(token, `${target} has capsule authority`);
    // Capsules own opaque origins. Fetch their projections from a real sandboxed
    // frame with the route and authority returned by Home's launch surface.
    await page.evaluate(({ route, target }) => {
      const iframe = document.createElement("iframe");
      iframe.id = `installed-policy-${target}`;
      iframe.sandbox = "allow-scripts allow-forms";
      iframe.src = route;
      document.body.append(iframe);
    }, { route: response.body.route, target });
    const frame = await (await page.locator(`#installed-policy-${target}`).elementHandle()).contentFrame();
    await frame.waitForURL(url => url.pathname.startsWith(`/apps/${target}/`));
    return { token, frame };
  }
  const wallet = await appToken("wallet"), marketplace = await appToken("marketplace");
  async function policy(configured) {
    const summary = await api("/api/apps/wallet/wallet/summary", wallet.token, undefined, wallet.frame);
    assert.equal(summary.status, 200, "Wallet summary responds");
    assert.equal(summary.body.approval_methods.walletconnect.available, configured, "Wallet offers only configured connector");
    const catalog = await api("/api/capsules/catalog", marketplace.token, undefined, marketplace.frame);
    assert.equal(catalog.status, 200, "Marketplace catalog responds");
    const row = catalog.body.capsules.find(row => row.name === "wallet-walletconnect");
    assert.equal(Boolean(row?.launchable), configured, "Marketplace offers only configured connector");
    if (!configured) assert.equal(row, undefined, "unconfigured connector stays hidden");
    const launched = await launch("wallet-walletconnect");
    assert.equal(launched.status === 200, configured, "Home launches only configured connector");
    if (!configured) assert(launched.status >= 400 && launched.status < 500, "Home refuses unconfigured launch");
  }
  await policy(false);
  // A disposable project file exercises operator configuration without relay access.
  await writeFile(project, "installed-policy-fixture", { flag: "wx", mode: 0o600 });
  const adapter = JSON.parse(await readFile(join(capsule, "vendor/adapter.json"), "utf8"));
  assert.equal(adapter.sdk_sha256, createHash("sha256").update(await readFile(join(capsule, "vendor/reown-appkit.js"))).digest("hex"));
  await mkdir(dirname(config), { recursive: true, mode: 0o700 });
  await chmod(dirname(config), 0o700);
  await writeFile(config, JSON.stringify({ schema: "elastos.walletconnect.connector/v1",
    project_id: (await readFile(project, "utf8")).trim(), sdk_package: adapter.sdk_package,
    sdk_version: adapter.sdk_version, sdk_sha256: adapter.sdk_sha256 }), { flag: "wx", mode: 0o600 });
  await policy(true);
  console.log("WalletConnect installed policy PASS: installed; unconfigured hidden and refused; configured offered and launchable");
} finally {
  await browser?.close();
  runtime.kill("SIGTERM");
  const timeout = setTimeout(() => runtime.kill("SIGKILL"), 10000);
  await stopped; clearTimeout(timeout); log.end();
  await rm(project, { force: true });
  await rm(config, { force: true });
}
