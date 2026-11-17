import { readFile, mkdir } from "node:fs/promises";
import { extname } from "node:path";
import { pathToFileURL } from "node:url";
import { productSmokeLaunchOptions, requireProductSmokePlaywright } from "../product-smoke-browser.mjs";

export const packets = JSON.parse(await readFile(new URL("../fixtures/wallet-connector-v2-messages.json", import.meta.url)));
const root = process.env.WALLET_RUNTIME_SOURCE ? pathToFileURL(`${process.env.WALLET_RUNTIME_SOURCE}/`) : new URL("../../", import.meta.url);
const types = { ".js": "text/javascript", ".mjs": "text/javascript", ".css": "text/css", ".html": "text/html", ".png": "image/png", ".woff2": "font/woff2", ".svg": "image/svg+xml" };

// Serve the real capsule files. The fixture supplies only Runtime HTTP and
// Home's existing passkey reply; it does not implement a capsule renderer.
export async function runtimeView(t, app, state = {}) {
  const { chromium } = requireProductSmokePlaywright();
  const browser = await chromium.launch({ ...productSmokeLaunchOptions(), headless: true });
  const context = await browser.newContext({ viewport: { width: 1040, height: 682 } });
  const calls = [];
  const errors = [];
  state.entries ||= [];
  state.approvals ||= [];
  state.accounts ||= [];
  state.permission ||= "off";
  state.cleanup ??= state.permission === "cleanup";
  state.question ||= "consent:current";
  const question = () => ({ id: state.question, resource: "elastos://walletconnect/internet", issued_at: Math.floor(Date.now() / 1000), text: "WalletConnect internet access" });
  await context.route("https://runtime.test/**", async route => {
    const request = route.request(), url = new URL(request.url());
    const json = (body, status = 200) => route.fulfill({ status, contentType: "application/json", headers: { "access-control-allow-origin": "*" }, body: JSON.stringify(body) });
    if (request.method() === "OPTIONS") return json({});
    if (url.pathname === "/") return route.fulfill({ contentType: "text/html", body: `<!doctype html><style>html,body,iframe{margin:0;width:100%;height:100%;border:0}</style><iframe id="app" src="/apps/${app}/index.html?home_origin=https%3A%2F%2Fruntime.test&wallet_request=${encodeURIComponent(state.requestId || "")}#home_token=fixture-token"></iframe><script>window.messages=[];addEventListener('message',e=>{messages.push(e.data);if(e.data.type==='elastos.home.passkey-step-up.request/v1')e.source.postMessage({type:'elastos.home.passkey-step-up.result/v1',requestId:e.data.requestId,stepUpToken:'fixture-proof'},'*')})</script>` });
    if (url.pathname.startsWith("/api/")) {
      const input = request.postDataJSON();
      calls.push({ path: url.pathname, method: request.method(), input });
      if (url.pathname === "/api/apps/inbox/summary") return json({ notifications: { entries: state.entries, attention_count: state.entries.filter(e => e.severity === "attention").length, unread_count: state.entries.filter(e => !e.read).length } });
      if (url.pathname === "/api/apps/wallet/wallet/summary") return json({ wallet_accounts: { accounts: state.accounts, default_accounts: [] }, wallet_approvals: { approval_requests: state.approvals }, approval_methods: { walletconnect: { available: true } } });
      if (url.pathname === "/api/apps/wallet-walletconnect/internet") {
        if (input?.action === "request") {
          if (state.guest) return json({ error: "owner required" }, 403);
          if (state.cleanup) return json({ error: "cleanup required" }, 409);
          state.permission = "requested";
        }
        return json({ status: state.permission === "cleanup" ? "revoked" : state.permission, request: ["requested", "granted"].includes(state.permission) ? question() : null });
      }
      if (url.pathname === "/api/apps/inbox/actions") {
        if (state.conflict) return json({ schema: "elastos.home.wallet-connector.effect.error/v1", code: "conflict" }, 409);
        if (input.action_id?.startsWith("walletconnect-internet-allow:")) {
          if (state.permission !== "requested" || input.action_id !== `walletconnect-internet-allow:${state.question}` || input.step_up_token !== "fixture-proof") return json({ schema: "elastos.home.wallet-connector.effect.error/v1", code: "conflict" }, 409);
          state.permission = "granted";
          state.entries = [permissionEntry("granted", state.question)];
        } else if (input.action_id?.startsWith("walletconnect-internet-turn-off:")) {
          if (!["granted", "cleanup"].includes(state.permission) || input.action_id !== `walletconnect-internet-turn-off:${state.question}`) return json({ schema: "elastos.home.wallet-connector.effect.error/v1", code: "conflict" }, 409);
          if (state.cleanupFailure) return json({ error: "cleanup could not finish" }, 503);
          state.permission = "revoked";
          state.cleanup = false;
          state.entries = [permissionEntry("revoked", state.question)];
        } else if (input.action_id?.startsWith("wallet-reject-request:")) {
          state.entries = state.entries.filter(e => !e.id.endsWith(input.action_id.slice("wallet-reject-request:".length)));
        }
        return json({});
      }
      if (url.pathname.endsWith("/reject")) {
        const id = decodeURIComponent(url.pathname.split("/").at(-2));
        const current = state.approvals.find(r => r.request_id === id);
        if (!current) return json({ error: "request unavailable" }, 404);
        const dismissed = current.status === "approved" && current.connector_id === "wallet-walletconnect" && current.intent === "transaction_intent";
        current.status = "rejected";
        return json({ receipt_status: dismissed ? "dismissed" : null });
      }
      if (url.pathname === "/api/wallet/prices") return json({ prices: {}, unavailable: true });
      if (url.pathname === "/api/provider/chain/balance") return json({ status: "unavailable" });
      if (url.pathname === "/api/apps/inbox/notifications/read") return json({});
      errors.push(`Unhandled fixture route: ${request.method()} ${url.pathname}`);
      return json({ error: "unsupported fixture route" }, 501);
    }
    const match = url.pathname.match(/^\/apps\/([^/]+)\/(.*)$/);
    if (!match || match[2].split("/").includes("..")) return route.abort();
    try {
      const file = new URL(`capsules/${match[1]}/browser/${match[2]}`, root);
      await route.fulfill({ body: await readFile(file), contentType: types[extname(file.pathname)] || "application/octet-stream" });
    } catch { await route.fulfill({ status: 404, body: "missing fixture asset" }); }
  });
  const page = await context.newPage();
  page.setDefaultTimeout(5000);
  page.on("pageerror", e => errors.push(e.message));
  t.after(async () => {
    if (errors.length) t.diagnostic(JSON.stringify({ errors, calls: calls.map(c => `${c.method} ${c.path}`) }));
    await browser.close();
  });
  await page.goto("https://runtime.test/");
  const frame = page.frameLocator("#app");
  await frame.locator(app === "inbox" ? "#inbox-shell" : ".wallet-shell").waitFor();
  return { page, frame, calls, state, errors, async capture(name) {
    if (!process.env.WALLET_RUNTIME_SCREENS) return;
    await mkdir(process.env.WALLET_RUNTIME_SCREENS, { recursive: true });
    await frame.locator("html").evaluate(() => window.elastosTheme.set("light"));
    await page.screenshot({ path: `${process.env.WALLET_RUNTIME_SCREENS}/${name}` });
    await frame.locator("html").evaluate(() => window.elastosTheme.set("dark"));
    await page.screenshot({ path: `${process.env.WALLET_RUNTIME_SCREENS}/${name.replace("-light-", "-dark-")}` });
  } };
}

export function permissionEntry(status, id = "consent:current") {
  const asked = status === "requested";
  return { id: "walletconnect-internet:permission", source_app: "wallet-walletconnect", kind: `walletconnect_internet_${asked ? "request" : "decision"}`, title: asked ? "Allow WalletConnect to use the internet?" : "WalletConnect internet access", body: ({ requested: "WalletConnect uses the internet to connect your wallet app. The service that carries messages can see this computer's internet address. Your keys stay in your wallet, where you approve each request. You can turn this off at any time in Inbox.", granted: "WalletConnect can use the internet.", refused: "You chose Don't Allow. Allow access when you want to connect.", revoked: "Internet access is off.", expired: "This access question expired. You can allow access now.", cleanup: "Internet access is off. A saved connection still needs to be removed." })[status], severity: asked ? "attention" : "info", read: !asked, created_at: Math.floor(Date.now() / 1000), action_ref: asked ? { action_id: `walletconnect-internet-allow:${id}` } : ["granted", "cleanup"].includes(status) ? { action_id: `walletconnect-internet-turn-off:${id}` } : null };
}
