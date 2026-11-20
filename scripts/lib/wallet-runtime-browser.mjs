import { readFile, mkdir, writeFile, readdir } from "node:fs/promises";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { extname } from "node:path";
import { pathToFileURL } from "node:url";
import { productSmokeLaunchOptions, requireProductSmokePlaywright } from "../product-smoke-browser.mjs";

export const packets = JSON.parse(await readFile(new URL("../fixtures/wallet-connector-v2-messages.json", import.meta.url)));
const root = process.env.WALLET_RUNTIME_SOURCE ? pathToFileURL(`${process.env.WALLET_RUNTIME_SOURCE}/`) : new URL("../../", import.meta.url);
const proofHead = process.env.WALLET_RUNTIME_SCREENS ? execFileSync("git", ["rev-parse", "HEAD"], { cwd:root, encoding:"utf8" }).trim() : null;
function checkProofSource() {
  if (proofHead && (execFileSync("git", ["rev-parse", "HEAD"], { cwd:root, encoding:"utf8" }).trim() !== proofHead
    || execFileSync("git", ["status", "--porcelain"], { cwd:root, encoding:"utf8" }).trim())) throw new Error("Source changed during rendered proof");
}
const types = { ".js": "text/javascript", ".mjs": "text/javascript", ".css": "text/css", ".html": "text/html", ".png": "image/png", ".woff2": "font/woff2", ".svg": "image/svg+xml" };
const consentText = "WalletConnect needs internet access to connect your wallet to this Home. The WalletConnect service carries the messages and can see this computer's internet address. Your keys stay in your wallet, where you approve each request. You can turn this off at any time in Inbox.";

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
  state.accounts ||= [...new Map(state.approvals.filter(r => r.status === "pending" || r.status === "approved").map(r => [r.account_id, {
    account_id:r.account_id, chain_namespace:r.chain_namespace, address:r.address, proof_type:r.proof_type, connector_id:r.connector_id,
    linked_at:Math.floor(Date.now()/1000), signing_available:true, signing_status:r.proof_type?.startsWith("managed_") ? "managed_key_available" : "external_connector_available",
  }])).values()];
  state.entries = state.entries.map(e => ({ created_at:Math.floor(Date.now()/1000), ...e,
    action_ref:e.action_ref ? { app:e.kind === "wallet_approval_request" ? "wallet" : "inbox", ...e.action_ref } : null }));
  if (app === "wallet") state.accounts = state.accounts.map(a => ({ linked_at:Math.floor(Date.now()/1000), signing_available:true,
    signing_status:a.proof_type?.startsWith("managed_") ? "managed_key_available" : "external_connector_available", ...a }));
  state.permission ||= "off";
  state.cleanup ??= state.permission === "cleanup";
  state.question ||= "consent:current";
  state.issuedAt ||= Math.floor(Date.now() / 1000);
  const question = () => ({ id: state.question, resource: "elastos://walletconnect/internet", issued_at: state.issuedAt,
    text: state.permission === "granted" ? "Stop WalletConnect relay access on this computer." : consentText });
  await context.route("https://runtime.test/**", async route => {
    const request = route.request(), url = new URL(request.url());
    const cors = { "access-control-allow-origin": "*", "access-control-allow-headers":"content-type,x-elastos-home-token", "access-control-allow-methods":"GET,POST,PUT,DELETE,OPTIONS" };
    const json = (body, status = 200) => route.fulfill({ status, contentType: "application/json", headers: cors, body: JSON.stringify(body) });
    const plain = (body, status) => route.fulfill({ status, contentType:"text/plain", headers:cors, body });
    if (request.method() === "OPTIONS") return json({});
    if (url.pathname === "/") return route.fulfill({ contentType: "text/html", body: `<!doctype html><style>html,body,iframe{margin:0;width:100%;height:100%;border:0}</style><iframe id="app" sandbox="allow-scripts allow-forms" src="/apps/${app}/index.html?home_origin=https%3A%2F%2Fruntime.test&notification_id=${encodeURIComponent(state.notificationId || "")}&presentation=${encodeURIComponent(state.presentation || 'window')}&wallet_request=${encodeURIComponent(state.requestId || "")}#home_token=fixture-token"></iframe><script>const fixturePasskeyError=${JSON.stringify(state.passkeyError || "")};window.messages=[];addEventListener('message',e=>{if(e.source!==document.getElementById('app')?.contentWindow||e.origin!=='null')return;messages.push(e.data);if(e.data.type==='elastos.home.passkey-step-up.request/v1')e.source.postMessage({type:'elastos.home.passkey-step-up.result/v1',requestId:e.data.requestId,...(fixturePasskeyError?{error:fixturePasskeyError}:{stepUpToken:'fixture-proof'})},'*')})</script>` });
    if (url.pathname.startsWith("/api/")) {
      if (request.headers()["x-elastos-home-token"] !== "fixture-token") return json({error:"missing fixture launch"}, 403);
      const input = request.postDataJSON();
      calls.push({ path: url.pathname, method: request.method(), input });
      if (url.pathname === "/api/apps/inbox/summary" && state.conflictSeen && state.summaryFailureAfterConflict) return route.abort("failed");
      if (url.pathname === "/api/apps/inbox/summary") {
        const snapshot = { notifications: { entries: structuredClone(state.entries), attention_count: state.entries.filter(e => e.severity === "attention").length, unread_count: state.entries.filter(e => !e.read).length } };
        if (state.beforeInboxSummary) await state.beforeInboxSummary();
        return json(snapshot);
      }
      if (url.pathname === "/api/apps/wallet/wallet/summary" && (state.approvalsUnavailable || state.decisionComplete && state.summaryFailureAfterDecision === "unavailable")) return json({ wallet_accounts:{available:true, accounts:state.accounts, default_accounts:[]}, wallet_approvals:{available:false, pending_count:0, approval_requests:[], note:"Wallet requests are unavailable."}, approval_methods:{} });
      if (url.pathname === "/api/apps/wallet/wallet/summary" && state.decisionComplete && state.summaryFailureAfterDecision) return route.abort("failed");
      if (url.pathname === "/api/apps/wallet/wallet/summary") return json({ wallet_accounts: { available:true, accounts: state.accounts, default_accounts: [] }, wallet_approvals: { available:true, pending_count:state.approvals.filter(r => r.status === "pending").length, approval_requests: state.approvals }, approval_methods: { walletconnect: { available: true } } });
      if (url.pathname === "/api/apps/wallet-walletconnect/internet") {
        if (input?.action === "request") {
          if (state.cleanup) return plain("Finish clearing the previous WalletConnect session in Inbox first.", 500);
          if (!["requested", "granted"].includes(state.permission)) {
            if (state.guest) return plain("Ask an admin of this Home to open WalletConnect, choose Connect wallet, then allow internet access in Inbox.", 500);
            state.question = "consent:new";
            state.issuedAt = Math.floor(Date.now() / 1000);
            state.permission = "requested";
          }
        }
        return json({ status: state.permission === "cleanup" ? "revoked" : state.permission === "expired" ? "requested" : state.permission,
          request: ["requested", "granted"].includes(state.permission) ? question() : null });
      }
      if (url.pathname === "/api/apps/inbox/actions") {
        if (state.conflict) { state.conflictSeen = true; return json({ schema: "elastos.home.wallet-connector.effect.error/v1", code: "conflict" }, 409); }
        let message = "Saved.";
        if (input.action_id?.startsWith("walletconnect-internet-allow:")) {
          if (state.permission !== "requested" || input.action_id !== `walletconnect-internet-allow:${state.question}`) return json({ schema: "elastos.home.wallet-connector.effect.error/v1", code: "conflict" }, 409);
          if (input.step_up_token !== "fixture-proof") return plain(input.step_up_token ? "invalid passkey step-up token encoding" : "missing passkey step-up token", 403);
          state.permission = "granted";
          state.entries = [permissionEntry("granted", state.question)];
        } else if (input.action_id?.startsWith("walletconnect-internet-deny:")) {
          if (state.permission !== "requested" || input.action_id !== `walletconnect-internet-deny:${state.question}`) return json({ schema: "elastos.home.wallet-connector.effect.error/v1", code: "conflict" }, 409);
          state.permission = "refused";
          state.entries = [permissionEntry("refused", state.question)];
        } else if (input.action_id?.startsWith("walletconnect-internet-turn-off:")) {
          if (!["granted", "cleanup"].includes(state.permission) || input.action_id !== `walletconnect-internet-turn-off:${state.question}`) return json({ schema: "elastos.home.wallet-connector.effect.error/v1", code: "conflict" }, 409);
          if (state.permission === "granted" && input.step_up_token !== "fixture-proof") return plain(input.step_up_token ? "invalid passkey step-up token encoding" : "missing passkey step-up token", 403);
          state.permission = "cleanup";
          state.cleanup = true;
          state.entries = [permissionEntry("cleanup", state.question)];
          if (state.cleanupFailure) return plain("cleanup could not finish", 500);
          state.permission = "revoked";
          state.cleanup = false;
          state.entries = [permissionEntry("revoked", state.question)];
          message = "Internet access for WalletConnect is off.";
        } else if (input.action_id?.startsWith("wallet-reject-request:")) {
          const id = `wallet-approval-request:${input.action_id.slice("wallet-reject-request:".length)}`;
          if (!state.entries.some(e => e.id === id)) return json({ error:"request unavailable" }, 404);
          state.entries = state.entries.filter(e => e.id !== id);
          message = "Request rejected.";
        } else if (input.action_id?.startsWith("notification-read:")) {
          // Generated permission entries have no persisted notification row.
          message = "That inbox entry was already read or is no longer present.";
        } else {
          errors.push(`Unhandled fixture Inbox action: ${input.action_id}`);
          return json({ error:"unsupported fixture action" }, 501);
        }
        return json({ message });
      }
      if (url.pathname.endsWith("/reject")) {
        const id = decodeURIComponent(url.pathname.split("/").at(-2));
        const current = state.approvals.find(r => r.request_id === id);
        if (!current) return json({ error: "request unavailable" }, 404);
        const dismissed = current.status === "approved" && current.connector_id === "wallet-walletconnect" && current.intent === "transaction_intent";
        current.status = "rejected";
        state.decisionComplete = true;
        const pending = state.approvals.filter(r => r.status === "pending");
        return json({ available:true, pending_count:pending.length, approval_requests:pending,
          ...(dismissed ? { receipt_status:"dismissed", note:"Request dismissed. This does not cancel a transaction in your wallet. Check your wallet before sending again." } : {}) });
      }
      if (url.pathname === "/api/wallet/prices") return json({ prices: {}, unavailable: true });
      if (url.pathname === "/api/provider/chain/balance") return json(state.balance ? { status:"ok", data:{balance_hex:"0xde0b6b3a7640000"} } : { status: "unavailable" });
      if (url.pathname === "/api/apps/inbox/notifications/read") return json({});
      errors.push(`Unhandled fixture route: ${request.method()} ${url.pathname}`);
      return json({ error: "unsupported fixture route" }, 501);
    }
    const match = url.pathname.match(/^\/apps\/([^/]+)\/(.*)$/);
    if (!match || match[2].split("/").includes("..")) return route.abort();
    try {
      const file = new URL(`capsules/${match[1]}/browser/${match[2]}`, root);
      await route.fulfill({ body: await readFile(file), headers:cors, contentType: types[extname(file.pathname)] || "application/octet-stream" });
    } catch { errors.push(`Missing fixture asset: ${url.pathname}`); await route.fulfill({ status: 404, body: "missing fixture asset" }); }
  });
  const page = await context.newPage();
  page.setDefaultTimeout(5000);
  page.on("pageerror", e => errors.push(e.message));
  t.after(async () => {
    if (errors.length) t.diagnostic(JSON.stringify({ errors, calls: calls.map(c => `${c.method} ${c.path}`) }));
    await browser.close();
    if (errors.length) throw new Error(`Unexpected Runtime fixture calls: ${errors.join("; ")}`);
  });
  await page.goto("https://runtime.test/");
  const frame = page.frameLocator("#app");
  await frame.locator(app === "inbox" ? "#inbox-shell" : ".wallet-shell").waitFor();
  return { page, frame, calls, state, errors, async capture(name) {
    if (!process.env.WALLET_RUNTIME_SCREENS) return;
    checkProofSource();
    if (app === "inbox") await frame.locator("#refresh:enabled").waitFor();
    await mkdir(process.env.WALLET_RUNTIME_SCREENS, { recursive: true });
    const files = {};
    const directory = new URL(`capsules/${app}/browser/`, root);
    for (const file of await readdir(directory, { recursive: true, withFileTypes: true })) {
      if (!file.isFile()) continue;
      const path = `${file.parentPath}/${file.name}`;
      files[path] = createHash("sha256").update(await readFile(path)).digest("hex");
    }
    const receiptPath = `${process.env.WALLET_RUNTIME_SCREENS}/receipt.json`;
    let receipt = { screens: {} };
    try { receipt = JSON.parse(await readFile(receiptPath, "utf8")); } catch (_) {}
    for (const theme of ["light", "dark"]) {
      await frame.locator("html").evaluate((_, theme) => window.elastosTheme.set(theme), theme);
      const facts = await frame.locator("html").evaluate(async () => {
        await document.fonts.ready;
        await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
        const finite = () => document.getAnimations().filter(a => a.effect?.getTiming().iterations !== Infinity && a.playState === "running");
        let timer;
        try {
          await Promise.race([
            Promise.all(finite().map(a => a.finished.catch(() => {}))),
            new Promise((_, reject) => { timer = setTimeout(() => reject(new Error("Theme transitions did not settle")), 5000); }),
          ]);
        } finally { clearTimeout(timer); }
        await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
        const running = finite().length;
        if (running) throw new Error("Theme transition still running at capture");
        return { theme:window.elastosTheme.resolved(), width:innerWidth, height:innerHeight, finite_animations:running };
      });
      if (facts.theme !== theme) throw new Error("Screenshot theme does not match its filename");
      const file = name.replace("-light-", `-${theme}-`);
      const bytes = await page.screenshot({ animations: "allow", path: `${process.env.WALLET_RUNTIME_SCREENS}/${file}` });
      receipt.screens[file] = { ...facts, sha256: createHash("sha256").update(bytes).digest("hex"), files,
        commit: execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim(),
        tree: execFileSync("git", ["rev-parse", "HEAD^{tree}"], { cwd: root, encoding: "utf8" }).trim(),
        browser: browser.version(), node: process.version };
    }
    checkProofSource();
    await writeFile(receiptPath, JSON.stringify(receipt, null, 2) + "\n");
  } };
}

export function permissionEntry(status, id = "consent:current") {
  const asked = status === "requested";
  return { id: "walletconnect-internet:permission", source_app: "wallet-walletconnect", kind: `walletconnect_internet_${asked ? "request" : "decision"}`,
    title: "WalletConnect internet access", body: asked ? consentText : status === "granted" ? "WalletConnect can use the internet."
      : status === "cleanup" ? "Internet access for WalletConnect is off. Choose Finish disconnecting to remove the saved connection." : "Internet access for WalletConnect is off.",
    severity: asked ? "attention" : "info", read: !asked, created_at: Math.floor(Date.now() / 1000),
    action_ref: asked ? { app: "inbox", action_id: `walletconnect-internet-allow:${id}` }
      : ["granted", "cleanup"].includes(status) ? { app: "inbox", action_id: `walletconnect-internet-turn-off:${id}` } : null };
}
