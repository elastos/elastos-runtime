#!/usr/bin/env node
import { historicalTestSource } from './lib/historical-test-source.mjs';

import {installSigninProviders, evmAddress, bitcoinAddress} from './lib/wallet-signin-fixture.mjs';
import {windowTestOptions} from './lib/walletconnect-window-resources.mjs';

import { createServer } from "node:http";
import { accessSync, constants, existsSync, mkdirSync, readFileSync } from "node:fs";
import { extname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { importProductSmokePlaywright, productSmokeLaunchOptions } from "./product-smoke-browser.mjs";

const engine = process.env.HOME_WALLET_CONNECTOR_ENGINE || "chromium";
const {skip} = windowTestOptions(engine);
if (skip) console.log(`Home wallet connector launch smoke in ${engine} # SKIP ${skip}`);
else if (process.env.MARKETPLACE_CONNECT_BEFORE === "1") {
  // One isolated regression run checks the pinned source and the candidate.
  let baselineFailed = false;
  try { await runSmoke(); }
  catch (error) {
    if (!String(error.message).includes("Home refuses direct connector targets before sending a GUI launch command")) throw error;
    baselineFailed = true;
    console.log(`[marketplace-connect] baseline FAIL: ${error.message}`);
  }
  if (!baselineFailed) throw new Error("The pinned baseline unexpectedly passed the connector regression");
  delete process.env.MARKETPLACE_CONNECT_BEFORE;
  for (const kind of ["connectors", "connectors-phone", "assistant", ""]) {
    process.env.MARKETPLACE_OPEN_CASE = kind;
    await runSmoke();
  }
}
else if (process.env.WALLET_CONNECT_RETURN === "1") {
  const failures = [];
  const delays = process.env.WALLET_RETURN_SLOW === 'all' ? ['prices','balances','existing-balances'] : [process.env.WALLET_RETURN_SLOW || 'normal'];
  const recoveries = process.env.WALLET_RETURN_RECOVERY === 'all' ? ['summary','approvals'] : [process.env.WALLET_RETURN_RECOVERY || ''];
  for (const marketFailure of recoveries) for (const slowMarket of delays) for (const width of [1440, 390]) {
    try {
      await runSmoke({connectReturn:true,width,slowMarket,marketFailure});
    }
    catch (error) { failures.push(error); console.error(`[wallet-connect-return] FAIL ${engine} ${width} ${marketFailure || slowMarket}: ${error.stack}`); }
  }
  if (failures.length) throw new AggregateError(failures, 'Wallet connection return failed');
} else await runSmoke();

async function runSmoke({connectReturn = false, width = 1440, slowMarket = 'normal', marketFailure = ''} = {}) {
const repoRoot = fileURLToPath(new URL("../", import.meta.url));
const principalId = "did:elastos:fixture-wallet-connector-launch";
const homeAuthorityToken = "fixture-home-authority-token";
const homeGuiToken = "fixture-home-gui-token";
const walletToken = "fixture-wallet-token";
const connectorTokens = Object.freeze({
  "wallet-metamask": "fixture-metamask-token",
  "wallet-unisat": "fixture-unisat-token",
  "wallet-walletconnect": "fixture-walletconnect-token",
});
const connectorTitles = Object.freeze({
  "wallet-metamask": "MetaMask",
  "wallet-unisat": "UniSat",
  "wallet-walletconnect": "WalletConnect",
});
const issuedLaunchTokens = new Map();
const state = {
  launches: {
    "home-gui": 0,
    marketplace: 0,
    assistant: 0,
    wallet: 0,
    "wallet-metamask": 0,
    "wallet-unisat": 0,
    "wallet-walletconnect": 0,
  },
  connectorEffects: 0,
  approvalRequests: [],
  walletAccounts: connectReturn ? [
    {account_id:'fixture-home',address:'0x'+'34'.repeat(20),chain_namespace:'eip155:20',proof_type:'managed_evm',label:'Home address'},
    {account_id:'fixture-bitcoin',address:bitcoinAddress,chain_namespace:'bip122:000000000019d6689c085ae165831e93',proof_type:'bip322_simple',connector_id:'wallet-unisat',wallet_display_name:'UniSat'},
  ] : [],
  walletSummaryReads: 0,
  summaryFailure: false,
  approvalsUnavailable: false,
  balanceHex: marketFailure ? '0xde0b6b3a7640000' : '0x0',
  balanceReads: [],
  holdMarket: '',
  heldMarket: [],
  homeStateWrites: [],
  serverErrors: [],
};

function assert(condition, message, details = undefined) {
  if (condition) {
    return;
  }
  const suffix = details === undefined ? "" : `\n${JSON.stringify(details, null, 2)}`;
  throw new Error(`${message}${suffix}`);
}

function json(res, status, value) {
  const body = JSON.stringify(value);
  res.writeHead(status, {
    "access-control-allow-origin": "*",
    "cache-control": "no-store",
    "content-length": Buffer.byteLength(body),
    "content-type": "application/json; charset=utf-8",
  });
  res.end(body);
}

function empty(res) {
  res.writeHead(204, {
    "access-control-allow-origin": "*",
    "cache-control": "no-store",
  });
  res.end();
}

function contentType(path) {
  return {
    ".css": "text/css; charset=utf-8",
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".mjs": "text/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".png": "image/png",
    ".svg": "image/svg+xml",
    ".webp": "image/webp",
  }[extname(path)] || "application/octet-stream";
}

function staticPath(pathname) {
  const roots = [
    ["/apps/home/", join(repoRoot, "capsules/home/browser")],
    ["/apps/home-gui/", join(repoRoot, "capsules/home-gui/browser")],
    ["/apps/marketplace/", join(repoRoot, "capsules/marketplace/browser")],
    ["/apps/assistant/", join(repoRoot, "capsules/assistant/browser")],
    ["/apps/wallet/", join(repoRoot, "capsules/wallet/browser")],
    ["/apps/wallet-metamask/", join(repoRoot, "capsules/wallet-metamask/browser")],
    ["/apps/wallet-unisat/", join(repoRoot, "capsules/wallet-unisat/browser")],
    ["/apps/wallet-walletconnect/", join(repoRoot, "capsules/wallet-walletconnect/browser")],
  ];
  for (const [prefix, root] of roots) {
    if (!pathname.startsWith(prefix)) {
      continue;
    }
    const suffix = decodeURIComponent(pathname.slice(prefix.length)) || "index.html";
    const candidate = resolve(root, suffix);
    const escaped = relative(root, candidate);
    if (escaped.startsWith(`..${sep}`) || escaped === ".." || isAbsolute(escaped)) {
      return null;
    }
    return candidate;
  }
  return null;
}

async function readBody(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > 1_048_576) {
      throw new Error("fixture request exceeds 1 MiB");
    }
    chunks.push(chunk);
  }
  const text = Buffer.concat(chunks).toString("utf8");
  return text ? JSON.parse(text) : null;
}

function homeSummary() {
  return {
    home: { route: "/apps/home/", attach_kind: "iframe" },
    app: { id: "home", route: "/apps/home/" },
    identity: { id: principalId, display_name: "Connector Fixture" },
    authority: {
      signed_in: true,
      principal_id: principalId,
      proof_binding_id: "fixture-proof-binding",
    },
    active_shell: {
      active: "home-gui",
      candidates: [{
        name: "home-gui",
        title: "Desktop",
        launchable: true,
      }],
    },
    appearance: {
      schema: "elastos.home.appearance/v1", revision: 0, theme: "dark",
      accent: "blue", accent_custom: "#007aff", dock_auto_hide: false,
      sounds: false, focus_mode: false,
    },
    browser_state: {
      schema: "elastos.home.browser-state/v1",
      principal_id: principalId,
      layout: {
        desktop: {},
        // Keep Marketplace on the phone grid, with Wallet in the Dock.
        homeDock: ["wallet"],
        homePages: [["marketplace"]],
        taskbar: [],
        desktopHidden: [],
        desktopIconsVisible: true,
      },
      recent_targets: [],
      session: null,
    },
    runtime: {},
    site: {},
    room: {},
    people: {},
    services: {},
    notifications: [],
    desktop_objects: [],
    capsule_catalog: { capsules: Object.keys(connectorTokens).map(name => ({
      name, launch_target: name, launchable: true,
      window_policy: JSON.parse(readFileSync(join(repoRoot, "capsules", name, "capsule.json"), "utf8")).window_policy,
    })) },
    capsule_interfaces: [],
    targets: [...["marketplace", "assistant"].map(target => ({
      target, title: target === "assistant" ? "Assistant" : "Marketplace", role: "app",
      target_kind: "app", attach_kind: "iframe",
    })), {
      target: "wallet",
      title: "Wallet",
      description: "Private Wallet",
      window_policy: JSON.parse(readFileSync(join(repoRoot,"capsules/wallet/capsule.json"),"utf8")).window_policy,
      role: "app",
      target_kind: "app",
      attach_kind: "iframe",
    }],
  };
}

function launchToken(target) {
  if (target === "home-gui") {
    return homeGuiToken;
  }
  if (target === "wallet") {
    return walletToken;
  }
  return connectorTokens[target] || `fixture-${target}-token`;
}

function launchResponse(origin, target, query) {
  state.launches[target] += 1;
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query || {})) {
    params.set(key, String(value));
  }
  params.set("home_origin", origin);
  const ownerToken = launchToken(target);
  const issuedToken = `${ownerToken}-${state.launches[target]}`;
  issuedLaunchTokens.set(issuedToken, ownerToken);
  return {
    target,
    title: connectorTitles[target] || (target === "home-gui" ? "Desktop" : "Wallet"),
    attach_kind: "iframe",
    launch_status: "launched",
    route:
      `/apps/${target}/?${params.toString()}` +
      `#home_token=${encodeURIComponent(issuedToken)}`,
  };
}

function requireToken(req, token, res) {
  if (req.headers["x-elastos-home-token"] === token || issuedLaunchTokens.get(req.headers["x-elastos-home-token"]) === token) {
    return true;
  }
  json(res, 401, { error: "fixture launch owner rejected" });
  return false;
}

async function handleApi(req, res, url) {
  if (url.pathname === "/api/capsules/catalog" && req.method === "GET") {
    json(res, 200, { capsules: ["assistant", "wallet", ...Object.keys(connectorTitles)].map(name => ({
      name, title: connectorTitles[name] || (name === "wallet" ? "Wallet" : "Assistant"), role: "app", installed: true,
      launchable: true, launch_target: name,
    })) });
    return true;
  }
  if (url.pathname === "/api/capsules/interfaces" && req.method === "GET") {
    json(res, 200, { interfaces: [] });
    return true;
  }
  if (req.method === "OPTIONS") {
    res.writeHead(204, {
      "access-control-allow-headers": "content-type,x-elastos-home-token,if-match",
      "access-control-allow-methods": "GET,POST,OPTIONS",
      "access-control-allow-origin": "*",
    });
    res.end();
    return true;
  }
  if (url.pathname === "/api/auth/sessions/refresh" && req.method === "POST") {
    json(res, 200, { home_token: homeAuthorityToken });
    return true;
  }
  if (url.pathname === "/api/apps/home/summary" && req.method === "GET") {
    json(res, 200, homeSummary());
    return true;
  }
  if (url.pathname === "/api/apps/home/runtime/ensure" && req.method === "POST") {
    json(res, 200, { ready: true });
    return true;
  }
  if (url.pathname === "/api/apps/home/events/stream" && req.method === "GET") {
    empty(res);
    return true;
  }
  if (url.pathname === "/api/apps/home/events" && req.method === "GET") {
    json(res, 200, { events: [], cursor: "" });
    return true;
  }
  if (url.pathname === "/api/apps/home/launch" && req.method === "POST") {
    if (!requireToken(req, homeAuthorityToken, res)) {
      return true;
    }
    const input = await readBody(req);
    const target = typeof input?.target === "string" ? input.target : "";
    if (!Object.hasOwn(state.launches, target)) {
      json(res, 404, { error: "fixture target not found" });
      return true;
    }
    const origin = String(input?.query?.home_origin || "");
    json(res, 200, launchResponse(origin, target, input?.query || {}));
    return true;
  }
  if (url.pathname === "/api/apps/home/state" && req.method === "POST") {
    if (!requireToken(req, homeGuiToken, res)) {
      return true;
    }
    state.homeStateWrites.push(await readBody(req));
    json(res, 200, { saved: true });
    return true;
  }
  if (url.pathname === "/api/apps/wallet/wallet/inventory" && req.method === "GET") {
    if (!requireToken(req,walletToken,res)) return true;
    json(res,200,{schema:'elastos.wallet.inventory/v1',principal_id:'fixture',account_name:'Alex',entries:state.walletAccounts.map(account=>({inventory_id:`${account.chain_namespace}:${account.address.toLowerCase()}`,address:account.address,chain_namespace:account.chain_namespace,accounts:[account],sign_in:null}))});return true;
  }
  if (url.pathname === "/api/apps/wallet/wallet/summary" && req.method === "GET") {
    if (!requireToken(req, walletToken, res)) {
      return true;
    }
    state.walletSummaryReads++;
    if(state.summaryFailure) {json(res,503,{error:'fixture summary unavailable'});return true;}
    json(res, 200, {
      wallet_accounts: { accounts: state.walletAccounts, default_accounts: [] },
      wallet_approvals: { available: !state.approvalsUnavailable, approval_requests: state.approvalRequests },
      approval_methods: { walletconnect: { available: true } },
    });
    return true;
  }
  if (connectReturn && url.pathname === '/api/provider/chain/balance') {
    const input = await readBody(req);
    state.balanceReads.push({address:input.address,network:input.network});
    const value = {status:'ok',data:{balance_hex:state.balanceHex}};
    if (state.holdMarket === 'balances') state.heldMarket.push(()=>json(res,200,value));
    else json(res,200,value);
    return true;
  }
  if (url.pathname === "/api/wallet/prices" && req.method === "GET") {
    if (!requireToken(req, walletToken, res)) {
      return true;
    }
    const value = {prices:{},stale:false,unavailable:false};
    if (state.holdMarket === 'prices') state.heldMarket.push(()=>json(res,200,value));
    else json(res,200,value);
    return true;
  }
  for (const [target, token] of Object.entries(connectorTokens)) {
    if (url.pathname === `/api/apps/${target}/internet` && req.method === "GET") {
      if (!requireToken(req, token, res)) return true;
      json(res, 200, { status: "granted" });
      return true;
    }
    if (target === "wallet-walletconnect" && req.method === "GET" && ["wallet/config", "storage"].some(resource => url.pathname === `/api/apps/${target}/${resource}`)) {
      if (!requireToken(req, token, res)) return true;
      json(res, 200, url.pathname.endsWith("/wallet/config") ? { walletconnect: { project_id: "fixture-project", storage_revision: JSON.stringify("0") } } : {});
      return true;
    }
    if (
      url.pathname === `/api/apps/${target}/wallet/accounts` &&
      req.method === "GET"
    ) {
      if (!requireToken(req, token, res)) {
        return true;
      }
      json(res, 200, { accounts: connectReturn ? state.walletAccounts.filter(account=>account.connector_id===target) : [] });
      return true;
    }
    if (
      url.pathname === `/api/apps/${target}/wallet/approvals` &&
      req.method === "GET"
    ) {
      if (!requireToken(req, token, res)) {
        return true;
      }
      json(res, 200, { approval_requests: state.approvalRequests.filter(request => request.connector_id === target) });
      return true;
    }
  }
  if (url.pathname.includes("/wallet-connector/")) {
    state.connectorEffects += 1;
    if (connectReturn && req.method === 'POST') {
      if (!requireToken(req, homeAuthorityToken, res)) return true;
      const body = await readBody(req);
      assert(body.connector_id === 'wallet-metamask', 'only the named test connector links');
      const schema = 'elastos.home.wallet-connector.effect.result/v1';
      if (url.pathname.endsWith('/evm/link/challenge')) {
        json(res,200,{schema,action:'evm_link_challenge',connector_id:body.connector_id,challenge:{schema:'elastos.auth.challenge/v1',challenge_id:'fixture-return',message:'Isolated wallet return proof',expires_at:Math.floor(Date.now()/1000)+300,resources:[]}});return true;
      }
      if (url.pathname.endsWith('/evm/link/verify')) {
        if (slowMarket !== 'normal') state.holdMarket = slowMarket === 'prices' ? 'prices' : 'balances';
        state.walletAccounts.push({account_id:'fixture-new-metamask',address:evmAddress,chain_namespace:'eip155:20',proof_type:'siwe',connector_id:'wallet-metamask',wallet_display_name:'MetaMask'});
        json(res,200,{schema,action:'evm_link_complete',connector_id:body.connector_id,status:'linked'});return true;
      }
    }
    json(res, 500, { error: "credential-free fixture forbids connector effects" });
    return true;
  }
  return false;
}

const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url || "/", "http://127.0.0.1");
    if (await handleApi(req, res, url)) {
      return;
    }
    const path = staticPath(url.pathname);
    if (!path || !existsSync(path)) {
      json(res, 404, { error: "fixture route not found", path: url.pathname });
      return;
    }
    const beforePath = relative(repoRoot, path);
    const body = process.env.MARKETPLACE_CONNECT_BEFORE === "1"
      && ["capsules/marketplace/browser/marketplace.js", "capsules/home/browser/home-shell-host.js", "capsules/wallet/browser/wallet.js"].includes(beforePath)
      ? Buffer.from(historicalTestSource(`73394822a053272452f561ec0344344598ecc16c:${beforePath}`))
      : process.env.MARKETPLACE_OPEN_BEFORE === "1"
      && ["capsules/marketplace/browser/marketplace.js", "capsules/home/browser/home-shell-host.js"].includes(beforePath)
      ? Buffer.from(historicalTestSource(`5cc6f5b8cd55c0ae3d37bd3a56e57c04315e44a1:${beforePath}`))
      : process.env.HOME_WALLET_REFRESH_BEFORE === "1" && path === join(repoRoot, "capsules/home/browser/home-shell-host.js")
      ? Buffer.from(historicalTestSource("0db7eb247c8d89f367d5458acb03339605cc216e:capsules/home/browser/home-shell-host.js"))
      : readFileSync(path);
    res.writeHead(200, {
      "access-control-allow-origin": "*",
      "cache-control": "no-store",
      "content-length": body.length,
      "content-type": contentType(path),
    });
    res.end(body);
  } catch (error) {
    state.serverErrors.push(String(error?.stack || error));
    if (!res.headersSent) {
      json(res, 500, { error: String(error?.message || error) });
    } else {
      res.end();
    }
  }
});

async function listen() {
  await new Promise((resolveListen, rejectListen) => {
    server.once("error", rejectListen);
    server.listen(0, "127.0.0.1", resolveListen);
  });
  const address = server.address();
  assert(address && typeof address === "object", "fixture server did not bind");
  return `http://127.0.0.1:${address.port}`;
}

function configuredBrowserExecutable() {
  const configured = (process.env.ELASTOS_BROWSER_EXECUTABLE || "").trim();
  if (!configured) {
    return null;
  }
  const absolute = isAbsolute(configured) ? configured : resolve(configured);
  assert(existsSync(absolute), "configured browser executable does not exist", {
    executablePath: absolute,
  });
  try {
    accessSync(absolute, constants.X_OK);
  } catch {
    throw new Error(
      `configured browser executable is not executable\n${JSON.stringify({ executablePath: absolute }, null, 2)}`,
    );
  }
  return absolute;
}

function frameFor(page, target) {
  return page.frames().find((frame) => frame.url().includes(`/apps/${target}/`)) || null;
}

async function waitFor(check, timeoutMs, label) {
  const startedAt = Date.now();
  while (Date.now() - startedAt <= timeoutMs) {
    if (await check()) {
      return;
    }
    await new Promise((resolveWait) => setTimeout(resolveWait, 50));
  }
  throw new Error(`timed out waiting for ${label}`);
}

async function postGuiCommandFromHost(page, descriptor) {
  await page.evaluate(({ value }) => {
    const frame = document.querySelector("#active-shell-frame");
    frame?.contentWindow?.postMessage({
      type: "home:gui-command",
      command: "attach-authorized-target",
      descriptor: value,
    }, "*");
  }, { value: descriptor });
}

async function homeWindowSnapshot(homeGui, target, { rememberWallet = false } = {}) {
  return homeGui.evaluate(({ targetId, remember }) => {
    const node = document.querySelector(`.window[data-target="${targetId}"]`);
    const frame = node?.querySelector(".window-frame");
    if (!node || !frame) {
      return null;
    }
    if (remember) {
      globalThis.__walletContinuityWindow = node;
      globalThis.__walletContinuityFrame = frame;
      globalThis.__walletContinuityContentWindow = frame.contentWindow;
    }
    const rect = node.getBoundingClientRect();
    return {
      id: node.dataset.windowId || "",
      target: node.dataset.target || "",
      route: frame.dataset.route || frame.getAttribute("src") || "",
      hidden:
        node.classList.contains("hidden") ||
        node.getAttribute("aria-hidden") !== "false",
      active: node.classList.contains("window-active"),
      maximized: node.dataset.maximized === "true",
      rect: {
        x: rect.x,
        y: rect.y,
        width: rect.width,
        height: rect.height,
        right: rect.right,
        bottom: rect.bottom,
      },
      walletWindowPreserved:
        !remember && globalThis.__walletContinuityWindow === node,
      walletFramePreserved:
        !remember && globalThis.__walletContinuityFrame === frame,
      walletContentWindowPreserved:
        !remember &&
        globalThis.__walletContinuityContentWindow === frame.contentWindow,
      distinctFromWalletFrame:
        !remember && globalThis.__walletContinuityFrame !== frame,
      distinctFromWalletContentWindow:
        !remember &&
        globalThis.__walletContinuityContentWindow !== frame.contentWindow,
    };
  }, { targetId: target, remember: rememberWallet });
}

async function walletUiSnapshot(wallet, { remember = false } = {}) {
  return wallet.evaluate(({ rememberState }) => {
    if (rememberState) {
      globalThis.__walletContinuityState = { marker: "wallet-state-preserved" };
    }
    return {
      route: window.location.href,
      settingsOpen:
        document.querySelector("#wallet-settings-drawer")?.hidden === false,
      statePreserved:
        !rememberState &&
        globalThis.__walletContinuityState?.marker === "wallet-state-preserved",
    };
  }, { rememberState: remember });
}

function rectsEqual(left, right) {
  return ["x", "y", "width", "height"].every(
    (key) => Math.abs(Number(left?.[key]) - Number(right?.[key])) < 0.5,
  );
}

function rectangleIntersectionRatio(subject, overlay) {
  const width = Math.max(
    0,
    Math.min(subject.right, overlay.right) - Math.max(subject.x, overlay.x),
  );
  const height = Math.max(
    0,
    Math.min(subject.bottom, overlay.bottom) - Math.max(subject.y, overlay.y),
  );
  const area = Math.max(1, subject.width * subject.height);
  return (width * height) / area;
}

async function checkWalletPhoneOpen(page, homeGui) {
  assert(!frameFor(page, "wallet"), "phone starts without a preloaded Wallet rail");
  await homeGui.locator('.taskbar-item[data-target="wallet"]').tap();
  await waitFor(() => frameFor(page, "wallet"), 15000, "phone Wallet frame");
  const wallet = frameFor(page, "wallet");
  for (const [target, title] of Object.entries(connectorTitles)) {
    await wallet.getByRole("button",{name:"Add wallet for apps",exact:true}).tap();
    const button = wallet.locator(`[data-wallet-open-method="${target}"]`).first();
    await button.waitFor({state:"visible",timeout:15000});
    await button.tap();
    await waitFor(() => frameFor(page, target), 5000, `${title} from Wallet on phone`);
    await checkPhoneConnectorFront(page, homeGui, target);
    console.log(`[wallet-phone] PASS ${title}: connector in front, Connect visible and clickable`);
    await page.waitForTimeout(2700);
    await homeGui.locator(`.window[data-target="${target}"] [data-action="close"]`).tap();
    await waitFor(() => !frameFor(page, target), 5000, `${title} closes on phone`);
  }
}

async function checkPhoneConnectorFront(page, homeGui, target) {
  const connector = frameFor(page, target);
  // Check the settled presentation as well as the Connect button hit target.
  await page.waitForTimeout(1000);
  const windows = await homeGui.evaluate(target => {
    const connector = document.querySelector(`.window[data-target="${target}"]`);
    const wallet = document.querySelector('.window[data-target="wallet"]');
    return {active:connector?.classList.contains("window-active"),
      connectorZ:Number(getComputedStyle(connector).zIndex), walletZ:Number(getComputedStyle(wallet).zIndex)};
  }, target);
  console.log(`[phone-window-order] ${target} ${JSON.stringify(windows)}`);
  assert(windows.active && windows.connectorZ > windows.walletZ,
    `${target} stays in front of Wallet on phone`, windows);
  await connector.locator('[data-action="connect"]').click({trial:true,timeout:5000});
}

async function checkMarketplaceOpen(page, homeGui, pageErrors) {
  const phone = process.env.MARKETPLACE_OPEN_CASE === "connectors-phone";
  if (phone) {
    await homeGui.locator('.phone-home-app[data-target="marketplace"]').click();
  } else {
    await homeGui.locator('#launcher-toggle').click();
    await homeGui.locator('#launcher-grid [data-target="marketplace"]').click();
  }
  await waitFor(() => frameFor(page, "marketplace"), 15000, "Marketplace frame");
  const marketplace = frameFor(page, "marketplace");
  await marketplace.locator('.store-row[data-app="assistant"]').first().waitFor({timeout:5000}).catch(async error => {
    throw new Error(`${error.message}\nMarketplace: ${await marketplace.locator("body").innerText()}\nPage errors: ${JSON.stringify(pageErrors)}`);
  });
  if (process.env.MARKETPLACE_OPEN_CASE.startsWith("connectors")) {
    await homeGui.evaluate(() => {
      window.directConnectorOpens = [];
      window.addEventListener("message", event => {
        if (event.source === window.top && event.data?.type === "home:gui-command"
          && event.data.command === "open-target" && event.data.target?.startsWith("wallet-")) {
          window.directConnectorOpens.push(event.data.target);
        }
      });
    });
    if (!phone) {
      // Desktop also proves Open works with Home's hidden Wallet rail mounted.
      // Coarse pointers use a full Wallet window instead of this rail.
      await homeGui.evaluate(async () => {
        const {preloadWalletRail} = await import("./shell-wallet-rail.js?v=home-20261101d");
        preloadWalletRail();
      });
      await waitFor(() => frameFor(page, "wallet"), 5000, "Home preloads Wallet rail");
      await frameFor(page, "wallet").locator('#wallet-add-apps')
        .waitFor({state:"attached",timeout:5000});
    } else {
      assert(!frameFor(page, "wallet"), "phone starts without a preloaded Wallet rail");
    }
    const walletLaunchesBefore = state.launches.wallet;
    await page.evaluate(() => {
      window.walletOpens = [];
      window.addEventListener("message", event => {
        if (event.data?.type === "home:open-target" && event.data.homeToken?.startsWith("fixture-wallet-token-")) {
          window.walletOpens.push(event.data.target);
        }
      });
    });
    // Even a valid Marketplace token cannot launch a connector directly or
    // turn a malformed Wallet query into a connection command.
    await marketplace.evaluate(targets => {
      const homeToken = new URLSearchParams(location.hash.slice(1)).get("home_token");
      const origin = new URLSearchParams(location.search).get("home_origin");
      const send = message => top.postMessage({homeToken, ...message}, origin);
      for (const target of targets) send({type:"home:open-target", target});
      for (const query of [null, [], {}, {connect:"browser"}, {connect:targets[0], extra:true}]) {
        send({type:"home:open-target", target:"wallet", query});
      }
      for (const type of ["home:deliver-to-target", "home:open-target-with-payload"]) {
        send({type, target:"wallet", payload:{type:"elastos.wallet.connect/v1", target:targets[0]}});
      }
    }, Object.keys(connectorTitles));
    await page.waitForTimeout(300);
    assert(await homeGui.evaluate(() => window.directConnectorOpens.length === 0),
      "Home refuses direct connector targets before sending a GUI launch command");
    assert(state.launches.wallet === walletLaunchesBefore && Object.keys(connectorTitles).every(target => state.launches[target] === 0),
      "direct connector launches and malformed or generic handoffs stay blocked");
    for (const destination of ["discover", "installed"]) {
      if (phone) await marketplace.locator('[data-el-drawer-toggle="store-sidebar"]').click();
      await marketplace.locator(`.store-nav-item[data-destination="${destination}"]`).click();
      for (const [target, title] of Object.entries(connectorTitles)) {
        const row = marketplace.locator(`.store-row[data-app="${target}"]`).first();
        assert(await row.count() === 1, `${title} stays listed in ${destination}`);
        const launchesBefore = state.launches[target];
        if (destination === "discover") {
          await row.locator('[data-action="open"]').click({timeout:5000});
        } else {
          await row.locator('.store-row-title').click();
          await marketplace.locator('#detail-content [data-action="open"]').click({timeout:5000});
        }
        await waitFor(() => frameFor(page, target), 5000, `${title} connection window from Marketplace`);
        if (phone) {
          assert(state.launches.wallet === walletLaunchesBefore + 1,
            "phone opens and reuses a full Wallet window for connector requests");
          await homeGui.locator('.window[data-target="wallet"] iframe')
            .waitFor({state:"attached",timeout:5000});
        }
        const connector = frameFor(page, target);
        await connector.locator('[data-action="connect"]').waitFor({timeout:5000});
        await connector.locator('[data-action="connect"]').click({trial:true,timeout:5000});
        if (phone) await checkPhoneConnectorFront(page, homeGui, target);
        assert(await (await connector.frameElement()).isVisible(), `${title} connection window is visible`);
        assert(state.launches[target] === launchesBefore + 1, `${title} uses one Runtime launch`);
        assert(await page.evaluate(target => window.walletOpens.at(-1) === target, target),
          `${title} launch comes from Wallet's existing open path`);
        assert(state.launches.wallet === walletLaunchesBefore + (phone ? 1 : 0), "the mounted Wallet frame is reused");
        assert(state.connectorEffects === 0, "opening a connection window leaves connection approval to the person");
        // A connector app cannot impersonate Marketplace, send Wallet commands,
        // or open another connector with its own valid launch token.
        const launchesBeforeForgery = {...state.launches};
        const totalBefore = Object.values(launchesBeforeForgery).reduce((a,b) => a+b, 0);
        await connector.evaluate(() => {
          const homeToken = new URLSearchParams(location.hash.slice(1)).get("home_token");
          const origin = new URLSearchParams(location.search).get("home_origin");
          top.postMessage({type:"home:open-target-with-payload", target:"wallet",
            payload:{type:"elastos.wallet.connect/v1", target:"wallet-metamask"}, homeToken}, origin);
          top.postMessage({type:"home:open-target", target:"wallet-unisat", homeToken}, origin);
        });
        const wallet = frameFor(page, "wallet");
        await wallet.evaluate(() => window.dispatchEvent(new MessageEvent("message", {
          origin:new URLSearchParams(location.search).get("home_origin"), source:window,
          data:{type:"elastos.wallet.connect/v1", target:"wallet-metamask"},
        })));
        await page.waitForTimeout(200);
        assert(Object.values(state.launches).reduce((a,b) => a+b, 0) === totalBefore,
          "another app and a forged Home command cannot start a connector", {before:launchesBeforeForgery, after:state.launches});
        if (process.env.MARKETPLACE_CONNECT_SCREENSHOTS) {
          mkdirSync(process.env.MARKETPLACE_CONNECT_SCREENSHOTS, {recursive:true});
          await page.screenshot({path:join(process.env.MARKETPLACE_CONNECT_SCREENSHOTS,
            `${process.env.MARKETPLACE_OPEN_CASE}-${destination}-${target}.png`)});
        }
        // A new connector can share the previous Close position. Home never
        // sees the iframe's Open press, so wait out its 2600 ms ghost-click guard.
        await page.waitForTimeout(2700);
        await homeGui.locator(`.window[data-target="${target}"] [data-action="close"]`).click();
        await waitFor(() => !frameFor(page, target), 5000, `${title} window closes`);
        if (phone) {
          // The first Close returns to Wallet. Later requests reuse that
          // minimized Wallet, so their Close already returns to Marketplace.
          const walletWindow = homeGui.locator('.window[data-target="wallet"]');
          if (await walletWindow.isVisible()) {
            await walletWindow.locator('[data-action="minimize"]').click({timeout:5000});
          }
          assert(await homeGui.locator('.window[data-target="marketplace"]').isVisible(),
            "closing the connector lets the person return to Marketplace");
        }
      }
    }
    if (phone) {
      // Retire the reused phone window through its controls before checking
      // the Wallet card's ordinary Open, which creates a separate window.
      await homeGui.locator('#phone-dock-handle').tap();
      await homeGui.locator('.taskbar-item[data-target="wallet"]').tap();
      await homeGui.locator('.window[data-target="wallet"] [data-action="close"]').tap();
      await homeGui.locator('.window[data-target="wallet"]').waitFor({state:"detached",timeout:5000});
    }
    // The Wallet app card still has its ordinary Open, without a connector query.
    const walletsBeforePlainOpen = state.launches.wallet;
    await marketplace.locator('.store-row[data-app="wallet"] [data-action="open"]').first().click();
    await homeGui.locator('.window[data-target="wallet"] iframe').waitFor({state:"visible",timeout:5000});
    await homeGui.frameLocator('.window[data-target="wallet"] iframe')
      .locator('#wallet-add-apps').waitFor({state:"attached",timeout:5000});
    assert(state.launches.wallet === walletsBeforePlainOpen + 1, "ordinary Wallet Open uses its normal launch path");
    await page.waitForTimeout(2700);
    await homeGui.locator('.window[data-target="wallet"] [data-action="close"]').click();
    await homeGui.locator('.window[data-target="wallet"]').waitFor({state:"detached",timeout:5000});
    const walletsBeforeReopen = state.launches.wallet;
    await marketplace.locator('.store-row[data-app="wallet-metamask"] [data-action="open"]').first().click();
    await waitFor(() => frameFor(page, "wallet-metamask"), 5000, "connector Open after closing Wallet");
    await frameFor(page, "wallet-metamask").locator('[data-action="connect"]').click({trial:true,timeout:5000});
    assert(state.launches.wallet === walletsBeforeReopen + (phone ? 1 : 0),
      phone ? "Home opens a fresh Wallet after its phone window retires"
        : "Home reuses the mounted Wallet rail after its separate window retires");
    if (phone) await checkPhoneConnectorFront(page, homeGui, "wallet-metamask");
    await page.waitForTimeout(2700);
    await homeGui.locator('.window[data-target="wallet-metamask"] [data-action="close"]').click();
    await waitFor(() => !frameFor(page, "wallet-metamask"), 5000, "reopened connector closes");
  } else {
    // A plain Open is distinct from a model selection. Model handoffs retain their narrow contract.
    for (const query of [null, [], {}, {offer_id:"model:private"}, {model_cid:"bad"}, {authority:"new"}]) {
      await marketplace.evaluate(query => top.postMessage({type:"home:open-target", target:"assistant", query,
        homeToken:new URLSearchParams(location.hash.slice(1)).get("home_token")},
        new URLSearchParams(location.search).get("home_origin")), query);
    }
    await page.waitForTimeout(1500);
    assert(!await homeGui.locator('#assistant-face').isVisible(), "malformed handoffs cannot show the Assistant face");
    assert(state.launches.assistant === 0, "malformed model handoffs cannot launch Assistant");
    await marketplace.locator('.store-row[data-app="assistant"] .store-row-title').first().click();
    await marketplace.locator('#detail-content [data-action="open"]').click();
    await homeGui.locator('#assistant-face').waitFor({state:"visible", timeout:5000});
    await waitFor(() => state.launches.assistant === 1, 5000, "Assistant Runtime launch");
    await waitFor(() => frameFor(page, "assistant"), 5000, "Assistant app frame");
    const assistant = frameFor(page, "assistant");
    assert(await (await assistant.frameElement()).isVisible(), "Assistant app frame is visible");
    const query = new URL(assistant.url()).searchParams;
    assert(!query.has("model_cid") && !query.has("offer_id"), "plain Open selects no model");
    await assistant.evaluate(() => top.postMessage({type:"home:open-target", target:"wallet",
      query:{connect:"wallet-metamask"},
      homeToken:new URLSearchParams(location.hash.slice(1)).get("home_token")},
      new URLSearchParams(location.search).get("home_origin")));
    await page.waitForTimeout(200);
    assert(Object.keys(connectorTitles).every(target => state.launches[target] === 0),
      "another app cannot use Marketplace's Wallet connection handoff");
    const bounds = await homeGui.locator('#assistant-face').boundingBox();
    const viewport = await homeGui.evaluate(() => ({width:innerWidth,height:innerHeight}));
    assert(bounds && bounds.x >= 0 && bounds.y >= 0 && bounds.x + bounds.width <= viewport.width
      && bounds.y + bounds.height <= viewport.height, "Assistant opens on screen");
  }
  console.log(`[marketplace-open] PASS ${process.env.MARKETPLACE_OPEN_CASE}`);
}

const origin = await listen();
let browser = null;
try {
  const engines = await importProductSmokePlaywright();
  assert(["chromium", "webkit"].includes(engine), "named browser engine required");
  const executablePath = configuredBrowserExecutable();
  browser = await engines[engine].launch({
    headless: true,
    ...(engine === "chromium" ? {
    ...productSmokeLaunchOptions(),
    ...(executablePath ? { executablePath } : {}),
    args: [
      "--disable-background-networking",
      "--disable-breakpad",
      "--disable-component-update",
      "--disable-domain-reliability",
      "--disable-extensions",
      "--disable-sync",
      "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1, EXCLUDE localhost",
      "--no-first-run",
      "--no-proxy-server",
    ],
    } : {}),
  });
  const phoneLayout = process.env.MARKETPLACE_OPEN_CASE === "connectors-phone" || process.env.WALLET_PHONE_OPEN === "1" || connectReturn && width === 390;
  const context = await browser.newContext(process.env.MARKETPLACE_OPEN_CASE || phoneLayout || connectReturn
    ? { reducedMotion: "reduce", ...(phoneLayout
      ? {viewport:{width:390,height:844},isMobile:!connectReturn,hasTouch:true} : {}) } : {});
  if (connectReturn) {
    await context.addInitScript(installSigninProviders, {evmAddress,bitcoinAddress,theme:'dark'});
  }
  const page = await context.newPage();
  if (connectReturn) await page.setViewportSize({width,height:780});
  const pageErrors = [];
  page.on("pageerror", (error) => pageErrors.push(String(error?.stack || error)));
  page.on("console", message => {
    if (message.type() === "error" && message.text().startsWith("home-gui summary failed")) {
      pageErrors.push(message.text());
    }
  });

  await page.goto(`${origin}/apps/home/`, { waitUntil: "domcontentloaded" });
  await page.waitForFunction(
    () => document.body.dataset.homeStatus === "ready",
    null,
    { timeout: 15_000 },
  );
  await waitFor(() => frameFor(page, "home-gui"), 15_000, "real Home GUI frame");
  const homeGui = frameFor(page, "home-gui");
  if (connectReturn) {
    if (phoneLayout) await homeGui.locator('.taskbar-item[data-target="wallet"]').tap();
    else {
      await homeGui.locator('#launcher-toggle').click();
      await homeGui.locator('#launcher-grid [data-target="wallet"]').click();
    }
    const windowNode = homeGui.locator('.window[data-target="wallet"]');
    const walletFrame = windowNode.locator('iframe');
    await walletFrame.waitFor({timeout:15000});
    const wallet = await (await walletFrame.elementHandle()).contentFrame();
    await wallet.locator('.one-wallet').nth(1).waitFor();
    await wallet.evaluate(()=>{window.walletReturnDocument=document;});
    if(marketFailure) {
      const balance = amount => wallet.waitForFunction(value=>[...document.querySelectorAll('.one-network-balance strong')].some(node=>node.textContent===value),`${amount}.00 ELA`,{timeout:3000});
      const refresh = (count=1) => homeGui.evaluate(count=>{
        const frame=document.querySelector('.window[data-target="wallet"] iframe');
        for(let i=0;i<count;i++)frame.contentWindow.postMessage({type:'elastos:wallet-refresh'},'*');
      },count);
      const release = () => {for(const finish of state.heldMarket.splice(0))finish();};
      const oldAddress=state.walletAccounts[0].address;
      const newAddress='0x'+'56'.repeat(20);
      await balance(1);
      // A valid market result is already pending when the next account read fails.
      state.holdMarket='balances';state.balanceHex='0x1bc16d674ec80000';
      await refresh();
      await waitFor(()=>state.heldMarket.length===3,3000,'market read for the shown accounts');
      state.walletAccounts=[{...state.walletAccounts[0],account_id:'fixture-replacement',address:newAddress,label:'Replacement address'},state.walletAccounts[1]];
      state.summaryFailure=marketFailure==='summary';
      state.approvalsUnavailable=marketFailure==='approvals';
      const response=page.waitForResponse(r=>new URL(r.url()).pathname==='/api/apps/wallet/wallet/summary');
      await refresh(2);
      await (await response).finished();
      await wallet.evaluate(()=>new Promise(requestAnimationFrame));
      const shownAddress=marketFailure==='summary'?oldAddress:newAddress;
      await wallet.locator(`.one-meta code[title="${shownAddress}"]`).waitFor();
      state.balanceHex='0x29a2241af62c0000';
      release();
      try {
        if(marketFailure==='summary')await balance(2);
        await waitFor(()=>state.heldMarket.length===3,3000,'replacement market read after account error');
      } catch(error) {
        throw new Error(`${marketFailure}: ${error.message}; ${JSON.stringify({held:state.heldMarket.length,reads:state.balanceReads.length,view:await wallet.locator('#wallet-inventory').innerText()})}`);
      }
      const expectedAddresses=new Set([shownAddress,state.walletAccounts[1].address]);
      assert(state.balanceReads.slice(-3).every(read=>expectedAddresses.has(read.address)),
        'replacement balances belong to the committed account list',state.balanceReads.slice(-3));
      if(marketFailure==='approvals')assert(!await wallet.locator('.one-network-balances').innerText().then(text=>text.includes('2.00 ELA')),
        'old-account market results stay out of the new list');
      state.holdMarket='';release();
      await balance(3);
      await wallet.waitForFunction(()=>document.querySelector('#wallet-status').dataset.tone==='error');
      assert(await wallet.locator(`.one-meta code[title="${shownAddress}"]`).count()===1 && state.serverErrors.length===0 && pageErrors.length===0,
        'account error keeps its committed list and reports its error after market recovery',{pageErrors,errors:state.serverErrors});
      console.log(`[wallet-market-recovery] PASS ${engine} ${width} ${marketFailure}: shown-account balances 1 -> ${marketFailure==='summary'?'2 -> ':''}3; replacement market read completed`);
      return;
    }
    if (slowMarket === 'existing-balances') {
      state.holdMarket = 'balances';
      await wallet.evaluate(()=>top.postMessage({type:'home:refresh-summary',homeToken:new URLSearchParams(location.hash.slice(1)).get('home_token')},new URLSearchParams(location.search).get('home_origin')));
      await waitFor(()=>state.heldMarket.length>0,5000,'an earlier balance read waits');
    }
    await wallet.getByRole('button',{name:'Add wallet for apps',exact:true}).click();
    await wallet.locator('[data-wallet-open-method="wallet-metamask"]').click();
    await waitFor(()=>frameFor(page,'wallet-metamask'),15000,'MetaMask opens');
    const connector = frameFor(page,'wallet-metamask');
    await connector.locator('[data-action="connect"]').click();
    await connector.locator('[data-state="linked"]').waitFor({timeout:15000}).catch(async error=>{
      throw new Error(`${error.message}\n${await connector.locator('body').innerText()}\n${JSON.stringify({effects:state.connectorEffects,accounts:state.walletAccounts.length,errors:state.serverErrors,pageErrors})}`);
    });
    if (slowMarket !== 'normal') await waitFor(()=>state.heldMarket.length>0,5000,'market data waits after connect');
    await connector.locator('[data-action="close-window"]').click();
    await waitFor(()=>!frameFor(page,'wallet-metamask'),5000,'MetaMask closes');
    await windowNode.evaluate(()=>{window.walletReturnFocus=document.activeElement;});
    const before = await wallet.evaluate(()=>({rows:document.querySelectorAll('.one-wallet').length,metamask:[...document.querySelectorAll('.one-wallet')].some(node=>node.textContent.includes('MetaMask')),scroll:document.scrollingElement.scrollTop,height:document.scrollingElement.scrollHeight,viewport:document.documentElement.clientHeight,modal:!!document.querySelector(':modal'),inert:document.body.inert}));
    assert(before.rows===3 && before.metamask && before.height>before.viewport && !before.modal && !before.inert,
      'Wallet renders the saved MetaMask and its scroll range as the connector closes, while market reads wait',before);
    const observeWheel = process.env.WALLET_RETURN_WHEEL_RECEIPT === '1';
    await wallet.evaluate(observe=>{
      window.walletReturnPointer=null;
      addEventListener('pointermove',event=>{window.walletReturnPointer={trusted:event.isTrusted,wallet:!!event.target.closest('.one-wallet')};},{once:true});
      // Receipt runs are separate: the main regression leaves WebKit's async
      // wheel path unobserved, since a wheel listener can change its routing.
      window.walletReturnWheels=[];
      if(observe)addEventListener('wheel',event=>window.walletReturnWheels.push({trusted:event.isTrusted,deltaY:event.deltaY,prevented:event.defaultPrevented}),{passive:true});
    },observeWheel);
    await wallet.locator('.one-wallet').first().hover();
    assert(await wallet.evaluate(top=>document.scrollingElement.scrollTop===top,before.scroll),
      'Targeting the visible Wallet card keeps the initial scroll position');
    await page.mouse.wheel(0,460);
    await wallet.waitForFunction(top=>document.scrollingElement.scrollTop>top,before.scroll,{timeout:3000}).catch(()=>{});
    const after = await wallet.evaluate(()=>({pointer:window.walletReturnPointer,wheels:window.walletReturnWheels,rows:document.querySelectorAll('.one-wallet').length,scroll:document.scrollingElement.scrollTop,metamask:[...document.querySelectorAll('.one-wallet')].some(node=>node.textContent.includes('MetaMask')),sameDocument:window.walletReturnDocument===document}));
    const chrome = await windowNode.evaluate(node=>({active:node.classList.contains('window-active'),inert:node.inert,pointer:getComputedStyle(node.querySelector('iframe')).pointerEvents,sameFocus:document.activeElement===window.walletReturnFocus}));
    console.log('[wallet-connect-return] measurement '+JSON.stringify({engine,width,slowMarket,observeWheel,held:state.heldMarket.length,before,after,chrome}));
    assert(after.metamask && after.rows===3 && after.scroll>before.scroll && after.pointer?.trusted && after.pointer.wallet && chrome.sameFocus,
      'Wallet accepts the first wheel after connector close without a focus change',{before,after,chrome});
    if(observeWheel)assert(after.wheels.length===1 && after.wheels[0].trusted && after.wheels[0].deltaY>0 && !after.wheels[0].prevented,
      'Wallet receives one trusted, uncancelled wheel',after.wheels);
    const held = state.heldMarket.splice(0); state.holdMarket = ''; for (const release of held) release();
    const copy = await wallet.locator('body').innerText();
    assert(!copy.includes('Built-in addresses')&&!copy.includes('Passkey-controlled')&&!copy.includes('Wallet Send')&&!copy.includes('Wallets & signers'),'rc.2 Wallet copy stays removed');
    if (process.env.WALLET_RETURN_SCREENS) {
      mkdirSync(process.env.WALLET_RETURN_SCREENS,{recursive:true});
      await page.screenshot({path:join(process.env.WALLET_RETURN_SCREENS,`wallet-connected-${engine}-${width}-${slowMarket}.png`)});
    }
    assert(state.connectorEffects===2 && after.sameDocument && state.serverErrors.length===0 && pageErrors.length===0,'one real connector link completes in the same Wallet without source errors',{effects:state.connectorEffects,pageErrors,errors:state.serverErrors});
    console.log(`[wallet-connect-return] PASS ${engine} ${width} ${slowMarket}: new entry and first wheel, same Wallet frame`);
    return;
  }
  if (process.env.WALLET_SIGNIN_ENTRY === "1") {
    await homeGui.evaluate(async()=>{const rail=await import('./shell-wallet-rail.js?v=home-20261101d');rail.preloadWalletRail();});
    await waitFor(()=>frameFor(page,'wallet'),15000,'preloaded hidden Wallet rail');
    const railRoute=await homeGui.locator('#wallet-rail-frame').getAttribute('data-route');
    const railToken=new URLSearchParams(new URL(railRoute,origin).hash.slice(1)).get('home_token');
    const ask=()=>page.evaluate(()=>new Promise((resolve,reject)=>{
      const desktop=document.querySelector('#active-shell-frame').contentWindow,requestId=crypto.randomUUID();
      const timer=setTimeout(()=>{removeEventListener('message',receive);reject(new Error('Desktop reply timed out'));},15000);
      function receive(event){if(event.source!==desktop||event.origin!=='null'||event.data?.type!=='home:wallet-connect-entry-ready'||event.data.requestId!==requestId)return;clearTimeout(timer);removeEventListener('message',receive);resolve(event.data);}
      addEventListener('message',receive);desktop.postMessage({type:'home:gui-command',command:'open-wallet-connect-entry',requestId},'*');
    }));
    const reply=await ask();
    await homeGui.locator('.window[data-target="wallet"]').waitFor({state:'visible',timeout:15000});
    const visible=await homeWindowSnapshot(homeGui,'wallet');
    const visibleToken=new URLSearchParams(new URL(visible.route,origin).hash.slice(1)).get('home_token');
    const desktopToken=await page.locator('#active-shell-frame').evaluate(frame=>new URLSearchParams(new URL(frame.dataset.route,location.href).hash.slice(1)).get('home_token'));
    assert(JSON.stringify(Object.keys(reply).sort())===JSON.stringify(['homeToken','requestId','type','walletToken']), 'real Desktop reply has separate envelope and Wallet tokens',reply);
    assert(reply.homeToken===desktopToken&&reply.walletToken===visibleToken&&reply.walletToken!==railToken,'real reply selects the visible Wallet rather than Desktop or rail',reply);
    const launches=state.launches.wallet;
    const again=await ask();assert(again.walletToken===visibleToken&&state.launches.wallet===launches,'New wallet reuses its already-open visible window');
    await page.waitForTimeout(2700);
    await homeGui.locator('.window[data-target="wallet"] [data-action="close"]').click();
    await homeGui.locator('.window[data-target="wallet"]').waitFor({state:'detached',timeout:5000});
    const reopened=await ask();assert(reopened.walletToken&&reopened.walletToken!==visibleToken,'closing Wallet retires its selected window token');
    assert(state.serverErrors.length===0&&pageErrors.length===0,'real Home/Desktop source errors',{pageErrors,errors:state.serverErrors});
    console.log(`[wallet-signin-entry] PASS ${engine}: hidden rail, exact reply tokens, existing window reuse and close/reopen`);
    return;
  }
  if (phoneLayout) {
    await homeGui.waitForFunction(() => document.body.dataset.formFactor === "phone", null, {timeout:15000});
    const device = await homeGui.evaluate(() => ({width:innerWidth,
      coarse:matchMedia("(pointer: coarse)").matches, factor:document.body.dataset.formFactor}));
    assert(device.width === 390 && device.coarse && device.factor === "phone",
      "fixture uses the 390 px coarse-pointer phone layout", device);
    // Let the real idle warmup run: phones keep Wallet in its full window.
    await page.waitForTimeout(2200);
    assert(!frameFor(page, "wallet"), "phone idle warmup leaves the Wallet rail unmounted");
  }
  if (process.env.WALLET_PHONE_OPEN === "1") {
    await checkWalletPhoneOpen(page, homeGui);
    assert(state.serverErrors.length === 0 && pageErrors.length === 0, "phone Wallet source errors", {pageErrors, errors:state.serverErrors});
    return;
  }
  if (process.env.MARKETPLACE_OPEN_CASE) {
    await checkMarketplaceOpen(page, homeGui, pageErrors);
    assert(state.serverErrors.length === 0, "fixture server recorded errors", state.serverErrors);
    assert(pageErrors.length === 0, "real Marketplace/Home source raised page errors", pageErrors);
    return;
  }
  await homeGui.evaluate(async () => {
    const {shellState} = await import("./shell-core.js?v=home-20261101d");
    window.connectorSmokeState = shellState;
  });
  await homeGui.waitForFunction(() => window.connectorSmokeState.currentSummary?.capsule_catalog?.capsules
    ?.some(capsule => capsule.launch_target === "wallet-walletconnect"), null, {timeout:15000});
  const windowPolicy = await homeGui.evaluate(async () => {
    const {supportsMenuNewWindow} = await import("./shell-windows.js?v=home-20261101d");
    // Exercise the rule with fixed inputs; engine availability and summary timing are host-owned.
    const summary = {targets:[{target:"library",window_policy:"hybrid"}],capsule_catalog:{capsules:
      ["wallet-metamask","wallet-unisat","wallet-walletconnect"].map(launch_target => ({launch_target,launchable:true,window_policy:"single"}))}};
    return Object.fromEntries(["browser","library","wallet-metamask","wallet-unisat","wallet-walletconnect"].map(target => [target,supportsMenuNewWindow(target,summary)]));
  });
  assert(JSON.stringify(windowPolicy) === JSON.stringify({browser:false,library:true,"wallet-metamask":true,"wallet-unisat":true,"wallet-walletconnect":false}),
    "only WalletConnect reuses a connector window; Browser and Library keep their menu rules", windowPolicy);
  await homeGui.locator('#launcher-toggle').click();
  await homeGui.locator('#launcher-grid [data-target="wallet"]').click();
  await waitFor(() => frameFor(page, "wallet"), 15_000, "real Wallet frame");
  const walletFrame = homeGui.locator('.window[data-target="wallet"] iframe');
  await walletFrame.waitFor({state:"attached",timeout:15000});
  const wallet = await (await walletFrame.elementHandle()).contentFrame();
  // The static Settings button can exist before Wallet's module binds handlers.
  await wallet.waitForLoadState("domcontentloaded", { timeout: 15_000 });
  await wallet.waitForSelector("#wallet-add-apps", { timeout: 15_000 });
  const connectorLabels = Object.freeze({
    "wallet-metamask": "Connect wallet",
    "wallet-unisat": "Connect wallet",
    "wallet-walletconnect": "Connect wallet",
  });
  const walletWindowBeforeConnectors = await homeWindowSnapshot(
    homeGui,
    "wallet",
    { rememberWallet: true },
  );
  const walletUiBeforeConnectors = await walletUiSnapshot(wallet, {
    remember: true,
  });
  assert(walletWindowBeforeConnectors, "Home GUI did not expose the Wallet window");
  assert(walletUiBeforeConnectors.settingsOpen === false, "Wallet fixture opened settings early");

  let walletRecoveryLaunches=0;
  for (const [target, connectLabel] of Object.entries(connectorLabels)) {
    await wallet.getByRole("button",{name:"Add wallet for apps",exact:true}).click();
    // Connector controls belong to the app-use chooser.
    await wallet.locator(`[data-wallet-open-method="${target}"]`).waitFor({
      state: "attached", timeout: 15_000,
    });
    // The approved Add control returns to the same Wallet list.
    await wallet.evaluate(({ connectorTarget }) => {
      document
        .querySelector(`[data-wallet-open-method="${connectorTarget}"]`)
        .click();
    }, { connectorTarget: target });
    await waitFor(() => frameFor(page, target), 15_000, `${target} connector UI`);
    const connector = frameFor(page, target);
    const connectorHomeToken = await connector.evaluate(() => new URLSearchParams(location.hash.slice(1)).get("home_token"));
    const connectSelector = '[data-action="connect"]';
    await connector.waitForSelector(connectSelector, { timeout: 15_000 });
    assert(
      await connector.locator(connectSelector).textContent() === connectLabel,
      `${target} did not render its credential-free UI`,
    );
    await homeGui.waitForFunction(targetId=>{
      const node=document.querySelector(`.window[data-target="${targetId}"]`);
      const height=node?.getBoundingClientRect().height;
      return height>=240&&height<560;
    },target,{timeout:5000});

    const walletWindowDuringConnector = await homeWindowSnapshot(
      homeGui,
      "wallet",
    );
    const connectorWindow = await homeWindowSnapshot(homeGui, target);
    const walletUiDuringConnector = await walletUiSnapshot(wallet);
    const viewport = await homeGui.evaluate(() => ({
      width: window.innerWidth,
      height: window.innerHeight,
    }));
    assert(
      walletWindowDuringConnector?.id === walletWindowBeforeConnectors.id &&
        connectorWindow?.id &&
        connectorWindow.id !== walletWindowBeforeConnectors.id,
      `${target} replaced the Wallet window identity`,
      { walletWindowBeforeConnectors, walletWindowDuringConnector, connectorWindow },
    );
    assert(
      walletWindowDuringConnector.walletWindowPreserved === true &&
        walletWindowDuringConnector.walletFramePreserved === true &&
        walletWindowDuringConnector.walletContentWindowPreserved === true &&
        connectorWindow.distinctFromWalletFrame === true &&
        connectorWindow.distinctFromWalletContentWindow === true,
      `${target} did not retain distinct Wallet and connector frames`,
      { walletWindowDuringConnector, connectorWindow },
    );
    assert(
      walletWindowDuringConnector.hidden === false &&
        walletWindowDuringConnector.route === walletWindowBeforeConnectors.route &&
        rectsEqual(
          walletWindowDuringConnector.rect,
          walletWindowBeforeConnectors.rect,
        ),
      `${target} hid, navigated, or resized the Wallet window`,
      { walletWindowBeforeConnectors, walletWindowDuringConnector },
    );
    assert(
      walletUiDuringConnector.route === walletUiBeforeConnectors.route &&
        walletUiDuringConnector.settingsOpen === false &&
        walletUiDuringConnector.statePreserved === true,
      `${target} replaced or reset the Wallet frame state`,
      { walletUiBeforeConnectors, walletUiDuringConnector },
    );
    assert(
      connectorWindow.hidden === false &&
        connectorWindow.active === true &&
        connectorWindow.maximized === false &&
        connectorWindow.rect.width >= 320 &&
        connectorWindow.rect.width <= 520 &&
        connectorWindow.rect.height >= 220 &&
        connectorWindow.rect.height <= 620 &&
        connectorWindow.rect.x >= 0 &&
        connectorWindow.rect.y >= 0 &&
        connectorWindow.rect.right <= viewport.width &&
        connectorWindow.rect.bottom <= viewport.height &&
        rectangleIntersectionRatio(
          walletWindowDuringConnector.rect,
          connectorWindow.rect,
        ) < 0.55,
      `${target} did not open as a bounded, non-covering connector window`,
      { viewport, walletWindowDuringConnector, connectorWindow },
    );
    assert(
      await homeGui.locator(`.window[data-target="${target}"]`).count() === 1,
      `${target} click attached more than one connector window`,
    );

    assert(connectorWindow.rect.width>=360&&connectorWindow.rect.width<=640&&connectorWindow.rect.height>=240&&connectorWindow.rect.height<560,
      `${target} fits its initial content with a sensible minimum`,connectorWindow.rect);
    const content = await connector.evaluate(() => ({width:innerWidth,height:innerHeight}));
    assert(Math.abs(content.width-connectorWindow.rect.width)<1&&Math.abs(connectorWindow.rect.height-content.height-38)<1,
      `${target} keeps Home's title bar outside its content`,{content,rect:connectorWindow.rect});
    if (target === "wallet-metamask") {
      state.approvalRequests = [{request_id:"metamask-second",capsule_id:"browser",address:"0x3333333333333333333333333333333333333333",connector_id:target,proof_type:"siwe",intent:"browser_personal_sign",status:"pending",reason:"Second MetaMask request",chain_namespace:"eip155:20",expires_at:Math.floor(Date.now()/1000)+600}];
      // Wallet's real request card opens the second request while the first connector stays open.
      await homeGui.evaluate(() => document.querySelector('.window[data-target="wallet"] iframe').contentWindow.postMessage({type:'elastos:wallet-refresh'},'*'));
      const add = wallet.getByRole('button',{name:'Add wallet for apps',exact:true});
      const addBounds = await add.boundingBox();
      // The first press on inactive app content belongs to Home's focus layer.
      await page.mouse.click(addBounds.x+addBounds.width/2,addBounds.y+addBounds.height/2);
      assert((await homeWindowSnapshot(homeGui,'wallet')).active && await wallet.locator(':modal').count()===0,
        'inactive Wallet content activates its window before an app control can run');
      await add.click();await wallet.locator('.one-dialog [data-wallet-open-method="wallet-metamask"]').click();
      await waitFor(() => page.frames().filter(frame=>frame.url().includes('/apps/wallet-metamask/')).length === 2,5000,'fresh MetaMask request window');
      const fresh = page.frames().filter(frame=>frame.url().includes('/apps/wallet-metamask/')).find(frame=>frame!==connector);
      await fresh.getByText('Second MetaMask request',{exact:true}).waitFor();
      assert(await connector.getByText('Second MetaMask request',{exact:true}).count() === 0,'original MetaMask frame retains its load-time list');
      await homeGui.locator('.window[data-target="wallet-metamask"] [data-action="close"]').last().click();
      state.approvalRequests = [];
      await homeGui.locator('.window[data-target="wallet-metamask"] .window-head').click({position:{x:80,y:14}});
    }
    if (target === "wallet-walletconnect") {
      state.approvalRequests = [{request_id:"wc-return",connector_id:target,proof_type:"siwe",intent:"browser_personal_sign",status:"pending",reason:"New request on Home return",address:"0x"+"12".repeat(20),expires_at:Math.floor(Date.now()/1000)+600,chain_namespace:"eip155:20"}];
      await homeGui.locator('.window[data-target="wallet-walletconnect"] [data-action="minimize"]').click();
      await wallet.evaluate(() => {document.querySelector('#wallet-add-apps').click();document.querySelector('[data-wallet-open-method="wallet-walletconnect"]').click();});
      await waitFor(() => state.launches["wallet-walletconnect"] === 2, 5000, "WalletConnect return launch");
      await page.waitForTimeout(300);
      assert(await homeGui.locator('.window[data-target="wallet-walletconnect"]').count() === 1,
        "returning to WalletConnect keeps its original window");
      assert(frameFor(page, target) === connector, "WalletConnect return preserves its requesting frame");
      const returned = await homeWindowSnapshot(homeGui, target);
      assert(!returned.hidden && returned.active, "WalletConnect return restores and activates its requesting window");
      await connector.getByText('New request on Home return',{exact:true}).waitFor();
      // Returning to an already visible frame also refreshes, without a click inside it.
      state.approvalRequests[0].reason = 'Another request on Home return';
      await wallet.evaluate(() => {document.querySelector('#wallet-add-apps').click();document.querySelector('[data-wallet-open-method="wallet-walletconnect"]').click();});
      await connector.getByText('Another request on Home return',{exact:true}).waitFor();
      assert(await homeGui.locator('.window[data-target="wallet-walletconnect"]').count() === 1,'visible return keeps one WalletConnect frame');
      state.approvalRequests = [];
      if (process.env.WALLETCONNECT_SCREENSHOTS) {
        mkdirSync(process.env.WALLETCONNECT_SCREENSHOTS, {recursive:true});
        for (const theme of ["dark", "light"]) {
          for (const frame of page.frames()) {
            await frame.evaluate(theme => { document.documentElement.dataset.elTheme = theme; }, theme);
          }
          await page.screenshot({path:join(process.env.WALLETCONNECT_SCREENSHOTS, `r15-home-return-${theme}.png`)});
        }
      }
    }

    if (target === "wallet-walletconnect") {
      for (const observed of [page.mainFrame(), homeGui, wallet]) await observed.evaluate(() => {
        window.fixtureAccountHints = [];
        addEventListener("message", event => {
          if (!["elastos:runtime-events", "home:refresh-summary"].includes(event.data?.type)) return;
          window.fixtureAccountHints.push({type:event.data.type,origin:event.origin,parent:event.source===window.parent,top:event.source===window.top,hasToken:!!event.data.homeToken,kinds:(event.data.events||[]).slice(0,5).map(row=>row.kind)});
          window.fixtureAccountHints = window.fixtureAccountHints.slice(-8);
        });
      });
      const notify = () => connector.evaluate(homeToken => window.top.postMessage({
        type: "home:refresh-summary", homeToken,
      }, new URLSearchParams(location.search).get("home_origin")), connectorHomeToken);
      state.walletAccounts = [{account_id:"fixture-linked-account",address:"0x1212121212121212121212121212121212121212",chain_namespace:"eip155:1",connector_id:"wallet-walletconnect",proof_type:"siwe",wallet_display_name:"WalletConnect",wallet_mark:"wallet",linked_at:1}];
      const readsBeforeSibling = state.walletSummaryReads;
      await connector.evaluate(() => {
        for (let i=0;i<window.parent.length;i++) window.parent.frames[i].postMessage({
          type:"elastos:runtime-events",events:[{kind:"wallet.accounts.changed",scope:"wallet"}],
        },"*");
        window.parent.postMessage({type:"elastos:runtime-events",events:[{kind:"wallet.accounts.changed",scope:"wallet"}]},"*");
      });
      await page.waitForTimeout(150);
      assert(state.walletSummaryReads === readsBeforeSibling, "a sibling connector cannot forward Home GUI events");
      await notify();
      try {
        await wallet.waitForFunction(() => document.querySelector("#wallet-account-state")?.textContent.trim() === "1 address", null, {timeout:4000});
      } catch (cause) {
        const frames = await Promise.all([page.mainFrame(),homeGui,wallet].map(frame=>frame.evaluate(()=>({hints:window.fixtureAccountHints,label:document.querySelector("#wallet-account-state")?.textContent,status:document.querySelector("#wallet-status")?.textContent}))));
        throw new Error("Account refresh failed: "+JSON.stringify({readsBefore:readsBeforeSibling,readsAfter:state.walletSummaryReads,frames}),{cause});
      }
      state.walletAccounts = [];
      await notify();
      await wallet.waitForFunction(() => document.querySelector("#wallet-account-state")?.textContent.trim() === "0 addresses", null, {timeout:4000});
    }

    // Recovery opens the admitted Wallet only; queries and payload handoffs stay separate.
    await homeGui.evaluate(()=>{window.round5WalletOpens=[];addEventListener('message',event=>{if(event.data?.type==='home:gui-command'&&event.data.command==='open-target'&&event.data.target==='wallet')round5WalletOpens.push(event.data);});});
    await connector.evaluate(()=>{const homeToken=new URLSearchParams(location.hash.slice(1)).get('home_token'),origin=new URLSearchParams(location.search).get('home_origin');for(const message of [{type:'home:open-target',target:'wallet',query:{}},{type:'home:open-target-with-payload',target:'wallet',payload:{type:'elastos.wallet.connect/v1',target:'wallet-metamask'}}])top.postMessage({...message,homeToken},origin);});
    await page.waitForTimeout(150);assert(await homeGui.evaluate(()=>round5WalletOpens.length)===0,'connector recovery rejects queries and payloads');
    const beforeRecovery=state.launches.wallet;
    await connector.evaluate(()=>top.postMessage({type:'home:open-target',target:'wallet',homeToken:new URLSearchParams(location.hash.slice(1)).get('home_token')},new URLSearchParams(location.search).get('home_origin')));
    await homeGui.waitForFunction(()=>document.querySelector('.window[data-target="wallet"]')?.classList.contains('window-active'));
    walletRecoveryLaunches+=state.launches.wallet-beforeRecovery;
    assert((await homeWindowSnapshot(homeGui,'wallet')).id===walletWindowBeforeConnectors.id,'recovery keeps the same Wallet');
    await homeGui.locator(`.window[data-target="${target}"] .window-head`).click({position:{x:80,y:14}});

    const connectorClose = homeGui.locator(
      `.window[data-target="${target}"] [data-action="close"]`,
    );
    assert(
      await connectorClose.count() === 1,
      `${target} did not expose exactly one independent close control`,
    );
    await page.waitForTimeout(2_700);
    await connectorClose.click();
    await waitFor(
      async () =>
        await homeGui.locator(`.window[data-target="${target}"]`).count() === 0,
      15_000,
      `${target} independent close`,
    );
    const walletWindowAfterClose = await homeWindowSnapshot(homeGui, "wallet");
    const walletUiAfterClose = await walletUiSnapshot(wallet);
    assert(
      walletWindowAfterClose?.active === true &&
        walletWindowAfterClose.hidden === false &&
        walletWindowAfterClose.id === walletWindowBeforeConnectors.id &&
        walletWindowAfterClose.route === walletWindowBeforeConnectors.route &&
        walletWindowAfterClose.walletWindowPreserved === true &&
        walletWindowAfterClose.walletFramePreserved === true &&
        walletWindowAfterClose.walletContentWindowPreserved === true &&
        rectsEqual(walletWindowAfterClose.rect, walletWindowBeforeConnectors.rect) &&
        walletUiAfterClose.route === walletUiBeforeConnectors.route &&
        walletUiAfterClose.settingsOpen === false &&
        walletUiAfterClose.statePreserved === true,
      `${target} close did not return focus to the unchanged Wallet`,
      {
        walletWindowBeforeConnectors,
        walletWindowAfterClose,
        walletUiBeforeConnectors,
        walletUiAfterClose,
      },
    );
  }

  assert(state.launches["home-gui"] === 1, "Home launched multiple GUI roots", state);
  // A valid summary also permits Home's idle desktop rail preload. Each
  // mounted Wallet surface gets one launch; connector opens reuse the window.
  const railMounted = await homeGui.locator('#wallet-rail-frame')
    .evaluate(frame => Boolean(frame.dataset.route));
  assert(state.launches.wallet === 1 + Number(railMounted) + walletRecoveryLaunches,
    "Home launched Wallet once per mounted surface", state);
  assert(
    state.launches["wallet-metamask"] === 2 &&
      state.launches["wallet-unisat"] === 1 && state.launches["wallet-walletconnect"] === 3,
    "each Wallet open must produce one Runtime connector launch",
    state,
  );
  assert(
    await homeGui.locator('.window[data-target="wallet-metamask"]').count() === 0 &&
      await homeGui.locator('.window[data-target="wallet-unisat"]').count() === 0 &&
      await homeGui.locator('.window[data-target="wallet-walletconnect"]').count() === 0,
    "Home GUI did not close connector windows independently",
  );

  const windowCountBeforeRejectedDescriptors = await homeGui.locator(".window").count();
  await postGuiCommandFromHost(page, {
    schema: "elastos.home.authorized-target-attachment/v1",
    receipt_id: "forged-target",
    target: "wallet-unknown",
    title: "Unknown connector",
    attach_kind: "iframe",
    route:
      `/apps/wallet-unknown/?home_origin=${encodeURIComponent(origin)}` +
      "#home_token=forged",
  });
  await postGuiCommandFromHost(page, {
    schema: "elastos.home.authorized-target-attachment/v1",
    receipt_id: "substituted-route",
    target: "wallet-metamask",
    title: "MetaMask",
    attach_kind: "iframe",
    route:
      `/apps/wallet-unisat/?home_origin=${encodeURIComponent(origin)}` +
      "#home_token=substituted",
  });
  await wallet.evaluate((targetOrigin) => {
    window.parent.postMessage({
      type: "home:gui-command",
      command: "attach-authorized-target",
      descriptor: {
        schema: "elastos.home.authorized-target-attachment/v1",
        receipt_id: "wrong-source",
        target: "wallet-metamask",
        title: "MetaMask",
        attach_kind: "iframe",
        route:
          `/apps/wallet-metamask/?home_origin=${encodeURIComponent(targetOrigin)}` +
          "#home_token=wrong-source",
      },
    }, targetOrigin);
  }, origin);
  await page.waitForTimeout(100);
  assert(
    await homeGui.locator(".window").count() === windowCountBeforeRejectedDescriptors,
    "forged, substituted, or wrong-source descriptor attached a connector window",
  );
  assert(
    state.launches["wallet-metamask"] === 2 &&
      state.launches["wallet-unisat"] === 1 && state.launches["wallet-walletconnect"] === 3,
    "descriptor rejection invoked the generic Runtime launch path",
    state,
  );

  const replayDescriptor = {
    schema: "elastos.home.authorized-target-attachment/v1",
    receipt_id: "bounded-replay-proof",
    target: "wallet-metamask",
    title: "MetaMask",
    attach_kind: "iframe",
    route:
      `/apps/wallet-metamask/?home_origin=${encodeURIComponent(origin)}` +
      "#home_token=fixture-replay-token",
  };
  await postGuiCommandFromHost(page, replayDescriptor);
  await waitFor(
    async () =>
      await homeGui.locator('.window[data-target="wallet-metamask"]').count() === 1,
    15_000,
    "first bounded descriptor attachment",
  );
  await postGuiCommandFromHost(page, replayDescriptor);
  await page.waitForTimeout(100);
  assert(
    await homeGui.locator('.window[data-target="wallet-metamask"]').count() === 1,
    "Home GUI accepted a replayed authorized attachment descriptor",
  );
  assert(
    state.launches["wallet-metamask"] === 2,
    "authorized attachment replay invoked Runtime launch",
    state,
  );

  const persistedState = JSON.stringify(state.homeStateWrites);
  assert(
    !persistedState.includes("wallet-metamask") &&
      !persistedState.includes("wallet-unisat") &&
      !persistedState.includes("wallet-walletconnect") &&
      !persistedState.includes("fixture-walletconnect-token") &&
      !persistedState.includes("home_token") &&
      !persistedState.includes("fixture-metamask-token") &&
      !persistedState.includes("fixture-unisat-token") &&
      !persistedState.includes("fixture-replay-token"),
    "Home persisted a hidden connector descriptor or launch token",
    state.homeStateWrites,
  );
  assert(state.connectorEffects === 0, "credential-free UI proof invoked a connector effect");
  assert(state.serverErrors.length === 0, "fixture server recorded errors", state.serverErrors);
  assert(pageErrors.length === 0, "real Home/GUI/Wallet source raised page errors", pageErrors);

  console.log(
    "[home-wallet-connector-launch-headless] PASS " +
      `wallet_launches=${state.launches.wallet} ` +
      `metamask_launches=${state.launches["wallet-metamask"]} ` +
      `unisat_launches=${state.launches["wallet-unisat"]} ` +
      `walletconnect_launches=${state.launches["wallet-walletconnect"]} ` +
      `connector_effects=${state.connectorEffects}`,
  );
} finally {
  await browser?.close().catch(() => {});
  await new Promise((resolveClose) => server.close(resolveClose));
}

}
