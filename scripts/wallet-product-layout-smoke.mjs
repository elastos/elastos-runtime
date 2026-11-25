#!/usr/bin/env node

import { createServer } from "node:http";
import { observeCopiedFeedback } from "./lib/wallet-copy-feedback.mjs";
import { productSmokeLaunchOptions, requireProductSmokePlaywright } from "./product-smoke-browser.mjs";
import { mkdtemp, readFile, rm, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { extname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(fileURLToPath(new URL("../", import.meta.url)));
const walletRoot = join(repoRoot, "capsules/wallet/browser");
const homeRoot = join(repoRoot, "capsules/home/browser");
const { chromium } = requireProductSmokePlaywright();

const pictureRoot=process.env.WALLET_ROUND2_PICTURES, walletCaptures=[];
async function capture(frame,id,caption){
  if(!pictureRoot)return;await mkdir(pictureRoot,{recursive:true});
  await frame.locator('main.wallet-shell').screenshot({path:join(pictureRoot,id+'.png')});
  walletCaptures.push({file:id+'.png',caption});await writeFile(join(pictureRoot,'wallet-index.json'),JSON.stringify(walletCaptures,null,2));
}

const groupAddress = "0x1111111111111111111111111111111111111111";
const sendAddress = "0x2222222222222222222222222222222222222222";
const clipboardGeneration = "wallet-clipboard-generation-1";
const defaultGenericError = "Wallet action could not be completed.";

function assert(condition, message, details = undefined) {
  if (condition) {
    return;
  }
  const suffix = details === undefined ? "" : `\n${JSON.stringify(details, null, 2)}`;
  throw new Error(`${message}${suffix}`);
}

function json(response, status, value) {
  const body = Buffer.from(JSON.stringify(value));
  response.writeHead(status, {
    "access-control-allow-origin": "*",
    "access-control-allow-headers": "content-type,x-elastos-home-token",
    "access-control-allow-methods": "GET,POST,PUT,DELETE,OPTIONS",
    "cache-control": "no-store",
    "content-length": body.length,
    "content-type": "application/json; charset=utf-8",
  });
  response.end(body);
}

function text(response, status, value) {
  const body = Buffer.from(String(value));
  response.writeHead(status, {
    "access-control-allow-origin": "*",
    "cache-control": "no-store",
    "content-length": body.length,
    "content-type": "text/plain; charset=utf-8",
  });
  response.end(body);
}

function contentType(path) {
  return {
    ".css": "text/css; charset=utf-8",
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".mjs": "text/javascript; charset=utf-8",
    ".png": "image/png",
    ".svg": "image/svg+xml",
    ".woff2": "font/woff2",
  }[extname(path)] || "application/octet-stream";
}

function defaultState() {
  return {
    summaryCalls: 0,
    priceCalls: 0,
    balanceCalls: [],
    qrCalls: [],
    sendBodies: [],
    rejectBodies: [],
    defaultBodies: [],
    renameBodies: [],
    deleteBodies: [],
    recoveryCalls: [],
    clipboardRequests: [],
    clipboardShouldFail: false,
    openTargets: [],
    refreshSummaryCount: 0,
    appReadyCount: 0,
    privacyMessages: [],
    pendingMessages: [],
    stepUps: [],
    requestFailures: [],
    requestErrors: [],
    homeMessages: [],
    accounts: [
      {
        account_id: "acc-esc",
        chain_namespace: "eip155:20",
        address: groupAddress,
        label: "Family",
        proof_type: "managed_evm",
        signing_status: "managed_key_available",
        signing_available: true,
      },
      {
        account_id: "acc-base",
        chain_namespace: "eip155:8453",
        address: groupAddress,
        label: "Family",
        proof_type: "managed_evm",
        signing_status: "managed_key_available",
        signing_available: true,
      },
    ],
    defaultAccounts: [
      {
        account_id: "acc-esc",
        chain_namespace: "eip155:20",
        intent: "transaction_intent",
        set_at: 10,
      },
    ],
    approvals: [
      {
        request_id: "req-wallet-1",
        capsule_id: "browser",
        address: groupAddress,
        reason: "Review this action.",
        created_at: Math.floor(Date.now() / 1000) - 30,
        expires_at: Math.floor(Date.now() / 1000) + 600,
        status: "pending",
        proof_type: "managed_evm",
        intent: "browser_personal_sign",
      },
    ],
  };
}

function summaryResponse(state) {
  return {
    wallet_accounts: {
      accounts: state.accounts,
      default_accounts: state.defaultAccounts,
    },
    wallet_approvals: {
      approval_requests: state.approvals,
    },
    approval_methods: {
      walletconnect: { available: true },
    },
  };
}

function hexUnits(units, decimals) {
  const raw = BigInt(Math.round(units * (10 ** Math.min(decimals, 6)))) * (10n ** BigInt(decimals - Math.min(decimals, 6)));
  return `0x${raw.toString(16)}`;
}

function staticPath(pathname) {
  const roots = [
    ["/apps/wallet/", walletRoot],
    ["/apps/home/", homeRoot],
  ];
  for (const [prefix, root] of roots) {
    if (!pathname.startsWith(prefix)) {
      continue;
    }
    const suffix = decodeURIComponent(pathname.slice(prefix.length)) || "index.html";
    const candidate = resolve(root, suffix);
    const escaped = relative(root, candidate);
    if (escaped.startsWith(`..${sep}`) || escaped === "..") {
      return null;
    }
    return candidate;
  }
  return null;
}

async function readBody(request) {
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > 1_048_576) {
      throw new Error("fixture request exceeds 1 MiB");
    }
    chunks.push(Buffer.from(chunk));
  }
  const textValue = Buffer.concat(chunks).toString("utf8");
  return textValue ? JSON.parse(textValue) : {};
}

function fixtureHtml(baseUrl, mode) {
  const homeToken = mode === "locked" ? "" : "wallet-home-token";
  const search = new URLSearchParams({
    home_origin: baseUrl,
    ...(mode === "rail" ? { presentation: "rail" } : {}),
  });
  const walletSrc = `${baseUrl}/apps/wallet/?${search.toString()}${homeToken ? `#home_token=${encodeURIComponent(homeToken)}` : ""}`;
  return `<!DOCTYPE html>
<html lang="en">
<body style="margin:0;background:#101012;">
  <iframe id="wallet-frame" src="${walletSrc}" style="border:0;width:100vw;height:100vh;"></iframe>
  <script>
    const clipboardTargetId = "wallet";
    const state = {
      clipboardGeneration: "${clipboardGeneration}",
      clipboardShouldFail: false,
      appReadyCount: 0,
      openTargets: [],
      refreshSummaryCount: 0,
      privacyMessages: [],
      pendingMessages: [],
      clipboardRequests: [],
      stepUps: [],
      homeMessages: [],
    };
    window.__walletFixture = state;
    window.addEventListener("message", (event) => {
      const data = event.data || {};
      state.homeMessages.push({ origin: event.origin, sourceIsFrame: event.source === document.getElementById("wallet-frame").contentWindow, type: data.type || "" });
      if (data.type === "home:app-ready") {
        state.appReadyCount += 1;
        event.source.postMessage({
          type: "home:clipboard-ready",
          schema: "elastos.home.clipboard.ready/v1",
          targetId: clipboardTargetId,
          homeToken: data.homeToken,
          parentOrigin: "${baseUrl}",
          generation: state.clipboardGeneration,
        }, "${baseUrl}");
        return;
      }
      if (data.type === "home:clipboard-request") {
        state.clipboardRequests.push(data);
        event.source.postMessage(
          state.clipboardShouldFail
            ? {
                type: "home:clipboard-result",
                schema: "elastos.home.clipboard.result/v1",
                requestId: data.requestId,
                targetId: clipboardTargetId,
                homeToken: data.homeToken,
                parentOrigin: data.parentOrigin,
                generation: data.generation,
                operation: data.operation,
                purpose: data.purpose,
                ok: false,
                error: "denied",
              }
            : {
                type: "home:clipboard-result",
                schema: "elastos.home.clipboard.result/v1",
                requestId: data.requestId,
                targetId: clipboardTargetId,
                homeToken: data.homeToken,
                parentOrigin: data.parentOrigin,
                generation: data.generation,
                operation: data.operation,
                purpose: data.purpose,
                ok: true,
              },
          "${baseUrl}",
        );
        state.clipboardShouldFail = false;
        return;
      }
      if (data.type === "home:wallet-signin-request" && data.action === "list"
          && event.source === document.getElementById("wallet-frame").contentWindow) {
        event.source.postMessage({type:"home:wallet-signin-result",requestId:data.requestId,
          result:{status:"complete",account_id:"principal:wallet-fixture",methods:[],can_manage:false}}, "${baseUrl}");
        return;
      }
      if (data.type === "elastos.home.passkey-step-up.request/v1") {
        state.stepUps.push(data);
        event.source.postMessage({
          type: "elastos.home.passkey-step-up.result/v1",
          requestId: data.requestId,
          stepUpToken: "fixture-step-up-token-" + state.stepUps.length,
        }, "${baseUrl}");
        return;
      }
      if (data.type === "home:open-target") {
        state.openTargets.push(data);
        return;
      }
      if (data.type === "home:refresh-summary") {
        state.refreshSummaryCount += 1;
        return;
      }
      if (data.type === "wallet:privacy-state") {
        state.privacyMessages.push(data);
        return;
      }
      if (data.type === "wallet:pending-count") {
        state.pendingMessages.push(data);
      }
    });
  </script>
</body>
</html>`;
}

async function startServer() {
  const state = defaultState();
  const server = createServer(async (request, response) => {
    try {
      const url = new URL(request.url || "/", "http://127.0.0.1");
      if (request.method === "OPTIONS") {
        response.writeHead(204, {
          "access-control-allow-origin": "*",
          "access-control-allow-headers": "content-type,x-elastos-home-token",
          "access-control-allow-methods": "GET,POST,PUT,DELETE,OPTIONS",
        });
        response.end();
        return;
      }
      if (url.pathname === "/favicon.ico") {
        response.writeHead(204, { "cache-control": "no-store" });
        response.end();
        return;
      }
      if (url.pathname === "/fixture-host.html") {
        const baseUrl = `http://127.0.0.1:${server.address().port}`;
        const html = fixtureHtml(baseUrl, url.searchParams.get("mode") || "window");
        response.writeHead(200, {
          "cache-control": "no-store",
          "content-length": Buffer.byteLength(html),
          "content-type": "text/html; charset=utf-8",
        });
        response.end(html);
        return;
      }
      const staticFile = staticPath(url.pathname);
      if (staticFile) {
        const body = await readFile(staticFile);
        response.writeHead(200, {
          "access-control-allow-origin": "*",
          "cache-control": "no-store",
          "content-length": body.length,
          "content-type": contentType(staticFile),
        });
        response.end(body);
        return;
      }
      if (url.pathname === "/api/apps/wallet/wallet/inventory" && request.method === "GET") {
        json(response,200,{schema:'elastos.wallet.inventory/v1',account_id:'fixture',account_name:'Alex',entries:state.accounts.map(account=>({inventory_id:`${account.chain_namespace}:${account.address.toLowerCase()}`,address:account.address,chain_namespace:account.chain_namespace,accounts:[account],sign_in:null}))});return;
      }
      if (url.pathname === "/api/apps/wallet/wallet/summary" && request.method === "GET") {
        state.summaryCalls += 1;
        const token = request.headers["x-elastos-home-token"];
        if (token !== "wallet-home-token") {
          json(response, 401, { error: "fixture token rejected" });
          return;
        }
        json(response, 200, summaryResponse(state));
        return;
      }
      if (url.pathname === "/api/apps/wallet/wallet/approvals/approved-send/reject" && request.method === "POST") {
        assert(request.headers["x-elastos-home-token"] === "wallet-home-token", "dismissal carries Wallet authority");
        state.rejectBodies.push(await readBody(request));
        state.approvals[0].status = "rejected";
        json(response, 200, { approval_requests: state.approvals, receipt_status: "dismissed", note: "Request dismissed. This does not cancel the transaction in your wallet. Check your wallet before making a new request." });
        return;
      }
      if (url.pathname === "/api/wallet/prices" && request.method === "GET") {
        state.priceCalls += 1;
        json(response, 200, {
          stale: false,
          unavailable: false,
          prices: {
            ELA: { usd: 2 },
            ETH: { usd: 3000 },
          },
        });
        return;
      }
      if (url.pathname === "/api/provider/chain/balance" && request.method === "POST") {
        const body = await readBody(request);
        state.balanceCalls.push(body);
        if (body.network === "esc-mainnet" && body.address === groupAddress) {
          json(response, 200, { status: "ok", data: { balance_hex: hexUnits(12, 18) } });
          return;
        }
        if (body.network === "base-mainnet" && body.address === groupAddress) {
          json(response, 200, { status: "ok", data: { balance_hex: hexUnits(1.5, 18) } });
          return;
        }
        json(response, 200, { status: "error", message: "Unknown fixture balance target" });
        return;
      }
      if (url.pathname === "/api/wallet/qr" && request.method === "POST") {
        const body = await readBody(request);
        state.qrCalls.push(body);
        json(response, 200, {
          svg: '<svg viewBox="0 0 64 64" xmlns="http://www.w3.org/2000/svg"><rect width="64" height="64" fill="white"/><rect x="8" y="8" width="16" height="16" fill="black"/><rect x="40" y="8" width="16" height="16" fill="black"/><rect x="24" y="24" width="16" height="16" fill="black"/><rect x="8" y="40" width="16" height="16" fill="black"/><rect x="40" y="40" width="16" height="16" fill="black"/></svg>',
        });
        return;
      }
      if (url.pathname === "/api/apps/wallet/wallet/send" && request.method === "POST") {
        const body = await readBody(request);
        state.sendBodies.push(body);
        json(response, 200, {
          transaction_hash: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          approval_request: {
            request_id: `completed-${state.sendBodies.length}`,
            status: "completed",
          },
        });
        return;
      }
      if (url.pathname === "/api/apps/wallet/wallet/default" && request.method === "POST") {
        const body = await readBody(request);
        state.defaultBodies.push(body);
        state.defaultAccounts = [{
          account_id: body.account_id,
          chain_namespace: body.chain_namespace,
          intent: body.intent,
          set_at: 100 + state.defaultBodies.length,
        }];
        json(response, 200, {});
        return;
      }
      if (/^\/api\/apps\/wallet\/wallet\/accounts\/[^/]+\/recovery-key$/.test(url.pathname) && request.method === "POST") {
        const body = await readBody(request);
        const accountId = decodeURIComponent(url.pathname.split("/")[6]);
        state.recoveryCalls.push({ accountId, body });
        const account = state.accounts.find((item) => item.account_id === accountId);
        json(response, 200, {
          account_id: accountId,
          chain_namespace: account?.chain_namespace || "",
          address: account?.address || "",
          secret_type: "hex",
          private_key_hex: "ab".repeat(32),
          note: "Fixture recovery key",
        });
        return;
      }
      if (/^\/api\/apps\/wallet\/wallet\/accounts\/[^/]+$/.test(url.pathname) && request.method === "PUT") {
        const body = await readBody(request);
        const accountId = decodeURIComponent(url.pathname.split("/")[6]);
        state.renameBodies.push({ accountId, body });
        state.accounts = state.accounts.map((item) =>
          item.account_id === accountId ? { ...item, label: body.label } : item,
        );
        json(response, 200, {});
        return;
      }
      if (/^\/api\/apps\/wallet\/wallet\/accounts\/[^/]+$/.test(url.pathname) && request.method === "DELETE") {
        const body = await readBody(request);
        const accountId = decodeURIComponent(url.pathname.split("/")[6]);
        state.deleteBodies.push({ accountId, body });
        state.accounts = state.accounts.filter((item) => item.account_id !== accountId);
        state.defaultAccounts = state.defaultAccounts.filter((item) => item.account_id !== accountId);
        json(response, 200, {});
        return;
      }
      text(response, 500, `Unexpected fixture route: ${request.method} ${url.pathname}`);
    } catch (error) {
      state.requestErrors.push(String(error.message || error));
      text(response, 500, String(error.message || error));
    }
  });

  await new Promise((resolvePromise) => server.listen(0, "127.0.0.1", resolvePromise));
  return {
    baseUrl: `http://127.0.0.1:${server.address().port}`,
    state,
    async close() {
      await new Promise((resolvePromise, rejectPromise) =>
        server.close((error) => (error ? rejectPromise(error) : resolvePromise())),
      );
    },
  };
}

async function walletFrame(page) {
  await page.waitForSelector("#wallet-frame");
  await page.waitForFunction(() => {
    const frame = document.querySelector("#wallet-frame");
    return frame && frame.contentWindow && frame.contentWindow.location.href.includes("/apps/wallet/");
  }, { timeout: 5000 });
  const frame = page.frames().find((item) => item.url().includes("/apps/wallet/"));
  assert(frame, "Wallet iframe did not load.");
  return frame;
}

async function fixtureState(page) {
  return page.evaluate(() => structuredClone(window.__walletFixture));
}

async function waitForCondition(check, timeoutMs, label) {
  const startedAt = Date.now();
  while (Date.now() - startedAt <= timeoutMs) {
    if (await check()) {
      return;
    }
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 50));
  }
  throw new Error(`timed out waiting for ${label}`);
}

async function assertNoErrors(page, server, label) {
  const details = await page.evaluate(() => ({
    fixture: structuredClone(window.__walletFixture),
  }));
  assert(server.state.requestErrors.length === 0, `${label}: fixture server errors must stay empty.`, server.state.requestErrors);
  assert(server.state.requestFailures.length === 0, `${label}: unexpected request failures must stay empty.`, server.state.requestFailures);
  assert((page.__pageErrors || []).length === 0, `${label}: page errors must stay empty.`, page.__pageErrors);
  assert((page.__consoleErrors || []).length === 0, `${label}: console errors must stay empty.`, page.__consoleErrors);
  assert((page.__requestFailures || []).length === 0, `${label}: request failures must stay empty.`, {
    requestFailures: page.__requestFailures,
    fixture: details.fixture,
  });
}

async function screenshot(frame, path) {
  await frame.locator("main.wallet-shell").screenshot({ path });
}

async function assertNoHorizontalOverflow(frame, label) {
  const layout = await frame.evaluate(() => ({
    documentScrollWidth: document.documentElement.scrollWidth,
    innerWidth: window.innerWidth,
    shellScrollWidth: document.querySelector("main.wallet-shell")?.scrollWidth || 0,
  }));
  assert(
    layout.documentScrollWidth <= layout.innerWidth && layout.shellScrollWidth <= layout.innerWidth,
    `${label}: Wallet must not overflow horizontally.`,
    layout,
  );
}

async function controlRect(frame, selector, label) {
  const rect = await frame.locator(selector).evaluate((node) => {
    const box = node.getBoundingClientRect();
    return {
      left: box.left,
      top: box.top,
      right: box.right,
      bottom: box.bottom,
      width: box.width,
      height: box.height,
      viewportWidth: window.innerWidth,
      viewportHeight: window.innerHeight,
    };
  });
  assert(rect.width > 0 && rect.height > 0, `${label}: control must be visible.`, rect);
  assert(rect.left >= 0 && rect.top >= 0 && rect.right <= rect.viewportWidth && rect.bottom <= rect.viewportHeight, `${label}: control must fit inside the viewport.`, rect);
}

async function openAccountMenu(frame) {
  await frame.locator('.one-wallet-top button:visible').first().waitFor();
  if(!await frame.getByRole('button',{name:'Manage address',exact:true}).isVisible())await frame.getByRole('button',{name:/Open (Family|Home address|ELA Wallet)/}).first().click();
  await frame.getByRole('button',{name:'Manage address',exact:true}).click();
  await frame
    .locator(".wallet-flow-row")
    .filter({ hasText: "Use by default" })
    .waitFor({ state: "visible", timeout: 5000 });
}

async function run() {
  const server=await startServer(),tempDir=await mkdtemp(join(tmpdir(),'wallet-uiux-'));
  const browser=await chromium.launch({...productSmokeLaunchOptions(),headless:true});
  const pageWithErrors=async viewport=>{const page=await browser.newPage({viewport});page.__pageErrors=[];page.__consoleErrors=[];page.__requestFailures=[];page.on('pageerror',e=>page.__pageErrors.push(e.message));page.on('console',m=>{if(m.type()==='error')page.__consoleErrors.push(m.text());});page.on('requestfailed',r=>page.__requestFailures.push(r.url()));return page;};
  try {
    const locked=await pageWithErrors({width:1280,height:900});await locked.goto(server.baseUrl+'/fixture-host.html?mode=locked');const lockedFrame=await walletFrame(locked);
    await lockedFrame.getByText('Open Wallet from Home.',{exact:true}).waitFor();assert(server.state.summaryCalls===0&&server.state.priceCalls===0,'a locked Wallet keeps its APIs closed');await locked.close();
    const page=await pageWithErrors({width:1280,height:900});await page.goto(server.baseUrl+'/fixture-host.html?mode=window',{waitUntil:'networkidle'});const frame=await walletFrame(page);
    await frame.locator('.one-wallet').nth(1).waitFor();assert(await frame.locator('.one-wallet').count()===2,'the list identifies each address and network once');
    assert((await fixtureState(page)).appReadyCount===1,'Wallet announces its admitted launch once');assert(server.state.balanceCalls.length===2,'balances read each supported network once');
    await capture(frame,'wallet-list','Wallet lists each identity and its uses.');await assertNoHorizontalOverflow(frame,'desktop list');
    await frame.locator('.one-wallet').filter({hasText:'Base'}).getByRole('button',{name:'Send',exact:true}).click();
    await frame.locator('.wallet-flow-row').filter({hasText:'1.5 ETH'}).filter({hasText:'Base'}).click();
    await frame.locator('input[name="amount"]').fill('0.25');await frame.locator('input[name="to"]').fill(sendAddress);await frame.getByRole('button',{name:'Review',exact:true}).click();await frame.getByRole('button',{name:'Sign',exact:true}).click();
    await waitForCondition(()=>server.state.sendBodies.length===1,5000,'exact Base send');assert(server.state.sendBodies[0].account_id==='acc-base'&&server.state.sendBodies[0].chain_namespace==='eip155:8453','Send binds the selected Base record');
    await frame.locator('.one-wallet').first().getByRole('button',{name:'Receive',exact:true}).click();await frame.locator('.wallet-qr').waitFor();assert(server.state.qrCalls[0].address===groupAddress,'Receive binds the shared address');
    assert((await frame.locator('.wallet-flow-hint').last().innerText()).includes('Always choose the correct chain'),'Receive retains its network warning');await frame.getByRole('button',{name:'Done',exact:true}).click();
    await frame.getByRole('button',{name:'Open Family',exact:true}).first().click();await frame.getByRole('button',{name:'Settings',exact:true}).click();await frame.locator('#wallet-settings-drawer').waitFor();
    await frame.locator('#wallet-currency-settings [data-wallet-currency="usd"]').click();assert(await frame.evaluate(()=>localStorage.getItem('wallet.displayCurrency'))==='usd','currency remains a display preference');await frame.getByRole('button',{name:'Close settings',exact:true}).click();
    await frame.getByRole('button',{name:'Hide balances',exact:true}).click();await waitForCondition(async()=>((await fixtureState(page)).privacyMessages.at(-1)?.privacyMode===true),5000,'privacy chrome state');assert((await fixtureState(page)).privacyMessages.at(-1).privacyMode===true,'privacy remains a chrome fact');
    const copied=await observeCopiedFeedback(frame,'.one-wallet-top .el-button');try{await frame.getByRole('button',{name:'Copy',exact:true}).click();await copied.wait();}finally{await copied.close();}
    assert((await fixtureState(page)).clipboardRequests.at(-1).purpose==='wallet.address','Copy uses Home Clipboard for the address');
    await page.evaluate(()=>window.__walletFixture.clipboardShouldFail=true);await frame.getByRole('button',{name:'Copy',exact:true}).click();await frame.getByText(defaultGenericError,{exact:true}).waitFor();await page.evaluate(()=>window.__walletFixture.clipboardShouldFail=false);
    await frame.getByRole('button',{name:'Back to wallets',exact:true}).click();const opened=(await fixtureState(page)).openTargets.length;await frame.getByRole('button',{name:'Add wallet for apps',exact:true}).click();await frame.locator('[data-wallet-open-method="wallet-metamask"]').click();await waitForCondition(async()=>((await fixtureState(page)).openTargets.length===opened+1),5000,'exact connector launch');
    assert((await fixtureState(page)).openTargets.at(-1).target==='wallet-metamask','Add uses the Home connector launch');
    await openAccountMenu(frame);await frame.locator('.wallet-flow-row').filter({hasText:'Use by default'}).click();await frame.locator('.wallet-flow-row').filter({hasText:'Base'}).click();await waitForCondition(()=>server.state.defaultBodies.length===1,5000,'default');assert(server.state.defaultBodies[0].account_id==='acc-base','Default binds the exact network');
    await openAccountMenu(frame);await frame.locator('.wallet-flow-row').filter({hasText:'Show recovery key'}).click();await frame.locator('.wallet-flow-row').filter({hasText:'Elastos Smart Chain'}).click();await frame.locator('.wallet-secret').waitFor();assert(server.state.recoveryCalls.at(-1).accountId==='acc-esc','Recovery binds the exact network');assert(!(await frame.getByRole('dialog',{name:'Recovery key'}).innerText()).includes('undefined'),'Recovery has wallet and network labels');await frame.getByRole('button',{name:'Done',exact:true}).click();
    await openAccountMenu(frame);await frame.locator('.wallet-flow-row').filter({hasText:'Rename'}).click();await frame.locator('input[name="label"]').fill('Family Office');await frame.getByRole('button',{name:'Save',exact:true}).click();await waitForCondition(()=>server.state.renameBodies.length===2,5000,'grouped rename');
    await frame.getByRole('button',{name:'Back to wallets',exact:true}).click();for(const width of [1280,390]){await page.setViewportSize({width,height:900});await assertNoHorizontalOverflow(frame,'wallet '+width);await screenshot(frame,join(tempDir,'wallet-'+width+'.png'));}
    await openAccountMenu(frame);await frame.locator('.wallet-flow-row').filter({hasText:'Delete address'}).click();assert(server.state.deleteBodies.length===0,'Delete waits for confirmation');await frame.getByRole('button',{name:'Delete',exact:true}).click();await waitForCondition(()=>server.state.deleteBodies.length===2,5000,'grouped deletion');assert(server.state.deleteBodies.some(row=>row.accountId==='acc-esc')&&server.state.deleteBodies.some(row=>row.accountId==='acc-base'),'Delete binds both exact records');
    await assertNoErrors(page,server,'one-list journeys');await page.close();
    server.state.accounts=structuredClone(defaultState().accounts);server.state.approvals=[{...defaultState().approvals[0],request_id:'approved-send',status:'approved',proof_type:'siwe',intent:'transaction_intent',connector_id:'wallet-walletconnect',transaction_hash:'0x'+'ab'.repeat(32),reason:'Payment result needs checking'}];
    const rail=await pageWithErrors({width:390,height:844});await rail.goto(server.baseUrl+'/fixture-host.html?mode=rail',{waitUntil:'networkidle'});let railFrame=await walletFrame(rail);await railFrame.getByRole('button',{name:'Dismiss',exact:true}).waitFor();await assertNoHorizontalOverflow(railFrame,'late phone result');await railFrame.getByRole('button',{name:'Dismiss',exact:true}).click();await waitForCondition(()=>server.state.rejectBodies.length===1,5000,'dismissal');await railFrame.getByRole('button',{name:'Dismiss',exact:true}).waitFor({state:'hidden'});
    for(const name of ['Scripted wallet','Phone <img src=x onerror=alert(1)>','界'.repeat(40),'x'.repeat(41)]){
      server.state.accounts=[{account_id:'phone',address:sendAddress,connector_id:'wallet-walletconnect',proof_type:'siwe',chain_namespace:'eip155:8453',wallet_display_name:name,wallet_mark:'wallet'}];server.state.approvals=[];await rail.reload({waitUntil:'networkidle'});railFrame=await walletFrame(rail);
      await railFrame.locator('.one-identity strong').filter({hasText:name.length>40?'Your wallet':name}).waitFor();assert(await railFrame.locator('img[onerror]').count()===0,'wallet names render as text');await assertNoHorizontalOverflow(railFrame,'phone name');
      await railFrame.getByRole('button',{name:'Settings',exact:true}).click();await railFrame.locator('#wallet-settings-drawer').waitFor();await assertNoHorizontalOverflow(railFrame,'phone settings');
    }
    await assertNoErrors(rail,server,'rail');await rail.close();console.log('wallet-product-layout-smoke: PASS (one list, Send, Receive, preferences, clipboard, connector, default, recovery, rename, delete, late result and peer names)');
  } finally {await browser.close().catch(()=>{});await server.close().catch(()=>{});if(process.env.KEEP_WALLET_UIUX_SMOKE_TMP!=='1')await rm(tempDir,{recursive:true,force:true});}
}
await run();
