import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { runtimeView, packets, permissionEntry } from "./lib/wallet-runtime-browser.mjs";

const request = (id = "first") => ({ ...packets.n7PrivateSummaries.find(f => f.id === "site-wallet").summary,
  request_id:id, chain_namespace:"eip155:20", created_at:Math.floor(Date.now()/1000), expires_at:Math.floor(Date.now()/1000)+600,
  reason:`Reason for ${id}`, requesting_app_name:"Browser", address:id === "first" ? "0x1111111111111111111111111111111111111111" : "0x2222222222222222222222222222222222222222" });
const entry = (id = "first") => ({ id:`wallet-approval-request:${id}`, source_app:"browser", kind:"wallet_approval_request",
  title:"Sign a message", body:`Reason for ${id}`, severity:"attention", read:true, requesting_origin:"https://shop.example",
  action_ref:{ action_id:`wallet-approve-request:${id}` } });
const event = async (r, kind = "wallet.changed") => r.page.evaluate(kind => {
  document.querySelector("#app").contentWindow.postMessage({type:"elastos:runtime-events",events:[{kind,scope:"wallet"}]},"*");
}, kind);
const settled = async r => r.frame.locator("body").evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));

test("fix1 JB5 site consumers enforce the exact shared ASCII origin rule", async t => {
  for (const app of ["wallet", "inbox"]) await t.test(app, async t => {
    const r = await runtimeView(t, app, { approvals:[request()], entries:[entry()] });
    const vectors = ["https://shop.example/path", "https://shop.example/", "https://Shop.Example", "https://shop.example:443", "https://0x7f000001", "https://%65xample.org", "https://[broken]", "https://shop.example:99999", "https://shop.example", "https://shop_sub.example:8443", "https://xn--bcher-kva.example"];
    for (const origin of vectors) {
      r.state.approvals[0].requesting_origin=origin; r.state.entries[0].requesting_origin=origin;
      await r.page.reload();
      await r.frame.locator(app === "wallet" ? ".wallet-request" : "#entry-detail").waitFor();
      const count = await r.frame.getByText(origin,{exact:true}).count();
      let valid=false; try { valid=new URL(origin).origin===origin && /^https?:\/\/[^/?#@\\]+$/.test(origin); } catch {}
      assert.equal(count, valid ? 1 : 0, `${app}: ${origin}`);
    }
    r.state.approvals[0].capsule_id="notes"; r.state.entries[0].source_app="notes";
    r.state.approvals[0].requesting_origin="https://shop.example"; r.state.entries[0].requesting_origin="https://shop.example";
    await r.page.reload();
    await r.frame.locator(app === "wallet" ? ".wallet-request" : "#entry-detail").waitFor();
    assert.equal(await r.frame.getByText("https://shop.example",{exact:true}).count(),0,"a copied projection on another app is omitted");
  });
});

for (const dismissed of [false,true]) test(`fix1 JB9 acknowledged facts belong to the clicked request (dismissed=${dismissed})`, async t => {
  const first=request("first"), second={...request("second"), status:dismissed?"approved":"pending",
    intent:dismissed?"transaction_intent":"browser_personal_sign", connector_id:dismissed?"wallet-walletconnect":"wallet-metamask", approved_at:dismissed?1:undefined,
    requesting_origin:"https://second.example"};
  const r=await runtimeView(t,"wallet",{approvals:[first,second]});
  const card=r.frame.locator('[data-wallet-request-id="second"]');
  await card.getByRole("button",{name:dismissed?"Dismiss":"Reject",exact:true}).click();
  await card.locator('[role="status"]').waitFor();
  assert.match(await card.textContent(),/Reason for second/);
  assert.equal(await card.getByText("https://second.example",{exact:true}).count(),1);
  assert(!(await card.textContent()).includes("Reason for first"));
});

test("fix1 JB14 an older Inbox read cannot replace a newer permission decision", async t => {
  const r=await runtimeView(t,"inbox",{permission:"requested",entries:[permissionEntry("requested")]});
  await r.frame.getByRole("button",{name:"Allow",exact:true}).waitFor();
  let release, entered;
  const held=new Promise(resolve=>entered=resolve);
  const gate=new Promise(resolve=>release=resolve);
  r.state.beforeInboxSummary=async()=>{r.state.beforeInboxSummary=null;entered();await gate;};
  await event(r); await held;
  await r.frame.getByRole("button",{name:"Allow",exact:true}).click();
  await r.frame.getByRole("button",{name:"Turn Off",exact:true}).waitFor();
  const response=r.page.waitForResponse(u=>u.url().endsWith("/api/apps/inbox/summary"));
  release(); await response; await settled(r);
  assert.equal(await r.frame.getByRole("button",{name:"Turn Off",exact:true}).count(),1);
  assert.equal(await r.frame.getByRole("button",{name:"Allow",exact:true}).count(),0);
});

test("fix1 Wallet keeps focus and scroll in Send during a balance refresh and clears the acknowledgement on leaving it", async t => {
  const managed={account_id:"managed",chain_namespace:"eip155:20",address:"0x3333333333333333333333333333333333333333",proof_type:"managed_evm",label:"Travel"};
  const r=await runtimeView(t,"wallet",{approvals:[request()],accounts:[managed,{account_id:request().account_id,chain_namespace:"eip155:20",address:request().address,proof_type:"siwe",connector_id:"wallet-metamask"}],balance:true});
  await r.frame.getByRole("button",{name:"Reject",exact:true}).click();
  await r.frame.locator('[role="status"]').filter({hasText:"Request rejected."}).waitFor();
  await r.frame.getByRole("button",{name:/Send/}).first().click();
  await r.frame.locator("#wallet-hero-back button").filter({hasText:/ELA/}).first().click();
  const input=r.frame.locator('input[name="amount"]'); await input.fill("0.25");
  const before=await input.evaluate(el=>({top:scrollY,focused:document.activeElement===el,value:el.value}));
  const response=r.page.waitForResponse(u=>u.url().includes("/api/apps/wallet/wallet/summary"));
  await event(r,"account.balance.changed"); await response; await settled(r);
  const after=await input.evaluate(el=>({top:scrollY,focused:document.activeElement===el,value:el.value}));
  assert.deepEqual(after,before);
  assert.equal(await r.frame.locator('.wallet-request [role="status"]').count(),0,"a deliberate action outside the acknowledgement ends its display");
});

for (const presentation of ["window","rail"]) test(`fix1 Inbox background refresh preserves focus and acknowledgement ends on filter selection (${presentation})`,async t=>{
  const r=await runtimeView(t,"inbox",{entries:[entry()],presentation});
  await r.frame.getByRole("button",{name:"Reject",exact:true}).click();
  await r.frame.locator('[role="status"]').filter({hasText:"Request rejected."}).waitFor();
  await r.frame.locator("#refresh").focus();
  const before=await r.frame.locator("#refresh").evaluate(el=>({top:scrollY,focused:document.activeElement===el}));
  const response=r.page.waitForResponse(u=>u.url().endsWith("/api/apps/inbox/summary"));
  await event(r);await response;await settled(r);
  assert.deepEqual(await r.frame.locator("#refresh").evaluate(el=>({top:scrollY,focused:document.activeElement===el})),before);
  if (presentation === "rail") await r.frame.locator("body").evaluate(() => window.dispatchEvent(new MessageEvent("message", {
    origin:"null",source:window.parent,data:{type:"elastos:menu-command",cmd:"filter-review"},
  })));
  else await r.frame.locator('[data-filter="review"]').click();
  assert.equal(await r.frame.locator('[role="status"]').filter({hasText:"Request rejected."}).count(),0);
});

test("fix1 Wallet accounts remain visible when only requests are unavailable",async t=>{
  const r=await runtimeView(t,"wallet",{approvalsUnavailable:true,accounts:[{account_id:"external",chain_namespace:"eip155:20",address:request().address,
    connector_id:"wallet-walletconnect",proof_type:"siwe",wallet_display_name:"Trust Wallet",wallet_mark:"wallet"}]});
  await r.frame.locator("#wallet-status").filter({hasText:"Wallet could not load your requests."}).waitFor();
  assert.equal(await r.frame.locator('.wallet-account .wallet-card-name').count(),1,"the independent account read is rendered before the request-read error");
  assert.equal(await r.frame.locator('.wallet-account .wallet-card-name').textContent(),"Trust Wallet");
  assert.equal(await r.frame.getByRole("button",{name:/Send/}).first().isEnabled(),true);
});

test("fix1 removal dialog names its row and uses the shared removal sentence",async t=>{
  const r=await runtimeView(t,"wallet",{accounts:[{account_id:"external",chain_namespace:"eip155:20",address:request().address,
    connector_id:"wallet-walletconnect",proof_type:"siwe",wallet_display_name:"Trust Wallet",wallet_mark:"wallet"}]});
  await r.frame.getByRole("button",{name:"Remove",exact:true}).click();
  await r.frame.locator(".wallet-modal-header").waitFor();
  assert.equal(await r.frame.locator(".wallet-modal-header h2").textContent(),"Remove Trust Wallet?");
  const identity=r.frame.locator(".wallet-modal-header h2 bdi");
  assert.equal(await identity.textContent(),"Trust Wallet");
  assert.equal(await identity.evaluate(el=>el.dir),"auto");
  assert.equal(await identity.evaluate(el=>getComputedStyle(el).unicodeBidi),"isolate");
  assert.equal(await r.frame.getByText("Remove this account from your Home. Your funds stay unchanged. This does not cancel a transaction in your wallet. Removing the last account connected through WalletConnect also clears Home's saved connection. Confirm with your passkey to remove the account.",{exact:true}).count(),1);
});

test("fix1 passkey-begin consent conflict keeps the fixed Inbox sentence",async t=>{
  const r=await runtimeView(t,"inbox",{entries:[permissionEntry("requested")],permission:"requested",
    passkeyError:'request failed: 409 Conflict {"schema":"elastos.home.wallet-connector.effect.error/v1","code":"conflict"}'});
  await r.frame.getByRole("button",{name:"Allow",exact:true}).click();
  await r.frame.locator("#refresh:enabled").waitFor();
  assert.equal(await r.frame.locator("#status-text").textContent(),"This request has changed. Refresh Inbox and review the current request.");
  assert.equal(r.calls.filter(c=>c.path.endsWith("/actions")&&c.input.action_id.includes("allow")).length,0);
});

test("fix1 request cards use Runtime's catalog label",async t=>{
  const r=await runtimeView(t,"wallet",{approvals:[{...request(),capsule_id:"custom-app",requesting_app_name:"Studio Notes"}]});
  await r.frame.locator(".wallet-request").waitFor();
  assert.match(await r.frame.locator(".wallet-request-main").textContent(),/Studio Notes/);
  assert(!(await r.frame.locator(".wallet-request-main").textContent()).includes("custom-app"));
});

test("fix1 account-name branches after the external fallback are managed-only",async()=>{
  const {accountName}=await import("../capsules/wallet/browser/wallet-format.js");
  for(const connector_id of ["wallet-metamask","wallet-walletconnect","wallet-unisat"]) assert.equal(accountName({connector_id,proof_type:"siwe"},0),"Your wallet");
  const source=await readFile(new URL("../capsules/wallet/browser/wallet-format.js",import.meta.url),"utf8");
  const body=source.slice(source.indexOf("export function accountName("),source.indexOf("export function cleanAccountLabel("));
  assert(!body.includes('connectorId ==='),"unreachable external connector branches have been removed");
});

test("fix1 request-kind titles stay consistent across account proof types",async()=>{
  const {requestTitle}=await import("../capsules/wallet/browser/wallet-format.js");
  const titles={auth_challenge:"Review sign-in request",capability_grant:"Review access request",credential:"Sign a credential",
    publish_envelope:"Review publishing request",transaction_intent:"Send transaction",browser_account_access:"Share your wallet address with this site",
    browser_personal_sign:"Sign a message",browser_typed_data_sign:"Sign typed data",bitcoin_bip322_proof:"Confirm this Bitcoin account is yours",
    revocation:"Review request",unknown:"Review request"};
  for(const [intent,title] of Object.entries(titles)) for(const proof_type of ["managed_evm","siwe"])
    assert.equal(requestTitle({intent,proof_type,connector_id:proof_type==="siwe"?"wallet-metamask":null}),title,intent);
});
