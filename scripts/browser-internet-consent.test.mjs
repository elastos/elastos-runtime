import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { readFileSync, mkdirSync } from "node:fs";
import http from "node:http";
import test from "node:test";
import {makeSystemSummary,makeAppearanceRecord,inertSystemApiResponse} from "./system-uiux-fixture.mjs";
const require = createRequire(new URL("../elastos/tools/browser-playwright-engine/package.json", import.meta.url));
const { chromium } = require("playwright");
const root = new URL("../", import.meta.url);
const consentText = "Browser opens websites using this computer's internet connection, or another connection you chose in Browser settings. Websites can see that connection's address. You can turn this off at any time here in Inbox.";
const hostScript = `window.messages=[];window.approvals=[];window.passkeyAllowed=true;window.holdPasskey=false;
window.showFixtureApp=(target,query={})=>{
  for(const frame of document.querySelectorAll('iframe')) frame.hidden=true;
  let frame=document.querySelector('iframe[data-app="'+target+'"]');
  if(!frame){frame=document.createElement('iframe');frame.dataset.app=target;
    frame.src='/apps/'+target+'/?'+new URLSearchParams({home_origin:location.origin,...query})+'#home_token=fixture';document.body.append(frame);}
  frame.hidden=false;
};
addEventListener('message',e=>{
  messages.push(e.data);
  if(e.data?.type==='home:open-target' && new URLSearchParams(location.search).has('flow')) {
    showFixtureApp(e.data.target,e.data.query);return;
  }
  if(e.data?.type==="home:focus-browser" && document.querySelector('iframe[data-app="browser"]')) {showFixtureApp("browser");return;}
  if(e.data?.type!=="elastos.home.passkey-step-up.request/v1")return;
  approvals.push(e.data.operation);
  window.completeFixturePasskey=()=>e.source.postMessage({type:"elastos.home.passkey-step-up.result/v1",requestId:e.data.requestId,
    ...(passkeyAllowed?{stepUpToken:"fixture-step-up"}:{error:"Passkey cancelled."})},"*");
  if(!holdPasskey)completeFixturePasskey();
});`;

async function screen(page, name) {
  if (!process.env.BROWSER_INTERNET_SCREENSHOTS || page.viewportSize().width !== 1280) return;
  mkdirSync(process.env.BROWSER_INTERNET_SCREENSHOTS,{recursive:true});
  for (const frame of page.frames().slice(1)) await frame.evaluate(theme => window.elastosTheme?.set(theme), process.env.BROWSER_INTERNET_SCREEN_THEME || "light");
  await page.waitForTimeout(250);
  await page.screenshot({path:`${process.env.BROWSER_INTERNET_SCREENSHOTS}/${process.env.BROWSER_INTERNET_SCREEN_THEME === "dark" ? "dark-" : ""}${name}.png`});
}
async function fixture() {
  const state = {consent:"off", expired:false, grantedRequestId:"fixture", requests:0, requestAttempts:0, stopPending:false, reads:0, failedReads:0, opens:[], actions:[], navigations:[]};
  const server=http.createServer(async (req,res) => {
    const url=new URL(req.url,"http://localhost");
    res.setHeader("access-control-allow-origin","*");
    res.setHeader("access-control-allow-headers","content-type,x-elastos-home-token");
    res.setHeader("access-control-allow-methods","GET,POST,OPTIONS");
    if(req.method==="OPTIONS") {res.writeHead(204).end();return;}
    const json=value=>{res.setHeader("content-type","application/json");res.end(JSON.stringify(value));};
    let input;
    if (req.method === "POST") {let body="";for await (const chunk of req) body+=chunk;input=JSON.parse(body);}
    if(url.pathname === "/shell") {
      res.setHeader("content-type","text/html");
      res.end(`<style>html,body,iframe{margin:0;border:0;width:100%;height:100%}</style><script>${hostScript}
        addEventListener('message',e=>{
          if(['home:open-target','home:focus-browser'].includes(e.data?.type))document.querySelector('#gui').contentWindow.postMessage({fixtureAction:e.data},'*');
        });</script><iframe id="gui" sandbox="allow-scripts allow-forms allow-modals allow-pointer-lock" src="/shell-gui"></iframe>`);return;
    }
    if(url.pathname === "/shell-gui") {
      res.setHeader("content-type","text/html");
      const template=readFileSync(new URL("capsules/home-gui/browser/home-gui-template.html",root),"utf8");
      res.end(`<link rel="stylesheet" href="/apps/home-gui/style.css">${template}<script type="module">
        import * as core from '/apps/home-gui/shell-core.js?v=home-20261101d';
        import * as windows from '/apps/home-gui/shell-windows.js?v=home-20261101d';
        import * as stages from '/apps/home-gui/shell-stages.js?v=home-20261101d';
        for(const node of document.querySelectorAll('[data-home-gui-hidden-by-host]')) {node.hidden=false;node.inert=false;}
        core.shellState.currentSummary={targets:[{target:'browser',title:'Browser'},{target:'inbox',title:'Inbox'}]};
        core.shellState.browserContextId='browser:0123456789abcdef0123456789abcdef';
        let serial=0;
        windows.configureWindowHooks({clearIdentitySurface(){},refreshLauncherIfVisible(){},hideLauncher(){},renderDesktop(){},renderTaskbar(){},updateTaskbarState(){},syncMenubar(){},
          launchTarget:async(target,query)=>({target,title:target,attach_kind:'iframe',launch_status:'launched',
            route:'/apps/'+target+'/?'+new URLSearchParams({...query,home_origin:location.origin})+'#home_token=fixture-'+(++serial)})});
        addEventListener('message',e=>{
          if(e.source!==window.top)return;
          const action=e.data?.fixtureAction;
          if(action?.type==='home:open-target') {
            const owner=[...core.shellState.windows.values()].find(entry=>new URL(entry.node.querySelector('iframe')?.dataset.route || '/',location.href).hash==='#home_token='+action.homeToken);
            if(owner?.targetId==='browser' && action.target==='inbox' && action.query.browser_request_id)window.requestingBrowserInstance=owner.launchQuery.browser_instance;
            windows.openTarget(action.target,{query:action.target==='inbox' ? {notification_id:action.query.notification_id} : action.query});
          }
          if(action?.type==='home:focus-browser')windows.focusOpenBrowserWindow(window.requestingBrowserInstance || '');
        });
        window.fixtureShell={core,windows,stages};
      </script>`);return;
    }
    if(url.pathname === "/gui") {
      res.setHeader("content-type","text/html");
      res.end(`<iframe src="/apps/browser/?browser_restore=1&home_origin=http://127.0.0.1:${server.address().port}#home_token=fixture"></iframe>`);return;
    }
    if (url.pathname === "/") {
      if(url.searchParams.has("nested")) {
        res.setHeader("content-type","text/html");
        res.end(`<script>${hostScript}</script><iframe id="gui" sandbox="allow-scripts allow-forms" src="/gui"></iframe>`);return;
      }
      const app=url.searchParams.get("app") || "browser";
      res.setHeader("content-type","text/html");
      res.end(`<style>html,body{margin:0;height:100%}iframe{border:0;width:100%;height:100%}</style><script>${hostScript}</script><iframe data-app="${app}" src="/apps/${app}/?browser_restore=${url.searchParams.get("restore") || "0"}&notification_id=browser-internet:permission&url=https%3A%2F%2Fexample.com%2Frequested&home_origin=http://127.0.0.1:${server.address().port}#home_token=fixture"></iframe>`);return;
    }
    if (url.pathname === "/api/apps/browser/internet") {
      state.reads++;
      if(req.method==="GET" && state.failedReads>0) {state.failedReads--;res.statusCode=503;json({error:"Fixture read failed"});return;}
      if(input?.action === "revoke") {assert.equal(input.step_up_token,"fixture-step-up");state.consent="revoked";}
      if (input?.action === "end") {json({status:"ended"});return;}
      if (input?.action === "request" && state.requestError) {state.requestAttempts++;res.statusCode=403;json({error:state.requestError});return;}
      if (input?.action === "request" && state.stopPending) {state.requestAttempts++;res.statusCode=403;json({error:"Finish stopping Browser internet before requesting it again"});return;}
      if (input?.action === "request") {state.requestAttempts++;state.requests++;state.consent="requested";state.expired=false;await state.requestBarrier;}
      json({status:state.consent,stop_pending:state.stopPending,request_id:state.consent==="granted"?state.grantedRequestId:undefined,request:state.expired?null:{resource:"elastos://browser/internet",grant_id:"fixture-grant",request_id:"fixture",text:consentText,expires_at:Math.floor(Date.now()/1000)+3600}});return;
    }
    if (url.pathname === "/api/apps/inbox/summary") {
      const expired=state.consent === "requested" && state.expired;
      const pending=state.consent === "requested" && !expired;
      const body=expired?"This expired request was made.":pending?consentText:state.consent === "granted"?"Browser can open websites. Allowed with your passkey.":state.consent === "refused"?"Browser cannot open websites. Not allowed.":"Browser cannot open websites. Turned off.";
      json({notifications:{unread_count:pending?1:0,attention_count:pending?1:0,entries:[{
        id:"browser-internet:permission",source_app:"browser",kind:pending?"browser_internet_request":"browser_internet_decision",
        title:pending?"Allow Browser to use the internet?":"Browser internet access",body,severity:pending?"attention":"info",read:!pending,created_at:1794312000,
        action_ref:{app:"inbox",action_id:pending?"browser-internet-allow:fixture":state.consent==="granted"?"browser-internet-turn-off:fixture-grant":"browser-internet-request"},
      }]}});return;
    }
    if (url.pathname === "/api/apps/inbox/actions") {
      state.actions.push(input);
      if(input.action_id === "browser-internet-allow:fixture") {
        assert.equal(input.step_up_token,"fixture-step-up");state.consent="granted";
      } else if(input.action_id === "browser-internet-deny:fixture") state.consent="refused";
      else if(input.action_id === "browser-internet-turn-off:fixture-grant") {assert.equal(input.step_up_token,"fixture-step-up");state.consent="revoked";}
      json({ok:true});return;
    }
    if (url.pathname === "/api/apps/browser/summary") {
      json({net:{exit_provider:{remote_carrier_exits:[{id:"sasha-exit",display_name:"A shared Exit",contact_name:"Sasha",allowed_for_principal:true},{id:"legacy-exit",display_name:"A service label",allowed_for_principal:true}]}},engine_adapter:{adapters:[],display_attach_supported:true},sessions:{schema:"elastos.browser.session-capacity/v1",status:"configured",fresh_start_allowed:true,recoverable_page:state.recoverableUrl ? {
        schema:"elastos.browser.recoverable-page/v1",state:"active",page_id:"retained",
        cleanup:{schema:"elastos.browser.cleanup-handle/v1",id:"cleanup-retained"},
        service_selection:{schema:"elastos.browser.service-selection/v1",engine_id:"",exit_id:""},
        engine_page:{schema:"elastos.browser.engine.page/v1",page_id:"retained",actual_url:state.recoverableUrl,
          display_session:{mode:"webrtc_remote_display",display_generation:"display:"+"1".repeat(32)}}
      } : null}});return;
    }
    if (url.pathname === "/api/apps/browser/pages/retained/status") {
      if(state.bindOwners && req.headers["x-elastos-home-token"]!==state.ownerToken){res.writeHead(404).end();return;}
      json({schema:"elastos.browser.page-status/v1",page_id:"retained",direct_network:false,actual_url:state.recoverableUrl});return;
    }
    if (url.pathname === "/api/apps/browser/pages/retained/restore") {
      assert.equal(input.cleanup_id,"cleanup-retained");
      assert.match(input.browser_instance,/^browser:/);
      state.ownerToken=req.headers["x-elastos-home-token"];
      state.restores=(state.restores||0)+1;
      json({ok:true});return;
    }
    if (url.pathname === "/api/apps/browser/pages/retained/input") {
      if(state.bindOwners && req.headers["x-elastos-home-token"]!==state.ownerToken){res.writeHead(404).end();return;}
      state.navigations.push(input.event);state.recoverableUrl=input.event.url;json({accepted:true});return;
    }
    if (url.pathname === "/api/apps/browser/pages/retained/close") {
      state.recoverableUrl=null;
      json({schema:"elastos.browser.close-result/v1",page_id:"retained",cleanup_id:input.cleanup_id,closed:true});return;
    }
    if (url.pathname === "/api/apps/browser/pages/retained/webrtc" && state.completeOpen) {
      if(state.peerPage) {
        if(input.type==="offer") {
          const sdp=await state.peerPage.evaluate(async sdp=>{
            const peer=new RTCPeerConnection();(window.fixturePeers||=[]).push(peer);
            await peer.setRemoteDescription({type:"offer",sdp});
            const answer=await peer.createAnswer();await peer.setLocalDescription(answer);return answer.sdp;
          },input.sdp);
          json({schema:"elastos.browser.webrtc-answer/v1",type:"answer",sdp});
        } else json({schema:"elastos.browser.webrtc-signal-ack/v1",type:input.type,accepted:true});
        return;
      }
      // Hold the external media handshake; these checks cover Home and permission state.
      await new Promise(resolve=>res.on("close",resolve));return;
    }
    if (url.pathname === "/api/apps/browser/open") {
      state.ownerToken=req.headers["x-elastos-home-token"];
      if(state.completeOpen)state.recoverableUrl=input.url;
      state.opens.push(input);json({schema:"elastos.browser.open-accepted/v1",status_url:"/api/apps/browser/open/fixture"});return;
    }
    if (url.pathname === "/api/apps/browser/open/fixture") {
      if(state.completeOpen)json({schema:"elastos.browser.open-status/v1",status:"completed",result:{
        schema:"elastos.browser.open-result/v1",runtime_cleanup:{schema:"elastos.browser.cleanup-handle/v1",id:"cleanup-retained"},
        engine_page:{schema:"elastos.browser.engine.page/v1",page_id:"retained",actual_url:state.recoverableUrl,
          display_session:{schema:"elastos.browser.display-session/v1",mode:"webrtc_remote_display",width:1280,height:720,
            display_generation:"display:"+"1".repeat(32),signaling_url:"/api/apps/browser/pages/retained/webrtc",
            offerer:"browser",media_transport:"runtime_relay",ice_servers:[],input:"runtime_route",audio:false}}
      }});else json({schema:"elastos.browser.open-status/v1",status:"pending"});return;
    }
    if(url.pathname === "/api/apps/system/summary") {json(makeSystemSummary(makeAppearanceRecord({theme:"light"})));return;}
    if(url.pathname.startsWith("/api/")) {
      const response=inertSystemApiResponse(url.pathname);if(response) {json(response);return;}
    }
    const match=url.pathname.match(/^\/apps\/(browser|inbox|home|home-gui|system)\/(.*)$/);
    if (!match || match[2].includes("..")) {res.writeHead(404).end();return;}
    const name=match[2] || "index.html";
    try {const bytes=readFileSync(new URL(`capsules/${match[1]}/browser/${name}`,root));res.setHeader("content-type",(name.endsWith(".js") || name.endsWith(".mjs"))?"text/javascript":name.endsWith(".css")?"text/css":"text/html");res.end(bytes);} catch {res.writeHead(404).end();}
  });
  await new Promise(resolve=>server.listen(0,"127.0.0.1",resolve));
  return {state,url:`http://127.0.0.1:${server.address().port}/`,close:()=>new Promise(resolve=>server.close(resolve))};
}
async function inboxMessage(page) {
  await page.waitForFunction(()=>messages.some(m=>m.type==="home:open-target" && m.target==="inbox" && m.query.notification_id==="browser-internet:permission"));
}

test("fresh allowed Browser opens the default or launch URL; blocked Browser opens neither", async () => {
  const f=await fixture();const browser=await chromium.launch({headless:true});
  try {
    for (const url of [null,"https://example.com/startup"]) {
      f.state.consent="granted";f.state.opens=[];f.state.requests=0;
      const page=await browser.newPage();
      const query=new URLSearchParams({home_origin:f.url});if(url)query.set("url",url);
      const opened=page.waitForResponse(r=>r.url().endsWith("/api/apps/browser/open"));
      await page.goto(f.url+"apps/browser/?"+query+"#home_token=fixture");await opened;
      assert.deepEqual(f.state.opens.map(open=>open.url),[url || "https://ela.city/"]);
      assert.equal(f.state.requests,0,"an existing grant requires no new request");await page.close();
    }
    f.state.consent="refused";f.state.opens=[];f.state.requests=0;
    const page=await browser.newPage();await page.goto(f.url);
    await page.frameLocator("iframe").getByRole("button",{name:"Open Inbox",exact:true}).waitFor();
    await page.waitForTimeout(2200);
    assert.deepEqual(f.state.opens,[]);assert.equal(f.state.requests,0);await page.close();
  } finally {await browser.close();await f.close();}
});

test("Browser permission instructions point to Inbox",()=>{
  for(const path of ["SECURITY.md","docs/BROWSER_CAPSULE.md"]) {
    const text=readFileSync(new URL(path,root),"utf8");
    assert.match(text,/Manage in\s+Inbox/);
    assert.doesNotMatch(text,/opens System for passkey|System keeps Retry Stop/);
  }
  const source=readFileSync(new URL("capsules/browser/browser/browser.js",root),"utf8");
  assert.doesNotMatch(source,/System Security/);
});

test("revoking permission hides the old website and allowing restores the render panel", async () => {
 const f=await fixture();const browser=await chromium.launch({headless:true});
 try {
  f.state.consent="granted";const page=await browser.newPage();
  const opening=page.waitForResponse(r=>r.url().endsWith("/api/apps/browser/open"));await page.goto(f.url);await opening;
  const frame=page.frameLocator("iframe");
  await frame.locator("#browser-render-panel").evaluate(e=>{const old=document.createElement("div");old.id="old-website";old.textContent="Old website";e.append(old);});
  f.state.consent="revoked";await frame.getByRole("button",{name:"Open Inbox",exact:true}).waitFor({timeout:5000});
  assert.equal(await frame.locator("#old-website").isVisible(),false);
  f.state.consent="granted";await frame.locator("#browser-internet-request").waitFor({state:"hidden",timeout:5000});
  assert.equal(await frame.locator("#browser-render-panel").isVisible(),true);await page.close();
 } finally {await browser.close();await f.close();}
});
test("Allow after denial shows the empty hint and focuses the address without navigating", async () => {
 const f=await fixture();const browser=await chromium.launch({headless:true});
 try {
  const page=await browser.newPage({viewport:{width:1280,height:844}});await page.goto(f.url);const frame=page.frameLocator("iframe");
  await frame.getByRole("button",{name:"Show Request",exact:true}).waitFor();f.state.consent="refused";
  await frame.getByRole("button",{name:"Open Inbox",exact:true}).waitFor({timeout:5000});
  f.state.consent="granted";
  await frame.locator("#browser-render-empty").getByText("Type a website address to open it.",{exact:true}).waitFor({timeout:5000});
  assert.equal(await frame.locator("#browser-url").evaluate(e=>e===document.activeElement),true);
  await page.waitForTimeout(2200);assert.equal(f.state.opens.length,0);assert.equal(f.state.requests,1);
  assert.equal(await frame.locator("#browser-status").evaluate(e=>e.textContent.trim()==="" && getComputedStyle(e).opacity!=="0"),false,"an empty status message must not leave a visible bubble");
  await screen(page,"browser-empty-allowed");await page.close();
 } finally {await browser.close();await f.close();}
});
test("Inbox decision dates and keyboard focus are readable in light and dark themes", async () => {
 const f=await fixture();const browser=await chromium.launch({headless:true});
 try {
  f.state.consent="granted";
  for(const theme of ["light","dark"]) {
   const page=await browser.newPage({viewport:{width:1280,height:844}});await page.goto(f.url+"?app=inbox");const frame=page.frameLocator("iframe");
   const off=frame.getByRole("button",{name:"Turn Off",exact:true});await off.waitFor();
   await off.evaluate((e,theme)=>window.elastosTheme.set(theme),theme);
   const expected=await off.evaluate(()=>new Date(1794312000*1000).toLocaleString(undefined,{dateStyle:"medium",timeStyle:"short"}));
   assert.match(await frame.locator("#entry-detail .entry-body").innerText(),new RegExp(expected.replace(/[.*+?^${}()|[\]\\]/g,"\\$&")));
   await off.focus();await page.keyboard.press("Tab");await page.keyboard.press("Shift+Tab");
   const focus=await off.evaluate(e=>({focused:e===document.activeElement,width:getComputedStyle(e).outlineWidth,style:getComputedStyle(e).outlineStyle,offset:getComputedStyle(e).outlineOffset,color:getComputedStyle(e).outlineColor}));
   assert.equal(focus.focused,true);assert.equal(focus.width,"2px");assert.equal(focus.style,"solid");assert.equal(focus.offset,"2px");assert.notEqual(focus.color,"rgba(0, 0, 0, 0)");
   if(process.env.BROWSER_INTERNET_SCREENSHOTS)await page.screenshot({path:process.env.BROWSER_INTERNET_SCREENSHOTS+"/inbox-focus-"+theme+".png"});
   await page.close();
  }
 } finally {await browser.close();await f.close();}
});
test("permission flow copy uses plain connection names and an existing address control",()=>{
 for(const path of ["capsules/browser/browser/index.html","capsules/browser/browser/browser.js","capsules/browser/browser/browser-startup.js","capsules/browser/browser/browser-status.js","capsules/browser/browser/browser-remote-display.js"]) {
  const text=readFileSync(new URL(path,root),"utf8");assert.doesNotMatch(text,/press Go|this Mac's internet address|Exit Node|Browser exit node/);
 }
 const source=readFileSync(new URL("capsules/browser/browser/browser.js",root),"utf8");
 assert.match(source,/Websites can see this computer's internet address/);
 assert.match(source,/Websites can see the address of the connection Browser uses/);
});

test("Browser asks once, polls every two seconds and opens the requested page without a click", async () => {
  const f=await fixture();const browser=await chromium.launch({headless:true});
  try {
    for (const width of [1280,390]) {
      f.state.consent="off";f.state.opens=[];f.state.requests=0;
      const page=await browser.newPage({viewport:{width,height:844},colorScheme:"light"});
      await page.goto(f.url);const frame=page.frameLocator("iframe");
      await frame.getByText("Waiting for your answer in Inbox.",{exact:true}).waitFor({timeout:4000});
      assert.equal(await frame.locator("#browser-status").isVisible(),false);

      assert.equal(await frame.getByRole("button",{name:"Ask in Inbox",exact:true}).count(),0);
      await page.waitForFunction(()=>messages.some(m=>m.type==="home:open-target" && m.target==="inbox" && m.query.notification_id==="browser-internet:permission"));
      assert.equal(f.state.requests,1);
      await frame.getByRole("button",{name:"Show Request",exact:true}).click();
      assert.equal(f.state.requests,1,"Show Request reuses the current request");assert.equal(f.state.opens.length,0);
      await frame.getByText("Waiting for your answer in Inbox.",{exact:true}).waitFor();
      await screen(page,"browser-waiting");
      await frame.getByRole("button",{name:"Browser settings",exact:true}).click();
      assert.equal(await frame.locator("#browser-internet").count(),0);
      await frame.getByText("Internet access: Off",{exact:true}).waitFor();
      await frame.getByText("Websites can see this computer's internet address.",{exact:true}).waitFor();
      await frame.locator("#browser-exit").selectOption("sasha-exit");
      await frame.getByText("Websites can see the address of the connection Browser uses.",{exact:true}).waitFor();
      await frame.locator("#browser-exit").selectOption("legacy-exit");
      await frame.getByText("Websites can see the address of the connection Browser uses.",{exact:true}).waitFor();
      await frame.locator("#browser-exit").selectOption("");
      await frame.getByRole("button",{name:"Manage in Inbox",exact:true}).click();await inboxMessage(page);
      await frame.getByRole("button",{name:"Close Browser settings"}).click();
      f.state.consent="granted";
      await page.waitForResponse(r=>r.url().endsWith("/api/apps/browser/open"),{timeout:5000});
      assert.equal(f.state.opens.length,1);assert.equal(f.state.opens[0].url,"https://example.com/requested");
      assert.equal(await frame.locator("#browser-internet-request").isVisible(),false);
      await screen(page,"browser-allowed");
      await Promise.all([
        page.waitForResponse(r=>r.url().endsWith("/api/apps/browser/internet") && r.request().method()==="GET"),
        frame.getByRole("button",{name:"Browser settings",exact:true}).click(),
      ]);
      await frame.getByText("Internet access: Allowed",{exact:true}).waitFor();
      await frame.getByText("Pages go out through",{exact:true}).waitFor();await frame.getByText("Websites can see this computer's internet address.",{exact:true}).waitFor();
      await screen(page,"browser-settings");
      assert.equal(f.state.opens.length,1,"refresh does not repeat the open");
      f.state.consent="revoked";
      await frame.getByText("Internet access is off for Browser.",{exact:true}).waitFor({timeout:4000});
      await frame.getByRole("button",{name:"Close Browser settings"}).click();
      await frame.getByRole("button",{name:"Browser settings",exact:true}).click();
      await frame.getByText("Internet access: Off",{exact:true}).waitFor({timeout:2000});
      await page.close();
    }
    for (const consent of ["refused","revoked"]) {
      f.state.consent=consent;
      const page=await browser.newPage({viewport:{width:1280,height:844},colorScheme:"light"});await page.goto(f.url);const frame=page.frameLocator("iframe");
      await frame.getByText("Internet access is off for Browser.",{exact:true}).waitFor();
      await screen(page,"browser-off");
      await frame.getByRole("button",{name:"Open Inbox",exact:true}).click();await inboxMessage(page);
      const reads=f.state.reads;await page.goto("about:blank");await page.waitForTimeout(2200);
      assert.equal(f.state.reads,reads,"permission polling stops on leave");await page.close();
    }
  } finally {await browser.close();await f.close();}
});

test("only an explicit Browser action continues once; restore, close, denial and expiry cancel it", async () => {
  const f=await fixture();const browser=await chromium.launch({headless:true});
  try {
    const restored=await browser.newPage({viewport:{width:1280,height:844},colorScheme:"light"});await restored.goto(f.url+"?restore=1");
    await restored.frameLocator("iframe").locator("#browser-internet-request").waitFor();
    await screen(restored,"browser-blocked");
    assert.equal(f.state.requests,0);assert.equal(await restored.evaluate(()=>messages.some(m=>m.target==="inbox")),false);
    const asking=await browser.newPage();await asking.goto(f.url+"?restore=1");const frame=asking.frameLocator("iframe");
    await frame.locator("#browser-internet-request").waitFor();
    await frame.getByRole("textbox",{name:"Web address"}).fill("https://example.com/go");
    await frame.getByRole("textbox",{name:"Web address"}).press("Enter");
    await asking.waitForFunction(()=>messages.some(m=>m.target==="inbox" && m.query.notification_id==="browser-internet:permission"));
    assert.equal(f.state.requests,1);
    f.state.consent="granted";await asking.waitForResponse(r=>r.url().endsWith("/api/apps/browser/open"));
    await asking.waitForTimeout(4300);
    assert.equal(f.state.opens.length,1);assert.equal(f.state.opens[0].url,"https://example.com/go");
    await asking.close();await restored.close();
    for(const ending of ["closed","refused","expired"]) {
      f.state.consent="off";f.state.expired=false;f.state.opens=[];
      const page=await browser.newPage();await page.goto(f.url);
      await page.waitForFunction(()=>messages.some(m=>m.target==="inbox"),{timeout:4000});
      if(ending === "closed") await page.close();
      else {
        if(ending === "expired") f.state.expired=true;else f.state.consent="refused";
        await page.frameLocator("iframe").getByText("Internet access is off for Browser.",{exact:true}).waitFor({timeout:5000});
      }
      f.state.expired=false;f.state.consent="granted";
      await new Promise(resolve=>setTimeout(resolve,2300));assert.equal(f.state.opens.length,0,ending+" cancels continuation");
      if(!page.isClosed()) await page.close();
    }
  } finally {await browser.close();await f.close();}
});

test("an explicit Home open in a restored Browser uses the same permission request path", async () => {
  const f=await fixture();const browser=await chromium.launch({headless:true});
  try {
    const page=await browser.newPage();await page.goto(f.url+"?nested=1");
    const gui=page.frameLocator("#gui");const frame=gui.frameLocator("iframe");
    await frame.locator("#browser-internet-request").waitFor();assert.equal(f.state.requests,0);
    await gui.locator("body").evaluate(()=>document.querySelector("iframe").contentWindow.postMessage({
      type:"elastos.browser.navigate/v1",homeToken:"fixture",url:"https://example.com/from-home",
    },"*"));
    await page.waitForFunction(()=>messages.some(m=>m.target==="inbox" && m.query.notification_id==="browser-internet:permission"),null,{timeout:4000});
    assert.equal(f.state.requests,1);assert.equal(f.state.opens.length,0);
    f.state.consent="granted";await page.waitForResponse(r=>r.url().endsWith("/api/apps/browser/open"));
    assert.equal(f.state.opens.length,1);assert.equal(f.state.opens[0].url,"https://example.com/from-home");
    await page.close();
  } finally {await browser.close();await f.close();}
});

test("a grant for a replacement request cannot resume an earlier denied request", async () => {
  const f=await fixture();const browser=await chromium.launch({headless:true});
  try {
    const page=await browser.newPage();await page.goto(f.url);
    await page.waitForFunction(()=>messages.some(m=>m.target==="inbox"));
    // Refusal and a new grant can both happen between two summary polls.
    f.state.grantedRequestId="replacement";f.state.consent="granted";
    await page.waitForTimeout(2300);assert.equal(f.state.opens.length,0);
    await page.close();
  } finally {await browser.close();await f.close();}
});

test("restoring after approval never creates a fresh page, and reload never repeats a request", async () => {
  const f=await fixture();const browser=await chromium.launch({headless:true});
  try {
    f.state.consent="granted";
    const page=await browser.newPage();await page.goto(f.url+"?restore=1");
    await page.waitForTimeout(2300);assert.equal(f.state.opens.length,0);
    f.state.consent="off";await page.goto(f.url);
    await page.waitForFunction(()=>messages.some(m=>m.target==="inbox"));
    const requests=f.state.requests;
    await page.frameLocator("iframe").locator("body").evaluate(()=>location.reload());
    await page.waitForTimeout(2300);assert.equal(f.state.requests,requests);
    f.state.consent="granted";await page.waitForTimeout(2300);assert.equal(f.state.opens.length,0);
    await page.close();
  } finally {await browser.close();await f.close();}
});

test("Inbox manages active and off grants with confirmation, passkey and retained decisions", async () => {
  const f=await fixture();const browser=await chromium.launch({headless:true});
  try {
    f.state.consent="granted";
    const page=await browser.newPage({viewport:{width:1280,height:844},colorScheme:"light"});
    await page.goto(f.url+"?app=inbox");const frame=page.frameLocator("iframe");
    const off=frame.locator("#entry-detail").getByRole("button",{name:"Turn Off",exact:true});
    await off.waitFor({timeout:3000});await screen(page,"inbox-decided-allowed");
    await off.click();await frame.locator("dialog[open]").waitFor();
    assert.equal(await frame.locator('dialog [value="cancel"]').evaluate(e=>e===document.activeElement),true);
    await screen(page,"inbox-confirm");
    await frame.getByRole("button",{name:"Cancel",exact:true}).click();
    assert.deepEqual(await page.evaluate(()=>approvals),[]);assert.equal(f.state.consent,"granted");
    await page.evaluate(()=>passkeyAllowed=false);await off.click();await frame.locator('dialog [value="off"]').click();
    await page.waitForFunction(()=>approvals.length===1);
    await frame.locator('#entry-detail button:not(:disabled)').waitFor();assert.equal(f.state.consent,"granted");assert.equal(f.state.actions.length,0);
    await page.evaluate(()=>passkeyAllowed=true);await off.click();await frame.locator('dialog [value="off"]').click();
    await frame.locator("#entry-detail .entry-body").filter({hasText:/Browser cannot open websites. Turned off on/}).waitFor();
    assert.equal(f.state.requests,0);assert.equal(await frame.locator("#pending-count").innerText(),"0");await screen(page,"inbox-turned-off");
    await page.reload();await frame.locator("#entry-detail .entry-body").filter({hasText:/Turned off on/}).waitFor();
    await frame.getByRole("button",{name:"Allow",exact:true}).click();
    await frame.locator("#entry-detail .entry-body").filter({hasText:/Browser can open websites. Allowed with your passkey on/}).waitFor();
    assert.equal(f.state.requests,1);assert.equal(await frame.locator("#pending-count").innerText(),"0");
    await page.waitForFunction(()=>messages.some(m=>m.type==="home:focus-browser"));
    f.state.consent="requested";await page.reload();await screen(page,"inbox-request");
    await frame.getByRole("button",{name:"Don't Allow",exact:true}).click();
    await frame.locator("#entry-detail .entry-body").filter({hasText:/Browser cannot open websites. Not allowed on/}).waitFor();
    assert.equal(await frame.locator("#pending-count").innerText(),"0");
    await frame.getByRole("button",{name:"Allow",exact:true}).click();
    await off.waitFor();await page.close();
  } finally {await browser.close();await f.close();}
});

test("first-run Allow returns focus to the existing Browser, and off links select Inbox", async () => {
 const f=await fixture();const browser=await chromium.launch({headless:true});
 try {
  const page=await browser.newPage({viewport:{width:1280,height:844},colorScheme:"light"});
  let release;f.state.requestBarrier=new Promise(r=>release=r);
  await page.goto(f.url+"?flow=1");const frame=page.frameLocator('iframe[data-app="browser"]');
  await frame.locator("#browser-url").fill("https://example.com/first-run");await frame.locator("#browser-url").press("Enter");await screen(page,"flow-1");release();
  const inbox=page.frameLocator('iframe[data-app="inbox"]');await inbox.getByRole("button",{name:"Allow",exact:true}).waitFor();await screen(page,"flow-2");
  await page.evaluate(()=>holdPasskey=true);await inbox.getByRole("button",{name:"Allow",exact:true}).click();await page.waitForFunction(()=>approvals.length===1);await screen(page,"flow-3");
  await page.evaluate(()=>completeFixturePasskey());await page.waitForResponse(r=>r.url().endsWith("/api/apps/browser/open"));
  await page.waitForFunction(()=>!document.querySelector('iframe[data-app="browser"]').hidden);assert.equal(f.state.opens.length,1);await screen(page,"flow-4");
  await page.close();f.state.consent="revoked";
  for(const link of ["Open Inbox","Manage in Inbox"]) {
   const p=await browser.newPage({viewport:{width:1280,height:844},colorScheme:"light"});await p.goto(f.url+"?flow=1");const b=p.frameLocator('iframe[data-app="browser"]');
   await b.getByRole("button",{name:"Open Inbox",exact:true}).waitFor();await screen(p,"browser-off");
   if(link==="Manage in Inbox") await b.getByRole("button",{name:"Browser settings",exact:true}).click();
   await b.getByRole("button",{name:link,exact:true}).click();await p.frameLocator('iframe[data-app="inbox"]').getByRole("button",{name:"Allow",exact:true}).waitFor();await p.close();
  }
 } finally {await browser.close();await f.close();}
});

test("internet grant refusal points to the permission request", async () => {
  const {friendlyOpenError} = await import("../capsules/browser/browser/browser-status.js");
  assert.equal(friendlyOpenError({status:403,payload:{code:"browser_internet_grant_required"}}),"Internet access is off for Browser. Open Inbox to change it.");
});

 test("System contains no optional Browser permission integration",()=>{
   for(const name of ["index.html","system.js","style.css"]) {
     assert.doesNotMatch(readFileSync(new URL(`capsules/system/browser/${name}`,root),"utf8"),/browser-internet|browserInternet|browser\.internet|\/api\/apps\/browser\/internet/);
   }
 });


test("566a Return after Don't Allow or Turn Off continues once after Inbox passkey Allow", async t => {
  const f=await fixture();const browser=await chromium.launch({headless:true});
  try {
    for (const initial of ["refused", "revoked", "granted", "restored"]) await t.test(initial, async subtest => {
      subtest.after(async()=>{for(const context of browser.contexts())await context.close();});
      f.state.consent=["granted","restored"].includes(initial) ? "granted" : initial;f.state.opens=[];f.state.navigations=[];f.state.requests=0;
      f.state.recoverableUrl=initial==="granted" ? "https://example.com/current" : null;
      const page=await browser.newPage();
      const firstOpen=initial==="granted" ? page.waitForResponse(r=>r.url().includes("/pages/retained/status")) : null;
      await page.goto(f.url+"?flow=1"+(initial==="restored" ? "&restore=1" : ""));if(firstOpen)await firstOpen;
      const frame=page.frameLocator('iframe[data-app="browser"]');
      if(["granted","restored"].includes(initial)) {
        await frame.locator("#browser-internet-request").waitFor({state:"hidden"});f.state.consent="revoked";
      }
      await frame.getByRole("button",{name:"Open Inbox",exact:true}).waitFor({timeout:5000});
      const before=f.state.opens.length+f.state.navigations.length;
      const url="https://example.com/after-"+initial;
      await frame.locator("#browser-url").fill(url);await frame.locator("#browser-url").press("Enter");
      const inbox=page.frameLocator('iframe[data-app="inbox"]');
      await inbox.getByRole("button",{name:"Allow",exact:true}).waitFor();
      assert.equal(f.state.requests,1,"Return files a fresh request before Inbox Allow");
      await page.evaluate(()=>holdPasskey=true);
      await inbox.getByRole("button",{name:"Allow",exact:true}).click();
      await page.waitForFunction(()=>approvals.length===1);
      await page.waitForTimeout(2200);assert.equal(f.state.opens.length+f.state.navigations.length,before,"navigation waits for the passkey");
      const opened=page.waitForResponse(r=>r.url().endsWith(initial==="granted" ? "/pages/retained/input" : "/api/apps/browser/open"),{timeout:5000});
      await page.evaluate(()=>completeFixturePasskey());await opened;
      await page.waitForTimeout(4300);
      assert.deepEqual([...f.state.opens,...f.state.navigations].slice(before).map(open=>open.url),[url]);
      assert.equal(f.state.requests,1);
      f.state.consent="revoked";
      await frame.getByRole("button",{name:"Open Inbox",exact:true}).waitFor({timeout:5000});
      await page.close();
    });
  } finally {await browser.close();await f.close();}
});


test("566b a failed permission read recovers Allow and still observes Turn Off", async t => {
  const f=await fixture();const browser=await chromium.launch({headless:true});
  try {
    for (const when of ["initial", "waiting", "watching"]) await t.test(when, async subtest => {
      subtest.after(async()=>{for(const context of browser.contexts())await context.close();});
      f.state.consent=when==="watching" ? "granted" : "off";f.state.opens=[];f.state.requests=0;
      f.state.failedReads=when==="initial" ? 1 : 0;
      const page=await browser.newPage();
      const first=when==="watching" ? page.waitForResponse(r=>r.url().endsWith("/api/apps/browser/open")) : null;
      await page.goto(f.url);const frame=page.frameLocator("iframe");
      if(first)await first;
      else await frame.getByRole("button",{name:"Show Request",exact:true}).waitFor({timeout:7000});
      if(when!=="initial") {
        f.state.failedReads=1;
        await page.waitForResponse(r=>r.url().endsWith("/api/apps/browser/internet") && r.status()===503,{timeout:5000});
      }
      const before=f.state.opens.length;
      f.state.consent="granted";
      await frame.locator("#browser-internet-request").waitFor({state:"hidden",timeout:5000});
      if(when!=="watching") {
        await page.waitForTimeout(300);
        assert.equal(f.state.opens.length,before+1);assert.equal(f.state.opens.at(-1).url,"https://example.com/requested");
      }
      f.state.consent="revoked";
      await frame.getByRole("button",{name:"Open Inbox",exact:true}).waitFor({timeout:5000});
      await page.close();
    });
  } finally {await browser.close();await f.close();}
});


test("566c Inbox Allow brings a fullscreen Browser back into view", async () => {
  const f=await fixture();const browser=await chromium.launch({headless:true});
  try {
    f.state.consent="refused";
    const page=await browser.newPage();await page.goto(f.url+"shell");
    const gui=await (await page.locator("#gui").elementHandle()).contentFrame();
    await gui.waitForFunction(()=>window.fixtureShell);
    await gui.evaluate(()=>fixtureShell.windows.openTarget("browser"));
    const frame=gui.frameLocator('iframe[title="browser"]');
    await frame.getByRole("button",{name:"Open Inbox",exact:true}).waitFor();
    await gui.evaluate(()=>{const {core,stages}=fixtureShell;stages.enterFullscreenStage([...core.shellState.windows.keys()][0]);});
    assert.equal(await gui.locator('.window[data-target="browser"]').isVisible(),true);
    await gui.evaluate(()=>fixtureShell.windows.openTarget("inbox",{query:{notification_id:"browser-internet:permission"}}));
    const inbox=gui.frameLocator('iframe[title="inbox"]');
    await inbox.getByRole("button",{name:"Allow",exact:true}).waitFor();
    await gui.waitForFunction(()=>fixtureShell.stages.getActiveStageId()===fixtureShell.stages.desktopStageId() && !document.body.classList.contains("stage-sliding"));
    assert.equal(await gui.locator('.window[data-target="browser"]').isVisible(),false,"Inbox moves to the Desktop Space");
    await inbox.getByRole("button",{name:"Allow",exact:true}).click();
    await page.waitForFunction(()=>messages.some(m=>m.type==="home:focus-browser"));
    await gui.locator('.window[data-target="browser"]').waitFor({state:"visible",timeout:5000});
    assert.equal(await gui.locator('.window[data-target="browser"]').isVisible(),true,"Allow returns to Browser's fullscreen Space");
    assert.equal(await gui.evaluate(()=>fixtureShell.core.shellState.windows.size),2);
    await page.close();
  } finally {await browser.close();await f.close();}
});

test("566e renewing authority preserves the current page and does not repeat the first open", async t => {
  const f=await fixture();const browser=await chromium.launch({headless:true});
  try {
    for(const consent of ["off","granted","pending"]) await t.test(consent, async subtest => {
      subtest.after(async()=>{for(const context of browser.contexts())await context.close();});
      f.state.consent="granted";f.state.expired=false;f.state.completeOpen=true;
      f.state.bindOwners=true;f.state.restores=0;
      f.state.opens=[];f.state.requests=0;f.state.navigations=[];f.state.recoverableUrl=null;
      const page=await browser.newPage();await page.goto(f.url+"shell");
      f.state.peerPage=page;
      const gui=await (await page.locator("#gui").elementHandle()).contentFrame();
      await gui.waitForFunction(()=>window.fixtureShell);
      await gui.evaluate(()=>fixtureShell.windows.openTarget("browser",{query:{url:"https://example.com/first"}}));
      const node=await gui.locator('iframe[title="browser"]').elementHandle();
      const browserFrame=await node.contentFrame();
      await browserFrame.waitForFunction(()=>window.__elastosBrowserCurrentPageId==="retained" && new URL(location.href).searchParams.has("page_id"));
      await browserFrame.evaluate(()=>window.renewalDocument=crypto.randomUUID());
      const documentId=await browserFrame.evaluate(()=>window.renewalDocument);
      // Home ignores a repeated Browser open during its 700 ms launch guard.
      await page.waitForTimeout(750);
      const input=page.waitForResponse(r=>r.url().endsWith("/pages/retained/input"));
      await gui.evaluate(()=>fixtureShell.windows.openTarget("browser",{query:{url:"https://example.com/current"}}));await input;
      await browserFrame.waitForFunction(()=>document.querySelector("#browser-url").value==="https://example.com/current");
      if(consent==="off") {
        // Inbox Allow cancelled at the passkey can leave a request unanswered past its TTL.
        f.state.consent="requested";f.state.expired=true;
        await gui.frameLocator('iframe[title="browser"]').getByRole("button",{name:"Open Inbox",exact:true}).waitFor({timeout:5000});
      } else if(consent==="pending") {
        f.state.consent="revoked";
        await gui.frameLocator('iframe[title="browser"]').getByRole("button",{name:"Open Inbox",exact:true}).waitFor();
        await browserFrame.locator("#browser-url").fill("https://example.com/pending");
        await browserFrame.locator("#browser-url").press("Enter");
        await page.waitForFunction(()=>messages.some(m=>m.type==="home:open-target" && m.target==="inbox"));
      }
      const requests=f.state.requests, opens=f.state.opens.length;
      await page.evaluate(()=>messages=[]);await gui.evaluate(()=>fixtureShell.windows.showDesktopHome());
      await gui.evaluate(async()=>{const {core,windows}=fixtureShell;await windows.renewBrowserWindowAuthority([...core.shellState.windows.keys()][0]);});
      await page.waitForTimeout(2500);
      assert.equal(await gui.locator('.window[data-target="inbox"]').isVisible(),false,
        "renewal leaves Desktop visible instead of opening Inbox again");
      assert.equal(f.state.requests,requests,"renewal with access off files no request");
      assert.equal(f.state.opens.length,opens,"renewal with access on does not navigate to the first URL");
      assert.equal(f.state.restores,1,"Runtime binds the retained page to the new launch once");
      const frame=gui.frameLocator('iframe[title="browser"]');
      assert.equal(await (await node.contentFrame()).evaluate(()=>window.renewalDocument),documentId,
        "renewal retains the Browser document, its address and pending navigation");
      if(consent==="granted")assert.equal(await frame.locator("#browser-url").inputValue(),"https://example.com/current");
      if(consent==="pending") {
        f.state.consent="granted";
        await browserFrame.waitForFunction(()=>document.querySelector("#browser-url").value==="https://example.com/pending" && document.body.dataset.loading==="false");
        await page.waitForTimeout(2200);
        assert.equal(f.state.opens.filter(n=>n.url==="https://example.com/pending").length,1,"Allow opens the pre-renewal pending address once with a fresh internet connection");
      }
      await gui.evaluate(()=>fixtureShell.windows.openTarget("browser",{query:{url:"https://example.com/explicit"}}));
      await page.waitForTimeout(500);
      if(consent==="off")assert.equal(f.state.requests,requests+1);
      else assert.equal(f.state.navigations.at(-1)?.url,"https://example.com/explicit");
      await page.close();
    });
  } finally {await browser.close();await f.close();}
});


test("566r2 expired Inbox entry dates the expiry and renews through a fresh passkey", async () => {
  const f=await fixture();const browser=await chromium.launch({headless:true});
  try {
    f.state.consent="requested";f.state.expired=true;
    const page=await browser.newPage();await page.goto(f.url+"?app=inbox");
    const inbox=page.frameLocator("iframe");
    await inbox.getByRole("button",{name:"Allow",exact:true}).waitFor();
    const body=await inbox.locator("#entry-detail .entry-body").innerText();
    assert.match(body,/This expired request was made on .+\./);
    assert.equal(await inbox.locator("#pending-count").innerText(),"0");
    await page.evaluate(()=>holdPasskey=true);
    await inbox.getByRole("button",{name:"Allow",exact:true}).click();
    await page.waitForFunction(()=>approvals.length===1);
    assert.equal(f.state.requests,1);assert.equal(f.state.actions.length,0);
    await page.evaluate(()=>completeFixturePasskey());
    await inbox.getByRole("button",{name:"Turn Off",exact:true}).waitFor();
    assert.equal(f.state.actions.length,1);assert.equal(f.state.opens.length,0);
    await page.close();
  } finally {await browser.close();await f.close();}
});

test("566r2 Return waits for Turn Off then files once and navigates only after Allow", async () => {
  const f=await fixture();const browser=await chromium.launch({headless:true});
  try {
    f.state.consent="revoked";f.state.stopPending=true;
    const page=await browser.newPage();await page.goto(f.url+"?flow=1");
    const frame=page.frameLocator('iframe[data-app="browser"]');
    await frame.getByRole("button",{name:"Open Inbox",exact:true}).waitFor();
    await frame.locator("#browser-url").fill("https://example.com/stop-first");
    await frame.locator("#browser-url").press("Enter");
    await frame.locator("#browser-internet-hint").filter({hasText:"Your request will open in Inbox"}).waitFor({timeout:4000});
    await frame.locator("#browser-url").fill("https://example.com/stop-latest");
    await frame.locator("#browser-url").press("Enter");
    await page.waitForTimeout(2300);
    assert.equal(await frame.locator("#browser-internet-hint").isVisible(),true,"next poll preserves the waiting message");
    assert.equal(f.state.requests,0);assert.equal(f.state.opens.length,0);
    f.state.stopPending=false;
    const inbox=page.frameLocator('iframe[data-app="inbox"]');
    await inbox.getByRole("button",{name:"Allow",exact:true}).waitFor({timeout:5000});
    assert.equal(f.state.requests,1);assert.equal(f.state.opens.length,0);
    await page.evaluate(()=>holdPasskey=true);
    await inbox.getByRole("button",{name:"Allow",exact:true}).click();await page.waitForFunction(()=>approvals.length===1);
    await page.waitForTimeout(2200);assert.equal(f.state.opens.length,0);
    const opened=page.waitForResponse(r=>r.url().endsWith("/api/apps/browser/open"));
    await page.evaluate(()=>completeFixturePasskey());await opened;
    await page.waitForTimeout(2300);
    assert.deepEqual(f.state.opens.map(open=>open.url),["https://example.com/stop-latest"]);
    assert.equal(f.state.requests,1);await page.close();
    // Closing a waiting window cancels its request.
    f.state.consent="revoked";f.state.stopPending=true;f.state.requests=0;
    const closed=await browser.newPage();await closed.goto(f.url+"?restore=1");
    const b=closed.frameLocator("iframe");await b.getByRole("button",{name:"Open Inbox",exact:true}).waitFor();
    await b.locator("#browser-url").fill("https://example.com/closed");await b.locator("#browser-url").press("Enter");
    await b.locator("#browser-internet-hint").filter({hasText:"Your request will open in Inbox"}).waitFor();
    await closed.close();f.state.stopPending=false;await new Promise(r=>setTimeout(r,500));assert.equal(f.state.requests,0);
  } finally {await browser.close();await f.close();}
});

test("566r3 a refused request without a pending stop shows its error and stops retrying", async () => {
  const f=await fixture();const browser=await chromium.launch({headless:true});
  try {
    f.state.consent="revoked";f.state.requestError="Browser request was refused by Runtime.";
    const errorMessage="This page was blocked by your connection settings.";
    const page=await browser.newPage();await page.goto(f.url+"?flow=1");
    const frame=page.frameLocator('iframe[data-app="browser"]');
    await frame.getByRole("button",{name:"Open Inbox",exact:true}).waitFor();
    const refused=page.waitForResponse(r=>r.url().endsWith("/api/apps/browser/internet") && r.request().method()==="POST" && r.status()===403);
    await frame.locator("#browser-url").fill("https://example.com/refused");
    await frame.locator("#browser-url").press("Enter");await refused;
    await page.waitForTimeout(2200);
    assert.equal(f.state.requestAttempts,1,"a refusal without a pending stop sends only one POST, including after two seconds");
    const hint=frame.locator("#browser-internet-hint");
    assert.equal(await hint.isVisible(),true);assert.equal(await hint.innerText(),errorMessage);
    await page.waitForTimeout(2200);
    assert.equal(f.state.requestAttempts,1);assert.equal(await hint.isVisible(),true);
    assert.equal(await hint.innerText(),errorMessage,"consent polling preserves the error");
    assert.equal(f.state.requests,0);assert.deepEqual(f.state.opens,[]);assert.deepEqual(f.state.navigations,[]);
    assert.equal(await page.evaluate(()=>messages.filter(m=>m.type==="home:open-target").length),0);
    await page.close();
  } finally {await browser.close();await f.close();}
});

test("566r3 a stop that stays pending times out with a stable error and needs a new Return", async () => {
  const f=await fixture();const browser=await chromium.launch({headless:true});
  try {
    f.state.consent="revoked";f.state.stopPending=true;
    const page=await browser.newPage();await page.goto(f.url+"?flow=1");
    const frame=page.frameLocator('iframe[data-app="browser"]');
    await frame.getByRole("button",{name:"Open Inbox",exact:true}).waitFor();
    await frame.locator("#browser-url").fill("https://example.com/stop-timeout");
    await frame.locator("#browser-url").press("Enter");
    const hint=frame.locator("#browser-internet-hint");
    await hint.filter({hasText:"Browser is still stopping internet access. Try again in a moment."}).waitFor({timeout:13000});
    f.state.stopPending=false;await page.waitForTimeout(2200);
    assert.equal(await hint.isVisible(),true);
    assert.equal(await hint.innerText(),"Browser is still stopping internet access. Try again in a moment.");
    assert.equal(f.state.requestAttempts,1);assert.equal(f.state.requests,0);
    assert.deepEqual(f.state.opens,[]);assert.deepEqual(f.state.navigations,[]);
    assert.equal(await page.evaluate(()=>messages.filter(m=>m.type==="home:open-target").length),0);
    await frame.locator("#browser-url").press("Enter");
    await page.frameLocator('iframe[data-app="inbox"]').getByRole("button",{name:"Allow",exact:true}).waitFor();
    assert.equal(f.state.requestAttempts,2);assert.equal(f.state.requests,1);
    assert.deepEqual(f.state.opens,[]);assert.deepEqual(f.state.navigations,[]);
    assert.equal(await hint.evaluate(e=>e.hidden),true,"a new request clears the old error");
    await page.close();
  } finally {await browser.close();await f.close();}
});

test("566r2 Allow returns to the requesting Browser among several windows", async () => {
  const f=await fixture();const browser=await chromium.launch({headless:true});
  try {
    f.state.consent="revoked";
    const page=await browser.newPage();await page.goto(f.url+"shell");
    const gui=await (await page.locator("#gui").elementHandle()).contentFrame();await gui.waitForFunction(()=>window.fixtureShell);
    await gui.evaluate(()=>fixtureShell.windows.openTarget("browser"));
    const first=gui.frameLocator('iframe[title="browser"]').first();await first.getByRole("button",{name:"Open Inbox",exact:true}).waitFor();
    const owner=await gui.evaluate(()=>[...fixtureShell.core.shellState.windows.values()][0].id);
    await gui.evaluate(()=>fixtureShell.windows.openTarget("browser",{newWindow:true,authorizedLaunch:{target:'browser',title:'browser',attach_kind:'iframe',launch_status:'launched',route:'/apps/browser/?browser_restore=1&browser_instance=browser:other#home_token=other'}}));
    await gui.locator('iframe[title="browser"]').nth(1).waitFor();
    await first.locator("#browser-url").fill("https://example.com/owner");await first.locator("#browser-url").press("Enter");
    const inbox=gui.frameLocator('iframe[title="inbox"]');await inbox.getByRole("button",{name:"Allow",exact:true}).waitFor();
    await inbox.getByRole("button",{name:"Allow",exact:true}).click();
    await gui.waitForFunction(id=>fixtureShell.core.shellState.activeWindowId===id,owner,{timeout:5000});
    await page.waitForTimeout(2300);assert.deepEqual(f.state.opens.map(open=>open.url),["https://example.com/owner"]);
    assert.equal(await gui.evaluate(()=>fixtureShell.windows.focusOpenBrowserWindow('browser:closed')),false,"a closed requester does not focus an unrelated Browser");
    await page.close();
  } finally {await browser.close();await f.close();}
});

test("566r2 renewal with access on and no page keeps Browser empty", async () => {
  const f=await fixture();const browser=await chromium.launch({headless:true});
  try {
    f.state.consent="revoked";
    const page=await browser.newPage();await page.goto(f.url+"shell");
    const gui=await (await page.locator("#gui").elementHandle()).contentFrame();await gui.waitForFunction(()=>window.fixtureShell);
    await gui.evaluate(()=>fixtureShell.windows.openTarget("browser",{query:{url:"https://example.com/first"}}));
    const frame=gui.frameLocator('iframe[title="browser"]');await frame.getByRole("button",{name:"Open Inbox",exact:true}).waitFor();
    f.state.consent="granted";await frame.locator("#browser-internet-request").waitFor({state:"hidden",timeout:5000});
    assert.equal(f.state.opens.length,0);assert.equal(f.state.recoverableUrl,undefined);
    await gui.evaluate(async()=>{const {core,windows}=fixtureShell;await windows.renewBrowserWindowAuthority([...core.shellState.windows.keys()][0]);});
    await page.waitForTimeout(2500);assert.equal(f.state.opens.length,0,"renewal does not reopen the first address when there is no page");
    assert.equal(f.state.requests,0);
    const opened=page.waitForResponse(r=>r.url().endsWith("/api/apps/browser/open"));
    await gui.evaluate(()=>fixtureShell.windows.openTarget("browser",{query:{url:"https://example.com/explicit"}}));await opened;
    assert.deepEqual(f.state.opens.map(open=>open.url),["https://example.com/explicit"]);await page.close();
  } finally {await browser.close();await f.close();}
});
