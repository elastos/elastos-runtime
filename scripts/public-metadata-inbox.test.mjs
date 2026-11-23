// META-PUBLIC A4: consent and "Stop sharing metadata" live in Inbox. A
// Runtime-built card per state; Agree asks the Home's passkey over exactly
// the request the card shows, Stop asks to confirm and needs no passkey.
// Modelled on scripts/browser-internet-consent.test.mjs.
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import http from "node:http";
import test from "node:test";
import {inertSystemApiResponse} from "./system-uiux-fixture.mjs";
const require = createRequire(new URL("../elastos/tools/browser-playwright-engine/package.json", import.meta.url));
const { chromium } = require("playwright");
const root = new URL("../", import.meta.url);

const ENABLE = "public-metadata-enable";
const STOP = "public-metadata-stop";
const WORDING = "Publish your assets' metadata on IPFS";
const REQUEST = {wording_version:1,wording_sha256:"a".repeat(64)};

const hostScript = `window.messages=[];window.approvals=[];window.passkeyAllowed=true;
addEventListener('message',e=>{
  messages.push(e.data);
  if(e.data?.type!=="elastos.home.passkey-step-up.request/v1")return;
  approvals.push({operation:e.data.operation,request:e.data.request});
  e.source.postMessage({type:"elastos.home.passkey-step-up.result/v1",requestId:e.data.requestId,
    ...(passkeyAllowed?{stepUpToken:"fixture-step-up"}:{error:"Passkey cancelled."})},"*");
});`;

/// The card the Runtime projects for each state (amendment §1.3).
function card(kind, request = REQUEST) {
  const base = {id:"public-metadata",source_app:"creator",kind,severity:"info",read:true,created_at:1794312000};
  switch (kind) {
    case "public_metadata_consent":
      return {...base,title:"Share minted assets' metadata on public IPFS?",body:WORDING,
        action_ref:{app:"inbox",action_id:ENABLE},passkey_approval:true,step_up_request:request};
    case "public_metadata_sharing":
      return {...base,title:"Metadata sharing is on",body:"Your Home shares minted assets' metadata on public IPFS.",
        action_ref:{app:"inbox",action_id:STOP}};
    case "public_metadata_paused":
      return {...base,title:"Metadata sharing is paused",body:"Metadata sharing is paused on this Home (sharing is not offered). Your consent is kept.",
        action_ref:{app:"inbox",action_id:STOP}};
    case "public_metadata_stopping":
      return {...base,severity:"attention",read:false,title:"Stopping metadata sharing",
        body:"Still stopping: the repo lock is still held. Your Home keeps trying.",action_ref:{app:"inbox",action_id:STOP}};
    case "public_metadata_unreadable":
      return {...base,severity:"attention",read:false,title:"Metadata sharing",
        body:"Metadata sharing state can't be read. Stop sharing to reset it.",action_ref:{app:"inbox",action_id:STOP}};
    default: throw new Error(kind);
  }
}

async function fixture() {
  const state = {entry:card("public_metadata_consent"), actions:[]};
  const server = http.createServer(async (req,res) => {
    const url = new URL(req.url,"http://localhost");
    res.setHeader("access-control-allow-origin","*");
    res.setHeader("access-control-allow-headers","content-type,x-elastos-home-token");
    res.setHeader("access-control-allow-methods","GET,POST,OPTIONS");
    if (req.method === "OPTIONS") {res.writeHead(204).end();return;}
    const json = value => {res.setHeader("content-type","application/json");res.end(JSON.stringify(value));};
    let input;
    if (req.method === "POST") {let body="";for await (const chunk of req) body+=chunk;input=JSON.parse(body);}
    if (url.pathname === "/") {
      res.setHeader("content-type","text/html");
      res.end(`<style>html,body{margin:0;height:100%}iframe{border:0;width:100%;height:100%}</style><script>${hostScript}</script><iframe src="/apps/inbox/?home_origin=http://127.0.0.1:${server.address().port}#home_token=fixture"></iframe>`);
      return;
    }
    if (url.pathname === "/api/apps/inbox/summary") {
      const entries = state.entry ? [state.entry] : [];
      json({notifications:{unread_count:entries.filter(e=>!e.read).length,attention_count:entries.filter(e=>e.severity==="attention").length,entries}});
      return;
    }
    if (url.pathname === "/api/apps/inbox/actions") {
      // Opening the Inbox marks unread cards read; only consent actions are recorded.
      if (!String(input.action_id).startsWith("notification-read:")) state.actions.push(input);
      if (input.action_id === ENABLE) state.entry = card("public_metadata_sharing");
      if (input.action_id === STOP) state.entry = card("public_metadata_consent");
      json({message:"ok"});
      return;
    }
    if (url.pathname.startsWith("/api/")) {
      const response = inertSystemApiResponse(url.pathname);
      if (response) {json(response);return;}
    }
    const match = url.pathname.match(/^\/apps\/(inbox|home)\/(.*)$/);
    if (!match || match[2].includes("..")) {res.writeHead(404).end();return;}
    const name = match[2] || "index.html";
    try {
      const bytes = readFileSync(new URL(`capsules/${match[1]}/browser/${name}`,root));
      res.setHeader("content-type",(name.endsWith(".js") || name.endsWith(".mjs"))?"text/javascript":name.endsWith(".css")?"text/css":"text/html");
      res.end(bytes);
    } catch {res.writeHead(404).end();}
  });
  await new Promise(resolve=>server.listen(0,"127.0.0.1",resolve));
  return {state,url:`http://127.0.0.1:${server.address().port}/`,close:()=>new Promise(resolve=>server.close(resolve))};
}

test("Agree asks the passkey over exactly the card's request, then turns sharing on", async () => {
  const f = await fixture();const browser = await chromium.launch({headless:true});
  try {
    const page = await browser.newPage();await page.goto(f.url);const frame = page.frameLocator("iframe");
    await frame.getByText(WORDING).first().waitFor();
    await frame.getByRole("button",{name:"Agree",exact:true}).click();
    await frame.getByRole("button",{name:"Stop sharing",exact:true}).waitFor();
    const approvals = await page.evaluate(()=>approvals);
    assert.deepEqual(approvals,[{operation:"creator.public_ipfs.enable",request:REQUEST}]);
    assert.deepEqual(f.state.actions,[{action_id:ENABLE,step_up_token:"fixture-step-up",step_up_request:REQUEST}]);
  } finally {await browser.close();await f.close();}
});

test("a cancelled passkey enables nothing", async () => {
  const f = await fixture();const browser = await chromium.launch({headless:true});
  try {
    const page = await browser.newPage();await page.goto(f.url);const frame = page.frameLocator("iframe");
    await page.evaluate(()=>{window.passkeyAllowed=false;});
    await frame.getByRole("button",{name:"Agree",exact:true}).click();
    await page.waitForTimeout(500);
    assert.deepEqual(f.state.actions,[]);
  } finally {await browser.close();await f.close();}
});

test("a card whose request has other keys offers no Agree", async () => {
  const f = await fixture();const browser = await chromium.launch({headless:true});
  try {
    f.state.entry = card("public_metadata_consent",{...REQUEST,extra:true});
    const page = await browser.newPage();await page.goto(f.url);const frame = page.frameLocator("iframe");
    await frame.getByText(WORDING).first().waitFor();
    assert.equal(await frame.getByRole("button",{name:"Agree",exact:true}).count(),0);
  } finally {await browser.close();await f.close();}
});

test("Stop sharing asks to confirm, then stops without a passkey", async () => {
  const f = await fixture();const browser = await chromium.launch({headless:true});
  try {
    for (const kind of ["public_metadata_sharing","public_metadata_paused","public_metadata_unreadable"]) {
      f.state.entry = card(kind);f.state.actions = [];
      const page = await browser.newPage();await page.goto(f.url);const frame = page.frameLocator("iframe");
      await frame.getByRole("button",{name:"Stop sharing",exact:true}).first().click();
      const dialog = frame.locator("#public-metadata-confirm");
      await dialog.waitFor();
      // Cancel keeps sharing.
      await dialog.getByRole("button",{name:"Cancel",exact:true}).click();
      assert.deepEqual(f.state.actions,[],kind);
      await frame.getByRole("button",{name:"Stop sharing",exact:true}).first().click();
      await dialog.getByRole("button",{name:"Stop sharing",exact:true}).click();
      await page.waitForFunction(()=>true);
      await frame.getByText(WORDING).first().waitFor();
      assert.deepEqual(f.state.actions,[{action_id:STOP}],kind);
      assert.deepEqual(await page.evaluate(()=>approvals),[],kind);
      await page.close();
    }
  } finally {await browser.close();await f.close();}
});

test("a stopping card offers Try again, which posts the same Stop", async () => {
  const f = await fixture();const browser = await chromium.launch({headless:true});
  try {
    f.state.entry = card("public_metadata_stopping");
    const page = await browser.newPage();await page.goto(f.url);const frame = page.frameLocator("iframe");
    await frame.getByRole("button",{name:"Try again",exact:true}).click();
    await frame.getByText(WORDING).first().waitFor();
    assert.deepEqual(f.state.actions,[{action_id:STOP}]);
    assert.equal(await frame.getByRole("button",{name:"Agree",exact:true}).count() >= 1,true);
  } finally {await browser.close();await f.close();}
});

test("the Inbox source keeps the public metadata branch in one place", () => {
  const source = readFileSync(new URL("capsules/inbox/browser/inbox.js",root),"utf8");
  assert.match(source,/requestPasskeyStepUp\("creator\.public_ipfs\.enable", request\)/);
  assert.match(source,/PUBLIC_METADATA_KINDS/);
  const html = readFileSync(new URL("capsules/inbox/browser/index.html",root),"utf8");
  assert.match(html,/id="public-metadata-confirm"/);
});
