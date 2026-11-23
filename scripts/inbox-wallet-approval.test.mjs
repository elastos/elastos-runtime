import test from "node:test";
import assert from "node:assert/strict";
import {createServer} from "node:http";
import {readFile} from "node:fs/promises";
import {execFileSync} from "node:child_process";
import {extname,resolve} from "node:path";
import {requireProductSmokePlaywright} from "./product-smoke-browser.mjs";
const root=resolve(import.meta.dirname,"..");

test("Inbox wallet sessions approve each positive permission with its exact action and recover from Cancel", async()=>{
 const positives=["community-presence-always:test","community-presence-open:test","contact-accept-request:test","room-approve-request:test","capability-approve-request:test","service-approve-request:test","model-egress-approve:test","hosted-http-approve:test","wallet-price-http-approve:coingecko"];
 let action=positives[0],wallet=true;const writes=[];
 const headers={"access-control-allow-origin":"null","access-control-allow-headers":"content-type,x-elastos-home-token","access-control-allow-methods":"GET,POST,OPTIONS"};
 const server=createServer(async(req,res)=>{try{
  const url=new URL(req.url,"http://localhost"),path=url.pathname;
  const json=value=>res.writeHead(200,{...headers,"content-type":"application/json"}).end(JSON.stringify(value));
  if(req.method==="OPTIONS"){res.writeHead(204,headers).end();return;}
  if(path==="/fixture"){res.writeHead(200,{"content-type":"text/html"}).end(`<!doctype html><script>window.approvals=[];window.cancel=false;addEventListener('message',e=>{if(e.source!==document.querySelector('iframe').contentWindow||e.data?.type!=='elastos.home.passkey-step-up.request/v1')return;window.approvals.push(e.data);e.source.postMessage({type:'elastos.home.passkey-step-up.result/v1',requestId:e.data.requestId,...(window.cancel?{error:'Passkey cancelled.'}:{stepUpToken:'exact-inbox-approval'})},'*');});</script><iframe sandbox="allow-scripts allow-modals" src="/apps/inbox/?home_origin=${encodeURIComponent('http://127.0.0.1:'+server.address().port)}#home_token=inbox-token"></iframe>`);return;}
  if(path==="/api/apps/inbox/summary"){json({wallet_session:wallet,notifications:{attention_count:1,unread_count:0,entries:[{id:"approval",kind:action.startsWith("community-")?"community_presence_request":"permission_request",source_app:"inbox",title:"Permission request",body:"Review this choice.",severity:"attention",read:true,created_at:1,action_ref:{action_id:action.replace("community-presence-open:","community-presence-always:").replace("community-presence-later:","community-presence-always:").replace("community-presence-never:","community-presence-always:").replace("contact-decline-request:","contact-accept-request:").replace("room-deny-request:","room-approve-request:").replace("capability-deny-request:","capability-approve-request:").replace("service-deny-request:","service-approve-request:").replace("model-egress-deny:","model-egress-approve:").replace("hosted-http-deny:","hosted-http-approve:").replace("wallet-price-http-deny:","wallet-price-http-approve:")}}]}});return;}
  if(path==="/api/apps/inbox/actions"){let raw="";for await(const chunk of req)raw+=chunk;writes.push(JSON.parse(raw));json({message:"Saved."});return;}
  if(path==="/favicon.ico"){res.writeHead(204).end();return;}
  const relative=path.replace(/^\/apps\/inbox\//,"")||"index.html",file=resolve(root,"capsules/inbox/browser",relative);
  if(!file.startsWith(resolve(root,"capsules/inbox/browser")+"/")){res.writeHead(404).end();return;}
  const bytes=relative==="inbox.js"&&process.env.INBOX_WALLET_APPROVAL_BEFORE
   ? execFileSync("git",["show","1fef8c0f9:capsules/inbox/browser/inbox.js"],{cwd:root}) : await readFile(file);
  res.writeHead(200,{"content-type":({".html":"text/html",".js":"text/javascript",".css":"text/css",".svg":"image/svg+xml"})[extname(file)]||"application/octet-stream"}).end(bytes);
 }catch{res.writeHead(404).end();}});
 await new Promise(r=>server.listen(0,"127.0.0.1",r));const browser=await requireProductSmokePlaywright().chromium.launch({headless:true});
 try{
  const page=await browser.newPage();page.setDefaultTimeout(5000);
  async function open(){await page.goto(`http://127.0.0.1:${server.address().port}/fixture`);const frame=page.frames().find(f=>f.url().includes("/apps/inbox/"));await frame.locator(`[data-action-id="${action}"]`).first().waitFor();return frame;}
  for(action of positives){const frame=await open(),before=writes.length;await frame.locator(`[data-action-id="${action}"]`).first().click();await page.waitForFunction(()=>window.approvals.length===1);await frame.waitForFunction(()=>!document.querySelector('#refresh').disabled);assert.equal(writes.length,before+1,action);assert.deepEqual(writes.at(-1),{action_id:action,step_up_token:"exact-inbox-approval"});assert.deepEqual(await page.evaluate(()=>window.approvals.map(a=>[a.operation,a.request])),[["inbox.approve",{action_id:action}]]);}
  action=positives[2];let frame=await open();await page.evaluate(()=>window.cancel=true);let before=writes.length;await frame.locator(`[data-action-id="${action}"]`).first().click();await frame.waitForFunction(()=>!document.querySelector('#refresh').disabled);assert.equal(writes.length,before);await page.evaluate(()=>window.cancel=false);await frame.locator(`[data-action-id="${action}"]`).first().click();await frame.waitForFunction(()=>!document.querySelector('#refresh').disabled);assert.equal(writes.length,before+1,"retry after Cancel works");
  for(action of ["community-presence-later:test","community-presence-never:test","contact-decline-request:test","room-deny-request:test","capability-deny-request:test","service-deny-request:test","model-egress-deny:test","hosted-http-deny:test","wallet-price-http-deny:coingecko"]){frame=await open();before=writes.length;await frame.locator(`[data-action-id="${action}"]`).first().click();await frame.waitForFunction(()=>!document.querySelector('#refresh').disabled);assert.equal(writes.length,before+1,action);assert.deepEqual(writes.at(-1),{action_id:action});assert.equal(await page.evaluate(()=>window.approvals.length),0);}
  wallet=false;action=positives[2];frame=await open();await frame.locator(`[data-action-id="${action}"]`).first().click();await frame.waitForFunction(()=>!document.querySelector('#refresh').disabled);assert.deepEqual(writes.at(-1),{action_id:action});assert.equal(await page.evaluate(()=>window.approvals.length),0,"passkey session keeps existing policy");
 }finally{await browser.close();server.closeAllConnections();await new Promise(r=>server.close(r));}
});
