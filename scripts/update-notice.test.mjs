import test from "node:test";
import assert from "node:assert/strict";
import { readFile, mkdir } from "node:fs/promises";
import { chromium, makeSystemSummary, makeAppearanceRecord, startSystemFixtureServer, jsonResponse } from "./system-uiux-fixture.mjs";
import { productSmokeLaunchOptions } from "./product-smoke-browser.mjs";

const root = new URL("../", import.meta.url);
// Wording belongs to the real summary. Fixtures and assertions read that source.
const source = await readFile(new URL("elastos/crates/elastos-server/src/api/gateway_update_notice.rs", root), "utf8");
const copy = name => JSON.parse(source.match(new RegExp(`const ${name}: &str = ("[^"\\n]*");`))[1]);
const preference = (enabled, readable = true) => ({ enabled, readable, label:copy("SWITCH_LABEL"), save_error:copy("SAVE_ERROR"), message:copy(!readable ? "UNREADABLE_TEXT" : enabled ? "ON_TEXT" : "OFF_TEXT") });
const release = "bafkreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const notice = () => ({ id:`home-update:${release}`, kind:"home_update_available", source_app:"system", severity:"info", read:false,
  title:copy("NOTICE_TITLE"), body:copy("NOTICE_BODY").replace("{version}","0.7.1"), created_at:1794826800, action_ref:null });
const notes = ["# Home improvements", "Home tells you when a newer version was found.", "Review the release in System before installation.", "Read release notes before you approve.", "Keep your saved files through the update.", "Control background checks in System."];

async function fixture() {
  const state = { settings:preference(true), entry:notice(), actions:[], writes:[], approvals:[], holdReads:true, releases:[], guest:false, failWrite:false };
  const server = await startSystemFixtureServer({ title:"Home update notice", async onApiRequest({request,response,url}) {
    const html = body => {response.writeHead(200,{"content-type":"text/html"});response.end(body);};
    if (url.pathname === "/notice") {
      html(`<style>html,body,iframe{margin:0;border:0;width:100%;height:100%}</style><script>
        window.messages=[];
        addEventListener('message',e=>{messages.push(e.data);if(e.data?.type==='home:open-target')document.querySelector('iframe').contentWindow.postMessage({fixtureOpen:e.data},'*');});
        </script><iframe id="gui" sandbox="allow-scripts allow-forms allow-modals" src="/notice-gui"></iframe>`);return true;
    }
    if (url.pathname === "/notice-gui") {
      const template = await readFile(new URL("capsules/home-gui/browser/home-gui-template.html", root), "utf8");
      html(`<link rel="stylesheet" href="/apps/home-gui/elastos-ui.css"><link rel="stylesheet" href="/apps/home-gui/style.css">${template}<script src="/apps/home-gui/elastos-theme.js"></script><script type="module">
        import * as core from '/apps/home-gui/shell-core.js?v=home-20261101d';
        import * as windows from '/apps/home-gui/shell-windows.js?v=home-20261101d';
        import * as surface from '/apps/home-gui/shell-surface.js?v=home-20261101d';
        let serial=0;
        for(const node of document.querySelectorAll('[data-home-gui-hidden-by-host]')) {node.hidden=false;node.inert=false;}
        import * as control from '/apps/home-gui/shell-control-centre.js';
        const summary={targets:[{target:'system',title:'System',window_policy:'single'},{target:'inbox',title:'Inbox',window_policy:'single'}],notifications:{entries:[],unread_count:0,attention_count:0}};
        core.shellState.currentSummary=summary;
        core.pinTargetToTaskbar('system');core.pinTargetToTaskbar('inbox');
        windows.configureWindowHooks({clearIdentitySurface(){},refreshLauncherIfVisible(){},hideLauncher(){},renderDesktop(){},renderTaskbar(){surface.renderTaskbar(summary)},updateTaskbarState(){},syncMenubar(){},launchTarget:async(target,query={})=>({target,title:target==='system'?'System':'Inbox',attach_kind:'iframe',launch_status:'launched',route:'/apps/'+target+'/?'+new URLSearchParams({...query,home_origin:location.origin})+'#home_token='+btoa(JSON.stringify({payload:{launch_id:'launch:'+String(++serial).padStart(32,'0')}})).replace(/=+$/,'')})});
        control.bindControlCentre();
        window.refreshFixture=async()=>{const data=await fetch('/api/apps/inbox/summary').then(r=>r.json());summary.notifications=data.notifications;surface.renderTaskbar(summary);surface.renderInboxBadge(summary);control.syncControlCentre(summary);};
        addEventListener('message',e=>{
          if(e.source!==window.top)return;
          if(e.data.fixtureOpen)windows.openTarget(e.data.fixtureOpen.target,{query:e.data.fixtureOpen.query});
        });
        window.fixture={core,windows,surface,control};await refreshFixture();
      </script>`);return true;
    }
    if (url.pathname === "/api/apps/inbox/summary") {
      const entries = state.entry ? [state.entry] : [];
      if(state.approval)entries.push({id:"contact-request:fixture",kind:"contact_request",source_app:"people",severity:"attention",read:false,action_ref:{app:"inbox",action_id:"contact-accept-request:fixture"}});
      jsonResponse(response, {notifications:{entries,attention_count:state.approval?1:0,unread_count:entries.filter(e=>!e.read).length}});return true;
    }
    if (url.pathname === "/api/apps/inbox/actions") {
      let body="";for await (const part of request) body+=part;const action=JSON.parse(body);state.actions.push(action);
      if (action.action_id.startsWith("notification-read:")) {
        if(state.holdReads)await new Promise(resolve=>state.releases.push(resolve));
        if(state.entry)state.entry.read=true;
      } else if(action.action_id.startsWith("notification-dismiss:"))state.entry=null;
      else throw new Error("Notice attempted an approval");
      jsonResponse(response,{message:"Saved."});return true;
    }
    if (url.pathname === "/api/apps/system/summary") {
      const summary=makeSystemSummary(makeAppearanceRecord());summary.access.role=state.guest?"guest":"admin";
      summary.runtime.version="0.7.0";
      summary.source={configured:true,name:"Home publisher",channel:"stable",installed_version:"0.7.0",mode:"release",update_checks_allowed:true};
      summary.runtime_update=state.guest?null:{configured:true,available:true,can_apply:true,current_version:"0.7.0",new_version:"0.7.1",changes:notes,
        publisher:"Home publisher", publisher_did:"did:key:fixture", source_name:"Home publisher", channel:"stable", head_cid:release, release_cid:release, background_checks:state.settings,controller:{phase:"ready"}};
      if(summary.runtime_update && state.settings.message===copy("INVALID_VERSION_TEXT")) {
        summary.source.installed_version="broken";
        summary.runtime_update={configured:true,available:false,can_apply:false,checking:false,current_version:"broken",
          message:"Installed release version is invalid. Run `elastos update --force` locally to install a verified signed release and repair it.",background_checks:state.settings};
      }
      jsonResponse(response,summary);return true;
    }
    if (url.pathname === "/api/apps/system/update-background") {
      let body="";for await(const part of request)body+=part;const input=JSON.parse(body);
      state.writes.push({input,token:request.headers["x-elastos-home-token"]});
      if(state.failWrite)jsonResponse(response,{error:"Save failed"},state.failStatus||409);
      else{state.settings=preference(input.enabled);jsonResponse(response,state.settings);}return true;
    }
    if(url.pathname.startsWith("/icons/")) {
      const bytes=await readFile(new URL(`capsules/home-gui/browser${url.pathname}`,root));
      response.writeHead(200,{"content-type":"image/png","access-control-allow-origin":"*"});response.end(bytes);return true;
    }
    const match=url.pathname.match(/^\/apps\/(inbox|home-gui|home)\/(.*)$/);
    if(match && !["home-background-image.js","home-clipboard-client.js","home-clipboard-protocol.js"].includes(match[2])) {
      assert.ok(!match[2].includes(".."));
      const name=match[2]||"index.html";
      const bytes=await readFile(new URL(`capsules/${match[1]}/browser/${name}`,root));
      const type=name.endsWith(".js")||name.endsWith(".mjs")?"text/javascript":name.endsWith(".css")?"text/css":name.endsWith(".html")?"text/html":name.endsWith(".svg")?"image/svg+xml":"application/octet-stream";
      response.writeHead(200,{"content-type":type,"access-control-allow-origin":"*"});response.end(bytes);return true;
    }
    return false;
  }});
  return {...server,state,async close(){state.releases.splice(0).forEach(r=>r());await server.close();}};
}

const screenshots = process.env.UPDATE_NOTICE_SCREENSHOTS;
async function screen(page,name,wording=false) {
  if(!screenshots || (process.env.UPDATE_NOTICE_WORDING_ONLY && !wording))return;
  const theme = name.startsWith("dark-") ? "dark" : "light";
  for (const frame of page.frames().slice(1)) await frame.evaluate(theme => window.elastosTheme?.set(theme), theme);
  await page.waitForTimeout(120);
  await mkdir(screenshots,{recursive:true});
  await page.screenshot({path:`${screenshots}/${name}.png`});
}

test("update notice uses real Inbox, bell and System navigation; switch saves and recovers", async () => {
  const f=await fixture();const browser=await chromium.launch({headless:true,...productSmokeLaunchOptions()});
  try {
    for(const theme of ["light","dark"]) {
      f.state.entry=notice();f.state.holdReads=true;f.state.settings=preference(true);
      const page=await browser.newPage({viewport:{width:1280,height:950}});page.setDefaultTimeout(8000);
      const errors=[];page.on("pageerror",e=>errors.push(e.message));
      await page.goto(f.baseUrl+"/notice");
      const gui=page.frames().find(frame=>frame.url().endsWith("/notice-gui")) || await page.waitForSelector("#gui").then(h=>h.contentFrame());
      await gui.waitForFunction(()=>window.fixture, null, {timeout:5000}).catch(e=>{throw new Error(e.message+JSON.stringify({errors,failures:f.requestFailures}));});
      await gui.evaluate(theme=>window.elastosTheme?.set(theme),theme);
      const badge=gui.locator("#toolbar-inbox-count");
      await badge.waitFor();assert.equal(await badge.textContent(),"1");
      assert.equal(await gui.locator("#control-centre-approvals-detail").textContent(),"None","information is excluded from approvals");
      f.state.approval=true;await gui.evaluate(()=>refreshFixture());
      assert.equal(await badge.textContent(),"1","the bell retains attention-first counting");
      assert.equal(await gui.locator("#control-centre-approvals-detail").textContent(),"1 pending");
      f.state.approval=false;await gui.evaluate(()=>refreshFixture());
      await gui.evaluate(()=>fixture.windows.openTarget("inbox"));
      const inbox=gui.frameLocator('iframe.window-frame[title="Inbox"]');
      await inbox.getByRole("button",{name:"Open System",exact:true}).waitFor();
      assert.deepEqual(await inbox.locator("#entry-detail button").allTextContents(), ["Open System", "Dismiss"]);
      assert.equal(await inbox.locator("#pending-count").textContent(),"0");
      assert.equal(await inbox.locator("#review-count").textContent(),"0");
      await inbox.getByRole("button",{name:"Needs Review"}).click();
      assert.equal(await inbox.getByRole("button",{name:"Open System",exact:true}).count(),0);
      await inbox.getByRole("button",{name:/^All/}).click();
      assert.equal(await inbox.locator(".entry-row-unread").count(),1);
      await screen(page,`${theme}-inbox-unread`);
      f.state.holdReads=false;f.state.releases.splice(0).forEach(r=>r());
      await page.waitForFunction(()=>true);
      await inbox.locator(".entry-row-unread").waitFor({state:"hidden"});
      await gui.evaluate(()=>refreshFixture());await badge.waitFor({state:"hidden"});
      await screen(page,`${theme}-inbox-read`);
      await inbox.getByRole("button",{name:"Open System",exact:true}).click();
      assert.deepEqual(await page.evaluate(()=>messages.filter(m=>m.type==="home:open-target").at(-1)).then(m=>({target:m.target,query:m.query})), {target:"system",query:{settings:"about",focus:"update"}});
      const system=gui.frameLocator('iframe.window-frame[title="System"]');
      await system.locator("#runtime-update").waitFor();
      await system.locator("#update-background-choice").waitFor();
      await system.getByRole("button",{name:"Update and restart Home",exact:true}).waitFor();
      assert.equal(await system.locator("#update-background-message").textContent(),copy("ON_TEXT"));
      await system.locator("#runtime-update").evaluate(node=>{if(document.activeElement!==node)throw new Error("update card did not receive focus");});
      await system.locator("#update-background").evaluate(node=>{
        const button=document.querySelector('#runtime-update-apply');
        assertLayout(node, button);
        function assertLayout(row, button) {
          if(row.parentElement===button.parentElement)throw new Error('switch remains inside offer');
          if(row.getBoundingClientRect().top<button.getBoundingClientRect().bottom)throw new Error('switch must be below button');
          const label=document.querySelector('#update-background-label');
          const neighbour=document.querySelector('[data-field="update-heading"]');
          if(getComputedStyle(label).fontSize!==getComputedStyle(neighbour).fontSize)throw new Error('switch label differs from settings size');
        }
      });
      await screen(page,`${theme}-system-from-entry-on`);
      await system.locator("label.system-switch:has(#update-background-choice)").click();
      await system.getByText(copy("OFF_TEXT"),{exact:true}).waitFor({timeout:3000});
      assert.deepEqual(f.state.writes.at(-1).input,{enabled:false});
      assert.ok(f.state.writes.at(-1).token);
      await screen(page,`${theme}-switch-off`);
      await system.locator("label.system-switch:has(#update-background-choice)").click();
      await system.getByText(copy("ON_TEXT"),{exact:true}).waitFor();
      await screen(page,`${theme}-switch-on`);
      // The same live System window navigates from another tab to About.
      await system.locator("button[data-settings=account]").click();
      await gui.evaluate(()=>fixture.windows.openTarget("inbox"));
      await inbox.getByRole("button",{name:"Open System",exact:true}).click();
      await system.locator("#runtime-update").waitFor();
      assert.equal(await gui.locator('iframe.window-frame[title="System"]').count(),1);
      await system.locator("#runtime-update").evaluate(node=>{if(document.activeElement!==node)throw new Error("existing card did not receive focus");});
      await screen(page,`${theme}-system-already-open`);
      // Control Centre uses its real This device handler, both with System
      // open and with a fresh window. About keeps its ordinary focus.
      for (const fresh of [false,true]) {
        if(fresh)await gui.evaluate(()=>{
          const entry=[...fixture.core.shellState.windows.values()].find(e=>e.targetId==='system');
          fixture.windows.closeWindow(entry.id);
        });
        else await system.locator("button[data-settings=account]").click();
        await page.waitForTimeout(800); // Home suppresses repeated launch gestures.
        await gui.locator('#control-centre-this-device').evaluate(node=>node.click());
        await system.locator('#runtime-update').waitFor();
        await system.locator('#runtime-update').evaluate(node=>{
          if(document.activeElement===node)throw new Error('ordinary About focused update card');
        });
        await screen(page,`${theme}-system-control-centre-${fresh?'closed':'open'}`);
      }
      await system.locator("button[data-settings=account]").click();
      await gui.evaluate(()=>fixture.windows.openTarget('system',{query:{settings:'about',focus:'unknown'}}));
      await system.locator('#runtime-update').waitFor();
      await system.locator('#runtime-update').evaluate(node=>{
        if(document.activeElement===node)throw new Error('unknown focus marker focused the card');
      });
      assert.deepEqual(errors,[]);
      await page.close();
    }
    // Exercise the entry and ordinary About journey at phone width as well.
    {
      f.state.entry=notice();f.state.holdReads=false;f.state.settings=preference(true);
      const phone=await browser.newPage({viewport:{width:390,height:844}});
      phone.setDefaultTimeout(8000);
      await phone.goto(f.baseUrl+"/notice");
      const gui=await phone.locator('#gui').elementHandle().then(h=>h.contentFrame());
      await gui.waitForFunction(()=>window.fixture);
      await gui.evaluate(()=>fixture.windows.openTarget('inbox'));
      const inbox=gui.frameLocator('iframe.window-frame[title="Inbox"]');
      await inbox.locator('.entry-row').first().click();
      await inbox.getByRole('button',{name:'Open System',exact:true}).click();
      const system=gui.frameLocator('iframe.window-frame[title="System"]');
      await system.locator('#runtime-update').waitFor();
      await system.locator('#runtime-update').evaluate(node=>{
        if(document.activeElement!==node)throw new Error('phone entry did not focus update');
      });
      await gui.waitForFunction(()=>[...document.querySelectorAll('.window-traffic-lights img')].every(img=>img.complete&&img.naturalWidth>0));
      await screen(phone,'phone-system-from-entry');
      await system.locator('button[data-settings=account]').evaluate(node=>node.click());
      await gui.locator('#control-centre-this-device').evaluate(node=>node.click());
      await system.locator('#runtime-update').waitFor();
      await system.locator('#runtime-update').evaluate(node=>{
        if(document.activeElement===node)throw new Error('phone About focused update');
      });
      await screen(phone,'phone-system-control-centre');
      await phone.close();
    }
    const page=await browser.newPage({viewport:{width:390,height:844}});
    await page.goto(f.baseUrl+"/fixture?settings=about&focus=unknown");
    const system=page.frameLocator("#system-frame");
    await system.getByRole("switch",{name:copy("SWITCH_LABEL")}).waitFor();
    await system.locator('#runtime-update').evaluate(node=>{
      if(document.activeElement===node)throw new Error('startup unknown marker focused the card');
    });
    f.state.failWrite=true;
    await system.locator("label.system-switch:has(#update-background-choice)").click();
    await system.getByRole("switch",{name:copy("SWITCH_LABEL")}).waitFor();
    await system.getByText(copy("SAVE_ERROR"),{exact:true}).waitFor();
    assert.equal(await system.getByRole("switch",{name:copy("SWITCH_LABEL")}).isChecked(),true);
    await page.waitForTimeout(5300);
    await system.getByText(copy("SAVE_ERROR"),{exact:true}).waitFor();
    await screen(page,'phone-save-error',true);
    const writesBeforeRefresh=f.state.writes.length;
    f.state.settings=preference(false);
    await page.evaluate(()=>document.querySelector('#system-frame').contentWindow.postMessage({
      type:'elastos:runtime-events',schema:'elastos.home.runtime-events/v1',events:[],
    },'*'));
    await system.getByText(copy('OFF_TEXT'),{exact:true}).waitFor({timeout:5000});
    assert.equal(f.state.writes.length,writesBeforeRefresh,'server message change clears feedback without another save');

    for(const status of [401,403]) {
      f.state.failStatus=status;
      await system.locator("label.system-switch:has(#update-background-choice)").click();
      await system.getByText("Sign in as the Home owner to change background checks.",{exact:true}).waitFor();
      await system.locator('#update-background-choice:not(:disabled)').waitFor({state:'attached'});
    }
    f.state.failWrite=false;f.state.settings=preference(false,false);await page.reload();
    await system.getByText(copy("UNREADABLE_TEXT"),{exact:true}).waitFor();
    await screen(page,'phone-unreadable-settings',true);
    f.state.failWrite=true;f.state.failStatus=409;
    await system.locator("label.system-switch:has(#update-background-choice)").click();
    await system.locator('#update-background-choice:not(:disabled)').waitFor({state:'attached'});
    await system.getByText(copy('SAVE_ERROR'),{exact:true}).waitFor();
    assert.equal(await system.getByText(copy('UNREADABLE_TEXT'),{exact:true}).count(),0,'failed repair supplies the next step');
    await screen(page,'phone-repair-failed',true);
    f.state.failWrite=false;
    await system.locator("label.system-switch:has(#update-background-choice)").click();await system.getByText(copy("ON_TEXT"),{exact:true}).waitFor();
    await system.locator('#update-background').evaluate(row=>{
      const button=document.querySelector('#runtime-update-apply');
      if(row.parentElement===button.parentElement || row.getBoundingClientRect().top<button.getBoundingClientRect().bottom)throw new Error('phone switch is part of offer');
      const bounds=row.getBoundingClientRect();
      if(bounds.right>innerWidth || bounds.left<0)throw new Error('phone switch overflows');
      if(getComputedStyle(document.querySelector('#update-background-label')).fontSize!=='13px')throw new Error('phone label size');
    });
    await screen(page,"phone-switch-on");
    await screen(page,"phone-switch-repaired");
    await system.locator("#update-background-choice").focus();
    await page.keyboard.press("Space");
    await system.getByText(copy("OFF_TEXT"),{exact:true}).waitFor();
    await screen(page,"phone-switch-off");
    for(const stateName of ['INVALID_VERSION_TEXT','FOLDER_TEXT']) {
      f.state.settings={...preference(stateName==='INVALID_VERSION_TEXT',stateName!=='FOLDER_TEXT'),message:copy(stateName)};
      await page.reload();await system.getByText(copy(stateName),{exact:true}).waitFor();
      if(stateName==='FOLDER_TEXT') {
        f.state.failWrite=true;f.state.failStatus=409;
        await system.locator("label.system-switch:has(#update-background-choice)").click();
        await system.locator('#update-background-choice:not(:checked):not(:disabled)').waitFor({state:'attached'});
        await system.getByText(copy("SAVE_ERROR"),{exact:true}).waitFor();
        assert.equal(await system.getByRole("switch",{name:copy("SWITCH_LABEL")}).isChecked(),false);
        f.state.failWrite=false;
      }
      if(stateName==='FOLDER_TEXT') {
        // Reload gives the initial repair guidance; the failed save was tested above.
        await page.reload();await system.getByText(copy(stateName),{exact:true}).waitFor();
      }
      await screen(page,`phone-${stateName.toLowerCase()}`,true);
    }
    f.state.guest=true;await page.reload();
    await system.locator("#runtime-update").waitFor({state:"hidden"});
    assert.deepEqual(f.requestFailures,[]);
    await page.close();
  } finally {await browser.close();await f.close();}
});
