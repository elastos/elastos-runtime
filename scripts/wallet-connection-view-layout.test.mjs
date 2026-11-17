import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { resolve, extname } from 'node:path';
import { requireProductSmokePlaywright } from './product-smoke-browser.mjs';
import { states, pictures, pictureViewports, fixtureView } from './wallet-connection-view-fixtures.mjs';
import { layoutFailures } from './lib/wallet-connection-view-rules.mjs';
import { viewText } from '../capsules/_shared/wallet-connection-view.mjs';

const playwright = requireProductSmokePlaywright();
const proof = process.env.WALLET_VIEW_PROOF_DIR || '/tmp/codex-runs/wallet-sharedview-render';
const capture = process.env.WALLET_VIEW_CAPTURE === '1';
const root = resolve('.');
const sizes = [{name:'window',width:480,height:522},{name:'390',width:390,height:844},{name:'1280',width:1280,height:720},
  {name:'small',compact:true},{name:'phone',compact:true}];
const candidate=execFileSync('git',['rev-parse','HEAD','HEAD^{tree}'],{encoding:'utf8'}).trim().split('\n');
const results = [];
const frameGeometry = {};
const interactionChecks = [];
await mkdir(proof, {recursive:true});

for (const engine of ['chromium','webkit']) await test(`extension_request_feedback_in_view: render-only ${engine}, both themes and all states`, async () => {
  const browser = await playwright[engine].launch({headless:true});
  try {
    const context = await browser.newContext({serviceWorkers:'block'});
    await context.route('**/*',async route=>{
      const url=new URL(route.request().url());
      assert.equal(url.hostname,'wallet-view.test','headless test attempted network');
      if(url.pathname==='/geometry'){
        const width=Number(url.searchParams.get('width')),height=Number(url.searchParams.get('height'));
        assert([[320,220],[360,640]].some(([w,h])=>w===width&&h===height));
        return route.fulfill({contentType:'text/html',body:`<!doctype html><link rel="stylesheet" href="/capsules/home-gui/browser/style.css"><body style="margin:0"><div class="window window-active" style="left:0;top:0;width:${width}px;height:${height}px"><div class="window-head"></div><div class="window-body window-body-frame"><iframe class="window-frame is-ready" src="/fixture"></iframe></div></div>`});
      }
      if(url.pathname==='/fixture')return route.fulfill({contentType:'text/html',body:'<!doctype html><html><head><meta charset="utf-8"><link rel="stylesheet" href="/capsules/wallet-metamask/browser/elastos-ui.css"><link rel="stylesheet" href="/capsules/_shared/wallet-connection-view.css"></head><body style="margin:0"><div id="mount"></div></body></html>'});
      if(url.pathname.startsWith('/connection-'))return route.fulfill({body:await readFile(resolve(root,'capsules/_shared',url.pathname.slice(1))),contentType:'image/png'});
      assert(url.pathname.startsWith('/capsules/'));
      const path=resolve(root,'.'+url.pathname);assert(path.startsWith(root+'/capsules/'));
      return route.fulfill({body:await readFile(path),contentType:({'.mjs':'text/javascript','.js':'text/javascript','.css':'text/css','.png':'image/png','.woff2':'font/woff2'})[extname(path)]||'application/octet-stream'});
    });
    const page=await context.newPage();await page.goto('http://wallet-view.test/fixture');
    frameGeometry[engine]={};
    for(const [name,width,height]of [['small',320,220],['phone',360,640]]){
      await page.setViewportSize(name==='small'?{width:1280,height:720}:{width:360,height:778});await page.goto(`http://wallet-view.test/geometry?width=${width}&height=${height}`);
      frameGeometry[engine][name]=await page.locator('iframe').evaluate(e=>{
        const frame=e.getBoundingClientRect(),outer=document.querySelector('.window').getBoundingClientRect();
        return {outerWidth:outer.width,outerHeight:outer.height,width:e.contentWindow.innerWidth,height:e.contentWindow.innerHeight,visibleWidth:Math.min(frame.right,outer.right,innerWidth)-Math.max(frame.left,outer.left,0),visibleHeight:Math.min(frame.bottom,outer.bottom,innerHeight)-Math.max(frame.top,outer.top,0),chrome:document.querySelector('.window-head').getBoundingClientRect().height};
      });
      assert([38,44].includes(frameGeometry[engine][name].chrome));
      assert.equal(frameGeometry[engine][name].outerWidth,width);assert.equal(frameGeometry[engine][name].outerHeight,height);
    }
    for(const theme of ['dark','light'])for(const size of sizes){
      if(size.compact){const [width,height]=size.name==='small'?[320,220]:[360,640];await page.setViewportSize(size.name==='small'?{width:1280,height:720}:{width:360,height:778});await page.goto(`http://wallet-view.test/geometry?width=${width}&height=${height}`);}
      else{await page.setViewportSize({width:size.width,height:size.height});await page.goto('http://wallet-view.test/fixture');}
      const surface=size.compact?page.frames().find(f=>f.url()==='http://wallet-view.test/fixture'):page;
      const actualSize=size.compact?frameGeometry[engine][size.name]:size;
      let currentViewport=page.viewportSize();
      for(const row of states){
        const rowSize=size.compact?actualSize:pictureViewports[row.window][size.name];
        if(!size.compact&&(currentViewport.width!==rowSize.width||currentViewport.height!==rowSize.height)){await page.setViewportSize(rowSize);currentViewport=rowSize;}
        const view=fixtureView(row,{compact:!!size.compact});
        const observed=await surface.evaluate(async({view,theme,visibleFrame})=>{
          const {renderConnection}=await import('/capsules/_shared/wallet-connection-view.mjs');
          document.documentElement.dataset.elTheme=theme;
          const mount=document.querySelector('#mount');mount.replaceChildren(renderConnection(document,view));
          const root=mount.firstChild;
          await document.fonts.ready;
          const focus=view.focus==='outcome'||view.focus==='accounts'?root.querySelector(`[data-focus="${view.focus}"]`):[...root.querySelectorAll('button')].find(b=>b.dataset.action===view.focus);
          focus?.focus({preventScroll:true});
          // Start from a scrolled identity/list, then re-render the resulting state.
          if(view.compact&&!view.panel)root.querySelector('.connection-content').scrollTop=10000;
          const box=e=>{const b=e.getBoundingClientRect();return {top:b.top,bottom:b.bottom,left:b.left,right:b.right,width:b.width,height:b.height};};
          const shown=e=>{const b=box(e);return b.width>0&&b.height>0&&b.top>=-1&&b.left>=-1&&b.bottom<=Math.min(innerHeight,visibleFrame.visibleHeight??innerHeight)+1&&b.right<=Math.min(innerWidth,visibleFrame.visibleWidth??innerWidth)+1;};
          const controls=[...root.querySelectorAll('button')].map(b=>({id:b.dataset.action,label:b.textContent,primary:b.classList.contains('el-button-primary'),visible:shown(b),box:box(b)}));
          const feedback=[...root.querySelectorAll('.connection-wait,.connection-status')].filter(e=>e.textContent).map(e=>({text:e.textContent,visible:shown(e),box:box(e)}));
          const names=[...root.querySelectorAll('.connection-wallet,.connection-site')].map(e=>({text:e.textContent,dir:e.dir,bidi:getComputedStyle(e).unicodeBidi,overflow:getComputedStyle(e).overflowX,whiteSpace:getComputedStyle(e).whiteSpace}));
          let clicks=[];root.addEventListener('click',e=>{const b=e.target.closest('button');if(b)clicks.push(b.dataset.action);});
          const exit=controls.find(b=>b.visible&&['cancel','stop-waiting','close-window','start-over','open-wallet-activity','open-request-app','open-wallet','connect','finish','send-message','restore-access','inbox'].includes(b.id));
          if(exit)[...root.querySelectorAll('button')].find(b=>b.dataset.action===exit.id).click();
          return {controls,feedback,names,paragraphs:[...root.querySelectorAll('p')].filter(p=>p.checkVisibility()).map(p=>p.textContent),focus:document.activeElement.dataset.action||document.activeElement.dataset.focus||null,text:root.innerText,links:root.querySelectorAll('a').length,clicks,scrollWidth:root.scrollWidth,width:innerWidth};
        },{view,theme,visibleFrame:rowSize});
        const key=`${engine}/${theme}/${size.name}/${row.designState}`;
        try{
          assert.equal(observed.links,0,key+': zero navigation');
          const normalizedText=text=>text.replace(/\s+/g,' ').trim();
          for(const parts of [view.status,view.notice,view.afterNote])if(parts.length)assert(observed.paragraphs.some(text=>normalizedText(text)===normalizedText(viewText(parts))),key+': designed copy is rendered');
          assert.deepEqual(layoutFailures(view,observed),[],key+': layout invariants');
          if(view.wait&&observed.feedback.length){
            const broken=structuredClone(observed);broken.feedback[0].visible=false;
            assert(layoutFailures(view,broken).includes('feedback'),key+': broken geometry escaped');
          }
          if(observed.names.length){
            const broken=structuredClone(observed);broken.names[0].bidi='normal';
            assert(layoutFailures(view,broken).includes('isolation'),key+': broken isolation escaped');
          }
          assert(observed.scrollWidth<=rowSize.width+1,key+': horizontal overflow');
          for(const name of observed.names){assert.equal(name.dir,'auto');assert.equal(name.bidi,'isolate');assert.equal(name.overflow,'hidden');assert.equal(name.whiteSpace,'nowrap');}
          if(view.focus)assert.equal(observed.focus,view.focus,key+': focus');
          if(view.wait||view.answered||/busy|timeout|cancelled|preparing|disconnecting/.test(row.stage)){
            for(const f of observed.feedback)assert(f.visible,`${key}: feedback outside frame ${JSON.stringify(f)}`);
            if(!view.answered)assert(observed.controls.some(b=>b.visible&&['cancel','stop-waiting','close-window','start-over','open-wallet-activity','open-request-app','open-wallet','connect','finish','send-message','restore-access','inbox'].includes(b.id)),key+': usable exit');
          }
          if(view.answered)assert(!/Time left:/.test(observed.text),key+': answered timing');
          // The design receipt is an independent control-order oracle.
          const expected=pictures.find(p=>p.window===row.window&&p.stage===row.stage);
          const labels=expected.inventory.filter(s=>/\[(primary|quiet secondary|bordered secondary)\]$/.test(s));
          const normalized=label=>{
            const text=label.replace(/^\[mark:[^\]]+\]\s*/,'').replace(/\s+/g,' ');
            return row.window==='panel'?text:text.replaceAll('MetaMask',view.account?.name||'MetaMask').replaceAll('UniSat',view.account?.name||'UniSat').replaceAll('Browser',view.request?.app||'Browser').replaceAll('Notes',view.request?.app||'Notes');
          };
          const expectedControls=labels.map(s=>({label:normalized(s.replace(/ \[(primary|quiet secondary|bordered secondary)\]$/,'')),primary:s.endsWith('[primary]')}));
          if(row.stage==='disconnecting')expectedControls.push({label:'Close window',primary:true});
          const actual=observed.controls.map(b=>({label:b.label.replace(/\s+/g,' '),primary:b.primary}));
          assert.deepEqual(actual,expectedControls,key+': control order and main control');
          const expectedFocus=view.answered?'outcome':expected.focus;
          assert.equal(observed.focus,expectedFocus,key+': design focus, with answered-outcome override');
          if(observed.clicks.length)assert.equal(observed.clicks.length,1,key+': exit operable');
          const item={engine,theme,size:size.name,window:row.window,stage:row.stage,controls:observed.controls.map(({id,label,primary})=>({id,label,primary})),focus:observed.focus,text:observed.text,result:'pass'};
          results.push(item);
          if(capture&&engine==='chromium'&&['window','390','1280'].includes(size.name))await page.screenshot({path:`${proof}/${row.window}-${row.stage}-${theme}-${size.name}.png`,fullPage:true});
        }catch(error){await writeFile(`${proof}/failure-${engine}.json`,JSON.stringify({key,view,observed},null,2));await page.screenshot({path:`${proof}/failure-${engine}.png`});throw error;}
      }
    }
    const surface=page.frames().find(f=>f.url()==='http://wallet-view.test/fixture')||page;
    const multiple=states.find(r=>r.designState==='walletconnect/linked-multiple');
    const address=multiple.local.account.accounts[1].address;
    const updated=fixtureView(multiple,{previousFocus:{stage:multiple.stage,action:'copy-address',key:`copy-address:${address}`},compact:true});
    const restored=await surface.evaluate(async view=>{
      const {renderConnection}=await import('/capsules/_shared/wallet-connection-view.mjs');
      const mount=document.querySelector('#mount');mount.replaceChildren(renderConnection(document,view));
      const target=[...mount.querySelectorAll('button')].find(b=>b.dataset.focusKey===view.focusKey);target.focus();
      return document.activeElement.dataset.focusKey;
    },updated);
    assert.equal(restored,`copy-address:${address}`);
    const qr=fixtureView(states.find(r=>r.stage==='qr-shown'),{compact:true});
    await surface.evaluate(async view=>{
      const {renderConnection,connectionKey}=await import('/capsules/_shared/wallet-connection-view.mjs');
      const mount=document.querySelector('#mount');mount.replaceChildren(renderConnection(document,view));window.qrIntents=[];
      mount.querySelector('[data-action="copy-link"]').focus();
      mount.firstChild.addEventListener('keydown',event=>{
        const decision=connectionKey(view,{key:event.key,shiftKey:event.shiftKey,action:document.activeElement.dataset.action});
        if(!decision)return;event.preventDefault();
        if(decision.focus)[...mount.querySelectorAll('button')].find(b=>b.dataset.action===decision.focus).focus();
        if(decision.intent)window.qrIntents.push(decision.intent);
      });
    },qr);
    await page.keyboard.press('Tab');assert.equal(await surface.evaluate(()=>document.activeElement.dataset.action),'cancel');
    await page.keyboard.press('Tab');assert.equal(await surface.evaluate(()=>document.activeElement.dataset.action),'copy-link');
    await page.keyboard.press('Shift+Tab');assert.equal(await surface.evaluate(()=>document.activeElement.dataset.action),'cancel');
    await page.keyboard.press('Escape');assert.deepEqual(await surface.evaluate(()=>window.qrIntents),['cancel']);
    const hostile=structuredClone(multiple);hostile.local.account.name='<img src=x onerror=alert(1)>';
    const literal=await surface.evaluate(async view=>{
      const {renderConnection}=await import('/capsules/_shared/wallet-connection-view.mjs');
      document.querySelector('#mount').replaceChildren(renderConnection(document,view));
      return {name:document.querySelector('.connection-account-name').textContent,handlers:document.querySelectorAll('[onerror]').length,remote:[...document.images].some(i=>!i.src.startsWith('http://wallet-view.test/')&&!i.src.startsWith('data:image/png;'))};
    },fixtureView(hostile,{compact:true}));
    assert.equal(literal.name,hostile.local.account.name);assert.equal(literal.handlers,0);assert.equal(literal.remote,false);
    interactionChecks.push({engine,stableAddressFocus:true,qrTabAndEscape:true,walletTextLiteral:true});
  } finally {
    await browser.close();
    const hash=createHash('sha256').update(await readFile('capsules/_shared/wallet-connection-view.mjs')).digest('hex');
    await writeFile(`${proof}/results.json`,JSON.stringify({head:candidate[0],tree:candidate[1],sourceSha256:hash,frameGeometry,interactionChecks,results},null,2)+'\n');
  }
});
