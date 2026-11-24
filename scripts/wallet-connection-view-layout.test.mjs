import {windowTestOptions} from './lib/walletconnect-window-resources.mjs';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { resolve, extname, join } from 'node:path';
import { requireProductSmokePlaywright } from './product-smoke-browser.mjs';
import { states, contractStates, unknownSafetyStates, shared, pictures, pictureViewports, fixtureView, fixtureArguments } from './wallet-connection-view-fixtures.mjs';
import { layoutFailures, ruleFacts } from './lib/wallet-connection-view-rules.mjs';
import { viewText } from '../capsules/_shared/wallet-connection-view.mjs';

const playwright = requireProductSmokePlaywright();
const {temporaryProof}=await import('./lib/wallet-connection-browser-fixture.mjs');
const proofDirectory=await temporaryProof('wallet-view-render-',process.env.WALLET_VIEW_PROOF_DIR);
const proof=proofDirectory.path;
const capture = process.env.WALLET_VIEW_CAPTURE === '1';
const root = resolve(fileURLToPath(new URL('../',import.meta.url)));
const sizes = [{name:'window',width:480,height:522},{name:'390',width:390,height:844},{name:'1280',width:1280,height:720},
  {name:'small',compact:true},{name:'phone',compact:true}];
const candidate=execFileSync('git',['rev-parse','HEAD','HEAD^{tree}'],{encoding:'utf8',cwd:root}).trim().split('\n');
const results = [];
const frameGeometry = {};
const interactionChecks = [];
test.after(()=>proofDirectory.cleanup());

for (const engine of ['chromium','webkit']) test(`extension_request_feedback_in_view: render-only ${engine}, both themes and all states`, {skip:windowTestOptions(engine).skip}, async () => {
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
      if(url.pathname==='/fixture')return route.fulfill({contentType:'text/html',body:'<!doctype html><html><head><meta charset="utf-8"><link rel="stylesheet" href="/capsules/wallet-metamask/browser/elastos-ui.css"><link rel="stylesheet" href="/capsules/_shared/wallet-connection-view.css"></head><body class="el-app" style="margin:0"><div id="mount"></div></body></html>'});
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
      for(const row of [...states,...contractStates,...unknownSafetyStates]){
        const rowSize=size.compact?actualSize:pictureViewports[row.window][size.name];
        if(!size.compact&&(currentViewport.width!==rowSize.width||currentViewport.height!==rowSize.height)){await page.setViewportSize(rowSize);currentViewport=rowSize;}
        const view=fixtureView(row,{compact:!!size.compact});
        const expected=pictures.find(p=>p.window===row.window&&p.stage===row.stage);
        const facts=ruleFacts(row,shared,expected);
        const observed=await surface.evaluate(async({args,theme,visibleFrame})=>{
          const {mountConnection,reduceConnection}=await import('/capsules/_shared/wallet-connection-view.mjs');
          const view=reduceConnection(...args);
          document.documentElement.dataset.elTheme=theme;
          await document.fonts.load('600 28px Inter');
      const mount=document.querySelector('#mount');window.presentationMount?.dispose();window.presentationMount=mountConnection(mount,view);
          const root=mount.firstChild;
          await document.fonts.ready;
          const focus=view.focus==='outcome'||view.focus==='accounts'?root.querySelector(`[data-focus="${view.focus}"]`):[...root.querySelectorAll('button')].find(b=>b.dataset.action===view.focus);
          focus?.focus({preventScroll:true});
          // Start from a scrolled identity/list, then re-render the resulting state.
          if(view.compact&&!view.panel)root.querySelector('.connection-content').scrollTop=10000;
          const box=e=>{const b=e.getBoundingClientRect();return {top:b.top,bottom:b.bottom,left:b.left,right:b.right,width:b.width,height:b.height};};
          const shown=e=>{const b=box(e);return b.width>0&&b.height>0&&b.top>=-1&&b.left>=-1&&b.bottom<=Math.min(innerHeight,visibleFrame.visibleHeight??innerHeight)+1&&b.right<=Math.min(innerWidth,visibleFrame.visibleWidth??innerWidth)+1;};
          const controls=[...root.querySelectorAll('button')].map(b=>({id:b.dataset.action,label:b.textContent,primary:b.classList.contains('el-button-primary'),quiet:b.classList.contains('connection-quiet'),background:getComputedStyle(b).backgroundColor,visible:shown(b),box:box(b)}));
          const feedback=[...root.querySelectorAll('.connection-wait,.connection-status')].filter(e=>e.textContent).map(e=>({text:e.textContent,visible:shown(e),box:box(e)}));
          const names=[...root.querySelectorAll('.connection-isolated')].map(e=>({kind:e.classList.contains('connection-site')?'site':'name',textOverflow:getComputedStyle(e).textOverflow,text:e.textContent,dir:e.dir,bidi:getComputedStyle(e).unicodeBidi,overflow:getComputedStyle(e).overflowX,clipOverflow:e.querySelector('.connection-isolated-text')?getComputedStyle(e.querySelector('.connection-isolated-text')).overflowX:null,whiteSpace:getComputedStyle(e).whiteSpace}));
          let clicks=[];root.addEventListener('click',e=>{const b=e.target.closest('button');if(b)clicks.push(b.dataset.action);});
          const exit=controls.find(b=>b.visible&&['cancel','stop-waiting','close-window','start-over','open-wallet-activity','open-request-app','open-wallet','connect','finish','send-message','restore-access','inbox'].includes(b.id));
          if(exit)[...root.querySelectorAll('button')].find(b=>b.dataset.action===exit.id).click();
          const visibleHeading=root.querySelector(':scope > header.connection-heading');
          const headingBeforeFeedback=visibleHeading?(!root.querySelector('.connection-status')?.textContent||!visibleHeading.querySelector('h1')?.checkVisibility()||visibleHeading.querySelector('h1').getBoundingClientRect().top<=root.querySelector('.connection-status').getBoundingClientRect().top):true;
          return {headingBeforeFeedback,controls,feedback,names,qrHeadingMark:root.querySelector('.connection-dialog h2 img')?.getAttribute('src'),paragraphs:[...root.querySelectorAll('p')].filter(p=>p.checkVisibility()).map(p=>p.textContent),focus:document.activeElement.dataset.action||document.activeElement.dataset.focus||null,text:root.innerText,links:root.querySelectorAll('a').length,clicks,identityScroll:[...root.querySelectorAll('.connection-identity')].some(e=>e.scrollHeight>e.clientHeight+1),background:getComputedStyle(document.body).backgroundColor,siteOutsideIdentity:!!root.querySelector('.connection-status .connection-site,.connection-notice .connection-site'),requestAccountIsolated:[...root.querySelectorAll('.connection-request-account')].every(e=>e.querySelector('.connection-address')||e.querySelector('.connection-isolated.connection-address')),actionDisplays:[...root.querySelectorAll('.connection-actions button')].map(b=>getComputedStyle(b).display),documentHeight:document.documentElement.scrollHeight,scrollWidth:root.scrollWidth,width:innerWidth};
        },{args:fixtureArguments(row,{compact:!!size.compact}),theme,visibleFrame:rowSize});
        const key=`${engine}/${theme}/${size.name}/${row.caseId||row.designState}`;
        try{
          if(size.name==='window'){assert(observed.documentHeight<=rowSize.height,key+': ordinary screen fits');assert(observed.controls.every(b=>b.visible),key+': all controls in view');assert(!observed.identityScroll,key+': ordinary identity needs no scroll');}
          for(const b of observed.controls.filter(b=>b.primary)){assert.equal(b.quiet,false,key+': primary control is not quiet');assert(!['transparent','rgba(0, 0, 0, 0)'].includes(b.background),key+': primary control has a painted background');}
          assert.equal(observed.background,theme==='dark'?'rgb(11, 13, 16)':'rgb(238, 241, 246)',key+': designed app background');assert.equal(observed.headingBeforeFeedback,true,key+': trusted heading precedes status');assert.equal(observed.links,0,key+': zero navigation');assert.equal(observed.siteOutsideIdentity,false,key+': site once in identity');assert(observed.requestAccountIsolated,key+': isolated account address');assert(observed.actionDisplays.every(display=>display==='block'),key+': text spacing uses inline flow');
          if(view.qrData)assert.equal(observed.qrHeadingMark,'./connection-walletconnect.png',key+': designed local QR heading mark');
          const normalizedText=text=>text.replace(/\s+/g,' ').trim();
          for(const parts of [view.status,view.notice,view.afterNote])if(parts.length)assert(observed.paragraphs.some(text=>normalizedText(text)===normalizedText(viewText(parts))),key+': designed copy is rendered');
          assert.deepEqual(layoutFailures(view,observed,facts),[],key+': layout invariants');
          if(facts.wait&&observed.feedback.length){
            const broken=structuredClone(observed);broken.feedback[0].visible=false;
            assert(layoutFailures(view,broken,facts).includes('feedback'),key+': broken geometry escaped');
          }
          if(observed.names.length){
            const broken=structuredClone(observed);broken.names[0].bidi='normal';
            assert(layoutFailures(view,broken,facts).includes('isolation'),key+': broken isolation escaped');
          }
          assert(observed.scrollWidth<=rowSize.width+1,key+': horizontal overflow');
          for(const name of observed.names){assert.equal(name.dir,'auto');assert.equal(name.bidi,'isolate');if(name.kind==='site'){assert.equal(name.whiteSpace,'normal');assert.notEqual(name.textOverflow,'ellipsis');}else{assert.equal(name.clipOverflow,'hidden');assert.equal(name.whiteSpace,'nowrap');}}
          if(view.focus)assert.equal(observed.focus,view.focus,key+': focus');
          if(facts.wait||facts.answered||facts.needsExit){
            for(const f of observed.feedback)assert(f.visible,`${key}: feedback outside frame ${JSON.stringify(f)}`);
            if(!facts.answered)assert(observed.controls.some(b=>b.visible&&['cancel','stop-waiting','close-window','start-over','open-wallet-activity','open-request-app','open-wallet','connect','finish','send-message','restore-access','inbox'].includes(b.id)),key+': usable exit');
          }
          if(facts.answered)assert(!/Time left:/.test(observed.text),key+': answered timing');
          // The design receipt is an independent control-order oracle.
          const labels=(expected?.inventory||[`Open ${view.request.app} [primary]`]).filter(s=>/\[(primary|quiet secondary|bordered secondary)\]$/.test(s)).filter(s=>!((facts.capability||facts.payment)&&s.startsWith('WalletConnect [')));
          const normalized=label=>{
            const text=label.replace('Show Request','Show request').replace('Wallet activity','Activity in Wallet').replace(/^\[mark:[^\]]+\]\s*/,'').replace(/\s+/g,' ');
            return row.window==='panel'?text:text.replaceAll('MetaMask',view.account?.name||'MetaMask').replaceAll('UniSat',view.account?.name||'UniSat').replaceAll('Browser',view.request?.app||'Browser').replaceAll('Notes',view.request?.app||'Notes');
          };
          let expectedControls=labels.map(s=>({label:normalized(s.replace(/ \[(primary|quiet secondary|bordered secondary)\]$/,'')),primary:s.endsWith('[primary]')}));
          if(['walletconnect','metamask','unisat'].includes(row.window)&&['linked','linked-multiple'].includes(row.stage)){
            expectedControls=expectedControls.map(c=>c.label==='Open Wallet'?{label:'Close window',primary:true}:c);
            if(row.window==='walletconnect')expectedControls.push({label:'Add address',primary:false});
          }
          if(['request-cancelled','transaction-cancelled'].includes(row.stage))expectedControls=[{label:'Open Wallet',primary:true},{label:'Close window',primary:false}];
          if(row.window==='walletconnect'&&row.stage==='internet-ready')expectedControls=expectedControls.filter(c=>c.label!=='Manage in Inbox');
          if(row.window==='walletconnect'&&row.stage==='internet-refused')expectedControls=[{label:'Connect wallet',primary:true}];
          if(row.window==='walletconnect'&&row.stage==='internet-off')expectedControls=[{label:'Connect wallet',primary:true},{label:'Open Inbox',primary:false}];
          if(row.window==='metamask'&&['extension-missing','extensions-unavailable','other-ethereum-wallet','request-unsendable','link-error'].includes(row.stage))expectedControls=[{label:'Check again',primary:true},{label:'Close window',primary:false}];
          const fallbackClose=!expectedControls.length&&row.window==='metamask'&&expected?.inventory.some(s=>s.startsWith('WalletConnect [primary]'))&&(facts.payment||facts.capability);
          if(fallbackClose)expectedControls=[{label:'Close window',primary:true}];
          if(facts.approval){const main=expectedControls.filter(c=>c.primary),close=expectedControls.find(c=>['Close window','Cancel'].includes(c.label)),other=expectedControls.filter(c=>!c.primary&&!['Close window','Cancel'].includes(c.label));expectedControls=[...other.filter(c=>c.label==='View requests'),...main,...other.filter(c=>!c.label.startsWith('View request')),close?{...close,primary:false}:{label:'Cancel',primary:false},...other.filter(c=>c.label==='View request')];}
          if(row.unknownSafety&&['link-busy','request-busy','extension-busy'].includes(row.stage))expectedControls=[{label:'Close window',primary:true},...expectedControls.filter(c=>!c.primary&&c.label!=='Close window')];
          if(row.unknownSafety&&row.stage==='link-error')expectedControls=[{label:'Close window',primary:true}];
          if(row.stage==='disconnecting')expectedControls.push({label:'Close window',primary:true});
          if(['transaction-reopened','transaction-wallet-error','transaction-cancelled','transaction-timeout','transaction-wallet-removed'].includes(row.stage)&&!expectedControls.some(c=>c.label==='Close window'))expectedControls.push({label:'Close window',primary:false});
          const actual=observed.controls.map(b=>({label:b.label.replace(/\s+/g,' '),primary:b.primary}));
          assert.deepEqual(actual,expectedControls,key+': control order and main control');
          const expectedFocus=['request-cancelled','transaction-cancelled'].includes(row.stage)?'open-wallet':fallbackClose&&facts.focus||row.unknownSafety&&['link-busy','request-busy','extension-busy','link-error'].includes(row.stage)?'close-window':facts.focus;
          assert.equal(observed.focus,expectedFocus,key+': design focus, with answered-outcome override');
          if(observed.clicks.length)assert.equal(observed.clicks.length,1,key+': exit operable');
          const item={engine,theme,size:size.name,window:row.window,stage:row.stage,unknownSafety:!!row.unknownSafety,controls:observed.controls.map(({id,label,primary})=>({id,label,primary})),focus:observed.focus,text:observed.text,result:'pass'};
          results.push(item);
          if(capture&&engine==='chromium'&&['window','390','1280'].includes(size.name))await page.screenshot({path:`${proof}/${row.window}-${row.stage}${row.unknownSafety?'-unknown-safety':''}-${theme}-${size.name}.png`,fullPage:true});
        }catch(error){await writeFile(`${proof}/failure-${engine}.json`,JSON.stringify({key,view,observed},null,2));await page.screenshot({path:`${proof}/failure-${engine}.png`});throw error;}
      }
    }
    const surface=page.frames().find(f=>f.url()==='http://wallet-view.test/fixture')||page;
    const multiple=states.find(r=>r.designState==='walletconnect/linked-multiple');
    const address=multiple.local.account.accounts[1].address;
    const updated=fixtureView(multiple,{previousFocus:{stage:multiple.stage,action:'copy-address',key:`copy-address:${address}`},compact:true});
    const restored=await surface.evaluate(async args=>{
      const {renderConnection,reduceConnection}=await import('/capsules/_shared/wallet-connection-view.mjs');
      const view=reduceConnection(...args);
      const mount=document.querySelector('#mount');mount.replaceChildren(renderConnection(document,view));
      const target=[...mount.querySelectorAll('button')].find(b=>b.dataset.focusKey===view.focusKey);target.focus();
      return document.activeElement.dataset.focusKey;
    },fixtureArguments(multiple,{previousFocus:{stage:multiple.stage,action:'copy-address',key:`copy-address:${address}`},compact:true}));
    assert.equal(restored,`copy-address:${address}`);
    const qr=fixtureView(states.find(r=>r.stage==='qr-shown'),{compact:true});
    await surface.evaluate(async args=>{
      const {renderConnection,connectionKey,reduceConnection}=await import('/capsules/_shared/wallet-connection-view.mjs');
      const view=reduceConnection(...args);
      const mount=document.querySelector('#mount');mount.replaceChildren(renderConnection(document,view));window.qrIntents=[];
      mount.querySelector('[data-action="copy-link"]').focus();
      mount.firstChild.addEventListener('keydown',event=>{
        const decision=connectionKey(view,{key:event.key,shiftKey:event.shiftKey,action:document.activeElement.dataset.action});
        if(!decision)return;event.preventDefault();
        if(decision.focus)[...mount.querySelectorAll('button')].find(b=>b.dataset.action===decision.focus).focus();
        if(decision.intent)window.qrIntents.push(decision.intent);
      });
    },fixtureArguments(states.find(r=>r.stage==='qr-shown'),{compact:true}));
    await page.keyboard.press('Tab');assert.equal(await surface.evaluate(()=>document.activeElement.dataset.action),'cancel');
    await page.keyboard.press('Tab');assert.equal(await surface.evaluate(()=>document.activeElement.dataset.action),'copy-link');
    await page.keyboard.press('Shift+Tab');assert.equal(await surface.evaluate(()=>document.activeElement.dataset.action),'cancel');
    await page.keyboard.press('Escape');assert.deepEqual(await surface.evaluate(()=>window.qrIntents),['cancel']);
    const hostile=structuredClone(multiple);hostile.local.account.name='<img src=x onerror=alert(1)>';
    const literal=await surface.evaluate(async args=>{
      const {renderConnection,reduceConnection}=await import('/capsules/_shared/wallet-connection-view.mjs');
      const view=reduceConnection(...args);
      document.querySelector('#mount').replaceChildren(renderConnection(document,view));
      return {name:document.querySelector('.connection-account-name').textContent,handlers:document.querySelectorAll('[onerror]').length,remote:[...document.images].some(i=>!i.src.startsWith('http://wallet-view.test/')&&!i.src.startsWith('data:image/png;'))};
    },fixtureArguments(hostile,{compact:true}));
    assert.equal(literal.name,hostile.local.account.name);assert.equal(literal.handlers,0);assert.equal(literal.remote,false);
    interactionChecks.push({engine,stableAddressFocus:true,qrTabAndEscape:true,walletTextLiteral:true});
  } finally {
    await browser.close();
    const hash=createHash('sha256').update(await readFile(resolve(root,'capsules/_shared/wallet-connection-view.mjs'))).digest('hex');
    await writeFile(`${proof}/results.json`,JSON.stringify({head:candidate[0],tree:candidate[1],sourceSha256:hash,frameGeometry,interactionChecks,results},null,2)+'\n');
  }
});

for(const engine of ['chromium','webkit'])test(`isolated names share text baselines and linked screens retain their design spacing in ${engine}`,{skip:windowTestOptions(engine).skip},async()=>{
 const {browserFixture}=await import('./lib/wallet-connection-browser-fixture.mjs');
 const f=await browserFixture(engine);
 try{
  const checks=[];
  for(const name of ['metamask/request-waiting','metamask/request-done','unisat/request-declined','walletconnect/link-wait','metamask/linked','unisat/linked','walletconnect/transaction-declined']){
   await f.page.evaluate(async args=>{const {reduceConnection,renderConnection}=await import('/capsules/_shared/wallet-connection-view.mjs');document.querySelector('#mount').replaceChildren(renderConnection(document,reduceConnection(...args)));await document.fonts.ready;},fixtureArguments(states.find(r=>r.designState===name)));
   const measured=await f.page.evaluate(()=>{
    const baselines=[];
    for(const bdi of document.querySelectorAll('p .connection-isolated,button .connection-isolated')){
     if(bdi.classList.contains('connection-site'))continue;
     const parent=bdi.closest('p,button'),walker=document.createTreeWalker(parent,NodeFilter.SHOW_TEXT);const own=document.createTreeWalker(bdi,NodeFilter.SHOW_TEXT);own.nextNode();if(!own.currentNode?.length)continue;
     const range=document.createRange();range.setStart(own.currentNode,0);range.setEnd(own.currentNode,1);const nameBox=range.getBoundingClientRect();let node;
     while(node=walker.nextNode())if(!node.parentElement.closest('bdi')&&node.textContent.trim()){
      const index=node.textContent.search(/\S/);const copy=document.createRange();copy.setStart(node,index);copy.setEnd(node,index+1);const box=copy.getBoundingClientRect();const lineHeight=parseFloat(getComputedStyle(parent).lineHeight);
      if(Math.abs(box.top-nameBox.top)<lineHeight*.7)baselines.push({text:parent.textContent,delta:Math.abs(box.top-nameBox.top)});
     }
    }
    const mark=document.querySelector('.connection-account-header img')?.getBoundingClientRect();
    const note=[...document.querySelectorAll('.connection-content > .connection-note,.connection-step > .connection-note')].at(-1),button=document.querySelector('.connection-content > .connection-actions [data-action="close-window"],.connection-step > .connection-actions [data-action="close-window"]');
    return {baselines,mark:mark&&{width:mark.width,height:mark.height},gapBeforeClose:note&&button?button.getBoundingClientRect().top-note.getBoundingClientRect().bottom:null,computed:[...document.querySelectorAll('.connection-computed-detail')].map(e=>({text:e.textContent,hasAppLabel:!!e.querySelector('.connection-detail-label')})),app:[...document.querySelectorAll('.connection-context')].map(e=>e.textContent)};
   });
   if(name.includes('/request-')||name==='walletconnect/link-wait'){assert(measured.baselines.length,name+': baseline samples');assert(measured.baselines.every(b=>b.delta<=.5),name+': '+JSON.stringify(measured.baselines));}
   if(name.endsWith('/linked')){if(name==='metamask/linked')assert.equal(measured.mark,undefined);else assert.deepEqual(measured.mark,{width:24,height:24});if(name==='metamask/linked')assert(measured.gapBeforeClose>=8,'the single stop-sharing notice has space before Close window');}
   if(name==='walletconnect/transaction-declined'){assert.equal(measured.computed.length,1);assert.equal(measured.computed[0].hasAppLabel,false);assert(!measured.computed[0].text.includes('From app:'));}
   assert(measured.app.every(text=>!text.includes('BrowserSite in Browser:')&&!text.includes('Browser  Site reported')),'Browser shown once');
   checks.push({name,...measured});
  }
  const peer=await f.page.evaluate(async()=>{
   const {connectionView,renderConnection}=await import('/capsules/_shared/wallet-connection-view.mjs');
   document.querySelector('#mount').replaceChildren(renderConnection(document,connectionView({window:'walletconnect',stage:'linked',localSafety:false,account:{name:'WalletConnect',mark:'metamask',connection:'WalletConnect',accounts:[{address:'0x1122334455667788990011223344556677889900',networks:['Ethereum']}]}})));
   return {heading:document.querySelector('h1')?.textContent,peer:document.querySelector('.connection-account-name bdi')?.textContent,mark:document.querySelector('.connection-account-header img')?.getAttribute('src'),hint:document.querySelector('.connection-via')?.textContent};
  });
  assert.deepEqual(peer,{heading:'WalletConnect',peer:'WalletConnect',mark:'./connection-wallet.png',hint:undefined});
  await writeFile(`${proof}/polish-${engine}.json`,JSON.stringify(checks,null,2)+'\n');
 }finally{await f.close();}
});
