import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdir,readFile,writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {signinFixture,installSigninProviders,evmAddress,bitcoinAddress} from './lib/wallet-signin-fixture.mjs';
import {requireProductSmokePlaywright,productSmokeLaunchOptions} from './product-smoke-browser.mjs';
import {fixtureView,states,fixtureArguments} from './wallet-connection-view-fixtures.mjs';
import {windowTestOptions} from './lib/walletconnect-window-resources.mjs';
const pictures=process.env.WALLET_ROUND3_PICTURES;
async function shot(page,name){if(pictures){await mkdir(pictures,{recursive:true});await page.waitForTimeout(150);const bytes=await page.screenshot({path:join(pictures,name+'.png'),animations:'disabled'});await writeFile(join(pictures,name+'.json'),JSON.stringify({head:execFileSync('git',['rev-parse','HEAD'],{encoding:'utf8'}).trim(),tree:execFileSync('git',['rev-parse','HEAD^{tree}'],{encoding:'utf8'}).trim(),clean:!execFileSync('git',['status','--porcelain'],{encoding:'utf8'}).trim(),viewport:page.viewportSize(),sha256:createHash('sha256').update(bytes).digest('hex')},null,2));}}
for(const width of [1280,390])test(`round3 pointer Choose survives a focus refresh at ${width}`,{timeout:30000},async()=>{
 const f=await signinFixture(),browser=await requireProductSmokePlaywright().chromium.launch({headless:true,...productSmokeLaunchOptions()});
 const context=await browser.newContext({viewport:{width,height:900}});await context.addInitScript(installSigninProviders,{evmAddress,bitcoinAddress,theme:'light'});
 const page=await context.newPage();page.setDefaultTimeout(5000);f.state.methods=[];
 if(process.env.WALLET_ROUND3_BASELINE)await page.route('**/wallet-preferences.js*',r=>r.fulfill({contentType:'text/javascript',body:execFileSync('git',['show','61ed90494:capsules/wallet/browser/wallet-preferences.js'],{encoding:'utf8'})}));
 try {
  await page.goto(f.origin+'/home/');await page.waitForFunction(()=>window.fixtureReady);await page.evaluate(()=>window.showFixtureApps());
  const system=page.frameLocator('iframe[title=system]'),wallet=page.frameLocator('iframe[title=wallet]');
  await system.getByRole('button',{name:'Add wallet',exact:true}).click();await wallet.locator('#wallet-signers[data-signin=options]').waitFor();
  const choose=wallet.locator('.wallet-method-head').filter({hasText:'MetaMask'}).getByRole('button',{name:'Choose',exact:true});await choose.waitFor();
  const box=await choose.boundingBox();await page.mouse.move(box.x+box.width/2,box.y+box.height/2);await page.mouse.down();
  await wallet.locator('body').evaluate(()=>window.dispatchEvent(new Event('focus')));await page.waitForTimeout(300);
  await shot(page,`pointer-${width}`);await page.mouse.up();
  await system.locator('[data-wallet-method]').filter({hasText:'MetaMask'}).waitFor();
  assert.equal(f.state.methods.length,1);await shot(page,`added-${width}`);
 }finally{await context.close();await browser.close();await f.close();}
});
for(const width of [1280,390])test(`round3 title identity status and text focus at ${width}`,async()=>{
 const browser=await requireProductSmokePlaywright().chromium.launch({headless:true,...productSmokeLaunchOptions()});
 try{
  for(const stage of ['request-extension','request-done','request-cancelled']){
   const f=await extensionFixture(browser,'metamask',{saved:true,requests:true,pictures:false});
   try{
    await f.top.setViewportSize({width,height:560});await f.top.locator('iframe').evaluate((frame,width)=>frame.style.width=width+'px',width);await f.state('request-waiting');
    if(stage!=='request-done')await f.top.evaluate(()=>testState.mode='pending');
    await f.action('send-request').click();
    if(stage==='request-cancelled')await f.action('stop-waiting').click();
    await f.state(stage);
    // Outcome text can receive programmatic focus for screen-reader status.
    // Cancelled requests can also focus the working Close control.
    if(stage==='request-cancelled')await f.frame.locator('.connection-status').focus();
    const result=await f.frame.locator('main').evaluate(root=>{const h=root.querySelector('.connection-identity h2'),identity=root.querySelector('.connection-request-account'),status=root.querySelector('.connection-status');return {title:h.getBoundingClientRect().top,identity:identity.getBoundingClientRect().top,status:status.getBoundingClientRect().top,focused:status===document.activeElement,outline:getComputedStyle(status).outlineStyle};});
    assert(result.title<result.identity&&result.identity<result.status,JSON.stringify(result));
    const site=await f.frame.locator('.connection-site-row').innerText();assert.match(site,/^[^/]+ in Browser$/);assert.doesNotMatch(await f.frame.locator('main').innerText(),/Requesting app|Site in Browser:/);
    const waiting=await f.frame.locator('.connection-status,.connection-notice').allTextContents();assert(waiting.join(' ').split(/[.!?](?: |$)/).filter(x=>x.trim()).length<=2);if(stage!=='request-extension'){assert.equal(result.focused,true);assert.equal(result.outline,'none');}
    if(stage==='request-cancelled'){await f.top.evaluate(()=>{window.round5Navigation=[];addEventListener('message',event=>{if(event.data?.type==='home:open-target')round5Navigation.push(event.data);});});await f.action('open-wallet').click();const navigation=await f.top.evaluate(()=>round5Navigation);assert.equal(navigation.at(-1)?.target,'wallet');}
    assert.equal(await f.action('close-window').count()>0||stage==='request-extension',true);await shot(f.top,`${stage}-${width}`);
   }finally{await f.close();}
  }
 }finally{await browser.close();}
});
for(const width of [1280,390])test(`round3 Home bounds content size hints and can shrink connector windows at ${width}`,async()=>{
 const f=await signinFixture(),browser=await requireProductSmokePlaywright().chromium.launch({headless:true,...productSmokeLaunchOptions()});const page=await browser.newPage({viewport:{width,height:900}});
 try{
  await page.goto(f.origin+'/apps/home-gui/');
  const result=await page.evaluate(async()=>{
   const {shellState}=await import('/apps/home-gui/shell-core.js?v=home-20261101d');const {fitHomeGuiWalletWindow}=await import('/apps/home-gui/home-gui.js?v=home-20261101d');
   const node=document.createElement('section');node.className='window window-active';Object.assign(node.style,{width:'480px',height:'560px',left:'50px',top:'60px'});node.innerHTML='<div class="window-head"><span class="window-head-title">MetaMask</span></div><div class="window-body window-body-frame"><iframe class="window-frame is-ready" title="MetaMask"></iframe></div>';node.querySelector('iframe').dataset.route='/apps/wallet-metamask/#home_token=connector';node.querySelector('iframe').src='/apps/wallet-metamask/?home_origin='+encodeURIComponent(location.origin)+'#home_token=connector';document.body.append(node);shellState.windows.set('connector',{id:'connector',node,targetId:'wallet-metamask',kind:'browser'});
   window.walletFitHints=[];addEventListener('message',event=>{if(event.source===node.querySelector('iframe').contentWindow&&event.data?.type==='home:wallet-content-size'&&event.data.homeToken==='connector'){walletFitHints.push(event.data);fitHomeGuiWalletWindow('connector',event.data.width,event.data.height);}});
   const bad=fitHomeGuiWalletWindow('connector',480,100000),foreign=fitHomeGuiWalletWindow('wrong',480,300),ok=fitHomeGuiWalletWindow('connector',480,250);return {bad,foreign,ok,height:parseFloat(node.style.height)};
  });
  assert.deepEqual([result.bad,result.foreign,result.ok],[false,false,true]);assert(result.height<560);await page.frameLocator('iframe[title=MetaMask]').locator('main').waitFor();await page.waitForFunction(()=>walletFitHints.length>0);const hint=await page.evaluate(()=>walletFitHints.at(-1));assert(hint.height>=100&&hint.height<1000);await shot(page,`content-window-${width}`);
 }finally{await browser.close();await f.close();}
});

for(const width of [1280,390])for(const mount of ['connection-root','wallet-window'])test(`round3 QR stays readable while ${mount} fits its window at ${width}`,{timeout:15000},async()=>{
 const qrData=fixtureView(states.find(row=>row.window==='walletconnect'&&row.stage==='qr-shown')).qrData;
 const f=await signinFixture(),browser=await requireProductSmokePlaywright().chromium.launch({headless:true,...productSmokeLaunchOptions()});const page=await browser.newPage({viewport:{width,height:900}});page.setDefaultTimeout(5000);
 await page.route('**/qr-fit?*',route=>route.fulfill({contentType:'text/html',body:`<!doctype html><meta charset="utf-8"><link rel="stylesheet" href="/apps/wallet-walletconnect/elastos-ui.css"><link rel="stylesheet" href="/apps/wallet-walletconnect/wallet-connection-view.css"><body class="el-app" style="margin:0"><div id="${mount}"></div><script type="module">import '/apps/wallet-walletconnect/wallet-connection-loading.mjs';import {connectionView,mountConnection} from '/apps/wallet-walletconnect/wallet-connection-view.mjs';mountConnection(document.getElementById('${mount}'),connectionView(${JSON.stringify({window:'walletconnect',stage:'qr-shown',qrData,supportedActions:['copy-link','cancel','close-window']})}));</script>`}));
 try{
  await page.goto(f.origin+'/apps/home-gui/');await page.evaluate(async()=>{const {shellState}=await import('/apps/home-gui/shell-core.js?v=home-20261101d');const {fitHomeGuiWalletWindow}=await import('/apps/home-gui/home-gui.js?v=home-20261101d');const node=document.createElement('section');node.className='window window-active';node.style.cssText='width:480px;height:560px;left:50px;top:60px';node.innerHTML='<div class="window-head"><span class="window-head-title">WalletConnect</span></div><div class="window-body window-body-frame"><iframe class="window-frame is-ready" title="QR"></iframe></div>';const frame=node.querySelector('iframe');frame.dataset.route='/apps/wallet-walletconnect/#home_token=qr-fit';document.body.append(node);shellState.windows.set('qr-fit',{id:'qr-fit',node,targetId:'wallet-walletconnect',kind:'browser'});window.fitHints=[];addEventListener('message',event=>{if(event.source===frame.contentWindow&&event.data?.type==='home:wallet-content-size'){fitHints.push(event.data);fitHomeGuiWalletWindow('qr-fit',event.data.width,event.data.height);}});frame.src='/qr-fit?home_origin='+encodeURIComponent(location.origin)+'#home_token=qr-fit';});
  const frame=page.frameLocator('iframe[title=QR]');await frame.locator('.connection-qr').waitFor({state:'attached'});await page.waitForFunction(()=>fitHints.length>0);await page.waitForTimeout(700);const qr=await frame.locator('.connection-qr').boundingBox();assert(qr.width>=152&&qr.height>=152,JSON.stringify(qr));await frame.getByRole('button',{name:'Cancel',exact:true}).waitFor();await shot(page,`qr-content-fit-${mount}-${width}`);
 }finally{await browser.close();await f.close();}
});

import {fixture as extensionFixture} from './lib/wallet-extension-window-fixture.mjs';
for(const engine of ['chromium','webkit'])test(`round3 locked UniSat request keeps its consumed action in ${engine}`,windowTestOptions(engine,30000),async()=>{
 const browser=await requireProductSmokePlaywright()[engine].launch({headless:true,...(engine==='chromium'?productSmokeLaunchOptions():{})});const f=await extensionFixture(browser,'unisat',{saved:true,requests:true,pictures:false});
 try{await f.state('request-waiting');await f.top.evaluate(()=>testState.requestError={method:'signMessage',message:'Wallet is locked'});await f.action('send-request').click();await f.state('request-wallet-error');assert.equal(await f.action('connect').count(),0);assert.equal(await f.action('send-request').count(),0);assert.equal(await f.top.evaluate(()=>testState.requests[0].status),'approved');assert.equal(await f.top.evaluate(()=>testState.receipts.length),0);await f.assertShared();}
 finally{await f.close();await browser.close();}
});
for(const width of [1280,390])for(const kind of ['metamask','unisat'])test(`round3 ${kind} refusal names the wallet decision at ${width}`,{timeout:30000},async()=>{
 const browser=await requireProductSmokePlaywright().chromium.launch({headless:true,...productSmokeLaunchOptions()});
 const f=await extensionFixture(browser,kind,{saved:true,requests:true,pictures:false,...(process.env.WALLET_ROUND3_BASELINE?{hostSource:execFileSync('git',['show','61ed90494:capsules/home/browser/home-wallet-connector-host.js'],{encoding:'utf8'})}:{})});
 try{await f.top.setViewportSize({width,height:560});await f.top.locator('iframe').evaluate((frame,width)=>frame.style.width=width+'px',width);await f.state('request-waiting');await f.top.evaluate(()=>testState.mode='decline');await f.action('send-request').click();await f.state('request-declined');assert.match(await f.frame.locator('main').innerText(),/declined|did not approve/);await shot(f.top,`${kind}-declined-${width}`);}
 finally{await f.close();await browser.close();}
});
for(const width of [1280,390])for(const method of ['requestAccounts','signMessage'])test(`round3 locked first-use UniSat at ${method} offers unlock and a working retry at ${width}`,{timeout:30000},async()=>{
 const browser=await requireProductSmokePlaywright().chromium.launch({headless:true,...productSmokeLaunchOptions()});
 const f=await extensionFixture(browser,'unisat',{pictures:false});
 try{
  await f.top.setViewportSize({width,height:560});await f.top.locator('iframe').evaluate((frame,width)=>frame.style.width=width+'px',width);await f.state('ready');await f.top.evaluate(method=>{window.sizeHints=[];addEventListener('message',e=>{if(e.data?.type==='home:wallet-content-size')sizeHints.push(e.data);});testState.requestError={method,message:'Wallet is locked'};},method);
  await f.action('connect').click();await f.state('wallet-locked');await f.top.waitForFunction(()=>sizeHints.length>0);assert((await f.top.evaluate(()=>sizeHints)).every(h=>Number.isSafeInteger(h.width)&&h.width>=280&&h.width<=480&&h.height>=100&&h.height<=4000));assert.match(await f.frame.locator('main').innerText(),/Unlock UniSat, then select Try again/);assert.equal(await f.frame.locator('.connection-step .connection-status').count(),1);assert.equal(await f.frame.locator('.connection-step [data-action=connect]').count(),1);await shot(f.top,`unisat-locked-${method}-${width}`);
  await f.top.evaluate(()=>testState.requestError=null);await f.action('connect').click();await f.state('linked');assert.equal(await f.top.evaluate(()=>testState.receipts.length),1);assert.equal(await f.frame.locator('.connection-step .connection-status').count(),1);await shot(f.top,`unisat-unlocked-connected-${width}`);
 }finally{await f.close();await browser.close();}
});

for(const width of [1280,390])for(const status of [403,409])test(`round3 ${status} refusal has one working recovery at ${width}`,{timeout:30000},async()=>{
 const f=await signinFixture(),browser=await requireProductSmokePlaywright().chromium.launch({headless:true,...productSmokeLaunchOptions()});const context=await browser.newContext({viewport:{width,height:900}});await context.addInitScript(installSigninProviders,{evmAddress,bitcoinAddress,theme:'light'});const page=await context.newPage();page.setDefaultTimeout(5000);f.state.methods=[];let refuse=true;
 await page.route('**/api/auth/wallet-methods/complete',route=>refuse?route.fulfill({status,json:{error:'wallet_signin_refused'}}):route.continue());
 try{
  await page.goto(f.origin+'/home/');await page.waitForFunction(()=>window.fixtureReady);await page.evaluate(()=>window.showFixtureApps());const system=page.frameLocator('iframe[title=system]'),wallet=page.frameLocator('iframe[title=wallet]');
  await system.getByRole('button',{name:'Add wallet',exact:true}).click();await wallet.locator('#wallet-signers[data-signin=options]').waitFor();await wallet.locator('.wallet-method-head').filter({hasText:'MetaMask'}).getByRole('button',{name:'Choose',exact:true}).click();
  await wallet.locator('#wallet-signers[data-signin=error]').waitFor();const text=await wallet.locator('#wallet-signers').innerText();assert.match(text,/Home could not/);assert.doesNotMatch(text,/Check again/);assert(f.state.calls.some(c=>c.path.endsWith('/cancel')));await shot(page,`refusal-${status}-${width}`);
  refuse=false;await wallet.getByRole('button',{name:'Try again',exact:true}).click();await wallet.locator('#wallet-signers[data-signin=options]').waitFor();await wallet.locator('.wallet-method-head').filter({hasText:'MetaMask'}).getByRole('button',{name:'Choose',exact:true}).click();await system.locator('[data-wallet-method]').filter({hasText:'MetaMask'}).waitFor();assert.equal(f.state.methods.length,1);
 }finally{await context.close();await browser.close();await f.close();}
});

for(const width of [1280,390])test(`round3 a second Add brings the unknown change forward at ${width}`,{timeout:30000},async()=>{
 const f=await signinFixture(),browser=await requireProductSmokePlaywright().chromium.launch({headless:true,...productSmokeLaunchOptions()});const context=await browser.newContext({viewport:{width,height:900}});await context.addInitScript(installSigninProviders,{evmAddress,bitcoinAddress,theme:'light'});const page=await context.newPage();page.setDefaultTimeout(5000);f.state.methods=[];
 await page.route('**/api/auth/wallet-methods/complete',route=>route.abort('failed'));
 try{
  await page.goto(f.origin+'/home/');await page.waitForFunction(()=>window.fixtureReady);await page.evaluate(()=>window.showFixtureApps());const system=page.frameLocator('iframe[title=system]'),wallet=page.frameLocator('iframe[title=wallet]');
  await system.getByRole('button',{name:'Add wallet',exact:true}).click();await wallet.locator('#wallet-signers[data-signin=options]').waitFor();await wallet.locator('.wallet-method-head').filter({hasText:'MetaMask'}).getByRole('button',{name:'Choose',exact:true}).click();await wallet.locator('#wallet-signers[data-signin=unknown]').waitFor();
  await page.locator('iframe[title=wallet]').evaluate(frame=>frame.remove());await page.locator('#show-system').evaluate(el=>el.click());await system.getByRole('button',{name:'Add wallet',exact:true}).click();await wallet.getByRole('button',{name:'Check again',exact:true}).waitFor();assert.equal(await page.locator('iframe[title=wallet]').isVisible(),true);assert.equal(f.state.calls.filter(c=>c.path.endsWith('/wallet-methods/complete')).length,0,'lost transport sends no replacement proof');await shot(page,`unknown-second-add-${width}`);
 }finally{await context.close();await browser.close();await f.close();}
});

for(const width of [1280,390])test(`round3 Wallet shows account access plainly at ${width}`,{timeout:30000},async()=>{
 const f=await signinFixture(),browser=await requireProductSmokePlaywright().chromium.launch({headless:true,...productSmokeLaunchOptions()});const page=await browser.newPage({viewport:{width,height:900}});page.setDefaultTimeout(5000);
 const request={request_id:'account-access',status:'pending',intent:'browser_account_access',capsule_id:'browser',requesting_origin:'https://example.org',reason:'Share this address with example.org',account_id:'payment:one',address:evmAddress,proof_type:'managed_evm',created_at:Math.floor(Date.now()/1000),expires_at:Math.floor(Date.now()/1000)+600,review:{kind:'account_access',permission:'eth_accounts',origin:'https://example.org',account_id:'payment:one',requested_chain_namespace:'eip155:20',chain_namespaces:['eip155:20'],address:evmAddress,grant_expires_at:Math.floor(Date.now()/1000)+600}};
 await page.route('**/api/apps/wallet/wallet/summary',route=>route.fulfill({json:{wallet_accounts:{accounts:f.state.connected},wallet_approvals:{approval_requests:[request]},approval_methods:{walletconnect:{available:true}}}}));
 try{await page.goto(f.origin+'/apps/wallet/?home_origin='+encodeURIComponent(f.origin)+'#home_token=fixture-wallet');await page.getByRole('heading',{name:'Account access',exact:true}).waitFor();assert.equal(await page.locator('details,summary').count(),0);const copy=await page.locator('.wallet-request-review').innerText();assert.doesNotMatch(copy,/eth_accounts|eip155:|payment:one|Access expires/);assert.match(copy,/Your wallet address/);assert.match(copy,/Elastos Smart Chain/);assert.match(copy,/Access until/);assert.equal(await page.getByRole('button',{name:'Allow',exact:true}).isVisible(),true);await shot(page,`wallet-account-access-${width}`);}
 finally{await browser.close();await f.close();}
});

import {browserFixture} from './lib/wallet-connection-browser-fixture.mjs';
for(const width of [1280,390])for(const [window,stage] of [['metamask','transaction-extension'],['walletconnect','transaction-phone']])test(`round5 payment wait keeps two safety sentences in ${window} at ${width}`,async()=>{
 const f=await browserFixture('chromium',{width,height:900});
 try{
  const args=fixtureArguments(states.find(row=>row.window===window&&row.stage===stage));
  await f.page.evaluate(async args=>{const m=await import('/capsules/_shared/wallet-connection-view.mjs');m.mountConnection(document.querySelector('#mount'),m.reduceConnection(...args));},args);
  const text=(await f.page.locator('.connection-status,.connection-notice').allTextContents()).join(' ');
  assert((text.match(/[.!?](?:\s|$)/g)||[]).length<=2);assert.match(text,/transaction/);assert.match(text,/stop waiting/);
  await shot(f.page,`payment-wait-${window}-${width}`);
 }finally{await f.close();}
});
