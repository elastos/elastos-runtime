import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdir,readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {execFileSync} from 'node:child_process';
import {signinFixture,installSigninProviders,evmAddress,bitcoinAddress} from './lib/wallet-signin-fixture.mjs';
import {requireProductSmokePlaywright,productSmokeLaunchOptions} from './product-smoke-browser.mjs';
import {browserFixture} from './lib/wallet-connection-browser-fixture.mjs';
const pictures=process.env.WALLET_ROUND3_PICTURES;
async function shot(page,name){if(pictures){await mkdir(pictures,{recursive:true});await page.screenshot({path:join(pictures,name+'.png'),animations:'disabled'});}}
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
for(const width of [480,390])test(`round3 title identity status and text focus at ${width}`,async()=>{
 const f=await browserFixture('chromium',{width,height:560});
 try{
  for(const stage of ['request-extension','request-done','request-cancelled']){
   await f.page.evaluate(async({stage,address})=>{
    const {connectionView,reduceSummary,mountConnection}=await import('/capsules/_shared/wallet-connection-view.mjs');
    const summary=reduceSummary({request_id:'add',connector_id:'wallet-metamask',capsule_id:'browser',requesting_app_name:'Browser',requesting_origin:'https://example.org',intent:'browser_personal_sign',address,status:'pending',expires_at:1800000600},{connector:'wallet-metamask'});
    window.mounted?.dispose();window.mounted=mountConnection(document.querySelector('#mount'),connectionView({window:'metamask',stage,waitSeconds:300,summary,account:{name:'MetaMask',mark:'metamask',accounts:[{address,networks:['Ethereum']}]},supportedActions:['send-request','close-window','stop-waiting']}));
   },{stage,address:evmAddress});
   const result=await f.page.locator('main').evaluate(root=>{const h=root.querySelector('.connection-identity h2'),identity=root.querySelector('.connection-request-account'),status=root.querySelector('.connection-status');return {title:h.getBoundingClientRect().top,identity:identity.getBoundingClientRect().top,status:status.getBoundingClientRect().top,focused:status===document.activeElement,outline:getComputedStyle(status).outlineStyle};});
   assert(result.title<result.identity&&result.identity<result.status,JSON.stringify(result));if(stage!=='request-extension'){assert.equal(result.focused,true);assert.equal(result.outline,'none');}
   await shot(f.page,`${stage}-${width}`);
  }
 }finally{await f.close();}
});
for(const width of [1280,390])test(`round3 Home bounds content size hints and can shrink connector windows at ${width}`,async()=>{
 const f=await signinFixture(),browser=await requireProductSmokePlaywright().chromium.launch({headless:true,...productSmokeLaunchOptions()});const page=await browser.newPage({viewport:{width,height:900}});
 try{
  await page.goto(f.origin+'/apps/home-gui/');
  const result=await page.evaluate(async()=>{
   const {shellState}=await import('/apps/home-gui/shell-core.js?v=home-20261101d');const {fitHomeGuiWalletWindow}=await import('/apps/home-gui/home-gui.js?v=home-20261101d');
   const node=document.createElement('section');node.className='window';Object.assign(node.style,{width:'480px',height:'560px',left:'50px',top:'60px'});node.innerHTML='<div class="window-header"><span>MetaMask</span></div><div class="window-body"><iframe class="window-frame" title="MetaMask"></iframe></div>';node.querySelector('iframe').dataset.route='/apps/wallet-metamask/#home_token=connector';node.querySelector('iframe').src='/apps/wallet-metamask/?home_origin='+encodeURIComponent(location.origin)+'#home_token=connector';document.body.append(node);shellState.windows.set('connector',{id:'connector',node,targetId:'wallet-metamask',kind:'browser'});
   const bad=fitHomeGuiWalletWindow('connector',480,100000),foreign=fitHomeGuiWalletWindow('wrong',480,300),ok=fitHomeGuiWalletWindow('connector',480,250);return {bad,foreign,ok,height:parseFloat(node.style.height)};
  });
  assert.deepEqual([result.bad,result.foreign,result.ok],[false,false,true]);assert(result.height<560);await page.frameLocator('iframe[title=MetaMask]').locator('main').waitFor();await shot(page,`content-window-${width}`);
 }finally{await browser.close();await f.close();}
});

import {fixture as extensionFixture} from './lib/wallet-extension-window-fixture.mjs';
for(const kind of ['metamask','unisat'])test(`round3 ${kind} refusal names the wallet decision`,{timeout:30000},async()=>{
 const browser=await requireProductSmokePlaywright().chromium.launch({headless:true,...productSmokeLaunchOptions()});
 const f=await extensionFixture(browser,kind,{saved:true,requests:true,pictures:false,...(process.env.WALLET_ROUND3_BASELINE?{hostSource:execFileSync('git',['show','61ed90494:capsules/home/browser/home-wallet-connector-host.js'],{encoding:'utf8'})}:{})});
 try{await f.state('request-waiting');await f.top.evaluate(()=>testState.mode='decline');await f.action('send-request').click();await f.state('request-declined');assert.match(await f.frame.locator('main').innerText(),/declined|did not approve/);await shot(f.top,kind+'-declined');}
 finally{await f.close();await browser.close();}
});
test('round3 locked first-use UniSat offers unlock and a working retry',{timeout:30000},async()=>{
 const browser=await requireProductSmokePlaywright().chromium.launch({headless:true,...productSmokeLaunchOptions()});
 const f=await extensionFixture(browser,'unisat',{pictures:false});
 try{
  await f.state('ready');await f.top.evaluate(()=>{window.sizeHints=[];addEventListener('message',e=>{if(e.data?.type==='home:wallet-content-size')sizeHints.push(e.data);});testState.requestError={method:'requestAccounts',message:'Wallet is locked'};});
  await f.action('connect').click();await f.state('wallet-locked');await f.top.waitForFunction(()=>sizeHints.length>0);assert((await f.top.evaluate(()=>sizeHints)).every(h=>Number.isSafeInteger(h.width)&&h.width>=280&&h.width<=480&&h.height>=100&&h.height<=4000));assert.match(await f.frame.locator('main').innerText(),/Unlock UniSat, then select Try again/);await shot(f.top,'unisat-locked');
  await f.top.evaluate(()=>testState.requestError=null);await f.action('connect').click();await f.state('linked');assert.equal(await f.top.evaluate(()=>testState.receipts.length),1);await shot(f.top,'unisat-unlocked-connected');
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
