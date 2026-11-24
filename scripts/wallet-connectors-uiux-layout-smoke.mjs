#!/usr/bin/env node
import assert from 'node:assert/strict';
import {mkdir} from 'node:fs/promises';
import {join} from 'node:path';
import {importProductSmokePlaywright,productSmokeLaunchOptions} from './product-smoke-browser.mjs';
import {fixture as extensionFixture} from './lib/wallet-extension-window-fixture.mjs';
import {windowFixture,observeWindowErrors,walletWindowLifetime} from './lib/walletconnect-phone-window-fixture.mjs';
import {scriptedPhoneWallet} from './lib/walletconnect-phone-wallet.mjs';
import {temporaryDirectory} from './lib/wallet-connection-test-temp.mjs';
const {chromium}=await importProductSmokePlaywright();
const ownedPictures=process.env.WALLETCONNECT_SCREENSHOTS?null:temporaryDirectory('wallet-connectors-uiux-');
const screenshotRoot=process.env.WALLETCONNECT_SCREENSHOTS||ownedPictures.path;
await mkdir(screenshotRoot,{recursive:true});let browser;
const screenshots=[];
async function assertExtensionAuthority(f){
 assert(f.reads.length>0);for(const read of f.reads)assert.equal(read.headers['x-elastos-home-token'],'fixture-token');
}
async function capture(page,frame,id,control){
 for(const [width,theme] of [[1280,'dark'],[640,'light'],[390,'light']]){
  await page.setViewportSize({width,height:900});
  await frame.evaluate(theme=>document.documentElement.dataset.elTheme=theme,theme);
  await frame.locator(`button[data-action="${control}"]:visible:enabled`).waitFor();
  const snapshot=await frame.evaluate(control=>{
   const main=document.querySelector('main.connection-window'),button=main?.querySelector(`button[data-action="${control}"]`);
   const r=button?.getBoundingClientRect();
   return {main:!!main,width:innerWidth,scroll:document.documentElement.scrollWidth,token:getComputedStyle(document.documentElement).getPropertyValue('--el-bg').trim(),scheme:getComputedStyle(document.documentElement).colorScheme,rect:r&&{left:r.left,right:r.right,width:r.width,height:r.height}};
  },control);
  assert(snapshot.main,`${id}: shared window opened`);assert(snapshot.token,`${id}: shared tokens loaded`);assert.equal(snapshot.scheme,theme);
  assert(snapshot.scroll<=snapshot.width,`${id}: horizontal fit`);
  assert(snapshot.rect?.width>0&&snapshot.rect.height>=44,`${id}: visible ${control} control`);
  assert(snapshot.rect.left>=0&&snapshot.rect.right<=snapshot.width+1,`${id}: control fits`);
  const path=join(screenshotRoot,`${id}-${control}-${width}-${theme}.png`);await page.screenshot({path});screenshots.push(path);
 }
}
try{
 browser=await chromium.launch({headless:true,...productSmokeLaunchOptions()});
 for(const kind of ['metamask','unisat']){
  const locked=await extensionFixture(browser,kind,{launch:false});
  try{await locked.state('window-expired');assert.equal(await locked.frame.locator('button').count(),0);assert.equal(locked.reads.length,0);}finally{await locked.close();}
  const f=await extensionFixture(browser,kind);
  try{
   await f.state('ready');await capture(f.top,f.frame,kind,'connect');
   await f.action('connect').click();await f.state('linked');
   await assertExtensionAuthority(f);assert.equal(await f.frame.locator('.connection-account').count(),1);await capture(f.top,f.frame,kind,'copy-address');
  }finally{await f.close();}
  const review=await extensionFixture(browser,kind,{saved:true,requests:true});
  try{await review.state('request-waiting');await assertExtensionAuthority(review);assert.equal(await review.frame.locator('.connection-request-account').count(),1);await capture(review.top,review.frame,kind,'send-request');}finally{await review.close();}
 }
 const f=await windowFixture(),peer=await scriptedPhoneWallet({projectId:'fixture-project',relayUrl:f.origin.replace('http','ws')});
 const page=await browser.newPage({viewport:{width:480,height:560}}),{errors}=observeWindowErrors(page,f);
 await page.route('**/*',route=>new URL(route.request().url()).origin===f.origin?route.continue():route.abort());
 const tokens=[];page.on('request',request=>{if(new URL(request.url()).pathname.startsWith('/api/'))tokens.push(request.headers()['x-elastos-home-token']);});
 const settle=await walletWindowLifetime(page,f);let frame;
 const state=name=>frame.locator(`main[data-state="${name}"]`).waitFor({timeout:20000});
 try{
  await page.route(f.origin+'/',async route=>{const response=await route.fetch();await route.fulfill({response,body:(await response.text()).replace('#home_token=fixture-wallet','')});});
  await page.goto(f.origin);frame=page.frames().find(frame=>frame.url().includes('/apps/wallet-walletconnect/'));await state('window-expired');assert.equal(await frame.locator('button').count(),0);assert.equal(f.state.calls.length,0);
  await page.unroute(f.origin+'/');await settle(frame);await page.goto(f.origin);frame=page.frames().find(frame=>frame.url().includes('/apps/wallet-walletconnect/'));await state('internet-ready');
  await capture(page,frame,'walletconnect','connect');await frame.locator('[data-action=connect]').click();await state('qr-shown');await frame.locator('[data-action=copy-link]').click();await frame.getByText('Link copied.',{exact:true}).waitFor();await peer.pair(await page.evaluate(()=>window.copied));await state('linked');
  assert.equal(await page.evaluate(()=>window.events.filter(event=>event.type==='home:app-ready').length),1,'one app-ready per live frame');assert(tokens.length>0);assert(tokens.every(token=>token==='fixture-wallet'),'all reads use this frame launch token');
  await capture(page,frame,'walletconnect','copy-address');
  f.state.approvals=[{request_id:'layout-signature',connector_id:'wallet-walletconnect',capsule_id:'browser',requesting_origin:'https://example.test',reason:'Review this message.',status:'pending',intent:'browser_personal_sign',proof_type:'siwe',address:peer.address,chain_namespace:'eip155:8453',expires_at:Math.floor(Date.now()/1000)+600}];
  await frame.evaluate(()=>window.dispatchEvent(new Event('focus')));await state('request-waiting');await capture(page,frame,'walletconnect','send-request');
  f.state.approvals=[{...f.state.approvals[0],request_id:'layout-recovery',intent:'transaction_intent',status:'approved'}];await frame.evaluate(()=>window.dispatchEvent(new Event('focus')));
  await frame.waitForFunction(()=>document.querySelector('main')?.dataset.requestId==='layout-recovery'||document.querySelector('[data-action=view-requests]'));
  if(await frame.locator('main').getAttribute('data-request-id')!=='layout-recovery'){await frame.getByRole('button',{name:'View requests',exact:true}).click();await frame.locator('[data-focus-key="select-request:layout-recovery"]').click();}await state('transaction-reopened');
  assert.equal(await frame.locator('[data-action=send-request]').count(),0,'unfinished transaction cannot send again');await capture(page,frame,'walletconnect','open-wallet');
 }finally{try{await settle(frame);}finally{await peer.stop();await page.close();await f.stop();}assert.deepEqual(errors,[]);}
}finally{await browser?.close();ownedPictures?.cleanup();}
if(!ownedPictures)for(const path of screenshots)console.log('screenshot: '+path);
console.log('wallet connector UIUX layout smoke: ok');
