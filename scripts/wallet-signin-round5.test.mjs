import test from 'node:test';
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {mkdir} from 'node:fs/promises';
import {join} from 'node:path';
import {signinFixture,installSigninProviders,evmAddress,bitcoinAddress} from './lib/wallet-signin-fixture.mjs';
import {requireProductSmokePlaywright} from './product-smoke-browser.mjs';
import {windowTestOptions} from './lib/walletconnect-window-resources.mjs';
const pictures=process.env.WALLET_ROUND5_PICTURES;
async function shot(page,name){if(pictures){await mkdir(pictures,{recursive:true});await page.screenshot({path:join(pictures,name+'.png'),animations:'disabled'});}}
for(const engine of ['chromium','webkit'])for(const width of [1280,390])for(const kind of ['MetaMask','UniSat','WalletConnect'])test(`round5 new ${kind}: one Add signature, sign in and Remove in ${engine} at ${width}`,windowTestOptions(engine,30000),async()=>{
 const f=await signinFixture(),browser=await requireProductSmokePlaywright()[engine].launch({headless:true});
 f.state.methods=[];f.state.connected=[];f.state.wcConnected=false;
 const context=await browser.newContext({viewport:{width,height:900},locale:'en-US'});await context.addInitScript(installSigninProviders,{evmAddress,bitcoinAddress,theme:'light'});
 const page=await context.newPage();page.setDefaultTimeout(5000);let baselineLoads=0;
 if(process.env.WALLET_ROUND5_BASELINE)await page.route('**/wallet-signin-view.mjs*',r=>{baselineLoads++;return r.fulfill({contentType:'text/javascript',body:execFileSync('git',['show','42866a34e:capsules/home/browser/wallet-signin-view.mjs'],{encoding:'utf8'})});});
 const system=page.frameLocator('iframe[title=system]'),wallet=page;
 const name=`${engine}-${width}-${kind.toLowerCase()}`;
 const signatures=async()=>f.state.calls.filter(c=>c.path==='/api/fixture-sdk'&&c.body.method==='personal_sign').length+await page.evaluate(()=>window.walletFixture.calls.filter(c=>['personal_sign','signMessage'].includes(c.method)).length);
 const pair=async purpose=>{await page.locator('.signin-dialog[data-state=pairing]').waitFor();assert.equal((await page.locator('.signin-dialog').innerText()).match(/relay that can see this computer's internet address/g)?.length,1,'pairing shows the relay disclosure once');const bounds=await page.locator('.signin-dialog').boundingBox();assert(purpose==='signin'?bounds.height<=900:bounds.height<700,'QR dialog fits its content and the sign-in choices stay within the viewport');await shot(page,name+'-'+purpose+'-qr');await page.locator('iframe[title=WalletConnect]').evaluate(frame=>frame.contentWindow.postMessage('fixture-pair','*'));};
 try{
  await page.goto(f.origin+'/home/');await page.waitForFunction(()=>window.fixtureReady);if(process.env.WALLET_ROUND5_BASELINE)assert(baselineLoads>0,'pinned baseline module was served');await page.evaluate(()=>{window.showFixtureApps();window.walletFixture.passkeyMode='pending';});
  await system.getByRole('button',{name:'Add wallet',exact:true}).click();await wallet.locator('.signin-dialog[data-state=options]').waitFor();
  assert.doesNotMatch(await wallet.locator('.signin-dialog').innerText(),/Not connected|\bConnected\b/i);
  if(kind==='WalletConnect'){assert.match(await wallet.locator('.signin-dialog').innerText(),/Rainbow, Trust/);assert.match(await wallet.locator('.signin-dialog').innerText(),/relay.*internet address/);}
  await shot(page,name+'-chooser');
  const choice=wallet.locator('.connection-option').filter({hasText:kind});
  const box=await choice.boundingBox();await page.mouse.click(box.x+box.width/2,box.y+box.height/2);
  if(kind==='WalletConnect')await pair('add');
  await wallet.getByRole('button',{name:'Sign message',exact:true}).click();
  await wallet.getByRole('button',{name:'Approve with passkey',exact:true}).click();
  await wallet.locator('.signin-dialog[data-state=passkey]').waitFor();
  if(kind==='WalletConnect'){assert.match(await wallet.locator('.signin-dialog').innerText(),/relay.*internet address/);assert.match(await wallet.locator('.signin-dialog').innerText(),/Fixture Wallet/);}
  await shot(page,name+'-passkey');assert.equal(await signatures(),1);assert.equal(f.state.connected.length,0);
  assert(!f.state.calls.some(c=>/wallet\/(accounts|link)/.test(c.path)&&c.body));
  await page.evaluate(()=>{window.walletFixture.passkeyMode='normal';for(const job of window.walletFixture.pending.splice(0))job.resolve(job.result);});
  await system.locator('[data-wallet-method]').waitFor();await shot(page,name+'-added');assert.equal(f.state.methods.length,1);
  await page.goto(f.origin+'/home/');await page.waitForFunction(()=>window.fixtureReady);
  await page.getByRole('button',{name:'Sign in',exact:true}).click();await page.locator('.signin-dialog[data-state=options]').waitFor();
  await page.locator('.connection-option').filter({hasText:kind}).click();if(kind==='WalletConnect')await pair('signin');
  await page.waitForFunction(()=>window.openedPrincipal==='principal:alex');assert.equal(f.state.walletSession,true);
  await page.evaluate(()=>window.showFixtureApps());await system.locator('[data-wallet-method]').getByRole('button',{name:'Remove from sign-in',exact:true}).click();
  await system.locator('[data-wallet-method]').waitFor({state:'detached'});assert.equal(f.state.methods.length,0);assert.equal(f.state.connected.length,0);await shot(page,name+'-removed');
 }finally{await context.close();await browser.close();await f.close();}
});
for(const engine of ['chromium','webkit'])test(`round5 cancel new WalletConnect pairing in ${engine} leaves both stores unchanged`,windowTestOptions(engine,20000),async()=>{
 const f=await signinFixture(),browser=await requireProductSmokePlaywright()[engine].launch({headless:true});f.state.methods=[];f.state.connected=[];f.state.wcConnected=false;
 const context=await browser.newContext();await context.addInitScript(installSigninProviders,{evmAddress,bitcoinAddress,theme:'light'});const page=await context.newPage();page.setDefaultTimeout(5000);
 try{
  await page.goto(f.origin+'/home/');await page.waitForFunction(()=>window.fixtureReady);await page.evaluate(()=>window.showFixtureApps());
  await page.frameLocator('iframe[title=system]').getByRole('button',{name:'Add wallet',exact:true}).click();
  await page.locator('.signin-dialog .connection-option').filter({hasText:'WalletConnect'}).click();
  await page.locator('.signin-dialog[data-state=pairing]').getByRole('button',{name:'Cancel',exact:true}).click();
  await page.locator('.signin-dialog').waitFor({state:'detached'});assert.equal(await page.locator('iframe[title=WalletConnect]').count(),0);
  assert.equal(f.state.methods.length,0);assert.equal(f.state.connected.length,0);assert.equal(f.state.calls.filter(c=>c.path==='/api/fixture-sdk'&&c.body.method==='personal_sign').length,0);
  assert(f.state.calls.some(c=>c.path==='/api/auth/wallet/cancel'));
 }finally{await context.close();await browser.close();await f.close();}
});
test('round5 a saved sign-in method without a payment connection keeps WalletConnect pairing available',{timeout:20000},async()=>{
 const f=await signinFixture(),browser=await requireProductSmokePlaywright().chromium.launch({headless:true});f.state.methods=f.state.methods.filter(m=>m.connector==='walletconnect');f.state.connected=[];f.state.wcConnected=false;
 const context=await browser.newContext();await context.addInitScript(installSigninProviders,{evmAddress,bitcoinAddress,theme:'light'});const page=await context.newPage();page.setDefaultTimeout(5000);
 try{
  await page.goto(f.origin+'/home/');await page.waitForFunction(()=>window.fixtureReady);await page.evaluate(()=>window.showFixtureApps());
  await page.frameLocator('iframe[title=system]').getByRole('button',{name:'Add wallet',exact:true}).click();
  const choice=page.locator('.signin-dialog .connection-option').filter({hasText:'WalletConnect'});assert(await choice.isEnabled());await shot(page,'saved-signin-walletconnect-chooser-1280');await page.setViewportSize({width:390,height:900});await shot(page,'saved-signin-walletconnect-chooser-390');await choice.click();
  await page.locator('.signin-dialog[data-state=pairing]').getByRole('button',{name:'Cancel',exact:true}).click();await page.locator('.signin-dialog').waitFor({state:'detached'});
  assert.equal(f.state.methods.length,1);assert.equal(f.state.connected.length,0);
 }finally{await context.close();await browser.close();await f.close();}
});
