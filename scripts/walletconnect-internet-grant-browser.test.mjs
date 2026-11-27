import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdir,readFile} from 'node:fs/promises';
import {execFileSync} from 'node:child_process';
import {join} from 'node:path';
import {states,fixtureArguments} from './wallet-connection-view-fixtures.mjs';
import {requireProductSmokePlaywright} from './product-smoke-browser.mjs';
import {signinFixture,installSigninProviders,evmAddress,bitcoinAddress} from './lib/wallet-signin-fixture.mjs';
const baseline=process.env.WC_GRANT_BASELINE==='1',output=process.env.WC_GRANT_SCREENS;
for(const engine of ['chromium','webkit'])test(`${baseline?'baseline':'one-grant'} System Add and signed-out off state in ${engine}`,{timeout:60000},async t=>{
 const f=await signinFixture();t.after(()=>f.close());
 f.state.methods=[];f.state.connected=[];f.state.wcConnected=false;f.state.internetStatus='off';
 const browser=await requireProductSmokePlaywright()[engine].launch({headless:true});t.after(()=>browser.close());
 const context=await browser.newContext({viewport:{width:480,height:560},locale:'en-US',reducedMotion:'reduce'});
 await context.addInitScript(installSigninProviders,{evmAddress,bitcoinAddress});
 const page=await context.newPage(),errors=[];page.on('pageerror',e=>errors.push(e.message));
 if(baseline)await page.route('**/apps/home/*',async route=>{
  const name=new URL(route.request().url()).pathname.slice('/apps/home/'.length);
  if(!/\.(js|mjs)$/.test(name))return route.continue();
  try{const body=execFileSync('git',['show',`097f1ce55:capsules/home/browser/${name}`],{encoding:'utf8',stdio:['ignore','pipe','ignore']});await route.fulfill({contentType:'text/javascript',body});}catch{await route.continue();}
 });
 const shot=async name=>{if(output){await mkdir(output,{recursive:true});await page.screenshot({path:join(output,`${engine}-${name}.png`),animations:'disabled'});}};
 await page.goto(f.origin+'/home/');await page.getByRole('button',{name:'Sign in',exact:true}).click();
 await page.waitForFunction(()=>window.openedPrincipal==='principal:alex');
 await page.evaluate(()=>window.showFixtureApps());
 await page.locator('#show-system').evaluate(el=>el.click());
 const system=page.frameLocator('iframe[title=system]');await system.getByRole('button',{name:'Add wallet',exact:true}).click();
 const dialog=page.locator('.signin-dialog');await dialog.locator('.connection-option').filter({hasText:'WalletConnect'}).waitFor();
 await shot('system-not-allowed');
 if(baseline)f.state.internetStatus='granted';
 await dialog.locator('.connection-option').filter({hasText:'WalletConnect'}).click();
 if(baseline){await page.locator('.signin-dialog[data-state=pairing]').waitFor();await shot('system-off-opened-qr');}
 else {
  await page.locator('.signin-dialog[data-state=internet-pending]').waitFor();
  assert.equal(await page.locator('iframe[title=WalletConnect]').count(),0);assert.equal(await dialog.locator('.connection-qr').count(),0);
  assert.equal(f.state.calls.filter(c=>c.path.endsWith('/internet')&&c.body?.action==='request').length,1);
  await shot('system-waiting');
  assert.equal(await dialog.getByRole('button',{name:'Show request',exact:true}).count(),1);
  assert.equal(await dialog.getByRole('button',{name:'Try again',exact:true}).count(),0,'Inbox owns the next action while waiting');
  await dialog.getByRole('button',{name:'Show request',exact:true}).click();
  await page.waitForFunction(()=>window.fixtureOpenedTarget?.target==='inbox');
  assert.deepEqual(await page.evaluate(()=>window.fixtureOpenedTarget),{target:'inbox',query:{notification_id:'walletconnect-internet:permission'}});
  assert.equal(await dialog.evaluate(el=>el.open),false,'Show request frees Home to use Inbox');
  f.state.internetStatus='granted';await page.locator('.signin-dialog[data-state=pairing]').waitFor();await shot('system-allowed');
  assert.equal(f.state.calls.filter(c=>c.path==='/api/auth/wallet-methods/begin'&&c.status===200).length,1);
 }
 await dialog.getByRole('button',{name:'Cancel',exact:true}).click();
 f.state.signed=false;f.state.internetStatus='off';f.state.methods=[{connector:'walletconnect',address:evmAddress,chain_id:20,network:'',proof_binding_id:'phone',sign_in_enabled:true}];
 await page.goto(f.origin+'/home/');await page.getByRole('button',{name:'Sign in',exact:true}).click();
 const choice=page.locator('.signin-dialog .connection-option').filter({hasText:'WalletConnect'});await choice.waitFor();
 if(baseline)f.state.internetStatus='granted';
 await choice.click();
 if(baseline){await page.locator('.signin-dialog[data-state=pairing]').waitFor();await shot('signed-out-off-opened-qr');}
 else {await page.locator('.signin-dialog[data-state=error]').waitFor();assert.match(await dialog.innerText(),/WalletConnect is off on this Home\. Use your passkey, MetaMask or UniSat to sign in\./);assert.equal(await dialog.locator('.connection-option').filter({hasText:'Passkey'}).count(),1);assert.equal(await dialog.getByRole('button',{name:'Try again',exact:true}).count(),0);await shot('signed-out-off');}
 await page.goto(f.origin+'/home/');
 await page.addStyleTag({content:await readFile(new URL('../capsules/home/browser/wallet-connection-view.css',import.meta.url),'utf8')});
 for(const stage of ['internet-pending','internet-refused','internet-off','internet-expired','internet-clearing','request-internet-off','request-internet-pending']) {
  const row=states.find(row=>row.window==='walletconnect'&&row.stage===stage);
  assert.ok(row,`captured state fixture: ${stage}`);
  const args=fixtureArguments(row);
  await page.evaluate(async args=>{
   const {reduceConnection,renderConnection}=await import('/apps/home/wallet-connection-view.mjs');
   document.body.replaceChildren(renderConnection(document,reduceConnection(...args)));
  },args);
  if(!baseline){assert.equal(await page.locator('[data-action=inbox]').count(),1);if(stage==='internet-clearing')assert.match(await page.locator('body').innerText(),/Finish disconnecting/);}
  await shot('window-'+stage);
 }
 assert.deepEqual(errors,[]);
});
