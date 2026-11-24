import test from 'node:test';
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {mkdir} from 'node:fs/promises';
import {join} from 'node:path';
import {signinFixture,installSigninProviders,evmAddress,bitcoinAddress} from './lib/wallet-signin-fixture.mjs';
import {browserFixture,playwright} from './lib/wallet-connection-browser-fixture.mjs';
import {windowTestOptions} from './lib/walletconnect-window-resources.mjs';
import {fixtureArguments,states} from './wallet-connection-view-fixtures.mjs';
import {windowPresentation,walletConnectView} from '../capsules/wallet-walletconnect/browser/walletconnect-window-state.mjs';
import {fixture as extensionFixture} from './lib/wallet-extension-window-fixture.mjs';
import {runtimeView} from './lib/wallet-runtime-browser.mjs';
import {viewText} from '../capsules/_shared/wallet-connection-view.mjs';
const pictures=process.env.WALLET_ROUND6_PICTURES;
async function shot(page,name){if(pictures){await mkdir(pictures,{recursive:true});await page.screenshot({path:join(pictures,name+'.png'),animations:'disabled'});}}
for(const engine of ['chromium','webkit'])for(const name of ['Rabby Wallet','Brave Wallet'])test(`round6 Add selects ${name} without MetaMask in ${engine}`,windowTestOptions(engine,30000),async()=>{
 const f=await signinFixture(),browser=await playwright[engine].launch({headless:true});f.state.methods=[];f.state.connected=[];f.state.wcConnected=false;
 const context=await browser.newContext({viewport:{width:1280,height:900}});
 await context.addInitScript(installSigninProviders,{evmAddress,bitcoinAddress,theme:'light'});await context.addInitScript(()=>{walletFixture.multiple=true;walletFixture.passkeyMode='pending';});
 const page=await context.newPage();page.setDefaultTimeout(5000);
 if(process.env.WALLET_ROUND6_BASELINE)for(const path of ['home/browser/wallet-signin-view.mjs','home/browser/wallet-signin-connector.mjs','wallet/browser/wallet-preferences.js'])await page.route('**/'+path.split('/').at(-1)+'*',r=>r.fulfill({contentType:'text/javascript',body:execFileSync('git',['show','72af9c4ff:capsules/'+path],{encoding:'utf8'})}));
 try{
  await page.goto(f.origin+'/home/');await page.waitForFunction(()=>window.fixtureReady);await page.evaluate(()=>window.showFixtureApps());
  await page.frameLocator('iframe[title=system]').getByRole('button',{name:'Add wallet',exact:true}).click();
  const wallet=page.frameLocator('iframe[title=wallet]');await wallet.locator('#wallet-signers[data-signin=options]').waitFor();
  assert.equal(await wallet.locator('.wallet-method-head').filter({hasText:'Rabby Wallet'}).count(),1);assert.equal(await wallet.locator('.wallet-method-head').filter({hasText:'Brave Wallet'}).count(),1);
  assert.equal(await wallet.locator('.wallet-method-head .wallet-method-metamask').count(),0);
  await shot(page,`chooser-${engine}-${name.split(' ')[0]}-1280`);await page.setViewportSize({width:390,height:900});await shot(page,`chooser-${engine}-${name.split(' ')[0]}-390`);
  await wallet.locator('.wallet-method-head').filter({hasText:name}).getByRole('button',{name:'Choose',exact:true}).click();
  await wallet.locator('#wallet-signers[data-signin=passkey]').waitFor();assert.equal(await page.evaluate(()=>walletFixture.calls.filter(c=>c.method==='personal_sign').length),1);assert.equal(f.state.connected.length,0);
  await shot(page,`passkey-${engine}-${name.split(' ')[0]}-390`);
  await page.evaluate(()=>{walletFixture.passkeyMode='normal';for(const job of walletFixture.pending.splice(0))job.resolve(job.result);});
  await page.frameLocator('iframe[title=system]').locator('[data-wallet-method]').waitFor();assert.equal(f.state.methods.length,1);
 }finally{await context.close();await browser.close();await f.close();}
});
for(const engine of ['chromium','webkit'])for(const width of [1280,390])test(`round6 app outcomes and sent-payment recovery in ${engine} at ${width}`,windowTestOptions(engine,30000),async()=>{
 const f=await browserFixture(engine,{width,height:900});
 try{
  for(const window of ['metamask','unisat','walletconnect'])for(const stage of window==='walletconnect'?['request-phone','request-done','request-declined','transaction-phone','transaction-done','transaction-declined']:['request-extension','request-done','request-declined']){
   const args=fixtureArguments(states.find(r=>r.window===window&&r.stage===stage));
   args[1].summary.reason=window==='unisat'?'':stage.startsWith('transaction')?'Browser asks you to send a payment on Elastos Smart Chain.':'Browser asks you to sign a message.';
   args[0].supportedActions=['stop-waiting','close-window','open-wallet'];
   await f.page.evaluate(async args=>{const m=await import('/capsules/_shared/wallet-connection-view.mjs');window.testMount?.dispose();window.testMount=m.mountConnection(document.querySelector('#mount'),m.reduceConnection(...args));},args);
   const text=(await f.page.locator('.connection-reason,.connection-status,.connection-notice').allTextContents()).join(' ');
   assert((text.match(/[.!?](?:\s|$)/g)||[]).length<=2,text);await shot(f.page,`${window}-${stage}-${engine}-${width}`);
  }
  const args=fixtureArguments(states.find(r=>r.window==='walletconnect'&&r.stage==='transaction-reopened'));
  const request={...args[1].summary,status:'approved'};
  for(const outcome of ['transaction-cancelled',undefined,'transaction-timeout','transaction-wallet-error','checking-response']){
   const p=windowPresentation({accounts:[],requests:[request],permission:'granted',outcome:outcome==='checking-response'?undefined:outcome,checking:outcome==='checking-response'},1800000001);const view=walletConnectView(p);
   assert.match(viewText(view.status)+' '+viewText(view.notice),/may already have been sent/);if(outcome!=='checking-response'){assert.match(viewText(view.notice),/To pair again, resolve this request in Wallet/);assert(view.actions.some(a=>a.id==='open-wallet'));}assert(!view.actions.some(a=>['connect','start-over','send-request'].includes(a.id)));
   await f.page.evaluate(async input=>{const m=await import('/capsules/_shared/wallet-connection-view.mjs');window.testMount?.dispose();window.testMount=m.mountConnection(document.querySelector('#mount'),m.connectionView(input));},{...p.input,summary:view.request});
   await shot(f.page,`walletconnect-${outcome||'reopened'}-${engine}-${width}`);
  }
 }finally{await f.close();}
});

for(const engine of ['chromium','webkit'])for(const kind of ['metamask','unisat'])test(`round6 ${kind} refusal records a bound wallet outcome in ${engine}`,windowTestOptions(engine,20000),async()=>{
 const browser=await playwright[engine].launch({headless:true});const f=await extensionFixture(browser,kind,{saved:true,requests:true});
 try{await f.state('request-waiting');await f.top.evaluate(()=>testState.mode='decline');await f.action('send-request').click();await f.state('request-declined');
  assert.equal(await f.top.evaluate(()=>testState.requests[0].status),'rejected');assert.equal(await f.top.evaluate(()=>testState.declines.length),1);assert.equal(await f.top.evaluate(()=>testState.receipts.length),0);
  const body=await f.top.evaluate(()=>testState.declines[0]);assert.equal(body.declined,true);assert.match(body.payload_hash,/^0x[0-9a-f]{64}$/);assert.equal(body.signature,undefined);
 }finally{await f.close();await browser.close();}
});

for(const engine of ['chromium','webkit'])test(`round6 MetaMask adds then selects a network before one payment in ${engine}`,windowTestOptions(engine,20000),async()=>{
 const browser=await playwright[engine].launch({headless:true});
 const hostSource=process.env.WALLET_ROUND6_BASELINE?execFileSync('git',['show','72af9c4ff:capsules/home/browser/home-wallet-connector-host.js'],{encoding:'utf8'}):undefined;
 const f=await extensionFixture(browser,'metamask',{saved:true,requests:'transaction',hostSource});
 try{await f.state('transaction-waiting');await f.top.evaluate(()=>testState.addSelectsChain=false);await f.action('send-request').click();await f.state('transaction-done');
  const calls=await f.top.evaluate(()=>testState.calls);assert.deepEqual(calls.filter(c=>['wallet_switchEthereumChain','wallet_addEthereumChain','eth_sendTransaction'].includes(c.method)).map(c=>c.method),['wallet_switchEthereumChain','wallet_addEthereumChain','wallet_switchEthereumChain','eth_sendTransaction']);assert.equal(await f.top.evaluate(()=>testState.receipts.length),1);
  const send=calls.find(c=>c.method==='eth_sendTransaction');assert.equal(send.chain,'0x14');await shot(f.top,`metamask-payment-network-${engine}-1280`);
 }finally{await f.close();await browser.close();}
});

for(const width of [1280,390])test(`round6 Wallet Activity names the recorded wallet refusal at ${width}`,{timeout:20000},async t=>{
 const args=fixtureArguments(states.find(r=>r.window==='walletconnect'&&r.stage==='request-waiting'));
 const request={...args[1].summary,status:'rejected',approved_at:1800000000,wallet_outcome:'declined'};
 const r=await runtimeView(t,'wallet',{approvals:[request]});await r.page.setViewportSize({width,height:900});
 await r.frame.locator('#wallet-activity-open').click();await r.frame.locator('.wallet-activity-row strong').filter({hasText:'Wallet declined'}).waitFor();
 assert.doesNotMatch(await r.frame.locator('#wallet-activity-drawer').innerText(),/Dismissed/);await shot(r.page,`wallet-activity-declined-${width}`);
});
