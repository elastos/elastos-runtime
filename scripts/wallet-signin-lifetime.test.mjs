import test from 'node:test';
import assert from 'node:assert/strict';
import {signinFixture,installSigninProviders,evmAddress,bitcoinAddress} from './lib/wallet-signin-fixture.mjs';
import {requireProductSmokePlaywright} from './product-smoke-browser.mjs';
import {walletSigninRequestTimeoutMs} from '../capsules/home/browser/wallet-signin-methods.mjs';

test('Add wallet releases Home and System after list failure, close, or the management deadline',async()=>{
  const fixture=await signinFixture(),browser=await requireProductSmokePlaywright().chromium.launch({headless:true});
  const context=await browser.newContext();await context.addInitScript(installSigninProviders,{evmAddress,bitcoinAddress,theme:'light'});
  const page=await context.newPage();page.setDefaultTimeout(10000);let failSummary=false;
  await page.route('**/api/apps/wallet/wallet/inventory',route=>failSummary?route.fulfill({status:503,contentType:'application/json',body:'{}'}):route.continue());
  try {
    fixture.state.methods=[];fixture.state.connected=[];
    await page.goto(fixture.origin+'/home/');await page.waitForFunction(()=>window.fixtureReady);await page.evaluate(()=>window.showFixtureApps());
    const system=page.frameLocator('iframe[title=system]'),wallet=page,add=system.getByRole('button',{name:'Add wallet',exact:true});
    await add.waitFor();failSummary=true;await add.click();await wallet.locator('.signin-dialog[data-state=list-error]').waitFor();
    failSummary=false;await wallet.getByRole('button',{name:'Try again',exact:true}).click();await wallet.locator('.signin-dialog[data-state=options]').waitFor();
    await wallet.getByRole('button',{name:'Cancel',exact:true}).click();await add.waitFor();
    await page.clock.install();await add.click();await wallet.locator('.signin-dialog[data-state=options]').waitFor();
    assert(await system.locator('#wallet-signin-add').isEnabled(),'a second click can focus the active journey');
    await page.clock.fastForward(walletSigninRequestTimeoutMs-15000);await wallet.locator('.signin-dialog[data-state]').waitFor({state:'detached'});await add.waitFor();
    await add.click();await wallet.locator('.signin-dialog[data-state=options]').waitFor();
    await page.getByRole('button',{name:'Cancel',exact:true}).click();await page.locator('#show-system').evaluate(el=>el.click());await add.waitFor();
    await add.click();await page.locator('.signin-dialog[data-state=options]').waitFor();
    await page.getByRole('button',{name:'Cancel',exact:true}).click();
  }finally{await context.close();await browser.close();await fixture.close();}
});

test('Desktop focuses the exact admitted connector window without opening another target',async()=>{
  const fixture=await signinFixture(),{chromium}=requireProductSmokePlaywright(),browser=await chromium.launch({headless:true});
  const page=await browser.newPage();
  try {
    await page.goto(fixture.origin+'/apps/home-gui/');
    const result=await page.evaluate(async()=>{
      const {shellState}=await import('/apps/home-gui/shell-core.js?v=home-20261101d');
      const {focusHomeGuiWindowForToken}=await import('/apps/home-gui/home-gui.js?v=home-20261110a');
      for(const [id,token] of [['other','other-token'],['connector','connector-token']]){
        const node=document.createElement('section');node.className='window';node.innerHTML='<button data-action="close">Close</button><iframe class="window-frame"></iframe>';
        node.querySelector('iframe').dataset.route='/apps/wallet-metamask/#home_token='+token;document.body.append(node);
        shellState.windows.set(id,{id,node,targetId:'wallet-metamask',kind:'browser'});
      }
      const missing=focusHomeGuiWindowForToken('wrong-token'),matched=focusHomeGuiWindowForToken('connector-token');
      return {missing,matched,active:shellState.activeWindowId,count:shellState.windows.size};
    });
    assert.deepEqual(result,{missing:false,matched:true,active:'connector',count:2});
  }finally{await browser.close();await fixture.close();}
});

test('a declined extension signature keeps the wallet refusal instead of a disconnect error',async()=>{
  const fixture=await signinFixture(),{chromium}=requireProductSmokePlaywright(),browser=await chromium.launch({headless:true});
  const context=await browser.newContext();await context.addInitScript(installSigninProviders,{evmAddress,bitcoinAddress,theme:'light'});
  const page=await context.newPage();page.setDefaultTimeout(10000);
  try{
    fixture.state.methods=[];
    await page.goto(fixture.origin+'/home/');await page.waitForFunction(()=>window.fixtureReady);await page.evaluate(()=>window.showFixtureApps());
    const system=page.frameLocator('iframe[title=system]');await system.getByRole('button',{name:'Add wallet',exact:true}).click();
    await page.evaluate(()=>window.walletFixture.mode='rejected');
    await page.locator('.signin-dialog .connection-option').filter({hasText:'MetaMask'}).click();
    await page.getByRole('button',{name:'Sign message',exact:true}).click();
    const error=page.locator('.signin-dialog[data-state=error]');await error.waitFor();
    assert.match(await error.innerText(),/Your wallet declined the request/);assert.equal(fixture.state.methods.length,0);
  }finally{await context.close();await browser.close();await fixture.close();}
});

test('phone sign-in returns from QR to its waiting row in the same sheet',async()=>{
  const fixture=await signinFixture(),{chromium}=requireProductSmokePlaywright(),browser=await chromium.launch({headless:true});
  const context=await browser.newContext();await context.addInitScript(installSigninProviders,{evmAddress,bitcoinAddress,theme:'light'});
  const page=await context.newPage();page.setDefaultTimeout(10000);
  try{
    await page.goto(fixture.origin+'/home/?desktop-app');await page.waitForFunction(()=>window.fixtureReady);
    await page.getByRole('button',{name:'Sign in',exact:true}).click();await page.locator('.signin-dialog[data-state=options] .connection-option').filter({hasText:'WalletConnect'}).click();
    await page.locator('.signin-dialog[data-state=pairing]').waitFor();
    await page.locator('iframe[title="WalletConnect"]').evaluate(f=>{f.contentWindow.postMessage('fixture-sign-pending','*');f.contentWindow.postMessage('fixture-pair','*');});
    const sheet=page.locator('.signin-dialog[data-state=signing]');await sheet.waitFor();
    assert.equal(await sheet.locator('.connection-option').filter({hasText:'Waiting for WalletConnect…'}).count(),1);
    assert.equal(await sheet.locator('details,summary,pre').count(),0);assert.equal(await page.locator('#fixture-desktop iframe').count(),0);
    await sheet.getByRole('button',{name:'Cancel',exact:true}).click();
  }finally{await context.close();await browser.close();await fixture.close();}
});

test('expired address selection retries Add with one proof and zero payment records',async()=>{
  const fixture=await signinFixture(),browser=await requireProductSmokePlaywright().chromium.launch({headless:true});
  const context=await browser.newContext();await context.addInitScript(installSigninProviders,{evmAddress,bitcoinAddress,theme:'light'});
  const page=await context.newPage();page.setDefaultTimeout(10000);
  try {
    fixture.state.methods=[];fixture.state.connected=[];
    await page.goto(fixture.origin+'/home/');await page.waitForFunction(()=>window.fixtureReady);await page.evaluate(()=>window.showFixtureApps());
    await page.clock.install();const system=page.frameLocator('iframe[title=system]'),wallet=page;
    await system.getByRole('button',{name:'Add wallet',exact:true}).click();await wallet.locator('.signin-dialog[data-state=options]').waitFor();
    await page.evaluate(()=>window.walletFixture.mode='pending');
    await wallet.locator('.connection-option').filter({hasText:'MetaMask'}).click();
    await wallet.locator('.signin-dialog[data-state=connecting]').waitFor();
    await page.clock.fastForward(180001);fixture.state.clockOffsetMs=180001;
    await wallet.locator('.signin-dialog[data-state=error]').waitFor();
    await page.evaluate(()=>{window.walletFixture.mode='normal';for(const job of window.walletFixture.pending.splice(0))job.resolve(job.result);});
    await wallet.getByRole('button',{name:'Try again',exact:true}).click();
    await page.getByRole('button',{name:'Sign message',exact:true}).click();await page.getByRole('button',{name:'Approve with passkey',exact:true}).click();
    await system.locator('[data-wallet-method]').waitFor();assert.equal(fixture.state.methods.length,1);
    assert.equal(fixture.state.connected.length,0);assert.equal(await page.locator('iframe[title=wallet-metamask]').count(),0);
    assert.equal(await page.evaluate(()=>window.walletFixture.calls.filter(c=>c.method==='personal_sign').length),1);

  }finally{await context.close();await browser.close();await fixture.close();}
});
