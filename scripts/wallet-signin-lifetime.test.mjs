import test from 'node:test';
import assert from 'node:assert/strict';
import {signinFixture,installSigninProviders,evmAddress,bitcoinAddress} from './lib/wallet-signin-fixture.mjs';
import {requireProductSmokePlaywright} from './product-smoke-browser.mjs';
import {walletSigninRequestTimeoutMs} from '../capsules/home/browser/wallet-signin-methods.mjs';

test('Add wallet releases System and Home when connection polling fails or its whole journey expires',async()=>{
  const fixture=await signinFixture(),{chromium}=requireProductSmokePlaywright(),browser=await chromium.launch({headless:true});
  const context=await browser.newContext();await context.addInitScript(installSigninProviders,{evmAddress,bitcoinAddress,theme:'light'});
  const page=await context.newPage();page.setDefaultTimeout(10000);
  let failSummary=false;
  await page.route('**/api/apps/system/summary',route=>failSummary?route.fulfill({status:503,contentType:'application/json',body:'{}'}):route.continue());
  try {
    fixture.state.methods=[];fixture.state.connected=[];
    await page.goto(fixture.origin+'/home/');await page.waitForFunction(()=>window.fixtureReady);await page.evaluate(()=>window.showFixtureApps());
    const system=page.frameLocator('iframe[title=system]'),add=system.getByRole('button',{name:'Add wallet',exact:true}),dialog=page.locator('.signin-dialog');
    await add.waitFor();await add.click();await page.locator('.signin-dialog[data-state=connect]').waitFor();
    await dialog.locator('.connection-option').filter({hasText:'MetaMask'}).click();
    await page.frameLocator('iframe[title=wallet-metamask]').getByRole('button',{name:'Connect wallet',exact:true}).waitFor();
    failSummary=true;await page.locator('.signin-dialog[data-state=list-error]').waitFor();
    assert(await dialog.isVisible(),'failed connection polling restores a usable sheet');
    await dialog.getByRole('button',{name:'Cancel',exact:true}).click();await dialog.waitFor({state:'detached'});await add.waitFor({state:'visible'});
    failSummary=false;await page.clock.install();await add.click();await page.locator('.signin-dialog[data-state=connect]').waitFor();
    assert(await add.isDisabled(),'System retains ownership while Home handles the journey');
    await page.clock.fastForward(walletSigninRequestTimeoutMs-15000);await dialog.waitFor({state:'detached'});await system.locator('#wallet-signin-add:not([disabled])').waitFor();
    assert(await add.isEnabled(),'Home ends the journey before System times out');
    await add.click();await page.locator('.signin-dialog[data-state=connect]').waitFor();
    assert(await dialog.isVisible(),'another Add wallet starts without reloading Home');
    await dialog.getByRole('button',{name:'Cancel',exact:true}).click();
  }finally{await context.close();await browser.close();await fixture.close();}
});

test('Desktop focuses the exact admitted connector window without opening another target',async()=>{
  const fixture=await signinFixture(),{chromium}=requireProductSmokePlaywright(),browser=await chromium.launch({headless:true});
  const page=await browser.newPage();
  try {
    await page.goto(fixture.origin+'/apps/home-gui/');
    const result=await page.evaluate(async()=>{
      const {shellState}=await import('/apps/home-gui/shell-core.js?v=home-20261101d');
      const {focusHomeGuiWindowForToken}=await import('/apps/home-gui/home-gui.js?v=home-20261101d');
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
    await page.locator('.signin-dialog[data-state=options] .connection-option').filter({hasText:'MetaMask'}).click();
    await page.evaluate(()=>window.walletFixture.mode='rejected');
    await page.frameLocator('iframe[title=wallet-metamask]').locator('[data-action=send-request]').click();
    const error=page.locator('.signin-dialog[data-state=error]');await error.waitFor();
    assert.match(await error.innerText(),/Your wallet declined the request/);assert.equal(fixture.state.methods.length,0);
  }finally{await context.close();await browser.close();await fixture.close();}
});
