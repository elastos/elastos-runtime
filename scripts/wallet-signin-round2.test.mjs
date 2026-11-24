import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdir} from 'node:fs/promises';
import {join} from 'node:path';
import {signinFixture,installSigninProviders,evmAddress,bitcoinAddress} from './lib/wallet-signin-fixture.mjs';
import {requireProductSmokePlaywright} from './product-smoke-browser.mjs';

for(const width of [1280,390])test(`connected Add and uncertain save keep their action at ${width}px`,async()=>{
  const fixture=await signinFixture(),browser=await requireProductSmokePlaywright().chromium.launch({headless:true});
  fixture.state.methods=fixture.state.methods.filter(m=>m.connector!=='metamask');
  const context=await browser.newContext({viewport:{width,height:900},locale:'en-US'});
  await context.addInitScript(installSigninProviders,{evmAddress,bitcoinAddress,theme:'light'});
  const page=await context.newPage();page.setDefaultTimeout(10000);let dispatched=false,loseRead=true,releaseComplete,acknowledgeComplete;
  const completeHeld=new Promise(resolve=>acknowledgeComplete=resolve);
  await page.route('**/api/auth/wallet-methods/complete',async route=>{await route.fetch();dispatched=true;await new Promise(resolve=>{releaseComplete=resolve;acknowledgeComplete();});await route.abort('failed');});
  await page.route('**/api/auth/wallet-methods',route=>dispatched&&loseRead?route.abort('failed'):route.continue());
  const capture=async name=>{if(process.env.SIGNIN_SCREENSHOT_DIR){const target=['busy','saved'].includes(name)?'system':'wallet';if(!await page.locator('iframe[title='+target+']').isVisible())await page.locator('#show-'+target).evaluate(el=>el.click());await page.locator('iframe[title='+target+']').waitFor({state:'visible'});await page.waitForTimeout(200);await mkdir(process.env.SIGNIN_SCREENSHOT_DIR,{recursive:true});await page.screenshot({path:join(process.env.SIGNIN_SCREENSHOT_DIR,`round2-${width}-${name}.png`),fullPage:true,animations:'disabled'});}};
  try {
    await page.goto(fixture.origin+'/home/');await page.waitForFunction(()=>window.fixtureReady);await page.evaluate(()=>window.showFixtureApps());
    const system=page.frameLocator('iframe[title=system]'),wallet=page.frameLocator('iframe[title=wallet]');
    await system.getByRole('button',{name:'Add wallet',exact:true}).click();await wallet.locator('#wallet-signers[data-signin=options]').waitFor();await capture('chooser');
    await page.evaluate(()=>{window.walletFixture.signaturePending=true;window.walletFixture.passkeyMode='pending';});
    await wallet.locator('.wallet-method-head').filter({hasText:'MetaMask'}).getByRole('button',{name:'Choose',exact:true}).click();
    await wallet.locator('#wallet-signers[data-signin=signing]').waitFor();await capture('signature');
    assert.equal(await page.locator('iframe[title=wallet-metamask]').count(),0,'connected extension goes straight to its signature');
    // A second action must receive Busy rather than the first action's promise.
    await page.locator('#show-system').evaluate(el=>el.click());
    await system.locator('[data-wallet-method]').first().getByRole('button',{name:'Remove',exact:true}).click();
    const busy=system.getByText('Finish the open wallet request before you start another change.',{exact:true});await busy.waitFor();const busyBox=await busy.boundingBox();assert(busyBox.y>=0&&busyBox.y+busyBox.height<=900,'Accounts shows Busy without scrolling');await capture('busy');
    assert(!fixture.state.calls.some(c=>c.path.endsWith('/wallet-methods/begin')&&c.body.action==='remove'));
    await page.locator('#show-wallet').evaluate(el=>el.click());
    await page.evaluate(()=>{window.walletFixture.signaturePending=false;for(const p of window.walletFixture.pending.splice(0))p.resolve(p.result);});
    await wallet.locator('#wallet-signers[data-signin=passkey]').waitFor();await capture('passkey');
    await page.evaluate(()=>{window.walletFixture.passkeyMode='normal';for(const p of window.walletFixture.pending.splice(0))p.resolve(p.result);});
    await wallet.locator('#wallet-signers[data-signin=completing]').waitFor();
    assert.equal(await wallet.getByRole('button',{name:'Cancel',exact:true}).count(),0,'completing add hides Cancel');
    await wallet.locator('body').press('Escape');
    assert.equal(await wallet.locator('#wallet-signers').getAttribute('data-signin'),'completing');
    await completeHeld;releaseComplete();
    await wallet.locator('#wallet-signers[data-signin=unknown]').waitFor();
    assert.equal(await wallet.getByRole('button',{name:'Cancel',exact:true}).count(),0,'uncertain add hides Cancel');
    await wallet.locator('body').press('Escape');
    assert.equal(await wallet.locator('#wallet-signers').getAttribute('data-signin'),'unknown','Escape preserves unknown');
    await capture('unknown');
    // A second Add brings the existing uncertain action forward with its recovery control.
    await page.locator('#show-system').evaluate(el=>el.click());
    await system.getByRole('button',{name:'Add wallet',exact:true}).click();
    await wallet.getByRole('button',{name:'Check again',exact:true}).waitFor();
    await capture('unknown-refocused');
    const completeCount=fixture.state.calls.filter(c=>c.path.endsWith('/wallet-methods/complete')).length;
    assert.equal(completeCount,1);assert(fixture.state.methods.some(m=>m.connector==='metamask'));
    // Check again reads the authority list and never resends the proof.
    loseRead=false;await wallet.getByRole('button',{name:'Check again',exact:true}).click();
    await wallet.locator('#wallet-signers[data-signin]').waitFor({state:'detached'});
    await system.locator('[data-wallet-method]').filter({hasText:'MetaMask'}).waitFor();await capture('saved');
    const counts=await page.evaluate(()=>window.walletFixture.calls.map(c=>c.method));
    assert.equal(counts.filter(m=>m==='personal_sign').length,1);assert.equal(counts.filter(m=>m==='passkey').length,1);
    assert.equal(fixture.state.calls.filter(c=>c.path.endsWith('/wallet-methods/complete')).length,completeCount);
    assert(!fixture.state.calls.some(c=>c.path.endsWith('/wallet/cancel')));
    assert.equal(await page.locator('details,summary').count(),0);
    assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
  } finally {releaseComplete?.();await context.close();await browser.close();await fixture.close();}
});
