import test from 'node:test';
import assert from 'node:assert/strict';
import {signinFixture,installSigninProviders,evmAddress,bitcoinAddress} from './lib/wallet-signin-fixture.mjs';
import {requireProductSmokePlaywright} from './product-smoke-browser.mjs';

test('Accounts Add wallet uses Wallet chooser and a second click returns to the same chooser',async()=>{
  const fixture=await signinFixture(),browser=await requireProductSmokePlaywright().chromium.launch({headless:true});
  const context=await browser.newContext();await context.addInitScript(installSigninProviders,{evmAddress,bitcoinAddress,theme:'light'});
  const page=await context.newPage();page.setDefaultTimeout(4000);
  try {
    fixture.state.methods=[];
    await page.goto(fixture.origin+'/home/');await page.waitForFunction(()=>window.fixtureReady);await page.evaluate(()=>window.showFixtureApps());
    const system=page.frameLocator('iframe[title=system]'),wallet=page.frameLocator('iframe[title=wallet]');
    await system.getByRole('button',{name:'Add wallet',exact:true}).click();
    await wallet.locator('#wallet-signers[data-signin=options]').waitFor();
    assert.equal(await page.locator('.signin-dialog').count(),0);
    assert.equal(await wallet.locator('#wallet-methods .wallet-method-head').count(),3);
    assert.match(await wallet.locator('#wallet-methods').innerText(),/Connected/);
    assert.doesNotMatch(await wallet.locator('#wallet-signers').innerText(),/New wallet|Connect another|Built-in/);
    await page.evaluate(()=>document.querySelector('#show-system').click());
    await system.getByRole('button',{name:'Add wallet',exact:true}).click();
    await wallet.locator('#wallet-signers[data-signin=options]').waitFor();
    assert.equal(await page.locator('iframe[title=wallet]').count(),1);
    await wallet.getByRole('button',{name:'Cancel',exact:true}).click();
    await system.getByRole('button',{name:'Add wallet',exact:true}).waitFor();
    assert.equal(await page.locator('.signin-dialog').count(),0);
  }finally{await context.close();await browser.close();await fixture.close();}
});

import {openWalletSigninChooser} from '../capsules/home/browser/wallet-signin-connector.mjs';
test('Wallet chooser accepts only its admitted source, origin, token and request; close retires it',async()=>{
  const listen=new EventTarget(),sent=[],actions=[],focus=[];
  const source={postMessage:data=>sent.push(data)},context={homeToken:'wallet-token',source};
  const chooser=await openWalletSigninChooser({listen,open:async()=>context,current:c=>c===context,focus:token=>focus.push(token),onAction:action=>actions.push(action)});
  chooser.render({stage:'options',methods:[]});const requestId=sent[0].requestId;
  const emit=(data,from=source,origin='null')=>listen.dispatchEvent(Object.assign(new Event('message'),{data,source:from,origin}));
  const message={type:'home:wallet-signin-chooser-action',homeToken:'wallet-token',requestId,action:'metamask'};
  try {
    emit(message,{});emit(message,source,'https://other.example');emit({...message,homeToken:'other'});emit({...message,requestId:'old'});emit({...message,extra:true});assert.deepEqual(actions,[]);
    emit(message);assert.deepEqual(actions,['metamask']);chooser.focus();assert.deepEqual(focus,['wallet-token']);
    chooser.close();assert.equal(sent.at(-1).state.stage,'closed');emit({...message,action:'cancel'});assert.deepEqual(actions,['metamask']);
  }finally{chooser.close();}
});

test('a used MetaMask account does not disable another current connected account of that connector',async()=>{
  const fixture=await signinFixture(),browser=await requireProductSmokePlaywright().chromium.launch({headless:true});
  const context=await browser.newContext();await context.addInitScript(installSigninProviders,{evmAddress,bitcoinAddress,theme:'light'});
  const page=await context.newPage();page.setDefaultTimeout(10000);
  try {
    fixture.state.methods=fixture.state.methods.filter(m=>m.connector==='metamask').map(m=>({...m,address:'0x'+'34'.repeat(20)}));
    await page.goto(fixture.origin+'/home/');await page.waitForFunction(()=>window.fixtureReady);await page.evaluate(()=>window.showFixtureApps());
    const system=page.frameLocator('iframe[title=system]'),wallet=page.frameLocator('iframe[title=wallet]');
    await system.getByRole('button',{name:'Add wallet',exact:true}).click();await wallet.locator('#wallet-signers[data-signin=options]').waitFor();
    const choice=wallet.locator('.wallet-method-head').filter({hasText:'MetaMask'});assert.match(await choice.innerText(),/Connected/);assert(await choice.getByRole('button',{name:'Choose',exact:true}).isEnabled());
    await choice.getByRole('button',{name:'Choose',exact:true}).click();await page.frameLocator('iframe[title=wallet-metamask]').locator('[data-action=send-request]').click();
    await system.locator('[data-wallet-method]').nth(1).waitFor();assert.equal(fixture.state.methods.length,2);assert.equal(fixture.state.methods[1].address,evmAddress);
  }finally{await context.close();await browser.close();await fixture.close();}
});

test('a focus refresh that finishes after Choose preserves the active connector step',async()=>{
  const fixture=await signinFixture(),browser=await requireProductSmokePlaywright().chromium.launch({headless:true});
  const context=await browser.newContext();await context.addInitScript(installSigninProviders,{evmAddress,bitcoinAddress,theme:'light'});
  const page=await context.newPage();page.setDefaultTimeout(10000);let holdNext=false,release,acknowledge;
  const held=new Promise(resolve=>acknowledge=resolve);
  await page.route('**/api/auth/wallet-methods',async route=>{
    if(holdNext&&route.request().headers()['x-elastos-home-token']==='fixture-home') {holdNext=false;const response=await route.fetch();await new Promise(resolve=>{release=resolve;acknowledge();});return route.fulfill({response});}
    return route.continue();
  });
  try {
    fixture.state.methods=[];await page.goto(fixture.origin+'/home/');await page.waitForFunction(()=>window.fixtureReady);await page.evaluate(()=>window.showFixtureApps());
    const system=page.frameLocator('iframe[title=system]'),wallet=page.frameLocator('iframe[title=wallet]');
    await system.getByRole('button',{name:'Add wallet',exact:true}).click();await wallet.locator('#wallet-signers[data-signin=options]').waitFor();
    holdNext=true;await wallet.locator('body').evaluate(()=>window.dispatchEvent(new Event('focus')));await held;
    await wallet.locator('.wallet-method-head').filter({hasText:'MetaMask'}).getByRole('button',{name:'Choose',exact:true}).click();
    await page.frameLocator('iframe[title=wallet-metamask]').locator('[data-action=send-request]').waitFor();
    release();await page.waitForTimeout(200);assert.equal(await wallet.locator('#wallet-signers').getAttribute('data-signin'),'signing');
    assert.equal(await page.locator('iframe[title=wallet-metamask]').count(),1);
  }finally{release?.();await context.close();await browser.close();await fixture.close();}
});
