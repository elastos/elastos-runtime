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
