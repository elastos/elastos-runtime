import test from 'node:test';
import assert from 'node:assert/strict';
import {signinFixture,installSigninProviders,evmAddress,bitcoinAddress,sampleMethod} from './lib/wallet-signin-fixture.mjs';
import {requireProductSmokePlaywright} from './product-smoke-browser.mjs';
async function fixture(t) {
  const f=await signinFixture(),browser=await requireProductSmokePlaywright().chromium.launch({headless:true});
  const context=await browser.newContext();await context.addInitScript(installSigninProviders,{evmAddress,bitcoinAddress,theme:'light'});
  const page=await context.newPage();page.setDefaultTimeout(6000);
  t.after(async()=>{await context.close();await browser.close();await f.close();});
  f.state.methods=[];await page.goto(f.origin+'/home/');await page.waitForFunction(()=>window.fixtureReady);await page.evaluate(()=>window.showFixtureApps());
  const system=page.frameLocator('iframe[title=system]'),dialog=page.locator('.signin-dialog');
  return {f,page,system,dialog,open:()=>system.getByRole('button',{name:'Add wallet',exact:true}).click(),choose:()=>dialog.locator('.connection-option').filter({hasText:'MetaMask'}).click()};
}
test('Accounts Add wallet uses the Home chooser and a second click returns to that request',async t=>{
  const {f,page,system,dialog,open}=await fixture(t);await open();await dialog.locator('.connection-option').nth(2).waitFor();
  assert.equal(await dialog.locator('.connection-option').count(),3);assert.match(await dialog.innerText(),/Rainbow, Trust and other phone wallets/);
  assert.equal(await page.frameLocator('iframe[title=wallet]').locator('#wallet-signers').count(),0);
  const original=await dialog.elementHandle();await system.getByRole('button',{name:'Add wallet',exact:true}).evaluate(el=>el.click());
  assert.equal(await original.evaluate(node=>node===document.querySelector('.signin-dialog')),true);
  await dialog.getByRole('button',{name:'Cancel',exact:true}).click();await dialog.waitFor({state:'detached'});
  assert.equal(f.state.methods.length,0);assert.equal(f.state.connected.length,1);
});
test('a used MetaMask account keeps another connected address available in System',async t=>{
  const {f,dialog,open,choose}=await fixture(t);f.state.methods=[{...sampleMethod(),address:'0x'+'ab'.repeat(20)}];
  await open();await choose();await dialog.getByRole('button',{name:'Sign message',exact:true}).click();await dialog.getByRole('button',{name:'Approve with passkey',exact:true}).click();
  await dialog.waitFor({state:'detached'});assert.equal(f.state.methods.length,2);assert.equal(f.state.methods[1].address,evmAddress);
});
test('Cancel during the System signature preserves sign-in and app-use records',async t=>{
  const {f,page,dialog,open,choose}=await fixture(t);await open();await choose();await page.evaluate(()=>walletFixture.signaturePending=true);
  await dialog.getByRole('button',{name:'Sign message',exact:true}).click();await page.locator('.signin-dialog[data-state=signing]').waitFor();
  await dialog.getByRole('button',{name:'Cancel',exact:true}).click();await dialog.waitFor({state:'detached'});
  await page.evaluate(()=>{walletFixture.signaturePending=false;for(const pending of walletFixture.pending.splice(0))pending.resolve(pending.result);});
  assert.equal(f.state.methods.length,0);assert.equal(f.state.connected.length,1);assert(!f.state.calls.some(c=>c.path==='/api/auth/wallet-methods/complete'));
});
test('a new sign-in wallet whose proof is refused leaves app records unchanged',async t=>{
  const {f,page,dialog,open,choose}=await fixture(t);f.state.connected=[];await page.evaluate(()=>walletFixture.mode='rejected');
  await open();await choose();await dialog.getByRole('button',{name:'Sign message',exact:true}).click();await page.locator('.signin-dialog[data-state=error]').waitFor();
  assert.equal(await page.evaluate(()=>walletFixture.calls.filter(c=>c.method==='personal_sign').length),1);
  assert.equal(f.state.methods.length,0);assert.equal(f.state.connected.length,0);
});
test('a connected wallet that selects another account stops before Add signs',async t=>{
  const {f,page,dialog,open,choose}=await fixture(t);await open();await choose();await dialog.getByRole('button',{name:'Sign message',exact:true}).waitFor();
  await page.evaluate(()=>walletFixture.address='0x'+'34'.repeat(20));await dialog.getByRole('button',{name:'Sign message',exact:true}).click();await page.locator('.signin-dialog[data-state=error]').waitFor();
  assert.equal(await page.evaluate(()=>walletFixture.calls.filter(c=>c.method==='personal_sign').length),0);
  assert(!f.state.calls.some(c=>c.path==='/api/auth/wallet-methods/complete'));assert.equal(f.state.methods.length,0);
});
