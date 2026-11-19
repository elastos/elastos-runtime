import test from 'node:test';
import assert from 'node:assert/strict';
import {linkedWindow} from './lib/walletconnect-linked-window-fixture.mjs';
const sourceRef=process.env.WALLETCONNECT_LINKED_BEFORE==='copy'?'adf517637d41dfa8a42849e97f494e8b05eea708':undefined;
for(const engine of ['chromium','webkit']){
 test(`access-ready window offers the useful connection step in ${engine}`,{timeout:60000},async t=>{
  const r=await linkedWindow(t,engine,{sourceRef});await r.capture('access-ready');
  assert.equal(await r.frame.locator('[data-action=inbox]').count(),0);
  assert.equal(await r.frame.getByRole('button',{name:'Connect wallet',exact:true}).count(),1);
 });
 test(`expired linked window gives one clear close instruction in ${engine}`,{timeout:60000},async t=>{
  const r=await linkedWindow(t,engine,{sourceRef});await r.link();
  await r.page.waitForLoadState('networkidle');
  await r.frame.waitForFunction(()=>{const life=window.__walletFixtureLifetime;return !life.pending&&!life.fetches&&!life.bodies;});
  r.fixture.state.expiredLaunch=true;await r.refresh();await r.state('window-expired');await r.capture('linked-window-expired');
  const text=(await r.frame.locator('main').innerText()).replace(/\s+/g,' ');
  assert.equal(text.match(/Close this window/g)?.length,1,'Home close advice replaces the old instruction');
  assert.match(text,/Close this window with Home’s window controls, then choose WalletConnect in Wallet/);
  assert.equal(await r.frame.locator('button').count(),0);
 });
 test(`reopened linked window names the data it could not read in ${engine}`,{timeout:60000},async t=>{
  const r=await linkedWindow(t,engine,{sourceRef});await r.link();
  await r.page.route('**/wallet/accounts',route=>route.fulfill({status:503,body:'Unavailable'}));
  await r.reopen();await r.state('home-read-unavailable');await r.capture('linked-read-unavailable');
  const text=await r.frame.locator('main').innerText();
  assert.match(text,/Home could not load the wallet details/);assert.doesNotMatch(text,/requests/);
  await r.page.unroute('**/wallet/accounts');await r.click('refresh-status');await r.state('linked');await r.capture('linked-read-recovered');
 });
}
