import test from 'node:test';
import assert from 'node:assert/strict';
import {linkedWindow} from './lib/walletconnect-linked-window-fixture.mjs';
const sourceRef=process.env.WALLETCONNECT_LINKED_BEFORE==='copy'?'adf517637d41dfa8a42849e97f494e8b05eea708':undefined;
for(const engine of ['chromium','webkit']){
 test(`a reopened linked window waits for saved connection restoration before offering controls in ${engine}`,{timeout:60000},async t=>{
  const r=await linkedWindow(t,engine,{sourceRef:process.env.WALLETCONNECT_LINKED_BEFORE==='access'?'40af50bac2d0047500185205c0a50cea3744677c':undefined});await r.link();
  const restoring=r.holdApi('/api/apps/wallet-walletconnect/storage','GET');await r.reopen();await restoring.entered;await r.capture('linked-restoring');
  assert.equal(await r.frame.locator('[data-action=connect],[data-action=start-over]').count(),0,'restoration cannot offer a fresh connection before the saved session is known');
  restoring.release();await r.state('linked');await r.capture('linked-restored');
 });
 test(`a failed initial connection read offers a working retry in ${engine}`,{timeout:60000},async t=>{
  const r=await linkedWindow(t,engine,{sourceRef:process.env.WALLETCONNECT_LINKED_BEFORE==='access'?'40af50bac2d0047500185205c0a50cea3744677c':undefined});await r.link();
  await r.page.route('**/internet',route=>route.fulfill({status:503,body:'Unavailable'}));await r.reopen();await r.state('home-read-unavailable');await r.capture('linked-connection-read-failed');
  assert.equal(await r.frame.locator('[data-action=connect],[data-action=start-over]').count(),0);
  await r.page.unroute('**/internet');await r.click('refresh-status');await r.state('linked');
 });
 test(`an empty phone account list recovers by choosing an account without replacing the connection in ${engine}`,{timeout:60000},async t=>{
  const r=await linkedWindow(t,engine,{sourceRef:process.env.WALLETCONNECT_LINKED_BEFORE==='access'?'40af50bac2d0047500185205c0a50cea3744677c':undefined});await r.link();
  await r.peer.emptyAccounts();await r.state('account-unavailable-unknown');await r.capture('linked-account-not-shown');
  assert.match(await r.frame.locator('main').innerText(),/Choose an account in your wallet, then return here/);
  await r.peer.changeAccount(0);await r.state('linked');assert.equal(r.fixture.state.verified,1,'choosing the linked account restores it without a new connection or signature');await r.capture('linked-account-shown-again');
 });
 test(`disconnecting gives an instruction owned by the connector frame in ${engine}`,{timeout:60000},async t=>{
  const r=await linkedWindow(t,engine,{sourceRef:process.env.WALLETCONNECT_LINKED_BEFORE==='access'?'40af50bac2d0047500185205c0a50cea3744677c':undefined});await r.link();
  const clearing=r.holdApi('/api/apps/wallet-walletconnect/storage','DELETE');await r.click('disconnect');await clearing.entered;await r.state('disconnecting');await r.capture('linked-disconnecting');
  const text=await r.frame.locator('main').innerText();assert.match(text,/Keep this window open until disconnecting finishes/);assert.doesNotMatch(text,/after you close|Close this window/);
  clearing.release();await r.state('disconnected');
 });
 test(`a stopped account confirmation keeps the phone wallet name in ${engine}`,{timeout:60000},async t=>{
  const r=await linkedWindow(t,engine,{sourceRef:process.env.WALLETCONNECT_LINKED_BEFORE==='access'?'40af50bac2d0047500185205c0a50cea3744677c':undefined});
  await r.link();await r.peer.changeAccount();await r.state('account-changed');r.peer.choose({request:'silent'});
  await r.click('send-message');await r.state('link-wait');await r.click('stop-waiting');await r.state('link-cancelled');await r.capture('linked-confirmation-stopped');
  const text=(await r.frame.locator('main').innerText()).replace(/\s+/g,' ');
  assert.match(text,/The request may still be waiting in Trust Wallet/);assert.doesNotMatch(text,/waiting in WalletConnect/);
 });
 test(`a wallet-removed screen states the cause once in ${engine}`,{timeout:60000},async t=>{
  const r=await linkedWindow(t,engine,{sourceRef:process.env.WALLETCONNECT_LINKED_BEFORE==='access'?'40af50bac2d0047500185205c0a50cea3744677c':undefined});
  await r.link();await r.peer.deleteConnection();await r.state('wallet-removed');await r.capture('linked-wallet-removed');
  const text=await r.frame.locator('main').innerText();assert.equal(text.match(/Your wallet removed this connection\./g)?.length,1);
 });
 test(`turned-off access can be requested again without a navigation loop in ${engine}`,{timeout:60000},async t=>{
  const r=await linkedWindow(t,engine,{sourceRef:process.env.WALLETCONNECT_LINKED_BEFORE==='access'?'40af50bac2d0047500185205c0a50cea3744677c':undefined});
  await r.link();await r.idle();r.fixture.setPermission('revoked');await r.refresh();await r.state('internet-refused');await r.capture('linked-access-turned-off');
  assert.equal(await r.frame.locator('[data-action=inbox],[data-action=back-to-connection]').count(),0,'a decided request cannot be answered again in Inbox');
  assert.equal(await r.wallet.locator('#wallet-account-state').innerText(),'1 account','turning off access keeps the linked Wallet account');
  await r.click('connect');await r.state('internet-pending');await r.capture('linked-access-requested-again');
  assert.equal(r.fixture.state.permission,'requested');assert.equal(await r.frame.locator('[data-action=inbox]').count(),1);
  const clearing=r.holdApi('/api/apps/wallet-walletconnect/storage','DELETE');await r.click('cancel');await clearing.entered;await r.state('disconnecting');
  assert.equal(await r.frame.locator('button').count(),0,'cleanup owns the transition before recovery actions appear');await r.capture('linked-access-cancelling');
  clearing.release();await r.state('internet-off');await r.frame.locator('[data-action=connect]').waitFor();await r.capture('linked-access-request-without-wait');
  assert.equal(await r.frame.locator('[data-action=connect]').count(),1,'a waiting access request can resume connection without a Back detour');
  await r.click('connect');await r.state('internet-pending');
 });
 test(`access-ready window offers the useful connection step in ${engine}`,{timeout:60000},async t=>{
  const r=await linkedWindow(t,engine,{sourceRef});await r.capture('access-ready');
  assert.equal(await r.frame.locator('[data-action=inbox]').count(),0);
  assert.equal(await r.frame.getByRole('button',{name:'Connect wallet',exact:true}).count(),1);
 });
 test(`expired linked window gives one clear close instruction in ${engine}`,{timeout:60000},async t=>{
  const r=await linkedWindow(t,engine,{sourceRef});await r.link();
  await r.idle();
  r.fixture.state.expiredLaunch=true;await r.refresh();await r.state('window-expired');await r.capture('linked-window-expired');
  const text=(await r.frame.locator('main').innerText()).replace(/\s+/g,' ');
  assert.equal(text.match(/Close this window/g)?.length,1,'Home close advice replaces the old instruction');
  assert.match(text,/Close this window with Home['’]s window controls, then choose WalletConnect in Wallet/);
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
