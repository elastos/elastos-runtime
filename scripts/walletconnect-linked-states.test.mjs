import test from 'node:test';
import assert from 'node:assert/strict';
import {scriptedPhoneWallet} from './lib/walletconnect-phone-wallet.mjs';
import {linkedWindow} from './lib/walletconnect-linked-window-fixture.mjs';
for(const engine of ['chromium','webkit']) {
 test(`linked window has true copy and useful controls in ${engine}`,{timeout:60000},async t=>{
  const r=await linkedWindow(t,engine);await r.link();await r.capture('just-linked');
  assert.doesNotMatch(await r.frame.locator('main').innerText(),/review this request|Back to connection|Manage in Inbox/i);
  assert.equal(await r.frame.locator('[data-action=connect]').count(),0);
  assert.equal(await r.frame.locator('button.el-button-primary').count(),0,'completed connection has no highlighted action');
  await r.click('copy-address');await r.frame.getByText('Address copied.',{exact:true}).waitFor();assert.equal(await r.page.evaluate(()=>window.copied),r.peer.address);await r.capture('address-copied');
  await r.reopen();await r.state('linked');await r.capture('linked-reopened');
  assert.doesNotMatch(await r.frame.locator('main').innerText(),/review this request|Back to connection|Manage in Inbox/i);
 });
 test(`linked window cannot loop to a highlighted reconnect in ${engine}`,{timeout:60000},async t=>{
  const r=await linkedWindow(t,engine);await r.link();
  if(await r.frame.locator('[data-action=back-to-connection]').count())await r.click('back-to-connection');
  await r.capture('connection-after-navigation');
  assert.equal(await r.frame.locator('[data-action=connect]').count(),0,'a linked connection never offers a fresh connection as its next step');
  assert.equal(await r.frame.locator('[data-action=back-to-connection]').count(),0,'connection overview has no return to itself');
 });
 test(`two-network approval events preserve the linked selection in ${engine}`,{timeout:60000},async t=>{
  const r=await linkedWindow(t,engine);await r.link();assert.equal(r.fixture.state.accounts.length,1);
  await r.peer.approvalEvents();await r.refresh();await r.state('linked');await r.capture('two-networks-unchanged');
  assert.doesNotMatch(await r.frame.locator('main').innerText(),/Wallet now shows|different account|different network/);
  assert.equal(r.fixture.state.verified,1);
  await r.peer.changeChain('eip155:8453');await r.state('saved-unlinked');await r.capture('network-changed');
  assert.match(await r.frame.locator('main').innerText(),/different network/);
  await r.peer.changeChain('eip155:1');await r.state('linked');await r.capture('original-network-returned');
  assert.doesNotMatch(await r.frame.locator('main').innerText(),/Wallet now shows|different account|different network/,'returning to the linked selection clears the old change notice');
 });
 test(`open Wallet receives the new linked account in ${engine}`,{timeout:60000},async t=>{
  const r=await linkedWindow(t,engine);await r.wallet.locator('#wallet-account-state').filter({hasText:'0 accounts'}).waitFor();await r.link();
  await r.wallet.locator('#wallet-account-state').filter({hasText:'1 account'}).waitFor({timeout:4000});
  await r.capture('wallet-live-account');
 });
 test(`Wallet refresh after linking follows an older in-flight read in ${engine}`,{timeout:60000},async t=>{
  const r=await linkedWindow(t,engine,{holdWalletRead:true});await r.walletReadStarted;await r.link();
  await r.page.waitForFunction(()=>window.events.some(e=>e.type==='home:refresh-summary'));
  r.releaseWalletRead();
  await r.wallet.locator('#wallet-account-state').filter({hasText:'1 account'}).waitFor({timeout:4000});await r.capture('wallet-refresh-after-older-read');
 });
 test(`Wallet add control explains and adds another phone account in ${engine}`,{timeout:60000},async t=>{
  const r=await linkedWindow(t,engine);await r.link();
  // Opening Wallet again currently supplies the refresh that the link omitted.
  await r.wallet.locator('body').evaluate(()=>window.dispatchEvent(new MessageEvent('message',{origin:'null',source:window.parent,data:{type:'elastos:wallet-refresh'}})));
  await r.wallet.locator('#wallet-account-state').filter({hasText:'1 account'}).waitFor();
  await r.openFromWallet();const connector=r.frame;
  if(await connector.locator('[data-action=add-account]').count())await connector.locator('[data-action=add-account]').click();
  await r.capture('same-phone-add-instructions');
  assert.match(await connector.locator('main').innerText(),/select another account in Trust Wallet/i,'the add path names the phone step before ending anything');
  await r.peer.changeAccount();await connector.locator('[data-state=account-changed]').waitFor();await r.capture('account-changed');
  await connector.locator('[data-action=send-message]').click();await connector.locator('[data-state=linked]').waitFor();
  await r.wallet.locator('#wallet-account-state').filter({hasText:'2 accounts'}).waitFor({timeout:4000});
  assert.equal(new Set(r.fixture.state.accounts.map(a=>a.address.toLowerCase())).size,2);
  await r.capture('two-phone-accounts');
 });
 test(`Wallet adds a second wallet after an explicit disconnect in ${engine}`,{timeout:60000},async t=>{
  const r=await linkedWindow(t,engine);await r.link();
  await r.wallet.locator('body').evaluate(()=>window.dispatchEvent(new MessageEvent('message',{origin:'null',source:window.parent,data:{type:'elastos:wallet-refresh'}})));
  await r.wallet.locator('#wallet-account-state').filter({hasText:'1 account'}).waitFor();
  await r.openFromWallet();
  await r.click('add-account');await r.state('add-account');await r.capture('add-account');
  assert.match(await r.frame.locator('main').innerText(),/disconnect this connection first/i);
  assert.match(await r.frame.locator('main').innerText(),/linked accounts stay in Wallet/i);
  assert.equal(r.fixture.state.verified,1,'opening the add instructions preserves the first account and session');
  await r.click('back-to-connection');await r.state('linked');await r.click('add-account');await r.state('add-account');
  await r.click('disconnect');await r.state('disconnected');await r.capture('disconnected');
  const second=await scriptedPhoneWallet({projectId:'fixture-project',relayUrl:r.fixture.origin.replace('http','ws'),chains:['eip155:1','eip155:8453'],name:'Second phone wallet',emitApprovalEvents:true});t.after(()=>second.stop());
  await r.click('connect');await r.state('qr-shown');await r.capture('second-wallet-qr');await r.click('copy-link');
  await second.pair(await r.page.evaluate(()=>window.copied));await r.state('linked');
  await r.wallet.locator('#wallet-account-state').filter({hasText:'2 accounts'}).waitFor({timeout:4000});await r.capture('two-wallets');
  assert.equal(new Set(r.fixture.state.accounts.map(a=>a.address.toLowerCase())).size,2);
 });

}
