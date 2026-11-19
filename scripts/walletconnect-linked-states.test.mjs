import test from 'node:test';
import assert from 'node:assert/strict';
import {linkedWindow} from './lib/walletconnect-linked-window-fixture.mjs';
for(const engine of ['chromium','webkit']) {
 test(`linked window has true copy and useful controls in ${engine}`,{timeout:60000},async t=>{
  const r=await linkedWindow(t,engine);await r.link();await r.capture('just-linked');
  assert.doesNotMatch(await r.frame.locator('main').innerText(),/review this request|Back to connection|Manage in Inbox/i);
  assert.equal(await r.frame.locator('[data-action=connect]').count(),0);
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
 });
 test(`open Wallet receives the new linked account in ${engine}`,{timeout:60000},async t=>{
  const r=await linkedWindow(t,engine);await r.wallet.locator('#wallet-account-state').filter({hasText:'0 accounts'}).waitFor();await r.link();
  await r.wallet.locator('#wallet-account-state').filter({hasText:'1 account'}).waitFor({timeout:4000});
  await r.capture('wallet-live-account');
 });
 test(`Wallet add control explains and adds another phone account in ${engine}`,{timeout:60000},async t=>{
  const r=await linkedWindow(t,engine);await r.link();
  // Opening Wallet again currently supplies the refresh that the link omitted.
  await r.wallet.locator('body').evaluate(()=>window.dispatchEvent(new MessageEvent('message',{origin:'null',source:window.parent,data:{type:'elastos:wallet-refresh'}})));
  await r.wallet.locator('#wallet-account-state').filter({hasText:'1 account'}).waitFor();
  await r.settle();await r.wallet.locator('[data-wallet-open-method="wallet-walletconnect"]').click();
  // The host opens the connector's existing saved session, as the real Home does.
  const connector=r.page.frames().find(f=>f.url().includes('/apps/wallet-walletconnect/'));
  await connector.locator('[data-state=linked]').waitFor();
  if(await connector.locator('[data-action=add-account]').count())await connector.locator('[data-action=add-account]').click();
  assert.match(await connector.locator('main').innerText(),/select another account in Trust Wallet/i,'the add path names the phone step before ending anything');
  await r.peer.changeAccount();await connector.locator('[data-state=account-changed]').waitFor();
  await connector.locator('[data-action=send-message]').click();await connector.locator('[data-state=linked]').waitFor();
  await r.wallet.locator('#wallet-account-state').filter({hasText:'2 accounts'}).waitFor({timeout:4000});
  assert.equal(new Set(r.fixture.state.accounts.map(a=>a.address.toLowerCase())).size,2);
 });
}
