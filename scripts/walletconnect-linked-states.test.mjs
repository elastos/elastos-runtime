import {windowTestOptions} from './lib/walletconnect-window-resources.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import {once} from 'node:events';
import {scriptedPhoneWallet} from './lib/walletconnect-phone-wallet.mjs';
import {linkedWindow as fixtureWindow} from './lib/walletconnect-linked-window-fixture.mjs';
const linkedWindow=(t,engine,options={})=>fixtureWindow(t,engine,{...options,sourceRef:process.env.WALLETCONNECT_LINKED_BEFORE==='original'?'0db7eb247c8d89f367d5458acb03339605cc216e':process.env.WALLETCONNECT_LINKED_BEFORE==='1'?'1c2dcb195f5ee294366627cd7dc7d2d2d21ad1f0':process.env.WALLETCONNECT_LINKED_BEFORE==='copy'?'adf517637d41dfa8a42849e97f494e8b05eea708':undefined});
for(const engine of ['chromium','webkit']) {
 test(`linked window has true copy and useful controls in ${engine}`,windowTestOptions(engine,60000),async t=>{
  const r=await linkedWindow(t,engine);await r.link();await r.capture('just-linked');
  assert.match(await r.frame.locator('main').innerText(),/Close this window with Home['’]s window controls/);
  assert.doesNotMatch(await r.frame.locator('main').innerText(),/review this request|Back to connection|Manage in Inbox/i);
  assert.equal(await r.frame.locator('[data-action=connect]').count(),0);
  assert.equal(await r.frame.locator('button.el-button-primary').count(),0,'completed connection has no highlighted action');
  await r.click('copy-address');await r.frame.getByText('Address copied.',{exact:true}).waitFor();assert.equal(await r.page.evaluate(()=>window.copied),r.peer.address);await r.capture('address-copied');
  await r.reopen();await r.state('linked');await r.capture('linked-reopened');
  assert.doesNotMatch(await r.frame.locator('main').innerText(),/review this request|Back to connection|Manage in Inbox/i);
  assert.deepEqual(await r.frame.locator('button').evaluateAll(nodes=>nodes.map(node=>node.dataset.action).sort()),['add-account','copy-address','disconnect']);
  await r.click('add-account');await r.state('add-account');await r.click('back-to-connection');await r.state('linked');
  await r.click('disconnect');await r.state('disconnected');await r.capture('all-linked-actions-walked');
  assert.equal(await r.wallet.locator('#wallet-account-state').innerText(),'1 account','walking every linked-window action retains the account in Wallet');
 });
 test(`linked window cannot loop to a highlighted reconnect in ${engine}`,windowTestOptions(engine,60000),async t=>{
  const r=await linkedWindow(t,engine);await r.link();
  if(await r.frame.locator('[data-action=back-to-connection]').count())await r.click('back-to-connection');
  await r.capture('connection-after-navigation');
  assert.equal(await r.frame.locator('[data-action=connect]').count(),0,'a linked connection never offers a fresh connection as its next step');
  assert.equal(await r.frame.locator('[data-action=back-to-connection]').count(),0,'connection overview has no return to itself');
 });
 test(`two-network approval events preserve the linked selection in ${engine}`,windowTestOptions(engine,60000),async t=>{
  const r=await linkedWindow(t,engine);await r.link();assert.equal(r.fixture.state.accounts.length,1);
  await r.peer.approvalEvents();await r.refresh();await r.state('linked');await r.capture('two-networks-unchanged');
  assert.doesNotMatch(await r.frame.locator('main').innerText(),/now shows|different account|different network/);
  assert.equal(r.fixture.state.verified,1);
  await r.peer.changeChain('eip155:8453');await r.state('saved-unlinked');await r.capture('network-changed');
  assert.match(await r.frame.locator('main').innerText(),/different network/);
  await r.peer.changeChain('eip155:1');await r.state('linked');await r.capture('original-network-returned');
  assert.doesNotMatch(await r.frame.locator('main').innerText(),/now shows|different account|different network/,'returning to the linked selection clears the old change notice');
  await r.peer.changeChain('eip155:8453');await r.state('saved-unlinked');await r.click('finish');await r.state('linked');
  assert.equal(r.fixture.state.accounts.length,2,'both network proofs are stored');
  await r.wallet.locator('#wallet-account-state').filter({hasText:'1 account'}).waitFor();assert.equal(await r.wallet.locator('#wallet-accounts .wallet-account').count(),1);await r.capture('same-address-on-both-networks');
 });
 test(`open Wallet receives the new linked account in ${engine}`,windowTestOptions(engine,60000),async t=>{
  const r=await linkedWindow(t,engine);await r.wallet.locator('#wallet-account-state').filter({hasText:'0 accounts'}).waitFor();await r.link();
  await r.wallet.locator('#wallet-account-state').filter({hasText:'1 account'}).waitFor({timeout:4000});
  await r.capture('wallet-live-account');
 });
 test(`Wallet refresh after linking follows an older in-flight read in ${engine}`,windowTestOptions(engine,60000),async t=>{
  const r=await linkedWindow(t,engine,{holdWalletRead:true});await r.waitWalletRead();await r.link();
  await r.page.waitForFunction(()=>window.events.some(e=>e.type==='home:refresh-summary'));
  r.releaseWalletRead();
  await r.wallet.locator('#wallet-account-state').filter({hasText:'1 account'}).waitFor({timeout:4000});await r.capture('wallet-refresh-after-older-read');
 });
 test(`Wallet add control explains and adds another phone account in ${engine}`,windowTestOptions(engine,60000),async t=>{
  const r=await linkedWindow(t,engine);await r.link();
  if(process.env.WALLETCONNECT_LINKED_BEFORE==='original')await r.reopenWallet();
  await r.wallet.locator('#wallet-account-state').filter({hasText:'1 account'}).waitFor();
  await r.openFromWallet();const connector=r.frame;
  if(await connector.locator('[data-action=add-account]').count())await connector.locator('[data-action=add-account]').click();
  await r.capture('same-phone-add-instructions');
  assert.match((await connector.locator('main').innerText()).replace(/\s+/g,' '),/choose another account in Trust Wallet/i,'the add path names the phone step before ending anything');
  await r.peer.changeAccount();await connector.locator('[data-state=account-changed]').waitFor();await r.capture('account-changed');
  assert.equal(await connector.locator('.connection-current-selection').count(),0,'the account card already shows the selected account');
  assert.equal(await connector.getByRole('button',{name:'Replace connection',exact:true}).count(),1);
  assert.equal(await connector.locator('[data-action=start-over].el-button-primary').count(),0);
  const challenge=r.holdApi('/api/auth/evm/challenge'),verify=r.holdApi('/api/auth/evm/verify'),prompt=once(r.peer.events,'request');r.peer.choose({request:'silent'});
  await connector.locator('[data-action=send-message]').click();await challenge.entered;await r.state('preparing-connection');await r.capture('preparing-connection');challenge.release();
  await r.state('link-wait');await r.capture('link-wait');await prompt;await r.peer.answer('sign');await verify.entered;await r.state('checking-response');await r.capture('checking-response');verify.release();await r.state('linked');
  await r.wallet.locator('#wallet-account-state').filter({hasText:'2 accounts'}).waitFor({timeout:4000});
  assert.equal(new Set(r.fixture.state.accounts.map(a=>a.address.toLowerCase())).size,2);
  assert.equal(await r.wallet.locator('#wallet-accounts .wallet-account').count(),2,'Wallet displays both account cards');
  await r.capture('two-phone-accounts');
 });
 test(`Wallet adds a second wallet after an explicit disconnect in ${engine}`,windowTestOptions(engine,60000),async t=>{
  const r=await linkedWindow(t,engine);await r.link();
  if(process.env.WALLETCONNECT_LINKED_BEFORE==='original')await r.reopenWallet();
  await r.wallet.locator('#wallet-account-state').filter({hasText:'1 account'}).waitFor();
  await r.openFromWallet();
  await r.click('add-account');await r.state('add-account');await r.capture('add-account');
  assert.doesNotMatch(await r.frame.locator('main').innerText(),/Home['’]s window controls/,'the visible return action is enough on the add instructions');
  assert.match(await r.frame.locator('main').innerText(),/new code replaces this connection/i);
  assert.match(await r.frame.locator('main').innerText(),/Your accounts stay in Wallet/i);
  assert.equal(r.fixture.state.verified,1,'opening the add instructions preserves the first account and session');
  await r.click('back-to-connection');await r.state('linked');await r.click('add-account');await r.state('add-account');
  const clearing=r.holdApi('/api/apps/wallet-walletconnect/storage','DELETE');await r.click('disconnect');await clearing.entered;await r.state('disconnecting');await r.capture('disconnecting');clearing.release();await r.state('disconnected');await r.capture('disconnected');
  assert.doesNotMatch(await r.frame.locator('main').innerText(),/Remove account|funds stay unchanged/,'adding another wallet has no unrelated removal instructions');
  const second=await scriptedPhoneWallet({projectId:'fixture-project',relayUrl:r.fixture.origin.replace('http','ws'),chains:['eip155:1','eip155:8453'],name:'Second phone wallet',emitApprovalEvents:true});t.after(()=>second.stop());
  await r.click('connect');await r.state('qr-shown');await r.capture('second-wallet-qr');await r.click('copy-link');
  await second.pair(await r.page.evaluate(()=>window.copied));await r.state('linked');
  await r.wallet.locator('#wallet-account-state').filter({hasText:'2 accounts'}).waitFor({timeout:4000});await r.capture('two-wallets');
  assert.equal(new Set(r.fixture.state.accounts.map(a=>a.address.toLowerCase())).size,2);
  assert.equal(await r.wallet.locator('#wallet-accounts .wallet-account').count(),2,'Wallet displays both account cards');
 });

}

for(const engine of ['chromium','webkit'])test(`add-account reconnect adds a phone selection that leaves the old session unchanged in ${engine}`,windowTestOptions(engine,60000),async t=>{
 const r=await fixtureWindow(t,engine,{sourceRef:process.env.WALLETCONNECT_ADD_BEFORE==='1'?'5cc6f5b8cd55c0ae3d37bd3a56e57c04315e44a1':undefined});
 await r.page.setViewportSize({width:1440,height:900});await r.link();
 const first=r.peer.address,oldSessions=r.peer.client.session.getAll().map(s=>structuredClone(s.namespaces));
 await r.click('add-account');await r.state('add-account');await r.capture('add-before-code');
 r.peer.selectAccount();
 assert.deepEqual(r.peer.client.session.getAll().map(s=>s.namespaces),oldSessions,'switching in this phone leaves the approved session on the first account');
 const clearing=r.holdApi('/api/apps/wallet-walletconnect/storage','DELETE');await r.click('start-over');await clearing.entered;await r.state('preparing-qr');await r.capture('add-preparing-code');clearing.release();await r.state('qr-shown');await r.capture('add-waiting-for-scan');
 assert.equal(r.fixture.state.accounts.length,1);r.peer.choose({request:'silent'});
 const prompt=once(r.peer.events,'request');await r.pair();await r.state('link-wait');await prompt;await r.capture('add-new-account-signature');
 const verify=r.holdApi('/api/auth/evm/verify');await r.peer.answer('sign');await verify.entered;await r.state('checking-response');await r.capture('add-checking-signature');verify.release();await r.state('linked');
 await r.wallet.locator('#wallet-account-state').filter({hasText:'2 accounts'}).waitFor();
 assert.deepEqual(new Set(r.fixture.state.accounts.map(a=>a.address.toLowerCase())),new Set([first,r.peer.address].map(a=>a.toLowerCase())));
 assert.equal(await r.wallet.locator('#wallet-accounts .wallet-account').count(),2);await r.capture('add-both-accounts');
 assert.equal(r.peer.trace.filter(e=>e.kind==='proposal').length,2,'a fresh proposal offers the selected phone account');
 assert.equal(r.fixture.state.verified,2);
});

for(const engine of ['chromium','webkit']){
 test(`add-account duplicate offers retry without another signature in ${engine}`,windowTestOptions(engine,60000),async t=>{
  const r=await linkedWindow(t,engine);await r.page.setViewportSize({width:1440,height:900});await r.link();
  const first=r.peer.address;await r.click('add-account');await r.click('start-over');await r.state('qr-shown');await r.pair();await r.state('account-already-linked');assert.equal(await r.frame.locator('[data-action=back-to-connection]').count(),1,'one return control');await r.capture('add-already-linked');
  assert.equal(r.fixture.state.verified,1);assert.equal(r.peer.trace.filter(e=>e.kind==='request').length,1,'duplicate offers never request ownership again');
  assert.match(await r.frame.locator('main').innerText(),/This account is already in Wallet/);
  r.peer.selectAccount();await r.click('start-over');await r.state('qr-shown');await r.pair();await r.state('linked');
  await r.wallet.locator('#wallet-account-state').filter({hasText:'2 accounts'}).waitFor();
  assert.ok(r.fixture.state.accounts.some(a=>a.address.toLowerCase()===first.toLowerCase()));
 });
 test(`add-account Back preserves the old connection in ${engine}`,windowTestOptions(engine,60000),async t=>{
  const r=await linkedWindow(t,engine);await r.link();const sessions=r.peer.client.session.getAll().map(s=>s.topic);
  await r.click('add-account');await r.click('back-to-connection');await r.state('linked');
  assert.deepEqual(r.peer.client.session.getAll().map(s=>s.topic),sessions);assert.equal(r.fixture.state.verified,1);
 });
 for(const ending of ['qr-cancelled','qr-expired','connection-declined','link-declined','link-timeout','link-cancelled','link-error'])test(`add-account ${ending} retains the first account and recovers in ${engine}`,windowTestOptions(engine,60000),async t=>{
  const r=await linkedWindow(t,engine);await r.page.setViewportSize({width:1440,height:900});await r.link();const first=r.peer.address;
  // Fire only the actual product/SDK deadline callback, without a wall-clock wait.
  await r.frame.evaluate(()=>{
   const native=window.setTimeout,clear=window.clearTimeout;
   window.setTimeout=(fn,ms,...args)=>{const id=native(fn,ms,...args);if(typeof fn==='function'&&(ms===180000||ms===300000))window[ms===180000?'expireProposal':'expireOwnership']=()=>{clear(id);fn(...args);};return id;};
  });
  await r.click('add-account');r.peer.selectAccount();
  const proposal=ending==='connection-declined'?'reject':ending==='qr-expired'?'silent':'approve';
  const request=ending==='link-declined'?'reject':'silent';r.peer.choose({proposal,request});
  await r.click('start-over');await r.state('qr-shown');
  if(ending==='qr-cancelled')await r.click('cancel');
  else if(ending==='qr-expired'){await r.pair();await r.frame.evaluate(()=>window.expireProposal());}
  else if(ending==='connection-declined')await r.pair();
  else {
   const prompt=once(r.peer.events,'request');await r.pair();await prompt;if(ending!=='link-declined')await r.state('link-wait');
   if(ending==='link-timeout')await r.frame.evaluate(()=>window.expireOwnership());
   else if(ending==='link-cancelled')await r.click('stop-waiting');
   else if(ending==='link-error'){
    await r.page.route('**/api/auth/evm/verify',route=>route.fulfill({status:503,body:'Home unavailable'}));
    await r.peer.answer('sign');
   }
  }
  await r.state('add-'+ending);await r.capture('add-'+ending);
  assert.equal(r.fixture.state.accounts.length,1);assert.equal(r.fixture.state.accounts[0].address.toLowerCase(),first.toLowerCase());
  assert.match(await r.frame.locator('main').innerText(),/Your accounts stay in Wallet/);
  if(['link-cancelled','link-timeout'].includes(ending)){
   assert.equal(await r.frame.locator('button.el-button-primary').getAttribute('data-action'),'start-over','the highlighted recovery gets the new QR code named by the notice');
   assert.match(await r.frame.locator('main').innerText(),/[Gg]et a new QR code/);
  }
  if(['qr-cancelled','qr-expired','connection-declined','link-cancelled'].includes(ending))assert.equal(await r.frame.locator('[data-action=back-to-connection]').count(),0,'a deleted session has no Back to connection');
  if(ending==='link-error')await r.page.unroute('**/api/auth/evm/verify');
  r.peer.choose({proposal:'approve',request:'sign'});await r.click('start-over');await r.state('qr-shown');
  await r.capture('add-retry-'+ending);await r.pair();await r.state('linked');
  await r.wallet.locator('#wallet-account-state').filter({hasText:'2 accounts'}).waitFor();
 });
}

for(const engine of ['chromium','webkit'])test(`add-account recognizes the same address on another network in ${engine}`,windowTestOptions(engine,60000),async t=>{
 const r=await fixtureWindow(t,engine,{sourceRef:process.env.WALLETCONNECT_DUPLICATE_BEFORE==='1'?'b8027d77930ff012de1784687bad4c336717ca67':undefined});
 await r.link();r.peer.choose({chains:['eip155:8453']});
 await r.click('add-account');await r.click('start-over');await r.state('qr-shown');await r.pair();
 await r.state('account-already-linked');
 assert.equal(r.fixture.state.accounts.length,1,'a new network offer keeps the one saved account');
 assert.equal(r.fixture.state.verified,1,'a duplicate address requests no additional network proof in Add account');
 assert.equal(r.peer.trace.filter(e=>e.kind==='request').length,1);
});

for(const engine of ['chromium','webkit']){
 for(const add of [false,true])test(`later approval appears normally after ${add?'add-account':'initial link'} in ${engine}`,windowTestOptions(engine,60000),async t=>{
  const r=await linkedWindow(t,engine);await r.link();
  if(add){await r.click('add-account');r.peer.selectAccount();await r.click('start-over');await r.state('qr-shown');await r.pair();await r.state('linked');}
  r.fixture.state.approvals=[{request_id:'later-message',connector_id:'wallet-walletconnect',capsule_id:'browser',requesting_origin:'https://example.test',reason:'Review the later message',status:'pending',intent:'credential',proof_type:'siwe',address:r.peer.address,chain_namespace:'eip155:1',expires_at:Math.floor(Date.now()/1000)+600}];
  await r.refresh();await r.state('request-waiting');await r.capture(add?'add-later-request':'initial-later-request');
  await r.click('send-request');await r.state('request-done');assert.equal(r.fixture.state.completed,1,'the later approval completes without View requests');
 });
 for(const connector of ['wallet-metamask',undefined])for(const sameNetwork of [true,false])test(`add-account links ${connector||'legacy MetaMask'} address on ${sameNetwork?'the same':'another'} network through the scoped endpoint in ${engine}`,windowTestOptions(engine,60000),async t=>{
  const r=await linkedWindow(t,engine);await r.link();
  const first=r.fixture.state.accounts[0];r.peer.selectAccount();
  const other={...first,address:r.peer.address,account_id:'fixture-metamask-'+r.peer.address,connector_id:connector,wallet_display_name:'MetaMask'};
  r.fixture.state.accounts.push(other);
  const scoped=await fetch(r.fixture.origin+'/api/apps/wallet-walletconnect/wallet/accounts').then(response=>response.json());
  assert.deepEqual(scoped.accounts,[first],'the real connector endpoint hides other methods');
  if(!sameNetwork)r.peer.choose({chains:['eip155:8453']});
  await r.refresh();await r.click('add-account');await r.click('start-over');await r.state('qr-shown');await r.pair();await r.state('linked');
  assert.equal(r.fixture.state.verified,2,'linking requires a fresh ownership proof');
  assert.equal(r.fixture.state.accounts.length,sameNetwork?2:3,'the provider keeps one record per network and address');
  if(sameNetwork)assert.equal(r.fixture.state.accounts.find(a=>a.address===other.address).connector_id,'wallet-walletconnect','the existing network record now uses WalletConnect');
  else assert.ok(r.fixture.state.accounts.some(a=>a.connector_id===connector),'the other network keeps MetaMask');
  await r.wallet.locator('#wallet-account-state').filter({hasText:sameNetwork?'2 accounts':'3 accounts'}).waitFor();
  assert.equal(await r.wallet.locator('#wallet-accounts .wallet-account').count(),sameNetwork?2:3);
  await r.capture('add-method-result-'+(connector||'legacy-metamask')+'-'+(sameNetwork?'same':'other'));
 });
}
