import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {windowFixture,observeWindowErrors} from './lib/walletconnect-phone-window-fixture.mjs';
import {scriptedPhoneWallet} from './lib/walletconnect-phone-wallet.mjs';
import {importProductSmokePlaywright,productSmokeLaunchOptions} from './product-smoke-browser.mjs';
const pause=ms=>new Promise(resolve=>setTimeout(resolve,ms));
async function setup(t,engine,mutation){
 if(process.env.WALLETCONNECT_FIX1_BREAK==='B6')mutation={file:'walletconnect-client.mjs',from:"const {connectWithView} = await import('./walletconnect-pairing.mjs');\n        signal?.throwIfAborted();",to:"const {connectWithView} = await import('./walletconnect-pairing.mjs');"};
 const fixture=await windowFixture(),peer=await scriptedPhoneWallet({projectId:'fixture-project',relayUrl:fixture.origin.replace('http','ws')});
 const engines=await importProductSmokePlaywright(),browser=await engines[engine].launch({headless:true,...(engine==='chromium'?productSmokeLaunchOptions():{})});
 const page=await browser.newPage({viewport:{width:480,height:560}}),{errors}=observeWindowErrors(page,fixture);
 await page.route('**/*',route=>new URL(route.request().url()).origin===fixture.origin?route.continue():route.abort());
 if(mutation)await page.route(`**/${mutation.file}*`,async route=>{const source=await readFile(new URL('../capsules/wallet-walletconnect/browser/'+mutation.file,import.meta.url),'utf8');assert.ok(source.includes(mutation.from));await route.fulfill({contentType:'text/javascript',body:source.replace(mutation.from,mutation.to)});});
 t.after(async()=>{await peer.stop();await browser.close();await fixture.stop();assert.deepEqual(errors,[]);});
 const r={fixture,peer,page,frame:null};
 r.reopen=async()=>{await page.goto(fixture.origin);r.frame=page.frames().find(f=>f.url().includes('/apps/wallet-walletconnect/'));await r.frame.locator('main').waitFor();};
 r.state=name=>r.frame.locator(`main[data-state="${name}"]`).waitFor({timeout:20000});
 r.click=name=>r.frame.getByRole('button',{name,exact:true}).click();
 r.refresh=()=>r.frame.evaluate(()=>window.dispatchEvent(new Event('focus')));
 r.link=async()=>{await r.state('internet-ready');await r.click('Connect wallet');await r.state('qr-shown');await r.click('Copy link');await r.frame.getByText('Link copied.',{exact:true}).waitFor();await peer.pair(await page.evaluate(()=>window.copied));await r.state('linked');};
 r.request=(id,extra={})=>fixture.state.approvals.push({request_id:id,status:'pending',address:peer.address,chain_namespace:'eip155:8453',intent:'browser_personal_sign',proof_type:'siwe',connector_id:'wallet-walletconnect',capsule_id:'browser',requesting_origin:'https://example.test',reason:'Fix 1 '+id,expires_at:Math.floor(Date.now()/1000)+900,...extra});
 r.choose=async id=>{const read=page.waitForResponse(response=>response.url().endsWith('/wallet/approvals'));await r.refresh();await (await read).finished();await r.click('View requests');await r.frame.locator(`[data-focus-key="select-request:${id}"]`).click();};
 await r.reopen();return r;
}
for(const engine of ['chromium','webkit']){
 test(`F1 blocked-first and phone-declined transaction keep connection controls reachable in ${engine}`,{timeout:90000},async t=>{
  const r=await setup(t,engine);await r.link();
  r.request('typed',{intent:'browser_typed_data_sign'});await r.refresh();await r.state('linked');await r.choose('typed');await r.state('request-unsendable');
  await r.click('Back to connection');await r.state('linked');await r.click('Back to connection');await r.state('internet-ready');
  await r.click('Manage in Inbox');assert.equal(await r.page.evaluate(()=>window.events.some(event=>event.type==='home:open-target'&&event.target==='inbox')),true,'Manage uses the existing Inbox message');assert.equal(await r.frame.getByRole('button',{name:'Connect wallet',exact:true}).isVisible(),true);
  await r.click('Back to connection');await r.state('linked');assert.equal(await r.frame.getByRole('button',{name:'Disconnect',exact:true}).isVisible(),true);
  r.request('transaction',{intent:'transaction_intent'});await r.choose('transaction');await r.state('request-multiple');assert.equal(await r.frame.locator('main').getAttribute('data-request-id'),'transaction');assert.match(await r.frame.locator('main').innerText(),/Send transaction/);r.peer.choose({request:'reject'});await r.frame.getByRole('button',{name:/^Send to /}).click();await r.state('transaction-declined');
  assert.equal(r.fixture.state.approvals.find(row=>row.request_id==='transaction').status,'approved');
  await r.click('Back to connection');await r.state('linked');await r.choose('transaction');await r.state('transaction-declined');
  await r.reopen();await r.state('linked');assert.doesNotMatch(await r.frame.locator('main').innerText(),/Transaction result unknown/,'approved recovery never owns the default screen');
  await r.click('Disconnect');await r.state('disconnected');await r.click('Connect wallet');await r.state('qr-shown');await r.click('Cancel');
 });
 for(const ending of ['refused','failed'])test(`next waiting request is reachable after ${ending} through visible controls in ${engine}`,{timeout:60000},async t=>{
  const r=await setup(t,engine);await r.link();r.request('first');r.request('second');await r.refresh();await r.state('request-multiple');
  r.peer.choose({request:ending==='refused'?'reject':'sign'});r.fixture.state.invalidSignatureHandoff=ending==='failed';
  await r.frame.getByRole('button',{name:/^Send to /}).click();await r.state(ending==='refused'?'request-declined':'request-unavailable');
  assert.equal(r.fixture.state.completed,0);r.fixture.state.invalidSignatureHandoff=false;r.peer.choose({request:'sign'});
  await r.choose('second');await r.frame.getByRole('button',{name:/^Send to /}).click();await r.state('request-done');assert.equal(r.fixture.state.completed,1);assert.equal(r.fixture.state.approvals.find(row=>row.request_id==='second').status,'completed');
 });
 test(`linked account and saved unfinished connection name the real wallet in ${engine}`,{timeout:60000},async t=>{
  const r=await setup(t,engine);await r.link();assert.match(await r.frame.locator('.connection-account').innerText(),/Scripted phone wallet/);
  const extra='0x'+'56'.repeat(20);r.fixture.state.accounts.push({address:extra,chain_namespace:'eip155:1',connector_id:'wallet-walletconnect',proof_type:'siwe'});await r.refresh();await r.state('linked-multiple');assert.equal(await r.frame.locator('.connection-account code').count(),2);
  r.fixture.state.accounts=[];await r.reopen();await r.state('saved-unlinked');assert.match(await r.frame.locator('main').innerText(),/Scripted phone wallet/);assert.equal(await r.frame.locator('.connection-qr').count(),0);
 });
 test(`account change during a signature keeps the consumed request and outside-prompt notice in ${engine}`,{timeout:60000},async t=>{
  const r=await setup(t,engine);await r.link();const requestedAccount=r.peer.address;r.request('change');await r.refresh();await r.state('request-waiting');r.peer.choose({request:'silent'});await r.frame.getByRole('button',{name:/^Send to /}).click();await r.state('request-phone');
  await r.peer.changeAccount(1,true);await r.state('request-busy');assert.notEqual(r.peer.address.toLowerCase(),requestedAccount.toLowerCase());assert.match(await r.frame.locator('.connection-request-account').innerText(),new RegExp(requestedAccount.slice(0,6),'i'),'the consumed request still names its original signer');assert.match(await r.frame.locator('main').innerText(),/request may still be waiting.*Reject or close it there/s);assert.match(await r.frame.locator('.connection-current-selection').innerText(),new RegExp(r.peer.address.slice(0,6),'i'));assert.equal(r.fixture.state.completed,0);assert.equal(await r.frame.locator('[data-action=send-request]').count(),0);
 });
 test(`P9 selected unconfirmed hash survives status polls in ${engine}`,{timeout:60000},async t=>{
  const r=await setup(t,engine);await r.link();r.request('hash',{intent:'transaction_intent'});await r.refresh();await r.state('transaction-waiting');r.fixture.state.completeFails=true;await r.frame.getByRole('button',{name:/^Send to /}).click();await r.state('transaction-wallet-error');
  const before=await r.frame.locator('.connection-hash').evaluate(node=>{const range=document.createRange();range.selectNodeContents(node);getSelection().removeAllRanges();getSelection().addRange(range);window.selectedHashNode=node;return getSelection().toString();});assert.match(before,/^0x[0-9a-f]{64}$/i);
  await pause(6500);assert.equal(await r.frame.evaluate(()=>getSelection().toString()),before);assert.equal(await r.frame.evaluate(()=>document.contains(window.selectedHashNode)),true);
 });
 test(`B6 Stop during pairing import discards the old adapter before fresh Connect in ${engine}`,{timeout:60000},async t=>{
  const r=await setup(t,engine);let entered,release;const held=new Promise(resolve=>release=resolve),loading=new Promise(resolve=>entered=resolve);let imports=0;
  await r.page.route('**/vendor/reown-appkit.js?*',async route=>{
   imports++;const response=await route.fetch();const source=await response.text();const exported=source.match(/([\w$]+) as restoreWalletConnectEvm/);assert.ok(exported,'observe the real pinned SDK export');
   const body=source.replace(exported[0],exported[1]+' as originalRestoreWalletConnectEvm')+`\nexport function restoreWalletConnectEvm(...args){window.adapterRestoreCalls=(window.adapterRestoreCalls||0)+1;return ${exported[1]}(...args);}`;
   await route.fulfill({response,body});
  });
  await r.page.route('**/walletconnect-pairing.mjs',async route=>{entered();await held;await route.continue();});t.after(()=>release());
  await r.state('internet-ready');await r.click('Connect wallet');await loading;await r.click('Cancel');await r.state('qr-cancelled');release();await r.page.waitForLoadState('networkidle');await pause(100);assert.equal(await r.frame.evaluate(()=>window.adapterRestoreCalls||0),0,'a stopped import cannot enter real adapter restore');
  await r.click('Connect wallet');await r.state('qr-shown');assert.equal(imports,2,'fresh Connect imports a fresh adapter after the stopped import');await r.click('Cancel');
 });
}

for(const engine of ['chromium','webkit'])test(`a new review replaces a saved Connect only after visible Cancel in ${engine}`,{timeout:60000},async t=>{
 const r=await setup(t,engine);await r.link();await r.click('Disconnect');await r.state('disconnected');r.fixture.setPermission('off');await r.refresh();await r.state('nothing-saved');
 await r.click('Connect wallet');await r.state('internet-pending');r.request('new-review');await r.refresh();await r.state('request-internet-pending');await r.click('Cancel');await r.state('request-internet-off');
 const verified=r.fixture.state.verified;r.fixture.setPermission('granted');await r.refresh();await r.state('request-waiting');assert.equal(r.fixture.state.verified,verified,'Allow cannot resume the cancelled saved Connect');
 await r.frame.getByRole('button',{name:/^Send to /}).click();await r.state('qr-shown');await r.click('Copy link');await r.frame.getByText('Link copied.',{exact:true}).waitFor();await r.peer.pair(await r.page.evaluate(()=>window.copied));await r.state('request-done');assert.equal(r.fixture.state.completed,1);assert.equal(r.fixture.state.verified,verified,'the explicit request resumes Send rather than the old account proof');
});
