import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {observeWindowErrors,walletWindowLifetime} from './lib/walletconnect-phone-window-fixture.mjs';
import {windowResources,windowTestOptions} from './lib/walletconnect-window-resources.mjs';
const pause=ms=>new Promise(resolve=>setTimeout(resolve,ms));
async function setup(t,engine,mutation){
 if(process.env.WALLETCONNECT_FIX1_BREAK==='B6')mutation={file:'walletconnect-client.mjs',from:"const {connectWithView} = await import('./walletconnect-pairing.mjs');\n        signal?.throwIfAborted();",to:"const {connectWithView} = await import('./walletconnect-pairing.mjs');"};
 if(process.env.WALLETCONNECT_FIX1_BREAK==='P7')mutation={file:'wallet-walletconnect.js',from:"if (detail?.connection) connectionState={...connectionState,...detail.connection};",to:'void detail;'};
 if(process.env.WALLETCONNECT_FIX1_BREAK==='C1')mutation={file:'wallet-walletconnect.js',from:"if(epoch!==actionEpoch)throw new Error('Wallet connection cancelled.');",to:'void epoch;'};
 const {fixture,peer,browser,defer}=await windowResources(t,engine);
 const page=await browser.newPage({viewport:{width:480,height:560}}),{errors}=observeWindowErrors(page,fixture);
 await page.route('**/*',route=>new URL(route.request().url()).origin===fixture.origin?route.continue():route.abort());
 if(mutation)await page.route(`**/${mutation.file}*`,async route=>{const source=await readFile(new URL('../capsules/wallet-walletconnect/browser/'+mutation.file,import.meta.url),'utf8');assert.ok(source.includes(mutation.from));await route.fulfill({contentType:'text/javascript',body:source.replace(mutation.from,mutation.to)});});
 const settle=await walletWindowLifetime(page,fixture);
 defer(()=>settle(r.frame));
 t.after(()=>assert.deepEqual(errors,[]));
 const r={fixture,peer,page,frame:null};
 r.reopen=async()=>{await settle(r.frame);await page.goto(fixture.origin);r.frame=page.frames().find(f=>f.url().includes('/apps/wallet-walletconnect/'));await r.frame.locator('main').waitFor();};
 r.state=name=>r.frame.locator(`main[data-state="${name}"]`).waitFor({timeout:20000});
 r.click=name=>r.frame.getByRole('button',{name,exact:true}).click();
 r.refresh=()=>r.frame.evaluate(()=>window.dispatchEvent(new Event('focus')));
 r.link=async()=>{await r.state('internet-ready');await r.click('Connect wallet');await r.state('qr-shown');await r.click('Copy link');await r.frame.getByText('Link copied.',{exact:true}).waitFor();await peer.pair(await page.evaluate(()=>window.copied));await r.state('linked');};
 r.request=(id,extra={})=>fixture.state.approvals.push({request_id:id,status:'pending',address:peer.address,chain_namespace:'eip155:8453',intent:'browser_personal_sign',proof_type:'siwe',connector_id:'wallet-walletconnect',capsule_id:'browser',requesting_origin:'https://example.test',reason:'Fix 1 '+id,expires_at:Math.floor(Date.now()/1000)+900,...extra});
 r.choose=async id=>{const read=page.waitForResponse(response=>response.url().endsWith('/wallet/approvals'));await r.refresh();await (await read).finished();await r.click('View requests');await r.frame.locator(`[data-focus-key="select-request:${id}"]`).click();};
 await r.reopen();return r;
}
for(const engine of ['chromium','webkit']){
 test(`F1 blocked-first and phone-declined transaction keep connection controls reachable in ${engine}`,windowTestOptions(engine,90000),async t=>{
  const r=await setup(t,engine);await r.link();
  r.request('typed',{intent:'browser_typed_data_sign'});await r.refresh();await r.state('linked');await r.choose('typed');await r.state('request-unsendable');
  await r.click('Back to connection');await r.state('linked');assert.equal(await r.frame.getByRole('button',{name:'Back to connection',exact:true}).count(),0);
  assert.equal(await r.frame.getByRole('button',{name:'Manage in Inbox',exact:true}).count(),0);await r.click('Add account');await r.state('add-account');
  await r.click('Back to connection');await r.state('linked');assert.equal(await r.frame.getByRole('button',{name:'Disconnect',exact:true}).isVisible(),true);
  r.request('transaction',{intent:'transaction_intent'});await r.choose('transaction');await r.state('request-multiple');assert.equal(await r.frame.locator('main').getAttribute('data-request-id'),'transaction');assert.match(await r.frame.locator('main').innerText(),/Send transaction/);r.peer.choose({request:'reject'});await r.frame.getByRole('button',{name:/^Send to /}).click();await r.state('transaction-declined');
  assert.equal(r.fixture.state.approvals.find(row=>row.request_id==='transaction').status,'approved');
  await r.click('Back to connection');await r.state('linked');await r.choose('transaction');await r.state('transaction-declined');
  await r.reopen();await r.state('linked');assert.doesNotMatch(await r.frame.locator('main').innerText(),/Home could not confirm the transaction result/,'approved recovery never owns the default screen');
  await r.click('Disconnect');await r.state('disconnected');await r.click('Connect wallet');await r.state('qr-shown');await r.click('Cancel');
 });
 for(const ending of ['refused','failed'])test(`next waiting request is reachable after ${ending} through visible controls in ${engine}`,windowTestOptions(engine,60000),async t=>{
  const r=await setup(t,engine);await r.link();r.request('first');r.request('second');await r.refresh();await r.state('request-multiple');
  r.peer.choose({request:ending==='refused'?'reject':'sign'});r.fixture.state.invalidSignatureHandoff=ending==='failed';
  await r.frame.getByRole('button',{name:/^Send to /}).click();await r.state(ending==='refused'?'request-declined':'request-unavailable');
  assert.equal(r.fixture.state.completed,0);r.fixture.state.invalidSignatureHandoff=false;r.peer.choose({request:'sign'});
  await r.choose('second');await r.frame.getByRole('button',{name:/^Send to /}).click();await r.state('request-done');assert.equal(r.fixture.state.completed,1);assert.equal(r.fixture.state.approvals.find(row=>row.request_id==='second').status,'completed');
 });
 test(`linked account and saved unfinished connection name the real wallet in ${engine}`,windowTestOptions(engine,60000),async t=>{
  const r=await setup(t,engine);await r.state('internet-ready');assert.equal(await r.frame.locator('main > header.connection-heading').count(),0,'first screen has no visible heading');await r.link();assert.equal(await r.frame.locator('main > header.connection-heading').count(),0,'linked screen has no visible heading');assert.equal(await r.frame.locator('h1.connection-sr-only').innerText(),'WalletConnect');assert.match(await r.frame.locator('.connection-account').innerText(),/Scripted phone wallet/);
  const extra='0x'+'56'.repeat(20);r.fixture.state.accounts.push({address:extra,chain_namespace:'eip155:1',connector_id:'wallet-walletconnect',proof_type:'siwe'});await r.refresh();await r.state('linked');assert.equal(await r.frame.locator('.connection-account code').count(),1,'the connection names only its own account');assert.doesNotMatch(await r.frame.locator('.connection-account').innerText(),/Ethereum/);assert.equal(r.fixture.state.accounts.length,2,'Home retains its other linked account');
  r.fixture.state.accounts=[];await r.reopen();await r.state('saved-unlinked');assert.match(await r.frame.locator('main').innerText(),/Scripted phone wallet/);assert.equal(await r.frame.locator('.connection-qr').count(),0);
 });
 test(`account change during a signature keeps the consumed request and outside-prompt notice in ${engine}`,windowTestOptions(engine,60000),async t=>{
  const r=await setup(t,engine);await r.link();const requestedAccount=r.peer.address;r.request('change');await r.refresh();await r.state('request-waiting');r.peer.choose({request:'silent'});await r.frame.getByRole('button',{name:/^Send to /}).click();await r.state('request-phone');
  await r.page.waitForLoadState('networkidle');let release,entered;const held=new Promise(resolve=>release=resolve),reading=new Promise(resolve=>entered=resolve);
  await r.page.route('**/internet',async route=>{if(route.request().method()==='GET'){entered();await held;}await route.continue();});
  const response=r.page.waitForResponse(response=>response.url().endsWith('/internet')&&response.request().method()==='GET');
  try{await r.refresh();await reading;
  await r.peer.changeAccount(1,true);await r.state('request-busy');assert.notEqual(r.peer.address.toLowerCase(),requestedAccount.toLowerCase());assert.match(await r.frame.locator('.connection-request-account').innerText(),new RegExp(requestedAccount.slice(0,6),'i'),'the consumed request still names its original signer');assert.match(await r.frame.locator('main').innerText(),/request may still be waiting.*Reject or close it there/s);assert.match(await r.frame.locator('.connection-current-selection').innerText(),new RegExp(r.peer.address,'i'));assert.equal(r.fixture.state.completed,0);assert.equal(await r.frame.locator('[data-action=send-request]').count(),0);
  }finally{release();await (await response).finished();}
  await r.page.waitForLoadState('networkidle');
 });
 test(`P9 selected unconfirmed hash survives status polls in ${engine}`,windowTestOptions(engine,60000),async t=>{
  const r=await setup(t,engine);await r.link();r.request('hash',{intent:'transaction_intent'});await r.refresh();await r.state('transaction-waiting');r.fixture.state.completeFails=true;await r.frame.getByRole('button',{name:/^Send to /}).click();await r.state('transaction-wallet-error');
  const before=await r.frame.locator('.connection-hash').evaluate(node=>{const range=document.createRange();range.selectNodeContents(node);getSelection().removeAllRanges();getSelection().addRange(range);window.selectedHashNode=node;return getSelection().toString();});assert.match(before,/^0x[0-9a-f]{64}$/i);
  await pause(6500);assert.equal(await r.frame.evaluate(()=>getSelection().toString()),before);assert.equal(await r.frame.evaluate(()=>document.contains(window.selectedHashNode)),true);
 });
 test(`B6 Stop during pairing import discards the old adapter before fresh Connect in ${engine}`,windowTestOptions(engine,60000),async t=>{
  const r=await setup(t,engine);let entered,release;const held=new Promise(resolve=>release=resolve),loading=new Promise(resolve=>entered=resolve);let imports=0;
  r.page.on('request',request=>{if(new URL(request.url()).pathname.endsWith('/vendor/reown-appkit.js'))imports++;});
  await r.page.route('**/walletconnect-pairing.mjs',async route=>{entered();await held;await route.continue();});t.after(()=>release());
  await r.state('internet-ready');await r.click('Connect wallet');await loading;await r.click('Cancel');await r.state('qr-cancelled');release();await r.page.waitForLoadState('networkidle');await pause(100);assert.equal(await r.frame.evaluate(()=>window.__walletFixtureLifetime.restoreCalls),0,'a stopped import cannot enter real adapter restore');
  await r.click('Connect wallet');await r.state('qr-shown');assert.equal(imports,2,'fresh Connect imports a fresh adapter after the stopped import');await r.click('Cancel');
 });
}

for(const engine of ['chromium','webkit'])test(`a new review replaces a saved Connect only after visible Cancel in ${engine}`,windowTestOptions(engine,60000),async t=>{
 const r=await setup(t,engine);await r.state('internet-ready');r.fixture.setPermission('off');await r.refresh();await r.state('nothing-saved');
 await r.click('Connect wallet');await r.state('internet-pending');r.request('new-review');await r.refresh();await r.state('request-internet-pending');await r.click('Cancel');await r.state('request-internet-off');
 const verified=r.fixture.state.verified;r.fixture.setPermission('granted');await r.refresh();await r.state('request-waiting');assert.equal(r.fixture.state.verified,verified,'Allow cannot resume the cancelled saved Connect');
 await r.frame.getByRole('button',{name:/^Send to /}).click();await r.state('qr-shown');await r.click('Copy link');await r.frame.getByText('Link copied.',{exact:true}).waitFor();await r.peer.pair(await r.page.evaluate(()=>window.copied));await r.state('request-done');assert.equal(r.fixture.state.completed,1);assert.equal(r.fixture.state.verified,verified,'the explicit request resumes Send rather than the old account proof');
});

for(const engine of ['chromium','webkit'])test(`Cancel before Home internet reply prevents a late wallet prompt in ${engine}`,windowTestOptions(engine,60000),async t=>{
 const r=await setup(t,engine);let release,entered;const held=new Promise(resolve=>release=resolve),posting=new Promise(resolve=>entered=resolve);t.after(()=>release());
 await r.page.route('**/internet',async route=>{if(route.request().method()!=='POST')return route.continue();const response=await route.fetch();entered();await held;await route.fulfill({response});});
 await r.state('internet-ready');await r.click('Connect wallet');await posting;await r.click('Cancel');await r.state('qr-cancelled');release();
 for(let i=0;i<30;i++){await pause(100);assert.equal(r.fixture.methods.filter(method=>method==='wc_proposeSession').length,0,'late Home permission never starts the cancelled wallet proposal');assert.equal(await r.frame.locator('.connection-qr').count(),0);}
 assert.equal(r.fixture.state.verified,0);
});
