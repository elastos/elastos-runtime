import test from 'node:test';
import assert from 'node:assert/strict';
import {windowFixture} from './lib/walletconnect-phone-window-fixture.mjs';
import {scriptedPhoneWallet} from './lib/walletconnect-phone-wallet.mjs';
import {importProductSmokePlaywright,productSmokeLaunchOptions} from './product-smoke-browser.mjs';
const delay=ms=>new Promise(r=>setTimeout(r,ms));
async function until(fn,message,ms=20000){const end=Date.now()+ms;while(!fn()){assert.ok(Date.now()<end,message);await delay(25);}}
async function setup(t){
 const fixture=await windowFixture();const peer=await scriptedPhoneWallet({projectId:'fixture-project',relayUrl:fixture.origin.replace('http','ws')});
 const {chromium}=await importProductSmokePlaywright();const browser=await chromium.launch({headless:true,...productSmokeLaunchOptions()});
 const page=await browser.newPage();await page.route('**/*',r=>new URL(r.request().url()).origin===fixture.origin?r.continue():r.abort());
 t.after(async()=>{await peer.stop();await browser.close();await fixture.stop();});
 let frame;
 const reopen=async({ready=true}={})=>{await page.goto(fixture.origin);frame=page.frames().find(f=>f.url().includes('/apps/wallet-walletconnect/'));if(ready)await frame.locator('main[data-state]').waitFor();return frame;};
 await reopen();
 const pair=async()=>{
  await frame.locator('.connection-qr').waitFor({timeout:20000});let uri;
  if(process.env.WALLETCONNECT_BASELINE_PAIRING==='1'){
   const pairings=Object.entries(fixture.state.keys).find(([k])=>k.endsWith('//pairing'))?.[1];const pairing=pairings?.find(p=>!p.active);
   const raw=Object.entries(fixture.state.keys).find(([k])=>k.endsWith('//keychain'))?.[1];const keys=typeof raw==='string'?JSON.parse(raw):raw;
   const key=Array.isArray(keys)?new Map(keys).get(pairing.topic):keys?.[pairing.topic];uri=`wc:${pairing.topic}@2?symKey=${key}&relay-protocol=irn&expiryTimestamp=${pairing.expiry}`;
  }else{await frame.getByRole('button',{name:'Copy link',exact:true}).click();await frame.getByText('Connection link copied. Open it in your wallet app.',{exact:true}).waitFor({timeout:3000});uri=await page.evaluate(()=>window.copied);}
  await peer.pair(uri);
 };
 const unlinked=async()=>{peer.choose({request:'reject'});await frame.locator('[data-action=connect],[data-action=start-over]').click();await pair();await frame.locator('[data-state=link-declined]').waitFor({timeout:20000});assert.equal(fixture.state.verified,0);};
 const link=async()=>{peer.choose({request:'sign'});await frame.locator('[data-action=connect],[data-action=start-over]').click();await pair();await frame.locator('[data-state=linked]').waitFor({timeout:20000});};
 return {fixture,peer,page,reopen,pair,unlinked,link,get frame(){return frame;}};
}

test('round19 copies the pairing link from the real QR dialog and links Base without a Home wallet',{timeout:60000},async t=>{
 const r=await setup(t);await r.link();assert.equal(r.fixture.state.verified,1);assert.match(await r.frame.locator('.connection-content').innerText(),/Base/);assert.equal(await r.frame.locator('main').getAttribute('data-state'),'linked');
 assert.equal(await r.frame.locator('[data-action=connect],[data-action=start-over]').isVisible(),false);assert.equal(await r.frame.locator('[data-action=disconnect]').isVisible(),true);
});
test('round19 a saved unlinked connection explains the wallet and resumes only with Finish linking',{timeout:60000},async t=>{
 const r=await setup(t);await r.unlinked();await r.reopen();await r.frame.locator('[data-state=saved-unlinked]').waitFor({timeout:15000});
 assert.equal(await r.frame.locator('[data-action=disconnect]').isVisible(),false);assert.equal(await r.frame.getByRole('button',{name:'Send message',exact:true}).isVisible(),true);
 r.peer.choose({request:'sign'});const proposals=r.peer.trace.filter(e=>e.kind==='proposal').length;await r.frame.getByRole('button',{name:'Send message',exact:true}).click();await r.frame.locator('[data-state=linked]').waitFor({timeout:15000});assert.equal(r.peer.trace.filter(e=>e.kind==='proposal').length,proposals);
});
test('round19 Connect wallet replaces a saved unlinked connection with a new QR',{timeout:60000},async t=>{
 const r=await setup(t);await r.unlinked();await r.reopen();await r.frame.locator('[data-action=connect],[data-action=start-over]').click();await r.frame.locator('[data-state=qr-shown]').waitFor({timeout:15000});assert.equal(r.fixture.state.verified,0);
});
test('round19 wallet-side deletion while closed is observed and one Connect gives a QR',{timeout:60000},async t=>{
 const r=await setup(t);await r.unlinked();await r.page.goto('about:blank');await r.peer.deleteConnection();await r.reopen();await r.frame.locator('[data-state=wallet-removed]').waitFor({timeout:15000});await r.frame.locator('[data-action=connect],[data-action=start-over]').click();await r.frame.locator('[data-state=qr-shown]').waitFor({timeout:15000});
});
test('round19 Cancel ends a silent ownership wait and the next Connect works immediately',{timeout:60000},async t=>{
 const r=await setup(t);r.peer.choose({request:'silent'});await r.frame.locator('[data-action=connect],[data-action=start-over]').click();await r.pair();await until(()=>r.peer.trace.some(e=>e.kind==='request'),'phone receives ownership request');
 await r.frame.getByRole('button',{name:'Stop waiting',exact:true}).click();assert.equal(r.fixture.state.verified,0);await r.frame.locator('[data-action=connect],[data-action=start-over]').click({timeout:2000});await r.frame.locator('[data-state=qr-shown]').waitFor({timeout:15000});
});
test('round19 Turn Off cancels a silent ownership wait before the SDK deadline',{timeout:60000},async t=>{
 const r=await setup(t);r.peer.choose({request:'silent'});await r.frame.locator('[data-action=connect],[data-action=start-over]').click();await r.pair();await until(()=>r.peer.trace.some(e=>e.kind==='request'),'phone receives ownership request');
 r.fixture.setPermission('revoked');await r.frame.evaluate(()=>window.dispatchEvent(new Event('focus')));await r.frame.locator('[data-state=internet-off]').waitFor({timeout:5000});r.fixture.setPermission('granted');await r.frame.evaluate(()=>window.dispatchEvent(new Event('focus')));await r.frame.locator('[data-action=connect],[data-action=start-over]').click({timeout:2000});await r.frame.locator('[data-state=qr-shown]').waitFor({timeout:15000});
});
test('round19 disconnect stops the retired SDK heartbeat and its pulse listeners',{timeout:60000},async t=>{
 const r=await setup(t);await r.link();await r.frame.evaluate(()=>{window.retiredCore=globalThis['_walletConnectCore_wallet-walletconnect'];window.retiredIntervalCleared=false;const clear=window.clearInterval;window.clearInterval=id=>{if(id===window.retiredCore.heartbeat.intervalRef)window.retiredIntervalCleared=true;clear(id);};});
 await r.frame.locator('[data-action=disconnect]').click();await r.frame.locator('[data-state=disconnected]').waitFor();
 const remaining=await r.frame.evaluate(()=>({cleared:window.retiredIntervalCleared,listeners:window.retiredCore.heartbeat.events.eventNames().reduce((n,k)=>n+window.retiredCore.heartbeat.events.listenerCount(k),0)}));assert.deepEqual(remaining,{cleared:true,listeners:0});
 const count=r.fixture.state.calls.length;await r.frame.evaluate(()=>{for(const name of window.retiredCore.heartbeat.events.eventNames())window.retiredCore.heartbeat.events.emit(name);window.dispatchEvent(new Event('offline'));window.dispatchEvent(new Event('online'));});await delay(6000);
 assert.equal(r.fixture.state.calls.slice(count).some(e=>e.path.endsWith('/relay-admission')||e.path.endsWith('/storage')&&e.method==='POST'),false,'retired SDK sends no admission or storage write');
});

test('round19 an expired window leaves Close to the Home shell and offers no wallet actions',{timeout:30000},async t=>{
 const r=await setup(t);r.fixture.state.expiredLaunch=true;await r.reopen({ready:false});
 await r.frame.locator('[data-state=window-expired]').waitFor({timeout:10000});
 assert.equal(await r.frame.locator('button:visible').count(),0);
});
test('round19 a guest asks the Home owner and waits for the owner to allow access',{timeout:30000},async t=>{
 const r=await setup(t);r.fixture.setPermission('off');r.fixture.state.guest=true;await r.frame.locator('[data-action=connect],[data-action=start-over]').click();
 await r.frame.locator('[data-state=guest-access]').waitFor({timeout:10000});
 assert.equal(await r.frame.locator('[data-action=connect],[data-action=start-over]').isVisible(),false,'the guest cannot send the owner consent request');
 r.fixture.setPermission('granted');await r.frame.evaluate(()=>window.dispatchEvent(new Event('focus')));
 await r.frame.locator('[data-action=connect]:visible,[data-action=start-over]:visible').waitFor({timeout:3000});
});

test('round19 an approval on another network offers a working new-connection action',{timeout:60000},async t=>{
 const r=await setup(t);await r.link();
 r.fixture.state.accounts.push({address:r.peer.address,chain_namespace:'eip155:1',connector_id:'wallet-walletconnect',proof_type:'siwe'});
 r.fixture.state.approvals=[{request_id:'other-network',status:'pending',address:r.peer.address,chain_namespace:'eip155:1',intent:'credential',proof_type:'siwe',connector_id:'wallet-walletconnect',expires_at:Math.floor(Date.now()/1000)+600}];
 await r.frame.evaluate(()=>window.dispatchEvent(new Event('focus')));await r.frame.locator('[data-state=request-new-connection]').waitFor();
 assert.equal(await r.frame.locator('[data-action=connect],[data-action=start-over]').isVisible(),true);
 assert.equal(await r.frame.locator('[data-action=disconnect]').isVisible(),false);
 assert.equal(await r.frame.getByRole('button',{name:/^Send to / }).count(),0);
 await r.frame.locator('[data-action=connect],[data-action=start-over]').click();await r.frame.locator('[data-state=qr-shown]').waitFor({timeout:15000});
});

test('round19 Review during saved-session restore waits for the same live adapter',{timeout:60000},async t=>{
 const r=await setup(t);await r.link();await r.page.goto('about:blank');
 r.fixture.state.approvals=[{request_id:'restore-review',status:'pending',address:r.peer.address,chain_namespace:'eip155:8453',intent:'credential',proof_type:'siwe',connector_id:'wallet-walletconnect',expires_at:Math.floor(Date.now()/1000)+600}];
 let release,entered;const held=new Promise(resolve=>{release=resolve;}),restoring=new Promise(resolve=>{entered=resolve;});let first=true;
 await r.page.route('**/relay-admission',async route=>{if(first){first=false;entered();await held;}await route.continue();});
 t.after(()=>release());await r.reopen({ready:false});await restoring;
 release();await r.frame.locator('[data-state=request-waiting]').waitFor();await r.frame.getByRole('button',{name:/^Send to / }).click();
 await r.frame.locator('[data-state=request-done]').waitFor({timeout:15000});
 assert.equal(await r.frame.locator('iframe').count(),0,'optional website attestation has no direct frame route');
 assert.equal(r.fixture.state.completed,1);assert.equal(r.peer.trace.some(event=>event.kind==='deleted'),false,'restoring for Review keeps the phone session');
});

test('round19 a delayed account list cannot describe an already linked session as unfinished',{timeout:60000},async t=>{
 const r=await setup(t);await r.link();await r.page.goto('about:blank');let release,entered;
 const held=new Promise(resolve=>{release=resolve;}),reading=new Promise(resolve=>{entered=resolve;});
 await r.page.route('**/wallet/accounts',async route=>{entered();await held;await route.continue();});t.after(()=>release());
 await r.reopen({ready:false});await reading;await delay(8000);
 const before=await r.frame.locator('main').innerText();release();
 await r.frame.locator('[data-state=linked]').waitFor({timeout:15000});
 assert.doesNotMatch(before,/linking.*unfinished/i);assert.doesNotMatch(await r.frame.locator('main').innerText(),/linking.*unfinished/i);
});
