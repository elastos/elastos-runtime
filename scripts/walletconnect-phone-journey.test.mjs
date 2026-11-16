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
 const reopen=async()=>{await page.goto(fixture.origin);frame=page.frames().find(f=>f.url().includes('/apps/wallet-walletconnect/'));await frame.locator('#wallet-requests').getByText('No approval requests.',{exact:true}).waitFor();return frame;};
 await reopen();
 const pair=async()=>{
  await frame.locator('dialog[open] canvas').waitFor({timeout:20000});let uri;
  if(process.env.WALLETCONNECT_BASELINE_PAIRING==='1'){
   const pairings=Object.entries(fixture.state.keys).find(([k])=>k.endsWith('//pairing'))?.[1];const pairing=pairings?.find(p=>!p.active);
   const raw=Object.entries(fixture.state.keys).find(([k])=>k.endsWith('//keychain'))?.[1];const keys=typeof raw==='string'?JSON.parse(raw):raw;
   const key=Array.isArray(keys)?new Map(keys).get(pairing.topic):keys?.[pairing.topic];uri=`wc:${pairing.topic}@2?symKey=${key}&relay-protocol=irn&expiryTimestamp=${pairing.expiry}`;
  }else{await frame.getByRole('button',{name:'Copy connection link',exact:true}).click();uri=await page.evaluate(()=>window.copied);}
  await peer.pair(uri);
 };
 const unlinked=async()=>{peer.choose({request:'reject'});await frame.locator('#wallet-connect').click();await pair();await frame.locator('#wallet-status').filter({hasText:'declined the ownership signature'}).waitFor({timeout:20000});assert.equal(fixture.state.verified,0);};
 const link=async()=>{peer.choose({request:'sign'});await frame.locator('#wallet-connect').click();await pair();await frame.locator('#wallet-state').filter({hasText:'1 linked'}).waitFor({timeout:20000});};
 return {fixture,peer,page,reopen,pair,unlinked,link,get frame(){return frame;}};
}

test('round19 copies the pairing link from the real QR dialog and links Base without a Home wallet',{timeout:60000},async t=>{
 const r=await setup(t);await r.link();assert.equal(r.fixture.state.verified,1);assert.match(await r.frame.locator('#wallet-accounts').innerText(),/Base/);assert.match(await r.frame.locator('#wallet-connection').innerText(),/Linked/);
 assert.equal(await r.frame.locator('#wallet-connect').isVisible(),false);assert.equal(await r.frame.locator('#wallet-disconnect').isVisible(),true);
});
test('round19 a saved unlinked connection explains the wallet and resumes only with Finish linking',{timeout:60000},async t=>{
 const r=await setup(t);await r.unlinked();await r.reopen();await r.frame.locator('#wallet-status').filter({hasText:/Scripted phone wallet.*linking/i}).waitFor({timeout:15000});
 assert.equal(await r.frame.locator('#wallet-disconnect').isVisible(),false);assert.equal(await r.frame.getByRole('button',{name:'Finish linking',exact:true}).isVisible(),true);
 r.peer.choose({request:'sign'});const proposals=r.peer.trace.filter(e=>e.kind==='proposal').length;await r.frame.getByRole('button',{name:'Finish linking',exact:true}).click();await r.frame.locator('#wallet-state').filter({hasText:'1 linked'}).waitFor({timeout:15000});assert.equal(r.peer.trace.filter(e=>e.kind==='proposal').length,proposals);
});
test('round19 Connect wallet replaces a saved unlinked connection with a new QR',{timeout:60000},async t=>{
 const r=await setup(t);await r.unlinked();await r.reopen();await r.frame.locator('#wallet-connect').click();await r.frame.locator('dialog[open]').waitFor({timeout:15000});assert.equal(r.fixture.state.verified,0);
});
test('round19 wallet-side deletion while closed is observed and one Connect gives a QR',{timeout:60000},async t=>{
 const r=await setup(t);await r.unlinked();await r.page.goto('about:blank');await r.peer.deleteConnection();await r.reopen();await r.frame.locator('#wallet-status').filter({hasText:/removed.*connection/i}).waitFor({timeout:15000});await r.frame.locator('#wallet-connect').click();await r.frame.locator('dialog[open]').waitFor({timeout:15000});
});
test('round19 Cancel ends a silent ownership wait and the next Connect works immediately',{timeout:60000},async t=>{
 const r=await setup(t);r.peer.choose({request:'silent'});await r.frame.locator('#wallet-connect').click();await r.pair();await until(()=>r.peer.trace.some(e=>e.kind==='request'),'phone receives ownership request');
 await r.frame.getByRole('button',{name:'Cancel',exact:true}).click();assert.equal(r.fixture.state.verified,0);await r.frame.locator('#wallet-connect').click({timeout:2000});await r.frame.locator('dialog[open]').waitFor({timeout:15000});
});
test('round19 Turn Off cancels a silent ownership wait before the SDK deadline',{timeout:60000},async t=>{
 const r=await setup(t);r.peer.choose({request:'silent'});await r.frame.locator('#wallet-connect').click();await r.pair();await until(()=>r.peer.trace.some(e=>e.kind==='request'),'phone receives ownership request');
 r.fixture.setPermission('revoked');await r.frame.evaluate(()=>window.dispatchEvent(new Event('focus')));await r.frame.locator('#wallet-status').filter({hasText:'turned off'}).waitFor({timeout:5000});r.fixture.setPermission('granted');await r.frame.evaluate(()=>window.dispatchEvent(new Event('focus')));await r.frame.locator('#wallet-connect').click({timeout:2000});await r.frame.locator('dialog[open]').waitFor({timeout:15000});
});
test('round19 disconnect stops the retired SDK heartbeat and its pulse listeners',{timeout:60000},async t=>{
 const r=await setup(t);await r.link();await r.frame.evaluate(()=>{window.retiredCore=globalThis['_walletConnectCore_wallet-walletconnect'];window.retiredIntervalCleared=false;const clear=window.clearInterval;window.clearInterval=id=>{if(id===window.retiredCore.heartbeat.intervalRef)window.retiredIntervalCleared=true;clear(id);};});
 await r.frame.locator('#wallet-disconnect').click();await r.frame.locator('#wallet-status').filter({hasText:/Disconnected/}).waitFor();
 const remaining=await r.frame.evaluate(()=>({cleared:window.retiredIntervalCleared,listeners:window.retiredCore.heartbeat.events.eventNames().reduce((n,k)=>n+window.retiredCore.heartbeat.events.listenerCount(k),0)}));assert.deepEqual(remaining,{cleared:true,listeners:0});
 const count=r.fixture.state.calls.length;await r.frame.evaluate(()=>{for(const name of window.retiredCore.heartbeat.events.eventNames())window.retiredCore.heartbeat.events.emit(name);window.dispatchEvent(new Event('offline'));window.dispatchEvent(new Event('online'));});await delay(6000);
 assert.equal(r.fixture.state.calls.slice(count).some(e=>e.path.endsWith('/relay-admission')||e.path.endsWith('/storage')&&e.method==='POST'),false,'retired SDK sends no admission or storage write');
});
