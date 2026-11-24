import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdir,writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {execFileSync} from 'node:child_process';
import {signinFixture,installSigninProviders,evmAddress,bitcoinAddress} from './lib/wallet-signin-fixture.mjs';
import {requireProductSmokePlaywright} from './product-smoke-browser.mjs';
import {windowTestOptions} from './lib/walletconnect-window-resources.mjs';
const pictures=process.env.WALLET_ROUND7_PICTURES;
async function setup(engine,width,run) {
 const f=await signinFixture();let browser,context;
 try {
  browser=await requireProductSmokePlaywright()[engine].launch({headless:true});
  context=await browser.newContext({viewport:{width,height:900},locale:'en-US'});
  await context.addInitScript(installSigninProviders,{evmAddress,bitcoinAddress,theme:'light'});
  const page=await context.newPage();page.setDefaultTimeout(3000);
  if(process.env.WALLET_ROUND7_BASELINE)await page.route('**/*',route=>{const path=new URL(route.request().url()).pathname;const name=path.split('/').pop();if(['wallet-signin-view.mjs','wallet-signin-flow.mjs','shell-auth.js'].includes(name))return route.fulfill({contentType:'text/javascript',body:execFileSync('git',['show',process.env.WALLET_ROUND7_BASELINE+':capsules/home/browser/'+name],{encoding:'utf8'})});return route.continue();});
  await page.goto(f.origin+'/home/');await page.waitForFunction(()=>window.fixtureReady);await run({f,page});
 } finally {try{await context?.close();}finally{try{await browser?.close();}finally{await f.close();}}}
}

async function fixtureStep(promise,step) {
 let timeout;
 try{return await Promise.race([promise,new Promise((_,reject)=>{timeout=setTimeout(()=>reject(new Error('Wallet fixture timed out: '+step)),8000);})]);}
 finally{clearTimeout(timeout);}
}
const saved=page=>page.evaluate(()=>localStorage.getItem('elastos.signin.choice.v1'));
const starts=f=>f.state.calls.filter(c=>c.path==='/api/auth/wallet/signin/begin').length;
const passkeyStarts=f=>f.state.calls.filter(c=>c.path==='/api/auth/passkey/authenticate/begin').length;
async function shot(page,name){if(pictures){await mkdir(pictures,{recursive:true});await page.screenshot({path:join(pictures,name+'.png'),animations:'disabled'});}}
for(const engine of ['chromium','webkit'])for(const width of [1280,390])for(const connector of ['metamask','walletconnect'])test(`round7 ${connector} remembers once, cancels/retries ten times, then uses Passkey in ${engine} at ${width}`,windowTestOptions(engine,60000),()=>setup(engine,width,async({f,page})=>{
 const dialog=page.locator('.signin-dialog'),list=dialog.locator('.connection-options-list');
 const row=()=>dialog.locator('[data-choice="'+(connector==='metamask'?'metamask:io.metamask':'walletconnect')+'"]');
 const stage=connector==='metamask'?'signing':'pairing',choice=connector==='metamask'?'metamask:io.metamask':'walletconnect';
 const name=engine+'-'+width+'-'+connector;
 await page.evaluate(()=>{window.walletFixture.signaturePending=true;window.walletFixture.passkeyMode='pending';});
 await page.getByRole('button',{name:'Sign in',exact:true}).click();await dialog.getByLabel('Remember my choice').check();await row().click();
 await page.locator('.signin-dialog[data-state='+stage+']').waitFor();assert.equal(await saved(page),choice);
 await dialog.getByRole('button',{name:'Cancel',exact:true}).click();
 await list.waitFor();assert.equal(await dialog.getAttribute('data-state'),'options');
 await dialog.getByRole('button',{name:'Cancel',exact:true}).click();await dialog.waitFor({state:'detached'});
 for(let cycle=0;cycle<10;cycle++){
  const before=starts(f);await page.getByRole('button',{name:'Sign in',exact:true}).click();
  await page.locator('.signin-dialog[data-state='+stage+']').waitFor();await list.waitFor();assert.equal(starts(f),before+1,'one wallet begin per Sign in');
  assert(await dialog.getByRole('button',{name:/^Passkey\b/}).isEnabled(),'Passkey stays available during a wallet request');
  assert.equal(await page.getByRole('button',{name:'Other options',exact:true}).count(),0);
  if(cycle===0)await shot(page,name+'-remembered-starting');
  await dialog.getByRole('button',{name:'Cancel',exact:true}).click();await page.locator('.signin-dialog[data-state=options]').waitFor();
  assert.equal(await page.locator('iframe[title=WalletConnect]').count(),0);
  if(cycle===0)await shot(page,name+'-after-cancel');
  await dialog.getByLabel('Remember my choice').check();
  await dialog.getByRole('button',{name:'Cancel',exact:true}).click();await dialog.waitFor({state:'detached'});
 }
 await page.getByRole('button',{name:'Sign in',exact:true}).click();await page.locator('.signin-dialog[data-state='+stage+']').waitFor();
 const before=starts(f);await dialog.getByRole('button',{name:/^Passkey\b/}).click();
 await page.waitForFunction(()=>window.walletFixture.calls.some(c=>c.method==='passkey'));
 assert.equal(passkeyStarts(f),1);assert.equal(starts(f),before);assert.equal(await saved(page),'passkey');await page.locator('.signin-dialog[data-state=passkey-signin]').waitFor();
 await shot(page,name+'-after-passkey');
 await page.evaluate(()=>{window.walletFixture.passkeyMode='normal';for(const pending of window.walletFixture.pending.splice(0))pending.resolve(pending.result);});
 await page.waitForFunction(()=>window.openedPrincipal==='principal:alex');await dialog.waitFor({state:'detached'});assert.equal(f.state.walletSession,false);
 assert(f.state.calls.filter(c=>c.path==='/api/auth/wallet/cancel').length>=11);
}));
for(const connector of ['metamask','walletconnect'])test(`round7 ${connector}: ten cancellations in the wallet prompt retain Passkey recovery`,{timeout:60000},()=>setup('chromium',390,async({f,page})=>{
 f.state.rejectSignature=true;await page.evaluate(()=>window.walletFixture.mode='rejected');
 const dialog=page.locator('.signin-dialog'),choice=connector==='metamask'?'metamask:io.metamask':'walletconnect';
 for(let cycle=0;cycle<10;cycle++){
  await page.getByRole('button',{name:'Sign in',exact:true}).click();
  if(cycle===0){await dialog.getByLabel('Remember my choice').check();await dialog.locator('[data-choice="'+choice+'"]').click();}
  if(connector==='walletconnect'){await page.locator('.signin-dialog[data-state=pairing]').waitFor();await page.locator('iframe[title=WalletConnect]').evaluate(frame=>frame.contentWindow.postMessage('fixture-pair','*'));}
  await page.locator('.signin-dialog[data-state=error]').waitFor();assert.match(await dialog.innerText(),/wallet declined/);assert.equal(starts(f),cycle+1);
  if(cycle===9){await dialog.getByRole('button',{name:'Use passkey',exact:true}).click();await page.waitForFunction(()=>window.openedPrincipal==='principal:alex');assert.equal(passkeyStarts(f),1);}
  else {await dialog.getByRole('button',{name:'Cancel',exact:true}).click();await page.locator('.signin-dialog[data-state=options]').waitFor();assert(await dialog.getByLabel('Remember my choice').isChecked());await dialog.getByRole('button',{name:'Cancel',exact:true}).click();await dialog.waitFor({state:'detached'});}
 }
}));
test('round7 choosing another wallet changes the saved choice and rapid Sign in presses start once',()=>setup('chromium',1280,async({f,page})=>{
 await page.evaluate(()=>{localStorage.setItem('elastos.signin.choice.v1','metamask:io.metamask');window.walletFixture.signaturePending=true;});
 await page.getByRole('button',{name:'Sign in',exact:true}).click();const dialog=page.locator('.signin-dialog');await page.locator('.signin-dialog[data-state=signing]').waitFor();
 await dialog.locator('[data-choice=walletconnect]').click();await page.locator('.signin-dialog[data-state=pairing]').waitFor();assert.equal(await saved(page),'walletconnect');
 assert.equal(starts(f),2);assert(f.state.calls.some(c=>c.path==='/api/auth/wallet/cancel'));
 await dialog.getByRole('button',{name:'Cancel',exact:true}).click();await page.locator('.signin-dialog[data-state=options]').waitFor();
 await dialog.getByRole('button',{name:'Cancel',exact:true}).click();
 const before=starts(f);await page.evaluate(()=>{const signIn=document.querySelector('#home-unlock-person');signIn.click();signIn.click();signIn.click();});
 await page.locator('.signin-dialog[data-state=pairing]').waitFor();assert.equal(starts(f),before+1);
 await dialog.getByLabel('Remember my choice').uncheck();assert.equal(await saved(page),null);
}));
test('round7 a remembered Passkey starts once, Cancel leaves choices, and another choice replaces it',()=>setup('chromium',390,async({f,page})=>{
 await page.evaluate(()=>{localStorage.setItem('elastos.signin.choice.v1','passkey');window.walletFixture.passkeyMode='pending';window.walletFixture.signaturePending=true;});
 await page.getByRole('button',{name:'Sign in',exact:true}).click();const dialog=page.locator('.signin-dialog');
 await page.waitForFunction(()=>window.walletFixture.calls.some(c=>c.method==='passkey'));await page.locator('.signin-dialog[data-state=passkey-signin]').waitFor();assert.equal(passkeyStarts(f),1);
 await dialog.getByRole('button',{name:'Cancel',exact:true}).click();await page.locator('.signin-dialog[data-state=options]').waitFor();
 await dialog.locator('[data-choice="metamask:io.metamask"]').click();await page.locator('.signin-dialog[data-state=signing]').waitFor();assert.equal(await saved(page),'metamask:io.metamask');
 await dialog.getByRole('button',{name:'Cancel',exact:true}).click();await page.locator('.signin-dialog[data-state=options]').waitFor();
 await dialog.getByRole('button',{name:/^Passkey\b/}).click();await page.waitForFunction(()=>window.walletFixture.calls.filter(c=>c.method==='passkey').length===2);
 assert.equal(passkeyStarts(f),2);await dialog.getByRole('button',{name:'Cancel',exact:true}).click();await page.locator('.signin-dialog[data-state=options]').waitFor();
 await dialog.getByRole('button',{name:'Cancel',exact:true}).click();await dialog.waitFor({state:'detached'});await page.waitForFunction(()=>document.querySelector('#home-unlock-face-status').textContent==='');
}));
test('round7 wallet busy names its Retry-After and Passkey bypasses the saved wallet',()=>setup('chromium',390,async({f,page})=>{
 await page.evaluate(()=>localStorage.setItem('elastos.signin.choice.v1','metamask:io.metamask'));
 await page.route('**/api/auth/wallet/signin/begin',route=>route.fulfill({status:429,headers:{'retry-after':'47'},contentType:'application/json',body:'{"error":"wallet_attempts_busy"}'}));
 await page.getByRole('button',{name:'Sign in',exact:true}).click();const dialog=page.locator('.signin-dialog[data-state=error]');await dialog.waitFor();
 assert.match(await dialog.innerText(),/47 seconds/);await dialog.getByRole('button',{name:'Use passkey',exact:true}).click();
 await page.waitForFunction(()=>window.openedPrincipal==='principal:alex');assert.equal(passkeyStarts(f),1);assert.equal(await saved(page),'passkey');
}));
test('round7 cancelled and rate-limited passkeys leave visible recovery in the same list',()=>setup('chromium',390,async({f,page})=>{
 await page.evaluate(()=>{localStorage.setItem('elastos.signin.choice.v1','passkey');window.walletFixture.passkeyMode='cancelled';});
 await page.getByRole('button',{name:'Sign in',exact:true}).click();const dialog=page.locator('.signin-dialog[data-state=options]');
 await dialog.getByText('No passkey was used. Select your account to try again.',{exact:true}).waitFor();
 await page.route('**/api/auth/passkey/authenticate/begin',route=>route.fulfill({status:429,headers:{'retry-after':'181'},body:'Busy'}));
 await dialog.getByRole('button',{name:/^Passkey\b/}).click();await dialog.getByText('Sign-in is busy. Try again in 181 seconds.',{exact:true}).waitFor();
 assert(await dialog.locator('[data-choice="metamask:io.metamask"]').isEnabled());
 await dialog.locator('[data-choice="metamask:io.metamask"]').click();await page.waitForFunction(()=>window.openedPrincipal==='principal:alex');assert.equal(f.state.walletSession,true);
}));
for(const lost of [false,true])test(`round7 Passkey wins while wallet completion is ${lost?'unconfirmed':'in flight'}`,()=>setup('chromium',390,async({f,page})=>{
 let release,heldResolve;const held=new Promise(resolve=>heldResolve=resolve);
 await page.route('**/api/auth/wallet/signin/complete',async route=>{const response=await route.fetch();if(lost){heldResolve();return route.abort('failed');}await new Promise(resolve=>{release=resolve;heldResolve();});await route.fulfill({response});});
 try {
  await page.evaluate(()=>localStorage.setItem('elastos.signin.choice.v1','metamask:io.metamask'));
  await page.getByRole('button',{name:'Sign in',exact:true}).click();await fixtureStep(held,'request reached hold');
  const dialog=page.locator('.signin-dialog');
  if(lost){await page.locator('.signin-dialog[data-state=unknown]').waitFor();await dialog.getByRole('button',{name:'Use passkey',exact:true}).click();}
  else {await page.locator('.signin-dialog[data-state=completing]').waitFor();await dialog.getByRole('button',{name:/^Passkey\b/}).click();}
  await page.waitForFunction(()=>window.openedPrincipal==='principal:alex');release?.();
  await assertEventually(()=>assert([...f.state.ceremonies.values()].some(c=>c.cancelled)));
  assert.equal(await page.locator('.signin-dialog').count(),0);assert.equal(passkeyStarts(f),1);assert.equal(starts(f),1);
  assert.equal(await page.evaluate(()=>window.openedFlow?.walletSignin===true),false);assert.equal(f.state.walletSession,false);
 } finally {release?.();}
}));
for(const engine of ['chromium','webkit'])test(`round7 late wallet completion cannot replace the Passkey session cookie in ${engine}`,windowTestOptions(engine,30000),()=>setup(engine,390,async({f,page})=>{
 f.state.boundSigninCookies=true;
 let release,heldResolve,routeDoneResolve;const held=new Promise(resolve=>heldResolve=resolve),routeDone=new Promise(resolve=>routeDoneResolve=resolve);
 const settled=new Promise(resolve=>{for(const event of ['requestfinished','requestfailed'])page.on(event,request=>{if(request.url().endsWith('/api/auth/wallet/signin/complete'))resolve(event);});});
 await page.route('**/api/auth/wallet/signin/complete',async route=>{
  const response=await route.fetch();await new Promise(resolve=>{release=resolve;heldResolve();});
  try{await route.fulfill({response});}catch(error){if(!route.request().failure())throw error;}finally{routeDoneResolve();}
 });
 try {
  await page.evaluate(()=>localStorage.setItem('elastos.signin.choice.v1','metamask:io.metamask'));
  await page.getByRole('button',{name:'Sign in',exact:true}).click();await fixtureStep(held,'request reached hold');
  await page.locator('.signin-dialog').getByRole('button',{name:/^Passkey\b/}).click();await page.waitForFunction(()=>window.openedPrincipal==='principal:alex');
  release();await fixtureStep(routeDone,'release completion');await fixtureStep(settled,'settle completion');
  const status=await page.evaluate(async()=> (await fetch('/api/auth/sessions/refresh',{method:'POST',cache:'no-store'})).status);
  assert.equal(status,200,'Passkey remains signed in after the old wallet response arrives');
  const cookie=(await page.context().cookies()).find(cookie=>cookie.name==='fixture-session');assert.equal(cookie?.value,'passkey');
 } finally {release?.();}
}));
test('round7 a late wallet begin is retired after switching to Passkey; unticking clears the choice',()=>setup('chromium',1280,async({f,page})=>{
 let release,heldResolve;const held=new Promise(resolve=>heldResolve=resolve);
 await page.route('**/api/auth/wallet/signin/begin',async route=>{const response=await route.fetch();await new Promise(resolve=>{release=resolve;heldResolve();});await route.fulfill({response});});
 try {
  await page.evaluate(()=>localStorage.setItem('elastos.signin.choice.v1','metamask:io.metamask'));
  await page.getByRole('button',{name:'Sign in',exact:true}).click();await fixtureStep(held,'request reached hold');
  const dialog=page.locator('.signin-dialog');await dialog.getByLabel('Remember my choice').uncheck();assert.equal(await saved(page),null);
  await dialog.getByRole('button',{name:/^Passkey\b/}).click();await page.waitForFunction(()=>window.openedPrincipal==='principal:alex');release();
  await page.waitForFunction(()=>window.walletFixture.calls.some(c=>c.method==='passkey'));
  await assertEventually(()=>assert(f.state.calls.some(c=>c.path==='/api/auth/wallet/cancel')));
  assert.equal(await page.locator('.signin-dialog').count(),0);assert.equal(starts(f),1);assert.equal(passkeyStarts(f),1);
  assert.equal(await page.evaluate(()=>window.walletFixture.calls.filter(c=>c.method==='personal_sign').length),0);
 } finally {release?.();}
}));
async function assertEventually(check){for(let i=0;i<100;i++){try{return check();}catch(error){if(i===99)throw error;await new Promise(resolve=>setTimeout(resolve,10));}}}
if(pictures)test('round7 picture index',async()=>{
 const stages={'remembered-starting':'Remembered choice starting','after-cancel':'After Cancel','after-passkey':'After choosing Passkey'};
 const images=['chromium','webkit'].flatMap(engine=>[1280,390].flatMap(width=>['metamask','walletconnect'].flatMap(connector=>Object.entries(stages).map(([stage,label])=>({name:engine+'-'+width+'-'+connector+'-'+stage+'.png',caption:`${connector==='metamask'?'MetaMask':'WalletConnect'}: ${label}, ${engine==='webkit'?'WebKit':'Chromium'}, ${width} pixels.`})))));
 await mkdir(pictures,{recursive:true});await writeFile(join(pictures,'index.html'),'<!doctype html><meta charset="utf-8"><title>Round 7 sign-in</title><style>body{font:16px system-ui;margin:24px}img{max-width:100%;border:1px solid #ddd}figure{margin:24px 0}</style><h1>Round 7 sign-in</h1><p>Real Home modules with isolated wallet and passkey boundary fixtures. Desktop 1280 and phone 390.</p>'+images.map(({name,caption})=>'<figure><figcaption>'+caption+'</figcaption><a href="'+name+'"><img src="'+name+'" alt="'+caption+'" loading="lazy"></a></figure>').join(''));
});
