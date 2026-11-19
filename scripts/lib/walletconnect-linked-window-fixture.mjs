// Real connector and Wallet UI, pinned SDK, and a second protocol party.
import assert from 'node:assert/strict';
import {readFile, mkdir, writeFile} from 'node:fs/promises';
import {extname} from 'node:path';
import {execFileSync} from 'node:child_process';
import {windowFixture, observeWindowErrors, walletWindowLifetime} from './walletconnect-phone-window-fixture.mjs';
import {scriptedPhoneWallet} from './walletconnect-phone-wallet.mjs';
import {importProductSmokePlaywright, productSmokeLaunchOptions} from '../product-smoke-browser.mjs';
const captures=new Map();
export async function linkedWindow(t,engine,{holdWalletRead=false,sourceRef}={}) {
 const fixture=await windowFixture();
 const apiGates=new Map(),gateReleases=[];
 t.after(()=>gateReleases.forEach(release=>release()));
 function holdApi(path,method='POST'){let enter,release;const entered=new Promise(resolve=>enter=resolve),wait=new Promise(resolve=>release=resolve);apiGates.set(method+' '+path,{enter,wait});gateReleases.push(release);return {entered,release};}
 let enterWalletRead,releaseWalletRead,firstWalletRead=true;
 const walletReadStarted=new Promise(resolve=>enterWalletRead=resolve),walletReadGate=new Promise(resolve=>releaseWalletRead=resolve);
 t.after(()=>releaseWalletRead());
 const peer=await scriptedPhoneWallet({projectId:'fixture-project',relayUrl:fixture.origin.replace('http','ws'),chains:['eip155:1','eip155:8453'],name:'Trust Wallet',emitApprovalEvents:true});
 const engines=await importProductSmokePlaywright();
 const browser=await engines[engine].launch({headless:true,...(engine==='chromium'?productSmokeLaunchOptions():{})});
 const page=await browser.newPage({viewport:{width:1040,height:620}});page.setDefaultTimeout(6000);
 if(engine==='chromium')await page.context().grantPermissions(['local-network-access'],{origin:fixture.origin});
 const {errors}=observeWindowErrors(page,fixture);let frame;
 const walletReads=[],walletFailures=[];
 page.on('console',message=>{if(message.type()==='error')walletFailures.push({console:message.text().replaceAll('fixture-project','[test project]').slice(0,500)});});
 page.on('requestfailed',request=>{if(new URL(request.url()).pathname.startsWith('/api/apps/wallet/')||request.frame().url().includes('/apps/wallet/'))walletFailures.push({path:new URL(request.url()).pathname,error:request.failure()?.errorText});});
 async function waitWalletRead(){let timer;try{await Promise.race([walletReadStarted,new Promise((_,reject)=>{timer=setTimeout(()=>reject(new Error('Wallet did not start its account read: '+JSON.stringify(walletFailures))),6000);})]);}finally{clearTimeout(timer);}}
 const settle=await walletWindowLifetime(page,fixture);
 page.on('framenavigated',next=>{if(next.parentFrame()===page.mainFrame()&&next.url().includes('/apps/wallet-walletconnect/'))frame=next;});
 t.after(async()=>{try{await settle(frame);}finally{await peer.stop();await browser.close();await fixture.stop();}assert.deepEqual(errors,[]);});
 await page.route('**/*',route=>new URL(route.request().url()).origin===fixture.origin?route.continue():route.abort());
 const cors={'access-control-allow-origin':'*','access-control-allow-headers':'content-type,x-elastos-home-token','access-control-allow-methods':'GET,POST,OPTIONS'};
 await page.route('**/api/**',async route=>{
  const path=new URL(route.request().url()).pathname;
  const gate=apiGates.get(route.request().method()+' '+path);if(gate){apiGates.delete(route.request().method()+' '+path);gate.enter();await gate.wait;}
  const json=value=>route.fulfill({headers:cors,contentType:'application/json',body:JSON.stringify(value)});
  if(route.request().method()==='OPTIONS')return json({});
  if(path==='/api/apps/wallet/wallet/summary'){
   walletReads.push(fixture.state.accounts.length);
   const snapshot=structuredClone({wallet_accounts:{available:true,accounts:fixture.state.accounts,default_accounts:[]},wallet_approvals:{available:true,approval_requests:[],pending_count:0},approval_methods:{walletconnect:{available:true}}});
   if(firstWalletRead&&holdWalletRead){firstWalletRead=false;enterWalletRead();await walletReadGate;}
   return json(snapshot);
  }
  if(path==='/api/wallet/prices')return json({prices:{},unavailable:true});
  if(path==='/api/provider/chain/balance')return json({status:'unavailable'});
  if(path.endsWith('/verify')){
   // LinkVerifiedAccount adds a row; the older window fixture replaces its list.
   const prior=[...fixture.state.accounts],response=await route.fetch();
   if(response.ok())fixture.state.accounts=[...prior.filter(a=>!fixture.state.accounts.some(b=>a.address.toLowerCase()===b.address.toLowerCase()&&a.chain_namespace===b.chain_namespace)),...fixture.state.accounts].map((a,i)=>({...a,account_id:a.account_id||`fixture-account-${i}-${a.address}`,wallet_display_name:'Trust Wallet',wallet_mark:'wallet',linked_at:1,signing_available:true}));
   return route.fulfill({response});
  }
  return route.fallback();
 });
 await page.route('**/apps/wallet/**',async route=>{
  const path=new URL(route.request().url()).pathname;
  if(!path.startsWith('/apps/wallet/'))return route.fallback();
  const name=path.slice('/apps/wallet/'.length)||'index.html';
  assert.ok(!name.split('/').includes('..'));
  const file=new URL('../../capsules/wallet/browser/'+name,import.meta.url);
  return route.fulfill({headers:cors,contentType:({'.js':'text/javascript','.mjs':'text/javascript','.css':'text/css','.html':'text/html','.png':'image/png','.svg':'image/svg+xml','.woff2':'font/woff2'})[extname(name)]||'application/octet-stream',body:await readFile(file)});
 });
 await page.route(fixture.origin+'/',async route=>{
  const response=await route.fetch();let body=await response.text();
  body=body.replace('</style>','iframe{width:480px;height:522px;vertical-align:top}#accounts{width:550px;height:580px}</style>');
  body+=`<iframe id="accounts" sandbox="allow-scripts allow-forms" src="/apps/wallet/index.html?home_origin=${encodeURIComponent(fixture.origin)}#home_token=fixture-wallet-app"></iframe><script type="module">const host=await import('/apps/home/home-wallet-connector-host.js');addEventListener('message',e=>{if(e.source===document.querySelector('#wallet').contentWindow&&e.origin==='null'&&e.data?.type==='home:refresh-summary'&&e.data.homeToken==='fixture-wallet')host.notifyOpenWallets?.({kind:'app-frame',targetId:'wallet-walletconnect'},events=>document.querySelector('#accounts').contentWindow.postMessage({type:'elastos:runtime-events',events},'*'));if(e.data?.type==='home:open-target'&&e.data.target==='wallet-walletconnect'&&e.source===document.querySelector('#accounts').contentWindow){document.querySelector('#wallet').src='/apps/wallet-walletconnect/?home_origin='+encodeURIComponent(location.origin)+'#home_token=fixture-wallet';}});</script>`;
  return route.fulfill({response,body});
 });
 if(sourceRef){
  assert.equal(sourceRef,'1c2dcb195f5ee294366627cd7dc7d2d2d21ad1f0');
  for(const [asset,path] of [['wallet/wallet.js','capsules/wallet/browser/wallet.js'],['wallet-walletconnect/walletconnect-window-state.mjs','capsules/wallet-walletconnect/browser/walletconnect-window-state.mjs']])await page.route(`**/apps/${asset}*`,route=>route.fulfill({headers:cors,contentType:'text/javascript',body:execFileSync('git',['show',`${sourceRef}:${path}`])}));
 }
 await page.goto(fixture.origin);
 frame=page.frames().find(f=>f.url().includes('/apps/wallet-walletconnect/'));
 const wallet=page.frameLocator('#accounts');await wallet.locator('.wallet-shell').waitFor();
 if(!holdWalletRead)try{await wallet.locator('[data-wallet-open-method="wallet-walletconnect"]').waitFor();}catch(error){throw new Error('Wallet boot: '+await wallet.locator('main').innerText()+'; reads='+JSON.stringify(walletReads)+'; failed='+JSON.stringify(walletFailures),{cause:error});}
 async function state(name){try{await frame.locator(`[data-state="${name}"]`).waitFor();}catch(error){throw new Error(`Expected ${name}: ${await frame.locator('main').innerText()}`,{cause:error});}}
 const click=action=>frame.locator(`[data-action="${action}"]`).click();
 async function link(){await state('internet-ready');await click('connect');await state('qr-shown');await pair();await state('linked');}
 async function pair(){await click('copy-link');await page.waitForFunction(()=>window.copied.startsWith('wc:'));await peer.pair(await page.evaluate(()=>window.copied));}
 async function refresh(){await frame.evaluate(()=>window.dispatchEvent(new Event('focus')));}
 async function reopen(){await settle(frame);const loaded=page.waitForEvent('framenavigated',f=>f.parentFrame()===page.mainFrame()&&f.url().includes('/apps/wallet-walletconnect/'));await page.locator('#wallet').evaluate((node,src)=>node.src=src,nodeURL());frame=await loaded;await frame.locator('main[data-state]').waitFor();}
 function nodeURL(){return fixture.origin+'/apps/wallet-walletconnect/?home_origin='+encodeURIComponent(fixture.origin)+'#home_token=fixture-wallet';}
 async function openFromWallet(){await settle(frame);const loaded=page.waitForEvent('framenavigated',f=>f.parentFrame()===page.mainFrame()&&f.url().includes('/apps/wallet-walletconnect/'));await wallet.locator('[data-wallet-open-method="wallet-walletconnect"]').click();frame=await loaded;await state('linked');}
 const records=captures.get(engine)||[];captures.set(engine,records);
 async function capture(name){
  const output=process.env.WALLETCONNECT_LINKED_SCREENS;if(!output)return;
  await mkdir(`${output}/${engine}`,{recursive:true});
  for(const theme of ['light','dark']){
   await frame.evaluate(theme=>document.documentElement.dataset.elTheme=theme,theme);
   await wallet.locator('html').evaluate((node,theme)=>node.dataset.elTheme=theme,theme);
   await page.screenshot({path:`${output}/${engine}/${name}-${theme}.png`});
   records.push({name,theme,...await frame.locator('main').evaluate(main=>({stage:main.dataset.state,text:main.innerText,actions:[...main.querySelectorAll('button')].map(b=>({action:b.dataset.action,label:b.innerText,primary:b.classList.contains('el-button-primary')}))}))});
  }
  await writeFile(`${output}/${engine}/states.json`,JSON.stringify({head:execFileSync('git',['rev-parse','HEAD'],{encoding:'utf8'}).trim(),tree:execFileSync('git',['rev-parse','HEAD^{tree}'],{encoding:'utf8'}).trim(),engine,version:browser.version(),records},null,2));
 }
 await state('internet-ready');
 return {fixture,peer,page,wallet,holdApi,waitWalletRead,releaseWalletRead,get frame(){return frame;},state,click,link,pair,refresh,reopen,openFromWallet,capture,settle:()=>settle(frame)};
}
