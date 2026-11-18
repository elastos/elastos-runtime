import test from 'node:test';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import assert from 'node:assert/strict';
import {mkdir,writeFile,readFile} from 'node:fs/promises';
import {windowFixture,observeWindowErrors} from './lib/walletconnect-phone-window-fixture.mjs';
import {scriptedPhoneWallet} from './lib/walletconnect-phone-wallet.mjs';
import {importProductSmokePlaywright,productSmokeLaunchOptions} from './product-smoke-browser.mjs';
const output=process.env.WALLETCONNECT_WINDOW_SCREENS;
const sourceIdentity={commit:execFileSync('git',['rev-parse','HEAD'],{encoding:'utf8'}).trim(),tree:execFileSync('git',['rev-parse','HEAD^{tree}'],{encoding:'utf8'}).trim(),dirty:Boolean(execFileSync('git',['status','--porcelain','--untracked-files=no'],{encoding:'utf8'}).trim())};
const pause=ms=>new Promise(r=>setTimeout(r,ms));
async function until(fn,label,ms=20000){const end=Date.now()+ms;while(!await fn()){assert.ok(Date.now()<end,label);await pause(25);}}
async function setup(t,engine,mutation){
 const fixture=await windowFixture(),peer=await scriptedPhoneWallet({projectId:'fixture-project',relayUrl:fixture.origin.replace('http','ws')});
 const engines=await importProductSmokePlaywright(),browser=await engines[engine].launch({headless:true,...(engine==='chromium'?productSmokeLaunchOptions():{})});
 const page=await browser.newPage({viewport:{width:480,height:560}}),{errors}=observeWindowErrors(page,fixture);
 await page.route('**/*',r=>new URL(r.request().url()).origin===fixture.origin?r.continue():r.abort());
 if(mutation)await page.route(`**/${mutation.file}*`,async route=>{
  const source=await readFile(new URL(`../capsules/wallet-walletconnect/browser/${mutation.file}`,import.meta.url),'utf8');
  assert.ok(source.includes(mutation.from),'mutation hits current source');
  await route.fulfill({contentType:'text/javascript',body:source.replace(mutation.from,mutation.to)});
 });
 await page.addInitScript(()=>{
  const active=new Map(),nativeSet=window.setTimeout,nativeClear=window.clearTimeout;
  Object.defineProperty(window,'longTimers',{get:()=>[...active.values()]});
  window.setTimeout=(fn,ms,...args)=>{
   if(typeof fn!=='function')return nativeSet(fn,ms,...args);
   const id=nativeSet((...values)=>{active.delete(id);return Reflect.apply(fn,window,values);},ms,...args);
   const fire=()=>{active.delete(id);nativeClear(id);return Reflect.apply(fn,window,args);};
   if(ms===180000)window.qrDeadline=fire;
   if(ms>=290000&&ms<=610000)active.set(id,fire);
   return id;
  };
  window.clearTimeout=id=>{active.delete(id);nativeClear(id);};
 });
 t.after(async()=>{await peer.stop();await browser.close();await fixture.stop();assert.deepEqual(errors,[],'every live walk rejects unexpected page errors');});
 let frame;
 async function reopen(){await page.goto(fixture.origin);frame=page.frames().find(f=>f.url().includes('/apps/wallet-walletconnect/'));await frame.locator('main[data-state]').waitFor();}
 await reopen();await frame.locator('main[data-state="internet-ready"],main[data-state="link-error"]').waitFor();
 const state=async name=>{try{await frame.locator(`[data-state="${name}"]`).waitFor({timeout:20000});}catch(error){throw new Error('Expected '+name+'; current screen: '+await frame.locator('main').innerText()+'; peer: '+JSON.stringify(peer.trace.slice(-6))+'; verified: '+fixture.state.verified,{cause:error});}};
 async function assertSharedTree(){assert.equal(await frame.locator('body > :not(#wallet-window):not(script)').count(),0,'visible DOM belongs to the shared view');assert.equal(await frame.locator('#wallet-window > :not(main.connection-window)').count(),0);}
 const click=async action=>frame.locator(`[data-action="${action}"]`).click();
 const refresh=async()=>{await frame.evaluate(()=>window.dispatchEvent(new Event('focus')));await pause(150);};
 const records=[];
 const sourceHashes=Object.fromEntries(await Promise.all(['index.html','style.css','wallet-walletconnect.js','walletconnect-client.mjs','walletconnect-window-state.mjs','walletconnect-pairing.mjs','qrcode.mjs','wallet-connection-view.mjs','wallet-connection-screens.mjs','wallet-connection-view.css'].map(async name=>[name,createHash('sha256').update(await readFile(new URL('../capsules/wallet-walletconnect/browser/'+name,import.meta.url))).digest('hex')])));
 async function capture(name){
  await assertSharedTree();
  if(!output)return;
  await mkdir(`${output}/${engine}`,{recursive:true});
  for(const theme of ['dark','light']){
   await frame.evaluate(theme=>document.documentElement.dataset.elTheme=theme,theme);
   const before=await frame.evaluate(()=>({top:document.querySelector('main').scrollTop,key:document.activeElement?.dataset.focusKey,focus:document.activeElement?.dataset.focus,focused:document.hasFocus()}));
   const wanted=await frame.locator('button:visible:enabled').evaluateAll(nodes=>nodes.map(node=>node.dataset.focusKey));
   await frame.locator('body').evaluate(body=>{body.tabIndex=-1;body.focus();});
   const reached=new Set();
   for(let i=0;i<wanted.length*3+3;i++){
    await page.keyboard.press('Tab');
    const focused=await frame.evaluate(()=>{const node=document.activeElement;if(node?.tagName!=='BUTTON')return null;const r=node.getBoundingClientRect();return {key:node.dataset.focusKey,inside:r.left>=0&&r.right<=innerWidth+1&&r.top>=0&&r.bottom<=innerHeight+1};});
    if(focused){reached.add(focused.key);assert.equal(focused.inside,true,`${name}: keyboard control fits the window`);}
   }
   for(const key of wanted)assert.ok(reached.has(key),`${name}: ${key} is reachable with Tab`);
   await frame.evaluate(before=>{document.querySelector('main').scrollTop=before.top;const nodes=[...document.querySelectorAll('[data-focus-key]')];const node=nodes.find(node=>node.dataset.focusKey===before.key)||[...document.querySelectorAll('[data-focus]')].find(node=>node.dataset.focus===before.focus);if(node)node.focus({preventScroll:true});else if(before.focused)document.body.focus({preventScroll:true});},before);
   await pause(40);await page.screenshot({path:`${output}/${engine}/${name}-${theme}.png`});
   const result=await frame.locator('main').evaluate(main=>({state:main.dataset.state,text:main.innerText,actions:[...main.querySelectorAll('button')].map(b=>({action:b.dataset.action,text:b.innerText,disabled:b.disabled})),width:main.scrollWidth,viewport:innerWidth,frameHeight:innerHeight,bodyScroll:document.body.scrollHeight>innerHeight}));
   assert.equal(result.frameHeight,522,`${name}: 38px Home title bar leaves 522px`);assert.ok(result.width<=result.viewport+1,`${name}: horizontal fit`);assert.equal(result.bodyScroll,false,`${name}: single scroll owner`);
   records.push({name,theme,...result,sourceIdentity,sourceHashes,environment:{node:process.version,platform:process.platform,arch:process.arch,browser:browser.version()}});
  }
  await writeFile(`${output}/${engine}/${name}.json`,JSON.stringify(records.filter(row=>row.name===name),null,2));
  await writeFile(`${output}/${engine}/states.json`,JSON.stringify(records,null,2));
 }
 async function qr(){await click('connect');await state('qr-shown');assert.equal(await frame.locator('dialog').count(),0,'no old dialog');assert.equal(await frame.locator('main img.connection-qr').count(),1);}
 async function pair(){await page.evaluate(()=>window.copied='');await click('copy-link');await until(()=>page.evaluate(()=>window.copied.startsWith('wc:')),'clipboard gets pairing URI');await peer.pair(await page.evaluate(()=>window.copied));}
 async function link(){peer.choose({proposal:'approve',request:'sign'});await qr();await pair();await state('linked');assert.ok(fixture.state.verified>0);}
 async function approval(id='message',extra={}){fixture.state.approvals=[{request_id:id,connector_id:'wallet-walletconnect',capsule_id:'browser',requesting_origin:'https://example.test',reason:'Review the scripted message',status:'pending',intent:'credential',proof_type:'siwe',address:peer.address,chain_namespace:'eip155:8453',expires_at:Math.floor(Date.now()/1000)+600,...extra}];await refresh();}
 return {assertSharedTree,fixture,peer,page,get frame(){return frame;},errors,state,click,refresh,capture,qr,pair,link,approval,reopen};
}
for(const engine of ['chromium','webkit']){
 test(`shared WalletConnect real phone journey in ${engine}`,{timeout:180000},async t=>{
  const r=await setup(t,engine);await r.capture('internet-ready');
  r.fixture.setPermission('off');await r.click('connect');await r.state('internet-pending');await r.capture('internet-pending');
  r.fixture.setPermission('refused');await r.refresh();await r.state('internet-refused');await r.capture('internet-refused');
  r.fixture.setPermission('granted');await r.refresh();await r.state('internet-ready');
  await r.qr();await r.capture('qr-shown');
  assert.equal(await r.frame.getByRole('button',{name:'Copy link',exact:true}).count(),1);
  await r.frame.locator('[data-action="copy-link"]').focus();await r.frame.locator('[data-action="copy-link"]').press('Shift+Tab');assert.equal(await r.frame.evaluate(()=>document.activeElement.dataset.action),'cancel');
  await r.frame.locator('[data-action="cancel"]').press('Tab');assert.equal(await r.frame.evaluate(()=>document.activeElement.dataset.action),'copy-link');
  r.peer.choose({request:'silent'});await r.pair();await r.state('link-wait');await r.capture('link-wait');
  assert.equal(await r.frame.getByRole('button',{name:'Cancel',exact:true}).count(),0,'sent proof uses Stop waiting');
  await until(()=>r.peer.trace.some(e=>e.kind==='request'),'phone receives proof');await r.peer.answer('sign');await r.state('linked');assert.equal(r.fixture.state.verified,1);assert.doesNotMatch(await r.frame.locator('main').innerText(),/Connection link copied/);assert.equal(r.fixture.state.accounts[0].chain_namespace,'eip155:8453');await r.capture('linked');
  await r.approval();await r.state('request-waiting');await r.capture('request-waiting');
  await r.frame.locator('[data-action="send-request"]').focus();await r.refresh();assert.equal(await r.frame.evaluate(()=>document.activeElement.dataset.action),'send-request','redraw keeps keyboard focus');
  await r.click('send-request');await r.state('request-phone');await r.capture('request-phone');assert.equal(r.fixture.state.approvals[0].status,'approved');
  await until(()=>r.peer.trace.filter(e=>e.kind==='request').length>=2,'phone receives message');await r.peer.answer('sign');await r.state('request-done');assert.equal(r.fixture.state.completed,1);await r.capture('request-done');
  await r.reopen();await r.state('linked');await r.click('disconnect');await r.state('disconnected');await r.capture('disconnected');await r.link();
  assert.deepEqual(r.errors,[]);
 });
 test(`shared WalletConnect refusal saved-session stop and timeout in ${engine}`,{timeout:180000},async t=>{
  const r=await setup(t,engine);
  r.peer.choose({proposal:'reject'});await r.qr();await r.pair();await r.state('connection-declined');await r.capture('connection-declined');
  r.peer.choose({proposal:'approve',request:'reject'});await r.qr();await r.pair();await r.state('link-declined');await r.capture('link-declined');
  await r.reopen();await r.state('saved-unlinked');await r.capture('saved-unlinked');
  const proposals=r.peer.trace.filter(e=>e.kind==='proposal').length;r.peer.choose({request:'sign'});await r.click('finish');await r.state('linked');assert.equal(r.peer.trace.filter(e=>e.kind==='proposal').length,proposals,'explicit finish reuses session');
  await r.approval('declined');r.peer.choose({request:'reject'});await r.click('send-request');await r.state('request-declined');await r.capture('request-declined');assert.equal(r.fixture.state.completed,0);assert.equal(r.fixture.state.approvals[0].status,'approved');
  // Reopen clears only local display outcome, exactly as a person reopening the window.
  await r.page.goto('about:blank');r.fixture.state.approvals=[];await r.reopen();await r.state('linked');
  r.peer.choose({request:'silent'});await r.approval('silent');await r.click('send-request');await r.state('request-phone');await until(()=>r.peer.trace.some(e=>e.kind==='request'&&e.decision==='silent'),'silent wallet receives request');
  await r.frame.evaluate(()=>{for(const fn of window.longTimers)fn();});await r.state('request-timeout');await r.capture('request-timeout');assert.equal(r.fixture.state.completed,0);
  await r.page.goto('about:blank');r.fixture.state.approvals=[];await r.reopen();await r.state('linked');await r.click('disconnect');await r.state('disconnected');
  await r.qr();await r.frame.evaluate(()=>window.qrDeadline());await r.state('qr-expired');await r.capture('qr-expired');
  await r.qr();await r.click('cancel');await r.state('qr-cancelled');await r.capture('qr-cancelled');
  await r.qr();await r.pair();await r.state('link-wait');await r.click('stop-waiting');await r.state('link-cancelled');await r.capture('link-cancelled');
  assert.deepEqual(r.errors,[]);
 });
 test(`shared WalletConnect wallet changes in ${engine}`,{timeout:180000},async t=>{
  const r=await setup(t,engine);await r.link();await r.peer.changeAccount();await r.state('saved-unlinked');await r.capture('account-changed');
  assert.match(await r.frame.locator('code.connection-address').innerText(),new RegExp(r.peer.address.slice(0,6),'i'));
  assert.equal(r.fixture.state.verified,1,'account notification never links');
  await r.click('finish');await r.state('linked');assert.equal(r.fixture.state.verified,2,'explicit existing link route confirms new account');
  await r.peer.deleteConnection();await r.state('wallet-removed');await r.capture('wallet-removed');
  await r.link();await r.page.goto('about:blank');await r.peer.deleteConnection();await r.reopen();await r.state('wallet-removed');await r.capture('saved-wallet-dropped');
  await r.qr();await r.capture('fresh-after-wallet-dropped');
  assert.deepEqual(r.errors,[]);
 });
}

for(const [name,mutation,probe] of [
 ['wrong view state',{file:'walletconnect-window-state.mjs',from:"stage = permission === 'granted' ? 'internet-ready' : 'nothing-saved'",to:"stage = permission === 'granted' ? 'link-error' : 'nothing-saved'"},'initial'],
 ['wrong connect action',{file:'wallet-walletconnect.js',from:"action === 'connect' || action === 'start-over') return onConnect()",to:"action === 'connect' || action === 'start-over') return disconnect()"},'connect'],
 ['Cancel after dispatch',{file:'wallet-walletconnect.js',from:'const tree = renderConnection(document,currentView);',to:"const tree = renderConnection(document,currentView);for(const b of tree.querySelectorAll('[data-action=stop-waiting]'))b.textContent='Cancel';"},'sent'],
 ['stale view after answer',{file:'wallet-walletconnect.js',from:"outcome=result.effect === 'transaction' ? 'transaction-done' : 'request-done'",to:"outcome=result.effect === 'transaction' ? 'transaction-phone' : 'request-phone'"},'answered'],
 ['drawing outside shared view',{file:'wallet-walletconnect.js',from:'root.replaceChildren(tree);renderKey=key;',to:"root.replaceChildren(tree);renderKey=key;document.body.append(Object.assign(document.createElement('p'),{textContent:'outside'}));"},'tree'],
])test(`independent live guard rejects deliberate ${name}`,{timeout:60000},async t=>{
 const r=await setup(t,'chromium',mutation);
 let caught=false;
 if(probe==='initial')caught=await r.frame.locator('main').getAttribute('data-state')!=='internet-ready';
 if(probe==='tree'){try{await r.assertSharedTree();}catch(error){assert.equal(error.code,'ERR_ASSERTION');caught=true;}}
 if(probe==='connect'){
  await r.click('connect');await pause(500);caught=await r.frame.locator('main').getAttribute('data-state')!=='qr-shown';
 }
 if(probe==='sent'){
  r.peer.choose({request:'silent'});await r.qr();await r.pair();await r.state('link-wait');
  caught=await r.frame.getByRole('button',{name:'Cancel',exact:true}).count()>0;
 }
 if(probe==='answered'){
  await r.link();await r.approval();await r.click('send-request');await until(()=>r.fixture.state.completed===1,'signature really completed');await pause(200);
  caught=await r.frame.locator('main').getAttribute('data-state')!=='request-done';
 }
 assert.equal(caught,true,`deliberate ${name} escaped its independent guard`);
});

for(const engine of ['chromium','webkit'])for(const phase of ['idle','ownership','signature','result'])for(const event of ['account','session-account','network','empty','update','removed'])test(`scripted phone ${event} during ${phase} in ${engine}`,{timeout:60000},async t=>{
 const r=await setup(t,engine);r.peer.choose({chains:['eip155:8453','eip155:1']});
 if(phase==='ownership'){
  r.peer.choose({request:'silent'});await r.qr();await r.pair();await r.state('link-wait');await until(()=>r.peer.trace.some(e=>e.kind==='request'),'phone holds proof');
 }else{
  await r.link();
  if(phase==='signature'||phase==='result'){
   await r.approval('event-message');if(phase==='signature')r.peer.choose({request:'silent'});
   await r.click('send-request');await until(()=>r.peer.trace.filter(e=>e.kind==='request').length>=2,'phone sees application message');
   await r.state(phase==='signature'?'request-phone':'request-done');
  }
 }
 const before={verified:r.fixture.state.verified,completed:r.fixture.state.completed};
 if(event==='account'||event==='session-account')await r.peer.changeAccount(1,event==='account');
 if(event==='network')await r.peer.changeChain('eip155:1');
 if(event==='empty')await r.peer.emptyAccounts();
 if(event==='update')await r.peer.updateSession();
 if(event==='removed')await r.peer.deleteConnection();
 if(event==='account'||event==='session-account'||event==='network'||event==='empty')await r.state('saved-unlinked');
 else if(event==='removed')await r.state(phase==='signature'?'request-sent-wallet-removed':phase==='result'?'request-done':'wallet-removed');
 else await pause(250);
 await r.capture(`event-${event}-${phase}`);
 if(event==='account'||event==='session-account')assert.match(await r.frame.locator('main').innerText(),new RegExp(r.peer.address.slice(0,6),'i'));
 if(event==='network')assert.match(await r.frame.locator('main').innerText(),/Ethereum/);
 if(event==='empty')assert.equal(await r.frame.locator('code.connection-address').count(),0,'empty notification clears the displayed account');
 assert.deepEqual({verified:r.fixture.state.verified,completed:r.fixture.state.completed},before,'event grants no link or signing action');
 if(phase==='idle'&&['account','session-account','network'].includes(event)){
  await r.click('finish');await r.state('linked');assert.equal(r.fixture.state.verified,before.verified+1,'only explicit Finish links the reported account and network');assert.equal(r.fixture.state.accounts[0].address.toLowerCase(),r.peer.address.toLowerCase());assert.equal(r.fixture.state.accounts[0].chain_namespace,event==='network'?'eip155:1':'eip155:8453');await r.capture(`relinked-after-${event}`);
 }
 if(phase==='ownership'||phase==='signature'){
  if(event!=='removed')await r.peer.answer('sign').catch(()=>{});
  await pause(150);const after=event==='update'?{verified:before.verified+(phase==='ownership'?1:0),completed:before.completed+(phase==='signature'?1:0)}:before;assert.deepEqual({verified:r.fixture.state.verified,completed:r.fixture.state.completed},after,'only an answer for an unchanged selection can complete');
 }
 assert.deepEqual(r.errors,[]);
});

for(const engine of ['chromium','webkit'])test(`remaining live states and transaction hash in ${engine}`,{timeout:180000},async t=>{
 const r=await setup(t,engine);r.fixture.setPermission('off');await r.click('connect');await r.state('internet-pending');
 let release;const held=new Promise(resolve=>{release=resolve;});
 await r.page.route('**/relay-admission',async route=>{await held;await route.continue();});t.after(()=>release());
 r.fixture.setPermission('granted');await r.refresh();await r.state('preparing-qr');await r.capture('preparing-qr');release();
 await r.state('qr-shown');r.peer.choose({request:'silent'});await r.pair();await r.state('link-wait');await until(()=>r.peer.trace.some(e=>e.kind==='request'),'proof published');
 await r.frame.evaluate(()=>{for(const fn of window.longTimers)fn();});await r.state('link-timeout');await r.capture('link-timeout');
 await r.peer.answer('reject');
 await r.click('check-access');await r.state('saved-unlinked');assert.equal(r.fixture.state.verified,0);
 r.peer.choose({request:'sign'});await r.click('finish');await r.state('linked');
 await r.approval('unsupported',{intent:'browser_typed_data_sign'});await r.state('request-unsendable');await r.capture('request-unsendable');
 await r.approval('expired',{expires_at:Math.floor(Date.now()/1000)-1});await r.state('request-expired');await r.capture('request-expired');
 await r.approval('wrong-network',{chain_namespace:'eip155:1'});await r.state('request-new-connection');await r.capture('request-new-connection');
 await r.approval('transaction-short',{intent:'transaction_intent',expires_at:Math.floor(Date.now()/1000)+200});await r.state('transaction-deadline');await r.capture('transaction-deadline');
 await r.approval('transaction',{intent:'transaction_intent'});await r.state('transaction-waiting');await r.capture('transaction-waiting');
 r.peer.choose({request:'silent'});const count=r.peer.trace.filter(e=>e.kind==='request').length;await r.click('send-request');await r.state('transaction-phone');await until(()=>r.peer.trace.filter(e=>e.kind==='request').length>count,'transaction published');await r.capture('transaction-phone');
 await r.peer.answer('sign');await r.state('transaction-done');await r.capture('transaction-done');assert.equal(r.fixture.state.transactionHash,r.peer.lastTransactionHash,'Home recorded the hash of the peer-signed transaction');
 for(const ending of ['reject','timeout','cancel']){
  r.fixture.state.approvals=[];await r.reopen();await r.state('linked');await r.approval(`transaction-${ending}`,{intent:'transaction_intent'});
  r.peer.choose({request:ending==='reject'?'reject':'silent'});const before=r.peer.trace.filter(e=>e.kind==='request').length;await r.click('send-request');
  if(ending!=='reject'){await r.state('transaction-phone');await until(()=>r.peer.trace.filter(e=>e.kind==='request').length>before,'phone holds transaction');if(ending==='timeout')await r.frame.evaluate(()=>{for(const fn of window.longTimers)fn();});else await r.click('stop-waiting');}
  const stage={reject:'transaction-declined',timeout:'transaction-timeout',cancel:'transaction-cancelled'}[ending];await r.state(stage);await r.capture(stage);
  assert.equal(r.fixture.state.completed,1,'refusal/wait end creates no second result');
  if(ending==='timeout'){
   await r.peer.answer('reject'); // Close the old phone prompt before the next independent transaction.
   await until(()=>r.fixture.pendingDeliveryAcks()===0,'Runtime acknowledged the old wallet answer');await r.page.waitForLoadState('networkidle');
  }
 }
 assert.deepEqual(r.errors,[]);
});
for(const engine of ['chromium','webkit'])test(`guest off and expired window in ${engine}`,{timeout:60000},async t=>{
 const r=await setup(t,engine);r.fixture.setPermission('revoked');await r.refresh();await r.state('internet-off');await r.capture('internet-off');
 r.fixture.state.guest=true;await r.frame.locator('[data-action=inbox]').click();r.fixture.setPermission('granted');await r.refresh();await r.state('internet-ready');
 r.fixture.setPermission('off');await r.click('connect');await r.state('guest-access');await r.capture('guest-access');
 r.fixture.state.expiredLaunch=true;await r.reopen();await r.state('window-expired');await r.capture('window-expired');assert.equal(await r.frame.locator('button').count(),0,'unavailable N1 Close stays with the shell');
 assert.deepEqual(r.errors,[]);
});

for(const engine of ['chromium','webkit'])test(`wallet answer replaces the wait before a delayed Home summary in ${engine}`,{timeout:60000},async t=>{
 const r=await setup(t,engine);await r.link();await r.approval('delayed-summary');r.peer.choose({request:'silent'});
 await r.click('send-request');await r.state('request-phone');await until(()=>r.peer.trace.filter(e=>e.kind==='request').length>=2,'phone received message');
 let release;const held=new Promise(resolve=>{release=resolve;});t.after(()=>release());
 await r.page.route('**/wallet/approvals',async route=>{if(r.fixture.state.completed)await held;await route.continue();});
 await r.peer.answer('sign');await until(()=>r.fixture.state.completed===1,'Home verified the returned signature');await r.state('request-done');
 assert.equal(await r.frame.locator('[data-action=send-request]').count(),0,'answered request never regains Send during a slow refresh');
 await r.capture('answer-before-summary');release();assert.deepEqual(r.errors,[]);
});

for(const engine of ['chromium','webkit'])test(`keyboard activation and long-card redraw preserve focus and scroll in ${engine}`,{timeout:60000},async t=>{
 const r=await setup(t,engine);await r.frame.locator('[data-action=connect]').press('Enter');await r.state('qr-shown');
 await r.frame.locator('[data-action=copy-link]').press('Space');await until(()=>r.page.evaluate(()=>window.copied.startsWith('wc:')),'keyboard Copy link writes through Home');await r.peer.pair(await r.page.evaluate(()=>window.copied));await r.state('linked');
 await r.approval('long-keyboard',{reason:'Review this message from the requesting app. '.repeat(40),requesting_origin:'https://'+('a'.repeat(60)+'.').repeat(3)+'example.test'});await r.state('request-waiting');
 await r.frame.locator('[data-action=send-request]').focus();
 const before=await r.frame.evaluate(()=>({top:document.querySelector('main').scrollTop,action:document.activeElement.dataset.action}));assert.ok(before.top>0,'the long request scrolls');
 await r.refresh();const after=await r.frame.evaluate(()=>({top:document.querySelector('main').scrollTop,action:document.activeElement.dataset.action}));assert.deepEqual(after,before,'same request redraw preserves focus and scroll');
 await r.capture('long-request-redraw');r.peer.choose({request:'silent'});await r.frame.locator('[data-action=send-request]').press('Enter');await r.state('request-phone');await until(()=>r.peer.trace.filter(e=>e.kind==='request').length>=2,'long message published');await r.capture('long-request-phone');await r.peer.answer('sign');await r.state('request-done');assert.equal(r.fixture.state.completed,1,'Enter sent the exact request and returned a verified signature');
 await r.refresh();assert.equal(await r.frame.evaluate(()=>document.activeElement.dataset.focus),'outcome','result redraw preserves the non-action outcome focus');assert.deepEqual(r.errors,[]);
});

for(const engine of ['chromium','webkit'])test(`background wallet redraw keeps Home keyboard focus in ${engine}`,{timeout:60000},async t=>{
 const r=await setup(t,engine);await r.link();await r.frame.locator('[data-action=copy-address]').focus();
 await r.page.evaluate(()=>{const input=document.createElement('input');input.id='home-note';input.style.position='fixed';input.style.top='0';document.body.append(input);input.focus();});
 await r.peer.updateSession();await pause(250);assert.equal(await r.page.evaluate(()=>document.activeElement.id),'home-note','a wallet update keeps the Home input focused');
 await r.frame.evaluate(()=>window.focus());await r.refresh();assert.equal(await r.frame.evaluate(()=>document.activeElement.dataset.action),'copy-address','returning restores the same account action');assert.deepEqual(r.errors,[]);
});

for(const engine of ['chromium','webkit'])test(`unsupported wallet network is named and cannot be linked in ${engine}`,{timeout:60000},async t=>{
 const r=await setup(t,engine);r.peer.choose({chains:['eip155:8453','eip155:137']});await r.link();await r.peer.changeChain('eip155:137');await r.state('saved-unlinked');
 assert.match(await r.frame.locator('main').innerText(),/Unsupported network.*137/);assert.equal(await r.frame.locator('[data-action=finish]').count(),0);assert.equal(r.fixture.state.verified,1);
 await r.capture('network-unsupported');await r.click('start-over');await r.state('qr-shown');assert.deepEqual(r.errors,[]);
});
for(const engine of ['chromium','webkit'])for(const phase of ['idle','ownership','signature','result'])test(`relay drops and returns during ${phase} in ${engine}`,{timeout:60000},async t=>{
 const r=await setup(t,engine);
 if(phase==='ownership'){r.peer.choose({request:'silent'});await r.qr();await r.pair();await r.state('link-wait');await until(()=>r.peer.trace.some(e=>e.kind==='request'),'proof published');}
 else{await r.link();if(phase==='signature'||phase==='result'){await r.approval('relay-message');if(phase==='signature')r.peer.choose({request:'silent'});await r.click('send-request');await until(()=>r.peer.trace.filter(e=>e.kind==='request').length>=2,'message published');await r.state(phase==='signature'?'request-phone':'request-done');}}
 const before={verified:r.fixture.state.verified,completed:r.fixture.state.completed};assert.ok(r.fixture.setRelayAvailable(false)>0,'the active Runtime relay socket was interrupted');await r.frame.getByText(/WalletConnect is reconnecting/).waitFor({timeout:15000});await r.capture(`relay-dropped-${phase}`);
 assert.deepEqual({verified:r.fixture.state.verified,completed:r.fixture.state.completed},before);
 r.fixture.setRelayAvailable(true);await r.frame.evaluate(()=>window.dispatchEvent(new Event('online')));await until(async()=>!await r.frame.getByText(/WalletConnect is reconnecting/).count(),'transport returns',20000);await r.capture(`relay-returned-${phase}`);
 if(phase==='ownership'||phase==='signature'){await r.peer.answer('sign');await r.state(phase==='ownership'?'linked':'request-done');}
 assert.deepEqual(r.errors,[]);
});
for(const engine of ['chromium','webkit'])for(const phase of ['idle','ownership','signature','result'])test(`session expiry is observed during ${phase} in ${engine}`,{timeout:60000},async t=>{
 const r=await setup(t,engine);
 if(phase==='ownership'){r.peer.choose({request:'silent'});await r.qr();await r.pair();await r.state('link-wait');await until(()=>r.peer.trace.some(e=>e.kind==='request'),'proof published');}
 else{await r.link();if(phase==='signature'||phase==='result'){await r.approval('expiry-message');if(phase==='signature')r.peer.choose({request:'silent'});await r.click('send-request');await until(()=>r.peer.trace.filter(e=>e.kind==='request').length>=2,'message published');await r.state(phase==='signature'?'request-phone':'request-done');}}
 const before={verified:r.fixture.state.verified,completed:r.fixture.state.completed};
 await r.frame.evaluate(()=>{const now=Date.now;Date.now=()=>now()+8*86400*1000;const core=globalThis['_walletConnectCore_wallet-walletconnect'];for(const name of core.heartbeat.events.eventNames())core.heartbeat.events.emit(name);});await r.refresh();
 await r.state(phase==='result'?'request-done':phase==='signature'?'request-unavailable':'connection-expired');await r.capture(`session-expired-${phase}`);
 assert.deepEqual({verified:r.fixture.state.verified,completed:r.fixture.state.completed},before,'expiry records no proof or extra signature');
 if(phase==='result')assert.match(await r.frame.locator('main').innerText(),/Message signed.*This wallet connection expired/s);
});

for(const engine of ['chromium','webkit'])test(`a returned transaction hash stays visible when Home cannot confirm it in ${engine}`,{timeout:60000},async t=>{
 const r=await setup(t,engine);await r.link();r.fixture.state.completeFails=true;await r.approval('unconfirmed-hash',{intent:'transaction_intent'});await r.click('send-request');await r.state('transaction-wallet-error');
 assert.equal(r.fixture.state.completed,0);assert.equal(r.fixture.state.returnedHash,r.peer.lastTransactionHash);
 assert.ok((await r.frame.locator('main').innerText()).includes(r.peer.lastTransactionHash),'the exact returned hash survives the failed existing completion route');
 await r.capture('transaction-hash-unconfirmed');assert.deepEqual(r.errors,[]);
});

for(const engine of ['chromium','webkit'])test(`a wallet answer names Home while its existing completion is pending in ${engine}`,{timeout:60000},async t=>{
 const r=await setup(t,engine);await r.link();await r.approval('checking-response');
 let release,entered;const held=new Promise(resolve=>{release=resolve;}),checking=new Promise(resolve=>{entered=resolve;});t.after(()=>release());
 await r.page.route('**/wallet/approvals/checking-response/complete',async route=>{entered();await held;await route.continue();});
 await r.click('send-request');await checking;await r.frame.getByText('Your wallet has answered. Home is checking the response.',{exact:true}).waitFor();
 assert.equal(r.fixture.state.completed,0);assert.equal(await r.frame.getByRole('button',{name:'Stop waiting',exact:true}).count(),1);await r.capture('response-checking');
 release();await r.state('request-done');assert.equal(r.fixture.state.completed,1);assert.deepEqual(r.errors,[]);
});

for(const engine of ['chromium','webkit'])test(`proof checking stays bound while the wallet changes account in ${engine}`,{timeout:60000},async t=>{
 const r=await setup(t,engine),first=r.peer.address;
 let release,entered;const held=new Promise(resolve=>{release=resolve;}),checking=new Promise(resolve=>{entered=resolve;});t.after(()=>release());
 await r.page.route('**/api/auth/evm/verify',async route=>{entered();await held;await route.continue();});
 await r.qr();await r.pair();await checking;await r.peer.changeAccount();
 await r.frame.getByText('Your wallet has answered. Home is checking the response.',{exact:true}).waitFor();
 assert.match(await r.frame.locator('code.connection-address').innerText(),new RegExp(first.slice(0,6),'i'),'the response still belongs to the account that signed');assert.equal(r.fixture.state.verified,0);
 release();await r.state('saved-unlinked');assert.equal(r.fixture.state.verified,1);assert.match(await r.frame.locator('code.connection-address').innerText(),new RegExp(r.peer.address.slice(0,6),'i'),'the changed account is offered for a separate link');
 assert.equal(await r.frame.locator('[data-action=finish]').count(),1);await r.capture('account-changed-after-proof-response');assert.deepEqual(r.errors,[]);
});

for(const engine of ['chromium','webkit'])test(`an account change after proof awaits explicit Finish during a delayed Home refresh in ${engine}`,{timeout:60000},async t=>{
 const r=await setup(t,engine);let release,entered;const held=new Promise(resolve=>{release=resolve;}),refreshing=new Promise(resolve=>{entered=resolve;});t.after(()=>release());await r.page.route('**/wallet/accounts',async route=>{if(r.fixture.state.verified===1){entered();await held;}await route.continue();});
 await r.qr();await r.pair();await refreshing;await r.state('linked');assert.equal(r.fixture.state.verified,1);await r.peer.changeAccount();await r.state('saved-unlinked');assert.match(await r.frame.locator('main').innerText(),new RegExp(r.peer.address.slice(0,6),'i'));assert.equal(r.fixture.state.verified,1,'the changed account has no automatic proof');await r.capture('account-changed-during-linked-refresh');release();await r.page.unroute('**/wallet/accounts');await r.click('finish');await r.state('linked');assert.equal(r.fixture.state.verified,2);assert.equal(r.fixture.state.accounts[0].address.toLowerCase(),r.peer.address.toLowerCase());assert.deepEqual(r.errors,[]);
});

for(const engine of ['chromium','webkit'])test(`the selected second request finishes before the first can be sent in ${engine}`,{timeout:60000},async t=>{
 const r=await setup(t,engine);await r.link();await r.approval('first');r.fixture.state.approvals.push({...r.fixture.state.approvals[0],request_id:'second',reason:'Second request'});await r.refresh();await r.state('request-multiple');
 await r.click('view-requests');await r.state('request-list');await r.frame.locator('[data-focus-key="select-request:second"]').click();assert.equal(await r.frame.locator('.connection-request').getAttribute('data-request-id'),'second');
 let release,entered,first=true;const held=new Promise(resolve=>{release=resolve;}),captured=new Promise(resolve=>{entered=resolve;});t.after(()=>release());
 await r.page.route('**/wallet/approvals',async route=>{if(!first){await route.continue();return;}first=false;const response=await route.fetch();entered();await held;await route.fulfill({response,headers:{...response.headers(),'x-wallet-test-stale':'1'}});});
 const staleResponse=r.page.waitForResponse(response=>response.headers()['x-wallet-test-stale']==='1');await r.refresh();await captured;
 await r.click('send-request');await r.state('request-next');assert.equal(r.fixture.state.approvals.find(row=>row.request_id==='second').status,'completed');assert.equal(r.fixture.state.approvals.find(row=>row.request_id==='first').status,'pending');
 assert.equal(await r.frame.locator('[data-action=send-request]').count(),0,'a fresh approval is not substituted under the completed action');await r.capture('request-next');
 await r.frame.locator('[data-focus-key="select-request:first"]').click();await r.state('request-waiting');await r.click('send-request');await r.state('request-done');assert.equal(r.fixture.state.completed,2,'clearing the consumed selection leaves a working first request');
 release();await (await staleResponse).finished();await r.frame.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));await r.state('request-done');assert.equal(await r.frame.locator('[data-action=send-request]').count(),0,'an older pending snapshot cannot restore either completed request');assert.deepEqual(r.errors,[]);
});

for(const engine of ['chromium','webkit'])test(`cleanup refusal local stop and permission recovery states in ${engine}`,{timeout:180000},async t=>{
 const r=await setup(t,engine);r.fixture.state.deleteFails=true;await r.click('connect');await r.state('link-error');await r.capture('cleanup-error');
 r.fixture.state.deleteFails=false;await r.link();
 let release,entered;const held=new Promise(resolve=>{release=resolve;}),deleting=new Promise(resolve=>{entered=resolve;});t.after(()=>release());
 await r.page.route('**/storage',async route=>{if(route.request().method()==='DELETE'){entered();await held;}await route.continue();});
 await r.click('disconnect');await deleting;await r.state('disconnecting');await r.capture('disconnecting');release();await r.state('disconnected');await r.page.unroute('**/storage');await r.link();
 r.peer.choose({request:'silent'});await r.approval('local-stop');await r.click('send-request');await r.state('request-phone');await until(()=>r.peer.trace.filter(e=>e.kind==='request').length>=3,'phone holds message');await r.click('stop-waiting');await r.state('request-cancelled');await r.capture('request-cancelled');assert.equal(r.fixture.state.completed,0);
 r.fixture.state.approvals=[];await r.reopen();await r.state('internet-ready');await r.link();await r.approval('permission-message');
 r.fixture.setPermission('off');await r.click('send-request');await r.state('request-internet-pending');await r.capture('request-internet-pending');await r.click('cancel');await r.state('request-internet-off');await r.capture('request-internet-off');
 r.fixture.setPermission('granted');r.fixture.state.approvals=[];await r.reopen();await r.state('internet-ready');await r.link();
 await r.approval('complete-error');r.fixture.state.completeFails=true;r.peer.choose({request:'sign'});await r.click('send-request');await r.state('request-unavailable');await r.capture('request-unavailable');assert.equal(r.fixture.state.completed,0);
 r.fixture.state.completeFails=false;await r.approval('already-approved',{intent:'transaction_intent',status:'approved'});await r.reopen();await r.state('transaction-reopened');await r.capture('transaction-reopened');assert.equal(await r.frame.locator('[data-action=send-request]').count(),0);
 assert.deepEqual(r.errors,[]);
});

for(const engine of ['chromium','webkit'])for(const phase of ['idle','ownership','signature','result'])test(`session extension during ${phase} keeps the current request in ${engine}`,{timeout:60000},async t=>{
 const r=await setup(t,engine);
 if(phase==='ownership'){r.peer.choose({request:'silent'});await r.qr();await r.pair();await r.state('link-wait');await until(()=>r.peer.trace.some(e=>e.kind==='request'),'proof published');}
 else{await r.link();if(phase==='signature'||phase==='result'){await r.approval('extended-session');if(phase==='signature')r.peer.choose({request:'silent'});await r.click('send-request');await until(()=>r.peer.trace.filter(e=>e.kind==='request').length>=2,'message published');await r.state(phase==='signature'?'request-phone':'request-done');}}
 const before={verified:r.fixture.state.verified,completed:r.fixture.state.completed};await r.peer.extendSession();await r.refresh();await r.state({idle:'linked',ownership:'link-wait',signature:'request-phone',result:'request-done'}[phase]);await r.capture(`session-extended-${phase}`);
 assert.deepEqual({verified:r.fixture.state.verified,completed:r.fixture.state.completed},before,'extension grants no link/sign action');
 if(phase==='ownership'||phase==='signature'){await r.peer.answer('sign');await r.state(phase==='ownership'?'linked':'request-done');}
 assert.deepEqual(r.errors,[]);
});

for(const engine of ['chromium','webkit'])test(`read failure during a phone wait retains Stop waiting in ${engine}`,{timeout:60000},async t=>{
 const r=await setup(t,engine);await r.link();r.peer.choose({request:'silent'});await r.approval('read-failure');await r.click('send-request');await r.state('request-phone');await until(()=>r.peer.trace.filter(e=>e.kind==='request').length>=2,'message published');
 await r.page.route('**/wallet/accounts',route=>route.fulfill({status:503,body:'Unavailable'}));await r.refresh();await r.state('request-phone');assert.equal(await r.frame.locator('[data-action=stop-waiting]:enabled').count(),1);await r.capture('home-read-failed-during-wait');
 await r.page.unroute('**/wallet/accounts');await r.peer.answer('sign');await r.state('request-done');assert.equal(r.fixture.state.completed,1);assert.deepEqual(r.errors,[]);
});
for(const engine of ['chromium','webkit'])for(const ending of ['permission','expiry'])test(`sent transaction survives ${ending} without a Send control in ${engine}`,{timeout:60000},async t=>{
 const r=await setup(t,engine);await r.link();await r.approval('sent-transaction',{intent:'transaction_intent'});r.peer.choose({request:'silent'});await r.click('send-request');await r.state('transaction-phone');await until(()=>r.peer.trace.filter(e=>e.kind==='request').length>=2,'transaction published');
 if(ending==='permission'){r.fixture.setPermission('revoked');await r.refresh();}
 else{await r.frame.evaluate(()=>{const now=Date.now;Date.now=()=>now()+8*86400*1000;const core=globalThis['_walletConnectCore_wallet-walletconnect'];for(const name of core.heartbeat.events.eventNames())core.heartbeat.events.emit(name);});await r.refresh();}
 await r.state('transaction-wallet-error');assert.equal(await r.frame.locator('[data-action=send-request]').count(),0);await r.capture(`transaction-${ending}-ended`);
 if(ending==='permission'){r.fixture.setPermission('granted');await r.refresh();await r.state('transaction-wallet-error');assert.equal(await r.frame.locator('[data-action=send-request]').count(),0);await r.capture('transaction-after-access-returned');}
 assert.equal(r.fixture.state.approvals[0].status,'approved');assert.equal(r.fixture.state.completed,0);assert.deepEqual(r.errors,[]);
});
for(const engine of ['chromium','webkit'])test(`a blocked first request leaves the real queue usable in ${engine}`,{timeout:60000},async t=>{
 const r=await setup(t,engine);await r.link();await r.approval('blocked',{intent:'browser_typed_data_sign'});r.fixture.state.approvals.push({...r.fixture.state.approvals[0],request_id:'valid',intent:'credential'});await r.refresh();await r.state('request-multiple');assert.equal(await r.frame.locator('.connection-request').first().getAttribute('data-request-id'),'valid');await r.capture('blocked-first-queue');
 await r.click('send-request');await r.state('request-next');assert.equal(r.fixture.state.completed,1);assert.equal(r.fixture.state.approvals.find(row=>row.request_id==='valid').status,'completed');assert.deepEqual(r.errors,[]);
});
for(const engine of ['chromium','webkit'])test(`picker cannot replace an expired window in ${engine}`,{timeout:60000},async t=>{
 const r=await setup(t,engine);await r.link();await r.approval('one');r.fixture.state.approvals.push({...r.fixture.state.approvals[0],request_id:'two'});await r.refresh();await r.click('view-requests');await r.state('request-list');r.fixture.state.expiredLaunch=true;await r.refresh();await r.state('window-expired');assert.equal(await r.frame.locator('[data-action=select-request]').count(),0);await r.capture('expired-window-from-picker');assert.deepEqual(r.errors,[]);
});

for(const engine of ['chromium','webkit'])test(`proof timeout survives relay and session-extension updates in ${engine}`,{timeout:60000},async t=>{
 const r=await setup(t,engine);r.peer.choose({request:'silent'});await r.qr();await r.pair();await r.state('link-wait');await until(()=>r.peer.trace.some(e=>e.kind==='request'),'proof published');await r.frame.evaluate(()=>{for(const fn of window.longTimers)fn();});await r.state('link-timeout');
 await r.peer.extendSession();await r.refresh();await r.state('link-timeout');r.fixture.setRelayAvailable(false);await r.frame.getByText(/WalletConnect is reconnecting/).waitFor();await r.state('link-timeout');r.fixture.setRelayAvailable(true);await r.frame.evaluate(()=>window.dispatchEvent(new Event('online')));await until(async()=>!await r.frame.getByText(/WalletConnect is reconnecting/).count(),'transport returns');await r.state('link-timeout');await r.capture('proof-timeout-after-session-events');assert.equal(r.fixture.state.verified,0);assert.deepEqual(r.errors,[]);
});
for(const engine of ['chromium','webkit'])test(`a known hash survives stopping Home completion in ${engine}`,{timeout:60000},async t=>{
 const r=await setup(t,engine);await r.link();await r.approval('hash-before-stop',{intent:'transaction_intent'});
 let release,entered;const held=new Promise(resolve=>{release=resolve;}),checking=new Promise(resolve=>{entered=resolve;});t.after(()=>release());await r.page.route('**/wallet/approvals/hash-before-stop/complete',async route=>{entered();await held;await route.continue();});
 await r.click('send-request');await checking;await r.frame.getByText('Your wallet has answered. Home is checking the response.',{exact:true}).waitFor();await r.click('stop-waiting');await r.state('transaction-cancelled');assert.ok((await r.frame.locator('main').innerText()).includes(r.peer.lastTransactionHash));await r.capture('known-hash-after-stop');release();await until(()=>r.fixture.state.completed===1,'the existing posted completion can finish');await r.state('transaction-cancelled');assert.deepEqual(r.errors,[]);
});
for(const engine of ['chromium','webkit'])test(`Send remains bound to its visible request ID in ${engine}`,{timeout:60000},async t=>{
 const r=await setup(t,engine);await r.link();await r.approval('current');const before=r.fixture.state.calls.filter(row=>row.path.endsWith('/approve')).length;
 await r.frame.evaluate(()=>{const button=document.createElement('button');button.dataset.action='send-request';button.dataset.walletRequestSign='stale-other-request';document.querySelector('#wallet-window').append(button);button.click();button.remove();});await pause(200);
 assert.equal(r.fixture.state.calls.filter(row=>row.path.endsWith('/approve')).length,before,'a stale control cannot send the current different request');assert.equal(r.fixture.state.completed,0);await r.click('send-request');await r.state('request-done');assert.equal(r.fixture.state.completed,1);assert.deepEqual(r.errors,[]);
});
for(const engine of ['chromium','webkit'])test(`a confirmed signature survives a failed following summary read in ${engine}`,{timeout:60000},async t=>{
 const r=await setup(t,engine);await r.link();await r.approval('answered-before-read-failure');r.peer.choose({request:'silent'});await r.click('send-request');await r.state('request-phone');await until(()=>r.peer.trace.filter(e=>e.kind==='request').length>=2,'message published');
 await r.page.route('**/wallet/accounts',route=>route.fulfill({status:503,body:'Unavailable'}));await r.peer.answer('sign');await r.state('request-done');await pause(200);await r.state('request-done');assert.equal(r.fixture.state.completed,1);await r.capture('known-result-with-summary-error');assert.deepEqual(r.errors,[]);
});
for(const engine of ['chromium','webkit'])test(`idle background read failure recovers without replacing wallet facts in ${engine}`,{timeout:60000},async t=>{
 const r=await setup(t,engine);await r.link();await r.page.route('**/internet',route=>route.fulfill({status:503,body:'Unavailable'}));await r.page.route('**/wallet/accounts',route=>route.fulfill({status:503,body:'Unavailable'}));await r.refresh();await r.state('linked');
 await r.peer.changeAccount();await r.state('saved-unlinked');assert.match(await r.frame.locator('main').innerText(),new RegExp(r.peer.address.slice(0,6),'i'),'wallet selection refreshes even while the Home read fails');
 await r.page.unroute('**/internet');await r.page.unroute('**/wallet/accounts');await r.refresh();await r.state('saved-unlinked');await r.capture('background-read-recovered');assert.deepEqual(r.errors,[]);
});
for(const engine of ['chromium','webkit'])test(`unsent request returns to Send after refusal and later Allow in ${engine}`,{timeout:60000},async t=>{
 const r=await setup(t,engine);await r.link();await r.approval('access-return');r.fixture.setPermission('off');await r.click('send-request');await r.state('request-internet-pending');r.fixture.setPermission('refused');await r.refresh();await r.state('internet-refused');r.fixture.setPermission('granted');await r.refresh();await r.state('request-waiting');await r.capture('unsent-request-after-access-return');
 await r.click('send-request');await r.state('qr-shown');await r.pair();await r.state('request-done');assert.equal(r.fixture.state.completed,1);assert.deepEqual(r.errors,[]);
});
for(const engine of ['chromium','webkit'])test(`a no-op wallet update keeps timeout recovery and a known hash in ${engine}`,{timeout:60000},async t=>{
 const r=await setup(t,engine);r.peer.choose({request:'silent'});await r.qr();await r.pair();await r.state('link-wait');await until(()=>r.peer.trace.some(e=>e.kind==='request'),'proof published');await r.frame.evaluate(()=>{for(const fn of window.longTimers)fn();});await r.state('link-timeout');await r.peer.updateSession();await r.refresh();await r.state('link-timeout');await r.peer.answer('reject');await r.click('check-access');await r.state('saved-unlinked');r.peer.choose({request:'sign'});await r.click('finish');await r.state('linked');
 r.fixture.state.completeFails=true;await r.approval('retained-hash',{intent:'transaction_intent'});await r.click('send-request');await r.state('transaction-wallet-error');const hash=r.peer.lastTransactionHash;await r.peer.updateSession();await r.refresh();await r.state('transaction-wallet-error');assert.ok((await r.frame.locator('main').innerText()).includes(hash));await r.peer.deleteConnection();await r.state('transaction-wallet-removed');assert.ok((await r.frame.locator('main').innerText()).includes(hash));await r.capture('known-hash-after-wallet-removed');assert.deepEqual(r.errors,[]);
});
for(const engine of ['chromium','webkit'])test(`failed Disconnect has a working fresh connection recovery in ${engine}`,{timeout:60000},async t=>{
 const r=await setup(t,engine);await r.link();r.fixture.state.deleteFails=true;await r.click('disconnect');await r.state('link-error');await r.capture('disconnect-error');r.fixture.state.deleteFails=false;await r.link();assert.equal(r.fixture.state.verified,2);assert.deepEqual(r.errors,[]);
});
for(const engine of ['chromium','webkit'])test(`a cached grant never repeats the saved permission action in ${engine}`,{timeout:60000},async t=>{
 const r=await setup(t,engine);await r.link();await r.approval('fresh-grant');r.fixture.setPermission('off');await r.page.route('**/internet',route=>route.request().method()==='GET'?route.fulfill({status:503,body:'Unavailable'}):route.continue());
 const posts=()=>r.fixture.state.calls.filter(row=>row.path.endsWith('/internet')&&row.method==='POST').length;
 await r.click('send-request');await r.state('request-internet-pending');const once=posts();await r.refresh();await r.refresh();assert.equal(posts(),once,'a cached old grant cannot trigger another permission POST');assert.equal(r.fixture.state.completed,0);
 r.fixture.setPermission('granted');await r.page.unroute('**/internet');await r.refresh();await r.state('qr-shown');await r.pair();await r.state('request-done');assert.equal(r.fixture.state.completed,1);assert.deepEqual(r.errors,[]);
});
for(const engine of ['chromium','webkit'])test(`clipboard refusal pending answer and retry stay in the shared view in ${engine}`,{timeout:60000},async t=>{
 const r=await setup(t,engine);await r.qr();await r.page.evaluate(()=>window.clipboardAllowed=false);await r.click('copy-link');await r.frame.getByText('Home could not copy the connection link. Select Copy link to try again.',{exact:true}).waitFor();assert.ok(await r.page.evaluate(()=>window.copied===''),'denied copy leaves the fixture clipboard empty');await r.capture('qr-copy-denied');
 await r.page.evaluate(()=>{window.clipboardAllowed=true;window.holdClipboard=true;});await r.click('copy-link');assert.equal(await r.frame.locator('[data-action=copy-link]').isDisabled(),true);await r.capture('qr-copy-pending');await r.page.evaluate(()=>{window.holdClipboard=false;for(const reply of window.clipboardReplies.splice(0))reply();});await r.frame.getByText('Connection link copied. Open it in your wallet app.',{exact:true}).waitFor();await r.peer.pair(await r.page.evaluate(()=>window.copied));await r.state('linked');
 const copied=await r.page.evaluate(()=>window.copied);await r.page.evaluate(()=>window.clipboardAllowed=false);await r.click('copy-address');await r.frame.getByText('Home could not copy the address. Select Copy to try again.',{exact:true}).waitFor();assert.ok(await r.page.evaluate(copied=>window.copied===copied,copied),'denied copy preserves the fixture clipboard');await r.capture('address-copy-denied');await r.page.evaluate(()=>window.clipboardAllowed=true);await r.click('copy-address');await r.frame.getByText('Address copied.',{exact:true}).waitFor();assert.equal(await r.page.evaluate(()=>window.copied),r.peer.address);await r.capture('address-copied');assert.deepEqual(r.errors,[]);
});
for(const engine of ['chromium','webkit'])test(`initial off picker and unsent connection-loss scenes recover in ${engine}`,{timeout:60000},async t=>{
 const r=await setup(t,engine);r.fixture.setPermission('off');await r.refresh();await r.state('nothing-saved');await r.capture('nothing-saved');r.fixture.setPermission('granted');await r.refresh();await r.state('internet-ready');await r.link();
 await r.approval('unsent');r.fixture.state.approvals.push({...r.fixture.state.approvals[0],request_id:'other',reason:'Another waiting request'});await r.refresh();await r.click('view-requests');await r.state('request-list');await r.capture('request-list');await r.frame.locator('[data-focus-key="select-request:unsent"]').click();r.fixture.state.approvals=r.fixture.state.approvals.filter(row=>row.request_id==='unsent');await r.refresh();await r.state('request-waiting');
 await r.peer.deleteConnection();await r.state('request-wallet-removed');await r.capture('request-wallet-removed');assert.equal(r.fixture.state.approvals[0].status,'pending');await r.click('start-over');await r.state('qr-shown');await r.pair();await r.state('request-waiting');
 await until(()=>r.fixture.pendingDeliveryAcks()===0,'Runtime acknowledged prior wallet responses');await r.page.waitForLoadState('networkidle');await r.page.goto('about:blank');const sessions=Object.entries(r.fixture.state.keys).find(([key])=>key.endsWith('//session'))?.[1];assert.ok(Array.isArray(sessions)&&sessions.length,'real SDK persisted its session');for(const session of sessions)session.expiry=Math.floor(Date.now()/1000)-1;
 const proposals=r.peer.trace.filter(row=>row.kind==='proposal').length;await r.reopen();await r.state('request-connection-expired');await r.capture('request-connection-expired');assert.equal(r.peer.trace.filter(row=>row.kind==='proposal').length,proposals,'opening an expired saved session sends no new proposal');await r.click('start-over');await r.state('qr-shown');await r.pair();await r.state('request-waiting');await r.click('send-request');await r.state('request-done');assert.equal(r.fixture.state.completed,1);await r.capture('recovered-after-unsent-session-expiry');assert.deepEqual(r.errors,[]);
});
for(const engine of ['chromium','webkit'])test(`an invalid Home handoff sends nothing to the phone in ${engine}`,{timeout:60000},async t=>{
 const r=await setup(t,engine);await r.link();await r.approval('invalid-home-handoff');const before=r.peer.trace.filter(row=>row.kind==='request').length;r.fixture.state.invalidSignatureHandoff=true;await r.click('send-request');await r.state('request-unavailable');assert.equal(r.peer.trace.filter(row=>row.kind==='request').length,before,'invalid handoff never opens a signing prompt');assert.equal(r.fixture.state.completed,0);await r.capture('home-handoff-unavailable');await r.peer.deleteConnection();await r.state('request-unavailable');await r.capture('home-handoff-unavailable-after-removal');assert.deepEqual(r.errors,[]);
});

for(const engine of ['chromium','webkit'])test(`an expired Home-approved transaction reopens as result unknown in ${engine}`,{timeout:60000},async t=>{
 const r=await setup(t,engine);await r.link();await r.approval('already-sent-expired',{intent:'transaction_intent'});r.peer.choose({request:'silent'});await r.click('send-request');await r.state('transaction-phone');await until(()=>r.peer.trace.filter(row=>row.kind==='request').length>=2,'phone holds the actual transaction');assert.equal(r.fixture.state.approvals[0].status,'approved');
 await r.page.goto('about:blank');r.fixture.state.approvals[0].expires_at=Math.floor(Date.now()/1000)-1;await r.reopen();await r.state('transaction-reopened');assert.equal(await r.frame.locator('[data-action=send-request],[data-action=start-over]').count(),0);await r.capture('expired-approved-transaction-reopened');
 await r.peer.deleteConnection();await r.state('transaction-wallet-removed');await r.capture('expired-approved-transaction-wallet-removed');assert.equal(r.fixture.state.completed,0);assert.equal(r.peer.trace.filter(row=>row.kind==='request').length,2,'reopen and deletion send no second transaction');assert.deepEqual(r.errors,[]);
});
