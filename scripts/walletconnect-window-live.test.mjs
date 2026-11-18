import test from 'node:test';
import {createHash} from 'node:crypto';
import assert from 'node:assert/strict';
import {mkdir,writeFile,readFile} from 'node:fs/promises';
import {windowFixture} from './lib/walletconnect-phone-window-fixture.mjs';
import {scriptedPhoneWallet} from './lib/walletconnect-phone-wallet.mjs';
import {importProductSmokePlaywright,productSmokeLaunchOptions} from './product-smoke-browser.mjs';
const output=process.env.WALLETCONNECT_WINDOW_SCREENS;
const pause=ms=>new Promise(r=>setTimeout(r,ms));
async function until(fn,label,ms=20000){const end=Date.now()+ms;while(!await fn()){assert.ok(Date.now()<end,label);await pause(25);}}
async function setup(t,engine,mutation){
 const fixture=await windowFixture(),peer=await scriptedPhoneWallet({projectId:'fixture-project',relayUrl:fixture.origin.replace('http','ws')});
 const engines=await importProductSmokePlaywright(),browser=await engines[engine].launch({headless:true,...(engine==='chromium'?productSmokeLaunchOptions():{})});
 const page=await browser.newPage({viewport:{width:480,height:560}}),errors=[];
 page.on('pageerror',error=>errors.push(error.message));
 await page.route('**/*',r=>new URL(r.request().url()).origin===fixture.origin?r.continue():r.abort());
 if(mutation)await page.route(`**/${mutation.file}*`,async route=>{
  const source=await readFile(new URL(`../capsules/wallet-walletconnect/browser/${mutation.file}`,import.meta.url),'utf8');
  assert.ok(source.includes(mutation.from),'mutation hits current source');
  await route.fulfill({contentType:'text/javascript',body:source.replace(mutation.from,mutation.to)});
 });
 await page.addInitScript(()=>{window.longTimers=[];const native=setTimeout;window.setTimeout=(fn,ms,...args)=>{if(ms===180000)window.qrDeadline=fn;if(ms>=290000&&ms<=610000)window.longTimers.push(fn);return native(fn,ms,...args);};});
 t.after(async()=>{await peer.stop();await browser.close();await fixture.stop();});
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
   const before=await frame.evaluate(()=>({top:document.querySelector('main').scrollTop,key:document.activeElement?.dataset.focusKey,focus:document.activeElement?.dataset.focus}));
   const wanted=await frame.locator('button:visible:enabled').evaluateAll(nodes=>nodes.map(node=>node.dataset.focusKey));
   await frame.locator('body').evaluate(body=>{body.tabIndex=-1;body.focus();});
   const reached=new Set();
   for(let i=0;i<wanted.length*3+3;i++){
    await page.keyboard.press('Tab');
    const focused=await frame.evaluate(()=>{const node=document.activeElement;if(node?.tagName!=='BUTTON')return null;const r=node.getBoundingClientRect();return {key:node.dataset.focusKey,inside:r.left>=0&&r.right<=innerWidth+1&&r.top>=0&&r.bottom<=innerHeight+1};});
    if(focused){reached.add(focused.key);assert.equal(focused.inside,true,`${name}: keyboard control fits the window`);}
   }
   for(const key of wanted)assert.ok(reached.has(key),`${name}: ${key} is reachable with Tab`);
   await frame.evaluate(before=>{document.querySelector('main').scrollTop=before.top;const nodes=[...document.querySelectorAll('[data-focus-key]')];const node=nodes.find(node=>node.dataset.focusKey===before.key)||[...document.querySelectorAll('[data-focus]')].find(node=>node.dataset.focus===before.focus);node?.focus({preventScroll:true});},before);
   await pause(40);await page.screenshot({path:`${output}/${engine}/${name}-${theme}.png`});
   const result=await frame.locator('main').evaluate(main=>({state:main.dataset.state,text:main.innerText,actions:[...main.querySelectorAll('button')].map(b=>({action:b.dataset.action,text:b.innerText,disabled:b.disabled})),width:main.scrollWidth,viewport:innerWidth,bodyScroll:document.body.scrollHeight>innerHeight}));
   assert.ok(result.width<=result.viewport+1,`${name}: horizontal fit`);assert.equal(result.bodyScroll,false,`${name}: single scroll owner`);
   records.push({name,theme,...result,sourceHashes});
  }
  await writeFile(`${output}/${engine}/${name}.json`,JSON.stringify(records.filter(row=>row.name===name),null,2));
  await writeFile(`${output}/${engine}/states.json`,JSON.stringify(records,null,2));
 }
 async function qr(){await click('connect');await state('qr-shown');assert.equal(await frame.locator('dialog').count(),0,'no old dialog');assert.equal(await frame.locator('main img.connection-qr').count(),1);}
 async function pair(){await click('copy-link');await until(()=>page.evaluate(()=>window.copied.startsWith('wc:')),'clipboard gets pairing URI');await peer.pair(await page.evaluate(()=>window.copied));}
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
 if(phase==='ownership'||phase==='signature'){
  if(event!=='removed')await r.peer.answer('sign').catch(()=>{});
  await pause(150);assert.deepEqual({verified:r.fixture.state.verified,completed:r.fixture.state.completed},before,'old answer cannot complete after wallet change');
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
 const before={verified:r.fixture.state.verified,completed:r.fixture.state.completed};r.fixture.setRelayAvailable(false);await r.frame.getByText(/WalletConnect is reconnecting/).waitFor({timeout:15000});await r.capture(`relay-dropped-${phase}`);
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
 await r.state(phase==='result'?'request-done':phase==='signature'?'request-connection-expired':'connection-expired');await r.capture(`session-expired-${phase}`);
 assert.deepEqual({verified:r.fixture.state.verified,completed:r.fixture.state.completed},before,'expiry records no proof or extra signature');
 if(phase==='result')assert.match(await r.frame.locator('main').innerText(),/Message signed.*This wallet connection expired/s);
});
