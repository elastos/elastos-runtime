// Visual fixtures use the real window, client, adapter, locked SDK and signing peer.
// Installed acceptance and real timeout durations are recorded separately.
import {mkdir,writeFile,copyFile} from 'node:fs/promises';
import assert from 'node:assert/strict';
import {windowFixture} from './lib/walletconnect-phone-window-fixture.mjs';
import {scriptedPhoneWallet} from './lib/walletconnect-phone-wallet.mjs';
import {importProductSmokePlaywright,productSmokeLaunchOptions} from './product-smoke-browser.mjs';
const output=process.env.WALLETCONNECT_SCREENSHOTS;assert.ok(output,'Set WALLETCONNECT_SCREENSHOTS to the output directory');await mkdir(output,{recursive:true});
const {chromium}=await importProductSmokePlaywright();const browser=await chromium.launch({headless:true,...productSmokeLaunchOptions()});
const records=[];let flow=0,current;
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
async function until(fn,label,ms=25000){const end=Date.now()+ms;while(!await fn()){if(Date.now()>end)throw new Error(label);await sleep(50);}}
async function setup(){
 const fixture=await windowFixture(),peer=await scriptedPhoneWallet({projectId:'fixture-project',relayUrl:fixture.origin.replace('http','ws')});
 const context=await browser.newContext({viewport:{width:1280,height:900}}),page=await context.newPage();
 await page.route('**/*',r=>new URL(r.request().url()).origin===fixture.origin?r.continue():r.abort());
 await page.addInitScript(()=>{window.longTimers=[];const native=window.setTimeout;window.setTimeout=(fn,ms,...args)=>{if(ms===180000)window.qrDeadline=fn;if(ms>=290000&&ms<=610000)window.longTimers.push(fn);return native(fn,ms,...args);};});
 const r={fixture,peer,context,page,get frame(){return page.frames().find(f=>f.url().includes('/apps/wallet-walletconnect/'));},async close(){await peer.stop();await context.close();await fixture.stop();}};
 await page.goto(fixture.origin);await r.frame.locator('#wallet-requests').getByText('No approval requests.',{exact:true}).waitFor();return r;
}
async function capture(r,name,why,next,isFlow=false){
 const frame=r.frame,files=[];
 for(const width of [1280,390]){await r.page.setViewportSize({width,height:width===390?844:900});for(const theme of ['dark','light']){
  await frame.evaluate(theme=>document.documentElement.dataset.elTheme=theme,theme);await sleep(70);
  const file=`${name}-${theme}-${width}.png`;await r.page.screenshot({path:output+'/'+file});files.push(file);
 }}
 const text=await frame.locator('body').innerText(),controls=await frame.locator('button:visible').evaluateAll(nodes=>nodes.map(n=>({text:n.textContent.trim(),disabled:n.disabled})));
 if(isFlow){flow++;await copyFile(output+'/'+files[0],output+`/flow-${flow}.png`);}
 records.push({state:name,why,next,text,controls,files,flow:isFlow?flow:undefined});await writeFile(output+'/states.json',JSON.stringify(records,null,2));console.log('captured '+name);
}
async function refresh(r){await r.frame.evaluate(()=>window.dispatchEvent(new Event('focus')));await sleep(150);}
async function qr(r){await r.frame.locator('#wallet-connect').click();await r.frame.locator('dialog[open] canvas').waitFor({timeout:25000});}
async function copyLink(r){await r.frame.getByRole('button',{name:'Copy connection link',exact:true}).click();await r.frame.getByText('Connection link copied. Open it in your wallet app.',{exact:true}).waitFor();return r.page.evaluate(()=>window.copied);}
async function pair(r){await r.peer.pair(await copyLink(r));}
async function linked(r){await r.frame.locator('#wallet-status').filter({hasText:'Approval method added.'}).waitFor({timeout:25000});await r.frame.locator('#wallet-state').filter({hasText:'1 linked'}).waitFor({timeout:25000});}
async function waiting(r,before){await until(()=>r.peer.trace.filter(e=>e.kind==='request').length>before,'phone request');}
async function approval(r,id,intent='credential'){
 r.fixture.state.approvals=[{request_id:id,status:'pending',address:r.peer.address,chain_namespace:'eip155:8453',intent,proof_type:'siwe',connector_id:'wallet-walletconnect',reason:'Review this test message',expires_at:Math.floor(Date.now()/1000)+600}];
 await refresh(r);await r.frame.getByRole('button',{name:'Review',exact:true}).waitFor();
}
async function reconnect(r){r.peer.choose({proposal:'approve',request:'sign',chains:['eip155:8453']});await qr(r);await pair(r);await linked(r);}
try{
 const r=current=await setup();
 await capture(r,'ready','Home has no saved phone session.','Connect wallet starts a new QR.',true);
 r.fixture.state.permission='off';await r.frame.locator('#wallet-connect').click();await r.frame.locator('#wallet-status').filter({hasText:'The Home owner can allow it in Inbox.'}).waitFor();
 await capture(r,'permission-requested','The owner approval is pending.','Allow in Inbox continues once; Cancel stops the saved action.',true);
 r.fixture.setPermission('granted');await refresh(r);await r.frame.locator('#wallet-status').filter({hasText:'Preparing a new connection.'}).waitFor({timeout:5000});
 await capture(r,'preparing','A fresh connection is starting.','Cancel stops this attempt.',true);
 await r.frame.locator('dialog[open] canvas').waitFor({timeout:20000});
 await capture(r,'qr','The SDK issued a live pairing link.','Scan it or Copy connection link; Cancel closes it.',true);
 await copyLink(r);await capture(r,'qr-copied','Home Clipboard accepted the link write.','Open the copied link in the wallet app.',true);
 r.peer.choose({request:'silent'});await r.peer.pair(await r.page.evaluate(()=>window.copied));await waiting(r,0);
 await capture(r,'linking-wait','The Base-only session is approved and the ownership signature is pending.','Sign in the phone app or Cancel.',true);
 await r.peer.answer('sign');await linked(r);await capture(r,'linked-base','Runtime fixture verified the real ownership signature on Base.','Disconnect or Review a pending request.',true);
 await approval(r,'screen-sign');await capture(r,'approval-ready','A fresh message approval is pending.','Review sends this exact request to the phone.',true);
 let before=r.peer.trace.filter(e=>e.kind==='request').length;r.peer.choose({request:'silent'});await r.frame.getByRole('button',{name:'Review',exact:true}).click();await waiting(r,before);
 await capture(r,'approval-wait','The handoff consumed this request and the phone is waiting for a decision.','Sign on the phone or Cancel.',true);
 await r.peer.answer('sign');await r.frame.locator('#wallet-status').filter({hasText:'Request signed.'}).waitFor();await capture(r,'approval-signed','The fixture verified the real approval signature.','A new request can be reviewed.',true);
 await approval(r,'screen-decline');r.peer.choose({request:'reject'});await r.frame.getByRole('button',{name:'Review',exact:true}).click();await r.frame.locator('#wallet-status').filter({hasText:'declined this signature request'}).waitFor();
 await capture(r,'signature-declined','The peer returned an encrypted rejection; the consumed request left the list.','Ask the app for a new request.');
 await r.frame.getByRole('button',{name:'Copy',exact:true}).click();await r.frame.locator('#wallet-status').filter({hasText:'Address copied.'}).waitFor();await capture(r,'address-copied','Home Clipboard accepted this public test address.','Review a new request or Disconnect.');
 r.fixture.state.accounts.push({address:r.peer.address,chain_namespace:'eip155:1',connector_id:'wallet-walletconnect',proof_type:'siwe'});
 r.fixture.state.approvals=[{request_id:'other-network',status:'pending',address:r.peer.address,chain_namespace:'eip155:1',intent:'credential',proof_type:'siwe',connector_id:'wallet-walletconnect',reason:'This request uses the earlier linked Ethereum account',expires_at:Math.floor(Date.now()/1000)+600}];
 await refresh(r);await r.frame.getByRole('button',{name:'Review',exact:true}).click();await r.frame.locator('#wallet-status').filter({hasText:'no approved account on Ethereum'}).waitFor();await capture(r,'another-network-needed','The saved Base session does not approve the request network; handoff remains pending.','Connect wallet creates a QR to choose the requested account and network.');
 r.fixture.state.approvals=[];await r.frame.locator('#wallet-connect').click();await r.frame.locator('dialog[open]').waitFor();r.peer.choose({proposal:'approve',request:'sign',chains:['eip155:1']});await pair(r);await linked(r);
 await r.frame.locator('#wallet-disconnect').click();await r.frame.locator('#wallet-status').filter({hasText:'Disconnected.'}).waitFor();await reconnect(r);
 await r.frame.locator('#wallet-disconnect').click();await r.frame.locator('#wallet-status').filter({hasText:'Disconnected.'}).waitFor();await capture(r,'disconnected','The SDK stopped and storage deletion completed; the linked account remains.','Connect wallet gives a new QR.');
 await reconnect(r);r.fixture.setPermission('revoked');await refresh(r);await r.frame.locator('#wallet-status').filter({hasText:'turned off'}).waitFor();await capture(r,'access-off','The owner revoked internet access and the phone session was cleared.','Connect wallet asks the owner again.');
 r.fixture.setPermission('granted');await refresh(r);await r.frame.locator('#wallet-status').filter({hasText:'Internet access is allowed.'}).waitFor();await capture(r,'access-allowed','The owner restored access after an ending; no action is pending.','Connect wallet starts one new QR.');
 r.fixture.state.accounts=[];await refresh(r);r.peer.choose({request:'reject'});await qr(r);await pair(r);await r.frame.locator('#wallet-status').filter({hasText:'declined the ownership signature'}).waitFor();
 await capture(r,'link-signature-declined','The peer approved Base but declined ownership.','Finish linking retries; Connect wallet starts over.');
 await r.page.reload();await r.frame.getByRole('button',{name:'Finish linking',exact:true}).waitFor({timeout:20000});await capture(r,'saved-unlinked','The SDK restored a live Base-only session with no linked account.','Open the named wallet app and Finish linking, or Connect wallet for a new QR.');
 before=r.peer.trace.filter(e=>e.kind==='request').length;r.peer.choose({request:'silent'});await r.frame.getByRole('button',{name:'Finish linking',exact:true}).click();await waiting(r,before);await capture(r,'finish-linking-wait','Resume reused the session only after the person selected Finish linking.','Sign the new linking message or Cancel.');
 await r.frame.getByRole('button',{name:'Cancel',exact:true}).click();await r.frame.locator('#wallet-status').filter({hasText:'Home stopped waiting'}).waitFor();await capture(r,'phone-wait-cancelled','Local waiting ended and the saved session was cleared.','Connect wallet works immediately.');
 r.peer.choose({proposal:'reject'});await qr(r);await pair(r);await r.frame.locator('#wallet-status').filter({hasText:'declined the connection request'}).waitFor();await capture(r,'connection-declined','The wallet rejected the proposal.','Connect wallet creates another QR.');
 await qr(r);await r.frame.evaluate(()=>window.qrDeadline());await r.frame.locator('#wallet-status').filter({hasText:'The QR code expired.'}).waitFor();await capture(r,'qr-expired','The fixture invoked the actual adapter QR deadline callback.','Connect wallet creates a new QR.');
 await qr(r);await r.frame.getByRole('button',{name:'Cancel',exact:true}).click();await r.frame.locator('#wallet-status').filter({hasText:'Wallet connection cancelled.'}).waitFor();await capture(r,'qr-cancelled','The person cancelled pairing; the dialog was removed synchronously.','Connect wallet creates a new QR.');
 await reconnect(r);await r.peer.deleteConnection();await r.frame.locator('#wallet-status').filter({hasText:'removed this connection'}).waitFor({timeout:20000});await capture(r,'wallet-removed','The real wallet peer sent session_delete.','Connect wallet gives a new QR.');
 await r.close();current=undefined;
 const guest=current=await setup();guest.fixture.state.permission='off';guest.fixture.state.guest=true;await guest.frame.locator('#wallet-connect').click();await guest.frame.locator('#wallet-status').filter({hasText:'The Home owner can allow WalletConnect internet access in Inbox.'}).waitFor();await capture(guest,'guest-owner-needed','Runtime fixture refused the owner consent mutation for this guest.','The owner allows access; the open window then restores Connect.');await guest.close();current=undefined;
 const expired=current=await setup();expired.fixture.state.expiredLaunch=true;await refresh(expired);await expired.frame.locator('#wallet-status').filter({hasText:'This wallet window expired.'}).waitFor();await capture(expired,'window-expired','The verified-launch route returned 403; wallet actions are hidden.','Close the window and reopen WalletConnect.');await expired.close();current=undefined;
 console.log(`screens ready: ${records.length} states, ${records.length*4} theme/width PNGs, ${flow} flow PNGs`);
}catch(error){console.log('capture failed: '+(records.at(-1)?.state||'start')+' '+error.name);process.exitCode=1;}
finally{await current?.close().catch(()=>{});await browser.close();}
