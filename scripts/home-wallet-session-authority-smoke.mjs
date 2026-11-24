// Real installed Runtime regression. Uses disposable Home credentials, never API fixtures.
import assert from 'node:assert/strict';
import {readFile,writeFile,mkdir} from 'node:fs/promises';
import {requireProductSmokePlaywright} from './product-smoke-browser.mjs';
const {chromium}=requireProductSmokePlaywright();
const origin=process.env.HOME_AUTH_ORIGIN;
const credentialFile=process.env.HOME_AUTH_PASSKEY;
const output=process.env.HOME_AUTH_PROOF;
assert(origin && credentialFile && output,'Set HOME_AUTH_ORIGIN, HOME_AUTH_PASSKEY and HOME_AUTH_PROOF for an isolated Home');
assert([8091,8092,8093,8095,8098,8084].includes(Number(new URL(origin).port)),'Use an agent copy port');
await mkdir(output,{recursive:true});
const browser=await chromium.launch({headless:true, ...(process.env.HOME_AUTH_CHROMIUM?{executablePath:process.env.HOME_AUTH_CHROMIUM}:{})});
const traffic=[];let current;
async function windowFor(credentials,label){
 const context=await browser.newContext({viewport:{width:1440,height:900}}),page=await context.newPage();page.setDefaultTimeout(15000);
 const cdp=await context.newCDPSession(page);await cdp.send('WebAuthn.enable');
 const {authenticatorId}=await cdp.send('WebAuthn.addVirtualAuthenticator',{options:{protocol:'ctap2',transport:'internal',hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true}});
 for(const credential of credentials)await cdp.send('WebAuthn.addCredential',{authenticatorId,credential});
 page.on('response',r=>{const u=new URL(r.url());if(u.origin===origin&&/auth|system\/summary/.test(u.pathname))traffic.push({label,path:u.pathname,status:r.status(),frame:r.frame().url().split('?')[0]});});
 await page.goto(origin+'/home/');await page.locator('#home-unlock-person').click();await page.waitForFunction(()=>document.body.dataset.homeAuthority==='signed'&&document.body.dataset.homeStatus==='ready');
 const frame=async target=>{for(let n=0;n<150;n++){for(const f of page.frames().filter(f=>f.url().includes('/apps/'+target+'/')).reverse())if(await(await f.frameElement()).isVisible())return f;await page.waitForTimeout(100);}throw Error('Missing '+target);};
 const system=async()=>{const gui=await frame('home-gui');if(await gui.locator('#setup-sheet').isVisible())await gui.locator('#setup-sheet-close').click();await gui.locator('#toolbar-home').click();await gui.locator('#identity-menu-system').click();const sys=await frame('system');await sys.getByRole('button',{name:'Accounts',exact:true}).click();return sys;};
 return {page,context,cdp,authenticatorId,system,frame};
}
try{
 const saved=JSON.parse(await readFile(credentialFile,'utf8'));
 current=await windowFor(Array.isArray(saved)?saved:saved.credentials,'retained');
 let sys=await current.system();
 if(process.env.HOME_AUTH_CASE!=='revocation'){
  const start=traffic.length;await sys.getByRole('button',{name:'Add wallet',exact:true}).click();
  await Promise.race([current.page.locator('.signin-dialog').getByText('New wallet',{exact:true}).waitFor({timeout:18000}),current.frame('wallet')]);
  const reads=traffic.slice(start).filter(r=>r.path==='/api/apps/system/summary');
  assert(reads.some(r=>r.status===200&&r.frame.includes('/apps/system/')),'System owns the actual HTTP summary read');
  assert(!reads.some(r=>r.frame.includes('/home/')),'Home does not call the System route');
  await current.page.screenshot({path:output+'/wallet-picker.png'});
  if(await current.page.locator('.signin-dialog').isVisible())await current.page.locator('.signin-dialog').getByRole('button',{name:'Cancel',exact:true}).click();
  sys=await current.system();
  console.log('PASS real System-origin Add wallet HTTP route');
 }
 if(process.env.HOME_AUTH_CASE!=='wallet'){
  let spareId;
  current.page.on('response',async response=>{if(new URL(response.url()).pathname==='/api/auth/passkey-step-up/complete'&&response.ok()&&!spareId){await current.cdp.send('WebAuthn.setAutomaticPresenceSimulation',{authenticatorId:current.authenticatorId,enabled:false});spareId=(await current.cdp.send('WebAuthn.addVirtualAuthenticator',{options:{protocol:'ctap2',transport:'usb',hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true}})).authenticatorId;}});
  await sys.getByRole('button',{name:'Add passkey',exact:true}).click();
  await sys.locator('[data-passkey-revoke]').last().waitFor();
  for(let n=0;n<100&&!spareId;n++)await current.page.waitForTimeout(100);
  let spare=[];for(let n=0;n<100;n++){spare=(await current.cdp.send('WebAuthn.getCredentials',{authenticatorId:spareId})).credentials;if(spare.length)break;await current.page.waitForTimeout(100);}
  assert(spare.length,'new real spare passkey');
  await writeFile(credentialFile+'.spare',JSON.stringify(spare),{mode:0o600});
  await sys.getByText('Another device or security key',{exact:true}).last().waitFor();
  const revoked=await windowFor(spare,'revoked');await revoked.system();
  await current.cdp.send('WebAuthn.setAutomaticPresenceSimulation',{authenticatorId:current.authenticatorId,enabled:true});
  const remove=sys.locator('[data-passkey-revoke]').last();await remove.click();await sys.locator('#passkey-remove-dialog button[value="remove"]').click();
  for(let n=0;n<100&&!traffic.some(r=>r.path.endsWith('/revoke')&&r.status===200);n++)await current.page.waitForTimeout(100);
  assert(traffic.some(r=>r.path.endsWith('/revoke')&&r.status===200),'real server revocation accepted');
  const started=Date.now();
  if(process.env.HOME_AUTH_REVOCATION_IDLE!=='1'){const revokedSystem=await revoked.system();await revokedSystem.getByRole('button',{name:'Add passkey',exact:true}).click();}
  await revoked.page.waitForFunction(()=>document.body.dataset.homeAuthority==='unsigned'&&!document.querySelector('#home-unlock').hidden,null,{timeout:15000});
  assert(traffic.some(r=>r.label==='revoked'&&[401,403].includes(r.status)&&r.path.includes('/auth/')),'Runtime denies revoked session');
  assert.equal(await current.page.getAttribute('body','data-home-authority'),'signed');
  await writeFile(output+'/revocation-timing.json',JSON.stringify({idle:process.env.HOME_AUTH_REVOCATION_IDLE==='1',elapsedMs:Date.now()-started}));
  await revoked.page.bringToFront();
  await revoked.page.locator('#home-unlock-person').waitFor({state:'visible'});
  await revoked.page.waitForFunction(()=>['#home-unlock','.home-unlock-account','.home-unlock-clock'].every(selector=>getComputedStyle(document.querySelector(selector)).opacity==='1'));
  await revoked.page.screenshot({path:output+'/revoked-window-signin.png'});await current.page.screenshot({path:output+'/retained-window.png'});
  console.log('PASS real passkey revocation signs the removed window out; retained window stays signed in');
 }
}catch(error){
 if(current)await current.page.screenshot({path:output+'/failure.png'});
 throw error;
}finally{
 if(current){const retained=(await current.cdp.send('WebAuthn.getCredentials',{authenticatorId:current.authenticatorId})).credentials;await writeFile(credentialFile,JSON.stringify(retained),{mode:0o600});}
 await writeFile(output+'/http-evidence.json',JSON.stringify(traffic,null,2));await browser.close();
}
