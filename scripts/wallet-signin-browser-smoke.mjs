#!/usr/bin/env node
import assert from 'node:assert/strict';
import {mkdir,writeFile,readFile} from 'node:fs/promises';
import {join,basename} from 'node:path';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {requireProductSmokePlaywright} from './product-smoke-browser.mjs';
import {signinFixture,installSigninProviders,sampleMethod,evmAddress,bitcoinAddress,walletconnectAddress} from './lib/wallet-signin-fixture.mjs';
const output=process.env.SIGNIN_SCREENSHOT_DIR;
if(!output)throw new Error('Set SIGNIN_SCREENSHOT_DIR to the screens evidence directory.');
await mkdir(output,{recursive:true});
const playwright=requireProductSmokePlaywright(),pictures=[],checks=[],browserVersions={};let passed=false;
const widths=process.env.SIGNIN_WIDTH?[Number(process.env.SIGNIN_WIDTH)]:[1280,390];
const themes=process.env.SIGNIN_THEME?[process.env.SIGNIN_THEME]:['light','dark'];
async function exercise(engine,width,theme) {
  const fixture=await signinFixture(),browser=await playwright[engine].launch({headless:true});fixture.state.theme=theme;
  browserVersions[engine]=browser.version();
  const context=await browser.newContext({viewport:{width,height:width===390?844:900},locale:'en-US',timezoneId:'America/Panama',reducedMotion:'reduce',colorScheme:theme});
  await context.addInitScript(installSigninProviders,{evmAddress,bitcoinAddress,theme});
  await context.addInitScript(()=>addEventListener('message',event=>{if(event.source===top&&event.data?.type==='home:wallet-connector-effect-result'&&typeof event.data.error==='string')window.fixtureConnectorError=event.data.error;}));
  const page=await context.newPage(),errors=[],outside=[],lostReplies=new Set();
  page.on('pageerror',error=>errors.push(error.message));
  await context.route('**/*',async route=>{
    const url=new URL(route.request().url());if(url.origin!==fixture.origin){outside.push(url.origin);return route.abort();}
    if(fixture.state.scenario==='unknown'&&url.pathname.endsWith('/complete')&&url.pathname.includes('/auth/wallet')) {
      const id=route.request().postDataJSON().ceremony_id;if(!lostReplies.has(id)){lostReplies.add(id);await route.fetch();return route.abort('failed');}
    }
    return route.continue();
  });
  const state=stage=>page.locator(`.signin-dialog[data-state="${stage}"]`).waitFor({timeout:15000});
  const dialog=()=>page.locator('.signin-dialog');
  const cancel=async()=>{await dialog().getByRole('button',{name:'Cancel',exact:true}).click();await dialog().waitFor({state:'detached'});};
  async function home() {await page.goto(fixture.origin+'/home/',{waitUntil:'domcontentloaded'});await page.waitForFunction(()=>window.fixtureReady);}
  async function capture(name) {
    const walletFrames=['08-wallet-chooser','11b-already-signs-in','13-connect-wallet','17b-phone-stopped','18-check-again','19-passkey-retry','20-wallet-connections'];
    const target=walletFrames.includes(name)?'wallet':['09-add-signature','10-one-passkey','14-connected-signin-request'].includes(name)?'wallet-metamask':name==='17-existing-phone-session'?'wallet-walletconnect':['11-signs-in','12-remove-wallet','25-wallet-removed'].includes(name)?'system':null;
    if(target)await page.locator('iframe[title="'+target+'"]').waitFor({state:'visible',timeout:5000});
    await page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));
    const file=`${engine}-${width}-${theme}-${name}.png`;
    await page.waitForFunction(()=>[...document.querySelectorAll('.signin-dialog img')].every(img=>img.complete&&img.naturalWidth>0),null,{timeout:5000});
    await page.screenshot({path:join(output,file),fullPage:true,animations:'disabled'});
    const overflow=await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth);
    assert.equal(overflow,false,`horizontal overflow at ${name}`);
    pictures.push({engine,width,theme,state:name,file,sha256:createHash('sha256').update(await readFile(join(output,file))).digest('hex')});
  }
  const release=()=>page.evaluate(()=>{const jobs=window.walletFixture.pending.splice(0);for(const job of jobs)job.resolve(job.result);});
  const approveExtension=async(kind='metamask')=>{const frame=page.frameLocator('iframe[title=wallet-'+kind+']');await frame.locator('[data-action=send-request]').click();return frame;};
  const option=kind=>dialog().locator('.connection-option').filter({hasText:kind});
  async function startSignin(kind) {await page.getByRole('button',{name:'Sign in',exact:true}).click();await state('options');await option(kind).click();}
  async function apps() {await page.evaluate(()=>window.showFixtureApps());const system=page.frameLocator('iframe[title=system]');await system.locator('#wallet-signin-add').waitFor();return system;}
  async function refreshSystem() {await page.locator('iframe[title=system]').evaluate(f=>f.contentWindow.postMessage({type:'home:wallet-signin-changed'},'*'));}
  try {
    await home();await capture('01-sign-in');
    assert.equal(await page.getByRole('button',{name:'Sign in',exact:true}).count(),1);
    assert.equal(await page.getByRole('button',{name:'Sign in with wallet',exact:true}).count(),0);
    await page.locator('#home-unlock-person .home-unlock-passkey-label').click();await state('options');assert.equal(await dialog().locator('.connection-option').count(),4);await option('Passkey').click();await page.waitForFunction(()=>window.openedPrincipal==='principal:alex');
    assert.equal(await page.evaluate(()=>localStorage.getItem('elastos.signin.options.v1')),null);
    assert.equal(fixture.state.calls.filter(c=>c.path==='/api/auth/passkey/authenticate/complete').length,1,'fresh browser offers its configured WalletConnect and passkey');
    await home();await page.getByRole('button',{name:'Sign in',exact:true}).click();await state('options');await capture('02-sign-in-options');
    assert.equal(await dialog().locator('.connection-option').count(),4);
    assert.doesNotMatch(await dialog().innerText(),/0x|bc1|Smart Chain|Bitcoin|Base/);
    assert.equal(await option('Passkey').locator('[aria-hidden=true]').count(),1);
    await dialog().getByLabel('Remember my choice').check();
    fixture.state.longSigningMessage=true;
    await page.evaluate(()=>{window.walletFixture.mode='pending';window.walletFixture.signaturePending=true;});await option('MetaMask').click();await state('connecting');
    assert.equal(await dialog().getByText('Waiting for MetaMask…',{exact:true}).count(),1,'connection handoff names the selected wallet before it returns an account');
    await capture('02b-extension-connection');await page.evaluate(()=>window.walletFixture.mode='normal');await release();await state('signing');await capture('03-extension-signature');
    assert.equal(await dialog().getByText('Waiting for MetaMask…',{exact:true}).count(),1);
    assert.equal(await dialog().locator('details,summary').count(),0);
    assert.equal(await option('Waiting for MetaMask…').count(),1,'selected row stays in the Sign in sheet');
    await release();await page.waitForFunction(()=>window.openedPrincipal==='principal:alex');
    await home();await page.evaluate(()=>window.walletFixture.signaturePending=true);
    await page.getByRole('button',{name:'Sign in',exact:true}).click();await state('signing');
    assert.equal(await option('Waiting for MetaMask…').count(),1,'remembered wallet keeps its waiting row');await cancel();
    await page.getByRole('button',{name:'Other options',exact:true}).click();await state('options');await capture('04-other-options');
    await dialog().getByLabel('Remember my choice').uncheck();await cancel();
    await home();await page.evaluate(()=>window.walletFixture.signaturePending=true);await startSignin('UniSat');await state('signing');assert.equal(await dialog().getByText('Waiting for UniSat…',{exact:true}).count(),1);await release();await page.waitForFunction(()=>window.openedPrincipal==='principal:alex');
    await page.goto(fixture.origin+'/home/?no-passkeys',{waitUntil:'domcontentloaded'});await page.waitForFunction(()=>window.fixtureReady);
    await page.getByRole('button',{name:'Sign in',exact:true}).click();await state('options');assert(await option('Passkey').isDisabled());await option('MetaMask').click();await page.waitForFunction(()=>window.openedPrincipal==='principal:alex');
    checks.push(`${engine}/${width}/${theme}: single Sign in, passkey fallback, enabled wallet list, extension and UniSat signing, remember, Other options and wallets without browser passkey support`);

    await home();const before=fixture.state.calls.filter(c=>c.path==='/api/auth/wallet/signin/begin').length;
    await page.getByRole('button',{name:'Sign in',exact:true}).click();await state('options');
    assert.equal(await option('Phone wallet').locator('.connection-note').textContent(),"Connects through a relay that can see this computer's internet address.");
    await capture('05-phone-relay-notice');assert.equal(fixture.state.calls.filter(c=>c.path==='/api/auth/wallet/signin/begin').length,before);
    await option('Phone wallet').click();await state('pairing');
    assert.equal(await dialog().getByRole('heading',{name:'Sign in',exact:true}).count(),1);
    const destination=dialog().getByText(fixture.origin,{exact:true});assert.equal(await destination.count(),1);
    const codeBox=await dialog().locator('.connection-qr').boundingBox(),destinationBox=await destination.boundingBox();
    assert(destinationBox.y+destinationBox.height<=codeBox.y,'Home destination stays above the QR code');
    assert.equal(await dialog().getByText('Scan with your wallet, or paste the copied link into your wallet.',{exact:true}).count(),1);
    for(const control of await dialog().getByRole('button').all())assert.ok((await control.boundingBox()).height>=44,'QR footer controls retain their 44px target height');
    await capture('06-shared-qr');
    await dialog().getByRole('button',{name:'Copy link',exact:true}).click();await dialog().getByRole('button',{name:'Link copied.',exact:true}).waitFor();
    await page.locator('iframe[title=WalletConnect]').evaluate(f=>{f.contentWindow.postMessage('fixture-sign-pending','*');f.contentWindow.postMessage('fixture-pair','*');});
    await state('signing');assert.equal(await dialog().getByText('Waiting for Phone wallet…',{exact:true}).count(),1);await capture('07-phone-signature');
    await page.locator('iframe[title=WalletConnect]').evaluate(f=>f.contentWindow.postMessage('fixture-release-signature','*'));
    await page.waitForFunction(()=>window.openedPrincipal==='principal:alex');
    assert(fixture.state.calls.filter(c=>c.path==='/api/fixture-sdk'&&c.body.method==='personal_sign').length>0);
    checks.push(`${engine}/${width}/${theme}: signed-out WalletConnect uses the shared QR, explicit relay consent, personal_sign and temporary transport`);

    await page.goto(fixture.origin+'/home/?desktop-app',{waitUntil:'domcontentloaded'});await page.waitForFunction(()=>window.fixtureReady);await page.evaluate(()=>{localStorage.removeItem('elastos.signin.options.v1');localStorage.removeItem('elastos.signin.choice.v1');});
    await page.getByRole('button',{name:'Sign in',exact:true}).click();await state('options');
    assert.equal(await dialog().locator('.connection-option').count(),2,'desktop without local hints offers Passkey and configured WalletConnect');
    assert.equal(await option('MetaMask').count(),0);assert.equal(await option('UniSat').count(),0);await capture('21-desktop-options');
    fixture.state.rejectSignature=true;await option('Phone wallet').click();await state('pairing');
    await page.locator('iframe[title=WalletConnect]').evaluate(f=>f.contentWindow.postMessage('fixture-pair','*'));await state('error');await capture('22-walletconnect-retry');
    fixture.state.rejectSignature=false;await dialog().getByRole('button',{name:'Try again',exact:true}).click();await state('pairing');await page.locator('iframe[title=WalletConnect]').evaluate(f=>f.contentWindow.postMessage('fixture-pair','*'));await page.waitForFunction(()=>window.openedPrincipal==='principal:alex');
    checks.push(`${engine}/${width}/${theme}: fresh desktop hides extension wallets and signs in through configured WalletConnect without browser-local hints; a refused signature retries through consent`);

    fixture.state.methods=[];fixture.state.signed=true;await home();await page.getByRole('button',{name:'Sign in',exact:true}).click();await page.waitForFunction(()=>window.openedPrincipal==='principal:alex');
    const system=await apps(),wallet=page.frameLocator('iframe[title=wallet]'),chooser=wallet.locator('#wallet-signers');
    const choose=kind=>wallet.locator('.wallet-method-head').filter({hasText:kind}).getByRole('button',{name:'Choose',exact:true});
    const addState=stage=>wallet.locator('#wallet-signers[data-signin='+stage+']').waitFor();
    const addDone=()=>wallet.locator('#wallet-signers[data-signin]').waitFor({state:'detached'});
    const startAdd=async()=>{await page.locator('#show-system').evaluate(el=>el.click());await system.getByRole('button',{name:'Add wallet',exact:true}).click();await addState('options');};
    const cancelAdd=async()=>{await page.locator('#show-wallet').evaluate(el=>el.click());await wallet.getByRole('button',{name:'Cancel',exact:true}).click();await addDone();await page.locator('iframe[title=system]').waitFor({state:'visible'});};
    await startAdd();await capture('08-wallet-chooser');
    assert.equal(await wallet.locator('.wallet-method-head').count(),3);assert.equal(await dialog().count(),0);
    assert.doesNotMatch(await chooser.innerText(),/New wallet|Connect another|Built-in/);
    await page.locator('#show-system').evaluate(el=>el.click());await system.getByRole('button',{name:'Add wallet',exact:true}).click();await chooser.waitFor();await cancelAdd();
    await startAdd();await page.evaluate(()=>{window.walletFixture.signaturePending=true;window.walletFixture.passkeyMode='pending';});
    const callsBefore=await page.evaluate(()=>window.walletFixture.calls.length);
    await choose('MetaMask').click();const extension=await approveExtension();await extension.locator('[data-state=request-extension]').waitFor();assert.equal(await dialog().count(),0);await capture('09-add-signature');
    await release();await page.waitForFunction(()=>window.walletFixture.calls.some(c=>c.method==='passkey'));assert.equal(await dialog().count(),0);await capture('10-one-passkey');await release();await addDone();
    await system.locator('[data-wallet-method]').getByRole('button',{name:'Remove',exact:true}).waitFor();await capture('11-signs-in');
    const counts=await page.evaluate(start=>window.walletFixture.calls.slice(start).map(c=>c.method),callsBefore);
    assert.equal(counts.filter(m=>m==='personal_sign').length,1);assert.equal(counts.filter(m=>m==='passkey').length,1);assert.equal(fixture.state.methods[0].sign_in_enabled,true);
    await page.evaluate(()=>{window.walletFixture.signaturePending=false;window.walletFixture.passkeyMode='normal';});
    await startAdd();assert(await choose('MetaMask').isDisabled());await capture('11b-already-signs-in');await cancelAdd();
    await page.evaluate(()=>window.walletFixture.passkeyMode='pending');
    await system.locator('[data-wallet-method]').getByRole('button',{name:'Remove',exact:true}).click();await state('passkey');await capture('12-remove-wallet');
    await release();await dialog().waitFor({state:'detached'});await system.locator('[data-wallet-method]').waitFor({state:'detached'});assert.equal(fixture.state.methods.length,0);await capture('25-wallet-removed');
    await page.evaluate(()=>window.walletFixture.passkeyMode='normal');
    checks.push(`${engine}/${width}/${theme}: Wallet chooser, cancel, second Add, one signature and one passkey, used wallet disabled, Remove`);

    await page.locator('iframe[title=wallet-metamask]').evaluate(f=>f.remove());
    fixture.state.methods=[];fixture.state.connected=[];await refreshSystem();await startAdd();await capture('13-connect-wallet');
    await choose('MetaMask').click();const newExtension=page.frameLocator('iframe[title=wallet-metamask]');
    await newExtension.getByRole('button',{name:'Connect wallet',exact:true}).click();
    await newExtension.locator('[data-action=send-request]').waitFor();assert.equal(await dialog().count(),0);await capture('14-connected-signin-request');
    await approveExtension();await addDone();assert.equal(fixture.state.methods[0].sign_in_enabled,true);
    checks.push(`${engine}/${width}/${theme}: no connected wallets uses Wallet chooser then connector connection, signature, passkey and Accounts`);

    fixture.state.methods=[];fixture.state.connected=[{account_id:'phone',connector_id:'wallet-walletconnect',address:walletconnectAddress,chain_namespace:'eip155:20',proof_type:'siwe'}];await refreshSystem();await system.locator('[data-wallet-method]').waitFor({state:'detached'});
    await startAdd();
    const sdkBefore=fixture.state.calls.filter(c=>c.path==='/api/fixture-sdk'&&c.body.method==='personal_sign').length;
    fixture.state.holdSignature=true;await choose('Phone wallet').click();
    const phone=page.frameLocator('iframe[title=wallet-walletconnect]');await phone.locator('.connection-status').filter({hasText:/Sign the message in .* to add this wallet to Home\./}).waitFor();await capture('17-existing-phone-session');
    await page.locator('iframe[title=wallet-walletconnect]').evaluate(f=>f.contentWindow.postMessage({type:'home:wallet-signin-effect',homeToken:'fixture-wallet-walletconnect',requestId:'fixture-stop',operation:'stop'},'*'));
    await addState('error');await capture('17b-phone-stopped');await cancelAdd();assert.equal(fixture.state.methods.length,0);
    await page.locator('#show-system').evaluate(el=>el.click());
    await page.locator('iframe[title=wallet-walletconnect]').evaluate(f=>f.contentWindow.postMessage('fixture-release-signature','*'));fixture.state.holdSignature=false;
    await page.locator('iframe[title=wallet-walletconnect]').evaluate(f=>f.contentWindow.postMessage('fixture-sign-pending','*'));
    await startAdd();await choose('Phone wallet').click();
    await phone.getByRole('button',{name:'Stop waiting',exact:true}).click();await addState('error');await cancelAdd();assert.equal(fixture.state.methods.length,0);
    await page.locator('iframe[title=wallet-walletconnect]').evaluate(f=>f.contentWindow.postMessage('fixture-release-signature','*'));
    await startAdd();await choose('Phone wallet').click();await addDone();
    await system.locator('[data-wallet-method]').getByRole('button',{name:'Remove',exact:true}).waitFor();assert.equal(fixture.state.methods[0].sign_in_enabled,true);
    assert.equal(fixture.state.calls.filter(c=>c.path==='/api/fixture-sdk'&&c.body.method==='personal_sign').length-sdkBefore,3);
    assert.equal(await page.locator('iframe[title=WalletConnect]').count(),0);await page.locator('iframe[title=wallet-walletconnect]').evaluate(f=>f.remove());
    checks.push(`${engine}/${width}/${theme}: connected phone uses connector; Home stop and Stop waiting preserve payment connection; new attempt succeeds`);

    fixture.state.methods=[];fixture.state.connected=[{account_id:'retry',connector_id:'wallet-metamask',address:evmAddress,chain_namespace:'eip155:20',proof_type:'siwe'}];await refreshSystem();await system.locator('[data-wallet-method]').waitFor({state:'detached'});
    fixture.state.scenario='unknown';await startAdd();await choose('MetaMask').click();await approveExtension();await addState('unknown');await capture('18-check-again');
    await wallet.getByRole('button',{name:'Check again',exact:true}).click();await addDone();assert.equal(fixture.state.methods[0].sign_in_enabled,true);
    fixture.state.scenario='normal';fixture.state.methods=[];await refreshSystem();await system.locator('[data-wallet-method]').waitFor({state:'detached'});
    fixture.state.longSigningMessage=true;await page.evaluate(()=>window.walletFixture.passkeyMode='cancelled');await startAdd();await choose('MetaMask').click();await approveExtension();await addState('approval');await capture('19-passkey-retry');
    assert.equal(await wallet.locator('details,summary').count(),0);fixture.state.longSigningMessage=false;await cancelAdd();assert.equal(fixture.state.methods.length,0);
    await page.evaluate(()=>window.walletFixture.passkeyMode='normal');
    checks.push(`${engine}/${width}/${theme}: lost completion checks same request; refused passkey offers Use passkey and Cancel in Wallet`);
    await page.locator('#show-wallet').evaluate(el=>el.click());assert.equal(await wallet.locator('#wallet-signin-methods').count(),0);await capture('20-wallet-connections');
    assert.deepEqual(outside,[],'all network stays inside the fixture');assert.deepEqual(errors,[],'browser modules produce no uncaught errors');
    const storage=await page.evaluate(()=>JSON.stringify({...localStorage}));
    assert(!/browser_secret|step_up_token|fixture-signature|fixture-home|symKey|wc:|0x|bc1/.test(storage),'secrets stay out of browser storage');
  } catch(error) {
    await page.screenshot({path:join(output,`${engine}-${width}-${theme}-failure.png`),fullPage:true}).catch(()=>{});
    console.error('Connector errors:',await Promise.all(page.frames().map(frame=>frame.evaluate(()=>window.fixtureConnectorError||'').catch(()=>''))));
    console.error('Link routes:',fixture.state.calls.filter(c=>c.path.includes('/wallet-connector/')).map(({path,status})=>({path,status})));
    console.error('Screen:',await dialog().evaluateAll(nodes=>nodes[0]?.dataset.state||null),'page errors:',errors,'routes:',fixture.state.calls.slice(-12).map(({path,status})=>({path,status})));throw error;
  } finally {await context.close();await browser.close();await fixture.close();}
}
try {for(const engine of(process.env.SIGNIN_ENGINE?[process.env.SIGNIN_ENGINE]:['chromium','webkit']))for(const width of widths)for(const theme of themes)await exercise(engine,width,theme);passed=true;}
finally {
  const sources={};for(const file of ['scripts/lib/wallet-signin-fixture.mjs','scripts/wallet-signin-browser-smoke.mjs','capsules/home/browser/wallet-signin-flow.mjs','capsules/home/browser/wallet-signin-view.mjs','capsules/home/browser/wallet-signin-host.mjs','capsules/home/browser/wallet-signin-signers.mjs','capsules/home/browser/wallet-signin-connector.mjs','capsules/home/browser/wallet-signin-window.mjs','capsules/home-gui/browser/home-gui-shell.js','capsules/home-gui/browser/shell-windows.js','capsules/system/browser/style.css','capsules/home/browser/wallet-signin-options.mjs','capsules/home/browser/wallet-signin.css','capsules/home/browser/wallet-signin-connection.css','capsules/home/browser/shell-auth.js','capsules/home/browser/home-shell-host.js','capsules/system/browser/system.js','capsules/wallet-walletconnect/browser/wallet-walletconnect.js','capsules/wallet-walletconnect/browser/walletconnect-client.mjs'])sources[file]=createHash('sha256').update(await readFile(file)).digest('hex');
  await writeFile(join(output,'index.json'),JSON.stringify({status:passed?'PASS':'FAIL',environment:{node:process.version,platform:process.platform,arch:process.arch,browsers:browserVersions},head:execFileSync('git',['rev-parse','HEAD'],{encoding:'utf8'}).trim(),tree:execFileSync('git',['rev-parse','HEAD^{tree}'],{encoding:'utf8'}).trim(),dirty:execFileSync('git',['status','--short'],{encoding:'utf8'}).trim(),sources,pictures,checks},null,2)+'\n');
  await writeFile(join(output,'index.html'),`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Wallet sign-in</title><style>body{font:14px/1.5 system-ui;margin:24px;background:#f4f5f7;color:#18202b}main{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:20px}article{background:white;border:1px solid #ccd0d8;border-radius:12px;padding:16px}img{width:100%;height:300px;object-fit:contain}h2{font-size:14px}</style><h1>Wallet sign-in: ${passed?'PASS':'FAIL'}</h1><p>Real browser modules; fixture Runtime, extension, phone wallet and passkey boundaries.</p><p>${pictures.length} captures. <a href="index.json">Sources, hashes and checks</a></p><main>${pictures.map(p=>`<article><h2>${p.engine} · ${p.width} px · ${p.theme} · ${p.state}</h2><a href="${encodeURIComponent(basename(p.file))}"><img loading="lazy" src="${encodeURIComponent(basename(p.file))}" alt="${p.state}"></a></article>`).join('')}</main></html>`);
}
console.log(`Wallet sign-in browser smoke PASS: ${checks.length} checks, ${pictures.length} screenshots.`);
