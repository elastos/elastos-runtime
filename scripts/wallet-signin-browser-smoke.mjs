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
    const file=`${engine}-${width}-${theme}-${name}.png`;
    await page.screenshot({path:join(output,file),fullPage:true});
    const overflow=await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth);
    assert.equal(overflow,false,`horizontal overflow at ${name}`);
    pictures.push({engine,width,theme,state:name,file,sha256:createHash('sha256').update(await readFile(join(output,file))).digest('hex')});
  }
  const release=()=>page.evaluate(()=>{const jobs=window.walletFixture.pending.splice(0);for(const job of jobs)job.resolve(job.result);});
  const option=kind=>dialog().locator('.connection-option').filter({hasText:kind});
  async function startSignin(kind) {await page.getByRole('button',{name:'Sign in',exact:true}).click();await state('options');await option(kind).click();}
  async function apps() {await page.evaluate(()=>window.showFixtureApps());const system=page.frameLocator('iframe[title=system]');await system.locator('#wallet-signin-add').waitFor();return system;}
  async function refreshSystem() {await page.locator('iframe[title=system]').evaluate(f=>f.contentWindow.postMessage({type:'home:wallet-signin-changed'},'*'));}
  try {
    await home();await capture('01-sign-in');
    assert.equal(await page.getByRole('button',{name:'Sign in',exact:true}).count(),1);
    assert.equal(await page.getByRole('button',{name:'Sign in with wallet',exact:true}).count(),0);
    await page.locator('#home-unlock-person .home-unlock-passkey-label').click();await page.waitForFunction(()=>window.openedPrincipal==='principal:alex');
    assert.equal(fixture.state.calls.filter(c=>c.path==='/api/auth/passkey/authenticate/complete').length,1,'passkey-only browser goes straight to its passkey');
    await home();await page.getByRole('button',{name:'Sign in',exact:true}).click();await state('options');await capture('02-sign-in-options');
    assert.equal(await dialog().locator('.connection-option').count(),4);
    await dialog().getByLabel('Remember my choice').check();
    await page.evaluate(()=>window.walletFixture.signaturePending=true);await option('MetaMask').click();await state('signing');await capture('03-extension-signature');
    assert.equal(await page.getByText('Continue only if you started this sign-in in this browser.',{exact:true}).count(),1);
    await release();await page.waitForFunction(()=>window.openedPrincipal==='principal:alex');
    await home();await page.evaluate(()=>window.walletFixture.signaturePending=true);
    await page.getByRole('button',{name:'Sign in',exact:true}).click();await state('signing');
    assert.equal(await dialog().locator('.connection-option').count(),0,'remembered wallet goes straight to signing');await cancel();
    await page.getByRole('button',{name:'Other options',exact:true}).click();await state('options');await capture('04-other-options');
    await dialog().getByLabel('Remember my choice').uncheck();await cancel();
    await home();await startSignin('UniSat');await page.waitForFunction(()=>window.openedPrincipal==='principal:alex');
    await page.goto(fixture.origin+'/home/?no-passkeys',{waitUntil:'domcontentloaded'});await page.waitForFunction(()=>window.fixtureReady);
    await page.getByRole('button',{name:'Sign in',exact:true}).click();await state('options');assert(await option('Passkey').isDisabled());await option('MetaMask').click();await page.waitForFunction(()=>window.openedPrincipal==='principal:alex');
    checks.push(`${engine}/${width}/${theme}: single Sign in, passkey fallback, enabled wallet list, extension and UniSat signing, remember, Other options and wallets without browser passkey support`);

    await home();const before=fixture.state.calls.filter(c=>c.path==='/api/auth/wallet/signin/begin').length;
    await startSignin('WalletConnect');await state('internet-notice');await capture('05-walletconnect-consent');
    assert.equal(fixture.state.calls.filter(c=>c.path==='/api/auth/wallet/signin/begin').length,before,'consent precedes relay admission');
    await dialog().getByRole('button',{name:'Continue',exact:true}).click();await state('pairing');await capture('06-shared-qr');
    await dialog().getByRole('button',{name:'Copy link',exact:true}).click();await dialog().getByRole('button',{name:'Link copied.',exact:true}).waitFor();
    await page.locator('iframe[title=WalletConnect]').evaluate(f=>{f.contentWindow.postMessage('fixture-sign-pending','*');f.contentWindow.postMessage('fixture-pair','*');});
    await state('signing');await capture('07-phone-signature');
    await page.locator('iframe[title=WalletConnect]').evaluate(f=>f.contentWindow.postMessage('fixture-release-signature','*'));
    await page.waitForFunction(()=>window.openedPrincipal==='principal:alex');
    assert(fixture.state.calls.filter(c=>c.path==='/api/fixture-sdk'&&c.body.method==='personal_sign').length>0);
    checks.push(`${engine}/${width}/${theme}: signed-out WalletConnect uses the shared QR, explicit relay consent, personal_sign and temporary transport`);

    fixture.state.methods=[];fixture.state.signed=true;await home();let system=await apps();
    await system.getByRole('button',{name:'Add wallet',exact:true}).click();await state('options');await capture('08-connected-wallets');
    assert.equal(await dialog().locator('.connection-option').count(),2,'connected wallet plus New wallet');
    await page.evaluate(()=>{window.walletFixture.signaturePending=true;window.walletFixture.passkeyMode='pending';});
    const callsBefore=await page.evaluate(()=>window.walletFixture.calls.length);
    await option('MetaMask').click();await state('signing');await capture('09-add-signature');
    await release();await state('passkey');await capture('10-one-passkey');await release();await dialog().waitFor({state:'detached'});
    await system.getByRole('button',{name:'Turn off sign-in',exact:true}).waitFor();await capture('11-signs-in');
    const counts=await page.evaluate(start=>window.walletFixture.calls.slice(start).map(c=>c.method),callsBefore);
    assert.equal(counts.filter(m=>m==='personal_sign').length,1);assert.equal(counts.filter(m=>m==='passkey').length,1);
    assert.equal(fixture.state.methods[0].sign_in_enabled,true);
    await page.evaluate(()=>{window.walletFixture.signaturePending=false;window.walletFixture.passkeyMode='normal';});
    await system.getByRole('button',{name:'Turn off sign-in',exact:true}).click();await dialog().waitFor({state:'detached'});
    await system.getByRole('button',{name:'Use to sign in',exact:true}).waitFor();await capture('12-payments-only');
    assert.equal(fixture.state.methods[0].sign_in_enabled,false);
    await system.getByRole('button',{name:'Use to sign in',exact:true}).click();await system.getByRole('button',{name:'Turn off sign-in',exact:true}).waitFor();await dialog().waitFor({state:'detached'});assert.equal(fixture.state.methods[0].sign_in_enabled,true);
    checks.push(`${engine}/${width}/${theme}: connected wallet adds sign-in with one signature and one passkey, closes directly, and disable/enable controls work`);

    fixture.state.methods=[];fixture.state.connected=[];await refreshSystem();await system.locator('[data-wallet-method]').waitFor({state:'detached'});
    await system.getByRole('button',{name:'Add wallet',exact:true}).click();await state('options');assert.equal(await dialog().locator('.connection-option').count(),1);await capture('13-new-wallet-only');
    await option('New wallet').click();await state('new-wallet');await capture('14-connector-options');
    await option('MetaMask').click();const extension=page.frameLocator('iframe[title=wallet-metamask]');await extension.getByRole('button',{name:'Connect wallet',exact:true}).waitFor();await capture('15-existing-connector');
    await extension.getByRole('button',{name:'Connect wallet',exact:true}).click();await state('options');await option('MetaMask').waitFor();await capture('16-connected-return');
    await page.locator('iframe[title=wallet-metamask]').evaluate(f=>f.remove());await option('MetaMask').click();await dialog().waitFor({state:'detached'});assert.equal(fixture.state.methods[0].sign_in_enabled,true);
    checks.push(`${engine}/${width}/${theme}: New wallet launches the real MetaMask connector and returns its saved account to Add wallet`);

    fixture.state.methods=[];fixture.state.connected=[{account_id:'phone',connector_id:'wallet-walletconnect',address:walletconnectAddress,chain_namespace:'eip155:20',proof_type:'siwe'}];await refreshSystem();await system.locator('[data-wallet-method]').waitFor({state:'detached'});
    await system.getByRole('button',{name:'Add wallet',exact:true}).click();await state('options');
    const sdkBefore=fixture.state.calls.filter(c=>c.path==='/api/fixture-sdk'&&c.body.method==='personal_sign').length;
    fixture.state.holdSignature=true;await option('WalletConnect').click();
    const phone=page.frameLocator('iframe[title=wallet-walletconnect]');await phone.locator('.connection-status').filter({hasText:/Sign the message in .* to sign in to this Home\./}).waitFor();await capture('17-existing-phone-session');
    await page.locator('iframe[title=wallet-walletconnect]').evaluate(f=>f.contentWindow.postMessage('fixture-release-signature','*'));
    await system.getByRole('button',{name:'Turn off sign-in',exact:true}).waitFor();await dialog().waitFor({state:'detached'});fixture.state.holdSignature=false;
    assert.equal(fixture.state.methods[0].sign_in_enabled,true);assert.equal(fixture.state.calls.filter(c=>c.path==='/api/fixture-sdk'&&c.body.method==='personal_sign').length-sdkBefore,1);
    assert.equal(await page.locator('iframe[title=WalletConnect]').count(),0,'connected signing reuses the admitted connector window');
    await page.locator('iframe[title=wallet-walletconnect]').evaluate(f=>f.remove());
    checks.push(`${engine}/${width}/${theme}: connected WalletConnect signs once through its real connector controller and restored session`);

    fixture.state.methods=[];fixture.state.connected=[{account_id:'retry',connector_id:'wallet-metamask',address:evmAddress,chain_namespace:'eip155:20',proof_type:'siwe'}];await refreshSystem();await system.locator('[data-wallet-method]').waitFor({state:'detached'});
    fixture.state.scenario='unknown';await system.getByRole('button',{name:'Add wallet',exact:true}).click();await state('options');await option('MetaMask').click();await state('unknown');await capture('18-check-again');
    await dialog().getByRole('button',{name:'Check again',exact:true}).click();await dialog().waitFor({state:'detached'});assert.equal(fixture.state.methods[0].sign_in_enabled,true);
    fixture.state.scenario='normal';fixture.state.methods=[];await refreshSystem();await system.locator('[data-wallet-method]').waitFor({state:'detached'});
    await page.evaluate(()=>window.walletFixture.passkeyMode='cancelled');await system.getByRole('button',{name:'Add wallet',exact:true}).click();await state('options');await option('MetaMask').click();await state('approval');await capture('19-passkey-retry');await cancel();assert.equal(fixture.state.methods.length,0);
    await page.evaluate(()=>window.walletFixture.passkeyMode='normal');
    checks.push(`${engine}/${width}/${theme}: lost completion reconciles the same request; cancelled approval leaves the method unchanged`);
    fixture.state.connected=[{account_id:'brave',connector_id:'wallet-metamask',address:evmAddress,chain_namespace:'eip155:20',proof_type:'siwe',provider_id:'com.brave.wallet',wallet_display_name:'Brave Wallet'}];
    await page.evaluate(()=>window.walletFixture.multiple=true);await page.locator('#show-wallet').click();
    const wallet=page.frameLocator('iframe[title=wallet]');await wallet.locator('#wallet-signin-methods').getByRole('button',{name:'Use to sign in',exact:true}).click();
    await wallet.locator('#wallet-signin-methods').getByRole('button',{name:'Turn off sign-in',exact:true}).waitFor();assert.equal(fixture.state.methods[0].sign_in_enabled,true);
    await wallet.locator('#wallet-signin-methods').scrollIntoViewIfNeeded();await capture('20-wallet-shortcut');
    checks.push(`${engine}/${width}/${theme}: Wallet shortcut reads its saved Brave provider and signs without a duplicate extension chooser`);
    assert.deepEqual(outside,[],'all network stays inside the fixture');assert.deepEqual(errors,[],'browser modules produce no uncaught errors');
    const storage=await page.evaluate(()=>JSON.stringify({...localStorage}));
    assert(!/browser_secret|step_up_token|fixture-signature|fixture-home|symKey|wc:/.test(storage),'secrets stay out of browser storage');
  } catch(error) {
    await page.screenshot({path:join(output,`${engine}-${width}-${theme}-failure.png`),fullPage:true}).catch(()=>{});
    console.error('Connector errors:',await Promise.all(page.frames().map(frame=>frame.evaluate(()=>window.fixtureConnectorError||'').catch(()=>''))));
    console.error('Link routes:',fixture.state.calls.filter(c=>c.path.includes('/wallet-connector/')).map(({path,status})=>({path,status})));
    console.error('Screen:',await dialog().getAttribute('data-state').catch(()=>null),'page errors:',errors,'routes:',fixture.state.calls.slice(-12).map(({path,status})=>({path,status})));throw error;
  } finally {await context.close();await browser.close();await fixture.close();}
}
try {for(const engine of(process.env.SIGNIN_ENGINE?[process.env.SIGNIN_ENGINE]:['chromium','webkit']))for(const width of widths)for(const theme of themes)await exercise(engine,width,theme);passed=true;}
finally {
  const sources={};for(const file of ['scripts/lib/wallet-signin-fixture.mjs','scripts/wallet-signin-browser-smoke.mjs','capsules/home/browser/wallet-signin-flow.mjs','capsules/home/browser/wallet-signin-view.mjs','capsules/home/browser/wallet-signin-host.mjs','capsules/home/browser/wallet-signin-signers.mjs','capsules/home/browser/wallet-signin-connector.mjs','capsules/home/browser/wallet-signin-options.mjs','capsules/home/browser/wallet-signin.css','capsules/home/browser/wallet-signin-connection.css','capsules/home/browser/shell-auth.js','capsules/home/browser/home-shell-host.js','capsules/system/browser/system.js','capsules/wallet-walletconnect/browser/wallet-walletconnect.js','capsules/wallet-walletconnect/browser/walletconnect-client.mjs'])sources[file]=createHash('sha256').update(await readFile(file)).digest('hex');
  await writeFile(join(output,'index.json'),JSON.stringify({status:passed?'PASS':'FAIL',environment:{node:process.version,platform:process.platform,arch:process.arch,browsers:browserVersions},head:execFileSync('git',['rev-parse','HEAD'],{encoding:'utf8'}).trim(),tree:execFileSync('git',['rev-parse','HEAD^{tree}'],{encoding:'utf8'}).trim(),dirty:execFileSync('git',['status','--short'],{encoding:'utf8'}).trim(),sources,pictures,checks},null,2)+'\n');
  await writeFile(join(output,'index.html'),`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Wallet sign-in</title><style>body{font:14px/1.5 system-ui;margin:24px;background:#f4f5f7;color:#18202b}main{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:20px}article{background:white;border:1px solid #ccd0d8;border-radius:12px;padding:16px}img{width:100%;height:300px;object-fit:contain}h2{font-size:14px}</style><h1>Wallet sign-in: ${passed?'PASS':'FAIL'}</h1><p>Real browser modules; fixture Runtime, extension, phone wallet and passkey boundaries.</p><p>${pictures.length} captures. <a href="index.json">Sources, hashes and checks</a></p><main>${pictures.map(p=>`<article><h2>${p.engine} · ${p.width} px · ${p.theme} · ${p.state}</h2><a href="${encodeURIComponent(basename(p.file))}"><img loading="lazy" src="${encodeURIComponent(basename(p.file))}" alt="${p.state}"></a></article>`).join('')}</main></html>`);
}
console.log(`Wallet sign-in browser smoke PASS: ${checks.length} checks, ${pictures.length} screenshots.`);
