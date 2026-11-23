#!/usr/bin/env node
import assert from 'node:assert/strict';
import {mkdir,writeFile,readFile} from 'node:fs/promises';
import {join,basename} from 'node:path';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {requireProductSmokePlaywright} from './product-smoke-browser.mjs';
import {signinFixture,installSigninProviders,sampleMethod,evmAddress,bitcoinAddress,relayNotice} from './lib/wallet-signin-fixture.mjs';
const output=process.env.SIGNIN_SCREENSHOT_DIR;
if(!output)throw new Error('Set SIGNIN_SCREENSHOT_DIR to the screens evidence directory.');
await mkdir(output,{recursive:true});
const playwright=requireProductSmokePlaywright();
const pictures=[],checks=[],browserVersions={};let passed=false;
const widths=process.env.SIGNIN_WIDTH?[Number(process.env.SIGNIN_WIDTH)]:[1280,390];
async function exercise(engine,width) {
  const fixture=await signinFixture(),browser=await playwright[engine].launch({headless:true});
  browserVersions[engine]=browser.version();
  const context=await browser.newContext({viewport:{width,height:width===390?844:900},locale:'en-US',timezoneId:'America/Panama',reducedMotion:'reduce',colorScheme:'light'});
  const errors=[],outside=[],lostReplies=new Set();
  await context.addInitScript(installSigninProviders,{evmAddress,bitcoinAddress});
  const page=await context.newPage();page.on('pageerror',error=>errors.push(error.message));
  await context.route('**/*',async route=>{
    const url=new URL(route.request().url());
    if(url.origin!==fixture.origin){outside.push(route.request().url());return route.abort();}
    if(fixture.state.scenario==='unknown' && ['/api/auth/wallet/signin/complete','/api/auth/wallet-methods/complete'].includes(url.pathname)) {
      const id=route.request().postDataJSON().ceremony_id;
      if(!lostReplies.has(id)){lostReplies.add(id);await route.fetch();return route.abort('failed');}
    }
    return route.continue();
  });
  async function state(stage){
    await page.locator(`.signin-dialog[data-state="${stage}"]`).waitFor({timeout:15000});
    if(stage==='done')assert(['Wallet added. Sign in is off.','Wallet sign-in is on.','Wallet sign-in is off.','Wallet removed.'].includes(await page.locator('.signin-dialog [role=status]').innerText()),'Confirmed completion replaces prior errors');
  }
  async function capture(name,scope=page) {
    await page.evaluate(()=>document.fonts.ready);
    const fit=await scope.evaluate(()=>({width:innerWidth,scroll:document.documentElement.scrollWidth}));
    assert(fit.scroll<=fit.width+1,`${name} fits at ${width}`);
    const methodControls=await scope.evaluate(()=>[...document.querySelectorAll('[data-wallet-method] button, #wallet-signin-add')].filter(button=>{const r=button.getBoundingClientRect();return r.width>0&&(r.height<44||r.left<0||r.right>innerWidth+1);}).map(button=>button.textContent));
    assert.deepEqual(methodControls,[],`${name}: method controls fit and have 44px targets`);
    const misplaced=await scope.evaluate(()=>[...document.querySelectorAll('tr[data-wallet-method] .account-name')].filter(cell=>{const title=cell.querySelector('strong'),details=cell.querySelector('.signin-method-note');return title&&details&&details.getBoundingClientRect().left+1<title.getBoundingClientRect().left;}).length);
    assert.equal(misplaced,0,`${name}: wallet details stay in the value column`);
    const clipped=await scope.evaluate(()=>[...document.querySelectorAll('tr[data-wallet-method] .signin-method-note')].filter(node=>node.scrollWidth>node.clientWidth+1).length);
    assert.equal(clipped,0,`${name}: connector, address and network text stays visible`);
    const bad=await page.locator('.signin-dialog button:visible').evaluateAll(buttons=>buttons.filter(button=>{const r=button.getBoundingClientRect();return r.height<44||r.left<0||r.right>innerWidth+1;}).map(button=>button.textContent));
    assert.deepEqual(bad,[],`${name}: controls fit and are 44px high`);
    const expiryVisible=await page.locator('.signin-dialog').evaluateAll(dialogs=>dialogs.every(dialog=>{const expiry=dialog.querySelector('.signin-expiry');if(!expiry?.textContent)return true;const r=expiry.getBoundingClientRect(),d=dialog.getBoundingClientRect();return r.top>=d.top&&r.bottom<=d.bottom-4;}));
    assert(expiryVisible,`${name}: expiry label stays fully visible`);
    if(await page.locator('.signin-dialog').count()) {
      const style=await page.locator('.signin-dialog').evaluate(node=>{const s=getComputedStyle(node);return {background:s.backgroundColor,font:s.getPropertyValue('--el-font').trim()};});
      assert.notEqual(style.background,'rgba(0, 0, 0, 0)',`${name}: dialog has its shared surface color`);assert(style.font,`${name}: shared type tokens loaded`);
    }
    const path=join(output,`${engine}-${width}-${name}.png`);
    assert(!pictures.some(p=>p.file===path),'Each screenshot state has a unique saved path');
    await page.screenshot({path,fullPage:true});
    pictures.push({engine,width,height:width===390?844:900,state:name,file:path,sha256:createHash('sha256').update(await readFile(path)).digest('hex')});
  }
  async function home({scenario='normal',methods}={}) {
    fixture.state.scenario=scenario;fixture.state.methods=methods||['metamask','unisat','walletconnect'].map(connector=>sampleMethod(connector,true));
    await page.goto(fixture.origin+'/home/'+(scenario==='unsupported-browser'?'?no-passkeys=1':''),{waitUntil:'domcontentloaded'});await page.waitForFunction(()=>window.fixtureReady);
    await page.evaluate(()=>document.documentElement.dataset.elTheme='light');
  }
  async function start(connector='metamask') {
    await page.locator('[data-home-wallet-signin]:visible').click();await state('choice');
    await page.locator('.signin-dialog').getByRole('button',{name:({metamask:'MetaMask',unisat:'UniSat',walletconnect:'WalletConnect'})[connector],exact:connector!=='metamask'}).click();
  }
  async function cancel(){await page.locator('.signin-dialog').getByRole('button',{name:'Cancel',exact:true}).click();await page.locator('.signin-dialog').waitFor({state:'detached'});}
  async function pair(){const frame=page.frames().find(frame=>frame.url().includes('signin-transport.html'));assert(frame);await page.evaluate(()=>{const f=document.querySelector('iframe[title=WalletConnect]');f.contentWindow.postMessage('fixture-pair','*');});await state('review');}
  try {
    await page.goto(fixture.origin+'/real-home/',{waitUntil:'domcontentloaded'});
    await page.locator('[data-home-wallet-signin]:visible').waitFor();await capture('real-home-entry');
    await page.locator('[data-home-wallet-signin]:visible').click();await state('choice');await cancel();
    checks.push(`${engine}/${width}: real Home host loads wallet signer choice`);
    await page.route('http://home.example/**',async route=>{
      const url=new URL(route.request().url()),response=await fetch(fixture.origin+url.pathname+url.search);
      await route.fulfill({status:response.status,headers:{'content-type':response.headers.get('content-type')||'application/octet-stream'},body:Buffer.from(await response.arrayBuffer())});
    });
    await page.goto('http://home.example/home/',{waitUntil:'domcontentloaded'});await page.waitForFunction(()=>window.fixtureReady);
    await page.locator('[data-home-wallet-signin]:visible').click();await state('error');await page.getByText('Open this Home with HTTPS to sign in with a wallet.',{exact:true}).waitFor();await capture('https-required');
    assert.equal(await page.locator('.signin-dialog').getByRole('button',{name:'Try again',exact:true}).count(),0);await cancel();await page.unroute('http://home.example/**');
    await home();await page.locator('.home-unlock-passkey-label:visible').waitFor();await capture('home');
    await page.locator('#home-recover-owner').click();await page.getByText('Recovery removes this account’s other passkeys and wallet sign-in methods.',{exact:true}).waitFor();await capture('recovery-wallet-warning');
    checks.push(`${engine}/${width}: recovery explains wallet sign-in removal before recovery`);await home();
    assert.equal(await page.getByRole('button',{name:'Use passkey',exact:true}).count(),1);
    await page.locator('[data-home-wallet-signin]:visible').click();await state('choice');await capture('signer-choice');await cancel();
    await home({scenario:'first-run'});assert.equal(await page.locator('[data-home-wallet-signin]:visible').count(),0);await capture('first-run');
    await home({scenario:'unsupported-browser'});await page.locator('#home-unlock-status').filter({hasText:'Passkeys are not available in this browser.'}).waitFor();await capture('passkeys-unavailable');
    await start();await state('review');await page.locator('.signin-dialog').getByRole('button',{name:'Sign in with wallet',exact:true}).click();await page.waitForFunction(()=>window.openedPrincipal==='principal:alex');fixture.state.calls=[];
    for(const connector of ['metamask','unisat','walletconnect']) {
      await home();await start(connector);
      if(connector==='walletconnect') {
        await state('pairing');await capture('walletconnect-pairing');
        await page.locator('.signin-dialog').getByRole('button',{name:'Copy link',exact:true}).click();await page.getByText('Link copied.',{exact:true}).waitFor();await capture('walletconnect-link-copied');
        await page.evaluate(()=>window.walletFixture.copyFailed=true);await page.locator('.signin-dialog').getByRole('button',{name:'Copy link',exact:true}).click();await page.getByText('Could not copy. Try again.',{exact:true}).waitFor();await capture('walletconnect-copy-failed');
        await pair();
      }
      await state('review');assert.equal(await page.locator('.signin-dialog').getByText('Confirm this wallet sign-in method change with your passkey.',{exact:true}).count(),0);await capture(`${connector}-signin-review`);
      assert.equal(fixture.state.calls.filter(c=>c.path.endsWith('/signin/complete')).length,0,'no completion before review');
      await page.locator('.signin-dialog').getByRole('button',{name:'Sign in with wallet',exact:true}).click();
      await page.waitForFunction(()=>window.openedPrincipal==='principal:alex');assert.equal(await page.evaluate(()=>window.openedFlow.walletSignin),true);assert(!fixture.state.calls.some(c=>c.path.startsWith('/api/auth/passkey-step-up/')),'Wallet sign-in opens without passkey approval');
      assert((await context.cookies(fixture.origin)).some(cookie=>cookie.name==='fixture-session'&&cookie.httpOnly),'Runtime session cookie is retained');await capture(`${connector}-same-account`);
      const persistent=await page.evaluate(()=>({local:Object.entries(localStorage),session:Object.entries(sessionStorage)}));
      assert(!JSON.stringify(persistent).includes('fixture-signature'));
      const secrets=fixture.state.calls.filter(c=>c.body?.browser_secret).map(c=>c.body.browser_secret);
      for(const secret of secrets)assert(!JSON.stringify(persistent).includes(secret),'browser secrets stay in memory');
      checks.push(`${engine}/${width} ${connector}: same account opens directly`);
      fixture.state.calls=[];
    }
    await home();await page.evaluate(()=>window.walletFixture.openFailed=true);await start();await state('review');await page.locator('.signin-dialog').getByRole('button',{name:'Sign in with wallet',exact:true}).click();
    await page.locator('#home-unlock-face-status').filter({hasText:'Home could not open after sign-in. Reload this page.'}).waitFor();await capture('home-open-failed');
    for(const scenario of ['missing','rejected','changed','busy','offline','refused','unknown','expired','pending','account-choice','disabled','unadded']) {
      await home({scenario:['busy','offline','refused','unknown','expired'].includes(scenario)?scenario:'normal',...(scenario==='disabled'?{methods:[sampleMethod('metamask',false)]}:scenario==='unadded'?{methods:[]}: {})});
      if(scenario==='missing')await page.evaluate(()=>window.walletFixture.missing=true);
      if(scenario==='rejected')await page.evaluate(()=>window.walletFixture.mode='rejected');
      if(scenario==='pending')await page.evaluate(()=>window.walletFixture.mode='pending');
      if(scenario==='account-choice')await page.evaluate(()=>window.walletFixture.multiple=true);
      if(scenario==='expired')await page.clock.install();
      await start();
      if(scenario==='account-choice') {await state('wallet-choice');await capture('browser-wallet-choice');await page.locator('.signin-dialog').getByRole('button',{name:'Rabby Wallet',exact:true}).click();await state('review');await cancel();continue;}
      if(scenario==='pending'){await state('connecting');await capture('select-account-pending');await cancel();continue;}
      if(['missing','busy','offline'].includes(scenario))await state('error');
      else {
        await state('review');
        if(scenario==='changed')await page.evaluate(()=>{window.walletFixture.address='0x'+'34'.repeat(20);window.emitSigninWallet('accountsChanged');});
        else if(scenario==='expired'){await page.clock.fastForward(1500);}
        else await page.locator('.signin-dialog').getByRole('button',{name:'Sign in with wallet',exact:true}).click();
        await state(scenario==='unknown'?'unknown':'error');
      }
      await capture(`signin-${scenario}`);
      if(scenario==='unknown') {
        const before=fixture.state.calls.filter(c=>c.path.endsWith('/signin/complete'));
        await page.evaluate(()=>{window.walletFixture.address='0x'+'34'.repeat(20);window.emitSigninWallet('accountsChanged');});await state('unknown');
        await page.locator('.signin-dialog').getByRole('button',{name:'Check again',exact:true}).click();await page.waitForFunction(()=>window.openedPrincipal==='principal:alex');
        const after=fixture.state.calls.filter(c=>c.path.endsWith('/signin/complete'));assert(JSON.stringify(after.at(-1).body)===JSON.stringify(before.at(-1).body),'Sign-in retry keeps the exact proof body');
      } else if(scenario==='unadded') {
        await page.locator('.signin-dialog').getByRole('button',{name:'Use passkey',exact:true}).click();await page.waitForFunction(()=>window.openedPrincipal==='principal:alex');await capture('passkey-after-wallet-refusal');
        assert.equal((await page.evaluate(()=>window.walletFixture.calls)).filter(call=>call.method==='passkey').length,1);
      } else {
        await cancel();
        if(scenario==='expired')await page.clock.resume();
      }
      checks.push(`${engine}/${width} sign-in: ${scenario}`);
    }
    for(const connector of ['metamask','unisat','walletconnect']) {
      await home();await start(connector);if(connector==='walletconnect'){await state('pairing');await pair();}
      await state('review');
      if(connector==='walletconnect')await page.evaluate(()=>document.querySelector('iframe[title=WalletConnect]').contentWindow.postMessage('fixture-sign-pending','*'));
      else await page.evaluate(()=>window.walletFixture.mode='pending');
      await page.locator('.signin-dialog').getByRole('button',{name:'Sign in with wallet',exact:true}).click();await state('signing');await capture(`${connector}-signing-pending`);await cancel();
      assert.equal(await page.evaluate(()=>window.openedPrincipal),'','Cancel keeps Home locked');
    }
    await home();fixture.state.holdComplete=true;await start();await state('review');await page.locator('.signin-dialog').getByRole('button',{name:'Sign in with wallet',exact:true}).click();await state('completing');await capture('signin-checking');
    await cancel();fixture.state.holdComplete=false;fixture.state.releaseComplete();
    assert.equal(await page.evaluate(()=>window.openedPrincipal),'');
    await home();await start('unisat');await state('review');await page.evaluate(()=>window.emitSigninWallet('disconnect'));await state('error');await page.getByText('The connection to your wallet ended. Try again.',{exact:true}).waitFor();await capture('unisat-disconnected');await cancel();
    await home();await page.evaluate(()=>window.walletFixture.network='testnet');await start('unisat');await state('error');await capture('unisat-unsupported-network');await cancel();
    await home();await page.evaluate(()=>delete window.unisat);await start('unisat');await state('error');await capture('unisat-missing');await cancel();
    await home();await start('walletconnect');await state('pairing');
    await page.evaluate(()=>document.querySelector('iframe[title=WalletConnect]').contentWindow.postMessage({type:'fixture-network',chain:1},'*'));
    await page.evaluate(()=>document.querySelector('iframe[title=WalletConnect]').contentWindow.postMessage('fixture-pair','*'));
    await state('error');await capture('walletconnect-unsupported-network');await cancel();
    await home();await start('walletconnect');await state('pairing');await pair();
    await page.evaluate(()=>document.querySelector('iframe[title=WalletConnect]').contentWindow.postMessage('fixture-account-change','*'));
    await state('error');await capture('walletconnect-account-changed');await cancel();
    await home();await start('walletconnect');await state('pairing');await cancel();
    assert.equal(await page.locator('iframe[title=WalletConnect]').count(),0,'Cancel removes the temporary SDK document');
    await home();fixture.state.methods=[sampleMethod('metamask',false)];await page.evaluate(()=>window.showFixtureApps());
    const system=page.frameLocator('iframe[title=system]');
    await system.getByRole('button',{name:'Add wallet',exact:true}).waitFor();
    await system.locator('[data-wallet-method]').waitFor();await capture('system-methods',await page.frames().find(f=>f.url().includes('/apps/system/')));
    await system.getByText('Safari on Mac',{exact:false}).waitFor();
    await system.locator('[data-wallet-method]').scrollIntoViewIfNeeded();await capture('system-wallet-row');
    await system.locator('[data-passkey-revoke]').isDisabled().then(disabled=>assert(disabled,'last Admin passkey protected'));
    await system.getByRole('switch').click();await state('review');await page.getByText(relayNotice,{exact:true}).waitFor();await capture('enable-review');
    await page.locator('.signin-dialog').getByRole('button',{name:'Sign message',exact:true}).click();await state('approval');await capture('enable-approval');
    await page.evaluate(()=>window.walletFixture.passkeyMode='pending');await page.locator('.signin-dialog').getByRole('button',{name:'Use passkey',exact:true}).click();await state('passkey');await capture('passkey-pending');await cancel();
    assert.equal(fixture.state.methods[0].sign_in_enabled,false,'cancelled passkey leaves switch off');
    await page.evaluate(()=>window.walletFixture.passkeyMode='cancelled');
    await system.getByRole('switch').click();await state('review');await page.locator('.signin-dialog').getByRole('button',{name:'Sign message',exact:true}).click();await state('approval');await page.locator('.signin-dialog').getByRole('button',{name:'Use passkey',exact:true}).click();await state('approval');await page.getByText('Home could not confirm your passkey.',{exact:false}).waitFor();await capture('passkey-cancelled');
    await page.evaluate(()=>window.walletFixture.passkeyMode='normal');await page.locator('.signin-dialog').getByRole('button',{name:'Use passkey',exact:true}).click();await state('done');await capture('enable-done');await page.locator('.signin-dialog').getByRole('button',{name:'Done',exact:true}).click();
    await system.locator('[role=switch][aria-checked=true]').waitFor();await capture('system-enabled');
    await page.locator('#show-wallet').click();const wallet=page.frameLocator('iframe[title=wallet]');await wallet.locator('#wallet-signin-methods [role=switch][aria-checked=true]').waitFor();await wallet.locator('#wallet-signin-methods').scrollIntoViewIfNeeded();await capture('wallet-methods',page.frames().find(f=>f.url().includes('/apps/wallet/')));
    await wallet.locator('#wallet-signin-methods [role=switch]').click();await state('review');await capture('disable-review');
    await page.locator('.signin-dialog').getByRole('button',{name:'Use passkey',exact:true}).click();await state('done');await capture('disable-done');await page.locator('.signin-dialog').getByRole('button',{name:'Done',exact:true}).click();
    await page.locator('#show-system').click();await system.locator('[role=switch][aria-checked=false]').waitFor();
    await system.locator('[data-wallet-method]').getByRole('button',{name:'Remove',exact:true}).click();await state('review');await capture('remove-review');await page.locator('.signin-dialog').getByRole('button',{name:'Use passkey',exact:true}).click();await state('done');await capture('remove-done');await page.locator('.signin-dialog').getByRole('button',{name:'Done',exact:true}).click();
    assert.equal(fixture.state.methods.length,0);
    await page.locator('#show-wallet').click();await wallet.locator('[data-wallet-method="payment:payment:one"] [role=switch]').waitFor();
    assert(await wallet.locator('[data-wallet-method="payment:payment:one"] [role=switch]').isDisabled());await wallet.locator('#wallet-signin-methods').scrollIntoViewIfNeeded();await capture('wallet-payment-only');
    await page.locator('#show-system').click();
    for(const connector of ['metamask','unisat','walletconnect']) {
      await system.getByRole('button',{name:'Add wallet',exact:true}).click();await state('choice');await capture(`add-${connector}-choice`);
      await page.locator('.signin-dialog').getByRole('button',{name:({metamask:'MetaMask',unisat:'UniSat',walletconnect:'WalletConnect'})[connector],exact:connector!=='metamask'}).click();
      if(connector==='walletconnect'){await state('pairing');await pair();}
      await state('review');await capture(`add-${connector}-review`);await page.locator('.signin-dialog').getByRole('button',{name:'Sign message',exact:true}).click();await state('approval');await page.locator('.signin-dialog').getByRole('button',{name:'Use passkey',exact:true}).click();await state('done');await capture(`add-${connector}-done`);await page.locator('.signin-dialog').getByRole('button',{name:'Done',exact:true}).click();
      assert.equal(fixture.state.methods.find(m=>m.connector===connector).sign_in_enabled,false,'added wallet defaults off');
      assert.equal(fixture.state.methods.find(m=>m.connector===connector).last_used_at,null,'new method has never signed in');
      await system.locator(`[data-wallet-method="wallet:${connector}"]`).getByText('Not used yet',{exact:true}).waitFor();
    }
    for(const connector of ['unisat','walletconnect']) {
      const row=system.locator(`[data-wallet-method="wallet:${connector}"]`);
      await row.getByRole('switch').click();
      if(connector==='walletconnect'){await state('pairing');await pair();}
      await state('review');await capture(`${connector}-enable-review`);
      await page.locator('.signin-dialog').getByRole('button',{name:'Sign message',exact:true}).click();await state('approval');await capture(`${connector}-enable-approval`);
      await page.locator('.signin-dialog').getByRole('button',{name:'Use passkey',exact:true}).click();await state('done');await capture(`${connector}-enable-done`);await page.locator('.signin-dialog').getByRole('button',{name:'Done',exact:true}).click();
    }
    fixture.state.scenario='unknown';
    await system.locator('[data-wallet-method="wallet:metamask"]').getByRole('button',{name:'Remove',exact:true}).click();await state('review');await page.locator('.signin-dialog').getByRole('button',{name:'Use passkey',exact:true}).click();await state('unknown');await capture('remove-result-retry');
    await page.locator('.signin-dialog').getByRole('button',{name:'Check again',exact:true}).click();await state('done');await page.locator('.signin-dialog').getByRole('button',{name:'Done',exact:true}).click();fixture.state.scenario='normal';
    checks.push(`${engine}/${width}: add all three connectors, enable, disable, remove, passkey cancel/retry, one record across System and Wallet`);
    for(const action of ['add','enable','disable','remove'])for(const outcome of ['busy','refused','unknown']) {
      fixture.state.methods=action==='add'?[]:[sampleMethod('metamask',['disable','remove'].includes(action))];
      fixture.state.scenario='normal';
      await page.evaluate(()=>document.querySelector('iframe[title=system]').contentWindow.postMessage({type:'home:wallet-signin-changed'},'*'));
      if(action==='add')await system.locator('[data-wallet-method]').first().waitFor({state:'detached'});
      else await system.locator(`[data-wallet-method="wallet:metamask"] [role=switch][aria-checked=${['disable','remove'].includes(action)}]`).waitFor();
      fixture.state.scenario=outcome;
      if(action==='add') {
        await system.getByRole('button',{name:'Add wallet',exact:true}).click();await state('choice');await page.locator('.signin-dialog').getByRole('button',{name:'MetaMask',exact:false}).click();
      } else if(action==='remove')await system.locator('[data-wallet-method="wallet:metamask"]').getByRole('button',{name:'Remove',exact:true}).click();
      else await system.locator('[data-wallet-method="wallet:metamask"]').getByRole('switch').click();
      if(outcome!=='busy') {
        await state('review');
        await page.locator('.signin-dialog').getByRole('button',{name:['disable','remove'].includes(action)?'Use passkey':'Sign message',exact:true}).click();
        if(['add','enable'].includes(action)){await state('approval');await page.locator('.signin-dialog').getByRole('button',{name:'Use passkey',exact:true}).click();}
      }
      await state(outcome==='unknown'?'unknown':'error');await capture(`${action}-${outcome}`);
      if(outcome==='unknown') {
        const before=fixture.state.calls.filter(c=>c.path==='/api/auth/wallet-methods/complete').at(-1).body;
        await page.locator('.signin-dialog').getByRole('button',{name:'Check again',exact:true}).click();await state('done');await capture(`${action}-retry-done`);
        assert(JSON.stringify(fixture.state.calls.filter(c=>c.path==='/api/auth/wallet-methods/complete').at(-1).body)===JSON.stringify(before),'Method retry keeps the exact approved proof body');
        await page.locator('.signin-dialog').getByRole('button',{name:'Done',exact:true}).click();
      } else await cancel();
      fixture.state.scenario='normal';
      checks.push(`${engine}/${width} ${action}: ${outcome}`);
    }
    fixture.state.methods=[sampleMethod('metamask',false)];fixture.state.scenario='normal';
    await page.evaluate(()=>document.querySelector('iframe[title=system]').contentWindow.postMessage({type:'home:wallet-signin-changed'},'*'));
    await system.locator('[data-wallet-method="wallet:metamask"] [role=switch][aria-checked=false]').waitFor();
    await system.getByRole('button',{name:'Add wallet',exact:true}).click();await state('choice');await page.locator('.signin-dialog').getByRole('button',{name:'MetaMask',exact:false}).click();await state('error');await capture('add-already-added');
    await page.locator('.signin-dialog').getByRole('button',{name:'Refresh',exact:true}).click();await page.locator('.signin-dialog').waitFor({state:'detached'});await system.locator('[data-wallet-method="wallet:metamask"]').waitFor();
    fixture.state.otherAdmin=true;
    await page.evaluate(()=>document.querySelector('iframe[title=system]').contentWindow.postMessage({type:'home:wallet-signin-changed'},'*'));
    await system.getByText('Morgan',{exact:true}).waitFor();
    await system.locator('[data-passkey-revoke="passkey:other"]').click();
    await system.getByText("This is the account's last passkey. Home will also clear its wallet sign-in access.",{exact:true}).waitFor();await capture('last-passkey-review');
    await system.locator('#passkey-remove-dialog').getByRole('button',{name:'Cancel',exact:true}).click();fixture.state.otherAdmin=false;
    fixture.state.scenario='passkeys-load-failed';await page.evaluate(()=>document.querySelector('iframe[title=system]').contentWindow.postMessage({type:'home:wallet-signin-changed'},'*'));
    await system.getByText('Home could not load sign-in methods.',{exact:true}).waitFor();await capture('system-passkeys-load-failed');
    fixture.state.scenario='normal';await system.locator('#account-list').getByRole('button',{name:'Try again',exact:true}).click();await system.getByText('Safari on Mac',{exact:false}).waitFor();await capture('system-reloaded');
    fixture.state.scenario='load-failed';await page.evaluate(()=>{for(const f of document.querySelectorAll('#fixture-desktop iframe'))f.contentWindow.postMessage({type:'home:wallet-signin-changed'},'*');});await system.getByText('Home could not load wallet sign-in methods.',{exact:true}).waitFor();await capture('system-load-failed');
    fixture.state.role='guest';await home({methods:[sampleMethod('metamask',false)]});await page.evaluate(()=>window.showFixtureApps());
    const guestSystem=page.frameLocator('iframe[title=system]');await guestSystem.locator('[data-wallet-method] [role=switch]').waitFor();
    assert(await guestSystem.locator('[data-wallet-method] [role=switch]').isDisabled());assert.equal(await guestSystem.getByRole('button',{name:'Add wallet',exact:true}).count(),0);
    await guestSystem.getByText('Keep at least one sign-in method for this account.',{exact:true}).waitFor();await capture('system-guest-last-method');
    await page.locator('#show-wallet').click();const guestWallet=page.frameLocator('iframe[title=wallet]');await guestWallet.locator('#wallet-signin-methods [role=switch]').waitFor();assert(await guestWallet.locator('#wallet-signin-methods [role=switch]').isDisabled());await guestWallet.locator('#wallet-signin-methods').scrollIntoViewIfNeeded();await capture('wallet-guest');
    checks.push(`${engine}/${width}: Guest controls and last sign-in method protected`);
    assert.deepEqual(outside,[],'all traffic uses fixture Runtime');
    assert.deepEqual(errors,[],'no page errors');
    const signerPaths=fixture.state.calls.filter(c=>c.path.startsWith('/api/auth/wallet-methods'));
    assert(signerPaths.every(c=>c.headers.authorization?.startsWith('Bearer ')),'method routes carry launch authorization');
    const transports=fixture.state.calls.filter(c=>c.path.startsWith('/api/apps/wallet-walletconnect/'));
    assert(transports.length>0);assert(transports.every(c=>c.headers['x-elastos-wallet-attempt']?.startsWith('fixture-attempt:')&&c.headers['x-elastos-wallet-instance']&&c.headers['if-match']==='"0"'),'temporary connector and revision headers');
    assert(!fixture.state.calls.some(c=>c.path.startsWith('/api/auth/wallet-methods')&&c.headers['x-elastos-home-token']==='fixture-wallet'),'Wallet uses Home authority for methods');
  } catch(error) {
    await page.screenshot({path:join(output,`${engine}-${width}-failure.png`),fullPage:true}).catch(()=>{});
    console.error('Failing screen state:',await page.locator('.signin-dialog').count()?await page.locator('.signin-dialog').getAttribute('data-state'):null,'page errors:',errors);
    console.error('Recent fixture routes:',fixture.state.calls.slice(-12).map(({path,status})=>({path,status})));
    throw error;
  } finally {await context.close();await browser.close();await fixture.close();}
}
try {
  for(const engine of (process.env.SIGNIN_ENGINE?[process.env.SIGNIN_ENGINE]:['chromium','webkit']))for(const width of widths)await exercise(engine,width);
  passed=true;
} finally {
  const sources={};
  for(const file of ['scripts/lib/wallet-signin-fixture.mjs','scripts/wallet-signin-browser-smoke.mjs','capsules/home/browser/index.html','capsules/home/browser/shell-core.js','capsules/home/browser/home-shell-host.js','capsules/system/browser/index.html','capsules/wallet/browser/index.html','capsules/home/browser/wallet-signin-flow.mjs','capsules/home/browser/wallet-signin-signers.mjs','capsules/home/browser/wallet-signin-view.mjs','capsules/home/browser/wallet-signin-host.mjs','capsules/home/browser/wallet-signin-methods.mjs','capsules/home/browser/wallet-signin.css','capsules/home/browser/shell-auth.js','capsules/system/browser/system.js','capsules/wallet/browser/wallet.js','capsules/wallet-walletconnect/browser/signin-transport.mjs','capsules/wallet-walletconnect/browser/walletconnect-pairing.mjs'])sources[file]=createHash('sha256').update(await readFile(file)).digest('hex');
  await writeFile(join(output,'index.json'),JSON.stringify({status:passed?'PASS':'FAIL',environment:{node:process.version,platform:process.platform,arch:process.arch,browsers:browserVersions},head:execFileSync('git',['rev-parse','HEAD'],{encoding:'utf8'}).trim(),tree:execFileSync('git',['rev-parse','HEAD^{tree}'],{encoding:'utf8'}).trim(),dirty:execFileSync('git',['status','--short'],{encoding:'utf8'}).trim(),sources,pictures,checks},null,2)+'\n');
  await writeFile(join(output,'index.html'),`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Wallet sign-in screens</title><style>body{font:14px/1.5 system-ui;margin:24px;background:#f4f5f7;color:#18202b}main{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:20px}article{background:white;border:1px solid #ccd0d8;border-radius:12px;padding:16px}img{width:100%;height:240px;object-fit:contain;background:#e4e7eb}h2{font-size:14px}</style><h1>Wallet sign-in fixture screens: ${passed?'PASS':'FAIL'}</h1><p>Fixture Runtime. Wallet signers and passkeys are replaced at their boundaries.</p><p>${pictures.length} captures. <a href="index.json">Hashes, source identity and checks</a></p><main>${pictures.map(p=>`<article><h2>${p.engine} · ${p.width} px · ${p.state}</h2><a href="${encodeURIComponent(basename(p.file))}"><img loading="lazy" src="${encodeURIComponent(basename(p.file))}" alt="${p.state}"></a></article>`).join('')}</main></html>`);

}
console.log(`Wallet sign-in browser smoke PASS: ${checks.length} checks, ${pictures.length} screenshots.`);
