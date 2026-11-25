import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdir,writeFile,readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {signinFixture,installSigninProviders,sampleMethod,evmAddress,bitcoinAddress,walletconnectAddress} from './lib/wallet-signin-fixture.mjs';
import {requireProductSmokePlaywright,productSmokeLaunchOptions} from './product-smoke-browser.mjs';

const output=process.env.WALLET_ONE_LIST_SCREENS;
const captureRecords=[];
const btc='bip122:000000000019d6689c085ae165831e93';
const fixtureAddresses={home:'0x42e8a1b23597c9d48605f162ab30cd84e9123a71',evm:'0x7a3b4116a8ce04ed72562ac0904c3b6510239f20',bitcoin:'bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh',phone:'0x91d4f5a3c2179bed640d67ea5fc8a7dc55146c08'};
function seed(state,{pictures=false}={}) {
  const addresses=pictures?fixtureAddresses:{...fixtureAddresses,evm:evmAddress,bitcoin:bitcoinAddress,phone:walletconnectAddress};
  state.theme='dark';state.walletAddresses=addresses;
  state.connected=[
    {account_id:'home-address',address:addresses.home,chain_namespace:'eip155:20',proof_type:'managed_evm',label:'Home address'},
    {account_id:'app:metamask',address:addresses.evm,chain_namespace:'eip155:8453',proof_type:'siwe',connector_id:'wallet-metamask',wallet_display_name:'MetaMask'},
    {account_id:'app:phone',address:addresses.phone,chain_namespace:'eip155:8453',proof_type:'siwe',connector_id:'wallet-walletconnect',wallet_display_name:'Rainbow',wallet_mark:'wallet'},
  ];
  state.methods=[{...sampleMethod('unisat'),address:addresses.bitcoin},{...sampleMethod('walletconnect'),address:addresses.phone,chain_id:8453}];
  state.balanceValues={[addresses.home]:{'esc-mainnet':String(125n*10n**18n)}};state.passkeyCount=2;
  return addresses;
}
async function shot(frame,id,width,engine) {
  if(!output || engine!=='chromium')return;
  await mkdir(output,{recursive:true});await frame.locator('body').evaluate(async()=>{await document.fonts.ready;await new Promise(requestAnimationFrame);});
  const file=`a2-${id}-${width}.png`, bytes=await frame.locator('body').screenshot({path:join(output,file),animations:'disabled'});
  const bounds=await frame.locator('body').evaluate(()=>({width:innerWidth,scrollWidth:document.documentElement.scrollWidth,height:document.body.scrollHeight,text:document.body.innerText}));
  assert.equal(bounds.scrollWidth,width,id+' has horizontal overflow');
  captureRecords.push({file,sha256:createHash('sha256').update(bytes).digest('hex'),...bounds});
}
async function setup(engine,width,{pictures=false}={}) {
  if(output)assert.equal(execFileSync('git',['status','--porcelain'],{encoding:'utf8'}).trim(),'','pictures require committed source');
  const fixture=await signinFixture(),addresses=seed(fixture.state,{pictures});
  const browser=await requireProductSmokePlaywright()[engine].launch({headless:true,...(engine==='chromium'?productSmokeLaunchOptions():{})});
  const context=await browser.newContext({viewport:{width,height:1000},colorScheme:'dark',reducedMotion:'reduce'});
  await context.addInitScript(installSigninProviders,{evmAddress:addresses.evm,bitcoinAddress:addresses.bitcoin,theme:'dark'});
  if(process.env.WALLET_ONE_LIST_BASELINE)await context.route('**/apps/wallet/**',async route=>{
    const path='capsules/wallet/browser/'+new URL(route.request().url()).pathname.split('/apps/wallet/')[1].split('?')[0];
    try {const body=execFileSync('git',['show',`${process.env.WALLET_ONE_LIST_BASELINE}:${path.endsWith('/')?path+'index.html':path}`]);await route.fulfill({body,contentType:path.endsWith('.js')?'text/javascript':path.endsWith('.css')?'text/css':'text/html'});}catch{await route.continue();}
  });
  if(process.env.WALLET_CONNECTOR_BASELINE)await context.route('**/apps/home/wallet-connection-view.mjs*',route=>route.fulfill({contentType:'text/javascript',body:execFileSync('git',['show',`${process.env.WALLET_CONNECTOR_BASELINE}:capsules/_shared/wallet-connection-view.mjs`])}));
  const page=await context.newPage();page.setDefaultTimeout(8000);const errors=[];page.on('pageerror',e=>errors.push(e.message));
  await page.goto(fixture.origin+'/home/');await page.waitForFunction(()=>window.fixtureReady);await page.evaluate(()=>{walletFixture.chain=8453;window.showFixtureApps();});
  const wallet=page.frameLocator('iframe[title=wallet]'),system=page.frameLocator('iframe[title=system]');
  return {fixture,browser,context,page,wallet,system,addresses,errors,close:async()=>{await context.close();await browser.close();await fixture.close();}};
}
async function show(f,target) {await f.page.evaluate(target=>document.querySelector('#show-'+target).click(),target);}
async function refresh(f) {await f.wallet.locator('body').evaluate(()=>window.dispatchEvent(new Event('focus')));}
for(const engine of ['chromium','webkit'])for(const width of [1440,390]) {
  test(`one wallet list: real Wallet list and entries in ${engine} at ${width}`,{timeout:90000},async()=>{
    const f=await setup(engine,width,{pictures:Boolean(output)});
    try {
      await show(f,'wallet');await f.wallet.locator('.one-wallet').nth(3).waitFor();
      assert.equal(await f.wallet.locator('.one-wallet').count(),4);assert.equal(await f.wallet.getByRole('switch').count(),0);
      assert.equal(await f.wallet.getByRole('button',{name:'Add wallet for apps',exact:true}).count(),1);
      assert.match(await f.wallet.locator('#wallet-inventory').innerText(),/To sign in with a wallet, use System > Accounts\./);
      assert.equal(await f.wallet.locator('#wallet-methods').count(),0);
      await shot(f.wallet,'wallet-list',width,engine);
      await f.wallet.getByRole('button',{name:'Open UniSat',exact:true}).click();
      await f.wallet.getByRole('heading',{name:'Used by',exact:true}).waitFor();
      const toggle=f.wallet.getByRole('switch',{name:'Apps and websites',exact:true});
      assert.equal(await toggle.getAttribute('aria-checked'),'false');
      assert.match(await f.wallet.locator('.one-owner').first().innerText(),/System: signs in to Alex's account/);
      assert.equal(await f.wallet.getByRole('link',{name:'Manage in System'}).count(),1);
      assert.equal(await f.wallet.getByText('Sending Bitcoin from this Home is not available yet.',{exact:true}).count(),1);
      await shot(f.wallet,'unisat-entry',width,engine);
      await toggle.click();await f.wallet.getByRole('dialog',{name:'Connect for apps'}).waitFor();await shot(f.wallet,'unisat-app-signature',width,engine);
      await f.wallet.getByRole('button',{name:'Cancel',exact:true}).click();assert.equal(await toggle.getAttribute('aria-checked'),'false');
      assert.equal(f.fixture.state.calls.filter(c=>c.path.endsWith('/bitcoin/link/verify')).length,0);
      await toggle.click();await f.wallet.getByRole('button',{name:'Sign message',exact:true}).click();
      await f.wallet.getByText('Connected for apps.',{exact:true}).waitFor();assert.equal(await toggle.getAttribute('aria-checked'),'true');
      assert.equal(f.fixture.state.methods.filter(m=>m.connector==='unisat').length,1);
      assert.equal(f.fixture.state.calls.filter(c=>c.path.endsWith('/bitcoin/link/verify')).length,1);
      assert.equal(await f.page.evaluate(()=>walletFixture.calls.filter(c=>c.method==='signMessage').length),1);
      await shot(f.wallet,'unisat-app-connected',width,engine);
      await f.wallet.getByRole('button',{name:'Back to wallets',exact:true}).click();await f.wallet.getByRole('button',{name:'Open Rainbow',exact:true}).click();
      await shot(f.wallet,'rainbow-entry',width,engine);assert.equal(await toggle.getAttribute('aria-checked'),'true');
      await toggle.click();await f.wallet.getByRole('dialog',{name:'Turn off app use?'}).waitFor();
      assert.match(await f.wallet.getByRole('dialog').innerText(),/for this wallet only \(Rainbow\)/);await shot(f.wallet,'rainbow-app-off-passkey',width,engine);
      await f.wallet.getByRole('button',{name:'Cancel',exact:true}).click();assert.equal(await toggle.getAttribute('aria-checked'),'true');
      await toggle.click();await f.page.evaluate(()=>walletFixture.passkeyMode='cancelled');await f.wallet.getByRole('button',{name:'Approve with passkey',exact:true}).click();
      await f.wallet.locator('.one-dialog [role=alert]').waitFor();assert.equal(await toggle.getAttribute('aria-checked'),'true');
      await f.page.evaluate(()=>walletFixture.passkeyMode='normal');await f.wallet.getByRole('button',{name:'Approve with passkey',exact:true}).click();
      await f.wallet.getByText('App use turned off.',{exact:true}).waitFor();assert.equal(await toggle.getAttribute('aria-checked'),'false');
      assert(f.fixture.state.methods.some(m=>m.connector==='walletconnect'));assert(f.fixture.state.connected.some(a=>a.connector_id==='wallet-metamask'));
      await shot(f.wallet,'rainbow-app-off-complete',width,engine);await refresh(f);assert.equal(await toggle.getAttribute('aria-checked'),'false');
      assert.deepEqual(f.errors,[]);
    } finally {await f.close();}
  });
  test(`one wallet list: real System Accounts, Add, Remove and exact-entry link in ${engine} at ${width}`,{timeout:90000},async()=>{
    const f=await setup(engine,width,{pictures:Boolean(output)});
    try {
      await f.system.locator('[data-wallet-method]').nth(1).waitFor();
      assert.equal(await f.system.getByRole('heading',{name:'Wallets for sign-in',exact:true}).count(),1);
      assert.equal(await f.system.getByRole('link',{name:'Open Wallet',exact:true}).count(),2);
      await shot(f.system,'system-accounts',width,engine);
      await f.system.locator('[data-wallet-method]').filter({hasText:'UniSat'}).getByRole('link',{name:'Open Wallet'}).click();
      await f.wallet.getByRole('heading',{name:'Used by'}).waitFor();assert.equal(await f.wallet.locator('.one-identity strong').textContent(),'UniSat');
      await f.wallet.getByRole('link',{name:'Manage in System'}).click();
      await f.system.getByRole('button',{name:'Add wallet',exact:true}).click();
      const dialog=f.page.locator('.signin-dialog');await dialog.locator('.connection-option').nth(2).waitFor();
      await shot(f.page,'system-add-chooser',width,engine);
      await dialog.locator('.connection-option').filter({hasText:'MetaMask'}).click();await dialog.getByRole('button',{name:'Sign message',exact:true}).waitFor();
      await shot(f.page,'system-add-signature',width,engine);assert.equal(f.fixture.state.methods.length,2);
      await dialog.getByRole('button',{name:'Sign message',exact:true}).click();await dialog.getByRole('button',{name:'Approve with passkey',exact:true}).waitFor();
      await shot(f.page,'system-add-passkey',width,engine);assert.equal(f.fixture.state.methods.length,2);
      await dialog.getByRole('button',{name:'Approve with passkey',exact:true}).click();
      await f.system.locator('[data-wallet-method]').nth(2).waitFor();assert.equal(f.fixture.state.methods.length,3);
      assert.equal(await f.page.evaluate(()=>walletFixture.calls.filter(c=>c.method==='personal_sign').length),1);
      assert.equal(f.fixture.state.calls.filter(c=>c.path==='/api/auth/passkey-step-up/complete').length,1);
      await shot(f.system,'system-add-returned',width,engine);
      await show(f,'wallet');await f.wallet.getByRole('button',{name:'Back to wallets',exact:true}).click();await refresh(f);
      await f.wallet.locator('.one-wallet').filter({hasText:'MetaMask'}).filter({hasText:"Signs in to Alex's account"}).waitFor();
      assert.equal(await f.wallet.locator('.one-wallet').count(),4);await shot(f.wallet,'wallet-list-after-system-add',width,engine);
      await show(f,'system');await f.system.locator('[data-wallet-method]').filter({hasText:'MetaMask'}).getByRole('button',{name:'Remove from sign-in',exact:true}).click();
      await f.system.locator('[data-wallet-method]').filter({hasText:'MetaMask'}).waitFor({state:'detached'});
      assert(f.fixture.state.connected.some(a=>a.connector_id==='wallet-metamask'));assert.equal(f.fixture.state.calls.filter(c=>c.path==='/api/auth/passkey-step-up/complete').length,2);
      assert.deepEqual(f.errors,[]);
    } finally {await f.close();}
  });
  test(`one wallet list: connector names once in real ${engine} renderer at ${width}`,{timeout:30000},async()=>{
    const f=await setup(engine,width);
    try {
      for(const kind of ['metamask','unisat','walletconnect']) {
        await f.page.goto(f.fixture.origin+'/apps/wallet/');
        const measurements=await f.page.evaluate(async kind=>{
          const {connectionView,renderConnection}=await import('/apps/home/wallet-connection-view.mjs');
          const name=kind==='walletconnect'?'Rainbow':kind==='unisat'?'UniSat':'MetaMask';
          const view=connectionView({window:kind,stage:'linked',localSafety:false,account:{name,mark:kind==='walletconnect'?'wallet':kind,connection:kind==='walletconnect'?'WalletConnect':null,accounts:[{address:kind==='unisat'?'bc1qtestaddress':'0x'+'12'.repeat(20),networks:[kind==='unisat'?'Bitcoin':'Base']}]},supportedActions:['copy-address','close-window']});
          const bar=document.createElement('header');bar.textContent=kind==='walletconnect'?'WalletConnect':name;
          document.body.replaceChildren(bar,renderConnection(document,view));
          return {text:document.body.innerText,peer:document.querySelector('.connection-account-name')?.textContent};
        },kind);
        const brand=kind==='walletconnect'?'WalletConnect':kind==='unisat'?'UniSat':'MetaMask';
        assert.equal(measurements.text.split(brand).length-1,1,measurements.text);
        if(kind==='walletconnect')assert.equal(measurements.peer,'Rainbow');
      }
    } finally {await f.close();}
  });
}
test.after(async()=>{if(output){const sources={};for(const path of ['capsules/wallet/browser/index.html','capsules/wallet/browser/wallet.js','capsules/wallet/browser/wallet-inventory.js','capsules/wallet/browser/wallet-inventory.css','capsules/system/browser/system.js','capsules/system/browser/style.css','capsules/home/browser/wallet-signin-view.mjs','capsules/home/browser/wallet-signin-management.mjs','capsules/_shared/wallet-connection-view.mjs'])sources[path]=createHash('sha256').update(await readFile(path)).digest('hex');await writeFile(join(output,'captures.json'),JSON.stringify({sources,head:execFileSync('git',['rev-parse','HEAD'],{encoding:'utf8'}).trim(),tree:execFileSync('git',['rev-parse','HEAD^{tree}'],{encoding:'utf8'}).trim(),captures:captureRecords},null,2)+'\n');}});
