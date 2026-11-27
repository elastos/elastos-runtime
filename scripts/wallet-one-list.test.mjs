import { historicalTestSource } from './lib/historical-test-source.mjs';
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
  if(pictures){state.otherAdmin=true;state.otherRole='guest';state.otherDisplayName='Sam';state.passkeyLabels=['This computer','Security key'];}
  state.connected=[
    {account_id:'home-address',address:addresses.home,chain_namespace:'eip155:20',proof_type:'managed_evm',label:'Home address'},
    {account_id:'app:metamask',address:addresses.evm,chain_namespace:'eip155:8453',proof_type:'siwe',connector_id:'wallet-metamask',wallet_display_name:'MetaMask'},
    {account_id:'app:phone',address:addresses.phone,chain_namespace:'eip155:8453',proof_type:'siwe',connector_id:'wallet-walletconnect',wallet_display_name:'Rainbow',wallet_mark:'wallet'},
  ];
  state.methods=[{...sampleMethod('unisat'),address:addresses.bitcoin},{...sampleMethod('walletconnect'),address:addresses.phone,chain_id:8453}];
  state.balanceValues={[addresses.home]:{'esc-mainnet':String(125n*10n**18n)}};state.passkeyCount=2;
  return addresses;
}
async function shot(frame,id,width,engine,page) {
  if(!output || engine!=='chromium')return;
  page ||= typeof frame.owner==='function' ? frame.owner().page() : frame;
  const height=await frame.locator('body').evaluate(node=>Math.max(1000,node.scrollHeight,node.querySelector('.settings-content-container')?.scrollHeight||0));
  await page.setViewportSize({width,height});
  await mkdir(output,{recursive:true});await frame.locator('body').evaluate(async()=>{await document.fonts.ready;await new Promise(requestAnimationFrame);});
  const file=`a2-${id}-${width}.png`, bytes=await frame.locator('body').screenshot({path:join(output,file),animations:'disabled'});
  const brightPixels=await frame.locator('body').evaluate(async(_body,data)=>{
    const image=new Image();image.src=data;await image.decode();
    const canvas=document.createElement('canvas');canvas.width=image.width;canvas.height=image.height;
    const context=canvas.getContext('2d');context.drawImage(image,0,0);
    const pixels=context.getImageData(0,0,canvas.width,canvas.height).data;let count=0;
    for(let i=0;i<pixels.length;i+=4)if(pixels[i]+pixels[i+1]+pixels[i+2]>360)count++;
    return count;
  },'data:image/png;base64,'+bytes.toString('base64'));
  assert(brightPixels>100,id+' screenshot contains visible content');
  const bounds=await frame.locator('body').evaluate(()=>({width:innerWidth,scrollWidth:document.documentElement.scrollWidth,height:document.body.scrollHeight,text:document.body.innerText}));
  assert.equal(bounds.scrollWidth,width,id+' has horizontal overflow');
  captureRecords.push({file,sha256:createHash('sha256').update(bytes).digest('hex'),brightPixels,...bounds});
  await page.setViewportSize({width,height:1000});
}
async function setup(engine,width,{pictures=false}={}) {
  if(output)assert.equal(execFileSync('git',['status','--porcelain'],{encoding:'utf8'}).trim(),'','pictures require committed source');
  const fixture=await signinFixture(),addresses=seed(fixture.state,{pictures});
  let browser,context;
  try {
  browser=await requireProductSmokePlaywright()[engine].launch({headless:true,...(engine==='chromium'?productSmokeLaunchOptions():{})});
  context=await browser.newContext({viewport:{width,height:1000},colorScheme:'dark',reducedMotion:'reduce'});
  await context.addInitScript(installSigninProviders,{evmAddress:addresses.evm,bitcoinAddress:addresses.bitcoin,theme:'dark'});
  if(process.env.WALLET_ONE_LIST_BASELINE)await context.route('**/apps/wallet/**',async route=>{
    if(new URL(route.request().url()).pathname.startsWith('/api/'))return route.continue();
    const path='capsules/wallet/browser/'+new URL(route.request().url()).pathname.split('/apps/wallet/')[1].split('?')[0];
    try {const body=historicalTestSource(`${process.env.WALLET_ONE_LIST_BASELINE}:${path.endsWith('/')?path+'index.html':path}`);await route.fulfill({body,contentType:path.endsWith('.js')?'text/javascript':path.endsWith('.css')?'text/css':'text/html'});}catch{await route.continue();}
  });
  if(process.env.WALLET_CONNECTOR_BASELINE)await context.route('**/apps/home/wallet-connection-view.mjs*',route=>route.fulfill({contentType:'text/javascript',body:historicalTestSource(`${process.env.WALLET_CONNECTOR_BASELINE}:capsules/_shared/wallet-connection-view.mjs`)}));
  const page=await context.newPage();page.setDefaultTimeout(8000);const errors=[];page.on('pageerror',e=>errors.push(e.message));
  await page.goto(fixture.origin+'/home/');await page.waitForFunction(()=>window.fixtureReady);await page.evaluate(()=>{walletFixture.chain=8453;window.showFixtureApps();});
  const wallet=page.frameLocator('iframe[title=wallet]'),system=page.frameLocator('iframe[title=system]');
  await wallet.locator('.one-wallet').nth(3).waitFor({state:'attached'});await system.locator('[data-wallet-method]').nth(1).waitFor({state:'attached'});
  return {fixture,browser,context,page,wallet,system,addresses,errors,close:async()=>{await context.close();await browser.close();await fixture.close();}};
  } catch(error) {await context?.close().catch(()=>{});await browser?.close().catch(()=>{});await fixture.close();throw error;}
}
async function show(f,target) {await f.page.evaluate(target=>document.querySelector('#show-'+target).click(),target);}
async function refresh(f) {await f.page.evaluate(()=>document.querySelector('iframe[title=wallet]').contentWindow.postMessage({type:'home:wallet-signin-changed'},'*'));}
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
      await f.wallet.getByRole('button',{name:'Add wallet for apps',exact:true}).click();
      assert.equal(await f.wallet.locator('[data-wallet-open-method]').count(),3);await f.wallet.getByRole('button',{name:'Cancel',exact:true}).click();
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
      assert.match(await f.system.locator('.account-block').first().locator('.account-role').innerText(), /Admin · You/);
      assert.equal(await f.system.locator('.account-block').first().getByRole('button',{name:'Remove passkey',exact:true}).count(),2);
      assert.equal(await f.system.getByRole('heading',{name:'Wallets for sign-in',exact:true}).count(),1);
      assert.equal(await f.system.getByRole('link',{name:'Open Wallet',exact:true}).count(),2);
      await shot(f.system,'system-accounts',width,engine,f.page);
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
      await f.system.locator('[data-wallet-method]').nth(2).waitFor();await f.system.getByText('MetaMask added for sign-in.',{exact:true}).waitFor();assert.equal(f.fixture.state.methods.length,3);
      assert.equal(await f.page.evaluate(()=>walletFixture.calls.filter(c=>c.method==='personal_sign').length),1);
      assert.equal(f.fixture.state.calls.filter(c=>c.path==='/api/auth/passkey-step-up/complete').length,1);
      await shot(f.system,'system-add-returned',width,engine,f.page);
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
      for(const [kind,connectedName] of [['metamask','MetaMask'],['unisat','UniSat'],['walletconnect','Rainbow'],['metamask','Rabby Wallet']]) {
        await f.page.goto(f.fixture.origin+'/apps/wallet/');
        const measurements=await f.page.evaluate(async ({kind,connectedName})=>{
          const {connectionView,renderConnection}=await import('/apps/home/wallet-connection-view.mjs');
          const sheet=document.createElement('link');sheet.rel='stylesheet';sheet.href='/apps/home/wallet-signin-connection.css';document.head.append(sheet);await new Promise((resolve,reject)=>{sheet.onload=resolve;sheet.onerror=reject;});
          const name=connectedName;
          const view=connectionView({window:kind,stage:'linked',localSafety:false,account:{name,mark:kind==='walletconnect'?'wallet':kind,connection:kind==='walletconnect'?'WalletConnect':null,accounts:[{address:kind==='unisat'?'bc1qtestaddress':'0x'+'12'.repeat(20),networks:[kind==='unisat'?'Bitcoin':'Base']}]},supportedActions:['copy-address','close-window']});
          const bar=document.createElement('header');bar.textContent=kind==='walletconnect'?'WalletConnect':kind==='unisat'?'UniSat':'MetaMask';
          document.body.replaceChildren(bar,renderConnection(document,view));
          const visible=[...document.body.querySelectorAll('*')].filter(el=>!el.closest('.connection-sr-only')&&el.getClientRects().length&&getComputedStyle(el).visibility!=='hidden').flatMap(el=>[...el.childNodes].filter(n=>n.nodeType===Node.TEXT_NODE).map(n=>n.textContent)).join(' ');
          return {text:visible,peer:document.querySelector('.connection-account-name')?.textContent};
        },{kind,connectedName});
        const brand=kind==='walletconnect'?'WalletConnect':kind==='unisat'?'UniSat':'MetaMask';
        assert.equal(measurements.text.split(brand).length-1,1,measurements.text);
        if(kind==='walletconnect'||connectedName==='Rabby Wallet')assert.equal(measurements.peer,connectedName);
      }
    } finally {await f.close();}
  });
}
// A refresh can finish between the native pointer press and release.
for(const engine of ['chromium','webkit'])for(const width of [1440,390])for(const phase of ['inventory','balance']) {
  test(`one wallet list: Add survives ${phase} refresh during a click in ${engine} at ${width}`,{timeout:45000},async()=>{
    const f=await setup(engine,width);
    try {
      await show(f,'wallet');await f.wallet.getByText('125.00 ELA',{exact:true}).waitFor();
      const add=f.wallet.getByRole('button',{name:'Add wallet for apps',exact:true});
      const endpoint=phase==='inventory'?'inventory':'summary';
      let release,requested;
      const held=new Promise(resolve=>release=resolve),seen=new Promise(resolve=>requested=resolve);
      await f.context.route(`**/api/apps/wallet/wallet/${endpoint}`,async route=>{
        requested();await held;await route.continue();
      });
      if(phase==='inventory')f.fixture.state.connected.find(account=>account.account_id==='app:phone').wallet_display_name='Trust';
      else f.fixture.state.balanceValues[f.addresses.home]['esc-mainnet']=String(126n*10n**18n);
      try {
        await refresh(f);await seen;
        const bounds=await add.boundingBox();
        await f.page.mouse.move(bounds.x+bounds.width/2,bounds.y+bounds.height/2);await f.page.mouse.down();
        release();
        if(phase==='inventory')await f.wallet.getByRole('button',{name:'Open Trust',exact:true}).waitFor();
        else await f.wallet.getByText('126.00 ELA',{exact:true}).waitFor();
        await f.page.mouse.up();
        const chooser=f.wallet.getByRole('dialog',{name:'Add wallet for apps',exact:true});
        await chooser.waitFor();assert.equal(await chooser.locator('[data-wallet-open-method]').count(),3);
        // A further rendered refresh preserves the chooser and its Cancel control.
        f.fixture.state.balanceValues[f.addresses.home]['esc-mainnet']=String((phase==='inventory'?124n:127n)*10n**18n);
        await refresh(f);await f.wallet.getByText(phase==='inventory'?'124.00 ELA':'127.00 ELA',{exact:true}).waitFor();
        assert.equal(await chooser.isVisible(),true);await chooser.getByRole('button',{name:'Cancel',exact:true}).click();
      } finally {
        release();await f.page.mouse.up();await f.context.unroute(`**/api/apps/wallet/wallet/${endpoint}`);
      }
      assert.deepEqual(f.errors,[]);
    } finally {await f.close();}
  });
}
for(const engine of ['chromium','webkit'])test(`one wallet list keeps saved identities while unavailable methods leave Add in ${engine}`,{timeout:30000},async()=>{
  const f=await setup(engine,390);
  try {
    await show(f,'wallet');await f.wallet.locator('.one-wallet').nth(3).waitFor();f.fixture.state.walletconnectAvailable=false;
    const response=f.page.waitForResponse(r=>r.url().includes('/api/apps/wallet/wallet/summary'));
    await refresh(f);await response;
    // Wait for that refresh to finish before opening the controls it owns.
    await f.wallet.locator('body').evaluate(()=>new Promise(resolve=>setTimeout(resolve,100)));
    await f.wallet.getByRole('button',{name:'Add wallet for apps',exact:true}).click();
    assert.equal(await f.wallet.locator('[data-wallet-open-method]').count(),2);assert.equal(await f.wallet.locator('[data-wallet-open-method="wallet-walletconnect"]').count(),0);
    await f.wallet.getByRole('button',{name:'Cancel',exact:true}).click();assert.equal(await f.wallet.getByRole('button',{name:'Open Rainbow',exact:true}).count(),1);
  } finally {await f.close();}
});
for(const engine of ['chromium','webkit'])test(`one wallet list: phone app use signs once and Cancel preserves sign-in in ${engine}`,{timeout:45000},async()=>{
  const f=await setup(engine,390);
  try {
    const phone=f.fixture.state.connected.find(a=>a.connector_id==='wallet-walletconnect');
    f.fixture.state.revokedAccounts=[{...phone,chain_namespace:'eip155:20'}];f.fixture.state.connected=f.fixture.state.connected.filter(a=>a!==phone);
    f.fixture.state.methods.find(m=>m.connector==='walletconnect').chain_id=20;
    await show(f,'wallet');await refresh(f);await f.wallet.getByRole('button',{name:'Open Rainbow',exact:true}).click();
    const toggle=f.wallet.getByRole('switch',{name:'Apps and websites',exact:true});
    await f.wallet.locator('[role=switch][aria-checked=false]').waitFor();
    f.fixture.state.holdSignature=true;
    await toggle.click();const signature=f.page.waitForResponse(r=>r.url().endsWith('/api/fixture-sdk')&&r.request().postDataJSON().method==='personal_sign');
    await f.wallet.getByRole('button',{name:'Sign message',exact:true}).click();await signature;
    await f.wallet.getByRole('button',{name:'Cancel',exact:true}).click();assert.equal(await toggle.getAttribute('aria-checked'),'false');
    assert.equal(f.fixture.state.calls.filter(c=>c.path==='/api/auth/evm/verify').length,0);assert(f.fixture.state.methods.some(m=>m.connector==='walletconnect'));
    await f.page.locator('iframe[data-target=wallet-walletconnect]').waitFor({state:'detached'});
    f.fixture.state.holdSignature=false;
    await toggle.click();await f.wallet.getByRole('button',{name:'Sign message',exact:true}).click();
    await f.wallet.getByText('Connected for apps.',{exact:true}).waitFor();assert.equal(await toggle.getAttribute('aria-checked'),'true');
    assert.equal(f.fixture.state.calls.filter(c=>c.path==='/api/auth/evm/verify').length,1);assert.deepEqual(f.errors,[]);
  } finally {await f.close();}
});
// Fix-round regressions run the real capsule modules against controlled Runtime replies.
for(const engine of ['chromium','webkit'])for(const width of [1440,390]) {
  test(`fix2 single saved ESC record shows every EVM balance in ${engine} at ${width}`,{timeout:45000},async()=>{
    const f=await setup(engine,width);
    try {
      const home=f.fixture.state.connected[0];
      assert.equal(f.fixture.state.connected.filter(account=>account.address===home.address).length,1);
      assert.equal(home.chain_namespace,'eip155:20');
      f.fixture.state.balanceValues[home.address]['base-mainnet']=String(5n*10n**17n);
      await show(f,'wallet');await refresh(f);
      const card=f.wallet.locator('.one-wallet').filter({hasText:'Home address'});
      await card.getByText('0.50 ETH',{exact:true}).waitFor();
      assert.deepEqual(await card.locator('.one-network-balance').allTextContents(),['ESC125.00 ELA','Base0.50 ETH']);
      assert.match(await card.locator('.one-meta').innerText(),/\bEVM\b/);
      await shot(f.wallet,'home-address-single-record',width,engine);
      await card.getByRole('button',{name:'Open Home address',exact:true}).click();
      assert.deepEqual(await card.locator('.one-network-balance').allTextContents(),['ESC125.00 ELA','Base0.50 ETH']);
      // Only Base changes: the saved ESC record and its balance stay the same.
      f.fixture.state.balanceValues[home.address]['base-mainnet']=String(75n*10n**16n);await refresh(f);
      await card.getByText('0.75 ETH',{exact:true}).waitFor();
      assert.equal(await card.getByText('125.00 ELA',{exact:true}).count(),1);
      f.fixture.state.balanceValues[home.address]['base-mainnet']='0';await refresh(f);
      await card.getByText('0.00 ETH',{exact:true}).waitFor();
      assert.equal(f.fixture.state.connected.filter(account=>account.address===home.address).length,1);
      assert.deepEqual(f.errors,[]);
    }finally{await f.close();}
  });
}
for(const engine of ['chromium','webkit']) {
  test(`fix1 built-in networks keep their own balances and one EVM card in ${engine}`,{timeout:45000},async()=>{
    const f=await setup(engine,390);
    try {
      const home=f.fixture.state.connected[0];
      f.fixture.state.connected.push({...home,account_id:'home-base',chain_namespace:'eip155:8453'}, {...home,account_id:'home-btc',address:bitcoinAddress,chain_namespace:btc,proof_type:'managed_btc_p2wpkh',label:'Bitcoin address'});
      f.fixture.state.balanceValues[home.address]['base-mainnet']=String(5n*10n**17n);
      await show(f,'wallet');await refresh(f);
      const card=f.wallet.locator('.one-wallet').filter({has:f.wallet.getByRole('button',{name:'Open Home address',exact:true})});
      await card.getByText('0.50 ETH',{exact:true}).waitFor();
      assert.equal(await f.wallet.getByRole('button',{name:'Open Home address',exact:true}).count(),1);
      assert.equal(await card.getByText('125.00 ELA',{exact:true}).count(),1);
      const bitcoin=f.wallet.locator('.one-wallet').filter({hasText:'Bitcoin address'});
      assert.equal(await bitcoin.getByRole('button',{name:'Send',exact:true}).count(),0);
      await shot(f.wallet,'home-address-networks',390,engine);
      await f.page.setViewportSize({width:1440,height:1000});await shot(f.wallet,'home-address-networks',1440,engine);
      await f.page.setViewportSize({width:390,height:1000});
      f.fixture.state.balanceValues[home.address]['base-mainnet']=String(75n*10n**16n);await refresh(f);
      await card.getByText('0.75 ETH',{exact:true}).waitFor();
      f.fixture.state.balanceValues={};await refresh(f);
      await card.getByText('0.00 ETH',{exact:true}).waitFor();assert.equal(await card.getByText('0.00 ELA',{exact:true}).count(),1);
      await shot(f.wallet,'home-address-networks-zero',390,engine);
      await f.page.setViewportSize({width:1440,height:1000});await shot(f.wallet,'home-address-networks-zero',1440,engine);
    }finally{await f.close();}
  });
  test(`fix1 relay disclosure precedes Add pairing in ${engine}`,{timeout:30000},async()=>{
    const f=await setup(engine,390);
    try {
      f.fixture.state.methods=[];f.fixture.state.connected=[];f.fixture.state.wcConnected=false;
      await f.system.getByRole('button',{name:'Add wallet',exact:true}).click();
      const row=f.page.locator('.signin-dialog .connection-option').filter({hasText:'WalletConnect'});
      await row.waitFor();const copy=await row.locator('small').allTextContents();
      assert.equal(copy[0],'Rainbow, Trust and other phone wallets');
      assert.match(copy[1]||'',/relay.*internet address/);
      assert.equal(f.fixture.state.calls.filter(c=>c.body?.allow_temporary_internet||c.path.endsWith('/relay-admission')).length,0);
      await row.click();await f.page.locator('.signin-dialog[data-state=pairing]').waitFor();
      assert.match(await f.page.locator('.signin-dialog').innerText(),/relay.*internet address/);
    }finally{await f.close();}
  });
  test(`fix1 phone app use requests saved internet access and keeps pairing visible in ${engine}`,{timeout:45000},async()=>{
    const f=await setup(engine,390);
    try {
      const phone=f.fixture.state.connected.find(a=>a.connector_id==='wallet-walletconnect');
      f.fixture.state.revokedAccounts=[{...phone,chain_namespace:'eip155:20'}];
      f.fixture.state.connected=f.fixture.state.connected.filter(a=>a!==phone);
      f.fixture.state.methods.find(m=>m.connector==='walletconnect').chain_id=20;
      f.fixture.state.wcConnected=false;f.fixture.state.internetStatus='required';
      await show(f,'wallet');await refresh(f);await f.wallet.getByRole('button',{name:'Open Rainbow',exact:true}).click();
      await f.wallet.getByRole('switch').click();await f.wallet.getByRole('button',{name:'Sign message',exact:true}).click();
      await f.wallet.getByText('Allow WalletConnect internet access in Inbox, then select Try again.',{exact:true}).waitFor();
      assert.equal(f.fixture.state.calls.filter(c=>c.path==='/api/apps/wallet-walletconnect/internet'&&c.body).length,1);
      assert.equal(f.fixture.state.calls.filter(c=>c.path.endsWith('/relay-admission')).length,0);
      await shot(f.wallet,'apps-internet-permission',390,engine);
      await f.page.setViewportSize({width:1440,height:1000});await shot(f.wallet,'apps-internet-permission',1440,engine);await f.page.setViewportSize({width:390,height:1000});
      f.fixture.state.internetStatus='granted';
      await f.wallet.getByRole('button',{name:'Try again',exact:true}).click();
      const connector=f.page.frameLocator('iframe[data-target=wallet-walletconnect]');
      await connector.locator('[data-state=qr-shown]').waitFor();
      assert.equal(await f.page.locator('iframe[data-target=wallet-walletconnect]').isVisible(),true);
      await shot(connector,'app-walletconnect-pairing',390,engine);
      await f.page.setViewportSize({width:1440,height:1000});await shot(connector,'app-walletconnect-pairing',1440,engine);await f.page.setViewportSize({width:390,height:1000});
      await f.page.locator('iframe[data-target=wallet-walletconnect]').evaluate(frame=>frame.contentWindow.postMessage('fixture-pair','*'));
      await f.wallet.getByText('Connected for apps.',{exact:true}).waitFor();
    }finally{await f.close();}
  });
  test(`fix1 app off uses one approval for all links and Cancel preserves every link in ${engine}`,{timeout:45000},async()=>{
    const f=await setup(engine,390);
    try {
      const account=f.fixture.state.connected.find(a=>a.connector_id==='wallet-metamask');
      f.fixture.state.connected.push({...account,account_id:'app:second',connector_id:'wallet-walletconnect'});
      await show(f,'wallet');await refresh(f);await f.wallet.getByRole('button',{name:'Open MetaMask',exact:true}).click();
      await f.wallet.getByRole('switch').click();
      await f.page.evaluate(()=>walletFixture.passkeyMode='cancelled');await f.wallet.getByRole('button',{name:'Approve with passkey',exact:true}).click();
      await f.wallet.locator('[role=alert]').waitFor();assert.equal(f.fixture.state.connected.filter(a=>a.address===account.address).length,2);
      await f.page.evaluate(()=>walletFixture.passkeyMode='normal');await f.wallet.getByRole('button',{name:'Approve with passkey',exact:true}).click();
      await f.wallet.getByText('App use turned off.',{exact:true}).waitFor();
      assert.equal(f.fixture.state.calls.filter(c=>c.path==='/api/auth/passkey-step-up/complete').length,1);
      assert.equal(f.fixture.state.connected.filter(a=>a.address===account.address).length,0);
    }finally{await f.close();}
  });
  test(`fix1 inventory failure keeps Wallet usable and System sign-in removable in ${engine}`,{timeout:30000},async()=>{
    const f=await setup(engine,390);
    try {
      await f.context.route('**/api/apps/wallet/wallet/inventory',route=>route.fulfill({status:503,body:'{}'}));
      await f.page.evaluate(()=>window.showFixtureApps());await show(f,'wallet');
      await f.wallet.getByRole('button',{name:'Open Home address',exact:true}).waitFor();
      await show(f,'system');await f.system.locator('[data-wallet-method]').nth(1).waitFor();
      assert.equal(await f.system.getByRole('button',{name:'Remove from sign-in',exact:true}).count(),2);
      await show(f,'wallet');await f.wallet.getByText('Home could not load wallet sign-in use.',{exact:true}).waitFor();
      await shot(f.wallet,'inventory-read-unavailable',390,engine);
      await f.page.setViewportSize({width:1440,height:1000});await shot(f.wallet,'inventory-read-unavailable',1440,engine);
      await f.context.unroute('**/api/apps/wallet/wallet/inventory');
      await f.wallet.getByRole('button',{name:'Try again',exact:true}).click();
      await f.wallet.getByRole('button',{name:'Open UniSat',exact:true}).waitFor();
      assert.equal(await f.wallet.getByText('Home could not load wallet sign-in use.',{exact:true}).count(),0);
    }finally{await f.close();}
  });
}
for(const engine of ['chromium','webkit'])test(`fix1 provider outage keeps sign-in visible and app use unknown in ${engine}`,{timeout:30000},async()=>{
  const f=await setup(engine,390);let partial=true;
  try {
    await f.context.route('**/api/apps/wallet/wallet/inventory',async route=>{
      const response=await route.fetch(),inventory=await response.json();
      if(partial){inventory.apps_available=false;inventory.entries=inventory.entries.filter(entry=>entry.sign_in).map(entry=>({...entry,accounts:[]}));}
      await route.fulfill({response,json:inventory});
    });
    await f.page.evaluate(()=>window.showFixtureApps());await show(f,'wallet');
    await f.wallet.getByRole('button',{name:'Open UniSat',exact:true}).click();
    assert.equal(await f.wallet.getByRole('switch',{name:'Apps and websites',exact:true}).count(),0,'missing app-use data is not a saved Off value');
    await f.wallet.getByText('Home could not load app use.',{exact:true}).waitFor();
    await show(f,'system');
    await f.system.getByRole('button',{name:'Remove from sign-in',exact:true}).nth(1).waitFor();
    assert.equal(await f.system.getByRole('button',{name:'Remove from sign-in',exact:true}).count(),2);
    await show(f,'wallet');await f.wallet.getByText('Home could not load app use.',{exact:true}).waitFor();
    await shot(f.wallet,'app-use-unavailable',390,engine);
    await f.page.setViewportSize({width:1440,height:1000});await shot(f.wallet,'app-use-unavailable',1440,engine);
    partial=false;await f.wallet.getByRole('button',{name:'Try again',exact:true}).click();
    await f.wallet.getByRole('switch',{name:'Apps and websites',exact:true}).waitFor();
    assert.equal(await f.wallet.getByText('Home could not load app use.',{exact:true}).count(),0);
    assert.deepEqual(f.errors,[]);
  }finally{await f.close();}
});
test.after(async()=>{if(output){const sources={};for(const path of ['capsules/wallet/browser/index.html','capsules/wallet/browser/wallet.js','capsules/wallet/browser/wallet-inventory.js','capsules/wallet/browser/wallet-inventory.css','capsules/system/browser/index.html','capsules/system/browser/system.js','capsules/system/browser/style.css','capsules/home/browser/wallet-signin-view.mjs','capsules/home/browser/wallet-signin-management.mjs','capsules/_shared/wallet-connection-view.mjs'])sources[path]=createHash('sha256').update(await readFile(path)).digest('hex');await writeFile(join(output,'captures.json'),JSON.stringify({sources,head:execFileSync('git',['rev-parse','HEAD'],{encoding:'utf8'}).trim(),tree:execFileSync('git',['rev-parse','HEAD^{tree}'],{encoding:'utf8'}).trim(),captures:captureRecords},null,2)+'\n');}});
