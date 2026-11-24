import test from 'node:test';
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {mkdir,readFile,writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {createHash} from 'node:crypto';
import {signinFixture,installSigninProviders,evmAddress,bitcoinAddress,relayNotice} from './lib/wallet-signin-fixture.mjs';
import {requireProductSmokePlaywright} from './product-smoke-browser.mjs';
import {windowTestOptions} from './lib/walletconnect-window-resources.mjs';

const pictures=process.env.WALLET_ROUND8_PICTURES;
for(const engine of ['chromium','webkit'])for(const width of [1280,390])for(const kind of ['MetaMask','UniSat','WalletConnect'])test(`round8 ${kind} passkey instruction precedes its notice in ${engine} at ${width}`,windowTestOptions(engine,30000),async()=>{
  const f=await signinFixture(),browser=await requireProductSmokePlaywright()[engine].launch({headless:true});
  f.state.methods=[];f.state.connected=[];f.state.wcConnected=false;
  const context=await browser.newContext({viewport:{width,height:900},locale:'en-US'});
  await context.addInitScript(installSigninProviders,{evmAddress,bitcoinAddress,theme:'light'});
  const page=await context.newPage();page.setDefaultTimeout(15000);
  if(process.env.WALLET_ROUND8_BASELINE)await page.route('**/wallet.js*',route=>route.fulfill({contentType:'text/javascript',body:execFileSync('git',['show','296461e65:capsules/wallet/browser/wallet.js'],{encoding:'utf8'})}));
  try{
    await page.goto(f.origin+'/home/');await page.waitForFunction(()=>window.fixtureReady);
    await page.evaluate(()=>{window.showFixtureApps();walletFixture.passkeyMode='pending';});
    const system=page.frameLocator('iframe[title=system]'),wallet=page.frameLocator('iframe[title=wallet]');
    await system.getByRole('button',{name:'Add wallet',exact:true}).click();
    await wallet.locator('#wallet-signers[data-signin=options]').waitFor();
    await wallet.locator('.wallet-method-head').filter({hasText:kind}).getByRole('button',{name:'Choose',exact:true}).click();
    if(kind==='WalletConnect'){
      await page.locator('.signin-dialog[data-state=pairing]').waitFor();
      await page.locator('iframe[title=WalletConnect]').evaluate(frame=>frame.contentWindow.postMessage('fixture-pair','*'));
    }
    await wallet.locator('#wallet-signers[data-signin=passkey]').waitFor();
    const copy=await wallet.locator('#wallet-signin-actions .wallet-state').allTextContents();
    assert.deepEqual(copy,kind==='WalletConnect'?['Confirm with your passkey.',relayNotice]:['Confirm with your passkey.']);
    assert.equal(f.state.methods.length,0,'the instruction is visible before the change completes');
    if(pictures){
      assert.equal(execFileSync('git',['status','--porcelain'],{encoding:'utf8'}).trim(),'','pictures bind a clean candidate');
      await mkdir(pictures,{recursive:true});
      const name=`passkey-${kind.toLowerCase()}-${engine}-${width}`;
      const bytes=await page.screenshot({path:join(pictures,name+'.png'),animations:'disabled'});
      await writeFile(join(pictures,name+'.json'),JSON.stringify({head:execFileSync('git',['rev-parse','HEAD'],{encoding:'utf8'}).trim(),tree:execFileSync('git',['rev-parse','HEAD^{tree}'],{encoding:'utf8'}).trim(),source:'capsules/wallet/browser/wallet.js',sourceSha256:createHash('sha256').update(await readFile('capsules/wallet/browser/wallet.js')).digest('hex'),engine,viewport:page.viewportSize(),copy,sha256:createHash('sha256').update(bytes).digest('hex')},null,2));
    }
    await page.evaluate(()=>{walletFixture.passkeyMode='normal';for(const job of walletFixture.pending.splice(0))job.resolve(job.result);});
    await system.locator('[data-wallet-method]').waitFor();
    assert.equal(f.state.methods.length,1);assert.equal(f.state.methods[0].connector,kind.toLowerCase());
    assert.equal(f.state.connected.length,0,'adding a sign-in method preserves payment accounts');
  }finally{await context.close();await browser.close();await f.close();}
});
