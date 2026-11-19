import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';

test('failed WebKit launch releases the already started relay and SDK peer',()=>{
 const helper=new URL('./lib/walletconnect-window-resources.mjs',import.meta.url).href;
 const product=new URL('./product-smoke-browser.mjs',import.meta.url).href;
 const script=`
  import test from 'node:test';
  import {windowResources} from ${JSON.stringify(helper)};
  import {requireProductSmokePlaywright} from ${JSON.stringify(product)};
  test('absent WebKit',async t=>{
   await windowResources(t,'webkit',()=>requireProductSmokePlaywright().webkit.launch({executablePath:'/missing-wallet-test-webkit',headless:true}));
  });
 `;
 const result=spawnSync(process.execPath,['--input-type=module','--eval',script],{encoding:'utf8',timeout:30000});
 assert.equal(result.error,undefined,'failed launch exits naturally within 30s');
 assert.equal(result.status,1,'the injected launch failure is reported');
 assert.match(result.stdout+result.stderr,/missing-wallet-test-webkit/);
 assert.doesNotMatch(result.stdout+result.stderr,/cleanup failed/i);
});


test('the reporter names missing WebKit as the reason for skipping window cases',()=>{
 const helper=new URL('./lib/walletconnect-window-resources.mjs',import.meta.url).href;
 const script=`
  import test from 'node:test';
  import {windowTestOptions} from ${JSON.stringify(helper)};
  test('WalletConnect window in webkit',windowTestOptions('webkit',1000),()=>{throw new Error('missing engine case ran');});
 `;
 const env={...process.env,PLAYWRIGHT_BROWSERS_PATH:'/missing-wallet-test-browsers'};
 delete env.ELASTOS_PLAYWRIGHT_MODULE;
 const result=spawnSync(process.execPath,['--test-reporter=spec','--input-type=module','--eval',script],{encoding:'utf8',timeout:30000,env});
 assert.equal(result.error,undefined,'the skip probe exits naturally');
 assert.equal(result.status,0,'missing WebKit remains an optional skip');
 assert.match(result.stdout,/WalletConnect window in webkit.*WebKit is not installed on this machine/);
 assert.doesNotMatch(result.stdout+result.stderr,/missing engine case ran/);
});
