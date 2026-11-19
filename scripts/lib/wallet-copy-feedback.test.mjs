import test from 'node:test';
import assert from 'node:assert/strict';
import {existsSync} from 'node:fs';
import {browserFixture,playwright} from './wallet-connection-browser-fixture.mjs';
import {observeCopiedFeedback} from './wallet-copy-feedback.mjs';

for(const engine of ['chromium','webkit'])test(`Copied observation survives expiry and requires both labels in ${engine}`,{
 skip:engine==='webkit'&&!existsSync(playwright.webkit.executablePath())&&!process.env.ELASTOS_PLAYWRIGHT_MODULE?'WebKit required in content-sandbox CI':false,
},async()=>{
 const f=await browserFixture(engine);
 try{
  await f.page.clock.install();
  await f.page.evaluate(()=>{document.querySelector('#mount').innerHTML='<button id="copy" class="wallet-copy-icon" title="Copy address" aria-label="Copy address"></button>';});
  const feedback=await observeCopiedFeedback(f.page,'#copy');
  try{
   await f.page.evaluate(async()=>{const {pulseCopied}=await import('/capsules/wallet/browser/wallet-render.js');pulseCopied(document.querySelector('#copy'));});
   await f.page.clock.runFor(1200);
   assert.deepEqual(await f.page.locator('#copy').evaluate(button=>[button.title,button.getAttribute('aria-label')]),['Copy address','Copy address'],'real product feedback has expired before the host checks');
   await assert.rejects(f.page.waitForFunction(()=>{const button=document.querySelector('#copy');return button.title==='Copied'&&button.getAttribute('aria-label')==='Copied';},undefined,{timeout:50}),/Timeout/,'the old post-action poll misses the expired pulse');
   await feedback.wait();
  }finally{await feedback.close();}
  const partial=await observeCopiedFeedback(f.page,'#copy');
  try{
   await f.page.locator('#copy').evaluate(button=>{button.title='Copied';});
   await assert.rejects(partial.wait(50),/Timeout/,'a title alone does not satisfy the product feedback assertion');
   await f.page.locator('#copy').evaluate(button=>{button.setAttribute('aria-label','Copied');});
   await partial.wait();
  }finally{await partial.close();}
 }finally{await f.close();}
});
