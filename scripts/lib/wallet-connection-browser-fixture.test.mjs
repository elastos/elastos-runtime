import {windowTestOptions} from './walletconnect-window-resources.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import {browserFixture,playwright,closeSmokeBrowsers} from './wallet-connection-browser-fixture.mjs';

test.after(closeSmokeBrowsers);

for(const engine of ['chromium','webkit'])test(`reused ${engine} keeps fresh contexts and closes each fixture independently`,{
 skip:windowTestOptions(engine).skip,
},async()=>{
 let first,second;
 try{
  await Promise.all([
   browserFixture(engine,{reuseBrowser:true}).then(f=>{first=f;}),
   browserFixture(engine,{reuseBrowser:true}).then(f=>{second=f;}),
  ]);
  assert(first.browser===second.browser,'fixtures share one engine process');
  assert(first.context!==second.context,'each fixture owns a fresh context');
  await first.page.evaluate(()=>{window.fixtureOwner='first';localStorage.setItem('fixture-owner','first');});
  assert.deepEqual(await second.page.evaluate(()=>[window.fixtureOwner??null,localStorage.getItem('fixture-owner')]),[null,null]);
  await first.close();
  assert.equal(first.page.isClosed(),true);
  assert.equal(await second.page.evaluate(()=>Boolean(document.querySelector('#mount'))),true,'closing one context keeps the other alive');
  await second.close();
  assert.equal(first.browser.contexts().length,0,'all fixture contexts are released');
 }finally{
  try{await first?.close();}finally{await second?.close();}
 }
});
