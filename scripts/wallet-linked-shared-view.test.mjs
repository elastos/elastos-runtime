import {windowTestOptions} from './lib/walletconnect-window-resources.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdir,writeFile} from 'node:fs/promises';
import {execFileSync} from 'node:child_process';
import {fixture} from './lib/wallet-extension-window-fixture.mjs';
import {requireProductSmokePlaywright} from './product-smoke-browser.mjs';
const playwright=requireProductSmokePlaywright();
for(const engine of ['chromium','webkit'])for(const kind of ['metamask','unisat'])test(`linked ${kind} has useful copy and controls in ${engine}`,windowTestOptions(engine),async t=>{
 const browser=await playwright[engine].launch({headless:true});let f;t.after(async()=>{try{await f?.close();}finally{await browser.close();}});
 f=await fixture(browser,kind);
 await f.state('ready');await f.action('connect').click();await f.state('linked');
 const shown=await f.frame.locator('main').evaluate(main=>({text:main.innerText,actions:[...main.querySelectorAll('[data-action]')].map(b=>({id:b.dataset.action,primary:b.classList.contains('el-button-primary')}))}));
 assert.doesNotMatch(shown.text,/review this request|Back to connection|Manage in Inbox|Close this window/i);
 assert.ok(shown.actions.every(a=>!['connect','start-over','inbox','back-to-connection'].includes(a.id)));
 assert.ok(shown.actions.every(a=>!a.primary||a.id==='close-window'));
 const output=process.env.WALLETCONNECT_LINKED_SCREENS;
 if(output){
  await mkdir(`${output}/${engine}`,{recursive:true});
  for(const theme of ['light','dark']){
   await f.frame.evaluate(theme=>window.elastosTheme.set(theme),theme);
   assert.equal(await f.frame.evaluate(()=>window.elastosTheme.resolved()),theme);
   await f.top.screenshot({path:`${output}/${engine}/linked-${kind}-${theme}.png`,animations:'disabled'});
  }
  await writeFile(`${output}/${engine}/linked-${kind}.json`,JSON.stringify({head:execFileSync('git',['rev-parse','HEAD'],{encoding:'utf8'}).trim(),tree:execFileSync('git',['rev-parse','HEAD^{tree}'],{encoding:'utf8'}).trim(),engine,kind,...shown},null,2));
 }
 await f.action('copy-address').click();await f.top.waitForFunction(()=>testState.copies.length===1);
 await f.action('close-window').click();await f.top.waitForFunction(()=>testState.closed===true);
});
