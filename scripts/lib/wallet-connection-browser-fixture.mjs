import assert from 'node:assert/strict';
import {readFile,mkdir} from 'node:fs/promises';
import {resolve,extname} from 'node:path';
import {temporaryDirectory} from './wallet-connection-test-temp.mjs';
import {fileURLToPath} from 'node:url';
import {requireProductSmokePlaywright} from '../product-smoke-browser.mjs';
export const playwright=requireProductSmokePlaywright();
const root=resolve(fileURLToPath(new URL('../../',import.meta.url)));
// The combined smoke shares engine processes; each fixture keeps its own context.
const smokeBrowsers=new Map();
export async function closeSmokeBrowsers(){
 const results=await Promise.allSettled([...smokeBrowsers.values()].map(async pending=>(await pending).close()));
 smokeBrowsers.clear();
 const errors=results.filter(row=>row.status==='rejected').map(row=>row.reason);
 if(errors.length)throw new AggregateError(errors,'View browser cleanup failed');
}
async function acquireBrowser(engine,reuse){
 if(!reuse)return playwright[engine].launch({headless:true});
 let pending=smokeBrowsers.get(engine);
 if(!pending){pending=playwright[engine].launch({headless:true});smokeBrowsers.set(engine,pending);}
 let browser;
 try{browser=await pending;}catch(error){if(smokeBrowsers.get(engine)===pending)smokeBrowsers.delete(engine);throw error;}
 if(!browser.isConnected()){
  if(smokeBrowsers.get(engine)===pending)smokeBrowsers.delete(engine);
  return acquireBrowser(engine,true);
 }
 return browser;
}
export async function browserFixture(engine,{width=480,height=522,scale=1,delayFont=false,reuseBrowser=process.env.WALLET_VIEW_BROWSER_SMOKE==='1'}={}){
 const browser=await acquireBrowser(engine,reuseBrowser);
 const context=await browser.newContext({viewport:{width,height},deviceScaleFactor:scale,serviceWorkers:'block'});
 let release;let fontReady=new Promise(r=>{release=r;});if(!delayFont)release();let family='Inter';let serial=0;
 await context.route('**/*',async route=>{
  const url=new URL(route.request().url());assert.equal(url.hostname,'wallet-view.test','no network in view tests');
  if(url.pathname==='/fixture')return route.fulfill({contentType:'text/html',body:'<!doctype html><meta charset="utf-8"><link rel="stylesheet" href="/capsules/wallet-metamask/browser/elastos-ui.css"><link rel="stylesheet" href="/capsules/_shared/wallet-connection-view.css"><body class="el-app" style="margin:0"><div id="mount"></div></body>'});
  const path=url.pathname.startsWith('/connection-')?resolve(root,'capsules/_shared',url.pathname.slice(1)):resolve(root,'.'+url.pathname);
  assert(path.startsWith(root+'/capsules/'));
  if(extname(path)==='.woff2')await fontReady;
  return route.fulfill({body:await readFile(path),contentType:({'.mjs':'text/javascript','.css':'text/css','.png':'image/png','.woff2':'font/woff2'})[extname(path)]||'application/octet-stream'});
 });
 const page=await context.newPage();await page.goto('http://wallet-view.test/fixture',{waitUntil:'domcontentloaded'});await page.waitForFunction(()=>document.styleSheets.length>=2);
 return {browser,context,page,prepareFont:async()=>{release();fontReady=new Promise(r=>{release=r;});family='ViewDelayed'+(++serial);await page.evaluate(({family,serial})=>{let style=document.querySelector('#delayed-font');if(!style){style=document.createElement('style');style.id='delayed-font';document.head.append(style);}style.textContent=`@font-face{font-family:${family};src:url('/capsules/wallet-metamask/browser/assets/fonts/Inter-latin-var.woff2?case=${serial}');font-display:swap;font-weight:400 700}:root{--el-font:${family},system-ui,sans-serif}`;},{family,serial});return family;},releaseFont:async()=>{release();await page.evaluate(async family=>{await document.fonts.load('600 12px '+family);await document.fonts.ready;await new Promise(r=>requestAnimationFrame(()=>requestAnimationFrame(r)));},family);},close:async()=>{release();if(reuseBrowser)await context.close();else await browser.close();}};
}
export async function temporaryProof(prefix,requested){
 const owned=requested?null:temporaryDirectory(prefix);const path=requested||owned.path;await mkdir(path,{recursive:true});
 return {path,cleanup:()=>owned?.cleanup()};
}
