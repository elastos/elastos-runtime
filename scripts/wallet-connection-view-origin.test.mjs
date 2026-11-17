import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { resolve, extname } from 'node:path';
import { requireProductSmokePlaywright } from './product-smoke-browser.mjs';
import { states, fixtureView, fixtureArguments } from './wallet-connection-view-fixtures.mjs';
const playwright=requireProductSmokePlaywright();
for(const engine of ['chromium','webkit'])test(`F1: full origins and fixed feedback in ${engine}`,{skip:engine==='webkit'&&!existsSync(playwright.webkit.executablePath())&&!process.env.ELASTOS_PLAYWRIGHT_MODULE?'WebKit required in content-sandbox CI':false},async()=>{
  const browser=await playwright[engine].launch({headless:true});
  try{
    const page=await browser.newPage();
    await page.route('**/*',async route=>{
      const url=new URL(route.request().url());assert.equal(url.hostname,'wallet-view.test');
      if(url.pathname==='/')return route.fulfill({contentType:'text/html',body:'<!doctype html><link rel="stylesheet" href="/capsules/wallet-metamask/browser/elastos-ui.css"><link rel="stylesheet" href="/capsules/_shared/wallet-connection-view.css"><body class="el-app" style="margin:0"></body>'});
      if(url.pathname.startsWith('/connection-'))return route.fulfill({body:await readFile(resolve('capsules/_shared',url.pathname.slice(1))),contentType:'image/png'});
      assert(url.pathname.startsWith('/capsules/'));
      return route.fulfill({body:await readFile(resolve('.'+url.pathname)),contentType:extname(url.pathname)==='.mjs'?'text/javascript':extname(url.pathname)==='.css'?'text/css':'image/png'});
    });
    await page.goto('http://wallet-view.test/');
    const origins=['https://accounts.example.com.secure-login-verify-session.attacker-domain.net','https://'+('long-lookalike.'.repeat(28))+'attacker-domain.net'];
    for(const [width,height,compact]of [[480,522,false],[320,182,true],[360,596,true]])for(const origin of origins){
      await page.setViewportSize({width,height});
      const v=fixtureView(states.find(r=>r.designState==='metamask/request-extension'));
      const observed=await page.evaluate(async({v,origin,compact})=>{
        const {connectionView,renderConnection}=await import('/capsules/_shared/wallet-connection-view.mjs');
        const view=connectionView({window:v.window,stage:v.stage,summary:{...v.request,site:origin},account:v.account,waitSeconds:299,localSafety:false,compact});
        document.body.replaceChildren(renderConnection(document,view));await document.fonts.ready;
        const site=document.querySelector('.connection-site');
        let identity=site.closest('.connection-identity');
        while(identity&&!['auto','scroll'].includes(getComputedStyle(identity).overflowY))identity=identity.parentElement;
        const style=getComputedStyle(site),box=site.getBoundingClientRect();

        const visible=e=>{const b=e.getBoundingClientRect();return b.top>=0&&b.bottom<=innerHeight&&b.width>0};
        const range=document.createRange();range.setStart(site.firstChild,origin.length-1);range.setEnd(site.firstChild,origin.length);
        const area=identity.getBoundingClientRect();
        identity.scrollTop+=Math.max(0,range.getBoundingClientRect().bottom-Math.min(area.bottom,innerHeight)+2);
        const end=range.getBoundingClientRect();
        return {siteCount:document.querySelectorAll('.connection-site').length,reasonLabel:document.querySelector('.connection-detail-label')?.textContent,text:site.textContent,style:{whiteSpace:style.whiteSpace,overflow:style.overflowX,textOverflow:style.textOverflow},width:box.width,scrollWidth:site.scrollWidth,identityIsScoped:identity.classList.contains('connection-identity')||identity.classList.contains('connection-content'),lastCharacterVisible:end.top>=Math.max(area.top,0)-1&&end.bottom<=Math.min(area.bottom,innerHeight)+1,feedback:[...document.querySelectorAll('.connection-status,.connection-wait,.connection-actions button')].filter(e=>e.textContent).every(visible),documentHeight:document.documentElement.scrollHeight};
      },{v,origin,compact});
      assert.equal(observed.text,origin);assert.equal(observed.style.whiteSpace,'normal');assert.equal(observed.siteCount,1);assert.equal(observed.reasonLabel,'From app: ');assert.notEqual(observed.style.textOverflow,'ellipsis');assert(observed.scrollWidth<=observed.width+1);assert(observed.identityIsScoped);assert(observed.lastCharacterVisible,JSON.stringify({width,height,observed}));assert(observed.feedback,JSON.stringify({width,height,observed}));assert(observed.documentHeight<=height);
    }
    for(const name of ['walletconnect/request-list','metamask/request-unsendable','metamask/access-wrong-account']){
      await page.setViewportSize({width:480,height:522});const v=fixtureView(states.find(r=>r.designState===name));
      const height=await page.evaluate(async args=>{
        const {reduceConnection,renderConnection}=await import('/capsules/_shared/wallet-connection-view.mjs');
        const model=reduceConnection(...args);
        document.body.replaceChildren(renderConnection(document,model));await document.fonts.ready;return document.documentElement.scrollHeight;
      },fixtureArguments(states.find(r=>r.designState===name)));assert(height<=522,`${name}: ${height}>522`);
    }
    const identity=await page.evaluate(async()=>{
      const {connectionView,renderConnection}=await import('/capsules/_shared/wallet-connection-view.mjs');
      document.body.replaceChildren(renderConnection(document,connectionView({window:'walletconnect',stage:'linked',localSafety:false,account:{name:'WalletConnect',mark:'metamask',connection:'WalletConnect',accounts:[{address:'0x1122334455667788990011223344556677889900',networks:['Ethereum']}]}})));
      return {heading:document.querySelector('h1')?.textContent,peer:document.querySelector('.connection-account-name bdi')?.textContent,mark:document.querySelector('.connection-account-header img')?.getAttribute('src'),hint:document.querySelector('.connection-via')?.textContent};
    });
    assert.deepEqual(identity,{heading:'WalletConnect',peer:'WalletConnect',mark:'./connection-wallet.png',hint:undefined});
  }finally{await browser.close();}
});
