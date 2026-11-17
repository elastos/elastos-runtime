#!/usr/bin/env node
import assert from 'node:assert/strict';
import { requireProductSmokePlaywright } from './product-smoke-browser.mjs';
import { fixture } from './lib/wallet-extension-window-fixture.mjs';

// Exercise the actual opaque window and trusted Home host. Runtime replies and
// the provider are isolated test doubles; no real funds or account are used.
const browser = await requireProductSmokePlaywright().chromium.launch({headless:true});
let result;
try {
  const f = await fixture(browser, 'metamask', { saved:true, requests:'transaction' });
  try {
    await f.state('transaction-waiting');
    await f.action('send-request').click();
    await f.state('transaction-done');
    const observed = await f.top.evaluate(() => ({calls:testState.calls,receipts:testState.receipts,effects:testState.effects,runtimeCalls:testState.runtimeCalls}));
    const methods=observed.calls.map(c=>c.method);
    for(const method of ['wallet_switchEthereumChain','wallet_addEthereumChain','eth_accounts','eth_sendTransaction']) assert(methods.includes(method),method);
    assert.equal(observed.effects.length,1);
    assert.deepEqual(observed.effects[0].action,{kind:'approve',approvalRequestId:'approval-1'});
    assert.equal(observed.effects[0].connectorToken,'fixture-token');
    assert.equal(observed.receipts.length,1);
    assert.equal(observed.receipts[0].transaction_hash,'0x'+'aa'.repeat(32));
    assert(!Object.hasOwn(observed.receipts[0],'signature'));
    assert.equal(await f.frame.evaluate(()=>typeof window.ethereum),'undefined');
    assert.equal(await f.frame.evaluate(()=>location.search.includes('home_token')),false);
    assert.equal(await f.frame.evaluate(()=>location.hash.includes('home_token=fixture-token')),true);
    for(const read of f.reads) assert.equal(read.headers['x-elastos-home-token'],'fixture-token');
    assert(observed.runtimeCalls.every(c=>c.url.startsWith('/api/apps/home/wallet-connector/') && c.body.connector_token==='fixture-token' && c.body.connector_id==='wallet-metamask' && c.body.schema==='elastos.home.wallet-connector.effect.request/v1'));
    assert.equal(f.context.pages().length,1,'connector opens no extra window');
    result={connectorId:'wallet-metamask',providerMethods:methods,runtimeEndpoints:observed.runtimeCalls.map(c=>c.url),authorityTransport:'fragment',effectOwner:'home-host'};
  }finally{await f.close();}
}finally{await browser.close();}
const {exerciseWalletConnect}=await import('./lib/walletconnect-capsule-fixture.mjs');
const wc=await exerciseWalletConnect();
if(wc.error)throw Error(wc.error);
console.log(JSON.stringify({ok:true,results:[result,{connectorId:'wallet-walletconnect',effectOwner:'capsule',result:wc.result}]},null,2));
