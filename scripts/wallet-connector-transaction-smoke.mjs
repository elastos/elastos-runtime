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
    assert.deepEqual(observed.calls.find(c=>c.method==='wallet_addEthereumChain').params,[{chainId:'0x14',chainName:'Elastos Smart Chain',nativeCurrency:{name:'ELA',symbol:'ELA',decimals:18},rpcUrls:['https://api.elastos.io/esc']}]);
    const send=observed.calls.find(c=>c.method==='eth_sendTransaction');
    assert.equal(send.chain,'0x14');assert.equal(send.signer,'0x'+'1'.repeat(40));
    assert.equal(send.params[0].from,send.signer);assert.equal(send.params[0].chainId,'0x14');
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
// The WalletConnect half must open the real window and use its visible Send
// control too. A client-only fixture cannot detect a missing window/control.
const {windowFixture,observeWindowErrors,walletWindowLifetime}=await import('./lib/walletconnect-phone-window-fixture.mjs');
const {scriptedPhoneWallet}=await import('./lib/walletconnect-phone-wallet.mjs');
const home=await windowFixture(),peer=await scriptedPhoneWallet({projectId:'fixture-project',relayUrl:home.origin.replace('http','ws')});
const wcBrowser=await requireProductSmokePlaywright().chromium.launch({headless:true});
const page=await wcBrowser.newPage({viewport:{width:480,height:560}}),{errors}=observeWindowErrors(page,home);
await page.route('**/*',route=>new URL(route.request().url()).origin===home.origin?route.continue():route.abort());
const settle=await walletWindowLifetime(page,home);let frame,wc;
const state=name=>frame.locator(`main[data-state="${name}"]`).waitFor({timeout:20000});
try{
 await page.goto(home.origin);frame=page.frames().find(frame=>frame.url().includes('/apps/wallet-walletconnect/'));
 assert(frame,'Home opens the WalletConnect frame');
 await state('internet-ready');await frame.locator('[data-action=connect]:visible:enabled').click();await state('qr-shown');
 await frame.getByRole('button',{name:'Copy link',exact:true}).click();await frame.getByText('Link copied.',{exact:true}).waitFor();
 await peer.pair(await page.evaluate(()=>window.copied));await state('linked');assert.equal(home.state.verified,1);
 home.state.approvals=[{request_id:'transaction-smoke',connector_id:'wallet-walletconnect',capsule_id:'browser',requesting_origin:'https://example.test',reason:'Review the fixture transaction',status:'pending',intent:'transaction_intent',proof_type:'siwe',address:peer.address,chain_namespace:'eip155:8453',expires_at:Math.floor(Date.now()/1000)+600}];
 await frame.evaluate(()=>window.dispatchEvent(new Event('focus')));await state('transaction-waiting');
 await frame.locator('[data-action=send-request]:visible:enabled').click();await state('transaction-done');
 assert.equal(home.state.completed,1);assert.equal(home.state.approvals[0].status,'completed');
 assert.match(home.state.transactionHash,/^0x[0-9a-fA-F]{64}$/);assert.equal(home.state.transactionHash,peer.lastTransactionHash,'Home records the exact hash of the disposable transaction the phone signed');
 assert.equal(peer.trace.filter(event=>event.kind==='request'&&event.method==='eth_sendTransaction').length,1);
 wc={status:home.state.approvals[0].status,effect:'transaction',transaction_hash:home.state.transactionHash};
}finally{try{await settle(frame);}finally{await peer.stop();await wcBrowser.close();await home.stop();}assert.deepEqual(errors,[]);}
console.log(JSON.stringify({ok:true,results:[result,{connectorId:'wallet-walletconnect',effectOwner:'capsule',result:wc}]},null,2));
