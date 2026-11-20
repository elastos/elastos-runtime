import assert from 'node:assert/strict';
import test from 'node:test';
import http from 'node:http';
import {readFileSync} from 'node:fs';
import {importProductSmokePlaywright,productSmokeLaunchOptions} from './product-smoke-browser.mjs';
import {walletConnectRelayFixture,walletConnectFixtureRequire} from './lib/walletconnect-relay-fixture.mjs';
const {SignClient} = walletConnectFixtureRequire('@walletconnect/sign-client');
import {execFileSync} from 'node:child_process';
import {walletConnectMessages as messages} from '../capsules/wallet-walletconnect/browser/walletconnect-client.mjs';
const chains = ['eip155:1','eip155:20','eip155:8453','eip155:11155111'];
const unsupported = 'Your wallet did not approve a network this Home supports. Select Connect wallet and choose Ethereum, Elastos Smart Chain, Base or Sepolia in your wallet.';
const expiryReplies=['ownership','signature'].map(scope=>[`${scope} wallet expiry-text reply`,['eip155:8453'],{scope,code:6,message:'Request expired. Please try again.',expected:scope==='ownership'?'linkError':'signatureError'}]);
const declines = [4001,5000].flatMap(code => ['proposal','signature'].map(scope => [`${scope} decline ${code}`,['eip155:8453'],{scope,code}]));
for (const [name,approved,rejection] of [['Base only',['eip155:8453']],['unsupported only',['eip155:137']],['all four',chains],...declines,...expiryReplies]) {
  test(`real pinned SDK ${rejection ? name : 'links with '+name}`,{timeout:45000},async () => {
    const files = new Map([
      ['/fixture.mjs','scripts/lib/walletconnect-session-fixture.mjs'],
      ['/walletconnect-client.mjs','capsules/wallet-walletconnect/browser/walletconnect-client.mjs'],
      ['/vendor/reown-appkit.js','capsules/wallet-walletconnect/vendor/reown-appkit.js'],
    ]);
    const server = http.createServer((req,res) => {
      if (files.has(req.url)) {res.setHeader('content-type','text/javascript');res.end(process.env.WALLETCONNECT_BASELINE && req.url !== '/fixture.mjs' ? execFileSync('git',['show',`4cd5a7302:${files.get(req.url)}`],{maxBuffer:4*1024*1024}) : readFileSync(files.get(req.url)));}
      else {res.setHeader('content-type','text/html');res.end('<!doctype html><script type="module" src="/fixture.mjs"></script>');}
    });
    const {relay,methods} = walletConnectRelayFixture(server);
    await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
    const origin = `http://127.0.0.1:${server.address().port}`;
    let wallet,browser,page,proposal;const requests=[];
    try {
      wallet = await SignClient.init({projectId:'fixture-project',relayUrl:origin.replace('http','ws'),logger:'silent',telemetryEnabled:false,
        customStoragePrefix:`fixture-${crypto.randomUUID()}`,storageOptions:{database:':memory:'},metadata:{name:'Stand-in wallet',description:'Test',url:origin,icons:[]}});
      wallet.on('session_proposal',async event=>{
        proposal=event.params;
        if (rejection?.scope === 'proposal') { await wallet.reject({id:event.id,reason:{code:rejection.code,message:rejection.message||'User rejected.'}}); return; }
        await wallet.approve({id:event.id,namespaces:{eip155:{chains:approved,accounts:approved.map(chain=>`${chain}:0x${'12'.repeat(20)}`),methods:['personal_sign','eth_sendTransaction'],events:['accountsChanged','chainChanged']}}});
      });
      wallet.on('session_request',async event=>{requests.push(event.params);await wallet.respond({topic:event.topic,response:{jsonrpc:'2.0',id:event.id,...(rejection ? {error:{code:rejection.code,message:rejection.message||'User rejected.'}} : {result:`0x${'ab'.repeat(65)}`})}});});
      const engine=process.env.WALLETCONNECT_TEST_ENGINE || 'chromium',engines=await importProductSmokePlaywright();browser=await engines[engine].launch({headless:true,...(engine==='chromium'?productSmokeLaunchOptions():{})});
      page=await browser.newPage();
      await page.route('**/*',route=>new URL(route.request().url()).origin===origin?route.continue():route.abort());
      await page.exposeBinding('pairTestWallet',(_source,uri)=>wallet.core.pairing.pair({uri}));
      await page.goto(origin+(rejection?.scope==='signature'?'?action=approve':''));
      try { await page.waitForFunction(()=>window.result||window.error,null,{timeout:25000}); } catch(error) { console.log({methods,proposal:!!proposal,state:await page.evaluate(()=>({paired:window.pairingSent,error:window.error,dialog:!!document.querySelector('dialog')}))});throw error; }
      const state=await page.evaluate(()=>({result:window.result,error:window.error,challenge:window.challenge}));
      if (rejection) {assert.equal(state.error,messages[rejection.expected||`${rejection.scope}Declined`]);assert.equal(await page.evaluate(()=>window.errorTone),'muted');assert.equal(requests.length,rejection.scope==='proposal'?0:1);if(rejection.scope==='signature'){assert.equal(await page.evaluate(()=>window.provider.connected),true,'declining a signing request keeps the connection');assert.equal(await page.evaluate(()=>window.reviewAgain()),messages.consumed);assert.equal(requests.length,1,'the real SDK receives no second signing request');}}
      else if(name==='unsupported only') {assert.equal(state.error,unsupported);assert.equal(requests.length,0);}
      else {assert.equal(state.error,undefined);assert.equal(state.result.status,'linked');assert.equal(requests.length,1);assert.ok(approved.includes(requests[0].chainId));assert.equal(state.challenge.chain_id,Number(approved[0].split(':')[1]));}
      console.log(`${name}: link expectation PASS; ${requests.length} wallet request(s)`);
      assert.deepEqual(proposal.requiredNamespaces,{});
      assert.deepEqual(proposal.optionalNamespaces.eip155.chains,chains);
      assert.equal(proposal.proposer.metadata.description,'Approve requests from your ElastOS Home');
      if (name !== 'unsupported only' && !rejection) {
        const repaired = await Promise.race([page.evaluate(async () => {
          delete window.provider.session.namespaces.eip155.chains; // Accounts alone also prove approval.
          window.provider.chainId = 137; // A stale saved default lies outside Home's list.
          return window.relink();
        }),new Promise((_,reject)=>setTimeout(()=>reject(new Error('repair timed out')),10000))]).catch(async error=>{console.log({methods,requests:requests.map(r=>({method:r.request.method,chainId:r.chainId})),chain:await page.evaluate(()=>window.provider.chainId)});throw error;});
        assert.equal(repaired.status,'linked');
        assert.equal(requests.length,2);
        assert.equal(requests[1].chainId,approved[0]);
        assert.ok(requests.every(request=>request.request.method==='personal_sign'),'selection sends no network-switch request');
      }
    } finally {
      await page?.evaluate(()=>window.cleanup?.()).catch(()=>{});
      for(const session of wallet?.session.getAll()||[])await wallet.disconnect({topic:session.topic,reason:{code:6000,message:'Fixture ended'}}).catch(()=>{});
      wallet?.core.heartbeat.stop();
      await wallet?.core.relayer.transportClose().catch(()=>{});
      wallet?.removeAllListeners();
      await browser?.close();for(const socket of relay.clients)socket.terminate();
      await new Promise(resolve=>relay.close(resolve));server.closeAllConnections();await new Promise(resolve=>server.close(resolve));
    }
  });
}
