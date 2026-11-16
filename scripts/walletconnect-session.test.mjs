import assert from 'node:assert/strict';
import test from 'node:test';
import http from 'node:http';
import {readFileSync} from 'node:fs';
import {createRequire} from 'node:module';
import {importProductSmokePlaywright,productSmokeLaunchOptions} from './product-smoke-browser.mjs';
const require = createRequire(new URL('./walletconnect/package.json',import.meta.url));
const {SignClient} = require('@walletconnect/sign-client');
const {WebSocketServer} = require('ws');
const chains = ['eip155:1','eip155:20','eip155:8453','eip155:11155111'];
const unsupported = 'Your wallet did not approve a network this Home supports. Connect again and choose Ethereum, Elastos Smart Chain, Base or Sepolia in your wallet.';
for (const [name,approved] of [['Base only',['eip155:8453']],['unsupported only',['eip155:137']],['all four',chains]]) {
  test(`real pinned SDK links with ${name}`,{timeout:45000},async () => {
    const files = new Map([
      ['/fixture.mjs','scripts/lib/walletconnect-session-fixture.mjs'],
      ['/walletconnect-client.mjs','capsules/wallet-walletconnect/browser/walletconnect-client.mjs'],
      ['/vendor/reown-appkit.js','capsules/wallet-walletconnect/vendor/reown-appkit.js'],
    ]);
    const server = http.createServer((req,res) => {
      if (files.has(req.url)) {res.setHeader('content-type','text/javascript');res.end(readFileSync(files.get(req.url)));}
      else {res.setHeader('content-type','text/html');res.end('<!doctype html><script type="module" src="/fixture.mjs"></script>');}
    });
    const relay = new WebSocketServer({server});
    const subscriptions = new Map(),messages = new Map();let id=1;const methods=[];
    const deliver = (socket,topic,message) => socket.send(JSON.stringify({jsonrpc:'2.0',id:id++,method:'irn_subscription',params:{id:'fixture-subscription',data:{topic,message,publishedAt:Date.now()}}}));
    relay.on('connection',socket => socket.on('message',raw => {
      const rpc = JSON.parse(String(raw));
      if (rpc.token) {socket.send('{"ready":true}');return;}
      if (!rpc.method) return;methods.push(rpc.method);
      let result = true;
      if (rpc.method.endsWith('batchSubscribe') || rpc.method.endsWith('subscribe')) {
        const topics = rpc.params.topics || [rpc.params.topic];
        for (const topic of topics) {if(!subscriptions.has(topic))subscriptions.set(topic,new Set());subscriptions.get(topic).add(socket);}
        result = rpc.method.endsWith('batchSubscribe') ? topics.map(()=>'fixture-subscription') : 'fixture-subscription';
        socket.send(JSON.stringify({jsonrpc:'2.0',id:rpc.id,result}));
        for(const topic of topics)for(const message of messages.get(topic)||[])deliver(socket,topic,message);
        return;
      }
      if (rpc.method === 'wc_proposeSession' || rpc.method === 'wc_approveSession') {
        const topic=rpc.method === 'wc_proposeSession' ? rpc.params.pairingTopic : rpc.params.sessionTopic;
        if(!subscriptions.has(topic))subscriptions.set(topic,new Set());subscriptions.get(topic).add(socket);
      }
      if (rpc.method === 'wc_approveSession') {
        for (const [topic,message] of [[rpc.params.pairingTopic,rpc.params.sessionProposalResponse],[rpc.params.sessionTopic,rpc.params.sessionSettlementRequest]]) {
          if(!messages.has(topic))messages.set(topic,[]);messages.get(topic).push(message);
          for(const peer of subscriptions.get(topic)||[])if(peer!==socket&&peer.readyState===1)deliver(peer,topic,message);
        }
      }
      if (rpc.method.endsWith('publish') || rpc.method === 'wc_proposeSession') {
        const topic = rpc.params.topic || rpc.params.pairingTopic;
        const message = rpc.params.message || rpc.params.sessionProposal;
        if(!messages.has(topic))messages.set(topic,[]);messages.get(topic).push(message);
        for(const peer of subscriptions.get(topic)||[])if(peer!==socket&&peer.readyState===1)deliver(peer,topic,message);
      }
      socket.send(JSON.stringify({jsonrpc:'2.0',id:rpc.id,result}));
    }));
    await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
    const origin = `http://127.0.0.1:${server.address().port}`;
    let wallet,browser,page,proposal;const requests=[];
    try {
      wallet = await SignClient.init({projectId:'fixture-project',relayUrl:origin.replace('http','ws'),logger:'silent',telemetryEnabled:false,
        customStoragePrefix:`fixture-${crypto.randomUUID()}`,storageOptions:{database:':memory:'},metadata:{name:'Stand-in wallet',description:'Test',url:origin,icons:[]}});
      wallet.on('session_proposal',async event=>{
        proposal=event.params;
        await wallet.approve({id:event.id,namespaces:{eip155:{chains:approved,accounts:approved.map(chain=>`${chain}:0x${'12'.repeat(20)}`),methods:['personal_sign','eth_sendTransaction'],events:['accountsChanged','chainChanged']}}});
      });
      wallet.on('session_request',async event=>{requests.push(event.params);await wallet.respond({topic:event.topic,response:{jsonrpc:'2.0',id:event.id,result:`0x${'ab'.repeat(65)}`}});});
      const {chromium}=await importProductSmokePlaywright();browser=await chromium.launch({headless:true,...productSmokeLaunchOptions()});
      page=await browser.newPage();
      await page.route('**/*',route=>new URL(route.request().url()).origin===origin?route.continue():route.abort());
      await page.exposeBinding('pairTestWallet',(_source,uri)=>wallet.core.pairing.pair({uri}));
      await page.goto(origin);
      try { await page.waitForFunction(()=>window.result||window.error,null,{timeout:25000}); } catch(error) { console.log({methods,proposal:!!proposal,state:await page.evaluate(()=>({paired:window.pairingSent,error:window.error,dialog:!!document.querySelector('dialog')}))});throw error; }
      const state=await page.evaluate(()=>({result:window.result,error:window.error,challenge:window.challenge}));
      if(name==='unsupported only') {assert.equal(state.error,unsupported);assert.equal(requests.length,0);}
      else {assert.equal(state.error,undefined);assert.equal(state.result.status,'linked');assert.equal(requests.length,1);assert.ok(approved.includes(requests[0].chainId));assert.equal(state.challenge.chain_id,Number(approved[0].split(':')[1]));}
      assert.deepEqual(proposal.requiredNamespaces,{});
      assert.deepEqual(proposal.optionalNamespaces.eip155.chains,chains);
    } finally {
      await page?.evaluate(()=>window.cleanup?.()).catch(()=>{});
      for(const session of wallet?.session.getAll()||[])await wallet.disconnect({topic:session.topic,reason:{code:6000,message:'Fixture ended'}}).catch(()=>{});
      await wallet?.core.relayer.transportClose().catch(()=>{});
      await browser?.close();for(const socket of relay.clients)socket.terminate();
      await new Promise(resolve=>relay.close(resolve));server.closeAllConnections();await new Promise(resolve=>server.close(resolve));
    }
  });
}
