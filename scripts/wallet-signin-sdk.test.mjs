import test from 'node:test';
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {readFile} from 'node:fs/promises';
import {execFileSync} from 'node:child_process';
import {resolve,extname} from 'node:path';
import {requireProductSmokePlaywright} from './product-smoke-browser.mjs';
import {walletConnectRelayFixture} from './lib/walletconnect-relay-fixture.mjs';
import {scriptedPhoneWallet} from './lib/walletconnect-phone-wallet.mjs';
const root=resolve(import.meta.dirname,'..');

test('the sign-in opaque frame imports the real SDK, pairs, signs and keeps protocol storage in Runtime', {timeout:45000}, async()=>{
 let revision=0,reads=0,writes=0;const keys=Object.create(null),origins=[];
 const headers={'access-control-allow-origin':'null','access-control-allow-headers':'content-type,x-elastos-wallet-attempt,x-elastos-wallet-instance,if-match','access-control-allow-methods':'GET,POST,OPTIONS','access-control-expose-headers':'etag'};
 const server=createServer(async(req,res)=>{try{
  const path=new URL(req.url,'http://localhost').pathname;
  const json=value=>res.writeHead(200,{...headers,'content-type':'application/json',etag:`"${revision}"`}).end(JSON.stringify(value));
  if(req.method==='OPTIONS'){res.writeHead(204,headers).end();return;}
  if(path==='/'){res.writeHead(200,{'content-type':'text/html'}).end(`<!doctype html><script>window.pairing=false;window.failed=false;window.signed=false;window.pairingUri='';addEventListener('message',e=>{if(e.source!==document.querySelector('iframe').contentWindow||e.origin!=='null'||e.data?.type!=='wallet-signin-transport-result')return;if(e.data.event==='ready')e.source.postMessage({type:'wallet-signin-transport',id:'connect',operation:'connect',transport:{attempt_token:'fixture-attempt',instance_id:'fixture-instance',storage_revision:0,expires_at:Date.now()/1000+180}},'*');if(e.data.event==='pairing'){window.pairing=true;window.pairingUri=e.data.uri;}if(e.data.id==='connect'&&e.data.result)e.source.postMessage({type:'wallet-signin-transport',id:'sign',operation:'sign',message:'Disposable sign-in protocol regression'},'*');if(e.data.id==='sign'&&e.data.result)window.signed=/^0x[0-9a-f]{130}$/i.test(e.data.result.signature);if(e.data.error)window.failed=true;});</script><iframe sandbox="allow-scripts" src="/apps/wallet-walletconnect/signin-transport.html?home_origin=${encodeURIComponent('http://127.0.0.1:'+server.address().port)}"></iframe>`);return;}
  if(path.startsWith('/api/')){
   origins.push(req.headers.origin);assert.equal(req.headers['x-elastos-wallet-attempt'],'fixture-attempt');assert.equal(req.headers['x-elastos-wallet-instance'],'fixture-instance');
   if(path.endsWith('/wallet/config')){json({walletconnect:{project_id:'fixture-project-id'}});return;}
   if(path.endsWith('/relay-admission')){json({token:'fixture-admission'});return;}
   assert.ok(path.endsWith('/storage'));assert.equal(req.headers['if-match'],`"${revision}"`);
   if(req.method==='POST'){let raw='';for await(const chunk of req)raw+=chunk;const {key,value}=JSON.parse(raw);if(value===null)delete keys[key];else keys[key]=value;revision++;writes++;}else reads++;
   json(keys);return;
  }
  assert.ok(path.startsWith('/apps/wallet-walletconnect/'));
  const rel=path.slice('/apps/wallet-walletconnect/'.length),file=resolve(root,'capsules/wallet-walletconnect',rel.startsWith('vendor/')?rel:'browser/'+rel);
  assert.ok(file.startsWith(resolve(root,'capsules/wallet-walletconnect')+'/'));
  const bytes=rel==='signin-transport.mjs'&&process.env.SIGNIN_SDK_BEFORE?execFileSync('git',['show',`${process.env.SIGNIN_SDK_BEFORE==='expiry'?'79fa3ffa2':'a9ecb6bc0'}:capsules/wallet-walletconnect/browser/signin-transport.mjs`],{cwd:root}):await readFile(file);
  res.writeHead(200,{...headers,'content-type':extname(file)==='.html'?'text/html':'text/javascript'}).end(bytes);
 }catch(error){res.writeHead(500).end('Fixture refused request');}});
 const relay=walletConnectRelayFixture(server);await new Promise(r=>server.listen(0,'127.0.0.1',r));const browser=await requireProductSmokePlaywright().chromium.launch({headless:true});const phone=await scriptedPhoneWallet({projectId:'fixture-project-id',relayUrl:`ws://127.0.0.1:${server.address().port}`,chains:['eip155:8453']});let requestExpiry;phone.client.on('session_request',event=>{requestExpiry=event.params.request.expiryTimestamp;});
 try{const page=await browser.newPage();await page.goto(`http://127.0.0.1:${server.address().port}/`);await page.waitForFunction(()=>window.pairing||window.failed,null,{timeout:30000});assert.equal(await page.evaluate(()=>window.pairing),true,'actual sign-in entry reaches QR with the real SDK');await phone.pair(await page.evaluate(()=>window.pairingUri));await page.waitForFunction(()=>window.signed||window.failed,null,{timeout:30000});assert.equal(await page.evaluate(()=>window.signed),true,'real SDK signature request reaches the phone and returns its proof');assert.ok(phone.trace.some(event=>event.kind==='response'&&event.method==='personal_sign'));const remaining=requestExpiry-Date.now()/1000;assert.ok(remaining>290&&remaining<=300,'phone receives the minimum supported 300-second request expiry');assert.ok(reads>0&&writes>0,'SDK protocol state uses revision-bound Runtime storage');assert.ok(origins.every(origin=>origin==='null'));}
 finally{await phone.stop();await browser.close();for(const socket of relay.relay.clients)socket.terminate();await new Promise(r=>relay.relay.close(r));server.closeAllConnections();await new Promise(r=>server.close(r));}
});
