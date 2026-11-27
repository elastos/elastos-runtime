import assert from 'node:assert/strict';
import http from 'node:http';
import {readFileSync} from 'node:fs';
import {resolve,relative,extname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {walletConnectRelayFixture} from './walletconnect-relay-fixture.mjs';
import {walletConnectFixtureRequire as require} from './walletconnect-relay-fixture.mjs';
const root=fileURLToPath(new URL('../..',import.meta.url));
const {recoverMessageAddress}=require('viem');
// gateway_walletconnect.rs:409-415, exact existing scoped-storage fence.
export const staleSessionMessage='WalletConnect session changed. Close this window and open WalletConnect again.';
// All window walks use one strict page-error oracle. Only the unchanged SDK's
// rejected POST at a retired storage revision is an expected diagnostic.
export function observeWindowErrors(page,fixture) {
 const errors=[],sdkFences=[];
 page.on('pageerror',error=>{
  const fenced=fixture.state.calls.findLast(row=>row.status===409&&row.method==='POST'&&!row.observedRejection&&row.path.endsWith('/storage')&&typeof row.revision==='string'&&row.revision!==JSON.stringify(String(fixture.state.revision)));
  if(fenced&&[staleSessionMessage,`Error: ${staleSessionMessage}`].includes(error.message)&&/fetchJson|persist/.test(error.stack||'')&&(error.stack||'').includes('/apps/wallet-walletconnect/')){
   fenced.observedRejection=true;sdkFences.push({message:staleSessionMessage,method:fenced.method,revision:fenced.revision,status:409});
   console.error('Expected retired SDK storage fence:',JSON.stringify(sdkFences.at(-1)));
  }else errors.push(error.message);
  if(process.env.WALLETCONNECT_ERROR_DIAGNOSTICS)console.error(JSON.stringify({message:error.message,stack:error.stack,storage:fixture.state.calls.filter(row=>row.path.endsWith('/storage')).slice(-6)}));
 });
 return {errors,sdkFences};
}
export async function windowFixture() {
 const state={windowLoads:0,permission:'granted',revision:0,keys:{},accounts:[],approvals:[],verified:0,completed:0,calls:[],fencedWrites:0,deleteFails:false,guest:false,expiredLaunch:false};
 const server=http.createServer(async(req,res)=>{
  const path=new URL(req.url,'http://localhost').pathname;res.setHeader('access-control-allow-origin','*');res.setHeader('access-control-allow-headers','content-type,x-elastos-home-token,if-match');res.setHeader('access-control-allow-methods','GET,POST,DELETE,OPTIONS');if(req.method==='OPTIONS'){res.writeHead(204).end();return;}
  const json=(body,code=200)=>{res.writeHead(code,{'content-type':'application/json'}).end(JSON.stringify(body));};
  try{
   if(path==='/') {state.windowLoads++;res.setHeader('content-type','text/html');res.end(`<!doctype html><style>body{margin:0;padding-top:38px;box-sizing:border-box;height:100vh}iframe{border:0;width:100%;height:calc(100vh - 38px)}</style><iframe id="wallet" sandbox="allow-scripts allow-forms" src="/apps/wallet-walletconnect/?home_origin=http://127.0.0.1:${server.address().port}#home_token=fixture-wallet"></iframe><script>
   window.events=[];window.copied='';window.clipboardAllowed=true;window.holdClipboard=false;window.clipboardReplies=[];addEventListener('message',async e=>{const d=e.data;window.events.push({type:d.type,target:d.target});if(d.type==='home:app-ready')e.source.postMessage({type:'home:clipboard-ready',schema:'elastos.home.clipboard.ready/v1',targetId:'wallet-walletconnect',homeToken:'fixture-wallet',parentOrigin:location.origin,generation:'fixture-generation'},'*');
   if(d.type==='home:clipboard-request'){const ok=window.clipboardAllowed;if(ok)window.copied=d.text;const result={type:'home:clipboard-result',schema:'elastos.home.clipboard.result/v1',targetId:'wallet-walletconnect',homeToken:d.homeToken,parentOrigin:location.origin,generation:d.generation,requestId:d.requestId,operation:d.operation,purpose:d.purpose,ok,...(ok?{}:{error:'denied'})};const reply=()=>e.source.postMessage(result,'*');if(window.holdClipboard)window.clipboardReplies.push(reply);else reply();}});</script>`);return;}
   if(path.startsWith('/api/')) {
    const call={path,method:req.method,revision:req.headers['if-match']};state.calls.push(call);
    if(state.expiredLaunch){res.writeHead(403).end('Launch expired');return;}
    if(state.guest&&path.endsWith('/internet')&&req.method==='POST'&&state.permission!=='granted'){assert.equal(req.headers.accept,'application/json');return json({code:'walletconnect_admin_required',message:'Fixture wording differs from the product sentence.'},500);}
    let input='';for await(const chunk of req)input+=chunk;const body=input?JSON.parse(input):{};
    if(path.endsWith('/internet')&&req.method==='POST'&&state.permission!=='granted')state.permission='requested';
    if(path.endsWith('/internet'))return json({status:state.permission,cleanup_pending:Boolean(state.cleanupPending),request:{id:'request-1',issued_at:Math.floor(Date.now()/1000)}});
    if(path.endsWith('/wallet/config'))return json({walletconnect:{project_id:'fixture-project',storage_revision:JSON.stringify(String(state.revision))}});
    if(path.endsWith('/relay-admission'))return json({token:'fixture-admission'});
    if(path.endsWith('/storage')){
     if(req.method==='DELETE'){if(state.deleteFails)return json({},503);state.keys={};state.revision++;}
     else {if(req.headers['if-match']!==JSON.stringify(String(state.revision))){call.status=409;state.fencedWrites++;return res.writeHead(409,{'content-type':'text/plain'}).end(staleSessionMessage);}if(req.method==='POST'){if(body.value===null)delete state.keys[body.key];else state.keys[body.key]=body.value;}}
     return json(state.keys);
    }
    if(path.endsWith('/wallet/accounts'))return json({accounts:state.accounts.filter(account=>account.connector_id==='wallet-walletconnect'&&!['managed_evm','managed_btc_p2wpkh'].includes(account.proof_type))});
    if(path.endsWith('/wallet/approvals'))return json({approval_requests:state.approvals.filter(r=>r.status==='pending'||r.status==='approved'&&r.intent==='transaction_intent')});
    if(path.endsWith('/challenge')){state.challenge={message:'Test Home ownership proof '+crypto.randomUUID(),expires_at:Math.floor(Date.now()/1000)+300,address:body.address,chain:body.chain_id};return json(state.challenge);}
    if(path.endsWith('/verify')){if(body.message!==state.challenge.message)return json({},400);const address=await recoverMessageAddress({message:body.message,signature:body.signature});if(address.toLowerCase()!==state.challenge.address.toLowerCase())return json({},400);state.verified++;state.accounts=[{address,chain_namespace:`eip155:${state.challenge.chain}`,connector_id:'wallet-walletconnect',proof_type:'siwe'}];return json({status:'linked'});}
    const approval=state.approvals.find(r=>path.includes(encodeURIComponent(r.request_id)));
    if(path.endsWith('/approve')&&approval?.status==='pending'){approval.status='approved';return json({handoff:{request_id:approval.request_id,payload_hash:'0x'+'34'.repeat(32),signer:approval.address,intent:approval.intent,signature_type:state.invalidSignatureHandoff?'invalid-test-type':'personal_sign',message:'Fixture approval message',...(approval.intent==='transaction_intent'?{transaction:{from:approval.address,chainId:'0x2105',to:'0x'+'78'.repeat(20),value:'0x1',gas:'0x5208',gasPrice:'0x1',nonce:'0x0'}}:{})},binding:{payload_hash:'0x'+'34'.repeat(32),chain_namespace:approval.chain_namespace,expires_at:approval.expires_at}});}
    if(path.endsWith('/complete')&&approval?.status==='approved'){if(state.completeFails){state.returnedHash=body.transaction_hash;return json({},500);}if(body.declined){if(body.payload_hash!=='0x'+'34'.repeat(32)||body.signer.toLowerCase()!==approval.address.toLowerCase()||body.signature||body.transaction_hash)return json({},400);approval.status='rejected';approval.wallet_outcome='declined';return json({receipt_status:'declined'});}if(approval.intent==='transaction_intent'){if(!/^0x[0-9a-fA-F]{64}$/.test(body.transaction_hash||''))return json({},400);state.transactionHash=body.transaction_hash;approval.status='completed';state.completed++;return json({receipt_status:'completed'});}const address=await recoverMessageAddress({message:'Fixture approval message',signature:body.signature});if(address.toLowerCase()!==approval.address.toLowerCase())return json({},400);approval.status='completed';state.completed++;return json({receipt_status:'completed'});}
    return json({},404);
   }
   const match=path.match(/^\/apps\/(wallet-walletconnect|home)\/(.*)$/);
   if(match){const base=resolve(root,'capsules',match[1],match[2].startsWith('vendor/')?'':'browser');const file=resolve(base,match[2]||'index.html');if(relative(base,file).startsWith('..'))return json({},400);res.setHeader('content-type',({'.js':'text/javascript','.mjs':'text/javascript','.css':'text/css','.html':'text/html','.woff2':'font/woff2'})[extname(file)]||'application/octet-stream');return res.end(readFileSync(file));}
   json({},404);
  }catch(error){json({error:error.name},500);}
 });
 let relayAvailable=true;const {relay,methods}=walletConnectRelayFixture(server);
 // A relay outage interrupts the old socket and holds a new Runtime handshake,
 // as a network black hole does. It does not turn a valid admission into an error.
 relay.on('connection',(socket,request)=>{
  socket.windowPeer=request.url.startsWith('/api/apps/');socket.held=[];socket.pendingAcks=new Set();const send=socket.send;
  socket.on('message',raw=>{const reply=JSON.parse(String(raw));if(!reply.method)socket.pendingAcks.delete(reply.id);});
  socket.send=function(...args){if(socket.windowPeer&&!relayAvailable){socket.held.push(args);return;}const message=JSON.parse(String(args[0]));if(socket.windowPeer&&message.method==='irn_subscription')socket.pendingAcks.add(message.id);return send.apply(socket,args);};
 });await new Promise(r=>server.listen(0,'127.0.0.1',r));
 return {state,methods,pendingDeliveryAcks(){return [...relay.clients].filter(socket=>socket.windowPeer).reduce((count,socket)=>count+socket.pendingAcks.size,0);},setRelayAvailable(value){relayAvailable=value;let dropped=0;for(const socket of relay.clients)if(socket.windowPeer){if(!value){dropped++;socket.terminate();}else for(const args of socket.held.splice(0))socket.send(...args);}return dropped;},setPermission(value){state.permission=value;state.keys={};state.revision++;},origin:`http://127.0.0.1:${server.address().port}`,async stop(){for(const socket of relay.clients)socket.terminate();await new Promise(r=>relay.close(r));server.closeAllConnections();await new Promise(r=>server.close(r));}};
}

// A fixture navigation ends a frame, not its wallet connection. Observe real SDK
// work and let its existing storage queue settle before destroying that frame.
export async function walletWindowLifetime(page,fixture,{holdRetirement=false}={}) {
 await page.addInitScript(()=>{
  const life=window.__walletFixtureLifetime={providers:[],restoreCalls:0,pending:0,payloadStarts:0,engineStarts:0,storageStarts:0,fetches:0,bodies:0,intervals:new Set(),timeouts:new Set(),listeners:[]};
  const fetch=window.fetch.bind(window),setInterval=window.setInterval.bind(window),clearInterval=window.clearInterval.bind(window),setTimeout=window.setTimeout.bind(window),clearTimeout=window.clearTimeout.bind(window),add=window.addEventListener.bind(window);
  window.fetch=async(...args)=>{life.fetches++;try{const response=await fetch(...args);for(const key of ['json','text','arrayBuffer']){const original=response[key];response[key]=function(...args){life.bodies++;try{return Promise.resolve(original.apply(this,args)).finally(()=>life.bodies--);}catch(error){life.bodies--;throw error;}};}return response;}finally{life.fetches--;}};
  window.setInterval=(...args)=>{const id=setInterval(...args);life.intervals.add(id);return id;};window.clearInterval=id=>{life.intervals.delete(id);clearInterval(id);};
  window.setTimeout=(fn,ms,...args)=>{let id;id=setTimeout(typeof fn==='function'?function(...values){life.timeouts.delete(id);return fn.apply(window,values);}:fn,ms,...args);life.timeouts.add(id);return id;};window.clearTimeout=id=>{life.timeouts.delete(id);clearTimeout(id);};
  window.addEventListener=(name,listener,options)=>{if(['focus','message','online','offline'].includes(name))life.listeners.push({name,listener,options});return add(name,listener,options);};
  life.stopInputs=()=>{for(const id of life.intervals)clearInterval(id);life.intervals.clear();for(const {name,listener,options} of life.listeners)window.removeEventListener(name,listener,options);life.listeners=[];};
  life.stopTimers=()=>{for(const id of life.timeouts)clearTimeout(id);life.timeouts.clear();};
  life.observe=provider=>{
  const life=window.__walletFixtureLifetime;if(life.providers.includes(provider))return;life.providers.push(provider);
  const wrap=(object,key,counter)=>{if(typeof object?.[key]!=='function')return;const original=object[key];object[key]=function(...args){life.pending++;if(counter)life[counter]++;try{return Promise.resolve(original.apply(this,args)).finally(()=>life.pending--);}catch(error){life.pending--;throw error;}};};
  const client=provider.signer.client;wrap(client.engine,'onRelayMessage','engineStarts');wrap(client.core.relayer,'onProviderPayload','payloadStarts');wrap(client.core.storage,'setItem','storageStarts');wrap(client.core.storage,'removeItem','storageStarts');
 };
 });

 await page.route('**/vendor/reown-appkit.js?*',async route=>{
  assert.equal(new URL(route.request().url()).origin,fixture.origin);const response=await route.fetch(),source=await response.text(),exported=source.match(/([\w$]+) as restoreWalletConnectEvm/);assert.ok(exported,'observe the real pinned provider export');
  let body=source.replace(exported[0],exported[1]+' as originalRestoreWalletConnectEvm')+`\nexport async function restoreWalletConnectEvm(...args){window.__walletFixtureLifetime.restoreCalls++;const provider=await ${exported[1]}(...args);window.__walletFixtureLifetime.observe(provider);return provider;}`;
  const connected=source.match(/([\w$]+) as connectWalletConnectEvm/);assert.ok(connected,'observe the real pinned connect export');
  body=body.replace(connected[0],connected[1]+' as originalConnectWalletConnectEvm')+`\nexport async function connectWalletConnectEvm(...args){const provider=await ${connected[1]}(...args);window.__walletFixtureLifetime.observe(provider);return provider;}`;
  if(holdRetirement){
   const disconnected=source.match(/([\w$]+) as disconnectWalletConnectEvm/);assert.ok(disconnected,'observe the real pinned disconnect export');
   body=body.replace(disconnected[0],disconnected[1]+' as originalDisconnectWalletConnectEvm')+`\nexport async function disconnectWalletConnectEvm(...args){try{await ${disconnected[1]}(...args);}finally{const life=window.__walletFixtureLifetime;if(life.holdRetirement)await new Promise(resolve=>{life.retirementHeld=true;life.releaseRetirement=resolve;});}}`;
  }
  await route.fulfill({response,body});
 });
 return async frame=>{
  if(!frame||frame.isDetached()||process.env.WALLETCONNECT_SKIP_PHONE_DRAIN==='1')return;
  await frame.evaluate(()=>window.__walletFixtureLifetime?.stopInputs());
  const end=Date.now()+20000;
  while(true){
   const ready=fixture.pendingDeliveryAcks()===0&&await frame.evaluate(async mayRead=>{
    const life=window.__walletFixtureLifetime;if(!life)return true;
    const idle=()=>!life.pending&&!life.fetches&&!life.bodies&&life.providers.every(provider=>!(provider.signer.client.engine.relayMessageCache?.length)&&!(provider.signer.client.engine.requestQueue?.queue?.length));
    if(!idle())return false;const starts=life.storageStarts;
    const cores=mayRead?[...new Set(life.providers.map(provider=>provider.signer.client.core))].filter(core=>core.heartbeat.events.eventNames().length):[];
    await Promise.all(cores.map(core=>core.storage.getKeys()));
    if(!idle()||starts!==life.storageStarts)return false;
    life.stopTimers();return true;
   },fixture.state.permission==='granted'&&!fixture.state.expiredLaunch);
   if(ready)return;assert.ok(Date.now()<end,'real SDK handlers, network bodies and storage settled before fixture navigation');await new Promise(resolve=>setTimeout(resolve,25));
  }
 };
}
