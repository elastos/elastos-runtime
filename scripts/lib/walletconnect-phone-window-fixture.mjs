import http from 'node:http';
import {readFileSync} from 'node:fs';
import {resolve,relative,extname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {walletConnectRelayFixture} from './walletconnect-relay-fixture.mjs';
import {walletConnectFixtureRequire as require} from './walletconnect-relay-fixture.mjs';
const root=fileURLToPath(new URL('../..',import.meta.url));
const {recoverMessageAddress}=require('viem');
export async function windowFixture() {
 const state={permission:'granted',revision:0,keys:{},accounts:[],approvals:[],verified:0,completed:0,calls:[],deleteFails:false,guest:false,expiredLaunch:false};
 const server=http.createServer(async(req,res)=>{
  const path=new URL(req.url,'http://localhost').pathname;res.setHeader('access-control-allow-origin','*');res.setHeader('access-control-allow-headers','content-type,x-elastos-home-token,if-match');res.setHeader('access-control-allow-methods','GET,POST,DELETE,OPTIONS');if(req.method==='OPTIONS'){res.writeHead(204).end();return;}
  const json=(body,code=200)=>{res.writeHead(code,{'content-type':'application/json'}).end(JSON.stringify(body));};
  try{
   if(path==='/') {res.setHeader('content-type','text/html');res.end(`<!doctype html><style>body{margin:0}iframe{border:0;width:100%;height:100vh}</style><iframe id="wallet" sandbox="allow-scripts allow-forms" src="/apps/wallet-walletconnect/?home_origin=http://127.0.0.1:${server.address().port}#home_token=fixture-wallet"></iframe><script>
   window.copied='';addEventListener('message',async e=>{const d=e.data;if(d.type==='home:app-ready')e.source.postMessage({type:'home:clipboard-ready',schema:'elastos.home.clipboard.ready/v1',targetId:'wallet-walletconnect',homeToken:'fixture-wallet',parentOrigin:location.origin,generation:'fixture-generation'},'*');
   if(d.type==='home:clipboard-request'){window.copied=d.text;e.source.postMessage({type:'home:clipboard-result',schema:'elastos.home.clipboard.result/v1',targetId:'wallet-walletconnect',homeToken:d.homeToken,parentOrigin:location.origin,generation:d.generation,requestId:d.requestId,operation:d.operation,purpose:d.purpose,ok:true},'*');}});</script>`);return;}
   if(path.startsWith('/api/')) {
    state.calls.push({path,method:req.method,revision:req.headers['if-match']});
    if(state.expiredLaunch){res.writeHead(403).end('Launch expired');return;}
    if(state.guest&&path.endsWith('/internet')&&req.method==='POST'&&state.permission!=='granted'){res.writeHead(403).end("Only this Home's owner can allow WalletConnect internet access. Ask the owner to review Inbox.");return;}
    let input='';for await(const chunk of req)input+=chunk;const body=input?JSON.parse(input):{};
    if(path.endsWith('/internet')&&req.method==='POST'&&state.permission!=='granted')state.permission='requested';
    if(path.endsWith('/internet'))return json({status:state.permission,request:{id:'request-1',issued_at:Math.floor(Date.now()/1000)}});
    if(path.endsWith('/wallet/config'))return json({walletconnect:{project_id:'fixture-project',storage_revision:JSON.stringify(String(state.revision))}});
    if(path.endsWith('/relay-admission'))return json({token:'fixture-admission'});
    if(path.endsWith('/storage')){
     if(req.method==='DELETE'){if(state.deleteFails)return json({},503);state.keys={};state.revision++;}
     else {if(req.headers['if-match']!==JSON.stringify(String(state.revision)))return json({},409);if(req.method==='POST'){if(body.value===null)delete state.keys[body.key];else state.keys[body.key]=body.value;}}
     return json(state.keys);
    }
    if(path.endsWith('/wallet/accounts'))return json({accounts:state.accounts});
    if(path.endsWith('/wallet/approvals'))return json({approval_requests:state.approvals.filter(r=>r.status==='pending'||r.status==='approved'&&r.intent==='transaction_intent')});
    if(path.endsWith('/challenge')){state.challenge={message:'Test Home ownership proof '+crypto.randomUUID(),expires_at:Math.floor(Date.now()/1000)+300,address:body.address,chain:body.chain_id};return json(state.challenge);}
    if(path.endsWith('/verify')){if(body.message!==state.challenge.message)return json({},400);const address=await recoverMessageAddress({message:body.message,signature:body.signature});if(address.toLowerCase()!==state.challenge.address.toLowerCase())return json({},400);state.verified++;state.accounts=[{address,chain_namespace:`eip155:${state.challenge.chain}`,connector_id:'wallet-walletconnect',proof_type:'siwe'}];return json({status:'linked'});}
    const approval=state.approvals.find(r=>path.includes(encodeURIComponent(r.request_id)));
    if(path.endsWith('/approve')&&approval?.status==='pending'){approval.status='approved';return json({handoff:{request_id:approval.request_id,payload_hash:'0x'+'34'.repeat(32),signer:approval.address,intent:approval.intent,signature_type:'personal_sign',message:'Fixture approval message'},binding:{payload_hash:'0x'+'34'.repeat(32),chain_namespace:approval.chain_namespace,expires_at:approval.expires_at}});}
    if(path.endsWith('/complete')&&approval?.status==='approved'){const address=await recoverMessageAddress({message:'Fixture approval message',signature:body.signature});if(address.toLowerCase()!==approval.address.toLowerCase())return json({},400);approval.status='completed';state.completed++;return json({receipt_status:'completed'});}
    return json({},404);
   }
   const match=path.match(/^\/apps\/(wallet-walletconnect|home)\/(.*)$/);
   if(match){const base=resolve(root,'capsules',match[1],match[2].startsWith('vendor/')?'':'browser');const file=resolve(base,match[2]||'index.html');if(relative(base,file).startsWith('..'))return json({},400);res.setHeader('content-type',({'.js':'text/javascript','.mjs':'text/javascript','.css':'text/css','.html':'text/html','.woff2':'font/woff2'})[extname(file)]||'application/octet-stream');return res.end(readFileSync(file));}
   json({},404);
  }catch(error){json({error:error.name},500);}
 });
 const {relay,methods}=walletConnectRelayFixture(server);await new Promise(r=>server.listen(0,'127.0.0.1',r));
 return {state,methods,setPermission(value){state.permission=value;state.keys={};state.revision++;},origin:`http://127.0.0.1:${server.address().port}`,async stop(){for(const socket of relay.clients)socket.terminate();await new Promise(r=>relay.close(r));server.closeAllConnections();await new Promise(r=>server.close(r));}};
}
