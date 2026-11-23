import http from 'node:http';
import {readFile} from 'node:fs/promises';
import {resolve,extname} from 'node:path';
import {fileURLToPath} from 'node:url';
const root=fileURLToPath(new URL('../../',import.meta.url));
export const evmAddress='0x'+'12'.repeat(20),walletconnectAddress='0x'+'56'.repeat(20),bitcoinAddress='bc1q'+'a'.repeat(38);
export const relayNotice="Turning Sign in on lets visitors start short WalletConnect sign-in connections to this Home. The relay service can see this Home computer's internet address. Payment connections keep their separate Inbox permission.";
export const sampleMethod=(connector='metamask',sign_in_enabled=false)=>({method_id:`wallet:${connector}`,connector,address:connector==='unisat'?bitcoinAddress:connector==='walletconnect'?walletconnectAddress:evmAddress,chain_id:connector==='unisat'?0:20,network:connector==='unisat'?'bitcoin':'',sign_in_enabled,created_at:Math.floor(Date.parse('2026-11-20T15:00:00Z')/1000),last_used_at:Math.floor(Date.parse('2026-11-21T15:00:00Z')/1000)});
export async function signinFixture() {
  const state={methods:['metamask','unisat','walletconnect'].map(connector=>sampleMethod(connector,true)),calls:[],ceremonies:new Map(),scenario:'normal',signed:false,passkeyCount:1,serial:0,role:'admin',stepUps:new Map()};
  let origin;
  const server=http.createServer(async(req,res)=>{
    res.setHeader('access-control-allow-origin','*');res.setHeader('access-control-allow-headers','content-type,x-elastos-home-token,x-elastos-step-up-token,x-elastos-wallet-attempt,x-elastos-wallet-instance,if-match');res.setHeader('access-control-allow-methods','GET,POST,DELETE,OPTIONS');
    let call;const json=(body,status=200)=>{if(call)call.status=status;res.writeHead(status,{'content-type':'application/json'}).end(JSON.stringify(body));};
    if(req.method==='OPTIONS'){res.writeHead(204).end();return;}
    const url=new URL(req.url,origin),path=url.pathname;
    try {
      if(path.startsWith('/api/')) {
        let raw='';for await(const chunk of req){raw+=chunk;if(raw.length>98304)return json({error:'too_large'},413);}
        const body=raw?JSON.parse(raw):undefined;
        // Keep secrets and signatures out of the evidence. Assertions use memory only.
        call={path,body,headers:req.headers};state.calls.push(call);
        const now=Date.now()/1000;
        if((path.startsWith('/api/auth/wallet-methods')||path==='/api/auth/passkeys') && !['fixture-home','fixture-system'].includes(req.headers['x-elastos-home-token']))return json({},403);
        if(path.startsWith('/api/auth/wallet')&&req.headers.authorization)return json({},403);
        const passkeys=()=>[...Array.from({length:state.passkeyCount},(_,index)=>({proof_binding_id:`passkey:${index}`,principal_id:'principal:alex',display_name:'Alex',added_from:index?'Security key':'Safari on Mac',role:state.role,current:index===0&&!state.walletSession,created_at:Math.floor(Date.parse('2026-11-20T15:00:00Z')/1000),last_used_at:Math.floor(Date.parse('2026-11-21T15:00:00Z')/1000)})),...(state.otherAdmin?[{proof_binding_id:'passkey:other',principal_id:'principal:morgan',display_name:'Morgan',added_from:'Security key',role:state.otherRole||'admin',current:false,created_at:Math.floor(Date.parse('2026-11-20T15:00:00Z')/1000)}]:[])];
        if(path==='/api/auth/passkey/authenticate/begin')return json({ceremony_id:'passkey-login',options:{publicKey:{challenge:'YWJj',rpId:'127.0.0.1',allowCredentials:[{type:'public-key',id:'YWJj'}]}}});
        if(path==='/api/auth/passkey/authenticate/complete'){state.signed=true;state.walletSession=false;return json({home_token:'fixture-home',session_id:'fixture-session',principal_id:'principal:alex',proof_binding_id:'proof:passkey:one'});}
        if(path==='/api/auth/passkey/status')return json({registered:state.scenario!=='first-run',guest_registration_enabled:false,wallet_signin_available:state.methods.some(m=>m.sign_in_enabled),walletconnect_signin_available:state.methods.some(m=>m.sign_in_enabled&&m.connector!=='unisat'&&[20,8453].includes(m.chain_id))});
        if(path==='/api/auth/passkeys')return state.scenario==='passkeys-load-failed'?json({},503):json({passkeys:passkeys()});
        if(path==='/api/auth/wallet-methods' && req.method==='GET') {
          if(state.holdList)await new Promise(resolve=>state.releaseList=resolve);
          if(state.scenario==='load-failed')return json({},503);
          return json({account_id:'principal:alex',methods:state.methods});
        }
        if(path==='/api/auth/wallet/cancel'){const c=state.ceremonies.get(body.ceremony_id);if(c)c.cancelled=true;return json({status:'cancelled'});}
        if(['/api/auth/wallet-methods/begin','/api/auth/wallet/signin/begin'].includes(path)) {
          if(state.scenario==='busy')return json({},429);
          if(state.scenario==='offline')return json({},503);
          if(state.scenario==='conflict')return json({},409);
          if(body.connector==='walletconnect' || body.action==='enable'&&state.methods.find(m=>m.method_id===body.method_id)?.connector==='walletconnect') {
            if(body.allow_temporary_internet!==true)return json({},403);
            if(path==='/api/auth/wallet/signin/begin'&&!state.methods.some(m=>m.sign_in_enabled&&m.connector!=='unisat'&&[20,8453].includes(m.chain_id)))return json({},403);
          }
          if(body.action==='add' && body.address && state.methods.some(m=>m.address.toLowerCase()===body.address.toLowerCase() && m.chain_id===body.chain_id && m.network===body.network))return json({},409);
          const method=body.method_id?state.methods.find(m=>m.method_id===body.method_id):body;
          const ceremony_id=`ceremony:${++state.serial}`,expires_at=now+(state.scenario==='expired'?1:180);
          const approval={operation:'auth.wallet.method',notice:body.action==='enable'&&method?.connector!=='unisat'?relayNotice:'Confirm this wallet sign-in method change with your passkey.',request:{ceremony_id,account_id:'principal:alex',action:body.action,method_id:body.method_id||`wallet:${body.connector}`,connector:method?.connector,address:method?.address,chain_id:method?.chain_id,network:method?.network,authorizes_short_public_walletconnect:body.action==='enable'&&method?.connector!=='unisat'&&[20,8453].includes(method?.chain_id)}};
          const result={ceremony_id,message:['disable','remove'].includes(body.action)||!method?.address?'':`Sign in to ${origin}\nAccount: ${method?.address||'Select wallet'}\nRequest: ${ceremony_id}`,expires_at,...(body.action?{approval}:{}),
            ...(method?.connector==='walletconnect'?{attempt_token:`fixture-attempt:${ceremony_id}`,instance_id:`instance:${ceremony_id}`,storage_revision:0}:{})};
          state.ceremonies.set(ceremony_id,{...result,secret:body.browser_secret,action:body.action||'signin',method,actor:body.action?req.headers['x-elastos-home-token']:null});return json(result);
        }
        if(path==='/api/auth/wallet/signin/select') {
          const c=state.ceremonies.get(body.ceremony_id);
          if(!c||c.secret!==body.browser_secret||c.selected||c.method.connector!=='walletconnect'||c.method.address||c.actor&&req.headers['x-elastos-home-token']!==c.actor)return json({},403);
          c.selected=true;c.method={...c.method,address:body.address,chain_id:body.chain_id};c.message=`Sign in to ${origin}\nAccount: ${body.address}\nRequest: ${body.ceremony_id}`;
          if(c.action==='add')Object.assign(c.approval.request,{address:body.address,chain_id:body.chain_id});
          return json({ceremony_id:c.ceremony_id,message:c.message,expires_at:c.expires_at,...(c.action==='add'?{approval:c.approval}:{})});
        }
        if(path==='/api/auth/passkey-step-up/begin') {
          const id=`step-up:${++state.serial}`;state.stepUps.set(id,{operation:body.operation,request:body.request});
          return json({schema:'elastos.auth.passkey-step-up.begin.result/v1',ceremony_id:id,options:{publicKey:{challenge:'YWJj',rpId:'127.0.0.1',allowCredentials:[{type:'public-key',id:'YWJj'}]}}});
        }
        if(path==='/api/auth/passkey-step-up/complete') {
          if(!state.stepUps.has(body.ceremony_id))return json({},403);
          return json({schema:'elastos.auth.passkey-step-up.complete.result/v1',step_up_token:body.ceremony_id});
        }
        if(path==='/api/auth/passkey-step-up/cancel')return json({status:'cancelled'});
        if(path.endsWith('/complete')&&path.includes('/auth/wallet')) {
          if(state.holdComplete)await new Promise(resolve=>state.releaseComplete=resolve);
          const c=state.ceremonies.get(body.ceremony_id);
          if(!c||c.secret!==body.browser_secret||c.cancelled||now>=c.expires_at||c.actor&&req.headers['x-elastos-home-token']!==c.actor)return json({error:'wallet_signin_refused'},403);
          if(state.scenario==='refused')return json({error:'wallet_signin_refused'},403);
          if(c.action==='signin' && !state.methods.some(m=>m.sign_in_enabled && m.address.toLowerCase()===c.method.address.toLowerCase() && m.chain_id===c.method.chain_id && m.network===c.method.network))return json({error:'wallet_signin_refused'},403);
          if(c.action!=='signin'&&JSON.stringify(state.stepUps.get(body.step_up_token))!==JSON.stringify({operation:c.approval.operation,request:c.approval.request}))return json({},403);
          if(!['disable','remove'].includes(c.action)&&body.signature!=='fixture-signature')return json({},403);
          if(!c.result){
            if(c.action==='signin') {
              const signedMethod=state.methods.find(m=>m.sign_in_enabled&&m.address.toLowerCase()===c.method.address.toLowerCase()&&m.chain_id===c.method.chain_id&&m.network===c.method.network);signedMethod.last_used_at=Math.floor(now);
              state.signed=true;state.walletSession=true;c.result={session_id:'fixture-session',principal_id:'principal:alex',proof_binding_id:signedMethod.method_id,expires_at:now+3600,app_token:'fixture-home'};
            } else {
              const id=c.method.method_id||`wallet:${c.method.connector}`;
              if(c.action==='add')state.methods.push({...sampleMethod(c.method.connector),created_at:Math.floor(now),last_used_at:null,method_id:id,address:c.method.address,chain_id:c.method.chain_id,network:c.method.network});
              else if(c.action==='remove')state.methods=state.methods.filter(m=>m.method_id!==id);
              else state.methods.find(m=>m.method_id===id).sign_in_enabled=c.action==='enable';
              c.result={status:c.action==='remove'?'removed':'complete',method_id:id,sign_in_enabled:c.action==='enable'};
            }
          }
          if(c.action==='signin')res.setHeader('set-cookie','fixture-session=fixture; HttpOnly; SameSite=Lax; Path=/');
          return json(c.result);
        }
        const passkeyAction=path.match(/^\/api\/auth\/passkeys\/([^/]+)\/(revoke|promote-admin|demote-guest)$/);
        if(passkeyAction) {
          if(req.headers['x-elastos-home-token']!=='fixture-system')return json({},403);
          const id=decodeURIComponent(passkeyAction[1]),action=passkeyAction[2],target=passkeys().find(p=>p.proof_binding_id===id);
          if(!target)return json({},403);
          const operation=action==='promote-admin'?'auth.account.promote':action==='demote-guest'?'auth.account.demote':body?.remove_account?'auth.account.remove':'auth.passkey.remove';
          const request=body?.remove_account?{proof_binding_id:id,account_id:body.account_id,remove_account:true}:{proof_binding_id:id};
          if(body?.remove_account&&body.account_id!==target.principal_id)return json({},403);
          if(action==='revoke'&&!body?.remove_account&&passkeys().filter(p=>p.principal_id===target.principal_id).length<=1)return json({},409);
          if(JSON.stringify(state.stepUps.get(req.headers['x-elastos-step-up-token']))!==JSON.stringify({operation,request}))return json({},403);
          state.stepUps.delete(req.headers['x-elastos-step-up-token']);
          if(action==='revoke') {
            if(target.principal_id==='principal:morgan')state.otherAdmin=false;
            else if(body?.remove_account){state.passkeyCount=0;state.methods=[];state.signed=false;}
            else state.passkeyCount--;
          } else if(target.principal_id==='principal:morgan')state.otherRole=action==='promote-admin'?'admin':'guest';
          else state.role=action==='promote-admin'?'admin':'guest';
          return json({status:action==='revoke'?'revoked':action==='promote-admin'?'promoted':'demoted',proof_binding_id:id});
        }
        if(path.startsWith('/api/apps/wallet-walletconnect/')) {
          const c=[...state.ceremonies.values()].find(c=>c.instance_id===req.headers['x-elastos-wallet-instance']);
          if(!c||c.cancelled||now>=c.expires_at||req.headers['x-elastos-wallet-attempt']!==c.attempt_token)return json({},403);
          if(req.headers['if-match']!=='"0"')return json({},409);
        }
        if(path==='/api/apps/wallet-walletconnect/wallet/config')return json({walletconnect:{project_id:'fixture-project'}});
        if(path==='/api/apps/wallet-walletconnect/storage')return json({});
        if(path==='/api/apps/wallet-walletconnect/relay-admission')return json({token:'fixture-relay'});
        if(path==='/api/apps/system/summary' || path==='/api/apps/system/update')return json({identity:{profile:{schema:'elastos.profile-summary/v1',display_name:'Alex'}},access:{role:state.role},authority:{proof_binding_id:state.walletSession?'proof:signin-wallet:fixture':'proof:passkey:fixture'},runtime:{},source:{},appearance:{schema:'elastos.home.appearance/v1',revision:0,theme:'light',accent:'blue',accent_custom:'#4f7fff',dock_auto_hide:false,sounds:false,focus_mode:false,background_image_url:null,background_overlay_enabled:true,background_overlay_opacity:0.55}});
        if(path==='/api/apps/wallet/wallet/summary')return json({wallet_accounts:{accounts:[{account_id:'payment:one',connector_id:'wallet-metamask',address:evmAddress,chain_namespace:'eip155:20',proof_type:'siwe'}]},wallet_approvals:{approval_requests:[]},approval_methods:{}});
        if(path==='/api/auth/sessions/refresh')return state.signed?json({home_token:'fixture-home',session_id:'fixture-session',principal_id:'principal:alex',proof_binding_id:'wallet:metamask'}):json({},403);
        if(path==='/api/apps/home/summary')return json({authority:{signed_in:state.signed},signed_in:state.signed,active_shell:{},targets:[]});
        return json({});
      }
      if(path==='/fixture-host.mjs') {
        res.setHeader('content-type','text/javascript');res.end(`
import {bindHomeUnlock,showHomeUnlock,hideHomeUnlock,manageWalletSignin,requestPasskeyStepUp} from '/apps/home/shell-auth.js?v=wallet-signin-fixture';
import {handleWalletSigninRequest} from '/apps/home/wallet-signin-host.mjs';
import {walletSigninApi} from '/apps/home/wallet-signin-view.mjs';
window.openedPrincipal='';
bindHomeUnlock();
await showHomeUnlock(async (result,flow)=>{if(window.walletFixture.openFailed)throw new Error("Fixture Home opening failure");window.openedFlow=flow;window.openedPrincipal=result.principal_id;hideHomeUnlock();document.querySelector('.home-host-shell').hidden=true;document.querySelector('#fixture-desktop').hidden=false;});
const area=document.createElement('section');area.id='fixture-desktop';area.hidden=true;area.innerHTML='<h1>Home</h1><p>Alex</p>';document.body.append(area);
window.showFixtureApps=()=>{
 document.querySelector('#home-unlock').hidden=true;document.querySelector('.home-host-shell').hidden=true;
 area.hidden=false;area.replaceChildren();area.style.cssText='height:100vh;display:grid;grid-template-rows:40px 1fr';
 const tabs=document.createElement('nav');tabs.innerHTML='<button id="show-system">System</button><button id="show-wallet">Wallet</button>';
 const frames=[];
 for(const target of ['system','wallet']) {
   const frame=document.createElement('iframe');frame.title=target;frame.dataset.target=target;frame.style.cssText='width:100%;height:calc(100vh - 50px);border:0';frame.setAttribute('sandbox','allow-scripts allow-forms');frame.src='/apps/'+target+'/?home_origin='+encodeURIComponent(location.origin)+'#home_token=fixture-'+target;frame.hidden=target!=='system';area.append(frame);frames.push(frame);
   tabs.querySelector('#show-'+target).onclick=()=>{frames.forEach(f=>f.hidden=f!==frame);frame.contentWindow.postMessage({type:'home:wallet-signin-changed'},'*');};
 }
 area.prepend(tabs);
};
addEventListener('message',event=>{
 const frame=[...document.querySelectorAll('#fixture-desktop iframe')].find(f=>f.contentWindow===event.source);
 if(!frame)return;
 if(event.data?.type==='elastos.home.passkey-step-up.request/v1'&&frame.dataset.target==='system'&&event.data.homeToken==='fixture-system') {
   requestPasskeyStepUp('fixture-system',event.data.operation,event.data.request).then(stepUpToken=>event.source.postMessage({type:'elastos.home.passkey-step-up.result/v1',requestId:event.data.requestId,stepUpToken},'*'),()=>event.source.postMessage({type:'elastos.home.passkey-step-up.result/v1',requestId:event.data.requestId,error:'Passkey verification failed.'},'*'));return;
 }
 const context={kind:'app-frame',targetId:frame.dataset.target,source:event.source,homeToken:'fixture-'+frame.dataset.target};
 handleWalletSigninRequest(event,context,{authorityToken:()=> 'fixture-home',api:(path,body,token)=>walletSigninApi(path,body,token),manage:manageWalletSignin,current:()=>frame.isConnected,changed:()=>{for(const f of document.querySelectorAll('#fixture-desktop iframe'))f.contentWindow.postMessage({type:'home:wallet-signin-changed'},'*');}});
});
window.fixtureReady=true;
`);return;
      }
      if(path==='/apps/wallet-walletconnect/vendor/reown-appkit.js') {
        res.setHeader('content-type','text/javascript');res.end(`
let callback,holdSignature=false,chainOverride;const listeners=new Map();let account=${JSON.stringify(walletconnectAddress)},chain=20;
const provider={connected:false,session:null,signer:{client:{core:{relayer:{transportClose:async()=>{}}}},abortPairingAttempt(){},async connect(){}},
 on(name,fn){listeners.set(name,fn);},removeListener(name){listeners.delete(name);},
 async connect(){listeners.get('display_uri')?.('wc:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@2?relay-protocol=irn&symKey=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb');await new Promise(resolve=>callback=resolve);this.connected=true;this.session={expiry:Date.now()/1000+180};},
 async request({method,params}){await fetch('/api/fixture-sdk',{method:'POST',body:JSON.stringify({method,params})});if(method==='eth_accounts')return [account];if(method==='eth_chainId')return chainOverride??chain;if(method==='personal_sign'){if(holdSignature)await new Promise(()=>{});return 'fixture-signature';}}};
addEventListener('message',event=>{if(event.source!==parent)return;if(event.data==='fixture-pair')callback?.();if(event.data==='fixture-sign-pending')holdSignature=true;if(event.data?.type==='fixture-network')chainOverride=event.data.chain;if(event.data==='fixture-account-change'){account='0x'+'34'.repeat(20);listeners.get('accountsChanged')?.([account]);}});
export async function restoreWalletConnectEvm(options){if(options.authenticationOnly!==true)throw new Error('Sign-in needs authentication-only pairing');await options.api('storage');await options.api('relay-admission',{method:'POST'});return provider;}
`);return;
      }
      let file;
      if(path==='/home/'||path==='/real-home/')file=resolve(root,'capsules/home/browser/index.html');
      else {
        const match=path.match(/^\/apps\/([a-z-]+)\/(.*)$/) || path.match(/^\/(?:home|real-home)\/(.*)$/)?.map((part,index)=>index===0?part:index===1?'home':part);
        const homeAsset=path.match(/^\/(?:home|real-home)\/(.+)$/);
        if(homeAsset) {match[1]='home';match[2]=homeAsset[1];}
        if(!match)return json({},404);
        const [,capsule,asset]=match;
        file=resolve(root,'capsules',capsule,asset.startsWith('vendor/')?asset:'browser/'+(asset||'index.html'));
        if(!file.startsWith(resolve(root,'capsules')+'/'))return json({},404);
      }
      let content=await readFile(file);
      if(path==='/home/')content=Buffer.from(content.toString().replace('./home-shell-host.js?v=download-progress-20261112','/fixture-host.mjs'));
      res.setHeader('content-type',({'.js':'text/javascript','.mjs':'text/javascript','.html':'text/html','.css':'text/css','.svg':'image/svg+xml','.woff2':'font/woff2','.png':'image/png','.webp':'image/webp'})[extname(file)]||'application/octet-stream');res.end(content);
    }catch(error){res.writeHead(500).end('Fixture failed: '+error.code);}
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));origin=`http://127.0.0.1:${server.address().port}`;
  return {origin,state,async close(){server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}};
}

// Boundary fixture: browsers/extensions and passkey authenticators are external signers.
export function installSigninProviders({evmAddress,bitcoinAddress}) {
  addEventListener('DOMContentLoaded',()=>document.documentElement.dataset.elTheme='light',{once:true});
  if(window!==window.top)return;
  if(new URLSearchParams(location.search).has('no-passkeys'))window.PublicKeyCredential=undefined;
  else window.PublicKeyCredential ||= function PublicKeyCredential(){};
  const listeners=new Map();
  window.walletFixture={mode:'normal',chain:20,address:evmAddress,network:'livenet',calls:[],pending:[],missing:false,multiple:false,passkeyMode:'normal'};
  const f=window.walletFixture;
  function ask(method,result){
    f.calls.push({method});
    if(f.mode==='pending' && ['personal_sign','signMessage','eth_requestAccounts','requestAccounts'].includes(method))return new Promise((resolve,reject)=>f.pending.push({resolve,reject,result}));
    if(f.mode==='rejected'&&['personal_sign','signMessage'].includes(method))return Promise.reject({code:4001});
    return Promise.resolve(result);
  }
  const provider={on:(name,listener)=>{if(!listeners.has(name))listeners.set(name,new Set());listeners.get(name).add(listener);},removeListener:(name,listener)=>listeners.get(name)?.delete(listener),request:({method})=>ask(method,method==='eth_chainId'?f.chain:method==='personal_sign'?'fixture-signature':[f.address])};
  window.addEventListener('eip6963:requestProvider',()=>{
    if(f.missing)return;
    for(const [uuid,rdns,name]of f.multiple?[['rabby','io.rabby','Rabby Wallet'],['brave','com.brave.wallet','Brave Wallet']]:[['metamask','io.metamask','MetaMask']])window.dispatchEvent(new CustomEvent('eip6963:announceProvider',{detail:{provider:f.multiple?{...provider,request:args=>provider.request(args)}:provider,info:{uuid,rdns,name}}}));
  });
  window.unisat={...provider,requestAccounts:()=>ask('requestAccounts',[bitcoinAddress]),getAccounts:()=>Promise.resolve([bitcoinAddress]),getNetwork:()=>Promise.resolve(f.network),getPublicKey:()=>Promise.resolve('fixture-public-key'),signMessage:()=>ask('signMessage','fixture-signature')};
  window.emitSigninWallet=name=>{for(const listener of listeners.get(name)||[])listener();};
  Object.defineProperty(navigator,'credentials',{value:{get:async({signal})=>{
    f.calls.push({method:'passkey'});
    if(f.passkeyMode==='cancelled')throw new DOMException('Cancelled','NotAllowedError');
    if(f.passkeyMode==='pending')await new Promise((resolve,reject)=>{f.pending.push({resolve,reject});signal?.addEventListener('abort',()=>reject(new DOMException('Aborted','AbortError')),{once:true});});
    return {id:'fixture',rawId:new Uint8Array([1]).buffer,type:'public-key',response:{clientDataJSON:new Uint8Array([2]).buffer,authenticatorData:new Uint8Array([3]).buffer,signature:new Uint8Array([4]).buffer,userHandle:null}};
  }}});
  Object.defineProperty(navigator,'clipboard',{value:{writeText:async value=>{if(f.copyFailed)throw new Error('refused');f.copied=value;}}});
}
