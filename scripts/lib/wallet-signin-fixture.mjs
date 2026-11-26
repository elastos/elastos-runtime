import http from 'node:http';
import {readFile} from 'node:fs/promises';
import {resolve,extname} from 'node:path';
import {fileURLToPath} from 'node:url';
const root=fileURLToPath(new URL('../../',import.meta.url));
export const evmAddress='0x'+'12'.repeat(20),walletconnectAddress='0x'+'56'.repeat(20),bitcoinAddress='bc1q'+'a'.repeat(38);
export const relayNotice="Your wallet connects through a relay that can see this computer's internet address.";
export const sampleMethod=(connector='metamask',sign_in_enabled=true)=>({method_id:`wallet:${connector}`,connector,address:connector==='unisat'?bitcoinAddress:connector==='walletconnect'?walletconnectAddress:evmAddress,chain_id:connector==='unisat'?0:20,network:connector==='unisat'?'bitcoin':'',sign_in_enabled,created_at:Math.floor(Date.parse('2026-11-20T15:00:00Z')/1000),last_used_at:Math.floor(Date.parse('2026-11-21T15:00:00Z')/1000)});
// API fixtures project two independent saved uses for the real UI modules.
export function fixtureInventory(state) {
  const entries = new Map();
  const identity = (namespace, address) => `${namespace}:${namespace.startsWith('eip155:') ? address.toLowerCase() : address}`;
  for (const account of state.connected) {
    if (account.revoked_at) continue;
    const id = identity(account.chain_namespace, account.address);
    if (!entries.has(id)) entries.set(id, {inventory_id:id,address:account.address,chain_namespace:account.chain_namespace,accounts:[],sign_in:null});
    entries.get(id).accounts.push(account);
  }
  for (const method of state.methods) {
    if (!method.sign_in_enabled) continue;
    const namespace = method.connector === 'unisat' ? 'bip122:000000000019d6689c085ae165831e93' : `eip155:${method.chain_id}`;
    const id = identity(namespace, method.address);
    if (!entries.has(id)) entries.set(id, {inventory_id:id,address:method.address,chain_namespace:namespace,accounts:[],sign_in:null});
    entries.get(id).sign_in = method;
    entries.get(id).wallet_display_name ||= state.revokedAccounts?.find(a=>a.chain_namespace===namespace&&a.address===method.address)?.wallet_display_name;
  }
  const rank=entry=>({metamask:1,unisat:2,walletconnect:3}[entry.accounts[0]?.connector_id?.replace('wallet-','')||entry.sign_in?.connector]||0);
  return {schema:'elastos.wallet.inventory/v1',account_id:'principal:alex',account_name:'Alex',entries:[...entries.values()].sort((a,b)=>rank(a)-rank(b))};
}
export async function signinFixture() {
  const state={theme:'light',connected:[{account_id:'payment:one',connector_id:'wallet-metamask',address:evmAddress,chain_namespace:'eip155:20',proof_type:'siwe'}],wcConnected:true,methods:['metamask','unisat','walletconnect'].map(connector=>sampleMethod(connector,true)),calls:[],ceremonies:new Map(),scenario:'normal',signed:false,passkeyCount:1,serial:0,role:'admin',stepUps:new Map()};
  let origin;
  const server=http.createServer(async(req,res)=>{
    res.setHeader('access-control-allow-origin','*');res.setHeader('access-control-expose-headers','etag');res.setHeader('access-control-allow-headers','content-type,x-elastos-home-token,x-elastos-step-up-token,x-elastos-wallet-attempt,x-elastos-wallet-instance,if-match');res.setHeader('access-control-allow-methods','GET,POST,DELETE,OPTIONS');
    let call;const json=(body,status=200)=>{if(call)call.status=status;res.writeHead(status,{'content-type':'application/json'}).end(JSON.stringify(body));};
    if(req.method==='OPTIONS'){res.writeHead(204).end();return;}
    const url=new URL(req.url,origin),path=url.pathname;
    try {
      if(path.startsWith('/api/')) {
        let raw='';for await(const chunk of req){raw+=chunk;if(raw.length>98304)return json({error:'too_large'},413);}
        const body=raw?JSON.parse(raw):undefined;
        // Keep secrets and signatures out of the evidence. Assertions use memory only.
        call={path,body,headers:req.headers};state.calls.push(call);
        const selectedBitcoin=state.walletAddresses?.bitcoin || bitcoinAddress;
        const selectedEvm=state.walletAddresses?.evm || evmAddress;
        const now=(Date.now()+(state.clockOffsetMs||0))/1000;
        if((path.startsWith('/api/auth/wallet-methods')||path==='/api/auth/passkeys') && !['fixture-home','fixture-system'].includes(req.headers['x-elastos-home-token']))return json({},403);
        if(path.startsWith('/api/auth/wallet')&&req.headers.authorization)return json({},403);
        const passkeys=()=>[...Array.from({length:state.passkeyCount},(_,index)=>({proof_binding_id:`passkey:${index}`,principal_id:'principal:alex',display_name:'Alex',added_from:state.passkeyLabels?.[index]||(index?'Security key':'Safari on Mac'),role:state.role,current:index===0&&!state.walletSession,created_at:Math.floor(Date.parse('2026-11-20T15:00:00Z')/1000),last_used_at:Math.floor(Date.parse('2026-11-21T15:00:00Z')/1000)})),...(state.otherAdmin?[{proof_binding_id:'passkey:other',principal_id:'principal:morgan',display_name:state.otherDisplayName||'Morgan',added_from:'Security key',role:state.otherRole||'admin',current:false,created_at:Math.floor(Date.parse('2026-11-20T15:00:00Z')/1000)}]:[])];
        if(path==='/api/auth/passkey/authenticate/begin')return json({ceremony_id:'passkey-login',options:{publicKey:{challenge:'YWJj',rpId:'127.0.0.1',allowCredentials:[{type:'public-key',id:'YWJj'}]}}});
        if(path==='/api/auth/passkey/authenticate/complete'){state.signed=true;state.walletSession=false;if(state.boundSigninCookies){state.activeSession='fixture-passkey-session';res.setHeader('set-cookie','fixture-session=passkey; HttpOnly; SameSite=Lax; Path=/');}return json({home_token:'fixture-home',session_id:'fixture-session',principal_id:'principal:alex',proof_binding_id:'proof:passkey:one'});}
        if(path==='/api/auth/passkey/status')return json({registered:state.scenario!=='first-run',guest_registration_enabled:false,wallet_signin_connectors:[...(state.methods.some(m=>m.sign_in_enabled&&m.connector!=='unisat')?['metamask']:[]),...(state.methods.some(m=>m.sign_in_enabled&&m.connector==='unisat')?['unisat']:[]),...(state.methods.some(m=>m.sign_in_enabled&&m.connector==='walletconnect'&&[20,8453].includes(m.chain_id))?['walletconnect']:[])],wallet_signin_relay_notice:relayNotice,wallet_signin_available:state.methods.some(m=>m.sign_in_enabled),walletconnect_signin_available:state.methods.some(m=>m.sign_in_enabled&&m.connector==='walletconnect'&&[20,8453].includes(m.chain_id))});
        if(path==='/api/auth/passkeys')return state.scenario==='passkeys-load-failed'?json({},503):json({passkeys:passkeys()});
        if(path==='/api/auth/wallet-methods' && req.method==='GET') {
          if(state.holdList)await new Promise(resolve=>state.releaseList=resolve);
          if(state.scenario==='load-failed')return json({},503);
          return json({account_id:'principal:alex',methods:state.methods,open_changes:[...state.ceremonies.values()].filter(c=>c.actor&&['add','remove'].includes(c.action)&&!c.cancelled&&!c.result&&c.expires_at>now).map(c=>c.ceremony_id)});
        }
        if(path==='/api/auth/wallet/cancel') {
          const c=state.ceremonies.get(body.ceremony_id);
          if(!c||c.secret!==body.browser_secret)return json({},403);
          if(c.result?.session_id&&c.result.session_id===state.activeSession){state.signed=false;state.activeSession=null;}
          c.cancelled=true;return json({status:'cancelled'});
        }
        if(path==='/api/auth/wallet-methods/begin'&&!['add','remove'].includes(body.action))return json({error:'wallet_signin_refused'},403);
        if(['/api/auth/wallet-methods/begin','/api/auth/wallet/signin/begin'].includes(path)) {
          if(body.action&&body.action==='add'&&state.role!=='admin')return json({},403);
          if(state.scenario==='busy')return json({},429);
          if(state.scenario==='offline')return json({},503);
          if(state.scenario==='conflict')return json({},409);
          if(body.connector==='walletconnect') {
            if(body.allow_temporary_internet!==true)return json({},403);
            if(path==='/api/auth/wallet/signin/begin'&&!state.methods.some(m=>m.sign_in_enabled&&m.connector==='walletconnect'&&[20,8453].includes(m.chain_id)))return json({},403);
          }
          if(['add'].includes(body.action) && body.address && state.methods.some(m=>m.address.toLowerCase()===body.address.toLowerCase() && m.chain_id===body.chain_id && m.network===body.network))return json({},409);
          const method=body.method_id?state.methods.find(m=>m.method_id===body.method_id):body;
          const ceremony_id=`ceremony:${++state.serial}`,expires_at=now+(state.scenario==='expired'?1:180);
          const approval={operation:'auth.wallet.method',notice:body.action==='add'&&method?.connector==='walletconnect'?relayNotice:'',request:{ceremony_id,account_id:'principal:alex',action:body.action,method_id:body.method_id||`wallet:${body.connector}`,connector:method?.connector,address:method?.address,chain_id:method?.chain_id,network:method?.network,authorizes_short_public_walletconnect:body.action==='add'&&method?.connector==='walletconnect'&&[20,8453].includes(method?.chain_id)}};
          const result={ceremony_id,message:body.action==='remove'||!method?.address?'':`Sign in to ${origin}\nAccount: ${method?.address||'Select wallet'}\nRequest: ${ceremony_id}${state.longSigningMessage?'\nMessage detail line'.repeat(150):''}`,expires_at,...(body.action?{approval}:{}),
            ...(method?.connector==='walletconnect'?{attempt_token:`fixture-attempt:${ceremony_id}`,instance_id:`instance:${ceremony_id}`,storage_revision:0}:{})};
          state.ceremonies.set(ceremony_id,{...result,secret:body.browser_secret,action:body.action||'signin',method,actor:body.action?req.headers['x-elastos-home-token']:null});return json(result);
        }
        if(path==='/api/auth/wallet/signin/select') {
          const c=state.ceremonies.get(body.ceremony_id);
          if(!c||c.secret!==body.browser_secret||c.selected||c.method.connector!=='walletconnect'||c.method.address||c.actor&&req.headers['x-elastos-home-token']!==c.actor)return json({},403);
          c.selected=true;c.method={...c.method,address:body.address,chain_id:body.chain_id};c.message=`Sign in to ${origin}\nAccount: ${body.address}\nRequest: ${body.ceremony_id}`;
          if(['add'].includes(c.action))Object.assign(c.approval.request,{address:body.address,chain_id:body.chain_id});
          return json({ceremony_id:c.ceremony_id,message:c.message,expires_at:c.expires_at,...(['add'].includes(c.action)?{approval:c.approval}:{})});
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
          if(c.action!=='signin'&&['add'].includes(c.action)&&state.role!=='admin')return json({},403);
          if(state.scenario==='refused')return json({error:'wallet_signin_refused'},403);
          if(c.action==='signin' && !state.methods.some(m=>m.sign_in_enabled && m.address.toLowerCase()===c.method.address.toLowerCase() && m.chain_id===c.method.chain_id && m.network===c.method.network))return json({error:'wallet_signin_refused'},403);
          if(c.action!=='signin'&&JSON.stringify(state.stepUps.get(body.step_up_token))!==JSON.stringify({operation:c.approval.operation,request:c.approval.request}))return json({},403);
          if(c.action!=='remove'&&body.signature!=='fixture-signature')return json({},403);
          if(!c.result){
            if(c.action==='signin') {
              const signedMethod=state.methods.find(m=>m.sign_in_enabled&&m.address.toLowerCase()===c.method.address.toLowerCase()&&m.chain_id===c.method.chain_id&&m.network===c.method.network);signedMethod.last_used_at=Math.floor(now);
              state.signed=true;state.walletSession=true;state.activeSession=`fixture-session:${c.ceremony_id}`;c.result={session_id:state.activeSession,principal_id:'principal:alex',proof_binding_id:signedMethod.method_id,expires_at:now+3600,app_token:'fixture-home'};
            } else {
              const id=c.method.method_id||`wallet:${c.method.connector}`;
              if(['add'].includes(c.action))state.methods.push({...sampleMethod(c.method.connector),created_at:Math.floor(now),last_used_at:null,method_id:id,address:c.method.address,chain_id:c.method.chain_id,network:c.method.network,sign_in_enabled:c.action==='add'});
              else if(c.action==='remove')state.methods=state.methods.filter(m=>m.method_id!==id);
              c.result={status:c.action==='remove'?'removed':'complete',method_id:id,sign_in_enabled:c.action==='add'};
            }
          }
          if(c.action==='signin')res.setHeader('set-cookie',`fixture-session=${state.boundSigninCookies?'wallet':'fixture'}; HttpOnly; SameSite=Lax; Path=/`);
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
        if(path.startsWith('/api/apps/wallet-walletconnect/')&&req.headers['x-elastos-wallet-attempt']) {
          const c=[...state.ceremonies.values()].find(c=>c.instance_id===req.headers['x-elastos-wallet-instance']);
          if(!c||c.cancelled||now>=c.expires_at||req.headers['x-elastos-wallet-attempt']!==c.attempt_token)return json({},403);
          call.transportRevision=c.revision||0;
          if(req.headers['if-match']!==`"${call.transportRevision}"`)return json({},409);
          if(path.endsWith('/storage')) {
            c.values ||= {};
            if(req.method==='POST'){if(body.value===null)delete c.values[body.key];else c.values[body.key]=body.value;c.revision=call.transportRevision+1;}
            res.setHeader('etag',`"${c.revision||0}"`);return json(c.values);
          }
        }
        if(path==='/api/apps/wallet-walletconnect/wallet/config')return json({walletconnect:{project_id:'fixture-project',storage_revision:'"0"'}});
        if(path==='/api/apps/wallet-walletconnect/internet')return json({status:state.internetStatus||'granted'});
        if(path==='/api/apps/wallet-walletconnect/storage'&&!req.headers['x-elastos-wallet-attempt'])return json(state.wcConnected?{'wc//session':[{expiry:now+600}]}:{});
        const connectorRead=path.match(/^\/api\/apps\/(wallet-metamask|wallet-unisat|wallet-walletconnect)\/wallet\/(accounts|approvals)$/);
        if(connectorRead)return json(connectorRead[2]==='accounts'?{accounts:state.connected.filter(a=>a.connector_id===connectorRead[1])}:{approval_requests:[]});
        if(path==='/api/apps/home/wallet-connector/bitcoin/link/challenge')return json({schema:'elastos.home.wallet-connector.effect.result/v1',action:'bitcoin_link_challenge',connector_id:'wallet-unisat',challenge:{schema:'elastos.wallet.bitcoin_challenge/v1',challenge_id:'bitcoin-ownership',message:'Runtime Bitcoin ownership message',expires_at:Math.floor(now)+180,address:selectedBitcoin,network:'bitcoin',resources:[],proof_type:'bip322_simple'}});
        if(path==='/api/apps/home/wallet-connector/bitcoin/link/verify') {
          state.connected.push({account_id:'app:bitcoin',connector_id:'wallet-unisat',address:selectedBitcoin,chain_namespace:'bip122:000000000019d6689c085ae165831e93',proof_type:'bip322'});
          return json({schema:'elastos.home.wallet-connector.effect.result/v1',action:'bitcoin_link_complete',connector_id:'wallet-unisat',status:'linked'});
        }
        if(path==='/api/apps/home/wallet-connector/evm/link/challenge')return json({schema:'elastos.home.wallet-connector.effect.result/v1',action:'evm_link_challenge',connector_id:'wallet-metamask',challenge:{schema:'elastos.auth.challenge/v1',challenge_id:'link',message:'Runtime ownership message',expires_at:Math.floor(now)+180,resources:[]}});
        if(path==='/api/apps/home/wallet-connector/evm/link/verify') {
          if(!state.connected.some(a=>a.address===selectedEvm))state.connected.push({account_id:'payment:new',connector_id:'wallet-metamask',address:selectedEvm,chain_namespace:'eip155:20',proof_type:'siwe'});
          return json({schema:'elastos.home.wallet-connector.effect.result/v1',action:'evm_link_complete',connector_id:'wallet-metamask',status:'linked'});
        }
        if(path==='/api/auth/evm/challenge')return json({message:'Runtime phone ownership message',expires_at:Math.floor(now)+180});
        if(path==='/api/auth/evm/verify') {state.connected.push({account_id:'app:phone',connector_id:'wallet-walletconnect',address:state.walletAddresses?.phone||walletconnectAddress,chain_namespace:'eip155:20',proof_type:'siwe',wallet_display_name:'Rainbow'});return json({status:'linked'});}
        if(path==='/api/apps/wallet-walletconnect/storage')return json({});
        if(path==='/api/apps/wallet-walletconnect/relay-admission')return json({token:'fixture-relay'});
        if(path==='/api/apps/system/summary' || path==='/api/apps/system/update')return json({wallet_accounts:{accounts:state.connected},identity:{profile:{schema:'elastos.profile-summary/v1',display_name:'Alex'}},access:{role:state.role},authority:{proof_binding_id:state.walletSession?'proof:signin-wallet:fixture':'proof:passkey:fixture'},runtime:{},source:{},appearance:{schema:'elastos.home.appearance/v1',revision:0,theme:state.theme,accent:'blue',accent_custom:'#4f7fff',dock_auto_hide:false,sounds:false,focus_mode:false,background_image_url:null,background_overlay_enabled:true,background_overlay_opacity:0.55}});
        const removeWallet=path.match(/^\/api\/apps\/wallet\/wallet\/accounts\/([^/]+)$/);
        if(removeWallet && req.method==='DELETE') {
          const id=decodeURIComponent(removeWallet[1]),ids=body.account_ids||[id];
          if(JSON.stringify(state.stepUps.get(body.step_up_token))!==JSON.stringify({operation:'wallet.account.delete',request:body.account_ids?{account_ids:ids}:{account_id:id}}))return json({},403);
          state.revokedAccounts=[...(state.revokedAccounts||[]),...state.connected.filter(a=>ids.includes(a.account_id))];state.connected=state.connected.filter(a=>!ids.includes(a.account_id));return json({});
        }
        if(path==='/api/provider/chain/balance')return json({status:'ok',data:{balance_hex:'0x'+BigInt(state.balanceValues?.[body.address]?.[body.network] || 0).toString(16)}});
        if(path==='/api/wallet/prices')return json({prices:{},stale:false});
        if(path==='/api/apps/wallet/wallet/inventory')return json(fixtureInventory(state));
        if(path==='/api/apps/wallet/wallet/summary')return json({wallet_accounts:{accounts:state.connected},wallet_approvals:{approval_requests:[]},approval_methods:{walletconnect:{available:state.walletconnectAvailable!==false}}});
        if(path==='/api/auth/sessions/refresh'&&state.boundSigninCookies&&!/(?:^|; )fixture-session=passkey(?:;|$)/.test(req.headers.cookie||''))return json({},403);
        if(path==='/api/auth/sessions/refresh')return state.signed?json({home_token:'fixture-home',session_id:'fixture-session',principal_id:'principal:alex',proof_binding_id:'wallet:metamask'}):json({},403);
        if(path==='/api/apps/home/summary')return json({authority:{signed_in:state.signed},signed_in:state.signed,active_shell:{},targets:[]});
        return json({});
      }
      if(path==='/fixture-host.mjs') {
        res.setHeader('content-type','text/javascript');res.end(`
import {bindHomeUnlock,showHomeUnlock,hideHomeUnlock,manageWalletSignin,requestPasskeyStepUp} from '/apps/home/shell-auth.js?v=wallet-signin-fixture';
import {handleWalletSigninRequest} from '/apps/home/wallet-signin-host.mjs';
import {walletSigninApi} from '/apps/home/wallet-signin-view.mjs';
import {selectConnectedWalletConnect} from '/apps/home/wallet-signin-connector.mjs';
import {openWalletSigninEntry} from '/apps/home/wallet-signin-window.mjs';
import {homeGuiReply} from '/apps/home-gui/home-gui-authority.js';
import {handleHomeWalletConnectorEffect,connectInventoryWallet} from '/apps/home/home-wallet-connector-host.js?v=home-wallpaper-20261030b';
import {handleWalletAppUse,retireWalletAppUse} from '/apps/home/wallet-app-use-host.mjs';
const contexts=new WeakMap();
async function openFixtureConnector(target) {
  let frame=document.querySelector('iframe[data-target='+target+']');
  if(!frame){frame=document.createElement('iframe');frame.dataset.target=target;frame.title=target;frame.style.cssText='position:fixed;inset:0;width:100%;height:100vh;border:0;z-index:20;background:var(--el-surface)';frame.setAttribute('sandbox','allow-scripts allow-forms');frame.src='/apps/'+target+'/?home_origin='+encodeURIComponent(location.origin)+'#home_token=fixture-'+target;document.querySelector('#fixture-desktop').append(frame);await new Promise(resolve=>frame.onload=resolve);}
  document.querySelectorAll('#fixture-desktop iframe').forEach(f=>f.hidden=f!==frame);frame.hidden=false;if(target==='wallet')frame.contentWindow.postMessage({type:'elastos.wallet.connect-entry/v1'},'*');return {close:()=>frame.remove(),isOpen:()=>frame.isConnected,homeToken:'fixture-'+target,source:frame.contentWindow,focus:()=>{document.querySelectorAll('#fixture-desktop iframe').forEach(f=>f.hidden=f!==frame);}};
}
async function openConnector(target) {
 if(target!=='wallet')return openFixtureConnector(target);
 const desktop=document.querySelector('#active-shell-frame').contentWindow;
 let visible;
 const hidden={targetId:'wallet',source:{postMessage(){throw new Error('Hidden Wallet rail selected');}}};
 const contextsByToken=new Map([['fixture-wallet-rail',hidden]]);
 return openWalletSigninEntry({source:()=>desktop,desktopToken:()=> 'fixture-desktop',context:token=>contextsByToken.get(token),post:message=>{
  void openFixtureConnector('wallet').then(opened=>{
   visible={targetId:'wallet',source:opened.source};contextsByToken.set(opened.homeToken,visible);
   window.fixtureWindowChoice='visible-wallet';
   dispatchEvent(new MessageEvent('message',{source:desktop,origin:'null',data:homeGuiReply({type:'home:wallet-connect-entry-ready',requestId:message.requestId,walletToken:opened.homeToken},'fixture-desktop')}));
  });return true;
 }});
}
const selectWalletConnect=options=>selectConnectedWalletConnect(options,{open:()=>openConnector('wallet-walletconnect'),current:context=>[...document.querySelectorAll('#fixture-desktop iframe')].some(f=>f.isConnected&&f.contentWindow===context.source)});
window.openedPrincipal='';
bindHomeUnlock();
await showHomeUnlock(async (result,flow)=>{if(window.walletFixture.openFailed)throw new Error("Fixture Home opening failure");window.openedFlow=flow;window.openedPrincipal=result.principal_id;hideHomeUnlock();document.querySelector('.home-host-shell').hidden=true;document.querySelector('#fixture-desktop').hidden=false;});
const area=document.createElement('section');area.id='fixture-desktop';area.hidden=true;area.innerHTML='<h1>Home</h1><p>Alex</p>';document.body.append(area);
window.showFixtureApps=()=>{
 document.querySelector('#home-unlock').hidden=true;document.querySelector('.home-host-shell').hidden=true;
 area.hidden=false;area.replaceChildren();area.style.cssText='height:100vh;display:grid;grid-template-rows:1fr';
 const tabs=document.createElement('nav');tabs.style.display='none';tabs.innerHTML='<button id="show-system">System</button><button id="show-wallet">Wallet</button>';
 const frames=[];
 for(const target of ['system','wallet']) {
   const frame=document.createElement('iframe');frame.title=target;frame.dataset.target=target;frame.style.cssText='width:100%;height:100vh;border:0';frame.setAttribute('sandbox','allow-scripts allow-forms');frame.src='/apps/'+target+'/?home_origin='+encodeURIComponent(location.origin)+'#home_token=fixture-'+target;frame.hidden=target!=='system';area.append(frame);frames.push(frame);
   tabs.querySelector('#show-'+target).onclick=()=>{area.querySelectorAll('iframe[data-target^=wallet-]').forEach(f=>f.hidden=true);frames.forEach(f=>f.hidden=f!==frame);frame.contentWindow.postMessage({type:'home:wallet-signin-changed'},'*');};
 }
 area.prepend(tabs);
};
addEventListener('message',event=>{
 const frame=[...document.querySelectorAll('#fixture-desktop iframe')].find(f=>f.contentWindow===event.source);
 if(!frame)return;
 if(event.data?.type==='elastos.home.passkey-step-up.request/v1'&&['system','wallet'].includes(frame.dataset.target)&&event.data.homeToken==='fixture-'+frame.dataset.target) {
   requestPasskeyStepUp('fixture-'+frame.dataset.target,event.data.operation,event.data.request).then(stepUpToken=>event.source.postMessage({type:'elastos.home.passkey-step-up.result/v1',requestId:event.data.requestId,stepUpToken},'*'),()=>event.source.postMessage({type:'elastos.home.passkey-step-up.result/v1',requestId:event.data.requestId,error:'Passkey verification failed.'},'*'));return;
 }
 if(event.data?.type==='home:close-self'){frame.remove();return;}
 if(event.data?.type==='home:open-target'&&frame.dataset.target==='system'&&event.data.target==='wallet'&&event.data.query?.wallet_entry){
  const wallet=document.querySelector('iframe[data-target=wallet]');for(const f of document.querySelectorAll('#fixture-desktop iframe'))f.hidden=f!==wallet;
  wallet.src='/apps/wallet/?wallet_entry='+encodeURIComponent(event.data.query.wallet_entry)+'&home_origin='+encodeURIComponent(location.origin)+'#home_token=fixture-wallet';return;
 }
 if(event.data?.type==='home:open-target'&&frame.dataset.target==='wallet'&&event.data.target==='system'){for(const f of document.querySelectorAll('#fixture-desktop iframe'))f.hidden=f.dataset.target!=='system';return;}
 if(event.data?.type==='home:open-target'&&frame.dataset.target==='wallet'&&event.data.homeToken==='fixture-wallet'&&['wallet-metamask','wallet-unisat','wallet-walletconnect'].includes(event.data.target)){void openConnector(event.data.target);return;}
 const context=contexts.get(frame)||{kind:'app-frame',targetId:frame.dataset.target,source:event.source,homeToken:'fixture-'+frame.dataset.target,walletEffectState:{inFlight:false,requestIds:new Set()}};contexts.set(frame,context);
 if(event.data?.type==='home:app-ready'&&event.data.homeToken===context.homeToken)retireWalletAppUse(context);
 if(handleWalletAppUse(event,context,{
  inventory:()=>walletSigninApi('/api/apps/wallet/wallet/inventory',undefined,'fixture-home'),
  current:()=>frame.isConnected,
  connect:async(entry,current)=>{const opened=await openFixtureConnector('wallet-'+entry.sign_in.connector);const target=document.querySelector('iframe[data-target=wallet-'+entry.sign_in.connector+']');const c={kind:'app-frame',targetId:target.dataset.target,source:opened.source,homeToken:opened.homeToken,walletEffectState:{inFlight:false,requestIds:new Set()}};if(entry.sign_in.connector!=='walletconnect')for(const f of document.querySelectorAll('#fixture-desktop iframe'))f.hidden=f!==frame;let watch;const controller=new AbortController();try{if(entry.sign_in.connector==='walletconnect'){watch=setInterval(()=>{if(!current())controller.abort();},100);await selectConnectedWalletConnect({signal:controller.signal,method:entry.sign_in,appUse:true,ready:()=>{for(const f of document.querySelectorAll('#fixture-desktop iframe'))f.hidden=f!==frame;}},{open:async()=>opened,current:()=>target.isConnected});}else await connectInventoryWallet(entry,c,current);}finally{clearInterval(watch);controller.abort();opened.close();}},
  changed:()=>{},focus:()=>{for(const f of document.querySelectorAll('#fixture-desktop iframe'))f.hidden=f!==frame;},
 }))return;
 if(handleHomeWalletConnectorEffect(event,context,event.data))return;
 handleWalletSigninRequest(event,context,{authorityToken:()=> 'fixture-home',api:(path,body,token)=>walletSigninApi(path,body,token),manage:manageWalletSignin,openConnector,selectWalletConnect,focusCaller:()=>{for(const f of document.querySelectorAll('#fixture-desktop iframe'))f.hidden=f.dataset.target!==frame.dataset.target;},current:()=>frame.isConnected,changed:()=>{for(const f of document.querySelectorAll('#fixture-desktop iframe'))f.contentWindow.postMessage({type:'home:wallet-signin-changed'},'*');}});
});
window.fixtureReady=true;
`);return;
      }
      if(path==='/apps/wallet-walletconnect/vendor/reown-appkit.js') {
        res.setHeader('content-type','text/javascript');res.end(`
let callback,holdSignature=${JSON.stringify(state.holdSignature===true)},rejectSignature=${JSON.stringify(state.rejectSignature===true)},chainOverride,releaseSignature;const listeners=new Map();let account=${JSON.stringify(walletconnectAddress)},chain=20;
const provider={connected:false,session:null,signer:{client:{core:{relayer:{transportClose:async()=>{}}}},abortPairingAttempt(){},async connect(){}},
 on(name,fn){listeners.set(name,fn);},removeListener(name){listeners.delete(name);},
 async connect(){listeners.get('display_uri')?.('wc:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@2?relay-protocol=irn&symKey=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb');await new Promise(resolve=>callback=resolve);this.connected=true;this.chainId=20;this.accounts=[account];this.session={expiry:Date.now()/1000+180,peer:{metadata:{name:'Fixture Wallet'}},namespaces:{eip155:{chains:['eip155:20'],accounts:['eip155:20:'+account],methods:['personal_sign']}}};},
 async request({method,params}){await fetch('/api/fixture-sdk',{method:'POST',body:JSON.stringify({method,params})});if(method==='eth_accounts')return [account];if(method==='eth_chainId')return chainOverride??chain;if(method==='personal_sign'){if(rejectSignature){rejectSignature=false;throw Object.assign(new Error('Wallet declined'),{code:4001});}if(holdSignature)await new Promise(resolve=>releaseSignature=resolve);return 'fixture-signature';}}};
addEventListener('message',event=>{if(event.source!==parent)return;if(event.data==='fixture-pair')callback?.();if(event.data==='fixture-sign-pending')holdSignature=true;if(event.data==='fixture-release-signature'){holdSignature=false;releaseSignature?.();}if(event.data?.type==='fixture-network')chainOverride=event.data.chain;if(event.data==='fixture-account-change'){account='0x'+'34'.repeat(20);listeners.get('accountsChanged')?.([account]);}});
export async function restoreWalletConnectEvm(options){if(options.authenticationOnly!==true&&${JSON.stringify(state.wcConnected)}){provider.chainId=20;provider.accounts=[account];provider.connected=true;provider.session={expiry:Date.now()/1000+600,namespaces:{eip155:{chains:['eip155:20'],accounts:['eip155:20:'+account],methods:['personal_sign']}}};return provider;}await options.api('storage');await Promise.all([options.api('storage',{method:'POST',body:JSON.stringify({key:'fixture:first',value:1})}),options.api('storage',{method:'POST',body:JSON.stringify({key:'fixture:second',value:2})}),options.api('relay-admission',{method:'POST'})]);return provider;}
export async function connectWalletConnectEvm(options){await restoreWalletConnectEvm(options);await provider.connect();return provider;}
export async function disconnectWalletConnectEvm(){}
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
export function installSigninProviders({evmAddress,bitcoinAddress,theme='light'}) {
  addEventListener('DOMContentLoaded',()=>document.documentElement.dataset.elTheme=theme,{once:true});
  if(window!==window.top)return;
  if(new URLSearchParams(location.search).has('no-passkeys'))window.PublicKeyCredential=undefined;
  else window.PublicKeyCredential ||= function PublicKeyCredential(){};
  const listeners=new Map();
  window.walletFixture={mode:'normal',chain:20,address:evmAddress,network:'livenet',calls:[],pending:[],missing:new URLSearchParams(location.search).has('desktop-app'),multiple:false,passkeyMode:'normal'};
  const f=window.walletFixture;
  function ask(method,result){
    f.calls.push({method});
    if((f.mode==='pending'||f.signaturePending&&['personal_sign','signMessage'].includes(method)) && ['personal_sign','signMessage','eth_requestAccounts','requestAccounts'].includes(method))return new Promise((resolve,reject)=>f.pending.push({resolve,reject,result}));
    if(f.mode==='rejected'&&['personal_sign','signMessage'].includes(method))return Promise.reject({code:4001});
    return Promise.resolve(result);
  }
  const provider={on:(name,listener)=>{if(!listeners.has(name))listeners.set(name,new Set());listeners.get(name).add(listener);},removeListener:(name,listener)=>listeners.get(name)?.delete(listener),request:({method})=>ask(method,method==='eth_chainId'?'0x'+Number(f.chain).toString(16):method==='personal_sign'?'fixture-signature':[f.address])};
  window.addEventListener('eip6963:requestProvider',()=>{
    if(f.missing)return;
    for(const [uuid,rdns,name]of f.multiple?[['rabby','io.rabby','Rabby Wallet'],['brave','com.brave.wallet','Brave Wallet']]:[['metamask','io.metamask','MetaMask']])window.dispatchEvent(new CustomEvent('eip6963:announceProvider',{detail:{provider:f.multiple?{...provider,request:args=>{const result=provider.request(args);f.calls.at(-1).providerId=rdns;return result;}}:provider,info:{uuid,rdns,name}}}));
  });
  window.unisat={...provider,requestAccounts:()=>ask('requestAccounts',[bitcoinAddress]),getAccounts:()=>Promise.resolve([bitcoinAddress]),getNetwork:()=>Promise.resolve(f.network),getPublicKey:()=>Promise.resolve('fixture-public-key'),signMessage:()=>ask('signMessage','fixture-signature')};
  if(new URLSearchParams(location.search).has('desktop-app'))window.unisat=undefined;
  window.emitSigninWallet=name=>{for(const listener of listeners.get(name)||[])listener();};
  Object.defineProperty(navigator,'credentials',{value:{get:async({signal})=>{
    f.calls.push({method:'passkey'});
    if(f.passkeyMode==='cancelled')throw new DOMException('Cancelled','NotAllowedError');
    if(f.passkeyMode==='pending')await new Promise((resolve,reject)=>{f.pending.push({resolve,reject});signal?.addEventListener('abort',()=>reject(new DOMException('Aborted','AbortError')),{once:true});});
    return {id:'fixture',rawId:new Uint8Array([1]).buffer,type:'public-key',response:{clientDataJSON:new Uint8Array([2]).buffer,authenticatorData:new Uint8Array([3]).buffer,signature:new Uint8Array([4]).buffer,userHandle:null}};
  }}});
  Object.defineProperty(navigator,'clipboard',{value:{writeText:async value=>{if(f.copyFailed)throw new Error('refused');f.copied=value;}}});
}
