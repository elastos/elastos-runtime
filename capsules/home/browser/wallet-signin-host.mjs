import {walletConnectorKind} from './wallet-signin-options.mjs?v=wallet-signin-2';
import {inventorySigninMethods} from './wallet-signin-methods.mjs?v=wallet-signin-2';
// Repeated intents follow one observed ceremony across asynchronous auth reads.
const pendingChanges = new WeakMap();
// The shell supplies a source/token-bound context from its launch registry.
export function handleWalletSigninRequest(event,context,{api,manage,current,changed,authorityToken,authorityCurrent,sessionMethodId=()=>'',openConnector,selectWalletConnect,focusCaller=()=>{}}) {
  const data=event.data;
  if(data?.type!=='home:wallet-signin-request')return false;
  const keys=['type','requestId','homeToken','action','methodId'];
  if(context?.kind!=='app-frame' || context.targetId!=='system'
    || context.source!==event.source || context.homeToken!==data.homeToken
    || Object.keys(data).length!==keys.length || keys.some(key=>!Object.hasOwn(data,key))
    || typeof data.requestId!=='string' || !data.requestId || data.requestId.length>128
    || !['list','add','remove'].includes(data.action)
    || typeof data.methodId!=='string' || data.methodId.length>256
    || (['list','add'].includes(data.action)?data.methodId!=='':!data.methodId))return true;
  const token=authorityToken();
  const sameAuthority=authorityCurrent?authorityCurrent():()=>authorityToken()===token;
  const active=()=>current() && sameAuthority();
  const reply=result=>{if(active())event.source.postMessage({type:'home:wallet-signin-result',requestId:data.requestId,result},'*');};
  if(!token){reply({status:'failed'});return true;}
  const previous=pendingChanges.get(event.source);
  if(data.action!=='list'&&previous?.active()&&active()) {
    if(previous.action!==data.action||previous.methodId!==data.methodId){reply({status:'busy'});return true;}
    // The original validated options only refocus the still-active ceremony.
    if(previous.options){try{void Promise.resolve(manage(previous.options)).catch(()=>{});}catch{}}
    void previous.result.then(reply);return true;
  }
  const pending={active,action:data.action,methodId:data.methodId,options:null};
  pending.result=Promise.all([api('/api/auth/wallet-methods',undefined,token),api('/api/auth/passkeys',undefined,token)])
    .then(async([wallets,passkeys])=>{
      if(!active())return;
      const method=data.action==='add'?null:wallets.methods?.find(row=>row.proof_binding_id===data.methodId);
      const passkey=passkeys.passkeys?.find(row=>row.principal_id===wallets.principal_id && !row.revoked_at);
      if(data.action==='list')return {status:'complete',...wallets,can_manage:passkey?.role==='admin'};
      if(data.action!=='add' && !method)return {status:'changed'};
      pending.options={action:data.action,method:method?{...method,connector:walletConnectorKind(method.connector)}:null,token,account:passkey?.display_name||'Your account',accountId:wallets.principal_id,sessionMethodId:sessionMethodId(),sessionCurrent:sameAuthority,isCurrent:active,openConnector,selectWalletConnect,loadConnected:async()=>{
        const inventory=await api('/api/apps/wallet/wallet/inventory',undefined,token);
        if(!active())throw new Error('Home session changed');
        if(inventory.principal_id!==wallets.principal_id)throw new Error('Home account changed');
        return inventorySigninMethods(inventory);
      }};
      const result=await manage(pending.options);
      if(result?.status==='complete')changed();if(active()&&result?.refocus!==false)focusCaller();
      return result;
    }).catch(()=>({status:'failed'}));
  if(data.action!=='list')pendingChanges.set(event.source,pending);
  void pending.result.then(result=>{if(result)reply(result);}).finally(()=>{
    if(pendingChanges.get(event.source)===pending)pendingChanges.delete(event.source);
  });
  return true;
}
