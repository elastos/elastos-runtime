// The shell supplies a source/token-bound context from its launch registry.
export function handleWalletSigninRequest(event,context,{api,manage,current,changed,authorityToken}) {
  const data=event.data;
  if(data?.type!=='home:wallet-signin-request')return false;
  const keys=['type','requestId','homeToken','action','methodId'];
  if(context?.kind!=='app-frame' || !['system','wallet'].includes(context.targetId)
    || context.source!==event.source || context.homeToken!==data.homeToken
    || Object.keys(data).length!==keys.length || keys.some(key=>!Object.hasOwn(data,key))
    || typeof data.requestId!=='string' || !data.requestId || data.requestId.length>128
    || !['list','add','enable','disable','remove'].includes(data.action)
    || typeof data.methodId!=='string' || data.methodId.length>256
    || (['list','add'].includes(data.action)?data.methodId!=='':!data.methodId))return true;
  const reply=result=>{if(current())event.source.postMessage({type:'home:wallet-signin-result',requestId:data.requestId,result},'*');};
  const token=authorityToken();
  if(!token){reply({status:'failed'});return true;}
  Promise.all([api('/api/auth/wallet-methods',undefined,token),api('/api/auth/passkeys',undefined,token)])
    .then(async([wallets,passkeys])=>{
      if(!current())return;
      const method=wallets.methods?.find(row=>row.method_id===data.methodId);
      const passkey=passkeys.passkeys?.find(row=>row.principal_id===wallets.account_id && !row.revoked_at);
      if(data.action==='list')return reply({status:'complete',...wallets,can_manage:passkey?.role==='admin'});
      if(data.action!=='add' && !method)return reply({status:'changed'});
      const result=await manage({action:data.action,method,token,account:passkey?.display_name||'Your account',accountId:wallets.account_id,isCurrent:current});
      reply(result);changed();
    }).catch(()=>reply({status:'failed'}));
  return true;
}
