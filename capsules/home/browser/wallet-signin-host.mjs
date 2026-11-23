import {connectedWalletSigninMethods,requestConnectedSigninWallets} from './wallet-signin-methods.mjs';
// The shell supplies a source/token-bound context from its launch registry.
export function handleWalletSigninRequest(event,context,{api,manage,current,changed,authorityToken,authorityCurrent,openConnector,selectWalletConnect,focusCaller=()=>{}}) {
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
  Promise.all([api('/api/auth/wallet-methods',undefined,token),api('/api/auth/passkeys',undefined,token)])
    .then(async([wallets,passkeys])=>{
      if(!active())return;
      const method=data.action==='add'?null:wallets.methods?.find(row=>row.method_id===data.methodId);
      const passkey=passkeys.passkeys?.find(row=>row.principal_id===wallets.account_id && !row.revoked_at);
      if(data.action==='list')return reply({status:'complete',...wallets,can_manage:passkey?.role==='admin'});
      if(data.action!=='add' && !method)return reply({status:'changed'});
      const result=await manage({action:data.action,method,token,account:passkey?.display_name||'Your account',accountId:wallets.account_id,isCurrent:active,openConnector,selectWalletConnect,loadConnected:async()=>{
        const accounts=await requestConnectedSigninWallets(event.source,data.requestId);
        if(!active())throw new Error('Home session changed');
        const latest=await api('/api/auth/wallet-methods',undefined,token);
        if(!active())throw new Error('Home session changed');
        return connectedWalletSigninMethods(accounts,[]).map(row=>{
          const existing=latest.methods.find(m=>(row.connector==='unisat'?m.address===row.address:m.address.toLowerCase()===row.address.toLowerCase())&&m.chain_id===row.chain_id&&m.network===row.network);
          return existing?{...row,...existing,connector:row.connector,paymentOnly:false}:row;
        }).filter(row=>!row.sign_in_enabled);
      }});
      reply(result);changed();if(result?.status==='complete'&&active())focusCaller();
    }).catch(()=>reply({status:'failed'}));
  return true;
}
