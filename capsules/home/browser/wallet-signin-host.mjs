// The shell supplies a source/token-bound context from its launch registry.
export function handleWalletSigninRequest(event,context,{api,manage,current,changed,authorityToken}) {
  const data=event.data;
  if(data?.type!=='home:wallet-signin-request')return false;
  const keys=['type','requestId','homeToken','action','methodId'];
  if(Object.hasOwn(data,'wallet')) {
    const wallet=data.wallet;
    if(data.action!=='add' || context?.targetId!=='wallet' || !wallet
      || Object.keys(wallet).length!==4 || !['connector','address','chain_id','network'].every(key=>Object.hasOwn(wallet,key))
      || !['metamask','walletconnect','unisat'].includes(wallet.connector)
      || typeof wallet.address!=='string' || !wallet.address || wallet.address.length>256
      || !Number.isSafeInteger(wallet.chain_id)
      || (wallet.connector==='unisat'?wallet.chain_id!==0||wallet.network!=='bitcoin':wallet.chain_id<=0||wallet.network!==''))return true;
    keys.push('wallet');
  }
  if(context?.kind!=='app-frame' || !['system','wallet'].includes(context.targetId)
    || context.source!==event.source || context.homeToken!==data.homeToken
    || Object.keys(data).length!==keys.length || keys.some(key=>!Object.hasOwn(data,key))
    || typeof data.requestId!=='string' || !data.requestId || data.requestId.length>128
    || !['list','add','remove'].includes(data.action)
    || typeof data.methodId!=='string' || data.methodId.length>256
    || (['list','add'].includes(data.action)?data.methodId!=='':!data.methodId))return true;
  const token=authorityToken();
  const active=()=>current() && authorityToken()===token;
  const reply=result=>{if(active())event.source.postMessage({type:'home:wallet-signin-result',requestId:data.requestId,result},'*');};
  if(!token){reply({status:'failed'});return true;}
  Promise.all([api('/api/auth/wallet-methods',undefined,token),api('/api/auth/passkeys',undefined,token)])
    .then(async([wallets,passkeys])=>{
      if(!active())return;
      const method=data.action==='add'?data.wallet:wallets.methods?.find(row=>row.method_id===data.methodId);
      const passkey=passkeys.passkeys?.find(row=>row.principal_id===wallets.account_id && !row.revoked_at);
      if(data.action==='list')return reply({status:'complete',...wallets,can_manage:passkey?.role==='admin'});
      if(data.action!=='add' && !method)return reply({status:'changed'});
      const result=await manage({action:data.action,method,token,account:passkey?.display_name||'Your account',accountId:wallets.account_id,isCurrent:active});
      reply(result);changed();
    }).catch(()=>reply({status:'failed'}));
  return true;
}
