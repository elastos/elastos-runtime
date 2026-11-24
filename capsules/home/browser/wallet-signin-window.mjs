// Desktop owns window selection; Home binds the returned Runtime launch token.
export async function openWalletSigninEntry({post,listen=window,source,desktopToken,context,timeoutMs=15000}) {
  const requestId=crypto.randomUUID(),desktop=source(),shellToken=desktopToken(),deadline=Date.now()+timeoutMs;
  let receive,timer;
  const token=await new Promise((resolve,reject)=>{
    receive=event=>{
      const data=event.data;
      if(event.source!==desktop||source()!==desktop||event.origin!=='null'||desktopToken()!==shellToken||data?.homeToken!==shellToken||data?.type!=='home:wallet-connect-entry-ready'||data.requestId!==requestId)return;
      if(Object.keys(data).length!==4||typeof data.walletToken!=='string'||data.walletToken.length>4096)return;
      if(!data.walletToken){reject(new Error('Wallet did not open'));return;}
      resolve(data.walletToken);
    };
    listen.addEventListener('message',receive);
    timer=setTimeout(()=>reject(new Error('Wallet did not open')),timeoutMs);
    if(!post({type:'home:gui-command',command:'open-wallet-connect-entry',requestId}))reject(new Error('Desktop is unavailable'));
  }).finally(()=>{clearTimeout(timer);listen.removeEventListener('message',receive);});
  let wallet=context(token);
  while(wallet?.targetId==='wallet'&&!wallet.source&&source()===desktop&&Date.now()<deadline){
    await new Promise(resolve=>setTimeout(resolve,50));wallet=context(token);
  }
  if(source()!==desktop||desktopToken()!==shellToken||wallet?.targetId!=='wallet'||!wallet.source||wallet.source.closed)throw new Error('Wallet window changed');
  wallet.source.postMessage({type:'elastos.wallet.connect-entry/v1'},'*');
  return {homeToken:token,source:wallet.source,isOpen:()=>context(token)===wallet&&!wallet.source.closed};
}
