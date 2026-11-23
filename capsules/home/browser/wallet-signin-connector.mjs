// Home talks only to its admitted WalletConnect window. Proof stays in memory.
export async function selectConnectedWalletConnect({signal,method},{open,current,listen=window}) {
  const context=await open();signal.throwIfAborted();
  const pending=new Map();let sequence=0,monitor,closed=false;
  const prefix=crypto.randomUUID();
  const valid=()=>!closed&&!signal.aborted&&current(context);
  const send=(operation,body={})=>new Promise((resolve,reject)=>{
    if(!valid())return reject(new Error('Wallet window changed'));
    const requestId=`${prefix}:${++sequence}`;pending.set(requestId,{resolve,reject});
    context.source.postMessage({type:'home:wallet-signin-effect',homeToken:context.homeToken,requestId,operation,...body},'*');
  });
  const receive=event=>{
    if(!valid()||event.source!==context.source||event.origin!=='null'||event.data?.type!=='home:wallet-signin-effect-result'||event.data.homeToken!==context.homeToken)return;
    const job=pending.get(event.data.requestId);if(!job)return;pending.delete(event.data.requestId);
    if(event.data.error)job.reject(Object.assign(new Error('Wallet could not sign'),{code:event.data.code}));else job.resolve(event.data.result);
  };
  const close=()=>{
    if(closed)return;closed=true;clearInterval(monitor);
    listen.removeEventListener('message',receive);signal.removeEventListener('abort',close);
    if(current(context))context.source.postMessage({type:'home:wallet-signin-effect',homeToken:context.homeToken,requestId:`${prefix}:stop`,operation:'stop'},'*');
    for(const job of pending.values())job.reject(Object.assign(new Error('Wallet request ended'),{code:'disconnected'}));pending.clear();
  };
  listen.addEventListener('message',receive);signal.addEventListener('abort',close,{once:true});
  monitor=setInterval(()=>{if(!current(context)||context.source.closed)close();},250);
  try {
    const wallet=await send('select');
    if(!wallet||wallet.connector!=='walletconnect'||!/^0x[0-9a-fA-F]{40}$/.test(wallet.address)||!Number.isSafeInteger(wallet.chain_id)||wallet.chain_id<=0||wallet.network!=='')throw new Error('Invalid wallet identity');
    if(![20,8453].includes(wallet.chain_id))throw Object.assign(new Error('Unsupported sign-in network'),{code:'network'});
    if(method&&(method.address.toLowerCase()!==wallet.address.toLowerCase()||method.chain_id!==wallet.chain_id))throw Object.assign(new Error('Wallet changed'),{code:'changed'});
    return {...wallet,check:()=>send('check',{address:wallet.address,chain_id:wallet.chain_id}),
      async sign(message){
        const proof=await send('sign',{address:wallet.address,chain_id:wallet.chain_id,message});
        if(typeof proof?.signature!=='string'||!proof.signature||proof.signature.length>16384||proof.signature_type!=='personal_sign'||proof.public_key!=='')throw new Error('Invalid wallet proof');
        return {signature:proof.signature,signature_type:'personal_sign',public_key:''};
      },close};
  }catch(error){close();throw error;}
}
