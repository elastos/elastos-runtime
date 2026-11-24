// A display acknowledgement cannot hold Runtime's confirmed result open.
async function completeReview(send, reviewRequestId) {
  if (!reviewRequestId) return;
  let timer;
  try {
    await Promise.race([send('complete', {reviewRequestId}), new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error('Wallet completion display did not answer')), 1500);
    })]);
  } finally { clearTimeout(timer); }
}

// Home talks only to its admitted WalletConnect window. Proof stays in memory.
export async function selectConnectedWalletConnect({signal,method,opened,action='signin',changed=()=>{}},{open,current,listen=window}) {
  const context=await open();signal.throwIfAborted();opened?.(context.focus);
  const pending=new Map();let sequence=0,monitor,closed=false;
  const prefix=crypto.randomUUID();let reviewRequestId;
  const valid=()=>!closed&&!signal.aborted&&current(context);
  const send=(operation,body={})=>new Promise((resolve,reject)=>{
    if(!valid())return reject(new Error('Wallet window changed'));
    const requestId=`${prefix}:${++sequence}`;if(operation==='sign')reviewRequestId=requestId;pending.set(requestId,{resolve,reject});
    context.source.postMessage({type:'home:wallet-signin-effect',homeToken:context.homeToken,requestId,operation,...body},'*');
  });
  const receive=event=>{
    if(!valid()||event.source!==context.source||event.origin!=='null'||event.data?.type!=='home:wallet-signin-effect-result'||event.data.homeToken!==context.homeToken)return;
    const job=pending.get(event.data.requestId);if(!job)return;pending.delete(event.data.requestId);
    if(event.data.error)job.reject(Object.assign(new Error('Wallet could not sign'),{code:event.data.code||'disconnected'}));else job.resolve(event.data.result);
  };
  const close=()=>{
    if(closed)return;closed=true;clearInterval(monitor);
    listen.removeEventListener('message',receive);signal.removeEventListener('abort',close);
    if(current(context))context.source.postMessage({type:'home:wallet-signin-effect',homeToken:context.homeToken,requestId:`${prefix}:stop`,operation:'stop'},'*');
    for(const job of pending.values())job.reject(Object.assign(new Error('Wallet request ended'),{code:'disconnected'}));pending.clear();
  };
  listen.addEventListener('message',receive);signal.addEventListener('abort',close,{once:true});
  monitor=setInterval(()=>{if(!current(context)||context.source.closed){close();changed('disconnected');}},250);
  try {
    const wallet=await send('select');
    if(!wallet||wallet.connector!=='walletconnect'||!/^0x[0-9a-fA-F]{40}$/.test(wallet.address)||!Number.isSafeInteger(wallet.chain_id)||wallet.chain_id<=0||wallet.network!=='')throw new Error('Invalid wallet identity');
    if(![20,8453].includes(wallet.chain_id))throw Object.assign(new Error('Unsupported sign-in network'),{code:'network'});
    if(method&&(method.address.toLowerCase()!==wallet.address.toLowerCase()||method.chain_id!==wallet.chain_id))throw Object.assign(new Error('Wallet changed'),{code:'changed'});
    return {...wallet,focus:context.focus,check:()=>send('check',{address:wallet.address,chain_id:wallet.chain_id}),
      complete:()=>completeReview(send,reviewRequestId),
      async sign(message){
        const proof=await send('sign',{address:wallet.address,chain_id:wallet.chain_id,message,action});
        if(typeof proof?.signature!=='string'||!proof.signature||proof.signature.length>16384||proof.signature_type!=='personal_sign'||proof.public_key!=='')throw new Error('Invalid wallet proof');
        return {signature:proof.signature,signature_type:'personal_sign',public_key:''};
      },close};
  }catch(error){close();throw error;}
}


// The admitted Wallet owns the chooser; Home owns its ceremony and proof.
export async function openWalletSigninChooser({open,current,focus,listen=window,onAction,setStage=()=>{}}) {
  const context=await open('wallet'),requestId=crypto.randomUUID();
  let stopped=false,monitor,acknowledged=false,lastState;
  const valid=()=>!stopped&&current(context);
  const canCancel=()=>!['completing','unknown'].includes(lastState?.stage);
  const send=state=>{lastState=state;setStage(context.homeToken,state.stage);if(valid())context.source.postMessage({type:'home:wallet-signin-chooser',homeToken:context.homeToken,requestId,state},'*');};
  const receive=event=>{
    const data=event.data;
    if(!valid()||event.source!==context.source||event.origin!=='null'||data?.type!=='home:wallet-signin-chooser-action'||data.homeToken!==context.homeToken||data.requestId!==requestId||Object.keys(data).length!==4)return;
    if(data.action==='ready'){acknowledged=true;return;}
    if(data.action==='cancel'&&!canCancel())return;
    if(['metamask','unisat','walletconnect','cancel','retry','approve','check','refresh'].includes(data.action)||lastState?.stage==='options'&&lastState.methods?.some(m=>m.providerId&&data.action===`${m.connector}:${m.providerId}`))onAction(data.action);
  };
  listen.addEventListener('message',receive);
  monitor=setInterval(()=>{if(!stopped&&!current(context)&&canCancel()){onAction('cancel');}else if(!acknowledged&&lastState)send(lastState);},250);
  return {isOpen:valid,render:send,focus:()=>{if(valid())focus(context.homeToken);},close(){if(stopped)return;send({stage:'closed'});stopped=true;clearInterval(monitor);listen.removeEventListener('message',receive);}};
}
