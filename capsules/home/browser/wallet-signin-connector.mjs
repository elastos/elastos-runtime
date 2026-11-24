// Home talks only to its admitted WalletConnect window. Proof stays in memory.
export async function selectConnectedWalletConnect({signal,method,opened},{open,current,listen=window}) {
  const context=await open();signal.throwIfAborted();opened?.(context.focus);
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
    return {...wallet,focus:context.focus,check:()=>send('check',{address:wallet.address,chain_id:wallet.chain_id}),
      async sign(message){
        const proof=await send('sign',{address:wallet.address,chain_id:wallet.chain_id,message});
        if(typeof proof?.signature!=='string'||!proof.signature||proof.signature.length>16384||proof.signature_type!=='personal_sign'||proof.public_key!=='')throw new Error('Invalid wallet proof');
        return {signature:proof.signature,signature_type:'personal_sign',public_key:''};
      },close};
  }catch(error){close();throw error;}
}


// Extension providers live in Home; their admitted connector owns request review.
export async function selectConnectedExtension(connector, options, {open,current,select,listen=window}) {
  const context=await open(connector);options.signal.throwIfAborted();options.opened?.(context.focus);
  const signer=await select(connector,options);
  let closed=false,monitor;const pending=new Map(),prefix=crypto.randomUUID();let sequence=0;
  const valid=()=>!closed&&!options.signal.aborted&&current(context);
  const send=(operation,body={})=>new Promise((resolve,reject)=>{
    if(!valid())return reject(Object.assign(new Error('Wallet window changed'),{code:'disconnected'}));
    const requestId=`${prefix}:${++sequence}`;pending.set(requestId,{resolve,reject});
    context.source.postMessage({type:'home:wallet-signin-effect',homeToken:context.homeToken,requestId,operation,...body},'*');
  });
  const receive=event=>{
    const data=event.data;
    if(!valid()||event.source!==context.source||event.origin!=='null'||data?.type!=='home:wallet-signin-effect-result'||data.homeToken!==context.homeToken)return;
    const job=pending.get(data.requestId);if(!job)return;pending.delete(data.requestId);
    data.error?job.reject(Object.assign(new Error('Wallet request stopped'),{code:'disconnected'})):job.resolve(data.result);
  };
  const close=()=>{
    if(closed)return;closed=true;clearInterval(monitor);signer.close();listen.removeEventListener('message',receive);options.signal.removeEventListener('abort',close);
    if(current(context))context.source.postMessage({type:'home:wallet-signin-effect',homeToken:context.homeToken,requestId:`${prefix}:stop`,operation:'stop'},'*');
    for(const job of pending.values())job.reject(Object.assign(new Error('Wallet request ended'),{code:'disconnected'}));pending.clear();
  };
  listen.addEventListener('message',receive);options.signal.addEventListener('abort',close,{once:true});
  monitor=setInterval(()=>{if(!current(context)||context.source.closed){close();options.changed('disconnected');}},250);
  if(options.signal.aborted){close();options.signal.throwIfAborted();}
  return {...signer,focus:context.focus,close,async sign(message){
    const result=await send('review',{address:signer.address,chain_id:signer.chain_id,network:signer.network,name:signer.name||'',message});
    if(result?.approved!==true)throw new Error('Wallet did not approve the request');
    await signer.check();
    try {const proof=await signer.sign(message);await send('finish');return proof;}
    catch(error){await send('stop').catch(()=>{});throw error;}
  }};
}

// The admitted Wallet owns the chooser; Home owns its ceremony and proof.
export async function openWalletSigninChooser({open,current,focus,listen=window,onAction}) {
  const context=await open('wallet'),requestId=crypto.randomUUID();
  let stopped=false,monitor,acknowledged=false,lastState;
  const valid=()=>!stopped&&current(context);
  const send=state=>{lastState=state;if(valid())context.source.postMessage({type:'home:wallet-signin-chooser',homeToken:context.homeToken,requestId,state},'*');};
  const receive=event=>{
    const data=event.data;
    if(!valid()||event.source!==context.source||event.origin!=='null'||data?.type!=='home:wallet-signin-chooser-action'||data.homeToken!==context.homeToken||data.requestId!==requestId||Object.keys(data).length!==4)return;
    if(data.action==='ready'){acknowledged=true;return;}
    if(['metamask','unisat','walletconnect','cancel','retry','approve','check','refresh'].includes(data.action))onAction(data.action);
  };
  listen.addEventListener('message',receive);
  monitor=setInterval(()=>{if(!stopped&&!current(context)){onAction('cancel');}else if(!acknowledged&&lastState)send(lastState);},250);
  return {isOpen:valid,render:send,focus:()=>{if(valid())focus(context.homeToken);},close(){if(stopped)return;send({stage:'closed'});stopped=true;clearInterval(monitor);listen.removeEventListener('message',receive);}};
}
