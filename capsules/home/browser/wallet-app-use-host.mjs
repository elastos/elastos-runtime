// Wallet requests app use; Home reuses a live connector's existing proof authority.
export function handleWalletAppUse(event, context, {inventory, connect, current, changed, focus}) {
  const data = event.data;
  if (!['home:wallet-app-connect', 'home:wallet-app-connect-cancel'].includes(data?.type)) return false;
  const exact = keys => Object.keys(data).length === keys.length && keys.every(key => Object.hasOwn(data, key));
  if (context?.kind !== 'app-frame' || context.targetId !== 'wallet' || context.source !== event.source
    || context.homeToken !== data.homeToken || !context.walletEffectState
    || typeof data.requestId !== 'string' || !/^[a-zA-Z0-9-]{1,64}$/.test(data.requestId)) return true;
  if (!current()) return true;
  const state = context.walletEffectState;
  if (data.type === 'home:wallet-app-connect-cancel') {
    if (exact(['type', 'requestId', 'homeToken']) && state.appConnection?.id === data.requestId) state.appConnection.cancelled = true;
    return true;
  }
  if (!exact(['type', 'requestId', 'homeToken', 'inventoryId'])
    || typeof data.inventoryId !== 'string' || data.inventoryId.length > 256) return true;
  const reply = result => {if (current()) event.source.postMessage({type:'home:wallet-app-connect-result',requestId:data.requestId,result}, '*');};
  if (state.appConnection) {reply({status:'failed',message:'Finish the open wallet connection first.'}); return true;}
  const pending = {id:data.requestId, cancelled:false}; state.appConnection = pending;
  const active = () => current() && !pending.cancelled && state.appConnection === pending;
  Promise.resolve().then(inventory).then(async saved => {
    if (!active()) return;
    const entry = saved.entries.find(entry => entry.inventory_id === data.inventoryId);
    if (!entry?.sign_in) throw new Error('This wallet changed. Open its entry again.');
    if (entry.accounts.length) return {status:'complete'};
    await connect(entry, active);
    if (!active()) return;
    changed(); focus(); return {status:'complete'};
  }).then(result => {if (result && active()) reply(result);})
    .catch(error => {if (active()) reply({status:'failed',message:error.message || 'Home could not connect this wallet.'});})
    .finally(() => {if (state.appConnection === pending) state.appConnection = null;});
  return true;
}

// A new Wallet document starts with a new request, even when its frame is reused.
export function retireWalletAppUse(context) {
  if (context?.walletEffectState?.appConnection) context.walletEffectState.appConnection.cancelled = true;
}
