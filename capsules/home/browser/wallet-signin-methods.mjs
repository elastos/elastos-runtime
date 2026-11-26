// Home ends management before the requesting capsule stops waiting.
export const walletSigninRequestTimeoutMs=420000;
export function requestWalletSigninChange({action,methodId='',token,origin}) {
  if(window.top===window || !token || !origin)return Promise.reject(new Error('Open this app from Home to change wallet sign-in.'));
  const requestId=crypto.randomUUID();
  return new Promise((resolve,reject)=>{
    const timeout=setTimeout(()=>{window.removeEventListener('message',receive);resolve({status:'unknown'});},walletSigninRequestTimeoutMs);
    const receive=event=>{
      if(event.source!==window.top||event.origin!==origin||event.data?.requestId!==requestId)return;
      if(event.data?.type!=='home:wallet-signin-result')return;
      clearTimeout(timeout);window.removeEventListener('message',receive);resolve(event.data.result);
    };
    window.addEventListener('message',receive);
    window.top.postMessage({type:'home:wallet-signin-request',requestId,homeToken:token,action,methodId},origin);
  });
}
function text(tag,value,className) {const el=document.createElement(tag);el.textContent=value;if(className)el.className=className;return el;}
export function walletSigninControls(method,{onAction,buttonClass=''}) {
  const controls=text('div','','signin-method-controls');
  const remove=text('button','Remove from sign-in',buttonClass);remove.type='button';remove.onclick=()=>onAction('remove',method.method_id);controls.append(remove);
  return controls;
}

export function watchWalletSigninMethods(refresh,origin) {
  window.addEventListener('focus',()=>void refresh());
  document.addEventListener('visibilitychange',()=>{if(document.visibilityState==='visible')void refresh();});
  window.addEventListener('message',event=>{
    if(event.source===window.top && event.origin===origin && event.data?.type==='home:wallet-signin-changed' && Object.keys(event.data).length===1)void refresh();
  });
}

// Runtime owns the identity join. Clients select a view of that projection.
export async function readWalletInventory(token) {
  const controller = new AbortController(), timer = setTimeout(() => controller.abort(), 15000);
  try {
    const response = await fetch('/api/apps/wallet/wallet/inventory', {
      cache:'no-store', signal:controller.signal, headers:{'x-elastos-home-token':token},
    });
    if (!response.ok) throw new Error('Home could not load your wallets.');
    const inventory = await response.json();
    if (inventory.schema !== 'elastos.wallet.inventory/v1' || typeof inventory.account_id !== 'string'
      || !Array.isArray(inventory.entries) || inventory.entries.length > 512) throw new Error('Home could not load your wallets.');
    return inventory;
  } finally {clearTimeout(timer);}
}

export function inventorySigninMethods(inventory) {
  return inventory.entries.flatMap(entry => {
    const account = entry.accounts.find(account => account.connector_id
      && !['managed_evm', 'managed_btc_p2wpkh'].includes(account.proof_type));
    if (!entry.sign_in && !account) return [];
    const connector = entry.sign_in?.connector || account.connector_id.replace('wallet-', '');
    const method = entry.sign_in || {
      method_id: `payment:${account.account_id}`, connector,
      address: entry.address,
      chain_id: connector === 'unisat' ? 0 : Number(entry.chain_namespace.split(':')[1]),
      network: connector === 'unisat' ? 'bitcoin' : '', sign_in_enabled: false,
      paymentOnly: true, last_used_at: null,
    };
    return [{...method, inventory_id: entry.inventory_id,
      paymentConnected: Boolean(account),
      ...(account?.wallet_display_name ? {displayName: account.wallet_display_name} : {}),
      ...(account?.provider_id ? {providerId: account.provider_id} : {}),
    }];
  });
}
