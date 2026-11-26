export function requestWalletAppConnection(entry, {token, origin, current, signal}) {
  if (window.top === window || !token || !origin) return Promise.reject(new Error('Open Wallet from Home to connect this wallet.'));
  const requestId = crypto.randomUUID();
  return new Promise((resolve, reject) => {
    const finish = (error, value) => {
      clearInterval(watch); clearTimeout(timeout); window.removeEventListener('message', receive); signal?.removeEventListener('abort', cancel);
      error ? reject(error) : resolve(value);
    };
    const cancel = () => {
      window.top.postMessage({type:'home:wallet-app-connect-cancel',requestId,homeToken:token}, origin);
      finish(new Error('Connection cancelled.'));
    };
    const watch = setInterval(() => {if (!current()) cancel();}, 100);
    const timeout = setTimeout(() => {cancel();}, 180000);
    const receive = event => {
      if (event.source !== window.top || event.origin !== origin || event.data?.type !== 'home:wallet-app-connect-result'
        || event.data.requestId !== requestId) return;
      if (!current()) {cancel(); return;}
      const result = event.data.result;
      finish(result?.status === 'complete' ? null : Object.assign(new Error(result?.message || 'Home could not connect this wallet.'), {code:result?.code}), result);
    };
    signal?.addEventListener('abort', cancel, {once:true});
    window.addEventListener('message', receive);
    window.top.postMessage({type:'home:wallet-app-connect',requestId,homeToken:token,inventoryId:entry.inventory_id}, origin);
  });
}
