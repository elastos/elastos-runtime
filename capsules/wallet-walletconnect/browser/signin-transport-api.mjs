// One attempt owns its storage revision. Relay admission shares the write queue.
export function createSigninTransportApi(homeOrigin,transport,fetchImpl=fetch) {
  let revision=transport.storage_revision,queue=Promise.resolve();
  return (resource,init={})=>{
    if(!['wallet/config','storage','relay-admission'].includes(resource))return Promise.reject(new Error('Invalid wallet transport resource'));
    const call=queue.then(async()=>{
      const response=await fetchImpl(`${homeOrigin}/api/apps/wallet-walletconnect/${resource}`,{
        ...init,signal:AbortSignal.timeout(15000),headers:{...init.headers,'content-type':'application/json',
          'x-elastos-wallet-attempt':transport.attempt_token,'x-elastos-wallet-instance':transport.instance_id,'if-match':`"${revision}"`},
      });
      if(!response.ok)throw Object.assign(new Error('Runtime transport refused'),{status:response.status});
      if(resource==='storage') {
        const match=/^"(0|[1-9][0-9]*)"$/.exec(response.headers.get('etag')||'');
        const next=match?Number(match[1]):NaN;
        if(!Number.isSafeInteger(next)||next<revision)throw new Error('Invalid wallet storage revision');
        revision=next;
      }
      return response.json();
    });
    queue=call.catch(()=>{});
    return call;
  };
}
