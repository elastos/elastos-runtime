// Browser-local display hints. Runtime verifies every sign-in independently.
// Only these public identity fields and the selected option reach browser storage.
const methodsKey='elastos.signin.options.v1',choiceKey='elastos.signin.choice.v1';
export const optionId=method=>[method.connector==='unisat'?'bitcoin':'evm',method.connector==='unisat'?method.address:method.address.toLowerCase(),method.chain_id,method.network].join(':');
export function signinOptions(methods) {
  if(!Array.isArray(methods)||methods.length>256)return [];
  return methods.filter(m=>m?.sign_in_enabled===true&&['metamask','unisat','walletconnect'].includes(m.connector)
    &&typeof m.address==='string'&&m.address.length<=128
    &&(m.connector==='unisat'?/^(bc1|[13])[A-Za-z0-9]{20,100}$/.test(m.address)&&m.chain_id===0&&m.network==='bitcoin':/^0x[0-9a-fA-F]{40}$/.test(m.address)&&Number.isSafeInteger(m.chain_id)&&m.chain_id>0&&m.network===''))
    .map(({connector,address,chain_id,network,providerId,displayName})=>({connector,address,chain_id,network,sign_in_enabled:true,
      ...(typeof providerId==='string'&&providerId.length<=128&&/^[a-z0-9]+(?:\.[a-z0-9-]+)+$/.test(providerId)?{providerId}:{}),
      ...(typeof displayName==='string'&&displayName.length<=80&&!/[\p{Cc}\p{Cf}]/u.test(displayName)?{displayName}:{})}));
}
export function saveSigninOptions(methods,storage,{preferProvided=false}={}) {
  try {
    storage ||= globalThis.localStorage;
    const previous=readSigninOptions(storage);
    const options=signinOptions(methods).map(method=>{
      const prior=previous.find(row=>optionId(row)===optionId(method));
      return prior&&!preferProvided?{...method,...prior}: {...(prior?.connector===method.connector?prior:{}),...method};
    });
    storage.setItem(methodsKey,JSON.stringify(options));
  }catch{}
}
export function readSigninOptions(storage) {
  try{storage ||= globalThis.localStorage;const raw=storage.getItem(methodsKey);return raw?.length<=65536?signinOptions(JSON.parse(raw)):[];}catch{return [];}
}
export function readSigninChoice(storage) {
  try{storage ||= globalThis.localStorage;const value=storage.getItem(choiceKey);return typeof value==='string'&&value.length<=512?value:'';}catch{return '';}
}
export function saveSigninChoice(value,storage) {
  try{storage ||= globalThis.localStorage;if(value)storage.setItem(choiceKey,value);else storage.removeItem(choiceKey);}catch{}
}

// Host capabilities are inputs so desktop and browser cases share one rule.
export function availableSigninOptions(methods,{providers=[],unisatAvailable=false,walletconnectAvailable=false}={}) {
  const options=methods.filter(method=>method.connector==='walletconnect'?walletconnectAvailable:
    method.connector==='unisat'?unisatAvailable:
    providers.some(provider=>!method.providerId||provider.rdns===method.providerId));
  if(walletconnectAvailable&&!options.some(method=>method.connector==='walletconnect'))options.push({connector:'walletconnect',chooseConnector:true});
  return options;
}
