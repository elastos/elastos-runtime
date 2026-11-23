// Runtime owns the available connectors. This browser remembers only a choice.
const choiceKey='elastos.signin.choice.v1';
const choices=['passkey','metamask','unisat','walletconnect'];
export const optionId=method=>[method.connector==='unisat'?'bitcoin':'evm',method.connector==='unisat'?method.address:method.address.toLowerCase(),method.chain_id,method.network].join(':');
export function readSigninChoice(storage) {
  try {storage ||= globalThis.localStorage;storage.removeItem('elastos.signin.options.v1');const value=storage.getItem(choiceKey);return choices.includes(value)?value:'';}catch{return '';}
}
export function saveSigninChoice(value,storage) {
  try {storage ||= globalThis.localStorage;storage.removeItem('elastos.signin.options.v1');if(choices.includes(value))storage.setItem(choiceKey,value);else storage.removeItem(choiceKey);}catch{}
}
// Host capabilities are explicit inputs for browser and desktop surfaces.
export function availableSigninOptions(connectors,{providers=[],unisatAvailable=false,walletconnectAvailable=false}={}) {
  if(!Array.isArray(connectors))return [];
  return ['metamask','unisat','walletconnect'].filter(connector=>connectors.includes(connector)&&(
    connector==='walletconnect'?walletconnectAvailable:connector==='unisat'?unisatAvailable:providers.length>0
  )).map(connector=>({connector,chooseConnector:true}));
}
