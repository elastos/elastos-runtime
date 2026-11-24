// Runtime owns the available connectors. This browser remembers only a choice.
const choiceKey='elastos.signin.choice.v1';
const choices=['passkey','metamask','unisat','walletconnect'];
const validChoice=value=>typeof value==='string'&&value.length<=160&&(choices.includes(value)||/^metamask:[a-z0-9]+(?:\.[a-z0-9-]+)+$/.test(value));
export const signinChoiceId=method=>method.providerId?`${method.connector}:${method.providerId}`:method.connector;
export const optionId=method=>[method.connector==='unisat'?'bitcoin':'evm',method.connector==='unisat'?method.address:method.address.toLowerCase(),method.chain_id,method.network].join(':');
export function readSigninChoice(storage) {
  try {storage ||= globalThis.localStorage;const value=storage.getItem(choiceKey);return validChoice(value)?value:'';}catch{return '';}
}
export function saveSigninChoice(value,storage) {
  try {storage ||= globalThis.localStorage;if(validChoice(value))storage.setItem(choiceKey,value);else storage.removeItem(choiceKey);}catch{}
}
// Host capabilities are explicit inputs for browser and desktop surfaces.
export function availableSigninOptions(connectors,{providers=[],unisatAvailable=false,walletconnectAvailable=false}={}) {
  if(!Array.isArray(connectors))return [];
  const enabled=['metamask','unisat','walletconnect'].filter(connector=>connectors.includes(connector)&&(
    connector==='walletconnect'?walletconnectAvailable:connector==='unisat'?unisatAvailable:providers.length>0
  ));
  return enabled.flatMap(connector=>connector==='metamask'?providers.filter(p=>typeof p.rdns==='string'&&validChoice(`metamask:${p.rdns}`)).map(p=>({connector,chooseConnector:true,providerId:p.rdns,displayName:typeof p.name==='string'?p.name.slice(0,80):'Browser wallet'})):[{connector,chooseConnector:true}]);
}
