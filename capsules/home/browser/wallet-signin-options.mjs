// Runtime owns connector IDs. Short names are local view keys only.
const choiceKey='elastos.signin.choice.v1';
const choices=['passkey','metamask','unisat','walletconnect'];
export const walletConnectorId=kind=>['metamask','unisat','walletconnect'].includes(kind)?`wallet-${kind}`:kind;
export const walletConnectorKind=id=>['wallet-metamask','wallet-unisat','wallet-walletconnect'].includes(id)?id.slice(7):id;
const validChoice=value=>typeof value==='string'&&value.length<=160&&(choices.includes(value)||/^metamask:[a-z0-9]+(?:\.[a-z0-9-]+)+$/.test(value));
const legacyChoice=value=>typeof value==='string'?value.replace(/^wallet-(metamask|unisat|walletconnect)(?=:|$)/,'$1'):'';
export const signinChoiceId=method=>method.providerId?`${method.connector}:${method.providerId}`:method.connector;
export const optionId=method=>[method.connector==='unisat'?'bitcoin':'evm',method.connector==='unisat'?method.address:method.address.toLowerCase(),method.chain_id,method.network].join(':');
export function readSigninChoice(storage) {
  try {
    storage ||= globalThis.localStorage;
    // One key serves this browser and the previous browser during Undo.
    const value=storage.getItem(choiceKey);
    return validChoice(value)?value:'';
  }catch{return '';}
}
export function saveSigninChoice(value,storage) {
  try {
    storage ||= globalThis.localStorage;value=legacyChoice(value);
    if(validChoice(value))storage.setItem(choiceKey,value);
    else storage.removeItem(choiceKey);
  }catch{}
}
// Host capabilities are explicit inputs for browser and desktop surfaces.
export function availableSigninOptions(connectors,{providers=[],unisatAvailable=false,walletconnectAvailable=false}={}) {
  if(!Array.isArray(connectors))return [];
  connectors=connectors.map(walletConnectorKind);
  const enabled=['metamask','unisat','walletconnect'].filter(connector=>connectors.includes(connector)&&(
    connector==='walletconnect'?walletconnectAvailable:connector==='unisat'?unisatAvailable:providers.length>0
  ));
  return enabled.flatMap(connector=>connector==='metamask'?providers.filter(p=>typeof p.rdns==='string'&&validChoice(`metamask:${p.rdns}`)).map(p=>({connector,chooseConnector:true,providerId:p.rdns,displayName:typeof p.name==='string'?p.name.slice(0,80):'Browser wallet'})):[{connector,chooseConnector:true}]);
}
