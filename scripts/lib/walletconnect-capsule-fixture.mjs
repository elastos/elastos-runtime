import assert from 'node:assert/strict';
import { createWalletConnectClient } from '../../capsules/wallet-walletconnect/browser/walletconnect-client.mjs';
export const address = `0x${'12'.repeat(20)}`, payloadHash=`0x${'34'.repeat(32)}`, transactionHash=`0x${'56'.repeat(32)}`;
export async function exerciseWalletConnect(scenario='valid') {
  const clock=Date.now, calls=[],routes=[],events=new Map(); let changed=false, memoryCleared=false;
  const signatureIntent=scenario.startsWith('signature-');
  const kind=scenario.replace(/^signature-/,'');
  const lifetime=scenario==='signature-short'?180:scenario==='long-request'?1800:600;
  const signature=`0x${'ab'.repeat(65)}`;
  const message=scenario==='link-uppercase-hex'?'0X4142':scenario==='link-odd-hex'?'0x123':'Runtime ownership proof · fixture';
  const change=()=>{changed=true;if(kind==='account-change-during-send')events.get('accountsChanged')?.([]);
    if(kind==='chain-change-during-send')events.get('chainChanged')?.('0x1');if(kind==='expired-during-send')Date.now=()=>clock()+601000;};
  const provider={connected:true,session:{expiry:clock()/1000+3600},signer:{client:{core:{relayer:{connected:true}}}},
    on:(name,fn)=>events.set(name,fn),async request(input,expiry){calls.push({...input,expiry});
      if(input.method==='eth_accounts')return [scenario==='wrong-account'||changed&&kind==='account-change-during-send'?`0x${'ab'.repeat(20)}`:address];
      if(input.method==='eth_chainId')return scenario==='wrong-chain'||changed&&kind==='chain-change-during-send'?'0x1':'0x14';
      if(input.method==='personal_sign'){if(signatureIntent)change();return signature;}
      if(input.method==='eth_sendTransaction'){change();return scenario==='invalid-hash'?'Open a fake recovery website':transactionHash;}
      throw new Error('Unexpected wallet call');
    }};
  const api=async(path,input)=>{routes.push({path,input});
    if(path==='wallet/config')return {walletconnect:{project_id:'fixture-project'}};
    if(path==='internet')return {status:'granted'};
    if(path==='storage')return {};
    if(path.endsWith('/challenge'))return {schema:'elastos.auth.challenge/v1',message,expires_at:Math.floor(clock()/1000)+600};
    if(path.endsWith('/verify')){const body=JSON.parse(input.body);assert.equal(body.message,message);assert.equal(body.signature,signature);return {status:'linked'};}
    if(path==='wallet/approvals')return {approval_requests:[{request_id:'approval:fixture',status:scenario==='approved'?'approved':'pending',address,
      intent:signatureIntent?'browser_personal_sign':'transaction_intent',chain_namespace:'eip155:20',expires_at:Math.floor(clock()/1000)+lifetime}]};
    if(path.endsWith('/approve'))return {handoff:{request_id:'approval:fixture',intent:signatureIntent?'browser_personal_sign':'transaction_intent',
      payload_hash:payloadHash,signer:address,signature_type:'personal_sign',message:'Runtime approval fixture',
      transaction:{from:address,to:`0x${'78'.repeat(20)}`,value:'0x1',data:'0x',gas:'0x5208',gasPrice:'0x1',nonce:'0x1',chainId:'0x14'}},
      binding:{principal_id:'fixture',requested_by_actor:'documents',account_id:'fixture-account',chain_namespace:'eip155:20',payload_hash:payloadHash,
      expires_at:scenario==='expired'?1:Math.floor(clock()/1000)+lifetime}};
    if(path.endsWith('/complete')){const body=JSON.parse(input.body);assert.equal(body.payload_hash,payloadHash);assert.equal(body.signer,address);
      if(scenario==='completion-refused')throw new Error('Completion refused');return {};}
    throw new Error('Unexpected Runtime resource');
  };
  const client=createWalletConnectClient({api,origin:'http://localhost:61180',clearMemory:()=>{memoryCleared=true;},
    loadAdapter:async()=>({connectWalletConnectEvm:async options=>{assert.equal(options.contextKey,'wallet-walletconnect');return provider;},disconnectWalletConnectEvm:async()=>{}})});
  try {return {result:await client.effect({kind:scenario.startsWith('link')?'link':scenario==='disconnect'?'disconnect':'approve',approvalRequestId:'approval:fixture'}),calls,routes,memoryCleared};}
  catch(error){return {error:error.message,calls,routes,memoryCleared};}
  finally{Date.now=clock;}
}
