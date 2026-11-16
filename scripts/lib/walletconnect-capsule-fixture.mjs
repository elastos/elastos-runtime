import assert from 'node:assert/strict';
import { createWalletConnectClient, walletConnectMessages as messages } from '../../capsules/wallet-walletconnect/browser/walletconnect-client.mjs';
export const address = `0x${'12'.repeat(20)}`, payloadHash=`0x${'34'.repeat(32)}`, transactionHash=`0x${'56'.repeat(32)}`;
export async function exerciseWalletConnect(scenario='valid') {
  const clock=Date.now, calls=[],routes=[],events=new Map(); let changed=false, memoryCleared=false, status=scenario==='approved'?'approved':'pending';
  const signatureIntent=scenario.startsWith('signature-') || scenario.startsWith('typed') || scenario==='unsupported' || scenario==='protected-content';
  const intent=scenario.startsWith('typed')?'browser_typed_data_sign':scenario==='unsupported'?'unavailable_intent':scenario==='protected-content'?'protected_content_rights_signature':signatureIntent?'browser_personal_sign':'transaction_intent';
  const kind=scenario.replace(/^signature-/,'');
  const lifetime=scenario==='signature-short'?180:scenario==='long-request'?1800:600;
  const signature=`0x${'ab'.repeat(65)}`;
  const message=scenario==='link-uppercase-hex'?'0X4142':scenario==='link-odd-hex'?'0x123':'Runtime ownership proof · fixture';
  const change=()=>{changed=true;if(kind==='account-change-during-send')events.get('accountsChanged')?.([]);
    if(kind==='chain-change-during-send'){provider.chainId=1;events.get('chainChanged')?.('0x1');}
    if(kind==='unsupported-chain-after-sign'){provider.chainId=137;events.get('chainChanged')?.('0x89');}if(kind==='expired-during-send')Date.now=()=>clock()+601000;};
  const expiredMessage = 'Request expired. Please try again.';
  const phoneError = () => {
    if (scenario.includes('phone-declined:')) throw {code:Number(scenario.split(':')[1]),message:'User rejected.'};
    if (scenario.includes('phone-error:')) throw {code:Number(scenario.split(':')[1]),message:scenario.endsWith(':expired-text')?expiredMessage:scenario.endsWith(':cancelled-text')?messages.cancelled:'Private wallet error fixture'};
    if (scenario.includes('phone-expired')) throw new Error(expiredMessage);
  };
  const provider={chainId:20,connected:true,session:{expiry:clock()/1000+3600,namespaces:{eip155:{chains:['eip155:1','eip155:20'],accounts:[`eip155:20:${address}`],methods:scenario==='typed-unavailable'?['personal_sign']:['personal_sign','eth_sendTransaction','eth_signTypedData_v4']}}},signer:{client:{core:{relayer:{connected:true}}}},
    on:(name,fn)=>events.set(name,fn),async request(input,expiry){calls.push({...input,expiry});
      if(input.method==='eth_accounts')return [scenario==='wrong-account'||changed&&kind==='account-change-during-send'?`0x${'ab'.repeat(20)}`:address];
      if(input.method==='eth_chainId'&&scenario.startsWith('numeric-chain'))return 20;
      if(input.method==='eth_chainId'&&scenario.startsWith('invalid-chain:'))return JSON.parse(scenario.slice('invalid-chain:'.length));
      if(input.method==='eth_chainId')return scenario==='wrong-chain'||changed&&kind==='chain-change-during-send'?'0x1':'0x14';
      if (['personal_sign','eth_sendTransaction'].includes(input.method)) phoneError();
      if(['personal_sign','eth_signTypedData_v4'].includes(input.method)){if(signatureIntent)change();return signature;}
      if(input.method==='eth_sendTransaction'){if(scenario==='sdk-unknown')throw new Error('Opaque SDK failure fixture');change();return scenario==='invalid-hash'?'Open a fake recovery website':transactionHash;}
      throw new Error('Unexpected wallet call');
    }};
  const api=async(path,input)=>{routes.push({path,input});
    if(path==='wallet/config')return {walletconnect:{project_id:'fixture-project',storage_revision:'"0"'}};
    if(path==='internet')return {status:'granted'};
    if(path==='storage')return {};
    if(path.endsWith('/challenge'))return {schema:'elastos.auth.challenge/v1',message,expires_at:Math.floor(clock()/1000)+600};
    if(path.endsWith('/verify')){const body=JSON.parse(input.body);assert.equal(body.message,message);assert.equal(body.signature,signature);return {status:'linked'};}
    if(path==='wallet/approvals')return {approval_requests:[{request_id:'approval:fixture',status,address,
      intent,chain_namespace:scenario==='unapproved-network'?'eip155:8453':scenario==='listed-without-account'?'eip155:1':scenario==='unknown-network'?'eip155:137':'eip155:20',expires_at:Math.floor(clock()/1000)+lifetime}].filter(r=>r.status==='pending'||r.status==='approved'&&r.intent==='transaction_intent')};
    if(path.endsWith('/approve')){assert.equal(status,'pending');status='approved';return {handoff:{request_id:'approval:fixture',intent,
      payload_hash:payloadHash,signer:address,signature_type:scenario.startsWith('typed')?'eip712':'personal_sign',message:scenario==='protected-content'?'0x414243':'Runtime approval fixture',
      transaction:{from:address,to:`0x${'78'.repeat(20)}`,value:'0x1',data:'0x',gas:'0x5208',gasPrice:'0x1',nonce:'0x1',chainId:'0x14'}},
      binding:{principal_id:'fixture',requested_by_actor:'documents',account_id:'fixture-account',chain_namespace:'eip155:20',payload_hash:payloadHash,
      expires_at:scenario==='expired'?1:Math.floor(clock()/1000)+lifetime}};}
    if(path.endsWith('/complete')){const body=JSON.parse(input.body);assert.equal(body.payload_hash,payloadHash);assert.equal(body.signer,address);
      if(scenario==='completion-refused')throw new Error('Completion refused');return {receipt_status:scenario==='dismissed-during-send'?'sent_after_dismissal':'completed'};}
    throw new Error('Unexpected Runtime resource');
  };
  const client=createWalletConnectClient({api,origin:'http://localhost:61180',clearMemory:()=>{memoryCleared=true;},
    loadAdapter:async()=>({connectWalletConnectEvm:async options=>{assert.equal(options.contextKey,'wallet-walletconnect');if (scenario.startsWith('proposal-')) phoneError();return provider;},disconnectWalletConnectEvm:async()=>{}})});
  try {return {result:await client.effect({kind:(scenario.startsWith('link')||scenario==='numeric-chain-link')?'link':scenario==='disconnect'?'disconnect':'approve',approvalRequestId:'approval:fixture'}),calls,routes,memoryCleared};}
  catch(error){
    let secondError;
    if (/^(signature|transaction)-phone-/.test(scenario)) {
      try { await client.effect({kind:'approve',approvalRequestId:'approval:fixture'}); }
      catch(repeated) { secondError=repeated.message; }
    }
    return {error:error.message,tone:error.tone,secondError,status,calls,routes,memoryCleared};
  }
  finally{Date.now=clock;}
}
