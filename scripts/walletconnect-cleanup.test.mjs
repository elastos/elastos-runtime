import test from 'node:test';
import assert from 'node:assert/strict';
import {createWalletConnectClient} from '../capsules/wallet-walletconnect/browser/walletconnect-client.mjs';

test('round19 a failed storage DELETE prevents a second SDK from sharing the store',async()=>{
  const address='0x'+'12'.repeat(20);
  let failDelete=true,revision=0,loaded=0;
  const provider={chainId:1,connected:true,session:{expiry:Date.now()/1000+3600,namespaces:{eip155:{accounts:[`eip155:1:${address}`],methods:['personal_sign']}}},
    signer:{client:{core:{relayer:{connected:true}}}},on(){},
    async request({method}){if(method==='eth_accounts')return [address];if(method==='eth_chainId')return 1;return '0x'+'ab'.repeat(65);}};
  const api=async(path,input)=>{
    if(path==='wallet/config')return {walletconnect:{project_id:'fixture-project',storage_revision:JSON.stringify(String(revision))}};
    if(path==='internet')return {status:'granted'};
    if(path==='storage'){if(input?.method==='DELETE'){if(failDelete)throw new Error('Storage is busy');revision++;}return {};}
    if(path.endsWith('/challenge'))return {message:'Test ownership',expires_at:Math.floor(Date.now()/1000)+300};
    if(path.endsWith('/verify'))return {};
    throw new Error('Unexpected fixture resource');
  };
  const client=createWalletConnectClient({api,origin:'http://localhost',loadAdapter:async()=>{
    loaded++;return {connectWalletConnectEvm:async()=>provider,disconnectWalletConnectEvm:async()=>{}};
  }});
  await client.effect({kind:'link'});
  await assert.rejects(client.effect({kind:'disconnect'}));
  await assert.rejects(client.effect({kind:'link'}));
  assert.equal(loaded,1,'cleanup failure keeps the old store fenced before another SDK can start');
  failDelete=false;
  await client.effect({kind:'link'});
  assert.equal(loaded,2,'a confirmed storage revision change permits the replacement SDK');
});
