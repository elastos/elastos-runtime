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

test('round19 an older off reply cannot cancel a newer granted phone request',async()=>{
  const address='0x'+'12'.repeat(20);let internetReads=0,releaseOld,releasePhone,phoneReady;
  const reachedPhone=new Promise(resolve=>{phoneReady=resolve;});
  const provider={chainId:1,connected:true,session:{expiry:Date.now()/1000+3600,namespaces:{eip155:{accounts:[`eip155:1:${address}`]}}},signer:{client:{core:{relayer:{connected:true}}}},on(){},async request({method}){
    if(method==='eth_accounts')return [address];if(method==='eth_chainId')return 1;
    return new Promise(resolve=>{releasePhone=resolve;phoneReady();});
  }};
  const api=async(path)=>{
    if(path==='internet')return ++internetReads===1?new Promise(resolve=>{releaseOld=resolve;}):{status:'granted'};
    if(path==='wallet/config')return {walletconnect:{project_id:'fixture-project',storage_revision:'"0"'}};
    if(path.endsWith('/challenge'))return {message:'New ownership',expires_at:Math.floor(Date.now()/1000)+300};
    return {};
  };
  const client=createWalletConnectClient({api,origin:'http://localhost',loadAdapter:async()=>({connectWalletConnectEvm:async()=>provider,disconnectWalletConnectEvm:async()=>{}})});
  const old=client.effect({kind:'status'});
  const link=client.effect({kind:'link'}).then(value=>({value}),error=>({error:error.message}));
  await reachedPhone;releaseOld({status:'revoked'});await old;releasePhone('0x'+'ab'.repeat(65));
  const result=await link;assert.equal(result.error,undefined);assert.equal(result.value.status,'linked');
});
