// Test-only second protocol party. Never imported by a shipped app.
import {randomUUID} from 'node:crypto';
import {EventEmitter} from 'node:events';
import {walletConnectFixtureRequire as require} from './walletconnect-relay-fixture.mjs';
const {SignClient} = require('@walletconnect/sign-client');
const {generatePrivateKey,privateKeyToAccount} = require('viem/accounts');
const {keccak256} = require('viem');
export async function scriptedPhoneWallet({projectId,relayUrl,chains=['eip155:8453'],storage=new Map(),name='Scripted phone wallet'}={}) {
  const account=privateKeyToAccount(generatePrivateKey());
  const events=new EventEmitter(), trace=[], pending=[];
  let connection='approve', response='sign', approvedChains=chains;
  const store={async getItem(key){return storage.get(key);},async setItem(key,value){storage.set(key,value);},async removeItem(key){storage.delete(key);},async getKeys(){return [...storage.keys()];},async getEntries(){return [...storage.entries()];}};
  const client=await SignClient.init({projectId,relayUrl,logger:'silent',telemetryEnabled:false,customStoragePrefix:`phone-${randomUUID()}`,storage:store,metadata:{name,description:'Disposable protocol test wallet',url:'https://example.test',icons:[]}});
  const run=fn=>(event)=>Promise.resolve(fn(event)).catch(error=>{trace.push({kind:'error',name:error.name,code:typeof error.code==='number'?error.code:undefined});events.emit('failure',error);});
  client.on('session_proposal',run(async event=>{
    trace.push({kind:'proposal',offered:event.params.optionalNamespaces.eip155?.chains,decision:connection});events.emit('proposal');
    if(connection==='silent')return;
    if(connection==='reject'){await client.reject({id:event.id,reason:{code:5000,message:'User rejected.'}});return;}
    const {acknowledged}=await client.approve({id:event.id,namespaces:{eip155:{chains:approvedChains,accounts:approvedChains.map(chain=>`${chain}:${account.address}`),methods:['personal_sign','eth_sendTransaction'],events:['accountsChanged','chainChanged']}}});
    await acknowledged();trace.push({kind:'session',chains:approvedChains});events.emit('session');
  }));
  async function answer(event,choice) {
    const {request}=event.params;
    if(choice==='silent')return;
    let result;
    if(choice!=='reject') {
      if(request.method==='personal_sign')result=await account.signMessage({message:{raw:request.params[0]}});
      else if(request.method==='eth_sendTransaction') {
        const input=request.params[0];
        const tx={to:input.to,value:BigInt(input.value||0),data:input.data||'0x',chainId:Number(input.chainId||event.params.chainId.split(':')[1]),gas:BigInt(input.gas||21000),gasPrice:BigInt(input.gasPrice||1),nonce:Number(input.nonce||0),type:'legacy'};
        // Sign a throwaway transaction. No network broadcast: return its exact hash.
        result=keccak256(await account.signTransaction(tx));
      } else throw new Error('Unsupported test wallet request');
    }
    await client.respond({topic:event.topic,response:{jsonrpc:'2.0',id:event.id,...(choice==='reject'?{error:{code:4001,message:'User rejected.'}}:{result})}});
    const index=pending.findIndex(item=>item.id===event.id);if(index>=0)pending.splice(index,1);trace.push({kind:'response',method:request.method,decision:choice});events.emit('response');
  }
  client.on('session_request',run(async event=>{pending.push(event);trace.push({kind:'request',method:event.params.request.method,chain:event.params.chainId,decision:response});events.emit('request');await answer(event,response);}));
  client.on('session_delete',event=>{for(let i=pending.length-1;i>=0;i--)if(pending[i].topic===event.topic)pending.splice(i,1);trace.push({kind:'deleted'});events.emit('deleted');});
  client.on('session_request_expire',event=>{const i=pending.findIndex(item=>item.id===event.id);if(i>=0)pending.splice(i,1);trace.push({kind:'request-expired'});});
  return {client,events,trace,address:account.address,
    choose({proposal,request,chains}={}){if(proposal)connection=proposal;if(request)response=request;if(chains)approvedChains=chains;},
    async pair(uri){if(typeof uri!=='string'||!uri.startsWith('wc:'))throw new Error('Expected copied connection link');await client.pair({uri});},
    async answer(choice){const event=pending.at(-1);if(!event)throw new Error('No waiting request');await answer(event,choice);},
    async deleteConnection(){for(const session of client.session.getAll())await client.disconnect({topic:session.topic,reason:{code:6000,message:'Wallet removed connection'}});pending.length=0;},
    async stop(){client.core.heartbeat.stop();await client.core.relayer.transportClose();client.removeAllListeners();},
  };
}
