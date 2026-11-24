import test from 'node:test';
import assert from 'node:assert/strict';
const events=new EventTarget();
globalThis.window=events;
globalThis.location=new URL('http://127.0.0.1/home/');
globalThis.document={querySelector:()=>null,querySelectorAll:()=>[]};
const {selectSigninWallet,currentConnectedSigninMethods}=await import('../capsules/home/browser/wallet-signin-signers.mjs');
const address='0x'+'12'.repeat(20),bitcoin='bc1q'+'a'.repeat(38),legacy='1'+'a'.repeat(33);
function provider() {
  const calls=[],listeners=new Map();
  const state={address,chain:'0x14',network:'livenet',btc:bitcoin};
  const api={
    on(name,listener){if(!listeners.has(name))listeners.set(name,new Set());listeners.get(name).add(listener);},
    removeListener(name,listener){listeners.get(name)?.delete(listener);},
    async request(input){calls.push(input);if(input.method==='eth_chainId')return state.chain;if(input.method==='personal_sign')return 'proof';return [state.address];},
    async requestAccounts(){return [state.btc];},async getAccounts(){return [state.btc];},async getNetwork(){return state.network;},
    async getPublicKey(){calls.push({method:'getPublicKey'});return 'public-key';},async signMessage(message,mode){calls.push({method:'signMessage',message,mode});return 'bitcoin-proof';},
  };
  return {api,calls,listeners,state};
}
function options() {return {signal:new AbortController().signal,choices(){throw new Error('unexpected choice');},changed(){}};}
test('compatible EIP-1193 provider signs the UTF-8 message bytes with personal_sign',async()=>{
  const p=provider();window.ethereum=p.api;
  const wallet=await selectSigninWallet('metamask',options());await wallet.check();
  const proof=await wallet.sign('Home ✓');
  assert.deepEqual(p.calls.find(call=>call.method==='personal_sign'),{method:'personal_sign',params:['0x486f6d6520e29c93',address]});
  assert.equal(proof.signature_type,'personal_sign');wallet.close();
  assert([...p.listeners.values()].every(set=>set.size===0));delete window.ethereum;
});
test('UniSat uses the contract proof modes for SegWit and legacy addresses',async()=>{
  for(const [btc,type,mode]of [[bitcoin,'bip322_simple','bip322-simple'],[legacy,'bitcoin_signed_message','ecdsa']]) {
    const p=provider();p.state.btc=btc;window.unisat=p.api;
    const wallet=await selectSigninWallet('unisat',options());assert.equal(wallet.network,'bitcoin');await wallet.check();const proof=await wallet.sign('exact Home message');
    assert.equal(proof.signature_type,type);assert.equal(proof.public_key,btc===legacy?'public-key':'');
    assert.deepEqual(p.calls.find(call=>call.method==='signMessage'),{method:'signMessage',message:'exact Home message',mode});wallet.close();
  }
  delete window.unisat;
});
test('extension account and network changes fail the pre-sign check',async()=>{
  for(const change of ['address','chain']) {
    const p=provider();window.ethereum=p.api;const wallet=await selectSigninWallet('metamask',options());
    p.state[change]=change==='address'?'0x'+'34'.repeat(20):'0x2105';await assert.rejects(wallet.check(),{code:'changed'});wallet.close();
  }
  delete window.ethereum;
});
test('a missing extension and unsupported Bitcoin network have clear typed failures',async()=>{
  delete window.unisat;delete window.ethereum;
  await assert.rejects(selectSigninWallet('metamask',options()),{code:'missing'});
  await assert.rejects(selectSigninWallet('unisat',options()),{code:'missing'});
  const p=provider();p.state.network='testnet';window.unisat=p.api;
  await assert.rejects(selectSigninWallet('unisat',options()),{code:'bitcoin-network'});delete window.unisat;
});
test('Cancel stops waiting for a wallet extension that keeps its prompt open',async()=>{
  const p=provider();p.api.request=()=>new Promise(()=>{});window.ethereum=p.api;
  const controller=new AbortController();const pending=selectSigninWallet('metamask',{...options(),signal:controller.signal});controller.abort();
  await assert.rejects(pending,{code:'cancelled'});delete window.ethereum;
});
test('same-account notifications keep the ceremony; a new account ends it',async()=>{
  const p=provider();window.ethereum=p.api;let changes=0;
  const wallet=await selectSigninWallet('metamask',{...options(),changed:()=>changes++});
  for(const listener of p.listeners.get('accountsChanged'))listener([address]);
  for(const listener of p.listeners.get('chainChanged'))listener('0x14');assert.equal(changes,0);
  for(const listener of p.listeners.get('accountsChanged'))listener(['0x'+'34'.repeat(20)]);assert.equal(changes,1);
  wallet.close();delete window.ethereum;
});
test('a connected compatible wallet selects its saved provider instead of another installed extension',async()=>{
  const metamask=provider(),brave=provider();
  const announce=()=>{
    for(const [rdns,name,p]of [['io.metamask','MetaMask',metamask],['com.brave.wallet','Brave Wallet',brave]])
      window.dispatchEvent(new CustomEvent('eip6963:announceProvider',{detail:{provider:p.api,info:{uuid:rdns,rdns,name}}}));
  };
  window.addEventListener('eip6963:requestProvider',announce);
  try {
    const wallet=await selectSigninWallet('metamask',{...options(),method:{providerId:'com.brave.wallet'}});await wallet.sign('Home sign-in');wallet.close();
    assert.equal(brave.calls.filter(c=>c.method==='personal_sign').length,1);assert.equal(metamask.calls.length,0);
    await assert.rejects(selectSigninWallet('metamask',{...options(),method:{providerId:'io.missing.wallet'}}),{code:'missing'});
  }finally{window.removeEventListener('eip6963:requestProvider',announce);}
});
test('a connected account without a provider hint uses the matching extension account and network',async()=>{
  const metamask=provider(),brave=provider();metamask.state.address='0x'+'34'.repeat(20);
  const announce=()=>{
    for(const [rdns,name,p]of [['io.metamask','MetaMask',metamask],['com.brave.wallet','Brave Wallet',brave]])
      window.dispatchEvent(new CustomEvent('eip6963:announceProvider',{detail:{provider:p.api,info:{uuid:rdns,rdns,name}}}));
  };
  window.addEventListener('eip6963:requestProvider',announce);
  try {
    const wallet=await selectSigninWallet('metamask',{...options(),method:{address,chain_id:20}});await wallet.sign('Home sign-in');wallet.close();
    assert.equal(brave.calls.filter(c=>c.method==='personal_sign').length,1);assert.equal(metamask.calls.filter(c=>c.method==='eth_requestAccounts'||c.method==='personal_sign').length,0);
    brave.state.chain='0x2105';await assert.rejects(selectSigninWallet('metamask',{...options(),method:{address,chain_id:20}}),{code:'changed'});
  }finally{window.removeEventListener('eip6963:requestProvider',announce);}
});

test('ambiguous extensions stop before access instead of opening another Home picker',async()=>{
  const first=provider(),second=provider();
  const announce=()=>{
    for(const [rdns,p]of [['io.rabby',first],['com.brave.wallet',second]])window.dispatchEvent(new CustomEvent('eip6963:announceProvider',{detail:{provider:p.api,info:{uuid:rdns,rdns,name:rdns}}}));
  };
  window.addEventListener('eip6963:requestProvider',announce);
  try{await assert.rejects(selectSigninWallet('metamask',options()),{code:'changed'});assert.equal(first.calls.length+second.calls.length,0);}
  finally{window.removeEventListener('eip6963:requestProvider',announce);}
});

test('locked extensions ask the user to open the wallet before retrying',async()=>{
  const first=provider(),second=provider();
  for(const p of [first,second])p.api.request=async input=>{p.calls.push(input);return input.method==='eth_chainId'?'0x14':[];};
  const announce=()=>{for(const [rdns,p]of [['io.metamask',first],['com.brave.wallet',second]])window.dispatchEvent(new CustomEvent('eip6963:announceProvider',{detail:{provider:p.api,info:{uuid:rdns,rdns,name:rdns}}}));};
  window.addEventListener('eip6963:requestProvider',announce);
  try{await assert.rejects(selectSigninWallet('metamask',{...options(),method:{address,chain_id:20}}),{code:'wallet-unavailable'});assert(![...first.calls,...second.calls].some(c=>c.method==='eth_requestAccounts'||c.method==='personal_sign'));}
  finally{window.removeEventListener('eip6963:requestProvider',announce);}
});

test('the signed-out option binds its selected extension without a cached address',async()=>{
 const rabby=provider(),brave=provider();
 const announce=()=>{for(const [rdns,p]of [['io.rabby',rabby],['com.brave.wallet',brave]])window.dispatchEvent(new CustomEvent('eip6963:announceProvider',{detail:{provider:p.api,info:{uuid:rdns,rdns,name:rdns}}}));};
 window.addEventListener('eip6963:requestProvider',announce);
 try {const wallet=await selectSigninWallet('metamask',{...options(),providerId:'com.brave.wallet'});await wallet.sign('Home sign-in');wallet.close();assert.equal(brave.calls.filter(c=>c.method==='personal_sign').length,1);assert.equal(rabby.calls.length,0);}
 finally {window.removeEventListener('eip6963:requestProvider',announce);}
});

test('chooser resolves the current external account rather than the first used method of its connector',async()=>{
  const address='0x'+'34'.repeat(20),old='0x'+'12'.repeat(20);
  const rows=[{connector:'metamask',address:old,chain_id:20,network:'',sign_in_enabled:true},{connector:'metamask',address,chain_id:8453,network:'',sign_in_enabled:false}];
  const calls=[],provider={request:async({method})=>{calls.push(method);return method==='eth_accounts'?[address]:'0x2105';}};
  const selected=await currentConnectedSigninMethods(rows,{providers:[{provider,rdns:'io.metamask'}],unisat:null});
  assert.equal(selected.length,1);assert.equal(selected[0].address,address);assert.equal(selected[0].sign_in_enabled,false);
  assert.deepEqual(calls.sort(),['eth_accounts','eth_chainId']);
  const absent=await currentConnectedSigninMethods(rows,{providers:[{provider:{request:async({method})=>method==='eth_accounts'?['0x'+'56'.repeat(20)]:'0x2105'}}],unisat:null});
  assert.deepEqual(absent,[],'a new active account can connect instead of inheriting a different account sign-in flag');
});
