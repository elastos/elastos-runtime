import test from 'node:test';
import assert from 'node:assert/strict';
const events=new EventTarget();
globalThis.window=events;
globalThis.location=new URL('http://127.0.0.1/home/');
globalThis.document={querySelector:()=>null,querySelectorAll:()=>[]};
const {selectSigninWallet}=await import('../capsules/home/browser/wallet-signin-signers.mjs');
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
    const wallet=await selectSigninWallet('unisat',options());const proof=await wallet.sign('exact Home message');
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
