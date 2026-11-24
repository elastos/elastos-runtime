import test from 'node:test';
import assert from 'node:assert/strict';
globalThis.location={href:'http://localhost:18091/home/',origin:'http://localhost:18091'};
globalThis.window=globalThis;globalThis.addEventListener=()=>{};globalThis.removeEventListener=()=>{};globalThis.dispatchEvent=()=>true;globalThis.document={activeElement:null,createElement:()=>({}),addEventListener(){},querySelector:()=>null,body:{append(){}}};
const {createHomeWalletSignin}=await import('../capsules/home/browser/wallet-signin-view.mjs');

test('TRACE E: Remove requested while Add wallet is open is merged into the Add request',async()=>{
  const fetched=[];globalThis.fetch=async(path,init)=>{fetched.push(path);return {ok:true,json:async()=>({ceremony_id:'wallet:1',expires_at:Date.now()/1000+180,message:'',approval:{operation:'auth.wallet.method',request:{ceremony_id:'wallet:1',action:'remove',account_id:'acct',method_id:'m-old'}}})};};
  const rendered=[];
  const chooser={isOpen:()=>true,render:s=>rendered.push(s),focus(){},close(){}};
  const signin=createHomeWalletSignin({approve:async()=>{throw new Error('no passkey in this trace');}});
  const common={token:'t',account:'A',accountId:'acct',isCurrent:()=>true,openChooser:async()=>chooser,openConnector:async()=>({focus(){},isOpen:()=>true}),loadConnected:async()=>[]};
  const add=signin.start({...common,action:'add',method:null});
  await new Promise(r=>setTimeout(r,20));
  const method={method_id:'m-old',connector:'metamask',address:'0x'+'22'.repeat(20),chain_id:20,network:'',sign_in_enabled:true};
  const remove=signin.start({...common,action:'remove',method});
  await new Promise(r=>setTimeout(r,20));
  const beganRemove=fetched.some(p=>String(p).includes('/api/auth/wallet-methods/begin'));
  await signin.cancel();
  const [a,r]=await Promise.all([add,remove]);
  console.log('add ->',JSON.stringify(a),'| remove ->',JSON.stringify(r),'| remove ceremony begun:',beganRemove,'| fetched:',fetched.join(','));
  assert.equal(beganRemove,false);assert.equal(r.status,'busy','Remove must be refused as busy, not adopt the Add result');
});
