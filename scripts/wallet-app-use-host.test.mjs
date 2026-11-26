import test from 'node:test';
import assert from 'node:assert/strict';
import {handleWalletAppUse,retireWalletAppUse} from '../capsules/home/browser/wallet-app-use-host.mjs';
const tick = () => new Promise(resolve => setImmediate(resolve));
function fixture() {
  const replies = [], source = {postMessage: message => replies.push(message)}, calls = [];
  const context = {kind:'app-frame',targetId:'wallet',source,homeToken:'launch',walletEffectState:{}};
  const entry = {inventory_id:'selected',address:'0x'+'12'.repeat(20),chain_namespace:'eip155:20',accounts:[],sign_in:{connector:'metamask'}};
  const data = {type:'home:wallet-app-connect',requestId:'one',homeToken:'launch',inventoryId:'selected'};
  const dependencies = {inventory:async()=>({entries:[entry]}),connect:async value=>calls.push(value),current:()=>true,changed(){},focus(){}};
  return {replies,source,context,entry,data,dependencies,calls};
}
test('Wallet app-use intent selects only an identity from the Home inventory', async () => {
  const f = fixture(); handleWalletAppUse({source:f.source,data:f.data},f.context,f.dependencies); await tick();
  assert.equal(f.calls[0],f.entry); assert.equal(f.replies[0].result.status,'complete');
  f.data = {...f.data,requestId:'two',inventoryId:'other-account'};
  handleWalletAppUse({source:f.source,data:f.data},f.context,f.dependencies); await tick();
  assert.equal(f.calls.length,1); assert.equal(f.replies[1].result.status,'failed');
});
test('Wallet app-use intent rejects another source, app, token and extra fields', async () => {
  for (const variation of ['source','app','token','extra']) {
    const f = fixture();
    const event={source:variation==='source'?{}:f.source,data:{...f.data,...(variation==='token'?{homeToken:'foreign'}:{}),...(variation==='extra'?{connector:'unisat'}:{})}};
    handleWalletAppUse(event,{...f.context,...(variation==='app'?{targetId:'system'}:{})},f.dependencies); await tick();
    assert.equal(f.calls.length,0,variation); assert.equal(f.replies.length,0,variation);
  }
});
test('Cancel retires an app connection while a proof is pending and preserves the saved uses', async () => {
  const f=fixture(); let finish, active;
  f.dependencies.connect=async (_entry,current)=>{active=current;await new Promise(resolve=>finish=resolve);if(current())f.calls.push('committed');};
  handleWalletAppUse({source:f.source,data:f.data},f.context,f.dependencies); await tick(); assert.equal(active(),true);
  handleWalletAppUse({source:f.source,data:{type:'home:wallet-app-connect-cancel',requestId:'one',homeToken:'launch'}},f.context,f.dependencies);
  assert.equal(active(),false); finish(); await tick();
  assert.deepEqual(f.calls,[]); assert.deepEqual(f.replies,[]); assert.deepEqual(f.entry.accounts,[]);
});
test('a second app-use request stays outside the active proof and session change retires it', async () => {
  const f=fixture();let release, live=true;
  f.dependencies.current=()=>live; f.dependencies.inventory=()=>new Promise(resolve=>release=resolve);
  handleWalletAppUse({source:f.source,data:f.data},f.context,f.dependencies);await tick();
  handleWalletAppUse({source:f.source,data:{...f.data,requestId:'two'}},f.context,f.dependencies);
  assert.equal(f.replies[0].result.status,'failed');live=false;release({entries:[f.entry]});await tick();
  assert.equal(f.calls.length,0);assert.equal(f.replies.length,1);
});

test('an old Wallet frame cannot use a new Home account authority', async () => {
  const f=fixture();let reads=0;
  f.dependencies.current=()=>false;f.dependencies.inventory=async()=>{reads++;return {entries:[f.entry]};};
  handleWalletAppUse({source:f.source,data:f.data},f.context,f.dependencies);await tick();
  assert.equal(reads,0);assert.deepEqual(f.calls,[]);assert.deepEqual(f.replies,[]);
});

test('a replacement Wallet document retires the old proof in its reused frame', async () => {
  const f=fixture();let release;
  f.dependencies.connect=async(_entry,current)=>{await new Promise(resolve=>release=resolve);if(current())f.calls.push('committed');};
  handleWalletAppUse({source:f.source,data:f.data},f.context,f.dependencies);await tick();
  retireWalletAppUse(f.context);release();await tick();
  assert.deepEqual(f.calls,[]);assert.deepEqual(f.replies,[]);assert.equal(f.context.walletEffectState.appConnection,null);
});

// Removal guards keep the retired presentation protocol out of production.
test('fix1 retired Wallet sign-in chooser has no production surface', async()=>{
  const {readFile}=await import('node:fs/promises');
  for(const path of ['capsules/home/browser/wallet-signin-connector.mjs','capsules/home/browser/wallet-signin-view.mjs','capsules/home/browser/wallet-signin-methods.mjs','capsules/home-gui/browser/home-gui-shell.js','capsules/wallet/browser/style.css']) {
    assert.doesNotMatch(await readFile(path,'utf8'),/openWalletSigninChooser|openChooser|wallet-signin-state|readWalletSigninMethods|data-signin-chooser|#wallet-signers/,path);
  }
});
test('fix1 refined wallet copy uses the approved direction and straight apostrophes', async()=>{
  const {readFile}=await import('node:fs/promises');
  for(const path of ['capsules/wallet/browser/wallet-inventory.js','capsules/home/browser/wallet-signin-management.mjs']) {
    const source=await readFile(path,'utf8');assert.doesNotMatch(source,/System manages sign-in use\.|[’‘]/,path);
  }
});

test('fix1 WalletConnect permission revocation during selection retains its error code', async()=>{
  const {createWalletConnectClient}=await import('../capsules/wallet-walletconnect/browser/walletconnect-client.mjs');
  let release;
  const client=createWalletConnectClient({origin:'http://localhost',api:async resource=>{
    if(resource==='wallet/config')return new Promise(resolve=>release=resolve);
    if(resource==='internet')return {status:'required'};
    return {};
  }});
  const selected=assert.rejects(client.effect({kind:'signin-select'}),error=>error.code==='permission');
  await Promise.resolve();await client.effect({kind:'status'});await selected;release({walletconnect:{}});
});
