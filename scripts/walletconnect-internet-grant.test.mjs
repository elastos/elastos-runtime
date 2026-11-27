import test from 'node:test';
import assert from 'node:assert/strict';
import {createWalletSigninFlow,walletSigninError} from '../capsules/home/browser/wallet-signin-flow.mjs';
import {windowPresentation} from '../capsules/wallet-walletconnect/browser/walletconnect-window-state.mjs';
import {screens} from '../capsules/_shared/wallet-connection-screens.mjs';
const internet='/api/apps/wallet-walletconnect/internet';
const wallet={connector:'walletconnect',address:'0x'+'12'.repeat(20),chain_id:20,network:'',close(){}};
for(const delegateWalletConnect of [false,true])test(`System waits for the one Inbox grant and resumes once (existing connection ${delegateWalletConnect})`,async t=>{
 t.mock.timers.enable({apis:['setTimeout']});
 let status='off',selected=0,requests=0,begins=0;const calls=[];
 const flow=createWalletSigninFlow({api:async(path,body)=>{
  calls.push({path,body});
  if(path===internet){if(body){assert.deepEqual(body,{action:'request'});requests++;status='requested';}return {status};}
  if(path.endsWith('/cancel'))return {};
  if(path.endsWith('/begin')){begins++;assert.equal(body.allow_temporary_internet,undefined);if(status!=='granted')throw Object.assign(new Error('off'),{status:403,code:'walletconnect_internet_off'});}
  if(path.endsWith('/begin')||path.endsWith('/select'))return {ceremony_id:'one',expires_at:Date.now()/1000+120,message:body.address?'Add this wallet':'',approval:{operation:'auth.wallet.method.change',request:{ceremony_id:'one',action:'add',principal_id:'account',proof_binding_id:'wallet'}}};
 },select:async()=>{selected++;return wallet;},approve(){},render(){}});
 t.after(()=>flow.cancel());
 await flow.start({action:'add',delegateWalletConnect});await flow.choose('walletconnect');
 assert.equal(flow.state.stage,'internet-pending');assert.equal(flow.state.message,'Allow WalletConnect internet access in Inbox to continue.');assert.equal(requests,1);assert.equal(selected,0,'no pairing or QR before Inbox Allow');
 status='granted';t.mock.timers.tick(1000);await new Promise(r=>setImmediate(r));
 assert.equal(flow.state.stage,'review');assert.equal(selected,1);
 t.mock.timers.tick(3000);await new Promise(r=>setImmediate(r));
 assert.equal(selected,1);assert.equal(requests,1);assert.equal(begins,delegateWalletConnect?1:2);
 assert(!calls.some(c=>c.path.includes('grant')||c.path.includes('step-up')),'only Inbox grants internet');
});
test('signed-out off refusal names the state and other sign-in methods, without filing a request',async t=>{
 const calls=[];const flow=createWalletSigninFlow({api:async(path,body)=>{calls.push({path,body});if(path.endsWith('/status'))return {walletconnect_signin_available:true};throw Object.assign(new Error('off'),{status:403,code:'walletconnect_internet_off'});},select(){throw new Error('QR before grant');},approve(){},render(){}});t.after(()=>flow.cancel());
 await flow.start();await flow.choose('walletconnect');assert.equal(flow.state.stage,'error');
 assert.equal(flow.state.message,'WalletConnect is off on this Home. Choose another way to sign in.');
 assert(!calls.some(c=>c.path===internet));
 assert.equal(walletSigninError({status:403,code:'walletconnect_internet_off'},'signin'),flow.state.message);
});
test('System cleanup waits in the same Inbox entry before filing the request',async t=>{
 t.mock.timers.enable({apis:['setTimeout']});let cleanup=true,requests=0;
 const flow=createWalletSigninFlow({api:async(path,body)=>{if(path===internet){if(body)requests++;return {status:'revoked',cleanup_pending:cleanup};}throw Object.assign(new Error('off'),{code:'walletconnect_internet_off'});},select(){throw new Error('pairing before grant');},approve(){},render(){}});t.after(()=>flow.cancel());
 await flow.start({action:'add'});await flow.choose('walletconnect');assert.equal(flow.state.stage,'internet-clearing');assert.match(flow.state.message,/Finish disconnecting in Inbox/);assert.equal(requests,0);
 cleanup=false;t.mock.timers.tick(1000);await new Promise(r=>setImmediate(r));assert.equal(requests,1);
});
for(const [permission,cleanupPending,pending,expected]of [['revoked',true,false,'internet-clearing'],['revoked',false,false,'internet-refused'],['refused',false,false,'internet-refused'],['requested',false,false,'internet-off'],['requested',false,true,'internet-pending']])test(`window ${permission}, cleanup ${cleanupPending}, pending ${pending} leads to the one Inbox entry`,()=>{
 const result=windowPresentation({permission,cleanupPending,pending,accounts:[],requests:[]},Date.now()/1000);
 assert.equal(result.input.stage,expected);assert.equal(screens.walletconnect[expected].primary.id,'inbox');
 if(cleanupPending){assert.match(screens.walletconnect[expected].notice,/Finish disconnecting/);assert.equal(result.input.localReturn,false);}
});

test('Wallet app use gives the Inbox action that matches the cleanup state',async()=>{
 const {handleWalletAppUse}=await import('../capsules/home/browser/wallet-app-use-host.mjs');
 for(const code of ['permission','permission-cleanup']) {
  const replies=[],source={postMessage:message=>replies.push(message)};
  const context={kind:'app-frame',targetId:'wallet',source,homeToken:'wallet',walletEffectState:{}};
  const event={source,data:{type:'home:wallet-app-connect',requestId:'one',homeToken:'wallet',inventoryId:'entry'}};
  handleWalletAppUse(event,context,{inventory:async()=>({entries:[{inventory_id:'entry',sign_in:{connector:'wallet-walletconnect'},accounts:[]}]}),connect:async()=>{throw Object.assign(new Error('off'),{code});},current:()=>true,changed(){},focus(){}});
  await new Promise(r=>setImmediate(r));
  assert.equal(replies.length,1);assert.equal(replies[0].result.code,code);
  assert.equal(replies[0].result.message,code==='permission-cleanup'?'Choose Finish disconnecting in Inbox before you allow internet access again.':'Allow WalletConnect internet access in Inbox, then select Try again.');
 }
});
