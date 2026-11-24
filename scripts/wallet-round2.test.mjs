import test from 'node:test';
import assert from 'node:assert/strict';
import {windowPresentation, walletConnectView} from '../capsules/wallet-walletconnect/browser/walletconnect-window-state.mjs';
import {fixture} from './lib/wallet-extension-window-fixture.mjs';
import {requireProductSmokePlaywright} from './product-smoke-browser.mjs';
import {browserFixture} from './lib/wallet-connection-browser-fixture.mjs';
import {observeApproval,assertApprovalGeometry,assertApprovalPaint} from './lib/wallet-connection-approval-oracle.mjs';
import {mkdir,writeFile,readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {connectionView,reduceSummary,viewText} from '../capsules/_shared/wallet-connection-view.mjs';

const now=1800000000, address='0x'+'12'.repeat(20);
const transaction={request_id:'payment',connector_id:'wallet-walletconnect',capsule_id:'browser',requesting_origin:'https://shop.example',reason:'One test payment',status:'pending',intent:'transaction_intent',proof_type:'siwe',address,chain_namespace:'eip155:8453',expires_at:now+600};
const captures=process.env.WALLET_ROUND2_PICTURES?await readFile(join(process.env.WALLET_ROUND2_PICTURES,'screen-index.json'),'utf8').then(JSON.parse).catch(()=>[]):[];
async function capture(page,id,caption){
  const path=process.env.WALLET_ROUND2_PICTURES;if(!path)return;
  await mkdir(path,{recursive:true});await page.screenshot({path:join(path,id+'.png'),animations:'disabled'});
  const record={file:id+'.png',caption},existing=captures.findIndex(row=>row.file===record.file);if(existing<0)captures.push(record);else captures[existing]=record;await writeFile(join(path,'screen-index.json'),JSON.stringify(captures,null,2));
}
test('W2 unresolved payment takes precedence over every QR and connection input',()=>{
  let checked=0;
  for(const outcome of [undefined,'transaction-cancelled','transaction-timeout','transaction-wallet-error'])
  for(const qrData of [undefined,'data:image/png;base64,AAAA'])
  for(const permission of ['granted','requested','refused','revoked'])
  for(const phase of ['starting','ownership','signature','transaction','disconnecting'])
  for(const busy of [false,true])
  for(const loading of [false,true])
  for(const expired of [false,true])
  for(const connection of [{},{removed:true},{expired:true},{session:{address,chain:'eip155:8453'}}]) {
    const p=windowPresentation({activeRequest:transaction,dispatchedRequestId:'payment',outcome,qrData,permission,phase,busy,loading,expired,connection},now);
    const view=walletConnectView(p);
    assert.match(p.input.stage,/^(transaction-(cancelled|timeout|wallet-error|wallet-removed|reopened|phone)|checking-response)$/,
      JSON.stringify({outcome,qr:!!qrData,permission,phase,busy,loading,expired,connection,stage:p.input.stage}));
    assert.equal(view.qrData,null);
    assert.equal(view.paymentRisk,true);
    assert(view.actions.some(a=>['close-window','stop-waiting'].includes(a.id)),'uncertain payment retains a way out');
    assert(!view.actions.some(a=>['connect','start-over','send-request','finish','add-account'].includes(a.id)));
    checked++;
  }
  assert.equal(checked,5120);
});

test('W2 payment precedence also covers a reloaded approved request and a dispatched request outside the active card',()=>{
  for(const status of ['pending','approved'])for(const source of ['active','selected','dispatched'])for(const qrData of [undefined,'data:image/png;base64,AAAA']){
    const request={...transaction,status};
    const p=windowPresentation({permission:'granted',qrData,requests:[request],dispatchedRequestId:'payment',...(source==='active'?{activeRequest:request}:source==='selected'?{selectedId:'payment'}:{})},now);
    assert.equal(p.request.request_id,'payment');assert.equal(p.input.stage,'transaction-reopened');assert.equal(walletConnectView(p).qrData,null);
  }
  for(const outcome of ['transaction-done','transaction-declined']){
    const p=windowPresentation({activeRequest:transaction,dispatchedRequestId:'payment',outcome,qrData:'data:image/png;base64,AAAA'},now);
    assert.equal(p.input.stage,outcome);
  }
});

for(const engine of ['chromium','webkit'])test(`W2 ${engine} action titles, one identity line and one action row at desktop and phone widths`,{timeout:60000},async()=>{
  const f=await browserFixture(engine);
  try{
    for(const width of [480,390])for(const window of ['metamask','unisat','walletconnect'])for(const [action,stage,complete] of [['add',window==='walletconnect'?'request-phone':'request-waiting',false],['signin',window==='walletconnect'?'request-phone':'request-extension',false],['add','request-done',true]]){
      await f.page.setViewportSize({width,height:522});
      await f.page.evaluate(async({window,action,stage,complete,address})=>{
        const {connectionView,reduceSummary,mountConnection}=await import('/capsules/_shared/wallet-connection-view.mjs');
        const name={metamask:'MetaMask',unisat:'UniSat',walletconnect:'Phone wallet'}[window];
        const summary=reduceSummary({request_id:'signin',connector_id:'wallet-'+window,capsule_id:'home',intent:'auth_challenge',address,status:'pending',reason:'Runtime supplies the signature in the wallet.',expires_at:1800000600},{connector:'wallet-'+window});
        const view=connectionView({window,stage,purpose:'home-signin',signinAction:action,signinComplete:stage==='request-done'?complete:undefined,summary,account:{name,mark:window==='walletconnect'?'wallet':window,accounts:[{address,networks:[window==='unisat'?'Bitcoin':'Elastos Smart Chain']}]},supportedActions:['send-request','stop-waiting','close-window']});
        globalThis.mounted?.dispose();globalThis.mounted=mountConnection(document.querySelector('#mount'),view);
      },{window,action,stage,complete,address});
      const text=await f.page.locator('main').textContent(),name={metamask:'MetaMask',unisat:'UniSat',walletconnect:'Phone wallet'}[window];
      assert.match(text,new RegExp(action==='add'?'Add '+name+' as a way to sign in':'Sign in with '+name));
      assert.doesNotMatch(text,/From app:|Review sign-in request|Account saved in Wallet|Runtime supplies|Time left:|\nHome\n/);
      assert.equal(await f.page.locator('details').count(),0);
      if(stage==='request-done')assert.match(text,new RegExp(name+' can now sign in to this Home\\.'));
      if(stage==='request-waiting'){
        assert.equal(await f.page.getByRole('button',{name:'Continue in '+name,exact:true}).count(),1);
        assert.equal(await f.page.locator('.el-button-primary').count(),1);
      }
      const size=await f.page.locator('.connection-request-account').boundingBox();assert(size.height<=32,'wallet identity stays on one line');
      assert.equal(await f.page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
      await capture(f.page,`${engine}-${window}-${action}-${stage}-${width}`,`${name} ${stage==='request-done'?'can sign in':action==='add'?'add request':'sign-in request'} at ${width} pixels.`);
    }
  }finally{await f.close();}
});

for(const engine of ['chromium','webkit'])test(`W2 ${engine} ordinary signature keeps every origin character and the final line beside Continue`,{timeout:60000},async()=>{
  const f=await browserFixture(engine);
  try{
    for(const width of [480,390])for(const origin of ['https://shop.example.com','https://'+'account-check.'.repeat(20)+'attacker-domain.net']){
      await f.page.setViewportSize({width,height:522});
      await f.page.evaluate(async({origin,address})=>{
        const {connectionView,reduceSummary,mountConnection}=await import('/capsules/_shared/wallet-connection-view.mjs');
        const summary=reduceSummary({request_id:'ordinary',connector_id:'wallet-metamask',capsule_id:'browser',requesting_app_name:'Browser',requesting_origin:origin,intent:'browser_personal_sign',address,status:'pending',reason:'A harmless test message',expires_at:1800000600},{connector:'wallet-metamask'});
        const view=connectionView({window:'metamask',stage:'request-waiting',summary,waitSeconds:300,account:{name:'MetaMask',mark:'metamask',accounts:[{address,networks:['Ethereum']}]},supportedActions:['send-request','close-window']});
        globalThis.mounted?.dispose();globalThis.mounted=mountConnection(document.querySelector('#mount'),view);
      },{origin,address});
      const max=await f.page.locator('main').evaluate(r=>r.scrollHeight-r.clientHeight);
      for(let y=0;y<=max;y++){
        await f.page.locator('main').evaluate((r,y)=>r.scrollTop=y,y);
        assertApprovalGeometry(await observeApproval(f.page));
      }
      await assertApprovalPaint(f.page,await observeApproval(f.page));
      assert.equal(await f.page.getByRole('button',{name:'Cancel',exact:true}).count(),1);
      await capture(f.page,`${engine}-ordinary-origin-${origin.length>50?'long':'short'}-${width}`,`Ordinary signature with ${origin.length>50?'long':'short'} site name at ${width} pixels.`);
    }
  }finally{await f.close();}
});

for(const engine of ['chromium','webkit'])test(`W2 ${engine} boot wait has a working Cancel before the connector module loads`,{timeout:30000},async()=>{
  const f=await browserFixture(engine);
  try{
    for(const kind of ['metamask','unisat','walletconnect']){
      await f.page.route(`**/wallet-${kind}.js*`,route=>route.abort());
      await f.page.evaluate(kind=>{
        globalThis.loadingMessages=[];
        globalThis.receiveLoading=e=>{if(e.data?.type==='home:close-self')loadingMessages.push(e.data);};
        addEventListener('message',receiveLoading);
        document.querySelector('#mount').innerHTML=`<iframe style="border:0;width:100%;height:480px" sandbox="allow-scripts" src="/capsules/wallet-${kind}/browser/index.html?home_origin=${encodeURIComponent(location.origin)}#home_token=loading-test"></iframe>`;
      },kind);
      const frame=f.page.frameLocator('iframe');
      await frame.getByText('Loading wallet connection…',{exact:true}).waitFor();
      await capture(f.page,`${engine}-${kind}-loading`,`${kind} waits for its module with Cancel.`);
      await frame.getByRole('button',{name:'Cancel',exact:true}).click();
      await f.page.waitForFunction(()=>loadingMessages.length===1);
      assert.deepEqual(await f.page.evaluate(()=>loadingMessages),[{type:'home:close-self',homeToken:'loading-test'}]);
      await f.page.evaluate(()=>removeEventListener('message',receiveLoading));
    }
  }finally{await f.close();}
});

for(const kind of ['metamask','unisat'])test(`W2 ${kind} completion belongs to its reviewed action and ordinary Wallet keeps its receipt`,{timeout:30000},async()=>{
  const browser=await requireProductSmokePlaywright().chromium.launch({headless:true});
  const f=await fixture(browser,kind,{saved:true,pictures:false});
  const send=async(operation,fields={})=>f.top.evaluate(({operation,fields,kind})=>document.querySelector('iframe').contentWindow.postMessage({type:'home:wallet-signin-effect',homeToken:'fixture-token',requestId:operation==='review'?'review-action':operation,operation,...(operation==='review'?{address:kind==='metamask'?'0x'+'1'.repeat(40):'bc1q'+'a'.repeat(38),chain_id:kind==='metamask'?1:0,network:kind==='metamask'?'':'bitcoin',name:kind==='metamask'?'MetaMask':'UniSat',message:'Runtime fixed sentence.',action:'add'}:{}),...fields},'*'),{operation,fields,kind});
  try{
    await f.state('linked');assert.match(await f.frame.locator('main').textContent(),kind==='metamask'?/Address saved in Wallet/:/Connected\./);
    await send('review');await f.action('send-request').click();await send('finish');
    await f.state('request-done');assert.doesNotMatch(await f.frame.locator('main').textContent(),/Account saved in Wallet|can now sign in/);
    await send('complete',{reviewRequestId:'old-action'});
    assert.doesNotMatch(await f.frame.locator('main').textContent(),/can now sign in/);
    await send('complete',{reviewRequestId:'review-action'});
    await f.frame.getByText(/can now sign in to this Home\./).waitFor();
    await capture(f.top,`live-${kind}-signin-complete`,`${kind} completed the add-for-sign-in action.`);
  }finally{await f.close();await browser.close();}
});

for(const kind of ['metamask','unisat'])test(`W2 ${kind} review approval has one answer through Stop and page close`,async()=>{
  const browser=await requireProductSmokePlaywright().chromium.launch({headless:true});
  const f=await fixture(browser,kind,{saved:true,pictures:false});
  try {
    await f.top.evaluate(kind=>{
      window.reviewAnswers=[];
      addEventListener('message',e=>{if(e.data?.type==='home:wallet-signin-effect-result')reviewAnswers.push(e.data);});
      document.querySelector('iframe').contentWindow.postMessage({type:'home:wallet-signin-effect',homeToken:'fixture-token',requestId:'review-1',operation:'review',address:kind==='metamask'?'0x'+'1'.repeat(40):'bc1q'+'a'.repeat(38),chain_id:kind==='metamask'?1:0,network:kind==='metamask'?'':'bitcoin',name:kind==='metamask'?'MetaMask':'UniSat',message:'Runtime owns this exact message.'},'*');
    },kind);
    await f.frame.locator('[data-action=send-request]').click();
    await f.top.waitForFunction(()=>reviewAnswers.length===1);
    assert.deepEqual(await f.top.evaluate(()=>reviewAnswers.map(a=>a.result)),[{approved:true}]);
    // Stop from Approved has no reply left, even when a stale click is queued.
    await f.frame.evaluate(()=>{const stale=document.createElement('button');stale.dataset.action='stop-waiting';document.querySelector('main').append(stale);stale.click();});
    await f.top.evaluate(()=>document.querySelector('iframe').contentWindow.postMessage({type:'home:wallet-signin-effect',homeToken:'fixture-token',requestId:'stop-after-approved',operation:'stop'},'*'));
    await f.top.evaluate(()=>new Promise(resolve=>setTimeout(resolve,50)));
    await f.frame.evaluate(()=>window.dispatchEvent(new Event('pagehide')));
    await f.top.evaluate(()=>new Promise(resolve=>setTimeout(resolve,50)));
    assert.deepEqual(await f.top.evaluate(()=>reviewAnswers.filter(a=>a.requestId==='review-1').map(a=>({result:a.result,error:a.error}))),[{result:{approved:true},error:undefined}]);
  }finally{await f.close();await browser.close();}
});

// Purpose is an explicit presentation field. Translated or changed headings
// cannot grant sign-in presentation to an ordinary connect proof.
test('W2 sign-in presentation uses purpose instead of an English heading',()=>{
  const summary=reduceSummary({...transaction,capsule_id:'home',intent:'credential'},{connector:'wallet-walletconnect'});
  const view=connectionView({window:'walletconnect',stage:'request-phone',purpose:'home-signin',signinAction:'add',summary,account:{name:'Phone wallet',mark:'wallet',accounts:[{address,networks:['Base']}]}});
  assert.equal(viewText(view.requestHeading),'Add Phone wallet as a way to sign in');
  assert.equal(connectionView({window:'walletconnect',stage:'link-wait',waitSeconds:120}).signinScreen,false);
  assert.equal(connectionView({window:'walletconnect',stage:'nothing-saved'}).title,'Phone wallet');
});


test('W2 Wallet chooser shows only state below names and one refusal with recovery controls',{timeout:30000},async()=>{
  const {signinFixture,installSigninProviders,evmAddress,bitcoinAddress}=await import('./lib/wallet-signin-fixture.mjs');
  const source=await signinFixture(),browser=await requireProductSmokePlaywright().chromium.launch({headless:true});
  const context=await browser.newContext();await context.addInitScript(installSigninProviders,{evmAddress,bitcoinAddress,theme:'light'});
  const page=await context.newPage();
  try{
    await page.goto(source.origin+'/home/');await page.waitForFunction(()=>window.fixtureReady);await page.evaluate(()=>window.showFixtureApps());
    const frame=page.frameLocator('iframe[title=wallet]');await page.evaluate(()=>document.querySelector('#show-wallet').click());await frame.locator('#wallet-methods').waitFor();
    for(const width of [480,390])for(const stage of ['options','error']){
      await page.setViewportSize({width,height:680});
      await page.evaluate(stage=>document.querySelector('iframe[title=wallet]').contentWindow.postMessage({type:'home:wallet-signin-chooser',homeToken:'fixture-wallet',requestId:'w2-chooser',state:{stage,message:stage==='error'?'Your wallet declined the request.':'',methods:[{connector:'metamask',used:true,connected:true},{connector:'unisat',connected:false},{connector:'walletconnect',connected:true}]}},'*'),stage);
      await frame.locator('#wallet-signers[data-signin='+stage+']').waitFor();
      const rows=frame.locator('#wallet-methods .wallet-method-head');
      assert.deepEqual(await rows.locator('div > span').allTextContents(),['Already signs in','Not connected','Connected']);
      assert.deepEqual(await rows.locator('button').allTextContents(),['Choose','Choose','Choose']);
      assert.equal(await rows.nth(0).getByRole('button',{name:'Choose',exact:true}).isDisabled(),true);
      if(stage==='error'){assert.equal(await frame.getByText('Your wallet declined the request.',{exact:true}).count(),1);assert.equal(await frame.getByRole('button',{name:'Try again',exact:true}).count(),1);}
      assert.equal(await frame.getByRole('button',{name:'Cancel',exact:true}).count(),1);
      await frame.locator('#wallet-signers').scrollIntoViewIfNeeded();await capture(page,`wallet-chooser-${stage}-${width}`,`Wallet chooser ${stage==='options'?'shows each wallet state':'offers Try again and Cancel after refusal'} at ${width} pixels.`);
    }
  }finally{await context.close();await browser.close();await source.close();}
});
