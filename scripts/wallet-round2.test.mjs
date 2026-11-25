import test from 'node:test';
import {windowTestOptions} from './lib/walletconnect-window-resources.mjs';
import assert from 'node:assert/strict';
import {windowPresentation, walletConnectView} from '../capsules/wallet-walletconnect/browser/walletconnect-window-state.mjs';
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

for(const engine of ['chromium','webkit'])test(`W2 ${engine} action titles, one identity line and one action row at desktop and phone widths`,windowTestOptions(engine,60000),async()=>{
  const f=await browserFixture(engine);
  try{
    for(const width of [480,390])for(const window of ['walletconnect'])for(const [action,stage,complete] of [['add','request-phone',false],['signin','request-phone',false],['add','request-done',true]]){
      await f.page.setViewportSize({width,height:522});
      await f.page.evaluate(async({window,action,stage,complete,address})=>{
        const {connectionView,reduceSummary,mountConnection}=await import('/capsules/_shared/wallet-connection-view.mjs');
        const name={metamask:'MetaMask',unisat:'UniSat',walletconnect:'WalletConnect'}[window];
        const summary=reduceSummary({request_id:'signin',connector_id:'wallet-'+window,capsule_id:'home',intent:'auth_challenge',address,status:'pending',reason:'Runtime supplies the signature in the wallet.',expires_at:1800000600},{connector:'wallet-'+window});
        const view=connectionView({window,stage,purpose:'home-signin',signinAction:action,signinComplete:stage==='request-done'?complete:undefined,summary,account:{name,mark:window==='walletconnect'?'wallet':window,accounts:[{address,networks:[window==='unisat'?'Bitcoin':'Elastos Smart Chain']}]},supportedActions:['send-request','stop-waiting','close-window']});
        globalThis.mounted?.dispose();globalThis.mounted=mountConnection(document.querySelector('#mount'),view);
      },{window,action,stage,complete,address});
      const text=await f.page.locator('main').textContent(),name={metamask:'MetaMask',unisat:'UniSat',walletconnect:'WalletConnect'}[window];
      assert.match(text,new RegExp(action==='add'?'Add '+name+' as a way to sign in':'Sign in with '+name));
      assert.doesNotMatch(text,/From app:|Review sign-in request|Account saved in Wallet|Runtime supplies|Time left:|\nHome\n/);
      assert.equal(await f.page.locator('details').count(),0);
      if(stage==='request-done')assert.match(text,new RegExp(name+' can now sign in to this Home\\.'));
      const size=await f.page.locator('.connection-request-account').boundingBox();assert(size.height<=32,'wallet identity stays on one line');
      assert.equal(await f.page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
      await capture(f.page,`${engine}-${window}-${action}-${stage}-${width}`,`${name} ${stage==='request-done'?'can sign in':action==='add'?'add request':'sign-in request'} at ${width} pixels.`);
    }
  }finally{await f.close();}
});

for(const engine of ['chromium','webkit'])test(`W2 ${engine} ordinary signature keeps every origin character and the final line beside Continue`,windowTestOptions(engine,60000),async()=>{
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

for(const engine of ['chromium','webkit'])test(`W2 ${engine} boot wait has a working Cancel before the connector module loads`,windowTestOptions(engine,30000),async()=>{
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

// Purpose is an explicit presentation field. Translated or changed headings
// cannot grant sign-in presentation to an ordinary connect proof.
test('W2 sign-in presentation uses purpose instead of an English heading',()=>{
  const summary=reduceSummary({...transaction,capsule_id:'home',intent:'credential'},{connector:'wallet-walletconnect'});
  const view=connectionView({window:'walletconnect',stage:'request-phone',purpose:'home-signin',signinAction:'add',summary,account:{name:'WalletConnect',mark:'wallet',accounts:[{address,networks:['Base']}]}});
  assert.equal(viewText(view.requestHeading),'Add WalletConnect as a way to sign in');
  assert.equal(connectionView({window:'walletconnect',stage:'link-wait',waitSeconds:120}).signinScreen,false);
  assert.equal(connectionView({window:'walletconnect',stage:'nothing-saved'}).title,'WalletConnect');
});


test('W2 System chooser shows wallet choices and one refusal with recovery controls',{timeout:30000},async()=>{
  const {signinFixture,installSigninProviders,evmAddress,bitcoinAddress}=await import('./lib/wallet-signin-fixture.mjs');
  const source=await signinFixture(),browser=await requireProductSmokePlaywright().chromium.launch({headless:true});source.state.methods=[];
  const context=await browser.newContext();await context.addInitScript(installSigninProviders,{evmAddress,bitcoinAddress,theme:'light'});const page=await context.newPage();
  try{
    await page.goto(source.origin+'/home/');await page.waitForFunction(()=>window.fixtureReady);await page.evaluate(()=>window.showFixtureApps());
    await page.frameLocator('iframe[title=system]').getByRole('button',{name:'Add wallet',exact:true}).click();
    const dialog=page.locator('.signin-dialog');await dialog.locator('.connection-option').nth(2).waitFor();assert.equal(await dialog.locator('.connection-option').count(),3);
    await page.evaluate(()=>walletFixture.mode='rejected');await dialog.locator('.connection-option').filter({hasText:'MetaMask'}).click();await dialog.getByRole('button',{name:'Sign message',exact:true}).click();
    await page.locator('.signin-dialog[data-state=error]').waitFor();assert.equal(await dialog.getByText('Your wallet declined the request.',{exact:true}).count(),1);
    assert.equal(await dialog.getByRole('button',{name:'Try again',exact:true}).count(),1);assert.equal(await dialog.getByRole('button',{name:'Cancel',exact:true}).count(),1);
    await capture(page,'system-chooser-refusal','System keeps the wallet refusal and recovery controls together.');
  }finally{await context.close();await browser.close();await source.close();}
});
