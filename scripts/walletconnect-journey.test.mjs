import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {execFileSync} from 'node:child_process';
import {readFileSync,mkdirSync} from 'node:fs';
import {extname,resolve,relative} from 'node:path';
import {importProductSmokePlaywright,productSmokeLaunchOptions} from './product-smoke-browser.mjs';
import {walletConnectRelayFixture} from './lib/walletconnect-relay-fixture.mjs';
import {walletConnectMessages as messages} from '../capsules/wallet-walletconnect/browser/walletconnect-client.mjs';
const permissionText = 'WalletConnect needs internet access. Answer the request in Inbox. If it is no longer there, select Connect wallet to ask again.';
const turnedOff = 'Internet access for WalletConnect was turned off. Select Connect wallet to ask again.';
// API and passkey responses are fixtures. All app markup, scripts, CSS and SDK are real.
test('WalletConnect permission, expiry and Turn Off journeys in real capsules',{timeout:240000},async()=>{
  let permissionPosts=0,holdApprovalList=false,releaseApprovalList,approvalListHeld;
  let status='off',requestId=0,issuedAt=Math.floor(Date.now()/1000),passkeys=0,failSummary=false,keys={},verified=0,completions=0,approvalRequests=[];
  const consent=()=>({status,request:['requested','granted'].includes(status)?{id:String(requestId),issued_at:issuedAt,text:'Fixture consent'}:null});
  const actions=[];
  const notification=()=>({id:'walletconnect-internet:permission',source_app:'wallet-walletconnect',kind:status==='requested'?'walletconnect_internet_request':'walletconnect_internet_decision',title:'WalletConnect internet access',body:status==='requested'
    ? readFileSync('elastos/crates/elastos-server/src/api/gateway_walletconnect.rs','utf8').match(/const CONSENT: &str = "([^"]+)"/)[1]
    : status==='granted'?'WalletConnect can use the internet.':'Internet access for WalletConnect is off.',read:status!=='requested',created_at:Math.floor(Date.now()/1000),severity:status==='requested'?'attention':'info',action_ref:['requested','granted'].includes(status)?{action_id:`walletconnect-internet-${status==='requested'?'allow':'turn-off'}:${requestId}`} : null});
  const server=http.createServer(async(req,res)=>{
    const url=new URL(req.url,'http://localhost');const path=url.pathname;
    const json=(value,code=200)=>{res.writeHead(code,{'content-type':'application/json'});res.end(JSON.stringify(value));};
    try {
      if(path==='/') {res.setHeader('content-type','text/html');res.end(`<!doctype html><style>body{margin:0}iframe{border:0;width:100%;height:100vh}#inbox{position:fixed;inset:0;background:white;display:none}</style><iframe id="wallet" src="/apps/wallet-walletconnect/?home_origin=http://127.0.0.1:${server.address().port}#home_token=fixture-wallet"></iframe><iframe id="inbox"></iframe><script>
      window.events=[];addEventListener('message',e=>{events.push(e.data.type);if(e.data.type==='elastos.home.passkey-step-up.request/v1'){fetch('/passkey',{method:'POST'});e.source.postMessage({type:'elastos.home.passkey-step-up.result/v1',requestId:e.data.requestId,stepUpToken:'fixture-step-up'},location.origin);}
      if(e.data.type==='home:open-target'){if(e.data.target==='inbox'){inbox.src='/apps/inbox/?home_origin='+encodeURIComponent(location.origin)+'#home_token=fixture-inbox';inbox.style.display='block';}else if(e.data.target==='wallet-walletconnect'){inbox.style.display='none';wallet.contentWindow.focus();}}});</script>`);return;}
      if(path==='/passkey'){passkeys++;json({});return;}
      if(path==='/api/apps/wallet-walletconnect/internet'){if(req.method==='POST')permissionPosts++;if(req.method==='POST'&&status!=='granted'&&status!=='requested'){status='requested';requestId++;issuedAt=Math.floor(Date.now()/1000);}json(consent());return;}
      if(path==='/api/apps/wallet-walletconnect/wallet/config'){json({walletconnect:{project_id:'fixture-project',storage_revision:'"0"'}});return;}
      if(path.endsWith('/wallet/accounts')){if(failSummary){res.writeHead(500);res.end();}else json({accounts:[]});return;}
      if(path.endsWith('/wallet/approvals')){const summary={approval_requests:approvalRequests.filter(r=>r.status==='pending'||r.status==='approved'&&r.intent==='transaction_intent')};if(holdApprovalList){holdApprovalList=false;const snapshot=structuredClone(summary);releaseApprovalList=()=>json(snapshot);approvalListHeld();return;}json(summary);return;}
      if(path.includes('/wallet/approvals/')&&path.endsWith('/complete')){const approvalId=decodeURIComponent(path.split('/').at(-2));const request=approvalRequests.find(r=>r.request_id===approvalId);if(request?.status!=='approved'){json({},409);return;}request.status='completed';completions++;json({});return;}
      if(path.includes('/wallet/approvals/')&&path.endsWith('/approve')){const approvalId=decodeURIComponent(path.split('/').at(-2));const request=approvalRequests.find(r=>r.request_id===approvalId);if(request?.status!=='pending'){json({},409);return;}request.status='approved';json({handoff:{request_id:request.request_id,intent:request.intent,transaction:{from:'0x'+'12'.repeat(20),chainId:'0x14',to:'0x'+'78'.repeat(20),value:'0x1'},payload_hash:'0x'+'34'.repeat(32),signer:'0x'+'12'.repeat(20),signature_type:'personal_sign',message:'Fixture review'},binding:{payload_hash:'0x'+'34'.repeat(32),chain_namespace:'eip155:20',expires_at:Math.floor(Date.now()/1000)+600}});return;}
      if(path.endsWith('/api/auth/evm/challenge')){json({message:'Fixture ownership',expires_at:Math.floor(Date.now()/1000)+600});return;}
      if(path.endsWith('/api/auth/evm/verify')){verified++;json({});return;}
      if(path.endsWith('/relay-admission')){json({token:'fixture-admission'});return;}
      if(path.endsWith('/storage')){let body='';for await(const chunk of req)body+=chunk;if(req.method==='DELETE')keys={};else if(body){const {key,value}=JSON.parse(body);if(value===null)delete keys[key];else keys[key]=value;}json(keys);return;}
      if(path==='/api/apps/inbox/summary'){json({notifications:{entries:[notification()]}});return;}
      if(path==='/api/apps/inbox/actions'){let body='';for await(const chunk of req)body+=chunk;const action=JSON.parse(body);actions.push(action);if(action.action_id.includes('-deny:'))status='refused';else if(action.action_id.includes('-allow:'))status='granted';else if(action.action_id.includes('-turn-off:'))status='revoked';json({});return;}
      if(path.startsWith('/api/')){json({});return;}
      const match=path.match(/^\/apps\/(wallet-walletconnect|inbox|home)\/(.*)$/);
      if(match){const root=resolve('capsules',match[1],match[1]==='wallet-walletconnect'&&match[2].startsWith('vendor/')?'':'browser');const file=resolve(root,match[2]||'index.html');assert.ok(!relative(root,file).startsWith('..'));res.setHeader('content-type',({'.js':'text/javascript','.mjs':'text/javascript','.css':'text/css','.html':'text/html','.woff2':'font/woff2'})[extname(file)]||'application/octet-stream');res.end(readFileSync(file));return;}
      res.writeHead(404).end();
    }catch(error){res.writeHead(500).end(error.message);}
  });
  const {relay,methods}=walletConnectRelayFixture(server);
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  let browser;const evidence=process.env.WALLETCONNECT_SCREENSHOTS;
  if(evidence)mkdirSync(evidence,{recursive:true});
  try {
    const {chromium}=await importProductSmokePlaywright();browser=await chromium.launch({headless:true,...productSmokeLaunchOptions()});
    const page=await browser.newPage({viewport:{width:1000,height:850}});
    await page.route('**/*',route=>new URL(route.request().url()).origin===`http://127.0.0.1:${server.address().port}`?route.continue():route.abort());
    const errors=[];page.on('pageerror',error=>errors.push(error.message));
    await page.addInitScript(()=>{window.fixtureIntervals=[];const native=setInterval;window.setInterval=(fn,ms,...args)=>{window.fixtureIntervals.push(ms);return native(fn,ms,...args);};});
    await page.goto(`http://127.0.0.1:${server.address().port}`);
    const wallet=page.frameLocator('#wallet'),inbox=page.frameLocator('#inbox');
    const screenshotNames=new Set((process.env.WALLETCONNECT_SCREENSHOT_NAMES||'').split(',').filter(Boolean));
    const shot=async(name)=>{if(evidence&&(!screenshotNames.size||screenshotNames.has(name)))await page.screenshot({path:`${evidence}/${name}.png`});};
    const theme=async value=>{for(const frame of page.frames())if(frame!==page.mainFrame())await frame.evaluate(value=>document.documentElement.dataset.elTheme=value,value);};
    const guardCase=process.env.WALLETCONNECT_GUARD_CASE;
    const initialWalletFrame=page.frames().find(frame=>frame.url().includes('/apps/wallet-walletconnect/'));
    const walletFrame=initialWalletFrame;
    if(!guardCase) {
    await wallet.locator('#wallet-requests').getByText('No approval requests.',{exact:true}).waitFor();
    assert.deepEqual(await initialWalletFrame.evaluate(()=>window.fixtureIntervals),[5000],'idle uses the earlier five-second interval');
    await wallet.locator('#wallet-connect').click();
    await wallet.locator('#wallet-status').filter({hasText:permissionText}).waitFor();
    assert.equal(await initialWalletFrame.evaluate(()=>window.fixtureIntervals.at(-1)),1000,'pending permission polls each second');
    assert.equal(await wallet.locator('#wallet-status').getAttribute('data-tone'),'muted');
    await theme('dark');await shot('r4-r5-permission-dark');
    await page.evaluate(()=>inbox.style.display='none');await shot('r4-waiting-dark');await page.evaluate(()=>inbox.style.display='block');
    await theme('light');await shot('r4-r5-permission-light');
    await page.evaluate(()=>inbox.style.display='none');await shot('r4-waiting-light');await page.evaluate(()=>inbox.style.display='block');
    await inbox.locator('#entry-detail').getByRole('button',{name:"Don't Allow",exact:true}).click();
    await inbox.locator('#entry-detail').getByRole('button',{name:'Allow',exact:true}).waitFor();
    await shot('r12-off-light');await theme('dark');await shot('r12-off-dark');
    // A refusal clears the saved action. A later Allow from the off entry cannot resume it.
    const refusedRead=page.waitForResponse(async response=>response.url().endsWith('/api/apps/wallet-walletconnect/internet')&&response.request().method()==='GET'&&(await response.json()).status==='refused');
    await refusedRead;
    await initialWalletFrame.waitForFunction(()=>window.fixtureIntervals.at(-1)===5000);
    await inbox.locator('#entry-detail button:not(:disabled)').filter({hasText:/^Allow$/}).waitFor();
    for(const value of ['dark','light']){await theme(value);await shot(`r15-off-no-action-${value}`);}

    await inbox.locator('#entry-detail').getByRole('button',{name:'Allow',exact:true}).click();
    await page.waitForResponse(async response=>response.url().endsWith('/api/apps/wallet-walletconnect/internet')&&response.request().method()==='GET'&&(await response.json()).status==='granted');
    assert.equal(await wallet.locator('dialog').count(),0,'later Allow from off entry leaves the saved action cleared');
    assert.equal(methods.filter(method=>method==='wc_proposeSession').length,0);
    await wallet.locator('#wallet-connect').click();
    await wallet.locator('dialog[open] canvas').waitFor({timeout:20000});
    assert.equal(methods.filter(method=>method==='wc_proposeSession').length,1,'Allow continues one pairing');
    assert.equal(await page.locator('#wallet').count(),1);
    assert.equal(await wallet.getByRole('dialog',{name:'Connect wallet',exact:true}).count(),1);
    const canvas=await wallet.locator('canvas').evaluate(canvas=>{const {data}=canvas.getContext('2d').getImageData(0,0,canvas.width,canvas.height);let min=canvas.width;for(let y=0;y<canvas.height;y++)for(let x=0;x<canvas.width;x++)if(data[(y*canvas.width+x)*4]<10)min=Math.min(min,x);return {width:canvas.width,margin:min};});
    assert.ok(canvas.margin>=16,JSON.stringify(canvas));
    for(const value of ['dark','light']){await theme(value);await shot(`r6-r7-r8-r9-qr-${value}`);}
    await page.setViewportSize({width:390,height:844});
    for(const value of ['dark','light']){await theme(value);await shot(`r9-qr-phone-${value}`);}
    assert.ok(await wallet.locator('dialog').evaluate(node=>node.getBoundingClientRect().width<=innerWidth));
    await page.setViewportSize({width:1000,height:850});
    // The continuation must leave status polling free while its first QR is open.
    status='revoked';
    await wallet.locator('#wallet-status').filter({hasText:turnedOff}).waitFor({timeout:10000});
    assert.equal(await wallet.locator('dialog').count(),0);
    status='granted';
    await wallet.locator('#wallet-connect').click();
    await wallet.locator('dialog[open] canvas').waitFor({timeout:20000});
    // Accelerate only the app's 180s deadline; the SDK and production handler stay real.
    await wallet.getByRole('button',{name:'Cancel',exact:true}).click();
    await walletFrame.evaluate(()=>{const native=window.r14NativeTimeout=setTimeout;window.setTimeout=(fn,ms,...args)=>{if(ms===180000)window.r14Expire=fn;return native(fn,ms,...args);};});
    await wallet.locator('#wallet-connect').click();
    await wallet.locator('dialog[open] canvas').waitFor({timeout:20000});
    await walletFrame.evaluate(()=>window.r14Expire());
    await wallet.locator('#wallet-status').filter({hasText:'The QR code expired. Select Connect wallet for a new one.'}).waitFor({timeout:20000});
    assert.equal(await wallet.locator('dialog').count(),0);
    for(const value of ['dark','light']){await theme(value);await shot(`r17-proposal-qr-expired-${value}`);}
    await walletFrame.evaluate(()=>{window.setTimeout=window.r14NativeTimeout;});
    await wallet.locator('#wallet-connect').click();
    await wallet.locator('dialog[open] canvas').waitFor({timeout:20000});
    await page.evaluate(()=>{inbox.style.display='block';inbox.contentWindow.location.reload();});
    const turnOff=inbox.locator('#entry-detail').getByRole('button',{name:'Turn Off',exact:true});await turnOff.click();
    const dialog=inbox.locator('#walletconnect-internet-confirm');await dialog.waitFor();
    assert.equal(await dialog.locator(':focus').textContent(),'Cancel');
    const before=passkeys;
    for(const value of ['dark','light']){await theme(value);await shot(`r5-r14-confirm-${value}`);}
    await dialog.getByRole('button',{name:'Cancel',exact:true}).click();assert.equal(passkeys,before);
    await turnOff.click();await dialog.getByRole('button',{name:'Turn Off',exact:true}).click();
    await wallet.locator('#wallet-status').filter({hasText:turnedOff}).waitFor({timeout:10000});
    assert.equal(await wallet.locator('dialog').count(),0);assert.equal(passkeys,before+1);
    await inbox.locator('#entry-detail').getByRole('button',{name:'Allow',exact:true}).waitFor();
    for(const value of ['dark','light']){await theme(value);await shot(`r5-r12-off-${value}`);await page.evaluate(()=>inbox.style.display='none');await shot(`r15-turned-off-${value}`);await page.evaluate(()=>inbox.style.display='block');}
    const allowed = page.waitForResponse(response=>response.url().endsWith('/api/apps/inbox/actions') && response.request().postDataJSON().action_id.includes('-allow:'));
    await inbox.locator('#entry-detail').getByRole('button',{name:'Allow',exact:true}).click();
    await allowed;
    assert.equal(status,'granted');
    failSummary=true;await Promise.all([walletFrame.waitForNavigation({waitUntil:'load'}),walletFrame.evaluate(()=>location.reload())]);
    try { await wallet.locator('#wallet-status').filter({hasText:'ElastOS could not complete this request. Try again.'}).waitFor({timeout:5000}); } catch(error) {console.log({status:await wallet.locator('#wallet-status').textContent(),hasLaunch:await walletFrame.evaluate(()=>!!location.hash),errors});throw error;}
    for(const value of ['dark','light']){await theme(value);await shot(`r16-error-${value}`);}
    assert.deepEqual(errors,[]);
    assert.equal(actions.filter(action=>action.action_id.includes('-turn-off:')).length,1);
    }
    // Keep the app/client real; this stand-in wallet settles ownership immediately.
    // It lets the next checks place a click between Allow and the next permission poll.
    await page.route('**/vendor/reown-appkit.js?*', route=>route.fulfill({contentType:'text/javascript',body:`
      const provider={chainId:20,connected:true,session:{expiry:Date.now()/1000+3600,namespaces:{eip155:{accounts:['eip155:20:0x'+'12'.repeat(20)]}}},
        signer:{client:{core:{relayer:{connected:true}}}},on(){},request:async({method})=>{
          if(method==='eth_accounts')return ['0x'+'12'.repeat(20)];if(method==='eth_chainId')return 20;
          if(window.phoneWait)await new Promise(resolve=>window.finishPhone=resolve);
          if(window.phoneFailure)throw window.phoneFailure;if(method==='personal_sign'&&window.afterPhoneChain)provider.chainId=window.afterPhoneChain;return '0x'+'ab'.repeat(65);
        }};
      export const connectWalletConnectEvm=async()=>{if(window.proposalFailure)throw window.proposalFailure;return provider;};
      export const disconnectWalletConnectEvm=async()=>{};
    `}));
    failSummary=false;
    const reload=async()=>{
      await walletFrame.evaluate(()=>location.reload());
      await wallet.locator('#wallet-connect').waitFor();
      await wallet.locator('#wallet-requests').getByText(approvalRequests.length?'Fixture review':'No approval requests.',{exact:true}).waitFor();
      await page.evaluate(()=>inbox.style.display='none');
    };
    const settlePermission = async () => {
      await walletFrame.waitForFunction(()=>window.fixtureIntervals.at(-1)===5000);
      await page.waitForResponse(response=>response.url().endsWith('/api/apps/wallet-walletconnect/internet')&&response.request().method()==='GET');
      // Count admission posts as well as completions: a wrongly resumed effect starts here.
      await walletFrame.evaluate(()=>new Promise(resolve=>setTimeout(resolve,100)));
    };
    if(!guardCase || guardCase==='double-run') {
    // Matching Allow resumes once; a new Connect click consumes the old saved action first.
    status='off';await reload();await wallet.locator('#wallet-connect').click();
    await wallet.locator('#wallet-status').filter({hasText:permissionText}).waitFor();await page.evaluate(()=>inbox.style.display='none');
    status='granted';
    await wallet.locator('#wallet-connect').click();
    await wallet.locator('#wallet-status').filter({hasText:'Approval method added.'}).waitFor();
    assert.equal(verified,1);
    const oncePosts=permissionPosts;
    await settlePermission();
    assert.equal(permissionPosts,oncePosts,'double-run: saved Connect cannot start another permission post');
    assert.equal(verified,1,'Connect before the first Allow poll consumes the saved action');
    // An uninterrupted request continues once from its matching Allow.
    status='off';await reload();await wallet.locator('#wallet-connect').click();
    await wallet.locator('#wallet-status').filter({hasText:permissionText}).waitFor();await page.evaluate(()=>inbox.style.display='none');status='granted';
    await wallet.locator('#wallet-status').filter({hasText:'Approval method added.'}).waitFor();
    assert.equal(verified,2);
    }
    const expectedVerified=verified;
    for(const reason of ['refused','revoked','expired','replacement','disconnect','new-link'].filter(reason=>!guardCase||reason===guardCase)) {
      status='off';await reload();await wallet.locator('#wallet-connect').click();
      await wallet.locator('#wallet-status').filter({hasText:permissionText}).waitFor();await page.evaluate(()=>inbox.style.display='none');
      if(reason==='disconnect')await wallet.locator('#wallet-disconnect').click();
      else if(reason==='expired') {
        // Move the frame clock past the stored permission deadline, leaving the grant ID unchanged.
        await walletFrame.evaluate(()=>{const now=Date.now;Date.now=()=>now()+1801000;});
      } else if(reason==='replacement'){requestId++;}
      else if(reason==='new-link') {
        // A fresh link starts while the first permission is still pending.
        await wallet.locator('#wallet-connect').click();
        await wallet.locator('#wallet-connect:enabled').waitFor();
        requestId++; // A later grant of the earlier entry cannot match this new request.
      } else {
        status=reason;
        await page.waitForResponse(async response=>response.url().endsWith('/api/apps/wallet-walletconnect/internet')&&response.request().method()==='GET'&&(await response.json()).status===reason);
      }
      const beforePosts=permissionPosts;
      status='granted';
      await settlePermission();
      assert.equal(permissionPosts,beforePosts,`${reason} clears the saved action before a permission post`);
      assert.equal(verified,expectedVerified,`${reason} clears the saved action`);
    }
    if(guardCase){console.log(`saved-action guard ${guardCase}: PASS`);return;}
    status='requested';requestId++;issuedAt=Math.floor(Date.now()/1000);await reload();
    await walletFrame.waitForFunction(()=>window.fixtureIntervals.at(-1)===1000);
    status='granted';
    await walletFrame.waitForFunction(()=>window.fixtureIntervals.at(-1)===5000);
    assert.equal(verified,2,'a restored permission request polls promptly without a saved action');
    approvalRequests=[{request_id:'approval-fixture',connector_id:'wallet-walletconnect',proof_type:'siwe',intent:'browser_personal_sign',status:'pending',address:'0x'+'12'.repeat(20),reason:'Fixture review',chain_namespace:'eip155:20',expires_at:Math.floor(Date.now()/1000)+600}];
    status='off';await reload();await wallet.locator('#wallet-connect').click();
    await wallet.locator('#wallet-status').filter({hasText:permissionText}).waitFor();await page.evaluate(()=>inbox.style.display='none');
    await page.evaluate(()=>inbox.style.display='none');
    await wallet.locator('[data-wallet-request-sign]').click();
    await wallet.locator('#wallet-status').filter({hasText:permissionText}).waitFor();await page.evaluate(()=>inbox.style.display='none');status='granted';
    await wallet.locator('#wallet-status').filter({hasText:'Request signed.'}).waitFor();
    assert.equal(completions,1,'a new review replaces the saved link and runs once');
    assert.equal(verified,2,'a new review clears the older saved ownership signature');
    approvalRequests=[];
    // Capture the real client error rendering with a deterministic phone wallet.
    status='granted';await reload();
    const freshRequest = (intent='browser_personal_sign',chain='eip155:20') => ({request_id:'approval-fixture',connector_id:'wallet-walletconnect',proof_type:'siwe',intent,status:'pending',address:'0x'+'12'.repeat(20),reason:'Fixture review',chain_namespace:chain,expires_at:Math.floor(Date.now()/1000)+600});
    const endings=[['decline',{code:4001,message:'User rejected.'},'Declined'],['timeout',{code:6,message:'Request expired. Please try again.'},'Timeout',true],['error-32000',{code:-32000,message:'Private library text'},'Error'],['error5100',{code:5100,message:'Private library text'},'Error']];
    for(const scope of ['proposal','ownership','signature','transaction']) for(const [ending,error,suffix,sdkError] of endings){
      const linking=['proposal','ownership'].includes(scope);
      const key=scope==='proposal'?'proposalFailure':'phoneFailure';
      const phoneError=scope==='proposal'&&ending==='timeout'?{message:'The QR code expired. Select Connect wallet for a new one.'}:error;
      const message=scope==='proposal'&&ending==='timeout'?phoneError.message:messages[`${linking&&suffix!=='Declined'?'link':scope}${suffix}`];
      approvalRequests=linking?[]:[freshRequest(scope==='transaction'?'transaction_intent':'browser_personal_sign')];
      await reload();
      await walletFrame.evaluate(({key,error,sdkError})=>{window[key]=sdkError?Object.assign(new Error(error.message),error.code===undefined?{}:{code:error.code}):error;},{key,error:phoneError,sdkError});
      const review=wallet.locator('[data-wallet-request-sign]');
      await (linking?wallet.locator('#wallet-connect'):review).click();
      await wallet.locator('#wallet-status').filter({hasText:message}).waitFor();
      assert.equal(await wallet.locator('#wallet-status').getAttribute('data-tone'),'muted');
      if(!linking)await walletFrame.waitForFunction(()=>!document.querySelector('[data-wallet-request-sign]'));
      if(scope!=='proposal')await wallet.locator('#wallet-connection').filter({hasText:/^Connected$/}).waitFor();
      for(const value of ['dark','light']){await theme(value);await shot(`r17-${scope}-${ending}-${value}`);}
      if(!linking) {
        assert.equal(approvalRequests[0].status,'approved','handoff consumes the pending request');
        if(scope==='transaction')assert.equal(await wallet.locator('.wallet-request p').textContent(),messages.transactionRecovery);
        else assert.equal(await wallet.locator('.wallet-request').count(),0,'consumed signature leaves the list');
        // Dispatch the stale Review once more through the actual click handler.
        const posts=permissionPosts;
        await walletFrame.evaluate(()=>{const button=document.createElement('button');button.dataset.walletRequestSign='approval-fixture';document.querySelector('#wallet-requests').append(button);button.click();});
        await wallet.locator('#wallet-status').filter({hasText:messages.consumed}).waitFor();
        await walletFrame.waitForFunction(()=>!document.querySelector('[data-wallet-request-sign]'));
        assert.equal(permissionPosts,posts+1,'second Review reaches admission once but cannot dispatch to the phone');
        for(const value of ['dark','light']){await theme(value);await shot(`r16-consumed-${scope}-${ending}-${value}`);}
      }
    }
    for(const [chain,key] of [['eip155:137','unsupported'],['eip155:8453','unapproved']]) {
      approvalRequests=[freshRequest('browser_personal_sign',chain)];await reload();
      if(key==='unsupported') {
        await wallet.locator('.wallet-request p').filter({hasText:messages.pendingUnsupportedNetwork('137')}).waitFor();
        assert.equal(await wallet.locator('[data-wallet-request-sign]').count(),0,'an unoffered network has no dead Review action');
        // An older rendered control also gets the same safe explanation.
        await walletFrame.evaluate(()=>{const button=document.createElement('button');button.dataset.walletRequestSign='approval-fixture';document.querySelector('#wallet-requests').append(button);button.click();});
      } else await wallet.locator('[data-wallet-request-sign]').click();
      await wallet.locator('#wallet-status').filter({hasText:key==='unsupported'?messages.unsupportedNetwork('137'):messages.unapprovedNetwork('Base')}).waitFor();
      await wallet.locator('#wallet-connection').filter({hasText:/^Connected$/}).waitFor();
      assert.equal(approvalRequests[0].status,'pending','unsupported network stays available for rejection in Wallet');
      for(const value of ['dark','light']){await theme(value);await shot(`r16-${key}-${value}`);}
    }
    // A network check can also fail after a consumed signature, when Reject is gone.
    approvalRequests=[freshRequest()];await reload();
    await walletFrame.evaluate(()=>window.afterPhoneChain=137);
    await wallet.locator('[data-wallet-request-sign]').click();
    await wallet.locator('#wallet-status').filter({hasText:messages.unsupportedNetwork('137')}).waitFor();
    await walletFrame.waitForFunction(()=>!document.querySelector('[data-wallet-request-sign]'));
    assert.equal(approvalRequests[0].status,'approved');
    assert.equal(await wallet.locator('#wallet-status').getAttribute('data-tone'),'muted');
    await wallet.locator('#wallet-connection').filter({hasText:/^Connected$/}).waitFor();
    for(const value of ['dark','light']){await theme(value);await shot(`r16-post-handoff-network-${value}`);}
    // A Home return while the phone is waiting must render a disabled Review.
    approvalRequests=[freshRequest()];await reload();
    await walletFrame.evaluate(()=>window.phoneWait=true);
    await wallet.locator('[data-wallet-request-sign]').click();
    await walletFrame.waitForFunction(()=>typeof window.finishPhone==='function');
    // Use the same origin-bound message that Home sends when it returns this window.
    await walletFrame.evaluate(()=>window.dispatchEvent(new MessageEvent('message',{source:window.parent,origin:'null',data:{type:'elastos:shell-layout',layout:{visible:true}}})));
    await wallet.locator('#wallet-requests').getByText('No approval requests.',{exact:true}).waitFor();
    // Another pending request can appear during this wait, but its Review stays disabled.
    approvalRequests.push({...freshRequest(),request_id:'approval-next'});await walletFrame.evaluate(()=>window.dispatchEvent(new MessageEvent('message',{source:window.parent,origin:'null',data:{type:'elastos:shell-layout',layout:{visible:true}}})));
    await wallet.locator('[data-wallet-request-sign="approval-next"]:disabled').waitFor();
    assert.equal(approvalRequests.find(r=>r.request_id==='approval-fixture').status,'approved','Home return preserves the consumed request');
    assert.equal(await wallet.locator('[data-wallet-request-sign="approval-fixture"]').count(),0);
    // Hold a valid pending snapshot from a Home return until the next request ends.
    await walletFrame.evaluate(()=>{
      window.fixtureApprovalReads=0;const nativeFetch=window.fetch.bind(window);
      window.fetch=async(...args)=>{const response=await nativeFetch(...args);
        if(String(args[0]).endsWith('/wallet/approvals')){const nativeJson=response.json.bind(response);response.json=async()=>{const value=await nativeJson();window.fixtureApprovalReads++;return value;};}
        return response;
      };
    });
    const held=new Promise(resolve=>approvalListHeld=resolve);holdApprovalList=true;
    await walletFrame.evaluate(()=>window.dispatchEvent(new MessageEvent('message',{source:window.parent,origin:'null',data:{type:'elastos:shell-layout',layout:{visible:true}}})));
    await held;
    await walletFrame.evaluate(()=>{window.phoneFailure={code:4001,message:'User rejected.'};window.finishPhone();});
    await wallet.locator('#wallet-status').filter({hasText:messages.signatureDeclined}).waitFor();
    await wallet.locator('[data-wallet-request-sign="approval-next"]:enabled').waitFor();
    await walletFrame.evaluate(()=>{delete window.phoneWait;delete window.phoneFailure;});
    await wallet.locator('[data-wallet-request-sign="approval-next"]').click();
    await wallet.locator('#wallet-status').filter({hasText:'Request signed.'}).waitFor();
    await wallet.locator('#wallet-requests').getByText('No approval requests.',{exact:true}).waitFor();
    assert.equal(completions,2,'the next request works after the phone reply ends');
    assert.equal(approvalRequests.find(r=>r.request_id==='approval-next').status,'completed');
    const reads=await walletFrame.evaluate(()=>window.fixtureApprovalReads);
    releaseApprovalList();
    await walletFrame.waitForFunction(reads=>window.fixtureApprovalReads>reads,reads);
    assert.equal(await wallet.locator('[data-wallet-request-sign]').count(),0,'a late Home return cannot restore a consumed Review');
    assert.deepEqual(errors,[]);
  } finally {await browser?.close();for(const socket of relay.clients)socket.terminate();await new Promise(resolve=>relay.close(resolve));server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
});

// Exercise the real window module while Runtime changes its list during a link or disconnect.
for (const ending of ['decline','expiry','cancel','disconnect']) for (const returning of ['focus','Home']) {
  test(`request controls recover after ${ending} and ${returning} return`,{timeout:20000},async()=>{
    const pending=id=>({request_id:id,connector_id:'wallet-walletconnect',proof_type:'siwe',intent:'browser_personal_sign',status:'pending',address:'0x'+'12'.repeat(20),reason:id,chain_namespace:'eip155:20',expires_at:Math.floor(Date.now()/1000)+600});
    let requests=[pending('first')];
    const server=http.createServer((req,res)=>{
      const path=new URL(req.url,'http://localhost').pathname;
      const json=value=>{res.setHeader('content-type','application/json');res.end(JSON.stringify(value));};
      if(path==='/'){res.setHeader('content-type','text/html');res.end('<iframe id="wallet" style="width:100%;height:800px" src="/apps/wallet-walletconnect/?home_origin='+encodeURIComponent(`http://127.0.0.1:${server.address().port}`)+'#home_token=fixture-window"></iframe>');return;}
      if(path.endsWith('/internet'))return json({status:'granted'});
      if(path.endsWith('/wallet/config'))return json({walletconnect:{project_id:'fixture-project',storage_revision:'"0"'}});
      if(path.endsWith('/wallet/accounts'))return json({accounts:[]});
      if(path.endsWith('/wallet/approvals'))return json({approval_requests:requests});
      if(path.endsWith('/challenge'))return json({message:'Fixture ownership',expires_at:Math.floor(Date.now()/1000)+600});
      if(path.endsWith('/verify')||path.endsWith('/storage'))return json({});
      const match=path.match(/^\/apps\/(wallet-walletconnect|home)\/(.*)$/);
      if(match){const root=resolve('capsules',match[1],'browser');const file=resolve(root,match[2]||'index.html');assert.ok(!relative(root,file).startsWith('..'));res.setHeader('content-type',({'.js':'text/javascript','.mjs':'text/javascript','.css':'text/css','.html':'text/html'})[extname(file)]||'application/octet-stream');res.end(readFileSync(file));return;}
      res.writeHead(404).end();
    });
    await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));const origin=`http://127.0.0.1:${server.address().port}`;
    let browser;
    try {
      const {chromium}=await importProductSmokePlaywright();browser=await chromium.launch({headless:true,...productSmokeLaunchOptions()});const page=await browser.newPage();
      await page.route('**/*',route=>new URL(route.request().url()).origin===origin?route.continue():route.abort());
      await page.route('**/vendor/reown-appkit.js?*',route=>route.fulfill({contentType:'text/javascript',body:`
        const provider={chainId:20,connected:true,session:{expiry:Date.now()/1000+3600,namespaces:{eip155:{accounts:['eip155:20:0x'+'12'.repeat(20)]}}},signer:{client:{core:{relayer:{connected:true}}}},on(){},async request({method}){return method==='eth_accounts'?['0x'+'12'.repeat(20)]:method==='eth_chainId'?20:'0x'+'ab'.repeat(65);}};
        export async function connectWalletConnectEvm(){
          if(window.holdLink){const dialog=document.createElement('dialog'),cancel=document.createElement('button');cancel.textContent='Cancel';dialog.append(cancel);document.body.append(dialog);dialog.showModal();try{await new Promise((resolve,reject)=>{window.endLink=reject;cancel.onclick=()=>reject(new Error('Wallet connection cancelled.'));});}finally{dialog.remove();}}
          return provider;
        }
        export async function disconnectWalletConnectEvm(){if(window.holdDisconnect)await new Promise(resolve=>window.endDisconnect=resolve);}
      `}));
      await page.goto(origin);const frame=page.frames().find(frame=>frame.url().includes('/apps/wallet-walletconnect/'));const wallet=page.frameLocator('#wallet');
      await wallet.locator('[data-wallet-request-sign="first"]:enabled').waitFor();
      if(ending==='disconnect'){
        await wallet.locator('#wallet-connect').click();await wallet.locator('#wallet-status').filter({hasText:'Approval method added.'}).waitFor();
        await frame.evaluate(()=>window.holdDisconnect=true);await wallet.locator('#wallet-disconnect').click();await frame.waitForFunction(()=>!!window.endDisconnect);
      }else{
        await frame.evaluate(()=>window.holdLink=true);await wallet.locator('#wallet-connect').click();await wallet.locator('dialog[open]').waitFor();
      }
      await frame.evaluate(returning=>{if(returning==='focus')window.dispatchEvent(new Event('focus'));else window.dispatchEvent(new MessageEvent('message',{source:window.parent,origin:'null',data:{type:'elastos:shell-layout',layout:{visible:true}}}));},returning);
      await wallet.locator('[data-wallet-request-sign="first"]:disabled').waitFor();
      // Runtime may change the list while the window is waiting. Ending the action must fetch it again.
      requests=[pending('next'),{...pending('unsupported'),chain_namespace:'eip155:137'},{...pending('sent'),intent:'transaction_intent',status:'approved'}];
      if(ending==='disconnect')await frame.evaluate(()=>window.endDisconnect());
      else if(ending==='cancel')await wallet.getByRole('button',{name:'Cancel',exact:true}).click();
      else await frame.evaluate(ending=>window.endLink(ending==='decline'?{code:4001,message:'User rejected.'}:new Error('The QR code expired. Select Connect wallet for a new one.')),ending);
      await wallet.locator('#wallet-status').filter({hasText:ending==='disconnect'?'Disconnected. Linked accounts stay in Wallet.':ending==='cancel'?messages.cancelled:ending==='expiry'?'The QR code expired. Select Connect wallet for a new one.':messages.proposalDeclined}).waitFor();
      // Wait for a possible final refresh, then inspect without any extra focus or visibility event.
      await wallet.locator('#wallet-connect:enabled').waitFor();await frame.evaluate(()=>new Promise(resolve=>setTimeout(resolve,100)));
      assert.equal(await wallet.locator('[data-wallet-request-sign="first"]').count(),0,'ending the action refreshes the stale list');
      assert.equal(await wallet.locator('[data-wallet-request-sign="next"]').isEnabled(),true,'the pending request is ready for Review');
      assert.equal(await wallet.locator('[data-wallet-request-sign]').count(),1,'unsupported and approved requests have their own recovery controls');
      assert.equal(await wallet.getByText(messages.pendingUnsupportedNetwork('137'),{exact:true}).count(),1);
      assert.equal(await wallet.getByText(messages.transactionRecovery,{exact:true}).count(),1);
    }finally{await browser?.close();server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
  });
}

// Round 18 replays the installed Home's replies, including its stale-revision 500.
// The page, window module, client, adapter and pinned SDK are production code.
for (const journey of ['A','B']) test(`round18 ${journey}: the open window recovers after Allow`, {timeout:90000}, async t => {
  let status='granted', revision=journey==='A'?11:12, keys={}, requestId='installed-request', polls=0;
  const failures=[];
  const consent=()=>({status,request:['requested','granted'].includes(status)?{
    id:requestId,issued_at:Math.floor(Date.now()/1000),resource:'elastos://walletconnect/internet',
    text:status==='granted'?'Stop WalletConnect relay access on this computer.':
      readFileSync('elastos/crates/elastos-server/src/api/gateway_walletconnect.rs','utf8').match(/const CONSENT: &str = "([^"]+)"/)[1],
  }:null});
  const server=http.createServer(async(req,res)=>{
    const path=new URL(req.url,'http://fixture').pathname;
    const json=value=>{res.setHeader('content-type','application/json');res.end(JSON.stringify(value));};
    if(path==='/') {res.setHeader('content-type','text/html');res.end('<iframe id="wallet" style="border:0;width:100%;height:96vh" src="/apps/wallet-walletconnect/?home_origin='+encodeURIComponent(`http://127.0.0.1:${server.address().port}`)+'#home_token=fixture-wallet"></iframe>');return;}
    if(path.endsWith('/internet')) {if(req.method==='GET')polls++;if(req.method==='POST'&&!['requested','granted'].includes(status)){status='requested';requestId='replacement-request';}json(consent());return;}
    if(path.endsWith('/wallet/config')) {json({walletconnect:{project_id:'fixture-project',storage_revision:`"${revision}"`}});return;}
    if(path.endsWith('/wallet/accounts')) {json({accounts:[]});return;}
    if(path.endsWith('/wallet/approvals')) {json({approval_requests:[]});return;}
    if(path.endsWith('/storage')&&req.method==='DELETE') {keys={};revision++;json({});return;}
    if(path.endsWith('/storage')||path.endsWith('/relay-admission')) {
      if((req.headers['if-match']||'"0"')!==`"${revision}"`) {
        const body='WalletConnect session changed. Close this window and open WalletConnect again.';
        failures.push({method:req.method,route:path,status:500,body,sent:req.headers['if-match'],expected:`"${revision}"`});res.writeHead(500);res.end(body);return;
      }
      if(path.endsWith('/relay-admission')) {json({token:'fixture-admission'});return;}
      let body='';for await(const chunk of req)body+=chunk;
      if(req.method==='POST'){const {key,value}=JSON.parse(body);if(value===null)delete keys[key];else keys[key]=value;}
      json(keys);return;
    }
    const match=path.match(/^\/apps\/(wallet-walletconnect|home)\/(.*)$/);
    if(match){const root=resolve('capsules',match[1],match[2].startsWith('vendor/')?'':'browser');const file=resolve(root,match[2]||'index.html');assert.ok(!relative(root,file).startsWith('..'));res.setHeader('content-type',({'.js':'text/javascript','.mjs':'text/javascript','.css':'text/css','.html':'text/html'})[extname(file)]||'application/octet-stream');res.end(process.env.WALLETCONNECT_SOURCE_REF?execFileSync('git',['show',`${process.env.WALLETCONNECT_SOURCE_REF}:${relative(process.cwd(),file)}`],{maxBuffer:4*1024*1024}):readFileSync(file));return;}
    res.writeHead(404).end();
  });
  const {relay,methods}=walletConnectRelayFixture(server);
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  let browser;
  try {
    const {chromium}=await importProductSmokePlaywright();browser=await chromium.launch({headless:true,...productSmokeLaunchOptions()});
    const page=await browser.newPage({viewport:{width:1000,height:850}});
    const origin=`http://127.0.0.1:${server.address().port}`;
    await page.route('**/*',route=>new URL(route.request().url()).origin===origin?route.continue():route.abort());
    await page.goto(origin);
    const wallet=page.frameLocator('#wallet'),frame=page.frames().find(f=>f.url().includes('/apps/wallet-walletconnect/'));
    const text=()=>wallet.locator('#wallet-status').innerText();
    const nextPoll=async()=>{const before=polls;await page.waitForFunction(()=>true);for(let i=0;polls===before&&i<70;i++)await page.waitForTimeout(100);assert.ok(polls>before);await frame.evaluate(()=>new Promise(resolve=>setTimeout(resolve,50)));};
    await wallet.locator('#wallet-connect').click();await wallet.locator('dialog[open] canvas').waitFor({timeout:20000});
    if(journey==='A') {
      await wallet.getByRole('button',{name:'Cancel',exact:true}).click();
      await wallet.locator('#wallet-status').filter({hasText:messages.cancelled}).waitFor();
      await t.test('own Cancel has neutral tone',async()=>assert.equal(await wallet.locator('#wallet-status').getAttribute('data-tone'),'muted'));
      status='revoked';revision++;keys={};
      await wallet.locator('#wallet-connect:enabled').click();
      await wallet.locator('#wallet-status').filter({hasText:permissionText}).waitFor();
      status='refused';await nextPoll();
      await t.test('refusal gives a true sentence and a working next step',async()=>assert.equal(await text(),'Internet access for WalletConnect was refused. Select Allow in Inbox, then Connect wallet.'));
    } else {
      status='revoked';revision++;keys={};await wallet.locator('#wallet-status').filter({hasText:turnedOff}).waitFor({timeout:10000});
      assert.equal(await wallet.locator('dialog[open]').count(),0,'Turn Off removes the QR');
    }
    status='granted';await nextPoll();
    await t.test('Allow replaces the old permission sentence',async()=>assert.equal(await text(),'Internet access is allowed. Select Connect wallet to continue.'));
    const before=methods.filter(m=>m==='wc_proposeSession').length;
    await wallet.locator('#wallet-connect:enabled').click();
    await t.test('one Connect produces a QR in the same window',async()=>{
      await wallet.locator('dialog[open] canvas').waitFor({timeout:15000});
      assert.equal(methods.filter(m=>m==='wc_proposeSession').length,before+1);
      assert.equal(page.frames().find(f=>f.url().includes('/apps/wallet-walletconnect/')),frame);
      if(process.env.WALLETCONNECT_SCREENSHOTS){mkdirSync(process.env.WALLETCONNECT_SCREENSHOTS,{recursive:true});for(const theme of ['dark','light']){await frame.evaluate(theme=>document.documentElement.dataset.elTheme=theme,theme);await page.waitForTimeout(200);await frame.waitForFunction(()=>{const c=document.querySelector('dialog[open] canvas');return c&&c.getContext('2d').getImageData(0,0,c.width,c.height).data.some((v,i)=>i%4===0&&v<10);});await page.screenshot({path:`${process.env.WALLETCONNECT_SCREENSHOTS}/r18-${journey}-allowed-qr-${theme}.png`});}}
    });
    await t.test('Cancel has neutral tone',async()=>{
      if(await wallet.locator('dialog[open]').count())await wallet.getByRole('button',{name:'Cancel',exact:true}).click();
      await wallet.locator('#wallet-status').filter({hasText:messages.cancelled}).waitFor({timeout:3000});
      assert.equal(await text(),messages.cancelled);assert.equal(await wallet.locator('#wallet-status').getAttribute('data-tone'),'muted');
    });
    // A stale SDK is still fenced by the exact installed response, rather than
    // silently acquiring the new revision. The fresh adapter can recover anyway.
    for(const failure of failures)assert.equal(failure.body,'WalletConnect session changed. Close this window and open WalletConnect again.');
  } finally {await browser?.close();for(const client of relay.clients)client.terminate();await new Promise(resolve=>relay.close(resolve));server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
});
