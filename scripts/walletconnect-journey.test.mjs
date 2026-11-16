import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {readFileSync,mkdirSync} from 'node:fs';
import {extname,resolve,relative} from 'node:path';
import {importProductSmokePlaywright,productSmokeLaunchOptions} from './product-smoke-browser.mjs';
import {walletConnectRelayFixture} from './lib/walletconnect-relay-fixture.mjs';
const permissionText = 'WalletConnect needs internet access. Answer the request in Inbox. If it is no longer there, select Connect wallet to ask again.';
const turnedOff = 'Internet access for WalletConnect was turned off. Select Connect wallet to ask again.';
// API and passkey responses are fixtures. All app markup, scripts, CSS and SDK are real.
test('WalletConnect permission, expiry and Turn Off journeys in real capsules',{timeout:55000},async()=>{
  let status='off',requestId=0,passkeys=0,failSummary=false,keys={};
  const consent=()=>({status,request:['requested','granted'].includes(status)?{id:String(requestId),text:'Fixture consent'}:null});
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
      if(path==='/api/apps/wallet-walletconnect/internet'){if(req.method==='POST'&&status!=='granted'&&status!=='requested'){status='requested';requestId++;}json(consent());return;}
      if(path==='/api/apps/wallet-walletconnect/wallet/config'){json({walletconnect:{project_id:'fixture-project',storage_revision:'"0"'}});return;}
      if(path.endsWith('/wallet/accounts')){if(failSummary){res.writeHead(500);res.end();}else json({accounts:[]});return;}
      if(path.endsWith('/wallet/approvals')){json({approval_requests:[]});return;}
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
    await page.goto(`http://127.0.0.1:${server.address().port}`);
    const wallet=page.frameLocator('#wallet'),inbox=page.frameLocator('#inbox');
    const screenshotNames=new Set((process.env.WALLETCONNECT_SCREENSHOT_NAMES||'').split(',').filter(Boolean));
    const shot=async(name)=>{if(evidence&&(!screenshotNames.size||screenshotNames.has(name)))await page.screenshot({path:`${evidence}/${name}.png`});};
    const theme=async value=>{for(const frame of page.frames())if(frame!==page.mainFrame())await frame.evaluate(value=>document.documentElement.dataset.elTheme=value,value);};
    await wallet.locator('#wallet-connect').click();
    await wallet.locator('#wallet-status').filter({hasText:permissionText}).waitFor();
    assert.equal(await wallet.locator('#wallet-status').getAttribute('data-tone'),'muted');
    await theme('dark');await shot('r4-r5-permission-dark');
    await page.evaluate(()=>inbox.style.display='none');await shot('r4-waiting-dark');await page.evaluate(()=>inbox.style.display='block');
    await theme('light');await shot('r4-r5-permission-light');
    await page.evaluate(()=>inbox.style.display='none');await shot('r4-waiting-light');await page.evaluate(()=>inbox.style.display='block');
    await inbox.locator('#entry-detail').getByRole('button',{name:"Don't Allow",exact:true}).click();
    await inbox.locator('#entry-detail').getByRole('button',{name:'Allow',exact:true}).waitFor();
    await shot('r12-off-light');await theme('dark');await shot('r12-off-dark');
    // Allow again resumes only the action saved in the original window.
    await inbox.locator('#entry-detail').getByRole('button',{name:'Allow',exact:true}).click();
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
    const walletFrame=page.frames().find(frame=>frame.url().includes('/apps/wallet-walletconnect/'));
    await walletFrame.evaluate(()=>{const native=window.r14NativeTimeout=setTimeout;window.setTimeout=(fn,ms,...args)=>{if(ms===180000)window.r14Expire=fn;return native(fn,ms,...args);};});
    await wallet.locator('#wallet-connect').click();
    await wallet.locator('dialog[open] canvas').waitFor({timeout:20000});
    await walletFrame.evaluate(()=>window.r14Expire());
    await wallet.locator('#wallet-status').filter({hasText:'The QR code expired. Select Connect wallet for a new one.'}).waitFor({timeout:20000});
    assert.equal(await wallet.locator('dialog').count(),0);
    for(const value of ['dark','light']){await theme(value);await shot(`r10-expired-${value}`);}
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
  } finally {await browser?.close();for(const socket of relay.clients)socket.terminate();await new Promise(resolve=>relay.close(resolve));server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
});
