import assert from 'node:assert/strict';
import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { resolve, extname, join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
const baseFixture = JSON.parse(await readFile(new URL('../fixtures/wallet-extension-window-base.json', import.meta.url), 'utf8'));
for (const file of Object.values(baseFixture.files)) assert.equal(createHash('sha256').update(file.source).digest('hex'), file.sha256);
import { installScriptedExtension, replayInput } from '../wallet-extension-test/index.mjs';
const root = resolve('.');
const A = '0x' + '1'.repeat(40), U = 'bc1q' + 'a'.repeat(38);
// Runtime handoff is one-use: wallet-provider/src/approval.rs:486-490 marks
// Approved, and :362 omits it from the pending list. Home checks the signer later.
// This provider exercises the live Home controller with isolated test results.
// Recorded peers below are kept separate and retain their exact parameters.
function installProvider({ kind, address }) {
  if (window !== window.top) return;
  window.testState = { mode: 'approve', address, chain: '0x1', linked: false, requests: [], calls: [], receipts: [], effects: [], copies: [], pending: [] };
  const listeners = new Map();
  const provider = { on(name, callback) { listeners.set(name, callback); },
    async request({ method, params }) {
      const s = testState; s.calls.push({ method, params, chain: s.chain, signer: s.walletAddress ?? s.address });
      if (method === 'eth_accounts') return [s.walletAddress ?? s.address];
      if (method === 'eth_chainId') return s.chain;
      if (method === 'wallet_switchEthereumChain') { if(s.refuseSwitch) return null; if (!s.added) throw {code:4902}; s.chain=params[0].chainId; return null; }
      if (method === 'wallet_addEthereumChain') { s.added=true; s.chain=params[0].chainId; return null; }
      if (method === 'eth_sendTransaction') return ask(method,'0x'+'aa'.repeat(32));
      return ask(method, method === 'eth_requestAccounts' ? [s.walletAddress ?? s.address] : '0x' + 'ab'.repeat(65));
    },
    async requestAccounts() { testState.calls.push({ method: 'requestAccounts' }); return ask('requestAccounts', [testState.walletAddress ?? testState.address]); },
    async getAccounts() { testState.calls.push({ method: 'getAccounts' }); return [testState.walletAddress ?? testState.address]; },
    async getNetwork() { testState.calls.push({ method: 'getNetwork' }); return testState.network ?? 'livenet'; },
    async signMessage() { testState.calls.push({ method: 'signMessage' }); return ask('signMessage', 'fixture-signature'); },
  };
  function ask(method, result) {
    if (testState.mode === 'pending') return new Promise((resolve, reject) => testState.pending.push({ resolve, reject, method, result }));
    if (testState.mode === 'decline' || testState.mode === 'closed') return Promise.reject({ code: 4001, message: 'User rejected the request.' });
    return Promise.resolve(result);
  }
  window.emitWallet = (name, value) => listeners.get(name)?.(value);
  window.addEventListener('eip6963:requestProvider', () => window.dispatchEvent(new CustomEvent('eip6963:announceProvider', { detail: { info: { rdns: 'io.metamask', uuid: 'test' }, provider } })));
  if (kind === 'unisat') window.unisat = provider;
}

export async function fixture(browser, kind, { saved = false, requests = false, recording, mutate, oldHost = false, oldWindow = false, readFailure = null, launch = true, noHomeWallet = false, extraHomeAccount = false, pictures = true, pictureContext = null } = {}) {
  const address = kind === 'metamask' ? A : U;
  const context = await browser.newContext({ viewport: { width: 480, height: 560 }, colorScheme: 'dark' });
  const replay = recording ? await replayInput(recording) : null;
  const firstCase = replay?.fixture.cases.find(c => c.id === replay.spec.calls[0]?.id);
  const peerElapsed = firstCase?.snapshots.filter(s => s.call).at(-1)?.call.elapsed_ms;
  if (recording) {
    await context.addInitScript(({ source, input }) => { if (window === window.top) (0, eval)(`(${source})`)(input); }, { source: installScriptedExtension.toString(), input: replay });
    await context.addInitScript(({ address }) => { if (window === window.top) window.testState = { address, linked: false, requests: [], receipts: [], effects: [], copies: [], calls: [] }; }, { address });
  } else await context.addInitScript(installProvider, { kind, address });
  const errors = [], reads = []; 
  const top = await context.newPage(); top.on('pageerror', e => errors.push(e.message));
  await top.clock.install();
  await context.route('**/*', async route => {
    const url = new URL(route.request().url());
    assert.equal(url.hostname, 'extensions.test', 'all harness traffic stays local');
    if (url.pathname === '/') return route.fulfill({ contentType: 'text/html', body: `<!doctype html><body style="margin:0"><script type="module">
import { handleHomeWalletConnectorEffect } from '/apps/home/home-wallet-connector-host.js';
const kind=${JSON.stringify(kind)}, id='wallet-'+kind;
const state=window.testState;
state.linked=${saved};
if(${JSON.stringify(requests)}) state.requests=[{request_id:'approval-1',status:'pending',intent:${JSON.stringify(requests)}==='transaction'?'transaction_intent':${JSON.stringify(requests)}==='typed'?'browser_typed_data_sign':kind==='metamask'?'browser_personal_sign':'bitcoin_bip322_proof',proof_type:kind==='metamask'?'siwe':'bip322_simple',capsule_id:'browser',reason:'Test signing',requesting_origin:'https://shop.example.com',connector_id:id,address:state.address,chain_namespace:kind==='metamask'?(${JSON.stringify(requests)}==='transaction'?'eip155:20':'eip155:1'):'bip122:000000000019d6689c085ae165831e93',expires_at:Math.floor(Date.now()/1000)+300}];
if(${JSON.stringify(requests)}==='multiple') state.requests.push({...state.requests[0],request_id:'approval-2',reason:'Second test signing'});
const lifetime={retired:false,generation:'document-1'}, walletEffectState={inFlight:false,requestIds:new Set()};
addEventListener('message',event=>{
 if(event.source!==document.querySelector('iframe')?.contentWindow) return;
 const data=event.data;
 if(data.type==='home:wallet-connector-effect') {state.effects.push(data);handleHomeWalletConnectorEffect(event,{kind:'app-frame',targetId:id,homeToken:'fixture-token',source:event.source,clipboardState:lifetime,walletEffectState},data);}
 if(data.type==='home:close-self')state.closed=true;
 if(data.type==='fixture:copy')state.copies.push(data.value);
});
window.runtimeFetch=async(url,init)=>{
 state.runtimeCalls||=[];state.runtimeCalls.push({url,body:JSON.parse(init.body)});
 if (${noHomeWallet} && url.includes('/link/challenge')) throw Error('Create a Home wallet first.');
 const requestId=decodeURIComponent(url.split('/approvals/')[1]?.split('/')[0]||'');
 const body=JSON.parse(init.body), schema='elastos.home.wallet-connector.effect.result/v1';
 if(url.endsWith('/handoff')){
   const pending=state.requests.find(request=>request.request_id===requestId && request.status==='pending');
   if(!pending)throw Error('wallet approval request not found');
   pending.status='approved';
 }
 const action=url.includes('/link/challenge')?(kind==='metamask'?'evm_link_challenge':'bitcoin_link_challenge'):url.includes('/link/verify')?(kind==='metamask'?'evm_link_complete':'bitcoin_link_complete'):url.endsWith('/handoff')?'approval_handoff':'approval_complete';
 if(url.includes('/link/challenge') && state.accountDuringChallenge) state.walletAddress=state.accountDuringChallenge;
 if(url.includes('/link/challenge'))return {schema,action,connector_id:id,challenge:{schema:kind==='metamask'?'elastos.auth.challenge/v1':'elastos.wallet.bitcoin_challenge/v1',challenge_id:'fixture-challenge',message:'Isolated account proof',expires_at:Math.floor(Date.now()/1000)+300,resources:[],...(kind==='unisat'?{network:'bitcoin',address:state.address,proof_type:'bip322_simple'}:{})}};
 if(url.includes('/link/verify')){state.linked=true;state.receipts.push(body);return {schema,action,connector_id:id,status:'linked'};}
 if(url.endsWith('/handoff')&&${JSON.stringify(requests)}==='transaction') return {schema,action,connector_id:id,request_id:requestId,evm_chains:[{chainId:'0x14',chainName:'Elastos Smart Chain',nativeCurrency:{name:'ELA',symbol:'ELA',decimals:18},rpcUrls:['https://api.elastos.io/esc']}],handoff:{schema:'elastos.wallet.webconnect_handoff/v1',request_id:requestId,intent:'transaction_intent',payload_hash:'0x'+'ab'.repeat(32),signer:state.address,status:'awaiting_wallet_transaction',transaction:{from:state.address,to:'0x'+'2'.repeat(40),value:'0x1',data:'0x',gas:'0x5208',gasPrice:'0x1',nonce:'0x0',chainId:'0x14'}}};
 if(url.endsWith('/handoff'))return {schema,action,connector_id:id,request_id:requestId,evm_chains:[],handoff:{schema:'elastos.wallet.webconnect_handoff/v1',request_id:requestId,intent:${JSON.stringify(requests)}==='transaction'?'transaction_intent':${JSON.stringify(requests)}==='typed'?'browser_typed_data_sign':kind==='metamask'?'browser_personal_sign':'bitcoin_bip322_proof',payload_hash:'0x'+'ab'.repeat(32),signer:state.address,status:'awaiting_wallet_signature',message:'Isolated app request',signature_type:kind==='metamask'?'personal_sign':'bip322_simple'}};
 state.receipts.push(body);state.requests=state.requests.filter(r=>r.request_id!==requestId);return {schema,action,connector_id:id,request_id:requestId,status:'completed'};
};
const frame=document.createElement('iframe');frame.style='width:480px;height:522px;border:0;display:block';frame.sandbox='allow-scripts';frame.src='/apps/'+id+'/?home_origin='+encodeURIComponent(location.origin)+${JSON.stringify(launch ? '#home_token=fixture-token' : '')};document.body.append(frame);
</script>` });
    if (url.pathname.endsWith('/shell-core.js')) return route.fulfill({ contentType: 'text/javascript', body: 'export const fetchJson=(...args)=>window.runtimeFetch(...args);' });
    if (url.pathname.endsWith('/home-clipboard-client.js')) return route.fulfill({ contentType: 'text/javascript', body: `export const createHomeClipboardClient=()=>({start(){},teardown(){},async writeText(value){window.top.postMessage({type:'fixture:copy',value},'http://extensions.test');}});` });
    if (url.pathname.includes('/api/')) {
      reads.push({ url: url.pathname, headers: route.request().headers() });
      if (readFailure) return route.fulfill({ status: readFailure, json: { error: 'fixture read failure' } });
      const data = await top.evaluate(({ url, kind, extraHomeAccount }) => {
        const s = testState;
        return url.endsWith('/accounts') ? { accounts: s.linked ? [{ address: s.address, connector_id: 'wallet-' + kind, chain_namespace: kind === 'metamask' ? 'eip155:1' : 'bip122:000000000019d6689c085ae165831e93' }, ...(extraHomeAccount ? [{address:kind==='metamask'?'0x'+'2'.repeat(40):'bc1q'+'b'.repeat(38),connector_id:'wallet-'+kind,chain_namespace:kind==='metamask'?'eip155:1':'bip122:000000000019d6689c085ae165831e93'}] : [])] : [] } : { approval_requests: s.requests.filter(request=>request.status==='pending') };
      }, { url: url.pathname, kind, extraHomeAccount });
      return route.fulfill({ json: data });
    }
    const relative = url.pathname.replace(/^\/apps\//, 'capsules/').replace(/^(capsules\/[^/]+)\/(.*)$/, '$1/browser/$2');
    let path = join(root, relative);
    if (url.pathname.endsWith('/')) path = join(path, 'index.html');
    let body = (oldHost && path.endsWith('/home-wallet-connector-host.js') || oldWindow && (path.endsWith('/index.html') || path.endsWith(`/wallet-${kind}.js`))) ? Buffer.from(baseFixture.files[path.slice(root.length+1)].source) : await readFile(path);
    if (path.endsWith('/wallet-connection-view.mjs')) body = Buffer.from(body.toString().replace('export function renderConnection(document, view)', 'function renderConnectionBase(document, view)') + `
export function renderConnection(document,view) {
  window.__sharedElements ||= new WeakSet();
  const proxy = new Proxy(document,{get(target,key) {
    if(key==='createElement')return (...args)=>{const element=target.createElement(...args);window.__sharedElements.add(element);return element;};
    const value=Reflect.get(target,key,target);return typeof value==='function'?value.bind(target):value;
  }});
  const root=renderConnectionBase(proxy,view);
  window.__sharedNodes ||= new WeakMap();
  const walk=document.createTreeWalker(root,NodeFilter.SHOW_ALL);
  do {window.__sharedNodes.set(walk.currentNode,walk.currentNode.nodeValue);} while(walk.nextNode());
  return root;
}`);
    if (mutate && path.endsWith('/extension-window.mjs')) body = Buffer.from(mutate(body.toString()));
    return route.fulfill({ body, contentType: ({ '.js': 'text/javascript', '.mjs': 'text/javascript', '.html': 'text/html', '.css': 'text/css', '.png': 'image/png', '.woff2': 'font/woff2' })[extname(path)] || 'application/octet-stream' });
  });
  await top.goto('http://extensions.test/');
  const frame = top.frames().find(f => f !== top.mainFrame());
  await frame.waitForSelector(oldWindow ? '#wallet-connect' : 'main[data-state]', { timeout: 3000 });
  // Home opens a 480 by 560 window with a 38px title bar (design's -window PNGs).
  assert.deepEqual(await frame.evaluate(() => ({width:innerWidth,height:innerHeight})), {width:480,height:522});
  if (recording) await top.evaluate(() => __walletReplay.advance(1000));
  const action = id => frame.locator(`[data-action="${id}"]`);
  const state = async expected => { try { await frame.locator(`main[data-state="${expected}"]`).waitFor({ timeout: 3000 }); } catch (e) { throw Error(e.message + JSON.stringify(await frame.locator('body').innerText()) + JSON.stringify(await top.evaluate(() => ({effects:testState.effects,calls:testState.calls,receipts:testState.receipts})))) }
    if (process.env.EXTENSION_WINDOW_PICTURES && pictures && !mutate && !oldHost && !oldWindow) {
      const receipts = process.env.EXTENSION_WINDOW_RECEIPTS || process.env.EXTENSION_WINDOW_PICTURES;
      const dir = join(receipts, 'window-extensions-captures', randomUUID());
      await mkdir(receipts, {recursive:true});
      await mkdir(dir, { recursive: true });
      const candidate = { head: execFileSync('git', ['rev-parse','HEAD'], {encoding:'utf8'}).trim(), tree: execFileSync('git', ['rev-parse','HEAD^{tree}'], {encoding:'utf8'}).trim() };
      assert.equal(execFileSync('git', ['status','--porcelain'], {encoding:'utf8'}).trim(), '', 'pictures require a clean tree');
      const copy = await frame.evaluate(() => ({ state: document.querySelector('main').dataset.state,
        sentences: [...document.querySelectorAll('.connection-status,.connection-note,.connection-more')].map(n => n.textContent.trim()).filter(Boolean),
        controls: [...document.querySelectorAll('[data-action]')].map(n => ({action:n.dataset.action,label:n.textContent.trim(),disabled:n.disabled})) }));
      assert.equal(copy.state, expected, 'capture state must match the requested live state');
      const captures = [];
      for (const theme of ['dark', 'light']) {
        await frame.evaluate(theme => { document.documentElement.toggleAttribute('data-el-theme', theme === 'light'); if (theme === 'light') document.documentElement.setAttribute('data-el-theme','light'); }, theme);
        const bytes = await (await frame.frameElement()).screenshot();
        assert.equal(await frame.locator('main').getAttribute('data-state'), expected, 'state changed during capture');
        captures.push({theme,bytes});
      }
      await frame.evaluate(() => document.documentElement.removeAttribute('data-el-theme'));
      assert.equal(execFileSync('git', ['status','--porcelain'], {encoding:'utf8'}).trim(), '', 'tree changed during capture');
      assert.equal(execFileSync('git', ['rev-parse','HEAD'], {encoding:'utf8'}).trim(), candidate.head);
      const pngs = [];
      for (const {theme,bytes} of captures) {
        const path = join(dir, `${expected}-${theme}.png`); await writeFile(path, bytes);
        pngs.push({theme,path,sha256:createHash('sha256').update(bytes).digest('hex')});
      }
      // Raw captures are never acceptance by themselves. A single publisher
      // matches sourceTestFile to the exact-tree passing process receipt.
      await writeFile(join(dir, 'capture.json'), JSON.stringify({ qualification:'staged-requires-passing-file-result',
        sourceTestFile:resolve(process.argv[1]), capturedAt:Date.now(), candidate, clean:true,
        fixture:{kind,oldHost,oldWindow,readFailure,pictureContext,recording:recording||null,saved,requests,launch,noHomeWallet,extraHomeAccount},
        pngs,engine:browser.browserType().name(),viewport:{width:480,height:560},content:{width:480,height:522},...copy },null,2));
    }
  };
  return { top, frame, context, errors, reads, peerElapsed, action, state, async assertShared() { assert.equal(await frame.evaluate(() => { const root=document.querySelector('#connection-root main'), walk=document.createTreeWalker(root,NodeFilter.SHOW_ALL); do {const n=walk.currentNode; if(n.nodeType===Node.TEXT_NODE && n.parentElement?.classList.contains('connection-wait') && /^Time left: [0-9]+:[0-9]+$/.test(n.nodeValue)) continue; if(n.nodeType===Node.TEXT_NODE && ['consumed','unknown-error'].includes(root.dataset.extensionFeedback) && (n.parentElement?.matches('.connection-status,.connection-notice'))) continue; if(!__sharedNodes.has(n) || __sharedNodes.get(n)!==n.nodeValue)return false;} while(walk.nextNode());return true;}),true,'all mounted content comes from a shared render'); assert.equal(await frame.evaluate(() => [...document.querySelectorAll('#connection-root *')].every(element => __sharedElements.has(element))), true, 'every mounted element must come from the shared renderer'); assert.equal(await frame.locator('body > :not(#connection-root):not(script)').count(), 0); }, async close() { if (recording) await top.evaluate(() => __walletReplay.assertNoViolations()); await context.close(); assert.deepEqual(errors, []); } };
}

