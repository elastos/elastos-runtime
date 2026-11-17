import assert from 'node:assert/strict';
import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { resolve, extname, join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
const baseFixture = JSON.parse(await readFile(new URL('../fixtures/wallet-extension-window-base.json', import.meta.url), 'utf8'));
for (const file of Object.values(baseFixture.files)) assert.equal(createHash('sha256').update(file.source).digest('hex'), file.sha256);
import { installScriptedExtension, replayInput } from '../wallet-extension-test/index.mjs';
const root = resolve('.');
const A = '0x' + '1'.repeat(40), U = 'bc1q' + 'a'.repeat(38);
// This provider exercises the live Home controller with isolated test results.
// Recorded peers below are kept separate and retain their exact parameters.
function installProvider({ kind, address }) {
  if (window !== window.top) return;
  window.testState = { mode: 'approve', address, chain: '0x1', linked: false, requests: [], calls: [], receipts: [], effects: [], copies: [], pending: [] };
  const listeners = new Map();
  const provider = { on(name, callback) { listeners.set(name, callback); },
    async request({ method, params }) {
      const s = testState; s.calls.push({ method, params });
      if (method === 'eth_accounts') return [s.address];
      if (method === 'eth_chainId') return s.chain;
      if (method === 'wallet_switchEthereumChain') { if (!s.added) throw {code:4902}; s.chain=params[0].chainId; return null; }
      if (method === 'wallet_addEthereumChain') { s.added=true; s.chain=params[0].chainId; return null; }
      if (method === 'eth_sendTransaction') return ask(method,'0x'+'aa'.repeat(32));
      return ask(method, method === 'eth_requestAccounts' ? [s.address] : '0x' + 'ab'.repeat(65));
    },
    async requestAccounts() { testState.calls.push({ method: 'requestAccounts' }); return ask('requestAccounts', [testState.address]); },
    async getAccounts() { return [testState.address]; }, async getNetwork() { return 'livenet'; },
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

export async function fixture(browser, kind, { saved = false, requests = false, recording, mutate, oldHost = false, oldWindow = false, readFailure = null, launch = true, noHomeWallet = false } = {}) {
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
if(${JSON.stringify(requests)}) state.requests=[{request_id:'approval-1',status:'pending',intent:${JSON.stringify(requests)}==='transaction'?'transaction_intent':${JSON.stringify(requests)}==='typed'?'browser_typed_data_sign':kind==='metamask'?'browser_personal_sign':'bitcoin_bip322_proof',proof_type:kind==='metamask'?'siwe':'bip322_simple',capsule_id:'browser',reason:'Test signing',requesting_origin:'https://shop.example.com',connector_id:id,address:state.address,chain_namespace:kind==='metamask'?'eip155:1':'bip122:000000000019d6689c085ae165831e93',expires_at:Math.floor(Date.now()/1000)+300}];
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
 const body=JSON.parse(init.body), schema='elastos.home.wallet-connector.effect.result/v1';
 const action=url.includes('/link/challenge')?(kind==='metamask'?'evm_link_challenge':'bitcoin_link_challenge'):url.includes('/link/verify')?(kind==='metamask'?'evm_link_complete':'bitcoin_link_complete'):url.endsWith('/handoff')?'approval_handoff':'approval_complete';
 if(url.includes('/link/challenge'))return {schema,action,connector_id:id,challenge:{schema:kind==='metamask'?'elastos.auth.challenge/v1':'elastos.wallet.bitcoin_challenge/v1',challenge_id:'fixture-challenge',message:'Isolated account proof',expires_at:Math.floor(Date.now()/1000)+300,resources:[],...(kind==='unisat'?{network:'bitcoin',address:state.address,proof_type:'bip322_simple'}:{})}};
 if(url.includes('/link/verify')){state.linked=true;state.receipts.push(body);return {schema,action,connector_id:id,status:'linked'};}
 if(url.endsWith('/handoff')&&${JSON.stringify(requests)}==='transaction') return {schema,action,connector_id:id,request_id:'approval-1',evm_chains:[{chainId:'0x14',chainName:'Elastos Smart Chain',nativeCurrency:{name:'ELA',symbol:'ELA',decimals:18},rpcUrls:['https://api.elastos.io/esc']}],handoff:{schema:'elastos.wallet.webconnect_handoff/v1',request_id:'approval-1',intent:'transaction_intent',payload_hash:'0x'+'ab'.repeat(32),signer:state.address,status:'awaiting_wallet_transaction',transaction:{from:state.address,to:'0x'+'2'.repeat(40),value:'0x1',data:'0x',gas:'0x5208',gasPrice:'0x1',nonce:'0x0',chainId:'0x14'}}};
 if(url.endsWith('/handoff'))return {schema,action,connector_id:id,request_id:'approval-1',evm_chains:[],handoff:{schema:'elastos.wallet.webconnect_handoff/v1',request_id:'approval-1',intent:${JSON.stringify(requests)}==='transaction'?'transaction_intent':${JSON.stringify(requests)}==='typed'?'browser_typed_data_sign':kind==='metamask'?'browser_personal_sign':'bitcoin_bip322_proof',payload_hash:'0x'+'ab'.repeat(32),signer:state.address,status:'awaiting_wallet_signature',message:'Isolated app request',signature_type:kind==='metamask'?'personal_sign':'bip322_simple'}};
 state.receipts.push(body);state.requests=[];return {schema,action,connector_id:id,request_id:'approval-1',status:'completed'};
};
const frame=document.createElement('iframe');frame.style='width:480px;height:560px;border:0;display:block';frame.sandbox='allow-scripts';frame.src='/apps/'+id+'/?home_origin='+encodeURIComponent(location.origin)+${JSON.stringify(launch ? '#home_token=fixture-token' : '')};document.body.append(frame);
</script>` });
    if (url.pathname.endsWith('/shell-core.js')) return route.fulfill({ contentType: 'text/javascript', body: 'export const fetchJson=(...args)=>window.runtimeFetch(...args);' });
    if (url.pathname.endsWith('/home-clipboard-client.js')) return route.fulfill({ contentType: 'text/javascript', body: `export const createHomeClipboardClient=()=>({start(){},teardown(){},async writeText(value){window.top.postMessage({type:'fixture:copy',value},'http://extensions.test');}});` });
    if (url.pathname.includes('/api/')) {
      reads.push({ url: url.pathname, headers: route.request().headers() });
      if (readFailure) return route.fulfill({ status: readFailure, json: { error: 'fixture read failure' } });
      const data = await top.evaluate(({ url, kind }) => {
        const s = testState;
        return url.endsWith('/accounts') ? { accounts: s.linked ? [{ address: s.address, connector_id: 'wallet-' + kind, chain_namespace: kind === 'metamask' ? 'eip155:1' : 'bip122:000000000019d6689c085ae165831e93' }] : [] } : { approval_requests: s.requests };
      }, { url: url.pathname, kind });
      return route.fulfill({ json: data });
    }
    const relative = url.pathname.replace(/^\/apps\//, 'capsules/').replace(/^(capsules\/[^/]+)\/(.*)$/, '$1/browser/$2');
    let path = join(root, relative);
    if (url.pathname.endsWith('/')) path = join(path, 'index.html');
    let body = (oldHost && path.endsWith('/home-wallet-connector-host.js') || oldWindow && (path.endsWith('/index.html') || path.endsWith(`/wallet-${kind}.js`))) ? Buffer.from(baseFixture.files[path.slice(root.length+1)].source) : await readFile(path);
    if (mutate && path.endsWith('/extension-window.mjs')) body = Buffer.from(mutate(body.toString()));
    return route.fulfill({ body, contentType: ({ '.js': 'text/javascript', '.mjs': 'text/javascript', '.html': 'text/html', '.css': 'text/css', '.png': 'image/png', '.woff2': 'font/woff2' })[extname(path)] || 'application/octet-stream' });
  });
  await top.goto('http://extensions.test/');
  const frame = top.frames().find(f => f !== top.mainFrame());
  await frame.waitForSelector(oldWindow ? '#wallet-connect' : 'main[data-state]', { timeout: 3000 });
  if (recording) await top.evaluate(() => __walletReplay.advance(1000));
  const action = id => frame.locator(`[data-action="${id}"]`);
  const state = async expected => { try { await frame.locator(`main[data-state="${expected}"]`).waitFor({ timeout: 3000 }); } catch (e) { throw Error(e.message + JSON.stringify(await frame.locator('body').innerText()) + JSON.stringify(await top.evaluate(() => ({effects:testState.effects,calls:testState.calls,receipts:testState.receipts})))) }
    if (process.env.EXTENSION_WINDOW_PICTURES && !mutate) {
      const dir = join(process.env.EXTENSION_WINDOW_PICTURES, 'windows-' + kind);
      const receipts = process.env.EXTENSION_WINDOW_RECEIPTS || process.env.EXTENSION_WINDOW_PICTURES;
      await mkdir(receipts, {recursive:true});
      await mkdir(dir, { recursive: true });
      const candidate = { head: execFileSync('git', ['rev-parse','HEAD'], {encoding:'utf8'}).trim(), tree: execFileSync('git', ['rev-parse','HEAD^{tree}'], {encoding:'utf8'}).trim() };
      const copy = await frame.evaluate(() => ({ state: document.querySelector('main').dataset.state,
        sentences: [...document.querySelectorAll('.connection-status,.connection-note,.connection-more')].map(n => n.textContent.trim()).filter(Boolean),
        controls: [...document.querySelectorAll('[data-action]')].map(n => ({action:n.dataset.action,label:n.textContent.trim(),disabled:n.disabled})) }));
      await writeFile(join(receipts, `window-extensions-copy-${kind}-${expected}.json`), JSON.stringify({ candidate, ...copy }, null, 2));
      for (const theme of ['dark', 'light']) {
        await frame.evaluate(theme => { document.documentElement.toggleAttribute('data-el-theme', theme === 'light'); if (theme === 'light') document.documentElement.setAttribute('data-el-theme','light'); }, theme);
        await top.locator('iframe').screenshot({ path: join(dir, `${expected}-${theme}.png`) });
      }
      await frame.evaluate(() => document.documentElement.removeAttribute('data-el-theme'));
    }
  };
  return { top, frame, context, errors, reads, peerElapsed, action, state, async close() { if (recording) await top.evaluate(() => __walletReplay.assertNoViolations()); await context.close(); assert.deepEqual(errors, []); } };
}

