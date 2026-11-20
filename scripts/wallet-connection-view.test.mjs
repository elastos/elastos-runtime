import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { connectionView, connectionKey, reduceProvider, reduceSummary, reduceConnection, reduceAlternative, stageNames, viewText, renderConnection } from '../capsules/_shared/wallet-connection-view.mjs';
import { states, shared, pictures, fixtureView } from './wallet-connection-view-fixtures.mjs';
import { ruleFailures } from './lib/wallet-connection-view-rules.mjs';
import { contractCopy } from './lib/wallet-connection-picture-oracle.mjs';

test('closed view covers the three connector tables and Wallet connect panel', () => {
  assert.deepEqual(Object.fromEntries(Object.entries(stageNames).map(([key, rows]) => [key, rows.length])),
    { walletconnect: 78, metamask: 65, unisat: 53, panel: 11 });
  assert.throws(() => connectionView({ window: 'metamask', stage: 'raw-wallet-error' }));
});

test('wallet_windows_state_producers_and_controls: render-only matrix', async t => {
  for (const row of states) await t.test(row.designState, () => {
    const view = fixtureView(row);
    assert.equal(view.stage, row.stage);
    assert.deepEqual(ruleFailures(view,{row,shared}), [], row.designState);
    const expected=pictures.find(p=>p.window===row.window&&p.stage===row.stage);
    const copy=contractCopy(expected,row,view);
    assert.deepEqual({status:viewText(view.status),notice:viewText(view.notice),afterNote:viewText(view.afterNote)},copy,`${row.designState}: design sentences with explicit contract overrides`);
    assert(pictures.some(p => p.window === row.window && p.stage === row.stage));
    assert(['window-local: produced by the window lane','reducer over shared fixture','provisional'].includes(row.origin));
    if(row.origin === 'provisional')assert(row.provisional.every(p=>p.startsWith('needs an example from the foundation lane:')));
  });
});

test('rule oracles reject deliberate broken states, one mutation per rule', () => {
  const busy = fixtureView(states.find(r => r.designState === 'metamask/link-busy'));
  const answered = fixtureView(states.find(r => r.designState === 'metamask/request-next'));
  const action = id => ({id,label:[{kind:'copy',text:id}],primary:true});
  const mutations = [
    ['exit', {...busy, actions:[action('check-access')]}],
    ['payment', {...busy, paymentRisk:true, notice:[{kind:'copy',text:'Reload Home.'}]}],
    ['known-result', {...busy,walletResult:{disposition:'refused',receipt:'recording_failed'},status:[{kind:'copy',text:'Result unknown.'}]}],
    ['capability', {...busy, window:'unisat',actions:[action('use-walletconnect'),action('close-window')]}],
    ['sentence', {...busy,notice:[{kind:'copy',text:'Then check again.'}]}],
    ['answered', {...answered,wait:'Time left: 1:00'}],
    ['internal', {...busy,notice:[{kind:'copy',text:'home:wallet-connector-effect N2 invalid_request'}]}],
    ['isolation', {...busy,notice:[{kind:'html',text:'wallet'}]}],
  ];
  for(const [rule,view]of mutations)assert(ruleFailures(view,{facts:{needsExit:true,payment:rule==='payment',notSent:rule==='known-result',capability:rule==='capability',answered:rule==='answered'}}).includes(rule),`${rule} mutation escaped`);
});

test('reducers consume the original shared objects and preserve safety uncertainty', () => {
  for(const row of shared.messages.filter(r=>r.valid&&r.message.snapshot)){
    const before=JSON.stringify(row);
    const reduced=reduceProvider(row.message.snapshot);
    assert.deepEqual(reduced,row.message.snapshot,row.id);assert.equal(JSON.stringify(row),before);
    assert.notEqual(reduced,row.message.snapshot);
  }
  const row=states.find(r=>r.designState==='metamask/extension-missing');
  for(const paymentPending of [true,null]){
    const v=reduceConnection({window:'metamask',stage:row.stage},{message:shared.messages.find(r=>r.id==='outcome-no_wallet').message,safetyMessage:shared.messages.find(r=>r.id===`state-payment-${paymentPending===null?'none':'true'}`).message});
    assert(v.paymentRisk);assert(!v.actions.some(a=>a.id==='use-walletconnect'));assert(!/reload/i.test(viewText(v.notice)));
  }
});

test('n7_connector_site_rendering: shared summary matrix, exact origins and audience isolation', () => {
  for(const row of shared.n7PrivateSummaries){
    const summary=reduceSummary(row.summary,{connector:'wallet-metamask',audience:row.audience});
    assert.equal(!!summary?.site,row.expect==='show_site',row.id);
    if(summary?.site)assert.equal(summary.site,row.summary.requesting_origin);
  }
  for(const window of ['walletconnect','metamask','unisat']){
    const row=states.find(r=>r.window===window&&r.stage==='request-waiting');
    const v=fixtureView(row);assert(v.request);assert(v.request.site===null||v.request.site.startsWith('https://'));
  }
});

test('changed shared summary values reach the view without a copied request shape', () => {
  const fixture=structuredClone(shared), row={...states.find(r=>r.designState==='metamask/request-waiting'),summary:'site-wallet-metamask'};
  const summary=fixture.n7PrivateSummaries.find(r=>r.id===row.summary).summary;
  summary.reason='A different request';summary.requesting_origin='https://xn--bcher-kva.example';summary.address='0x1122334455667788990011223344556677889900';
  const v=fixtureView(row,{sharedFixture:fixture});
  assert.equal(v.request.detail,summary.reason);assert.equal(v.request.site,summary.requesting_origin);assert.equal(v.account.accounts[0].address,summary.address);
});

test('closed inputs and bounded display fields reject authority-shaped or unsafe data', () => {
  assert.throws(()=>connectionView({window:'metamask',stage:'ready',status:'Wallet raw error'}),/closed view input/);
  assert.throws(()=>reduceProvider({paymentPending:false}),/closed provider snapshot/);
  for(const row of states.filter(r=>r.local.qr))assert.throws(()=>connectionView({window:row.window,stage:row.stage,qrData:'https://wallet.example/icon.svg'}),/local PNG/);
});

test('alternative reducer uses every shared selection near miss and withholds unknown readiness', () => {
  for(const row of shared.n1Queries.filter(r=>r.id.startsWith('alternative-')||r.id.startsWith('extension-walletconnect-'))){
    assert.equal(reduceAlternative(row),row.valid,row.id);
  }
  assert.equal(reduceAlternative(undefined),false);
  const row=states.find(r=>r.designState==='metamask/extension-missing');
  const without=structuredClone(row);delete without.alternative;
  assert(!fixtureView(without).actions.some(a=>a.id==='use-walletconnect'));
});

test('provider network changes select the matching view, and provider choice drives fixed brand copy',()=>{
  const packet=shared.messages.find(r=>r.id==='state-network-fractal').message;
  assert.equal(reduceConnection({window:'unisat',stage:'ready'},{message:packet}).stage,'network-fractal');
  const brave=shared.messages.find(r=>r.id==='state-com.brave.wallet').message;
  const v=reduceConnection({window:'metamask',stage:'ready-multiple'},{message:brave});
  assert.equal(viewText(v.notice),'Connect will use Brave Wallet.');
  const safe=reduceConnection({window:'metamask',stage:'ready-multiple'},{message:brave,safetyMessage:shared.messages.find(r=>r.id==='state-payment-false').message});
  assert.equal(viewText(safe.notice),'Connect will use Brave Wallet. MetaMask is also available.');
});

test('network refusal before handoff preserves a pending request and retry control',()=>{
  const v=fixtureView(states.find(r=>r.designState==='metamask/request-network-declined'));
  assert.equal(v.answered,false);assert(v.actions.some(a=>a.id==='send-request'));assert.notEqual(v.focus,'outcome');
});

test('waits use the earliest shared deadline and an explicit clock, never a new TTL',()=>{
  const row=states.find(r=>r.designState==='metamask/request-extension');
  const original=fixtureView(row);
  assert.equal(original.wait,'Time left: 4:59');
  const fixture=structuredClone(shared);
  fixture.messages.find(r=>r.id===row.provider).message.deadlineAt=1800000011000;
  assert.equal(fixtureView(row,{sharedFixture:fixture}).wait,'Time left: 0:10');
});

test('a canonical deadline refuses a local wait substitute when the clock is absent',()=>{
  const message=shared.messages.find(r=>r.id==='progress-waiting_signature').message;
  assert.throws(()=>reduceConnection({window:'metamask',stage:'extension-wait',waitSeconds:123},{message}),/explicit clock/);
});

test('snapshot enums match the contract, and first account is captured only once',()=>{
  const snapshot=structuredClone(shared.messages.find(r=>r.id==='state-io.metamask').message.snapshot);
  for(const access of ['unknown','available','empty','lost'])assert.equal(reduceProvider({...snapshot,access}).access,access);
  assert.equal(reduceProvider({...snapshot,availability:'absent'}).availability,'absent');
  assert.throws(()=>reduceProvider({...snapshot,availability:'missing'}));
  assert.throws(()=>reduceProvider({...snapshot,access:'removed'}));
  const address='0x1122334455667788990011223344556677889900';
  const message={snapshot:{...snapshot,firstAccount:address}};
  const first=reduceConnection({window:'metamask',stage:'link-wait',waitSeconds:300},{message});
  assert.equal(first.account.accounts[0].address,address);
  const second=reduceConnection({window:'metamask',stage:'link-wait',waitSeconds:299,account:first.account},{message:{snapshot:{...snapshot,firstAccount:'0x0011223344556677889900112233445566778899'}}});
  assert.equal(second.account.accounts[0].address,address);
});

test('QR keyboard reducer cycles controls and produces only a cancel intent',()=>{
  const v=fixtureView(states.find(r=>r.stage==='qr-shown'));
  assert.deepEqual(connectionKey(v,{key:'Tab',action:'cancel'}),{intent:null,focus:'copy-link'});
  assert.deepEqual(connectionKey(v,{key:'Tab',shiftKey:true,action:'copy-link'}),{intent:null,focus:'cancel'});
  assert.deepEqual(connectionKey(v,{key:'Escape'}),{intent:'cancel',focus:null});
  assert.equal(connectionKey(fixtureView(states[0]),{key:'Escape'}),null);
});

test('consumed summary IDs never expose Send, and remaining counts use supplied summaries',()=>{
  const row={...states.find(r=>r.designState==='metamask/request-waiting'),summary:'site-wallet-metamask'};
  const fixture=structuredClone(shared);
  fixture.n7PrivateSummaries.find(r=>r.id===row.summary).summary.status='approved';
  const v=fixtureView(row,{sharedFixture:fixture});
  assert(!v.actions.some(a=>a.id==='send-request'));assert.equal(v.wait,null);
  const next=structuredClone(states.find(r=>r.designState==='metamask/request-next'));
  next.otherSummaryInputs=[];
  assert.equal(fixtureView(next).queueCount,0);
});

test('known transaction refusal survives failed saving; failed hash recording never claims sent',()=>{
  const row=states.find(r=>r.designState==='metamask/transaction-access-error');
  for(const provider of ['settled-refused-recorded','settled-refused-recording_failed']){
    const v=fixtureView({...row,provider});
    assert.equal(viewText(v.status),'Your wallet did not allow this transaction.');
    assert(!/unknown|waiting/i.test(viewText(v.status)));
    assert.equal(v.focus,'outcome');assert(!v.actions.some(a=>a.id==='send-request'));
    if(provider.endsWith('recording_failed'))assert.match(viewText(v.notice),/Home cannot save that answer/);
  }
  const sent=states.find(r=>r.designState==='metamask/transaction-done');
  const v=fixtureView({...sent,provider:'transaction-recording_failed'});
  assert.match(viewText(v.status),/returned a transaction result.*cannot save/);
  assert(!/Transaction sent|result unknown/i.test(viewText(v.status)));
});

test('same-stage focus uses stable address keys and invalid display bounds use the generic fallback',()=>{
  const row=states.find(r=>r.designState==='walletconnect/linked-multiple');
  const key=`copy-address:${row.local.account.accounts[1].address}`;
  const v=fixtureView(row,{previousFocus:{stage:row.stage,action:'copy-address',key}});
  assert.equal(v.focus,'copy-address');assert.equal(v.focusKey,key);
  const malformed=structuredClone(row);malformed.local.account.name='A'.repeat(41);
  const fallback=fixtureView(malformed);assert.equal(fallback.account.name,'Your wallet');assert.equal(fallback.account.mark,'wallet');
});

test('provider and summary reducers are public pure exports', () => {
  assert.equal(typeof reduceProvider, 'function');
  assert.equal(typeof reduceSummary, 'function');
});

function walletViewDocument() {
  const makeEl = tag => {
    const el = {
      tagName: tag.toUpperCase(), children: [], childNodes: [], parentNode: null, hidden: false, dataset: {}, tabIndex: 0, dir: '', textContent: '',
      classList: { _c: [], add(...items) { this._c.push(...items); }, contains(item) { return this._c.includes(item); } },
      append(...items) { for (const item of items) { item.parentNode = this; this.children.push(item); this.childNodes.push(item); } },
      appendChild(item) { this.append(item); },
      replaceChildren(...items) { this.children = []; this.childNodes = []; this.append(...items); },
      insertBefore(item, ref) { const index = this.children.indexOf(ref); item.parentNode = this; if (index < 0) this.children.push(item); else this.children.splice(index, 0, item); },
      prepend(item) { item.parentNode = this; this.children.unshift(item); this.childNodes.unshift(item); },
      setAttribute() {},
      querySelector(sel) { const wanted = sel.startsWith('.') ? [null, sel.slice(1)] : sel.includes('.') ? sel.split('.') : [sel, null]; let found = null; const walk = node => { if (found || !node) return; const tag = wanted[0] ? node.tagName?.toLowerCase() === wanted[0] : true; const cls = wanted[1] ? node.classList?.contains(wanted[1]) : true; if (tag && cls) found = node; for (const child of node.children ?? []) walk(child); }; walk(this); return found; },
      querySelectorAll() { return []; },
      get className() { return this.classList._c.join(' '); },
      set className(value) { this.classList._c = value.trim().split(/\s+/).filter(Boolean); },
    };
    return el;
  };
  const doc = {
    createElement(tag) { const el = makeEl(tag); el.ownerDocument = doc; return el; },
    createTextNode(text) { return { nodeType: 3, textContent: text, parentNode: null }; },
  };
  return doc;
}

test('signing windows expose sr-only page titles and no visible connection-heading', () => {
  const document = walletViewDocument();
  const linkedAccount = { name: 'Scripted phone wallet', mark: 'wallet', accounts: [{ address: '0x' + '1'.repeat(40), networks: ['Ethereum'] }] };
  const cases = [
    ['metamask', 'ready', null, 'MetaMask or Brave Wallet'],
    ['metamask', 'linked', linkedAccount, 'MetaMask or Brave Wallet'],
    ['unisat', 'ready', null, 'UniSat'],
    ['unisat', 'linked', linkedAccount, 'UniSat'],
    ['walletconnect', 'nothing-saved', null, 'WalletConnect'],
    ['walletconnect', 'linked', { ...linkedAccount, connection: 'WalletConnect' }, 'WalletConnect'],
  ];
  for (const [window, stage, account, title] of cases) {
    const view = connectionView({ window, stage, ...(account ? { account, localSafety: false } : {}) });
    const root = renderConnection(document, view);
    assert.equal(root.querySelector('h1.connection-sr-only')?.textContent, title, `${window}/${stage}: sr-only title`);
    assert.equal(root.children.some(child => child.classList.contains('connection-heading')), false, `${window}/${stage}: visible heading`);
  }
  const panel = connectionView({ window: 'panel', stage: 'linked', account: linkedAccount });
  const panelRoot = renderConnection(document, panel);
  assert.ok(panelRoot.children.some(child => child.classList.contains('connection-heading') && child.children.some(node => node.tagName === 'H1')), 'Wallet panel keeps its visible heading header');
});

test('import and model construction work with browser/effect globals forbidden',()=>{
  const result=spawnSync(process.execPath,['--input-type=module','-e',`
    for(const key of ['document','window','location','localStorage','sessionStorage','fetch','WebSocket'])Object.defineProperty(globalThis,key,{get(){throw new Error('effect global: '+key)}});
    const {connectionView}=await import(process.argv[1]);
    const input=Object.freeze({window:'metamask',stage:'ready'});
    const view=connectionView(input);
    if(view.title!=='MetaMask or Brave Wallet')throw new Error('view');
  `,new URL('../capsules/_shared/wallet-connection-view.mjs',import.meta.url).href],{encoding:'utf8',timeout:10000});
  assert.equal(result.status,0,result.stderr);
});
