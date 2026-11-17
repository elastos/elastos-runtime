/**
 * Pure connection presentation. No bootstrap, clock, storage, messages or wallet calls.
 * connectionView(input) returns text parts, controls, focus and layout data.
 * renderConnection(document, view) creates a detached tree; the window owns mounting,
 * focus, event handling, QR generation and every effect. A control is an intent only.
 *
 * Public input: window + closed stage; reduced provider/summary/otherRequests;
 * account (already-cleaned name/mark, address/network rows), waitSeconds, qrData,
 * homeOrigin, localSafety (WalletConnect only), compact. The window lane must
 * produce these inputs from real state, including all stages in stageNames.
 * Local stage inventory: scripts/fixtures/wallet-connection-view-states.json.
 * Provisional examples in that file are render-only and require foundation inputs.
 */
import { screens } from './wallet-connection-screens.mjs';

const brands = { walletconnect: 'WalletConnect', metamask: 'MetaMask', unisat: 'UniSat', panel: 'Wallet' };
const providerCopy = { 'io.metamask': 'MetaMask', 'com.brave.wallet': 'Brave Wallet', unisat: 'UniSat' };
const providerKeys = ['providerId', 'alternatives', 'availability', 'firstAccount', 'requiredAccountAvailable', 'network', 'networkIssue', 'access', 'busy', 'paymentPending'];
const providers = new Set(['io.metamask', 'com.brave.wallet', 'unisat', null]);
const bounded = (value, max) => typeof value === 'string' && [...value].length <= max;
const plain = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const requireValue = (valid, message) => { if (!valid) throw new TypeError(message); };
const boolOrNull = (value) => value === null || typeof value === 'boolean';
const clone = (value) => structuredClone(value);
export const stageNames = Object.freeze(Object.fromEntries(Object.entries(screens).map(([key, value]) => [key, Object.freeze(Object.keys(value))])));

export function reduceProvider(snapshot) {
  requireValue(plain(snapshot) && Object.keys(snapshot).length === providerKeys.length && providerKeys.every(key => Object.hasOwn(snapshot, key)), 'closed provider snapshot');
  requireValue(providers.has(snapshot.providerId) && Array.isArray(snapshot.alternatives) && snapshot.alternatives.length <= 1 && snapshot.alternatives.every(p => p !== null && p !== snapshot.providerId && providers.has(p)), 'provider enum');
  requireValue(['unknown', 'found', 'absent', 'unavailable'].includes(snapshot.availability) && ['unknown', 'available', 'empty', 'lost'].includes(snapshot.access), 'provider facts');
  requireValue(typeof snapshot.busy === 'boolean' && boolOrNull(snapshot.paymentPending) && boolOrNull(snapshot.requiredAccountAvailable), 'provider safety');
  requireValue(snapshot.firstAccount === null || bounded(snapshot.firstAccount, 128) && (/^0x[0-9a-f]{40}$/.test(snapshot.firstAccount) || /^(bc1|[13])[A-Za-z0-9]+$/.test(snapshot.firstAccount)), 'first account');
  requireValue(snapshot.network === null || snapshot.network === 'bip122:000000000019d6689c085ae165831e93' || /^eip155:[1-9][0-9]*$/.test(snapshot.network) && Number.isSafeInteger(Number(snapshot.network.slice(7))), 'network');
  requireValue([null, 'bitcoin_testnet', 'fractal', 'unrecognized'].includes(snapshot.networkIssue), 'network issue');
  return clone(snapshot);
}

// Validate the Runtime projection's bounds; preserve its exact ASCII serialization.
// This does not derive identity from reason, page_url, or a friendly hostname.
export function displayOrigin(value) {
  if (!bounded(value, 512) || !/^[\x21-\x7e]+$/.test(value) || !/^https?:\/\/[^/?#@\\]+$/.test(value)) return null;
  try { return new URL(value).origin === value ? value : null; } catch { return null; }
}

export function reduceSummary(summary, { connector, audience = connector } = {}) {
  if (!plain(summary) || !['wallet', 'inbox', connector].includes(audience) || !['wallet-metamask', 'wallet-unisat', 'wallet-walletconnect'].includes(connector) || summary.connector_id !== connector) return null;
  requireValue(bounded(summary.request_id, 256) && bounded(summary.capsule_id, 128), 'request identity');
  const transaction = summary.intent === 'transaction_intent';
  const app = bounded(summary.requesting_app_name, 128) && summary.requesting_app_name ? summary.requesting_app_name : summary.capsule_id;
  return {
    id: summary.request_id, app, actor: summary.capsule_id,
    title: transaction ? 'Send transaction' : 'Sign a message', transaction,
    detail: bounded(summary.reason, 2048) ? summary.reason : '',
    site: summary.capsule_id === 'browser' ? displayOrigin(summary.requesting_origin) : null,
    address: bounded(summary.address, 128) ? summary.address : null,
    status: ['pending', 'approved', 'rejected', 'dismissed', 'completed'].includes(summary.status) ? summary.status : 'unavailable',
    expiresAt: Number.isSafeInteger(summary.expires_at) ? summary.expires_at : null,
  };
}

function summaryProjection(value) {
  const keys=['id','app','actor','title','transaction','detail','site','address','status','expiresAt'];
  requireValue(plain(value)&&Object.keys(value).length===keys.length&&keys.every(k=>Object.hasOwn(value,k)), 'closed reduced request');
  requireValue(bounded(value.id,256)&&bounded(value.app,128)&&bounded(value.actor,128)&&bounded(value.detail,2048)&&typeof value.transaction==='boolean'&&['Sign a message','Send transaction'].includes(value.title), 'reduced request fields');
  requireValue(value.site===null||value.actor==='browser'&&displayOrigin(value.site)===value.site, 'reduced site');
  return clone(value);
}

/** Derive contract-owned fields; presentation stage/context remains window-owned. */
export function reduceAlternative(row) {
  const s = row?.selection;
  return row?.source === 'wallet-metamask' && row?.target === 'wallet-walletconnect' && plain(s)
    && s.accountId === null && s.walletRequest === null && s.handedOff === false
    && s.paymentPending === false && s.ready === true && s.targetConfigured === true;
}

export function reduceConnection(input, { message, safetyMessage, summary, otherSummaries = [], audience, alternative, nowSeconds } = {}) {
  const connector = `wallet-${input.window}`;
  let provider = message?.snapshot ? reduceProvider(message.snapshot) : null;
  if (safetyMessage?.snapshot && provider) provider.paymentPending = reduceProvider(safetyMessage.snapshot).paymentPending;
  const request = summary ? reduceSummary(summary, { connector, audience }) : null;
  let stage = input.stage;
  if (input.window === 'unisat' && provider?.networkIssue) {
    const issue = { bitcoin_testnet: request ? 'testnet' : 'changed', fractal: 'fractal', unrecognized: 'unknown' }[provider.networkIssue];
    stage = request ? `request-network-${issue}` : `network-${issue}`;
  }
  if (message?.outcome === 'no_wallet') stage = input.window === 'metamask' && stage === 'other-ethereum-wallet' ? stage : 'extension-missing';
  const settled=message?.settled;
  // Refusing a network change before handoff is not a transaction-send result.
  const disposition=request?.transaction&&!stage.startsWith('transaction-')?null:settled?.result || ({declined:'declined',request_not_authorized:'refused'}[message?.outcome]) || null;
  const walletResult={disposition,receipt:settled?.receipt??null};
  if(request?.transaction&&stage.startsWith('transaction-')){
    if(disposition==='declined')stage='transaction-declined';
    if(disposition==='refused')stage='transaction-access-error';
    if(disposition==='failed')stage='transaction-wallet-error';
    if(disposition==='answered'&&settled.receipt==='recorded'&&stage!=='transaction-late-result')stage='transaction-done';
  }
  const deadlines = [request?.expiresAt, Number.isSafeInteger(message?.deadlineAt) ? Math.floor(message.deadlineAt / 1000) : null].filter(Number.isSafeInteger);
  requireValue(!deadlines.length||Number.isSafeInteger(nowSeconds),'explicit clock for contract deadline');
  const waitSeconds = deadlines.length && Number.isSafeInteger(nowSeconds) ? Math.max(0, Math.min(...deadlines) - nowSeconds) : input.waitSeconds;
  let account=input.account;
  if(!account && screens[input.window]?.[stage]?.selectedAccount && provider?.firstAccount){
    const networks={'eip155:1':'Ethereum','eip155:8453':'Base','eip155:20':'Elastos Smart Chain','bip122:000000000019d6689c085ae165831e93':'Bitcoin'};
    account={name:providerCopy[provider.providerId]||'Your wallet',mark:provider.providerId==='unisat'?'unisat':provider.providerId==='io.metamask'?'metamask':'wallet',connection:null,accounts:[{address:provider.firstAccount,networks:[networks[provider.network]||'Selected network']}]};
  }
  return connectionView({ ...input, stage, provider, summary: request, account, waitSeconds, walletResult, alternativeAllowed: reduceAlternative(alternative),
    otherRequests: otherSummaries.map(s => reduceSummary(s, { connector, audience })).filter(Boolean) });
}

function accountDisplay(account, window, summary) {
  if (!account) return null;
  requireValue(plain(account) && Array.isArray(account.accounts) && account.accounts.length > 0 && account.accounts.length <= 8, 'account rows');
  const validName = bounded(account.name, 40) && new TextEncoder().encode(account.name).length <= 160 && account.name;
  const name = validName ? account.name : 'Your wallet';
  const mark = !validName || window === 'walletconnect' || account.connection === 'WalletConnect' ? 'wallet' : ['wallet', 'metamask', 'unisat'].includes(account.mark) ? account.mark : 'wallet';
  const accounts = account.accounts.map((row, index) => {
    requireValue(bounded(row.address, 128) && Array.isArray(row.networks) && row.networks.length <= 8 && row.networks.every(n => bounded(n, 80)), 'account address/network');
    return { address: index === 0 && summary?.address ? summary.address : row.address, networks: [...row.networks] };
  });
  return { name, mark, connection: account.connection === 'WalletConnect' ? 'WalletConnect' : null, accounts };
}

export function connectionView(input) {
  const allowed = ['window', 'stage', 'provider', 'summary', 'otherRequests', 'account', 'waitSeconds', 'qrData', 'homeOrigin', 'localSafety', 'compact', 'alternativeAllowed', 'previousFocus', 'targetNetwork', 'walletResult'];
  requireValue(plain(input) && Object.keys(input).every(key => allowed.includes(key)), 'closed view input');
  const { window, stage } = input;
  requireValue(Object.hasOwn(screens, window) && Object.hasOwn(screens[window], stage), 'closed window/stage');
  const screen = screens[window][stage];
  const provider = input.provider ? reduceProvider(input.provider) : null;
  requireValue(!provider?.providerId || (window === 'unisat' ? provider.providerId === 'unisat' : window === 'metamask' ? provider.providerId !== 'unisat' : true), 'provider belongs to window');
  requireValue(!provider || (window === 'unisat' ? provider.alternatives.length === 0 : provider.alternatives.every(p=>p!=='unisat')), 'provider alternatives belong to window');
  const summary = input.summary ? summaryProjection(input.summary) : null;
  requireValue(!screen.request || summary && bounded(summary.id,256) && bounded(summary.app,128) && bounded(summary.detail,2048) && ['Sign a message','Send transaction'].includes(summary.title) && (summary.site===null || displayOrigin(summary.site)===summary.site), 'reduced selected request summary');
  const account = accountDisplay(input.account, window, summary);
  const safety = window === 'walletconnect' ? input.localSafety ?? null : provider?.paymentPending ?? null;
  requireValue(boolOrNull(safety), 'payment safety');
  const name = account?.name || providerCopy[provider?.providerId] || brands[window];
  const home = displayOrigin(input.homeOrigin);
  requireValue(input.targetNetwork===undefined||bounded(input.targetNetwork,80),'requested network label');
  const values = { wallet: name, network: input.targetNetwork || account?.accounts[0].networks[0] || 'the requested network', alternative: providerCopy[provider?.alternatives[0]] || 'another wallet', app: summary?.app || 'Browser', site: summary?.site || 'the requesting site', home: home ? new URL(home).host : 'this Home' };
  const parts = text => (text || '').split(/(\{\{(?:wallet|alternative|app|site|home|network)\}\})/).filter(Boolean).map(value => {
    const key = value.match(/^\{\{(.+)\}\}$/)?.[1];
    return key ? { kind: key === 'alternative' ? 'wallet' : key, text: values[key] } : { kind: 'copy', text: value };
  });
  const action = a => ({ id: a.id, label: parts(a.label), primary: a === screen.primary || a === screen.requestAction, quiet: a.quiet });
  let notice = screen.notice || '';
  const result=input.walletResult||{disposition:null,receipt:null};
  requireValue(plain(result)&&Object.keys(result).length===2&&[null,'answered','declined','refused','failed'].includes(result.disposition)&&[null,'recorded','recording_failed'].includes(result.receipt),'closed wallet result');
  const knownNotSent=['declined','refused'].includes(result.disposition);
  requireValue(!knownNotSent||!summary?.transaction||['transaction-declined','transaction-access-error'].includes(stage),'known transaction outcome stage');
  const transactionRisk = safety !== false || (!knownNotSent && summary?.transaction && (screen.dispatched || /timeout|cancelled|reopened|error|removed/.test(stage)));
  if (transactionRisk) notice = notice.replace(/If .*?Reload control\./g, '').replace(/Enable .*?Open .*? from Wallet\./g, 'Close this window and check your wallet.');
  let actions = screen.requestPicker ? [] : [screen.primary, ...(screen.secondary || []), screen.requestAction, screen.reviewAction].filter(Boolean).map(action);
  if (window !== 'metamask' || input.alternativeAllowed !== true || screen.request || screen.account || transactionRisk) actions = actions.filter(a => a.id !== 'use-walletconnect');
  if (!screen.qr && !screen.requestPicker && !actions.length && !screen.afterAnswer && window !== 'panel') actions.push({id:'close-window',label:parts('Close window'),primary:true,quiet:false});
  if(actions.some(a=>a.primary&&a.id==='close-window')&&!/close (this )?window/i.test(`${screen.status||''} ${notice}`))notice=`Close this window. ${notice}`.trim();
  if(knownNotSent&&result.receipt==='recording_failed')notice+=' Home cannot save that answer.';
  const answered = !!(screen.afterAnswer || summary?.transaction&&result.disposition!==null&&result.receipt!==null || summary && /^(request-(done|declined|access-error|wallet-error|expired|late-ignored|sent-wallet-removed)|transaction-(done|declined|access-error|late-result))$/.test(stage));
  let outcome = parts(screen.status);
  if(summary?.transaction&&result.disposition==='answered'&&result.receipt!=='recorded'){
    outcome=parts('The wallet returned a transaction result. Home cannot save it.');
    notice='Check {{wallet}} and Wallet activity before sending again.';
    actions=actions.filter(a=>a.id!=='send-request'&&a.id!=='use-walletconnect');
  }
  const consumedSend = summary && summary.status !== 'pending' && actions.some(a=>a.id==='send-request');
  if(consumedSend){actions=actions.filter(a=>!['send-request','open-wallet'].includes(a.id));actions.unshift({id:'open-wallet',label:parts('Review in Wallet'),primary:true,quiet:false});outcome=parts('Review this request in Wallet.');}
  let focus = screen.focusOutcome || answered ? 'outcome' : screen.returnFocus ? 'accounts' : screen.qr ? 'copy-link' : screen.requestPicker ? 'select-request' : actions.some(a => a.id === screen.focus) ? screen.focus : null;
  let focusKey=null;
  if(input.previousFocus?.stage===stage && !answered && !screen.qr){
    const previous=input.previousFocus;
    if(bounded(previous.action,40)&&bounded(previous.key,256)&&['copy-address','select-request',...actions.map(a=>a.id)].includes(previous.action)){focus=previous.action;focusKey=previous.key;}
  }
  if (screen.qr) actions = [{id:'copy-link',label:parts('Copy link'),primary:false,quiet:false},{id:'cancel',label:parts('Cancel'),primary:false,quiet:false}];
  const wait = screen.wait && !answered && !screen.requestPicker && !consumedSend ? input.waitSeconds : null;
  requireValue(wait === null || Number.isSafeInteger(wait) && wait >= 0 && wait <= 86400, 'wait seconds supplied by owner');
  requireValue(!screen.qr || bounded(input.qrData, 200000) && /^data:image\/png;base64,[A-Za-z0-9+/]+=*$/.test(input.qrData), 'local PNG QR data');
  requireValue(input.otherRequests===undefined||Array.isArray(input.otherRequests)&&input.otherRequests.length<=100,'bounded request choices');
  const choices = screen.choices ? (input.otherRequests || []).slice(0, screen.choices === 3 ? 2 : 1).map(summaryProjection) : [];
  if (screen.requestPicker && summary) choices.unshift(summary);
  return {
    window, stage, title: brands[window], account, selectedAccount: !!screen.selectedAccount,
    showAccount: !!screen.account, requiredAccount: !!screen.requiredAccount, disconnect: screen.disconnect !== false && window === 'walletconnect',
    request: screen.request ? summary : null, choices, picker: !!screen.requestPicker,
    queueCount: screen.queueCount ? (input.otherRequests?.length||0)+(screen.afterAnswer?0:1) : 0, status: outcome, notice: parts(notice), afterNote: parts(screen.afterActionsNote),
    wait: wait === null ? null : `Time left: ${Math.floor(wait / 60)}:${String(wait % 60).padStart(2, '0')}`,
    actions, focus, focusKey, answered, walletResult:result, paymentRisk: transactionRisk, compact: input.compact === true,
    qrData: screen.qr ? input.qrData : null, panel: window === 'panel',
    walletconnectAvailable: screen.walletconnectAvailable !== false || !!account,
  };
}

export const viewText = parts => parts.map(p => p.text).join('');

/** Keyboard decisions only; the mounting window applies focus/preventDefault. */
export function connectionKey(view, {key, shiftKey = false, action} = {}) {
  if(!view.qrData)return null;
  if(key==='Escape')return {intent:'cancel',focus:null};
  if(key!=='Tab')return null;
  const ids=['copy-link','cancel'];
  const index=ids.indexOf(action);
  return {intent:null,focus:ids[(index+(shiftKey?-1:1)+ids.length)%ids.length]};
}

/** Creates detached DOM only. The owning window installs its own event handler. */
export function renderConnection(document, view) {
  const el = (tag, text, className) => {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (Array.isArray(text)) for (const part of text) {
      if (part.kind === 'copy') element.append(document.createTextNode(part.text));
      else { const span = el('bdi', part.text, `connection-isolated connection-${part.kind}`); span.dir = 'auto'; element.append(span); }
    }
    else if (text) element.textContent = text;
    return element;
  };
  const icon = mark => { const img = el('img'); img.src = `./connection-${mark}.png`; img.alt = ''; return img; };
  const isolated = (value, kind) => [{ kind, text: value }];
  const button = a => { const b = el('button', a.label, `el-button${a.primary ? ' el-button-primary' : ''}${a.quiet ? ' connection-quiet' : ''}`); b.type = 'button'; b.dataset.action = a.id; b.dataset.focusKey=a.key||a.id; return b; };
  const short = a => a.startsWith('bc1') ? `${a.slice(0,8)}…${a.slice(-6)}` : `${a.slice(0,6)}…${a.slice(-4)}`;
  const root = el('main', null, `connection-window${view.panel ? ' connection-panel' : ''}${view.compact ? ' connection-compact' : ''}`);
  root.dataset.state = view.stage;
  const heading = el('header', null, 'connection-heading');
  if (!view.panel) heading.append(icon(view.window));
  heading.append(el('h1', view.title)); root.append(heading);
  const status = el('p', view.status, 'connection-status'); status.dataset.focus = 'outcome'; status.tabIndex = -1; status.setAttribute('role','status');
  if(view.window==='walletconnect'&&!view.request&&!view.showAccount&&view.account&&view.status.some(p=>p.kind==='wallet'))status.prepend(icon('wallet'));
  status.setAttribute('aria-live','polite'); status.setAttribute('aria-atomic','true');
  const content = el('div', null, 'connection-content');
  const feedback = el('section', null, 'connection-feedback');
  const controls = el('div', null, 'connection-actions');
  for (const a of view.actions) controls.append(button(a));
  const wait = view.wait ? el('p',view.wait,'connection-note connection-wait') : null;
  const notice = view.notice.length ? el('p',view.notice,'connection-note connection-notice') : null;
  function accountCard(account, selected = false) {
    const card = el('article',null,`connection-card ${selected ? 'connection-selected' : 'connection-account'}`);
    const h = el('div',null,'connection-account-header');
    if (!selected) h.append(icon(account.mark));
    const joinedHeading = !view.panel && !selected && account.name === view.title && view.showAccount && !view.request;
    if(joinedHeading){h.replaceChildren(heading);if(!view.compact&&view.status.length)h.append(status);}
    else h.append(el('h2',selected ? 'Account to confirm' : isolated(account.name,'wallet'),'connection-account-name'));
    if(view.panel)h.append(button({id:'open-wallet',label:isolated('Manage','copy'),quiet:true}));
    card.append(h);
    if(account.connection)card.append(el('p','via WalletConnect','connection-note connection-via'));
    for (const row of account.accounts) {
      const r=el('div',null,'connection-address-row');r.append(el('code',short(row.address),'connection-address'));
      if(!selected){const copy=button({id:'copy-address',label:isolated('Copy','copy'),key:`copy-address:${row.address}`});copy.setAttribute('aria-label',`Copy address ${short(row.address)}`);r.append(copy);}
      card.append(r,el('p',row.networks.join(' · '),'connection-network'));
    }
    if(view.disconnect&&!selected){const foot=el('div',null,'connection-account-foot');foot.append(button({id:'disconnect',label:isolated('Disconnect','copy'),quiet:true}));card.append(foot);}
    return card;
  }
  function requestIdentity(request, card) {
    card.dataset.requestId = request.id;
    card.append(el('p',isolated(request.app,'app'),'connection-note connection-app'));
    if(request.site){const site=el('div',null,'connection-site-row');site.append(el('span','Site reported by Browser'),el('bdi',request.site,'connection-isolated connection-site'));site.lastChild.dir='auto';site.lastChild.title=request.site;site.lastChild.tabIndex=0;card.append(site);}
    const detail=el('p',request.detail,'connection-detail');detail.setAttribute('aria-label','Content from app');
    card.append(el('h2',request.title),detail);
  }
  if(view.panel){
    const accounts=el('section',null,'connection-accounts');const h=el('h2','Accounts');h.dataset.focus='accounts';h.tabIndex=-1;accounts.append(h);
    if(view.account)accounts.append(accountCard(view.account));
    const row=el('div',null,'connection-actions');row.append(button({id:'create',label:isolated('Create account','copy')}),button({id:'import',label:isolated('Import account','copy'),quiet:true}));accounts.append(row);content.append(accounts);
    const options=el('section',null,'connection-wallet-options');options.append(el('h2',view.account?'Connect another wallet':'Connect a wallet'));
    const list=el('div',null,'connection-card connection-options-list');
    for(const kind of ['walletconnect','metamask','unisat']){if(kind==='walletconnect'&&!view.walletconnectAvailable)continue;const b=button({id:`use-${kind}`,label:[]});b.className='connection-option';b.append(icon(kind),el('span',brands[kind]),document.createTextNode(' '),el('span',kind==='walletconnect'?(view.account?.connection?'Add account':'Connect a wallet app with a QR code'):kind==='unisat'?'Bitcoin extension':'Browser extension','connection-note'),document.createTextNode(' '),el('span','›'));list.append(b);}options.append(list);content.append(options);
  }else{
    if(view.showAccount&&view.account&&!view.request)content.append(accountCard(view.account));
    if(view.selectedAccount&&view.account&&!view.request)content.append(accountCard(view.account,true));
    let destination=content;
    if(view.request&&!view.picker){const card=el('article',null,'connection-card connection-request');requestIdentity(view.request,card);
      if(view.account){const a=el('div',null,'connection-request-account');if(view.window==='walletconnect')a.append(icon('wallet'));const parts=[];if(view.requiredAccount)parts.push({kind:'copy',text:'Required account · '});if(view.account.name!==view.title)parts.push({kind:'wallet',text:view.account.name},{kind:'copy',text:' · '});parts.push({kind:'copy',text:`${short(view.account.accounts[0].address)} · ${view.account.accounts[0].networks.join(' · ')}`});a.append(el('span',parts));card.append(a);}content.append(card);destination=card;}
    if(view.queueCount){const queue=el('div',null,'connection-queue');queue.append(el('h2',`${view.queueCount} requests waiting`));if(!view.picker)queue.append(button({id:'view-requests',label:isolated('View requests','copy'),quiet:true}));content.prepend(queue);}
    if(!view.compact){if(view.status.length&&!status.parentNode)(view.request?destination:root).append(status);if(wait)destination.append(wait);if(notice)destination.append(notice);destination.append(controls);}
    else{if(notice)destination.append(notice);if(view.status.length)feedback.append(status);if(wait)feedback.append(wait);feedback.append(controls);}
    for(const request of view.choices){const card=el('article',null,'connection-card connection-request connection-request-choice');const text=el('div');requestIdentity(request,text);card.append(text,button({id:'select-request',label:isolated('View request','copy'),quiet:true,key:`select-request:${request.id}`}));content.append(card);}
    if(view.afterNote.length)content.append(el('p',view.afterNote,'connection-note'));
  }
  root.append(content);
  if(view.compact)root.append(feedback);
  if(view.qrData){heading.hidden=true;content.replaceChildren();const dialog=el('section',null,'connection-dialog');dialog.setAttribute('role','dialog');dialog.setAttribute('aria-modal','true');dialog.setAttribute('aria-label','WalletConnect');const title=el('h2','WalletConnect');title.prepend(icon('walletconnect'));dialog.append(title);const qr=el('img',null,'connection-qr');qr.src=view.qrData;qr.alt='Wallet connection QR code';dialog.append(qr,el('p','Scan this QR Code with your phone'),el('p','Or paste the copied link into a wallet app on this computer.'));if(!view.compact)dialog.append(controls);content.append(dialog);}
  return root;
}
