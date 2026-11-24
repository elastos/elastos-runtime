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

const renderedViews = new WeakSet();
const freeze = value => { if (value && typeof value === 'object') { Object.values(value).forEach(freeze); Object.freeze(value); } return value; };
const requestTitles={auth_challenge:'Review sign-in request',capability_grant:'Review access request',credential:'Sign a credential',publish_envelope:'Review publishing request',transaction_intent:'Send transaction',browser_account_access:'Share your wallet address with this site',browser_personal_sign:'Sign a message',browser_typed_data_sign:'Sign typed data',bitcoin_bip322_proof:'Confirm this Bitcoin account is yours',revocation:'Review request'};
const requestTitleValues=[...Object.values(requestTitles),'Review request','Approval request'];
const connectionNotices={'account-changed':'Your wallet is using a different account.','network-changed':'Your wallet is using a different network.','network-unsupported':'This network is not supported here.','network-unknown':'Your wallet\'s network could not be identified.','transport-unavailable':'The connection to your wallet was lost.','transport-reconnecting':'WalletConnect is reconnecting.','connection-removed':'Your wallet removed this connection.','connection-expired':'This wallet connection expired.','provider-unavailable':'The connection to your wallet is unavailable.'};
const copyFeedbacks={'link-copied':'Link copied.','address-copied':'Address copied.','copy-failed':'Could not copy. Try again.'};
const brands = { walletconnect: 'WalletConnect', metamask: 'MetaMask', unisat: 'UniSat', panel: 'Wallet' };
// H:754 (busy recovery), H:767-779 (unknown cross-window work).
const unknownRecoveryStages = new Set(['extension-busy','link-busy','request-busy']);
const approves = id => ['connect','restore-access','send-request','send-message','finish'].includes(id);
const providerCopy = { 'io.metamask': 'MetaMask', 'com.brave.wallet': 'Brave Wallet', unisat: 'UniSat' };
const providerKeys = ['providerId', 'alternatives', 'availability', 'firstAccount', 'requiredAccountAvailable', 'network', 'networkIssue', 'access', 'busy', 'paymentPending'];
const providers = new Set(['io.metamask', 'com.brave.wallet', 'unisat', null]);
const extensionRdns = (value) => typeof value === 'string' && value.length <= 128 && /^[a-z0-9]+(?:\.[a-z0-9-]+)+$/.test(value);
const plainWalletName = (value) => typeof value === 'string' && value.length > 0 && value.length <= 80
  && new TextEncoder().encode(value).length <= 320 && !/[<>&\p{Cc}\p{Cf}\p{Co}\p{Cs}\p{Zl}\p{Zp}]/u.test(value);
const dataWalletIcon = (value) => value === null || (typeof value === 'string' && value.length <= 65536
  && /^data:image\/(?:png|jpeg|webp|gif|svg\+xml);base64,[A-Za-z0-9+/]+=*$/.test(value));
const bounded = (value, max) => typeof value === 'string' && [...value].length <= max;
const plain = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const requireValue = (valid, message) => { if (!valid) throw new TypeError(message); };
const boolOrNull = (value) => value === null || typeof value === 'boolean';
const clone = (value) => structuredClone(value);
export const connectionActionIds=Object.freeze([...new Set([...Object.values(screens).flatMap(window=>Object.values(window).flatMap(screen=>[screen.primary,...(screen.secondary||[]),screen.requestAction,screen.reviewAction].filter(Boolean).map(a=>a.id))),'copy-address','disconnect','copy-link','select-request','select-wallet','view-requests','create','import','use-metamask','use-unisat','back-to-connection'])]);
export const stageNames = Object.freeze(Object.fromEntries(Object.entries(screens).map(([key, value]) => [key, Object.freeze(Object.keys(value))])));

export function reduceProvider(snapshot) {
  requireValue(plain(snapshot) && Object.keys(snapshot).length === providerKeys.length + (Object.hasOwn(snapshot,'displayName') ? 1 : 0) && providerKeys.every(key => Object.hasOwn(snapshot, key)), 'closed provider snapshot');
  requireValue((snapshot.providerId === null || snapshot.providerId === 'unisat' || extensionRdns(snapshot.providerId))
    && (snapshot.displayName === undefined || snapshot.displayName === null || plainWalletName(snapshot.displayName)), 'provider enum');
  requireValue(Array.isArray(snapshot.alternatives) && snapshot.alternatives.length <= 1
    && snapshot.alternatives.every(p => p !== null && p !== snapshot.providerId && (p === 'unisat' || extensionRdns(p))), 'provider enum');
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
  const app = bounded(summary.requesting_app_name, 128) && summary.requesting_app_name ? summary.requesting_app_name : 'Requesting app';
  return {
    id: summary.request_id, app, actor: summary.capsule_id,
    title: Object.hasOwn(requestTitles,summary.intent)?requestTitles[summary.intent]:'Review request', transaction,
    detail: summary.capsule_id==='browser'&&/^(?:Browser page requests (?:personal_sign|eth_signTypedData(?:_v4)?|eth_sendTransaction)(?: on [a-z0-9-]+)?|Browser asks you to (?:sign a message|sign the displayed data|send a payment on [^.]+)\.)$/.test(summary.reason)?'':bounded(summary.reason, 2048) ? summary.reason : '',
    site: summary.capsule_id === 'browser' ? displayOrigin(summary.requesting_origin) : null,
    address: bounded(summary.address, 128) ? summary.address : null,
    status: summary.status==='rejected'&&Number.isSafeInteger(summary.approved_at)&&summary.wallet_outcome!=='declined'&&summary.approved_at>=0?'dismissed':['pending', 'approved', 'rejected', 'dismissed', 'completed','expired'].includes(summary.status) ? summary.status : 'unavailable',
    expiresAt: Number.isSafeInteger(summary.expires_at) ? summary.expires_at : null,
  };
}

function summaryProjection(value) {
  const keys=['id','app','actor','title','transaction','detail','site','address','status','expiresAt'];
  requireValue(plain(value)&&Object.keys(value).length===keys.length&&keys.every(k=>Object.hasOwn(value,k)), 'closed reduced request');
  requireValue(bounded(value.id,256)&&bounded(value.app,128)&&bounded(value.actor,128)&&bounded(value.detail,2048)&&typeof value.transaction==='boolean'&&requestTitleValues.includes(value.title), 'reduced request fields');
  requireValue(value.site===null||value.actor==='browser'&&displayOrigin(value.site)===value.site, 'reduced site');
  const result=clone(value);if(result.title==='Approval request')result.title='Review request';return result;
}

/** Derive contract-owned fields; presentation stage/context remains window-owned. */
export function reduceAlternative(row) {
  const s = row?.selection;
  return row?.source === 'wallet-metamask' && row?.target === 'wallet-walletconnect' && plain(s)
    && s.accountId === null && s.walletRequest === null && s.handedOff === false
    && s.paymentPending === false && s.ready === true && s.targetConfigured === true;
}

export function reduceConnection(input, { message, safetyMessage, summary, otherSummaries = [], contextSummary, audience, alternative, nowSeconds } = {}) {
  const connector = `wallet-${input.window}`;
  let provider = message?.snapshot ? reduceProvider(message.snapshot) : null;
  if (safetyMessage?.snapshot && provider) provider.paymentPending = reduceProvider(safetyMessage.snapshot).paymentPending;
  const request = summary ? reduceSummary(summary, { connector, audience }) : null;
  const context=contextSummary?reduceSummary(contextSummary,{connector,audience}):null;
  const requestContext=context?{id:context.id,app:context.app,actor:context.actor,site:context.site}:null;
  let stage = input.stage;
  if (input.window === 'unisat' && provider?.networkIssue) {
    const issue = { bitcoin_testnet: request ? 'testnet' : 'changed', fractal: 'fractal', unrecognized: 'unknown' }[provider.networkIssue];
    stage = request ? `request-network-${issue}` : `network-${issue}`;
  }
  if (message?.outcome === 'no_wallet') stage = input.window === 'metamask' && stage === 'other-ethereum-wallet' ? stage : 'extension-missing';
  const settled=message?.settled;
  // Refusing a network change before handoff is not a transaction-send result.
  const transactionStage=stage.startsWith('transaction-')||summary?.wallet_outcome==='declined'&&request?.transaction;
  const disposition=request?.transaction&&!transactionStage?null:settled?.result || ({declined:'declined',request_not_authorized:'refused'}[message?.outcome]) || (summary?.wallet_outcome==='declined'?'declined':null);
  const walletResult={disposition,receipt:settled?.receipt??null};
  if(request?.transaction&&transactionStage){
    if(disposition==='declined')stage='transaction-declined';
    if(disposition==='refused')stage='transaction-access-error';
    if(disposition==='failed')stage='transaction-wallet-error';
    if(disposition==='answered'&&settled.receipt==='recorded'&&stage!=='transaction-late-result')stage='transaction-done';
  }
  if(request && !request.transaction && stage.startsWith('request-')) {
    if(disposition==='declined')stage='request-declined';
    if(disposition==='refused')stage=Object.hasOwn(screens[input.window],'request-access-error')?'request-access-error':'request-wallet-error';
    if(disposition==='failed')stage='request-wallet-error';
    if(disposition==='answered')stage='request-done';
  }
  if(request && message?.outcome==='request_unavailable')stage='request-unavailable';
  if(request&&['rejected','dismissed'].includes(request.status)&&!disposition&&stage!=='request-unavailable'&&(screens[input.window]?.[stage]?.request||screens[input.window]?.[stage]?.optionalRequest))stage=request.status==='dismissed'?'request-dismissed':'request-rejected';
  if(request?.status==='expired'&&screens[input.window]?.[stage]?.request&&!disposition&&!screens[input.window]?.[stage]?.dispatched&&!screens[input.window]?.[stage]?.afterAnswer&&stage!=='request-unavailable')stage='request-expired';
  const deadlines = [request?.expiresAt, Number.isSafeInteger(message?.deadlineAt) ? Math.floor(message.deadlineAt / 1000) : null].filter(Number.isSafeInteger);
  requireValue(!deadlines.length||Number.isSafeInteger(nowSeconds),'explicit clock for contract deadline');
  const waitSeconds = deadlines.length && Number.isSafeInteger(nowSeconds) ? Math.max(0, Math.min(...deadlines) - nowSeconds) : input.waitSeconds;
  let account=input.account;
  if(!account && screens[input.window]?.[stage]?.selectedAccount && provider?.firstAccount){
    const networks={'eip155:1':'Ethereum','eip155:8453':'Base','eip155:20':'Elastos Smart Chain','eip155:11155111':'Sepolia','bip122:000000000019d6689c085ae165831e93':'Bitcoin'};
    account={name:provider.displayName||providerCopy[provider.providerId]||'Your wallet',mark:provider.providerId==='unisat'?'unisat':provider.providerId==='io.metamask'?'metamask':'wallet',connection:null,accounts:[{address:provider.firstAccount,networks:[networks[provider.network]||'Selected network']}]};
  }
  return connectionView({ ...input, stage, provider, summary: request, requestContext, account, waitSeconds, walletResult, alternativeAllowed: reduceAlternative(alternative),
    otherRequests: otherSummaries.map(s => reduceSummary(s, { connector, audience })).filter(Boolean) });
}

function accountDisplay(account, window, summary) {
  if (!account) return null;
  requireValue(plain(account) && Array.isArray(account.accounts) && account.accounts.length > 0 && account.accounts.length <= 100, 'account rows');
  const validName = bounded(account.name, 40) && new TextEncoder().encode(account.name).length <= 160 && account.name;
  const name = validName ? account.name : 'Your wallet';
  const mark = !validName || window === 'walletconnect' || account.connection === 'WalletConnect' ? 'wallet' : ['wallet', 'metamask', 'unisat'].includes(account.mark) ? account.mark : 'wallet';
  const accounts = account.accounts.map((row, index) => {
    requireValue(bounded(row.address, 128) && Array.isArray(row.networks) && row.networks.length <= 8 && row.networks.every(n => bounded(n, 80)), 'account address/network');
    return { address: index === 0 && summary?.address ? summary.address : row.address, networks: [...row.networks] };
  });
  requireValue(account.walletAddress === undefined || bounded(account.walletAddress, 128), 'wallet account address');
  return { name, mark, ...(account.walletAddress ? {walletAddress:account.walletAddress} : {}), connection: account.connection === 'WalletConnect' ? 'WalletConnect' : null, accounts };
}

function windowManualClose(window) {
  return window === 'metamask'
    ? "Close this window with Home's window controls, or close this tab if you opened it separately."
    : "Close this window with Home's window controls.";
}

function reduceWalletChoice(row) {
  requireValue(plain(row) && Object.keys(row).length === 3 && bounded(row.id, 128) && plainWalletName(row.name) && dataWalletIcon(row.icon), 'closed wallet choice');
  return { id: row.id, name: row.name, icon: row.icon };
}

export function connectionView(input) {
  const allowed = ['window', 'stage', 'provider', 'summary', 'otherRequests', 'account', 'waitSeconds', 'qrData', 'homeOrigin', 'localSafety', 'compact', 'alternativeAllowed', 'previousFocus', 'targetNetwork', 'walletResult', 'transactionDisplay', 'requestContext','supportedActions','copyFeedback','connectionNotice','currentSelection','localReturn','transactionHash','showNextRequests','linkedConnection','walletChoices','walletIcon','purpose','signinAction','signinComplete'];
  requireValue(plain(input) && Object.keys(input).every(key => allowed.includes(key)), 'closed view input');
  const { window, stage } = input;
  requireValue(Object.hasOwn(screens, window) && Object.hasOwn(screens[window], stage), 'closed window/stage');
  requireValue(input.purpose===undefined||input.purpose==='home-signin'&&window==='walletconnect'&&['request-waiting','request-extension','request-phone','checking-response','request-done','request-cancelled'].includes(stage),'closed connection purpose');
  requireValue(input.signinAction===undefined||input.purpose==='home-signin'&&['add','signin'].includes(input.signinAction),'closed sign-in action');
  requireValue(input.signinComplete===undefined||input.purpose==='home-signin'&&stage==='request-done'&&typeof input.signinComplete==='boolean','sign-in completion');
  const baseScreen=screens[window][stage];
  const signinScreen=input.purpose==='home-signin';
  const screen=signinScreen?{request:true,account:true,wait:false,
    status:stage==='request-waiting'?'':stage==='request-done'?input.signinComplete&&input.signinAction==='add'?'{{wallet}} can now sign in to this Home.':'Your wallet has answered.':stage==='request-cancelled'?'Request cancelled.':stage==='checking-response'?'Checking your wallet answer.':'Continue in {{wallet}}.',
    ...(stage==='request-waiting'?{primary:{id:'send-request',label:'Continue in {{wallet}}'},secondary:[{id:'stop-waiting',label:'Cancel',quiet:true}]}:
      {secondary:[{id:window==='walletconnect'&&!['request-done','request-cancelled'].includes(stage)?'stop-waiting':'close-window',label:stage==='request-done'&&window==='walletconnect'&&!input.signinComplete?'Stop waiting':stage==='request-done'||stage==='request-cancelled'?'Close window':window==='walletconnect'?'Stop waiting':'Cancel',quiet:true}]}),
    afterAnswer:['request-done','request-cancelled'].includes(stage)}:baseScreen;
  const supported=input.supportedActions===undefined?null:input.supportedActions;
  requireValue(supported===null||Array.isArray(supported)&&supported.length<=connectionActionIds.length&&new Set(supported).size===supported.length&&supported.every(a=>connectionActionIds.includes(a)),'closed supported actions');
  requireValue(input.copyFeedback===undefined||Object.hasOwn(copyFeedbacks,input.copyFeedback),'closed copy feedback');
  requireValue(input.connectionNotice===undefined||Object.hasOwn(connectionNotices,input.connectionNotice),'closed connection notice');
  requireValue(input.showNextRequests===undefined||typeof input.showNextRequests==='boolean','next requests flag');
  requireValue(input.linkedConnection===undefined||typeof input.linkedConnection==='boolean','linked connection flag');
  requireValue(input.localReturn===undefined||typeof input.localReturn==='boolean','local return flag');
  const currentSelection=input.currentSelection?clone(input.currentSelection):null;
  requireValue(!currentSelection||plain(currentSelection)&&Object.keys(currentSelection).length===2&&bounded(currentSelection.address,128)&&bounded(currentSelection.network,80),'closed current selection');
  const provider = input.provider ? reduceProvider(input.provider) : null;
  requireValue(!provider?.providerId || (window === 'unisat' ? provider.providerId === 'unisat' : window === 'metamask' ? provider.providerId === null || extensionRdns(provider.providerId) : providers.has(provider.providerId)), 'provider belongs to window');
  requireValue(!provider || (window === 'unisat' ? provider.alternatives.length === 0 : provider.alternatives.every(p=>p!=='unisat')), 'provider alternatives belong to window');
  const summary = input.summary ? summaryProjection(input.summary) : null;
  requireValue(input.purpose===undefined||input.purpose==='home-signin'&&summary?.actor==='home'&&!summary.transaction,'Home sign-in presentation');
  const requestScreen=!!screen.request||!!screen.optionalRequest&&!!summary;
  const context=input.requestContext?clone(input.requestContext):null;
  requireValue(!context||plain(context)&&Object.keys(context).length===4&&['id','app','actor','site'].every(k=>Object.hasOwn(context,k))&&bounded(context.id,256)&&context.id.length>0&&bounded(context.app,128)&&bounded(context.actor,128)&&(context.site===null||context.actor==='browser'&&displayOrigin(context.site)===context.site),'closed request context');
  requireValue(!context||!summary||context.id===summary.id&&context.app===summary.app&&context.actor===summary.actor&&context.site===summary.site,'one request identity per card');
  const requestId=(requestScreen?summary?.id:null)||context?.id||null;
  const transactionHash=input.transactionHash??null;
  requireValue(transactionHash===null||typeof transactionHash==='string'&&summary?.transaction&&['metamask','walletconnect'].includes(window)&&['transaction-wallet-error','transaction-timeout','transaction-cancelled','transaction-reopened','transaction-late-result','transaction-done','checking-response'].includes(stage)&&/^0x[0-9a-fA-F]{64}$/.test(transactionHash),'closed transaction hash');
  const transactionDisplay = input.transactionDisplay ? clone(input.transactionDisplay) : null;
  if(transactionDisplay)requireValue(summary?.transaction && plain(transactionDisplay) && Object.keys(transactionDisplay).length===4 && bounded(transactionDisplay.destination,128) && bounded(transactionDisplay.network,80) && (transactionDisplay.amount===null&&transactionDisplay.asset===null || bounded(transactionDisplay.amount,80)&&/^[0-9]+(?:\.[0-9]+)?$/.test(transactionDisplay.amount)&&bounded(transactionDisplay.asset,16)), 'closed computed transaction display');
  requireValue(!requestScreen || summary && bounded(summary.id,256) && bounded(summary.app,128) && bounded(summary.detail,2048) && requestTitleValues.includes(summary.title) && (summary.site===null || displayOrigin(summary.site)===summary.site), 'reduced selected request summary');
  const account = accountDisplay(input.account, window, requestScreen?summary:null);
  if (window === 'metamask' && account && input.account.name === provider?.displayName) account.name = provider.displayName;
  const safety = window === 'walletconnect' ? input.localSafety ?? null : provider?.paymentPending ?? null;
  requireValue(boolOrNull(safety), 'payment safety');
  const providerName=provider?.availability==='found'?(provider.displayName||providerCopy[provider.providerId]||null):null;
  const extension=window==='metamask'||window==='unisat';
  const name = signinScreen ? account?.name || brands[window] : extension ? providerName||(window==='metamask'?'your wallet':'UniSat') : account?.name || (window==='walletconnect'?'your wallet':brands[window]);
  const title=brands[window];
  const accountMark=extension?(providerName&&provider.providerId==='io.metamask'?'metamask':providerName&&provider.providerId==='unisat'?'unisat':'wallet'):account?.mark;
  const home = displayOrigin(input.homeOrigin);
  requireValue(input.targetNetwork===undefined||bounded(input.targetNetwork,80),'requested network label');
  const values = { wallet: name, network: input.targetNetwork || account?.accounts[0].networks[0] || 'the requested network', alternative: providerCopy[provider?.alternatives[0]] || 'another wallet', app: !summary && !context || (summary?.app || context?.app) === 'Requesting app' ? 'the app' : summary?.app || context?.app || 'the app', site: summary?.site || context?.site || 'the requesting site', home: home ? new URL(home).host : 'this Home' };
  const manualClose = supported !== null && !supported.includes('close-window');
  const close = manualClose ? windowManualClose(window) : 'Close this window.';
  values.close = manualClose ? close : '';
  values.closeThen = manualClose ? close.slice(0,-1)+', then' : '';
  const parts = text => (text || '').replace(/\{\{close\}\}\s*/g,match=>manualClose?match:'').replace(/\{\{closeThen\}\}\s*([a-z])/g,(match,letter)=>manualClose?match:letter.toUpperCase()).split(/(\{\{(?:wallet|alternative|app|site|home|network|close|closeThen)\}\})/).filter(Boolean).map((value,index) => {
    const key = value.match(/^\{\{(.+)\}\}$/)?.[1];
    return key ? { kind: ['close','closeThen'].includes(key) ? 'copy' : key === 'alternative' ? 'wallet' : key, text: key==='wallet'&&index===0&&values[key]==='your wallet'?'Your wallet':values[key] } : { kind: 'copy', text: value };
  });
  const requestHeading=signinScreen?parts(input.signinAction==='add'?'Add {{wallet}} as a way to sign in':input.signinAction==='signin'?'Sign in with {{wallet}}':'Review wallet request'):null;
  const action = a => ({ id: a.id, label: parts(a.label), primary: a === screen.primary || a === screen.requestAction, quiet: a.quiet });
  let notice = screen.notice || '';
  const result=input.walletResult?clone(input.walletResult):{disposition:null,receipt:null};
  requireValue(plain(result)&&Object.keys(result).length===2&&[null,'answered','declined','refused','failed'].includes(result.disposition)&&[null,'recorded','recording_failed'].includes(result.receipt),'closed wallet result');
  const knownNotSent=['declined','refused'].includes(result.disposition);
  requireValue(!(transactionHash&&knownNotSent),'transaction hash conflicts with not-sent outcome');
  requireValue(!knownNotSent||!summary?.transaction||['transaction-declined','transaction-access-error'].includes(stage),'known transaction outcome stage');
  const transactionRisk = transactionHash!==null || safety !== false || (!knownNotSent && summary?.transaction && (screen.dispatched || /timeout|cancelled|reopened|error|removed/.test(stage)));
  if (transactionRisk) notice = notice.replace(/If .*?Reload control\./g, '').replace(', then reload Home using the browser\'s Reload control.', '.').trim();
  if(transactionRisk&&screen.paymentSafeNotice!==undefined)notice=screen.paymentSafeNotice;
  requireValue(input.walletChoices===undefined||Array.isArray(input.walletChoices)&&input.walletChoices.length<=32,'wallet choices');
  const walletChoices = screen.walletPicker ? (input.walletChoices || []).map(reduceWalletChoice) : [];
  let actions = screen.requestPicker ? [] : [screen.primary, ...(screen.secondary || []), screen.requestAction, screen.reviewAction].filter(Boolean).map(action);
  if (window !== 'metamask' || input.alternativeAllowed !== true || requestScreen || screen.account || screen.selectedAccount || transactionRisk) actions = actions.filter(a => a.id !== 'use-walletconnect');
  if (!screen.qr && !screen.requestPicker && !screen.walletPicker && !actions.length && !screen.afterAnswer && window !== 'panel') actions.push({id:'close-window',label:parts('Close window'),primary:true,quiet:false});
  if(!['linked','linked-multiple'].includes(stage)&&actions.some(a=>a.primary&&a.id==='close-window')&&!notice.includes('{{close')&&!/close (this )?window/i.test(`${screen.status||''} ${notice}`))notice=`{{close}} ${notice}`.trim();
  const unknownRecovery=safety===null && !knownNotSent && unknownRecoveryStages.has(stage);
  let safetyNotice=transactionRisk&&screen.paymentSafeNotice!==undefined?notice:null;
  if(unknownRecovery){
    notice=summary?.transaction&&stage==='request-busy'?'{{close}} The transaction may still be waiting in {{wallet}}. Check {{wallet}} and Activity in Wallet before trying again.':'{{close}} A request may still be waiting in {{wallet}}. Home cannot tell whether another window has a transaction in progress. Check your wallet and Activity in Wallet before trying again.';
    safetyNotice=notice;
    actions=actions.filter(a=>!approves(a.id)&&a.id!=='start-over').map(a=>({...a,primary:a.id==='close-window',quiet:a.id==='close-window'?false:a.quiet}));
    const close=actions.find(a=>a.id==='close-window')||{id:'close-window',label:parts('Close window'),primary:true,quiet:false};
    actions=[close,...actions.filter(a=>a.id!=='close-window')];
  }
  if(screen.requiresSafeRetry&&safety!==false){notice='{{close}} Check {{wallet}} and Activity in Wallet before trying again.';safetyNotice=notice;actions=actions.filter(a=>!approves(a.id)&&a.id!=='start-over');}
  const unknownLinkRecovery=safety===null&&stage==='link-error';
  if(unknownLinkRecovery){notice=window==='metamask'?'{{close}} Before you try again, check your wallet, then open Wallet from Home and check Activity.':window==='unisat'?'{{close}} Before you try again, check UniSat and Activity in Wallet.':'{{close}} Check your wallet and Activity in Wallet before trying again.';safetyNotice=notice;actions=[{id:'close-window',label:parts('Close window'),primary:true,quiet:false}];}
  if(stage==='disconnecting')notice=window==='walletconnect'&&supported&&!supported.includes('close-window')?'Keep this window open until disconnecting finishes.':'Disconnecting continues after you close this window.';
  if(knownNotSent&&result.receipt==='recording_failed'){notice+=' Home cannot save that answer.';if(safetyNotice!==null)safetyNotice=notice;}
  const answered = !!(screen.afterAnswer || summary?.transaction&&result.disposition!==null&&result.receipt!==null || summary && /^(request-(done|declined|access-error|wallet-error|expired|late-ignored|sent-wallet-removed|unavailable)|transaction-(done|declined|access-error|late-result))$/.test(stage));
  let outcome = parts(screen.status);
  if(summary?.transaction&&result.disposition==='answered'&&result.receipt!=='recorded'){
    outcome=parts('The wallet returned a transaction result. Home cannot save it.');
    notice='Check {{wallet}} and Activity in Wallet before sending again.';
    safetyNotice=notice;
    actions=actions.filter(a=>a.id!=='send-request'&&a.id!=='use-walletconnect');
  }
  const consumedSend = summary && summary.status !== 'pending' && actions.some(a=>a.id==='send-request');
  if(consumedSend){actions=actions.filter(a=>!['send-request','open-wallet'].includes(a.id));actions.unshift({id:'open-wallet',label:parts('Review in Wallet'),primary:true,quiet:false});outcome=parts('Review this request in Wallet.');notice=summary.transaction?'Check {{wallet}} and Activity in Wallet before sending again.':'';}
  if (screen.qr) actions = [{id:'copy-link',label:parts('Copy link'),primary:false,quiet:false},{id:'cancel',label:parts('Cancel'),primary:false,quiet:false}];
  if(screen.requiresSafeRetry&&safety!==false){const close=actions.find(a=>a.id==='close-window');if(close){close.primary=true;close.quiet=false;}}
  if(transactionHash)actions=actions.filter(a=>!approves(a.id)&&a.id!=='start-over'&&a.id!=='use-walletconnect');
  if(input.linkedConnection)actions=actions.map(a=>['connect','start-over'].includes(a.id)?{...a,label:parts('Replace connection'),primary:false,quiet:true}:a);
  const localNavigationAllowed=!screen.qr&&!actions.some(a=>['stop-waiting','cancel'].includes(a.id));
  if(input.localReturn&&localNavigationAllowed)actions.push({id:'back-to-connection',label:parts('Back to connection'),primary:false,quiet:true});
  if(supported){
    const removed=actions.filter(a=>!supported.includes(a.id));actions=actions.filter(a=>supported.includes(a.id));
    if(removed.some(a=>['check-access','check-status'].includes(a.id))){
      notice=answered?'To try again, go back to {{app}} and start a new request.':screen.dispatched||/timeout|cancelled/.test(stage)?'A request may still be waiting in {{wallet}}. Closing this window does not cancel it. Home will ignore a later answer.':'Open {{wallet}} to check its account and connection.';
      if(summary?.transaction&&!knownNotSent)notice='The transaction may still be waiting in {{wallet}}. Check {{wallet}} and Activity in Wallet before trying again.';
    }
    if(window==='unisat'&&stage==='request-network-testnet'&&removed.some(a=>['check-access','check-status'].includes(a.id)))notice='Select Bitcoin mainnet in UniSat.';
    if(requestId&&removed.some(a=>['open-wallet','open-wallet-activity'].includes(a.id))&&!notice.includes('Open Wallet from Home'))notice+=window==='metamask'&&stage==='transaction-done'?' Open Wallet from Home and check Activity for this transaction.':' Open Wallet from Home to review this request.';
    if(removed.some(a=>a.id==='open-request-app')&&stage!=='request-unavailable'&&!notice.includes('{{app}}'))notice+=' Return to {{app}}.';
    if(!signinScreen&&!actions.some(a=>a.primary)&&!screen.qr&&!screen.walletPicker){const next=actions.find(a=>a.id==='close-window');if(next){next.primary=true;next.quiet=false;}}
  }
  // A dispatched payment keeps its warning and a working route to resolution.
  if(window==='walletconnect'&&summary?.transaction&&!knownNotSent&&!answered&&input.localSafety===true){
    if(stage==='checking-response'){notice='The transaction may already have been sent; check {{wallet}} and Activity in Wallet before sending again.';safetyNotice=notice;}
    if(!['transaction-phone','checking-response'].includes(stage)){
      outcome=parts('The transaction may already have been sent.');
      notice='To pair again, resolve this request in Wallet after checking {{wallet}} and Activity.';
      actions=[{id:'open-wallet',label:parts('Open Wallet'),primary:true,quiet:false},{id:'close-window',label:parts('Close window'),primary:false,quiet:true}].filter(a=>!supported||supported.includes(a.id));
      safetyNotice=null;
    }
  }
  let effectiveNotice = safetyNotice ?? notice;
  if(!signinScreen&&supported&&!supported.includes('close-window')&&!(window==='walletconnect'&&stage==='disconnecting')&&!actions.some(a=>['cancel','stop-waiting','back-to-connection'].includes(a.id))&&!((summary?.site||context?.site)&&actions.some(a=>approves(a.id)))){
    if(!effectiveNotice.includes('{{close'))effectiveNotice+=' {{close}}';
  }
  const approvalSite = !screen.requestPicker && !screen.walletPicker && (summary?.site||context?.site) && actions.some(a=>approves(a.id));
  if(approvalSite&&(!supported||supported.includes('close-window'))&&!actions.some(a=>a.id==='close-window'))actions.push({id:'close-window',label:parts('Cancel'),primary:false,quiet:true});
  let focus = approvalSite || unknownRecovery || unknownLinkRecovery || screen.requiresSafeRetry&&safety!==false ? 'close-window' : screen.focusOutcome || answered ? 'outcome' : screen.returnFocus ? 'accounts' : screen.qr ? 'copy-link' : screen.walletPicker ? 'select-wallet' : screen.requestPicker ? 'select-request' : actions.some(a => a.id === screen.focus) ? screen.focus : screen.focus&&actions.find(a=>a.primary&&a.id==='close-window')?.id||null;
  if(consumedSend)focus='outcome';
  if(approvalSite&&supported&&!supported.includes('close-window'))focus='dismissal';
  if(focus&&!['outcome','accounts','dismissal'].includes(focus)&&!actions.some(a=>a.id===focus)&&!( ['select-request','select-wallet','copy-address'].includes(focus)&&(!supported||supported.includes(focus))))focus=actions.find(a=>a.primary)?.id||actions[0]?.id|| (outcome.length?'outcome':null);
  let focusKey=null;
  const previous=input.previousFocus;
  const sameCard=previous?.window===window&&previous.stage===stage&&previous.requestId===requestId;
  const legacyFocus=previous?.stage===stage&&!approvalSite&&!answered&&!screen.qr;
  if((sameCard||legacyFocus)&&!screen.qr){
    if(sameCard&&previous.action===null)focus=null;
    else if((!supported||supported.includes(previous.action))&&bounded(previous.action,40)&&bounded(previous.key,512)&&['copy-address','select-request','select-wallet',...actions.map(a=>a.id)].includes(previous.action)){focus=previous.action;focusKey=previous.key;}
    else if(sameCard&&['outcome','accounts','dismissal'].includes(previous.action))focus=previous.action;
  }
  const wait = screen.wait && !answered && !screen.requestPicker && !screen.walletPicker && !consumedSend ? input.waitSeconds : null;
  requireValue(wait === null || Number.isSafeInteger(wait) && wait >= 0 && wait <= 86400, 'wait seconds supplied by owner');
  requireValue(!screen.qr || bounded(input.qrData, 200000) && /^data:image\/png;base64,[A-Za-z0-9+/]+=*$/.test(input.qrData), 'local PNG QR data');
  requireValue(input.otherRequests===undefined||Array.isArray(input.otherRequests)&&input.otherRequests.length<=100,'bounded request choices');
  const choices = screen.choices ? (screen.requestPicker?(input.otherRequests||[]):(input.otherRequests || []).slice(0, screen.choices === 3 ? 2 : 1)).map(summaryProjection) : [];
  if (screen.requestPicker && summary) choices.unshift(summary);
  const queued = screen.queueCount ? [...(input.otherRequests||[]).map(summaryProjection),...(!screen.afterAnswer&&summary?[summary]:[])] : input.showNextRequests&&localNavigationAllowed ? (input.otherRequests||[]).map(summaryProjection) : [];
  const queuePendingCount=queued.filter(r=>r.status==='pending').length;
  const queueRecoveryCount=queued.filter(r=>r.status==='approved'&&r.transaction).length;
  const queueRejectedCount=queued.filter(r=>r.status==='rejected').length;
  const queueDismissedCount=queued.filter(r=>r.status==='dismissed').length;
  const view = {
    window, stage, requestId, context, requestHeading, signinScreen, homeOrigin:home, supportedActions:supported?clone(supported):null, copyFeedback:parts(copyFeedbacks[input.copyFeedback]), connectionNotice:parts(connectionNotices[input.connectionNotice]), currentSelection, transactionHash, localReturn:input.localReturn===true, title, account, accountMark, walletIcon: dataWalletIcon(input.walletIcon ?? null) ? input.walletIcon ?? null : null, selectedAccount: !!screen.selectedAccount,
    showAccount: !!screen.account, requiredAccount: !!screen.requiredAccount||!!(summary&&currentSelection&&(summary.address&&summary.address!==currentSelection.address||account?.accounts[0].networks[0]!==currentSelection.network)), disconnect: screen.disconnect !== false && window === 'walletconnect',
    request: requestScreen ? summary : null, transactionDisplay, choices, walletChoices, picker: !!(screen.requestPicker || screen.walletPicker),
    queueCount:queued.length, queuePendingCount, queueRecoveryCount, queueRejectedCount, queueDismissedCount, queueOtherCount:queued.length-queuePendingCount-queueRecoveryCount-queueRejectedCount-queueDismissedCount, queueOthers:!!(input.showNextRequests&&!screen.queueCount), status: outcome, notice: parts(effectiveNotice.trim()), afterNote: parts(screen.afterActionsNote),
    wait: wait === null || wait > 30 ? null : `Time left: ${Math.floor(wait / 60)}:${String(wait % 60).padStart(2, '0')}`,
    actions, focus, focusKey, answered, walletResult:result, paymentRisk: transactionRisk, compact: input.compact === true,
    qrData: screen.qr ? input.qrData : null, panel: window === 'panel',
    walletconnectAvailable: screen.walletconnectAvailable !== false || !!account,
  };
  freeze(view); renderedViews.add(view); return view;
}

export const viewText = parts => parts.map(p => p.text).join('');

/** Keyboard decisions only; the mounting window applies focus/preventDefault. */
export function connectionKey(view, {key, shiftKey = false, action} = {}) {
  if(!view.qrData)return null;
  if(key==='Escape')return view.actions.some(a=>a.id==='cancel')?{intent:'cancel',focus:null}:null;
  if(key!=='Tab')return null;
  const ids=['copy-link','cancel'].filter(id=>view.actions.some(a=>a.id===id));if(!ids.length)return null;
  const index=ids.indexOf(action);
  return {intent:null,focus:ids[(index+(shiftKey?-1:1)+ids.length)%ids.length]};
}

/** Creates detached DOM only. The owning window installs its own event handler. */
export function renderConnection(document, view) {
  requireValue(renderedViews.has(view), 'renderConnection requires a connectionView result from this module');
  const el = (tag, text, className) => {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (Array.isArray(text)) for (let index=0;index<text.length;index++) {
      const part=text[index];
      if (part.kind === 'copy') element.append(document.createTextNode(part.text));
      else { const span = el('bdi', part.text, `connection-isolated connection-${part.kind}`); span.dir = 'auto';
        const suffix=text[index+1]?.kind==='copy' && text[index+1].text.startsWith("'s") ? "'s" : null;
        if(suffix){const group=el('span',null,'connection-possessive');group.append(span,document.createTextNode(suffix));element.append(group);const rest=text[++index].text.slice(2);if(rest)element.append(document.createTextNode(rest));}
        else element.append(span); }
    }
    else if (text) {
      if(className?.split(' ').includes('connection-isolated')&&!className.split(' ').includes('connection-site'))element.append(el('span',text,'connection-isolated-text'));
      else element.textContent = text;
    }
    return element;
  };
  const icon = mark => { const img = el('img'); img.src = `./connection-${mark}.png`; img.alt = ''; return img; };
  const supports=id=>!view.supportedActions||view.supportedActions.includes(id);
  const isolated = (value, kind) => [{ kind, text: value }];
  const button = a => { const b = el('button', a.label, `el-button${a.primary ? ' el-button-primary' : ''}${a.quiet ? ' connection-quiet' : ''}`); b.type = 'button'; b.tabIndex = 0; b.dataset.action = a.id; b.dataset.focusKey=a.key||a.id; return b; };
  const short = a => a.startsWith('bc1') ? `${a.slice(0,8)}…${a.slice(-6)}` : `${a.slice(0,6)}…${a.slice(-4)}`;
  const root = el('main', null, `connection-window${view.panel ? ' connection-panel' : ''}${view.compact ? ' connection-compact' : ''}`);
  const approvalSite = (view.request?.site||view.context?.site) && !view.picker && view.actions.some(a=>approves(a.id));
  if(approvalSite)root.classList.add('connection-approval-window');if(view.picker)root.classList.add('connection-picker');
  root.dataset.state = view.stage;root.dataset.window=view.window;root.dataset.requestId=view.requestId||'';root.dataset.scrollKey='root';
  let heading = null;
  if (view.panel) {
    heading = el('header', null, 'connection-heading');
    heading.append(el('h1', view.title));
    root.append(heading);
  } else {
    heading = el('h1', view.title, 'connection-sr-only');
    root.append(heading);
  }
  const status = el('p', view.status, 'connection-status'); status.dataset.focus = 'outcome'; status.tabIndex = -1; status.setAttribute('role','status');
  if(view.window==='walletconnect'&&!view.request&&!view.showAccount&&view.account&&view.status.some(p=>p.kind==='wallet'))status.prepend(icon('wallet'));
  status.setAttribute('aria-live','polite'); status.setAttribute('aria-atomic','true');
  const content = el('div', null, 'connection-content');content.dataset.scrollKey='content';
  const feedback = el('section', null, 'connection-feedback');
  const controls = el('div', null, 'connection-actions');
  for (const a of [...view.actions].sort((a,b)=>Number(b.primary)-Number(a.primary))) controls.append(button(a));
  const wait = view.wait ? el('p',view.wait,'connection-note connection-wait') : null;
  const notice = view.notice.length ? el('p',view.notice,'connection-note connection-notice') : null;
  function accountCard(account, selected = false) {
    if (view.window === 'metamask' && account.walletAddress && account.accounts.length > 1 && !selected) {
      const cards = document.createDocumentFragment();
      for (const row of account.accounts) cards.append(accountCard({...account, accounts:[row]}));
      return cards;
    }
    const matchesAction = !account.walletAddress || account.accounts[0].address.toLowerCase() === account.walletAddress.toLowerCase();
    const card = el('article',null,`connection-card ${selected ? 'connection-selected' : 'connection-account'}`);
    const h = el('div',null,'connection-account-header');
    if (!selected) {
      if (view.window === 'metamask') { if (view.walletIcon && matchesAction) { const img=el('img');img.src=view.walletIcon;img.alt='';h.append(img); } }
      else h.append(icon(view.accountMark));
    }
    h.append(el('h2',selected ? (view.stage==='site-access-ended'?'Required account':'Account to confirm') : isolated(matchesAction ? account.name : 'Your wallet','wallet'),'connection-account-name'));
    if(view.panel&&supports('open-wallet'))h.append(button({id:'open-wallet',label:isolated('Manage','copy'),quiet:true}));
    card.append(h);
    if(account.connection && (view.panel||view.window!=='walletconnect'))card.append(el('p','WalletConnect','connection-note connection-via'));
    for (const row of account.accounts) {
      const r=el('div',null,'connection-address-row');r.append(el('code',isolated(short(row.address),'address'),'connection-address'));
      if(!selected&&supports('copy-address')){const copy=button({id:'copy-address',label:isolated('Copy','copy'),key:`copy-address:${row.address}`});copy.setAttribute('aria-label',`Copy address ${short(row.address)}`);r.append(copy);}
      card.append(r,el('p',row.networks.flatMap((network,i)=>[...(i?[{kind:'copy',text:' · '}]:[]),...isolated(network,'network')]),'connection-network'));
    }
    if(view.disconnect&&!selected&&supports('disconnect')){const foot=el('div',null,'connection-account-foot');foot.append(button({id:'disconnect',label:isolated('Disconnect','copy'),quiet:true}));card.append(foot);}
    return card;
  }
  function siteIdentity(origin) {
    const row=el('div',null,'connection-site-row');
    const site=el('bdi',null,'connection-isolated connection-site');site.dir='auto';
    const labels=new URL(origin).host.split('.'), tail=labels.splice(Math.max(0,labels.length-3));
    const label=(value,parent,dot=false)=>{const part=el('span',null,'connection-host-label');part.append(document.createTextNode(value.slice(0,-1)),el('span',value.slice(-1)+(dot?'.':''),'connection-host-label-last'));parent.append(part);if(dot)parent.append(el('wbr'));};
    for(const value of labels)label(value,site,true);
    const end=el('span',null,'connection-host-end'),endText=el('span',null,'connection-host-end-text');
    tail.forEach((value,i)=>label(value,endText,i<tail.length-1));endText.lastElementChild.lastElementChild.append(document.createTextNode(' in Browser'));end.append(endText);
    site.append(end);row.append(site);return row;
  }
  function requestIdentity(request, card, decision = false) {
    card.dataset.requestId = request.id;
    const identity=el('div',null,'connection-identity');identity.dataset.scrollKey='request:'+request.id;
    const context=el('div',null,'connection-context');
    if(!request.site){const app=el('bdi',request.app,'connection-isolated connection-app');app.dir='auto';context.append(app);}
    if(request.site&&!decision)context.append(siteIdentity(request.site));
    const detail=el('p',null,'connection-detail');detail.append(el('bdi',request.detail,'connection-app-content'));detail.lastChild.dir='auto';
    if(request.actor!=='home')identity.append(context);
    identity.append(el('h2',request===view.request&&view.requestHeading?view.requestHeading:request.title));
    if(view.transactionDisplay&&request===view.request){
      const d=view.transactionDisplay,p=el('p',null,'connection-computed-detail');
      const value=text=>{const bdi=el('bdi',text,'connection-computed-value');bdi.dir='auto';return bdi;};
      if(d.amount!==null)p.append(value(d.amount),document.createTextNode(' '),value(d.asset),document.createTextNode(' to '));else p.append(document.createTextNode('To '));
      p.append(value(d.destination),document.createTextNode(' · '),value(d.network));identity.append(p);
    }
    if(request.detail&&!view.signinScreen)identity.append(detail);
    if(view.signinScreen&&view.homeOrigin)identity.append(el('p',isolated(view.homeOrigin,'home'),'connection-note connection-home-origin'));
    card.append(identity);return identity;
  }
  if(view.panel){
    const accounts=el('section',null,'connection-accounts');const h=el('h2','Addresses');h.dataset.focus='accounts';h.tabIndex=-1;accounts.append(h);
    if(view.account)accounts.append(accountCard(view.account));
    const row=el('div',null,'connection-actions');if(supports('create'))row.append(button({id:'create',label:isolated('Create address','copy')}));if(supports('import'))row.append(button({id:'import',label:isolated('Import address','copy'),quiet:true}));accounts.append(row);content.append(accounts);
    const options=el('section',null,'connection-wallet-options');options.append(el('h2',view.account?'Connect another wallet':'Connect a wallet'));
    const list=el('div',null,'connection-card connection-options-list');
    for(const kind of ['walletconnect','metamask','unisat']){if(!supports(`use-${kind}`))continue;if(kind==='walletconnect'&&!view.walletconnectAvailable)continue;const b=button({id:`use-${kind}`,label:[]});b.className='connection-option';const label=el('span',null,'connection-option-text');label.append(el('span',brands[kind],'connection-option-label'),document.createTextNode(' '),el('span',kind==='walletconnect'?(view.account?.connection?'Add address':'Connect a wallet with a QR code'):kind==='unisat'?'Bitcoin extension':'Browser extension','connection-note'));b.append(icon(kind),label,document.createTextNode(' '),el('span','›'));list.append(b);}options.append(list);content.append(options);
  }else{
    let destination=content;
    if(!view.panel&&!view.request&&!view.context&&!view.qrData){
      destination=el('article',null,'connection-card connection-step');
      destination.append(el('h2',view.title));content.append(destination);
    }
    if(view.showAccount&&view.account&&!view.request){const card=accountCard(view.account);if(destination!==content&&card.nodeType!==11){destination.classList.add('connection-account');destination.append(...card.childNodes);}else destination.append(card);}
    if(view.selectedAccount&&view.account&&!view.request)destination.append(accountCard(view.account,true));
    if(view.request&&!view.picker){const card=el('article',null,'connection-card connection-request');const identity=requestIdentity(view.request,card,approvalSite);
      if(view.account){const a=el('div',null,'connection-request-account');if(view.window==='metamask'&&view.walletIcon){const img=el('img');img.src=view.walletIcon;img.alt='';a.append(img);}else a.append(icon(view.account.mark));const parts=[];if(view.requiredAccount)parts.push({kind:'copy',text:'Required account · '});parts.push({kind:'wallet',text:view.account.name},{kind:'copy',text:' · '});parts.push({kind:'address',text:short(view.account.accounts[0].address)},{kind:'copy',text:' · '},...view.account.accounts[0].networks.flatMap((network,i)=>[...(i?[{kind:'copy',text:' · '}]:[]),{kind:'network',text:network}]));a.append(el('span',parts));identity.append(a);}content.append(card);destination=card;}
    if(view.context&&!view.request){const card=el('article',null,'connection-card connection-request');card.dataset.requestId=view.context.id;const identity=el('div',null,'connection-identity');identity.dataset.scrollKey='context:'+view.context.id;const context=el('div',null,'connection-context');if(!view.context.site){const app=el('bdi',view.context.app,'connection-isolated connection-app');app.dir='auto';context.append(app);}if(view.context.site&&!approvalSite)context.append(siteIdentity(view.context.site));identity.append(context);card.append(identity);content.append(card);destination=card;}
    const connectionNote=view.connectionNotice.length?el('p',view.connectionNotice,'connection-note connection-change'):null;
    if(connectionNote)destination.append(connectionNote);
    if(view.currentSelection){const p=el('p',null,'connection-note connection-current-selection');p.append(el('bdi',view.account?.name || 'Your wallet','connection-isolated connection-wallet'),document.createTextNode(' now shows '),el('bdi',view.currentSelection.address,'connection-isolated connection-address'),document.createTextNode(' · '),el('bdi',view.currentSelection.network,'connection-isolated connection-network'));for(const bdi of p.querySelectorAll('bdi'))bdi.dir='auto';destination.append(p);}
    if(view.transactionHash){const p=el('p',null,'connection-note connection-transaction-hash');const hash=el('bdi',view.transactionHash,'connection-hash');hash.dir='ltr';p.append(document.createTextNode('Transaction hash: '),hash);destination.append(p);}
    if(view.copyFeedback.length){const p=el('p',view.copyFeedback,'connection-note connection-copy-feedback');p.setAttribute('role','status');p.setAttribute('aria-live','polite');destination.append(p);}
    if(view.queueCount){const queue=el('div',null,'connection-queue');if(view.queuePendingCount)queue.append(el('h2',`${view.queuePendingCount} ${view.queueOthers?'other ':''}request${view.queuePendingCount===1?'':'s'} waiting`));if(view.queueRecoveryCount)queue.append(el('p',`${view.queueRecoveryCount} transaction${view.queueRecoveryCount===1?'':'s'} to review`));if(view.queueRejectedCount)queue.append(el('p',`${view.queueRejectedCount} rejected request${view.queueRejectedCount===1?'':'s'}`));if(view.queueDismissedCount)queue.append(el('p',`${view.queueDismissedCount} dismissed request${view.queueDismissedCount===1?'':'s'}`));if(view.queueOtherCount)queue.append(el('p',`${view.queueOtherCount} request${view.queueOtherCount===1?'':'s'} to review`));if(!view.picker&&supports('view-requests'))queue.append(button({id:'view-requests',label:isolated('View requests','copy'),quiet:true}));content.prepend(queue);}
    if(approvalSite){
      if(view.status.length)destination.append(status);
      if(wait)destination.append(wait);if(notice)destination.append(notice);
      const unit=el('section',null,'connection-approval-unit');unit.append(siteIdentity(view.request?.site||view.context.site));
      const decisions=el('div',null,'connection-actions connection-approve-actions');
      for(const a of [...view.actions].sort((a,b)=>Number(b.primary)-Number(a.primary)))decisions.append(button(a));
      if(!supports('close-window')){const manual=el('p',windowManualClose(view.window),'connection-note');manual.dataset.focus='dismissal';manual.tabIndex=-1;decisions.append(manual);}
      unit.append(decisions);destination.append(unit);
    }else if(!view.compact){if(view.status.length&&!status.parentNode){destination.append(status);}if(wait)destination.append(wait);if(notice)destination.append(notice);destination.append(controls);}
    else{if(notice)destination.append(notice);if(view.status.length)feedback.append(status);if(wait)feedback.append(wait);feedback.append(controls);}
    if(connectionNote&&status.parentNode)status.after(connectionNote);
    for(const request of view.choices){const card=el('article',null,'connection-card connection-request connection-request-choice');const text=el('div');requestIdentity(request,text);card.append(text);if(supports('select-request'))card.append(button({id:'select-request',label:isolated('View request','copy'),quiet:true,key:`select-request:${request.id}`}));if(approvalSite)content.insertBefore(card,destination);else content.append(card);}
    for (const choice of view.walletChoices || []) {
      if (!supports('select-wallet')) continue;
      const row = button({id:'select-wallet',label:isolated(choice.name,'wallet'),key:`select-wallet:${choice.id}`});
      row.classList.add('connection-wallet-choice');
      if (choice.icon) { const img=el('img');img.src=choice.icon;img.alt='';row.prepend(img); }
      if (controls.parentNode === destination) destination.insertBefore(row, controls); else content.append(row);
    }
    if(view.afterNote.length){const note=el('p',view.afterNote,'connection-note');if(approvalSite)destination.insertBefore(note,destination.querySelector('.connection-approval-unit'));else content.append(note);}
  }
  root.append(content);
  if(view.compact&&!approvalSite)root.append(feedback);
  if(view.qrData){heading.hidden=true;content.replaceChildren();const dialog=el('section',null,'connection-dialog');dialog.setAttribute('role','dialog');dialog.setAttribute('aria-modal','true');dialog.setAttribute('aria-label','WalletConnect');const title=el('h2','WalletConnect');title.prepend(icon('walletconnect'));dialog.append(title);const qr=el('img',null,'connection-qr');qr.src=view.qrData;qr.alt='Wallet connection QR code';dialog.append(qr,el('p','Scan with your wallet.'),el('p','Or paste the copied link into your wallet.'));if(view.copyFeedback.length){const p=el('p',view.copyFeedback,'connection-copy-feedback');p.setAttribute('role','status');p.setAttribute('aria-live','polite');dialog.append(p);}if(!view.compact)dialog.append(controls);content.append(dialog);}
  return root;
}


/** Read only this rendered window's presentation state; the caller owns the snapshot. */
export function captureConnectionPresentation(root) {
  const active=root.ownerDocument.activeElement,owned=root.contains(active);
  const action=owned?(active.dataset.action||active.dataset.focus||null):null;
  const key=owned?(active.dataset.focusKey||action):null;
  return {window:root.dataset.window,stage:root.dataset.state,requestId:root.dataset.requestId||null,action,key,
    scrollTop:root.scrollTop,scrollLeft:root.scrollLeft,
    scrolls:[root,...root.querySelectorAll('[data-scroll-key]')].map(e=>({key:e.dataset.scrollKey,top:e.scrollTop,left:e.scrollLeft}))};
}

function installPresentation(root,view,snapshot) {
  const buttons=[...root.querySelectorAll('button')];
  const target=(action,key)=>key&&buttons.find(b=>b.dataset.focusKey===key)||buttons.find(b=>b.dataset.action===action)||[...root.querySelectorAll('[data-focus]')].find(e=>e.dataset.focus===action);
  const focus=snapshot?(snapshot.action===null?null:target(snapshot.action,snapshot.key)||target(view.focus,view.focusKey)):target(view.focus,view.focusKey);
  focus?.focus({preventScroll:true});
  if(snapshot){for(const row of snapshot.scrolls){const e=[root,...root.querySelectorAll('[data-scroll-key]')].find(e=>e.dataset.scrollKey===row.key);if(e){e.scrollTop=row.top;e.scrollLeft=row.left;}}}
  else {root.scrollTop=0;root.scrollLeft=0;}
  const revealApproval=event=>{if((event.key==='Enter'||event.key===' ')&&approves(event.target.dataset.action))event.target.scrollIntoView({block:'end',inline:'nearest'});};
  root.addEventListener('keydown',revealApproval,true);
  return ()=>root.removeEventListener('keydown',revealApproval,true);
}

/** Mount only inside the caller's container. Pass its previous return value on redraw. */
export function mountConnection(container,view,previous=null) {
  requireValue(renderedViews.has(view),'mountConnection requires a connectionView result from this module');
  const old=previous?.root,valid=old?.parentNode===container&&renderedViews.has(previous.view);
  const same=valid&&previous.view.window===view.window&&previous.view.stage===view.stage&&previous.view.requestId===view.requestId;
  const snapshot=same?captureConnectionPresentation(old):null;
  const markupKey=v=>JSON.stringify(Object.fromEntries(Object.entries(v).filter(([k])=>!['wait','focus','focusKey'].includes(k))));
  if(same&&!!previous.view.wait===!!view.wait&&markupKey(previous.view)===markupKey(view)){
    const wait=old.querySelector('.connection-wait');if(wait&&wait.textContent!==view.wait)wait.textContent=view.wait;
    return {root:old,view,dispose:previous.dispose,reused:true};
  }
  if(valid)previous.dispose();
  const root=renderConnection(container.ownerDocument,view);container.replaceChildren(root);
  if(same&&old.classList.contains('connection-approval-window')){
    root.classList.add('connection-approval-window');
    if(!root.querySelector('.connection-approval-unit')){
      root.classList.add('connection-retained-feedback');
      const missing=Math.max(0,snapshot.scrollTop-(root.scrollHeight-root.clientHeight));
      if(missing){const spacer=root.ownerDocument.createElement('div');spacer.setAttribute('aria-hidden','true');spacer.style.height=missing+'px';root.append(spacer);}
    }
  }
  return {root,view,dispose:installPresentation(root,view,snapshot),reused:false};
}
