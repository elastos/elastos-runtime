import {installWalletConnectStorage} from './walletconnect-storage.mjs';
import {createWalletConnectClient} from './walletconnect-client.mjs';
import {renderConnection, connectionKey} from './wallet-connection-view.mjs';
import {windowPresentation, walletConnectView, errorStage, baseActions, signableRequest, connectorId} from './walletconnect-window-state.mjs';
import {createHomeClipboardClient} from "/apps/home/home-clipboard-client.js?v=home-20260726a";

const CONNECTOR_ID = connectorId;
const root = document.querySelector('#wallet-window');
const frameHomeToken = readText(new URLSearchParams(location.hash.slice(1)).get('home_token'));
const homeOrigin = readText(new URLSearchParams(location.search).get('home_origin'));
const runtimeOrigin = new URL(import.meta.url).origin;
const clearMemory = installWalletConnectStorage(window);
let hostEffectInFlight = false, walletStateRevision = 0, connectionCheckInFlight = false, actionEpoch = 0;
let walletChanged=false;
let effectPhase = 'idle';
let currentPhase = 'idle', connectionState, linkedAccounts = [], requests = [], accountsLoaded = false;
let recoveryAction, launchExpired = false, ownerConsentNeeded = false, connectionNeedsReplacement = false;
let pendingEffect, permissionStatus, connectionReturnPending = false, connectionTimer, connectionInterval;
let rememberedFocus;
let unrecordedHash,proofAccount;
let dispatchedRequestId;
let outcome, activeRequest, selectedId, deadline, qrData, qrControls, currentView, renderKey;
let showPicker = false;
let copying=false;
let clipboardFeedback = '';
let clipboardFeedbackKey;

const homeClipboard = createHomeClipboardClient({targetId: CONNECTOR_ID,homeOrigin,homeToken:frameHomeToken});
homeClipboard.start();
const api = (resource, init={}) => {
  if (init.method === 'POST' && (resource === '/api/auth/evm/verify' || /^wallet\/approvals\/[^/]+\/complete$/.test(resource))) {
    const hash=JSON.parse(init.body || '{}').transaction_hash;
    if (/^0x[0-9a-fA-F]{64}$/.test(hash || '')) unrecordedHash=hash;
    currentPhase='checking';draw();
  }
  return fetchJson(resource.startsWith('/api/') ? runtimeOrigin + resource : `${runtimeOrigin}/api/apps/${CONNECTOR_ID}/${resource}`, {
    ...init,headers:shellHeaders({...init.headers,'content-type':'application/json'}),
  });
};
const connector = createWalletConnectClient({api,origin:runtimeOrigin,clearMemory,copyLink:copyConnectionLink,
  pairingView:{show(data, controls){qrData=data;qrControls=controls;draw();},hide(result){qrData=undefined;qrControls=undefined;clipboardFeedback='';if(result?.connected)currentPhase='confirming';draw();}},
  onPhase(phase, detail) {
    if (phase === 'changed') {
      walletChanged ||= detail?.selectionChanged === true && ['ownership','signature','transaction'].includes(effectPhase);
      // Wallet notifications carry facts locally. Home authority stays on the base routes.
      clipboardFeedback='';
      const identityEvent=detail?.selectionChanged === true;
      const retained=knownOutcome() || activeRequest?.intent === 'transaction_intent' && Boolean(outcome);
      if (identityEvent && !retained) outcome=undefined;
      if (!hostEffectInFlight && identityEvent && !retained) activeRequest=undefined;
      refreshReturnedWindow();
      return;
    }
    if (phase !== 'pairing') clipboardFeedback='';
    currentPhase = phase;effectPhase=phase;
    if(phase==='ownership')proofAccount={address:detail.address,chain:detail.chain,name:detail.name};
    if (['ownership','signature','transaction'].includes(phase)) {
      if (phase !== 'ownership' && activeRequest) {dispatchedRequestId=activeRequest.request_id;activeRequest.status='approved';}
      deadline = detail?.expiresAt || activeRequest?.expires_at || Math.floor(Date.now()/1000)+300;
      checkConnection().catch(()=>{});
    }
    draw();
  },
});

root.addEventListener('click', async event => {
  const button = event.target.closest('button[data-action]');
  if (!button || button.disabled || !root.contains(button)) return;
  const action = button.dataset.action;
  if (action === 'connect' || action === 'start-over') return onConnect();
  if (action === 'finish') return onConnect({fresh:false});
  if (action === 'cancel') return qrControls ? qrControls.cancel() : cancelWalletWait();
  if (action === 'stop-waiting') return cancelWalletWait();
  if (action === 'disconnect') return disconnect();
  if (action === 'inbox') return showInternetRequest();
  if (action === 'check-access' || action === 'check-status') {
    outcome = undefined;activeRequest = undefined;
    await refreshWalletState().catch(()=>{});
    await checkConnection();draw();return;
  }
  if (action === 'send-request') {
    const id=button.dataset.walletRequestSign;
    if (id && id === currentView?.request?.id) return onRequestClick(id);
    return;
  }
  if (action === 'select-request') {
    selectedId = button.dataset.focusKey.slice('select-request:'.length);showPicker=false;
    outcome = undefined;activeRequest = undefined;draw();return;
  }
  if (action === 'view-requests') {outcome=undefined;activeRequest=undefined;selectedId=undefined;showPicker=true;draw();return;}
  if (action === 'copy-link' || action === 'copy-address') {
    const copyingQR=qrControls,copyingStage=copyFeedbackKey();
    copying=true;button.disabled = true;
    try {
      if (action === 'copy-link') await copyingQR.copy();
      else await homeClipboard.writeText(button.dataset.focusKey.slice('copy-address:'.length),{purpose:'wallet.address'});
      if (copyFeedbackKey() !== copyingStage || action === 'copy-link' && qrControls !== copyingQR) return;
      clipboardFeedback = action === 'copy-link' ? 'Connection link copied. Open it in your wallet app.' : 'Address copied.';
      clipboardFeedbackKey=copyingStage;
    } catch { if (copyFeedbackKey() !== copyingStage || action === 'copy-link' && qrControls !== copyingQR) return;clipboardFeedbackKey=copyingStage;clipboardFeedback = action === 'copy-link' ? 'Home could not copy the connection link. Select Copy link to try again.' : 'Home could not copy the address. Select Copy to try again.'; }
    finally { copying=false;button.disabled = false;draw(); }
  }
});
root.addEventListener('focusin',event=>{
  const node=event.target;
  if(node?.dataset&&(node.dataset.action||node.dataset.focus))rememberedFocus={key:renderKey,action:node.dataset.action,focusKey:node.dataset.focusKey,outcome:node.dataset.focus};
});
root.addEventListener('keydown',event=>{
  if (!currentView) return;
  const result = connectionKey(currentView,{key:event.key,shiftKey:event.shiftKey,action:document.activeElement?.dataset.action});
  if (!result) return;
  event.preventDefault();
  if (result.intent === 'cancel') qrControls?.cancel();
  else root.querySelector(`[data-action="${result.focus}"]`)?.focus();
});
window.addEventListener('focus',()=>{
  if (!root.contains(document.activeElement) && rememberedFocus?.key === renderKey) {
    const target=[...root.querySelectorAll('[data-action],[data-focus]')].find(node=>rememberedFocus.action ? node.dataset.action===rememberedFocus.action&&node.dataset.focusKey===rememberedFocus.focusKey : node.dataset.focus===rememberedFocus.outcome);
    target?.focus({preventScroll:true});
  }
  refreshReturnedWindow();
});
window.addEventListener('message',event=>{
  if (event.source !== window.parent || event.origin !== 'null' || event.data?.type !== 'elastos:shell-layout') return;
  if (event.data.layout?.visible === true) refreshReturnedWindow();
});

function draw() {
  const now = Math.floor(Date.now()/1000);
  const presentation = windowPresentation({connection:connectionState,accounts:linkedAccounts,requests,busy:hostEffectInFlight && !outcome,
    phase:currentPhase,checking:currentPhase==='checking',effectPhase,permission:permissionStatus,pending:pendingEffect,ownerNeeded:ownerConsentNeeded,expired:launchExpired,
    outcome,qrData,selectedId,activeRequest,deadline,homeOrigin,action:recoveryAction,unrecordedHash,proofAccount,walletChanged,dispatchedRequestId},now);
  const requestReady=['request-waiting','request-multiple','transaction-waiting','request-new-connection'].includes(presentation.input.stage);
  if (connectionNeedsReplacement && requestReady && !hostEffectInFlight) presentation.input.stage = 'request-new-connection';
  if (showPicker && requestReady && presentation.request && requests.length > 0) presentation.input.stage = 'request-list';
  const stage = presentation.input.stage;
  currentView=walletConnectView(presentation);
  const key = `${stage}:${currentView.request?.id || ''}`;
  const previous = root.querySelector('main');
  const focus = document.activeElement;
  const same = key === renderKey;
  const scroll = same ? {top:previous?.scrollTop || 0,content:previous?.querySelector('.connection-content')?.scrollTop || 0} : null;
  const focusAction = same && root.contains(focus) ? focus.dataset.action : null;
  const focusKey = focusAction ? focus.dataset.focusKey : null;
  const focusOutcome = same && root.contains(focus) ? focus.dataset.focus : null;
  const hadFocus=document.hasFocus();
  if(root.contains(focus)&&(focus.dataset.action||focus.dataset.focus))rememberedFocus={key:renderKey,action:focus.dataset.action,focusKey:focus.dataset.focusKey,outcome:focus.dataset.focus};
  const tree = renderConnection(document,currentView);
  // The shared owner's capability input is pending. Withhold N1 intents; retain
  // only base actions, so every visible control has an existing effect.
  for (const button of tree.querySelectorAll('[data-action]')) {
    if (!baseActions.has(button.dataset.action) || button.dataset.action === 'finish' && (!connectionState?.session?.address || !/^eip155:(1|20|8453|11155111)$/.test(connectionState.session.chain))) button.remove();
    else if (copying && ['copy-link','copy-address'].includes(button.dataset.action)) button.disabled=true;
    else if (hostEffectInFlight && !['cancel','stop-waiting','copy-link'].includes(button.dataset.action)) button.disabled = true;
  }
  if (presentation.checkingMessage) {tree.querySelector('[data-focus=outcome]').textContent=presentation.checkingMessage;tree.querySelector('.connection-wait')?.remove();tree.querySelector('.connection-notice').textContent='Stopping here ends this wait. Home may still record the response.';}
  if (presentation.connectionNotice) {const node=tree.querySelector('[data-focus=outcome],.connection-wait,.connection-notice');if(node)node.textContent+=' '+presentation.connectionNotice;}
  if (presentation.hashNotice) {const node=tree.querySelector('.connection-notice');node.textContent+='\n'+presentation.hashNotice;node.style.whiteSpace='pre-line';node.style.overflowWrap='anywhere';node.style.userSelect='text';}
  if (presentation.preparingMessage) tree.querySelector('[data-focus=outcome]').textContent=presentation.preparingMessage;
  if (clipboardFeedback && clipboardFeedbackKey === `${key}:${currentView.account?.accounts[0]?.address || ''}`) {
    const status = tree.querySelector('.connection-dialog p:last-of-type') || tree.querySelector('[data-focus="outcome"]');
    if (status) {status.textContent=clipboardFeedback;status.setAttribute('role','status');status.setAttribute('aria-live','polite');}
  }
  for (const button of tree.querySelectorAll('[data-action=send-request]')) {button.dataset.walletRequestSign=presentation.request.request_id;button.dataset.walletRequestIntent=presentation.request.intent;}
  root.replaceChildren(tree);renderKey=key;
  if (scroll) {tree.scrollTop=scroll.top;const content=tree.querySelector('.connection-content');if(content)content.scrollTop=scroll.content;}
  const controls = [...tree.querySelectorAll('[data-action]')];
  if (!hadFocus) return;
  if (focusAction) {
    const target = controls.find(node=>node.dataset.action === focusAction && node.dataset.focusKey === focusKey);
    if(target){const r=target.getBoundingClientRect();target.focus({preventScroll:r.top>=0&&r.bottom<=innerHeight});}
  } else if (focusOutcome) {
    [...tree.querySelectorAll('[data-focus]')].find(node=>node.dataset.focus===focusOutcome)?.focus({preventScroll:true});
  } else if (!same) {
    const target = controls.find(node=>node.dataset.action === currentView.focus) || tree.querySelector(`[data-focus="${currentView.focus}"]`);
    target?.focus({preventScroll:true});
  }
}

function watchConnection() {
  if (launchExpired) {clearInterval(connectionTimer);connectionTimer=undefined;return;}
  if (!frameHomeToken) return;
  const interval = pendingEffect || hostEffectInFlight || permissionStatus && permissionStatus !== 'granted' || qrData ? 1000 : 5000;
  if (connectionTimer && connectionInterval === interval) return;
  clearInterval(connectionTimer);connectionInterval=interval;
  connectionTimer = setInterval(checkConnection,interval);
}
async function checkConnection() {
  if (launchExpired || !frameHomeToken || !accountsLoaded) return;
  if (pendingEffect && (!pendingEffect.requestId || !Number.isFinite(pendingEffect.expiresAt) || pendingEffect.expiresAt <= Date.now())) pendingEffect=undefined;
  if (connectionCheckInFlight) {watchConnection();return;}
  connectionCheckInFlight=true;
  try {
    const saved=pendingEffect,epoch=actionEpoch;
    const current=await connector.effect({kind:'status'});
    if (epoch !== actionEpoch && current.permission.status === 'granted') return;
    const previousPermission=permissionStatus;
    if (current.permissionFresh !== false) permissionStatus=current.permission.status;
    if (permissionStatus === 'granted') ownerConsentNeeded=false;
    if (current.permissionFresh !== false && saved && pendingEffect === saved && (!saved.requestId || !Number.isFinite(saved.expiresAt) || saved.expiresAt <= Date.now() || current.permission.request?.id !== saved.requestId || !['requested','granted'].includes(permissionStatus))) pendingEffect=undefined;
    connectionState=current;
    if (previousPermission !== permissionStatus && !activeRequest) outcome=undefined;
    if (previousPermission !== permissionStatus && permissionStatus === 'granted' && activeRequest?.request_id !== dispatchedRequestId && !hostEffectInFlight) {outcome=undefined;activeRequest=undefined;}
    draw();
    if (current.permissionFresh !== false && permissionStatus === 'granted' && pendingEffect && pendingEffect === saved && !hostEffectInFlight) {
      const resume=pendingEffect.run;pendingEffect=undefined;resume();return;
    }
  } catch {} // A failed background read cannot change the wallet's last known outcome.
  finally {
    connectionCheckInFlight=false;watchConnection();
    if (connectionReturnPending) {connectionReturnPending=false;checkConnection().catch(()=>{});}
  }
}
function refreshReturnedWindow() {
  refreshWalletState().catch(()=>{});
  if (connectionCheckInFlight) connectionReturnPending=true;
  else checkConnection().catch(()=>{});
}
async function refreshWalletState() {
  if (!frameHomeToken) {launchExpired=true;draw();return;}
  const revision=++walletStateRevision;
  const [accountSummary,requestSummary]=await Promise.all([
    fetchJson(`/api/apps/${CONNECTOR_ID}/wallet/accounts`,{headers:shellHeaders()}),
    fetchJson(`/api/apps/${CONNECTOR_ID}/wallet/approvals`,{headers:shellHeaders()}),
  ]);
  if (revision !== walletStateRevision) return;
  linkedAccounts=Array.isArray(accountSummary?.accounts) ? accountSummary.accounts : [];
  requests=(Array.isArray(requestSummary?.approval_requests) ? requestSummary.approval_requests : []).filter(signableRequest).map(row=>({...row,capsule_id:readText(row.capsule_id)}));
  if (selectedId && !requests.some(row=>row.request_id===selectedId)) selectedId=undefined;
  if (outcome==='request-done' && activeRequest && requests.some(row=>row.request_id !== activeRequest.request_id)) outcome='request-next';
  const first=!accountsLoaded;accountsLoaded=true;draw();
  if (first) checkConnection().catch(()=>{});
}
function copyFeedbackKey() {return `${renderKey}:${currentView?.account?.accounts[0]?.address || ''}`;}
function resetFeedback() {proofAccount=undefined;unrecordedHash=undefined;dispatchedRequestId=undefined;walletChanged=false;outcome=undefined;clipboardFeedback='';deadline=undefined;}
async function onConnect({fresh=true}={}) {
  if (hostEffectInFlight || launchExpired) return;
  resetFeedback();activeRequest=undefined;connectionNeedsReplacement=false;
  const epoch=++actionEpoch;currentPhase='starting';effectPhase='starting';
  try {
    await requestCapsuleWalletEffect({kind:'link',fresh});
    if (epoch !== actionEpoch) return;
    notifyHomeSummaryChanged();await refreshWalletState();outcome=undefined;
  } catch (error) {if (epoch === actionEpoch && !outcome && !awaitingAccess()) {connectionNeedsReplacement=Boolean(error.freshConnection);outcome=errorStage(error,recoveryAction,effectPhase);}}
  finally {if (epoch === actionEpoch) {draw();checkConnection().catch(()=>{});}}
}
async function onRequestClick(approvalRequestId=currentView?.request?.id || selectedId) {
  if (hostEffectInFlight || launchExpired) return;
  const request=(approvalRequestId ? requests.find(row=>row.request_id === approvalRequestId) : requests[0]) || (activeRequest?.request_id === approvalRequestId ? activeRequest : undefined);
  if (!request) return;
  resetFeedback();activeRequest=structuredClone(request);
  const epoch=++actionEpoch;currentPhase='starting';effectPhase='starting';
  try {
    await requestCapsuleWalletEffect({kind:'approve',approvalRequestId:request.request_id,intent:request.intent});
    if (epoch !== actionEpoch) return;
    notifyHomeSummaryChanged();await refreshWalletState();
  } catch (error) {if (epoch === actionEpoch && !outcome && !awaitingAccess()) {connectionNeedsReplacement=Boolean(error.freshConnection);outcome=errorStage(error,recoveryAction,effectPhase);}}
  finally {draw();}
}
async function disconnect() {
  if (hostEffectInFlight || launchExpired) return;
  resetFeedback();const epoch=++actionEpoch;currentPhase='disconnecting';effectPhase='disconnecting';
  try {await requestCapsuleWalletEffect({kind:'disconnect'});if(epoch===actionEpoch){connectionState=undefined;outcome='disconnected';}}
  catch(error){showError(error);}
  finally{draw();checkConnection().catch(()=>{});}
}
async function cancelWalletWait() {
  const phase=currentPhase === 'checking' ? effectPhase : currentPhase;
  const knownHash=currentPhase === 'checking' && phase === 'transaction' ? unrecordedHash : undefined;
  const sentId=dispatchedRequestId;
  const unsent=Boolean(pendingEffect) || activeRequest && activeRequest.request_id !== sentId;
  ++actionEpoch;pendingEffect=undefined;resetFeedback();unrecordedHash=knownHash;dispatchedRequestId=sentId;
  try {await connector.effect({kind:'cancel'});connectionState=undefined;
    if (unsent) {activeRequest=undefined;outcome=undefined;}
    else outcome=phase === 'ownership' ? 'link-cancelled' : phase === 'signature' ? 'request-cancelled' : phase === 'transaction' ? 'transaction-cancelled' : 'qr-cancelled';
  } catch(error){showError(error);}
  finally {hostEffectInFlight=false;currentPhase='idle';draw();watchConnection();refreshWalletState().catch(()=>{});}
}
async function requestCapsuleWalletEffect(action) {
  const epoch=actionEpoch;recoveryAction=action;pendingEffect=undefined;
  watchConnection();
  if (!frameHomeToken || hostEffectInFlight) throw new Error('A wallet request is already active.');
  hostEffectInFlight=true;draw();watchConnection();
  try {
    if (['link','approve'].includes(action.kind)) {
      const consent=await api('internet',{method:'POST',body:JSON.stringify({action:'request'})});
      permissionStatus=consent.status;
      if (consent.status === 'granted') ownerConsentNeeded=false;
      if (consent.status !== 'granted') {
        pendingEffect={requestId:consent.request?.id,expiresAt:(consent.request?.issued_at+1800)*1000,action,run:action.kind === 'link' ? ()=>onConnect({fresh:action.fresh !== false}) : ()=>onRequestClick(action.approvalRequestId)};
        watchConnection();showInternetRequest();
        throw Object.assign(new Error('WalletConnect needs internet access. The Home owner can allow it in Inbox. Then continue here.'),{tone:'muted'});
      }
    }
    const result=await connector.effect(action);
    if (epoch === actionEpoch) {
      if (action.kind === 'approve') {outcome=result.effect === 'transaction' ? 'transaction-done' : 'request-done';activeRequest.status='completed';}
      else outcome=action.kind === 'link' ? walletChanged ? undefined : 'linked' : 'disconnected';
      draw();
    }
    return result;
  } catch(error) {
    if (epoch === actionEpoch && /^0x[0-9a-fA-F]{64}$/.test(error?.transactionHash || '')) unrecordedHash=error.transactionHash;
    if (epoch === actionEpoch && !awaitingAccess()) {connectionNeedsReplacement=Boolean(error.freshConnection);outcome=errorStage(error,action,effectPhase);draw();}
    throw error;
  } finally {
    if (epoch === actionEpoch) {
      hostEffectInFlight=false;currentPhase='idle';effectPhase='idle';
      deadline=undefined;
      try {connectionState=await connector.effect({kind:'status'});if(connectionState.permissionFresh !== false)permissionStatus=connectionState.permission.status;if(permissionStatus==='granted')ownerConsentNeeded=false;}catch{}
      draw();watchConnection();
    }
    await refreshWalletState().catch(()=>{});
  }
}
function showInternetRequest() {window.top.postMessage({type:'home:open-target',target:'inbox',query:{notification_id:'walletconnect-internet:permission'},homeToken:frameHomeToken},homeOrigin);}
async function copyConnectionLink(uri,{signal}) {
  signal.throwIfAborted();
  if (!homeClipboard.canRequest()) throw new Error('Home Clipboard is unavailable.');
  const requestId=homeClipboard.newRequestId(),cancel=()=>homeClipboard.cancel(requestId);
  signal.addEventListener('abort',cancel,{once:true});
  try {await homeClipboard.writeText(uri,{purpose:'wallet.connection-link',requestId});signal.throwIfAborted();}
  finally {signal.removeEventListener('abort',cancel);}
}
async function fetchJson(url,init) {
  const response=await fetch(url,init);
  if (!response.ok) {
    const detail=await response.text().catch(()=>'');
    if (detail.trim() === "Only this Home's owner can allow WalletConnect internet access. Ask the owner to review Inbox.") {
      ownerConsentNeeded=true;permissionStatus='off';pendingEffect=undefined;draw();watchConnection();
      throw Object.assign(new Error('The Home owner can allow WalletConnect internet access in Inbox.'),{tone:'muted'});
    }
    if (response.status === 403) {launchExpired=true;draw();watchConnection();}
    throw new Error(response.status === 403 ? 'This wallet window expired. Close it and open WalletConnect again.' : detail.trim() || 'ElastOS could not complete this request. Try again.');
  }
  return response.json();
}
function shellHeaders(extra={}) {return {...extra,'x-elastos-home-token':frameHomeToken};}
function notifyHomeSummaryChanged() {if(frameHomeToken && homeOrigin && window.top !== window)window.top.postMessage({type:'home:refresh-summary',homeToken:frameHomeToken},homeOrigin);}
function readText(value) {return typeof value === 'string' ? value.trim() : '';}
function knownOutcome() {return ['linked','request-done','request-next','transaction-done','request-declined','transaction-declined'].includes(outcome);}
function awaitingAccess() {return Boolean(pendingEffect) || permissionStatus !== 'granted' && Boolean(ownerConsentNeeded || activeRequest && activeRequest.request_id !== dispatchedRequestId);}
function showError(error) {if(!launchExpired && !hostEffectInFlight && !knownOutcome()){outcome=activeRequest ? errorStage(error,recoveryAction,effectPhase) : 'link-error';}draw();}

draw();watchConnection();refreshWalletState().catch(showError);
