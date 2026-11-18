import {installWalletConnectStorage} from './walletconnect-storage.mjs';
import {createWalletConnectClient} from './walletconnect-client.mjs';
import {connectionView, reduceSummary, renderConnection, connectionKey} from './wallet-connection-view.mjs';
import {windowPresentation, errorStage, baseActions, signableRequest, connectorId} from './walletconnect-window-state.mjs';
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
let outcome, activeRequest, selectedId, deadline, qrData, qrControls, currentView, renderKey;
let showPicker = false;
let copying=false;
let clipboardFeedback = '';

const homeClipboard = createHomeClipboardClient({targetId: CONNECTOR_ID,homeOrigin,homeToken:frameHomeToken});
homeClipboard.start();
const api = (resource, init={}) => fetchJson(resource.startsWith('/api/') ? runtimeOrigin + resource : `${runtimeOrigin}/api/apps/${CONNECTOR_ID}/${resource}`, {
  ...init,headers:shellHeaders({...init.headers,'content-type':'application/json'}),
});
const connector = createWalletConnectClient({api,origin:runtimeOrigin,clearMemory,copyLink:copyConnectionLink,
  pairingView:{show(data, controls){qrData=data;qrControls=controls;draw();},hide(result){qrData=undefined;qrControls=undefined;clipboardFeedback='';if(result?.connected)currentPhase='confirming';draw();}},
  onPhase(phase, detail) {
    if (phase === 'changed') {
      walletChanged ||= ['accountsChanged','chainChanged','session_update'].includes(detail?.event) && ['ownership','signature','transaction'].includes(currentPhase);
      // Wallet notifications carry facts locally. Home authority stays on the base routes.
      clipboardFeedback='';
      const identityEvent=['accountsChanged','chainChanged','session_update'].includes(detail?.event);
      if (identityEvent || !activeRequest) outcome=undefined;
      if (!hostEffectInFlight && identityEvent) activeRequest=undefined;
      refreshReturnedWindow();
      return;
    }
    if (phase !== 'pairing') clipboardFeedback='';
    currentPhase = phase;effectPhase=phase;
    if (['ownership','signature','transaction'].includes(phase)) {
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
    await refreshWalletState().catch(showError);
    await checkConnection();draw();return;
  }
  if (action === 'send-request') return onRequestClick();
  if (action === 'select-request') {
    selectedId = button.dataset.focusKey.slice('select-request:'.length);showPicker=false;
    outcome = undefined;activeRequest = undefined;draw();return;
  }
  if (action === 'view-requests') {outcome=undefined;activeRequest=undefined;selectedId=undefined;showPicker=true;draw();return;}
  if (action === 'copy-link' || action === 'copy-address') {
    const copyingQR=qrControls,copyingStage=renderKey;
    copying=true;button.disabled = true;
    try {
      if (action === 'copy-link') await copyingQR.copy();
      else await homeClipboard.writeText(button.dataset.focusKey.slice('copy-address:'.length),{purpose:'wallet.address'});
      if (renderKey !== copyingStage || action === 'copy-link' && qrControls !== copyingQR) return;
      clipboardFeedback = action === 'copy-link' ? 'Connection link copied. Open it in your wallet app.' : 'Address copied.';
    } catch { if (renderKey !== copyingStage || action === 'copy-link' && qrControls !== copyingQR) return;clipboardFeedback = action === 'copy-link' ? 'Home could not copy the connection link. Select Copy link to try again.' : 'Home could not copy the address. Select Copy to try again.'; }
    finally { copying=false;button.disabled = false;draw(); }
  }
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
    phase:currentPhase,permission:permissionStatus,pending:pendingEffect,ownerNeeded:ownerConsentNeeded,expired:launchExpired,
    outcome,qrData,selectedId,activeRequest,deadline,homeOrigin,action:recoveryAction,walletChanged,dispatched:['signature','transaction'].includes(effectPhase)},now);
  if (connectionNeedsReplacement && presentation.request && !hostEffectInFlight) presentation.input.stage = 'request-new-connection';
  if (showPicker && presentation.request && requests.length > 1) presentation.input.stage = 'request-list';
  const stage = presentation.input.stage;
  const key = `${stage}:${presentation.request?.request_id || ''}`;
  const previous = root.querySelector('main');
  const focus = document.activeElement;
  const same = key === renderKey;
  const scroll = same ? {top:previous?.scrollTop || 0,content:previous?.querySelector('.connection-content')?.scrollTop || 0} : null;
  const focusAction = same && root.contains(focus) ? focus.dataset.action : null;
  const focusKey = focusAction ? focus.dataset.focusKey : null;
  const focusOutcome = same && root.contains(focus) ? focus.dataset.focus : null;
  const hadFocus=document.hasFocus();
  if(root.contains(focus))rememberedFocus={key:renderKey,action:focus.dataset.action,focusKey:focus.dataset.focusKey,outcome:focus.dataset.focus};
  currentView = connectionView({...presentation.input,summary:presentation.request ? reduceSummary(presentation.request,{connector:CONNECTOR_ID}) : null,otherRequests:presentation.otherRequests.map(row=>reduceSummary(row,{connector:CONNECTOR_ID})).filter(Boolean)});
  const tree = renderConnection(document,currentView);
  // The shared owner's capability input is pending. Withhold N1 intents; retain
  // only base actions, so every visible control has an existing effect.
  for (const button of tree.querySelectorAll('[data-action]')) {
    if (!baseActions.has(button.dataset.action) || button.dataset.action === 'finish' && (!connectionState?.session?.address || !/^eip155:(1|20|8453|11155111)$/.test(connectionState.session.chain))) button.remove();
    else if (copying && ['copy-link','copy-address'].includes(button.dataset.action)) button.disabled=true;
    else if (hostEffectInFlight && !['cancel','stop-waiting','copy-link'].includes(button.dataset.action)) button.disabled = true;
  }
  if (presentation.connectionNotice) {const node=tree.querySelector('[data-focus=outcome],.connection-wait,.connection-notice');if(node)node.textContent+=' '+presentation.connectionNotice;}
  if (presentation.preparingMessage) tree.querySelector('[data-focus=outcome]').textContent=presentation.preparingMessage;
  if (clipboardFeedback) {
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
    permissionStatus=current.permission.status;
    if (permissionStatus === 'granted') ownerConsentNeeded=false;
    if (saved && pendingEffect === saved && (!saved.requestId || !Number.isFinite(saved.expiresAt) || saved.expiresAt <= Date.now() || current.permission.request?.id !== saved.requestId || !['requested','granted'].includes(permissionStatus))) pendingEffect=undefined;
    connectionState=current;
    if (previousPermission !== permissionStatus) outcome=undefined;
    draw();
    if (permissionStatus === 'granted' && pendingEffect && pendingEffect === saved && !hostEffectInFlight) {
      const resume=pendingEffect.run;pendingEffect=undefined;resume();return;
    }
  } catch (error) {if (!hostEffectInFlight) showError(error);}
  finally {
    connectionCheckInFlight=false;watchConnection();
    if (connectionReturnPending) {connectionReturnPending=false;checkConnection().catch(()=>{});}
  }
}
function refreshReturnedWindow() {
  refreshWalletState().catch(showError);
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
  if (outcome && activeRequest && requests.some(row=>row.request_id !== activeRequest.request_id)) {outcome=undefined;activeRequest=undefined;}
  const first=!accountsLoaded;accountsLoaded=true;draw();
  if (first) checkConnection().catch(()=>{});
}
function resetFeedback() {walletChanged=false;outcome=undefined;clipboardFeedback='';deadline=undefined;}
async function onConnect({fresh=true}={}) {
  if (hostEffectInFlight || launchExpired) return;
  resetFeedback();activeRequest=undefined;connectionNeedsReplacement=false;
  const epoch=++actionEpoch;currentPhase='starting';effectPhase='starting';
  try {
    await requestCapsuleWalletEffect({kind:'link',fresh});
    if (epoch !== actionEpoch) return;
    notifyHomeSummaryChanged();await refreshWalletState();outcome=undefined;
  } catch (error) {if (epoch === actionEpoch) {connectionNeedsReplacement=Boolean(error.freshConnection);outcome=errorStage(error,recoveryAction,effectPhase);}}
  finally {if (epoch === actionEpoch) {draw();checkConnection().catch(()=>{});}}
}
async function onRequestClick(approvalRequestId=selectedId) {
  if (hostEffectInFlight || launchExpired) return;
  const request=approvalRequestId ? requests.find(row=>row.request_id === approvalRequestId) : requests[0];
  if (!request || request.status !== 'pending') return;
  resetFeedback();activeRequest=structuredClone(request);
  const epoch=++actionEpoch;currentPhase='starting';effectPhase='starting';
  try {
    await requestCapsuleWalletEffect({kind:'approve',approvalRequestId:request.request_id,intent:request.intent});
    if (epoch !== actionEpoch) return;
    notifyHomeSummaryChanged();await refreshWalletState();
  } catch (error) {if (epoch === actionEpoch) {connectionNeedsReplacement=Boolean(error.freshConnection);outcome=errorStage(error,recoveryAction,effectPhase);}}
  finally {draw();}
}
async function disconnect() {
  if (hostEffectInFlight || launchExpired) return;
  resetFeedback();const epoch=++actionEpoch;currentPhase='disconnecting';
  try {await requestCapsuleWalletEffect({kind:'disconnect'});if(epoch===actionEpoch){connectionState=undefined;outcome='disconnected';}}
  catch(error){showError(error);}
  finally{draw();checkConnection().catch(()=>{});}
}
async function cancelWalletWait() {
  const phase=currentPhase;
  ++actionEpoch;pendingEffect=undefined;resetFeedback();
  try {await connector.effect({kind:'cancel'});connectionState=undefined;
    outcome=phase === 'ownership' ? 'link-cancelled' : phase === 'signature' ? 'request-cancelled' : phase === 'transaction' ? 'transaction-cancelled' : 'qr-cancelled';
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
      else outcome=action.kind === 'link' ? 'linked' : 'disconnected';
      draw();
    }
    return result;
  } catch(error) {
    if (epoch === actionEpoch) {connectionNeedsReplacement=Boolean(error.freshConnection);outcome=errorStage(error,action,effectPhase);draw();}
    throw error;
  } finally {
    if (epoch === actionEpoch) {
      hostEffectInFlight=false;currentPhase='idle';
      try {connectionState=await connector.effect({kind:'status'});permissionStatus=connectionState.permission.status;if(permissionStatus==='granted')ownerConsentNeeded=false;}catch{}
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
function showError(error) {if(!launchExpired){outcome=activeRequest ? errorStage(error,recoveryAction,effectPhase) : 'link-error';}draw();}

draw();watchConnection();refreshWalletState().catch(showError);
