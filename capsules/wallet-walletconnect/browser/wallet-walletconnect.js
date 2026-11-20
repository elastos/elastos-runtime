import {installWalletConnectStorage} from './walletconnect-storage.mjs';
import {createWalletConnectClient} from './walletconnect-client.mjs';
import {mountConnection, captureConnectionPresentation, connectionKey} from './wallet-connection-view.mjs';
import {windowPresentation, walletConnectView, errorStage, baseActions, signableRequest, connectorId, sameAccount} from './walletconnect-window-state.mjs';
import {createHomeClipboardClient} from "/apps/home/home-clipboard-client.js?v=home-20260726a";

const CONNECTOR_ID = connectorId;
const root = document.querySelector('#wallet-window');
const frameHomeToken = readText(new URLSearchParams(location.hash.slice(1)).get('home_token'));
const homeOrigin = readText(new URLSearchParams(location.search).get('home_origin'));
const runtimeOrigin = new URL(import.meta.url).origin;
const clearMemory = installWalletConnectStorage(window);
let hostEffectInFlight = false, walletStateRevision = 0, connectionCheckInFlight = false, actionEpoch = 0;
let walletChanged=false;
let walletChange;
let effectPhase = 'idle';
let currentPhase = 'idle', connectionState, linkedAccounts = [], requests = [], accountsLoaded = false;
let recoveryAction, launchExpired = false, ownerConsentNeeded = false, connectionNeedsReplacement = false;
let pendingEffect, permissionStatus, connectionReturnPending = false, connectionTimer, connectionInterval;
let rememberedFocus, mounted;
let connectionPage, homeReadFailed=false;
const requestOutcomes=new Map();
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
    if (phase === 'permission') {
      permissionStatus=detail.status;connectionState={...connectionState,permission:detail};draw();return;
    }
    if (phase === 'changed') {
      walletChanged ||= detail?.selectionChanged === true;
      if (detail?.selectionChanged) {
        const previous=connectionState?.session,next=detail.connection?.session;
        walletChange=!next?.address ? undefined : !sameAccount(previous?.address,next.address) ? 'account-changed' : previous?.chain !== next.chain ? 'network-changed' : walletChange;
      }
      // Wallet notifications carry facts locally. Home authority stays on the base routes.
      clipboardFeedback='';
      if (detail?.connection) connectionState={...connectionState,...detail.connection};
      const identityEvent=detail?.selectionChanged === true;
      const retained=knownOutcome() || activeRequest?.intent === 'transaction_intent' && Boolean(outcome);
      if (identityEvent && !retained && !dispatchedRequestId) outcome=undefined;
      if (!hostEffectInFlight && identityEvent && !retained && !dispatchedRequestId) activeRequest=undefined;
      draw();refreshReturnedWindow();
      return;
    }
    if (phase !== 'pairing') clipboardFeedback='';
    currentPhase = phase;effectPhase=phase;
    if(phase==='ownership')proofAccount={address:detail.address,chain:detail.chain,name:detail.name};
    if (['ownership','signature','transaction'].includes(phase)) {
      if (phase !== 'ownership' && activeRequest) {dispatchedRequestId=activeRequest.request_id;activeRequest.status='approved';activeRequest.walletName=detail?.name;}
      deadline = detail?.expiresAt || activeRequest?.expires_at || Math.floor(Date.now()/1000)+300;
      checkConnection().catch(()=>{});
    }
    draw();
  },
});

root.addEventListener('click', async event => {
  const button = event.target.closest('button[data-action]');
  if (!button || button.disabled || !mounted?.root.contains(button)) return;
  const action = button.dataset.action;
  if (action === 'connect' || action === 'start-over') return onConnect();
  if (action === 'finish' || action === 'send-message') return onConnect({fresh:false});
  if (action === 'cancel') return qrControls ? qrControls.cancel() : cancelWalletWait();
  if (action === 'stop-waiting') return cancelWalletWait();
  if (action === 'disconnect') return disconnect();
  if (action === 'inbox') return showInternetRequest();
  if (action === 'add-account') {connectionPage='add-account';showPicker=false;activeRequest=undefined;selectedId=undefined;outcome=undefined;draw();return;}
  if (action === 'back-to-connection') {
    connectionPage='overview';showPicker=false;activeRequest=undefined;selectedId=undefined;outcome=undefined;draw();return;
  }
  if (action === 'check-access' || action === 'check-status' || action === 'refresh-status') {
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
    connectionPage=undefined;const saved=requestOutcomes.get(selectedId);outcome=saved?.outcome;unrecordedHash=saved?.hash;dispatchedRequestId=saved?.dispatched?selectedId:undefined;activeRequest=requests.find(row=>row.request_id===selectedId);if(activeRequest&&saved?.walletName)activeRequest={...activeRequest,walletName:saved.walletName};draw();return;
  }
  if (action === 'view-requests') {connectionPage=undefined;outcome=undefined;activeRequest=undefined;selectedId=undefined;showPicker=true;draw();return;}
  if (action === 'copy-link' || action === 'copy-address') {
    const copyingQR=qrControls,copyingStage=copyFeedbackKey();
    copying=true;button.disabled = true;
    try {
      if (action === 'copy-link') await copyingQR.copy();
      else await homeClipboard.writeText(button.dataset.focusKey.slice('copy-address:'.length),{purpose:'wallet.address'});
      if (copyFeedbackKey() !== copyingStage || action === 'copy-link' && qrControls !== copyingQR) return;
      clipboardFeedback = action === 'copy-link' ? 'link-copied' : 'address-copied';
      clipboardFeedbackKey=copyingStage;
    } catch { if (copyFeedbackKey() !== copyingStage || action === 'copy-link' && qrControls !== copyingQR) return;clipboardFeedbackKey=copyingStage;clipboardFeedback = 'copy-failed'; }
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
window.addEventListener('pagehide',()=>mounted?.dispose());
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
  if(mounted){const saved=captureConnectionPresentation(mounted.root);if(saved.action)rememberedFocus={key:renderKey,action:document.activeElement?.dataset.action,focusKey:saved.key,outcome:saved.action};}
  if(activeRequest && /^(request|transaction)-/.test(outcome || '')) {
    if(dispatchedRequestId===activeRequest.request_id || unrecordedHash)requestOutcomes.set(activeRequest.request_id,{outcome,hash:unrecordedHash,dispatched:dispatchedRequestId===activeRequest.request_id,walletName:activeRequest.walletName});
    else requestOutcomes.delete(activeRequest.request_id);
  }
  const now = Math.floor(Date.now()/1000);
  const presentation = windowPresentation({loading:!accountsLoaded || !connectionState && !outcome && !hostEffectInFlight && !homeReadFailed && !launchExpired,connection:connectionState,accounts:linkedAccounts,requests:connectionPage ? [] : requests,busy:hostEffectInFlight && !outcome,
    phase:currentPhase,checking:currentPhase==='checking',effectPhase,permission:permissionStatus,pending:pendingEffect,ownerNeeded:ownerConsentNeeded,expired:launchExpired,
    outcome:homeReadFailed&&!knownOutcome()&&!hostEffectInFlight ? 'home-read-unavailable' : outcome,qrData,selectedId,activeRequest,deadline,homeOrigin,action:recoveryAction,unrecordedHash,proofAccount,walletChanged,walletChange,dispatchedRequestId,connectionPage,resultWalletName:outcome?activeRequest?.walletName:undefined,
    paymentPending:requests.some(row=>row.intent==='transaction_intent'&&row.status==='approved'&&!['transaction-declined','transaction-done'].includes(requestOutcomes.get(row.request_id)?.outcome))},now);
  if (connectionPage === 'add-account' && presentation.input.stage === 'linked') {presentation.input.stage='add-account';presentation.input.localReturn=false;}
  if (connectionPage) presentation.otherRequests=requests;
  if (connectionNeedsReplacement && ['request-waiting','request-multiple','transaction-waiting'].includes(presentation.input.stage) && !hostEffectInFlight) presentation.input.stage='request-new-connection';
  const canChooseRequests=Boolean(accountsLoaded&&requests.length&&!hostEffectInFlight&&!launchExpired&&permissionStatus==='granted'&&!homeReadFailed);
  presentation.input.supportedActions=presentation.input.supportedActions.filter(action=>!['view-requests','select-request'].includes(action)||canChooseRequests);
  presentation.input.showNextRequests=canChooseRequests;
  if (showPicker && canChooseRequests) {
    presentation.input.stage='request-list';presentation.input.transactionHash=undefined;presentation.input.walletResult=undefined;presentation.request=requests.find(row=>row.request_id===selectedId)||requests[0];
    presentation.otherRequests=requests.filter(row=>row.request_id!==presentation.request.request_id);
  }
  if (clipboardFeedback && clipboardFeedbackKey === `${presentation.input.stage}:${(presentation.input.stage.startsWith('request-') || presentation.input.stage.startsWith('transaction-') || presentation.input.stage==='checking-response' ? presentation.request?.request_id : '') || ''}:${presentation.input.account?.accounts[0]?.address || ''}`) presentation.input.copyFeedback=clipboardFeedback;
  if (hostEffectInFlight && !outcome) presentation.input.supportedActions=presentation.input.supportedActions.filter(id=>['cancel','stop-waiting','copy-link'].includes(id));
  currentView=walletConnectView(presentation);
  const key=`${currentView.stage}:${currentView.request?.id || ''}`;
  mounted=mountConnection(root,currentView,mounted);renderKey=key;
  for (const button of mounted.root.querySelectorAll('[data-action=send-request]')) {button.dataset.walletRequestSign=currentView.request.id;button.dataset.walletRequestIntent=presentation.request.intent;}
  for(const button of mounted.root.querySelectorAll('[data-action=copy-link],[data-action=copy-address]'))button.disabled=copying;

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
  } catch {
    // Keep established facts on a background failure; an initial failure needs recovery.
    if (!connectionState) {homeReadFailed=true;draw();}
  }
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
  if(activeRequest&&!hostEffectInFlight&&!outcome&&activeRequest.request_id!==dispatchedRequestId&&!requests.some(row=>row.request_id===activeRequest.request_id))activeRequest=undefined;
  if (outcome==='request-done' && activeRequest && requests.some(row=>row.request_id !== activeRequest.request_id)) outcome='request-next';
  for(const id of requestOutcomes.keys())if(id!==activeRequest?.request_id&&!requests.some(row=>row.request_id===id))requestOutcomes.delete(id);
  homeReadFailed=false;const first=!accountsLoaded;accountsLoaded=true;draw();
  if (first) checkConnection().catch(()=>{});
}
function copyFeedbackKey() {return `${renderKey}:${currentView?.account?.accounts[0]?.address || ''}`;}
function resetFeedback() {homeReadFailed=false;connectionPage=undefined;showPicker=false;proofAccount=undefined;unrecordedHash=undefined;dispatchedRequestId=undefined;walletChanged=false;walletChange=undefined;outcome=undefined;clipboardFeedback='';deadline=undefined;}
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
  catch(error){if(epoch===actionEpoch&&!launchExpired)outcome=errorStage(error,{kind:'disconnect'},'disconnecting');}
  finally{draw();checkConnection().catch(()=>{});}
}
async function cancelWalletWait() {
  const phase=currentPhase === 'checking' ? effectPhase : currentPhase;
  const knownHash=currentPhase === 'checking' && phase === 'transaction' ? unrecordedHash : undefined;
  const sentId=dispatchedRequestId;
  const confirmationAccount=phase === 'ownership' ? proofAccount : undefined;
  const unsent=Boolean(pendingEffect) || activeRequest && activeRequest.request_id !== sentId;
  ++actionEpoch;pendingEffect=undefined;resetFeedback();proofAccount=confirmationAccount;unrecordedHash=knownHash;dispatchedRequestId=sentId;
  try {hostEffectInFlight=true;currentPhase='disconnecting';draw();await connector.effect({kind:'cancel'});connectionState={};
    if (unsent) {activeRequest=undefined;outcome=undefined;}
    else outcome=phase === 'ownership' ? 'link-cancelled' : phase === 'signature' ? 'request-cancelled' : phase === 'transaction' ? 'transaction-cancelled' : 'qr-cancelled';
  } catch {outcome=!unsent && activeRequest?.intent === 'transaction_intent' ? 'transaction-wallet-error' : 'disconnect-error';draw();}
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
      if(epoch!==actionEpoch)throw new Error('Wallet connection cancelled.');
      permissionStatus=consent.status;
      if (consent.status === 'granted') ownerConsentNeeded=false;
      if (consent.status !== 'granted') {
        pendingEffect={requestId:consent.request?.id,expiresAt:(consent.request?.issued_at+1800)*1000,action,run:action.kind === 'link' ? ()=>onConnect({fresh:action.fresh !== false}) : ()=>onRequestClick(action.approvalRequestId)};
        watchConnection();showInternetRequest();
        throw Object.assign(new Error('WalletConnect needs internet access. An admin of this Home can allow it in Inbox. Then continue here.'),{tone:'muted'});
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
      deadline=undefined;draw();watchConnection();
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
    let code;
    try {code=JSON.parse(detail).code;} catch {}
    if (response.status === 403 && code === 'walletconnect_admin_required') {
      ownerConsentNeeded=true;permissionStatus='off';pendingEffect=undefined;draw();watchConnection();
      throw Object.assign(new Error('An admin of this Home can allow WalletConnect internet access in Inbox.'),{tone:'muted'});
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
function showError(error) {homeReadFailed=true;if(!launchExpired && !hostEffectInFlight && !knownOutcome()){outcome=activeRequest ? errorStage(error,recoveryAction,effectPhase) : 'link-error';}draw();}

draw();watchConnection();refreshWalletState().catch(showError);
