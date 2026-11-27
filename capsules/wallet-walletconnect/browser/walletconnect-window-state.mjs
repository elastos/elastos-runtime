import {screens} from './wallet-connection-screens.mjs';
import {connectionView,reduceSummary} from './wallet-connection-view.mjs';
import {isWalletConnectNetwork, walletConnectMessages as messages} from './walletconnect-client.mjs';

export const connectorId = 'wallet-walletconnect';
export const sameAccount = (a,b) => String(a || '').toLowerCase() === String(b || '').toLowerCase();
export const networkLabel = value => ({'eip155:1':'Ethereum','eip155:20':'Elastos Smart Chain','eip155:8453':'Base','eip155:11155111':'Sepolia test network'}[value] || `Unsupported network (${String(value || '').slice(0,60)})`);
export const signableRequest = request => request?.connector_id === connectorId && !['managed_evm','managed_btc_p2wpkh'].includes(request.proof_type) && request.intent !== 'bitcoin_bip322_proof' && ['siwe','siwe_erc1271'].includes(request.proof_type);
export const sessionLinked = (session, accounts) => Boolean(session && accounts.some(account => account.chain_namespace === session.chain && sameAccount(account.address, session.address)));
export const sendable = (request, now) => request.status === 'pending' && isWalletConnectNetwork(request.chain_namespace) && request.intent !== 'browser_typed_data_sign' && request.expires_at - now >= (request.intent === 'transaction_intent' ? 300 : 1);

// Presentation uses the clock supplied by the window. It grants no authority.
export function windowPresentation(state, nowSeconds) {
  const {connection, accounts = [], requests = [], busy, phase, permission, pending, ownerNeeded, expired, outcome, qrData, selectedId, activeRequest} = state;
  const session = connection?.session;
  const request = activeRequest || requests.find(row => row.request_id === selectedId) || requests.find(row=>row.request_id===state.dispatchedRequestId) || requests.find(row=>sendable(row,nowSeconds));
  const sent = Boolean(request && (state.dispatchedRequestId === request.request_id || request.status === 'approved' && request.intent === 'transaction_intent'));
  const completed = ['request-done','request-next','transaction-done'].includes(outcome);
  const walletDeclined=request?.wallet_outcome==='declined';
  const answered = completed || walletDeclined || ['request-declined','transaction-declined'].includes(outcome);
  const linked = sessionLinked(session, accounts) || Boolean(outcome === 'linked' && session && state.proofAccount && sameAccount(session.address,state.proofAccount.address) && session.chain === state.proofAccount.chain);
  // Once dispatched, a payment owns this window until its answer is known.
  // QR, launch, access and connection changes cannot turn it into a new send.
  const unresolvedPayment = request?.intent === 'transaction_intent' && sent && !answered;
  let stage;
  if (unresolvedPayment) {
    if (['transaction-cancelled','transaction-timeout','transaction-wallet-error'].includes(outcome)) stage=outcome;
    else if (state.checking || busy && phase === 'checking') stage='checking-response';
    else if (connection?.removed) stage='transaction-wallet-removed';
    else if (expired || state.loading || permission && permission !== 'granted' || connection?.expired) stage='transaction-wallet-error';
    else if (busy && phase === 'transaction') stage='transaction-phone';
    else stage='transaction-reopened';
  }
  else if (expired) stage = 'window-expired';
  else if (state.loading) stage = outcome==='home-read-unavailable' ? outcome : 'wallet-loading';
  else if (answered) stage=walletDeclined?request.intent==='transaction_intent'?'transaction-declined':'request-declined':outcome;
  else if (outcome === 'request-unavailable' && !sent && (connection?.removed || connection?.expired || permission && permission !== 'granted')) stage=outcome;
  else if (sent && permission && permission !== 'granted') stage=request.intent === 'transaction_intent' ? 'transaction-wallet-error' : 'request-unavailable';
  else if (busy && phase === 'disconnecting') stage = 'disconnecting';
  else if (state.cleanupPending && permission !== 'granted') stage='internet-clearing';
  else if (ownerNeeded && permission !== 'granted') stage = 'guest-access';
  else if (permission === 'requested') stage = pending ? request ? 'request-internet-pending' : 'internet-pending' : request ? 'request-internet-off' : 'internet-off';
  else if (permission === 'refused' || permission === 'revoked' && !request) stage = 'internet-refused';
  else if (permission === 'revoked' && connection) stage = request ? 'request-internet-off' : 'internet-off';
  else if (qrData) stage = 'qr-shown';
  else if (busy) {stage = state.checking ? 'checking-response' : phase === 'ownership' ? 'link-wait' : phase === 'signature' ? 'request-phone' : phase === 'transaction' ? 'transaction-phone' : phase === 'disconnecting' ? 'disconnecting' : state.action?.kind === 'approve' ? 'preparing-request' : phase === 'confirming' || state.action?.fresh === false ? 'preparing-connection' : 'preparing-qr';}
  else if (!sent && request?.status === 'pending' && request.expires_at <= nowSeconds) stage='request-expired';
  else if (state.walletChanged && session && !linked && !sent && ['linked','link-error','request-wallet-error','request-unsendable','request-unavailable'].includes(outcome)) stage = 'account-changed';
  else if (connection?.removed && outcome !== 'disconnected') stage = request ? sent ? request.intent === 'transaction_intent' ? 'transaction-wallet-removed' : 'request-sent-wallet-removed' : 'request-wallet-removed' : 'wallet-removed';
  else if (connection?.expired && outcome !== 'disconnected') stage = request ? sent ? request.intent === 'transaction_intent' ? 'transaction-wallet-error' : 'request-unavailable' : 'request-connection-expired' : 'connection-expired';
  else if (state.walletChanged && sent && request?.intent !== 'transaction_intent' && outcome === 'request-unavailable') stage='request-busy';
  else if (outcome) stage = outcome;
  else if (session && !linked && !sent && (!request || !sameAccount(session.address,request.address) || session.chain !== request.chain_namespace)) stage = state.walletChanged ? 'account-changed' : 'saved-unlinked';
  else if (request) {
    if (request.status === 'rejected' || request.status === 'dismissed') stage = request.status === 'dismissed' || Number.isSafeInteger(request.approved_at) ? 'request-dismissed' : 'request-rejected';
    else if (request.status === 'approved' && request.intent === 'transaction_intent') stage = 'transaction-reopened';
    else if (!isWalletConnectNetwork(request.chain_namespace) || request.intent === 'browser_typed_data_sign') stage = 'request-unsendable';
    else if (request.status === 'expired' || request.expires_at <= nowSeconds) stage = 'request-expired';
    else if (request.intent === 'transaction_intent' && request.expires_at - nowSeconds < 300) stage = 'transaction-deadline';
    else if (session && (!sameAccount(session.address, request.address) || session.chain !== request.chain_namespace)) stage = 'request-new-connection';
    else stage = requests.length > 1 ? 'request-multiple' : request.intent === 'transaction_intent' ? 'transaction-waiting' : 'request-waiting';
  }
  else if (linked) stage = 'linked';
  else stage = permission === 'granted' ? 'internet-ready' : 'nothing-saved';
  if (!busy && !answered && session && !sent && !['window-expired','internet-refused','internet-off','request-internet-off','guest-access','disconnect-error','home-read-unavailable'].includes(stage)) {
    if (!session.address) stage='account-unavailable-unknown';
    else if (!isWalletConnectNetwork(session.chain)) stage='network-unsupported';
  }
  if (stage==='transaction-wallet-removed' && /^0x[0-9a-fA-F]{64}$/.test(state.unrecordedHash || '')) stage='transaction-wallet-error';
  if (stage === 'account-changed' && state.walletChange === 'network-changed') stage='saved-unlinked';
  const requestAccount = request && (screens.walletconnect[stage].request || screens.walletconnect[stage].optionalRequest);
  const confirming = (stage.startsWith('link-') && screens.walletconnect[stage].selectedAccount || stage === 'checking-response' && state.effectPhase === 'ownership') && state.proofAccount;
  const current = requestAccount ? {address:request.address,chain:request.chain_namespace} : confirming || session || null;
  const account = current?.address ? {name:String(requestAccount && state.resultWalletName || current?.name || session?.name || 'your wallet').replace(/[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/g,'').trim().slice(0,40) || 'your wallet',mark:'wallet',connection:'WalletConnect',accounts:[{address:current.address,networks:[networkLabel(current.chain)]}]} : null;
  const waitDeadline = ['link-wait','request-phone','transaction-phone'].includes(stage) ? state.deadline : request?.expires_at;
  const waitSeconds = Math.max(0,Math.min(86400,(waitDeadline || nowSeconds + 300)-nowSeconds));
  const walletResult = stage === 'transaction-declined' ? {disposition:'declined',receipt:null} : undefined;
  const selectionNotice=state.walletChanged && !linked && session?.address ? !isWalletConnectNetwork(session.chain) ? 'network-unsupported' : state.walletChange || 'account-changed' : undefined;
  const notice = connection?.removed ? 'connection-removed' : connection?.expired ? 'connection-expired' : selectionNotice || (!expired && permission === 'granted' && session && connection.relayConnected === false ? 'transport-reconnecting' : undefined);
  const connectionNotice=notice === stage || stage === 'wallet-removed' && notice === 'connection-removed' ? undefined : notice;
  const currentSelection=session?.address && (state.walletChanged && !linked && stage === 'network-unsupported' || requestAccount && (!sameAccount(session.address,request.address) || session.chain !== request.chain_namespace)) ? {address:session.address,network:networkLabel(session.chain)} : undefined;
  const transactionHash = ['transaction-wallet-error','transaction-cancelled','transaction-timeout','transaction-reopened','transaction-done','checking-response'].includes(stage) && /^0x[0-9a-fA-F]{64}$/.test(state.unrecordedHash || '') ? state.unrecordedHash : undefined;
  const localSafety=Boolean(state.paymentPending || request?.intent === 'transaction_intent' && sent && !answered);
  const supportedActions=[...baseActions].filter(action=> (!unresolvedPayment || !['connect','start-over','finish','send-message','send-request','add-account','back-to-connection','view-requests','select-request'].includes(action)) && (!['finish','send-message'].includes(action) || session?.address && isWalletConnectNetwork(session.chain)));
  return {input:{walletResult,window:'walletconnect',stage,account,waitSeconds,qrData:qrData || undefined,homeOrigin:state.homeOrigin,
    localSafety,linkedConnection:Boolean(session),compact:false,targetNetwork:networkLabel(request?.chain_namespace),supportedActions,
    connectionNotice,currentSelection,transactionHash,localReturn:!unresolvedPayment&&!expired&&!state.loading&&!['home-read-unavailable','guest-access'].includes(stage)&&!['linked','disconnected','saved-unlinked','account-changed','account-unavailable-unknown','network-unsupported','wallet-removed','connection-expired','internet-off','internet-refused','internet-clearing','nothing-saved','internet-ready'].includes(stage),showNextRequests:true},request,otherRequests:requests.filter(row => row.request_id !== request?.request_id)};
}

export function errorStage(error, action, phase) {
  if (action?.kind === 'disconnect') return 'disconnect-error';
  const message = error?.message || String(error);
  if (message.includes('QR code expired')) return 'qr-expired';
  if (message === messages.cancelled) return 'qr-cancelled';
  if (action?.kind === 'link') {
    if (message === messages.proposalDeclined) return 'connection-declined';
    if (message === messages.ownershipDeclined) return 'link-declined';
    if (message === messages.linkTimeout) return 'link-timeout';
    return 'link-error';
  }
  const transaction = action?.intent === 'transaction_intent';
  if (error?.walletRemoved === true && phase === 'signature') return 'request-sent-wallet-removed';
  if (message === messages.unapprovedNetwork('Ethereum') || error?.freshConnection) return 'request-new-connection';
  if (message.startsWith('WalletConnect in this Home does not offer network ')) return phase === 'starting' ? 'request-unsendable' : 'request-unavailable';
  if (message === messages.signatureDeclined) return 'request-declined';
  if (message === messages.signatureTimeout) return 'request-timeout';
  if (message === messages.consumed) return transaction ? 'transaction-wallet-error' : 'request-unavailable';
  if (message === messages.signatureError) return 'request-unavailable';
  if (message === messages.transactionDeclined) return 'transaction-declined';
  if (message === messages.transactionTimeout) return 'transaction-timeout';
  return transaction ? 'transaction-wallet-error' : 'request-unavailable';
}

// Only intents supported by the base controller are exposed. N1 is a separate gate.
export const baseActions = new Set(['connect','start-over','finish','cancel','close-window','open-wallet','stop-waiting','inbox','check-access','check-status','copy-link','copy-address','disconnect','send-request','select-request','view-requests','send-message','refresh-status','back-to-connection','add-account']);

// A latent request stays with the controller. Only a request screen receives its
// identity, so account confirmation can never inherit an earlier request address.
export function walletConnectView({input,request,otherRequests=[]}) {
  const shown=(screens.walletconnect[input.stage].request || screens.walletconnect[input.stage].optionalRequest) && request;
  const queued=shown || !request ? otherRequests : [request,...otherRequests];
  return connectionView({...input,
    summary:shown ? reduceSummary(request,{connector:connectorId}) : null,
    otherRequests:queued.map(row=>reduceSummary(row,{connector:connectorId})).filter(Boolean),
  });
}
