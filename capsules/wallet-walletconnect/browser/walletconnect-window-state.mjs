import {isWalletConnectNetwork, walletConnectMessages as messages} from './walletconnect-client.mjs';

export const connectorId = 'wallet-walletconnect';
export const sameAccount = (a,b) => String(a || '').toLowerCase() === String(b || '').toLowerCase();
export const networkLabel = value => ({'eip155:1':'Ethereum','eip155:20':'Elastos Smart Chain','eip155:8453':'Base','eip155:11155111':'Sepolia test network'}[value] || `Unsupported network (${String(value || '').slice(0,60)})`);
export const signableRequest = request => request?.connector_id === connectorId && !['managed_evm','managed_btc_p2wpkh'].includes(request.proof_type) && request.intent !== 'bitcoin_bip322_proof' && ['siwe','siwe_erc1271'].includes(request.proof_type);
export const sessionLinked = (session, accounts) => Boolean(session && accounts.some(account => account.chain_namespace === session.chain && sameAccount(account.address, session.address)));

// Presentation uses the clock supplied by the window. It grants no authority.
export function windowPresentation(state, nowSeconds) {
  const {connection, accounts = [], requests = [], busy, phase, permission, pending, ownerNeeded, expired, outcome, qrData, selectedId, activeRequest} = state;
  const session = connection?.session;
  const request = activeRequest || requests.find(row => row.request_id === selectedId) || requests[0];
  const linked = sessionLinked(session, accounts);
  let stage;
  if (expired) stage = 'window-expired';
  else if (ownerNeeded && permission !== 'granted') stage = 'guest-access';
  else if (permission === 'requested') stage = pending ? request ? 'request-internet-pending' : 'internet-pending' : request ? 'request-internet-off' : 'internet-off';
  else if (permission === 'refused') stage = 'internet-refused';
  else if (permission === 'revoked' && connection) stage = request ? 'request-internet-off' : 'internet-off';
  else if (qrData) stage = 'qr-shown';
  else if (busy) stage = phase === 'ownership' ? 'link-wait' : phase === 'signature' ? 'request-phone' : phase === 'transaction' ? 'transaction-phone' : phase === 'disconnecting' ? 'disconnecting' : 'preparing-qr';
  else if (state.walletChanged && session && !linked && ['link-error','request-wallet-error','request-unsendable','request-unavailable'].includes(outcome)) stage = 'saved-unlinked';
  else if (['request-done','transaction-done'].includes(outcome)) stage=outcome;
  else if (connection?.removed && outcome !== 'disconnected') stage = request ? state.dispatched ? request.intent === 'transaction_intent' ? 'transaction-wallet-removed' : 'request-sent-wallet-removed' : 'request-wallet-removed' : 'wallet-removed';
  else if (connection?.expired && outcome !== 'disconnected') stage = request ? 'request-connection-expired' : 'connection-expired';
  else if (outcome) stage = outcome;
  else if (session && !linked && (!request || !sameAccount(session.address,request.address) || session.chain !== request.chain_namespace)) stage = 'saved-unlinked';
  else if (request) {
    if (request.status === 'approved' && request.intent === 'transaction_intent') stage = 'transaction-reopened';
    else if (!isWalletConnectNetwork(request.chain_namespace) || request.intent === 'browser_typed_data_sign') stage = 'request-unsendable';
    else if (request.expires_at <= nowSeconds) stage = 'request-expired';
    else if (request.intent === 'transaction_intent' && request.expires_at - nowSeconds < 300) stage = 'transaction-deadline';
    else if (session && (!sameAccount(session.address, request.address) || session.chain !== request.chain_namespace)) stage = 'request-new-connection';
    else stage = requests.length > 1 ? 'request-multiple' : request.intent === 'transaction_intent' ? 'transaction-waiting' : 'request-waiting';
  }
  else if (linked) stage = 'linked';
  else stage = permission === 'granted' ? 'internet-ready' : 'nothing-saved';
  const requestAccount = request && /^(request|transaction)-/.test(stage);
  const current = requestAccount ? {address:request.address,chain:request.chain_namespace} : session || null;
  const account = current?.address ? {name:String(session?.name || 'Your wallet').replace(/[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/g,'').slice(0,40) || 'Your wallet',mark:'wallet',connection:'WalletConnect',accounts:[{address:current.address,networks:[networkLabel(current.chain)]}]} : null;
  const waitSeconds = Math.max(0,Math.min(86400,Math.min(state.deadline || nowSeconds + 86400,request?.expires_at || nowSeconds + 300)-nowSeconds));
  const walletResult = stage === 'transaction-declined' ? {disposition:'declined',receipt:null} : undefined;
  const preparingMessage = stage === 'preparing-qr' && (phase === 'confirming' || state.action?.kind === 'approve' || state.action?.kind === 'link' && state.action.fresh === false) ? state.action?.kind === 'approve' ? 'Preparing request.' : 'Preparing connection.' : null;
  const endedNotice = ['request-done','transaction-done'].includes(stage) ? connection?.removed ? 'Your wallet removed this connection.' : connection?.expired ? 'This wallet connection expired.' : null : null;
  const connectionNotice = endedNotice || (connection?.session && connection.relayConnected === false ? 'WalletConnect is reconnecting.' : null);
  return {connectionNotice,preparingMessage,input:{walletResult,window:'walletconnect',stage,account,waitSeconds,qrData:qrData || undefined,homeOrigin:state.homeOrigin,localSafety:null,compact:false,targetNetwork:networkLabel(request?.chain_namespace)},request,otherRequests:requests.filter(row => row.request_id !== request?.request_id)};
}

export function errorStage(error, action, phase) {
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
  if (message === messages.unapprovedNetwork('Ethereum') || error?.freshConnection) return 'request-new-connection';
  if (message === messages.signatureDeclined) return 'request-declined';
  if (message === messages.signatureTimeout) return 'request-timeout';
  if (message === messages.signatureError || message === messages.consumed) return 'request-unavailable';
  if (message === messages.transactionDeclined) return 'transaction-declined';
  if (message === messages.transactionTimeout) return 'transaction-timeout';
  return transaction ? 'transaction-wallet-error' : phase === 'starting' ? 'request-unavailable' : 'request-wallet-error';
}

// Only intents supported by the base controller are exposed. N1 is a separate gate.
export const baseActions = new Set(['connect','start-over','finish','cancel','stop-waiting','inbox','check-access','check-status','copy-link','copy-address','disconnect','send-request','select-request','view-requests']);
