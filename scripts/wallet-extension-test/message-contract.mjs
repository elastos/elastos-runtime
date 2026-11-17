// Test oracle for the pinned written contract, not a product authority validator.
const exact = (x, keys) => x !== null && typeof x === 'object' && !Array.isArray(x)
  && Object.keys(x).sort().join(',') === [...keys].sort().join(',');
const uuid = (v) => typeof v === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(v);
const opaque = (v) => typeof v === 'string' && /^[A-Za-z0-9_-]{16,128}$/.test(v);
const selector = (v) => typeof v === 'string' && /^[A-Za-z0-9:._-]{1,256}$/.test(v);
const connectors = ['wallet-metamask', 'wallet-unisat', 'wallet-walletconnect'];
const oneOf = (value, values) => values.includes(value);
const bool = (x) => typeof x === 'boolean';
const nullable = (x, predicate) => x === null || predicate(x);
const origin = (value) => {
  if (typeof value !== 'string' || value.length < 1 || value.length > 512 || /[^\x21-\x7e]|[@\\]/.test(value)) return false;
  try { const url = new URL(value); return ['http:', 'https:'].includes(url.protocol) && url.origin === value; } catch { return false; }
};
const stages = ['checking', 'choosing_account', 'choosing_network', 'waiting_signature', 'waiting_transaction', 'verifying'];
const outcomes = ['done', 'declined', 'request_not_authorized', 'account_not_authorized', 'access_removed', 'account_mismatch',
  'unknown_network', 'host_busy', 'wallet_busy', 'no_wallet', 'extensions_unavailable', 'stopped', 'unsupported_request',
  'request_expired', 'request_unavailable', 'invalid_request', 'denied', 'replay', 'retired', 'unsupported_kind', 'unsupported_version', 'failed'];
export const wireKeys = {
  hello: ['type', 'schema', 'connectorId', 'connectorToken', 'parentOrigin', 'documentNonce'],
  ready: ['type', 'schema', 'connectorId', 'documentNonce', 'generation'],
  effect: ['type', 'schema', 'requestId', 'connectorId', 'connectorToken', 'parentOrigin', 'generation', 'action'],
  result: ['type', 'schema', 'connectorId', 'generation', 'requestId', 'stage', 'deadlineAt', 'snapshot', 'outcome', 'waitEnd', 'dispatch'],
  state: ['type', 'schema', 'connectorId', 'documentNonce', 'generation', 'snapshot', 'settled'],
  navigation: ['type', 'schema', 'requestId', 'documentNonce', 'ok', 'reason'],
};
export const wireTypes = {
  hello: 'wallet-connector-hello', ready: 'wallet-connector-ready', effect: 'wallet-connector-effect',
  result: 'wallet-connector-effect-result', state: 'wallet-connector-state', navigation: 'open-target-result',
};
export const nestedKeys = {
  snapshot: ['providerId', 'alternatives', 'availability', 'firstAccount', 'requiredAccountAvailable', 'network', 'networkIssue', 'access', 'busy', 'paymentPending'],
};
function snapshot(s, connector) {
  if (!exact(s, nestedKeys.snapshot)) return false;
  const allowed = connector === 'wallet-unisat' ? ['unisat'] : ['io.metamask', 'com.brave.wallet'];
  if (!nullable(s.providerId, (p) => allowed.includes(p)) || !Array.isArray(s.alternatives) || s.alternatives.length > 1
    || s.alternatives.some((p) => !allowed.includes(p) || p === s.providerId) || (connector === 'wallet-unisat' && s.alternatives.length)) return false;
  return oneOf(s.availability, ['found', 'absent', 'unknown', 'unavailable'])
    && nullable(s.firstAccount, (v) => typeof v === 'string' && v.length <= 128 && (/^0x[0-9a-f]{40}$/.test(v) || /^(bc1|[13])[A-Za-z0-9]+$/.test(v)))
    && nullable(s.requiredAccountAvailable, bool)
    && nullable(s.network, (v) => v === 'bip122:000000000019d6689c085ae165831e93' || /^eip155:[1-9][0-9]*$/.test(v) && Number.isSafeInteger(Number(v.slice(7))))
    && nullable(s.networkIssue, (v) => oneOf(v, ['bitcoin_testnet', 'fractal', 'unrecognized']))
    && oneOf(s.access, ['unknown', 'available', 'empty', 'lost']) && bool(s.busy) && nullable(s.paymentPending, bool);
}
export function messageDecision(m) {
  const kind = Object.keys(wireTypes).find((k) => m?.type === `home:${wireTypes[k]}`);
  if (!kind) return 'ignore';
  const refusal = kind === 'hello' ? 'no_reply' : kind === 'effect' ? 'invalid_request' : 'ignore';
  if (kind === 'effect' && !opaque(m.requestId)) return 'no_reply';
  if (kind === 'effect' && m.schema !== 'elastos.home.wallet-connector-effect/v2') return 'unsupported_version';
  if (['ready', 'result', 'state'].includes(kind) && m.schema === `elastos.home.${wireTypes[kind]}/v1`) return 'unsupported_version';
  if (!exact(m, wireKeys[kind]) || m.schema !== `elastos.home.${wireTypes[kind]}/v2`) return refusal;
  if ('connectorId' in m && !connectors.includes(m.connectorId)) return refusal;
  if ('documentNonce' in m && !uuid(m.documentNonce)) return refusal;
  if ('generation' in m && !opaque(m.generation)) return refusal;
  if ('connectorToken' in m && (typeof m.connectorToken !== 'string' || !m.connectorToken)) return refusal;
  if ('parentOrigin' in m && !origin(m.parentOrigin)) return refusal;
  if (kind === 'effect') {
    const a = m.action;
    if (!a || typeof a !== 'object' || Array.isArray(a) || typeof a.kind !== 'string') return refusal;
    if (!['check', 'link', 'approve', 'stop'].includes(a.kind)) return 'unsupported_kind';
    const keys = ['kind'];
    if (a.kind === 'approve') keys.push('approvalRequestId');
    if (a.kind === 'stop') keys.push('effectRequestId');
    if (['check', 'link'].includes(a.kind) && 'accountId' in a) keys.push('accountId');
    if (!exact(a, keys) || keys.some((key) => key !== 'kind' && !(key === 'effectRequestId' ? opaque(a[key]) : selector(a[key])))) return refusal;
    if (m.connectorId === 'wallet-walletconnect') return 'denied';
  }
  if (kind === 'result') {
    if (!opaque(m.requestId) || !stages.includes(m.stage) || !nullable(m.deadlineAt, (v) => Number.isSafeInteger(v) && v >= 0)
      || !nullable(m.outcome, (v) => outcomes.includes(v)) || !oneOf(m.dispatch, ['not_sent', 'handed_off', 'sent', 'unknown'])
      || !(m.outcome === 'stopped' ? oneOf(m.waitEnd, ['user', 'deadline']) : m.waitEnd === null)) return refusal;
    if (m.dispatch === 'unknown' && !(['waiting_transaction', 'verifying'].includes(m.stage)
      && [null, 'stopped', 'failed'].includes(m.outcome))) return refusal;
    if (['checking', 'choosing_account', 'choosing_network'].includes(m.stage) && !['not_sent', 'handed_off'].includes(m.dispatch)) return refusal;
  }
  if ('snapshot' in m && !snapshot(m.snapshot, m.connectorId)) return refusal;
  if (kind === 'state' && m.settled !== null) {
    const s = m.settled;
    if (!exact(s, ['effectRequestId', 'result', 'receipt']) || !opaque(s.effectRequestId) || !oneOf(s.result, ['answered', 'declined', 'refused', 'failed'])
      || !nullable(s.receipt, (v) => ['recorded', 'recording_failed'].includes(v))) return refusal;
  }
  if (kind === 'navigation' && (!uuid(m.requestId) || !bool(m.ok) || !(m.ok ? m.reason === 'accepted'
    : ['invalid_request', 'denied', 'request_unavailable', 'target_unavailable', 'unsupported_version', 'delivery_failed', 'timeout'].includes(m.reason)))) return refusal;
  return 'accept';
}

export function queryValid(v) {
  const q = v.query;
  if (!q || typeof q !== 'object' || Array.isArray(q)) return false;
  if (v.delivery === 'trusted-close-return') return v.source === 'home-gui' && v.target === 'wallet'
    && v.cmd === 'review-request' && exact(q, ['tab']) && q.tab === 'accounts';
  if (v.walletRequestId !== undefined) return selector(v.walletRequestId) && exact(q, []) && connectors.includes(v.source)
    && v.target === v.runtimeSource && !['home', 'home-gui', 'home-cli', v.source].includes(v.target);
  if (exact(q, ['wallet_request']) && selector(q.wallet_request)) {
    if (v.target === 'wallet' && (v.source === 'inbox' || connectors.includes(v.source))) return !v.storedConnector || v.storedConnector === v.source;
    return v.source === 'wallet' && connectors.includes(v.target) && v.storedConnector === v.target;
  }
  if (exact(q, ['tab'])) return q.tab === 'activity' && v.target === 'wallet' && connectors.includes(v.source);
  if (exact(q, ['notification_id'])) return q.notification_id === 'walletconnect-internet:permission' && v.source === 'wallet-walletconnect' && v.target === 'inbox';
  if (!exact(q, [])) return false;
  if (v.source === 'wallet-metamask' && v.target === 'wallet-walletconnect') {
    const s = v.selection;
    return exact(s, ['accountId', 'walletRequest', 'handedOff', 'paymentPending', 'ready', 'targetConfigured'])
      && s.accountId === null && s.walletRequest === null && s.handedOff === false && s.paymentPending === false
      && s.ready === true && s.targetConfigured === true;
  }
  return (v.source === 'wallet' && connectors.includes(v.target)) || v.source === 'inbox' && v.target === 'wallet-walletconnect';
}

export function closeValid(m) {
  return exact(m, ['type', 'homeToken']) && m.type === 'home:close-self' && typeof m.homeToken === 'string' && m.homeToken.length > 0;
}

// Draft structural examples; authority and provider execution belong to the joined product tests.
export function handoffValid(m) {
  if (!exact(m, ['schema', 'action', 'connector_id', 'request_id', 'handoff', 'evm_chains'])
    || m.schema !== 'elastos.home.wallet-connector.effect.result/v1' || m.action !== 'approval_handoff'
    || !['wallet-metamask', 'wallet-unisat'].includes(m.connector_id) || !selector(m.request_id) || !Array.isArray(m.evm_chains)) return false;
  const h = m.handoff, tx = h?.intent === 'transaction_intent';
  if (!exact(h, ['schema', 'request_id', 'intent', 'payload_hash', 'signer', 'status', ...(tx ? ['transaction'] : ['message', 'signature_type'])])
    || h.schema !== 'elastos.wallet.webconnect_handoff/v1' || h.request_id !== m.request_id
    || !/^0x[0-9a-fA-F]{64}$/.test(h.payload_hash)) return false;
  if (tx) return m.connector_id === 'wallet-metamask' && h.status === 'awaiting_wallet_transaction'
    && exact(h.transaction, ['from', 'to', 'value', 'data', 'gas', 'gasPrice', 'nonce', 'chainId'])
    && h.transaction.from === h.signer && /^0x[0-9a-fA-F]{40}$/.test(h.signer)
    && /^0x[0-9a-fA-F]{40}$/.test(h.transaction.to)
    && Object.entries(h.transaction).every(([key, value]) => typeof value === 'string'
      && value.length <= (key === 'data' ? 65536 : 512) && (key === 'data' ? /^0x[0-9a-fA-F]*$/ : /^0x[0-9a-fA-F]+$/).test(value));
  return h.status === 'awaiting_wallet_signature' && typeof h.message === 'string' && h.message.length > 0
    && (m.connector_id === 'wallet-unisat' ? h.intent === 'bitcoin_bip322_proof'
      && ['bip322_simple', 'ecdsa'].includes(h.signature_type) && /^(bc1|[13])[A-Za-z0-9]+$/.test(h.signer)
      : h.intent !== 'bitcoin_bip322_proof' && h.signature_type === 'personal_sign' && /^0x[0-9a-fA-F]{40}$/.test(h.signer));
}

export function settlementValid(row) {
  const b = row.body, r = row.response, op = row.runtimeOperation;
  return row.method === 'POST' && selector(row.requestId)
    && row.route === `/api/apps/home/wallet-connector/approvals/${row.requestId}/call-settlement`
    && exact(b, ['schema', 'connector_id', 'connector_token', 'payload_hash', 'signer', 'outcome'])
    && b.schema === 'elastos.home.wallet-connector.call-settlement.request/v1' && b.connector_id === 'wallet-metamask'
    && typeof b.connector_token === 'string' && b.connector_token.length > 0
    && /^0x[0-9a-fA-F]{64}$/.test(b.payload_hash) && /^0x[0-9a-fA-F]{40}$/.test(b.signer)
    && ['not_approved', 'not_authorized', 'unresolved'].includes(b.outcome)
    && exact(r, ['schema', 'action', 'connector_id', 'request_id', 'status', 'outcome'])
    && r.schema === 'elastos.home.wallet-connector.effect.result/v1' && r.action === 'approval_call_settlement'
    && r.connector_id === b.connector_id && r.request_id === row.requestId && r.outcome === b.outcome
    && r.status === (b.outcome === 'unresolved' ? 'approved' : 'rejected')
    && op?.name === 'RecordExternalCallOutcome' && exact(op.data, ['request_id', 'payload_hash', 'signer', 'outcome'])
    && op.data.request_id === row.requestId && ['payload_hash', 'signer', 'outcome'].every((key) => op.data[key] === b[key]);
}

export function selectedResultDecision(row) {
  if (row.method !== 'GET' || !connectors.includes(row.connector)
    || row.route !== `/api/apps/${row.connector}/wallet/approvals`
    || !(exact(row.query, []) || exact(row.query, ['wallet_request']) && selector(row.query.wallet_request))) return 'invalid_request';
  if ('wallet_request' in row.query && (row.samePrincipal !== true || row.storedConnector !== row.connector)) return 'request_unavailable';
  return 'accept';
}

export function identityDecision(v) {
  const f = v.fields;
  if (v.operation === 'nonlink_complete' && Object.keys(f).length) return 'denied';
  if ('provider_id' in f && 'wallet_peer_name' in f) return 'denied';
  if ('wallet_peer_name' in f) {
    if (typeof f.wallet_peer_name !== 'string' || new TextEncoder().encode(f.wallet_peer_name).length > 1024) return 'invalid_request';
    return v.actor === 'wallet-walletconnect' ? 'accept' : 'denied';
  }
  if ('provider_id' in f) {
    if (typeof f.provider_id !== 'string') return 'invalid_request';
    return (v.actor === 'wallet-metamask' && ['io.metamask', 'com.brave.wallet'].includes(f.provider_id)
      || v.actor === 'wallet-unisat' && f.provider_id === 'unisat') ? 'accept' : 'denied';
  }
  return 'accept';
}

export function summarySiteDecision(v) {
  return ['wallet', 'inbox', v.summary.connector_id].includes(v.audience) && origin(v.summary.requesting_origin) ? 'show_site' : 'omit_site';
}
