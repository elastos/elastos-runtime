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
function snapshot(s, connector) {
  if (!exact(s, ['providerId', 'alternatives', 'availability', 'firstAccount', 'requiredAccountAvailable', 'network', 'networkIssue', 'access', 'busy'])) return false;
  const allowed = connector === 'wallet-unisat' ? ['unisat'] : ['io.metamask', 'com.brave.wallet'];
  if (!nullable(s.providerId, (p) => allowed.includes(p)) || !Array.isArray(s.alternatives) || s.alternatives.length > 1
    || s.alternatives.some((p) => !allowed.includes(p) || p === s.providerId) || (connector === 'wallet-unisat' && s.alternatives.length)) return false;
  return oneOf(s.availability, ['found', 'absent', 'unknown', 'unavailable'])
    && nullable(s.firstAccount, (v) => typeof v === 'string' && v.length <= 128 && (/^0x[0-9a-f]{40}$/.test(v) || /^(bc1|[13])[A-Za-z0-9]+$/.test(v)))
    && nullable(s.requiredAccountAvailable, bool)
    && nullable(s.network, (v) => v === 'bip122:000000000019d6689c085ae165831e93' || /^eip155:[1-9][0-9]*$/.test(v) && Number.isSafeInteger(Number(v.slice(7))))
    && nullable(s.networkIssue, (v) => oneOf(v, ['bitcoin_testnet', 'fractal', 'unrecognized']))
    && oneOf(s.access, ['unknown', 'available', 'empty', 'lost']) && bool(s.busy);
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
    if (m.dispatch === 'unknown' && !(m.stage === 'waiting_transaction' && m.outcome === 'stopped')) return refusal;
    if (['checking', 'choosing_account', 'choosing_network'].includes(m.stage) && !['not_sent', 'handed_off'].includes(m.dispatch)) return refusal;
  }
  if ('snapshot' in m && !snapshot(m.snapshot, m.connectorId)) return refusal;
  if (kind === 'state' && m.settled !== null) {
    const s = m.settled;
    if (!exact(s, ['effectRequestId', 'result', 'receipt']) || !opaque(s.effectRequestId) || !oneOf(s.result, ['answered', 'declined', 'failed'])
      || !nullable(s.receipt, (v) => ['recorded', 'recording_failed'].includes(v)) || s.receipt !== null && s.result !== 'answered') return refusal;
  }
  if (kind === 'navigation' && (!uuid(m.requestId) || !bool(m.ok) || !(m.ok ? m.reason === 'accepted'
    : ['invalid_request', 'denied', 'request_unavailable', 'target_unavailable', 'unsupported_version', 'delivery_failed', 'timeout'].includes(m.reason)))) return refusal;
  return 'accept';
}

export function queryValid(v) {
  const q = v.query;
  if (!q || typeof q !== 'object' || Array.isArray(q)) return false;
  if (v.walletRequestId !== undefined) return selector(v.walletRequestId) && exact(q, []) && connectors.includes(v.source)
    && v.target === v.runtimeSource && !['home', 'home-gui', 'home-cli', v.source].includes(v.target);
  if (exact(q, ['wallet_request']) && selector(q.wallet_request)) {
    if (v.target === 'wallet' && (v.source === 'inbox' || connectors.includes(v.source))) return !v.storedConnector || v.storedConnector === v.source;
    return v.source === 'wallet' && connectors.includes(v.target) && v.storedConnector === v.target;
  }
  if (exact(q, ['tab'])) return q.tab === 'activity' && v.target === 'wallet' && connectors.includes(v.source);
  if (exact(q, ['notification_id'])) return q.notification_id === 'walletconnect-internet:permission' && v.source === 'wallet-walletconnect' && v.target === 'inbox';
  return exact(q, []) && ((v.source === 'wallet' && connectors.includes(v.target))
    || (v.source === 'inbox' || ['wallet-metamask', 'wallet-unisat'].includes(v.source)) && v.target === 'wallet-walletconnect');
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
