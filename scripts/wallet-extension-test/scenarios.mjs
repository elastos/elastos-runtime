// Each request is consumed once, in order for its provider. No generic RPC replies.
const call = (id, action = null, unlock = false) => ({ id, action, unlock });
const scenario = (discovery, calls, events = []) => ({ discovery, calls, events });
const mm = 'MM-1-initial';
const both = 'R2-BOTH-discovery';
export const scenarios = {
  'metamask-before-access': scenario(mm, [call('MM-2-accounts')]),
  'metamask-silent-check': scenario(mm, [call('MM-5-after-switch-accounts'), call('MM-8-preflight-chain')]),
  'metamask-connect-late': scenario(mm, [call('MM-2-ignore', 'approves')]),
  'metamask-connect-declined': scenario(mm, [call('MM-2-reject', 'declines')]),
  'metamask-second-connect': scenario(mm, [call('MM-2-ignore', 'approves'), call('MM-4-second-connect')]),
  'metamask-signatures-queued': scenario(mm, [call('MM-4-sign-first'), call('MM-4-sign-second')]),
  'metamask-sign-approved': scenario(mm, [call('MM-5-sign-approve', 'approves')]),
  'metamask-sign-declined': scenario(mm, [call('MM-5-sign-reject', 'declines')]),
  'metamask-account-unavailable': scenario(mm, [call('MM-5-unpermitted-real-account')]),
  'metamask-access-removed': scenario(mm, [call('MM-6-ui-removal-accounts'), call('MM-6-ui-removal-after-confirm')],
    [{ id: 'MM-6-ui-removal-after-confirm', action: 'removes access', last: 1 }]),
  'metamask-switch-account': scenario(mm, [call('MM-6-switch-both-permitted')],
    [{ id: 'MM-6-switch-both-permitted', action: 'switches account', last: 2 }]),
  'metamask-unknown-network': scenario(mm, [call('MM-7-unknown')]),
  'metamask-network-declined': scenario(mm, [call('MM-7-known-reject', 'declines')]),
  'metamask-add-network-declined': scenario(mm, [call('MM-7-add-reject', 'declines')]),
  'metamask-transaction-declined': scenario(mm, [call('MM-8-reject', 'declines')]),
  'metamask-transaction-revoked': scenario(mm, [call('MM-8-confirm', 'removes access')]),
  'metamask-native-connect-close': scenario(both, [call('R2-MM-native-connect-retry', 'closes the prompt')]),
  'metamask-native-sign-close': scenario(both, [call('R2-MM-native-sign-retry', 'closes the prompt')]),
  'metamask-side-panel-close': scenario(both, [call('R2-MM-native-connect-close', 'approves')]),
  'metamask-disabled-stale': scenario('R2-DISABLED-existing-document', [call('R2-DISABLED-old-mm-request')]),
  'metamask-transaction-receipt': scenario(both, [call('R2-MM-send-after-reconnect', 'approves'), call('R2-MM-receipt-confirm')]),
  'metamask-transaction-late-receipt': scenario(both, [call('R2-MM-send-late75', 'approves'), call('R2-MM-receipt-late75')]),
  'metamask-transactions-queued': scenario(both, [call('R2-MM-queue-first', 'approves'),
    { ...call('R2-MM-queue-second', 'declines'), after: 'R2-MM-queue-first' }, call('R2-MM-receipt-queue-first')]),
  'unisat-before-access': scenario('US-10-presence', [call('US-10-accounts')]),
  'unisat-connect-declined': scenario('US-10-presence', [call('US-10-reject', 'declines')]),
  'unisat-connect-pending': scenario('US-10-presence', [call('US-10-ignore')]),
  'unisat-locked-connect': scenario('US-10-presence', [call('US-10-locked-accounts'), call('R2-US-locked-connect-clean', 'approves', true)]),
  'unisat-locked-sign': scenario('US-10-presence', [call('R2-US-locked-sign-clean', 'approves', true), call('R2-US-public-key')]),
  'unisat-sign-late': scenario('US-10-presence', [call('US-12-locked-sign-repeat', 'approves', true)]),
  'unisat-sign-declined': scenario('US-10-presence', [call('US-12-sign-reject', 'declines')]),
  'unisat-native-connect-close': scenario('US-10-presence', [call('R2-US-native-connect-close', 'closes the prompt')]),
  'unisat-two-calls': scenario('US-10-presence', [call('US-10-repeat-first'), call('US-10-repeat-second', 'approves')]),
  'unisat-mainnet': scenario('US-10-presence', [call('US-11-mainnet-network'), call('US-11-mainnet-chain')]),
  'unisat-testnet': scenario('US-10-presence', [call('US-11-testnet-network-real'), call('US-11-testnet-chain-real')]),
  'unisat-fractal': scenario('US-10-presence', [call('US-11-fractal-network'), call('US-11-fractal-chain')]),
  'unisat-switch-account': scenario('US-10-presence', [call('US-12-after-switch-accounts'), call('US-12-after-switch-sign', 'approves')],
    [{ id: 'US-12-after-switch-accounts', action: 'switches account', last: 1 }]),
  'metamask-and-rabby': scenario(both, [call('R2-BOTH-legacy-read'), call('R2-BOTH-rabby-read'), call('R2-BOTH-mm-read'), call('R2-BOTH-call-metamask-announced', 'approves'), call('R2-BOTH-rabby-after-mm-direct')]),
  'rabby-legacy-chooser': scenario(both, [call('R2-BOTH-legacy-fresh-events', 'approves')]),
  'rabby-only': scenario('R2-DISABLED-fresh-document', [call('R2-DISABLED-legacy-fresh-events')]),
  'private-no-extension': scenario('NONE-15-incognito-both', []),
  'brave-unconfigured': scenario('BRAVE-16', []),
};

export function caseIds(spec) {
  return [...new Set([spec.discovery, ...spec.calls.map((x) => x.id), ...spec.events.map((x) => x.id)])];
}
