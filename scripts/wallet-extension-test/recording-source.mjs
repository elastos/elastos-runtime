// Test-only, bounded projection of the original capture. No prompt text or profile paths.
export function projectCase(entry) {
  const snapshots = entry.snapshots.map((s) => {
    const out = {};
    for (const key of ['call', 'events', 'announcements', 'action', 'ignored_ms', 'waited_ms',
      'observed_at_ms', 'phase', 'action_at_ms', 'unlock_action_at_ms',
      'approve_action_at_ms', 'confirm_action_at_ms', 'sign_action_at_ms']) {
      if (Object.hasOwn(s, key)) out[key] = s[key];
    }
    if (s.observation) {
      out.observation = {};
      for (const key of ['ethereum', 'unisat', 'announcements', 'new_announcements',
        'announced_provider_flags', 'receipt', 'transaction', 'keys', 'methods', 'type', 'constructor',
        'isConnected', 'request_same', 'legacy_distinct_from_announced']) {
        if (Object.hasOwn(s.observation, key)) out.observation[key] = s.observation[key];
      }
    }
    return out;
  });
  return { id: entry.id, status: entry.status, snapshots };
}

export function finalCall(entry) {
  return entry.snapshots.filter((s) => s.call).at(-1)?.call;
}

export const providerBindings = {
  metamask: 'io.metamask', 'io.metamask': 'io.metamask', 'io.rabby': 'io.rabby',
  unisat: 'unisat', legacy: 'legacy', 'window.ethereum': 'legacy',
};

export function recordedProvider(name) {
  if (!Object.hasOwn(providerBindings, name)) throw new Error(`Unmapped recorded provider: ${name}`);
  return providerBindings[name];
}

export function validateScenarios(fixture, scenarios) {
  const entries = new Map(fixture.cases.map((c) => [c.id, c]));
  for (const [name, spec] of Object.entries(scenarios)) {
    for (const plan of spec.calls) {
      const entry = entries.get(plan.id), call = finalCall(entry);
      if (plan.action === 'approves' && call.state !== 'fulfilled') throw new Error(`${name}: approves must fulfill`);
      if (['declines', 'closes the prompt'].includes(plan.action)
        && !(call.state === 'rejected' && call.error.code === 4001)) throw new Error(`${name}: decline/close must reject with recorded 4001`);
      if (plan.action === 'closes the prompt' && !entry.snapshots.some((s) => /closed with real/i.test(s.phase || '')))
        throw new Error(`${name}: native-close evidence missing`);
      if (plan.unlock && !entry.snapshots.some((s) => 'unlock_action_at_ms' in s || /unlock/i.test(s.phase || '')))
        throw new Error(`${name}: unlock evidence missing`);
      if (plan.action === 'removes access') {
        const cleanup = finalCall(entries.get(plan.cleanup));
        if (!(plan.actor === 'page' && cleanup.method === 'wallet_revokePermissions' && cleanup.state === 'fulfilled'
          && cleanup.started_at_ms >= call.started_at_ms && cleanup.started_at_ms <= call.started_at_ms + call.elapsed_ms
          && call.state === 'rejected' && call.error.data?.cause === 'rejectAllApprovals')) throw new Error(`${name}: page cleanup evidence missing`);
      }
    }
    for (const action of spec.passiveActions || []) {
      if (!entries.get(action.id).snapshots.some((s) => s.call?.state === 'pending' && /side panel/i.test(s.phase || '')))
        throw new Error(`${name}: passive close must retain its recorded pending call`);
    }
    for (const action of spec.events) {
      const entry = entries.get(action.id), snapshot = entry.snapshots.filter((s) => s.call).at(-1);
      for (const index of action.indices) {
        const event = snapshot.events[index];
        if (!(event?.name === 'accountsChanged' && event.since_call_ms <= 0
          && JSON.stringify(event.payload) === JSON.stringify(snapshot.call.value))) throw new Error(`${name}: action event differs from its following account read`);
      }
    }
  }
}
