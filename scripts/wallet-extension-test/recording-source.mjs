// Test-only, bounded projection of the original capture. No prompt text or profile paths.
export function projectCase(entry) {
  const snapshots = entry.snapshots.map((s) => {
    const out = {};
    for (const key of ['call', 'events', 'announcements', 'ignored_ms', 'waited_ms',
      'observed_at_ms', 'phase', 'action_at_ms', 'unlock_action_at_ms',
      'approve_action_at_ms', 'confirm_action_at_ms', 'sign_action_at_ms']) {
      if (key in s) out[key] = s[key];
    }
    if (s.observation) {
      out.observation = {};
      for (const key of ['ethereum', 'unisat', 'announcements', 'new_announcements',
        'announced_provider_flags', 'receipt', 'transaction']) {
        if (key in s.observation) out.observation[key] = s.observation[key];
      }
    }
    return out;
  });
  return { id: entry.id, status: entry.status, snapshots };
}

export function finalCall(entry) {
  return entry.snapshots.filter((s) => s.call).at(-1)?.call;
}
