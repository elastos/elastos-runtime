// This function is self-contained so Playwright can install it with addInitScript.
export function installScriptedExtension({ fixture, spec }, page = globalThis) {
  if (page.__walletReplay) throw new Error('Wallet replay already installed');
  const copy = (x) => structuredClone(x);
  const entries = new Map(fixture.cases.map((x) => [x.id, x]));
  const last = (id) => entries.get(id).snapshots.filter((s) => s.call).at(-1);
  const providerId = (id) => id === 'metamask' ? 'io.metamask' : id;
  const ordered = (x) => Array.isArray(x) ? x.map(ordered) : x !== null && typeof x === 'object'
    ? Object.fromEntries(Object.keys(x).sort().map((k) => [k, ordered(x[k])])) : x;
  const listeners = new Map();
  const providers = new Map();
  const requests = [];
  const transcript = [];
  const tasks = [];
  let now = 0;
  let serial = 0;
  const schedule = (at, fn) => tasks.push({ at, fn, serial: serial++ });
  function emit(provider, name, payload, caseId) {
    provider = providerId(provider);
    transcript.push({ kind: 'event', provider, name, payload: copy(payload), caseId });
    for (const fn of [...(listeners.get(provider)?.get(name) || [])]) fn(copy(payload));
  }
  const plans = spec.calls.map((plan) => ({ ...plan, snapshot: last(plan.id), used: false }));
  function request(provider, method, params) {
    const plan = plans.find((x) => !x.used && providerId(x.snapshot.call.target || x.snapshot.call.kind) === provider);
    if (!plan || plan.snapshot.call.method !== method || JSON.stringify(ordered(plan.snapshot.call.params)) !== JSON.stringify(ordered(params))) {
      throw new Error(`Unrecorded wallet call: ${provider}.${method}`);
    }
    if (plan.afterReturn && !requests.some((r) => r.caseId === plan.afterReturn && r.state === 'fulfilled')) {
      throw new Error('Wait for the earlier recorded answer before this call');
    }
    plan.used = true;
    const c = plan.snapshot.call;
    const pending = { caseId: plan.id, provider, method, params: copy(params), startedAt: now,
      state: 'pending', unlocked: !plan.unlock, action: plan.action, after: plan.after };
    requests.push(pending);
    transcript.push({ kind: 'request', provider, method, params: copy(params), caseId: plan.id });
    return new Promise((resolve, reject) => {
      pending.finish = () => {
        // A pending recording supplies no eventual answer, even after virtual time advances.
        if (c.state === 'pending') return;
        const end = pending.startedAt + c.elapsed_ms;
        for (const e of plan.snapshot.events || []) {
          // Full snapshots also contain later, unrelated person actions. Replay
          // this call's interval only; explicit event scenarios own outside changes.
          if (e.since_call_ms >= 0 && e.since_call_ms <= c.elapsed_ms) {
            schedule(Math.max(now, pending.startedAt + e.since_call_ms), () => emit(e.provider, e.name, e.payload, plan.id));
          }
        }
        schedule(Math.max(now, end), () => {
          pending.state = c.state;
          if (c.state === 'fulfilled') {
            transcript.push({ kind: 'fulfilled', caseId: plan.id, value: copy(c.value) });
            resolve(copy(c.value));
          } else {
            // Capture has property names, code/message/data, but no stack text.
            const error = {};
            for (const key of c.error.own_properties) {
              Object.defineProperty(error, key, { value: copy(c.error[key]), enumerable: true });
            }
            transcript.push({ kind: 'rejected', caseId: plan.id, error: copy(c.error) });
            reject(error);
          }
        });
      };
      if (!plan.action) pending.finish();
    });
  }
  function getProvider(id, flags = {}) {
    if (!providers.has(id)) {
      const events = new Map();
      listeners.set(id, events);
      const provider = { ...flags,
        request: ({ method, params = [] }) => request(id, method, params),
        on(name, fn) { if (!events.has(name)) events.set(name, new Set()); events.get(name).add(fn); return provider; },
        removeListener(name, fn) { events.get(name)?.delete(fn); return provider; },
      };
      if (id === 'unisat') {
        for (const method of ['getAccounts', 'requestAccounts', 'getNetwork', 'getChain', 'getPublicKey', 'signMessage', 'switchNetwork', 'switchChain']) {
          provider[method] = (...params) => request(id, method, params);
        }
      }
      providers.set(id, provider);
    }
    return providers.get(id);
  }
  const observation = entries.get(spec.discovery).snapshots.find((s) => s.observation)?.observation || {};
  const announcements = observation.new_announcements || observation.announcements || [];
  const flags = observation.announced_provider_flags || [];
  for (const { info } of announcements) {
    const recorded = flags.find((f) => f.rdns === info.rdns);
    getProvider(info.rdns, recorded ? Object.fromEntries(Object.entries(recorded).filter(([k, v]) => k !== 'rdns' && v !== null)) : {});
  }
  const ethereum = observation.ethereum;
  if (ethereum === 'object' || ethereum?.type === 'object' || ethereum?.isMetaMask) {
    page.ethereum = ethereum?.isRabby ? getProvider('legacy', { isMetaMask: ethereum.isMetaMask, isRabby: true }) : getProvider('io.metamask', { isMetaMask: true });
  }
  if (observation.unisat === 'object' || spec.discovery === 'US-10-presence') page.unisat = getProvider('unisat');
  let discoveryUsed = false;
  function announce() {
    if (discoveryUsed) return; // The capture supplies one finite discovery history.
    discoveryUsed = true;
    for (const { info, at_ms } of announcements) {
      const at = now + at_ms - announcements[0].at_ms;
      schedule(at, () => {
        const provider = providers.get(info.rdns);
        transcript.push({ kind: 'announcement', info: copy(info) });
        page.dispatchEvent(new page.CustomEvent('eip6963:announceProvider', { detail: { info: copy(info), provider } }));
      });
    }
  }
  page.addEventListener('eip6963:requestProvider', announce);
  const usedEvents = new Set();
  const control = {
    requests, transcript,
    get now() { return now; },
    person(action, caseId) {
      if (action === 'does nothing') return;
      if (action === 'closes side panel' && spec.calls.some((x) => x.id === 'R2-MM-native-connect-close')) return;
      const external = spec.events.find((e) => e.action === action && (!caseId || e.id === caseId));
      if (external && !usedEvents.has(external.id)) {
        usedEvents.add(external.id);
        for (const e of (last(external.id).events || []).slice(-external.last)) emit(e.provider, e.name, e.payload, external.id);
        return;
      }
      const pending = requests.find((r) => r.state === 'pending' && !r.released && (!caseId || r.caseId === caseId) && (action === 'unlocks' ? !r.unlocked : r.action === action));
      if (!pending) throw new Error(`Unrecorded person action: ${action}`);
      if (action === 'unlocks') { pending.unlocked = true; return; }
      if (!pending.unlocked) throw new Error('Unlock before approval');
      if (pending.after && !requests.some((r) => r.caseId === pending.after && r.state === 'fulfilled')) {
        throw new Error('Finish the earlier queued prompt first');
      }
      pending.released = true;
      pending.finish();
    },
    async advance(ms) {
      if (!Number.isFinite(ms) || ms < 0) throw new Error('Virtual time must advance');
      const until = now + ms;
      while (true) {
        tasks.sort((a, b) => a.at - b.at || a.serial - b.serial);
        if (!tasks.length || tasks[0].at > until) break;
        const task = tasks.shift(); now = task.at; task.fn(); await Promise.resolve();
      }
      now = until;
      await Promise.resolve();
    },
    dispose() {
      tasks.length = 0; listeners.clear();
      page.removeEventListener('eip6963:requestProvider', announce);
      delete page.ethereum; delete page.unisat; delete page.__walletReplay;
    },
  };
  page.__walletReplay = control;
  return control;
}
