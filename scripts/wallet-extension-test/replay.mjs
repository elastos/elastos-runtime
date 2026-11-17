// This function is self-contained so Playwright can install it with addInitScript.
export function installScriptedExtension({ fixture, spec }, page = globalThis) {
  if (page.__walletReplay) throw new Error('Wallet replay already installed');
  const copy = (x) => structuredClone(x);
  const entries = new Map(fixture.cases.map((x) => [x.id, x]));
  const last = (id) => entries.get(id).snapshots.filter((s) => s.call).at(-1);
  const ordered = (x) => Array.isArray(x) ? x.map(ordered) : x !== null && typeof x === 'object'
    ? Object.fromEntries(Object.keys(x).sort().map((k) => [k, ordered(x[k])])) : x;
  const listeners = new Map();
  const providers = new Map();
  const surfaces = new Map();
  const requests = [];
  const transcript = [];
  const violations = [];
  function violate(reason, fields = {}) {
    violations.push({ reason, ...fields });
    throw new Error(reason);
  }
  function invoke(provider, call) {
    const before = violations.length;
    try { return call(); } catch (error) {
      // Argument extraction/serialization can fail before request() records it.
      if (violations.length === before) violations.push({ reason: 'Invalid wallet invocation', provider });
      throw error;
    }
  }
  function providerId(id) {
    if (!Object.hasOwn(fixture.providerBindings, id)) return violate('Unmapped recorded provider', { provider: id });
    return fixture.providerBindings[id];
  }
  const tasks = [];
  let now = 0;
  let serial = 0;
  const schedule = (at, fn) => tasks.push({ at, fn, serial: serial++ });
  function emit(provider, name, payload, caseId) {
    provider = providerId(provider);
    if (!listeners.has(provider)) return violate('Recorded event has no installed provider', { provider, caseId });
    transcript.push({ kind: 'event', provider, name, payload: copy(payload), caseId });
    for (const fn of [...(listeners.get(provider)?.get(name) || [])]) fn(copy(payload));
  }
  const plans = spec.calls.map((plan) => ({ ...plan, snapshot: last(plan.id), used: false }));
  function request(provider, method, params) {
    const plan = plans.find((x) => !x.used && providerId(x.snapshot.call.target || x.snapshot.call.kind) === provider);
    if (!plan || plan.snapshot.call.method !== method || JSON.stringify(ordered(plan.snapshot.call.params)) !== JSON.stringify(ordered(params))) {
      return violate(`Unrecorded wallet call: ${provider}.${method}`, { provider, method });
    }
    if (plan.afterReturn && !requests.some((r) => r.caseId === plan.afterReturn && r.state === 'fulfilled')) {
      return violate('Wait for the earlier recorded answer before this call', { provider, method, caseId: plan.id });
    }
    if (plan.whilePending && !requests.some((r) => r.caseId === plan.whilePending && r.state === 'pending'))
      return violate('Earlier connect must still be pending', { provider, method, caseId: plan.id });
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
      const eventMethods = {
        on(name, fn) {
          if (typeof fn !== 'function') return violate('Invalid wallet event listener', { provider: id, member: 'on' });
          if (!events.has(name)) events.set(name, new Set()); events.get(name).add(fn); return provider;
        },
      };
      const inventory = id === 'unisat' ? fixture.surfaces.unisat : id === 'legacy' && observation.ethereum?.isRabby ? fixture.surfaces.legacy : null;
      const target = Object.create(eventMethods);
      const provider = new Proxy(target, {
        get(target, member, receiver) {
          // EventTarget/Promise assimilation probes then on listener return values.
          if (typeof member === 'string' && member !== 'then' && !Reflect.has(target, member))
            return violate('Unrecorded wallet member', { provider: id, member });
          return Reflect.get(target, member, receiver);
        },
      });
      const set = (key, value) => Object.defineProperty(target, key, { value, writable: true, enumerable: true, configurable: true });
      for (const key of inventory?.keys || []) Object.defineProperty(target, key, {
        get: () => violate('Wallet member has no recorded behavior', { provider: id, member: key }),
        enumerable: true, configurable: true,
      });
      for (const [key, value] of Object.entries(flags)) set(key, value);
      if (id === 'unisat') {
        const recorded = new Set(fixture.cases.flatMap((c) => c.snapshots).filter((s) => s.call
          && providerId(s.call.target || s.call.kind) === id).map((s) => s.call.method));
        for (const method of inventory.methods) if (recorded.has(method))
          set(method, (...params) => invoke(id, () => request(id, method, params)));
      } else {
        set('request', (args) => invoke(id, () => {
          const { method, params = [] } = args;
          return request(id, method, params);
        }));
        if (inventory?.keys.includes('on')) set('on', eventMethods.on);
        const recorded = inventory && entries.get(inventory.caseId).snapshots.find((s) => s.observation).observation;
        if (recorded && typeof recorded.isConnected === 'boolean') set('isConnected', (...args) => {
          if (args.length) return violate('Unrecorded isConnected arguments', { provider: id, member: 'isConnected' });
          return recorded.isConnected;
        });
      }
      if (inventory) surfaces.set(id, Object.getOwnPropertyDescriptors(target));
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
    // Round 1 measured presence only, not flags or identity with an announcement.
    page.ethereum = getProvider('legacy', typeof ethereum === 'object'
      ? Object.fromEntries(['isMetaMask', 'isRabby'].filter((key) => typeof ethereum[key] === 'boolean').map((key) => [key, ethereum[key]])) : {});
  }
  if (observation.unisat === 'object' || observation.type === 'object' && Array.isArray(observation.methods)) page.unisat = getProvider('unisat');
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
    requests, transcript, violations,
    assertNoViolations() {
      for (const [id, provider] of providers) {
        const inventory = id === 'unisat' ? fixture.surfaces.unisat : id === 'legacy' && observation.ethereum?.isRabby ? fixture.surfaces.legacy : null;
        if (!inventory) continue;
        if (JSON.stringify(Object.keys(provider).sort()) !== JSON.stringify([...inventory.keys].sort())) violate('Provider own keys differ from recording', { provider: id });
        const actual = Object.getOwnPropertyDescriptors(provider);
        for (const [key, expected] of Object.entries(surfaces.get(id))) {
          const member = actual[key];
          if (!member || member.get !== expected.get || member.set !== expected.set || typeof member.value !== typeof expected.value)
            violate('Provider member descriptors differ from recording', { provider: id, member: key });
        }
      }
      if (violations.length) throw new Error(`Wallet replay violations: ${JSON.stringify(violations)}`);
    },
    get now() { return now; },
    person(action, caseId) {
      if (action === 'does nothing') return;
      const passive = spec.passiveActions?.find((x) => x.action === action && (!caseId || x.id === caseId));
      if (passive && requests.some((r) => r.caseId === passive.id && r.state === 'pending')) return;
      const external = spec.events.find((e) => e.action === action && (!caseId || e.id === caseId));
      if (external && !usedEvents.has(external.id)) {
        usedEvents.add(external.id);
        for (const index of external.indices) {
          const e = last(external.id).events[index]; emit(e.provider, e.name, e.payload, external.id);
        }
        return;
      }
      const pending = requests.find((r) => r.state === 'pending' && !r.released && (!caseId || r.caseId === caseId) && (action === 'unlocks' ? !r.unlocked : r.action === action));
      if (!pending) return violate(`Unrecorded person action: ${action}`);
      if (action === 'unlocks') { pending.unlocked = true; return; }
      if (!pending.unlocked) return violate('Unlock before approval', { caseId: pending.caseId });
      if (pending.after && !requests.some((r) => r.caseId === pending.after && r.state === 'fulfilled')) {
        return violate('Finish the earlier queued prompt first', { caseId: pending.caseId });
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
