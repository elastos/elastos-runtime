import { connectionView, renderConnection, reduceSummary } from './wallet-connection-view.mjs';

// Delivered byte-for-byte to both capsules, like the shared view. Home owns
// discovery, challenges, signing, completion and provider-account checks.
export function startExtensionWindow(kind, homeClipboard) {
  if (!['metamask', 'unisat'].includes(kind)) throw new TypeError('wallet kind');
  const CONNECTOR_ID = `wallet-${kind}`;
  const HOST_EFFECT_TYPE = 'home:wallet-connector-effect';
  const HOST_EFFECT_SCHEMA = 'elastos.home.wallet-connector-effect/v1';
  const HOST_RESULT_TYPE = 'home:wallet-connector-effect-result';
  const HOST_RESULT_SCHEMA = 'elastos.home.wallet-connector-effect-result/v1';
  const HOST_EFFECT_TIMEOUT_MS = 60_000;
  const frameHomeToken = readLaunchToken();
  const homeOrigin = readQueryParam('home_origin');
  let hostEffectInFlight = false, hostRequestSequence = 0;
  let picked = false;
  let stage = 'ready', accounts = [], requests = [], selected = null;
  let uncertain = false;
  let operation = null, revision = 0, refreshing = null, disposed = false;
  let accountEvent = null, networkEvent = null, disconnected = false;
  let lastMarkup = '', lastView = null;
  const mount = document.querySelector('#connection-root');

  function accountView() {
    const rows = accounts.filter(a => a?.connector_id === CONNECTOR_ID || !a?.connector_id)
      .filter(a => typeof a.address === 'string' && a.address.length <= 128).slice(0, 8);
    if (!rows.length) return null;
    const networks = chain => {
      if (networkEvent !== null) {
        if (kind === 'unisat') return [networkEvent === 'livenet' ? 'Bitcoin' : networkEvent === 'testnet' ? 'Bitcoin test network (unsupported)' : 'Unknown network'];
        const number = BigInt(networkEvent).toString();
        return [networkName(`eip155:${number}`)];
      }
      // A stored link names its recorded network, not a fresh provider read.
      return [networkName(chain)];
    };
    return { name: kind === 'metamask' ? 'MetaMask' : 'UniSat', mark: kind, connection: null,
      accounts: rows.map(row => ({ address: row.address, networks: networks(row.chain_namespace) })) };
  }

  function networkName(chain) {
    return ({ 'eip155:1': 'Ethereum', 'eip155:20': 'Elastos Smart Chain', 'eip155:8453': 'Base',
      'bip122:000000000019d6689c085ae165831e93': 'Bitcoin' })[chain] || String(chain || 'Network unknown').slice(0, 80);
  }

  function signable(request) {
    return request?.connector_id === CONNECTOR_ID && (kind === 'unisat'
      ? request.intent === 'bitcoin_bip322_proof' && ['bip322_simple', 'bitcoin_signed_message'].includes(request.proof_type)
        && request.chain_namespace === 'bip122:000000000019d6689c085ae165831e93'
      : request.intent !== 'bitcoin_bip322_proof' && ['siwe', 'siwe_erc1271'].includes(request.proof_type));
  }

  function chooseStage() {
    if (disconnected || accountEvent?.length === 0) return accounts.length ? kind === 'metamask' ? 'site-access-ended' : 'account-unavailable' : 'ready';
    if (accountEvent && accounts.length && !accounts.some(a => sameAccount(a.address, accountEvent[0]))) return 'account-unavailable';
    if (kind === 'unisat' && networkEvent !== null && networkEvent !== 'livenet') return networkEvent === 'testnet' ? 'network-changed' : 'network-unknown';
    if (requests.length > 1 && !picked) return 'request-list';
    if (selected) return selected.expiresAt !== null && selected.expiresAt <= now()
      ? 'request-expired' : selected.transaction ? 'transaction-waiting' : selected.title === 'Sign typed data' ? 'request-typed-data' : 'request-waiting';
    return accounts.length ? 'linked' : 'ready';
  }

  function now() { return Math.floor(Date.now() / 1000); }
  function sameAccount(a, b) { return kind === 'metamask' ? a?.toLowerCase() === b?.toLowerCase() : a === b; }
  function remaining() {
    const deadline = operation ? operation.deadline : selected?.expiresAt;
    return Number.isSafeInteger(deadline) ? Math.min(86400, Math.max(0, deadline - now())) : 0;
  }

  // Capabilities come from this branch's base. Home denies connector navigation.
  // Omit those shared-view intents instead of presenting controls with no effect.
  const supported = new Set(['connect', 'restore-access', 'send-message', 'send-request',
    'stop-waiting', 'close-window', 'copy-address', 'select-request', 'view-requests']);
  function draw() {
    if (disposed) return;
    const view = connectionView({ window: kind, stage, account: accountView(), summary: selected,
      otherRequests: requests.map(r => reduceSummary(r, { connector: CONNECTOR_ID })).filter(r => r && r.id !== selected?.id),
      waitSeconds: remaining(), homeOrigin, alternativeAllowed: false });
    const root = renderConnection(document, view);
    for (const control of root.querySelectorAll('[data-action]')) {
      if (!supported.has(control.dataset.action)) control.remove();
      else if ((operation || uncertain) && !['stop-waiting', 'close-window', 'copy-address'].includes(control.dataset.action)) control.disabled = true;
    }
    const markup = root.outerHTML.replace(/Time left: [0-9]+:[0-9]+/g, 'Time left:');
    if (markup === lastMarkup) {
      const wait = mount.querySelector('.connection-wait');
      if (wait) wait.textContent = view.wait;
      return;
    }
    const old = document.activeElement;
    const focusKey = mount.contains(old) ? old.dataset.focusKey : null;
    const sameFact = lastView?.stage === view.stage && lastView?.request?.id === view.request?.id;
    const scroll = { x: window.scrollX, y: window.scrollY };
    mount.replaceChildren(root);
    lastMarkup = markup;
    lastView = view;
    let focus = sameFact && focusKey ? [...root.querySelectorAll('[data-focus-key]')].find(n => n.dataset.focusKey === focusKey) : null;
    if (!focus && !sameFact) focus = root.querySelector(`[data-action="${view.focus}"]`) || root.querySelector(`[data-focus="${view.focus}"]`);
    focus?.focus({ preventScroll: sameFact });
    if (sameFact) window.scrollTo(scroll.x, scroll.y);
  }

  async function refresh() {
    if (disposed || refreshing) return refreshing;
    if (!frameHomeToken || !homeOrigin || window.top === window) { stage = 'window-expired'; draw(); return; }
    const observedRevision = revision;
    refreshing = (async () => {
      try {
        const [a, r] = await Promise.all(['accounts', 'approvals'].map(suffix => fetchJson(`/api/apps/${CONNECTOR_ID}/wallet/${suffix}`, { headers: { 'x-elastos-home-token': frameHomeToken } })));
        if (disposed) return;
        accounts = Array.isArray(a?.accounts) ? a.accounts : [];
        requests = (Array.isArray(r?.approval_requests) ? r.approval_requests : []).filter(signable);
        if (!operation && !uncertain && observedRevision === revision) {
          if (selected && !requests.some(request => request.request_id === selected.id)) {
            if (['request-waiting', 'request-typed-data', 'transaction-waiting', 'request-list'].includes(stage)) stage = 'request-unavailable';
          } else {
            selected = reduceSummary(requests.find(r => r.request_id === selected?.id) || requests[0], { connector: CONNECTOR_ID });
            stage = chooseStage();
          }
        }
        draw();
      } catch { if (!operation && !uncertain && observedRevision === revision) { stage = 'window-expired'; draw(); } }
      finally { refreshing = null; }
    })();
    return refreshing;
  }

  async function perform(action) {
    if (operation || uncertain) return;
    revision += 1;
    const pending = { action, deadline: now() + 60, stopped: false };
    operation = pending;
    stage = action.kind === 'link' ? 'extension-wait' : selected?.transaction ? 'transaction-extension' : 'request-extension';
    draw();
    try {
      const result = await requestHomeWalletEffect(action);
      // The existing host may finish after Stop waiting. Its real answer wins;
      // stopping the local wait grants neither cancellation nor another send.
      if (disposed) return;
      revision += 1;
      operation = null;
      notifyHomeSummaryChanged();
      if (action.kind === 'link') {
        if (refreshing) await refreshing;
        await refresh();
      } else { stage = (disconnected || accountEvent && !accounts.some(a => sameAccount(a.address, accountEvent[0]))) ? chooseStage() : result.effect === 'transaction' ? 'transaction-done' : 'request-done'; draw(); }
    } catch (error) {
      if (disposed) return;
      revision += 1; operation = null;
      const message = error.message;
      const prefix = action.kind === 'link' ? 'extension' : selected?.transaction ? 'transaction' : 'request';
      if (message === 'Wallet request timed out.') { uncertain = true; stage = `${prefix}-timeout`; }
      else if (/was not found in this browser profile/.test(message)) stage = 'extension-missing';
      else if (action.kind === 'link') stage = 'link-error';
      else stage = `${prefix}-wallet-error`;
      draw();
    }
  }

  function onClick(event) {
    const button = event.target.closest('[data-action]');
    if (!button || button.disabled) return;
    const action = button.dataset.action;
    if (action === 'close-window') window.top.postMessage({ type: 'home:close-self', homeToken: frameHomeToken }, homeOrigin);
    else if (action === 'stop-waiting' && operation) {
      operation.stopped = true;
      stage = operation.action.kind === 'link' ? 'extension-cancelled' : selected?.transaction ? 'transaction-cancelled' : 'request-cancelled';
      draw();
    } else if (operation && action !== 'copy-address') return;
    else if (['connect', 'restore-access', 'send-message'].includes(action)) void perform({ kind: 'link' });
    else if (action === 'send-request' && selected) void perform({ kind: 'approve', approvalRequestId: selected.id });
    else if (action === 'copy-address') {
      const address = button.dataset.focusKey.slice('copy-address:'.length);
      button.disabled = true;
      homeClipboard.writeText(address, { purpose: 'wallet.address' }).catch(() => { button.focus(); }).finally(() => { button.disabled = false; });
    } else if (action === 'view-requests') { picked = false; stage = 'request-list'; draw(); }
    else if (action === 'select-request') {
      const id = button.dataset.focusKey.slice('select-request:'.length);
      picked = true;
      selected = reduceSummary(requests.find(r => r.request_id === id), { connector: CONNECTOR_ID });
      stage = chooseStage(); draw();
    }
  }

  function onWalletEvent(event) {
    const data = event.data;
    if (event.source !== window.top || event.origin !== homeOrigin || data?.type !== 'home:wallet-connector-event'
      || !hasExactKeys(data, ['type', 'connectorId', 'event', 'value']) || data.connectorId !== CONNECTOR_ID) return;
    if (data.event === 'accountsChanged') {
      const pattern = kind === 'metamask' ? /^0x[0-9a-fA-F]{40}$/ : /^(?:bc1|[13])[A-Za-z0-9]{20,100}$/;
      if (!Array.isArray(data.value) || data.value.length > 8 || data.value.some(a => typeof a !== 'string' || !pattern.test(a))) return;
      accountEvent = data.value;
      disconnected = false;
    } else if (data.event === 'disconnect' && data.value === null) { disconnected = true; accountEvent = []; }
    else if (kind === 'metamask' && data.event === 'chainChanged' && typeof data.value === 'string' && /^0x[0-9a-fA-F]{1,16}$/.test(data.value)) networkEvent = data.value;
    else if (kind === 'unisat' && data.event === 'networkChanged' && ['livenet', 'testnet', 'unknown'].includes(data.value)) networkEvent = data.value;
    else return;
    revision += 1;
    if (operation && (disconnected || accountEvent?.length === 0 || accountEvent && accounts.length && !accounts.some(a => sameAccount(a.address, accountEvent[0])))) stage = accounts.length ? 'account-unavailable' : stage;
    if (!operation && !uncertain) stage = chooseStage();
    draw();
  }

  mount.addEventListener('click', onClick);
  window.addEventListener('message', onWalletEvent);
  window.addEventListener('focus', refresh);
  const tick = window.setInterval(() => {
    if (!operation && !uncertain && selected?.expiresAt !== null && selected?.expiresAt <= now() && ['request-waiting', 'request-typed-data', 'transaction-waiting', 'request-list'].includes(stage)) stage = 'request-expired';
    if (operation || selected) draw();
  }, 1000);
  window.addEventListener('pagehide', () => {
    disposed = true; window.clearInterval(tick); homeClipboard.teardown();
    window.removeEventListener('message', onWalletEvent); window.removeEventListener('focus', refresh);
  }, { once: true });
  draw(); void refresh();

  async function fetchJson(url, init) {
    const response = await fetch(url, init);
    if (!response.ok) throw new Error(`request failed: ${response.status}`);
    return response.json();
  }
  function notifyHomeSummaryChanged() {
    if (frameHomeToken && homeOrigin && window.top !== window) window.top.postMessage({ type: 'home:refresh-summary', homeToken: frameHomeToken }, homeOrigin);
  }
function requestHomeWalletEffect(action) {
  if (!frameHomeToken || !homeOrigin || window.top === window) {
    return Promise.reject(new Error("Open this approval method from Wallet."));
  }
  if (hostEffectInFlight) {
    return Promise.reject(new Error("A wallet request is already active."));
  }
  const requestId = nextHostRequestId();
  hostEffectInFlight = true;
  return new Promise((resolve, reject) => {
    const timeout = window.setTimeout(() => {
      finish();
      reject(new Error("Wallet request timed out."));
    }, HOST_EFFECT_TIMEOUT_MS);
    const finish = () => {
      window.clearTimeout(timeout);
      window.removeEventListener("message", onMessage);
      hostEffectInFlight = false;
    };
    const onMessage = (event) => {
      const data = event.data;
      if (
        event.source !== window.top
        || event.origin !== homeOrigin
        || data?.type !== HOST_RESULT_TYPE
        || data.schema !== HOST_RESULT_SCHEMA
        || data.requestId !== requestId
        || data.connectorId !== CONNECTOR_ID
      ) {
        return;
      }
      const hasResult = hasExactKeys(data, [
        "type",
        "schema",
        "requestId",
        "connectorId",
        "result",
      ]);
      const hasError = hasExactKeys(data, [
        "type",
        "schema",
        "requestId",
        "connectorId",
        "error",
      ]);
      if (!hasResult && !hasError) {
        return;
      }
      finish();
      if (hasError) {
        reject(new Error(readText(data.error) || "Wallet request failed."));
        return;
      }
      const expectedResultKeys = action.kind === "link" ? ["status"] : ["status", "effect"];
      if (
        !hasExactKeys(data.result, expectedResultKeys)
        || data.result.status !== (action.kind === "link" ? "linked" : "completed")
        || (
          action.kind === "approve"
          && !["signature", "transaction"].includes(data.result.effect)
        )
      ) {
        reject(new Error("Home returned an invalid wallet result."));
        return;
      }
      resolve(data.result);
    };
    window.addEventListener("message", onMessage);
    window.top.postMessage({
      type: HOST_EFFECT_TYPE,
      schema: HOST_EFFECT_SCHEMA,
      requestId,
      connectorId: CONNECTOR_ID,
      connectorToken: frameHomeToken,
      action,
    }, homeOrigin);
  });
}

function nextHostRequestId() {
  hostRequestSequence += 1;
  const random = typeof window.crypto?.randomUUID === "function"
    ? window.crypto.randomUUID()
    : `${Date.now().toString(36)}-${hostRequestSequence}`;
  return `wallet-effect:${random}`;
}

function hasExactKeys(value, expectedKeys) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const actual = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();
  return actual.length === expected.length
    && actual.every((key, index) => key === expected[index]);
}

function readQueryParam(name) {
  return readText(new URLSearchParams(window.location.search).get(name));
}

function readLaunchToken() {
  return readText(
    new URLSearchParams(window.location.hash.replace(/^#/, "")).get("home_token"),
  );
}

function readText(value) {
  return typeof value === "string" ? value.trim() : "";
}


}
