import { connectionView, renderConnection, mountConnection, reduceSummary } from './wallet-connection-view.mjs';

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
  let picked = false, linkObserved = false;
  let stage = 'ready', accounts = [], requests = [], selected = null;
  let uncertain = false, fixedOutcome = false;
  let operation = null, revision = 0, refreshing = null, disposed = false;
  let accountEvent = null, networkEvent = null, disconnected = false;
  let preflightFailure = null, refusal = null;
  let providerAvailability = 'unknown';
  let chosenWalletChoiceId = null;
  let walletChoicesFromHome = [];
  let operationWallet = null;
  let pendingEffectAction = null;
  const requestNetworks = new Map();
  let presentation = null;
  const mount = document.querySelector('#connection-root');

  function validAddress(value) {
    return typeof value === 'string' && (kind === 'metamask' ? /^0x[0-9a-fA-F]{40}$/ : /^(?:bc1|[13])[A-Za-z0-9]{20,100}$/).test(value);
  }

  function accountView() {
    const candidates = accounts.filter(a => a?.connector_id === CONNECTOR_ID || !a?.connector_id)
      .filter(a => typeof a.address === 'string' && a.address.length <= 128);
    const address = selected?.address || accountEvent?.[0];
    const row = address ? candidates.find(a => sameAccount(a.address, address)) || (selected && validAddress(selected.address) ? { address: selected.address, chain_namespace: requests.find(r => r.request_id === selected.id)?.chain_namespace } : null)
      : candidates[0] || null;
    const rows = address ? row ? [row] : [] : candidates;
    if (!rows.length) return null;
    const networks = chain => {
      if (selected && requestNetworks.has(selected.id)) return [networkName(requestNetworks.get(selected.id))];
      if (networkEvent !== null) {
        if (kind === 'unisat') return [networkEvent === 'livenet' ? 'Bitcoin' : networkEvent === 'testnet' ? 'Bitcoin test network (unsupported)' : 'Unknown network'];
        const number = BigInt(networkEvent).toString();
        return [networkName(`eip155:${number}`)];
      }
      // A stored link names its recorded network, not a fresh provider read.
      return [networkName(chain)];
    };
    return { name: kind === 'metamask' ? 'Your wallet' : 'UniSat', mark: kind === 'metamask' ? 'wallet' : kind, connection: null,
      accounts: rows.map(row => ({ address: row.address, networks: networks(row.chain_namespace) })) };
  }

  function networkName(chain) {
    return ({ 'eip155:1': 'Ethereum', 'eip155:20': 'Elastos Smart Chain', 'eip155:8453': 'Base',
      'bip122:000000000019d6689c085ae165831e93': 'Bitcoin' })[chain] || String(chain?.startsWith('eip155:') ? `Network ${chain.slice(7)}` : chain || 'Unknown network').slice(0, 80);
  }

  function signable(request) {
    return request?.connector_id === CONNECTOR_ID && (kind === 'unisat'
      ? request.intent === 'bitcoin_bip322_proof' && ['bip322_simple', 'bitcoin_signed_message'].includes(request.proof_type)
        && request.chain_namespace === 'bip122:000000000019d6689c085ae165831e93'
      : request.intent !== 'bitcoin_bip322_proof' && ['siwe', 'siwe_erc1271'].includes(request.proof_type));
  }

  function chooseStage() {
    if (selected && !validAddress(selected.address)) { fixedOutcome = true; return 'request-unavailable'; }
    if (selected?.status === 'rejected') return 'request-rejected';
    if (selected?.status === 'dismissed') return 'request-dismissed';
    if (selected?.status === 'completed') return selected.transaction ? 'transaction-done' : 'request-done';
    if (isRequestExpired()) { fixedOutcome = true; return 'request-expired'; }
    if (preflightFailure) return preflightFailure;
    if (disconnected) return linkObserved ? 'account-unavailable' : 'link-error';
    if (accountEvent && selected && !sameAccount(accountEvent[0], selected.address)) return 'account-unavailable';
    if (accountEvent?.length === 0) return accounts.length ? 'account-unavailable' : 'ready';
    if (accountEvent && accounts.length && !accounts.some(a => sameAccount(a.address, accountEvent[0]))) return 'account-unavailable';
    if (kind === 'unisat' && networkEvent !== null && networkEvent !== 'livenet') return networkEvent === 'testnet' ? 'network-changed' : 'network-unknown';
    if (requests.length > 1 && !picked) return 'request-list';
    if (selected) return requests.length > 1 ? 'request-multiple' : selected.transaction ? 'transaction-waiting' : requests.find(request => request.request_id === selected.id)?.intent === 'browser_typed_data_sign' ? 'request-typed-data' : 'request-waiting';
    if (kind === 'metamask' && walletChoicesFromHome.length && !chosenWalletChoiceId) return 'extension-choose-wallet';
    return accountView() ? 'linked' : 'ready';
  }

  function now() { return Math.floor(Date.now() / 1000); }
  function isRequestExpired() { return selected?.status === 'pending' && selected.expiresAt !== null && selected.expiresAt <= now(); }
  function sameAccount(a, b) { return kind === 'metamask' ? a?.toLowerCase() === b?.toLowerCase() : a === b; }
  function remaining() {
    const deadline = operation ? operation.deadline : selected?.expiresAt;
    return Number.isSafeInteger(deadline) ? Math.min(86400, Math.max(0, deadline - now())) : 0;
  }

  // Preserve a reused live region, and isolate each dynamic value just as
  // the shared renderer does. This is the two-copy fallback missing in r5.
  function feedbackText(node, parts) {
    const text = parts.map(part => typeof part === 'string' ? part : part.value).join('');
    if (node.textContent === text) return;
    node.replaceChildren(...parts.map(part => {
      if (typeof part === 'string') return document.createTextNode(part);
      const value = document.createElement('bdi');
      value.dir = 'auto'; value.className = 'connection-isolated'; value.textContent = part.value;
      return value;
    }));
  }

  // Home owns every effect. These are the intents this v1 window can perform.
  const supported = ['connect', 'restore-access', 'send-message', 'send-request',
    'stop-waiting', 'close-window', 'copy-address', 'select-request', 'select-wallet', 'view-requests', 'refresh-status'];

  function boundedWalletLabel(value) {
    const name = readText(value);
    if (!name || name.length > 80 || /[<>&]/.test(name)) return null;
    if (new TextEncoder().encode(name).length > 320) return null;
    return name;
  }

  function reduceOperationWallet(raw) {
    if (!raw || typeof raw !== 'object' || !readText(raw.rdns) || !readText(raw.name)) return null;
    const name = boundedWalletLabel(raw.name);
    if (!name) return null;
    return { rdns: readText(raw.rdns).toLowerCase(), name };
  }

  function buildProviderSnapshot() {
    if (operationWallet) {
      return {
        providerId: operationWallet.rdns || null, displayName: operationWallet.name, alternatives: [], availability: providerAvailability === 'unknown' ? 'found' : providerAvailability,
        firstAccount: null, requiredAccountAvailable: null, network: null, networkIssue: null, access: 'unknown',
        busy: false, paymentPending: null,
      };
    }
    return {
      providerId: kind === 'unisat' ? 'unisat' : null, displayName: null, alternatives: [], availability: providerAvailability,
      firstAccount: null, requiredAccountAvailable: null, network: null, networkIssue: null, access: 'unknown',
      busy: false, paymentPending: null,
    };
  }

  function effectAction(action) {
    if (!chosenWalletChoiceId) return action;
    return { ...action, walletChoiceId: chosenWalletChoiceId };
  }

  function draw() {
    if (disposed) return;
    const changedDuringRequest = selected && (disconnected || accountEvent && !sameAccount(accountEvent[0], selected.address));
    const provider = buildProviderSnapshot();
    const walletChoices = stage === 'extension-choose-wallet' ? walletChoicesFromHome : [];
    const viewStage = refusal ? 'request-dismissed' : stage;
    const view = connectionView({ window: kind, stage: viewStage, provider, walletChoices,
      previousFocus: !document.hasFocus() ? {window:kind,stage:viewStage,requestId:selected?.id || null,action:null,key:null} : undefined,
      account: changedDuringRequest && !refusal && (operation || uncertain || fixedOutcome || selected.status === 'completed') ? null : accountView(), summary: selected,
      otherRequests: requests.map(r => reduceSummary(r, { connector: CONNECTOR_ID })).filter(r => r && r.id !== selected?.id),
      waitSeconds: remaining(), homeOrigin, alternativeAllowed: false,
      supportedActions: frameHomeToken && homeOrigin && window.top !== window ? supported : supported.filter(a => a !== 'close-window') });
    presentation = mountConnection(mount, view, presentation);
    const root = presentation.root;
    for (const control of root.querySelectorAll('[data-action]')) {
      if ((operation || uncertain) && !['stop-waiting', 'close-window', 'copy-address'].includes(control.dataset.action)) control.disabled = true;
    }
    // R5 has no consumed-but-unsent state. Reuse its outcome/card/Close parts
    // once, with a closed local copy override. No control retries this request.
    if (refusal) {
      root.dataset.state = 'request-consumed';
      root.dataset.extensionFeedback = 'consumed';
      const wallet = kind === 'metamask' ? 'your wallet' : 'UniSat';
      const needed = refusal.cause === 'account' ? refusal.address : refusal.network;
      const app = selected.actor === 'browser' && selected.site ? selected.site : selected.app === 'Requesting app' ? 'the app' : selected.app;
      feedbackText(root.querySelector('.connection-status'), refusal.cause === 'account' ? [wallet[0].toUpperCase()+wallet.slice(1), ` was using a different ${refusal.cause}. This request needed ${refusal.cause} `, {value:needed}, '.'] : ['Home could not confirm that ', wallet, ' was on ', {value:needed}, '.']);
      feedbackText(root.querySelector('.connection-notice'), kind === 'metamask' ? [`This request can no longer be sent. In ${wallet}, switch to `, {value:needed}, '. Then go back to ', {value:app}, ' and start a new request.'] : [`This request can no longer be sent. Select ${refusal.cause} `, {value:needed}, ` in ${wallet}. Then go back to `, {value:app}, ' and start a new request.']);
    } else if (stage === 'network-changed' && preflightFailure === stage && networkEvent !== 'testnet') {
      root.querySelector('.connection-status')?.replaceChildren();
    } else if (['request-wallet-error', 'transaction-wallet-error'].includes(stage)) {
      root.dataset.extensionFeedback = 'unknown-error';
      feedbackText(root.querySelector('.connection-status'), [selected.transaction ? 'Home could not confirm the result. The transaction may have been sent.' : 'Home could not confirm the result.']);
      feedbackText(root.querySelector('.connection-notice'), [kind === 'metamask' ? 'Before you make another request, check your wallet, then open Wallet from Home and check Activity.' : 'Before you try again, check UniSat and Activity in Wallet.']);
    }
    // v1 keeps the admitted Home operation alive after local Stop/timeout.
    // R5's filtered Check action assumes a terminal wait, which v1 cannot claim.
    const notice = root.querySelector('.connection-notice');
    if (notice && ['extension-timeout','extension-cancelled','link-timeout','link-cancelled','request-timeout','request-cancelled'].includes(stage)) {
      root.dataset.extensionFeedback = 'local-wait';
      feedbackText(notice, [kind === 'metamask' ? 'This request may still be in progress in your wallet. Closing this window does not cancel it. Check your wallet and Activity in Wallet before making another request. Open Wallet from Home to see Activity.' : 'A request may still be waiting in UniSat. Closing this window does not cancel it. Check UniSat and Activity in Wallet.']);
    }
    // Some R5 outcome tables still offer only navigation that v1 cannot do.
    // Until the shared capability fallback covers them, reuse its Close part.
    if (!root.querySelector('button:not(:disabled)') && frameHomeToken && homeOrigin && window.top !== window) {
      const close = renderConnection(document, connectionView({ window: kind, stage: 'window-expired', provider, supportedActions: ['close-window'] })).querySelector('[data-action="close-window"]');
      root.querySelector('.connection-actions')?.append(close);
    }
  }

  async function refresh() {
    if (disposed || refreshing) return refreshing;
    if (!frameHomeToken || !homeOrigin || window.top === window) { fixedOutcome = true; stage = 'window-expired'; draw(); return; }
    const observedRevision = revision;
    refreshing = (async () => {
      try {
        const [a, r] = await Promise.all(['accounts', 'approvals'].map(suffix => fetchJson(`/api/apps/${CONNECTOR_ID}/wallet/${suffix}`, { headers: { 'x-elastos-home-token': frameHomeToken } })));
        if (disposed || observedRevision !== revision) return;
        if (a?.available === false || !Array.isArray(a?.accounts)) throw new Error('Home accounts are unavailable.');
        const approvals = approvalList(r);
        accounts = a.accounts;
        for (const request of approvals) requestNetworks.set(request.request_id, request.chain_namespace);
        requests = approvals.filter(signable).filter(r => !fixedOutcome || r.request_id !== selected?.id);

        if (refusal) {
          const next = requests.find(request => !refusal.knownIds.includes(request.request_id) && request.status === 'pending');
          if (!next) { draw(); return; }
          refusal = null; preflightFailure = null; fixedOutcome = false; picked = false;
          selected = reduceSummary(next, {connector: CONNECTOR_ID});
        }
        if (!operation && !uncertain && !fixedOutcome && observedRevision === revision) {
          if (selected && !requests.some(request => request.request_id === selected.id)) {
            if (selected.status === 'pending') { stage = 'request-unavailable'; fixedOutcome = true; }
          } else {
            const next = reduceSummary(requests.find(r => r.request_id === selected?.id) || requests[0], { connector: CONNECTOR_ID });
            if (next?.id !== selected?.id) preflightFailure = null;
            selected = next;
            stage = chooseStage();
          }
        }
        if (fixedOutcome && selected?.status === 'completed' && !selected.transaction) stage = requests.length ? 'request-next' : 'request-done';
        draw();
      } catch (error) {
        if (refusal) { draw(); return; }
        if (!operation && !uncertain && !fixedOutcome && observedRevision === revision) {
          stage = [401, 403].includes(error.status) ? 'window-expired' : 'wallet-unavailable';
          if (stage === 'window-expired') fixedOutcome = true;
          draw();
        }
      }
      finally { refreshing = null; }
    })();
    return refreshing;
  }

  async function perform(action) {
    if (operation || uncertain || fixedOutcome && action.kind === 'approve') return;
    revision += 1;
    preflightFailure = null;
    const pending = { action, deadline: now() + HOST_EFFECT_TIMEOUT_MS / 1000 };
    operation = pending;
    pendingEffectAction = action;
    if (action.kind === 'link') { accountEvent = null; networkEvent = null; disconnected = false; fixedOutcome = false; selected = null; picked = false; walletChoicesFromHome = []; }
    stage = action.kind === 'link' ? 'extension-wait' : selected?.transaction ? 'transaction-extension' : 'request-extension';
    draw();
    try {
      const result = await requestHomeWalletEffect(effectAction(action));
      // The existing host may finish after Stop waiting. Its real answer wins;
      // stopping the local wait grants neither cancellation nor another send.
      if (disposed) return;
      providerAvailability = 'found';
      revision += 1;
      operation = null;
      pendingEffectAction = null;
      walletChoicesFromHome = [];
      const wallet = reduceOperationWallet(result.wallet);
      if (wallet) operationWallet = wallet;
      notifyHomeSummaryChanged();
      if (action.kind === 'link') {
        linkObserved = true;
        selected = null;
        if (refreshing) await refreshing;
        await refresh();
      } else {
        fixedOutcome = true;
        requests = requests.filter(r => r.request_id !== selected.id);
        selected = { ...selected, status: 'completed' };
        stage = result.effect === 'transaction' ? 'transaction-done' : requests.length ? 'request-next' : 'request-done';
        draw(); void refresh();
      }
    } catch (error) {
      if (disposed) return;
      revision += 1; operation = null;
      const message = error.message;
      // These are Home's existing pre-sign checks. No wallet signing call ran,
      // but the one-use Runtime handoff may already have consumed the request.
      if (['Switch to the linked account before approving.', 'Switch to the linked Bitcoin account before signing.', 'Wallet account changed before signing.', 'UniSat account changed before signing.'].includes(message)) {
        preflightFailure = selected ? 'request-unsendable' : 'account-unavailable';
      } else if (message === 'Switch UniSat to Bitcoin mainnet.') {
        preflightFailure = selected ? 'request-network-testnet' : 'network-changed';
      } else if (message === 'Wallet did not switch to the Runtime-selected chain.') {
        preflightFailure = 'request-network-declined';
      }
      if (preflightFailure) {
        providerAvailability = 'found';
        if (action.kind === 'approve') {
          refusal = { id: selected.id, cause: preflightFailure === 'request-unsendable' ? 'account' : 'network',
            address: selected.address, network: kind === 'unisat' ? 'Bitcoin mainnet' : networkName(requestNetworks.get(selected.id)), knownIds: requests.map(request => request.request_id) };
          fixedOutcome = true; stage = 'request-consumed';
          requests = requests.filter(request => request.request_id !== selected.id);
          draw();
          if (refreshing) await refreshing;
          await refresh();
        } else { stage = preflightFailure; draw(); }
        return;
      }
      if (action.kind === 'approve' && message !== 'Choose a browser wallet in the connection window.') fixedOutcome = true;
      const prefix = action.kind === 'link' ? 'extension' : selected?.transaction ? 'transaction' : 'request';
      if (message === 'Wallet request timed out.') { uncertain = true; stage = `${prefix}-timeout`; }
      else if (message === 'Choose a browser wallet in the connection window.') {
        providerAvailability = 'found';
        walletChoicesFromHome = Array.isArray(error.walletChoices) ? error.walletChoices : [];
        stage = walletChoicesFromHome.length ? 'extension-choose-wallet' : 'link-error';
        operation = null;
      }
      else if (message === 'The selected browser wallet is not available.') {
        providerAvailability = 'absent';
        stage = action.kind === 'link' ? 'link-error' : `${prefix}-wallet-error`;
      }
      else if (/could not find a browser wallet|was not found in this browser profile/.test(message)) { providerAvailability = 'absent'; stage = 'extension-missing'; }
      else if (action.kind === 'link') stage = 'link-error';
      else stage = `${prefix}-wallet-error`;
      draw();
    }
  }

  function approvalList(response) {
    if (response?.available === false || !Array.isArray(response?.approval_requests)) throw new Error('Home requests are unavailable.');
    return response.approval_requests;
  }


  function onClick(event) {
    const button = event.target.closest('[data-action]');
    if (!button || button.disabled) return;
    const action = button.dataset.action;
    if (action === 'close-window') window.top.postMessage({ type: 'home:close-self', homeToken: frameHomeToken }, homeOrigin);
    else if (action === 'stop-waiting' && operation) {
      stage = operation.action.kind === 'link' ? 'extension-cancelled' : selected?.transaction ? 'transaction-cancelled' : 'request-cancelled';
      draw();
    } else if (operation && action !== 'copy-address') return;
    else if (action === 'refresh-status') void refresh();
    else if (action === 'select-wallet') {
      chosenWalletChoiceId = button.dataset.focusKey.slice('select-wallet:'.length);
      const choice = walletChoicesFromHome.find((row) => row.id === chosenWalletChoiceId);
      if (choice) operationWallet = { rdns: null, name: choice.name };
      revision += 1;
      if (pendingEffectAction) {
        const retry = { ...pendingEffectAction, ...effectAction(pendingEffectAction) };
        pendingEffectAction = null;
        void perform(retry);
        return;
      }
      stage = 'ready'; draw();
    } else if (['connect', 'restore-access', 'send-message'].includes(action)) {
      if (walletChoicesFromHome.length && !chosenWalletChoiceId) { stage = 'extension-choose-wallet'; draw(); return; }
      void perform({ kind: 'link' });
    }
    else if (action === 'send-request' && selected) void perform({ kind: 'approve', approvalRequestId: selected.id });
    else if (action === 'copy-address') {
      const address = button.dataset.focusKey.slice('copy-address:'.length);
      button.disabled = true;
      homeClipboard.writeText(address, { purpose: 'wallet.address' }).catch(() => { button.focus(); }).finally(() => { button.disabled = false; });
    } else if (action === 'view-requests') { revision += 1; fixedOutcome = false; picked = false; selected = reduceSummary(requests[0], { connector: CONNECTOR_ID }); stage = 'request-list'; draw(); }
    else if (action === 'select-request') {
      const id = button.dataset.focusKey.slice('select-request:'.length);
      revision += 1; fixedOutcome = false; picked = true;
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
      if (data.value.length) disconnected = false;
      if (preflightFailure === 'request-unsendable' && sameAccount(data.value[0], selected?.address) || preflightFailure === 'account-unavailable' && data.value.length) preflightFailure = null;
    } else if (data.event === 'disconnect' && data.value === null) { disconnected = true; }
    else if (kind === 'metamask' && data.event === 'chainChanged' && typeof data.value === 'string' && /^0x[0-9a-fA-F]{1,16}$/.test(data.value)) networkEvent = data.value;
    else if (kind === 'unisat' && data.event === 'networkChanged' && ['livenet', 'testnet', 'unknown'].includes(data.value)) networkEvent = data.value;
    else return;
    if (['network-changed', 'request-network-testnet', 'request-network-declined'].includes(preflightFailure) && (data.event === 'networkChanged' && data.value === 'livenet' || data.event === 'chainChanged' && selected && `eip155:${BigInt(data.value)}` === requestNetworks.get(selected.id))) preflightFailure = null;
    providerAvailability = 'found';
    revision += 1;
    if (!operation && !uncertain && !fixedOutcome) { stage = chooseStage(); }
    draw();
  }

  mount.addEventListener('click', onClick);
  window.addEventListener('message', onWalletEvent);
  window.addEventListener('focus', refresh);
  const tick = window.setInterval(() => {
    if (!operation && !uncertain && !fixedOutcome && isRequestExpired()) { stage = 'request-expired'; fixedOutcome = true; }
    if (operation || selected) draw();
  }, 1000);
  window.addEventListener('pagehide', () => {
    disposed = true; presentation?.dispose(); window.clearInterval(tick); homeClipboard.teardown();
    window.removeEventListener('message', onWalletEvent); window.removeEventListener('focus', refresh);
  }, { once: true });
  draw(); void refresh();

  async function fetchJson(url, init) {
    const response = await fetch(url, init);
    if (!response.ok) { const error = new Error(`request failed: ${response.status}`); error.status = response.status; throw error; }
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
      ]) || (
        data?.error
        && hasExactKeys(data, [
          "type",
          "schema",
          "requestId",
          "connectorId",
          "error",
          "walletChoices",
        ])
        && Array.isArray(data.walletChoices)
      );
      if (!hasResult && !hasError) {
        return;
      }
      finish();
      if (hasError) {
        const failure = new Error(readText(data.error) || "Wallet request failed.");
        if (Array.isArray(data.walletChoices)) failure.walletChoices = data.walletChoices;
        reject(failure);
        return;
      }
      const linkKeys = data.result?.wallet ? ["status", "wallet"] : ["status"];
      const approveKeys = data.result?.wallet ? ["status", "effect", "wallet"] : ["status", "effect"];
      const expectedResultKeys = action.kind === "link" ? linkKeys : approveKeys;
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
