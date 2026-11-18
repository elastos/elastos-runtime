import { installWalletConnectStorage } from './walletconnect-storage.mjs';
import { createWalletConnectClient, walletConnectMessages, isWalletConnectNetwork } from './walletconnect-client.mjs';
import {
  createHomeClipboardClient,
} from "/apps/home/home-clipboard-client.js?v=home-20260726a";

const CONNECTOR_ID = "wallet-walletconnect";
const connectButton = document.querySelector("#wallet-connect");
const statusNode = document.querySelector("#wallet-status");
const stateNode = document.querySelector("#wallet-state");
const accountsNode = document.querySelector("#wallet-accounts");
const requestsNode = document.querySelector("#wallet-requests");
const frameHomeToken = readLaunchToken();
const homeOrigin = readQueryParam("home_origin");
let hostEffectInFlight = false;
let walletStateRevision = 0;
let pendingEffect;
let connectionCheckInFlight = false;
let actionEpoch = 0;
let currentPhase = 'idle';
let connectionState;
let linkedAccounts = [];
let accountsLoaded = false;
let recoveryAction;
let launchExpired = false;
let ownerConsentNeeded = false;
let connectionNeedsReplacement = false;
const clearMemory = installWalletConnectStorage(window);
const runtimeOrigin = new URL(import.meta.url).origin;
const api = (resource, init={}) => fetchJson(resource.startsWith('/api/') ? runtimeOrigin+resource : `${runtimeOrigin}/api/apps/${CONNECTOR_ID}/${resource}`, {
  ...init, headers:shellHeaders({...init.headers,'content-type':'application/json'}),
});
const connector = createWalletConnectClient({api,origin:runtimeOrigin,clearMemory,copyLink:copyConnectionLink,onPhase:phase=>{
  currentPhase = phase;
  if (phase === 'pairing') showStatus('Scan the QR code with your wallet app, or copy the connection link. Approve the connection there.','muted');
  if (phase === 'ownership') showStatus('Open your wallet app on your phone and sign the linking message. If an older request is still open, decline it first.','muted');
  if (phase === 'signature') showStatus('Open your wallet app on your phone and review the signature request.','muted');
  if (phase === 'transaction') showStatus('Open your wallet app on your phone and review the transaction.','muted');
  renderConnection();
  if (phase === 'changed') refreshReturnedWindow();
  else if (['ownership','signature','transaction'].includes(phase)) checkConnection().catch(()=>{});
}});
window.addEventListener('focus',refreshReturnedWindow);
window.addEventListener('message', event => {
  if (event.source !== window.parent || event.origin !== 'null' || event.data?.type !== 'elastos:shell-layout') return;
  if (event.data.layout?.visible === true) refreshReturnedWindow();
});
let connectionTimer;
let connectionInterval;
let permissionPending = false;
let permissionStatus;
let connectionRevision;
let connectionReturnPending = false;
function watchConnection() {
  if (launchExpired) { window.clearInterval(connectionTimer);connectionTimer = undefined;return; }
  if (!frameHomeToken || typeof window.setInterval !== "function") return;
  const interval = pendingEffect || permissionPending || hostEffectInFlight || permissionStatus && permissionStatus !== 'granted' || document.querySelector('dialog[open]') ? 1000 : 5000;
  if (connectionTimer && connectionInterval === interval) return;
  window.clearInterval(connectionTimer);
  connectionInterval = interval;
  connectionTimer = window.setInterval(checkConnection, interval);
}
async function checkConnection() {
  if (launchExpired || !frameHomeToken || !accountsLoaded) return;
  if (pendingEffect && (!pendingEffect.requestId || !Number.isFinite(pendingEffect.expiresAt) || pendingEffect.expiresAt <= Date.now())) pendingEffect = undefined;
  if (connectionCheckInFlight) { watchConnection(); return; }
  connectionCheckInFlight = true;
  try {
    const saved = pendingEffect;
    const epoch = actionEpoch;
    const current = await connector.effect({ kind: "status" });
    if (epoch !== actionEpoch && current.permission.status === 'granted') return;
    const previousPermission = permissionStatus;
    permissionStatus = current.permission.status;
    if (permissionStatus === 'granted') ownerConsentNeeded = false;
    permissionPending = current.permission.status === "requested" && Boolean(current.permission.request);
    if (saved && pendingEffect === saved && (!saved.requestId || !Number.isFinite(saved.expiresAt) || saved.expiresAt <= Date.now() || current.permission.request?.id !== saved.requestId
      || !['requested','granted'].includes(current.permission.status))) pendingEffect = undefined;
    if (current.permission.status === 'granted' && pendingEffect && pendingEffect === saved && !hostEffectInFlight) {
      const resume = pendingEffect.run;
      pendingEffect = undefined;
      resume();
      return;
    }
    if (current.permission.status === 'revoked' && (hostEffectInFlight || Boolean(connectionState?.session))) {
      showStatus("Internet access for WalletConnect was turned off. Select Connect wallet to ask again.", "muted");
    }
    if (permissionStatus !== previousPermission || saved && permissionStatus === 'granted') {
      if (permissionStatus === 'refused') showStatus(`Internet access for WalletConnect was refused. The Home owner can select Allow in Inbox. Then ${recoveryStep()}.`, "muted");
      if (permissionStatus === 'granted' && !hostEffectInFlight && (saved || ['requested','refused','revoked'].includes(previousPermission))) showStatus(`Internet access is allowed. ${recoveryStep(true)}.`, "muted");
    }
    const previous = connectionState;
    connectionState = current;
    renderConnection();
    if (!hostEffectInFlight && current.permission.status === 'granted') {
      if (current.removed && !previous?.removed) showStatus('Your phone wallet removed this connection. Select Connect wallet for a new QR code.','muted');
      else if (current.expired && !previous?.expired) showStatus('This phone connection expired. Select Connect wallet for a new QR code.','muted');
      else if (current.session && !sessionIsLinked(current.session) && (!previous?.session || previous.revision !== current.revision)) showStatus(`Linking ${current.session.name} is unfinished. Open its app on your phone and select Finish linking, or select Connect wallet for a new QR code.`,'muted');
    }
    connectionRevision = current.revision;
  } catch (error) { if (!hostEffectInFlight) showStatus(errorMessage(error),error.tone || 'muted'); }
  finally {
    connectionCheckInFlight = false;
    watchConnection();
    if (connectionReturnPending) {
      connectionReturnPending = false;
      checkConnection().catch(()=>{});
    }
  }
}
function refreshReturnedWindow() {
  refreshWalletState().catch(()=>{});
  // A return after Inbox must observe access now, including when an older
  // status read is still finishing. Coalesce returns into one fresh read.
  if (connectionCheckInFlight) connectionReturnPending = true;
  else checkConnection().catch(()=>{});
}
new MutationObserver(()=>{watchConnection();renderConnection();}).observe(document.body, {subtree:true,childList:true,attributes:true,attributeFilter:['open']});

const homeClipboard = createHomeClipboardClient({
  targetId: CONNECTOR_ID,
  homeOrigin,
  homeToken: frameHomeToken,
});
homeClipboard.start();

boot();

function boot() {
  document.querySelector("#wallet-disconnect")?.addEventListener("click", async () => {
    const epoch = ++actionEpoch;
    try {
      await requestCapsuleWalletEffect({kind:'disconnect'});
      if (epoch === actionEpoch) { connectionState = undefined; showStatus('Disconnected. Linked accounts stay in Wallet.','muted'); }
    } catch (error) { if (epoch === actionEpoch) { connectionNeedsReplacement = Boolean(error.freshConnection);renderConnection();showStatus(errorMessage(error),error.tone || 'error'); } }
    finally { renderConnection();checkConnection().catch(()=>{}); }
  });
  connectButton?.addEventListener("click", () => onConnect());
  document.querySelector('#wallet-finish')?.addEventListener('click',()=>onConnect({fresh:false}));
  document.querySelector('#wallet-cancel')?.addEventListener('click',cancelWalletWait);
  accountsNode?.addEventListener("click", onAccountClick);
  requestsNode?.addEventListener("click", onRequestClick);
  watchConnection();
  checkConnection().catch(()=>{});
  setState("0 linked");
  refreshWalletState().catch((error) => {
    showStatus(errorMessage(error), error.tone || "error");
  });
}

function sessionIsLinked(session) {
  return linkedAccounts.some(account=>account.chain_namespace === session.chain && readText(account.address).toLowerCase() === readText(session.address).toLowerCase());
}
function recoveryStep(capital = false) {
  const review = recoveryAction?.kind === 'approve' && [...requestsNode.querySelectorAll('[data-wallet-request-sign]')].some(node=>node.dataset.walletRequestSign === recoveryAction.approvalRequestId);
  const text = review ? 'select Review on your request to continue' : 'select Connect wallet to continue';
  return capital ? text[0].toUpperCase()+text.slice(1) : text;
}
function renderConnection() {
  if (launchExpired) {
    for (const button of document.querySelectorAll('.wallet-shell button')) button.hidden = true;
    const node = document.querySelector('#wallet-connection');
    if (node.textContent !== 'Window expired') node.textContent = 'Window expired';
    return;
  }
  const needsOwner = ownerConsentNeeded && permissionStatus !== 'granted';
  const session = connectionState?.session;
  const replace = connectionNeedsReplacement && Boolean(session);
  for (const button of requestsNode.querySelectorAll('[data-wallet-request-sign]')) { button.disabled = hostEffectInFlight || needsOwner || replace;button.hidden = needsOwner || replace; }
  const linked = session && sessionIsLinked(session);
  connectButton.hidden = needsOwner || hostEffectInFlight || Boolean(linked) && !replace;
  connectButton.disabled = hostEffectInFlight;
  document.querySelector('#wallet-finish').hidden = needsOwner || hostEffectInFlight || replace || !session || Boolean(linked);
  document.querySelector('#wallet-disconnect').hidden = hostEffectInFlight || replace || !linked;
  document.querySelector('#wallet-cancel').hidden = !(hostEffectInFlight || pendingEffect) || Boolean(document.querySelector('dialog[open]'));
  const label = hostEffectInFlight
    ? currentPhase === 'starting' || currentPhase === 'idle' ? 'Preparing connection' : 'Waiting for phone'
    : needsOwner ? 'Owner approval needed' : replace ? 'New connection needed' : linked ? `Linked · ${chainLabel(session.chain)}` : session ? 'Linking unfinished'
    : connectionState?.removed ? 'Phone connection removed' : connectionState?.expired ? 'Phone connection expired' : 'Ready to connect';
  const node = document.querySelector('#wallet-connection');
  if (node.textContent !== label) node.textContent = label;
}
async function cancelWalletWait() {
  ++actionEpoch;
  pendingEffect = undefined;
  try {
    await connector.effect({kind:'cancel'});
    connectionState = undefined;
    showStatus(recoveryAction?.intent === 'transaction_intent' ? `Home stopped waiting. ${walletConnectMessages.transactionRecovery}` : 'Home stopped waiting for your wallet. Select Connect wallet for a new QR code.','muted');
  } catch (error) { showStatus(errorMessage(error),error.tone || 'muted'); }
  finally { hostEffectInFlight = false;currentPhase = 'idle';renderConnection();watchConnection();refreshWalletState().catch(()=>{}); }
}
async function copyConnectionLink(uri,{signal}) {
  signal.throwIfAborted();
  if (!homeClipboard.canRequest()) throw new Error('Home Clipboard is unavailable.');
  const requestId = homeClipboard.newRequestId();
  const cancel = ()=>homeClipboard.cancel(requestId);
  signal.addEventListener('abort',cancel,{once:true});
  try { await homeClipboard.writeText(uri,{purpose:'wallet.connection-link',requestId});signal.throwIfAborted(); }
  finally { signal.removeEventListener('abort',cancel); }
}
async function onConnect({fresh = true} = {}) {
  if (hostEffectInFlight || launchExpired) return;
  const epoch = ++actionEpoch;
  connectionNeedsReplacement = false;
  currentPhase = 'starting';
  showStatus(fresh ? 'Preparing a new connection.' : 'Open your wallet app on your phone to finish linking.','muted');
  try {
    await requestCapsuleWalletEffect({kind:'link',fresh});
    if (epoch !== actionEpoch) return;
    showStatus('Approval method added.','success');
    notifyHomeSummaryChanged();
    await refreshWalletState();
  } catch (error) {
    if (epoch === actionEpoch) { connectionNeedsReplacement = Boolean(error.freshConnection);renderConnection();showStatus(errorMessage(error),error.tone || 'error'); }
  } finally {
    if (epoch === actionEpoch) { renderConnection();checkConnection().catch(()=>{}); }
  }
}

async function refreshWalletState() {
  if (!frameHomeToken) {
    renderAccounts([]);
    renderRequests([]);
    showStatus("Open from Wallet to review approval requests.", "error");
    return;
  }
  const revision = ++walletStateRevision;
  const [accountSummary, requestSummary] = await Promise.all([
    fetchJson(`/api/apps/${CONNECTOR_ID}/wallet/accounts`, {
      headers: shellHeaders(),
    }),
    fetchJson(`/api/apps/${CONNECTOR_ID}/wallet/approvals`, {
      headers: shellHeaders(),
    }),
  ]);
  if (revision !== walletStateRevision) return;
  const accounts = Array.isArray(accountSummary?.accounts) ? accountSummary.accounts : [];
  const requests = Array.isArray(requestSummary?.approval_requests)
    ? requestSummary.approval_requests
    : [];
  linkedAccounts = accounts;
  const firstAccounts = !accountsLoaded;
  accountsLoaded = true;
  renderAccounts(accounts);
  renderRequests(requests);
  renderConnection();
  setState(accounts.length > 0 ? `${accounts.length} linked` : "0 linked");
  if (firstAccounts) checkConnection().catch(()=>{});
}

function renderAccounts(accounts) {
  if (!accountsNode) {
    return;
  }
  accountsNode.replaceChildren();
  if (accounts.length === 0) {
    accountsNode.append(emptyNode("No linked accounts."));
    return;
  }
  for (const account of accounts) {
    accountsNode.append(accountCard(account));
  }
}

function accountCard(account) {
  const card = document.createElement("div");
  card.className = "wallet-account";
  const main = document.createElement("div");
  main.className = "wallet-account-main";
  const title = document.createElement("strong");
  title.textContent = `Linked wallet · ${chainLabel(account?.chain_namespace)}`;
  const address = document.createElement("code");
  const addressText = readText(account?.address);
  address.className = "wallet-address";
  address.textContent = addressText || "Unknown address";
  main.append(title, address);
  const copy = document.createElement("button");
  copy.className = "wallet-button wallet-button-secondary wallet-copy-button";
  copy.type = "button";
  copy.textContent = "Copy";
  copy.dataset.walletCopyAddress = addressText;
  copy.disabled = !addressText;
  card.append(main, copy);
  return card;
}

function renderRequests(requests) {
  if (!requestsNode) {
    return;
  }
  requestsNode.replaceChildren();
  const connectorRequests = requests.filter((request) => (
    !isManagedWalletRequest(request) && isWalletConnectSignableRequest(request)
  ));
  if (connectorRequests.length === 0) {
    requestsNode.append(emptyNode("No approval requests."));
    return;
  }
  for (const request of connectorRequests) {
    requestsNode.append(requestCard(request));
  }
}

function requestCard(request) {
  const card = document.createElement("div");
  card.className = "wallet-request";
  const main = document.createElement("div");
  main.className = "wallet-request-main";
  const title = document.createElement("strong");
  title.textContent = walletIntentLabel(request?.intent);
  const meta = document.createElement("span");
  const capsule = readText(request?.capsule_id) || "capsule";
  const address = shortAddress(request?.address);
  meta.textContent = `${capsule} · ${chainLabel(request.chain_namespace)}${address ? ` · ${address}` : ""}`;
  const reason = document.createElement("small");
  reason.textContent = readText(request?.reason)
    || readText(request?.resource)
    || "Approval requested.";
  main.append(title, meta, reason);
  if (request.status === 'approved' && request.intent === 'transaction_intent') {
    const recovery = document.createElement('p');
    recovery.textContent = walletConnectMessages.transactionRecovery;
    card.append(main,recovery);
    return card;
  }
  if (!isWalletConnectNetwork(request.chain_namespace)) {
    const recovery = document.createElement('p');
    recovery.textContent = walletConnectMessages.pendingUnsupportedNetwork(readText(request.chain_namespace).split(':')[1]);
    card.append(main,recovery);
    return card;
  }
  const sign = document.createElement("button");
  sign.className = "wallet-button";
  sign.type = "button";
  sign.textContent = "Review";
  sign.disabled = hostEffectInFlight;
  sign.dataset.walletRequestSign = readText(request?.request_id);
  sign.dataset.walletRequestIntent = readText(request?.intent);
  card.append(main, sign);
  return card;
}

async function onAccountClick(event) {
  const button = event.target?.closest?.("[data-wallet-copy-address]");
  const address = readText(button?.dataset?.walletCopyAddress);
  if (!button || !address) {
    return;
  }
  setButtonBusy(button, true);
  try {
    await copyText(address);
    showStatus("Address copied.", "success");
  } catch (error) {
    showStatus(errorMessage(error), error.tone || "error");
  } finally {
    setButtonBusy(button, false);
  }
}

async function onRequestClick(event) {
  if (hostEffectInFlight || launchExpired) return;
  const button = event.target?.closest?.("[data-wallet-request-sign]");
  const approvalRequestId = readText(button?.dataset?.walletRequestSign);
  if (!button || !approvalRequestId) {
    return;
  }
  const epoch = ++actionEpoch;
  currentPhase = "starting";
  setButtonBusy(button, true);
  showStatus("Preparing request.", "muted");
  try {
    const result = await requestCapsuleWalletEffect({ kind: "approve", approvalRequestId, intent:button.dataset.walletRequestIntent });
    if (epoch !== actionEpoch) return;
    watchConnection();
    showStatus(
      result.message || (result.effect === "transaction" ? "Transaction sent." : "Request signed."),
      "success",
    );
    notifyHomeSummaryChanged();
    await refreshWalletState();
  } catch (error) {
    if (epoch === actionEpoch) { connectionNeedsReplacement = Boolean(error.freshConnection);renderConnection();showStatus(errorMessage(error), error.tone || "error"); }
    await refreshWalletState().catch(() => {});
  } finally {
    setButtonBusy(button, false);
  }
}

async function requestCapsuleWalletEffect(action) {
  const epoch = actionEpoch;
  recoveryAction = action;
  pendingEffect = undefined;
  watchConnection();
  if (!frameHomeToken || hostEffectInFlight) throw new Error('A wallet request is already active.');
  hostEffectInFlight = true;
  renderConnection();
  watchConnection();
  try {
    if (['link','approve'].includes(action.kind)) {
      const consent = await api('internet',{method:'POST',body:JSON.stringify({action:'request'})});
      permissionStatus = consent.status;
      if (consent.status === 'granted') ownerConsentNeeded = false;
      permissionPending = consent.status === 'requested' && Boolean(consent.request);
      if (consent.status !== 'granted') {
        pendingEffect = {requestId:consent.request?.id, expiresAt:(consent.request?.issued_at + 1800) * 1000, action, run: action.kind === 'link' ? ()=>onConnect({fresh:action.fresh !== false}) : () => {
          const button = [...requestsNode.querySelectorAll('[data-wallet-request-sign]')].find(node => node.dataset.walletRequestSign === action.approvalRequestId);
          if (button) return onRequestClick({target:button});
        }};
        watchConnection();
        window.top.postMessage({type:'home:open-target',target:'inbox',query:{notification_id:'walletconnect-internet:permission'},homeToken:frameHomeToken},homeOrigin);
        throw Object.assign(new Error('WalletConnect needs internet access. The Home owner can allow it in Inbox. Then continue here.'), {tone:'muted'});
      }
    }
    return await connector.effect(action);
  } finally {
    if (epoch === actionEpoch) {
      hostEffectInFlight = false;currentPhase = 'idle';
      try {
        connectionState = await connector.effect({kind:'status'});
        permissionStatus = connectionState.permission.status;
        if (permissionStatus === 'granted') ownerConsentNeeded = false;
      } catch {}
      renderConnection();watchConnection();
    }
    await refreshWalletState().catch(() => {});
  }
}

function walletIntentLabel(intent) {
  switch (readText(intent)) {
    case "auth_challenge": return "Sign in";
    case "browser_personal_sign": return "Sign message";
    case "browser_typed_data_sign": return "Sign typed data";
    case "capability_grant": return "Grant access";
    case "credential": return "Issue credential";
    case "publish_envelope": return "Publish";
    case "transaction_intent": return "Transaction";
    case "revocation": return "Revoke";
    default: return "Wallet request";
  }
}

function chainLabel(value) {
  switch (readText(value)) {
    case "eip155:1": return "Ethereum";
    case "eip155:20": return "Elastos Smart Chain";
    case "eip155:8453": return "Base";
    case "eip155:11155111": return "Sepolia test network";
    default: {
      const chainId = readText(value).replace(/^eip155:/, "");
      return chainId ? `an unsupported network (${chainId})` : "an unsupported network";
    }
  }
}

function isManagedWalletRequest(request) {
  return ["managed_evm", "managed_btc_p2wpkh"].includes(readText(request?.proof_type));
}

function isWalletConnectSignableRequest(request) {
  return readText(request?.connector_id) === CONNECTOR_ID
    && readText(request?.intent) !== "bitcoin_bip322_proof"
    && ["siwe", "siwe_erc1271"].includes(readText(request?.proof_type));
}

async function copyText(value) {
  const text = readText(value);
  if (!text) {
    throw new Error("Clipboard is unavailable.");
  }
  await homeClipboard.writeText(text, { purpose: "wallet.address" });
}

async function fetchJson(url, init) {
  const response = await fetch(url, init);
  if (!response.ok) {
    const detail = await response.text().catch(() => "");
    if (detail.trim() === "Only this Home's owner can allow WalletConnect internet access. Ask the owner to review Inbox.") {
      ownerConsentNeeded = true;permissionStatus = 'off';permissionPending = false;renderConnection();watchConnection();
      throw Object.assign(new Error('The Home owner can allow WalletConnect internet access in Inbox.'),{tone:'muted'});
    }
    if (response.status === 403) { launchExpired = true;renderConnection();watchConnection(); }
    throw new Error(response.status === 403 ? 'This wallet window expired. Close it and open WalletConnect again.' : detail.trim() || 'ElastOS could not complete this request. Try again.');
  }
  return response.json();
}

function shellHeaders(extra = {}) {
  return { ...extra, "x-elastos-home-token": frameHomeToken };
}

function notifyHomeSummaryChanged() {
  if (frameHomeToken && homeOrigin && window.top !== window) {
    window.top.postMessage({ type: "home:refresh-summary", homeToken: frameHomeToken }, homeOrigin);
  }
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

function shortAddress(value) {
  const address = readText(value);
  return address.length <= 14 ? address : `${address.slice(0, 6)}...${address.slice(-4)}`;
}

function emptyNode(message) {
  const empty = document.createElement("div");
  empty.className = "wallet-empty";
  empty.textContent = message;
  return empty;
}

function setState(message) {
  if (stateNode) stateNode.textContent = message;
}

function showStatus(message, tone) {
  if (!statusNode) return;
  const text = readText(message);
  statusNode.hidden = !text;
  statusNode.textContent = text;
  statusNode.dataset.tone = tone || "muted";
}

function setButtonBusy(button, busy) {
  if (button) button.disabled = Boolean(busy);
}

function errorMessage(error) {
  return error instanceof Error ? error.message : String(error || "Wallet request failed.");
}
