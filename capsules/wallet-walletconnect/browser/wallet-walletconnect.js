import { installWalletConnectStorage } from './walletconnect-storage.mjs';
import { createWalletConnectClient } from './walletconnect-client.mjs';
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
const clearMemory = installWalletConnectStorage(window);
const runtimeOrigin = new URL(import.meta.url).origin;
const api = (resource, init={}) => fetchJson(resource.startsWith('/api/') ? runtimeOrigin+resource : `${runtimeOrigin}/api/apps/${CONNECTOR_ID}/${resource}`, {
  ...init, headers:shellHeaders({'content-type':'application/json'}),
});
const connector = createWalletConnectClient({api,origin:runtimeOrigin,clearMemory});
window.addEventListener('focus',()=>refreshWalletState().catch(()=>{}));
let connectionTimer;
let connectionRevision;
function watchConnection() {
  if (!frameHomeToken || connectionTimer || typeof window.setInterval !== "function") return;
  connectionTimer = window.setInterval(async () => {
    if (hostEffectInFlight) return;
    try {
      const current = await requestCapsuleWalletEffect({ kind: "status" });
      document.querySelector("#wallet-connection").textContent = current.status === "connected" ? "Connected" : "Disconnected";
      if (current.status === "connected" && connectionRevision !== undefined && connectionRevision !== current.revision) {
        showStatus("Wallet changed. Check the account and network on your phone.", "muted");
      }
      connectionRevision = current.revision;
    } catch { document.querySelector("#wallet-connection").textContent = "Disconnected"; }
  }, 5000);
}

const homeClipboard = createHomeClipboardClient({
  targetId: CONNECTOR_ID,
  homeOrigin,
  homeToken: frameHomeToken,
});
homeClipboard.start();

boot();

function boot() {
  document.querySelector("#wallet-disconnect")?.addEventListener("click", async () => {
    try { await requestCapsuleWalletEffect({ kind: "disconnect" }); document.querySelector("#wallet-connection").textContent = "Disconnected"; showStatus("Disconnected. Linked accounts stay in Wallet.", "muted"); }
    catch (error) { showStatus(errorMessage(error), "error"); }
  });
  connectButton?.addEventListener("click", onConnect);
  accountsNode?.addEventListener("click", onAccountClick);
  requestsNode?.addEventListener("click", onRequestClick);
  watchConnection();
  setState("0 linked");
  refreshWalletState().catch((error) => {
    showStatus(errorMessage(error), "error");
  });
}

async function onConnect() {
  setButtonBusy(connectButton, true);
  showStatus("Approve in your phone wallet.", "muted");
  try {
    await requestCapsuleWalletEffect({ kind: "link" });
    document.querySelector("#wallet-connection").textContent = "Connected";
    watchConnection();
    showStatus("Approval method added.", "success");
    notifyHomeSummaryChanged();
    await refreshWalletState();
  } catch (error) {
    showStatus(errorMessage(error), "error");
  } finally {
    setButtonBusy(connectButton, false);
  }
}

async function refreshWalletState() {
  if (!frameHomeToken) {
    renderAccounts([]);
    renderRequests([]);
    showStatus("Open from Wallet to review approval requests.", "error");
    return;
  }
  const [accountSummary, requestSummary] = await Promise.all([
    fetchJson(`/api/apps/${CONNECTOR_ID}/wallet/accounts`, {
      headers: shellHeaders(),
    }),
    fetchJson(`/api/apps/${CONNECTOR_ID}/wallet/approvals`, {
      headers: shellHeaders(),
    }),
  ]);
  const accounts = Array.isArray(accountSummary?.accounts) ? accountSummary.accounts : [];
  const requests = Array.isArray(requestSummary?.approval_requests)
    ? requestSummary.approval_requests
    : [];
  renderAccounts(accounts);
  renderRequests(requests);
  setState(accounts.length > 0 ? `${accounts.length} linked` : "0 linked");
}

function renderAccounts(accounts) {
  if (!accountsNode) {
    return;
  }
  accountsNode.replaceChildren();
  if (accounts.length === 0) {
    accountsNode.append(emptyNode("No connected accounts."));
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
  title.textContent = `Connected wallet · ${chainLabel(account?.chain_namespace)}`;
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
    recovery.textContent = 'Check your phone wallet. It may have sent this transaction. Check Wallet activity before you send again.';
    card.append(main,recovery);
    return card;
  }
  const sign = document.createElement("button");
  sign.className = "wallet-button";
  sign.type = "button";
  sign.textContent = "Review";
  sign.dataset.walletRequestSign = readText(request?.request_id);
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
    showStatus(errorMessage(error), "error");
  } finally {
    setButtonBusy(button, false);
  }
}

async function onRequestClick(event) {
  const button = event.target?.closest?.("[data-wallet-request-sign]");
  const approvalRequestId = readText(button?.dataset?.walletRequestSign);
  if (!button || !approvalRequestId) {
    return;
  }
  setButtonBusy(button, true);
  showStatus("Preparing request.", "muted");
  try {
    const result = await requestCapsuleWalletEffect({ kind: "approve", approvalRequestId });
    watchConnection();
    showStatus(
      result.effect === "transaction" ? "Transaction sent." : "Request signed.",
      "success",
    );
    notifyHomeSummaryChanged();
    await refreshWalletState();
  } catch (error) {
    showStatus(errorMessage(error), "error");
  } finally {
    setButtonBusy(button, false);
  }
}

async function requestCapsuleWalletEffect(action) {
  if (!frameHomeToken || hostEffectInFlight) throw new Error('A wallet request is already active.');
  hostEffectInFlight = true;
  try {
    if (['link','approve'].includes(action.kind)) {
      const consent = await api('internet',{method:'POST',body:JSON.stringify({action:'request'})});
      if (consent.status !== 'granted') {
        window.top.postMessage({type:'home:open-target',target:'inbox',query:{notification_id:'walletconnect-internet:permission'},homeToken:frameHomeToken},homeOrigin);
        throw new Error('Allow WalletConnect internet access in Inbox, then connect again.');
      }
    }
    return await connector.effect(action);
  } finally { hostEffectInFlight = false; }
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
      return chainId ? `EVM ${chainId}` : "EVM";
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
    throw new Error(response.status === 403 ? 'This wallet window expired. Close it and open WalletConnect again.' : detail.trim() || 'Runtime could not complete this wallet request. Try again.');
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
