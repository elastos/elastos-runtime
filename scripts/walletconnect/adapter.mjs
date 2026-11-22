import { EthereumProvider } from "@walletconnect/ethereum-provider";
import QRCode from "qrcode";
import { configureRuntime, retireRuntime } from "./runtime-websocket.mjs";
import { runtimeStorage } from "./runtime-storage.mjs";

// The relay-only adapter uses Reown's provider and a bundled QR renderer. It
// needs neither the hosted wallet picker nor an external RPC for signing.
let provider;
let contextKey;
let currentApi;
let retired = false;
let initializing;
let ownedCore;
let ownedStorage;
const api = (...args) => {
  if (retired) throw new Error("WalletConnect adapter retired.");
  return currentApi(...args);
};
function stopCore(core, current) {
  core?.heartbeat?.stop();
  for (const object of [core?.heartbeat,core?.relayer,core?.relayer?.subscriber,core?.relayer?.publisher,
    core?.history,core?.expirer,core?.pairing,current,current?.signer,current?.signer?.client]) {
    object?.events?.removeAllListeners?.();
  }
}
export async function restoreWalletConnectEvm(options) {
  if (contextKey !== undefined && contextKey !== options.contextKey) await disconnectWalletConnectEvm({api:currentApi});
  if (contextKey !== options.contextKey) { provider = null; contextKey = options.contextKey; }
  currentApi = options.api;
  retired = false;
  configureRuntime({ url: options.relayUrl, authorize: () => options.api("relay-admission", { method: "POST" }) });
  options.signal?.throwIfAborted();
  // The pinned SDK shares Core across module imports. A new adapter must own
  // its Core and revision-bound API; keep the stable prefix for stored sessions.
  if (!provider && !initializing) delete globalThis[`_walletConnectCore_${options.contextKey}`];
  if (!provider && !initializing) {
  ownedStorage = runtimeStorage(api);
  initializing = EthereumProvider.init({
    projectId: options.projectId,
    customStoragePrefix: options.contextKey,
    chains: [],
    optionalChains: options.chains,
    methods: ["personal_sign", "eth_sendTransaction"],
    optionalMethods: [],
    disableProviderPing: true,
    events: ["accountsChanged", "chainChanged"],
    showQrModal: false,
    storage: ownedStorage,
    logger: "silent",
    telemetryEnabled: false,
    metadata: options.metadata,
    // Non-wallet read RPCs have no network route in this adapter.
    rpcMap: Object.fromEntries(options.chains.map(id => [id, `${options.runtimeUrl}/unavailable-rpc`])),
  });
  ownedCore = globalThis[`_walletConnectCore_${options.contextKey}`];
  }
  if (!provider) {
    try { provider = await initializing; ownedCore = provider.signer.client.core; }
    finally { initializing = undefined; }
  }
  if (retired) { stopCore(ownedCore,provider); retireRuntime(); throw new Error("WalletConnect adapter retired."); }
  options.signal?.throwIfAborted();
  // Runtime owns this adapter's relay-only networking. The optional website
  // reputation service uses direct HTTP/iframes, which this capsule cannot
  // reach. Its shared abort controller can strand restored requests before
  // publish. Return the protocol's empty optional attestation instead.
  if (ownedCore.verify) ownedCore.verify.register = async () => "";
  // init() restores a live session from Runtime storage. Reopen its transport
  // instead of asking the phone to approve another pairing after a restart.
  if (!provider.signer.client.core.relayer.connected) await provider.signer.client.core.relayer.transportOpen();
  options.signal?.throwIfAborted();
  return provider;
}

export async function connectWalletConnectEvm(options) {
  const current = await restoreWalletConnectEvm(options);
  if (current.connected && current.session?.expiry > Date.now() / 1000) return current;
  const dialog = document.createElement("dialog");
  dialog.className = "wallet-qr-dialog";
  dialog.setAttribute("aria-labelledby", "wallet-qr-title");
  const title = document.createElement("h2");
  title.id = "wallet-qr-title";
  title.textContent = "Connect wallet";
  const text = document.createElement("p");
  text.textContent = "Scan with your wallet. Then approve the connection in your wallet.";
  const canvas = document.createElement("canvas");
  const cancel = document.createElement("button");
  cancel.className = "wallet-button wallet-button-secondary";
  cancel.textContent = "Cancel";
  cancel.type = "button";
  const copy = document.createElement("button");
  copy.className = "wallet-button wallet-button-secondary";
  copy.textContent = "Copy connection link";
  copy.type = "button";
  copy.disabled = true;
  const copyStatus = document.createElement("p");
  copyStatus.setAttribute("role", "status");
  copyStatus.hidden = true;
  const copyLifetime = new AbortController();
  dialog.append(title, text, canvas, copy, cancel, copyStatus);
  let removed = false;
  const removeDialog = () => { if (!removed) { removed = true; copyLifetime.abort(); dialog.remove(); } };
  let rejectCancel;
  const cancelled = new Promise((_, reject) => { rejectCancel = reject; });
  const stop = (error = new Error("Wallet connection cancelled.")) => {
    removeDialog();
    rejectCancel(error);
    provider.signer.abortPairingAttempt();
    provider.signer.client.core.relayer.transportClose().catch(() => {});
  };
  cancel.onclick = () => stop();
  dialog.addEventListener("cancel", () => stop());
  const abort = () => stop(options.signal.reason);
  options.signal?.addEventListener("abort", abort, {once:true});
  const display = uri => {
    QRCode.toCanvas(canvas, uri, { width: 280, margin: 4 }).catch(error => stop(error));
    if (!dialog.open) dialog.showModal();
    options.onPhase?.('pairing');
    copy.disabled = false;
    copy.onclick = async () => {
      copy.disabled = true;
      try {
        await options.copyLink(uri, {signal:copyLifetime.signal});
        copyStatus.textContent = "Connection link copied. Open it in your wallet app.";
      } catch { copyStatus.textContent = "Home could not copy the connection link. Select Copy connection link to try again."; }
      finally { copyStatus.hidden = false; copy.disabled = false; }
    };
  };
  provider.on("display_uri", display);
  document.body.append(dialog);
  // EthereumProvider.connect rebuilds proposal errors from message alone. Keep
  // the wallet's code before that public wrapper drops it (pinned SDK 2.23.9).
  const signerConnect = provider.signer.connect;
  let proposalError;
  provider.signer.connect = async function (...args) {
    try { return await signerConnect.apply(this, args); }
    catch (error) { proposalError = error; throw error; }
  };
  let timer;
  try {
    timer = setTimeout(() => stop(new Error("The QR code expired. Select Connect wallet for a new one.")), 180000);
    await Promise.race([provider.connect(), cancelled]);
    return provider;
  } catch (error) {
    throw proposalError && error?.message === proposalError.message ? proposalError : error;
  } finally {
    copyLifetime.abort();
    provider.signer.connect = signerConnect;
    clearTimeout(timer);
    options.signal?.removeEventListener("abort", abort);
    provider.removeListener("display_uri", display);
    removeDialog();
  }
}

export async function disconnectWalletConnectEvm(options) {
  currentApi = options.api;
  const current = provider;
  const core = ownedCore;
  const storage = ownedStorage;
  let timer;
  try {
    if (current?.session) await Promise.race([
      current.disconnect(),
      new Promise(resolve => { timer = globalThis.setTimeout(resolve,1000); }),
    ]);
  } finally {
    globalThis.clearTimeout(timer);
    storage?.retire();
    retired = true;
    stopCore(core,current);
    retireRuntime();
    provider = undefined;
    ownedCore = undefined;
    // transportClose can wait for an SDK promise. The host resources above
    // are already stopped and the revision-bound storage API is fenced.
    core?.relayer.transportClose().catch(()=>{});
  }
}
