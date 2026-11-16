import { EthereumProvider } from "@walletconnect/ethereum-provider";
import QRCode from "qrcode";
import { configureRuntime } from "./runtime-websocket.mjs";
import { runtimeStorage } from "./runtime-storage.mjs";

// The relay-only adapter uses Reown's provider and a bundled QR renderer. It
// needs neither the hosted wallet picker nor an external RPC for signing.
let provider;
let contextKey;
let currentApi;
const api = (...args) => currentApi(...args);
export async function connectWalletConnectEvm(options) {
  if (contextKey !== options.contextKey) { provider = null; contextKey = options.contextKey; }
  currentApi = options.api;
  configureRuntime({ url: options.relayUrl, authorize: () => options.api("relay-admission", { method: "POST" }) });
  options.signal?.throwIfAborted();
  provider ??= await EthereumProvider.init({
    projectId: options.projectId,
    customStoragePrefix: options.contextKey,
    chains: [],
    optionalChains: options.chains,
    methods: ["personal_sign", "eth_sendTransaction"],
    optionalMethods: [],
    disableProviderPing: true,
    events: ["accountsChanged", "chainChanged"],
    showQrModal: false,
    storage: runtimeStorage(api),
    logger: "silent",
    telemetryEnabled: false,
    metadata: options.metadata,
    // Non-wallet read RPCs have no network route in this adapter.
    rpcMap: Object.fromEntries(options.chains.map(id => [id, `${options.runtimeUrl}/unavailable-rpc`])),
  });
  if (options.signal?.aborted) {
    await disconnectWalletConnectEvm(options);
    options.signal.throwIfAborted();
  }
  // init() restores a live session from Runtime storage. Reopen its transport
  // instead of asking the phone to approve another pairing after a restart.
  if (!provider.signer.client.core.relayer.connected) await provider.signer.client.core.relayer.transportOpen();
  if (options.signal?.aborted) {
    await disconnectWalletConnectEvm(options);
    options.signal.throwIfAborted();
  }
  if (provider.connected && provider.session?.expiry > Date.now() / 1000) return provider;
  const dialog = document.createElement("dialog");
  dialog.className = "wallet-qr-dialog";
  dialog.setAttribute("aria-labelledby", "wallet-qr-title");
  const title = document.createElement("h2");
  title.id = "wallet-qr-title";
  title.textContent = "Connect wallet";
  const text = document.createElement("p");
  text.textContent = "Scan with your phone wallet, then approve the connection there.";
  const canvas = document.createElement("canvas");
  const cancel = document.createElement("button");
  cancel.className = "wallet-button wallet-button-secondary";
  cancel.textContent = "Cancel";
  cancel.type = "button";
  dialog.append(title, text, canvas, cancel);
  let rejectCancel;
  const cancelled = new Promise((_, reject) => { rejectCancel = reject; });
  const stop = (error = new Error("Wallet connection cancelled.")) => {
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
    provider.signer.connect = signerConnect;
    clearTimeout(timer);
    options.signal?.removeEventListener("abort", abort);
    provider.removeListener("display_uri", display);
    dialog.remove();
  }
}

export async function disconnectWalletConnectEvm(options) {
  currentApi = options.api;
  try { if (provider?.session) await provider.disconnect(); }
  finally { await provider?.signer.client.core.relayer.transportClose(); }
}
