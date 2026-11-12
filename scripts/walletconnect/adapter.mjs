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
  provider ??= await EthereumProvider.init({
    projectId: options.projectId,
    customStoragePrefix: options.contextKey,
    chains: [options.chains[0]],
    optionalChains: options.chains.slice(1),
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
  // init() restores a live session from Runtime storage. Reopen its transport
  // instead of asking the phone to approve another pairing after a restart.
  await provider.signer.client.core.relayer.transportOpen();
  if (provider.connected && provider.session?.expiry > Date.now() / 1000) return provider;
  const dialog = document.createElement("dialog");
  const text = document.createElement("p");
  text.textContent = "Scan with your phone wallet, then approve the connection there.";
  const canvas = document.createElement("canvas");
  const cancel = document.createElement("button");
  cancel.textContent = "Cancel";
  cancel.type = "button";
  dialog.append(text, canvas, cancel);
  let rejectCancel;
  const cancelled = new Promise((_, reject) => { rejectCancel = reject; });
  const stop = () => {
    provider.signer.abortPairingAttempt();
    provider.signer.client.core.relayer.transportClose().catch(() => {});
    rejectCancel(new Error("Wallet connection cancelled."));
  };
  cancel.onclick = stop;
  dialog.addEventListener("cancel", stop);
  const display = uri => {
    QRCode.toCanvas(canvas, uri, { width: 280, margin: 2 }).catch(stop);
    if (!dialog.open) dialog.showModal();
  };
  provider.on("display_uri", display);
  document.body.append(dialog);
  let timer;
  try {
    await Promise.race([
      provider.connect(), cancelled,
      new Promise((_, reject) => { timer = setTimeout(() => { stop(); reject(new Error("Wallet connection expired.")); }, 180000); }),
    ]);
    return provider;
  } finally {
    clearTimeout(timer);
    provider.removeListener("display_uri", display);
    dialog.remove();
  }
}

export async function disconnectWalletConnectEvm(options) {
  currentApi = options.api;
  try { if (provider?.session) await provider.disconnect(); }
  finally { await provider?.signer.client.core.relayer.transportClose(); }
}
