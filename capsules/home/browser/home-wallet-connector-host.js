import { fetchJson } from "./shell-core.js?v=home-wallpaper-20261030b";

export const WALLET_CONNECTOR_EFFECT_TYPE = "home:wallet-connector-effect";
export const WALLET_CONNECTOR_EFFECT_SCHEMA = "elastos.home.wallet-connector-effect/v1";
const WALLET_CONNECTOR_EFFECT_RESULT_TYPE = "home:wallet-connector-effect-result";
const WALLET_CONNECTOR_EFFECT_RESULT_SCHEMA =
  "elastos.home.wallet-connector-effect-result/v1";
const RUNTIME_REQUEST_SCHEMA = "elastos.home.wallet-connector.effect.request/v1";
const RUNTIME_RESULT_SCHEMA = "elastos.home.wallet-connector.effect.result/v1";
const METAMASK_CONNECTOR_ID = "wallet-metamask";
const UNISAT_CONNECTOR_ID = "wallet-unisat";
const CONNECTOR_IDS = new Set([METAMASK_CONNECTOR_ID, UNISAT_CONNECTOR_ID]);
const METAMASK_RDNS = "io.metamask";
const EIP6963_RDNS_PATTERN = /^[a-z0-9]+(?:\.[a-z0-9-]+)+$/;
const MAX_EIP6963_PROVIDERS = 32;
const MAX_EFFECT_REQUESTS_PER_FRAME = 64;
const OPAQUE_FRAME_TARGET = "*";
const eip6963Providers = [];
const walletChoiceOffers = new WeakMap();
const WALLET_CHOICE_ID_PATTERN = /^wchoice-[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i;
const WALLET_LABEL_RESERVED = /^(?:wallet$|(?:home|inbox|elastos)(?:$| ))/i;
// Only an already admitted effect can identify the recipient. The existing
// clipboard lifetime binds this subscription to that same live document.
const walletEventRecipients = new Map();
const walletEventProviders = new Map();
const observedWalletProviders = new WeakSet();
const WALLET_EVENT_TYPE = "home:wallet-connector-event";

function rememberWalletEventRecipient(event, context) {
  const lifetime = context.clipboardState;
  if (!event.source || event.source !== context.source || lifetime?.retired
    || !lifetime?.generation) return;
  walletEventRecipients.set(context.targetId, {
    source: event.source, lifetime, generation: lifetime.generation,
  });
}

function walletEventValue(connectorId, name, value) {
  if (name === "disconnect") return null;
  if (name === "accountsChanged") {
    const pattern = connectorId === METAMASK_CONNECTOR_ID
      ? /^0x[0-9a-fA-F]{40}$/ : /^(?:bc1|[13])[A-Za-z0-9]{20,100}$/;
    if (!Array.isArray(value) || value.length > 8
      || value.some(account => typeof account !== "string" || !pattern.test(account))) return undefined;
    return [...value];
  }
  if (connectorId === METAMASK_CONNECTOR_ID && name === "chainChanged") {
    return typeof value === "string" && /^0x[0-9a-fA-F]{1,16}$/.test(value) ? value : undefined;
  }
  if (connectorId === UNISAT_CONNECTOR_ID && name === "networkChanged") {
    return ["livenet", "testnet", "unknown"].includes(value) ? value : undefined;
  }
  return undefined;
}

function observeWalletProvider(provider, connectorId) {
  walletEventProviders.set(connectorId, provider);
  if (observedWalletProviders.has(provider) || typeof provider.on !== "function") return;
  observedWalletProviders.add(provider);
  for (const name of ["accountsChanged", connectorId === METAMASK_CONNECTOR_ID
    ? "chainChanged" : "networkChanged", "disconnect"]) {
    provider.on(name, value => {
      if (walletEventProviders.get(connectorId) !== provider) return;
      const payload = walletEventValue(connectorId, name, value);
      const recipient = walletEventRecipients.get(connectorId);
      if (payload === undefined || !recipient) return;
      if (recipient.lifetime.retired || recipient.lifetime.generation !== recipient.generation
        || recipient.source.closed) {
        walletEventRecipients.delete(connectorId);
        return;
      }
      recipient.source.postMessage({ type: WALLET_EVENT_TYPE, connectorId, event: name, value: payload }, OPAQUE_FRAME_TARGET);
    });
  }
}
let eip6963Overflow = false;

installEip6963Discovery();

// This is a read hint. Each Wallet frame reads its own scoped account summary.
export function notifyOpenWallets(context, broadcast) {
  if (context?.kind !== "app-frame" || !["wallet", "wallet-walletconnect", ...CONNECTOR_IDS].includes(context.targetId)) return;
  broadcast([{kind:"wallet.accounts.changed",scope:"wallet",at:Math.floor(Date.now()/1000)}]);
}

export function handleHomeWalletConnectorEffect(event, context, data) {
  if (data?.type !== WALLET_CONNECTOR_EFFECT_TYPE) {
    return false;
  }
  const requestId = readText(data.requestId);
  const connectorId = readText(data.connectorId);
  // Current windows request display facts in their action. Legacy windows keep
  // their exact terminal result shape; this adds no pre-click exchange.
  const includeWallet = data.action?.includeWallet === true;
  const action = includeWallet ? Object.fromEntries(Object.entries(data.action).filter(([key]) => key !== 'includeWallet')) : data.action;
  const state = context?.walletEffectState;
  if (
    context?.kind !== "app-frame"
    || !CONNECTOR_IDS.has(context.targetId)
    || data.requestId !== requestId
    || data.connectorId !== connectorId
    || connectorId !== context.targetId
    || !hasExactKeys(data, [
      "type",
      "schema",
      "requestId",
      "connectorId",
      "connectorToken",
      "action",
    ])
    || data.schema !== WALLET_CONNECTOR_EFFECT_SCHEMA
    || data.connectorToken !== context.homeToken
    || !validRequestId(requestId)
    || !validAction(action)
    || connectorId === UNISAT_CONNECTOR_ID && (includeWallet || action.walletChoiceId || action.linkedAddress)
    || connectorId === METAMASK_CONNECTOR_ID && action.kind === "approve" && !/^0x[0-9a-fA-F]{40}$/.test(action.linkedAddress)
    || !state
  ) {
    replyToConnector(event, requestId, connectorId, null, "Home denied the wallet request.");
    return true;
  }
  if (state.inFlight || state.requestIds.has(requestId)) {
    replyToConnector(
      event,
      requestId,
      connectorId,
      null,
      state.inFlight ? "A wallet request is already active." : "Wallet request replay denied.",
    );
    return true;
  }
  while (state.requestIds.size >= MAX_EFFECT_REQUESTS_PER_FRAME) {
    state.requestIds.delete(state.requestIds.values().next().value);
  }
  rememberWalletEventRecipient(event, context);
  walletEventProviders.delete(connectorId);
  state.requestIds.add(requestId);
  state.inFlight = true;
  performConnectorEffect(connectorId, context.homeToken, action, context)
    .then((result) => {
      const {wallet, ...legacyResult} = result;
      replyToConnector(event, requestId, connectorId, includeWallet ? result : legacyResult);
    })
    .catch((error) => {
      replyToConnector(
        event,
        requestId,
        connectorId,
        null,
        error instanceof Error ? error.message : "Wallet request failed.",
        error?.walletChoices,
      );
    })
    .finally(() => {
      state.inFlight = false;
    });
  return true;
}

function boundedWalletName(value) {
  const name = readText(value);
  return name && name.length <= 80 && new TextEncoder().encode(name).length <= 320
    && !/[<>&\p{Cc}\p{Cf}\p{Co}\p{Cs}\p{Zl}\p{Zp}]/u.test(name) ? name : null;
}

function boundedWalletIcon(value) {
  const icon = readText(value);
  // 64 KiB allows larger wallet marks; recorded marks are 3,686 chars (MetaMask) and 6,006 (Rabby).
  return icon.length <= 65536 && /^data:image\/(?:png|jpeg|webp|gif|svg\+xml);base64,(?=[A-Za-z0-9+/])(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/][AQgw]==|[A-Za-z0-9+/]{2}[AEIMQUYcgkosw048]=)?$/.test(icon) ? icon : null;
}

function presentWalletName(value, rdns) {
  const name = boundedWalletName(value);
  if (!name) return null;
  const normalized = name.normalize('NFKC').toLowerCase();
  const brands = {metamask:'io.metamask', 'brave wallet':'com.brave.wallet', unisat:'unisat', walletconnect:'walletconnect'};
  return WALLET_LABEL_RESERVED.test(normalized) || brands[normalized] && brands[normalized] !== rdns ? null : name;
}

function walletDisplayForEntry(entry) {
  return entry ? Object.freeze({name:entry.name, rdns:entry.rdns, icon:entry.icon}) : null;
}

class WalletChoiceRequired extends Error {
  constructor(walletChoices) {
    super("Choose a browser wallet in the connection window.");
    this.walletChoices = walletChoices;
  }
}

function installEip6963Discovery() {
  window.addEventListener("eip6963:announceProvider", (event) => {
    const info = event?.detail?.info, provider = event?.detail?.provider;
    const rdns = readText(info?.rdns).toLowerCase(), uuid = readText(info?.uuid);
    if (!EIP6963_RDNS_PATTERN.test(rdns) || rdns.length > 128 || !uuid || uuid.length > 128
      || !provider || typeof provider.request !== 'function') return;
    if (eip6963Providers.some(e => e.provider === provider && e.rdns === rdns && e.uuid === uuid)) return;
    if (eip6963Providers.length >= MAX_EIP6963_PROVIDERS) { eip6963Overflow = true; return; }
    eip6963Providers.push({provider, rdns, uuid, name:presentWalletName(info.name, rdns), icon:boundedWalletIcon(info.icon)});
  });
}

function discoverWallets() {
  eip6963Providers.length = 0;
  eip6963Overflow = false;
  window.dispatchEvent(new Event("eip6963:requestProvider"));
  if (eip6963Overflow) throw new Error("Injected wallet provider discovery is ambiguous.");
  const entries = eip6963Providers.filter(entry => !eip6963Providers.some(other => other !== entry && (
    other.provider === entry.provider || other.uuid === entry.uuid || other.rdns === entry.rdns
  ))).filter(entry => entry.name);
  if (!entries.length && eip6963Providers.length) throw new Error("Injected wallet provider discovery is ambiguous.");
  return entries;
}

function sameWallet(a, b) {
  return a.provider === b.provider && a.rdns === b.rdns && a.uuid === b.uuid;
}

function ensureWalletPresent(selected) {
  let present = false;
  try { present = discoverWallets().some(entry => sameWallet(entry, selected)); } catch {}
  if (!present) throw new Error("The selected browser wallet is not available.");
}

function selectMetaMaskCompatibleProvider(context, walletChoiceId) {
  let entries;
  try { entries = discoverWallets(); } catch (error) {
    if (walletChoiceId) throw new Error("The selected browser wallet is not available.");
    throw error;
  }
  const scope = context.walletEffectState;
  const offer = walletChoiceOffers.get(scope);
  walletChoiceOffers.delete(scope);
  if (walletChoiceId) {
    const selected = offer?.source === context.source && offer?.token === context.homeToken && offer?.lifetime === context.clipboardState && offer?.generation === context.clipboardState?.generation
      && !context.clipboardState?.retired && offer.choices.get(walletChoiceId);
    if (!selected || !entries.some(entry => sameWallet(entry, selected))) throw new Error("The selected browser wallet is not available.");
    return selected;
  }
  if (!entries.length) throw new Error("Home could not find a browser wallet in this browser.");
  const metamask = entries.find(entry => entry.rdns === METAMASK_RDNS);
  if (metamask || entries.length === 1) return metamask || entries[0];
  const choices = new Map();
  for (const entry of entries.sort((a,b) => a.name.localeCompare(b.name))) choices.set(`wchoice-${crypto.randomUUID()}`, entry);
  walletChoiceOffers.set(scope, {source:context.source, token:context.homeToken, lifetime:context.clipboardState, generation:context.clipboardState?.generation, choices});
  throw new WalletChoiceRequired([...choices].map(([id, entry]) => ({id, name:entry.name, icon:entry.icon})));
}

async function walletForAccount(address) {
  const entries = discoverWallets().slice(0, 8);
  const results = await Promise.all(entries.map(async entry => {
    let timer;
    try {
      const accounts = await Promise.race([
        Promise.resolve().then(() => entry.provider.request({method:'eth_accounts'})),
        new Promise(resolve => { timer = setTimeout(() => resolve([]), 1000); }),
      ]);
      return Array.isArray(accounts) && accounts.length <= 32 && accounts.some(a => typeof a === 'string' && normalizeAddress(a) === normalizeAddress(address)) ? entry : null;
    } catch { return null; } finally { clearTimeout(timer); }
  }));
  const matches = results.filter(Boolean);
  const selected = matches.find(entry => entry.rdns === METAMASK_RDNS) || matches[0];
  if (!selected) throw new Error("Home cannot confirm access to the account this request needs in your wallet.");
  return selected;
}

async function performConnectorEffect(connectorId, connectorToken, action, context) {
  if (connectorId === METAMASK_CONNECTOR_ID && action.kind === "link") {
    return linkEvmWallet(connectorToken, action.walletChoiceId ?? null, context);
  }
  if (connectorId === UNISAT_CONNECTOR_ID && action.kind === "link") {
    return linkBitcoinWallet(connectorToken);
  }
  if (action.kind === "approve") {
    return completeApproval(connectorId, connectorToken, action.approvalRequestId, action.linkedAddress);
  }
  throw new Error("Unsupported wallet request.");
}

async function linkEvmWallet(connectorToken, walletChoiceId, context) {
  const selected = selectMetaMaskCompatibleProvider(context, walletChoiceId);
  ensureWalletPresent(selected);
  const provider = selected.provider;
  observeWalletProvider(provider, METAMASK_CONNECTOR_ID);
  const accounts = await provider.request({ method: "eth_requestAccounts" });
  const address = requireEvmAddress(firstProviderAccount(accounts));
  const chainId = requireEvmChainId(await provider.request({ method: "eth_chainId" }));
  const challengeResult = await runtimePost(
    "/api/apps/home/wallet-connector/evm/link/challenge",
    connectorBody(METAMASK_CONNECTOR_ID, connectorToken, {
      address,
      chain_id: chainId,
    }),
  );
  const challenge = requireEvmChallenge(challengeResult);
  const signer = requireEvmAddress(await currentEvmAccount(provider));
  ensureSameAddress(signer, address, "Wallet account changed before signing.");
  ensureWalletPresent(selected);
  const signature = requireProviderResult(await provider.request({
    method: "personal_sign",
    params: [challenge.message, signer],
  }), 16 * 1024, "Wallet returned an invalid signature.");
  const verified = await runtimePost(
    "/api/apps/home/wallet-connector/evm/link/verify",
    connectorBody(METAMASK_CONNECTOR_ID, connectorToken, {
      message: challenge.message,
      signature,
    }),
  );
  requireRuntimeCompletion(verified, "evm_link_complete", METAMASK_CONNECTOR_ID, "linked");
  const wallet = walletDisplayForEntry(selected);
  return Object.freeze({ status: "linked", ...(wallet ? { wallet } : {}) });
}

async function linkBitcoinWallet(connectorToken) {
  const provider = requireUniSatProvider();
  observeWalletProvider(provider, UNISAT_CONNECTOR_ID);
  const account = await requestUniSatAccount(provider);
  const challengeResult = await runtimePost(
    "/api/apps/home/wallet-connector/bitcoin/link/challenge",
    connectorBody(UNISAT_CONNECTOR_ID, connectorToken, {
      address: account.address,
      network: "bitcoin",
    }),
  );
  const challenge = requireBitcoinChallenge(challengeResult, account.address);
  const signer = await currentUniSatAccount(provider);
  ensureSameAddress(signer.address, account.address, "UniSat account changed before signing.");
  const proof = await signBitcoinMessage(provider, signer, challenge.message, challenge.proof_type);
  const verified = await runtimePost(
    "/api/apps/home/wallet-connector/bitcoin/link/verify",
    connectorBody(UNISAT_CONNECTOR_ID, connectorToken, {
      message: challenge.message,
      signature: proof.signature,
      signature_type: proof.signatureType,
      public_key: proof.publicKey,
    }),
  );
  requireRuntimeCompletion(verified, "bitcoin_link_complete", UNISAT_CONNECTOR_ID, "linked");
  return Object.freeze({ status: "linked" });
}

async function completeApproval(connectorId, connectorToken, approvalRequestId, linkedAddress) {
  const selected = connectorId === METAMASK_CONNECTOR_ID ? await walletForAccount(linkedAddress) : null;
  if (selected) ensureWalletPresent(selected);
  const provider = connectorId === METAMASK_CONNECTOR_ID
    ? selected.provider
    : requireUniSatProvider();
  observeWalletProvider(provider, connectorId);
  const encodedRequestId = encodeURIComponent(approvalRequestId);
  const response = await runtimePost(
    `/api/apps/home/wallet-connector/approvals/${encodedRequestId}/handoff`,
    connectorBody(connectorId, connectorToken),
  );
  const { handoff, evmChains } = requireHandoffResponse(
    response,
    connectorId,
    approvalRequestId,
  );
  if (connectorId === METAMASK_CONNECTOR_ID) {
    return completeEvmApproval(provider, connectorToken, handoff, evmChains, selected);
  }
  return completeBitcoinApproval(provider, connectorToken, handoff);
}

async function completeEvmApproval(provider, connectorToken, handoff, evmChains, selected = null) {
  const signer = requireEvmAddress(await currentEvmAccount(provider));
  ensureSameAddress(signer, handoff.signer, "Switch to the linked account before approving.");
  const path = `/api/apps/home/wallet-connector/approvals/${encodeURIComponent(handoff.request_id)}/complete`;
  if (handoff.intent === "transaction_intent") {
    await ensureProviderChain(provider, handoff.transaction.chainId, evmChains);
    const currentSigner = requireEvmAddress(await currentEvmAccount(provider));
    ensureSameAddress(
      currentSigner,
      handoff.signer,
      "Switch to the linked account before approving.",
    );
    const transactionHash = requireProviderResult(await provider.request({
      method: "eth_sendTransaction",
      params: [handoff.transaction],
    }), 66, "Wallet returned an invalid transaction hash.");
    if (!/^0x[0-9a-fA-F]{64}$/.test(transactionHash)) throw new Error('Wallet returned an invalid transaction hash. Check your wallet before sending again.');
    const completed = await runtimePost(path, connectorBody(METAMASK_CONNECTOR_ID, connectorToken, {
      payload_hash: handoff.payload_hash,
      signer: currentSigner,
      transaction_hash: transactionHash,
    }));
    requireApprovalCompletion(completed, METAMASK_CONNECTOR_ID, handoff.request_id);
    const wallet = walletDisplayForEntry(selected);
    return Object.freeze({ status: "completed", effect: "transaction", ...(wallet ? { wallet } : {}) });
  }
  const method = handoff.intent === "browser_typed_data_sign"
    ? "eth_signTypedData_v4"
    : "personal_sign";
  const params = method === "eth_signTypedData_v4"
    ? [signer, handoff.message]
    : [handoff.message, signer];
  const signature = requireProviderResult(await provider.request({ method, params }), 16 * 1024,
    "Wallet returned an invalid signature.");
  const completed = await runtimePost(path, connectorBody(METAMASK_CONNECTOR_ID, connectorToken, {
    payload_hash: handoff.payload_hash,
    signature,
    signature_type: method === "eth_signTypedData_v4" ? "eip712" : "personal_sign",
    signer,
  }));
  requireApprovalCompletion(completed, METAMASK_CONNECTOR_ID, handoff.request_id);
  const wallet = walletDisplayForEntry(selected);
  return Object.freeze({ status: "completed", effect: "signature", ...(wallet ? { wallet } : {}) });
}

async function completeBitcoinApproval(provider, connectorToken, handoff) {
  const account = await currentUniSatAccount(provider);
  ensureSameAddress(
    account.address,
    handoff.signer,
    "Switch to the linked Bitcoin account before signing.",
  );
  const proof = await signBitcoinMessage(
    provider,
    account,
    handoff.message,
    handoff.signature_type,
  );
  const path = `/api/apps/home/wallet-connector/approvals/${encodeURIComponent(handoff.request_id)}/complete`;
  const completed = await runtimePost(path, connectorBody(UNISAT_CONNECTOR_ID, connectorToken, {
    payload_hash: handoff.payload_hash,
    signature: proof.signature,
    signature_type: proof.signatureType,
    public_key: proof.publicKey,
    signer: account.address,
  }));
  requireApprovalCompletion(completed, UNISAT_CONNECTOR_ID, handoff.request_id);
  return Object.freeze({ status: "completed", effect: "signature" });
}

async function ensureProviderChain(provider, chainId, chains) {
  const target = normalizeChainId(chainId);
  const active = normalizeChainId(await provider.request({ method: "eth_chainId" }));
  if (active === target) {
    return;
  }
  try {
    await provider.request({
      method: "wallet_switchEthereumChain",
      params: [{ chainId: target }],
    });
  } catch (error) {
    if (!isUnknownChainError(error)) {
      throw error;
    }
    const chain = requireEvmChain(chains, target);
    await provider.request({
      method: "wallet_addEthereumChain",
      params: [chain],
    });
  }
  if (normalizeChainId(await provider.request({ method: "eth_chainId" })) !== target) {
    throw new Error("Wallet did not switch to the Runtime-selected chain.");
  }
}

function requireEvmChain(chains, chainId) {
  const matches = chains.filter((chain) => normalizeChainId(chain?.chainId) === chainId);
  if (matches.length !== 1) {
    throw new Error("Runtime did not provide one exact chain configuration.");
  }
  const chain = matches[0];
  if (
    !hasExactKeys(chain, ["chainId", "chainName", "nativeCurrency", "rpcUrls"])
    || !hasExactKeys(chain.nativeCurrency, ["name", "symbol", "decimals"])
    || !boundedText(chain.chainName, 128)
    || !boundedText(chain.nativeCurrency.name, 128)
    || !boundedText(chain.nativeCurrency.symbol, 32)
    || !Number.isSafeInteger(chain.nativeCurrency.decimals)
    || chain.nativeCurrency.decimals < 0
    || chain.nativeCurrency.decimals > 255
    || !Array.isArray(chain.rpcUrls)
    || chain.rpcUrls.length < 1
    || chain.rpcUrls.length > 4
    || chain.rpcUrls.some((url) => !boundedText(url, 2048) || !url.startsWith("https://"))
  ) {
    throw new Error("Runtime returned an invalid chain configuration.");
  }
  return chain;
}

function requireHandoffResponse(response, connectorId, requestId) {
  if (
    !hasExactKeys(response, [
      "schema",
      "action",
      "connector_id",
      "request_id",
      "handoff",
      "evm_chains",
    ])
    || response.schema !== RUNTIME_RESULT_SCHEMA
    || response.action !== "approval_handoff"
    || response.connector_id !== connectorId
    || response.request_id !== requestId
    || !Array.isArray(response.evm_chains)
  ) {
    throw new Error("Runtime returned an invalid wallet handoff envelope.");
  }
  const handoff = response.handoff;
  const commonKeys = [
    "schema",
    "request_id",
    "intent",
    "payload_hash",
    "signer",
    "status",
  ];
  const transaction = handoff?.intent === "transaction_intent";
  const expectedKeys = transaction
    ? [...commonKeys, "transaction"]
    : [...commonKeys, "message", "signature_type"];
  if (
    !hasExactKeys(handoff, expectedKeys)
    || handoff.schema !== "elastos.wallet.webconnect_handoff/v1"
    || handoff.request_id !== requestId
    || !boundedText(handoff.intent, 128)
    || !/^0x[0-9a-fA-F]{64}$/.test(handoff.payload_hash || "")
    || !boundedText(handoff.signer, 256)
  ) {
    throw new Error("Runtime returned an invalid typed wallet handoff.");
  }
  if (connectorId === UNISAT_CONNECTOR_ID) {
    if (
      handoff.intent !== "bitcoin_bip322_proof"
      || handoff.status !== "awaiting_wallet_signature"
      || !boundedSignedMessage(handoff.message)
      || !["bip322_simple", "ecdsa"].includes(handoff.signature_type)
      || !supportedBitcoinAddress(handoff.signer)
    ) {
      throw new Error("Runtime returned an invalid UniSat handoff.");
    }
  } else if (transaction) {
    if (
      handoff.status !== "awaiting_wallet_transaction"
      || !validTransaction(handoff.transaction, handoff.signer)
    ) {
      throw new Error("Runtime returned an invalid EVM transaction handoff.");
    }
  } else if (
    handoff.intent === "bitcoin_bip322_proof"
    || handoff.status !== "awaiting_wallet_signature"
    || handoff.signature_type !== "personal_sign"
    || !boundedSignedMessage(handoff.message)
    || !/^0x[0-9a-fA-F]{40}$/.test(handoff.signer)
  ) {
    throw new Error("Runtime returned an invalid EVM signature handoff.");
  }
  return { handoff, evmChains: response.evm_chains };
}

function validTransaction(transaction, signer) {
  const keys = ["from", "to", "value", "data", "gas", "gasPrice", "nonce", "chainId"];
  return hasExactKeys(transaction, keys)
    && keys.every((key) => boundedText(transaction[key], key === "data" ? 65_536 : 512))
    && normalizeAddress(transaction.from) === normalizeAddress(signer)
    && /^0x[0-9a-fA-F]{40}$/.test(transaction.from)
    && /^0x[0-9a-fA-F]{40}$/.test(transaction.to)
    && /^0x[0-9a-fA-F]+$/.test(transaction.value)
    && /^0x[0-9a-fA-F]*$/.test(transaction.data)
    && /^0x[0-9a-fA-F]+$/.test(transaction.gas)
    && /^0x[0-9a-fA-F]+$/.test(transaction.gasPrice)
    && /^0x[0-9a-fA-F]+$/.test(transaction.nonce)
    && /^0x[0-9a-fA-F]+$/.test(transaction.chainId);
}

function requireEvmChallenge(response) {
  if (
    !hasExactKeys(response, ["schema", "action", "connector_id", "challenge"])
    || response.schema !== RUNTIME_RESULT_SCHEMA
    || response.action !== "evm_link_challenge"
    || response.connector_id !== METAMASK_CONNECTOR_ID
  ) {
    throw new Error("Runtime returned an invalid EVM challenge envelope.");
  }
  const challenge = response.challenge;
  if (
    !hasExactKeys(challenge, ["schema", "challenge_id", "message", "expires_at", "resources"])
    || challenge.schema !== "elastos.auth.challenge/v1"
    || !boundedText(challenge.challenge_id, 256)
    || !boundedSignedMessage(challenge.message)
    || !Number.isSafeInteger(challenge.expires_at)
    || challenge.expires_at <= 0
    || !Array.isArray(challenge.resources)
  ) {
    throw new Error("Runtime returned an invalid EVM challenge.");
  }
  return challenge;
}

function requireBitcoinChallenge(response, address) {
  if (
    !hasExactKeys(response, ["schema", "action", "connector_id", "challenge"])
    || response.schema !== RUNTIME_RESULT_SCHEMA
    || response.action !== "bitcoin_link_challenge"
    || response.connector_id !== UNISAT_CONNECTOR_ID
  ) {
    throw new Error("Runtime returned an invalid Bitcoin challenge envelope.");
  }
  const challenge = response.challenge;
  if (
    !hasExactKeys(challenge, [
      "schema",
      "challenge_id",
      "message",
      "expires_at",
      "network",
      "address",
      "resources",
      "proof_type",
    ])
    || challenge.schema !== "elastos.wallet.bitcoin_challenge/v1"
    || challenge.network !== "bitcoin"
    || normalizeAddress(challenge.address) !== normalizeAddress(address)
    || !["bip322_simple", "bitcoin_signed_message"].includes(challenge.proof_type)
    || !boundedText(challenge.challenge_id, 256)
    || !boundedSignedMessage(challenge.message)
    || !Number.isSafeInteger(challenge.expires_at)
    || challenge.expires_at <= 0
    || !Array.isArray(challenge.resources)
  ) {
    throw new Error("Runtime returned an invalid Bitcoin challenge.");
  }
  return challenge;
}

function requireRuntimeCompletion(response, action, connectorId, status) {
  if (
    !hasExactKeys(response, ["schema", "action", "connector_id", "status"])
    || response.schema !== RUNTIME_RESULT_SCHEMA
    || response.action !== action
    || response.connector_id !== connectorId
    || response.status !== status
  ) {
    throw new Error("Runtime returned an invalid wallet completion.");
  }
}

function requireApprovalCompletion(response, connectorId, requestId) {
  if (
    !hasExactKeys(response, ["schema", "action", "connector_id", "request_id", "status"])
    || response.schema !== RUNTIME_RESULT_SCHEMA
    || response.action !== "approval_complete"
    || response.connector_id !== connectorId
    || response.request_id !== requestId
    || response.status !== "completed"
  ) {
    throw new Error("Runtime returned an invalid approval completion.");
  }
}

function requireUniSatProvider() {
  const provider = window.unisat;
  if (
    !provider
    || typeof provider.requestAccounts !== "function"
    || typeof provider.getAccounts !== "function"
    || typeof provider.getNetwork !== "function"
    || typeof provider.signMessage !== "function"
  ) {
    throw new Error("UniSat was not found in this browser profile.");
  }
  return provider;
}

async function requestUniSatAccount(provider) {
  const account = accountFromProvider(await provider.requestAccounts());
  await requireUniSatMainnet(provider);
  return account;
}

async function currentUniSatAccount(provider) {
  const account = accountFromProvider(await provider.getAccounts());
  await requireUniSatMainnet(provider);
  return account;
}

async function requireUniSatMainnet(provider) {
  if (readText(await provider.getNetwork()).toLowerCase() !== "livenet") {
    throw new Error("Switch UniSat to Bitcoin mainnet.");
  }
}

function accountFromProvider(accounts) {
  const value = Array.isArray(accounts) ? accounts[0] : accounts;
  const address = typeof value === "string"
    ? value.trim()
    : ["address", "walletAddress", "account", "value"]
      .map((key) => readText(value?.[key]))
      .find(Boolean) || "";
  const type = bitcoinAddressType(address);
  if (type === "unsupported") {
    throw new Error("UniSat returned an unsupported Bitcoin address.");
  }
  return { address, type };
}

async function signBitcoinMessage(provider, account, message, signatureType) {
  if (signatureType === "bip322_simple") {
    if (!["native-segwit", "taproot"].includes(account.type)) {
      throw new Error("Runtime challenge does not match the selected Bitcoin address.");
    }
    return {
      signature: requireProviderResult(
        await provider.signMessage(message, "bip322-simple"),
        16 * 1024,
        "UniSat returned an invalid signature.",
      ),
      signatureType: "bip322_simple",
      publicKey: null,
    };
  }
  if (signatureType === "bitcoin_signed_message" || signatureType === "ecdsa") {
    if (
      !["nested-segwit", "legacy"].includes(account.type)
      || typeof provider.getPublicKey !== "function"
    ) {
      throw new Error("UniSat public-key signing is unavailable for this address.");
    }
    return {
      signature: requireProviderResult(
        await provider.signMessage(message, "ecdsa"),
        16 * 1024,
        "UniSat returned an invalid signature.",
      ),
      signatureType: "ecdsa",
      publicKey: requireProviderResult(
        await provider.getPublicKey(),
        4096,
        "UniSat returned an invalid public key.",
      ),
    };
  }
  throw new Error("Runtime returned an unsupported Bitcoin signature type.");
}

async function currentEvmAccount(provider) {
  return firstProviderAccount(await provider.request({ method: "eth_accounts" }));
}

function firstProviderAccount(accounts) {
  return Array.isArray(accounts) && typeof accounts[0] === "string" ? accounts[0].trim() : "";
}

function requireEvmAddress(value) {
  const address = readText(value);
  if (!/^0x[0-9a-fA-F]{40}$/.test(address)) {
    throw new Error("Wallet returned an invalid EVM account.");
  }
  return address;
}

function requireEvmChainId(value) {
  const chainId = normalizeChainId(value);
  const number = Number.parseInt(chainId.slice(2), 16);
  if (!Number.isSafeInteger(number) || number <= 0) {
    throw new Error("Wallet returned an invalid chain.");
  }
  return number;
}

function normalizeChainId(value) {
  const text = readText(value).toLowerCase();
  if (!/^0x[0-9a-f]+$/.test(text)) {
    throw new Error("Wallet returned an invalid chain.");
  }
  return `0x${BigInt(text).toString(16)}`;
}

function isUnknownChainError(error) {
  const message = String(error?.message || "").toLowerCase();
  return Number(error?.code) === 4902
    || message.includes("unrecognized chain")
    || message.includes("unknown chain");
}

function connectorBody(connectorId, connectorToken, extra = {}) {
  return {
    schema: RUNTIME_REQUEST_SCHEMA,
    connector_id: connectorId,
    connector_token: connectorToken,
    ...extra,
  };
}

async function runtimePost(url, body) {
  return fetchJson(url, {
    method: "POST",
    body: JSON.stringify(body),
  });
}

function validWalletChoiceId(value) {
  return typeof value === "string" && WALLET_CHOICE_ID_PATTERN.test(value);
}

function validAction(action) {
  if (!action || typeof action !== "object" || Array.isArray(action)) {
    return false;
  }
  if (action.kind === "link") {
    if (hasExactKeys(action, ["kind"])) {
      return true;
    }
    return hasExactKeys(action, ["kind", "walletChoiceId"]) && validWalletChoiceId(action.walletChoiceId);
  }
  if (action.kind === "approve") {
    if (hasExactKeys(action, ["kind", "approvalRequestId"])
      && validApprovalRequestId(action.approvalRequestId)) {
      return true;
    }
    return hasExactKeys(action, ["kind", "approvalRequestId", "linkedAddress"])
      && validApprovalRequestId(action.approvalRequestId)
      && /^0x[0-9a-fA-F]{40}$/.test(action.linkedAddress);
  }
  return false;
}

function validRequestId(value) {
  return /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(value);
}

function validApprovalRequestId(value) {
  return boundedText(value, 256) && readText(value) === value;
}

function boundedText(value, maxLength) {
  return typeof value === "string"
    && value.length > 0
    && value.length <= maxLength
    && ![...value].some((character) => /\p{Cc}/u.test(character));
}

function boundedSignedMessage(value) {
  if (typeof value !== "string" || value.length === 0 || value.length > 65_536 || value.includes("\0")) {
    return false;
  }
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code === 10) {
      continue;
    }
    if (code === 13 && value.charCodeAt(index + 1) === 10) {
      index += 1;
      continue;
    }
    if (code < 32 || code === 127) {
      return false;
    }
  }
  return true;
}

function requireProviderResult(value, maxLength, message) {
  if (!boundedText(value, maxLength)) {
    throw new Error(message);
  }
  return value;
}

function supportedBitcoinAddress(value) {
  return bitcoinAddressType(value) !== "unsupported";
}

function bitcoinAddressType(value) {
  const address = normalizeAddress(value);
  if (address.startsWith("bc1q")) return "native-segwit";
  if (address.startsWith("bc1p")) return "taproot";
  if (address.startsWith("3")) return "nested-segwit";
  if (address.startsWith("1")) return "legacy";
  return "unsupported";
}

function ensureSameAddress(actual, expected, message) {
  if (normalizeAddress(actual) !== normalizeAddress(expected)) {
    throw new Error(message);
  }
}

function normalizeAddress(value) {
  return readText(value).toLowerCase();
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

function readText(value) {
  return typeof value === "string" ? value.trim() : "";
}

function reduceWalletChoiceForWire(choice) {
  if (!choice || typeof choice !== "object" || !validWalletChoiceId(choice.id)) {
    return null;
  }
  const name = boundedWalletName(choice.name);
  if (!name) {
    return null;
  }
  const icon = choice.icon === null || choice.icon === undefined
    ? null
    : boundedWalletIcon(choice.icon);
  if (choice.icon && icon === null) {
    return null;
  }
  return { id: choice.id, name, icon: icon ?? null };
}

function replyToConnector(event, requestId, connectorId, result, error = "", walletChoices = null) {
  if (!event.source || !validRequestId(requestId) || !CONNECTOR_IDS.has(connectorId)) {
    return;
  }
  const errorText = readText(error);
  const safeError = boundedText(errorText, 512) ? errorText : "Wallet request failed.";
  const payload = error
    ? {
        type: WALLET_CONNECTOR_EFFECT_RESULT_TYPE,
        schema: WALLET_CONNECTOR_EFFECT_RESULT_SCHEMA,
        requestId,
        connectorId,
        error: safeError,
      }
    : {
        type: WALLET_CONNECTOR_EFFECT_RESULT_TYPE,
        schema: WALLET_CONNECTOR_EFFECT_RESULT_SCHEMA,
        requestId,
        connectorId,
        result,
      };
  if (error && Array.isArray(walletChoices) && walletChoices.length > 0 && walletChoices.length <= 32) {
    const reduced = walletChoices.map(reduceWalletChoiceForWire).filter(Boolean);
    if (reduced.length > 0) {
      payload.walletChoices = reduced;
    }
  }
  event.source.postMessage(payload, OPAQUE_FRAME_TARGET);
}
