import {
  CHAIN_LABELS,
  MANAGED_CHAIN_NAMESPACES,
  isEvmChainNamespace,
  readText,
} from "./wallet-format.js?v=wallet-20261028a";

// Base comes first and is suggested: the contracts live there today.
export const SUGGESTED_EVM_CHAIN_NAMESPACE = "eip155:8453";

export const EVM_NETWORK_CHOICES = Object.freeze(
  MANAGED_CHAIN_NAMESPACES
    .filter((namespace) => isEvmChainNamespace(namespace))
    .sort((left, right) =>
      Number(right === SUGGESTED_EVM_CHAIN_NAMESPACE) - Number(left === SUGGESTED_EVM_CHAIN_NAMESPACE))
    .map((namespace) => Object.freeze({
      chainNamespace: namespace,
      label: CHAIN_LABELS[namespace] || namespace,
    })),
);

// Proof types whose address is an externally owned key, the same address on
// every EVM chain. A contract account exists only on the chain it was deployed
// to, so it keeps that one chain and has no network choice.
const EVM_EOA_PROOF_TYPES = Object.freeze(["managed_evm", "siwe"]);

function isEvmNetworkChoice(namespace) {
  const value = readText(namespace);
  return EVM_NETWORK_CHOICES.some((choice) => choice.chainNamespace === value);
}

function eoaAccountIds(records) {
  const evmRecords = records.filter((record) => isEvmChainNamespace(record.chain_namespace));
  if (!evmRecords.every((record) => EVM_EOA_PROOF_TYPES.includes(readText(record.proof_type)))) {
    return new Set();
  }
  return new Set(evmRecords.map((record) => record.account_id));
}

// The Wallet keeps one EVM transaction default. This is its chain when this
// card holds it, and "" otherwise.
export function accountDefaultChainNamespace(records, defaults) {
  const accountIds = eoaAccountIds(records);
  const latest = defaults
    .filter((item) => item.intent === "transaction_intent" && isEvmChainNamespace(item.chain_namespace))
    .reduce((current, item) =>
      !current || Number(item.set_at || 0) > Number(current.set_at || 0) ? item : current, null);
  return latest && accountIds.has(latest.account_id) && isEvmNetworkChoice(latest.chain_namespace)
    ? readText(latest.chain_namespace)
    : "";
}

// One EVM key serves every EVM chain, so an externally owned EVM card shows
// the network it pays on: the chain where it holds the transaction default,
// Base otherwise. The Wallet keeps that choice in the default itself, not in
// browser storage.
export function accountDisplayChainNamespace(records, defaults) {
  if (eoaAccountIds(records).size === 0) {
    return "";
  }
  return accountDefaultChainNamespace(records, defaults) || SUGGESTED_EVM_CHAIN_NAMESPACE;
}

// A grouped card binds the default to its exact record on the chosen chain
// when it has one, and to its own record otherwise.
export function accountRecordForNetwork(account, chainNamespace) {
  const records = Array.isArray(account.account_records) && account.account_records.length > 0
    ? account.account_records
    : [account];
  return records.find((record) => record.chain_namespace === chainNamespace)
    || records.find((record) => record.account_id === account.account_id)
    || records[0];
}
