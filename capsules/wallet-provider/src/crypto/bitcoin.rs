use super::*;
use ::bitcoin::{
    consensus::encode::serialize,
    hashes::Hash,
    sighash::{EcdsaSighashType, SighashCache},
    Amount, Network, Witness,
};
pub(super) use elastos_auth::bitcoin::*;
use k256::ecdsa::SigningKey;

pub(crate) fn btc_p2wpkh_address_for_signing_key(
    signing_key: &SigningKey,
) -> Result<String, String> {
    let verifying_key = signing_key.verifying_key();
    let encoded = verifying_key.to_encoded_point(true);
    let secp_pubkey = ::bitcoin::secp256k1::PublicKey::from_slice(encoded.as_bytes())
        .map_err(|err| format!("invalid managed Bitcoin public key: {err}"))?;
    Ok(::bitcoin::Address::p2wpkh(
        &::bitcoin::CompressedPublicKey(secp_pubkey),
        ::bitcoin::KnownHrp::Mainnet,
    )
    .to_string())
}

pub(crate) fn sign_bip322_simple_p2wpkh_approval(
    signing_key: &SigningKey,
    request: &WalletApprovalRequest,
) -> Result<(String, Value), String> {
    validate_bitcoin_bip322_proof_payload(
        &request.payload,
        &LinkedAccount {
            provider_id: None,
            wallet_display_name: None,
            wallet_mark: None,
            account_id: request.account_id.clone(),
            principal_id: request.principal_id.clone(),
            proof_binding_id: request.proof_binding_id.clone(),
            chain_namespace: request.chain_namespace.clone(),
            address: request.address.clone(),
            proof_type: MANAGED_BTC_P2WPKH_PROOF_TYPE.to_string(),
            connector_id: None,
            label: None,
            linked_at: 0,
            revoked_at: None,
        },
    )?;
    let message = request
        .payload
        .get("message")
        .and_then(Value::as_str)
        .ok_or_else(|| "Bitcoin BIP-322 payload missing message".to_string())?;
    let address = bitcoin_address(&request.address, Network::Bitcoin)?;
    let script_pubkey = address.script_pubkey();
    let script_bytes = script_pubkey.as_bytes();
    if script_bytes.len() != 22 || script_bytes[0] != 0x00 || script_bytes[1] != 0x14 {
        return Err("managed Bitcoin account must be native P2WPKH".to_string());
    }

    let message_hash = bip322_message_hash(message.as_bytes());
    let to_spend = bip322_to_spend_tx(&message_hash, script_pubkey.clone());
    let mut to_sign = bip322_to_sign_tx(to_spend.compute_txid(), Witness::new());
    let sighash = SighashCache::new(&mut to_sign)
        .p2wpkh_signature_hash(0, &script_pubkey, Amount::ZERO, EcdsaSighashType::All)
        .map_err(|err| format!("BIP-322 sighash failed: {err}"))?;
    let (signature, _) = signing_key
        .sign_prehash_recoverable(sighash.as_byte_array())
        .map_err(|err| format!("BIP-322 signing failed: {err}"))?;
    let mut signature_der = signature.to_der().as_bytes().to_vec();
    signature_der.push(EcdsaSighashType::All as u8);
    let pubkey = signing_key.verifying_key().to_encoded_point(true);
    let mut witness = Witness::new();
    witness.push(signature_der);
    witness.push(pubkey.as_bytes());
    let signature = BASE64_STANDARD.encode(serialize(&witness));
    let payload = json!({
        "schema": "elastos.wallet.bip322_signature_payload/v1",
        "request_id": request.request_id.clone(),
        "principal_id": request.principal_id.clone(),
        "account_id": request.account_id.clone(),
        "chain_namespace": request.chain_namespace.clone(),
        "address": request.address.clone(),
        "intent": request.intent.clone(),
        "capsule_id": request.requested_by_actor.clone(),
        "resource": request.resource.clone(),
        "reason": request.reason.clone(),
        "message_hash": format!("0x{}", hex::encode(message_hash)),
        "signature_type": "bip322_simple",
    });
    Ok((signature, payload))
}

pub(crate) fn validate_bitcoin_bip322_proof_payload(
    payload: &Value,
    account: &LinkedAccount,
) -> Result<(), String> {
    if payload.get("schema").and_then(Value::as_str)
        != Some("elastos.wallet.bitcoin_bip322_request/v1")
    {
        return Err("Bitcoin BIP-322 payload has unsupported schema".to_string());
    }
    if payload.get("wallet_intent").and_then(Value::as_str) != Some("bitcoin_bip322_proof") {
        return Err("Bitcoin BIP-322 payload has mismatched wallet_intent".to_string());
    }
    if payload.get("chain_namespace").and_then(Value::as_str)
        != Some(account.chain_namespace.as_str())
    {
        return Err("Bitcoin BIP-322 payload chain does not match account".to_string());
    }
    if payload.get("address").and_then(Value::as_str) != Some(account.address.as_str()) {
        return Err("Bitcoin BIP-322 payload address does not match account".to_string());
    }
    let message = payload
        .get("message")
        .and_then(Value::as_str)
        .ok_or_else(|| "Bitcoin BIP-322 payload missing message".to_string())?;
    if message.is_empty() || message.len() > MAX_APPROVAL_PAYLOAD_BYTES {
        return Err("Bitcoin BIP-322 message size is invalid".to_string());
    }
    if !message.contains("wants you to prove Bitcoin account ownership") {
        return Err("Bitcoin BIP-322 message must be a Runtime account proof".to_string());
    }
    if !message.contains(&account.address) {
        return Err("Bitcoin BIP-322 message address does not match account".to_string());
    }
    if !message.lines().any(|line| {
        line.trim()
            .starts_with("- elastos://auth/bitcoin-challenge/")
    }) {
        return Err("Bitcoin BIP-322 message must bind a Runtime bitcoin challenge".to_string());
    }
    Ok(())
}

pub(crate) fn bitcoin_challenge_id_from_message(message: &str) -> Option<&str> {
    message.lines().find_map(|line| {
        line.trim()
            .strip_prefix("- elastos://auth/bitcoin-challenge/")
            .filter(|challenge_id| !challenge_id.trim().is_empty())
    })
}
