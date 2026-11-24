//! Home-owned EOA proofs for account access. Wallet linking keeps its own contract.
//!
//! Caller contract:
//! Take expected purpose from Home-owned pending state, never from the request.
//! Use a fresh CSPRNG nonce/secret and Home's admitted browser channel.
//! Use WalletProofStore to insert Home+nonce if absent with the result's effect.
//! Keep consumed values at least until expiry, including across restarts.
//! Show WalletProofError's single Display message for every verification/store refusal.
//! Before issuance there is no clock skew allowance; retry when the clock catches up.
//! Bound wire decoding; caller owns admission, revocation and method-change policy.

use crate::{checksum_evm_address, recover_evm_address, AuthChallengeV1, ProofBinding};
use chrono::{DateTime, SecondsFormat, Utc};
use k256::ecdsa::Signature;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const SIGNIN_STATEMENT: &str = "Sign in to this Home.";
pub const ADD_SIGNIN_STATEMENT: &str = "Add this wallet as a way to sign in to this Home.";

pub const MAX_WALLET_PROOF_BYTES: usize = 8 * 1024;
pub const DEFAULT_WALLET_PROOF_TTL_SECS: u64 = 300;

/// A proof has exactly one purpose. Method-management policy belongs to the caller.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WalletProofPurpose {
    SignIn,
    AddSignInMethod {
        account_id: String,
        method_digest: [u8; 32],
    },
}

/// Home configuration and pending intent, never values accepted from signed text.
#[derive(Clone)]
pub struct WalletProofInput {
    pub origin: String,
    pub uri: String,
    pub home_id: String,
    pub ceremony_id: String,
    pub chain_id: u64,
    /// A 0x prefix with an unchecked uniform-case body, or a valid EIP-55 checksum.
    pub address: String,
    /// 256 bits from the caller's cryptographic random source, unique on this Home.
    pub nonce: [u8; 32],
    pub issued_at: u64,
    /// A positive lifetime of at most five minutes; callers may choose a shorter one.
    pub ttl_secs: u64,
    pub purpose: WalletProofPurpose,
}

/// Bounded errors carry neither proof material nor wallet identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletProofError {
    InvalidInput,
    Oversize,
    TextMismatch,
    PurposeMismatch,
    CeremonyMismatch,
    NotYetValid,
    Expired,
    InvalidSignature,
}

impl std::fmt::Display for WalletProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Wallet proof refused. Please try again.")
    }
}

impl std::error::Error for WalletProofError {}

/// Immutable, Home-built challenge. Rebuild it from the input and secret in the
/// caller's protected pending store after restart. The wallet receives a secret
/// commitment, while the browser proves possession of the secret itself.
pub struct WalletProofChallenge {
    message: String,
    home_id: String,
    nonce: [u8; 32],
    address: String,
    chain_id: u64,
    issued_at: u64,
    expires_at: u64,
    ceremony_commitment: [u8; 32],
    purpose: WalletProofPurpose,
}

impl WalletProofChallenge {
    pub fn new(
        input: WalletProofInput,
        ceremony_secret: &[u8; 32],
    ) -> Result<Self, WalletProofError> {
        use WalletProofError::InvalidInput;
        if [
            input.origin.len(),
            input.uri.len(),
            input.home_id.len(),
            input.address.len(),
        ]
        .into_iter()
        .any(|len| len > MAX_WALLET_PROOF_BYTES)
        {
            return Err(WalletProofError::Oversize);
        }
        crate::validate_siwe_origin_binding(&input.origin, &input.uri).map_err(|_| InvalidInput)?;
        if input.uri.len() > 512
            || !input
                .uri
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!$&'()*+,-./:;=?@_~%#[]".contains(&b))
            || input.uri.bytes().filter(|b| *b == b'#').count() > 1
            || input.uri[input.origin.len()..].contains(['[', ']'])
            // Preserve one exact configured spelling for wallet origin checks.
            || input.origin.bytes().any(|b| b.is_ascii_uppercase())
            || !token(&input.home_id)
            || !token(&input.ceremony_id)
            || input.address.len() != 42
            || input.chain_id == 0
            || input.nonce == [0; 32]
        {
            return Err(InvalidInput);
        }
        let address = checksum_evm_address(&input.address).map_err(|_| InvalidInput)?;
        let raw_address = &input.address[2..];
        // Uniform-case bodies are unchecked input. Mixed case supplies a checksum.
        if raw_address.bytes().any(|b| b.is_ascii_lowercase())
            && raw_address.bytes().any(|b| b.is_ascii_uppercase())
            && input.address != address
        {
            return Err(InvalidInput);
        }
        if input.ttl_secs == 0 || input.ttl_secs > DEFAULT_WALLET_PROOF_TTL_SECS {
            return Err(InvalidInput);
        }
        let expires_at = input
            .issued_at
            .checked_add(input.ttl_secs)
            .ok_or(InvalidInput)?;
        // Validate before using the legacy formatter, which falls back for invalid times.
        for time in [input.issued_at, expires_at] {
            let time = i64::try_from(time).map_err(|_| InvalidInput)?;
            let date = DateTime::<Utc>::from_timestamp(time, 0).ok_or(InvalidInput)?;
            if date.to_rfc3339_opts(SecondsFormat::Secs, true).len() != 20 {
                return Err(InvalidInput);
            }
        }
        let statement = input.purpose.statement()?;
        let ceremony_commitment = ceremony_commitment(ceremony_secret);
        let challenge = AuthChallengeV1 {
            schema: AuthChallengeV1::SCHEMA.to_string(),
            challenge_id: hex::encode(input.nonce),
            domain: input.origin,
            uri: input.uri,
            statement,
            address: address.clone(),
            chain_id: input.chain_id,
            nonce: hex::encode(input.nonce),
            issued_at: input.issued_at,
            expires_at,
            resources: input.purpose.resources(
                &input.home_id,
                &input.ceremony_id,
                ceremony_secret,
            )?,
        };
        let message = challenge.siwe_message();
        if message.len() > MAX_WALLET_PROOF_BYTES {
            return Err(WalletProofError::Oversize);
        }
        Ok(Self {
            message,
            home_id: input.home_id,
            nonce: input.nonce,
            address,
            chain_id: input.chain_id,
            issued_at: input.issued_at,
            expires_at,
            ceremony_commitment,
            purpose: input.purpose,
        })
    }

    /// The exact UTF-8 bytes to send to personal_sign (EIP-191 over EIP-4361 text).
    pub fn message(&self) -> &str {
        &self.message
    }

    /// `self` comes from Home's pending store; `expected_purpose` comes from the
    /// operation being completed, and `now` is the caller's Unix-seconds clock.
    /// Only ordinary 65-byte r || s || v signatures are supported. No ERC-1271
    /// or ERC-6492 resolution occurs; recovered-key equality supplies the proof.
    pub fn verify(
        &self,
        message: &str,
        signature: &[u8],
        expected_purpose: &WalletProofPurpose,
        ceremony_secret: &[u8; 32],
        now: u64,
    ) -> Result<WalletProofToConsume, WalletProofError> {
        use WalletProofError::*;
        if message.len() > MAX_WALLET_PROOF_BYTES {
            return Err(Oversize);
        }
        if signature.len() != 65 {
            return Err(InvalidSignature);
        }
        if message != self.message {
            return Err(TextMismatch);
        }
        if expected_purpose != &self.purpose {
            return Err(PurposeMismatch);
        }
        if ceremony_commitment(ceremony_secret) != self.ceremony_commitment {
            return Err(CeremonyMismatch);
        }
        if now < self.issued_at {
            return Err(NotYetValid);
        }
        if now >= self.expires_at {
            return Err(Expired);
        }
        let parsed = Signature::try_from(&signature[..64]).map_err(|_| InvalidSignature)?;
        if parsed.normalize_s().is_some() {
            return Err(InvalidSignature);
        }
        // Wallet linking and account access use this one recovery implementation.
        let (address, message_hash) =
            recover_evm_address(message, &hex::encode(signature)).map_err(|_| InvalidSignature)?;
        if !address.eq_ignore_ascii_case(&self.address) {
            return Err(InvalidSignature);
        }
        Ok(WalletProofToConsume {
            expires_at: self.expires_at,
            consumption: WalletProofUse {
                home_id: self.home_id.clone(),
                nonce: self.nonce,
            },
            result: WalletProofResult {
                binding: ProofBinding::evm_account(self.chain_id, &address, now),
                purpose: self.purpose.clone(),
                message_hash,
            },
        })
    }
}

/// Unique consumption key across ALL purposes on this Home. Retain its record
/// through challenge expiry, including restarts; fail closed if storage is lost.
/// Safe external code gets this key only from verification's store call.
/// ```compile_fail
/// use elastos_auth::wallet_signin::WalletProofUse;
/// let forged = WalletProofUse { home_id: "victim-home".into(), nonce: [1; 32] };
/// ```
/// Storage reads back its own key representation, rather than a proof capability.
/// ```compile_fail
/// use elastos_auth::wallet_signin::WalletProofUse;
/// let forged: WalletProofUse = serde_json::from_str(r#"{"home_id":"victim-home","nonce":[]}"#).unwrap();
/// ```
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct WalletProofUse {
    home_id: String,
    nonce: [u8; 32],
}

impl WalletProofUse {
    pub fn home_id(&self) -> &str {
        &self.home_id
    }

    pub fn nonce(&self) -> &[u8; 32] {
        &self.nonce
    }
}

/// A result originates in successful verification. The store receives it for
/// the atomic commit; consume releases it to the caller after that commit.
/// The review's external "victim" construction is rejected:
/// ```compile_fail
/// use elastos_auth::{ProofBinding, wallet_signin::{WalletProofResult, WalletProofPurpose}};
/// let forged = WalletProofResult {
///     binding: ProofBinding::evm_account(8453, "0x0000000000000000000000000000000000000001", 0),
///     purpose: WalletProofPurpose::SignIn,
///     message_hash: [0; 32],
/// };
/// ```
/// ```compile_fail
/// use elastos_auth::wallet_signin::WalletProofResult;
/// let forged: WalletProofResult = serde_json::from_str("{}").unwrap();
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct WalletProofResult {
    binding: ProofBinding,
    purpose: WalletProofPurpose,
    message_hash: [u8; 32],
}

impl WalletProofResult {
    pub fn binding(&self) -> &ProofBinding {
        &self.binding
    }

    pub fn purpose(&self) -> &WalletProofPurpose {
        &self.purpose
    }

    pub fn message_hash(&self) -> &[u8; 32] {
        &self.message_hash
    }
}

/// Caller-owned storage for the proof and its account/session/approval effect.
pub trait WalletProofStore {
    type Error;

    /// Atomically insert the Home+nonce key IF ABSENT with the result's effect.
    /// Refuse a duplicate; retain the key at least until expires_at across restart.
    /// Revalidate authority and terms in that transaction; return Ok only after
    /// commit. An implementation that returns Ok without storing breaks this contract.
    fn insert_if_absent(
        &mut self,
        key: WalletProofUse,
        expires_at: u64,
        result: &WalletProofResult,
    ) -> Result<(), Self::Error>;
}

/// Opaque and single-owner: a verified result is released only by `consume`.
///
/// Break: expose the result field, bypassing consumption.
/// ```compile_fail
/// use elastos_auth::wallet_signin::WalletProofToConsume;
/// fn bypass(proof: WalletProofToConsume) {
///     let _ = proof.result;
/// }
/// ```
///
/// Break: make the pending proof Copy or let consume borrow it.
/// ```compile_fail
/// use elastos_auth::wallet_signin::WalletProofToConsume;
/// use elastos_auth::wallet_signin::WalletProofStore;
/// fn consume_twice<S: WalletProofStore>(proof: WalletProofToConsume, store: &mut S) {
///     let _ = proof.consume(store);
///     let _ = proof.consume(store);
/// }
/// ```
/// A no-op closure supplies no store contract:
/// ```compile_fail
/// use elastos_auth::wallet_signin::WalletProofToConsume;
/// fn skip_storage(proof: WalletProofToConsume) {
///     let _ = proof.consume(&mut |_, _| Ok::<(), ()>(()));
/// }
/// ```
#[must_use = "record consumption atomically with the account, session or approval"]
pub struct WalletProofToConsume {
    consumption: WalletProofUse,
    expires_at: u64,
    result: WalletProofResult,
}

impl WalletProofToConsume {
    /// Release the result after the store's atomic insert-if-absent commits.
    pub fn consume<S: WalletProofStore>(
        self,
        store: &mut S,
    ) -> Result<WalletProofResult, S::Error> {
        store.insert_if_absent(self.consumption, self.expires_at, &self.result)?;
        Ok(self.result)
    }
}

// Values can contain proof material even in account IDs or operation names.
// Formatting these types therefore exposes only the type name.
macro_rules! redacted_format {
    ($($name:ident),+ $(,)?) => {$(
        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(concat!(stringify!($name), " [redacted]"))
            }
        }
        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                std::fmt::Debug::fmt(self, f)
            }
        }
    )+};
}

redacted_format!(
    WalletProofPurpose,
    WalletProofInput,
    WalletProofChallenge,
    WalletProofUse,
    WalletProofResult,
    WalletProofToConsume,
);

fn ceremony_commitment(secret: &[u8; 32]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"elastos.wallet-signin.ceremony/v1\0");
    hash.update(secret);
    hash.finalize().into()
}

fn token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
}

impl WalletProofPurpose {
    /// Runtime uses the same resource meanings for EVM and Bitcoin proofs.
    pub fn resources(
        &self,
        home_id: &str,
        ceremony_id: &str,
        secret: &[u8; 32],
    ) -> Result<Vec<String>, WalletProofError> {
        if !token(home_id) || !token(ceremony_id) {
            return Err(WalletProofError::InvalidInput);
        }
        let intent = match self {
            Self::SignIn => "signin".to_string(),
            Self::AddSignInMethod {
                account_id,
                method_digest,
            } => {
                if !token(account_id) {
                    return Err(WalletProofError::InvalidInput);
                }
                format!(
                    "add-signin:{}:{}",
                    hex::encode(account_id),
                    hex::encode(method_digest)
                )
            }
        };
        Ok(vec![
            format!("elastos://auth/home/{home_id}"),
            format!("elastos://auth/ceremony/{ceremony_id}"),
            format!(
                "elastos://auth/browser/{}",
                hex::encode(ceremony_commitment(secret))
            ),
            format!("elastos://auth/intent/{intent}"),
        ])
    }
    pub fn statement(&self) -> Result<String, WalletProofError> {
        Ok(match self {
            Self::SignIn => SIGNIN_STATEMENT,
            Self::AddSignInMethod { account_id, .. } => {
                if !token(account_id) {
                    return Err(WalletProofError::InvalidInput);
                }
                ADD_SIGNIN_STATEMENT
            }
        }
        .into())
    }
}

#[cfg(test)]
mod tests;
