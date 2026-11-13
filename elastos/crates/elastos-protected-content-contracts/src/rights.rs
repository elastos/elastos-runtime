use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use serde::Serialize;
use sha3::{Digest as _, Keccak256};
use thiserror::Error;

use elastos_auth::ethereum_signed_message_hash;

use crate::canonical::{CanonicalBody, ContractError, Decoder, Encoder};
use crate::{
    AtomicReplayClaimer, CanonicalContract, DeliveryKeyIdentityV1, Digest32,
    ProtectedContentBindingV1, RecipientKeyIdentityV1, ReplayClaimError, ReplayClaimKeyV1,
    WalletAddress, MAX_SESSION_RECIPIENTS_V2,
};

pub const MAX_RIGHTS_REQUEST_LIFETIME_SECS: u64 = 5 * 60;
pub const RIGHTS_CLOCK_SKEW_SECS: u64 = 5;
const WALLET_SIGNATURE_BYTES: usize = 65;
/// The version named on the first line of the V2 consent text and at the end
/// of its canonical domain.
const RIGHTS_REQUEST_V2_VERSION: &str = "rights-request/v2";
/// The `UnsupportedVersion` value for `rights-request/v2` bytes in the
/// layout before ADV-01 (no form tag, no chain id).
pub const PRE_ALIGNMENT_V2: &str = "rights-request/v2 pre-alignment layout";
/// After the recipients, the pre-alignment layout always holds exactly
/// delivery 32 + issued 8 + expires 8 + nonce 16 bytes. The aligned layout
/// holds 41 (tag 0) or 73 (tag 1), so 64 names the old layout. A malformed
/// tail of exactly 64 bytes is classified the same way; both are refusals
/// (AD01-F9).
const PRE_ALIGNMENT_V2_TAIL_BYTES: usize = 32 + 8 + 8 + 16;
/// Bytes of a key or digest the consent text shows.
const CONSENT_FINGERPRINT_BYTES: usize = 8;
/// The form tag after the recipients: 0 is the direct form, 1 the pool form
/// followed by the delivery key.
const RIGHTS_V2_DIRECT_FORM: u8 = 0;
const RIGHTS_V2_POOL_FORM: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RightsError {
    #[error(transparent)]
    Contract(#[from] ContractError),
    #[error(transparent)]
    Replay(#[from] ReplayClaimError),
    #[error("rights binding mismatch: {0}")]
    BindingMismatch(&'static str),
    #[error("Wallet signature does not recover the bound Wallet")]
    WalletMismatch,
    #[error("Wallet signature is invalid or noncanonical")]
    InvalidWalletSignature,
    #[error("rights authority is not yet valid")]
    NotYetValid,
    #[error("rights authority expired")]
    Expired,
    #[error("rights receipt issuer does not match Runtime selection")]
    UnexpectedReceiptIssuer,
    #[error("rights receipt signature is invalid")]
    InvalidReceiptSignature,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[repr(u8)]
pub enum RightsActionV1 {
    View = 1,
    Stream = 2,
    Download = 3,
    Execute = 4,
}

/// Lowercase hex, written here rather than taken from a crate.
///
/// `hex` is a dev-dependency of this crate, and this is the shared contract
/// every custody node links, so four lines of encoding are cheaper than
/// widening its shipped dependency surface.
fn hex_lower(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[usize::from(byte >> 4)] as char);
        out.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    out
}

/// The readable layout a V1 rights request is signed in: three facts a
/// person can check, then the canonical hash of the whole request. V2 signs
/// its own consent text (`consent_text_v2`).
fn readable_signing_message(
    action: RightsActionV1,
    wallet: WalletAddress,
    expires_at: u64,
    request_hash: Digest32,
) -> String {
    format!(
        "ElastOS\n\nOpen protected content.\n\nAction:  {action}\nAccount: 0x{account}\nExpires: {expires} (unix seconds)\nRequest: 0x{request}\n",
        action = action.label(),
        account = hex_lower(wallet.as_bytes()),
        expires = expires_at,
        request = hex_lower(request_hash.as_bytes()),
    )
}

/// The first `CONSENT_FINGERPRINT_BYTES` of a key or digest, as lowercase hex.
fn fingerprint(bytes: &[u8]) -> String {
    hex_lower(bytes.get(..CONSENT_FINGERPRINT_BYTES).unwrap_or(bytes))
}

/// The text a wallet signs for a V2 request (ADV-01 §3). Each line ends with
/// `\n`. The direct form shows the recipient as `Device:`, as P5 does. The
/// pool form shows the per-open delivery key as `Delivery key:` and one
/// `Server:` line per recipient, in canonical order. Every value is a
/// number, an enum label or a hash, so no value can carry a newline.
fn consent_text_v2(request: &RightsRequestV2) -> Result<String, ContractError> {
    let envelope = request.binding.key_envelope();
    let threshold = envelope.threshold();
    let mut text = format!(
        "ElastOS {version} chain {chain}\n\nOpen protected content.\n\nAction:  {action}\nAccount: 0x{account}\n",
        version = RIGHTS_REQUEST_V2_VERSION,
        chain = request.chain_id,
        action = request.action.label(),
        account = hex_lower(request.binding.wallet().as_bytes()),
    );
    match request.delivery_key {
        None => text.push_str(&format!(
            "Device:  0x{}\n",
            fingerprint(request.recipients[0].key_id().as_bytes())
        )),
        Some(delivery_key) => text.push_str(&format!(
            "Delivery key: 0x{}\n",
            fingerprint(delivery_key.digest().as_bytes())
        )),
    }
    text.push_str(&format!(
        "Profile: 0x{profile}\nPool:    0x{pool} ({required} of {total})\n",
        profile = fingerprint(request.binding.profile().public_key_bytes()),
        pool = fingerprint(envelope.custody_pool().pool_sha256().as_bytes()),
        required = threshold.required(),
        total = threshold.total(),
    ));
    if request.delivery_key.is_some() {
        for recipient in &request.recipients {
            text.push_str(&format!(
                "Server:  0x{}\n",
                fingerprint(recipient.key_id().as_bytes())
            ));
        }
    }
    text.push_str(&format!(
        "Expires: {expires} (unix seconds)\nRequest: 0x{request}\n",
        expires = request.expires_at,
        request = hex_lower(request.request_hash()?.as_bytes()),
    ));
    Ok(text)
}

impl RightsActionV1 {
    /// The word a person reads in the signature prompt. Stable wire text, not
    /// a display string: it is inside what the wallet signs, so changing it
    /// changes the signature.
    pub const fn label(self) -> &'static str {
        match self {
            Self::View => "View",
            Self::Stream => "Stream",
            Self::Download => "Download",
            Self::Execute => "Execute",
        }
    }

    pub(crate) fn decode(value: u8) -> Result<Self, ContractError> {
        match value {
            1 => Ok(Self::View),
            2 => Ok(Self::Stream),
            3 => Ok(Self::Download),
            4 => Ok(Self::Execute),
            _ => Err(ContractError::InvalidField("rights_action")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[repr(u8)]
pub enum RightsDecisionV1 {
    Denied = 0,
    Allowed = 1,
}

impl RightsDecisionV1 {
    pub(crate) fn decode(value: u8) -> Result<Self, ContractError> {
        match value {
            0 => Ok(Self::Denied),
            1 => Ok(Self::Allowed),
            _ => Err(ContractError::InvalidField("rights_decision")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct ReplayNonce16([u8; 16]);

impl ReplayNonce16 {
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct RightsAuthorityScopeV1 {
    binding: ProtectedContentBindingV1,
    action: RightsActionV1,
    recipient: RecipientKeyIdentityV1,
}

impl CanonicalBody for RightsAuthorityScopeV1 {
    const DOMAIN: &'static str = "elastos.protected-content.rights-authority-scope/v1";

    fn validate(&self) -> Result<(), ContractError> {
        self.binding.canonical_bytes()?;
        self.recipient.canonical_bytes().map(|_| ())
    }

    fn encode_fields(&self, encoder: &mut Encoder) -> Result<(), ContractError> {
        encoder.nested(&self.binding)?;
        encoder.u8(self.action as u8);
        encoder.nested(&self.recipient)?;
        Ok(())
    }

    fn decode_fields(decoder: &mut Decoder<'_>) -> Result<Self, ContractError> {
        Ok(Self {
            binding: decoder.nested("binding")?,
            action: RightsActionV1::decode(decoder.u8()?)?,
            recipient: decoder.nested("recipient")?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RightsRequestV1 {
    binding: ProtectedContentBindingV1,
    action: RightsActionV1,
    recipient: RecipientKeyIdentityV1,
    issued_at: u64,
    expires_at: u64,
    replay_nonce: ReplayNonce16,
}

impl RightsRequestV1 {
    pub fn new(
        binding: ProtectedContentBindingV1,
        action: RightsActionV1,
        recipient: RecipientKeyIdentityV1,
        issued_at: u64,
        expires_at: u64,
        replay_nonce: ReplayNonce16,
    ) -> Result<Self, ContractError> {
        let value = Self {
            binding,
            action,
            recipient,
            issued_at,
            expires_at,
            replay_nonce,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn binding(&self) -> &ProtectedContentBindingV1 {
        &self.binding
    }

    pub const fn action(&self) -> RightsActionV1 {
        self.action
    }

    pub fn recipient(&self) -> &RecipientKeyIdentityV1 {
        &self.recipient
    }

    pub const fn issued_at(&self) -> u64 {
        self.issued_at
    }

    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }

    pub const fn replay_nonce(&self) -> ReplayNonce16 {
        self.replay_nonce
    }

    pub fn request_hash(&self) -> Result<Digest32, ContractError> {
        self.canonical_hash()
    }

    /// The exact text a wallet is asked to sign for this request.
    ///
    /// The request used to be signed as its own canonical bytes. Those bytes
    /// are a nested identity graph -- roughly a dozen SHA-256 digests with
    /// their schema names and length prefixes -- and a wallet shown them
    /// renders them as two kilobytes of replacement characters. The signature
    /// was sound; the prompt was not something a person could read, so
    /// approving it was an act of trust rather than a decision.
    ///
    /// This message states the three facts a person can actually check and
    /// commits to everything else through `Request`, which is the canonical
    /// hash of the whole request. The three readable facts are themselves
    /// inside that hash, so none of them can be altered without changing the
    /// line below them.
    ///
    /// Every field here is an enum, a number or a hash. No caller-supplied
    /// text reaches this message, so no value can carry a newline and forge a
    /// line -- the injection risk that plain-text signing otherwise invites
    /// does not exist while that stays true. Adding a free-form field later
    /// means refusing control characters at the point the field enters the
    /// request, not escaping them here.
    pub fn signing_message(&self) -> Result<String, ContractError> {
        Ok(readable_signing_message(
            self.action,
            self.binding.wallet(),
            self.expires_at,
            self.request_hash()?,
        ))
    }

    /// The digest a wallet produces for this request, and the one every
    /// verifier recovers against.
    ///
    /// Producer and verifiers all reach the signature through here, so there
    /// is no second definition of what is signed for them to drift apart on.
    pub fn signing_hash(&self) -> Result<[u8; 32], ContractError> {
        Ok(ethereum_signed_message_hash(
            self.signing_message()?.as_bytes(),
        ))
    }

    pub fn replay_claim_key(&self) -> Result<ReplayClaimKeyV1, ContractError> {
        let scope = RightsAuthorityScopeV1 {
            binding: self.binding.clone(),
            action: self.action,
            recipient: self.recipient.clone(),
        };
        Ok(ReplayClaimKeyV1::new(
            scope.canonical_hash()?,
            self.replay_nonce,
        ))
    }
}

impl CanonicalBody for RightsRequestV1 {
    const DOMAIN: &'static str = "elastos.protected-content.rights-request/v1";

    fn validate(&self) -> Result<(), ContractError> {
        self.binding.canonical_bytes()?;
        self.recipient.canonical_bytes()?;
        validate_time_window(
            self.issued_at,
            self.expires_at,
            MAX_RIGHTS_REQUEST_LIFETIME_SECS,
            "rights_request_lifetime",
        )
    }

    fn encode_fields(&self, encoder: &mut Encoder) -> Result<(), ContractError> {
        encoder.nested(&self.binding)?;
        encoder.u8(self.action as u8);
        encoder.nested(&self.recipient)?;
        encoder.u64(self.issued_at);
        encoder.u64(self.expires_at);
        encoder.fixed(self.replay_nonce.as_bytes());
        Ok(())
    }

    fn decode_fields(decoder: &mut Decoder<'_>) -> Result<Self, ContractError> {
        let binding = decoder.nested("binding")?;
        let action = RightsActionV1::decode(decoder.u8()?)?;
        Self::new(
            binding,
            action,
            decoder.nested("recipient")?,
            decoder.u64()?,
            decoder.u64()?,
            ReplayNonce16::new(decoder.fixed()?),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WalletSignedRightsRequestV1 {
    request: RightsRequestV1,
    wallet_signature: Vec<u8>,
}

impl WalletSignedRightsRequestV1 {
    pub fn new(request: RightsRequestV1, wallet_signature: Vec<u8>) -> Result<Self, ContractError> {
        let value = Self {
            request,
            wallet_signature,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn request(&self) -> &RightsRequestV1 {
        &self.request
    }

    pub fn wallet_signature(&self) -> &[u8] {
        &self.wallet_signature
    }

    pub fn verify(
        &self,
        context: &RightsVerificationContextV1,
        replay: &mut impl AtomicReplayClaimer,
    ) -> Result<VerifiedRightsRequestV1, RightsError> {
        let verified = self.verify_unclaimed(context)?;
        replay.claim(
            self.request.replay_claim_key()?,
            self.request.expires_at,
            context.now,
        )?;
        Ok(verified)
    }

    pub(crate) fn verify_unclaimed(
        &self,
        context: &RightsVerificationContextV1,
    ) -> Result<VerifiedRightsRequestV1, RightsError> {
        self.canonical_bytes()?;
        let request = &self.request;
        if request.binding != context.expected_binding {
            return Err(RightsError::BindingMismatch("protected_content_binding"));
        }
        if request.action != context.expected_action {
            return Err(RightsError::BindingMismatch("rights_action"));
        }
        if request.recipient != context.expected_recipient {
            return Err(RightsError::BindingMismatch("recipient_key_identity"));
        }
        validate_active(request.issued_at, request.expires_at, context.now)?;

        let recovered = recover_wallet(&request.signing_hash()?, &self.wallet_signature)?;
        if recovered != request.binding.wallet() {
            return Err(RightsError::WalletMismatch);
        }

        Ok(VerifiedRightsRequestV1 {
            request_hash: request.request_hash()?,
            binding: request.binding.clone(),
            action: request.action,
            recipient: request.recipient.clone(),
            issued_at: request.issued_at,
            expires_at: request.expires_at,
        })
    }
}

impl CanonicalBody for WalletSignedRightsRequestV1 {
    const DOMAIN: &'static str = "elastos.protected-content.wallet-signed-rights-request/v1";

    fn validate(&self) -> Result<(), ContractError> {
        self.request.canonical_bytes()?;
        if self.wallet_signature.len() != WALLET_SIGNATURE_BYTES
            || !matches!(self.wallet_signature[64], 0 | 1)
        {
            return Err(ContractError::InvalidField("wallet_signature"));
        }
        Ok(())
    }

    fn encode_fields(&self, encoder: &mut Encoder) -> Result<(), ContractError> {
        encoder.nested(&self.request)?;
        encoder.bytes(&self.wallet_signature)
    }

    fn decode_fields(decoder: &mut Decoder<'_>) -> Result<Self, ContractError> {
        Self::new(
            decoder.nested("request")?,
            decoder.bytes("wallet_signature", WALLET_SIGNATURE_BYTES)?,
        )
    }
}

#[derive(Debug, Clone)]
pub struct RightsVerificationContextV1 {
    expected_binding: ProtectedContentBindingV1,
    expected_action: RightsActionV1,
    expected_recipient: RecipientKeyIdentityV1,
    now: u64,
}

impl RightsVerificationContextV1 {
    pub fn new(
        expected_binding: ProtectedContentBindingV1,
        expected_action: RightsActionV1,
        expected_recipient: RecipientKeyIdentityV1,
        now: u64,
    ) -> Self {
        Self {
            expected_binding,
            expected_action,
            expected_recipient,
            now,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRightsRequestV1 {
    request_hash: Digest32,
    binding: ProtectedContentBindingV1,
    action: RightsActionV1,
    recipient: RecipientKeyIdentityV1,
    issued_at: u64,
    expires_at: u64,
}

impl VerifiedRightsRequestV1 {
    pub const fn request_hash(&self) -> Digest32 {
        self.request_hash
    }

    pub fn binding(&self) -> &ProtectedContentBindingV1 {
        &self.binding
    }

    pub const fn action(&self) -> RightsActionV1 {
        self.action
    }

    pub fn recipient(&self) -> &RecipientKeyIdentityV1 {
        &self.recipient
    }

    pub const fn issued_at(&self) -> u64 {
        self.issued_at
    }

    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }
}

pub(crate) fn validate_time_window(
    issued_at: u64,
    expires_at: u64,
    maximum_lifetime: u64,
    field: &'static str,
) -> Result<(), ContractError> {
    if issued_at == 0 || expires_at <= issued_at || expires_at - issued_at > maximum_lifetime {
        return Err(ContractError::InvalidField(field));
    }
    Ok(())
}

pub(crate) fn validate_active(
    issued_at: u64,
    expires_at: u64,
    now: u64,
) -> Result<(), RightsError> {
    if now.saturating_add(RIGHTS_CLOCK_SKEW_SECS) < issued_at {
        return Err(RightsError::NotYetValid);
    }
    if now >= expires_at {
        return Err(RightsError::Expired);
    }
    Ok(())
}

/// Recovers the wallet that produced `signature_bytes` over `signing_hash`.
///
/// Takes the prehash rather than a message, so the one definition of what is
/// signed lives in `RightsRequestV1::signing_message` and this function cannot
/// hash something else by accident.
fn recover_wallet(
    signing_hash: &[u8; 32],
    signature_bytes: &[u8],
) -> Result<WalletAddress, RightsError> {
    if signature_bytes.len() != WALLET_SIGNATURE_BYTES {
        return Err(RightsError::InvalidWalletSignature);
    }
    let signature = Signature::from_slice(&signature_bytes[..64])
        .map_err(|_| RightsError::InvalidWalletSignature)?;
    if signature.normalize_s().is_some() {
        return Err(RightsError::InvalidWalletSignature);
    }
    let recovery_id =
        RecoveryId::from_byte(signature_bytes[64]).ok_or(RightsError::InvalidWalletSignature)?;
    let verifying_key = VerifyingKey::recover_from_prehash(signing_hash, &signature, recovery_id)
        .map_err(|_| RightsError::InvalidWalletSignature)?;
    let encoded = verifying_key.to_encoded_point(false);
    let public_key = encoded.as_bytes();
    if public_key.len() != 65 || public_key[0] != 4 {
        return Err(RightsError::InvalidWalletSignature);
    }
    let digest = Keccak256::digest(&public_key[1..]);
    Ok(WalletAddress::new(
        digest[12..]
            .try_into()
            .map_err(|_| RightsError::InvalidWalletSignature)?,
    ))
}

/// Recipients of a V2 request: 1..=[`MAX_SESSION_RECIPIENTS_V2`], unique, in
/// canonical-byte order (E2; `RecipientKeyIdentityV1` has no `Ord`).
pub(crate) fn validate_recipient_set(
    recipients: &[RecipientKeyIdentityV1],
    field: &'static str,
) -> Result<(), ContractError> {
    if recipients.is_empty() || recipients.len() > MAX_SESSION_RECIPIENTS_V2 {
        return Err(ContractError::InvalidField(field));
    }
    let mut previous: Option<Vec<u8>> = None;
    for recipient in recipients {
        let bytes = recipient.canonical_bytes()?;
        if previous.as_ref().is_some_and(|previous| *previous >= bytes) {
            return Err(ContractError::InvalidField(field));
        }
        previous = Some(bytes);
    }
    Ok(())
}

/// Puts recipients in canonical-byte order.
pub(crate) fn sort_by_canonical_bytes<T>(
    values: Vec<T>,
    key: impl Fn(&T) -> Result<Vec<u8>, ContractError>,
) -> Result<Vec<T>, ContractError> {
    let mut keyed = values
        .into_iter()
        .map(|value| Ok((key(&value)?, value)))
        .collect::<Result<Vec<_>, ContractError>>()?;
    keyed.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(keyed.into_iter().map(|(_, value)| value).collect())
}

/// The replay scope of a V2 request: `binding · action · n · recipient×n ·
/// tag · [delivery]`. It has no separate chain id: the chain is bound
/// through `binding.rights_policy`, whose identity hashes the policy body
/// and its chain (ADV-01 §3, AD01-F7).
#[derive(Debug, Clone, PartialEq, Eq)]
struct RightsAuthorityScopeV2 {
    binding: ProtectedContentBindingV1,
    action: RightsActionV1,
    recipients: Vec<RecipientKeyIdentityV1>,
    delivery_key: Option<DeliveryKeyIdentityV1>,
}

impl CanonicalBody for RightsAuthorityScopeV2 {
    const DOMAIN: &'static str = "elastos.protected-content.rights-authority-scope/v2";

    fn validate(&self) -> Result<(), ContractError> {
        self.binding.canonical_bytes()?;
        validate_recipient_set(&self.recipients, "rights_request.recipients")
    }

    fn encode_fields(&self, encoder: &mut Encoder) -> Result<(), ContractError> {
        encoder.nested(&self.binding)?;
        encoder.u8(self.action as u8);
        encode_recipients(encoder, &self.recipients)?;
        encode_delivery_key(encoder, self.delivery_key);
        Ok(())
    }

    fn decode_fields(decoder: &mut Decoder<'_>) -> Result<Self, ContractError> {
        Ok(Self {
            binding: decoder.nested("binding")?,
            action: RightsActionV1::decode(decoder.u8()?)?,
            recipients: decode_recipients(decoder)?,
            delivery_key: decode_delivery_key(decoder)?,
        })
    }
}

/// The form tag, then the delivery key in the pool form.
fn encode_delivery_key(encoder: &mut Encoder, delivery_key: Option<DeliveryKeyIdentityV1>) {
    match delivery_key {
        None => encoder.u8(RIGHTS_V2_DIRECT_FORM),
        Some(delivery_key) => {
            encoder.u8(RIGHTS_V2_POOL_FORM);
            encoder.fixed(delivery_key.digest().as_bytes());
        }
    }
}

fn decode_delivery_key(
    decoder: &mut Decoder<'_>,
) -> Result<Option<DeliveryKeyIdentityV1>, ContractError> {
    match decoder.u8()? {
        RIGHTS_V2_DIRECT_FORM => Ok(None),
        RIGHTS_V2_POOL_FORM => Ok(Some(DeliveryKeyIdentityV1::new(Digest32::new(
            decoder.fixed()?,
        )))),
        _ => Err(ContractError::InvalidField("rights_request.delivery_key")),
    }
}

fn encode_recipients(
    encoder: &mut Encoder,
    recipients: &[RecipientKeyIdentityV1],
) -> Result<(), ContractError> {
    encoder.u8(u8::try_from(recipients.len())
        .map_err(|_| ContractError::InvalidField("rights_request.recipients"))?);
    for recipient in recipients {
        encoder.nested(recipient)?;
    }
    Ok(())
}

fn decode_recipients(
    decoder: &mut Decoder<'_>,
) -> Result<Vec<RecipientKeyIdentityV1>, ContractError> {
    let count = usize::from(decoder.u8()?);
    if count == 0 || count > MAX_SESSION_RECIPIENTS_V2 {
        return Err(ContractError::InvalidField("rights_request.recipients"));
    }
    let mut recipients = Vec::with_capacity(count);
    for _ in 0..count {
        recipients.push(decoder.nested("recipient")?);
    }
    Ok(recipients)
}

/// A `rights-request/v2` (ADV-01). One layout carries two forms:
/// - the direct form (tag 0): one recipient, no delivery key;
/// - the pool form (tag 1): 1..=4 session recipients (one per pool server)
///   and the buyer's per-open delivery key.
///
/// `chain_id` is never 0 and is encoded last. The wallet signs the v2
/// consent text (`signing_message`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RightsRequestV2 {
    binding: ProtectedContentBindingV1,
    action: RightsActionV1,
    recipients: Vec<RecipientKeyIdentityV1>,
    delivery_key: Option<DeliveryKeyIdentityV1>,
    issued_at: u64,
    expires_at: u64,
    replay_nonce: ReplayNonce16,
    chain_id: u64,
}

impl RightsRequestV2 {
    /// The pool form. Recipients are kept in canonical-byte order;
    /// duplicates are refused.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        binding: ProtectedContentBindingV1,
        action: RightsActionV1,
        recipients: Vec<RecipientKeyIdentityV1>,
        delivery_key: DeliveryKeyIdentityV1,
        issued_at: u64,
        expires_at: u64,
        replay_nonce: ReplayNonce16,
        chain_id: u64,
    ) -> Result<Self, ContractError> {
        Self::from_parts(
            binding,
            action,
            recipients,
            Some(delivery_key),
            issued_at,
            expires_at,
            replay_nonce,
            chain_id,
        )
    }

    /// The direct form: one recipient and no delivery key.
    pub fn new_direct(
        binding: ProtectedContentBindingV1,
        action: RightsActionV1,
        recipient: RecipientKeyIdentityV1,
        issued_at: u64,
        expires_at: u64,
        replay_nonce: ReplayNonce16,
        chain_id: u64,
    ) -> Result<Self, ContractError> {
        Self::from_parts(
            binding,
            action,
            vec![recipient],
            None,
            issued_at,
            expires_at,
            replay_nonce,
            chain_id,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn from_parts(
        binding: ProtectedContentBindingV1,
        action: RightsActionV1,
        recipients: Vec<RecipientKeyIdentityV1>,
        delivery_key: Option<DeliveryKeyIdentityV1>,
        issued_at: u64,
        expires_at: u64,
        replay_nonce: ReplayNonce16,
        chain_id: u64,
    ) -> Result<Self, ContractError> {
        let value = Self {
            binding,
            action,
            recipients: sort_by_canonical_bytes(recipients, |recipient| {
                recipient.canonical_bytes()
            })?,
            delivery_key,
            issued_at,
            expires_at,
            replay_nonce,
            chain_id,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn binding(&self) -> &ProtectedContentBindingV1 {
        &self.binding
    }

    pub const fn action(&self) -> RightsActionV1 {
        self.action
    }

    pub fn recipients(&self) -> &[RecipientKeyIdentityV1] {
        &self.recipients
    }

    /// The delivery key the wallet signed; `None` in the direct form.
    pub const fn delivery_key(&self) -> Option<DeliveryKeyIdentityV1> {
        self.delivery_key
    }

    pub const fn issued_at(&self) -> u64 {
        self.issued_at
    }

    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }

    pub const fn replay_nonce(&self) -> ReplayNonce16 {
        self.replay_nonce
    }

    pub const fn chain_id(&self) -> u64 {
        self.chain_id
    }

    pub fn request_hash(&self) -> Result<Digest32, ContractError> {
        self.canonical_hash()
    }

    /// The v2 consent text (`consent_text_v2`). Its `Request` line is the
    /// hash of the whole request.
    pub fn signing_message(&self) -> Result<String, ContractError> {
        consent_text_v2(self)
    }

    pub fn signing_hash(&self) -> Result<[u8; 32], ContractError> {
        Ok(ethereum_signed_message_hash(
            self.signing_message()?.as_bytes(),
        ))
    }

    /// Keyed by binding, action, recipients, the form tag and the delivery
    /// key, with the nonce (L4).
    pub fn replay_claim_key(&self) -> Result<ReplayClaimKeyV1, ContractError> {
        let scope = RightsAuthorityScopeV2 {
            binding: self.binding.clone(),
            action: self.action,
            recipients: self.recipients.clone(),
            delivery_key: self.delivery_key,
        };
        Ok(ReplayClaimKeyV1::new(
            scope.canonical_hash()?,
            self.replay_nonce,
        ))
    }
}

impl CanonicalBody for RightsRequestV2 {
    const DOMAIN: &'static str = "elastos.protected-content.rights-request/v2";

    fn validate(&self) -> Result<(), ContractError> {
        self.binding.canonical_bytes()?;
        validate_recipient_set(&self.recipients, "rights_request.recipients")?;
        // The direct form names exactly one recipient.
        if self.delivery_key.is_none() && self.recipients.len() != 1 {
            return Err(ContractError::InvalidField("rights_request.recipients"));
        }
        if self.chain_id == 0 {
            return Err(ContractError::InvalidField("rights_request.chain_id"));
        }
        validate_time_window(
            self.issued_at,
            self.expires_at,
            MAX_RIGHTS_REQUEST_LIFETIME_SECS,
            "rights_request_lifetime",
        )
    }

    fn encode_fields(&self, encoder: &mut Encoder) -> Result<(), ContractError> {
        encoder.nested(&self.binding)?;
        encoder.u8(self.action as u8);
        encode_recipients(encoder, &self.recipients)?;
        encode_delivery_key(encoder, self.delivery_key);
        encoder.u64(self.issued_at);
        encoder.u64(self.expires_at);
        encoder.fixed(self.replay_nonce.as_bytes());
        encoder.u64(self.chain_id);
        Ok(())
    }

    fn decode_fields(decoder: &mut Decoder<'_>) -> Result<Self, ContractError> {
        let binding = decoder.nested("binding")?;
        let action = RightsActionV1::decode(decoder.u8()?)?;
        let recipients = decode_recipients(decoder)?;
        if decoder.remaining() == PRE_ALIGNMENT_V2_TAIL_BYTES {
            return Err(ContractError::UnsupportedVersion(PRE_ALIGNMENT_V2));
        }
        let delivery_key = decode_delivery_key(decoder)?;
        Self::from_parts(
            binding,
            action,
            recipients,
            delivery_key,
            decoder.u64()?,
            decoder.u64()?,
            ReplayNonce16::new(decoder.fixed()?),
            decoder.u64()?,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletSignedRightsRequestV2 {
    request: RightsRequestV2,
    wallet_signature: Vec<u8>,
}

impl WalletSignedRightsRequestV2 {
    pub fn new(request: RightsRequestV2, wallet_signature: Vec<u8>) -> Result<Self, ContractError> {
        let value = Self {
            request,
            wallet_signature,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn request(&self) -> &RightsRequestV2 {
        &self.request
    }

    pub fn wallet_signature(&self) -> &[u8] {
        &self.wallet_signature
    }

    /// The bound wallet signed this request and its window is open at `now`.
    /// Returns the request hash. It claims no replay: the operation exposes
    /// the claim key. The Wallet and the Runtime re-check a stored or
    /// returned V2 signature through here (T1.2).
    pub fn verify_unclaimed_at(&self, now: u64) -> Result<Digest32, RightsError> {
        self.canonical_bytes()?;
        validate_active(self.request.issued_at, self.request.expires_at, now)?;
        let recovered = recover_wallet(&self.request.signing_hash()?, &self.wallet_signature)?;
        if recovered != self.request.binding.wallet() {
            return Err(RightsError::WalletMismatch);
        }
        Ok(self.request.request_hash()?)
    }
}

impl CanonicalBody for WalletSignedRightsRequestV2 {
    const DOMAIN: &'static str = "elastos.protected-content.wallet-signed-rights-request/v2";

    fn validate(&self) -> Result<(), ContractError> {
        self.request.canonical_bytes()?;
        if self.wallet_signature.len() != WALLET_SIGNATURE_BYTES
            || !matches!(self.wallet_signature[64], 0 | 1)
        {
            return Err(ContractError::InvalidField("wallet_signature"));
        }
        Ok(())
    }

    fn encode_fields(&self, encoder: &mut Encoder) -> Result<(), ContractError> {
        encoder.nested(&self.request)?;
        encoder.bytes(&self.wallet_signature)
    }

    fn decode_fields(decoder: &mut Decoder<'_>) -> Result<Self, ContractError> {
        Self::new(
            decoder.nested("request")?,
            decoder.bytes("wallet_signature", WALLET_SIGNATURE_BYTES)?,
        )
    }
}

/// A V1 or V2 rights request, picked by its canonical domain.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(
    clippy::large_enum_variant,
    reason = "the V1 and V2 values are the planned by-value variants; callers match on them"
)]
pub enum RightsRequestAnyV1 {
    V1(RightsRequestV1),
    V2(RightsRequestV2),
}

impl RightsRequestAnyV1 {
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ContractError> {
        match RightsRequestV1::from_canonical_bytes(bytes) {
            Err(ContractError::WrongDomain) => {
                RightsRequestV2::from_canonical_bytes(bytes).map(Self::V2)
            }
            other => other.map(Self::V1),
        }
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ContractError> {
        match self {
            Self::V1(request) => request.canonical_bytes(),
            Self::V2(request) => request.canonical_bytes(),
        }
    }

    pub fn signing_message(&self) -> Result<String, ContractError> {
        match self {
            Self::V1(request) => request.signing_message(),
            Self::V2(request) => request.signing_message(),
        }
    }

    pub fn signing_hash(&self) -> Result<[u8; 32], ContractError> {
        match self {
            Self::V1(request) => request.signing_hash(),
            Self::V2(request) => request.signing_hash(),
        }
    }

    pub fn request_hash(&self) -> Result<Digest32, ContractError> {
        match self {
            Self::V1(request) => request.request_hash(),
            Self::V2(request) => request.request_hash(),
        }
    }

    pub fn binding(&self) -> &ProtectedContentBindingV1 {
        match self {
            Self::V1(request) => request.binding(),
            Self::V2(request) => request.binding(),
        }
    }

    pub const fn action(&self) -> RightsActionV1 {
        match self {
            Self::V1(request) => request.action(),
            Self::V2(request) => request.action(),
        }
    }

    pub const fn issued_at(&self) -> u64 {
        match self {
            Self::V1(request) => request.issued_at(),
            Self::V2(request) => request.issued_at(),
        }
    }

    pub const fn expires_at(&self) -> u64 {
        match self {
            Self::V1(request) => request.expires_at(),
            Self::V2(request) => request.expires_at(),
        }
    }
}

/// A wallet-signed V1 or V2 rights request, picked by its canonical domain
/// (L16).
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(
    clippy::large_enum_variant,
    reason = "the V1 and V2 values are the planned by-value variants; callers match on them"
)]
pub enum WalletSignedRightsRequestAnyV1 {
    V1(WalletSignedRightsRequestV1),
    V2(WalletSignedRightsRequestV2),
}

impl WalletSignedRightsRequestAnyV1 {
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ContractError> {
        match WalletSignedRightsRequestV1::from_canonical_bytes(bytes) {
            Err(ContractError::WrongDomain) => {
                WalletSignedRightsRequestV2::from_canonical_bytes(bytes).map(Self::V2)
            }
            other => other.map(Self::V1),
        }
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ContractError> {
        match self {
            Self::V1(request) => request.canonical_bytes(),
            Self::V2(request) => request.canonical_bytes(),
        }
    }

    pub fn wallet_signature(&self) -> &[u8] {
        match self {
            Self::V1(request) => request.wallet_signature(),
            Self::V2(request) => request.wallet_signature(),
        }
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer as _, SigningKey as ReceiptSigningKey};
    use k256::ecdsa::SigningKey;

    use super::*;
    use crate::test_support::{binding_for_wallet, digest, wallet, TestReplayClaims, NOW};
    use crate::{RightsReceiptIssuerKey, RightsReceiptStatementV1, SignedRightsReceiptV1};

    fn wallet_key(seed: u8) -> SigningKey {
        SigningKey::from_slice(&[seed; 32]).unwrap()
    }

    fn request(seed: u8, expires_at: u64, nonce: u8) -> RightsRequestV1 {
        let wallet = wallet(seed);
        RightsRequestV1::new(
            binding_for_wallet(wallet),
            RightsActionV1::View,
            recipient(0xa0),
            NOW,
            expires_at,
            ReplayNonce16::new([nonce; 16]),
        )
        .unwrap()
    }

    fn signature(request: &RightsRequestV1, seed: u8) -> Vec<u8> {
        let (signature, recovery_id) = wallet_key(seed)
            .sign_prehash_recoverable(&request.signing_hash().unwrap())
            .unwrap();
        let mut bytes = signature.to_bytes().to_vec();
        bytes.push(recovery_id.to_byte());
        bytes
    }

    fn signed(seed: u8) -> WalletSignedRightsRequestV1 {
        let request = request(seed, NOW + 120, 0x55);
        WalletSignedRightsRequestV1::new(request.clone(), signature(&request, seed)).unwrap()
    }

    fn context(request: &RightsRequestV1, now: u64) -> RightsVerificationContextV1 {
        RightsVerificationContextV1::new(
            request.binding().clone(),
            request.action(),
            request.recipient().clone(),
            now,
        )
    }

    fn recipient(seed: u8) -> RecipientKeyIdentityV1 {
        RecipientKeyIdentityV1::new("x25519-hkdf-sha256-aes256gcm/v1", digest(seed)).unwrap()
    }

    #[test]
    fn wallet_provider_zero_one_signature_is_the_only_canonical_form() {
        let signed = signed(7);
        assert!(matches!(signed.wallet_signature()[64], 0 | 1));
        let decoded =
            WalletSignedRightsRequestV1::from_canonical_bytes(&signed.canonical_bytes().unwrap())
                .unwrap();
        let mut replay = TestReplayClaims::default();
        decoded
            .verify(&context(decoded.request(), NOW + 1), &mut replay)
            .unwrap();

        let mut noncanonical_signature = signed.wallet_signature().to_vec();
        noncanonical_signature[64] += 27;
        assert_eq!(
            WalletSignedRightsRequestV1::new(signed.request().clone(), noncanonical_signature),
            Err(ContractError::InvalidField("wallet_signature"))
        );
        let mut noncanonical_wire = signed.canonical_bytes().unwrap();
        *noncanonical_wire.last_mut().unwrap() += 27;
        assert_eq!(
            WalletSignedRightsRequestV1::from_canonical_bytes(&noncanonical_wire),
            Err(ContractError::InvalidField("wallet_signature"))
        );
    }

    #[test]
    fn replay_claim_is_required_and_nonce_keyed_across_field_mutation() {
        let first = signed(7);
        let changed = request(7, NOW + 180, 0x55);
        let changed =
            WalletSignedRightsRequestV1::new(changed.clone(), signature(&changed, 7)).unwrap();
        let mut replay = TestReplayClaims::default();
        first
            .verify(&context(first.request(), NOW + 1), &mut replay)
            .unwrap();
        assert_eq!(
            changed.verify(&context(changed.request(), NOW + 1), &mut replay),
            Err(RightsError::Replay(ReplayClaimError::AlreadyClaimed))
        );
    }

    #[test]
    fn post_signature_field_mutation_fails_closed() {
        let signed = signed(7);
        let changed_request = RightsRequestV1::new(
            signed.request().binding().clone(),
            RightsActionV1::Stream,
            signed.request().recipient().clone(),
            signed.request().issued_at(),
            signed.request().expires_at(),
            signed.request().replay_nonce(),
        )
        .unwrap();
        let changed = WalletSignedRightsRequestV1::new(
            changed_request.clone(),
            signed.wallet_signature().to_vec(),
        )
        .unwrap();
        let mut replay = TestReplayClaims::default();
        assert_eq!(
            changed.verify(&context(&changed_request, NOW + 1), &mut replay),
            Err(RightsError::WalletMismatch)
        );
        assert!(replay.is_empty());
    }

    #[test]
    fn attacker_cannot_sign_a_victim_wallet_that_owns_content() {
        let victim_request = request(9, NOW + 120, 0x66);
        let attacker_signed =
            WalletSignedRightsRequestV1::new(victim_request.clone(), signature(&victim_request, 7))
                .unwrap();
        let mut replay = TestReplayClaims::default();
        assert_eq!(
            attacker_signed.verify(&context(&victim_request, NOW + 1), &mut replay),
            Err(RightsError::WalletMismatch)
        );
        assert!(replay.is_empty());
    }

    #[test]
    fn recipient_is_wallet_signed_and_runtime_selected() {
        let signed = signed(7);
        let changed_request = RightsRequestV1::new(
            signed.request().binding().clone(),
            RightsActionV1::View,
            recipient(0xa1),
            signed.request().issued_at(),
            signed.request().expires_at(),
            signed.request().replay_nonce(),
        )
        .unwrap();
        let changed = WalletSignedRightsRequestV1::new(
            changed_request.clone(),
            signed.wallet_signature().to_vec(),
        )
        .unwrap();
        let mut replay = TestReplayClaims::default();
        assert_eq!(
            changed.verify(&context(&changed_request, NOW + 1), &mut replay),
            Err(RightsError::WalletMismatch)
        );
        assert!(replay.is_empty());

        let mut replay = TestReplayClaims::default();
        let wrong_runtime_recipient = RightsVerificationContextV1::new(
            signed.request().binding().clone(),
            signed.request().action(),
            recipient(0xa1),
            NOW + 1,
        );
        assert_eq!(
            signed.verify(&wrong_runtime_recipient, &mut replay),
            Err(RightsError::BindingMismatch("recipient_key_identity"))
        );
        assert!(replay.is_empty());
    }

    #[test]
    fn forged_allow_receipt_and_lifetime_escape_fail() {
        let signed = signed(7);
        let mut replay = TestReplayClaims::default();
        let verified = signed
            .verify(&context(signed.request(), NOW + 1), &mut replay)
            .unwrap();
        let issuer_key = ReceiptSigningKey::from_bytes(&[11; 32]);
        let issuer = RightsReceiptIssuerKey::new(issuer_key.verifying_key().to_bytes()).unwrap();
        let statement = RightsReceiptStatementV1::new(
            verified.request_hash(),
            verified.binding().clone(),
            verified.action(),
            issuer,
            RightsDecisionV1::Allowed,
            digest(0x90),
            NOW + 2,
            NOW + 60,
        )
        .unwrap();
        let forged = SignedRightsReceiptV1::new(statement.clone(), vec![0x44; 64]).unwrap();
        assert_eq!(
            forged.verify_audit(&verified, issuer, NOW + 3),
            Err(RightsError::InvalidReceiptSignature)
        );

        let valid = SignedRightsReceiptV1::new(
            statement.clone(),
            issuer_key
                .sign(&statement.canonical_bytes().unwrap())
                .to_bytes()
                .to_vec(),
        )
        .unwrap();
        valid.verify_audit(&verified, issuer, NOW + 3).unwrap();

        let beyond_parent = RightsReceiptStatementV1::new(
            verified.request_hash(),
            verified.binding().clone(),
            verified.action(),
            issuer,
            RightsDecisionV1::Allowed,
            digest(0x90),
            NOW + 2,
            verified.expires_at() + 1,
        )
        .unwrap();
        let beyond_parent = SignedRightsReceiptV1::new(
            beyond_parent.clone(),
            issuer_key
                .sign(&beyond_parent.canonical_bytes().unwrap())
                .to_bytes()
                .to_vec(),
        )
        .unwrap();
        assert_eq!(
            beyond_parent.verify_audit(&verified, issuer, NOW + 3),
            Err(RightsError::BindingMismatch("rights_receipt_window"))
        );
    }

    #[test]
    fn wrong_profile_binding_fails_before_replay_claim() {
        let signed = signed(7);
        let wrong_profile = ProtectedContentBindingV1::new(
            signed.request().binding().encrypted_content().clone(),
            signed.request().binding().key_envelope().clone(),
            signed.request().binding().rights_policy().clone(),
            crate::ProfileIdentityV1::from_public_key_bytes(
                ReceiptSigningKey::from_bytes(&[12; 32])
                    .verifying_key()
                    .to_bytes(),
            )
            .unwrap(),
            signed.request().binding().wallet(),
            signed.request().binding().runtime_session_binding(),
        )
        .unwrap();
        let mut replay = TestReplayClaims::default();
        let wrong_context = RightsVerificationContextV1::new(
            wrong_profile,
            signed.request().action(),
            signed.request().recipient().clone(),
            NOW + 1,
        );
        assert_eq!(
            signed.verify(&wrong_context, &mut replay),
            Err(RightsError::BindingMismatch("protected_content_binding"))
        );
        assert!(replay.is_empty());
    }

    #[test]
    fn wrong_policy_and_expiry_fail_before_replay_claim() {
        let signed = signed(7);
        let mut wrong = binding_for_wallet(wallet(7));
        // Rebuild through public constructors so the immutable policy digest is
        // the only changed authority field.
        wrong = ProtectedContentBindingV1::new(
            wrong.encrypted_content().clone(),
            wrong.key_envelope().clone(),
            crate::RightsPolicyIdentityV1::new(digest(0xee), 384).unwrap(),
            wrong.profile(),
            wrong.wallet(),
            wrong.runtime_session_binding(),
        )
        .unwrap();
        let mut replay = TestReplayClaims::default();
        let wrong_context = RightsVerificationContextV1::new(
            wrong,
            RightsActionV1::View,
            signed.request().recipient().clone(),
            NOW + 1,
        );
        assert_eq!(
            signed.verify(&wrong_context, &mut replay),
            Err(RightsError::BindingMismatch("protected_content_binding"))
        );
        assert!(replay.is_empty());

        let mut replay = TestReplayClaims::default();
        assert_eq!(
            signed.verify(&context(signed.request(), NOW + 120), &mut replay),
            Err(RightsError::Expired)
        );
        assert!(replay.is_empty());
    }
}
