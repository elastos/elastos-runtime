//! Signed custody messages that contacts' Homes exchange to find, request and
//! confirm custody nodes.
//!
//! Every message is a canonical collaboration envelope from service
//! `custody`, signed by an endpoint the sender Profile authorizes for that
//! exact payload type. A payload never names its issuer: the receiver derives
//! it from the verified signer DID, which must be the sender Profile's sole
//! endpoint. Contact, admin and pool-state rules belong to the callers.

use anyhow::Context as _;
use base64::Engine as _;
use elastos_common::collaboration_protocol::{
    canonical_collaboration_message_bytes, canonical_signed_collaboration_message_bytes,
    CollaborationMessage, CollaborationRecipient, CollaborationRecipientKind,
    SignedCollaborationMessage, COLLABORATION_MESSAGE_SCHEMA_V1,
    COLLABORATION_MESSAGE_SIGNATURE_DOMAIN_V1, MAX_COLLABORATION_CLOCK_SKEW_SECS,
    MAX_COLLABORATION_ENVELOPE_BYTES, MAX_COLLABORATION_MESSAGE_LIFETIME_SECS,
    MAX_COLLABORATION_PAYLOAD_BYTES,
};
use elastos_protected_content_contracts::{
    CanonicalContract, SignedCustodyEpochV1, SignedCustodyPoolV1, ThresholdV1,
};
use elastos_runtime::signature::SigningKey;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::collaboration_network::VerifiedCollaborationNetworkProfile;
use crate::collaboration_profile_authority::VerifiedCollaborationProfileDocument;
use crate::collaboration_protocol::{
    verify_stored_collaboration_message, VerifiedCollaborationMessage,
};
use crate::crypto::{domain_separated_sign, encode_signing_key_did};
use crate::custody_node_card::{parse_node_card, NODE_CARD_PROVIDES};
use crate::custody_pool_setup::POOL_TERM_DAYS;
use crate::protected_content_config::validated_custody_node_label;
use crate::protected_content_runtime::{
    RuntimeCustodyCompositionConfigFile, CUSTODY_COMPOSITION_SCHEMA_V1,
};

pub(crate) const CUSTODY_SERVICE: &str = crate::custody_surface::MESSAGE_SERVICE_CUSTODY;
/// Custody messages are addressed to a Profile; the conversation is fixed so
/// no free-form id rides along.
pub(crate) const CUSTODY_CONVERSATION_ID: &str = "elastos.custody";
pub(crate) const CUSTODY_OFFER_QUERY_PAYLOAD_TYPE: &str =
    crate::custody_surface::MESSAGE_OFFER_QUERY;
pub(crate) const CUSTODY_OFFER_PAYLOAD_TYPE: &str = crate::custody_surface::MESSAGE_OFFER;
pub(crate) const CUSTODY_NODE_REQUEST_PAYLOAD_TYPE: &str =
    crate::custody_surface::MESSAGE_NODE_REQUEST;
pub(crate) const CUSTODY_NODE_DECISION_PAYLOAD_TYPE: &str =
    crate::custody_surface::MESSAGE_NODE_DECISION;
pub(crate) const CUSTODY_POOL_ACTIVE_PAYLOAD_TYPE: &str =
    crate::custody_surface::MESSAGE_POOL_ACTIVE;
pub(crate) const CUSTODY_POOL_DESCRIPTOR_PAYLOAD_TYPE: &str =
    crate::custody_surface::MESSAGE_POOL_DESCRIPTOR;
/// The Profile signing scope custody messages need. It is not a default
/// scope: the admin enables it explicitly, and a rename carries it forward.
/// Object types stay sorted, as the Profile format requires.
pub(crate) const CUSTODY_SIGNING_SCOPE: (&str, &[&str]) = (
    CUSTODY_SERVICE,
    &[
        elastos_common::collaboration_protocol::COLLABORATION_ACCEPTANCE_RECEIPT_SCHEMA_V1,
        CUSTODY_NODE_DECISION_PAYLOAD_TYPE,
        CUSTODY_NODE_REQUEST_PAYLOAD_TYPE,
        CUSTODY_OFFER_QUERY_PAYLOAD_TYPE,
        CUSTODY_OFFER_PAYLOAD_TYPE,
        CUSTODY_POOL_ACTIVE_PAYLOAD_TYPE,
        CUSTODY_POOL_DESCRIPTOR_PAYLOAD_TYPE,
    ],
);
/// An offer is a live answer to a live query; neither outlives the Find list.
const CUSTODY_OFFER_TTL_SECS: u64 = 2 * 60;
/// A person answers a request in their Inbox, and decisions and pool notices
/// retry from the sync loop, so these get the full envelope lifetime.
const CUSTODY_CONSENT_TTL_SECS: u64 = MAX_COLLABORATION_MESSAGE_LIFETIME_SECS;
/// Decoded composition bytes a pool-active message may carry. Its base64
/// plus a full member list must still fit the 64 KiB payload.
pub(crate) const MAX_POOL_ACTIVE_CONFIG_BYTES: usize = 40 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CustodyMessageType {
    OfferQuery,
    Offer,
    NodeRequest,
    NodeDecision,
    PoolActive,
    /// Plan B T3.3: the owner's signed pool descriptor.
    PoolDescriptor,
}

impl CustodyMessageType {
    pub(crate) const ALL: [Self; 6] = [
        Self::OfferQuery,
        Self::Offer,
        Self::NodeRequest,
        Self::NodeDecision,
        Self::PoolActive,
        Self::PoolDescriptor,
    ];

    pub(crate) fn payload_type(self) -> &'static str {
        match self {
            Self::OfferQuery => CUSTODY_OFFER_QUERY_PAYLOAD_TYPE,
            Self::Offer => CUSTODY_OFFER_PAYLOAD_TYPE,
            Self::NodeRequest => CUSTODY_NODE_REQUEST_PAYLOAD_TYPE,
            Self::NodeDecision => CUSTODY_NODE_DECISION_PAYLOAD_TYPE,
            Self::PoolActive => CUSTODY_POOL_ACTIVE_PAYLOAD_TYPE,
            Self::PoolDescriptor => CUSTODY_POOL_DESCRIPTOR_PAYLOAD_TYPE,
        }
    }

    pub(crate) fn max_lifetime_secs(self) -> u64 {
        match self {
            Self::OfferQuery | Self::Offer => CUSTODY_OFFER_TTL_SECS,
            Self::NodeRequest | Self::NodeDecision | Self::PoolActive | Self::PoolDescriptor => {
                CUSTODY_CONSENT_TTL_SECS
            }
        }
    }

    fn from_payload_type(payload_type: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|kind| kind.payload_type() == payload_type)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CustodyOfferQueryPayload {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CustodyOfferPayload {
    // Fields stay alphabetical: the canonical-payload check compares the
    // struct's bytes with the JSON value's sorted keys.
    pub(crate) location: String,
    pub(crate) provides: Vec<String>,
    pub(crate) run_by: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CustodyNodeRequestPayload {
    pub(crate) request_id: String,
    pub(crate) signing_key_fingerprint_full: String,
    pub(crate) term_days: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CustodyNodeDecisionOutcome {
    Approved,
    Declined,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CustodyDeclineCode {
    NotOffering,
    AlreadyServing,
    NotAdmin,
    Declined,
    Expired,
    /// Plan B T2.2 (S2-U1): this Home serves the most pools it can (8). An
    /// owner on an older build cannot decode it; its request waits to expiry
    /// (known limit, lead 2026-11-11 17:55).
    TooManyPools,
}

impl CustodyDeclineCode {
    /// Every code, in wire order.
    #[cfg(test)]
    pub(crate) const ALL: [Self; 6] = [
        Self::NotOffering,
        Self::AlreadyServing,
        Self::NotAdmin,
        Self::Declined,
        Self::Expired,
        Self::TooManyPools,
    ];

    /// The wire value, as the custody surface declares it.
    pub(crate) const fn code(self) -> &'static str {
        use crate::custody_surface as surface;
        match self {
            Self::NotOffering => surface::DECLINE_NOT_OFFERING,
            Self::AlreadyServing => surface::DECLINE_ALREADY_SERVING,
            Self::NotAdmin => surface::DECLINE_NOT_ADMIN,
            Self::Declined => surface::DECLINE_DECLINED,
            Self::Expired => surface::DECLINE_EXPIRED,
            Self::TooManyPools => surface::DECLINE_TOO_MANY_POOLS,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CustodyNodeDecisionPayload {
    /// The node card text; present exactly when approved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) card: Option<String>,
    /// Why the node declined; present exactly when declined.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) code: Option<CustodyDeclineCode>,
    pub(crate) outcome: CustodyNodeDecisionOutcome,
    pub(crate) request_id: String,
    pub(crate) request_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CustodyPoolThreshold {
    pub(crate) required: u8,
    pub(crate) total: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CustodyPoolMember {
    pub(crate) location: String,
    pub(crate) run_by: String,
    pub(crate) share: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CustodyPoolActivePayload {
    /// Standard base64 of the exact signed composition file bytes.
    pub(crate) config: String,
    pub(crate) fingerprint_full: String,
    /// Every member, ordered by share.
    pub(crate) members: Vec<CustodyPoolMember>,
    /// The signed pool's start, the latest member `valid_from`. It orders
    /// notices, and it is read from the composition so it cannot be set apart
    /// from it.
    pub(crate) pool_start: u64,
    /// The recipient's share.
    pub(crate) share: u8,
    /// The signed pool's end, the earliest member `valid_until`.
    pub(crate) term_end: u64,
    pub(crate) threshold: CustodyPoolThreshold,
}

/// Plan B T3.3: the owner's signed pool descriptor, public by design.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CustodyPoolDescriptorPayload {
    /// Standard base64 of the signed descriptor's canonical bytes.
    pub(crate) descriptor: String,
}

impl CustodyPoolDescriptorPayload {
    /// The owner sends the v3 descriptor it signed (item 10, #388 A2).
    pub(crate) fn new(
        descriptor: &elastos_protected_content_contracts::SignedPoolDescriptorV3,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            descriptor: base64::engine::general_purpose::STANDARD
                .encode(descriptor.canonical_bytes()?),
        })
    }

    /// The descriptor in either version, decoded by its domain (item 10),
    /// within its byte cap (L9). Its signatures and windows are checked where
    /// it is used.
    pub(crate) fn signed_descriptor(
        &self,
    ) -> Result<elastos_protected_content_contracts::SignedPoolDescriptorAnyV1, CustodyMessageRefusal>
    {
        let max = elastos_protected_content_contracts::MAX_SIGNED_POOL_DESCRIPTOR_BYTES_V1;
        if self.descriptor.len() > max.div_ceil(3) * 4 {
            return Err(CustodyMessageRefusal::InvalidPayload);
        }
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&self.descriptor)
            .map_err(|_| CustodyMessageRefusal::InvalidPayload)?;
        if bytes.is_empty() || bytes.len() > max {
            return Err(CustodyMessageRefusal::InvalidPayload);
        }
        elastos_protected_content_contracts::SignedPoolDescriptorAnyV1::from_canonical_bytes(&bytes)
            .map_err(|_| CustodyMessageRefusal::InvalidPayload)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CustodyPayload {
    OfferQuery(CustodyOfferQueryPayload),
    Offer(CustodyOfferPayload),
    NodeRequest(CustodyNodeRequestPayload),
    NodeDecision(CustodyNodeDecisionPayload),
    PoolActive(CustodyPoolActivePayload),
    PoolDescriptor(CustodyPoolDescriptorPayload),
}

impl CustodyPayload {
    pub(crate) fn message_type(&self) -> CustodyMessageType {
        match self {
            Self::OfferQuery(_) => CustodyMessageType::OfferQuery,
            Self::Offer(_) => CustodyMessageType::Offer,
            Self::NodeRequest(_) => CustodyMessageType::NodeRequest,
            Self::NodeDecision(_) => CustodyMessageType::NodeDecision,
            Self::PoolActive(_) => CustodyMessageType::PoolActive,
            Self::PoolDescriptor(_) => CustodyMessageType::PoolDescriptor,
        }
    }

    fn to_value(&self) -> serde_json::Result<serde_json::Value> {
        match self {
            Self::OfferQuery(payload) => serde_json::to_value(payload),
            Self::Offer(payload) => serde_json::to_value(payload),
            Self::NodeRequest(payload) => serde_json::to_value(payload),
            Self::NodeDecision(payload) => serde_json::to_value(payload),
            Self::PoolActive(payload) => serde_json::to_value(payload),
            Self::PoolDescriptor(payload) => serde_json::to_value(payload),
        }
    }

    fn decode(
        kind: CustodyMessageType,
        value: &serde_json::Value,
    ) -> Result<Self, CustodyMessageRefusal> {
        Ok(match kind {
            CustodyMessageType::OfferQuery => Self::OfferQuery(decode_canonical_payload(value)?),
            CustodyMessageType::Offer => Self::Offer(decode_canonical_payload(value)?),
            CustodyMessageType::NodeRequest => Self::NodeRequest(decode_canonical_payload(value)?),
            CustodyMessageType::NodeDecision => {
                Self::NodeDecision(decode_canonical_payload(value)?)
            }
            CustodyMessageType::PoolActive => Self::PoolActive(decode_canonical_payload(value)?),
            CustodyMessageType::PoolDescriptor => {
                Self::PoolDescriptor(decode_canonical_payload(value)?)
            }
        })
    }

    /// Rules the shape alone cannot express. `created_at` is the envelope's.
    fn validate(&self, created_at: u64) -> Result<(), CustodyMessageRefusal> {
        match self {
            Self::OfferQuery(_) => Ok(()),
            Self::Offer(offer) => {
                validate_label(&offer.run_by, "run by")?;
                validate_label(&offer.location, "location")?;
                validate_provides(&offer.provides)
            }
            Self::NodeRequest(request) => {
                validate_strong_id(&request.request_id)?;
                validate_sha256_label(&request.signing_key_fingerprint_full)?;
                if !POOL_TERM_DAYS.contains(&request.term_days) {
                    return Err(CustodyMessageRefusal::TermNotOffered);
                }
                Ok(())
            }
            Self::NodeDecision(decision) => validate_decision(decision),
            Self::PoolActive(pool) => validate_pool_active(pool, created_at),
            Self::PoolDescriptor(descriptor) => descriptor.signed_descriptor().map(|_| ()),
        }
    }
}

/// Why a custody message was refused. Codes are stable wire and UI strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CustodyMessageRefusal {
    InvalidEnvelope,
    Oversize,
    WrongService,
    WrongType,
    LifetimeTooLong,
    NotYetValid,
    Expired,
    WrongRecipient,
    WrongSender,
    SignerNotAuthorized,
    SignerNotEndpoint,
    InvalidPayload,
    InvalidLabels,
    TermNotOffered,
    InvalidDecision,
    InvalidCard,
    InvalidConfig,
    FingerprintMismatch,
    CompositionMismatch,
    InvalidPoolWindow,
    InvalidThreshold,
    InvalidMembers,
}

impl CustodyMessageRefusal {
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::InvalidEnvelope => "invalid_envelope",
            Self::Oversize => "oversize",
            Self::WrongService => "wrong_service",
            Self::WrongType => "wrong_type",
            Self::LifetimeTooLong => "lifetime_too_long",
            Self::NotYetValid => "not_yet_valid",
            Self::Expired => "expired",
            Self::WrongRecipient => "wrong_recipient",
            Self::WrongSender => "wrong_sender",
            Self::SignerNotAuthorized => "signer_not_authorized",
            Self::SignerNotEndpoint => "signer_not_endpoint",
            Self::InvalidPayload => "invalid_payload",
            Self::InvalidLabels => "invalid_labels",
            Self::TermNotOffered => "term_not_offered",
            Self::InvalidDecision => "invalid_decision",
            Self::InvalidCard => "invalid_card",
            Self::InvalidConfig => "invalid_config",
            Self::FingerprintMismatch => "fingerprint_mismatch",
            Self::CompositionMismatch => "composition_mismatch",
            Self::InvalidPoolWindow => "invalid_pool_window",
            Self::InvalidThreshold => "invalid_threshold",
            Self::InvalidMembers => "invalid_members",
        }
    }
}

impl std::fmt::Display for CustodyMessageRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "custody message refused: {}", self.code())
    }
}

impl std::error::Error for CustodyMessageRefusal {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifiedCustodyMessage {
    message: VerifiedCollaborationMessage,
    payload: CustodyPayload,
}

impl VerifiedCustodyMessage {
    pub(crate) fn message(&self) -> &VerifiedCollaborationMessage {
        &self.message
    }

    pub(crate) fn payload(&self) -> &CustodyPayload {
        &self.payload
    }

    // Read by the consent handlers the custody transport dispatches to.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn message_type(&self) -> CustodyMessageType {
        self.payload.message_type()
    }

    /// The verified signing endpoint: the sender's Home DID and the only
    /// source of the sender's identity.
    pub(crate) fn signer_did(&self) -> &str {
        &self.message.envelope().signer_did
    }

    pub(crate) fn sender_profile_did(&self) -> &str {
        &self.message.envelope().payload.sender_profile_did
    }

    // Read by the consent handlers the custody transport dispatches to.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn recipient_profile_did(&self) -> &str {
        &self.message.envelope().payload.recipient.id
    }

    /// `sha256:<hex>` of the exact envelope bytes; a decision cites a
    /// request by this value.
    pub(crate) fn envelope_sha256(&self) -> &str {
        self.message.envelope_sha256()
    }

    // Read by the consent handlers the custody transport dispatches to.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn created_at(&self) -> u64 {
        self.message.envelope().payload.created_at
    }

    pub(crate) fn expires_at(&self) -> u64 {
        self.message.envelope().payload.expires_at
    }
}

/// Sign one custody message from `sender_profile` to `recipient_profile_did`,
/// valid from `now` until `expires_at`, which must be within the type's
/// lifetime. A refusal is returned as a [`CustodyMessageRefusal`] the caller
/// can downcast, so a signer without the custody scope reads as one.
pub(crate) fn prepare_custody_message(
    signing_key: &SigningKey,
    network: &VerifiedCollaborationNetworkProfile,
    sender_profile: &VerifiedCollaborationProfileDocument,
    recipient_profile_did: &str,
    payload: &CustodyPayload,
    now: u64,
    expires_at: u64,
) -> anyhow::Result<Vec<u8>> {
    let kind = payload.message_type();
    let signer_did = encode_signing_key_did(signing_key);
    authorize_signer(sender_profile, &signer_did, kind)?;
    validate_lifetime(now, expires_at, kind)?;
    crate::crypto::decode_did_key(recipient_profile_did)
        .context("invalid custody message recipient Profile DID")?;
    payload.validate(now)?;
    let value = payload.to_value()?;
    if serde_json::to_vec(&value)?.len() > MAX_COLLABORATION_PAYLOAD_BYTES {
        return Err(CustodyMessageRefusal::Oversize.into());
    }
    let message = CollaborationMessage {
        schema: COLLABORATION_MESSAGE_SCHEMA_V1.to_string(),
        network_id: network.profile().network_id.clone(),
        conversation_id: CUSTODY_CONVERSATION_ID.to_string(),
        message_id: random_hex()?,
        nonce: random_hex()?,
        created_at: now,
        expires_at,
        sender_profile_did: sender_profile.document().profile_did.clone(),
        sender_service: CUSTODY_SERVICE.to_string(),
        recipient: CollaborationRecipient {
            kind: CollaborationRecipientKind::Profile,
            id: recipient_profile_did.to_string(),
        },
        payload_type: kind.payload_type().to_string(),
        payload: value,
    };
    let payload_bytes = canonical_collaboration_message_bytes(&message)?;
    let (signature, signer_did) = domain_separated_sign(
        signing_key,
        COLLABORATION_MESSAGE_SIGNATURE_DOMAIN_V1,
        &payload_bytes,
    );
    let envelope = canonical_signed_collaboration_message_bytes(&SignedCollaborationMessage {
        payload: message,
        signature,
        signer_did,
    })?;
    verify_custody_message(&envelope, network, sender_profile, None, kind, now)?;
    Ok(envelope)
}

/// Verify a custody message of exactly `expected` type from `sender_profile`,
/// admissible at `now`. When `recipient_profile` is given the message must be
/// addressed to it. Success does not establish contact, admin rights or pool
/// membership.
pub(crate) fn verify_custody_message(
    envelope_bytes: &[u8],
    network: &VerifiedCollaborationNetworkProfile,
    sender_profile: &VerifiedCollaborationProfileDocument,
    recipient_profile: Option<&VerifiedCollaborationProfileDocument>,
    expected: CustodyMessageType,
    now: u64,
) -> Result<VerifiedCustodyMessage, CustodyMessageRefusal> {
    verify_custody_envelope(
        envelope_bytes,
        network,
        sender_profile,
        recipient_profile,
        expected,
        Some(now),
    )
}

/// Reverify stored bytes without the wall clock, so an expired request is
/// still shown as expired rather than as damaged.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn verify_stored_custody_message(
    envelope_bytes: &[u8],
    network: &VerifiedCollaborationNetworkProfile,
    sender_profile: &VerifiedCollaborationProfileDocument,
    recipient_profile: Option<&VerifiedCollaborationProfileDocument>,
    expected: CustodyMessageType,
) -> Result<VerifiedCustodyMessage, CustodyMessageRefusal> {
    verify_custody_envelope(
        envelope_bytes,
        network,
        sender_profile,
        recipient_profile,
        expected,
        None,
    )
}

/// The type a message claims, before any check, so a transport can pick the
/// verifier. Only [`verify_custody_message`] makes the claim a fact.
pub(crate) fn claimed_custody_message_type(envelope_bytes: &[u8]) -> Option<CustodyMessageType> {
    if envelope_bytes.len() > MAX_COLLABORATION_ENVELOPE_BYTES {
        return None;
    }
    let envelope: SignedCollaborationMessage = serde_json::from_slice(envelope_bytes).ok()?;
    if envelope.payload.sender_service != CUSTODY_SERVICE {
        return None;
    }
    CustodyMessageType::from_payload_type(&envelope.payload.payload_type)
}

fn verify_custody_envelope(
    envelope_bytes: &[u8],
    network: &VerifiedCollaborationNetworkProfile,
    sender_profile: &VerifiedCollaborationProfileDocument,
    recipient_profile: Option<&VerifiedCollaborationProfileDocument>,
    expected: CustodyMessageType,
    now: Option<u64>,
) -> Result<VerifiedCustodyMessage, CustodyMessageRefusal> {
    if envelope_bytes.is_empty() {
        return Err(CustodyMessageRefusal::InvalidEnvelope);
    }
    if envelope_bytes.len() > MAX_COLLABORATION_ENVELOPE_BYTES {
        return Err(CustodyMessageRefusal::Oversize);
    }
    // Classify the cheap, specific refusals first. Each one refuses, so it
    // does not matter that the fields are not yet authenticated.
    let claimed: SignedCollaborationMessage = serde_json::from_slice(envelope_bytes)
        .map_err(|_| CustodyMessageRefusal::InvalidEnvelope)?;
    let claimed = &claimed.payload;
    if claimed.sender_service != CUSTODY_SERVICE {
        return Err(CustodyMessageRefusal::WrongService);
    }
    if claimed.payload_type != expected.payload_type() {
        return Err(CustodyMessageRefusal::WrongType);
    }
    validate_lifetime(claimed.created_at, claimed.expires_at, expected)?;
    let payload_bytes =
        serde_json::to_vec(&claimed.payload).map_err(|_| CustodyMessageRefusal::InvalidEnvelope)?;
    if payload_bytes.len() > MAX_COLLABORATION_PAYLOAD_BYTES {
        return Err(CustodyMessageRefusal::Oversize);
    }
    if let Some(now) = now {
        if claimed.created_at > now.saturating_add(MAX_COLLABORATION_CLOCK_SKEW_SECS) {
            return Err(CustodyMessageRefusal::NotYetValid);
        }
        if claimed.expires_at <= now {
            return Err(CustodyMessageRefusal::Expired);
        }
    }

    let message = verify_stored_collaboration_message(envelope_bytes, network, CUSTODY_SERVICE)
        .map_err(|error| {
            tracing::debug!(error = %format!("{error:#}"), "custody message envelope refused");
            CustodyMessageRefusal::InvalidEnvelope
        })?;
    let envelope = message.envelope();
    if envelope.payload.conversation_id != CUSTODY_CONVERSATION_ID
        || envelope.payload.recipient.kind != CollaborationRecipientKind::Profile
        || recipient_profile.is_some_and(|recipient| {
            envelope.payload.recipient.id != recipient.document().profile_did
        })
    {
        return Err(CustodyMessageRefusal::WrongRecipient);
    }
    if envelope.payload.sender_profile_did != sender_profile.document().profile_did {
        return Err(CustodyMessageRefusal::WrongSender);
    }
    authorize_signer(sender_profile, &envelope.signer_did, expected)?;
    let payload = CustodyPayload::decode(expected, &envelope.payload.payload)?;
    payload.validate(envelope.payload.created_at)?;
    Ok(VerifiedCustodyMessage { message, payload })
}

/// The signer must hold the custody scope for this exact type and be the
/// Profile's sole endpoint, so its DID can stand for the sender's Home.
fn authorize_signer(
    profile: &VerifiedCollaborationProfileDocument,
    signer_did: &str,
    kind: CustodyMessageType,
) -> Result<(), CustodyMessageRefusal> {
    if !profile.authorizes_signer(signer_did, CUSTODY_SERVICE, kind.payload_type()) {
        return Err(CustodyMessageRefusal::SignerNotAuthorized);
    }
    if profile.sole_endpoint_did().ok() != Some(signer_did) {
        return Err(CustodyMessageRefusal::SignerNotEndpoint);
    }
    Ok(())
}

fn validate_lifetime(
    created_at: u64,
    expires_at: u64,
    kind: CustodyMessageType,
) -> Result<(), CustodyMessageRefusal> {
    if expires_at <= created_at {
        return Err(CustodyMessageRefusal::InvalidEnvelope);
    }
    if expires_at - created_at > kind.max_lifetime_secs() {
        return Err(CustodyMessageRefusal::LifetimeTooLong);
    }
    Ok(())
}

fn decode_canonical_payload<T>(value: &serde_json::Value) -> Result<T, CustodyMessageRefusal>
where
    T: DeserializeOwned + Serialize,
{
    let raw = serde_json::to_vec(value).map_err(|_| CustodyMessageRefusal::InvalidPayload)?;
    let payload: T =
        serde_json::from_slice(&raw).map_err(|_| CustodyMessageRefusal::InvalidPayload)?;
    if serde_json::to_vec(&payload).ok().as_deref() != Some(raw.as_slice()) {
        return Err(CustodyMessageRefusal::InvalidPayload);
    }
    Ok(payload)
}

fn validate_decision(decision: &CustodyNodeDecisionPayload) -> Result<(), CustodyMessageRefusal> {
    validate_strong_id(&decision.request_id)?;
    validate_sha256_label(&decision.request_sha256)?;
    match (decision.outcome, &decision.card, &decision.code) {
        (CustodyNodeDecisionOutcome::Approved, Some(card), None) => {
            parse_node_card(card).map_err(|refusal| {
                tracing::debug!(code = refusal.code(), "custody decision card refused");
                CustodyMessageRefusal::InvalidCard
            })?;
            Ok(())
        }
        (CustodyNodeDecisionOutcome::Declined, None, Some(_)) => Ok(()),
        _ => Err(CustodyMessageRefusal::InvalidDecision),
    }
}

/// Count-agnostic: the threshold says how many members there are, and the
/// member list must be exactly shares 1..=total in order.
fn validate_pool_active(
    pool: &CustodyPoolActivePayload,
    created_at: u64,
) -> Result<(), CustodyMessageRefusal> {
    let threshold = ThresholdV1::new(pool.threshold.required, pool.threshold.total)
        .map_err(|_| CustodyMessageRefusal::InvalidThreshold)?;
    let total = threshold.total();
    if pool.members.len() != usize::from(total)
        || !(1..=total).contains(&pool.share)
        || pool
            .members
            .iter()
            .zip(1..=total)
            .any(|(member, share)| member.share != share)
    {
        return Err(CustodyMessageRefusal::InvalidMembers);
    }
    for member in &pool.members {
        validate_label(&member.run_by, "run by")?;
        validate_label(&member.location, "location")?;
    }
    validate_sha256_label(&pool.fingerprint_full)?;
    // Bound the text before decoding it.
    if pool.config.len() > MAX_POOL_ACTIVE_CONFIG_BYTES.div_ceil(3) * 4 {
        return Err(CustodyMessageRefusal::InvalidConfig);
    }
    let config = base64::engine::general_purpose::STANDARD
        .decode(&pool.config)
        .map_err(|_| CustodyMessageRefusal::InvalidConfig)?;
    if config.is_empty() || config.len() > MAX_POOL_ACTIVE_CONFIG_BYTES {
        return Err(CustodyMessageRefusal::InvalidConfig);
    }
    if format!("sha256:{}", hex::encode(Sha256::digest(&config))) != pool.fingerprint_full {
        return Err(CustodyMessageRefusal::FingerprintMismatch);
    }
    let signed = signed_composition_facts(&config)?;
    if pool.pool_start != signed.start
        || pool.term_end != signed.end
        || usize::from(total) != signed.members.len()
        || threshold.required() != signed.threshold.required()
        || total != signed.threshold.total()
    {
        return Err(CustodyMessageRefusal::CompositionMismatch);
    }
    // A far-future start would outrank every later pool and pin the
    // ordering, so the start may lead the message by clock skew only.
    if pool.pool_start >= pool.term_end
        || pool.pool_start > created_at.saturating_add(MAX_COLLABORATION_CLOCK_SKEW_SECS)
        || pool.term_end <= created_at
    {
        return Err(CustodyMessageRefusal::InvalidPoolWindow);
    }
    Ok(())
}

/// What a pool-active notice must agree with, read from its own signed
/// composition. The owner builds a notice from these, and a node checks its
/// place in the pool against them.
pub(crate) struct SignedCompositionFacts {
    /// The pool's issuer: the owner's pool signing key.
    pub(crate) issuer: [u8; 32],
    /// The latest member `valid_from`, as the Active view reads the start.
    pub(crate) start: u64,
    /// The earliest member `valid_until`.
    pub(crate) end: u64,
    /// Each member node's public key and share, from the signed epoch.
    pub(crate) members: Vec<([u8; 32], u8)>,
    pub(crate) threshold: ThresholdV1,
}

/// Signatures are checked against the composition's own issuer only, with
/// the epoch bound to the pool's issuer. Whether that issuer is the expected
/// owner, and the full epoch-to-pool binding, stay with
/// `load_runtime_custody_composition`.
pub(crate) fn signed_composition_facts(
    config: &[u8],
) -> Result<SignedCompositionFacts, CustodyMessageRefusal> {
    let file: RuntimeCustodyCompositionConfigFile =
        serde_json::from_slice(config).map_err(|_| CustodyMessageRefusal::InvalidConfig)?;
    if file.schema != CUSTODY_COMPOSITION_SCHEMA_V1 {
        return Err(CustodyMessageRefusal::InvalidConfig);
    }
    let pool: SignedCustodyPoolV1 = decode_contract_base64(&file.signed_pool_base64)?;
    let issuer = pool.statement().issuer();
    pool.verify(issuer)
        .map_err(|_| CustodyMessageRefusal::InvalidConfig)?;
    let epoch: SignedCustodyEpochV1 = decode_contract_base64(&file.signed_epoch_base64)?;
    let epoch = epoch
        .verify()
        .map_err(|_| CustodyMessageRefusal::InvalidConfig)?;
    if epoch.issuer() != issuer {
        return Err(CustodyMessageRefusal::InvalidConfig);
    }
    let pool_members = pool.statement().members();
    let start = pool_members.iter().map(|member| member.valid_from()).max();
    let end = pool_members.iter().map(|member| member.valid_until()).min();
    let (start, end) = start.zip(end).ok_or(CustodyMessageRefusal::InvalidConfig)?;
    let members: Vec<([u8; 32], u8)> = epoch
        .nodes()
        .iter()
        .map(|node| {
            (
                *node.node_public_key().as_bytes(),
                node.share_coordinate().get(),
            )
        })
        .collect();
    if members.len() != pool_members.len() {
        return Err(CustodyMessageRefusal::InvalidConfig);
    }
    Ok(SignedCompositionFacts {
        issuer: *issuer.as_bytes(),
        start,
        end,
        members,
        threshold: epoch.threshold(),
    })
}

fn decode_contract_base64<T: CanonicalContract>(encoded: &str) -> Result<T, CustodyMessageRefusal> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| CustodyMessageRefusal::InvalidConfig)?;
    T::from_canonical_bytes(&bytes).map_err(|_| CustodyMessageRefusal::InvalidConfig)
}

/// Whether `incoming` may replace the `stored` notice for the same owner.
/// Only a strictly later signed pool start does, so a replayed older notice,
/// or a different one of the same age, cannot downgrade the node. Both must
/// already be verified.
pub(crate) fn pool_active_is_newer(
    stored: &CustodyPoolActivePayload,
    incoming: &CustodyPoolActivePayload,
) -> bool {
    incoming.pool_start > stored.pool_start
}

fn validate_label(value: &str, label: &str) -> Result<(), CustodyMessageRefusal> {
    validated_custody_node_label(value, label)
        .map(|_| ())
        .map_err(|_| CustodyMessageRefusal::InvalidLabels)
}

/// A non-empty, sorted, distinct subset of the roles a node card can list.
fn validate_provides(provides: &[String]) -> Result<(), CustodyMessageRefusal> {
    let sorted_distinct = provides.windows(2).all(|pair| pair[0] < pair[1]);
    let known = provides
        .iter()
        .all(|role| NODE_CARD_PROVIDES.contains(&role.as_str()));
    if provides.is_empty() || !sorted_distinct || !known {
        return Err(CustodyMessageRefusal::InvalidPayload);
    }
    Ok(())
}

fn validate_strong_id(value: &str) -> Result<(), CustodyMessageRefusal> {
    if value.len() != 32 || !is_lower_hex(value) {
        return Err(CustodyMessageRefusal::InvalidPayload);
    }
    Ok(())
}

fn validate_sha256_label(value: &str) -> Result<(), CustodyMessageRefusal> {
    match value.strip_prefix("sha256:") {
        Some(digest) if digest.len() == 64 && is_lower_hex(digest) => Ok(()),
        _ => Err(CustodyMessageRefusal::InvalidPayload),
    }
}

fn is_lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn random_hex() -> anyhow::Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).context("OS randomness unavailable for custody message ID")?;
    Ok(hex::encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collaboration_profile_authority::{
        signed_profile_document_for_test, signed_profile_document_with_authority_for_test,
        with_signing_scope_for_test, ProfileAuthorityForTest,
    };
    use crate::crypto::{domain_separated_sign, encode_signing_key_did};
    use elastos_common::collaboration_protocol::MAX_COLLABORATION_MESSAGE_LIFETIME_SECS;
    use elastos_runtime::signature::generate_keypair;

    const NETWORK: &str = "elastos.community.test";
    const NOW: u64 = 1_800_000_000;

    fn network() -> VerifiedCollaborationNetworkProfile {
        let (trusted, _) = generate_keypair();
        crate::collaboration_discovery_runtime::tests::signed_profile(NETWORK, &trusted, vec![])
    }

    struct Party {
        device: SigningKey,
        profile_key: SigningKey,
        profile: VerifiedCollaborationProfileDocument,
    }

    impl Party {
        /// A Home whose admin enabled custody messages.
        fn new(name: &str) -> Self {
            let party = Self::without_custody_scope(name);
            Self {
                profile: with_signing_scope_for_test(
                    &party.profile_key,
                    &party.profile,
                    CUSTODY_SIGNING_SCOPE,
                )
                .unwrap(),
                ..party
            }
        }

        /// A default Profile: custody messages were never enabled.
        fn without_custody_scope(name: &str) -> Self {
            let (device, _) = generate_keypair();
            let (profile_key, _) = generate_keypair();
            let profile = signed_profile_document_for_test(
                &profile_key,
                name,
                None,
                1,
                None,
                NOW - 100,
                vec![encode_signing_key_did(&device)],
            )
            .unwrap();
            Self {
                device,
                profile_key,
                profile,
            }
        }

        fn did(&self) -> String {
            encode_signing_key_did(&self.device)
        }

        fn profile_did(&self) -> &str {
            &self.profile.document().profile_did
        }
    }

    struct Fixture {
        network: VerifiedCollaborationNetworkProfile,
        owner: Party,
        node: Party,
    }

    fn fixture() -> Fixture {
        Fixture {
            network: network(),
            owner: Party::new("Owner"),
            node: Party::new("Node"),
        }
    }

    fn request_id() -> String {
        "0123456789abcdef0123456789abcdef".to_string()
    }

    fn sha256_label(bytes: &[u8]) -> String {
        format!("sha256:{}", hex::encode(sha2::Sha256::digest(bytes)))
    }

    fn node_request(term_days: u16) -> CustodyPayload {
        CustodyPayload::NodeRequest(CustodyNodeRequestPayload {
            request_id: request_id(),
            signing_key_fingerprint_full: sha256_label(b"policy authority"),
            term_days,
        })
    }

    fn approved(node: &Party) -> CustodyNodeDecisionPayload {
        CustodyNodeDecisionPayload {
            card: Some(crate::custody_node_card::tests::card_for_device(
                &node.device.verifying_key(),
                "Node operator",
                "Lisbon",
                &["chain", "custody", "ipfs"],
            )),
            code: None,
            outcome: CustodyNodeDecisionOutcome::Approved,
            request_id: request_id(),
            request_sha256: sha256_label(b"request envelope"),
        }
    }

    fn declined(code: CustodyDeclineCode) -> CustodyNodeDecisionPayload {
        CustodyNodeDecisionPayload {
            card: None,
            code: Some(code),
            outcome: CustodyNodeDecisionOutcome::Declined,
            request_id: request_id(),
            request_sha256: sha256_label(b"request envelope"),
        }
    }

    const POOL_START: u64 = NOW - 60;
    const POOL_END: u64 = NOW + 365 * 24 * 60 * 60;

    /// The signed pieces of a composition, standard base64 each.
    struct CompositionParts {
        pool: String,
        epoch: String,
    }

    /// A pool and a `required`-of-N epoch over the same N fresh nodes, one per
    /// window, signed by one fresh issuer. Only these two are real: the
    /// protocol reads nothing else from the composition.
    fn composition_parts(required: u8, windows: &[(u64, u64)]) -> CompositionParts {
        use ed25519_dalek::Signer as _;
        use elastos_protected_content_contracts::{
            CustodyApprovedSuitesV1, CustodyEpochIssuerKeyV1, CustodyEpochStatementV1,
            CustodyNodeIdentityV1, CustodyPoolFailureDomainIdV1, CustodyPoolMemberStateV1,
            CustodyPoolMemberV1, CustodyPoolOperatorIdV1, CustodyPoolStatementV1,
            NodeCustodyPublicKeyV1, NodePublicKey, ShareCoordinateV1,
            CUSTODY_X_WING_AES256GCM_SUITE_ID_V1,
        };
        use x_wing::kem::Decapsulator as _;
        use x_wing::KeyExport as _;
        let suites = CustodyApprovedSuitesV1::new(
            CUSTODY_X_WING_AES256GCM_SUITE_ID_V1,
            CUSTODY_X_WING_AES256GCM_SUITE_ID_V1,
            CUSTODY_X_WING_AES256GCM_SUITE_ID_V1,
        )
        .unwrap();
        let nodes: Vec<_> = windows
            .iter()
            .map(|_| {
                let mut seed = [0u8; x_wing::DECAPSULATION_KEY_SIZE];
                getrandom::getrandom(&mut seed).unwrap();
                (
                    NodePublicKey::new(generate_keypair().1.to_bytes()).unwrap(),
                    NodeCustodyPublicKeyV1::new(
                        x_wing::DecapsulationKey::from(seed)
                            .encapsulation_key()
                            .to_bytes()
                            .into(),
                    )
                    .unwrap(),
                )
            })
            .collect();
        let (authority, _) = generate_keypair();
        let issuer = CustodyEpochIssuerKeyV1::new(authority.verifying_key().to_bytes()).unwrap();
        let members = nodes
            .iter()
            .zip(windows)
            .zip(1u8..)
            .map(|(((node_key, custody_key), window), index)| {
                CustodyPoolMemberV1::new(
                    *node_key,
                    *custody_key,
                    CustodyPoolOperatorIdV1::new([0x80 + index; 32]),
                    CustodyPoolFailureDomainIdV1::new([0x90 + index; 32]),
                    suites.clone(),
                    *window,
                    CustodyPoolMemberStateV1::Active,
                )
                .unwrap()
            })
            .collect();
        let pool = CustodyPoolStatementV1::new(issuer, members).unwrap();
        let pool_signature = authority.sign(&pool.canonical_bytes().unwrap());
        let pool = SignedCustodyPoolV1::new(pool, pool_signature.to_bytes().to_vec()).unwrap();
        let identities = nodes
            .iter()
            .zip(1u8..)
            .map(|((node_key, custody_key), index)| {
                CustodyNodeIdentityV1::new(
                    *node_key,
                    *custody_key,
                    ShareCoordinateV1::new(index).unwrap(),
                )
                .unwrap()
            })
            .collect();
        let total = u8::try_from(windows.len()).unwrap();
        let epoch = CustodyEpochStatementV1::new(
            issuer,
            suites,
            ThresholdV1::new(required, total).unwrap(),
            identities,
        )
        .unwrap();
        let epoch_signature = authority.sign(&epoch.canonical_bytes().unwrap());
        let epoch = SignedCustodyEpochV1::new(epoch, epoch_signature.to_bytes().to_vec()).unwrap();
        let encode = |bytes: Vec<u8>| base64::engine::general_purpose::STANDARD.encode(bytes);
        CompositionParts {
            pool: encode(pool.canonical_bytes().unwrap()),
            epoch: encode(epoch.canonical_bytes().unwrap()),
        }
    }

    fn composition_bytes(parts: CompositionParts) -> Vec<u8> {
        let file = RuntimeCustodyCompositionConfigFile {
            schema: CUSTODY_COMPOSITION_SCHEMA_V1.to_string(),
            expected_policy_authority_base64: String::new(),
            expected_committee_authorization_identity_base64: String::new(),
            signed_pool_base64: parts.pool,
            signed_epoch_base64: parts.epoch,
            signed_committee_authorization_base64: String::new(),
            routes: Vec::new(),
        };
        serde_json::to_vec(&serde_json::to_value(file).unwrap()).unwrap()
    }

    fn composition(required: u8, total: u8, window: (u64, u64)) -> Vec<u8> {
        composition_bytes(composition_parts(
            required,
            &vec![window; usize::from(total)],
        ))
    }

    fn pool_active_with_config(
        config: &[u8],
        required: u8,
        total: u8,
        share: u8,
        window: (u64, u64),
    ) -> CustodyPoolActivePayload {
        CustodyPoolActivePayload {
            config: base64::engine::general_purpose::STANDARD.encode(config),
            fingerprint_full: sha256_label(config),
            members: (1..=total)
                .map(|share| CustodyPoolMember {
                    location: format!("Place {share}"),
                    run_by: format!("Operator {share}"),
                    share,
                })
                .collect(),
            pool_start: window.0,
            share,
            term_end: window.1,
            threshold: CustodyPoolThreshold { required, total },
        }
    }

    fn pool_active_at(
        required: u8,
        total: u8,
        share: u8,
        window: (u64, u64),
    ) -> CustodyPoolActivePayload {
        let config = composition(required, total, window);
        pool_active_with_config(&config, required, total, share, window)
    }

    fn pool_active(required: u8, total: u8, share: u8) -> CustodyPoolActivePayload {
        pool_active_at(required, total, share, (POOL_START, POOL_END))
    }

    fn sample_payloads(node: &Party) -> Vec<CustodyPayload> {
        vec![
            CustodyPayload::OfferQuery(CustodyOfferQueryPayload {}),
            CustodyPayload::Offer(CustodyOfferPayload {
                location: "Lisbon".to_string(),
                provides: vec!["chain".to_string(), "custody".to_string()],
                run_by: "Node operator".to_string(),
            }),
            node_request(365),
            CustodyPayload::NodeDecision(approved(node)),
            CustodyPayload::PoolActive(pool_active(2, 3, 2)),
        ]
    }

    fn prepare(
        fixture: &Fixture,
        sender: &Party,
        recipient: &Party,
        payload: &CustodyPayload,
    ) -> anyhow::Result<Vec<u8>> {
        prepare_custody_message(
            &sender.device,
            &fixture.network,
            &sender.profile,
            recipient.profile_did(),
            payload,
            NOW,
            NOW + payload.message_type().max_lifetime_secs(),
        )
    }

    fn verify(
        fixture: &Fixture,
        bytes: &[u8],
        sender: &Party,
        recipient: &Party,
        expected: CustodyMessageType,
    ) -> Result<VerifiedCustodyMessage, CustodyMessageRefusal> {
        verify_custody_message(
            bytes,
            &fixture.network,
            &sender.profile,
            Some(&recipient.profile),
            expected,
            NOW,
        )
    }

    /// A correctly signed envelope from `sender` with whatever fields the
    /// test chose, for cases `prepare_custody_message` refuses to build.
    fn raw_message(
        fixture: &Fixture,
        sender: &Party,
        recipient: &Party,
        payload_type: &str,
        payload: serde_json::Value,
    ) -> CollaborationMessage {
        CollaborationMessage {
            schema: COLLABORATION_MESSAGE_SCHEMA_V1.to_string(),
            network_id: fixture.network.profile().network_id.clone(),
            conversation_id: CUSTODY_CONVERSATION_ID.to_string(),
            message_id: "00112233445566778899aabbccddeeff".to_string(),
            nonce: "ffeeddccbbaa99887766554433221100".to_string(),
            created_at: NOW,
            expires_at: NOW + 60,
            sender_profile_did: sender.profile_did().to_string(),
            sender_service: CUSTODY_SERVICE.to_string(),
            recipient: CollaborationRecipient {
                kind: CollaborationRecipientKind::Profile,
                id: recipient.profile_did().to_string(),
            },
            payload_type: payload_type.to_string(),
            payload,
        }
    }

    fn sign_raw(signing_key: &SigningKey, message: CollaborationMessage) -> Vec<u8> {
        let payload_bytes = canonical_collaboration_message_bytes(&message).unwrap();
        let (signature, signer_did) = domain_separated_sign(
            signing_key,
            COLLABORATION_MESSAGE_SIGNATURE_DOMAIN_V1,
            &payload_bytes,
        );
        canonical_signed_collaboration_message_bytes(&SignedCollaborationMessage {
            payload: message,
            signature,
            signer_did,
        })
        .unwrap()
    }

    fn refusal(error: anyhow::Error) -> CustodyMessageRefusal {
        *error
            .downcast_ref::<CustodyMessageRefusal>()
            .unwrap_or_else(|| panic!("expected a custody refusal, got {error:#}"))
    }

    #[test]
    fn every_custody_message_type_round_trips_with_the_signer_as_identity() {
        let fixture = fixture();
        for payload in sample_payloads(&fixture.node) {
            let kind = payload.message_type();
            let bytes = prepare(&fixture, &fixture.owner, &fixture.node, &payload).unwrap();
            let verified = verify(&fixture, &bytes, &fixture.owner, &fixture.node, kind).unwrap();
            assert_eq!(verified.payload(), &payload);
            assert_eq!(verified.message_type(), kind);
            assert_eq!(verified.signer_did(), fixture.owner.did());
            assert_eq!(verified.sender_profile_did(), fixture.owner.profile_did());
            assert_eq!(verified.recipient_profile_did(), fixture.node.profile_did());
            assert_eq!(verified.envelope_sha256(), sha256_label(&bytes));
            assert_eq!(verified.created_at(), NOW);
            assert_eq!(verified.expires_at(), NOW + kind.max_lifetime_secs());
            assert_eq!(claimed_custody_message_type(&bytes), Some(kind));
            let envelope = &verified.message().envelope().payload;
            assert_eq!(envelope.sender_service, CUSTODY_SERVICE);
            assert_eq!(envelope.payload_type, kind.payload_type());
            // The issuer is derived from the signer, never carried.
            let rendered = serde_json::to_string(&envelope.payload).unwrap();
            assert!(!rendered.contains(&fixture.owner.did()), "{rendered}");
            assert!(!rendered.contains("issuer"), "{rendered}");

            // Stored reverification ignores the clock but keeps every other rule.
            let stored = verify_stored_custody_message(
                &bytes,
                &fixture.network,
                &fixture.owner.profile,
                Some(&fixture.node.profile),
                kind,
            )
            .unwrap();
            assert_eq!(stored, verified);
        }
        let decline = CustodyPayload::NodeDecision(declined(CustodyDeclineCode::AlreadyServing));
        let bytes = prepare(&fixture, &fixture.node, &fixture.owner, &decline).unwrap();
        let verified = verify(
            &fixture,
            &bytes,
            &fixture.node,
            &fixture.owner,
            CustodyMessageType::NodeDecision,
        )
        .unwrap();
        assert_eq!(verified.payload(), &decline);
        assert_eq!(verified.signer_did(), fixture.node.did());
    }

    #[test]
    fn custody_message_types_and_lifetimes_are_fixed() {
        assert_eq!(
            CustodyMessageType::ALL.map(CustodyMessageType::payload_type),
            [
                "elastos.custody.offer-query/v1",
                "elastos.custody.offer/v1",
                "elastos.custody.node-request/v1",
                "elastos.custody.node-decision/v1",
                "elastos.custody.pool-active/v1",
                "elastos.custody.pool-descriptor/v1",
            ]
        );
        assert_eq!(CustodyMessageType::OfferQuery.max_lifetime_secs(), 120);
        assert_eq!(CustodyMessageType::Offer.max_lifetime_secs(), 120);
        for kind in CustodyMessageType::ALL {
            assert!(kind.max_lifetime_secs() <= MAX_COLLABORATION_MESSAGE_LIFETIME_SECS);
        }
    }

    #[test]
    fn refusal_codes_are_stable_and_distinct() {
        use CustodyMessageRefusal::*;
        let all = [
            (InvalidEnvelope, "invalid_envelope"),
            (Oversize, "oversize"),
            (WrongService, "wrong_service"),
            (WrongType, "wrong_type"),
            (LifetimeTooLong, "lifetime_too_long"),
            (NotYetValid, "not_yet_valid"),
            (Expired, "expired"),
            (WrongRecipient, "wrong_recipient"),
            (WrongSender, "wrong_sender"),
            (SignerNotAuthorized, "signer_not_authorized"),
            (SignerNotEndpoint, "signer_not_endpoint"),
            (InvalidPayload, "invalid_payload"),
            (InvalidLabels, "invalid_labels"),
            (TermNotOffered, "term_not_offered"),
            (InvalidDecision, "invalid_decision"),
            (InvalidCard, "invalid_card"),
            (InvalidConfig, "invalid_config"),
            (FingerprintMismatch, "fingerprint_mismatch"),
            (CompositionMismatch, "composition_mismatch"),
            (InvalidPoolWindow, "invalid_pool_window"),
            (InvalidThreshold, "invalid_threshold"),
            (InvalidMembers, "invalid_members"),
        ];
        for (refusal, code) in all {
            assert_eq!(refusal.code(), code);
        }
        let mut codes: Vec<_> = all.iter().map(|(_, code)| *code).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), all.len());
    }

    #[test]
    fn the_claimed_type_peek_is_bounded_before_parsing() {
        let fixture = fixture();
        let query = CustodyPayload::OfferQuery(CustodyOfferQueryPayload {});
        let bytes = prepare(&fixture, &fixture.owner, &fixture.node, &query).unwrap();
        // Trailing whitespace still parses, so only the bound refuses it.
        let mut at_limit = bytes.clone();
        at_limit.resize(MAX_COLLABORATION_ENVELOPE_BYTES, b' ');
        assert_eq!(
            claimed_custody_message_type(&at_limit),
            Some(CustodyMessageType::OfferQuery)
        );
        let mut over_limit = bytes;
        over_limit.resize(MAX_COLLABORATION_ENVELOPE_BYTES + 1, b' ');
        assert_eq!(claimed_custody_message_type(&over_limit), None);
    }

    #[test]
    fn wrong_service_and_wrong_type_are_refused() {
        let fixture = fixture();
        let query = CustodyPayload::OfferQuery(CustodyOfferQueryPayload {});
        let bytes = prepare(&fixture, &fixture.owner, &fixture.node, &query).unwrap();
        assert_eq!(
            verify(
                &fixture,
                &bytes,
                &fixture.owner,
                &fixture.node,
                CustodyMessageType::Offer
            ),
            Err(CustodyMessageRefusal::WrongType)
        );

        let mut message = raw_message(
            &fixture,
            &fixture.owner,
            &fixture.node,
            CUSTODY_OFFER_QUERY_PAYLOAD_TYPE,
            serde_json::json!({}),
        );
        message.sender_service = "people".to_string();
        let bytes = sign_raw(&fixture.owner.device, message);
        assert_eq!(
            verify(
                &fixture,
                &bytes,
                &fixture.owner,
                &fixture.node,
                CustodyMessageType::OfferQuery
            ),
            Err(CustodyMessageRefusal::WrongService)
        );

        // A type outside the custody set is refused even when asked for by name.
        let bytes = sign_raw(
            &fixture.owner.device,
            raw_message(
                &fixture,
                &fixture.owner,
                &fixture.node,
                "elastos.custody.unknown/v1",
                serde_json::json!({}),
            ),
        );
        assert_eq!(claimed_custody_message_type(&bytes), None);
        assert_eq!(
            verify(
                &fixture,
                &bytes,
                &fixture.owner,
                &fixture.node,
                CustodyMessageType::OfferQuery
            ),
            Err(CustodyMessageRefusal::WrongType)
        );
    }

    #[test]
    fn a_profile_without_the_custody_scope_cannot_send() {
        let fixture = fixture();
        let old = Party::without_custody_scope("Old Home");
        assert!(!old.profile.authorizes_signer(
            &old.did(),
            CUSTODY_SERVICE,
            CUSTODY_OFFER_QUERY_PAYLOAD_TYPE
        ));
        let query = CustodyPayload::OfferQuery(CustodyOfferQueryPayload {});
        let error = prepare(&fixture, &old, &fixture.node, &query).unwrap_err();
        assert_eq!(refusal(error), CustodyMessageRefusal::SignerNotAuthorized);

        let bytes = sign_raw(
            &old.device,
            raw_message(
                &fixture,
                &old,
                &fixture.node,
                CUSTODY_OFFER_QUERY_PAYLOAD_TYPE,
                serde_json::json!({}),
            ),
        );
        assert_eq!(
            verify(
                &fixture,
                &bytes,
                &old,
                &fixture.node,
                CustodyMessageType::OfferQuery
            ),
            Err(CustodyMessageRefusal::SignerNotAuthorized)
        );
    }

    #[test]
    fn the_signer_must_be_the_sender_profiles_endpoint() {
        let fixture = fixture();
        let (endpoint, _) = generate_keypair();
        let (signer, _) = generate_keypair();
        let (profile_key, _) = generate_keypair();
        let split_profile = signed_profile_document_with_authority_for_test(
            &profile_key,
            "Split",
            None,
            1,
            None,
            NOW - 100,
            ProfileAuthorityForTest {
                endpoint_dids: vec![encode_signing_key_did(&endpoint)],
                signer_dids: vec![encode_signing_key_did(&signer)],
            },
        )
        .unwrap();
        let split = Party {
            profile: with_signing_scope_for_test(
                &profile_key,
                &split_profile,
                CUSTODY_SIGNING_SCOPE,
            )
            .unwrap(),
            profile_key,
            device: signer,
        };
        let query = CustodyPayload::OfferQuery(CustodyOfferQueryPayload {});
        let error = prepare(&fixture, &split, &fixture.node, &query).unwrap_err();
        assert_eq!(refusal(error), CustodyMessageRefusal::SignerNotEndpoint);
        let bytes = sign_raw(
            &split.device,
            raw_message(
                &fixture,
                &split,
                &fixture.node,
                CUSTODY_OFFER_QUERY_PAYLOAD_TYPE,
                serde_json::json!({}),
            ),
        );
        assert_eq!(
            verify(
                &fixture,
                &bytes,
                &split,
                &fixture.node,
                CustodyMessageType::OfferQuery
            ),
            Err(CustodyMessageRefusal::SignerNotEndpoint)
        );
    }

    #[test]
    fn the_message_binds_its_sender_and_recipient_profiles() {
        let fixture = fixture();
        let stranger = Party::new("Stranger");
        let query = CustodyPayload::OfferQuery(CustodyOfferQueryPayload {});
        let bytes = prepare(&fixture, &fixture.owner, &fixture.node, &query).unwrap();
        assert_eq!(
            verify(
                &fixture,
                &bytes,
                &fixture.owner,
                &stranger,
                CustodyMessageType::OfferQuery
            ),
            Err(CustodyMessageRefusal::WrongRecipient)
        );
        assert_eq!(
            verify(
                &fixture,
                &bytes,
                &stranger,
                &fixture.node,
                CustodyMessageType::OfferQuery
            ),
            Err(CustodyMessageRefusal::WrongSender)
        );
        // Without a recipient Profile the address is not checked here.
        assert!(verify_custody_message(
            &bytes,
            &fixture.network,
            &fixture.owner.profile,
            None,
            CustodyMessageType::OfferQuery,
            NOW
        )
        .is_ok());

        let mut message = raw_message(
            &fixture,
            &fixture.owner,
            &fixture.node,
            CUSTODY_OFFER_QUERY_PAYLOAD_TYPE,
            serde_json::json!({}),
        );
        message.recipient = CollaborationRecipient {
            kind: CollaborationRecipientKind::Conversation,
            id: CUSTODY_CONVERSATION_ID.to_string(),
        };
        let bytes = sign_raw(&fixture.owner.device, message);
        assert_eq!(
            verify(
                &fixture,
                &bytes,
                &fixture.owner,
                &fixture.node,
                CustodyMessageType::OfferQuery
            ),
            Err(CustodyMessageRefusal::WrongRecipient)
        );

        let mut message = raw_message(
            &fixture,
            &fixture.owner,
            &fixture.node,
            CUSTODY_OFFER_QUERY_PAYLOAD_TYPE,
            serde_json::json!({}),
        );
        message.conversation_id = "elastos.people.contact".to_string();
        let bytes = sign_raw(&fixture.owner.device, message);
        assert_eq!(
            verify(
                &fixture,
                &bytes,
                &fixture.owner,
                &fixture.node,
                CustodyMessageType::OfferQuery
            ),
            Err(CustodyMessageRefusal::WrongRecipient)
        );
    }

    #[test]
    fn lifetimes_over_the_type_ceiling_or_24_hours_are_refused() {
        let fixture = fixture();
        let query = CustodyPayload::OfferQuery(CustodyOfferQueryPayload {});
        let error = prepare_custody_message(
            &fixture.owner.device,
            &fixture.network,
            &fixture.owner.profile,
            fixture.node.profile_did(),
            &query,
            NOW,
            NOW + 121,
        )
        .unwrap_err();
        assert_eq!(refusal(error), CustodyMessageRefusal::LifetimeTooLong);
        let error = prepare_custody_message(
            &fixture.owner.device,
            &fixture.network,
            &fixture.owner.profile,
            fixture.node.profile_did(),
            &query,
            NOW,
            NOW,
        )
        .unwrap_err();
        assert_eq!(refusal(error), CustodyMessageRefusal::InvalidEnvelope);

        let mut message = raw_message(
            &fixture,
            &fixture.owner,
            &fixture.node,
            CUSTODY_OFFER_QUERY_PAYLOAD_TYPE,
            serde_json::json!({}),
        );
        message.expires_at = NOW + 121;
        let bytes = sign_raw(&fixture.owner.device, message);
        assert_eq!(
            verify(
                &fixture,
                &bytes,
                &fixture.owner,
                &fixture.node,
                CustodyMessageType::OfferQuery
            ),
            Err(CustodyMessageRefusal::LifetimeTooLong)
        );

        let request = serde_json::to_value(CustodyNodeRequestPayload {
            request_id: request_id(),
            signing_key_fingerprint_full: sha256_label(b"policy authority"),
            term_days: 365,
        })
        .unwrap();
        let mut message = raw_message(
            &fixture,
            &fixture.owner,
            &fixture.node,
            CUSTODY_NODE_REQUEST_PAYLOAD_TYPE,
            request,
        );
        message.expires_at = NOW + MAX_COLLABORATION_MESSAGE_LIFETIME_SECS + 1;
        let bytes = sign_raw(&fixture.owner.device, message);
        assert_eq!(
            verify(
                &fixture,
                &bytes,
                &fixture.owner,
                &fixture.node,
                CustodyMessageType::NodeRequest
            ),
            Err(CustodyMessageRefusal::LifetimeTooLong)
        );
    }

    #[test]
    fn expired_and_future_messages_are_refused_but_stay_storable() {
        let fixture = fixture();
        let payload = node_request(182);
        let bytes = prepare(&fixture, &fixture.owner, &fixture.node, &payload).unwrap();
        let expires_at = NOW + CustodyMessageType::NodeRequest.max_lifetime_secs();
        let at = |now| {
            verify_custody_message(
                &bytes,
                &fixture.network,
                &fixture.owner.profile,
                Some(&fixture.node.profile),
                CustodyMessageType::NodeRequest,
                now,
            )
        };
        assert!(at(expires_at - 1).is_ok());
        assert_eq!(at(expires_at), Err(CustodyMessageRefusal::Expired));
        assert_eq!(
            at(NOW - MAX_COLLABORATION_CLOCK_SKEW_SECS - 1),
            Err(CustodyMessageRefusal::NotYetValid)
        );
        assert!(verify_stored_custody_message(
            &bytes,
            &fixture.network,
            &fixture.owner.profile,
            Some(&fixture.node.profile),
            CustodyMessageType::NodeRequest,
        )
        .is_ok());
    }

    #[test]
    fn oversize_envelopes_and_payloads_are_refused() {
        let fixture = fixture();
        let huge = vec![b' '; MAX_COLLABORATION_ENVELOPE_BYTES + 1];
        assert_eq!(
            verify(
                &fixture,
                &huge,
                &fixture.owner,
                &fixture.node,
                CustodyMessageType::Offer
            ),
            Err(CustodyMessageRefusal::Oversize)
        );
        assert_eq!(
            verify(
                &fixture,
                b"",
                &fixture.owner,
                &fixture.node,
                CustodyMessageType::Offer
            ),
            Err(CustodyMessageRefusal::InvalidEnvelope)
        );

        let payload = serde_json::json!({
            "location": "x".repeat(MAX_COLLABORATION_PAYLOAD_BYTES),
            "provides": ["custody"],
            "run_by": "Node operator",
        });
        let bytes = sign_raw(
            &fixture.node.device,
            raw_message(
                &fixture,
                &fixture.node,
                &fixture.owner,
                CUSTODY_OFFER_PAYLOAD_TYPE,
                payload,
            ),
        );
        assert!(bytes.len() <= MAX_COLLABORATION_ENVELOPE_BYTES);
        assert_eq!(
            verify(
                &fixture,
                &bytes,
                &fixture.node,
                &fixture.owner,
                CustodyMessageType::Offer
            ),
            Err(CustodyMessageRefusal::Oversize)
        );

        // A composition past the config bound is refused before decoding.
        let mut pool = pool_active(2, 3, 1);
        let config = vec![b'{'; MAX_POOL_ACTIVE_CONFIG_BYTES + 1];
        pool.config = base64::engine::general_purpose::STANDARD.encode(&config);
        pool.fingerprint_full = sha256_label(&config);
        let error = prepare(
            &fixture,
            &fixture.owner,
            &fixture.node,
            &CustodyPayload::PoolActive(pool),
        )
        .unwrap_err();
        assert_eq!(refusal(error), CustodyMessageRefusal::InvalidConfig);
    }

    #[test]
    fn unknown_fields_and_non_canonical_bytes_are_refused() {
        let fixture = fixture();
        let offer = |payload: serde_json::Value| {
            sign_raw(
                &fixture.node.device,
                raw_message(
                    &fixture,
                    &fixture.node,
                    &fixture.owner,
                    CUSTODY_OFFER_PAYLOAD_TYPE,
                    payload,
                ),
            )
        };
        let check = |bytes: &[u8]| {
            verify(
                &fixture,
                bytes,
                &fixture.node,
                &fixture.owner,
                CustodyMessageType::Offer,
            )
        };
        let valid = offer(serde_json::json!({
            "location": "Lisbon",
            "provides": ["custody"],
            "run_by": "Node operator",
        }));
        assert!(check(&valid).is_ok());
        // An issuer in the payload is exactly what must never be accepted.
        let with_issuer = offer(serde_json::json!({
            "issuer": fixture.node.did(),
            "location": "Lisbon",
            "provides": ["custody"],
            "run_by": "Node operator",
        }));
        assert_eq!(
            check(&with_issuer),
            Err(CustodyMessageRefusal::InvalidPayload)
        );

        // Re-encoded envelope bytes no longer match the signed canonical form.
        let value: serde_json::Value = serde_json::from_slice(&valid).unwrap();
        let pretty = serde_json::to_vec_pretty(&value).unwrap();
        assert_eq!(check(&pretty), Err(CustodyMessageRefusal::InvalidEnvelope));
        let mut unknown_envelope_field = value.clone();
        unknown_envelope_field["route"] = serde_json::json!("127.0.0.1");
        assert_eq!(
            check(&serde_json::to_vec(&unknown_envelope_field).unwrap()),
            Err(CustodyMessageRefusal::InvalidEnvelope)
        );
        let mut tampered = value;
        tampered["payload"]["payload"]["run_by"] = serde_json::json!("Someone else");
        assert_eq!(
            check(&serde_json::to_vec(&tampered).unwrap()),
            Err(CustodyMessageRefusal::InvalidEnvelope)
        );

        // An explicit null where the canonical form omits the field.
        let mut decision = serde_json::to_value(approved(&fixture.node)).unwrap();
        decision["code"] = serde_json::Value::Null;
        let bytes = sign_raw(
            &fixture.node.device,
            raw_message(
                &fixture,
                &fixture.node,
                &fixture.owner,
                CUSTODY_NODE_DECISION_PAYLOAD_TYPE,
                decision,
            ),
        );
        assert_eq!(
            verify(
                &fixture,
                &bytes,
                &fixture.node,
                &fixture.owner,
                CustodyMessageType::NodeDecision
            ),
            Err(CustodyMessageRefusal::InvalidPayload)
        );
    }

    #[test]
    fn offers_carry_bounded_labels_and_known_roles() {
        let fixture = fixture();
        let check = |offer: CustodyOfferPayload| {
            prepare(
                &fixture,
                &fixture.node,
                &fixture.owner,
                &CustodyPayload::Offer(offer),
            )
            .map_err(refusal)
        };
        let base = CustodyOfferPayload {
            location: "Lisbon".to_string(),
            provides: vec![
                "chain".to_string(),
                "custody".to_string(),
                "ipfs".to_string(),
            ],
            run_by: "Node operator".to_string(),
        };
        assert!(check(base.clone()).is_ok());
        for provides in [
            vec![],
            vec!["custody", "chain"],
            vec!["custody", "custody"],
            vec!["custody", "storage"],
        ] {
            let mut offer = base.clone();
            offer.provides = provides.into_iter().map(String::from).collect();
            assert_eq!(check(offer), Err(CustodyMessageRefusal::InvalidPayload));
        }
        for label in ["", " Lisbon", &"x".repeat(65)] {
            let mut offer = base.clone();
            offer.location = label.to_string();
            assert_eq!(check(offer), Err(CustodyMessageRefusal::InvalidLabels));
            let mut offer = base.clone();
            offer.run_by = label.to_string();
            assert_eq!(check(offer), Err(CustodyMessageRefusal::InvalidLabels));
        }
    }

    #[test]
    fn requests_name_a_preset_term_and_well_formed_ids() {
        let fixture = fixture();
        for term_days in crate::custody_pool_setup::POOL_TERM_DAYS {
            assert!(prepare(
                &fixture,
                &fixture.owner,
                &fixture.node,
                &node_request(term_days)
            )
            .is_ok());
        }
        for term_days in [0, 30, 364, 731, u16::MAX] {
            let error = prepare(
                &fixture,
                &fixture.owner,
                &fixture.node,
                &node_request(term_days),
            )
            .unwrap_err();
            assert_eq!(refusal(error), CustodyMessageRefusal::TermNotOffered);
        }
        // Built by hand, a term outside the presets is still refused on receipt.
        let bytes = sign_raw(
            &fixture.owner.device,
            raw_message(
                &fixture,
                &fixture.owner,
                &fixture.node,
                CUSTODY_NODE_REQUEST_PAYLOAD_TYPE,
                serde_json::json!({
                    "request_id": request_id(),
                    "signing_key_fingerprint_full": sha256_label(b"policy authority"),
                    "term_days": 30,
                }),
            ),
        );
        assert_eq!(
            verify(
                &fixture,
                &bytes,
                &fixture.owner,
                &fixture.node,
                CustodyMessageType::NodeRequest
            ),
            Err(CustodyMessageRefusal::TermNotOffered)
        );

        for (request_id, fingerprint) in [
            (
                "0123456789ABCDEF0123456789ABCDEF".to_string(),
                sha256_label(b"k"),
            ),
            ("0123".to_string(), sha256_label(b"k")),
            (request_id(), "sha256:abc".to_string()),
            (request_id(), sha256_label(b"k").to_uppercase()),
        ] {
            let payload = CustodyPayload::NodeRequest(CustodyNodeRequestPayload {
                request_id,
                signing_key_fingerprint_full: fingerprint,
                term_days: 365,
            });
            let error = prepare(&fixture, &fixture.owner, &fixture.node, &payload).unwrap_err();
            assert_eq!(refusal(error), CustodyMessageRefusal::InvalidPayload);
        }
    }

    #[test]
    fn a_decision_carries_a_card_or_a_code_never_both() {
        let fixture = fixture();
        let check = |decision: CustodyNodeDecisionPayload| {
            prepare(
                &fixture,
                &fixture.node,
                &fixture.owner,
                &CustodyPayload::NodeDecision(decision),
            )
            .map_err(refusal)
        };
        for code in CustodyDeclineCode::ALL {
            assert!(check(declined(code)).is_ok());
        }
        let mut both = approved(&fixture.node);
        both.code = Some(CustodyDeclineCode::Declined);
        assert_eq!(check(both), Err(CustodyMessageRefusal::InvalidDecision));
        let mut neither = approved(&fixture.node);
        neither.card = None;
        assert_eq!(check(neither), Err(CustodyMessageRefusal::InvalidDecision));
        let mut declined_with_card = declined(CustodyDeclineCode::Declined);
        declined_with_card.card = approved(&fixture.node).card;
        declined_with_card.code = None;
        assert_eq!(
            check(declined_with_card),
            Err(CustodyMessageRefusal::InvalidDecision)
        );
        let mut declined_without_code = declined(CustodyDeclineCode::Declined);
        declined_without_code.code = None;
        assert_eq!(
            check(declined_without_code),
            Err(CustodyMessageRefusal::InvalidDecision)
        );

        let mut not_a_card = approved(&fixture.node);
        not_a_card.card = Some("elastos-node-card:v1:not-a-card".to_string());
        assert_eq!(check(not_a_card), Err(CustodyMessageRefusal::InvalidCard));
        let mut bad_hash = approved(&fixture.node);
        bad_hash.request_sha256 = "sha256:00".to_string();
        assert_eq!(check(bad_hash), Err(CustodyMessageRefusal::InvalidPayload));

        // Both, built by hand, are refused on receipt too.
        let mut both = serde_json::to_value(approved(&fixture.node)).unwrap();
        both["code"] = serde_json::json!("declined");
        let bytes = sign_raw(
            &fixture.node.device,
            raw_message(
                &fixture,
                &fixture.node,
                &fixture.owner,
                CUSTODY_NODE_DECISION_PAYLOAD_TYPE,
                both,
            ),
        );
        assert_eq!(
            verify(
                &fixture,
                &bytes,
                &fixture.node,
                &fixture.owner,
                CustodyMessageType::NodeDecision
            ),
            Err(CustodyMessageRefusal::InvalidDecision)
        );
        let mut unknown_code =
            serde_json::to_value(declined(CustodyDeclineCode::Declined)).unwrap();
        unknown_code["code"] = serde_json::json!("busy");
        let bytes = sign_raw(
            &fixture.node.device,
            raw_message(
                &fixture,
                &fixture.node,
                &fixture.owner,
                CUSTODY_NODE_DECISION_PAYLOAD_TYPE,
                unknown_code,
            ),
        );
        assert_eq!(
            verify(
                &fixture,
                &bytes,
                &fixture.node,
                &fixture.owner,
                CustodyMessageType::NodeDecision
            ),
            Err(CustodyMessageRefusal::InvalidPayload)
        );
    }

    #[test]
    fn pool_active_is_count_agnostic() {
        let fixture = fixture();
        let check = |pool: CustodyPoolActivePayload| {
            let payload = CustodyPayload::PoolActive(pool);
            let bytes = prepare(&fixture, &fixture.owner, &fixture.node, &payload)?;
            verify(
                &fixture,
                &bytes,
                &fixture.owner,
                &fixture.node,
                CustodyMessageType::PoolActive,
            )
            .map_err(anyhow::Error::new)
        };
        for (required, total) in [(2, 2), (2, 3), (3, 5), (5, 5), (4, 7)] {
            for share in 1..=total {
                let verified = check(pool_active(required, total, share)).unwrap();
                let CustodyPayload::PoolActive(pool) = verified.payload() else {
                    panic!("pool-active payload expected");
                };
                assert_eq!(pool.members.len(), usize::from(total));
                assert_eq!(pool.share, share);
            }
        }
    }

    #[test]
    fn pool_active_refuses_an_inconsistent_threshold_or_member_list() {
        let fixture = fixture();
        let check = |pool: CustodyPoolActivePayload| {
            prepare(
                &fixture,
                &fixture.owner,
                &fixture.node,
                &CustodyPayload::PoolActive(pool),
            )
            .map_err(refusal)
        };
        for (required, total) in [(0, 3), (4, 3), (0, 0), (1, 3), (2, 17)] {
            let mut pool = pool_active(2, 3, 1);
            pool.threshold = CustodyPoolThreshold { required, total };
            assert_eq!(
                check(pool),
                Err(CustodyMessageRefusal::InvalidThreshold),
                "{required} of {total}"
            );
        }
        // Five members for a pool of three, and three for a pool of five.
        let mut pool = pool_active(3, 5, 1);
        pool.threshold = CustodyPoolThreshold {
            required: 2,
            total: 3,
        };
        assert_eq!(check(pool), Err(CustodyMessageRefusal::InvalidMembers));
        let mut pool = pool_active(3, 5, 1);
        pool.members.truncate(3);
        assert_eq!(check(pool), Err(CustodyMessageRefusal::InvalidMembers));
        let mut pool = pool_active(3, 5, 1);
        pool.members[4].share = 4;
        assert_eq!(check(pool), Err(CustodyMessageRefusal::InvalidMembers));
        let mut pool = pool_active(3, 5, 1);
        pool.members[4].share = 6;
        assert_eq!(check(pool), Err(CustodyMessageRefusal::InvalidMembers));
        let mut pool = pool_active(3, 5, 1);
        pool.members.swap(0, 1);
        assert_eq!(check(pool), Err(CustodyMessageRefusal::InvalidMembers));
        let mut pool = pool_active(3, 5, 1);
        pool.members[2].run_by = String::new();
        assert_eq!(check(pool), Err(CustodyMessageRefusal::InvalidLabels));
        for share in [0, 6] {
            let pool = pool_active(3, 5, share);
            assert_eq!(check(pool), Err(CustodyMessageRefusal::InvalidMembers));
        }

        let mut pool = pool_active(2, 3, 1);
        pool.fingerprint_full = sha256_label(b"another composition");
        assert_eq!(check(pool), Err(CustodyMessageRefusal::FingerprintMismatch));
        let mut pool = pool_active(2, 3, 1);
        pool.config = "not base64!".to_string();
        assert_eq!(check(pool), Err(CustodyMessageRefusal::InvalidConfig));
        let mut pool = pool_active(2, 3, 1);
        pool.config = String::new();
        assert_eq!(check(pool), Err(CustodyMessageRefusal::InvalidConfig));
        // Not a composition, or a pool whose signature does not hold.
        let mut pool = pool_active(2, 3, 1);
        let not_a_composition = br#"{"schema":"elastos.protected-content.custody-composition/v1"}"#;
        pool.config = base64::engine::general_purpose::STANDARD.encode(not_a_composition);
        pool.fingerprint_full = sha256_label(not_a_composition);
        assert_eq!(check(pool), Err(CustodyMessageRefusal::InvalidConfig));
        let window = (POOL_START, POOL_END);
        let flip_last = |encoded: String| {
            let mut bytes = base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .unwrap();
            let last = bytes.len() - 1;
            bytes[last] ^= 0x01;
            base64::engine::general_purpose::STANDARD.encode(bytes)
        };
        let mut parts = composition_parts(2, &[window; 3]);
        parts.pool = flip_last(parts.pool);
        let forged = composition_bytes(parts);
        let pool = pool_active_with_config(&forged, 2, 3, 1, window);
        assert_eq!(check(pool), Err(CustodyMessageRefusal::InvalidConfig));
        let mut parts = composition_parts(2, &[window; 3]);
        parts.epoch = flip_last(parts.epoch);
        let forged = composition_bytes(parts);
        let pool = pool_active_with_config(&forged, 2, 3, 1, window);
        assert_eq!(check(pool), Err(CustodyMessageRefusal::InvalidConfig));
        // An epoch from another issuer than the pool's.
        let mut parts = composition_parts(2, &[window; 3]);
        parts.epoch = composition_parts(2, &[window; 3]).epoch;
        let mixed = composition_bytes(parts);
        let pool = pool_active_with_config(&mixed, 2, 3, 1, window);
        assert_eq!(check(pool), Err(CustodyMessageRefusal::InvalidConfig));
    }

    #[test]
    fn pool_active_size_threshold_and_window_come_from_the_signed_composition() {
        let fixture = fixture();
        let check = |pool: CustodyPoolActivePayload| {
            prepare(
                &fixture,
                &fixture.owner,
                &fixture.node,
                &CustodyPayload::PoolActive(pool),
            )
            .map_err(refusal)
        };
        let window = (POOL_START, POOL_END);
        let mut pool = pool_active(2, 3, 1);
        pool.pool_start += 1;
        assert_eq!(check(pool), Err(CustodyMessageRefusal::CompositionMismatch));
        let mut pool = pool_active(2, 3, 1);
        pool.term_end += 1;
        assert_eq!(check(pool), Err(CustodyMessageRefusal::CompositionMismatch));

        // A signed three-member 2-of-3 pool announced as 5-of-5 with five
        // members, as 3-of-3, and a 3-of-5 announced as 2-of-5.
        let three = composition(2, 3, window);
        let pool = pool_active_with_config(&three, 5, 5, 1, window);
        assert_eq!(check(pool), Err(CustodyMessageRefusal::CompositionMismatch));
        let pool = pool_active_with_config(&three, 3, 3, 1, window);
        assert_eq!(check(pool), Err(CustodyMessageRefusal::CompositionMismatch));
        let five = composition(3, 5, window);
        let pool = pool_active_with_config(&five, 2, 5, 1, window);
        assert_eq!(check(pool), Err(CustodyMessageRefusal::CompositionMismatch));
        assert!(check(pool_active_with_config(&five, 3, 5, 1, window)).is_ok());

        // A signed term already over is not announced.
        let pool = pool_active_at(2, 3, 1, (NOW - 7200, NOW));
        assert_eq!(check(pool), Err(CustodyMessageRefusal::InvalidPoolWindow));
        // Members whose windows do not overlap: the latest start is not
        // before the earliest end.
        let config = composition_bytes(composition_parts(
            2,
            &[(NOW - 100, NOW + 10), (NOW + 20, POOL_END), window],
        ));
        let pool = pool_active_with_config(&config, 2, 3, 1, (NOW + 20, NOW + 10));
        assert_eq!(check(pool), Err(CustodyMessageRefusal::InvalidPoolWindow));
        // A far-future start would pin the ordering; clock skew is allowed.
        let pool = pool_active_at(2, 3, 1, (NOW + 3_600, POOL_END));
        assert_eq!(check(pool), Err(CustodyMessageRefusal::InvalidPoolWindow));
        let skew = MAX_COLLABORATION_CLOCK_SKEW_SECS;
        let pool = pool_active_at(2, 3, 1, (NOW + skew + 1, POOL_END));
        assert_eq!(check(pool), Err(CustodyMessageRefusal::InvalidPoolWindow));
        assert!(check(pool_active_at(2, 3, 1, (NOW + skew, POOL_END))).is_ok());
    }

    #[test]
    fn only_a_later_signed_pool_replaces_a_stored_notice() {
        let fixture = fixture();
        let verified = |pool: CustodyPoolActivePayload| {
            let bytes = prepare(
                &fixture,
                &fixture.owner,
                &fixture.node,
                &CustodyPayload::PoolActive(pool),
            )
            .unwrap();
            let verified = verify(
                &fixture,
                &bytes,
                &fixture.owner,
                &fixture.node,
                CustodyMessageType::PoolActive,
            )
            .unwrap();
            match verified.payload() {
                CustodyPayload::PoolActive(pool) => pool.clone(),
                other => panic!("pool-active payload expected, got {other:?}"),
            }
        };
        let older = verified(pool_active_at(2, 3, 1, (NOW - 1_000, POOL_END)));
        let newer = verified(pool_active_at(2, 3, 2, (NOW - 60, POOL_END)));
        let same_age = verified(pool_active_at(2, 3, 1, (NOW - 60, POOL_END)));
        assert_ne!(newer.fingerprint_full, same_age.fingerprint_full);

        assert!(pool_active_is_newer(&older, &newer));
        assert!(!pool_active_is_newer(&newer, &older));
        assert!(!pool_active_is_newer(&newer, &same_age));
        assert!(!pool_active_is_newer(&newer, &newer));
    }
}
