//! Pool contracts (Plan B T1.1): the signed pool descriptor, the recipient
//! attestation a pool node signs for one session key, the pool address, the
//! buyer's delivery key identity and the viewer-part AAD.
//!
//! A pool descriptor carries the pool's custody committees as the exact
//! signed V1 bundles (custody pool, epoch, committee authorization). It binds
//! to an item only through [`PoolEpochBundleV1::matches_key_envelope`], and
//! its bundles are checked with the release rule
//! ([`crate::validate_custody_epoch_for_release_at`]): the pool term stops new
//! provisioning, not releases (D5).

use std::collections::HashSet;

use ed25519_dalek::Signature;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::canonical::{validate_ascii_identifier, CanonicalBody, ContractError, Decoder, Encoder};
use crate::custody_envelope::{
    validate_pq_hybrid_wrap_public_key, PQ_HYBRID_WRAP_PUBLIC_KEY_BYTES,
};
use crate::identity::validate_ed25519_public_key;
use crate::rights::{validate_active, validate_time_window, RightsActionV1, RightsError};
use crate::{
    validate_custody_epoch_against_pool_at, validate_custody_epoch_for_release_at,
    CanonicalContract, CustodyEpochIdentityV1, CustodyEpochIssuerKeyV1, CustodyPoolError, Digest32,
    KeyEnvelopeIdentityV1, NodePublicKey, ProtectedContentBindingV1, RecipientKeyIdentityV1,
    RecipientPublicKeyBytesV1, RuntimeOperationIssuerKeyV1, SignedCustodyCommitteeAuthorizationV1,
    SignedCustodyEpochV1, SignedCustodyPoolV1, ValidatedCustodyCommitteeV1, VerifiedCustodyEpochV1,
    MAX_RECIPIENT_KEY_AUTHORIZATION_LIFETIME_SECS,
};

/// Structure check on the descriptor's committees (L9).
pub const MAX_POOL_DESCRIPTOR_EPOCHS_V1: usize = 4;
/// Structure check on the descriptor's members (L9).
pub const MAX_POOL_MEMBERS_V1: usize = 16;
pub const MAX_POOL_DESCRIPTOR_LIFETIME_SECS: u64 = 30 * 86_400;
/// The most recipients (servers) one V2 session may name.
pub const MAX_SESSION_RECIPIENTS_V2: usize = 4;
/// The signed descriptor's canonical size, checked in `new` and in decode (L9).
pub const MAX_SIGNED_POOL_DESCRIPTOR_BYTES_V1: usize = 40 * 1024;
/// Structure check inside the 40 KiB cap (64 × 32 B).
pub const MAX_ADMITTED_MINTERS_V1: usize = 64;
/// As the Runtime's peer DID limit for custody nodes (L16).
pub const MAX_POOL_MEMBER_PEER_DID_BYTES_V1: usize = 256;
/// Historical v1 reads only: v2 routes carry no ticket (item 10).
pub const MAX_POOL_MEMBER_CONNECT_TICKET_BYTES_V1: usize = 2048;
/// The sealer concurrency default of `MintPolicyV1::owner_default`.
pub const DEFAULT_MAX_SEALS_PER_SEALER_V1: u8 = 8;
/// The highest DASH rendition index a viewer part may name.
pub const MAX_VIEWER_DASH_RENDITION_V1: u8 = 1;
/// #388 A2 (A388-F4): the reserved ceiling of one trust attestation slot
/// (a descriptor member's `attestation`, a recipient attestation's
/// `evidence`). A field ceiling only: under [`PoolTrustModeV1::WciOperated`]
/// every slot is 0 bytes, and no existing cap is raised.
pub const MAX_TRUST_ATTESTATION_BYTES_V1: usize = 16 * 1024;

const ED25519_SIGNATURE_BYTES: usize = 64;
const DELIVERY_KEY_IDENTITY_DOMAIN_V1: &str = "elastos.protected-content.delivery-key-identity/v1";

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PoolContractError {
    #[error(transparent)]
    Contract(#[from] ContractError),
    #[error(transparent)]
    CustodyPool(#[from] CustodyPoolError),
    #[error("pool signature is invalid")]
    Signature,
    #[error("pool authority is not yet valid")]
    NotYetValid,
    #[error("pool authority expired")]
    Expired,
    #[error("node is not a member of the pool")]
    NotMember,
    #[error("pool member does not hold the required role")]
    RoleMissing,
    #[error("pool epoch does not match")]
    EpochMismatch,
    #[error("pool does not match")]
    IssuerMismatch,
    #[error("pool allows fewer servers")]
    TooMany,
    /// #388 A2: a new admission needs a v3 descriptor whose trust is
    /// `WciOperated` with every slot empty, and v2 recipient attestations of
    /// that mode. Historical formats (trust absent) only read.
    #[error("pool host trust is required")]
    TrustRequired,
}

/// #388 A2: how the pool's hosts are trusted. `WciOperated` is an operator
/// assertion; `AttestedTee` is reserved for #467 and refused for now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum PoolTrustModeV1 {
    WciOperated = 1,
    AttestedTee = 2,
}

impl PoolTrustModeV1 {
    pub const fn code(self) -> u8 {
        self as u8
    }

    pub fn from_code(code: u8) -> Result<Self, ContractError> {
        match code {
            1 => Ok(Self::WciOperated),
            2 => Ok(Self::AttestedTee),
            _ => Err(ContractError::InvalidField("trust_mode")),
        }
    }
}

/// One trust slot under `mode` (A388-F4): at most the reserved ceiling, empty
/// under `WciOperated`; `AttestedTee` is refused.
fn validate_trust_slot(
    mode: PoolTrustModeV1,
    slot: &[u8],
    field: &'static str,
) -> Result<(), ContractError> {
    if slot.len() > MAX_TRUST_ATTESTATION_BYTES_V1 {
        return Err(ContractError::FieldTooLong(field));
    }
    match mode {
        PoolTrustModeV1::WciOperated if slot.is_empty() => Ok(()),
        PoolTrustModeV1::WciOperated => Err(ContractError::InvalidField(field)),
        PoolTrustModeV1::AttestedTee => Err(ContractError::InvalidField("trust_mode")),
    }
}

/// A v3 descriptor's trust, as its verified form exposes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolTrustV1 {
    mode: PoolTrustModeV1,
    /// One slot per member, in member order.
    member_attestations: Vec<Vec<u8>>,
}

impl PoolTrustV1 {
    pub const fn mode(&self) -> PoolTrustModeV1 {
        self.mode
    }

    pub fn member_attestations(&self) -> &[Vec<u8>] {
        &self.member_attestations
    }
}

/// `validate_active` (E1): a short skew before the start, none at the end.
fn map_window(issued_at: u64, expires_at: u64, now: u64) -> Result<(), PoolContractError> {
    match validate_active(issued_at, expires_at, now) {
        Ok(()) => Ok(()),
        Err(RightsError::NotYetValid) => Err(PoolContractError::NotYetValid),
        Err(RightsError::Contract(error)) => Err(PoolContractError::Contract(error)),
        // `validate_active` answers only NotYetValid and Expired.
        Err(_) => Err(PoolContractError::Expired),
    }
}

fn verify_ed25519(
    public_key: [u8; 32],
    message: &[u8],
    signature: &[u8],
) -> Result<(), PoolContractError> {
    let key = validate_ed25519_public_key(public_key, "pool_signer")
        .map_err(|_| PoolContractError::Signature)?;
    let signature = Signature::from_slice(signature).map_err(|_| PoolContractError::Signature)?;
    key.verify_strict(message, &signature)
        .map_err(|_| PoolContractError::Signature)
}

fn encode_bool(encoder: &mut Encoder, value: bool) {
    encoder.u8(u8::from(value));
}

fn decode_bool(decoder: &mut Decoder<'_>, field: &'static str) -> Result<bool, ContractError> {
    match decoder.u8()? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(ContractError::InvalidField(field)),
    }
}

fn encode_count(
    encoder: &mut Encoder,
    count: usize,
    field: &'static str,
) -> Result<(), ContractError> {
    encoder.u8(u8::try_from(count).map_err(|_| ContractError::InvalidField(field))?);
    Ok(())
}

fn decode_count(
    decoder: &mut Decoder<'_>,
    maximum: usize,
    field: &'static str,
) -> Result<usize, ContractError> {
    let count = usize::from(decoder.u8()?);
    if count > maximum {
        return Err(ContractError::InvalidField(field));
    }
    Ok(count)
}

/// The pool's identity: the pool authority key, shown as `did:key`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PoolDidV1(CustodyEpochIssuerKeyV1);

impl PoolDidV1 {
    pub const fn from_issuer(issuer: CustodyEpochIssuerKeyV1) -> Self {
        Self(issuer)
    }

    pub const fn issuer(&self) -> CustodyEpochIssuerKeyV1 {
        self.0
    }

    pub fn to_did_key(&self) -> Result<String, ContractError> {
        let key = validate_ed25519_public_key(*self.0.as_bytes(), "pool_did")?;
        elastos_identity::encode_did_key(&key).map_err(|_| ContractError::InvalidField("pool_did"))
    }

    pub fn parse_did_key(did: &str) -> Result<Self, ContractError> {
        let key = elastos_identity::decode_did_key(did)
            .map_err(|_| ContractError::InvalidField("pool_did"))?;
        Ok(Self(CustodyEpochIssuerKeyV1::new(key.to_bytes())?))
    }

    fn encode(&self, encoder: &mut Encoder) {
        encoder.fixed(self.0.as_bytes());
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, ContractError> {
        Ok(Self(CustodyEpochIssuerKeyV1::new(decoder.fixed()?)?))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PoolMemberRolesV1 {
    pub hold: bool,
    pub serve: bool,
    pub seal: bool,
}

impl PoolMemberRolesV1 {
    const HOLD: u8 = 1;
    const SERVE: u8 = 2;
    const SEAL: u8 = 4;

    fn validate(self) -> Result<(), ContractError> {
        if !(self.hold || self.serve || self.seal) {
            return Err(ContractError::InvalidField("pool_member.roles"));
        }
        Ok(())
    }

    fn bits(self) -> u8 {
        (if self.hold { Self::HOLD } else { 0 })
            | (if self.serve { Self::SERVE } else { 0 })
            | (if self.seal { Self::SEAL } else { 0 })
    }

    fn from_bits(bits: u8) -> Result<Self, ContractError> {
        if bits & !(Self::HOLD | Self::SERVE | Self::SEAL) != 0 {
            return Err(ContractError::InvalidField("pool_member.roles"));
        }
        let roles = Self {
            hold: bits & Self::HOLD != 0,
            serve: bits & Self::SERVE != 0,
            seal: bits & Self::SEAL != 0,
        };
        roles.validate()?;
        Ok(roles)
    }
}

/// How a pool member is reached over Carrier, in the historical v1 format.
/// Decoded for reads only; writers emit [`PoolMemberRouteV2`] (item 10).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PoolMemberRouteV1 {
    peer_did: String,
    /// `None` when no node card was kept (E3).
    connect_ticket: Option<String>,
}

impl PoolMemberRouteV1 {
    pub fn new(peer_did: String, connect_ticket: Option<String>) -> Result<Self, ContractError> {
        let value = Self {
            peer_did,
            connect_ticket,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn peer_did(&self) -> &str {
        &self.peer_did
    }

    pub fn connect_ticket(&self) -> Option<&str> {
        self.connect_ticket.as_deref()
    }

    fn validate(&self) -> Result<(), ContractError> {
        validate_ascii_identifier(
            &self.peer_did,
            "pool_member.peer_did",
            MAX_POOL_MEMBER_PEER_DID_BYTES_V1,
        )?;
        if let Some(ticket) = &self.connect_ticket {
            validate_ascii_identifier(
                ticket,
                "pool_member.connect_ticket",
                MAX_POOL_MEMBER_CONNECT_TICKET_BYTES_V1,
            )?;
        }
        Ok(())
    }

    fn encode(&self, encoder: &mut Encoder) -> Result<(), ContractError> {
        encoder.string(&self.peer_did)?;
        match &self.connect_ticket {
            None => encoder.u8(0),
            Some(ticket) => {
                encoder.u8(1);
                encoder.string(ticket)?;
            }
        }
        Ok(())
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, ContractError> {
        let peer_did = decoder.string("pool_member.peer_did", MAX_POOL_MEMBER_PEER_DID_BYTES_V1)?;
        let connect_ticket = match decoder.u8()? {
            0 => None,
            1 => Some(decoder.string(
                "pool_member.connect_ticket",
                MAX_POOL_MEMBER_CONNECT_TICKET_BYTES_V1,
            )?),
            _ => return Err(ContractError::InvalidField("pool_member.connect_ticket")),
        };
        Self::new(peer_did, connect_ticket)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolMemberV1 {
    node_public_key: NodePublicKey,
    roles: PoolMemberRolesV1,
    route: PoolMemberRouteV1,
}

impl PoolMemberV1 {
    pub fn new(
        node_public_key: NodePublicKey,
        roles: PoolMemberRolesV1,
        route: PoolMemberRouteV1,
    ) -> Result<Self, ContractError> {
        let value = Self {
            node_public_key,
            roles,
            route,
        };
        value.validate()?;
        Ok(value)
    }

    pub const fn node_public_key(&self) -> NodePublicKey {
        self.node_public_key
    }

    pub const fn roles(&self) -> PoolMemberRolesV1 {
        self.roles
    }

    pub fn route(&self) -> &PoolMemberRouteV1 {
        &self.route
    }

    fn validate(&self) -> Result<(), ContractError> {
        NodePublicKey::new(*self.node_public_key.as_bytes())?;
        self.roles.validate()?;
        self.route.validate()
    }

    fn encode(&self, encoder: &mut Encoder) -> Result<(), ContractError> {
        encoder.fixed(self.node_public_key.as_bytes());
        encoder.u8(self.roles.bits());
        self.route.encode(encoder)
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, ContractError> {
        let node_public_key = NodePublicKey::new(decoder.fixed()?)?;
        let roles = PoolMemberRolesV1::from_bits(decoder.u8()?)?;
        Self::new(node_public_key, roles, PoolMemberRouteV1::decode(decoder)?)
    }
}

/// How a pool member is reached (item 10): its Carrier peer DID only. A buyer
/// finds the member through Carrier discovery; a pool member uses the node
/// card it kept.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PoolMemberRouteV2 {
    peer_did: String,
}

impl PoolMemberRouteV2 {
    pub fn new(peer_did: String) -> Result<Self, ContractError> {
        let value = Self { peer_did };
        value.validate()?;
        Ok(value)
    }

    pub fn peer_did(&self) -> &str {
        &self.peer_did
    }

    fn validate(&self) -> Result<(), ContractError> {
        validate_ascii_identifier(
            &self.peer_did,
            "pool_member.peer_did",
            MAX_POOL_MEMBER_PEER_DID_BYTES_V1,
        )
    }

    fn encode(&self, encoder: &mut Encoder) -> Result<(), ContractError> {
        encoder.string(&self.peer_did)
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, ContractError> {
        Self::new(decoder.string("pool_member.peer_did", MAX_POOL_MEMBER_PEER_DID_BYTES_V1)?)
    }
}

/// A pool member with a ticketless route (item 10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolMemberV2 {
    node_public_key: NodePublicKey,
    roles: PoolMemberRolesV1,
    route: PoolMemberRouteV2,
}

impl PoolMemberV2 {
    pub fn new(
        node_public_key: NodePublicKey,
        roles: PoolMemberRolesV1,
        route: PoolMemberRouteV2,
    ) -> Result<Self, ContractError> {
        let value = Self {
            node_public_key,
            roles,
            route,
        };
        value.validate()?;
        Ok(value)
    }

    pub const fn node_public_key(&self) -> NodePublicKey {
        self.node_public_key
    }

    pub const fn roles(&self) -> PoolMemberRolesV1 {
        self.roles
    }

    pub fn route(&self) -> &PoolMemberRouteV2 {
        &self.route
    }

    fn validate(&self) -> Result<(), ContractError> {
        NodePublicKey::new(*self.node_public_key.as_bytes())?;
        self.roles.validate()?;
        self.route.validate()
    }

    fn encode(&self, encoder: &mut Encoder) -> Result<(), ContractError> {
        encoder.fixed(self.node_public_key.as_bytes());
        encoder.u8(self.roles.bits());
        self.route.encode(encoder)
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, ContractError> {
        let node_public_key = NodePublicKey::new(decoder.fixed()?)?;
        let roles = PoolMemberRolesV1::from_bits(decoder.u8()?)?;
        Self::new(node_public_key, roles, PoolMemberRouteV2::decode(decoder)?)
    }
}

/// A member in one descriptor format. Only the route differs: v1 carries an
/// optional connect ticket, v2 the peer DID only (item 10).
trait DescriptorMember: Sized {
    fn member_key(&self) -> NodePublicKey;
    fn check(&self) -> Result<(), ContractError>;
    fn put(&self, encoder: &mut Encoder) -> Result<(), ContractError>;
    fn take(decoder: &mut Decoder<'_>) -> Result<Self, ContractError>;
    /// The member a verified descriptor exposes: never a v1 ticket.
    fn ticketless(&self) -> PoolMemberV2;
    /// The member's trust attestation slot (#388 A2); v1 and v2 have none.
    fn slot(&self) -> &[u8] {
        &[]
    }
}

/// A pool member of the v3 descriptor (#388 A2): the ticketless v2 member and
/// its trust attestation slot (u16 length; empty under `WciOperated`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolMemberV3 {
    member: PoolMemberV2,
    attestation: Vec<u8>,
}

impl PoolMemberV3 {
    pub fn new(member: PoolMemberV2, attestation: Vec<u8>) -> Result<Self, ContractError> {
        let value = Self {
            member,
            attestation,
        };
        value.validate()?;
        Ok(value)
    }

    pub const fn node_public_key(&self) -> NodePublicKey {
        self.member.node_public_key
    }

    pub const fn roles(&self) -> PoolMemberRolesV1 {
        self.member.roles
    }

    pub fn route(&self) -> &PoolMemberRouteV2 {
        &self.member.route
    }

    pub fn member(&self) -> &PoolMemberV2 {
        &self.member
    }

    pub fn attestation(&self) -> &[u8] {
        &self.attestation
    }

    fn validate(&self) -> Result<(), ContractError> {
        self.member.validate()?;
        if self.attestation.len() > MAX_TRUST_ATTESTATION_BYTES_V1 {
            return Err(ContractError::FieldTooLong("attestation"));
        }
        Ok(())
    }
}

impl DescriptorMember for PoolMemberV3 {
    fn member_key(&self) -> NodePublicKey {
        self.member.node_public_key
    }

    fn check(&self) -> Result<(), ContractError> {
        PoolMemberV3::validate(self)
    }

    fn put(&self, encoder: &mut Encoder) -> Result<(), ContractError> {
        self.member.encode(encoder)?;
        encoder.bytes(&self.attestation)
    }

    fn take(decoder: &mut Decoder<'_>) -> Result<Self, ContractError> {
        let member = PoolMemberV2::decode(decoder)?;
        let attestation = decoder.bytes("attestation", MAX_TRUST_ATTESTATION_BYTES_V1)?;
        Self::new(member, attestation)
    }

    fn ticketless(&self) -> PoolMemberV2 {
        self.member.clone()
    }

    fn slot(&self) -> &[u8] {
        &self.attestation
    }
}

impl DescriptorMember for PoolMemberV1 {
    fn member_key(&self) -> NodePublicKey {
        self.node_public_key
    }

    fn check(&self) -> Result<(), ContractError> {
        PoolMemberV1::validate(self)
    }

    fn put(&self, encoder: &mut Encoder) -> Result<(), ContractError> {
        PoolMemberV1::encode(self, encoder)
    }

    fn take(decoder: &mut Decoder<'_>) -> Result<Self, ContractError> {
        PoolMemberV1::decode(decoder)
    }

    fn ticketless(&self) -> PoolMemberV2 {
        PoolMemberV2 {
            node_public_key: self.node_public_key,
            roles: self.roles,
            route: PoolMemberRouteV2 {
                peer_did: self.route.peer_did.clone(),
            },
        }
    }
}

impl DescriptorMember for PoolMemberV2 {
    fn member_key(&self) -> NodePublicKey {
        self.node_public_key
    }

    fn check(&self) -> Result<(), ContractError> {
        PoolMemberV2::validate(self)
    }

    fn put(&self, encoder: &mut Encoder) -> Result<(), ContractError> {
        PoolMemberV2::encode(self, encoder)
    }

    fn take(decoder: &mut Decoder<'_>) -> Result<Self, ContractError> {
        PoolMemberV2::decode(decoder)
    }

    fn ticketless(&self) -> PoolMemberV2 {
        self.clone()
    }
}

/// One custody committee of the pool, as the exact signed V1 objects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolEpochBundleV1 {
    signed_pool: SignedCustodyPoolV1,
    signed_epoch: SignedCustodyEpochV1,
    signed_committee_authorization: SignedCustodyCommitteeAuthorizationV1,
}

impl PoolEpochBundleV1 {
    pub fn new(
        signed_pool: SignedCustodyPoolV1,
        signed_epoch: SignedCustodyEpochV1,
        signed_committee_authorization: SignedCustodyCommitteeAuthorizationV1,
    ) -> Result<Self, ContractError> {
        let value = Self {
            signed_pool,
            signed_epoch,
            signed_committee_authorization,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn signed_pool(&self) -> &SignedCustodyPoolV1 {
        &self.signed_pool
    }

    pub fn signed_epoch(&self) -> &SignedCustodyEpochV1 {
        &self.signed_epoch
    }

    pub fn signed_committee_authorization(&self) -> &SignedCustodyCommitteeAuthorizationV1 {
        &self.signed_committee_authorization
    }

    pub fn epoch_identity(&self) -> Result<CustodyEpochIdentityV1, ContractError> {
        self.signed_epoch.epoch_identity()
    }

    /// The only binding from a pool to an item (L3): the item's key envelope
    /// names this bundle's custody pool, epoch and committee authorization.
    pub fn matches_key_envelope(
        &self,
        key_envelope: &KeyEnvelopeIdentityV1,
    ) -> Result<bool, ContractError> {
        Ok(
            self.signed_pool.pool_identity()? == key_envelope.custody_pool()
                && self.signed_epoch.epoch_identity()? == key_envelope.custody_epoch()
                && self
                    .signed_committee_authorization
                    .authorization_identity()?
                    == key_envelope.custody_committee_authorization(),
        )
    }

    /// The release rule with the bundle's own authorization identity (L3, F1).
    fn validate_for_release(
        &self,
        authority: CustodyEpochIssuerKeyV1,
        now: u64,
    ) -> Result<ValidatedCustodyCommitteeV1, PoolContractError> {
        Ok(validate_custody_epoch_for_release_at(
            authority,
            self.signed_committee_authorization
                .authorization_identity()?,
            &self.signed_pool,
            &self.signed_epoch,
            &self.signed_committee_authorization,
            now,
        )?)
    }

    /// The provisioning rule (POOL-MINT): the pool term is open at `now`
    /// (`validate_custody_epoch_against_pool_at`).
    fn validate_for_provisioning(
        &self,
        authority: CustodyEpochIssuerKeyV1,
        now: u64,
    ) -> Result<ValidatedCustodyCommitteeV1, PoolContractError> {
        Ok(validate_custody_epoch_against_pool_at(
            authority,
            self.signed_committee_authorization
                .authorization_identity()?,
            &self.signed_pool,
            &self.signed_epoch,
            &self.signed_committee_authorization,
            now,
        )?)
    }

    fn validate(&self) -> Result<(), ContractError> {
        let statement = self.signed_committee_authorization.statement();
        if statement.pool_identity() != self.signed_pool.pool_identity()?
            || statement.custody_epoch_identity() != self.signed_epoch.epoch_identity()?
        {
            return Err(ContractError::InvalidField("pool_epoch_bundle"));
        }
        Ok(())
    }

    fn encode(&self, encoder: &mut Encoder) -> Result<(), ContractError> {
        encoder.nested(&self.signed_pool)?;
        encoder.nested(&self.signed_epoch)?;
        encoder.nested(&self.signed_committee_authorization)
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, ContractError> {
        Self::new(
            decoder.nested("signed_custody_pool")?,
            decoder.nested("signed_custody_epoch")?,
            decoder.nested("signed_custody_committee_authorization")?,
        )
    }
}

/// D1, D2 serve-side bounds of one session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionBoundsV1 {
    pub byte_rate_multiplier: u8,
    pub total_bytes_multiplier: u8,
    pub read_ahead_segments: u16,
    pub max_sessions_per_wallet_kid: u8,
    pub max_sessions_per_wallet: u8,
    pub max_sessions_per_endpoint: u8,
}

impl SessionBoundsV1 {
    pub const DEFAULT: Self = Self {
        byte_rate_multiplier: 2,
        total_bytes_multiplier: 3,
        read_ahead_segments: 6,
        max_sessions_per_wallet_kid: 2,
        max_sessions_per_wallet: 8,
        max_sessions_per_endpoint: 16,
    };

    fn validate(&self) -> Result<(), ContractError> {
        if self.byte_rate_multiplier == 0
            || self.total_bytes_multiplier == 0
            || self.read_ahead_segments == 0
            || self.max_sessions_per_wallet_kid == 0
            || self.max_sessions_per_wallet == 0
            || self.max_sessions_per_endpoint == 0
        {
            return Err(ContractError::InvalidField("serve_policy.bounds"));
        }
        Ok(())
    }

    fn encode(&self, encoder: &mut Encoder) {
        encoder.u8(self.byte_rate_multiplier);
        encoder.u8(self.total_bytes_multiplier);
        encoder.u16(self.read_ahead_segments);
        encoder.u8(self.max_sessions_per_wallet_kid);
        encoder.u8(self.max_sessions_per_wallet);
        encoder.u8(self.max_sessions_per_endpoint);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, ContractError> {
        Ok(Self {
            byte_rate_multiplier: decoder.u8()?,
            total_bytes_multiplier: decoder.u8()?,
            read_ahead_segments: decoder.u16()?,
            max_sessions_per_wallet_kid: decoder.u8()?,
            max_sessions_per_wallet: decoder.u8()?,
            max_sessions_per_endpoint: decoder.u8()?,
        })
    }
}

/// D1, D2: who serves a session and how many servers one session may use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ServePolicyV1 {
    pub max_servers_per_session: u8,
    pub allow_self_serve: bool,
    pub bounds: SessionBoundsV1,
}

impl ServePolicyV1 {
    pub const DEFAULT: Self = Self {
        max_servers_per_session: 1,
        allow_self_serve: false,
        bounds: SessionBoundsV1::DEFAULT,
    };

    fn validate(&self) -> Result<(), ContractError> {
        if self.max_servers_per_session == 0
            || usize::from(self.max_servers_per_session) > MAX_SESSION_RECIPIENTS_V2
        {
            return Err(ContractError::InvalidField(
                "serve_policy.max_servers_per_session",
            ));
        }
        self.bounds.validate()
    }

    fn encode(&self, encoder: &mut Encoder) {
        encoder.u8(self.max_servers_per_session);
        encode_bool(encoder, self.allow_self_serve);
        self.bounds.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, ContractError> {
        Ok(Self {
            max_servers_per_session: decoder.u8()?,
            allow_self_serve: decode_bool(decoder, "serve_policy.allow_self_serve")?,
            bounds: SessionBoundsV1::decode(decoder)?,
        })
    }
}

/// D2, D4 (admission only; there is no mint quota, user S7-U1).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MintPolicyV1 {
    /// Unique, at most [`MAX_ADMITTED_MINTERS_V1`]; the descriptor keeps them
    /// in key-byte order.
    pub admitted_minters: Vec<RuntimeOperationIssuerKeyV1>,
    pub allow_self_seal: bool,
    /// The sealer's concurrency limit (not a quota).
    pub max_seals_per_sealer: u8,
}

impl MintPolicyV1 {
    pub fn owner_default(owner: RuntimeOperationIssuerKeyV1) -> Self {
        Self {
            admitted_minters: vec![owner],
            allow_self_seal: false,
            max_seals_per_sealer: DEFAULT_MAX_SEALS_PER_SEALER_V1,
        }
    }

    fn sort(&mut self) {
        self.admitted_minters
            .sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    }

    fn validate(&self) -> Result<(), ContractError> {
        if self.admitted_minters.len() > MAX_ADMITTED_MINTERS_V1
            || self
                .admitted_minters
                .windows(2)
                .any(|pair| pair[0].as_bytes() >= pair[1].as_bytes())
        {
            return Err(ContractError::InvalidField("mint_policy.admitted_minters"));
        }
        for minter in &self.admitted_minters {
            RuntimeOperationIssuerKeyV1::new(*minter.as_bytes())?;
        }
        if self.max_seals_per_sealer == 0 {
            return Err(ContractError::InvalidField(
                "mint_policy.max_seals_per_sealer",
            ));
        }
        Ok(())
    }

    fn encode(&self, encoder: &mut Encoder) -> Result<(), ContractError> {
        encode_count(
            encoder,
            self.admitted_minters.len(),
            "mint_policy.admitted_minters",
        )?;
        for minter in &self.admitted_minters {
            encoder.fixed(minter.as_bytes());
        }
        encode_bool(encoder, self.allow_self_seal);
        encoder.u8(self.max_seals_per_sealer);
        Ok(())
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, ContractError> {
        let count = decode_count(
            decoder,
            MAX_ADMITTED_MINTERS_V1,
            "mint_policy.admitted_minters",
        )?;
        let mut admitted_minters = Vec::with_capacity(count);
        for _ in 0..count {
            admitted_minters.push(RuntimeOperationIssuerKeyV1::new(decoder.fixed()?)?);
        }
        Ok(Self {
            admitted_minters,
            allow_self_seal: decode_bool(decoder, "mint_policy.allow_self_seal")?,
            max_seals_per_sealer: decoder.u8()?,
        })
    }
}

/// The fields of both descriptor statement versions, in signed order. Only
/// the member route differs between v1 and v2 (item 10).
#[derive(Debug, Clone, PartialEq, Eq)]
struct DescriptorBody<M> {
    pool: PoolDidV1,
    sequence: u64,
    epochs: Vec<PoolEpochBundleV1>,
    members: Vec<M>,
    serve_policy: ServePolicyV1,
    mint_policy: MintPolicyV1,
    issued_at: u64,
    expires_at: u64,
}

impl<M: DescriptorMember> DescriptorBody<M> {
    /// Members are kept in node-key order and admitted minters in key-byte
    /// order; duplicates are refused.
    #[allow(clippy::too_many_arguments)]
    fn new(
        pool: PoolDidV1,
        sequence: u64,
        epochs: Vec<PoolEpochBundleV1>,
        mut members: Vec<M>,
        serve_policy: ServePolicyV1,
        mut mint_policy: MintPolicyV1,
        issued_at: u64,
        expires_at: u64,
    ) -> Result<Self, ContractError> {
        members.sort_unstable_by_key(M::member_key);
        mint_policy.sort();
        let value = Self {
            pool,
            sequence,
            epochs,
            members,
            serve_policy,
            mint_policy,
            issued_at,
            expires_at,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), ContractError> {
        CustodyEpochIssuerKeyV1::new(*self.pool.issuer().as_bytes())?;
        if self.epochs.is_empty() || self.epochs.len() > MAX_POOL_DESCRIPTOR_EPOCHS_V1 {
            return Err(ContractError::InvalidField("pool_descriptor.epochs"));
        }
        let mut epoch_identities = HashSet::with_capacity(self.epochs.len());
        for bundle in &self.epochs {
            bundle.validate()?;
            if !epoch_identities.insert(bundle.epoch_identity()?) {
                return Err(ContractError::InvalidField("pool_descriptor.epochs"));
            }
        }
        if self.members.is_empty() || self.members.len() > MAX_POOL_MEMBERS_V1 {
            return Err(ContractError::InvalidField("pool_descriptor.members"));
        }
        for member in &self.members {
            member.check()?;
        }
        if self
            .members
            .windows(2)
            .any(|pair| pair[0].member_key() >= pair[1].member_key())
        {
            return Err(ContractError::InvalidField("pool_descriptor.members"));
        }
        self.serve_policy.validate()?;
        self.mint_policy.validate()?;
        validate_time_window(
            self.issued_at,
            self.expires_at,
            MAX_POOL_DESCRIPTOR_LIFETIME_SECS,
            "pool_descriptor_lifetime",
        )
    }

    fn encode(&self, encoder: &mut Encoder) -> Result<(), ContractError> {
        self.pool.encode(encoder);
        encoder.u64(self.sequence);
        encode_count(encoder, self.epochs.len(), "pool_descriptor.epochs")?;
        for bundle in &self.epochs {
            bundle.encode(encoder)?;
        }
        encode_count(encoder, self.members.len(), "pool_descriptor.members")?;
        for member in &self.members {
            member.put(encoder)?;
        }
        self.serve_policy.encode(encoder);
        self.mint_policy.encode(encoder)?;
        encoder.u64(self.issued_at);
        encoder.u64(self.expires_at);
        Ok(())
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, ContractError> {
        let pool = PoolDidV1::decode(decoder)?;
        let sequence = decoder.u64()?;
        let epoch_count = decode_count(
            decoder,
            MAX_POOL_DESCRIPTOR_EPOCHS_V1,
            "pool_descriptor.epochs",
        )?;
        let mut epochs = Vec::with_capacity(epoch_count);
        for _ in 0..epoch_count {
            epochs.push(PoolEpochBundleV1::decode(decoder)?);
        }
        let member_count = decode_count(decoder, MAX_POOL_MEMBERS_V1, "pool_descriptor.members")?;
        let mut members = Vec::with_capacity(member_count);
        for _ in 0..member_count {
            members.push(M::take(decoder)?);
        }
        let serve_policy = ServePolicyV1::decode(decoder)?;
        let mint_policy = MintPolicyV1::decode(decoder)?;
        Self::new(
            pool,
            sequence,
            epochs,
            members,
            serve_policy,
            mint_policy,
            decoder.u64()?,
            decoder.u64()?,
        )
    }

    /// Verifies the descriptor at the verifier's own clock `now`:
    /// - the pool authority signed `statement_bytes`, the exact canonical
    ///   bytes of this statement in its own version;
    /// - its window is open (`validate_active`, E1);
    /// - every bundle passes the release rule with the pool authority and
    ///   the bundle's own authorization identity (L3, F1); the 2-of-3 rule
    ///   stays in that one place (L2);
    /// - every member is in at least one committee;
    /// - `max_servers_per_session` is at most the smallest committee total
    ///   and [`MAX_SESSION_RECIPIENTS_V2`] (L2).
    ///
    /// The verified form is the same in both versions and carries no ticket
    /// (item 10).
    fn verify(
        &self,
        statement_bytes: &[u8],
        authority_signature: &[u8],
        now: u64,
    ) -> Result<VerifiedPoolDescriptorV1, PoolContractError> {
        let authority = self.pool.issuer();
        verify_ed25519(*authority.as_bytes(), statement_bytes, authority_signature)?;
        map_window(self.issued_at, self.expires_at, now)?;
        let mut committee_nodes = HashSet::new();
        let mut server_bound = MAX_SESSION_RECIPIENTS_V2;
        for bundle in &self.epochs {
            let committee = bundle.validate_for_release(authority, now)?;
            server_bound = server_bound.min(usize::from(committee.committee().threshold().total()));
            committee_nodes.extend(
                committee
                    .committee()
                    .nodes()
                    .iter()
                    .map(|node| node.node_public_key()),
            );
        }
        if self
            .members
            .iter()
            .any(|member| !committee_nodes.contains(&member.member_key()))
        {
            return Err(PoolContractError::NotMember);
        }
        if usize::from(self.serve_policy.max_servers_per_session) > server_bound {
            return Err(PoolContractError::TooMany);
        }
        Ok(VerifiedPoolDescriptorV1 {
            pool: self.pool,
            sequence: self.sequence,
            expires_at: self.expires_at,
            serve_policy: self.serve_policy,
            mint_policy: self.mint_policy.clone(),
            members: self.members.iter().map(M::ticketless).collect(),
            epochs: self.epochs.clone(),
            // v1 and v2: trust ABSENT, never an implicit `WciOperated`.
            trust: None,
        })
    }

    fn unverified_epoch_for(
        &self,
        key_envelope: &KeyEnvelopeIdentityV1,
    ) -> Option<&PoolEpochBundleV1> {
        self.epochs
            .iter()
            .find(|bundle| matches!(bundle.matches_key_envelope(key_envelope), Ok(true)))
    }
}

/// The signed descriptor's canonical size (L9): domain, separator, then two
/// length-prefixed byte strings (statement, signature).
pub(crate) fn validate_signed_descriptor(
    domain: &str,
    statement_bytes: &[u8],
    authority_signature: &[u8],
) -> Result<(), ContractError> {
    if authority_signature.len() != ED25519_SIGNATURE_BYTES {
        return Err(ContractError::InvalidField("pool_descriptor_signature"));
    }
    let canonical_size =
        domain.len() + 1 + 2 + statement_bytes.len() + 2 + authority_signature.len();
    if canonical_size > MAX_SIGNED_POOL_DESCRIPTOR_BYTES_V1 {
        return Err(ContractError::FieldTooLong("signed_pool_descriptor"));
    }
    Ok(())
}

/// The historical v1 descriptor statement: its routes may carry a connect
/// ticket. Decoded for reads only; writers emit
/// [`PoolDescriptorStatementV2`] (item 10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolDescriptorStatementV1 {
    body: DescriptorBody<PoolMemberV1>,
}

impl PoolDescriptorStatementV1 {
    /// Members are kept in node-key order and admitted minters in key-byte
    /// order; duplicates are refused.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pool: PoolDidV1,
        sequence: u64,
        epochs: Vec<PoolEpochBundleV1>,
        members: Vec<PoolMemberV1>,
        serve_policy: ServePolicyV1,
        mint_policy: MintPolicyV1,
        issued_at: u64,
        expires_at: u64,
    ) -> Result<Self, ContractError> {
        Ok(Self {
            body: DescriptorBody::new(
                pool,
                sequence,
                epochs,
                members,
                serve_policy,
                mint_policy,
                issued_at,
                expires_at,
            )?,
        })
    }

    pub const fn pool(&self) -> &PoolDidV1 {
        &self.body.pool
    }

    pub const fn sequence(&self) -> u64 {
        self.body.sequence
    }

    pub fn epochs(&self) -> &[PoolEpochBundleV1] {
        &self.body.epochs
    }

    pub fn members(&self) -> &[PoolMemberV1] {
        &self.body.members
    }

    pub const fn serve_policy(&self) -> &ServePolicyV1 {
        &self.body.serve_policy
    }

    pub fn mint_policy(&self) -> &MintPolicyV1 {
        &self.body.mint_policy
    }

    pub const fn issued_at(&self) -> u64 {
        self.body.issued_at
    }

    pub const fn expires_at(&self) -> u64 {
        self.body.expires_at
    }
}

impl CanonicalBody for PoolDescriptorStatementV1 {
    const DOMAIN: &'static str = "elastos.protected-content.pool-descriptor-statement/v1";

    fn validate(&self) -> Result<(), ContractError> {
        self.body.validate()
    }

    fn encode_fields(&self, encoder: &mut Encoder) -> Result<(), ContractError> {
        self.body.encode(encoder)
    }

    fn decode_fields(decoder: &mut Decoder<'_>) -> Result<Self, ContractError> {
        Ok(Self {
            body: DescriptorBody::decode(decoder)?,
        })
    }
}

/// The historical v1 signed descriptor. Decoded for reads only; writers emit
/// [`SignedPoolDescriptorV2`] (item 10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedPoolDescriptorV1 {
    statement: PoolDescriptorStatementV1,
    authority_signature: Vec<u8>,
}

impl SignedPoolDescriptorV1 {
    pub fn new(
        statement: PoolDescriptorStatementV1,
        authority_signature: Vec<u8>,
    ) -> Result<Self, ContractError> {
        let value = Self {
            statement,
            authority_signature,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn statement(&self) -> &PoolDescriptorStatementV1 {
        &self.statement
    }

    pub fn authority_signature(&self) -> &[u8] {
        &self.authority_signature
    }

    /// Verifies the descriptor at the verifier's own clock `now`, with the
    /// signature over this v1 statement's own bytes (see
    /// [`SignedPoolDescriptorV2::verify`] for the rules). The verified form
    /// carries no ticket (item 10).
    pub fn verify(&self, now: u64) -> Result<VerifiedPoolDescriptorV1, PoolContractError> {
        CanonicalBody::validate(self)?;
        self.statement.body.verify(
            &self.statement.canonical_bytes()?,
            &self.authority_signature,
            now,
        )
    }

    /// The bundle the item's key envelope names, without any signature or
    /// window check: for decode-time routing only.
    pub(crate) fn unverified_epoch_for(
        &self,
        key_envelope: &KeyEnvelopeIdentityV1,
    ) -> Option<&PoolEpochBundleV1> {
        self.statement.body.unverified_epoch_for(key_envelope)
    }
}

impl CanonicalBody for SignedPoolDescriptorV1 {
    const DOMAIN: &'static str = "elastos.protected-content.pool-descriptor/v1";

    fn validate(&self) -> Result<(), ContractError> {
        validate_signed_descriptor(
            Self::DOMAIN,
            &self.statement.canonical_bytes()?,
            &self.authority_signature,
        )
    }

    fn encode_fields(&self, encoder: &mut Encoder) -> Result<(), ContractError> {
        encoder.nested(&self.statement)?;
        encoder.bytes(&self.authority_signature)
    }

    fn decode_fields(decoder: &mut Decoder<'_>) -> Result<Self, ContractError> {
        Self::new(
            decoder.nested("pool_descriptor_statement")?,
            decoder.bytes("pool_descriptor_signature", ED25519_SIGNATURE_BYTES)?,
        )
    }
}

/// The pool descriptor statement writers sign (item 10): the v1 fields, with
/// each route its peer DID only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolDescriptorStatementV2 {
    body: DescriptorBody<PoolMemberV2>,
}

impl PoolDescriptorStatementV2 {
    /// Members are kept in node-key order and admitted minters in key-byte
    /// order; duplicates are refused.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pool: PoolDidV1,
        sequence: u64,
        epochs: Vec<PoolEpochBundleV1>,
        members: Vec<PoolMemberV2>,
        serve_policy: ServePolicyV1,
        mint_policy: MintPolicyV1,
        issued_at: u64,
        expires_at: u64,
    ) -> Result<Self, ContractError> {
        Ok(Self {
            body: DescriptorBody::new(
                pool,
                sequence,
                epochs,
                members,
                serve_policy,
                mint_policy,
                issued_at,
                expires_at,
            )?,
        })
    }

    pub const fn pool(&self) -> &PoolDidV1 {
        &self.body.pool
    }

    pub const fn sequence(&self) -> u64 {
        self.body.sequence
    }

    pub fn epochs(&self) -> &[PoolEpochBundleV1] {
        &self.body.epochs
    }

    pub fn members(&self) -> &[PoolMemberV2] {
        &self.body.members
    }

    pub const fn serve_policy(&self) -> &ServePolicyV1 {
        &self.body.serve_policy
    }

    pub fn mint_policy(&self) -> &MintPolicyV1 {
        &self.body.mint_policy
    }

    pub const fn issued_at(&self) -> u64 {
        self.body.issued_at
    }

    pub const fn expires_at(&self) -> u64 {
        self.body.expires_at
    }
}

impl CanonicalBody for PoolDescriptorStatementV2 {
    const DOMAIN: &'static str = "elastos.protected-content.pool-descriptor-statement/v2";

    fn validate(&self) -> Result<(), ContractError> {
        self.body.validate()
    }

    fn encode_fields(&self, encoder: &mut Encoder) -> Result<(), ContractError> {
        self.body.encode(encoder)
    }

    fn decode_fields(decoder: &mut Decoder<'_>) -> Result<Self, ContractError> {
        Ok(Self {
            body: DescriptorBody::decode(decoder)?,
        })
    }
}

/// The signed pool descriptor writers emit (item 10). It is ticketless when
/// it is signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedPoolDescriptorV2 {
    statement: PoolDescriptorStatementV2,
    authority_signature: Vec<u8>,
}

impl SignedPoolDescriptorV2 {
    pub fn new(
        statement: PoolDescriptorStatementV2,
        authority_signature: Vec<u8>,
    ) -> Result<Self, ContractError> {
        let value = Self {
            statement,
            authority_signature,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn statement(&self) -> &PoolDescriptorStatementV2 {
        &self.statement
    }

    pub fn authority_signature(&self) -> &[u8] {
        &self.authority_signature
    }

    /// Verifies the descriptor at the verifier's own clock `now`:
    /// - the pool authority signed it;
    /// - its window is open (`validate_active`, E1);
    /// - every bundle passes the release rule with the pool authority and
    ///   the bundle's own authorization identity (L3, F1); the 2-of-3 rule
    ///   stays in that one place (L2);
    /// - every member is in at least one committee;
    /// - `max_servers_per_session` is at most the smallest committee total
    ///   and [`MAX_SESSION_RECIPIENTS_V2`] (L2).
    pub fn verify(&self, now: u64) -> Result<VerifiedPoolDescriptorV1, PoolContractError> {
        CanonicalBody::validate(self)?;
        self.statement.body.verify(
            &self.statement.canonical_bytes()?,
            &self.authority_signature,
            now,
        )
    }

    /// The bundle the item's key envelope names, without any signature or
    /// window check: for decode-time routing only.
    pub(crate) fn unverified_epoch_for(
        &self,
        key_envelope: &KeyEnvelopeIdentityV1,
    ) -> Option<&PoolEpochBundleV1> {
        self.statement.body.unverified_epoch_for(key_envelope)
    }
}

impl CanonicalBody for SignedPoolDescriptorV2 {
    const DOMAIN: &'static str = "elastos.protected-content.pool-descriptor/v2";

    fn validate(&self) -> Result<(), ContractError> {
        validate_signed_descriptor(
            Self::DOMAIN,
            &self.statement.canonical_bytes()?,
            &self.authority_signature,
        )
    }

    fn encode_fields(&self, encoder: &mut Encoder) -> Result<(), ContractError> {
        encoder.nested(&self.statement)?;
        encoder.bytes(&self.authority_signature)
    }

    fn decode_fields(decoder: &mut Decoder<'_>) -> Result<Self, ContractError> {
        Self::new(
            decoder.nested("pool_descriptor_statement")?,
            decoder.bytes("pool_descriptor_signature", ED25519_SIGNATURE_BYTES)?,
        )
    }
}

/// #388 A2 (A388-F1): the descriptor statement writers sign. The v2 fields,
/// each member with its trust attestation slot, then the pool's
/// `trust_mode`. Ticketless and trusted when it is signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolDescriptorStatementV3 {
    body: DescriptorBody<PoolMemberV3>,
    trust_mode: PoolTrustModeV1,
}

impl PoolDescriptorStatementV3 {
    /// Members are kept in node-key order and admitted minters in key-byte
    /// order; duplicates are refused.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pool: PoolDidV1,
        sequence: u64,
        epochs: Vec<PoolEpochBundleV1>,
        members: Vec<PoolMemberV3>,
        serve_policy: ServePolicyV1,
        mint_policy: MintPolicyV1,
        issued_at: u64,
        expires_at: u64,
        trust_mode: PoolTrustModeV1,
    ) -> Result<Self, ContractError> {
        let value = Self {
            body: DescriptorBody::new(
                pool,
                sequence,
                epochs,
                members,
                serve_policy,
                mint_policy,
                issued_at,
                expires_at,
            )?,
            trust_mode,
        };
        value.validate_trust()?;
        Ok(value)
    }

    fn validate_trust(&self) -> Result<(), ContractError> {
        for member in &self.body.members {
            validate_trust_slot(self.trust_mode, &member.attestation, "attestation")?;
        }
        if self.trust_mode == PoolTrustModeV1::AttestedTee {
            return Err(ContractError::InvalidField("trust_mode"));
        }
        Ok(())
    }

    pub const fn pool(&self) -> &PoolDidV1 {
        &self.body.pool
    }

    pub const fn sequence(&self) -> u64 {
        self.body.sequence
    }

    pub fn epochs(&self) -> &[PoolEpochBundleV1] {
        &self.body.epochs
    }

    pub fn members(&self) -> &[PoolMemberV3] {
        &self.body.members
    }

    pub const fn serve_policy(&self) -> &ServePolicyV1 {
        &self.body.serve_policy
    }

    pub fn mint_policy(&self) -> &MintPolicyV1 {
        &self.body.mint_policy
    }

    pub const fn issued_at(&self) -> u64 {
        self.body.issued_at
    }

    pub const fn expires_at(&self) -> u64 {
        self.body.expires_at
    }

    pub const fn trust_mode(&self) -> PoolTrustModeV1 {
        self.trust_mode
    }
}

impl CanonicalBody for PoolDescriptorStatementV3 {
    const DOMAIN: &'static str = "elastos.protected-content.pool-descriptor-statement/v3";

    fn validate(&self) -> Result<(), ContractError> {
        self.body.validate()?;
        self.validate_trust()
    }

    fn encode_fields(&self, encoder: &mut Encoder) -> Result<(), ContractError> {
        self.body.encode(encoder)?;
        encoder.u8(self.trust_mode.code());
        Ok(())
    }

    fn decode_fields(decoder: &mut Decoder<'_>) -> Result<Self, ContractError> {
        let body = DescriptorBody::decode(decoder)?;
        let value = Self {
            body,
            trust_mode: PoolTrustModeV1::from_code(decoder.u8()?)?,
        };
        value.validate_trust()?;
        Ok(value)
    }
}

/// #388 A2: the signed pool descriptor writers emit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedPoolDescriptorV3 {
    statement: PoolDescriptorStatementV3,
    authority_signature: Vec<u8>,
}

impl SignedPoolDescriptorV3 {
    pub fn new(
        statement: PoolDescriptorStatementV3,
        authority_signature: Vec<u8>,
    ) -> Result<Self, ContractError> {
        let value = Self {
            statement,
            authority_signature,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn statement(&self) -> &PoolDescriptorStatementV3 {
        &self.statement
    }

    pub fn authority_signature(&self) -> &[u8] {
        &self.authority_signature
    }

    /// As [`SignedPoolDescriptorV2::verify`], and the verified form carries
    /// the descriptor's trust.
    pub fn verify(&self, now: u64) -> Result<VerifiedPoolDescriptorV1, PoolContractError> {
        CanonicalBody::validate(self)?;
        let mut verified = self.statement.body.verify(
            &self.statement.canonical_bytes()?,
            &self.authority_signature,
            now,
        )?;
        verified.trust = Some(PoolTrustV1 {
            mode: self.statement.trust_mode,
            member_attestations: self
                .statement
                .body
                .members
                .iter()
                .map(|member| member.slot().to_vec())
                .collect(),
        });
        Ok(verified)
    }

    pub(crate) fn unverified_epoch_for(
        &self,
        key_envelope: &KeyEnvelopeIdentityV1,
    ) -> Option<&PoolEpochBundleV1> {
        self.statement.body.unverified_epoch_for(key_envelope)
    }
}

impl CanonicalBody for SignedPoolDescriptorV3 {
    const DOMAIN: &'static str = "elastos.protected-content.pool-descriptor/v3";

    fn validate(&self) -> Result<(), ContractError> {
        validate_signed_descriptor(
            Self::DOMAIN,
            &self.statement.canonical_bytes()?,
            &self.authority_signature,
        )
    }

    fn encode_fields(&self, encoder: &mut Encoder) -> Result<(), ContractError> {
        encoder.nested(&self.statement)?;
        encoder.bytes(&self.authority_signature)
    }

    fn decode_fields(decoder: &mut Decoder<'_>) -> Result<Self, ContractError> {
        Self::new(
            decoder.nested("pool_descriptor_statement")?,
            decoder.bytes("pool_descriptor_signature", ED25519_SIGNATURE_BYTES)?,
        )
    }
}

/// A signed pool descriptor of either version, decoded by its domain. Readers
/// take this form (item 10): the known-pools file and `describe`, the served
/// descriptors, the V2 release operation's `pool_descriptor`, and the remote
/// seal. Each version keeps its original bytes; a v1 value is never
/// normalized to v2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignedPoolDescriptorAnyV1 {
    V1(SignedPoolDescriptorV1),
    V2(SignedPoolDescriptorV2),
    /// #388 A2: the version writers emit; the only one with trust.
    V3(SignedPoolDescriptorV3),
}

impl SignedPoolDescriptorAnyV1 {
    /// Checks the signature over the exact original preimage of either
    /// version, then yields the same ticketless verified descriptor.
    pub fn verify(&self, now: u64) -> Result<VerifiedPoolDescriptorV1, PoolContractError> {
        match self {
            Self::V1(descriptor) => descriptor.verify(now),
            Self::V2(descriptor) => descriptor.verify(now),
            Self::V3(descriptor) => descriptor.verify(now),
        }
    }

    pub fn pool(&self) -> &PoolDidV1 {
        match self {
            Self::V1(descriptor) => descriptor.statement().pool(),
            Self::V2(descriptor) => descriptor.statement().pool(),
            Self::V3(descriptor) => descriptor.statement().pool(),
        }
    }

    pub fn sequence(&self) -> u64 {
        match self {
            Self::V1(descriptor) => descriptor.statement().sequence(),
            Self::V2(descriptor) => descriptor.statement().sequence(),
            Self::V3(descriptor) => descriptor.statement().sequence(),
        }
    }

    pub fn epochs(&self) -> &[PoolEpochBundleV1] {
        match self {
            Self::V1(descriptor) => descriptor.statement().epochs(),
            Self::V2(descriptor) => descriptor.statement().epochs(),
            Self::V3(descriptor) => descriptor.statement().epochs(),
        }
    }

    pub fn serve_policy(&self) -> &ServePolicyV1 {
        match self {
            Self::V1(descriptor) => descriptor.statement().serve_policy(),
            Self::V2(descriptor) => descriptor.statement().serve_policy(),
            Self::V3(descriptor) => descriptor.statement().serve_policy(),
        }
    }

    /// The peer DID of the member with `node_public_key`, read without any
    /// check (POOL-MINT: settling recorded work on a descriptor kept by this
    /// Home, whose window may have closed).
    pub fn member_peer_did(&self, node_public_key: NodePublicKey) -> Option<&str> {
        match self {
            Self::V1(descriptor) => descriptor
                .statement()
                .members()
                .iter()
                .find(|member| member.node_public_key() == node_public_key)
                .map(|member| member.route().peer_did()),
            Self::V2(descriptor) => descriptor
                .statement()
                .members()
                .iter()
                .find(|member| member.node_public_key() == node_public_key)
                .map(|member| member.route().peer_did()),
            Self::V3(descriptor) => descriptor
                .statement()
                .members()
                .iter()
                .find(|member| member.node_public_key() == node_public_key)
                .map(|member| member.route().peer_did()),
        }
    }

    pub fn mint_policy(&self) -> &MintPolicyV1 {
        match self {
            Self::V1(descriptor) => descriptor.statement().mint_policy(),
            Self::V2(descriptor) => descriptor.statement().mint_policy(),
            Self::V3(descriptor) => descriptor.statement().mint_policy(),
        }
    }

    pub fn expires_at(&self) -> u64 {
        match self {
            Self::V1(descriptor) => descriptor.statement().expires_at(),
            Self::V2(descriptor) => descriptor.statement().expires_at(),
            Self::V3(descriptor) => descriptor.statement().expires_at(),
        }
    }

    /// The bundle the item's key envelope names, without any signature or
    /// window check: for decode-time routing only.
    pub(crate) fn unverified_epoch_for(
        &self,
        key_envelope: &KeyEnvelopeIdentityV1,
    ) -> Option<&PoolEpochBundleV1> {
        match self {
            Self::V1(descriptor) => descriptor.unverified_epoch_for(key_envelope),
            Self::V2(descriptor) => descriptor.unverified_epoch_for(key_envelope),
            Self::V3(descriptor) => descriptor.unverified_epoch_for(key_envelope),
        }
    }
}

impl CanonicalContract for SignedPoolDescriptorAnyV1 {
    fn canonical_bytes(&self) -> Result<Vec<u8>, ContractError> {
        match self {
            Self::V1(descriptor) => descriptor.canonical_bytes(),
            Self::V2(descriptor) => descriptor.canonical_bytes(),
            Self::V3(descriptor) => descriptor.canonical_bytes(),
        }
    }

    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ContractError> {
        match SignedPoolDescriptorV1::from_canonical_bytes(bytes) {
            Err(ContractError::WrongDomain) => {
                match SignedPoolDescriptorV2::from_canonical_bytes(bytes) {
                    Err(ContractError::WrongDomain) => {
                        SignedPoolDescriptorV3::from_canonical_bytes(bytes).map(Self::V3)
                    }
                    other => other.map(Self::V2),
                }
            }
            other => other.map(Self::V1),
        }
    }
}

impl From<SignedPoolDescriptorV1> for SignedPoolDescriptorAnyV1 {
    fn from(descriptor: SignedPoolDescriptorV1) -> Self {
        Self::V1(descriptor)
    }
}

impl From<SignedPoolDescriptorV2> for SignedPoolDescriptorAnyV1 {
    fn from(descriptor: SignedPoolDescriptorV2) -> Self {
        Self::V2(descriptor)
    }
}

impl From<SignedPoolDescriptorV3> for SignedPoolDescriptorAnyV1 {
    fn from(descriptor: SignedPoolDescriptorV3) -> Self {
        Self::V3(descriptor)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPoolDescriptorV1 {
    pool: PoolDidV1,
    sequence: u64,
    expires_at: u64,
    serve_policy: ServePolicyV1,
    mint_policy: MintPolicyV1,
    /// Ticketless in every version (item 10).
    members: Vec<PoolMemberV2>,
    epochs: Vec<PoolEpochBundleV1>,
    /// #388 A2: `Some` only for v3. v1 and v2 report trust ABSENT, never an
    /// implicit `WciOperated`.
    trust: Option<PoolTrustV1>,
}

impl VerifiedPoolDescriptorV1 {
    pub const fn pool(&self) -> &PoolDidV1 {
        &self.pool
    }

    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }

    pub const fn serve_policy(&self) -> &ServePolicyV1 {
        &self.serve_policy
    }

    pub fn mint_policy(&self) -> &MintPolicyV1 {
        &self.mint_policy
    }

    pub fn members(&self) -> &[PoolMemberV2] {
        &self.members
    }

    pub fn member(&self, node_public_key: NodePublicKey) -> Option<&PoolMemberV2> {
        self.members
            .binary_search_by_key(&node_public_key, PoolMemberV2::node_public_key)
            .ok()
            .map(|index| &self.members[index])
    }

    /// The bundle whose three identities the item's key envelope names (L3).
    pub fn epoch_for(&self, key_envelope: &KeyEnvelopeIdentityV1) -> Option<&PoolEpochBundleV1> {
        self.epochs
            .iter()
            .find(|bundle| matches!(bundle.matches_key_envelope(key_envelope), Ok(true)))
    }

    pub fn eligible_servers(&self) -> Vec<&PoolMemberV2> {
        self.members
            .iter()
            .filter(|member| member.roles.serve)
            .collect()
    }

    pub fn eligible_sealers(&self) -> Vec<&PoolMemberV2> {
        self.members
            .iter()
            .filter(|member| member.roles.seal)
            .collect()
    }

    /// #388 A2: the descriptor's trust; `None` for v1 and v2.
    pub fn trust(&self) -> Option<&PoolTrustV1> {
        self.trust.as_ref()
    }

    /// Whether this descriptor admits a NEW release, session, seal or open:
    /// only a v3 descriptor whose trust is `WciOperated` with every member
    /// slot empty. Historical v1 and v2 descriptors only read.
    pub fn admits_new_release(&self) -> Result<PoolTrustModeV1, PoolContractError> {
        match &self.trust {
            Some(trust)
                if trust.mode == PoolTrustModeV1::WciOperated
                    && trust.member_attestations.iter().all(Vec::is_empty) =>
            {
                Ok(trust.mode)
            }
            _ => Err(PoolContractError::TrustRequired),
        }
    }

    /// Plan B POOL-MINT: the bundle the item's key envelope names, whose pool
    /// term is open at `now` (provisioning keeps the term).
    pub fn epoch_for_provisioning(
        &self,
        key_envelope: &KeyEnvelopeIdentityV1,
        now: u64,
    ) -> Result<&PoolEpochBundleV1, PoolContractError> {
        let bundle = self
            .epoch_for(key_envelope)
            .ok_or(PoolContractError::EpochMismatch)?;
        bundle.validate_for_provisioning(self.pool.issuer(), now)?;
        Ok(bundle)
    }

    fn holds_epoch(&self, epoch: CustodyEpochIdentityV1) -> bool {
        self.epochs
            .iter()
            .any(|bundle| matches!(bundle.epoch_identity(), Ok(identity) if identity == epoch))
    }
}

/// How to reach a pool, in the historical v1 format: its DID and one
/// member's route, which may carry a ticket. Decoded for reads only; writers
/// emit [`PoolAddressV2`] (item 10). Canonical bytes only; the text form
/// belongs to the server (T3.3, E4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolAddressV1 {
    pool: PoolDidV1,
    bootstrap: PoolMemberRouteV1,
}

impl PoolAddressV1 {
    pub fn new(pool: PoolDidV1, bootstrap: PoolMemberRouteV1) -> Result<Self, ContractError> {
        let value = Self { pool, bootstrap };
        value.validate()?;
        Ok(value)
    }

    pub const fn pool(&self) -> &PoolDidV1 {
        &self.pool
    }

    pub fn bootstrap(&self) -> &PoolMemberRouteV1 {
        &self.bootstrap
    }
}

impl CanonicalBody for PoolAddressV1 {
    const DOMAIN: &'static str = "elastos.protected-content.pool-address/v1";

    fn validate(&self) -> Result<(), ContractError> {
        CustodyEpochIssuerKeyV1::new(*self.pool.issuer().as_bytes())?;
        self.bootstrap.validate()
    }

    fn encode_fields(&self, encoder: &mut Encoder) -> Result<(), ContractError> {
        self.pool.encode(encoder);
        self.bootstrap.encode(encoder)
    }

    fn decode_fields(decoder: &mut Decoder<'_>) -> Result<Self, ContractError> {
        let pool = PoolDidV1::decode(decoder)?;
        Self::new(pool, PoolMemberRouteV1::decode(decoder)?)
    }
}

/// How to reach a pool (item 10): its DID and one member's peer DID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolAddressV2 {
    pool: PoolDidV1,
    bootstrap: PoolMemberRouteV2,
}

impl PoolAddressV2 {
    pub fn new(pool: PoolDidV1, bootstrap: PoolMemberRouteV2) -> Result<Self, ContractError> {
        let value = Self { pool, bootstrap };
        value.validate()?;
        Ok(value)
    }

    pub const fn pool(&self) -> &PoolDidV1 {
        &self.pool
    }

    pub fn bootstrap(&self) -> &PoolMemberRouteV2 {
        &self.bootstrap
    }
}

impl CanonicalBody for PoolAddressV2 {
    const DOMAIN: &'static str = "elastos.protected-content.pool-address/v2";

    fn validate(&self) -> Result<(), ContractError> {
        CustodyEpochIssuerKeyV1::new(*self.pool.issuer().as_bytes())?;
        self.bootstrap.validate()
    }

    fn encode_fields(&self, encoder: &mut Encoder) -> Result<(), ContractError> {
        self.pool.encode(encoder);
        self.bootstrap.encode(encoder)
    }

    fn decode_fields(decoder: &mut Decoder<'_>) -> Result<Self, ContractError> {
        let pool = PoolDidV1::decode(decoder)?;
        Self::new(pool, PoolMemberRouteV2::decode(decoder)?)
    }
}

/// A pool address of either version, decoded by its domain (item 10). A v1
/// ticket is never exposed: readers see the pool and the peer DID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PoolAddressAnyV1 {
    V1(PoolAddressV1),
    V2(PoolAddressV2),
}

impl PoolAddressAnyV1 {
    pub fn pool(&self) -> &PoolDidV1 {
        match self {
            Self::V1(address) => address.pool(),
            Self::V2(address) => address.pool(),
        }
    }

    /// The bootstrap member's peer DID.
    pub fn peer_did(&self) -> &str {
        match self {
            Self::V1(address) => address.bootstrap().peer_did(),
            Self::V2(address) => address.bootstrap().peer_did(),
        }
    }
}

impl CanonicalContract for PoolAddressAnyV1 {
    fn canonical_bytes(&self) -> Result<Vec<u8>, ContractError> {
        match self {
            Self::V1(address) => address.canonical_bytes(),
            Self::V2(address) => address.canonical_bytes(),
        }
    }

    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ContractError> {
        match PoolAddressV1::from_canonical_bytes(bytes) {
            Err(ContractError::WrongDomain) => {
                PoolAddressV2::from_canonical_bytes(bytes).map(Self::V2)
            }
            other => other.map(Self::V1),
        }
    }
}

impl From<PoolAddressV2> for PoolAddressAnyV1 {
    fn from(address: PoolAddressV2) -> Self {
        Self::V2(address)
    }
}

/// The buyer Runtime's session delivery key (X-Wing), validated as a
/// recipient public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeliveryPublicKeyBytesV1([u8; PQ_HYBRID_WRAP_PUBLIC_KEY_BYTES]);

impl DeliveryPublicKeyBytesV1 {
    pub fn new(bytes: [u8; PQ_HYBRID_WRAP_PUBLIC_KEY_BYTES]) -> Result<Self, ContractError> {
        validate_pq_hybrid_wrap_public_key(&bytes, "delivery_public_key")?;
        Ok(Self(bytes))
    }

    pub const fn as_bytes(&self) -> &[u8; PQ_HYBRID_WRAP_PUBLIC_KEY_BYTES] {
        &self.0
    }

    /// The identity the wallet signs (F3): sha256 of
    /// `"elastos.protected-content.delivery-key-identity/v1" || 0x00 || key`.
    /// The buyer, the pool server and the decrypt provider all derive it here.
    pub fn identity(&self) -> DeliveryKeyIdentityV1 {
        let mut hasher = Sha256::new();
        hasher.update(DELIVERY_KEY_IDENTITY_DOMAIN_V1.as_bytes());
        hasher.update([0u8]);
        hasher.update(self.0);
        DeliveryKeyIdentityV1(Digest32::new(hasher.finalize().into()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DeliveryKeyIdentityV1(Digest32);

impl DeliveryKeyIdentityV1 {
    /// A decoded identity; derive a new one with
    /// [`DeliveryPublicKeyBytesV1::identity`].
    pub const fn new(digest: Digest32) -> Self {
        Self(digest)
    }

    pub const fn digest(&self) -> Digest32 {
        self.0
    }
}

/// A pool node vouches that one session recipient key is its own, for one
/// item, action and Runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolRecipientAttestationStatementV1 {
    pool: PoolDidV1,
    epoch: CustodyEpochIdentityV1,
    server_node_public_key: NodePublicKey,
    binding: ProtectedContentBindingV1,
    action: RightsActionV1,
    recipient_public_key: RecipientPublicKeyBytesV1,
    recipient_identity: RecipientKeyIdentityV1,
    runtime_operation_issuer: RuntimeOperationIssuerKeyV1,
    issued_at: u64,
    expires_at: u64,
}

impl PoolRecipientAttestationStatementV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pool: PoolDidV1,
        epoch: CustodyEpochIdentityV1,
        server_node_public_key: NodePublicKey,
        binding: ProtectedContentBindingV1,
        action: RightsActionV1,
        recipient_public_key: RecipientPublicKeyBytesV1,
        recipient_identity: RecipientKeyIdentityV1,
        runtime_operation_issuer: RuntimeOperationIssuerKeyV1,
        issued_at: u64,
        expires_at: u64,
    ) -> Result<Self, ContractError> {
        let value = Self {
            pool,
            epoch,
            server_node_public_key,
            binding,
            action,
            recipient_public_key,
            recipient_identity,
            runtime_operation_issuer,
            issued_at,
            expires_at,
        };
        value.validate()?;
        Ok(value)
    }

    pub const fn pool(&self) -> &PoolDidV1 {
        &self.pool
    }

    pub const fn epoch(&self) -> CustodyEpochIdentityV1 {
        self.epoch
    }

    pub const fn server_node_public_key(&self) -> NodePublicKey {
        self.server_node_public_key
    }

    pub fn binding(&self) -> &ProtectedContentBindingV1 {
        &self.binding
    }

    pub const fn action(&self) -> RightsActionV1 {
        self.action
    }

    pub const fn recipient_public_key(&self) -> RecipientPublicKeyBytesV1 {
        self.recipient_public_key
    }

    pub fn recipient_identity(&self) -> &RecipientKeyIdentityV1 {
        &self.recipient_identity
    }

    pub const fn runtime_operation_issuer(&self) -> RuntimeOperationIssuerKeyV1 {
        self.runtime_operation_issuer
    }

    pub const fn issued_at(&self) -> u64 {
        self.issued_at
    }

    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }
}

impl CanonicalBody for PoolRecipientAttestationStatementV1 {
    const DOMAIN: &'static str =
        "elastos.protected-content.pool-recipient-attestation-statement/v1";

    fn validate(&self) -> Result<(), ContractError> {
        CustodyEpochIssuerKeyV1::new(*self.pool.issuer().as_bytes())?;
        self.epoch.canonical_bytes()?;
        NodePublicKey::new(*self.server_node_public_key.as_bytes())?;
        self.binding.canonical_bytes()?;
        RecipientPublicKeyBytesV1::new(*self.recipient_public_key.as_bytes())?;
        self.recipient_identity.canonical_bytes()?;
        RuntimeOperationIssuerKeyV1::new(*self.runtime_operation_issuer.as_bytes())?;
        validate_time_window(
            self.issued_at,
            self.expires_at,
            MAX_RECIPIENT_KEY_AUTHORIZATION_LIFETIME_SECS,
            "pool_recipient_attestation_lifetime",
        )?;
        if !self
            .recipient_identity
            .matches_public_key(self.recipient_public_key.as_bytes())
        {
            return Err(ContractError::InvalidField("recipient_key_identity"));
        }
        Ok(())
    }

    fn encode_fields(&self, encoder: &mut Encoder) -> Result<(), ContractError> {
        self.pool.encode(encoder);
        encoder.nested(&self.epoch)?;
        encoder.fixed(self.server_node_public_key.as_bytes());
        encoder.nested(&self.binding)?;
        encoder.u8(self.action as u8);
        encoder.fixed(self.recipient_public_key.as_bytes());
        encoder.nested(&self.recipient_identity)?;
        encoder.fixed(self.runtime_operation_issuer.as_bytes());
        encoder.u64(self.issued_at);
        encoder.u64(self.expires_at);
        Ok(())
    }

    fn decode_fields(decoder: &mut Decoder<'_>) -> Result<Self, ContractError> {
        let pool = PoolDidV1::decode(decoder)?;
        let epoch = decoder.nested("custody_epoch_identity")?;
        let server_node_public_key = NodePublicKey::new(decoder.fixed()?)?;
        let binding = decoder.nested("binding")?;
        let action = RightsActionV1::decode(decoder.u8()?)?;
        let recipient_public_key = RecipientPublicKeyBytesV1::new(decoder.fixed()?)?;
        let recipient_identity = decoder.nested("recipient_key_identity")?;
        let runtime_operation_issuer = RuntimeOperationIssuerKeyV1::new(decoder.fixed()?)?;
        Self::new(
            pool,
            epoch,
            server_node_public_key,
            binding,
            action,
            recipient_public_key,
            recipient_identity,
            runtime_operation_issuer,
            decoder.u64()?,
            decoder.u64()?,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedPoolRecipientAttestationV1 {
    statement: PoolRecipientAttestationStatementV1,
    node_signature: Vec<u8>,
}

impl SignedPoolRecipientAttestationV1 {
    pub fn new(
        statement: PoolRecipientAttestationStatementV1,
        node_signature: Vec<u8>,
    ) -> Result<Self, ContractError> {
        let value = Self {
            statement,
            node_signature,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn statement(&self) -> &PoolRecipientAttestationStatementV1 {
        &self.statement
    }

    pub fn node_signature(&self) -> &[u8] {
        &self.node_signature
    }

    /// Only the server's node-key signature over the statement. The provider
    /// contracts use it to check a node's answer to a signing request; every
    /// release still runs [`Self::verify`].
    pub fn verify_node_signature(&self) -> Result<(), PoolContractError> {
        CanonicalBody::validate(self)?;
        verify_ed25519(
            *self.statement.server_node_public_key.as_bytes(),
            &self.statement.canonical_bytes()?,
            &self.node_signature,
        )
    }

    /// Verifies the vouch against a verified descriptor and the item's
    /// verified epoch: same pool and epoch (the epoch is one the descriptor
    /// holds), the server is in the committee and is a descriptor member with
    /// `serve`, the window is open, and the server's node key signed it.
    pub fn verify(
        &self,
        descriptor: &VerifiedPoolDescriptorV1,
        epoch: &VerifiedCustodyEpochV1,
        now: u64,
    ) -> Result<VerifiedPoolRecipientAttestationV1, PoolContractError> {
        CanonicalBody::validate(self)?;
        verify_recipient_attestation(
            &self.statement,
            &self.statement.canonical_bytes()?,
            self.statement.canonical_hash()?,
            &self.node_signature,
            None,
            descriptor,
            epoch,
            now,
        )
    }
}

/// The vouch checks of every attestation version, over the version's own
/// signed bytes: same pool and epoch (the epoch is one the descriptor holds),
/// the server is in the committee and is a descriptor member with `serve`,
/// the window is open, and the server's node key signed `statement_bytes`.
#[allow(clippy::too_many_arguments)]
fn verify_recipient_attestation(
    statement: &PoolRecipientAttestationStatementV1,
    statement_bytes: &[u8],
    statement_hash: Digest32,
    node_signature: &[u8],
    trust_mode: Option<PoolTrustModeV1>,
    descriptor: &VerifiedPoolDescriptorV1,
    epoch: &VerifiedCustodyEpochV1,
    now: u64,
) -> Result<VerifiedPoolRecipientAttestationV1, PoolContractError> {
    if statement.pool != *descriptor.pool() {
        return Err(PoolContractError::IssuerMismatch);
    }
    if statement.epoch != epoch.epoch_identity() || !descriptor.holds_epoch(statement.epoch) {
        return Err(PoolContractError::EpochMismatch);
    }
    if epoch.node(statement.server_node_public_key).is_none() {
        return Err(PoolContractError::NotMember);
    }
    let member = descriptor
        .member(statement.server_node_public_key)
        .ok_or(PoolContractError::NotMember)?;
    if !member.roles.serve {
        return Err(PoolContractError::RoleMissing);
    }
    map_window(statement.issued_at, statement.expires_at, now)?;
    verify_ed25519(
        *statement.server_node_public_key.as_bytes(),
        statement_bytes,
        node_signature,
    )?;
    Ok(VerifiedPoolRecipientAttestationV1 {
        statement_hash,
        server_node_public_key: statement.server_node_public_key,
        binding: statement.binding.clone(),
        action: statement.action,
        recipient_public_key: statement.recipient_public_key,
        recipient_identity: statement.recipient_identity.clone(),
        runtime_operation_issuer: statement.runtime_operation_issuer,
        issued_at: statement.issued_at,
        expires_at: statement.expires_at,
        trust_mode,
    })
}

impl CanonicalBody for SignedPoolRecipientAttestationV1 {
    const DOMAIN: &'static str = "elastos.protected-content.pool-recipient-attestation/v1";

    fn validate(&self) -> Result<(), ContractError> {
        self.statement.canonical_bytes()?;
        if self.node_signature.len() != ED25519_SIGNATURE_BYTES {
            return Err(ContractError::InvalidField(
                "pool_recipient_attestation_signature",
            ));
        }
        Ok(())
    }

    fn encode_fields(&self, encoder: &mut Encoder) -> Result<(), ContractError> {
        encoder.nested(&self.statement)?;
        encoder.bytes(&self.node_signature)
    }

    fn decode_fields(decoder: &mut Decoder<'_>) -> Result<Self, ContractError> {
        Self::new(
            decoder.nested("pool_recipient_attestation_statement")?,
            decoder.bytes(
                "pool_recipient_attestation_signature",
                ED25519_SIGNATURE_BYTES,
            )?,
        )
    }
}

/// #388-2 (option (a), USER decision 02:55): the recipient attestation
/// writers emit. Its signed preimage binds the v1 fields, then the pool's
/// `trust_mode` and the `evidence` (u16 length; empty under `WciOperated`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolRecipientAttestationStatementV2 {
    base: PoolRecipientAttestationStatementV1,
    trust_mode: PoolTrustModeV1,
    evidence: Vec<u8>,
}

impl PoolRecipientAttestationStatementV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pool: PoolDidV1,
        epoch: CustodyEpochIdentityV1,
        server_node_public_key: NodePublicKey,
        binding: ProtectedContentBindingV1,
        action: RightsActionV1,
        recipient_public_key: RecipientPublicKeyBytesV1,
        recipient_identity: RecipientKeyIdentityV1,
        runtime_operation_issuer: RuntimeOperationIssuerKeyV1,
        issued_at: u64,
        expires_at: u64,
        trust_mode: PoolTrustModeV1,
        evidence: Vec<u8>,
    ) -> Result<Self, ContractError> {
        let value = Self {
            base: PoolRecipientAttestationStatementV1::new(
                pool,
                epoch,
                server_node_public_key,
                binding,
                action,
                recipient_public_key,
                recipient_identity,
                runtime_operation_issuer,
                issued_at,
                expires_at,
            )?,
            trust_mode,
            evidence,
        };
        value.validate()?;
        Ok(value)
    }

    pub const fn pool(&self) -> &PoolDidV1 {
        self.base.pool()
    }

    pub const fn epoch(&self) -> CustodyEpochIdentityV1 {
        self.base.epoch()
    }

    pub const fn server_node_public_key(&self) -> NodePublicKey {
        self.base.server_node_public_key()
    }

    pub fn binding(&self) -> &ProtectedContentBindingV1 {
        self.base.binding()
    }

    pub const fn action(&self) -> RightsActionV1 {
        self.base.action()
    }

    pub const fn recipient_public_key(&self) -> RecipientPublicKeyBytesV1 {
        self.base.recipient_public_key()
    }

    pub fn recipient_identity(&self) -> &RecipientKeyIdentityV1 {
        self.base.recipient_identity()
    }

    pub const fn runtime_operation_issuer(&self) -> RuntimeOperationIssuerKeyV1 {
        self.base.runtime_operation_issuer()
    }

    pub const fn issued_at(&self) -> u64 {
        self.base.issued_at()
    }

    pub const fn expires_at(&self) -> u64 {
        self.base.expires_at()
    }

    pub const fn trust_mode(&self) -> PoolTrustModeV1 {
        self.trust_mode
    }

    pub fn evidence(&self) -> &[u8] {
        &self.evidence
    }
}

impl CanonicalBody for PoolRecipientAttestationStatementV2 {
    const DOMAIN: &'static str =
        "elastos.protected-content.pool-recipient-attestation-statement/v2";

    fn validate(&self) -> Result<(), ContractError> {
        CanonicalBody::validate(&self.base)?;
        validate_trust_slot(self.trust_mode, &self.evidence, "evidence")
    }

    fn encode_fields(&self, encoder: &mut Encoder) -> Result<(), ContractError> {
        self.base.encode_fields(encoder)?;
        encoder.u8(self.trust_mode.code());
        encoder.bytes(&self.evidence)
    }

    fn decode_fields(decoder: &mut Decoder<'_>) -> Result<Self, ContractError> {
        let base = PoolRecipientAttestationStatementV1::decode_fields(decoder)?;
        let trust_mode = PoolTrustModeV1::from_code(decoder.u8()?)?;
        let evidence = decoder.bytes("evidence", MAX_TRUST_ATTESTATION_BYTES_V1)?;
        let value = Self {
            base,
            trust_mode,
            evidence,
        };
        value.validate()?;
        Ok(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedPoolRecipientAttestationV2 {
    statement: PoolRecipientAttestationStatementV2,
    node_signature: Vec<u8>,
}

impl SignedPoolRecipientAttestationV2 {
    pub fn new(
        statement: PoolRecipientAttestationStatementV2,
        node_signature: Vec<u8>,
    ) -> Result<Self, ContractError> {
        let value = Self {
            statement,
            node_signature,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn statement(&self) -> &PoolRecipientAttestationStatementV2 {
        &self.statement
    }

    pub fn node_signature(&self) -> &[u8] {
        &self.node_signature
    }

    /// Only the server's node-key signature over the v2 statement.
    pub fn verify_node_signature(&self) -> Result<(), PoolContractError> {
        CanonicalBody::validate(self)?;
        verify_ed25519(
            *self.statement.server_node_public_key().as_bytes(),
            &self.statement.canonical_bytes()?,
            &self.node_signature,
        )
    }

    /// As [`SignedPoolRecipientAttestationV1::verify`], over the v2 bytes; the
    /// verified form carries the trust mode.
    pub fn verify(
        &self,
        descriptor: &VerifiedPoolDescriptorV1,
        epoch: &VerifiedCustodyEpochV1,
        now: u64,
    ) -> Result<VerifiedPoolRecipientAttestationV1, PoolContractError> {
        CanonicalBody::validate(self)?;
        verify_recipient_attestation(
            &self.statement.base,
            &self.statement.canonical_bytes()?,
            self.statement.canonical_hash()?,
            &self.node_signature,
            Some(self.statement.trust_mode),
            descriptor,
            epoch,
            now,
        )
    }
}

impl CanonicalBody for SignedPoolRecipientAttestationV2 {
    const DOMAIN: &'static str = "elastos.protected-content.pool-recipient-attestation/v2";

    fn validate(&self) -> Result<(), ContractError> {
        self.statement.canonical_bytes()?;
        if self.node_signature.len() != ED25519_SIGNATURE_BYTES {
            return Err(ContractError::InvalidField(
                "pool_recipient_attestation_signature",
            ));
        }
        Ok(())
    }

    fn encode_fields(&self, encoder: &mut Encoder) -> Result<(), ContractError> {
        encoder.nested(&self.statement)?;
        encoder.bytes(&self.node_signature)
    }

    fn decode_fields(decoder: &mut Decoder<'_>) -> Result<Self, ContractError> {
        Self::new(
            decoder.nested("pool_recipient_attestation_statement")?,
            decoder.bytes(
                "pool_recipient_attestation_signature",
                ED25519_SIGNATURE_BYTES,
            )?,
        )
    }
}

/// The recipient attestation of either version, decoded by its domain: the
/// child of `PoolSessionRecipientV1` in the `/v2` operation. A v1 value (trust
/// absent) is read-only and never admits a new release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignedPoolRecipientAttestationAnyV1 {
    V1(SignedPoolRecipientAttestationV1),
    V2(SignedPoolRecipientAttestationV2),
}

impl SignedPoolRecipientAttestationAnyV1 {
    fn base(&self) -> &PoolRecipientAttestationStatementV1 {
        match self {
            Self::V1(attestation) => &attestation.statement,
            Self::V2(attestation) => &attestation.statement.base,
        }
    }

    pub fn verify(
        &self,
        descriptor: &VerifiedPoolDescriptorV1,
        epoch: &VerifiedCustodyEpochV1,
        now: u64,
    ) -> Result<VerifiedPoolRecipientAttestationV1, PoolContractError> {
        match self {
            Self::V1(attestation) => attestation.verify(descriptor, epoch, now),
            Self::V2(attestation) => attestation.verify(descriptor, epoch, now),
        }
    }

    pub fn verify_node_signature(&self) -> Result<(), PoolContractError> {
        match self {
            Self::V1(attestation) => attestation.verify_node_signature(),
            Self::V2(attestation) => attestation.verify_node_signature(),
        }
    }

    /// `None` for v1 (trust absent).
    pub fn trust_mode(&self) -> Option<PoolTrustModeV1> {
        match self {
            Self::V1(_) => None,
            Self::V2(attestation) => Some(attestation.statement.trust_mode),
        }
    }

    pub fn evidence(&self) -> &[u8] {
        match self {
            Self::V1(_) => &[],
            Self::V2(attestation) => &attestation.statement.evidence,
        }
    }

    pub fn pool(&self) -> &PoolDidV1 {
        self.base().pool()
    }

    pub fn epoch(&self) -> CustodyEpochIdentityV1 {
        self.base().epoch()
    }

    pub fn server_node_public_key(&self) -> NodePublicKey {
        self.base().server_node_public_key()
    }

    pub fn binding(&self) -> &ProtectedContentBindingV1 {
        self.base().binding()
    }

    pub fn action(&self) -> RightsActionV1 {
        self.base().action()
    }

    pub fn recipient_public_key(&self) -> RecipientPublicKeyBytesV1 {
        self.base().recipient_public_key()
    }

    pub fn recipient_identity(&self) -> &RecipientKeyIdentityV1 {
        self.base().recipient_identity()
    }

    pub fn runtime_operation_issuer(&self) -> RuntimeOperationIssuerKeyV1 {
        self.base().runtime_operation_issuer()
    }

    pub fn issued_at(&self) -> u64 {
        self.base().issued_at()
    }

    pub fn expires_at(&self) -> u64 {
        self.base().expires_at()
    }
}

impl CanonicalContract for SignedPoolRecipientAttestationAnyV1 {
    fn canonical_bytes(&self) -> Result<Vec<u8>, ContractError> {
        match self {
            Self::V1(attestation) => attestation.canonical_bytes(),
            Self::V2(attestation) => attestation.canonical_bytes(),
        }
    }

    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ContractError> {
        match SignedPoolRecipientAttestationV1::from_canonical_bytes(bytes) {
            Err(ContractError::WrongDomain) => {
                SignedPoolRecipientAttestationV2::from_canonical_bytes(bytes).map(Self::V2)
            }
            other => other.map(Self::V1),
        }
    }
}

impl From<SignedPoolRecipientAttestationV1> for SignedPoolRecipientAttestationAnyV1 {
    fn from(attestation: SignedPoolRecipientAttestationV1) -> Self {
        Self::V1(attestation)
    }
}

impl From<SignedPoolRecipientAttestationV2> for SignedPoolRecipientAttestationAnyV1 {
    fn from(attestation: SignedPoolRecipientAttestationV2) -> Self {
        Self::V2(attestation)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPoolRecipientAttestationV1 {
    statement_hash: Digest32,
    server_node_public_key: NodePublicKey,
    binding: ProtectedContentBindingV1,
    action: RightsActionV1,
    recipient_public_key: RecipientPublicKeyBytesV1,
    recipient_identity: RecipientKeyIdentityV1,
    runtime_operation_issuer: RuntimeOperationIssuerKeyV1,
    issued_at: u64,
    expires_at: u64,
    /// #388 A2: `Some` for a v2 attestation, `None` for v1 (trust absent).
    trust_mode: Option<PoolTrustModeV1>,
}

impl VerifiedPoolRecipientAttestationV1 {
    pub const fn trust_mode(&self) -> Option<PoolTrustModeV1> {
        self.trust_mode
    }

    pub const fn statement_hash(&self) -> Digest32 {
        self.statement_hash
    }

    pub const fn server_node_public_key(&self) -> NodePublicKey {
        self.server_node_public_key
    }

    pub fn binding(&self) -> &ProtectedContentBindingV1 {
        &self.binding
    }

    pub const fn action(&self) -> RightsActionV1 {
        self.action
    }

    pub const fn recipient_public_key(&self) -> RecipientPublicKeyBytesV1 {
        self.recipient_public_key
    }

    pub fn recipient_identity(&self) -> &RecipientKeyIdentityV1 {
        &self.recipient_identity
    }

    pub const fn runtime_operation_issuer(&self) -> RuntimeOperationIssuerKeyV1 {
        self.runtime_operation_issuer
    }

    pub const fn issued_at(&self) -> u64 {
        self.issued_at
    }

    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum PoolSessionContentKindV1 {
    MediaV1 = 1,
    DashV2 = 2,
    Object = 3,
}

impl PoolSessionContentKindV1 {
    pub const fn code(self) -> u8 {
        self as u8
    }

    pub fn from_code(code: u8) -> Result<Self, ContractError> {
        match code {
            1 => Ok(Self::MediaV1),
            2 => Ok(Self::DashV2),
            3 => Ok(Self::Object),
            _ => Err(ContractError::InvalidField("pool_session_content_kind")),
        }
    }
}

/// One part a pool server seals to the viewer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ViewerPartIndexV1 {
    MediaV1Init,
    MediaV1Segment(u32),
    /// `rendition` is 0..=[`MAX_VIEWER_DASH_RENDITION_V1`].
    DashInit {
        rendition: u8,
    },
    DashSegment {
        rendition: u8,
        index: u32,
    },
    ObjectChunk(u32),
}

impl ViewerPartIndexV1 {
    const MEDIA_V1_INIT: u8 = 1;
    const MEDIA_V1_SEGMENT: u8 = 2;
    const DASH_INIT: u8 = 3;
    const DASH_SEGMENT: u8 = 4;
    const OBJECT_CHUNK: u8 = 5;

    pub const fn content_kind(self) -> PoolSessionContentKindV1 {
        match self {
            Self::MediaV1Init | Self::MediaV1Segment(_) => PoolSessionContentKindV1::MediaV1,
            Self::DashInit { .. } | Self::DashSegment { .. } => PoolSessionContentKindV1::DashV2,
            Self::ObjectChunk(_) => PoolSessionContentKindV1::Object,
        }
    }

    fn validate(self) -> Result<(), ContractError> {
        match self {
            Self::DashInit { rendition } | Self::DashSegment { rendition, .. }
                if rendition > MAX_VIEWER_DASH_RENDITION_V1 =>
            {
                Err(ContractError::InvalidField("viewer_part.rendition"))
            }
            _ => Ok(()),
        }
    }

    fn encode(self, encoder: &mut Encoder) {
        match self {
            Self::MediaV1Init => encoder.u8(Self::MEDIA_V1_INIT),
            Self::MediaV1Segment(index) => {
                encoder.u8(Self::MEDIA_V1_SEGMENT);
                encoder.u32(index);
            }
            Self::DashInit { rendition } => {
                encoder.u8(Self::DASH_INIT);
                encoder.u8(rendition);
            }
            Self::DashSegment { rendition, index } => {
                encoder.u8(Self::DASH_SEGMENT);
                encoder.u8(rendition);
                encoder.u32(index);
            }
            Self::ObjectChunk(index) => {
                encoder.u8(Self::OBJECT_CHUNK);
                encoder.u32(index);
            }
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, ContractError> {
        let part = match decoder.u8()? {
            Self::MEDIA_V1_INIT => Self::MediaV1Init,
            Self::MEDIA_V1_SEGMENT => Self::MediaV1Segment(decoder.u32()?),
            Self::DASH_INIT => Self::DashInit {
                rendition: decoder.u8()?,
            },
            Self::DASH_SEGMENT => Self::DashSegment {
                rendition: decoder.u8()?,
                index: decoder.u32()?,
            },
            Self::OBJECT_CHUNK => Self::ObjectChunk(decoder.u32()?),
            _ => return Err(ContractError::InvalidField("viewer_part")),
        };
        part.validate()?;
        Ok(part)
    }
}

/// The AAD of one sealed viewer part: its canonical bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ViewerPartAadV1 {
    pub session_id: [u8; 16],
    pub operation_hash: Digest32,
    pub part: ViewerPartIndexV1,
}

impl CanonicalBody for ViewerPartAadV1 {
    const DOMAIN: &'static str = "elastos.protected-content.viewer-part-aad/v1";

    fn validate(&self) -> Result<(), ContractError> {
        self.part.validate()
    }

    fn encode_fields(&self, encoder: &mut Encoder) -> Result<(), ContractError> {
        encoder.fixed(&self.session_id);
        encoder.fixed(self.operation_hash.as_bytes());
        self.part.encode(encoder);
        Ok(())
    }

    fn decode_fields(decoder: &mut Decoder<'_>) -> Result<Self, ContractError> {
        Ok(Self {
            session_id: decoder.fixed()?,
            operation_hash: Digest32::new(decoder.fixed()?),
            part: ViewerPartIndexV1::decode(decoder)?,
        })
    }
}
