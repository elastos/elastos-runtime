//! Pool session values: ids, content references, staged content and refusals
//! shared by the pool client and the pool session server.

use elastos_protected_content_contracts::{
    DeliveryPublicKeyBytesV1, Digest32, EncryptedContentIdentityV1, PoolDidV1,
    PoolSessionContentKindV1, ProtectedContentBindingV1, RecipientPublicKeyBytesV1, RightsActionV1,
    RuntimeOperationIssuerKeyV1, SignedNodeContributionV1, SignedPoolRecipientAttestationV2,
    SignedRuntimeReleaseOperationV2, SignedTerminalReceiptV1, ViewerPartIndexV1,
};
use elastos_protected_content_provider_contracts::{
    CencDashMediaIdentityV2, CencFmp4MediaIdentityV1, ChunkedPayloadObjectIdentityV1,
};

/// A pool session id: 16 bytes, named in every sealed part's AAD.
pub type PoolSessionIdV1 = [u8; 16];

// ---------------------------------------------------------------------------
// Values
// ---------------------------------------------------------------------------

/// Who called: the authenticated Carrier endpoint, or this Runtime itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolSessionSource {
    pub endpoint_did: String,
    pub local: bool,
}

/// The full typed identity of the content a session serves (F4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PoolContentIdentityV1 {
    MediaV1(CencFmp4MediaIdentityV1),
    DashV2(CencDashMediaIdentityV2),
    Object(ChunkedPayloadObjectIdentityV1),
}

impl PoolContentIdentityV1 {
    pub fn kind(&self) -> PoolSessionContentKindV1 {
        match self {
            Self::MediaV1(_) => PoolSessionContentKindV1::MediaV1,
            Self::DashV2(_) => PoolSessionContentKindV1::DashV2,
            Self::Object(_) => PoolSessionContentKindV1::Object,
        }
    }

    pub fn encrypted_content(&self) -> &EncryptedContentIdentityV1 {
        match self {
            Self::MediaV1(identity) => identity.encrypted_content(),
            Self::DashV2(identity) => identity.encrypted_content(),
            Self::Object(identity) => identity.encrypted_content(),
        }
    }
}

/// What a session serves (F4). It comes from the buyer's verified draft.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolSessionContentRefV1 {
    pub cid: String,
    /// The kind the wire names; it must be the identity's kind.
    pub kind: PoolSessionContentKindV1,
    pub identity: PoolContentIdentityV1,
    pub content_key_commitment: Digest32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolSessionPrepareV1 {
    pub pool: PoolDidV1,
    pub binding: ProtectedContentBindingV1,
    pub action: RightsActionV1,
    pub runtime_operation_issuer: RuntimeOperationIssuerKeyV1,
    pub content: PoolSessionContentRefV1,
    pub expires_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolSessionPreparedV1 {
    pub session_id: PoolSessionIdV1,
    pub recipient_public_key: RecipientPublicKeyBytesV1,
    pub attestation: SignedPoolRecipientAttestationV2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolSessionOpenV1 {
    pub session_id: PoolSessionIdV1,
    pub operation: SignedRuntimeReleaseOperationV2,
    /// F3: its identity must be the operation's wallet-signed delivery key.
    pub delivery_public_key: DeliveryPublicKeyBytesV1,
    pub contributions: Vec<SignedNodeContributionV1>,
    pub terminal_receipt: SignedTerminalReceiptV1,
}

/// The session's end (user 2026-11-13 04:45): the signed rights expiry,
/// capped by the earliest attestation expiry
/// (`AuthenticatedRuntimeReleaseOperationV2::session_expires_at`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolSessionOpenedV1 {
    pub expires_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolSessionReadV1 {
    pub session_id: PoolSessionIdV1,
    pub part: ViewerPartIndexV1,
}

/// Bytes a content port staged and verified against the full identity (F4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolStagedContentV1 {
    pub handle: [u8; 16],
    pub total_ciphertext_bytes: u64,
    pub duration_secs: Option<u64>,
    pub open: PoolStagedOpenV1,
}

/// The open material of staged content: only bytes verified against the
/// identity. DASH leaves stay inside the stage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PoolStagedOpenV1 {
    MediaV1 {
        protected_init: Vec<u8>,
    },
    /// Head order.
    DashV2 {
        protected_inits: Vec<Vec<u8>>,
    },
    Object {
        framed_header: Vec<u8>,
    },
}

impl PoolStagedOpenV1 {
    pub(crate) fn kind(&self) -> PoolSessionContentKindV1 {
        match self {
            Self::MediaV1 { .. } => PoolSessionContentKindV1::MediaV1,
            Self::DashV2 { .. } => PoolSessionContentKindV1::DashV2,
            Self::Object { .. } => PoolSessionContentKindV1::Object,
        }
    }
}

/// One part's material. An init carries no bytes; a DASH segment carries its
/// audit path from the verified leaves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PoolStagedPartV1 {
    MediaV1Init,
    MediaV1Segment {
        index: u32,
        encrypted: Vec<u8>,
    },
    DashInit {
        rendition: u8,
    },
    DashSegment {
        rendition: u8,
        index: u32,
        encrypted: Vec<u8>,
        proof: Vec<Digest32>,
    },
    ObjectChunk {
        index: u32,
        framed_chunk: Vec<u8>,
    },
}

impl PoolStagedPartV1 {
    pub(crate) fn index(&self) -> ViewerPartIndexV1 {
        match self {
            Self::MediaV1Init => ViewerPartIndexV1::MediaV1Init,
            Self::MediaV1Segment { index, .. } => ViewerPartIndexV1::MediaV1Segment(*index),
            Self::DashInit { rendition } => ViewerPartIndexV1::DashInit {
                rendition: *rendition,
            },
            Self::DashSegment {
                rendition, index, ..
            } => ViewerPartIndexV1::DashSegment {
                rendition: *rendition,
                index: *index,
            },
            Self::ObjectChunk { index, .. } => ViewerPartIndexV1::ObjectChunk(*index),
        }
    }

    /// The ciphertext bytes the part serves; the budgets count these.
    pub(crate) fn ciphertext_bytes(&self) -> u64 {
        match self {
            Self::MediaV1Init | Self::DashInit { .. } => 0,
            Self::MediaV1Segment { encrypted, .. } | Self::DashSegment { encrypted, .. } => {
                encrypted.len() as u64
            }
            Self::ObjectChunk { framed_chunk, .. } => framed_chunk.len() as u64,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolSessionRefusal {
    SelfServe,
    NotEligible,
    NotReady,
    PoolBusy,
    /// A session bound; the name says which.
    Bound(&'static str),
    UnknownSession,
    Expired,
    BindingMismatch,
    ContentUnavailable,
    DecryptUnavailable,
}

impl PoolSessionRefusal {
    pub fn code(&self) -> &'static str {
        match self {
            Self::SelfServe => "self_serve_refused",
            Self::NotEligible => "not_eligible_server",
            Self::NotReady => "server_not_ready",
            Self::PoolBusy => "pool_busy",
            Self::Bound(_) => "session_bound_exceeded",
            Self::UnknownSession => "unknown_session",
            Self::Expired => "session_expired",
            Self::BindingMismatch => "binding_mismatch",
            Self::ContentUnavailable => "content_unavailable",
            Self::DecryptUnavailable => "decrypt_unavailable",
        }
    }
}
