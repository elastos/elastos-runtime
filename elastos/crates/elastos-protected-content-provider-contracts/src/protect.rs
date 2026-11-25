use std::collections::BTreeSet;

use elastos_protected_content_contracts::{
    ContentAccessIdV1, ContractError, CustodyCommitteeAuthorizationIdentityV1, CustodyEnvelopeV1,
    CustodyEpochIdentityV1, CustodyPoolIdentityV1, Digest32, EncryptedContentIdentityV1,
    NodeCustodyPublicKeyV1, NodePublicKey, ThresholdV1, MAX_ENCRYPTED_CONTENT_BYTES,
    PQ_HYBRID_WRAP_PUBLIC_KEY_BYTES,
};
use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};

use crate::media::{
    validate_visible_ascii, CencDashRenditionKindV2, CencFmp4MediaIdentityV1,
    MAX_CENC_FMP4_MEDIA_IDENTITY_BYTES_V1, MAX_INIT_PSSH_BYTES_V2, MAX_MEDIA_DECLARATION_BYTES_V1,
    MAX_PSSH_BOX_BYTES_V2,
};
use crate::media_dash::{CencDashMediaIdentityV2, MAX_CENC_DASH_MEDIA_IDENTITY_BYTES_V2};
use crate::object::{
    ChunkedPayloadObjectIdentityV1, MAX_CHUNKED_PAYLOAD_OBJECT_IDENTITY_BYTES_V1,
    MAX_OBJECT_FRAMED_CHUNK_BYTES_V1, MAX_OBJECT_FRAMED_HEADER_BYTES_V1,
    MAX_OBJECT_PLAINTEXT_CHUNK_BYTES_V1,
};
use crate::wire::{
    contract_decode_error, decode_json, encode_json, validate_schema, CanonicalBlob,
    CanonicalBlobList, OpaqueHandleV1, ProviderFailureCodeV1, MAX_CUSTODY_ENVELOPE_BYTES_V1,
    MAX_PROVIDER_BINDING_BYTES_V1, MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1,
};

pub const PROTECT_PROVIDER_REQUEST_SCHEMA_V1: &str =
    "elastos.protected-content.protect-provider.request/v1";
pub const PROTECT_PROVIDER_RESPONSE_SCHEMA_V1: &str =
    "elastos.protected-content.protect-provider.response/v1";
pub const MAX_PROTECT_MEDIA_PART_BYTES_V1: usize = 2 * 1024 * 1024;
pub const MAX_PROTECT_MEDIA_SEGMENTS_V1: u32 = 512;
/// Most extra (foreign) `pssh` boxes a v2 open may carry. It matches the
/// 64-child box scan of the init rewrite, which could not validate more.
const MAX_EXTRA_PSSH_BOXES_V2: usize = 64;
/// The v2 head refuses renditions whose segment counts differ by more.
const MAX_REPRESENTATION_SEGMENT_SKEW_V2: u32 = 1;
const REQUIRED_THRESHOLD_REQUIRED_V1: u8 = 2;
const REQUIRED_THRESHOLD_TOTAL_V1: u8 = 3;
/// Bound for the canonical byte encoding of `EncryptedContentIdentityV1` when
/// carried as a `CanonicalBlob`; the encoding is a domain string plus a
/// digest and a length, well under this bound.
const MAX_ENCRYPTED_CONTENT_IDENTITY_BYTES_V1: usize = 256;

type IdentityBlobV1 = CanonicalBlob<MAX_PROVIDER_BINDING_BYTES_V1>;
type MediaIdentityBlobV1 = CanonicalBlob<MAX_CENC_FMP4_MEDIA_IDENTITY_BYTES_V1>;
type CustodyEnvelopeBlobV1 = CanonicalBlob<MAX_CUSTODY_ENVELOPE_BYTES_V1>;
type MediaPartBlobV1 = CanonicalBlob<MAX_PROTECT_MEDIA_PART_BYTES_V1>;
type ObjectIdentityBlobV1 = CanonicalBlob<MAX_CHUNKED_PAYLOAD_OBJECT_IDENTITY_BYTES_V1>;
type ObjectPlaintextChunkBlobV1 = CanonicalBlob<MAX_OBJECT_PLAINTEXT_CHUNK_BYTES_V1>;
type ObjectFramedChunkBlobV1 = CanonicalBlob<MAX_OBJECT_FRAMED_CHUNK_BYTES_V1>;
type ObjectFramedHeaderBlobV1 = CanonicalBlob<MAX_OBJECT_FRAMED_HEADER_BYTES_V1>;
type EncryptedContentBlobV1 = CanonicalBlob<MAX_ENCRYPTED_CONTENT_IDENTITY_BYTES_V1>;
type ExtraPsshBoxListV2 = CanonicalBlobList<MAX_EXTRA_PSSH_BOXES_V2, MAX_PSSH_BOX_BYTES_V2>;
type ProtectedInitListV2 = CanonicalBlobList<2, MAX_PROTECT_MEDIA_PART_BYTES_V1>;
type MediaIdentityBlobV2 = CanonicalBlob<MAX_CENC_DASH_MEDIA_IDENTITY_BYTES_V2>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RenditionWireV2 {
    Video,
    Audio,
}

impl From<CencDashRenditionKindV2> for RenditionWireV2 {
    fn from(kind: CencDashRenditionKindV2) -> Self {
        match kind {
            CencDashRenditionKindV2::Video => Self::Video,
            CencDashRenditionKindV2::Audio => Self::Audio,
        }
    }
}

impl From<RenditionWireV2> for CencDashRenditionKindV2 {
    fn from(kind: RenditionWireV2) -> Self {
        match kind {
            RenditionWireV2::Video => Self::Video,
            RenditionWireV2::Audio => Self::Audio,
        }
    }
}

/// One rendition of a v2 open: its declaration and its clear init segment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectionRepresentationV2 {
    rendition: RenditionWireV2,
    mime_type: String,
    codecs: String,
    segment_count: u32,
    clear_init_segment: MediaPartBlobV1,
}

impl ProtectionRepresentationV2 {
    pub fn new(
        kind: CencDashRenditionKindV2,
        mime_type: impl Into<String>,
        codecs: impl Into<String>,
        segment_count: u32,
        clear_init_segment: &[u8],
    ) -> Result<Self, ContractError> {
        let value = Self {
            rendition: kind.into(),
            mime_type: mime_type.into(),
            codecs: codecs.into(),
            segment_count,
            clear_init_segment: MediaPartBlobV1::new(clear_init_segment.to_vec())?,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn kind(&self) -> CencDashRenditionKindV2 {
        self.rendition.into()
    }

    pub fn mime_type(&self) -> &str {
        &self.mime_type
    }

    pub fn codecs(&self) -> &str {
        &self.codecs
    }

    pub const fn segment_count(&self) -> u32 {
        self.segment_count
    }

    pub fn clear_init_segment(&self) -> &[u8] {
        self.clear_init_segment.as_slice()
    }

    fn validate(&self) -> Result<(), ContractError> {
        validate_visible_ascii(&self.mime_type, "mime_type", MAX_MEDIA_DECLARATION_BYTES_V1)?;
        validate_visible_ascii(&self.codecs, "codecs", MAX_MEDIA_DECLARATION_BYTES_V1)?;
        if self.segment_count == 0 {
            return Err(ContractError::InvalidField("segment_count"));
        }
        Ok(())
    }
}

/// Why a v2 media segment was refused, beyond the generic failure code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectFailureReasonV2 {
    CencTooManySubsamples,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectProviderRequestOpV1 {
    OpenProtectionSession,
    ProtectMediaSegment,
    FinalizeProtectionSession,
    CancelProtectionSession,
    CloseProtectionSession,
    OpenObjectProtectionSession,
    ProtectObjectChunk,
    FinalizeObjectProtectionSession,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectionSessionNodeV1 {
    node_public_key: [u8; 32],
    node_custody_public_key: Vec<u8>,
}

impl ProtectionSessionNodeV1 {
    pub fn new(
        node_public_key: NodePublicKey,
        node_custody_public_key: NodeCustodyPublicKeyV1,
    ) -> Result<Self, ContractError> {
        let value = Self {
            node_public_key: *node_public_key.as_bytes(),
            node_custody_public_key: node_custody_public_key.as_bytes().to_vec(),
        };
        let _ = value.node_public_key()?;
        let _ = value.node_custody_public_key()?;
        Ok(value)
    }

    pub fn node_public_key(&self) -> Result<NodePublicKey, ContractError> {
        NodePublicKey::new(self.node_public_key)
    }

    pub fn node_custody_public_key(&self) -> Result<NodeCustodyPublicKeyV1, ContractError> {
        let bytes: [u8; PQ_HYBRID_WRAP_PUBLIC_KEY_BYTES] = self
            .node_custody_public_key
            .as_slice()
            .try_into()
            .map_err(|_| ContractError::InvalidField("node_custody_public_key"))?;
        NodeCustodyPublicKeyV1::new(bytes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectProviderRequestV1(ProtectProviderRequestKindV1);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum ProtectProviderRequestKindV1 {
    OpenProtectionSession {
        schema: String,
        protection_session_request_id: [u8; 32],
        content_access_id: IdentityBlobV1,
        custody_pool: IdentityBlobV1,
        custody_epoch: IdentityBlobV1,
        custody_committee_authorization: IdentityBlobV1,
        threshold_required: u8,
        threshold_total: u8,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mime_type: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        codecs: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        segment_count: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        clear_init_segment: Option<MediaPartBlobV1>,
        nodes: Vec<ProtectionSessionNodeV1>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        representations: Option<Vec<ProtectionRepresentationV2>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        extra_pssh_boxes: Option<ExtraPsshBoxListV2>,
    },
    ProtectMediaSegment {
        schema: String,
        protection_session_handle: OpaqueHandleV1,
        segment_index: u32,
        clear_segment: MediaPartBlobV1,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        rendition_index: Option<u8>,
    },
    FinalizeProtectionSession {
        schema: String,
        protection_session_handle: OpaqueHandleV1,
    },
    CancelProtectionSession {
        schema: String,
        protection_session_handle: OpaqueHandleV1,
    },
    CloseProtectionSession {
        schema: String,
        protection_session_handle: OpaqueHandleV1,
    },
    OpenObjectProtectionSession {
        schema: String,
        session_id: [u8; 32],
        content_access_id: IdentityBlobV1,
        custody_pool: IdentityBlobV1,
        custody_epoch: IdentityBlobV1,
        custody_committee_authorization: IdentityBlobV1,
        threshold_required: u8,
        threshold_total: u8,
        content_type: String,
        plaintext_bytes: u64,
        nodes: Vec<ProtectionSessionNodeV1>,
    },
    ProtectObjectChunk {
        schema: String,
        session_id: [u8; 32],
        chunk_index: u32,
        plaintext: ObjectPlaintextChunkBlobV1,
    },
    FinalizeObjectProtectionSession {
        schema: String,
        session_id: [u8; 32],
        encrypted_content: EncryptedContentBlobV1,
    },
}

impl ProtectProviderRequestV1 {
    pub const fn op(&self) -> ProtectProviderRequestOpV1 {
        match self.0 {
            ProtectProviderRequestKindV1::OpenProtectionSession { .. } => {
                ProtectProviderRequestOpV1::OpenProtectionSession
            }
            ProtectProviderRequestKindV1::ProtectMediaSegment { .. } => {
                ProtectProviderRequestOpV1::ProtectMediaSegment
            }
            ProtectProviderRequestKindV1::FinalizeProtectionSession { .. } => {
                ProtectProviderRequestOpV1::FinalizeProtectionSession
            }
            ProtectProviderRequestKindV1::CancelProtectionSession { .. } => {
                ProtectProviderRequestOpV1::CancelProtectionSession
            }
            ProtectProviderRequestKindV1::CloseProtectionSession { .. } => {
                ProtectProviderRequestOpV1::CloseProtectionSession
            }
            ProtectProviderRequestKindV1::OpenObjectProtectionSession { .. } => {
                ProtectProviderRequestOpV1::OpenObjectProtectionSession
            }
            ProtectProviderRequestKindV1::ProtectObjectChunk { .. } => {
                ProtectProviderRequestOpV1::ProtectObjectChunk
            }
            ProtectProviderRequestKindV1::FinalizeObjectProtectionSession { .. } => {
                ProtectProviderRequestOpV1::FinalizeObjectProtectionSession
            }
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the producer session must bind the exact committee identities, media declaration, and bounded init bytes"
    )]
    pub fn new_open_protection_session(
        protection_session_request_id: Digest32,
        content_access_id: ContentAccessIdV1,
        custody_pool: CustodyPoolIdentityV1,
        custody_epoch: CustodyEpochIdentityV1,
        custody_committee_authorization: CustodyCommitteeAuthorizationIdentityV1,
        mime_type: impl Into<String>,
        codecs: impl Into<String>,
        segment_count: u32,
        clear_init_segment: &[u8],
        nodes: Vec<ProtectionSessionNodeV1>,
    ) -> Result<Self, ContractError> {
        let value = Self(ProtectProviderRequestKindV1::OpenProtectionSession {
            schema: PROTECT_PROVIDER_REQUEST_SCHEMA_V1.to_string(),
            protection_session_request_id: *protection_session_request_id.as_bytes(),
            content_access_id: CanonicalBlob::from_contract(&content_access_id)?,
            custody_pool: CanonicalBlob::from_contract(&custody_pool)?,
            custody_epoch: CanonicalBlob::from_contract(&custody_epoch)?,
            custody_committee_authorization: CanonicalBlob::from_contract(
                &custody_committee_authorization,
            )?,
            threshold_required: REQUIRED_THRESHOLD_REQUIRED_V1,
            threshold_total: REQUIRED_THRESHOLD_TOTAL_V1,
            mime_type: Some(mime_type.into()),
            codecs: Some(codecs.into()),
            segment_count: Some(segment_count),
            clear_init_segment: Some(MediaPartBlobV1::new(clear_init_segment.to_vec())?),
            nodes,
            representations: None,
            extra_pssh_boxes: None,
        });
        value.validate_structure()?;
        Ok(value)
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the v2 producer session binds the committee identities, every rendition, and the foreign pssh boxes"
    )]
    pub fn new_open_protection_session_v2(
        protection_session_request_id: Digest32,
        content_access_id: ContentAccessIdV1,
        custody_pool: CustodyPoolIdentityV1,
        custody_epoch: CustodyEpochIdentityV1,
        custody_committee_authorization: CustodyCommitteeAuthorizationIdentityV1,
        representations: Vec<ProtectionRepresentationV2>,
        extra_pssh_boxes: &[Vec<u8>],
        nodes: Vec<ProtectionSessionNodeV1>,
    ) -> Result<Self, ContractError> {
        let extra_pssh_boxes = if extra_pssh_boxes.is_empty() {
            None
        } else {
            Some(ExtraPsshBoxListV2::new(
                extra_pssh_boxes
                    .iter()
                    .map(|bytes| CanonicalBlob::new(bytes.clone()))
                    .collect::<Result<Vec<_>, _>>()?,
            )?)
        };
        let value = Self(ProtectProviderRequestKindV1::OpenProtectionSession {
            schema: PROTECT_PROVIDER_REQUEST_SCHEMA_V1.to_string(),
            protection_session_request_id: *protection_session_request_id.as_bytes(),
            content_access_id: CanonicalBlob::from_contract(&content_access_id)?,
            custody_pool: CanonicalBlob::from_contract(&custody_pool)?,
            custody_epoch: CanonicalBlob::from_contract(&custody_epoch)?,
            custody_committee_authorization: CanonicalBlob::from_contract(
                &custody_committee_authorization,
            )?,
            threshold_required: REQUIRED_THRESHOLD_REQUIRED_V1,
            threshold_total: REQUIRED_THRESHOLD_TOTAL_V1,
            mime_type: None,
            codecs: None,
            segment_count: None,
            clear_init_segment: None,
            nodes,
            representations: Some(representations),
            extra_pssh_boxes,
        });
        value.validate_structure()?;
        Ok(value)
    }

    pub fn new_protect_media_segment(
        protection_session_handle: [u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1],
        segment_index: u32,
        clear_segment: &[u8],
    ) -> Result<Self, ContractError> {
        let value = Self(ProtectProviderRequestKindV1::ProtectMediaSegment {
            schema: PROTECT_PROVIDER_REQUEST_SCHEMA_V1.to_string(),
            protection_session_handle: OpaqueHandleV1::new(protection_session_handle)?,
            segment_index,
            clear_segment: MediaPartBlobV1::new(clear_segment.to_vec())?,
            rendition_index: None,
        });
        value.validate_structure()?;
        Ok(value)
    }

    /// A v2 segment: `segment_index` is the 0-based index within the rendition
    /// at `rendition_index` (the position in the head, video first).
    pub fn new_protect_media_segment_v2(
        protection_session_handle: [u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1],
        rendition_index: u8,
        segment_index: u32,
        clear_segment: &[u8],
    ) -> Result<Self, ContractError> {
        let value = Self(ProtectProviderRequestKindV1::ProtectMediaSegment {
            schema: PROTECT_PROVIDER_REQUEST_SCHEMA_V1.to_string(),
            protection_session_handle: OpaqueHandleV1::new(protection_session_handle)?,
            segment_index,
            clear_segment: MediaPartBlobV1::new(clear_segment.to_vec())?,
            rendition_index: Some(rendition_index),
        });
        value.validate_structure()?;
        Ok(value)
    }

    pub fn new_finalize_protection_session(
        protection_session_handle: [u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1],
    ) -> Result<Self, ContractError> {
        let value = Self(ProtectProviderRequestKindV1::FinalizeProtectionSession {
            schema: PROTECT_PROVIDER_REQUEST_SCHEMA_V1.to_string(),
            protection_session_handle: OpaqueHandleV1::new(protection_session_handle)?,
        });
        value.validate_structure()?;
        Ok(value)
    }

    pub fn new_cancel_protection_session(
        protection_session_handle: [u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1],
    ) -> Result<Self, ContractError> {
        let value = Self(ProtectProviderRequestKindV1::CancelProtectionSession {
            schema: PROTECT_PROVIDER_REQUEST_SCHEMA_V1.to_string(),
            protection_session_handle: OpaqueHandleV1::new(protection_session_handle)?,
        });
        value.validate_structure()?;
        Ok(value)
    }

    pub fn new_close_protection_session(
        protection_session_handle: [u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1],
    ) -> Result<Self, ContractError> {
        let value = Self(ProtectProviderRequestKindV1::CloseProtectionSession {
            schema: PROTECT_PROVIDER_REQUEST_SCHEMA_V1.to_string(),
            protection_session_handle: OpaqueHandleV1::new(protection_session_handle)?,
        });
        value.validate_structure()?;
        Ok(value)
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the producer session must bind the exact committee identities, object declaration, and threshold, mirroring new_open_protection_session"
    )]
    pub fn new_open_object_protection_session(
        session_id: Digest32,
        content_access_id: ContentAccessIdV1,
        custody_pool: CustodyPoolIdentityV1,
        custody_epoch: CustodyEpochIdentityV1,
        custody_committee_authorization: CustodyCommitteeAuthorizationIdentityV1,
        threshold_required: u8,
        threshold_total: u8,
        content_type: impl Into<String>,
        plaintext_bytes: u64,
        nodes: Vec<ProtectionSessionNodeV1>,
    ) -> Result<Self, ContractError> {
        let value = Self(ProtectProviderRequestKindV1::OpenObjectProtectionSession {
            schema: PROTECT_PROVIDER_REQUEST_SCHEMA_V1.to_string(),
            session_id: *session_id.as_bytes(),
            content_access_id: CanonicalBlob::from_contract(&content_access_id)?,
            custody_pool: CanonicalBlob::from_contract(&custody_pool)?,
            custody_epoch: CanonicalBlob::from_contract(&custody_epoch)?,
            custody_committee_authorization: CanonicalBlob::from_contract(
                &custody_committee_authorization,
            )?,
            threshold_required,
            threshold_total,
            content_type: content_type.into(),
            plaintext_bytes,
            nodes,
        });
        value.validate_structure()?;
        Ok(value)
    }

    pub fn new_protect_object_chunk(
        session_id: Digest32,
        chunk_index: u32,
        plaintext: &[u8],
    ) -> Result<Self, ContractError> {
        let value = Self(ProtectProviderRequestKindV1::ProtectObjectChunk {
            schema: PROTECT_PROVIDER_REQUEST_SCHEMA_V1.to_string(),
            session_id: *session_id.as_bytes(),
            chunk_index,
            plaintext: ObjectPlaintextChunkBlobV1::new(plaintext.to_vec())?,
        });
        value.validate_structure()?;
        Ok(value)
    }

    pub fn new_finalize_object_protection_session(
        session_id: Digest32,
        encrypted_content: &EncryptedContentIdentityV1,
    ) -> Result<Self, ContractError> {
        let value = Self(
            ProtectProviderRequestKindV1::FinalizeObjectProtectionSession {
                schema: PROTECT_PROVIDER_REQUEST_SCHEMA_V1.to_string(),
                session_id: *session_id.as_bytes(),
                encrypted_content: CanonicalBlob::from_contract(encrypted_content)?,
            },
        );
        value.validate_structure()?;
        Ok(value)
    }

    pub fn to_json_vec(&self) -> Result<Vec<u8>, serde_json::Error> {
        encode_json(self)
    }

    pub fn from_json_slice(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        Self::decode_wire(bytes)
    }

    pub fn session_id(&self) -> Option<Digest32> {
        match &self.0 {
            ProtectProviderRequestKindV1::OpenObjectProtectionSession { session_id, .. }
            | ProtectProviderRequestKindV1::ProtectObjectChunk { session_id, .. }
            | ProtectProviderRequestKindV1::FinalizeObjectProtectionSession {
                session_id, ..
            } => Some(Digest32::new(*session_id)),
            _ => None,
        }
    }

    pub fn content_type(&self) -> Option<&str> {
        match &self.0 {
            ProtectProviderRequestKindV1::OpenObjectProtectionSession { content_type, .. } => {
                Some(content_type.as_str())
            }
            _ => None,
        }
    }

    pub fn plaintext_bytes(&self) -> Option<u64> {
        match &self.0 {
            ProtectProviderRequestKindV1::OpenObjectProtectionSession {
                plaintext_bytes, ..
            } => Some(*plaintext_bytes),
            _ => None,
        }
    }

    pub fn threshold_required(&self) -> Option<u8> {
        match &self.0 {
            ProtectProviderRequestKindV1::OpenObjectProtectionSession {
                threshold_required,
                ..
            } => Some(*threshold_required),
            _ => None,
        }
    }

    pub fn threshold_total(&self) -> Option<u8> {
        match &self.0 {
            ProtectProviderRequestKindV1::OpenObjectProtectionSession {
                threshold_total, ..
            } => Some(*threshold_total),
            _ => None,
        }
    }

    pub fn chunk_index(&self) -> Option<u32> {
        match &self.0 {
            ProtectProviderRequestKindV1::ProtectObjectChunk { chunk_index, .. } => {
                Some(*chunk_index)
            }
            _ => None,
        }
    }

    pub fn plaintext(&self) -> Option<&[u8]> {
        match &self.0 {
            ProtectProviderRequestKindV1::ProtectObjectChunk { plaintext, .. } => {
                Some(plaintext.as_slice())
            }
            _ => None,
        }
    }

    pub fn encrypted_content(&self) -> Result<Option<EncryptedContentIdentityV1>, ContractError> {
        match &self.0 {
            ProtectProviderRequestKindV1::FinalizeObjectProtectionSession {
                encrypted_content,
                ..
            } => Ok(Some(encrypted_content.decode()?)),
            _ => Ok(None),
        }
    }

    pub fn protection_session_request_id(&self) -> Option<Digest32> {
        match &self.0 {
            ProtectProviderRequestKindV1::OpenProtectionSession {
                protection_session_request_id,
                ..
            } => Some(Digest32::new(*protection_session_request_id)),
            _ => None,
        }
    }

    pub fn custody_pool(&self) -> Result<Option<CustodyPoolIdentityV1>, ContractError> {
        match &self.0 {
            ProtectProviderRequestKindV1::OpenProtectionSession { custody_pool, .. }
            | ProtectProviderRequestKindV1::OpenObjectProtectionSession { custody_pool, .. } => {
                Ok(Some(custody_pool.decode()?))
            }
            _ => Ok(None),
        }
    }

    pub fn content_access_id(&self) -> Result<Option<ContentAccessIdV1>, ContractError> {
        match &self.0 {
            ProtectProviderRequestKindV1::OpenProtectionSession {
                content_access_id, ..
            }
            | ProtectProviderRequestKindV1::OpenObjectProtectionSession {
                content_access_id, ..
            } => Ok(Some(content_access_id.decode()?)),
            _ => Ok(None),
        }
    }

    pub fn custody_epoch(&self) -> Result<Option<CustodyEpochIdentityV1>, ContractError> {
        match &self.0 {
            ProtectProviderRequestKindV1::OpenProtectionSession { custody_epoch, .. }
            | ProtectProviderRequestKindV1::OpenObjectProtectionSession { custody_epoch, .. } => {
                Ok(Some(custody_epoch.decode()?))
            }
            _ => Ok(None),
        }
    }

    pub fn custody_committee_authorization(
        &self,
    ) -> Result<Option<CustodyCommitteeAuthorizationIdentityV1>, ContractError> {
        match &self.0 {
            ProtectProviderRequestKindV1::OpenProtectionSession {
                custody_committee_authorization,
                ..
            }
            | ProtectProviderRequestKindV1::OpenObjectProtectionSession {
                custody_committee_authorization,
                ..
            } => Ok(Some(custody_committee_authorization.decode()?)),
            _ => Ok(None),
        }
    }

    pub fn mime_type(&self) -> Option<&str> {
        match &self.0 {
            ProtectProviderRequestKindV1::OpenProtectionSession { mime_type, .. } => {
                mime_type.as_deref()
            }
            _ => None,
        }
    }

    pub fn codecs(&self) -> Option<&str> {
        match &self.0 {
            ProtectProviderRequestKindV1::OpenProtectionSession { codecs, .. } => codecs.as_deref(),
            _ => None,
        }
    }

    pub fn segment_count(&self) -> Option<u32> {
        match &self.0 {
            ProtectProviderRequestKindV1::OpenProtectionSession { segment_count, .. } => {
                *segment_count
            }
            _ => None,
        }
    }

    pub fn representations(&self) -> Option<&[ProtectionRepresentationV2]> {
        match &self.0 {
            ProtectProviderRequestKindV1::OpenProtectionSession {
                representations, ..
            } => representations.as_deref(),
            _ => None,
        }
    }

    /// The foreign `pssh` boxes of a v2 open, empty when there are none.
    pub fn extra_pssh_boxes(&self) -> Vec<Vec<u8>> {
        match &self.0 {
            ProtectProviderRequestKindV1::OpenProtectionSession {
                extra_pssh_boxes: Some(boxes),
                ..
            } => boxes.iter().map(<[u8]>::to_vec).collect(),
            _ => Vec::new(),
        }
    }

    pub fn rendition_index(&self) -> Option<u8> {
        match &self.0 {
            ProtectProviderRequestKindV1::ProtectMediaSegment {
                rendition_index, ..
            } => *rendition_index,
            _ => None,
        }
    }

    pub fn clear_init_segment(&self) -> Option<&[u8]> {
        match &self.0 {
            ProtectProviderRequestKindV1::OpenProtectionSession {
                clear_init_segment, ..
            } => clear_init_segment.as_ref().map(CanonicalBlob::as_slice),
            _ => None,
        }
    }

    pub fn nodes(&self) -> Option<&[ProtectionSessionNodeV1]> {
        match &self.0 {
            ProtectProviderRequestKindV1::OpenProtectionSession { nodes, .. }
            | ProtectProviderRequestKindV1::OpenObjectProtectionSession { nodes, .. } => {
                Some(nodes)
            }
            _ => None,
        }
    }

    pub fn protection_session_handle(
        &self,
    ) -> Result<Option<[u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1]>, ContractError> {
        match &self.0 {
            ProtectProviderRequestKindV1::ProtectMediaSegment {
                protection_session_handle,
                ..
            }
            | ProtectProviderRequestKindV1::FinalizeProtectionSession {
                protection_session_handle,
                ..
            }
            | ProtectProviderRequestKindV1::CancelProtectionSession {
                protection_session_handle,
                ..
            }
            | ProtectProviderRequestKindV1::CloseProtectionSession {
                protection_session_handle,
                ..
            } => Ok(Some(*protection_session_handle.as_bytes())),
            _ => Ok(None),
        }
    }

    pub fn segment_index(&self) -> Option<u32> {
        match &self.0 {
            ProtectProviderRequestKindV1::ProtectMediaSegment { segment_index, .. } => {
                Some(*segment_index)
            }
            _ => None,
        }
    }

    pub fn clear_segment(&self) -> Option<&[u8]> {
        match &self.0 {
            ProtectProviderRequestKindV1::ProtectMediaSegment { clear_segment, .. } => {
                Some(clear_segment.as_slice())
            }
            _ => None,
        }
    }

    fn validate_structure(&self) -> Result<(), ContractError> {
        match &self.0 {
            ProtectProviderRequestKindV1::OpenProtectionSession {
                schema,
                protection_session_request_id,
                threshold_required,
                threshold_total,
                mime_type,
                codecs,
                segment_count,
                clear_init_segment,
                nodes,
                representations,
                extra_pssh_boxes,
                ..
            } => {
                validate_schema(
                    schema,
                    PROTECT_PROVIDER_REQUEST_SCHEMA_V1,
                    "protect_provider_request.schema",
                )?;
                if *protection_session_request_id == [0u8; 32] {
                    return Err(ContractError::InvalidField("protection_session_request_id"));
                }
                let _ = self
                    .content_access_id()?
                    .ok_or(ContractError::InvalidField("content_access_id"))?;
                if *threshold_required != REQUIRED_THRESHOLD_REQUIRED_V1
                    || *threshold_total != REQUIRED_THRESHOLD_TOTAL_V1
                {
                    return Err(ContractError::InvalidField("threshold"));
                }
                match (
                    mime_type,
                    codecs,
                    segment_count,
                    clear_init_segment,
                    representations,
                ) {
                    (Some(mime_type), Some(codecs), Some(segment_count), Some(_), None) => {
                        if extra_pssh_boxes.is_some() {
                            return Err(ContractError::InvalidField("extra_pssh_boxes"));
                        }
                        validate_visible_ascii(
                            mime_type,
                            "mime_type",
                            MAX_MEDIA_DECLARATION_BYTES_V1,
                        )?;
                        validate_visible_ascii(codecs, "codecs", MAX_MEDIA_DECLARATION_BYTES_V1)?;
                        if *segment_count == 0 || *segment_count > MAX_PROTECT_MEDIA_SEGMENTS_V1 {
                            return Err(ContractError::InvalidField("segment_count"));
                        }
                    }
                    (None, None, None, None, Some(representations)) => {
                        validate_representations_v2(representations)?;
                        if let Some(boxes) = extra_pssh_boxes {
                            let total: usize = boxes.iter().map(<[u8]>::len).sum();
                            if total > MAX_INIT_PSSH_BYTES_V2 {
                                return Err(ContractError::InvalidField("extra_pssh_boxes"));
                            }
                        }
                    }
                    _ => return Err(ContractError::InvalidField("representations")),
                }
                if nodes.len() != usize::from(REQUIRED_THRESHOLD_TOTAL_V1) {
                    return Err(ContractError::InvalidField("nodes"));
                }
                let mut node_keys = BTreeSet::new();
                let mut custody_keys = BTreeSet::new();
                for node in nodes {
                    let node_public_key = node.node_public_key()?;
                    let node_custody_public_key = node.node_custody_public_key()?;
                    if !node_keys.insert(node_public_key)
                        || !custody_keys.insert(node_custody_public_key)
                    {
                        return Err(ContractError::InvalidField("nodes"));
                    }
                }
                let _ = self
                    .custody_pool()?
                    .ok_or(ContractError::InvalidField("custody_pool"))?;
                let _ = self
                    .custody_epoch()?
                    .ok_or(ContractError::InvalidField("custody_epoch"))?;
                let _ =
                    self.custody_committee_authorization()?
                        .ok_or(ContractError::InvalidField(
                            "custody_committee_authorization",
                        ))?;
                Ok(())
            }
            ProtectProviderRequestKindV1::ProtectMediaSegment {
                schema,
                rendition_index,
                ..
            } => {
                validate_schema(
                    schema,
                    PROTECT_PROVIDER_REQUEST_SCHEMA_V1,
                    "protect_provider_request.schema",
                )?;
                if rendition_index.is_some_and(|index| index > 1) {
                    return Err(ContractError::InvalidField("rendition_index"));
                }
                Ok(())
            }
            ProtectProviderRequestKindV1::FinalizeProtectionSession { schema, .. }
            | ProtectProviderRequestKindV1::CancelProtectionSession { schema, .. }
            | ProtectProviderRequestKindV1::CloseProtectionSession { schema, .. } => {
                validate_schema(
                    schema,
                    PROTECT_PROVIDER_REQUEST_SCHEMA_V1,
                    "protect_provider_request.schema",
                )
            }
            ProtectProviderRequestKindV1::OpenObjectProtectionSession {
                schema,
                session_id,
                threshold_required,
                threshold_total,
                content_type,
                plaintext_bytes,
                nodes,
                ..
            } => {
                validate_schema(
                    schema,
                    PROTECT_PROVIDER_REQUEST_SCHEMA_V1,
                    "protect_provider_request.schema",
                )?;
                if *session_id == [0u8; 32] {
                    return Err(ContractError::InvalidField("session_id"));
                }
                let _ = self
                    .content_access_id()?
                    .ok_or(ContractError::InvalidField("content_access_id"))?;
                let threshold = ThresholdV1::new(*threshold_required, *threshold_total)
                    .map_err(|_| ContractError::InvalidField("threshold"))?;
                validate_visible_ascii(
                    content_type,
                    "content_type",
                    MAX_MEDIA_DECLARATION_BYTES_V1,
                )?;
                if *plaintext_bytes == 0 || *plaintext_bytes > MAX_ENCRYPTED_CONTENT_BYTES {
                    return Err(ContractError::InvalidField("plaintext_bytes"));
                }
                if nodes.len() != usize::from(threshold.total()) {
                    return Err(ContractError::InvalidField("nodes"));
                }
                let mut node_keys = BTreeSet::new();
                let mut custody_keys = BTreeSet::new();
                for node in nodes {
                    let node_public_key = node.node_public_key()?;
                    let node_custody_public_key = node.node_custody_public_key()?;
                    if !node_keys.insert(node_public_key)
                        || !custody_keys.insert(node_custody_public_key)
                    {
                        return Err(ContractError::InvalidField("nodes"));
                    }
                }
                let _ = self
                    .custody_pool()?
                    .ok_or(ContractError::InvalidField("custody_pool"))?;
                let _ = self
                    .custody_epoch()?
                    .ok_or(ContractError::InvalidField("custody_epoch"))?;
                let _ =
                    self.custody_committee_authorization()?
                        .ok_or(ContractError::InvalidField(
                            "custody_committee_authorization",
                        ))?;
                Ok(())
            }
            ProtectProviderRequestKindV1::ProtectObjectChunk {
                schema, session_id, ..
            } => {
                validate_schema(
                    schema,
                    PROTECT_PROVIDER_REQUEST_SCHEMA_V1,
                    "protect_provider_request.schema",
                )?;
                if *session_id == [0u8; 32] {
                    return Err(ContractError::InvalidField("session_id"));
                }
                Ok(())
            }
            ProtectProviderRequestKindV1::FinalizeObjectProtectionSession {
                schema,
                session_id,
                encrypted_content,
            } => {
                validate_schema(
                    schema,
                    PROTECT_PROVIDER_REQUEST_SCHEMA_V1,
                    "protect_provider_request.schema",
                )?;
                if *session_id == [0u8; 32] {
                    return Err(ContractError::InvalidField("session_id"));
                }
                let _ = encrypted_content.decode::<EncryptedContentIdentityV1>()?;
                Ok(())
            }
        }
    }

    fn decode_wire(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        let inner = decode_json::<ProtectProviderRequestKindV1>(bytes)?;
        let value = Self(inner);
        value.validate_structure().map_err(contract_decode_error)?;
        Ok(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectProviderResponseStatusV1 {
    ProtectionSessionOpened,
    MediaSegmentProtected,
    ProtectionSessionFinalized,
    ProtectionSessionCancelled,
    ProtectionSessionClosed,
    ProtectionSessionAlreadyAbsent,
    ObjectProtectionSessionOpened,
    ObjectChunkProtected,
    ObjectProtectionSessionFinalized,
    Failure,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectProviderResponseV1(ProtectProviderResponseKindV1);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
enum ProtectProviderResponseKindV1 {
    ProtectionSessionOpened {
        schema: String,
        protection_session_handle: OpaqueHandleV1,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        protected_init_segment: Option<MediaPartBlobV1>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        protected_init_segments: Option<ProtectedInitListV2>,
    },
    MediaSegmentProtected {
        schema: String,
        protection_session_handle: OpaqueHandleV1,
        segment_index: u32,
        protected_segment: MediaPartBlobV1,
    },
    ProtectionSessionFinalized {
        schema: String,
        protection_session_handle: OpaqueHandleV1,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        media_identity: Option<MediaIdentityBlobV1>,
        custody_envelope: CustodyEnvelopeBlobV1,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        media_identity_v2: Option<MediaIdentityBlobV2>,
    },
    ProtectionSessionCancelled {
        schema: String,
        protection_session_handle: OpaqueHandleV1,
    },
    ProtectionSessionClosed {
        schema: String,
        protection_session_handle: OpaqueHandleV1,
    },
    ProtectionSessionAlreadyAbsent {
        schema: String,
        protection_session_handle: OpaqueHandleV1,
    },
    ObjectProtectionSessionOpened {
        schema: String,
        framed_header: ObjectFramedHeaderBlobV1,
    },
    ObjectChunkProtected {
        schema: String,
        framed_chunk: ObjectFramedChunkBlobV1,
    },
    ObjectProtectionSessionFinalized {
        schema: String,
        object_identity: ObjectIdentityBlobV1,
        content_key_commitment: [u8; 32],
        custody_envelope: CustodyEnvelopeBlobV1,
    },
    Failure {
        schema: String,
        failure_code: ProviderFailureCodeV1,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        failure_reason: Option<ProtectFailureReasonV2>,
    },
}

impl ProtectProviderResponseV1 {
    pub const fn status(&self) -> ProtectProviderResponseStatusV1 {
        match self.0 {
            ProtectProviderResponseKindV1::ProtectionSessionOpened { .. } => {
                ProtectProviderResponseStatusV1::ProtectionSessionOpened
            }
            ProtectProviderResponseKindV1::MediaSegmentProtected { .. } => {
                ProtectProviderResponseStatusV1::MediaSegmentProtected
            }
            ProtectProviderResponseKindV1::ProtectionSessionFinalized { .. } => {
                ProtectProviderResponseStatusV1::ProtectionSessionFinalized
            }
            ProtectProviderResponseKindV1::ProtectionSessionCancelled { .. } => {
                ProtectProviderResponseStatusV1::ProtectionSessionCancelled
            }
            ProtectProviderResponseKindV1::ProtectionSessionClosed { .. } => {
                ProtectProviderResponseStatusV1::ProtectionSessionClosed
            }
            ProtectProviderResponseKindV1::ProtectionSessionAlreadyAbsent { .. } => {
                ProtectProviderResponseStatusV1::ProtectionSessionAlreadyAbsent
            }
            ProtectProviderResponseKindV1::ObjectProtectionSessionOpened { .. } => {
                ProtectProviderResponseStatusV1::ObjectProtectionSessionOpened
            }
            ProtectProviderResponseKindV1::ObjectChunkProtected { .. } => {
                ProtectProviderResponseStatusV1::ObjectChunkProtected
            }
            ProtectProviderResponseKindV1::ObjectProtectionSessionFinalized { .. } => {
                ProtectProviderResponseStatusV1::ObjectProtectionSessionFinalized
            }
            ProtectProviderResponseKindV1::Failure { .. } => {
                ProtectProviderResponseStatusV1::Failure
            }
        }
    }

    pub fn new_opened(
        protection_session_handle: [u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1],
        protected_init_segment: &[u8],
    ) -> Result<Self, ContractError> {
        let value = Self(ProtectProviderResponseKindV1::ProtectionSessionOpened {
            schema: PROTECT_PROVIDER_RESPONSE_SCHEMA_V1.to_string(),
            protection_session_handle: OpaqueHandleV1::new(protection_session_handle)?,
            protected_init_segment: Some(MediaPartBlobV1::new(protected_init_segment.to_vec())?),
            protected_init_segments: None,
        });
        value.validate_structure()?;
        Ok(value)
    }

    /// A v2 open: one protected init per rendition, in request order.
    pub fn new_opened_v2(
        protection_session_handle: [u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1],
        protected_init_segments: &[Vec<u8>],
    ) -> Result<Self, ContractError> {
        let value = Self(ProtectProviderResponseKindV1::ProtectionSessionOpened {
            schema: PROTECT_PROVIDER_RESPONSE_SCHEMA_V1.to_string(),
            protection_session_handle: OpaqueHandleV1::new(protection_session_handle)?,
            protected_init_segment: None,
            protected_init_segments: Some(ProtectedInitListV2::new(
                protected_init_segments
                    .iter()
                    .map(|bytes| MediaPartBlobV1::new(bytes.clone()))
                    .collect::<Result<Vec<_>, _>>()?,
            )?),
        });
        value.validate_structure()?;
        Ok(value)
    }

    pub fn new_segment_protected(
        protection_session_handle: [u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1],
        segment_index: u32,
        protected_segment: &[u8],
    ) -> Result<Self, ContractError> {
        let value = Self(ProtectProviderResponseKindV1::MediaSegmentProtected {
            schema: PROTECT_PROVIDER_RESPONSE_SCHEMA_V1.to_string(),
            protection_session_handle: OpaqueHandleV1::new(protection_session_handle)?,
            segment_index,
            protected_segment: MediaPartBlobV1::new(protected_segment.to_vec())?,
        });
        value.validate_structure()?;
        Ok(value)
    }

    pub fn new_finalized(
        protection_session_handle: [u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1],
        media_identity: &CencFmp4MediaIdentityV1,
        custody_envelope: &CustodyEnvelopeV1,
    ) -> Result<Self, ContractError> {
        let value = Self(ProtectProviderResponseKindV1::ProtectionSessionFinalized {
            schema: PROTECT_PROVIDER_RESPONSE_SCHEMA_V1.to_string(),
            protection_session_handle: OpaqueHandleV1::new(protection_session_handle)?,
            media_identity: Some(CanonicalBlob::from_contract(media_identity)?),
            custody_envelope: CanonicalBlob::from_contract(custody_envelope)?,
            media_identity_v2: None,
        });
        value.validate_structure()?;
        Ok(value)
    }

    pub fn new_finalized_v2(
        protection_session_handle: [u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1],
        media_identity: &CencDashMediaIdentityV2,
        custody_envelope: &CustodyEnvelopeV1,
    ) -> Result<Self, ContractError> {
        let value = Self(ProtectProviderResponseKindV1::ProtectionSessionFinalized {
            schema: PROTECT_PROVIDER_RESPONSE_SCHEMA_V1.to_string(),
            protection_session_handle: OpaqueHandleV1::new(protection_session_handle)?,
            media_identity: None,
            custody_envelope: CanonicalBlob::from_contract(custody_envelope)?,
            media_identity_v2: Some(CanonicalBlob::from_contract(media_identity)?),
        });
        value.validate_structure()?;
        Ok(value)
    }

    pub fn new_cancelled(
        protection_session_handle: [u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1],
    ) -> Result<Self, ContractError> {
        let value = Self(ProtectProviderResponseKindV1::ProtectionSessionCancelled {
            schema: PROTECT_PROVIDER_RESPONSE_SCHEMA_V1.to_string(),
            protection_session_handle: OpaqueHandleV1::new(protection_session_handle)?,
        });
        value.validate_structure()?;
        Ok(value)
    }

    pub fn new_closed(
        protection_session_handle: [u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1],
    ) -> Result<Self, ContractError> {
        let value = Self(ProtectProviderResponseKindV1::ProtectionSessionClosed {
            schema: PROTECT_PROVIDER_RESPONSE_SCHEMA_V1.to_string(),
            protection_session_handle: OpaqueHandleV1::new(protection_session_handle)?,
        });
        value.validate_structure()?;
        Ok(value)
    }

    pub fn new_already_absent(
        protection_session_handle: [u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1],
    ) -> Result<Self, ContractError> {
        let value = Self(
            ProtectProviderResponseKindV1::ProtectionSessionAlreadyAbsent {
                schema: PROTECT_PROVIDER_RESPONSE_SCHEMA_V1.to_string(),
                protection_session_handle: OpaqueHandleV1::new(protection_session_handle)?,
            },
        );
        value.validate_structure()?;
        Ok(value)
    }

    pub fn new_object_opened(framed_header: &[u8]) -> Result<Self, ContractError> {
        let value = Self(
            ProtectProviderResponseKindV1::ObjectProtectionSessionOpened {
                schema: PROTECT_PROVIDER_RESPONSE_SCHEMA_V1.to_string(),
                framed_header: ObjectFramedHeaderBlobV1::new(framed_header.to_vec())?,
            },
        );
        value.validate_structure()?;
        Ok(value)
    }

    pub fn new_object_chunk_protected(framed_chunk: &[u8]) -> Result<Self, ContractError> {
        let value = Self(ProtectProviderResponseKindV1::ObjectChunkProtected {
            schema: PROTECT_PROVIDER_RESPONSE_SCHEMA_V1.to_string(),
            framed_chunk: ObjectFramedChunkBlobV1::new(framed_chunk.to_vec())?,
        });
        value.validate_structure()?;
        Ok(value)
    }

    pub fn new_object_finalized(
        object_identity: &ChunkedPayloadObjectIdentityV1,
        content_key_commitment: Digest32,
        custody_envelope: &CustodyEnvelopeV1,
    ) -> Result<Self, ContractError> {
        let value = Self(
            ProtectProviderResponseKindV1::ObjectProtectionSessionFinalized {
                schema: PROTECT_PROVIDER_RESPONSE_SCHEMA_V1.to_string(),
                object_identity: CanonicalBlob::from_contract(object_identity)?,
                content_key_commitment: *content_key_commitment.as_bytes(),
                custody_envelope: CanonicalBlob::from_contract(custody_envelope)?,
            },
        );
        value.validate_structure()?;
        Ok(value)
    }

    pub fn new_failure(failure_code: ProviderFailureCodeV1) -> Result<Self, ContractError> {
        let value = Self(ProtectProviderResponseKindV1::Failure {
            schema: PROTECT_PROVIDER_RESPONSE_SCHEMA_V1.to_string(),
            failure_code,
            failure_reason: None,
        });
        value.validate_structure()?;
        Ok(value)
    }

    /// A failure on a v2 session that names why. Only `InvalidRequest` may
    /// carry a reason.
    pub fn new_failure_with_reason(
        failure_code: ProviderFailureCodeV1,
        failure_reason: ProtectFailureReasonV2,
    ) -> Result<Self, ContractError> {
        let value = Self(ProtectProviderResponseKindV1::Failure {
            schema: PROTECT_PROVIDER_RESPONSE_SCHEMA_V1.to_string(),
            failure_code,
            failure_reason: Some(failure_reason),
        });
        value.validate_structure()?;
        Ok(value)
    }

    pub fn to_json_vec(&self) -> Result<Vec<u8>, serde_json::Error> {
        encode_json(self)
    }

    pub fn from_json_slice(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        let inner = decode_json::<ProtectProviderResponseKindV1>(bytes)?;
        let value = Self(inner);
        value.validate_structure().map_err(contract_decode_error)?;
        Ok(value)
    }

    pub fn protection_session_handle(
        &self,
    ) -> Result<Option<[u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1]>, ContractError> {
        match &self.0 {
            ProtectProviderResponseKindV1::ProtectionSessionOpened {
                protection_session_handle,
                ..
            }
            | ProtectProviderResponseKindV1::MediaSegmentProtected {
                protection_session_handle,
                ..
            }
            | ProtectProviderResponseKindV1::ProtectionSessionFinalized {
                protection_session_handle,
                ..
            }
            | ProtectProviderResponseKindV1::ProtectionSessionCancelled {
                protection_session_handle,
                ..
            }
            | ProtectProviderResponseKindV1::ProtectionSessionClosed {
                protection_session_handle,
                ..
            }
            | ProtectProviderResponseKindV1::ProtectionSessionAlreadyAbsent {
                protection_session_handle,
                ..
            } => Ok(Some(*protection_session_handle.as_bytes())),
            ProtectProviderResponseKindV1::ObjectProtectionSessionOpened { .. }
            | ProtectProviderResponseKindV1::ObjectChunkProtected { .. }
            | ProtectProviderResponseKindV1::ObjectProtectionSessionFinalized { .. }
            | ProtectProviderResponseKindV1::Failure { .. } => Ok(None),
        }
    }

    pub fn protected_init_segment(&self) -> Option<&[u8]> {
        match &self.0 {
            ProtectProviderResponseKindV1::ProtectionSessionOpened {
                protected_init_segment,
                ..
            } => protected_init_segment.as_ref().map(CanonicalBlob::as_slice),
            _ => None,
        }
    }

    pub fn protected_init_segments(&self) -> Option<Vec<&[u8]>> {
        match &self.0 {
            ProtectProviderResponseKindV1::ProtectionSessionOpened {
                protected_init_segments: Some(segments),
                ..
            } => Some(segments.iter().collect()),
            _ => None,
        }
    }

    pub fn segment_index(&self) -> Option<u32> {
        match &self.0 {
            ProtectProviderResponseKindV1::MediaSegmentProtected { segment_index, .. } => {
                Some(*segment_index)
            }
            _ => None,
        }
    }

    pub fn protected_segment(&self) -> Option<&[u8]> {
        match &self.0 {
            ProtectProviderResponseKindV1::MediaSegmentProtected {
                protected_segment, ..
            } => Some(protected_segment.as_slice()),
            _ => None,
        }
    }

    pub fn media_identity(&self) -> Result<Option<CencFmp4MediaIdentityV1>, ContractError> {
        match &self.0 {
            ProtectProviderResponseKindV1::ProtectionSessionFinalized {
                media_identity: Some(media_identity),
                ..
            } => Ok(Some(media_identity.decode()?)),
            _ => Ok(None),
        }
    }

    pub fn media_identity_v2(&self) -> Result<Option<CencDashMediaIdentityV2>, ContractError> {
        match &self.0 {
            ProtectProviderResponseKindV1::ProtectionSessionFinalized {
                media_identity_v2: Some(media_identity),
                ..
            } => Ok(Some(media_identity.decode()?)),
            _ => Ok(None),
        }
    }

    pub fn custody_envelope(&self) -> Result<Option<CustodyEnvelopeV1>, ContractError> {
        match &self.0 {
            ProtectProviderResponseKindV1::ProtectionSessionFinalized {
                custody_envelope, ..
            }
            | ProtectProviderResponseKindV1::ObjectProtectionSessionFinalized {
                custody_envelope,
                ..
            } => Ok(Some(custody_envelope.decode()?)),
            _ => Ok(None),
        }
    }

    pub fn framed_header(&self) -> Option<&[u8]> {
        match &self.0 {
            ProtectProviderResponseKindV1::ObjectProtectionSessionOpened {
                framed_header, ..
            } => Some(framed_header.as_slice()),
            _ => None,
        }
    }

    pub fn framed_chunk(&self) -> Option<&[u8]> {
        match &self.0 {
            ProtectProviderResponseKindV1::ObjectChunkProtected { framed_chunk, .. } => {
                Some(framed_chunk.as_slice())
            }
            _ => None,
        }
    }

    pub fn object_identity(&self) -> Result<Option<ChunkedPayloadObjectIdentityV1>, ContractError> {
        match &self.0 {
            ProtectProviderResponseKindV1::ObjectProtectionSessionFinalized {
                object_identity,
                ..
            } => Ok(Some(object_identity.decode()?)),
            _ => Ok(None),
        }
    }

    pub fn content_key_commitment(&self) -> Option<Digest32> {
        match &self.0 {
            ProtectProviderResponseKindV1::ObjectProtectionSessionFinalized {
                content_key_commitment,
                ..
            } => Some(Digest32::new(*content_key_commitment)),
            _ => None,
        }
    }

    pub const fn failure_code(&self) -> Option<ProviderFailureCodeV1> {
        match self.0 {
            ProtectProviderResponseKindV1::Failure { failure_code, .. } => Some(failure_code),
            _ => None,
        }
    }

    pub const fn failure_reason(&self) -> Option<ProtectFailureReasonV2> {
        match self.0 {
            ProtectProviderResponseKindV1::Failure { failure_reason, .. } => failure_reason,
            _ => None,
        }
    }

    fn validate_structure(&self) -> Result<(), ContractError> {
        match &self.0 {
            ProtectProviderResponseKindV1::ProtectionSessionOpened { schema, .. }
            | ProtectProviderResponseKindV1::MediaSegmentProtected { schema, .. }
            | ProtectProviderResponseKindV1::ProtectionSessionFinalized { schema, .. }
            | ProtectProviderResponseKindV1::ProtectionSessionCancelled { schema, .. }
            | ProtectProviderResponseKindV1::ProtectionSessionClosed { schema, .. }
            | ProtectProviderResponseKindV1::ProtectionSessionAlreadyAbsent { schema, .. }
            | ProtectProviderResponseKindV1::ObjectProtectionSessionOpened { schema, .. }
            | ProtectProviderResponseKindV1::ObjectChunkProtected { schema, .. }
            | ProtectProviderResponseKindV1::ObjectProtectionSessionFinalized { schema, .. }
            | ProtectProviderResponseKindV1::Failure { schema, .. } => validate_schema(
                schema,
                PROTECT_PROVIDER_RESPONSE_SCHEMA_V1,
                "protect_provider_response.schema",
            ),
        }?;
        if let ProtectProviderResponseKindV1::ProtectionSessionOpened {
            protected_init_segment,
            protected_init_segments,
            ..
        } = &self.0
        {
            if protected_init_segment.is_some() == protected_init_segments.is_some() {
                return Err(ContractError::InvalidField("protected_init_segment"));
            }
        }
        if let ProtectProviderResponseKindV1::ProtectionSessionFinalized {
            media_identity,
            custody_envelope,
            media_identity_v2,
            ..
        } = &self.0
        {
            let custody_envelope = custody_envelope.decode::<CustodyEnvelopeV1>()?;
            let encrypted_content = match (media_identity, media_identity_v2) {
                (Some(identity), None) => identity
                    .decode::<CencFmp4MediaIdentityV1>()?
                    .encrypted_content()
                    .clone(),
                (None, Some(identity)) => identity
                    .decode::<CencDashMediaIdentityV2>()?
                    .encrypted_content()
                    .clone(),
                _ => return Err(ContractError::InvalidField("media_identity")),
            };
            if custody_envelope.manifest().encrypted_content() != &encrypted_content {
                return Err(ContractError::InvalidField("custody_envelope"));
            }
        }
        if let ProtectProviderResponseKindV1::Failure {
            failure_code,
            failure_reason: Some(_),
            ..
        } = &self.0
        {
            if *failure_code != ProviderFailureCodeV1::InvalidRequest {
                return Err(ContractError::InvalidField("failure_reason"));
            }
        }
        if let ProtectProviderResponseKindV1::ObjectProtectionSessionFinalized {
            object_identity,
            content_key_commitment,
            custody_envelope,
            ..
        } = &self.0
        {
            let object_identity = object_identity.decode::<ChunkedPayloadObjectIdentityV1>()?;
            let custody_envelope = custody_envelope.decode::<CustodyEnvelopeV1>()?;
            if custody_envelope.manifest().encrypted_content()
                != object_identity.encrypted_content()
            {
                return Err(ContractError::InvalidField("custody_envelope"));
            }
            if custody_envelope.manifest().content_key_commitment()
                != Digest32::new(*content_key_commitment)
            {
                return Err(ContractError::InvalidField("content_key_commitment"));
            }
        }
        Ok(())
    }
}

fn validate_representations_v2(
    representations: &[ProtectionRepresentationV2],
) -> Result<(), ContractError> {
    for representation in representations {
        representation.validate()?;
    }
    match representations {
        [_] => Ok(()),
        [video, audio] => {
            if video.kind() != CencDashRenditionKindV2::Video
                || audio.kind() != CencDashRenditionKindV2::Audio
            {
                return Err(ContractError::InvalidField("representations"));
            }
            if video.segment_count.abs_diff(audio.segment_count)
                > MAX_REPRESENTATION_SEGMENT_SKEW_V2
            {
                return Err(ContractError::InvalidField("segment_count"));
            }
            Ok(())
        }
        _ => Err(ContractError::InvalidField("representations")),
    }
}

impl Serialize for ProtectProviderRequestV1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ProtectProviderRequestV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let inner = ProtectProviderRequestKindV1::deserialize(deserializer)?;
        let value = Self(inner);
        value.validate_structure().map_err(D::Error::custom)?;
        Ok(value)
    }
}

impl Serialize for ProtectProviderResponseV1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ProtectProviderResponseV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let inner = ProtectProviderResponseKindV1::deserialize(deserializer)?;
        let value = Self(inner);
        value.validate_structure().map_err(D::Error::custom)?;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::{
        custody_envelope_for_encrypted_content, custody_envelope_for_media, digest,
        media_components, media_identity, node_custody_public_key, node_public_key,
    };

    use super::*;

    fn handle(seed: u8) -> [u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1] {
        let mut out = [0u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1];
        out[0] = seed.max(1);
        out[31] = seed ^ 0x5a;
        out
    }

    fn nodes() -> Vec<ProtectionSessionNodeV1> {
        [1u8, 2, 3]
            .into_iter()
            .map(|seed| {
                ProtectionSessionNodeV1::new(node_public_key(seed), node_custody_public_key(seed))
                    .unwrap()
            })
            .collect()
    }

    fn custody_pool_identity() -> CustodyPoolIdentityV1 {
        CustodyPoolIdentityV1::new(digest(0x35), 512).unwrap()
    }

    fn custody_epoch_identity() -> CustodyEpochIdentityV1 {
        CustodyEpochIdentityV1::new(digest(0x33), 512).unwrap()
    }

    fn custody_committee_authorization_identity() -> CustodyCommitteeAuthorizationIdentityV1 {
        CustodyCommitteeAuthorizationIdentityV1::new(digest(0x36), 512).unwrap()
    }

    fn content_access_id() -> ContentAccessIdV1 {
        ContentAccessIdV1::new([0x41; 16]).unwrap()
    }

    fn open_request_with(
        mime_type: &str,
        codecs: &str,
        segment_count: u32,
        clear_init_segment: &[u8],
    ) -> Result<ProtectProviderRequestV1, ContractError> {
        ProtectProviderRequestV1::new_open_protection_session(
            digest(0xa1),
            content_access_id(),
            custody_pool_identity(),
            custody_epoch_identity(),
            custody_committee_authorization_identity(),
            mime_type,
            codecs,
            segment_count,
            clear_init_segment,
            nodes(),
        )
    }

    #[test]
    fn open_request_round_trips_and_enforces_bounds() {
        let (init_segment, _, _, _) = media_components(0x11);
        let request =
            open_request_with("video/mp4", "avc1.640028,mp4a.40.2", 2, &init_segment).unwrap();

        let decoded =
            ProtectProviderRequestV1::from_json_slice(&request.to_json_vec().unwrap()).unwrap();
        assert_eq!(decoded, request);
        assert_eq!(decoded.segment_count(), Some(2));
        assert_eq!(decoded.clear_init_segment(), Some(init_segment.as_slice()));
        assert_eq!(
            decoded.content_access_id().unwrap(),
            Some(content_access_id())
        );
    }

    #[test]
    fn open_request_rejects_bad_threshold_and_duplicate_nodes() {
        let (init_segment, _, _, _) = media_components(0x11);
        let mut value = serde_json::from_slice::<serde_json::Value>(
            &open_request_with("video/mp4", "avc1.640028,mp4a.40.2", 2, &init_segment)
                .unwrap()
                .to_json_vec()
                .unwrap(),
        )
        .unwrap();
        value["threshold_required"] = serde_json::json!(1);
        assert!(
            ProtectProviderRequestV1::from_json_slice(&serde_json::to_vec(&value).unwrap())
                .is_err()
        );

        let mut dup = serde_json::from_slice::<serde_json::Value>(
            &open_request_with("video/mp4", "avc1.640028,mp4a.40.2", 2, &init_segment)
                .unwrap()
                .to_json_vec()
                .unwrap(),
        )
        .unwrap();
        dup["nodes"][1]["node_public_key"] = dup["nodes"][0]["node_public_key"].clone();
        assert!(
            ProtectProviderRequestV1::from_json_slice(&serde_json::to_vec(&dup).unwrap()).is_err()
        );
    }

    #[test]
    fn open_request_rejects_non_visible_or_oversize_media_declaration() {
        let (init_segment, _, _, _) = media_components(0x11);
        let too_long = "a".repeat(MAX_MEDIA_DECLARATION_BYTES_V1 + 1);

        assert!(open_request_with(&too_long, "avc1.640028,mp4a.40.2", 2, &init_segment).is_err());
        assert!(open_request_with("video/mp4", &too_long, 2, &init_segment).is_err());
        assert!(
            open_request_with("video/mp4\n", "avc1.640028,mp4a.40.2", 2, &init_segment).is_err()
        );
        assert!(
            open_request_with("video/mp4", "avc1.640028, mp4a.40.2", 2, &init_segment).is_err()
        );
    }

    #[test]
    fn protect_wire_rejects_zero_ids_handles_counts_parts_and_unknown_fields() {
        let (init_segment, _, _, _) = media_components(0x11);

        assert!(open_request_with("video/mp4", "avc1.640028,mp4a.40.2", 0, &init_segment).is_err());
        assert!(open_request_with(
            "video/mp4",
            "avc1.640028,mp4a.40.2",
            MAX_PROTECT_MEDIA_SEGMENTS_V1 + 1,
            &init_segment,
        )
        .is_err());
        assert!(open_request_with("video/mp4", "avc1.640028,mp4a.40.2", 2, &[]).is_err());
        assert!(open_request_with(
            "video/mp4",
            "avc1.640028,mp4a.40.2",
            2,
            &vec![0u8; MAX_PROTECT_MEDIA_PART_BYTES_V1 + 1],
        )
        .is_err());
        assert!(ProtectProviderRequestV1::new_open_protection_session(
            Digest32::new([0u8; 32]),
            content_access_id(),
            custody_pool_identity(),
            custody_epoch_identity(),
            custody_committee_authorization_identity(),
            "video/mp4",
            "avc1.640028,mp4a.40.2",
            2,
            &init_segment,
            nodes(),
        )
        .is_err());
        assert!(ProtectProviderRequestV1::new_protect_media_segment([0u8; 32], 0, b"x").is_err());
        assert!(ProtectProviderRequestV1::new_protect_media_segment(
            handle(0x22),
            0,
            &vec![0u8; MAX_PROTECT_MEDIA_PART_BYTES_V1 + 1],
        )
        .is_err());
        assert!(ProtectProviderRequestV1::new_protect_media_segment(handle(0x22), 0, &[]).is_err());

        let mut request_value = serde_json::from_slice::<serde_json::Value>(
            &open_request_with("video/mp4", "avc1.640028,mp4a.40.2", 2, &init_segment)
                .unwrap()
                .to_json_vec()
                .unwrap(),
        )
        .unwrap();
        request_value["unexpected"] = serde_json::json!(true);
        assert!(ProtectProviderRequestV1::from_json_slice(
            &serde_json::to_vec(&request_value).unwrap()
        )
        .is_err());

        let mut response_value = serde_json::from_slice::<serde_json::Value>(
            &ProtectProviderResponseV1::new_opened(handle(0x23), b"protected-init")
                .unwrap()
                .to_json_vec()
                .unwrap(),
        )
        .unwrap();
        response_value["unexpected"] = serde_json::json!(true);
        assert!(ProtectProviderResponseV1::from_json_slice(
            &serde_json::to_vec(&response_value).unwrap()
        )
        .is_err());
    }

    #[test]
    fn maximum_media_part_requests_stay_within_provider_frame_limit() {
        let max_decl = "a".repeat(MAX_MEDIA_DECLARATION_BYTES_V1);
        let open_request = open_request_with(
            &max_decl,
            &max_decl,
            MAX_PROTECT_MEDIA_SEGMENTS_V1,
            &vec![0x55; MAX_PROTECT_MEDIA_PART_BYTES_V1],
        )
        .unwrap();
        let open_json = open_request.to_json_vec().unwrap();
        assert!(open_json.len() <= crate::MAX_PROVIDER_FRAME_BYTES_V1);

        let segment_request = ProtectProviderRequestV1::new_protect_media_segment(
            handle(0x44),
            MAX_PROTECT_MEDIA_SEGMENTS_V1 - 1,
            &vec![0x66; MAX_PROTECT_MEDIA_PART_BYTES_V1],
        )
        .unwrap();
        let segment_json = segment_request.to_json_vec().unwrap();
        assert!(segment_json.len() <= crate::MAX_PROVIDER_FRAME_BYTES_V1);
    }

    #[test]
    fn finalized_response_round_trips_and_binds_media_to_envelope() {
        let response = ProtectProviderResponseV1::new_finalized(
            handle(0x33),
            &media_identity(0x11),
            &custody_envelope_for_media(0x11),
        )
        .unwrap();
        let decoded =
            ProtectProviderResponseV1::from_json_slice(&response.to_json_vec().unwrap()).unwrap();
        assert_eq!(decoded, response);
    }

    #[test]
    fn finalized_response_keeps_sealed_share_bytes_private_to_the_wire_surface() {
        let response = ProtectProviderResponseV1::new_finalized(
            handle(0x33),
            &media_identity(0x11),
            &custody_envelope_for_media(0x11),
        )
        .unwrap();

        let json = String::from_utf8(response.to_json_vec().unwrap()).unwrap();
        let debug = format!("{response:?}");
        for term in [
            "content_key",
            "raw_share",
            "plaintext_share",
            "recipient_secret",
        ] {
            assert!(!json.contains(term));
            assert!(!debug.contains(term));
        }
        assert!(debug.contains("[redacted]"));
    }

    #[test]
    fn finalized_response_rejects_mismatched_envelope() {
        let mut value = serde_json::from_slice::<serde_json::Value>(
            &ProtectProviderResponseV1::new_finalized(
                handle(0x33),
                &media_identity(0x11),
                &custody_envelope_for_media(0x11),
            )
            .unwrap()
            .to_json_vec()
            .unwrap(),
        )
        .unwrap();
        value["custody_envelope"] = serde_json::json!(
            CanonicalBlob::<MAX_CUSTODY_ENVELOPE_BYTES_V1>::from_contract(
                &custody_envelope_for_media(0x21)
            )
            .unwrap()
            .as_slice()
        );
        assert!(
            ProtectProviderResponseV1::from_json_slice(&serde_json::to_vec(&value).unwrap())
                .is_err()
        );
    }

    fn object_identity_for(seed: u8, plaintext_bytes: u64) -> ChunkedPayloadObjectIdentityV1 {
        ChunkedPayloadObjectIdentityV1::new(
            EncryptedContentIdentityV1::new(digest(seed), plaintext_bytes + 64).unwrap(),
            "application/octet-stream",
            plaintext_bytes,
            64,
        )
        .unwrap()
    }

    #[allow(clippy::too_many_arguments)]
    fn open_object_request_with(
        content_type: &str,
        plaintext_bytes: u64,
        nodes: Vec<ProtectionSessionNodeV1>,
        threshold_required: u8,
        threshold_total: u8,
    ) -> Result<ProtectProviderRequestV1, ContractError> {
        ProtectProviderRequestV1::new_open_object_protection_session(
            digest(0xa1),
            content_access_id(),
            custody_pool_identity(),
            custody_epoch_identity(),
            custody_committee_authorization_identity(),
            threshold_required,
            threshold_total,
            content_type,
            plaintext_bytes,
            nodes,
        )
    }

    #[test]
    fn object_open_request_round_trips_and_enforces_bounds() {
        let request =
            open_object_request_with("application/octet-stream", 4096, nodes(), 2, 3).unwrap();
        let decoded =
            ProtectProviderRequestV1::from_json_slice(&request.to_json_vec().unwrap()).unwrap();
        assert_eq!(decoded, request);
        assert_eq!(
            decoded.op(),
            ProtectProviderRequestOpV1::OpenObjectProtectionSession
        );
        assert_eq!(decoded.session_id(), Some(digest(0xa1)));
        assert_eq!(decoded.content_type(), Some("application/octet-stream"));
        assert_eq!(decoded.plaintext_bytes(), Some(4096));
        assert_eq!(decoded.threshold_required(), Some(2));
        assert_eq!(decoded.threshold_total(), Some(3));
        assert_eq!(decoded.nodes().unwrap().len(), 3);
        assert_eq!(
            decoded.content_access_id().unwrap(),
            Some(content_access_id())
        );
        assert_eq!(
            decoded.custody_pool().unwrap(),
            Some(custody_pool_identity())
        );
        assert_eq!(
            decoded.custody_epoch().unwrap(),
            Some(custody_epoch_identity())
        );
        assert_eq!(
            decoded.custody_committee_authorization().unwrap(),
            Some(custody_committee_authorization_identity())
        );

        assert!(
            ProtectProviderRequestV1::new_open_object_protection_session(
                Digest32::new([0u8; 32]),
                content_access_id(),
                custody_pool_identity(),
                custody_epoch_identity(),
                custody_committee_authorization_identity(),
                2,
                3,
                "application/octet-stream",
                4096,
                nodes(),
            )
            .is_err()
        );
        let too_long = "a".repeat(MAX_MEDIA_DECLARATION_BYTES_V1 + 1);
        assert!(open_object_request_with(&too_long, 4096, nodes(), 2, 3).is_err());
        assert!(open_object_request_with("application/octet-stream", 0, nodes(), 2, 3).is_err());
        assert!(open_object_request_with(
            "application/octet-stream",
            MAX_ENCRYPTED_CONTENT_BYTES + 1,
            nodes(),
            2,
            3,
        )
        .is_err());
        let eighty_mib = 80 * 1024 * 1024;
        let above_old_cap =
            open_object_request_with("application/octet-stream", eighty_mib, nodes(), 2, 3)
                .unwrap();
        let decoded =
            ProtectProviderRequestV1::from_json_slice(&above_old_cap.to_json_vec().unwrap())
                .unwrap();
        assert_eq!(decoded.plaintext_bytes(), Some(eighty_mib));
        assert!(open_object_request_with("application/octet-stream", 4096, nodes(), 1, 3).is_err());
        assert!(open_object_request_with(
            "application/octet-stream",
            4096,
            nodes()[..2].to_vec(),
            2,
            3,
        )
        .is_err());

        let mut dup =
            serde_json::from_slice::<serde_json::Value>(&request.to_json_vec().unwrap()).unwrap();
        dup["nodes"][1]["node_public_key"] = dup["nodes"][0]["node_public_key"].clone();
        assert!(
            ProtectProviderRequestV1::from_json_slice(&serde_json::to_vec(&dup).unwrap()).is_err()
        );

        let mut unknown =
            serde_json::from_slice::<serde_json::Value>(&request.to_json_vec().unwrap()).unwrap();
        unknown["unexpected"] = serde_json::json!(true);
        assert!(
            ProtectProviderRequestV1::from_json_slice(&serde_json::to_vec(&unknown).unwrap())
                .is_err()
        );

        let response = ProtectProviderResponseV1::new_object_opened(b"framed-header").unwrap();
        let decoded_response =
            ProtectProviderResponseV1::from_json_slice(&response.to_json_vec().unwrap()).unwrap();
        assert_eq!(decoded_response, response);
        assert_eq!(
            decoded_response.status(),
            ProtectProviderResponseStatusV1::ObjectProtectionSessionOpened
        );
        assert_eq!(
            decoded_response.framed_header(),
            Some(b"framed-header".as_slice())
        );

        let mut unknown_response =
            serde_json::from_slice::<serde_json::Value>(&response.to_json_vec().unwrap()).unwrap();
        unknown_response["unexpected"] = serde_json::json!(true);
        assert!(ProtectProviderResponseV1::from_json_slice(
            &serde_json::to_vec(&unknown_response).unwrap()
        )
        .is_err());

        let oversized_header = serde_json::json!(vec![7u8; MAX_OBJECT_FRAMED_HEADER_BYTES_V1 + 1]);
        let mut oversized =
            serde_json::from_slice::<serde_json::Value>(&response.to_json_vec().unwrap()).unwrap();
        oversized["framed_header"] = oversized_header;
        assert!(ProtectProviderResponseV1::from_json_slice(
            &serde_json::to_vec(&oversized).unwrap()
        )
        .is_err());
    }

    #[test]
    fn object_chunk_round_trips_rejects_unknown_fields_and_oversize_blobs() {
        let request =
            ProtectProviderRequestV1::new_protect_object_chunk(digest(0xb1), 3, b"clear-chunk")
                .unwrap();
        let decoded =
            ProtectProviderRequestV1::from_json_slice(&request.to_json_vec().unwrap()).unwrap();
        assert_eq!(decoded, request);
        assert_eq!(decoded.op(), ProtectProviderRequestOpV1::ProtectObjectChunk);
        assert_eq!(decoded.session_id(), Some(digest(0xb1)));
        assert_eq!(decoded.chunk_index(), Some(3));
        assert_eq!(decoded.plaintext(), Some(b"clear-chunk".as_slice()));

        assert!(ProtectProviderRequestV1::new_protect_object_chunk(
            Digest32::new([0u8; 32]),
            3,
            b"clear-chunk",
        )
        .is_err());
        assert!(ProtectProviderRequestV1::new_protect_object_chunk(
            digest(0xb1),
            3,
            &vec![0u8; MAX_OBJECT_PLAINTEXT_CHUNK_BYTES_V1 + 1],
        )
        .is_err());
        assert!(ProtectProviderRequestV1::new_protect_object_chunk(digest(0xb1), 3, &[]).is_err());

        let mut unknown =
            serde_json::from_slice::<serde_json::Value>(&request.to_json_vec().unwrap()).unwrap();
        unknown["unexpected"] = serde_json::json!(true);
        assert!(
            ProtectProviderRequestV1::from_json_slice(&serde_json::to_vec(&unknown).unwrap())
                .is_err()
        );

        let response =
            ProtectProviderResponseV1::new_object_chunk_protected(b"framed-chunk").unwrap();
        let decoded_response =
            ProtectProviderResponseV1::from_json_slice(&response.to_json_vec().unwrap()).unwrap();
        assert_eq!(decoded_response, response);
        assert_eq!(
            decoded_response.status(),
            ProtectProviderResponseStatusV1::ObjectChunkProtected
        );
        assert_eq!(
            decoded_response.framed_chunk(),
            Some(b"framed-chunk".as_slice())
        );

        assert!(ProtectProviderResponseV1::new_object_chunk_protected(&vec![
            0u8;
            MAX_OBJECT_FRAMED_CHUNK_BYTES_V1
                + 1
        ],)
        .is_err());

        let mut unknown_response =
            serde_json::from_slice::<serde_json::Value>(&response.to_json_vec().unwrap()).unwrap();
        unknown_response["unexpected"] = serde_json::json!(true);
        assert!(ProtectProviderResponseV1::from_json_slice(
            &serde_json::to_vec(&unknown_response).unwrap()
        )
        .is_err());
    }

    #[test]
    fn object_finalize_round_trips_and_binds_object_identity_and_commitment() {
        let object_identity = object_identity_for(0x21, 4096);
        let custody_envelope = custody_envelope_for_encrypted_content(
            object_identity.encrypted_content().clone(),
            0x21,
        );

        let request = ProtectProviderRequestV1::new_finalize_object_protection_session(
            digest(0xc1),
            object_identity.encrypted_content(),
        )
        .unwrap();
        let decoded =
            ProtectProviderRequestV1::from_json_slice(&request.to_json_vec().unwrap()).unwrap();
        assert_eq!(decoded, request);
        assert_eq!(
            decoded.op(),
            ProtectProviderRequestOpV1::FinalizeObjectProtectionSession
        );
        assert_eq!(decoded.session_id(), Some(digest(0xc1)));
        assert_eq!(
            decoded.encrypted_content().unwrap().unwrap(),
            *object_identity.encrypted_content()
        );

        assert!(
            ProtectProviderRequestV1::new_finalize_object_protection_session(
                Digest32::new([0u8; 32]),
                object_identity.encrypted_content(),
            )
            .is_err()
        );

        let mut unknown =
            serde_json::from_slice::<serde_json::Value>(&request.to_json_vec().unwrap()).unwrap();
        unknown["unexpected"] = serde_json::json!(true);
        assert!(
            ProtectProviderRequestV1::from_json_slice(&serde_json::to_vec(&unknown).unwrap())
                .is_err()
        );

        let mut oversized_encrypted_content =
            serde_json::from_slice::<serde_json::Value>(&request.to_json_vec().unwrap()).unwrap();
        oversized_encrypted_content["encrypted_content"] =
            serde_json::json!(vec![9u8; MAX_ENCRYPTED_CONTENT_IDENTITY_BYTES_V1 + 1]);
        assert!(ProtectProviderRequestV1::from_json_slice(
            &serde_json::to_vec(&oversized_encrypted_content).unwrap()
        )
        .is_err());

        let content_key_commitment = custody_envelope.manifest().content_key_commitment();
        let response = ProtectProviderResponseV1::new_object_finalized(
            &object_identity,
            content_key_commitment,
            &custody_envelope,
        )
        .unwrap();
        let decoded_response =
            ProtectProviderResponseV1::from_json_slice(&response.to_json_vec().unwrap()).unwrap();
        assert_eq!(decoded_response, response);
        assert_eq!(
            decoded_response.status(),
            ProtectProviderResponseStatusV1::ObjectProtectionSessionFinalized
        );
        assert_eq!(
            decoded_response.object_identity().unwrap().unwrap(),
            object_identity
        );
        assert_eq!(
            decoded_response.content_key_commitment().unwrap(),
            content_key_commitment
        );
        assert_eq!(
            decoded_response.custody_envelope().unwrap().unwrap(),
            custody_envelope
        );

        let mismatched_envelope = custody_envelope_for_encrypted_content(
            object_identity_for(0x31, 4096).encrypted_content().clone(),
            0x31,
        );
        assert!(ProtectProviderResponseV1::new_object_finalized(
            &object_identity,
            content_key_commitment,
            &mismatched_envelope,
        )
        .is_err());

        let mut mismatched_commitment =
            serde_json::from_slice::<serde_json::Value>(&response.to_json_vec().unwrap()).unwrap();
        mismatched_commitment["content_key_commitment"] = serde_json::json!(vec![0u8; 32]);
        assert!(ProtectProviderResponseV1::from_json_slice(
            &serde_json::to_vec(&mismatched_commitment).unwrap()
        )
        .is_err());

        let mut oversized_object_identity =
            serde_json::from_slice::<serde_json::Value>(&response.to_json_vec().unwrap()).unwrap();
        oversized_object_identity["object_identity"] =
            serde_json::json!(vec![9u8; MAX_CHUNKED_PAYLOAD_OBJECT_IDENTITY_BYTES_V1 + 1]);
        assert!(ProtectProviderResponseV1::from_json_slice(
            &serde_json::to_vec(&oversized_object_identity).unwrap()
        )
        .is_err());

        let mut oversized_custody_envelope =
            serde_json::from_slice::<serde_json::Value>(&response.to_json_vec().unwrap()).unwrap();
        oversized_custody_envelope["custody_envelope"] =
            serde_json::json!(vec![9u8; MAX_CUSTODY_ENVELOPE_BYTES_V1 + 1]);
        assert!(ProtectProviderResponseV1::from_json_slice(
            &serde_json::to_vec(&oversized_custody_envelope).unwrap()
        )
        .is_err());

        let mut unknown_response =
            serde_json::from_slice::<serde_json::Value>(&response.to_json_vec().unwrap()).unwrap();
        unknown_response["unexpected"] = serde_json::json!(true);
        assert!(ProtectProviderResponseV1::from_json_slice(
            &serde_json::to_vec(&unknown_response).unwrap()
        )
        .is_err());
    }

    #[test]
    fn maximum_object_chunk_requests_stay_within_provider_frame_limit() {
        let chunk_request = ProtectProviderRequestV1::new_protect_object_chunk(
            digest(0xd1),
            u32::MAX,
            &vec![0x77; MAX_OBJECT_PLAINTEXT_CHUNK_BYTES_V1],
        )
        .unwrap();
        let chunk_json = chunk_request.to_json_vec().unwrap();
        assert!(chunk_json.len() <= crate::MAX_PROVIDER_FRAME_BYTES_V1);

        let chunk_response = ProtectProviderResponseV1::new_object_chunk_protected(&vec![
            0x88;
            MAX_OBJECT_FRAMED_CHUNK_BYTES_V1
        ])
        .unwrap();
        let chunk_response_json = chunk_response.to_json_vec().unwrap();
        assert!(chunk_response_json.len() <= crate::MAX_PROVIDER_FRAME_BYTES_V1);
    }
    fn sha256_hex(bytes: &[u8]) -> String {
        use sha2::Digest as _;
        sha2::Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    #[test]
    fn v1_wire_bytes_are_pinned() {
        let (init_segment, _, _, _) = media_components(0x11);
        let encrypted = media_identity(0x11).encrypted_content().clone();
        let envelope = custody_envelope_for_encrypted_content(encrypted, 0x11);
        let pins: Vec<(&str, Vec<u8>, &str)> = vec![
            (
                "open",
                open_request_with("video/mp4", "avc1.640028,mp4a.40.2", 2, &init_segment)
                    .unwrap()
                    .to_json_vec()
                    .unwrap(),
                "a4ca54cdae694fb29196d506f1af0358707a2968be64989c1ced807c446063ec",
            ),
            (
                "segment",
                ProtectProviderRequestV1::new_protect_media_segment(handle(0x22), 1, b"clear")
                    .unwrap()
                    .to_json_vec()
                    .unwrap(),
                "ed536039d3081b10aa977b8f0a7343e1dc3500fec14c522f053d34bec0618291",
            ),
            (
                "finalize",
                ProtectProviderRequestV1::new_finalize_protection_session(handle(0x22))
                    .unwrap()
                    .to_json_vec()
                    .unwrap(),
                "8d9487c5e9c0dda75c7e91b2f3d0860f958f53bd7877cc55f13bb64500faaff0",
            ),
            (
                "cancel",
                ProtectProviderRequestV1::new_cancel_protection_session(handle(0x22))
                    .unwrap()
                    .to_json_vec()
                    .unwrap(),
                "5536d3352e959ad42a6952ade5072d7e7ffaebbe8af1f914147c2424eb606b84",
            ),
            (
                "close",
                ProtectProviderRequestV1::new_close_protection_session(handle(0x22))
                    .unwrap()
                    .to_json_vec()
                    .unwrap(),
                "f928591ab42ec4da045dbc0ec66f43567087f157588569544faed045c96c3d7f",
            ),
            (
                "opened",
                ProtectProviderResponseV1::new_opened(handle(0x23), b"protected-init")
                    .unwrap()
                    .to_json_vec()
                    .unwrap(),
                "8f1a63da50b093dc712ec65dbd28595d02683e22321fb606fe5a0ca821c999e6",
            ),
            (
                "segment_protected",
                ProtectProviderResponseV1::new_segment_protected(handle(0x23), 1, b"protected")
                    .unwrap()
                    .to_json_vec()
                    .unwrap(),
                "a8dfa91fef2831e1d1b53fe46933cb60c0a28a7c4585d2cb56b7e75856dcd3ad",
            ),
            (
                "finalized",
                ProtectProviderResponseV1::new_finalized(
                    handle(0x33),
                    &media_identity(0x11),
                    &envelope,
                )
                .unwrap()
                .to_json_vec()
                .unwrap(),
                "feb243daddb837387518b06565d764fad8c62f8e0a6de3147afd0ac7b92b9f12",
            ),
            (
                "failure",
                ProtectProviderResponseV1::new_failure(ProviderFailureCodeV1::InvalidRequest)
                    .unwrap()
                    .to_json_vec()
                    .unwrap(),
                "689a83a6bbf524f1b430d2e249afbc099781f4f4ceb2a8ce756f990426ac2c32",
            ),
        ];
        let changed: Vec<String> = pins
            .iter()
            .filter(|(_, bytes, pin)| sha256_hex(bytes) != *pin)
            .map(|(name, bytes, _)| format!("{name}={}", sha256_hex(bytes)))
            .collect();
        assert!(changed.is_empty(), "v1 wire bytes changed: {changed:?}");
    }
    mod v2 {
        use crate::media::v2_tests::{protect, pssh_v0, A, TIMESCALE, V, WIDEVINE_SYSTEM_ID};
        use crate::media_dash::CencDashRenditionBytesV2;

        use super::*;

        fn representation(
            kind: CencDashRenditionKindV2,
            segment_count: u32,
        ) -> ProtectionRepresentationV2 {
            ProtectionRepresentationV2::new(
                kind,
                if kind == V { "video/mp4" } else { "audio/mp4" },
                if kind == V {
                    "avc1.640028"
                } else {
                    "mp4a.40.2"
                },
                segment_count,
                &[0x11; 64],
            )
            .unwrap()
        }

        fn extras(count: usize, len: usize) -> Vec<Vec<u8>> {
            (0..count)
                .map(|index| pssh_v0(&WIDEVINE_SYSTEM_ID, &vec![index as u8; len - 32]))
                .collect()
        }

        fn open_v2(
            representations: Vec<ProtectionRepresentationV2>,
            extra: &[Vec<u8>],
        ) -> Result<ProtectProviderRequestV1, ContractError> {
            ProtectProviderRequestV1::new_open_protection_session_v2(
                digest(0xa1),
                content_access_id(),
                custody_pool_identity(),
                custody_epoch_identity(),
                custody_committee_authorization_identity(),
                representations,
                extra,
                nodes(),
            )
        }

        fn open_json(representations: Vec<ProtectionRepresentationV2>) -> serde_json::Value {
            serde_json::from_slice(
                &open_v2(representations, &[])
                    .unwrap()
                    .to_json_vec()
                    .unwrap(),
            )
            .unwrap()
        }

        fn decodes(value: &serde_json::Value) -> bool {
            ProtectProviderRequestV1::from_json_slice(&serde_json::to_vec(value).unwrap()).is_ok()
        }

        #[test]
        fn w1_open_round_trips_with_both_renditions_and_extras() {
            let extra = extras(2, 64);
            let request =
                open_v2(vec![representation(V, 3), representation(A, 4)], &extra).unwrap();
            let json = request.to_json_vec().unwrap();
            let decoded = ProtectProviderRequestV1::from_json_slice(&json).unwrap();
            assert_eq!(decoded, request);
            let representations = decoded.representations().unwrap();
            assert_eq!(representations.len(), 2);
            assert_eq!(representations[0].kind(), V);
            assert_eq!(representations[1].kind(), A);
            assert_eq!(representations[0].mime_type(), "video/mp4");
            assert_eq!(representations[1].codecs(), "mp4a.40.2");
            assert_eq!(representations[1].segment_count(), 4);
            assert_eq!(representations[0].clear_init_segment(), &[0x11; 64][..]);
            assert_eq!(decoded.extra_pssh_boxes(), extra);
            assert_eq!(decoded.mime_type(), None);
            assert_eq!(decoded.codecs(), None);
            assert_eq!(decoded.segment_count(), None);
            assert_eq!(decoded.clear_init_segment(), None);

            let value: serde_json::Value = serde_json::from_slice(&json).unwrap();
            assert!(value.get("representations").is_some());
            assert!(value.get("extra_pssh_boxes").is_some());
            for key in ["mime_type", "codecs", "segment_count", "clear_init_segment"] {
                assert!(value.get(key).is_none(), "{key}");
            }
            assert_eq!(value["representations"][0]["rendition"], "video");
            assert_eq!(value["representations"][1]["rendition"], "audio");

            let none = open_v2(vec![representation(V, 1)], &[]).unwrap();
            assert!(none.extra_pssh_boxes().is_empty());
            let value: serde_json::Value =
                serde_json::from_slice(&none.to_json_vec().unwrap()).unwrap();
            assert!(value.get("extra_pssh_boxes").is_none());
        }

        #[test]
        fn w2_open_refuses_every_invalid_shape() {
            assert!(open_v2(vec![], &[]).is_err());
            assert!(open_v2(
                vec![
                    representation(V, 1),
                    representation(A, 1),
                    representation(A, 1)
                ],
                &[]
            )
            .is_err());
            assert!(open_v2(vec![representation(A, 3), representation(V, 3)], &[]).is_err());
            assert!(open_v2(vec![representation(V, 3), representation(V, 3)], &[]).is_err());
            assert!(ProtectionRepresentationV2::new(V, "video/mp4", "avc1", 0, &[1]).is_err());
            let mut zero = open_json(vec![representation(V, 1)]);
            zero["representations"][0]["segment_count"] = serde_json::json!(0);
            assert!(!decodes(&zero));
            assert!(ProtectionRepresentationV2::new(V, "video/mp4", "a b", 1, &[1]).is_err());
            assert!(ProtectionRepresentationV2::new(V, "video/mp4", "avc1", 1, &[]).is_err());
            // The head rule: counts may differ by one, not two.
            assert!(open_v2(vec![representation(V, 3), representation(A, 5)], &[]).is_err());
            assert!(open_v2(vec![representation(V, 3), representation(A, 4)], &[]).is_ok());
            assert!(open_v2(vec![representation(V, 4), representation(A, 3)], &[]).is_ok());
            // No upper cap on the count.
            assert!(open_v2(vec![representation(V, 1_000_000)], &[]).is_ok());

            // v1 and v2 fields must not mix.
            let (init_segment, _, _, _) = media_components(0x11);
            let mut mixed = open_json(vec![representation(V, 1)]);
            mixed["mime_type"] = serde_json::json!("video/mp4");
            assert!(!decodes(&mixed));
            let v1 = serde_json::from_slice::<serde_json::Value>(
                &open_request_with("video/mp4", "avc1.640028,mp4a.40.2", 2, &init_segment)
                    .unwrap()
                    .to_json_vec()
                    .unwrap(),
            )
            .unwrap();
            let mut v1_with_extras = v1.clone();
            v1_with_extras["extra_pssh_boxes"] = serde_json::json!([extras(1, 64)[0].clone()]);
            assert!(!decodes(&v1_with_extras));
            let mut v1_with_representations = v1.clone();
            v1_with_representations["representations"] =
                open_json(vec![representation(V, 1)])["representations"].clone();
            assert!(!decodes(&v1_with_representations));
            let mut neither = v1;
            for key in ["mime_type", "codecs", "segment_count", "clear_init_segment"] {
                neither.as_object_mut().unwrap().remove(key);
            }
            assert!(!decodes(&neither));

            // Extras.
            let mut empty = open_json(vec![representation(V, 1)]);
            empty["extra_pssh_boxes"] = serde_json::json!([]);
            assert!(!decodes(&empty));
            assert!(open_v2(vec![representation(V, 1)], &extras(65, 64)).is_err());
            assert!(open_v2(vec![representation(V, 1)], &extras(64, 64)).is_ok());
            assert!(open_v2(
                vec![representation(V, 1)],
                &[vec![0u8; MAX_PSSH_BOX_BYTES_V2 + 1]]
            )
            .is_err());
            // 17 boxes of 64 KiB exceed the 1 MiB total; 16 fit.
            assert!(open_v2(
                vec![representation(V, 1)],
                &extras(17, MAX_PSSH_BOX_BYTES_V2)
            )
            .is_err());
            assert!(open_v2(
                vec![representation(V, 1)],
                &extras(16, MAX_PSSH_BOX_BYTES_V2)
            )
            .is_ok());

            // An unknown rendition name.
            let mut unknown = open_json(vec![representation(V, 1)]);
            unknown["representations"][0]["rendition"] = serde_json::json!("subtitle");
            assert!(!decodes(&unknown));
            let mut extra_field = open_json(vec![representation(V, 1)]);
            extra_field["representations"][0]["unexpected"] = serde_json::json!(1);
            assert!(!decodes(&extra_field));
        }

        #[test]
        fn w3_segment_carries_the_rendition_index() {
            let request =
                ProtectProviderRequestV1::new_protect_media_segment_v2(handle(0x22), 1, 7, b"x")
                    .unwrap();
            let decoded =
                ProtectProviderRequestV1::from_json_slice(&request.to_json_vec().unwrap()).unwrap();
            assert_eq!(decoded, request);
            assert_eq!(decoded.rendition_index(), Some(1));
            assert_eq!(decoded.segment_index(), Some(7));
            assert!(ProtectProviderRequestV1::new_protect_media_segment_v2(
                handle(0x22),
                2,
                0,
                b"x"
            )
            .is_err());
            let v1 =
                ProtectProviderRequestV1::new_protect_media_segment(handle(0x22), 7, b"x").unwrap();
            assert_eq!(v1.rendition_index(), None);
            let value: serde_json::Value =
                serde_json::from_slice(&v1.to_json_vec().unwrap()).unwrap();
            assert!(value.get("rendition_index").is_none());
        }

        #[test]
        fn w4_opened_carries_one_or_two_inits_and_exactly_one_form() {
            for inits in [vec![b"a".to_vec()], vec![b"a".to_vec(), b"b".to_vec()]] {
                let response =
                    ProtectProviderResponseV1::new_opened_v2(handle(0x23), &inits).unwrap();
                let decoded =
                    ProtectProviderResponseV1::from_json_slice(&response.to_json_vec().unwrap())
                        .unwrap();
                assert_eq!(decoded, response);
                let got: Vec<Vec<u8>> = decoded
                    .protected_init_segments()
                    .unwrap()
                    .into_iter()
                    .map(<[u8]>::to_vec)
                    .collect();
                assert_eq!(got, inits);
                assert_eq!(decoded.protected_init_segment(), None);
            }
            assert!(ProtectProviderResponseV1::new_opened_v2(handle(0x23), &[]).is_err());
            assert!(ProtectProviderResponseV1::new_opened_v2(
                handle(0x23),
                &[b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]
            )
            .is_err());

            let v1 = ProtectProviderResponseV1::new_opened(handle(0x23), b"init").unwrap();
            assert_eq!(v1.protected_init_segments(), None);
            let mut both: serde_json::Value =
                serde_json::from_slice(&v1.to_json_vec().unwrap()).unwrap();
            both["protected_init_segments"] = serde_json::json!([[1, 2, 3]]);
            assert!(ProtectProviderResponseV1::from_json_slice(
                &serde_json::to_vec(&both).unwrap()
            )
            .is_err());
            let mut neither = both;
            neither
                .as_object_mut()
                .unwrap()
                .remove("protected_init_segment");
            neither
                .as_object_mut()
                .unwrap()
                .remove("protected_init_segments");
            assert!(ProtectProviderResponseV1::from_json_slice(
                &serde_json::to_vec(&neither).unwrap()
            )
            .is_err());
        }

        fn head() -> CencDashMediaIdentityV2 {
            let video = protect(V, &[]);
            let audio = protect(A, &[]);
            let segments_v = vec![video.segment.clone(); 2];
            let segments_a = vec![audio.segment.clone(); 2];
            CencDashMediaIdentityV2::new_from_bytes(
                ContentAccessIdV1::new(crate::media::v2_tests::KID).unwrap(),
                &[
                    CencDashRenditionBytesV2 {
                        kind: V,
                        timescale: TIMESCALE,
                        init_segment: &video.init,
                        segments: &segments_v,
                    },
                    CencDashRenditionBytesV2 {
                        kind: A,
                        timescale: TIMESCALE,
                        init_segment: &audio.init,
                        segments: &segments_a,
                    },
                ],
            )
            .unwrap()
        }

        #[test]
        fn w5_finalized_v2_binds_the_head_to_the_envelope() {
            let head = head();
            let envelope =
                custody_envelope_for_encrypted_content(head.encrypted_content().clone(), 0x11);
            let response =
                ProtectProviderResponseV1::new_finalized_v2(handle(0x33), &head, &envelope)
                    .unwrap();
            let json = response.to_json_vec().unwrap();
            let decoded = ProtectProviderResponseV1::from_json_slice(&json).unwrap();
            assert_eq!(decoded, response);
            assert_eq!(decoded.media_identity_v2().unwrap(), Some(head.clone()));
            assert_eq!(decoded.custody_envelope().unwrap(), Some(envelope.clone()));
            // A v1 caller fails closed.
            assert_eq!(decoded.media_identity().unwrap(), None);
            let value: serde_json::Value = serde_json::from_slice(&json).unwrap();
            assert!(value.get("media_identity").is_none());

            let other = custody_envelope_for_encrypted_content(
                EncryptedContentIdentityV1::new(digest(0x99), 4096).unwrap(),
                0x11,
            );
            assert!(
                ProtectProviderResponseV1::new_finalized_v2(handle(0x33), &head, &other).is_err()
            );

            // Both identities present is refused.
            let mut both = value.clone();
            let v1 = ProtectProviderResponseV1::new_finalized(
                handle(0x33),
                &media_identity(0x11),
                &custody_envelope_for_media(0x11),
            )
            .unwrap();
            let v1_value: serde_json::Value =
                serde_json::from_slice(&v1.to_json_vec().unwrap()).unwrap();
            both["media_identity"] = v1_value["media_identity"].clone();
            assert!(ProtectProviderResponseV1::from_json_slice(
                &serde_json::to_vec(&both).unwrap()
            )
            .is_err());
            // Neither present is refused.
            let mut neither = value;
            neither.as_object_mut().unwrap().remove("media_identity_v2");
            assert!(ProtectProviderResponseV1::from_json_slice(
                &serde_json::to_vec(&neither).unwrap()
            )
            .is_err());
        }

        #[test]
        fn w6_failure_reason_rides_only_on_invalid_request() {
            let response = ProtectProviderResponseV1::new_failure_with_reason(
                ProviderFailureCodeV1::InvalidRequest,
                ProtectFailureReasonV2::CencTooManySubsamples,
            )
            .unwrap();
            let json = response.to_json_vec().unwrap();
            assert!(String::from_utf8(json.clone())
                .unwrap()
                .contains("\"failure_reason\":\"cenc_too_many_subsamples\""));
            let decoded = ProtectProviderResponseV1::from_json_slice(&json).unwrap();
            assert_eq!(decoded, response);
            assert_eq!(
                decoded.failure_reason(),
                Some(ProtectFailureReasonV2::CencTooManySubsamples)
            );
            assert!(ProtectProviderResponseV1::new_failure_with_reason(
                ProviderFailureCodeV1::BindingMismatch,
                ProtectFailureReasonV2::CencTooManySubsamples,
            )
            .is_err());
            let mut value: serde_json::Value = serde_json::from_slice(&json).unwrap();
            value["failure_reason"] = serde_json::json!("something_else");
            assert!(ProtectProviderResponseV1::from_json_slice(
                &serde_json::to_vec(&value).unwrap()
            )
            .is_err());
            value["failure_reason"] = serde_json::json!("cenc_too_many_subsamples");
            value["failure_code"] = serde_json::json!("binding_mismatch");
            assert!(ProtectProviderResponseV1::from_json_slice(
                &serde_json::to_vec(&value).unwrap()
            )
            .is_err());
            let plain =
                ProtectProviderResponseV1::new_failure(ProviderFailureCodeV1::InvalidRequest)
                    .unwrap();
            assert_eq!(plain.failure_reason(), None);
        }
    }
}
