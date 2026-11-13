use elastos_protected_content_contracts::{
    AuthenticatedRuntimeReleaseOperationV1, AuthenticatedRuntimeReleaseOperationV2,
    CanonicalContract, ContractError, DeliveryPublicKeyBytesV1, Digest32,
    EncryptedContentIdentityV1, KeyReleaseOutcomeV1, ProtectedContentBindingV1,
    RecipientKeyIdentityV1, RecipientPublicKeyBytesV1, RightsActionV1, RuntimeIssuerPolicyV1,
    RuntimeOperationIssuerKeyV1, RuntimeReleaseAuditIdV1, SignedNodeContributionV1,
    SignedRuntimeReleaseOperationV1, SignedRuntimeReleaseOperationV2, SignedTerminalReceiptV1,
    TerminalReceiptIssuerKey, MAX_RECIPIENT_KEY_AUTHORIZATION_LIFETIME_SECS,
    PQ_HYBRID_WRAP_PUBLIC_KEY_BYTES, X_WING_DRAFT06_CIPHERTEXT_BYTES,
};
use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};

use crate::media::{
    CencFmp4MediaIdentityV1, ValidatedCencFmp4MediaSessionLayoutV1,
    MAX_CENC_FMP4_MEDIA_IDENTITY_BYTES_V1,
};
use crate::media_dash::{
    CencDashMediaIdentityV2, ValidatedCencDashRenditionSessionV2, MAX_CENC_DASH_AUDIT_PATH_V2,
    MAX_CENC_DASH_MEDIA_IDENTITY_BYTES_V2,
};
use crate::object::{
    ChunkedPayloadObjectIdentityV1, MAX_CHUNKED_PAYLOAD_OBJECT_IDENTITY_BYTES_V1,
    MAX_OBJECT_FRAMED_CHUNK_BYTES_V1, MAX_OBJECT_FRAMED_HEADER_BYTES_V1,
    MAX_OBJECT_PLAINTEXT_CHUNK_BYTES_V1,
};
use crate::wire::{
    contract_decode_error, decode_json, encode_json, validate_schema, validate_time_window,
    CanonicalBlob, CanonicalBlobList, OpaqueHandleV1, ProviderFailureCodeV1,
    MAX_PROVIDER_BINDING_BYTES_V1, MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1,
    MAX_RECIPIENT_IDENTITY_BYTES_V1, MAX_SIGNED_NODE_CONTRIBUTIONS_COUNT_V1,
    MAX_SIGNED_NODE_CONTRIBUTION_BYTES_V1, MAX_SIGNED_RUNTIME_RELEASE_OPERATION_BYTES_V1,
    MAX_SIGNED_RUNTIME_RELEASE_OPERATION_BYTES_V2, MAX_SIGNED_TERMINAL_RECEIPT_BYTES_V1,
};

pub const DECRYPT_PROVIDER_REQUEST_SCHEMA_V1: &str =
    "elastos.protected-content.decrypt-provider.request/v1";
pub const DECRYPT_PROVIDER_RESPONSE_SCHEMA_V1: &str =
    "elastos.protected-content.decrypt-provider.response/v1";
pub const MAX_VIEWER_MEDIA_PART_BYTES_V1: usize = 2 * 1024 * 1024;
/// The decrypt capsule's bound on prepared recipients it holds at once.
pub const MAX_PREPARED_RECIPIENTS_V1: usize = 64;
/// The decrypt capsule's bound on open viewer sessions. A custody node's pool
/// sessions stay within it (Plan B L11).
pub const MAX_VIEWER_SESSIONS_V1: usize = 64;
/// Plan B T3.1: the bytes a sealed viewer part adds to its clear part: the
/// X-Wing ciphertext, then the AES-256-GCM nonce and tag (the custody crate's
/// `pq_hybrid` layout, `ciphertext ‖ nonce ‖ AEAD output`).
pub const SEALED_VIEWER_PART_OVERHEAD_BYTES_V1: usize = X_WING_DRAFT06_CIPHERTEXT_BYTES + 12 + 16;
/// The largest sealed viewer part: a clear part at its cap, sealed.
pub const MAX_SEALED_VIEWER_PART_BYTES_V1: usize =
    MAX_VIEWER_MEDIA_PART_BYTES_V1 + SEALED_VIEWER_PART_OVERHEAD_BYTES_V1;
/// The pool session id that names a sealed part in its AAD.
pub const VIEWER_SESSION_ID_BYTES_V1: usize = 16;

type BindingBlobV1 = CanonicalBlob<MAX_PROVIDER_BINDING_BYTES_V1>;
type RecipientIdentityBlobV1 = CanonicalBlob<MAX_RECIPIENT_IDENTITY_BYTES_V1>;
type SignedRuntimeReleaseOperationBlobV1 =
    CanonicalBlob<MAX_SIGNED_RUNTIME_RELEASE_OPERATION_BYTES_V1>;
type SignedRuntimeReleaseOperationV2BlobV1 =
    CanonicalBlob<MAX_SIGNED_RUNTIME_RELEASE_OPERATION_BYTES_V2>;
type SealedViewerPartBlobV1 = CanonicalBlob<MAX_SEALED_VIEWER_PART_BYTES_V1>;
type MediaIdentityBlobV1 = CanonicalBlob<MAX_CENC_FMP4_MEDIA_IDENTITY_BYTES_V1>;
type MediaPartBlobV1 = CanonicalBlob<MAX_VIEWER_MEDIA_PART_BYTES_V1>;
type DashMediaIdentityBlobV2 = CanonicalBlob<MAX_CENC_DASH_MEDIA_IDENTITY_BYTES_V2>;
type DashInitSegmentBlobListV2 = CanonicalBlobList<2, MAX_VIEWER_MEDIA_PART_BYTES_V1>;
type SignedNodeContributionBlobV1 = CanonicalBlob<MAX_SIGNED_NODE_CONTRIBUTION_BYTES_V1>;
type SignedNodeContributionBlobListV1 = CanonicalBlobList<
    MAX_SIGNED_NODE_CONTRIBUTIONS_COUNT_V1,
    MAX_SIGNED_NODE_CONTRIBUTION_BYTES_V1,
>;
type SignedTerminalReceiptBlobV1 = CanonicalBlob<MAX_SIGNED_TERMINAL_RECEIPT_BYTES_V1>;
type ObjectIdentityBlobV1 = CanonicalBlob<MAX_CHUNKED_PAYLOAD_OBJECT_IDENTITY_BYTES_V1>;
type ObjectFramedHeaderBlobV1 = CanonicalBlob<MAX_OBJECT_FRAMED_HEADER_BYTES_V1>;
type ObjectFramedChunkBlobV1 = CanonicalBlob<MAX_OBJECT_FRAMED_CHUNK_BYTES_V1>;
type ObjectPlaintextChunkBlobV1 = CanonicalBlob<MAX_OBJECT_PLAINTEXT_CHUNK_BYTES_V1>;

fn decode_rights_action(value: u8) -> Result<RightsActionV1, ContractError> {
    match value {
        x if x == RightsActionV1::View as u8 => Ok(RightsActionV1::View),
        x if x == RightsActionV1::Stream as u8 => Ok(RightsActionV1::Stream),
        x if x == RightsActionV1::Download as u8 => Ok(RightsActionV1::Download),
        x if x == RightsActionV1::Execute as u8 => Ok(RightsActionV1::Execute),
        _ => Err(ContractError::InvalidField("rights_action")),
    }
}

fn validate_rendition_index(rendition_index: Option<u8>) -> Result<(), ContractError> {
    if rendition_index.is_some_and(|index| index > 1) {
        return Err(ContractError::InvalidField("rendition_index"));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecryptProviderRequestOpV1 {
    PrepareRecipient,
    OpenViewerSession,
    ReadViewerMediaPart,
    CancelPreparedRecipient,
    CloseViewerSession,
    ReadViewerObjectChunk,
    /// Plan B T3.1: a recipient for a V2 pool release, under the Runtime
    /// issuer the request declares.
    PrepareRecipientV2,
    /// Plan B T3.1: a session over a V2 pool release; its parts are sealed to
    /// the delivery key the wallet signed.
    OpenViewerSessionV2,
    ReadViewerMediaPartSealed,
    ReadViewerObjectChunkSealed,
}

impl DecryptProviderRequestOpV1 {
    /// Whether the op validates under the issuer the request declares
    /// ([`ValidatedDecryptProviderRequestV1::decode_and_validate_declared_at`])
    /// rather than the provider's trusted issuer.
    pub const fn is_declared_issuer_op(self) -> bool {
        matches!(
            self,
            Self::PrepareRecipientV2
                | Self::OpenViewerSessionV2
                | Self::ReadViewerMediaPartSealed
                | Self::ReadViewerObjectChunkSealed
        )
    }
}

/// The one content pair of a viewer open, with the V1 open's blob types.
#[derive(Debug, Clone, Copy)]
pub enum DecryptViewerContentV1<'a> {
    MediaV1 {
        identity: &'a CencFmp4MediaIdentityV1,
        protected_init_segment: &'a [u8],
    },
    DashV2 {
        identity: &'a CencDashMediaIdentityV2,
        protected_init_segments: &'a [Vec<u8>],
    },
    Object {
        identity: &'a ChunkedPayloadObjectIdentityV1,
        framed_header: &'a [u8],
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViewerMediaPartSelectorV1(ViewerMediaPartSelectorKindV1);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "part", rename_all = "snake_case", deny_unknown_fields)]
enum ViewerMediaPartSelectorKindV1 {
    Init {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        rendition_index: Option<u8>,
    },
    Segment {
        segment_index: u32,
        encrypted_segment: MediaPartBlobV1,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        rendition_index: Option<u8>,
        // Present (even when empty: a one-segment rendition) only for a v2 read.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        segment_proof: Option<Vec<[u8; 32]>>,
    },
}

impl ViewerMediaPartSelectorV1 {
    pub const fn init() -> Self {
        Self(ViewerMediaPartSelectorKindV1::Init {
            rendition_index: None,
        })
    }

    pub fn init_v2(rendition_index: u8) -> Result<Self, ContractError> {
        let value = Self(ViewerMediaPartSelectorKindV1::Init {
            rendition_index: Some(rendition_index),
        });
        value.validate()?;
        Ok(value)
    }

    pub fn segment(segment_index: u32, encrypted_segment: Vec<u8>) -> Result<Self, ContractError> {
        let value = Self(ViewerMediaPartSelectorKindV1::Segment {
            segment_index,
            encrypted_segment: MediaPartBlobV1::new(encrypted_segment)?,
            rendition_index: None,
            segment_proof: None,
        });
        value.validate()?;
        Ok(value)
    }

    pub fn segment_v2(
        rendition_index: u8,
        segment_index: u32,
        encrypted_segment: Vec<u8>,
        segment_proof: Vec<Digest32>,
    ) -> Result<Self, ContractError> {
        let value = Self(ViewerMediaPartSelectorKindV1::Segment {
            segment_index,
            encrypted_segment: MediaPartBlobV1::new(encrypted_segment)?,
            rendition_index: Some(rendition_index),
            segment_proof: Some(segment_proof.iter().map(|node| *node.as_bytes()).collect()),
        });
        value.validate()?;
        Ok(value)
    }

    pub fn rendition_index(&self) -> Option<u8> {
        match &self.0 {
            ViewerMediaPartSelectorKindV1::Init { rendition_index }
            | ViewerMediaPartSelectorKindV1::Segment {
                rendition_index, ..
            } => *rendition_index,
        }
    }

    pub fn segment_proof(&self) -> Option<Vec<Digest32>> {
        match &self.0 {
            ViewerMediaPartSelectorKindV1::Init { .. } => None,
            ViewerMediaPartSelectorKindV1::Segment { segment_proof, .. } => segment_proof
                .as_ref()
                .map(|proof| proof.iter().copied().map(Digest32::new).collect()),
        }
    }

    pub const fn is_init(&self) -> bool {
        matches!(self.0, ViewerMediaPartSelectorKindV1::Init { .. })
    }

    pub fn segment_index(&self) -> Option<u32> {
        match self.0 {
            ViewerMediaPartSelectorKindV1::Init { .. } => None,
            ViewerMediaPartSelectorKindV1::Segment { segment_index, .. } => Some(segment_index),
        }
    }

    pub fn encrypted_segment(&self) -> Option<&[u8]> {
        match &self.0 {
            ViewerMediaPartSelectorKindV1::Init { .. } => None,
            ViewerMediaPartSelectorKindV1::Segment {
                encrypted_segment, ..
            } => Some(encrypted_segment.as_slice()),
        }
    }

    fn validate(&self) -> Result<(), ContractError> {
        match &self.0 {
            ViewerMediaPartSelectorKindV1::Init { rendition_index } => {
                validate_rendition_index(*rendition_index)
            }
            ViewerMediaPartSelectorKindV1::Segment {
                encrypted_segment,
                rendition_index,
                segment_proof,
                ..
            } => {
                let _ = encrypted_segment.as_slice();
                validate_rendition_index(*rendition_index)?;
                if rendition_index.is_some() != segment_proof.is_some() {
                    return Err(ContractError::InvalidField("segment_proof"));
                }
                if segment_proof
                    .as_ref()
                    .is_some_and(|proof| proof.len() > MAX_CENC_DASH_AUDIT_PATH_V2)
                {
                    return Err(ContractError::InvalidField("segment_proof"));
                }
                Ok(())
            }
        }
    }
}

impl Serialize for ViewerMediaPartSelectorV1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ViewerMediaPartSelectorV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let inner = ViewerMediaPartSelectorKindV1::deserialize(deserializer)?;
        let value = Self(inner);
        value.validate().map_err(D::Error::custom)?;
        Ok(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptProviderRequestV1(DecryptProviderRequestKindV1);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum DecryptProviderRequestKindV1 {
    PrepareRecipient {
        schema: String,
        protected_content_binding: BindingBlobV1,
        audit_request_id: [u8; 32],
        action: u8,
        runtime_operation_issuer: [u8; 32],
        issued_at: u64,
        expires_at: u64,
    },
    OpenViewerSession {
        schema: String,
        prepared_recipient_handle: OpaqueHandleV1,
        signed_runtime_release_operation: SignedRuntimeReleaseOperationBlobV1,
        expected_terminal_issuer: [u8; 32],
        content_key_commitment: [u8; 32],
        #[serde(default, skip_serializing_if = "Option::is_none")]
        media_identity: Option<MediaIdentityBlobV1>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        protected_init_segment: Option<MediaPartBlobV1>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        object_identity: Option<ObjectIdentityBlobV1>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        framed_header: Option<ObjectFramedHeaderBlobV1>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        media_identity_v2: Option<DashMediaIdentityBlobV2>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        protected_init_segments: Option<DashInitSegmentBlobListV2>,
        signed_node_contributions: SignedNodeContributionBlobListV1,
        signed_terminal_receipt: SignedTerminalReceiptBlobV1,
    },
    ReadViewerMediaPart {
        schema: String,
        audit_request_id: [u8; 32],
        viewer_session_handle: OpaqueHandleV1,
        part_selector: ViewerMediaPartSelectorV1,
    },
    CancelPreparedRecipient {
        schema: String,
        audit_request_id: [u8; 32],
        prepared_recipient_handle: OpaqueHandleV1,
    },
    CloseViewerSession {
        schema: String,
        audit_request_id: [u8; 32],
        viewer_session_handle: OpaqueHandleV1,
    },
    ReadViewerObjectChunk {
        schema: String,
        audit_request_id: [u8; 32],
        session_handle: OpaqueHandleV1,
        chunk_index: u32,
        framed_chunk: ObjectFramedChunkBlobV1,
    },
    PrepareRecipientV2 {
        schema: String,
        protected_content_binding: BindingBlobV1,
        audit_request_id: [u8; 32],
        action: u8,
        runtime_operation_issuer: [u8; 32],
        expires_at: u64,
    },
    OpenViewerSessionV2 {
        schema: String,
        prepared_recipient_handle: OpaqueHandleV1,
        signed_runtime_release_operation: SignedRuntimeReleaseOperationV2BlobV1,
        delivery_public_key: Vec<u8>,
        content_key_commitment: [u8; 32],
        #[serde(default, skip_serializing_if = "Option::is_none")]
        media_identity: Option<MediaIdentityBlobV1>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        protected_init_segment: Option<MediaPartBlobV1>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        object_identity: Option<ObjectIdentityBlobV1>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        framed_header: Option<ObjectFramedHeaderBlobV1>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        media_identity_v2: Option<DashMediaIdentityBlobV2>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        protected_init_segments: Option<DashInitSegmentBlobListV2>,
        signed_node_contributions: SignedNodeContributionBlobListV1,
        signed_terminal_receipt: SignedTerminalReceiptBlobV1,
    },
    ReadViewerMediaPartSealed {
        schema: String,
        audit_request_id: [u8; 32],
        viewer_session_handle: OpaqueHandleV1,
        part_selector: ViewerMediaPartSelectorV1,
        session_id: [u8; VIEWER_SESSION_ID_BYTES_V1],
    },
    ReadViewerObjectChunkSealed {
        schema: String,
        audit_request_id: [u8; 32],
        viewer_session_handle: OpaqueHandleV1,
        chunk_index: u32,
        framed_chunk: ObjectFramedChunkBlobV1,
        session_id: [u8; VIEWER_SESSION_ID_BYTES_V1],
    },
}

/// The content fields both opens share, by reference.
struct OpenContentFieldsV1<'a> {
    media_identity: &'a Option<MediaIdentityBlobV1>,
    protected_init_segment: &'a Option<MediaPartBlobV1>,
    object_identity: &'a Option<ObjectIdentityBlobV1>,
    framed_header: &'a Option<ObjectFramedHeaderBlobV1>,
    media_identity_v2: &'a Option<DashMediaIdentityBlobV2>,
    protected_init_segments: &'a Option<DashInitSegmentBlobListV2>,
}

/// The wire content fields of a content pair.
type OpenContentBlobsV1 = (
    Option<MediaIdentityBlobV1>,
    Option<MediaPartBlobV1>,
    Option<ObjectIdentityBlobV1>,
    Option<ObjectFramedHeaderBlobV1>,
    Option<DashMediaIdentityBlobV2>,
    Option<DashInitSegmentBlobListV2>,
);

fn open_content_blobs(
    content: DecryptViewerContentV1<'_>,
) -> Result<OpenContentBlobsV1, ContractError> {
    Ok(match content {
        DecryptViewerContentV1::MediaV1 {
            identity,
            protected_init_segment,
        } => (
            Some(CanonicalBlob::from_contract(identity)?),
            Some(MediaPartBlobV1::new(protected_init_segment.to_vec())?),
            None,
            None,
            None,
            None,
        ),
        DecryptViewerContentV1::DashV2 {
            identity,
            protected_init_segments,
        } => {
            let inits = protected_init_segments
                .iter()
                .map(|init| MediaPartBlobV1::new(init.clone()))
                .collect::<Result<Vec<_>, _>>()?;
            (
                None,
                None,
                None,
                None,
                Some(CanonicalBlob::from_contract(identity)?),
                Some(CanonicalBlobList::new(inits)?),
            )
        }
        DecryptViewerContentV1::Object {
            identity,
            framed_header,
        } => (
            None,
            None,
            Some(CanonicalBlob::from_contract(identity)?),
            Some(ObjectFramedHeaderBlobV1::new(framed_header.to_vec())?),
            None,
            None,
        ),
    })
}

/// The shape both opens require: exactly one content pair, each part of the
/// pair present with it, and an object header of the identity's length.
fn validate_open_content_shape(fields: &OpenContentFieldsV1<'_>) -> Result<(), ContractError> {
    let is_media = fields.media_identity.is_some();
    let is_media_v2 = fields.media_identity_v2.is_some();
    let is_object = fields.object_identity.is_some();
    if is_media_v2 != fields.protected_init_segments.is_some() {
        return Err(ContractError::InvalidField("protected_init_segments"));
    }
    if usize::from(is_media) + usize::from(is_media_v2) + usize::from(is_object) != 1 {
        return Err(ContractError::InvalidField("content"));
    }
    if is_media != fields.protected_init_segment.is_some() {
        return Err(ContractError::InvalidField("protected_init_segment"));
    }
    if is_object != fields.framed_header.is_some() {
        return Err(ContractError::InvalidField("framed_header"));
    }
    if let Some(media_identity_v2) = fields.media_identity_v2 {
        let _: CencDashMediaIdentityV2 = media_identity_v2.decode()?;
    } else if let Some(media_identity) = fields.media_identity {
        let _: CencFmp4MediaIdentityV1 = media_identity.decode()?;
        let _ = fields
            .protected_init_segment
            .as_ref()
            .ok_or(ContractError::InvalidField("protected_init_segment"))?
            .as_slice();
    } else {
        let decoded_object_identity: ChunkedPayloadObjectIdentityV1 = fields
            .object_identity
            .as_ref()
            .ok_or(ContractError::InvalidField("object_identity"))?
            .decode()?;
        let framed_header_bytes = fields
            .framed_header
            .as_ref()
            .ok_or(ContractError::InvalidField("framed_header"))?
            .as_slice();
        if framed_header_bytes.len() as u32 != decoded_object_identity.framed_header_bytes() {
            return Err(ContractError::InvalidField("framed_header"));
        }
    }
    Ok(())
}

/// The content of an open after its identity was bound to the release's
/// encrypted content and its inits or header were checked against the
/// identity. Both opens build it the same way.
fn validate_open_content(
    bound_encrypted_content: &EncryptedContentIdentityV1,
    blobs: OpenContentBlobsV1,
) -> Result<ValidatedOpenContentV1, ContractError> {
    let (
        media_identity,
        protected_init_segment,
        object_identity,
        framed_header,
        media_identity_v2,
        protected_init_segments,
    ) = blobs;
    Ok(
        match (
            media_identity,
            protected_init_segment,
            object_identity,
            framed_header,
            media_identity_v2,
            protected_init_segments,
        ) {
            (None, None, None, None, Some(media_identity_v2), Some(inits)) => {
                let head: CencDashMediaIdentityV2 = media_identity_v2.decode()?;
                if head.encrypted_content() != bound_encrypted_content {
                    return Err(ContractError::InvalidField("media_identity_v2"));
                }
                let inits: Vec<Vec<u8>> = inits.iter().map(<[u8]>::to_vec).collect();
                if inits.len() != head.renditions().len() {
                    return Err(ContractError::InvalidField("protected_init_segments"));
                }
                let sessions = inits
                    .iter()
                    .enumerate()
                    .map(|(index, init)| {
                        ValidatedCencDashRenditionSessionV2::new(&head, index, init)
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| ContractError::InvalidField("protected_init_segments"))?;
                ValidatedOpenContentV1 {
                    media_session_layout: None,
                    protected_init_segment: None,
                    object_identity: None,
                    framed_header: None,
                    media_dash: Some(Box::new(ValidatedMediaDashOpenV2 {
                        head,
                        sessions,
                        inits,
                    })),
                }
            }
            (Some(media_identity), Some(protected_init_segment), None, None, None, None) => {
                let media_identity: CencFmp4MediaIdentityV1 = media_identity.decode()?;
                if media_identity.encrypted_content() != bound_encrypted_content {
                    return Err(ContractError::InvalidField("media_identity"));
                }
                let media_session_layout = ValidatedCencFmp4MediaSessionLayoutV1::new(
                    &media_identity,
                    protected_init_segment.as_slice(),
                )
                .map_err(|_| ContractError::InvalidField("protected_init_segment"))?;
                ValidatedOpenContentV1 {
                    media_session_layout: Some(Box::new(media_session_layout)),
                    protected_init_segment: Some(protected_init_segment),
                    object_identity: None,
                    framed_header: None,
                    media_dash: None,
                }
            }
            (None, None, Some(object_identity), Some(framed_header), None, None) => {
                let object_identity: ChunkedPayloadObjectIdentityV1 = object_identity.decode()?;
                if object_identity.encrypted_content() != bound_encrypted_content {
                    return Err(ContractError::InvalidField("object_identity"));
                }
                if framed_header.as_slice().len() as u32 != object_identity.framed_header_bytes() {
                    return Err(ContractError::InvalidField("framed_header"));
                }
                ValidatedOpenContentV1 {
                    media_session_layout: None,
                    protected_init_segment: None,
                    object_identity: Some(Box::new(object_identity)),
                    framed_header: Some(framed_header),
                    media_dash: None,
                }
            }
            _ => return Err(ContractError::InvalidField("content")),
        },
    )
}

fn delivery_public_key_from_bytes(bytes: &[u8]) -> Result<DeliveryPublicKeyBytesV1, ContractError> {
    let bytes: [u8; PQ_HYBRID_WRAP_PUBLIC_KEY_BYTES] = bytes
        .try_into()
        .map_err(|_| ContractError::InvalidField("delivery_public_key"))?;
    DeliveryPublicKeyBytesV1::new(bytes)
}

impl DecryptProviderRequestV1 {
    pub const fn op(&self) -> DecryptProviderRequestOpV1 {
        match self.0 {
            DecryptProviderRequestKindV1::PrepareRecipient { .. } => {
                DecryptProviderRequestOpV1::PrepareRecipient
            }
            DecryptProviderRequestKindV1::OpenViewerSession { .. } => {
                DecryptProviderRequestOpV1::OpenViewerSession
            }
            DecryptProviderRequestKindV1::ReadViewerMediaPart { .. } => {
                DecryptProviderRequestOpV1::ReadViewerMediaPart
            }
            DecryptProviderRequestKindV1::CancelPreparedRecipient { .. } => {
                DecryptProviderRequestOpV1::CancelPreparedRecipient
            }
            DecryptProviderRequestKindV1::CloseViewerSession { .. } => {
                DecryptProviderRequestOpV1::CloseViewerSession
            }
            DecryptProviderRequestKindV1::ReadViewerObjectChunk { .. } => {
                DecryptProviderRequestOpV1::ReadViewerObjectChunk
            }
            DecryptProviderRequestKindV1::PrepareRecipientV2 { .. } => {
                DecryptProviderRequestOpV1::PrepareRecipientV2
            }
            DecryptProviderRequestKindV1::OpenViewerSessionV2 { .. } => {
                DecryptProviderRequestOpV1::OpenViewerSessionV2
            }
            DecryptProviderRequestKindV1::ReadViewerMediaPartSealed { .. } => {
                DecryptProviderRequestOpV1::ReadViewerMediaPartSealed
            }
            DecryptProviderRequestKindV1::ReadViewerObjectChunkSealed { .. } => {
                DecryptProviderRequestOpV1::ReadViewerObjectChunkSealed
            }
        }
    }

    /// Plan B T3.1: a recipient for a V2 pool release. The request declares
    /// the Runtime issuer whose release it awaits; the prepare lives until
    /// `expires_at`, at most a recipient authorization's lifetime.
    pub fn new_prepare_recipient_v2(
        protected_content_binding: &ProtectedContentBindingV1,
        audit_request_id: RuntimeReleaseAuditIdV1,
        action: RightsActionV1,
        runtime_operation_issuer: RuntimeOperationIssuerKeyV1,
        expires_at: u64,
    ) -> Result<Self, ContractError> {
        let value = Self(DecryptProviderRequestKindV1::PrepareRecipientV2 {
            schema: DECRYPT_PROVIDER_REQUEST_SCHEMA_V1.to_string(),
            protected_content_binding: CanonicalBlob::from_contract(protected_content_binding)?,
            audit_request_id: *audit_request_id.digest().as_bytes(),
            action: action as u8,
            runtime_operation_issuer: *runtime_operation_issuer.as_bytes(),
            expires_at,
        });
        value.validate_structure()?;
        Ok(value)
    }

    /// Plan B T3.1: opens a session over a V2 pool release. The provider
    /// seals every part of it to `delivery_public_key`, whose identity the
    /// wallet signed in the operation.
    pub fn new_open_pool_viewer_session(
        prepared_recipient_handle: [u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1],
        signed_runtime_release_operation: &SignedRuntimeReleaseOperationV2,
        delivery_public_key: &DeliveryPublicKeyBytesV1,
        content_key_commitment: Digest32,
        content: DecryptViewerContentV1<'_>,
        signed_node_contributions: &[SignedNodeContributionV1],
        signed_terminal_receipt: &SignedTerminalReceiptV1,
    ) -> Result<Self, ContractError> {
        let contributions = signed_node_contributions
            .iter()
            .map(CanonicalBlob::from_contract)
            .collect::<Result<Vec<SignedNodeContributionBlobV1>, _>>()?;
        let (
            media_identity,
            protected_init_segment,
            object_identity,
            framed_header,
            media_identity_v2,
            protected_init_segments,
        ) = open_content_blobs(content)?;
        let value = Self(DecryptProviderRequestKindV1::OpenViewerSessionV2 {
            schema: DECRYPT_PROVIDER_REQUEST_SCHEMA_V1.to_string(),
            prepared_recipient_handle: OpaqueHandleV1::new(prepared_recipient_handle)?,
            signed_runtime_release_operation: CanonicalBlob::from_contract(
                signed_runtime_release_operation,
            )?,
            delivery_public_key: delivery_public_key.as_bytes().to_vec(),
            content_key_commitment: *content_key_commitment.as_bytes(),
            media_identity,
            protected_init_segment,
            object_identity,
            framed_header,
            media_identity_v2,
            protected_init_segments,
            signed_node_contributions: CanonicalBlobList::new(contributions)?,
            signed_terminal_receipt: CanonicalBlob::from_contract(signed_terminal_receipt)?,
        });
        value.validate_structure()?;
        Ok(value)
    }

    /// Plan B T3.1: one media part of a V2 session, answered sealed.
    pub fn new_read_viewer_media_part_sealed(
        audit_request_id: RuntimeReleaseAuditIdV1,
        viewer_session_handle: [u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1],
        part_selector: ViewerMediaPartSelectorV1,
        session_id: [u8; VIEWER_SESSION_ID_BYTES_V1],
    ) -> Result<Self, ContractError> {
        let value = Self(DecryptProviderRequestKindV1::ReadViewerMediaPartSealed {
            schema: DECRYPT_PROVIDER_REQUEST_SCHEMA_V1.to_string(),
            audit_request_id: *audit_request_id.digest().as_bytes(),
            viewer_session_handle: OpaqueHandleV1::new(viewer_session_handle)?,
            part_selector,
            session_id,
        });
        value.validate_structure()?;
        Ok(value)
    }

    /// Plan B T3.1: one object chunk of a V2 session, answered sealed.
    pub fn new_read_viewer_object_chunk_sealed(
        audit_request_id: RuntimeReleaseAuditIdV1,
        viewer_session_handle: [u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1],
        chunk_index: u32,
        framed_chunk: &[u8],
        session_id: [u8; VIEWER_SESSION_ID_BYTES_V1],
    ) -> Result<Self, ContractError> {
        let value = Self(DecryptProviderRequestKindV1::ReadViewerObjectChunkSealed {
            schema: DECRYPT_PROVIDER_REQUEST_SCHEMA_V1.to_string(),
            audit_request_id: *audit_request_id.digest().as_bytes(),
            viewer_session_handle: OpaqueHandleV1::new(viewer_session_handle)?,
            chunk_index,
            framed_chunk: ObjectFramedChunkBlobV1::new(framed_chunk.to_vec())?,
            session_id,
        });
        value.validate_structure()?;
        Ok(value)
    }

    pub fn new_prepare_recipient(
        protected_content_binding: &ProtectedContentBindingV1,
        audit_request_id: RuntimeReleaseAuditIdV1,
        action: RightsActionV1,
        runtime_operation_issuer: RuntimeOperationIssuerKeyV1,
        issued_at: u64,
        expires_at: u64,
    ) -> Result<Self, ContractError> {
        let value = Self(DecryptProviderRequestKindV1::PrepareRecipient {
            schema: DECRYPT_PROVIDER_REQUEST_SCHEMA_V1.to_string(),
            protected_content_binding: CanonicalBlob::from_contract(protected_content_binding)?,
            audit_request_id: *audit_request_id.digest().as_bytes(),
            action: action as u8,
            runtime_operation_issuer: *runtime_operation_issuer.as_bytes(),
            issued_at,
            expires_at,
        });
        value.validate_structure()?;
        Ok(value)
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the protocol requires these independently validated signed and media bindings"
    )]
    pub fn new_open_viewer_session(
        prepared_recipient_handle: [u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1],
        signed_runtime_release_operation: &SignedRuntimeReleaseOperationV1,
        expected_terminal_issuer: TerminalReceiptIssuerKey,
        content_key_commitment: Digest32,
        media_identity: &CencFmp4MediaIdentityV1,
        protected_init_segment: &[u8],
        signed_node_contributions: &[SignedNodeContributionV1],
        signed_terminal_receipt: &SignedTerminalReceiptV1,
    ) -> Result<Self, ContractError> {
        let contributions = signed_node_contributions
            .iter()
            .map(CanonicalBlob::from_contract)
            .collect::<Result<Vec<SignedNodeContributionBlobV1>, _>>()?;
        let value = Self(DecryptProviderRequestKindV1::OpenViewerSession {
            schema: DECRYPT_PROVIDER_REQUEST_SCHEMA_V1.to_string(),
            prepared_recipient_handle: OpaqueHandleV1::new(prepared_recipient_handle)?,
            signed_runtime_release_operation: CanonicalBlob::from_contract(
                signed_runtime_release_operation,
            )?,
            expected_terminal_issuer: *expected_terminal_issuer.as_bytes(),
            content_key_commitment: *content_key_commitment.as_bytes(),
            media_identity: Some(CanonicalBlob::from_contract(media_identity)?),
            protected_init_segment: Some(MediaPartBlobV1::new(protected_init_segment.to_vec())?),
            object_identity: None,
            framed_header: None,
            media_identity_v2: None,
            protected_init_segments: None,
            signed_node_contributions: CanonicalBlobList::new(contributions)?,
            signed_terminal_receipt: CanonicalBlob::from_contract(signed_terminal_receipt)?,
        });
        value.validate_structure()?;
        Ok(value)
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the protocol requires these independently validated signed and media bindings"
    )]
    pub fn new_open_viewer_session_v2(
        prepared_recipient_handle: [u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1],
        signed_runtime_release_operation: &SignedRuntimeReleaseOperationV1,
        expected_terminal_issuer: TerminalReceiptIssuerKey,
        content_key_commitment: Digest32,
        media_identity_v2: &CencDashMediaIdentityV2,
        protected_init_segments: &[Vec<u8>],
        signed_node_contributions: &[SignedNodeContributionV1],
        signed_terminal_receipt: &SignedTerminalReceiptV1,
    ) -> Result<Self, ContractError> {
        let contributions = signed_node_contributions
            .iter()
            .map(CanonicalBlob::from_contract)
            .collect::<Result<Vec<SignedNodeContributionBlobV1>, _>>()?;
        let inits = protected_init_segments
            .iter()
            .map(|init| MediaPartBlobV1::new(init.clone()))
            .collect::<Result<Vec<_>, _>>()?;
        let value = Self(DecryptProviderRequestKindV1::OpenViewerSession {
            schema: DECRYPT_PROVIDER_REQUEST_SCHEMA_V1.to_string(),
            prepared_recipient_handle: OpaqueHandleV1::new(prepared_recipient_handle)?,
            signed_runtime_release_operation: CanonicalBlob::from_contract(
                signed_runtime_release_operation,
            )?,
            expected_terminal_issuer: *expected_terminal_issuer.as_bytes(),
            content_key_commitment: *content_key_commitment.as_bytes(),
            media_identity: None,
            protected_init_segment: None,
            object_identity: None,
            framed_header: None,
            media_identity_v2: Some(CanonicalBlob::from_contract(media_identity_v2)?),
            protected_init_segments: Some(CanonicalBlobList::new(inits)?),
            signed_node_contributions: CanonicalBlobList::new(contributions)?,
            signed_terminal_receipt: CanonicalBlob::from_contract(signed_terminal_receipt)?,
        });
        value.validate_structure()?;
        Ok(value)
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the protocol requires these independently validated signed and object bindings"
    )]
    pub fn new_open_viewer_session_for_object(
        prepared_recipient_handle: [u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1],
        signed_runtime_release_operation: &SignedRuntimeReleaseOperationV1,
        expected_terminal_issuer: TerminalReceiptIssuerKey,
        content_key_commitment: Digest32,
        object_identity: &ChunkedPayloadObjectIdentityV1,
        framed_header: &[u8],
        signed_node_contributions: &[SignedNodeContributionV1],
        signed_terminal_receipt: &SignedTerminalReceiptV1,
    ) -> Result<Self, ContractError> {
        let contributions = signed_node_contributions
            .iter()
            .map(CanonicalBlob::from_contract)
            .collect::<Result<Vec<SignedNodeContributionBlobV1>, _>>()?;
        let value = Self(DecryptProviderRequestKindV1::OpenViewerSession {
            schema: DECRYPT_PROVIDER_REQUEST_SCHEMA_V1.to_string(),
            prepared_recipient_handle: OpaqueHandleV1::new(prepared_recipient_handle)?,
            signed_runtime_release_operation: CanonicalBlob::from_contract(
                signed_runtime_release_operation,
            )?,
            expected_terminal_issuer: *expected_terminal_issuer.as_bytes(),
            content_key_commitment: *content_key_commitment.as_bytes(),
            media_identity: None,
            protected_init_segment: None,
            object_identity: Some(CanonicalBlob::from_contract(object_identity)?),
            framed_header: Some(ObjectFramedHeaderBlobV1::new(framed_header.to_vec())?),
            media_identity_v2: None,
            protected_init_segments: None,
            signed_node_contributions: CanonicalBlobList::new(contributions)?,
            signed_terminal_receipt: CanonicalBlob::from_contract(signed_terminal_receipt)?,
        });
        value.validate_structure()?;
        Ok(value)
    }

    pub fn new_read_viewer_media_part(
        audit_request_id: RuntimeReleaseAuditIdV1,
        viewer_session_handle: [u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1],
        part_selector: ViewerMediaPartSelectorV1,
    ) -> Result<Self, ContractError> {
        let value = Self(DecryptProviderRequestKindV1::ReadViewerMediaPart {
            schema: DECRYPT_PROVIDER_REQUEST_SCHEMA_V1.to_string(),
            audit_request_id: *audit_request_id.digest().as_bytes(),
            viewer_session_handle: OpaqueHandleV1::new(viewer_session_handle)?,
            part_selector,
        });
        value.validate_structure()?;
        Ok(value)
    }

    pub fn new_cancel_prepared_recipient(
        audit_request_id: RuntimeReleaseAuditIdV1,
        prepared_recipient_handle: [u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1],
    ) -> Result<Self, ContractError> {
        let value = Self(DecryptProviderRequestKindV1::CancelPreparedRecipient {
            schema: DECRYPT_PROVIDER_REQUEST_SCHEMA_V1.to_string(),
            audit_request_id: *audit_request_id.digest().as_bytes(),
            prepared_recipient_handle: OpaqueHandleV1::new(prepared_recipient_handle)?,
        });
        value.validate_structure()?;
        Ok(value)
    }

    pub fn new_close_viewer_session(
        audit_request_id: RuntimeReleaseAuditIdV1,
        viewer_session_handle: [u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1],
    ) -> Result<Self, ContractError> {
        let value = Self(DecryptProviderRequestKindV1::CloseViewerSession {
            schema: DECRYPT_PROVIDER_REQUEST_SCHEMA_V1.to_string(),
            audit_request_id: *audit_request_id.digest().as_bytes(),
            viewer_session_handle: OpaqueHandleV1::new(viewer_session_handle)?,
        });
        value.validate_structure()?;
        Ok(value)
    }

    pub fn new_read_viewer_object_chunk(
        audit_request_id: RuntimeReleaseAuditIdV1,
        session_handle: [u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1],
        chunk_index: u32,
        framed_chunk: &[u8],
    ) -> Result<Self, ContractError> {
        let value = Self(DecryptProviderRequestKindV1::ReadViewerObjectChunk {
            schema: DECRYPT_PROVIDER_REQUEST_SCHEMA_V1.to_string(),
            audit_request_id: *audit_request_id.digest().as_bytes(),
            session_handle: OpaqueHandleV1::new(session_handle)?,
            chunk_index,
            framed_chunk: ObjectFramedChunkBlobV1::new(framed_chunk.to_vec())?,
        });
        value.validate_structure()?;
        Ok(value)
    }

    pub fn to_json_vec(&self) -> Result<Vec<u8>, serde_json::Error> {
        encode_json(self)
    }

    fn audit_request_id(&self) -> Result<RuntimeReleaseAuditIdV1, ContractError> {
        match &self.0 {
            DecryptProviderRequestKindV1::PrepareRecipient {
                audit_request_id, ..
            }
            | DecryptProviderRequestKindV1::CancelPreparedRecipient {
                audit_request_id, ..
            }
            | DecryptProviderRequestKindV1::CloseViewerSession {
                audit_request_id, ..
            }
            | DecryptProviderRequestKindV1::ReadViewerMediaPart {
                audit_request_id, ..
            }
            | DecryptProviderRequestKindV1::ReadViewerObjectChunk {
                audit_request_id, ..
            }
            | DecryptProviderRequestKindV1::PrepareRecipientV2 {
                audit_request_id, ..
            }
            | DecryptProviderRequestKindV1::ReadViewerMediaPartSealed {
                audit_request_id, ..
            }
            | DecryptProviderRequestKindV1::ReadViewerObjectChunkSealed {
                audit_request_id, ..
            } => RuntimeReleaseAuditIdV1::new(elastos_protected_content_contracts::Digest32::new(
                *audit_request_id,
            )),
            DecryptProviderRequestKindV1::OpenViewerSession {
                signed_runtime_release_operation,
                ..
            } => {
                let operation: SignedRuntimeReleaseOperationV1 =
                    signed_runtime_release_operation.decode()?;
                Ok(operation.statement().audit_request_id())
            }
            DecryptProviderRequestKindV1::OpenViewerSessionV2 {
                signed_runtime_release_operation,
                ..
            } => {
                let operation: SignedRuntimeReleaseOperationV2 =
                    signed_runtime_release_operation.decode()?;
                Ok(operation.statement().audit_request_id())
            }
        }
    }

    fn protected_content_binding(&self) -> Result<ProtectedContentBindingV1, ContractError> {
        match &self.0 {
            DecryptProviderRequestKindV1::PrepareRecipient {
                protected_content_binding,
                ..
            }
            | DecryptProviderRequestKindV1::PrepareRecipientV2 {
                protected_content_binding,
                ..
            } => protected_content_binding.decode(),
            _ => Err(ContractError::InvalidField("protected_content_binding")),
        }
    }

    fn action(&self) -> Result<RightsActionV1, ContractError> {
        match &self.0 {
            DecryptProviderRequestKindV1::PrepareRecipient { action, .. }
            | DecryptProviderRequestKindV1::PrepareRecipientV2 { action, .. } => {
                decode_rights_action(*action)
            }
            _ => Err(ContractError::InvalidField("rights_action")),
        }
    }

    fn runtime_operation_issuer(&self) -> Result<RuntimeOperationIssuerKeyV1, ContractError> {
        match &self.0 {
            DecryptProviderRequestKindV1::PrepareRecipient {
                runtime_operation_issuer,
                ..
            }
            | DecryptProviderRequestKindV1::PrepareRecipientV2 {
                runtime_operation_issuer,
                ..
            } => RuntimeOperationIssuerKeyV1::new(*runtime_operation_issuer),
            _ => Err(ContractError::InvalidField("runtime_operation_issuer")),
        }
    }

    fn issued_at(&self) -> Result<u64, ContractError> {
        match &self.0 {
            DecryptProviderRequestKindV1::PrepareRecipient { issued_at, .. } => Ok(*issued_at),
            _ => Err(ContractError::InvalidField("issued_at")),
        }
    }

    fn expires_at(&self) -> Result<u64, ContractError> {
        match &self.0 {
            DecryptProviderRequestKindV1::PrepareRecipient { expires_at, .. }
            | DecryptProviderRequestKindV1::PrepareRecipientV2 { expires_at, .. } => {
                Ok(*expires_at)
            }
            _ => Err(ContractError::InvalidField("expires_at")),
        }
    }

    fn prepared_recipient_handle(
        &self,
    ) -> Result<&[u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1], ContractError> {
        match &self.0 {
            DecryptProviderRequestKindV1::OpenViewerSession {
                prepared_recipient_handle,
                ..
            }
            | DecryptProviderRequestKindV1::OpenViewerSessionV2 {
                prepared_recipient_handle,
                ..
            }
            | DecryptProviderRequestKindV1::CancelPreparedRecipient {
                prepared_recipient_handle,
                ..
            } => Ok(prepared_recipient_handle.as_bytes()),
            _ => Err(ContractError::InvalidField("prepared_recipient_handle")),
        }
    }

    /// The content fields of either open.
    fn open_content_fields(&self) -> Option<OpenContentFieldsV1<'_>> {
        match &self.0 {
            DecryptProviderRequestKindV1::OpenViewerSession {
                media_identity,
                protected_init_segment,
                object_identity,
                framed_header,
                media_identity_v2,
                protected_init_segments,
                ..
            }
            | DecryptProviderRequestKindV1::OpenViewerSessionV2 {
                media_identity,
                protected_init_segment,
                object_identity,
                framed_header,
                media_identity_v2,
                protected_init_segments,
                ..
            } => Some(OpenContentFieldsV1 {
                media_identity,
                protected_init_segment,
                object_identity,
                framed_header,
                media_identity_v2,
                protected_init_segments,
            }),
            _ => None,
        }
    }

    fn signed_runtime_release_operation(
        &self,
    ) -> Result<SignedRuntimeReleaseOperationV1, ContractError> {
        match &self.0 {
            DecryptProviderRequestKindV1::OpenViewerSession {
                signed_runtime_release_operation,
                ..
            } => signed_runtime_release_operation.decode(),
            _ => Err(ContractError::InvalidField(
                "signed_runtime_release_operation",
            )),
        }
    }

    fn expected_terminal_issuer(&self) -> Result<TerminalReceiptIssuerKey, ContractError> {
        match &self.0 {
            DecryptProviderRequestKindV1::OpenViewerSession {
                expected_terminal_issuer,
                ..
            } => TerminalReceiptIssuerKey::new(*expected_terminal_issuer),
            _ => Err(ContractError::InvalidField("expected_terminal_issuer")),
        }
    }

    fn content_key_commitment(&self) -> Result<Digest32, ContractError> {
        match &self.0 {
            DecryptProviderRequestKindV1::OpenViewerSession {
                content_key_commitment,
                ..
            }
            | DecryptProviderRequestKindV1::OpenViewerSessionV2 {
                content_key_commitment,
                ..
            } => Ok(Digest32::new(*content_key_commitment)),
            _ => Err(ContractError::InvalidField("content_key_commitment")),
        }
    }

    fn signed_node_contributions(&self) -> Result<Vec<SignedNodeContributionV1>, ContractError> {
        match &self.0 {
            DecryptProviderRequestKindV1::OpenViewerSession {
                signed_node_contributions,
                ..
            }
            | DecryptProviderRequestKindV1::OpenViewerSessionV2 {
                signed_node_contributions,
                ..
            } => signed_node_contributions
                .iter()
                .map(SignedNodeContributionV1::from_canonical_bytes)
                .collect(),
            _ => Err(ContractError::InvalidField("signed_node_contributions")),
        }
    }

    fn signed_terminal_receipt(&self) -> Result<SignedTerminalReceiptV1, ContractError> {
        match &self.0 {
            DecryptProviderRequestKindV1::OpenViewerSession {
                signed_terminal_receipt,
                ..
            }
            | DecryptProviderRequestKindV1::OpenViewerSessionV2 {
                signed_terminal_receipt,
                ..
            } => signed_terminal_receipt.decode(),
            _ => Err(ContractError::InvalidField("signed_terminal_receipt")),
        }
    }

    fn viewer_session_handle(
        &self,
    ) -> Result<&[u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1], ContractError> {
        match &self.0 {
            DecryptProviderRequestKindV1::ReadViewerMediaPart {
                viewer_session_handle,
                ..
            }
            | DecryptProviderRequestKindV1::CloseViewerSession {
                viewer_session_handle,
                ..
            } => Ok(viewer_session_handle.as_bytes()),
            _ => Err(ContractError::InvalidField("viewer_session_handle")),
        }
    }

    fn viewer_media_part_selector(&self) -> Result<&ViewerMediaPartSelectorV1, ContractError> {
        match &self.0 {
            DecryptProviderRequestKindV1::ReadViewerMediaPart { part_selector, .. } => {
                Ok(part_selector)
            }
            _ => Err(ContractError::InvalidField("part_selector")),
        }
    }

    fn validate_structure(&self) -> Result<(), ContractError> {
        match &self.0 {
            DecryptProviderRequestKindV1::PrepareRecipient { schema, .. } => {
                validate_schema(
                    schema,
                    DECRYPT_PROVIDER_REQUEST_SCHEMA_V1,
                    "decrypt_provider_request.schema",
                )?;
                self.protected_content_binding()?;
                self.audit_request_id()?;
                self.action()?;
                self.runtime_operation_issuer()?;
                validate_time_window(
                    self.issued_at()?,
                    self.expires_at()?,
                    MAX_RECIPIENT_KEY_AUTHORIZATION_LIFETIME_SECS,
                    "decrypt_prepare_window",
                )?;
                Ok(())
            }
            DecryptProviderRequestKindV1::OpenViewerSession { schema, .. } => {
                validate_schema(
                    schema,
                    DECRYPT_PROVIDER_REQUEST_SCHEMA_V1,
                    "decrypt_provider_request.schema",
                )?;
                self.prepared_recipient_handle()?;
                let _ = self.signed_runtime_release_operation()?;
                let _ = self.expected_terminal_issuer()?;
                let _ = self.content_key_commitment()?;
                validate_open_content_shape(
                    &self
                        .open_content_fields()
                        .ok_or(ContractError::InvalidField("content"))?,
                )?;
                let _ = self.signed_node_contributions()?;
                let _ = self.signed_terminal_receipt()?;
                Ok(())
            }
            DecryptProviderRequestKindV1::PrepareRecipientV2 { schema, .. } => {
                validate_schema(
                    schema,
                    DECRYPT_PROVIDER_REQUEST_SCHEMA_V1,
                    "decrypt_provider_request.schema",
                )?;
                self.protected_content_binding()?;
                self.audit_request_id()?;
                self.action()?;
                self.runtime_operation_issuer()?;
                Ok(())
            }
            DecryptProviderRequestKindV1::OpenViewerSessionV2 {
                schema,
                signed_runtime_release_operation,
                delivery_public_key,
                ..
            } => {
                validate_schema(
                    schema,
                    DECRYPT_PROVIDER_REQUEST_SCHEMA_V1,
                    "decrypt_provider_request.schema",
                )?;
                self.prepared_recipient_handle()?;
                let _: SignedRuntimeReleaseOperationV2 =
                    signed_runtime_release_operation.decode()?;
                delivery_public_key_from_bytes(delivery_public_key)?;
                validate_open_content_shape(
                    &self
                        .open_content_fields()
                        .ok_or(ContractError::InvalidField("content"))?,
                )?;
                let _ = self.signed_node_contributions()?;
                let _ = self.signed_terminal_receipt()?;
                Ok(())
            }
            DecryptProviderRequestKindV1::ReadViewerMediaPartSealed { schema, .. }
            | DecryptProviderRequestKindV1::ReadViewerObjectChunkSealed { schema, .. } => {
                validate_schema(
                    schema,
                    DECRYPT_PROVIDER_REQUEST_SCHEMA_V1,
                    "decrypt_provider_request.schema",
                )?;
                self.audit_request_id()?;
                Ok(())
            }
            DecryptProviderRequestKindV1::ReadViewerMediaPart { schema, .. } => {
                validate_schema(
                    schema,
                    DECRYPT_PROVIDER_REQUEST_SCHEMA_V1,
                    "decrypt_provider_request.schema",
                )?;
                self.audit_request_id()?;
                self.viewer_session_handle()?;
                let _ = self.viewer_media_part_selector()?;
                Ok(())
            }
            DecryptProviderRequestKindV1::CancelPreparedRecipient { schema, .. } => {
                validate_schema(
                    schema,
                    DECRYPT_PROVIDER_REQUEST_SCHEMA_V1,
                    "decrypt_provider_request.schema",
                )?;
                self.audit_request_id()?;
                self.prepared_recipient_handle()?;
                Ok(())
            }
            DecryptProviderRequestKindV1::CloseViewerSession { schema, .. } => {
                validate_schema(
                    schema,
                    DECRYPT_PROVIDER_REQUEST_SCHEMA_V1,
                    "decrypt_provider_request.schema",
                )?;
                self.audit_request_id()?;
                self.viewer_session_handle()?;
                Ok(())
            }
            DecryptProviderRequestKindV1::ReadViewerObjectChunk { schema, .. } => {
                validate_schema(
                    schema,
                    DECRYPT_PROVIDER_REQUEST_SCHEMA_V1,
                    "decrypt_provider_request.schema",
                )?;
                self.audit_request_id()?;
                Ok(())
            }
        }
    }

    fn decode_wire(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        let inner = decode_json::<DecryptProviderRequestKindV1>(bytes)?;
        let value = Self(inner);
        value.validate_structure().map_err(contract_decode_error)?;
        Ok(value)
    }

    fn into_validated_at(
        self,
        expected_runtime_issuer: RuntimeOperationIssuerKeyV1,
        now_unix_seconds: u64,
    ) -> Result<ValidatedDecryptProviderRequestV1, ContractError> {
        match self.0 {
            DecryptProviderRequestKindV1::PrepareRecipient {
                protected_content_binding,
                audit_request_id,
                action,
                runtime_operation_issuer,
                issued_at,
                expires_at,
                ..
            } => {
                if now_unix_seconds < issued_at || now_unix_seconds >= expires_at {
                    return Err(ContractError::InvalidField("decrypt_prepare_window"));
                }
                let runtime_operation_issuer =
                    RuntimeOperationIssuerKeyV1::new(runtime_operation_issuer)?;
                if runtime_operation_issuer != expected_runtime_issuer {
                    return Err(ContractError::InvalidField("runtime_operation_issuer"));
                }
                Ok(ValidatedDecryptProviderRequestV1(
                    ValidatedDecryptProviderRequestKindV1::PrepareRecipient {
                        protected_content_binding: Box::new(protected_content_binding.decode()?),
                        audit_request_id: RuntimeReleaseAuditIdV1::new(
                            elastos_protected_content_contracts::Digest32::new(audit_request_id),
                        )?,
                        action: decode_rights_action(action)?,
                        runtime_operation_issuer,
                        issued_at,
                        expires_at,
                    },
                ))
            }
            DecryptProviderRequestKindV1::OpenViewerSession {
                prepared_recipient_handle,
                signed_runtime_release_operation,
                expected_terminal_issuer,
                content_key_commitment,
                media_identity,
                protected_init_segment,
                object_identity,
                framed_header,
                media_identity_v2,
                protected_init_segments,
                signed_node_contributions,
                signed_terminal_receipt,
                ..
            } => {
                let authenticated_runtime_release_operation = signed_runtime_release_operation
                    .decode::<SignedRuntimeReleaseOperationV1>()?
                    .verify(expected_runtime_issuer, now_unix_seconds)
                    .map_err(|_| ContractError::InvalidField("signed_runtime_release_operation"))?;
                let expected_terminal_issuer =
                    TerminalReceiptIssuerKey::new(expected_terminal_issuer)?;
                let content_key_commitment = Digest32::new(content_key_commitment);
                let content = validate_open_content(
                    authenticated_runtime_release_operation
                        .statement()
                        .release_request()
                        .binding()
                        .encrypted_content(),
                    (
                        media_identity,
                        protected_init_segment,
                        object_identity,
                        framed_header,
                        media_identity_v2,
                        protected_init_segments,
                    ),
                )?;
                let signed_node_contributions: Vec<SignedNodeContributionV1> =
                    signed_node_contributions
                        .iter()
                        .map(SignedNodeContributionV1::from_canonical_bytes)
                        .collect::<Result<_, _>>()?;
                let signed_terminal_receipt: SignedTerminalReceiptV1 =
                    signed_terminal_receipt.decode()?;
                let node_set = authenticated_runtime_release_operation
                    .statement()
                    .custody_epoch()
                    .statement()
                    .node_set()
                    .map_err(|_| ContractError::InvalidField("signed_runtime_release_operation"))?;
                let mut verified_contributions =
                    Vec::with_capacity(signed_node_contributions.len());
                for contribution in &signed_node_contributions {
                    let verified = authenticated_runtime_release_operation
                        .verify_node_contribution(contribution, &node_set, now_unix_seconds)
                        .map_err(|_| ContractError::InvalidField("signed_node_contributions"))?;
                    verified_contributions.push(verified);
                }
                if signed_terminal_receipt.statement().outcome() != KeyReleaseOutcomeV1::Released {
                    return Err(ContractError::InvalidField("signed_terminal_receipt"));
                }
                authenticated_runtime_release_operation
                    .verify_terminal_receipt(
                        &signed_terminal_receipt,
                        &verified_contributions,
                        expected_terminal_issuer,
                        now_unix_seconds,
                    )
                    .map_err(|_| ContractError::InvalidField("signed_terminal_receipt"))?;
                Ok(ValidatedDecryptProviderRequestV1(
                    ValidatedDecryptProviderRequestKindV1::OpenViewerSession {
                        prepared_recipient_handle,
                        authenticated_runtime_release_operation: Box::new(
                            authenticated_runtime_release_operation,
                        ),
                        expected_terminal_issuer,
                        content_key_commitment,
                        content,
                        signed_node_contributions,
                        signed_terminal_receipt: Box::new(signed_terminal_receipt),
                    },
                ))
            }
            DecryptProviderRequestKindV1::ReadViewerMediaPart {
                audit_request_id,
                viewer_session_handle,
                part_selector,
                ..
            } => Ok(ValidatedDecryptProviderRequestV1(
                ValidatedDecryptProviderRequestKindV1::ReadViewerMediaPart {
                    audit_request_id: RuntimeReleaseAuditIdV1::new(
                        elastos_protected_content_contracts::Digest32::new(audit_request_id),
                    )?,
                    viewer_session_handle,
                    part_selector,
                },
            )),
            DecryptProviderRequestKindV1::CancelPreparedRecipient {
                audit_request_id,
                prepared_recipient_handle,
                ..
            } => Ok(ValidatedDecryptProviderRequestV1(
                ValidatedDecryptProviderRequestKindV1::CancelPreparedRecipient {
                    audit_request_id: RuntimeReleaseAuditIdV1::new(
                        elastos_protected_content_contracts::Digest32::new(audit_request_id),
                    )?,
                    prepared_recipient_handle,
                },
            )),
            DecryptProviderRequestKindV1::CloseViewerSession {
                audit_request_id,
                viewer_session_handle,
                ..
            } => Ok(ValidatedDecryptProviderRequestV1(
                ValidatedDecryptProviderRequestKindV1::CloseViewerSession {
                    audit_request_id: RuntimeReleaseAuditIdV1::new(
                        elastos_protected_content_contracts::Digest32::new(audit_request_id),
                    )?,
                    viewer_session_handle,
                },
            )),
            DecryptProviderRequestKindV1::ReadViewerObjectChunk {
                audit_request_id,
                session_handle,
                chunk_index,
                framed_chunk,
                ..
            } => Ok(ValidatedDecryptProviderRequestV1(
                ValidatedDecryptProviderRequestKindV1::ReadViewerObjectChunk {
                    audit_request_id: RuntimeReleaseAuditIdV1::new(
                        elastos_protected_content_contracts::Digest32::new(audit_request_id),
                    )?,
                    session_handle,
                    chunk_index,
                    framed_chunk,
                },
            )),
            // A V2 op validates only under the issuer it declares.
            DecryptProviderRequestKindV1::PrepareRecipientV2 { .. }
            | DecryptProviderRequestKindV1::OpenViewerSessionV2 { .. }
            | DecryptProviderRequestKindV1::ReadViewerMediaPartSealed { .. }
            | DecryptProviderRequestKindV1::ReadViewerObjectChunkSealed { .. } => {
                Err(ContractError::InvalidField("op"))
            }
        }
    }

    /// Plan B T3.1: the V2 ops, under the Runtime issuer each declares. A V1
    /// op is refused here; it keeps the provider's trusted issuer.
    fn into_validated_declared_at(
        self,
        now_unix_seconds: u64,
    ) -> Result<ValidatedDecryptProviderRequestV1, ContractError> {
        match self.0 {
            DecryptProviderRequestKindV1::PrepareRecipientV2 {
                protected_content_binding,
                audit_request_id,
                action,
                runtime_operation_issuer,
                expires_at,
                ..
            } => {
                if now_unix_seconds >= expires_at
                    || expires_at - now_unix_seconds > MAX_RECIPIENT_KEY_AUTHORIZATION_LIFETIME_SECS
                {
                    return Err(ContractError::InvalidField("decrypt_prepare_window"));
                }
                Ok(ValidatedDecryptProviderRequestV1(
                    ValidatedDecryptProviderRequestKindV1::PrepareRecipientV2 {
                        protected_content_binding: Box::new(protected_content_binding.decode()?),
                        audit_request_id: RuntimeReleaseAuditIdV1::new(Digest32::new(
                            audit_request_id,
                        ))?,
                        action: decode_rights_action(action)?,
                        runtime_operation_issuer: RuntimeOperationIssuerKeyV1::new(
                            runtime_operation_issuer,
                        )?,
                        expires_at,
                    },
                ))
            }
            DecryptProviderRequestKindV1::OpenViewerSessionV2 {
                prepared_recipient_handle,
                signed_runtime_release_operation,
                delivery_public_key,
                content_key_commitment,
                media_identity,
                protected_init_segment,
                object_identity,
                framed_header,
                media_identity_v2,
                protected_init_segments,
                signed_node_contributions,
                signed_terminal_receipt,
                ..
            } => {
                // The descriptor verifies with the release rule (F1), so an
                // item keeps opening after the members' term.
                let operation = signed_runtime_release_operation
                    .decode::<SignedRuntimeReleaseOperationV2>()?
                    .verify(RuntimeIssuerPolicyV1::Declared, now_unix_seconds)
                    .map_err(|_| ContractError::InvalidField("signed_runtime_release_operation"))?;
                let delivery_public_key = delivery_public_key_from_bytes(&delivery_public_key)?;
                // F4: the identity is the release binding's content, and the
                // inits or header validate against it, as the V1 open does.
                let content = validate_open_content(
                    operation.binding().encrypted_content(),
                    (
                        media_identity,
                        protected_init_segment,
                        object_identity,
                        framed_header,
                        media_identity_v2,
                        protected_init_segments,
                    ),
                )?;
                let signed_node_contributions: Vec<SignedNodeContributionV1> =
                    signed_node_contributions
                        .iter()
                        .map(SignedNodeContributionV1::from_canonical_bytes)
                        .collect::<Result<_, _>>()?;
                let signed_terminal_receipt: SignedTerminalReceiptV1 =
                    signed_terminal_receipt.decode()?;
                if signed_terminal_receipt.statement().outcome() != KeyReleaseOutcomeV1::Released {
                    return Err(ContractError::InvalidField("signed_terminal_receipt"));
                }
                // Every contribution is sealed to one wallet-signed recipient,
                // and the receipt over them is signed by the declared issuer
                // (L1: every release slot holds the operation hash).
                let node_set = operation
                    .epoch_bundle()
                    .signed_epoch()
                    .statement()
                    .node_set()
                    .map_err(|_| ContractError::InvalidField("signed_runtime_release_operation"))?;
                let recipient = signed_node_contributions
                    .first()
                    .map(|contribution| {
                        contribution
                            .statement()
                            .recipient_sealed_contribution()
                            .recipient()
                            .clone()
                    })
                    .ok_or(ContractError::InvalidField("signed_node_contributions"))?;
                let mut verified_contributions =
                    Vec::with_capacity(signed_node_contributions.len());
                for contribution in &signed_node_contributions {
                    let verified = operation
                        .verify_node_contribution(
                            contribution,
                            &node_set,
                            &recipient,
                            now_unix_seconds,
                        )
                        .map_err(|_| ContractError::InvalidField("signed_node_contributions"))?;
                    verified_contributions.push(verified);
                }
                let declared_terminal_issuer = TerminalReceiptIssuerKey::new(
                    *operation.runtime_operation_issuer().as_bytes(),
                )?;
                operation
                    .verify_terminal_receipt(
                        &signed_terminal_receipt,
                        &verified_contributions,
                        declared_terminal_issuer,
                        now_unix_seconds,
                    )
                    .map_err(|_| ContractError::InvalidField("signed_terminal_receipt"))?;
                Ok(ValidatedDecryptProviderRequestV1(
                    ValidatedDecryptProviderRequestKindV1::OpenViewerSessionV2 {
                        prepared_recipient_handle,
                        authenticated_runtime_release_operation: Box::new(operation),
                        delivery_public_key: Box::new(delivery_public_key),
                        contribution_recipient: recipient,
                        expected_terminal_issuer: declared_terminal_issuer,
                        content_key_commitment: Digest32::new(content_key_commitment),
                        content,
                        signed_node_contributions,
                        signed_terminal_receipt: Box::new(signed_terminal_receipt),
                    },
                ))
            }
            DecryptProviderRequestKindV1::ReadViewerMediaPartSealed {
                audit_request_id,
                viewer_session_handle,
                part_selector,
                session_id,
                ..
            } => Ok(ValidatedDecryptProviderRequestV1(
                ValidatedDecryptProviderRequestKindV1::ReadViewerMediaPartSealed {
                    audit_request_id: RuntimeReleaseAuditIdV1::new(Digest32::new(
                        audit_request_id,
                    ))?,
                    viewer_session_handle,
                    part_selector,
                    session_id,
                },
            )),
            DecryptProviderRequestKindV1::ReadViewerObjectChunkSealed {
                audit_request_id,
                viewer_session_handle,
                chunk_index,
                framed_chunk,
                session_id,
                ..
            } => Ok(ValidatedDecryptProviderRequestV1(
                ValidatedDecryptProviderRequestKindV1::ReadViewerObjectChunkSealed {
                    audit_request_id: RuntimeReleaseAuditIdV1::new(Digest32::new(
                        audit_request_id,
                    ))?,
                    viewer_session_handle,
                    chunk_index,
                    framed_chunk,
                    session_id,
                },
            )),
            _ => Err(ContractError::InvalidField("op")),
        }
    }
}

impl Serialize for DecryptProviderRequestV1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

/// A v2 open after the head, the release binding and every rendition init
/// were checked together.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ValidatedMediaDashOpenV2 {
    head: CencDashMediaIdentityV2,
    sessions: Vec<ValidatedCencDashRenditionSessionV2>,
    inits: Vec<Vec<u8>>,
}

/// The content of an open after it was checked against the release: exactly
/// one of the V1 media layout with its init, the DASH v2 open, or the object
/// identity with its header.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ValidatedOpenContentV1 {
    media_session_layout: Option<Box<ValidatedCencFmp4MediaSessionLayoutV1>>,
    protected_init_segment: Option<MediaPartBlobV1>,
    object_identity: Option<Box<ChunkedPayloadObjectIdentityV1>>,
    framed_header: Option<ObjectFramedHeaderBlobV1>,
    media_dash: Option<Box<ValidatedMediaDashOpenV2>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ValidatedDecryptProviderRequestKindV1 {
    PrepareRecipient {
        protected_content_binding: Box<ProtectedContentBindingV1>,
        audit_request_id: RuntimeReleaseAuditIdV1,
        action: RightsActionV1,
        runtime_operation_issuer: RuntimeOperationIssuerKeyV1,
        issued_at: u64,
        expires_at: u64,
    },
    OpenViewerSession {
        prepared_recipient_handle: OpaqueHandleV1,
        authenticated_runtime_release_operation: Box<AuthenticatedRuntimeReleaseOperationV1>,
        expected_terminal_issuer: TerminalReceiptIssuerKey,
        content_key_commitment: Digest32,
        content: ValidatedOpenContentV1,
        signed_node_contributions: Vec<SignedNodeContributionV1>,
        signed_terminal_receipt: Box<SignedTerminalReceiptV1>,
    },
    ReadViewerMediaPart {
        audit_request_id: RuntimeReleaseAuditIdV1,
        viewer_session_handle: OpaqueHandleV1,
        part_selector: ViewerMediaPartSelectorV1,
    },
    CancelPreparedRecipient {
        audit_request_id: RuntimeReleaseAuditIdV1,
        prepared_recipient_handle: OpaqueHandleV1,
    },
    CloseViewerSession {
        audit_request_id: RuntimeReleaseAuditIdV1,
        viewer_session_handle: OpaqueHandleV1,
    },
    ReadViewerObjectChunk {
        audit_request_id: RuntimeReleaseAuditIdV1,
        session_handle: OpaqueHandleV1,
        chunk_index: u32,
        framed_chunk: ObjectFramedChunkBlobV1,
    },
    PrepareRecipientV2 {
        protected_content_binding: Box<ProtectedContentBindingV1>,
        audit_request_id: RuntimeReleaseAuditIdV1,
        action: RightsActionV1,
        runtime_operation_issuer: RuntimeOperationIssuerKeyV1,
        expires_at: u64,
    },
    OpenViewerSessionV2 {
        prepared_recipient_handle: OpaqueHandleV1,
        authenticated_runtime_release_operation: Box<AuthenticatedRuntimeReleaseOperationV2>,
        delivery_public_key: Box<DeliveryPublicKeyBytesV1>,
        /// The one recipient every contribution is sealed to.
        contribution_recipient: RecipientKeyIdentityV1,
        /// The declared Runtime issuer, which signed the receipt.
        expected_terminal_issuer: TerminalReceiptIssuerKey,
        content_key_commitment: Digest32,
        content: ValidatedOpenContentV1,
        signed_node_contributions: Vec<SignedNodeContributionV1>,
        signed_terminal_receipt: Box<SignedTerminalReceiptV1>,
    },
    ReadViewerMediaPartSealed {
        audit_request_id: RuntimeReleaseAuditIdV1,
        viewer_session_handle: OpaqueHandleV1,
        part_selector: ViewerMediaPartSelectorV1,
        session_id: [u8; VIEWER_SESSION_ID_BYTES_V1],
    },
    ReadViewerObjectChunkSealed {
        audit_request_id: RuntimeReleaseAuditIdV1,
        viewer_session_handle: OpaqueHandleV1,
        chunk_index: u32,
        framed_chunk: ObjectFramedChunkBlobV1,
        session_id: [u8; VIEWER_SESSION_ID_BYTES_V1],
    },
}

/// Provider-authoritative decrypt request. Construct only through
/// [`ValidatedDecryptProviderRequestV1::decode_and_validate_at`].
///
/// ```compile_fail
/// use elastos_protected_content_provider_contracts::ValidatedDecryptProviderRequestV1;
///
/// let _ = serde_json::from_slice::<ValidatedDecryptProviderRequestV1>(br#"{}"#);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedDecryptProviderRequestV1(ValidatedDecryptProviderRequestKindV1);

impl ValidatedDecryptProviderRequestV1 {
    pub fn decode_and_validate_at(
        bytes: &[u8],
        expected_runtime_issuer: RuntimeOperationIssuerKeyV1,
        now_unix_seconds: u64,
    ) -> Result<Self, serde_json::Error> {
        DecryptProviderRequestV1::decode_wire(bytes)?
            .into_validated_at(expected_runtime_issuer, now_unix_seconds)
            .map_err(contract_decode_error)
    }

    /// Plan B T3.1: the second entry, for the V2 ops only. Each validates
    /// under the Runtime issuer it declares; a V1 op is refused.
    pub fn decode_and_validate_declared_at(
        bytes: &[u8],
        now_unix_seconds: u64,
    ) -> Result<Self, serde_json::Error> {
        DecryptProviderRequestV1::decode_wire(bytes)?
            .into_validated_declared_at(now_unix_seconds)
            .map_err(contract_decode_error)
    }

    pub const fn op(&self) -> DecryptProviderRequestOpV1 {
        match self.0 {
            ValidatedDecryptProviderRequestKindV1::PrepareRecipient { .. } => {
                DecryptProviderRequestOpV1::PrepareRecipient
            }
            ValidatedDecryptProviderRequestKindV1::OpenViewerSession { .. } => {
                DecryptProviderRequestOpV1::OpenViewerSession
            }
            ValidatedDecryptProviderRequestKindV1::ReadViewerMediaPart { .. } => {
                DecryptProviderRequestOpV1::ReadViewerMediaPart
            }
            ValidatedDecryptProviderRequestKindV1::CancelPreparedRecipient { .. } => {
                DecryptProviderRequestOpV1::CancelPreparedRecipient
            }
            ValidatedDecryptProviderRequestKindV1::CloseViewerSession { .. } => {
                DecryptProviderRequestOpV1::CloseViewerSession
            }
            ValidatedDecryptProviderRequestKindV1::ReadViewerObjectChunk { .. } => {
                DecryptProviderRequestOpV1::ReadViewerObjectChunk
            }
            ValidatedDecryptProviderRequestKindV1::PrepareRecipientV2 { .. } => {
                DecryptProviderRequestOpV1::PrepareRecipientV2
            }
            ValidatedDecryptProviderRequestKindV1::OpenViewerSessionV2 { .. } => {
                DecryptProviderRequestOpV1::OpenViewerSessionV2
            }
            ValidatedDecryptProviderRequestKindV1::ReadViewerMediaPartSealed { .. } => {
                DecryptProviderRequestOpV1::ReadViewerMediaPartSealed
            }
            ValidatedDecryptProviderRequestKindV1::ReadViewerObjectChunkSealed { .. } => {
                DecryptProviderRequestOpV1::ReadViewerObjectChunkSealed
            }
        }
    }

    pub fn audit_request_id(&self) -> RuntimeReleaseAuditIdV1 {
        match &self.0 {
            ValidatedDecryptProviderRequestKindV1::PrepareRecipient {
                audit_request_id, ..
            }
            | ValidatedDecryptProviderRequestKindV1::CancelPreparedRecipient {
                audit_request_id,
                ..
            }
            | ValidatedDecryptProviderRequestKindV1::CloseViewerSession {
                audit_request_id, ..
            }
            | ValidatedDecryptProviderRequestKindV1::ReadViewerMediaPart {
                audit_request_id, ..
            }
            | ValidatedDecryptProviderRequestKindV1::ReadViewerObjectChunk {
                audit_request_id,
                ..
            }
            | ValidatedDecryptProviderRequestKindV1::PrepareRecipientV2 {
                audit_request_id, ..
            }
            | ValidatedDecryptProviderRequestKindV1::ReadViewerMediaPartSealed {
                audit_request_id,
                ..
            }
            | ValidatedDecryptProviderRequestKindV1::ReadViewerObjectChunkSealed {
                audit_request_id,
                ..
            } => *audit_request_id,
            ValidatedDecryptProviderRequestKindV1::OpenViewerSession {
                authenticated_runtime_release_operation,
                ..
            } => authenticated_runtime_release_operation
                .statement()
                .audit_request_id(),
            ValidatedDecryptProviderRequestKindV1::OpenViewerSessionV2 {
                authenticated_runtime_release_operation,
                ..
            } => authenticated_runtime_release_operation
                .statement()
                .audit_request_id(),
        }
    }

    pub fn protected_content_binding(&self) -> Result<&ProtectedContentBindingV1, ContractError> {
        match &self.0 {
            ValidatedDecryptProviderRequestKindV1::PrepareRecipient {
                protected_content_binding,
                ..
            }
            | ValidatedDecryptProviderRequestKindV1::PrepareRecipientV2 {
                protected_content_binding,
                ..
            } => Ok(protected_content_binding),
            _ => Err(ContractError::InvalidField("protected_content_binding")),
        }
    }

    pub fn action(&self) -> Result<RightsActionV1, ContractError> {
        match &self.0 {
            ValidatedDecryptProviderRequestKindV1::PrepareRecipient { action, .. }
            | ValidatedDecryptProviderRequestKindV1::PrepareRecipientV2 { action, .. } => {
                Ok(*action)
            }
            _ => Err(ContractError::InvalidField("rights_action")),
        }
    }

    pub fn runtime_operation_issuer(&self) -> Result<RuntimeOperationIssuerKeyV1, ContractError> {
        match &self.0 {
            ValidatedDecryptProviderRequestKindV1::PrepareRecipient {
                runtime_operation_issuer,
                ..
            }
            | ValidatedDecryptProviderRequestKindV1::PrepareRecipientV2 {
                runtime_operation_issuer,
                ..
            } => Ok(*runtime_operation_issuer),
            _ => Err(ContractError::InvalidField("runtime_operation_issuer")),
        }
    }

    pub fn issued_at(&self) -> Result<u64, ContractError> {
        match &self.0 {
            ValidatedDecryptProviderRequestKindV1::PrepareRecipient { issued_at, .. } => {
                Ok(*issued_at)
            }
            _ => Err(ContractError::InvalidField("issued_at")),
        }
    }

    pub fn expires_at(&self) -> Result<u64, ContractError> {
        match &self.0 {
            ValidatedDecryptProviderRequestKindV1::PrepareRecipient { expires_at, .. }
            | ValidatedDecryptProviderRequestKindV1::PrepareRecipientV2 { expires_at, .. } => {
                Ok(*expires_at)
            }
            _ => Err(ContractError::InvalidField("expires_at")),
        }
    }

    pub fn prepared_recipient_handle(
        &self,
    ) -> Result<&[u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1], ContractError> {
        match &self.0 {
            ValidatedDecryptProviderRequestKindV1::OpenViewerSession {
                prepared_recipient_handle,
                ..
            }
            | ValidatedDecryptProviderRequestKindV1::OpenViewerSessionV2 {
                prepared_recipient_handle,
                ..
            }
            | ValidatedDecryptProviderRequestKindV1::CancelPreparedRecipient {
                prepared_recipient_handle,
                ..
            } => Ok(prepared_recipient_handle.as_bytes()),
            _ => Err(ContractError::InvalidField("prepared_recipient_handle")),
        }
    }

    pub fn authenticated_runtime_release_operation(
        &self,
    ) -> Result<&AuthenticatedRuntimeReleaseOperationV1, ContractError> {
        match &self.0 {
            ValidatedDecryptProviderRequestKindV1::OpenViewerSession {
                authenticated_runtime_release_operation,
                ..
            } => Ok(authenticated_runtime_release_operation.as_ref()),
            _ => Err(ContractError::InvalidField(
                "authenticated_runtime_release_operation",
            )),
        }
    }

    /// Plan B T3.1: the authenticated V2 operation of a V2 open.
    pub fn authenticated_runtime_release_operation_v2(
        &self,
    ) -> Result<&AuthenticatedRuntimeReleaseOperationV2, ContractError> {
        match &self.0 {
            ValidatedDecryptProviderRequestKindV1::OpenViewerSessionV2 {
                authenticated_runtime_release_operation,
                ..
            } => Ok(authenticated_runtime_release_operation.as_ref()),
            _ => Err(ContractError::InvalidField(
                "authenticated_runtime_release_operation",
            )),
        }
    }

    /// Plan B T3.1: the delivery public key a V2 open names. Its identity is
    /// not yet compared with the wallet-signed one; the provider does that
    /// before any key work.
    pub fn delivery_public_key(&self) -> Result<&DeliveryPublicKeyBytesV1, ContractError> {
        match &self.0 {
            ValidatedDecryptProviderRequestKindV1::OpenViewerSessionV2 {
                delivery_public_key,
                ..
            } => Ok(delivery_public_key.as_ref()),
            _ => Err(ContractError::InvalidField("delivery_public_key")),
        }
    }

    /// Plan B T3.1: the one recipient every contribution of a V2 open is
    /// sealed to.
    pub fn contribution_recipient(&self) -> Result<&RecipientKeyIdentityV1, ContractError> {
        match &self.0 {
            ValidatedDecryptProviderRequestKindV1::OpenViewerSessionV2 {
                contribution_recipient,
                ..
            } => Ok(contribution_recipient),
            _ => Err(ContractError::InvalidField("signed_node_contributions")),
        }
    }

    /// Plan B T3.1: the pool session id a sealed read names in its AAD.
    pub fn session_id(&self) -> Result<[u8; VIEWER_SESSION_ID_BYTES_V1], ContractError> {
        match &self.0 {
            ValidatedDecryptProviderRequestKindV1::ReadViewerMediaPartSealed {
                session_id, ..
            }
            | ValidatedDecryptProviderRequestKindV1::ReadViewerObjectChunkSealed {
                session_id,
                ..
            } => Ok(*session_id),
            _ => Err(ContractError::InvalidField("session_id")),
        }
    }

    fn open_content(&self) -> Option<&ValidatedOpenContentV1> {
        match &self.0 {
            ValidatedDecryptProviderRequestKindV1::OpenViewerSession { content, .. }
            | ValidatedDecryptProviderRequestKindV1::OpenViewerSessionV2 { content, .. } => {
                Some(content)
            }
            _ => None,
        }
    }

    /// V1: the issuer the caller named; V2: the declared Runtime issuer.
    pub fn expected_terminal_issuer(&self) -> Result<TerminalReceiptIssuerKey, ContractError> {
        match &self.0 {
            ValidatedDecryptProviderRequestKindV1::OpenViewerSession {
                expected_terminal_issuer,
                ..
            }
            | ValidatedDecryptProviderRequestKindV1::OpenViewerSessionV2 {
                expected_terminal_issuer,
                ..
            } => Ok(*expected_terminal_issuer),
            _ => Err(ContractError::InvalidField("expected_terminal_issuer")),
        }
    }

    pub fn content_key_commitment(&self) -> Result<Digest32, ContractError> {
        match &self.0 {
            ValidatedDecryptProviderRequestKindV1::OpenViewerSession {
                content_key_commitment,
                ..
            }
            | ValidatedDecryptProviderRequestKindV1::OpenViewerSessionV2 {
                content_key_commitment,
                ..
            } => Ok(*content_key_commitment),
            _ => Err(ContractError::InvalidField("content_key_commitment")),
        }
    }

    pub fn media_session_layout(
        &self,
    ) -> Result<&ValidatedCencFmp4MediaSessionLayoutV1, ContractError> {
        self.open_content()
            .and_then(|content| content.media_session_layout.as_deref())
            .ok_or(ContractError::InvalidField("media_session_layout"))
    }

    fn media_dash(&self) -> Result<&ValidatedMediaDashOpenV2, ContractError> {
        self.open_content()
            .and_then(|content| content.media_dash.as_deref())
            .ok_or(ContractError::InvalidField("media_identity_v2"))
    }

    pub fn media_identity_v2(&self) -> Result<&CencDashMediaIdentityV2, ContractError> {
        self.media_dash().map(|open| &open.head)
    }

    pub fn media_dash_sessions(
        &self,
    ) -> Result<&[ValidatedCencDashRenditionSessionV2], ContractError> {
        self.media_dash().map(|open| open.sessions.as_slice())
    }

    pub fn protected_init_segments(&self) -> Result<Vec<&[u8]>, ContractError> {
        self.media_dash()
            .map(|open| open.inits.iter().map(Vec::as_slice).collect())
    }

    pub fn protected_init_segment(&self) -> Result<&[u8], ContractError> {
        self.open_content()
            .and_then(|content| content.protected_init_segment.as_ref())
            .map(|init| init.as_slice())
            .ok_or(ContractError::InvalidField("protected_init_segment"))
    }

    pub fn object_identity(&self) -> Result<&ChunkedPayloadObjectIdentityV1, ContractError> {
        self.open_content()
            .and_then(|content| content.object_identity.as_deref())
            .ok_or(ContractError::InvalidField("object_identity"))
    }

    pub fn framed_header(&self) -> Result<&[u8], ContractError> {
        self.open_content()
            .and_then(|content| content.framed_header.as_ref())
            .map(|header| header.as_slice())
            .ok_or(ContractError::InvalidField("framed_header"))
    }

    pub fn session_handle(
        &self,
    ) -> Result<&[u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1], ContractError> {
        match &self.0 {
            ValidatedDecryptProviderRequestKindV1::ReadViewerObjectChunk {
                session_handle, ..
            } => Ok(session_handle.as_bytes()),
            _ => Err(ContractError::InvalidField("session_handle")),
        }
    }

    pub fn chunk_index(&self) -> Result<u32, ContractError> {
        match &self.0 {
            ValidatedDecryptProviderRequestKindV1::ReadViewerObjectChunk {
                chunk_index, ..
            }
            | ValidatedDecryptProviderRequestKindV1::ReadViewerObjectChunkSealed {
                chunk_index,
                ..
            } => Ok(*chunk_index),
            _ => Err(ContractError::InvalidField("chunk_index")),
        }
    }

    pub fn framed_chunk(&self) -> Result<&[u8], ContractError> {
        match &self.0 {
            ValidatedDecryptProviderRequestKindV1::ReadViewerObjectChunk {
                framed_chunk, ..
            }
            | ValidatedDecryptProviderRequestKindV1::ReadViewerObjectChunkSealed {
                framed_chunk,
                ..
            } => Ok(framed_chunk.as_slice()),
            _ => Err(ContractError::InvalidField("framed_chunk")),
        }
    }

    pub fn signed_node_contributions(&self) -> Result<&[SignedNodeContributionV1], ContractError> {
        match &self.0 {
            ValidatedDecryptProviderRequestKindV1::OpenViewerSession {
                signed_node_contributions,
                ..
            }
            | ValidatedDecryptProviderRequestKindV1::OpenViewerSessionV2 {
                signed_node_contributions,
                ..
            } => Ok(signed_node_contributions),
            _ => Err(ContractError::InvalidField("signed_node_contributions")),
        }
    }

    pub fn signed_terminal_receipt(&self) -> Result<&SignedTerminalReceiptV1, ContractError> {
        match &self.0 {
            ValidatedDecryptProviderRequestKindV1::OpenViewerSession {
                signed_terminal_receipt,
                ..
            }
            | ValidatedDecryptProviderRequestKindV1::OpenViewerSessionV2 {
                signed_terminal_receipt,
                ..
            } => Ok(signed_terminal_receipt.as_ref()),
            _ => Err(ContractError::InvalidField("signed_terminal_receipt")),
        }
    }

    pub fn viewer_session_handle(
        &self,
    ) -> Result<&[u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1], ContractError> {
        match &self.0 {
            ValidatedDecryptProviderRequestKindV1::ReadViewerMediaPart {
                viewer_session_handle,
                ..
            }
            | ValidatedDecryptProviderRequestKindV1::CloseViewerSession {
                viewer_session_handle,
                ..
            }
            | ValidatedDecryptProviderRequestKindV1::ReadViewerMediaPartSealed {
                viewer_session_handle,
                ..
            }
            | ValidatedDecryptProviderRequestKindV1::ReadViewerObjectChunkSealed {
                viewer_session_handle,
                ..
            } => Ok(viewer_session_handle.as_bytes()),
            _ => Err(ContractError::InvalidField("viewer_session_handle")),
        }
    }

    pub fn viewer_media_part_selector(&self) -> Result<&ViewerMediaPartSelectorV1, ContractError> {
        match &self.0 {
            ValidatedDecryptProviderRequestKindV1::ReadViewerMediaPart {
                part_selector, ..
            }
            | ValidatedDecryptProviderRequestKindV1::ReadViewerMediaPartSealed {
                part_selector,
                ..
            } => Ok(part_selector),
            _ => Err(ContractError::InvalidField("part_selector")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecryptProviderResponseStatusV1 {
    PreparedRecipient,
    ViewerSessionOpened,
    ViewerMediaPart,
    CancelledPreparedRecipient,
    PreparedRecipientAlreadyAbsent,
    ClosedViewerSession,
    ViewerSessionAlreadyAbsent,
    ViewerObjectChunk,
    /// Plan B T3.1: one part of a V2 session, sealed to its delivery key.
    ViewerSealedPart,
    Failure,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptProviderResponseV1(DecryptProviderResponseKindV1);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
enum DecryptProviderResponseKindV1 {
    PreparedRecipient {
        schema: String,
        audit_request_id: [u8; 32],
        prepared_recipient_handle: OpaqueHandleV1,
        recipient_public_key: Vec<u8>,
        recipient_identity: RecipientIdentityBlobV1,
    },
    ViewerSessionOpened {
        schema: String,
        audit_request_id: [u8; 32],
        viewer_session_handle: OpaqueHandleV1,
    },
    ViewerMediaPart {
        schema: String,
        audit_request_id: [u8; 32],
        viewer_session_handle: OpaqueHandleV1,
        part_selector: ViewerMediaPartSelectorV1,
        clear_media_part: MediaPartBlobV1,
    },
    CancelledPreparedRecipient {
        schema: String,
        audit_request_id: [u8; 32],
        prepared_recipient_handle: OpaqueHandleV1,
    },
    PreparedRecipientAlreadyAbsent {
        schema: String,
        audit_request_id: [u8; 32],
        prepared_recipient_handle: OpaqueHandleV1,
    },
    ClosedViewerSession {
        schema: String,
        audit_request_id: [u8; 32],
        viewer_session_handle: OpaqueHandleV1,
    },
    ViewerSessionAlreadyAbsent {
        schema: String,
        audit_request_id: [u8; 32],
        viewer_session_handle: OpaqueHandleV1,
    },
    ViewerObjectChunk {
        schema: String,
        audit_request_id: [u8; 32],
        plaintext: ObjectPlaintextChunkBlobV1,
    },
    ViewerSealedPart {
        schema: String,
        audit_request_id: [u8; 32],
        viewer_session_handle: OpaqueHandleV1,
        sealed_part: SealedViewerPartBlobV1,
    },
    Failure {
        schema: String,
        audit_request_id: [u8; 32],
        code: ProviderFailureCodeV1,
    },
}

impl DecryptProviderResponseV1 {
    pub const fn status(&self) -> DecryptProviderResponseStatusV1 {
        match self.0 {
            DecryptProviderResponseKindV1::PreparedRecipient { .. } => {
                DecryptProviderResponseStatusV1::PreparedRecipient
            }
            DecryptProviderResponseKindV1::ViewerSessionOpened { .. } => {
                DecryptProviderResponseStatusV1::ViewerSessionOpened
            }
            DecryptProviderResponseKindV1::ViewerMediaPart { .. } => {
                DecryptProviderResponseStatusV1::ViewerMediaPart
            }
            DecryptProviderResponseKindV1::CancelledPreparedRecipient { .. } => {
                DecryptProviderResponseStatusV1::CancelledPreparedRecipient
            }
            DecryptProviderResponseKindV1::ViewerObjectChunk { .. } => {
                DecryptProviderResponseStatusV1::ViewerObjectChunk
            }
            DecryptProviderResponseKindV1::PreparedRecipientAlreadyAbsent { .. } => {
                DecryptProviderResponseStatusV1::PreparedRecipientAlreadyAbsent
            }
            DecryptProviderResponseKindV1::ClosedViewerSession { .. } => {
                DecryptProviderResponseStatusV1::ClosedViewerSession
            }
            DecryptProviderResponseKindV1::ViewerSessionAlreadyAbsent { .. } => {
                DecryptProviderResponseStatusV1::ViewerSessionAlreadyAbsent
            }
            DecryptProviderResponseKindV1::ViewerSealedPart { .. } => {
                DecryptProviderResponseStatusV1::ViewerSealedPart
            }
            DecryptProviderResponseKindV1::Failure { .. } => {
                DecryptProviderResponseStatusV1::Failure
            }
        }
    }

    pub fn new_prepared_recipient(
        audit_request_id: RuntimeReleaseAuditIdV1,
        prepared_recipient_handle: [u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1],
        recipient_public_key: RecipientPublicKeyBytesV1,
        recipient_identity: &RecipientKeyIdentityV1,
    ) -> Result<Self, ContractError> {
        let value = Self(DecryptProviderResponseKindV1::PreparedRecipient {
            schema: DECRYPT_PROVIDER_RESPONSE_SCHEMA_V1.to_string(),
            audit_request_id: *audit_request_id.digest().as_bytes(),
            prepared_recipient_handle: OpaqueHandleV1::new(prepared_recipient_handle)?,
            recipient_public_key: recipient_public_key.as_bytes().to_vec(),
            recipient_identity: CanonicalBlob::from_contract(recipient_identity)?,
        });
        value.validate()?;
        Ok(value)
    }

    pub fn new_viewer_session_opened(
        audit_request_id: RuntimeReleaseAuditIdV1,
        viewer_session_handle: [u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1],
    ) -> Result<Self, ContractError> {
        let value = Self(DecryptProviderResponseKindV1::ViewerSessionOpened {
            schema: DECRYPT_PROVIDER_RESPONSE_SCHEMA_V1.to_string(),
            audit_request_id: *audit_request_id.digest().as_bytes(),
            viewer_session_handle: OpaqueHandleV1::new(viewer_session_handle)?,
        });
        value.validate()?;
        Ok(value)
    }

    pub fn new_viewer_media_part(
        audit_request_id: RuntimeReleaseAuditIdV1,
        viewer_session_handle: [u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1],
        part_selector: ViewerMediaPartSelectorV1,
        clear_media_part: Vec<u8>,
    ) -> Result<Self, ContractError> {
        let value = Self(DecryptProviderResponseKindV1::ViewerMediaPart {
            schema: DECRYPT_PROVIDER_RESPONSE_SCHEMA_V1.to_string(),
            audit_request_id: *audit_request_id.digest().as_bytes(),
            viewer_session_handle: OpaqueHandleV1::new(viewer_session_handle)?,
            part_selector,
            clear_media_part: MediaPartBlobV1::new(clear_media_part)?,
        });
        value.validate()?;
        Ok(value)
    }

    pub fn new_cancelled_prepared_recipient(
        audit_request_id: RuntimeReleaseAuditIdV1,
        prepared_recipient_handle: [u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1],
    ) -> Result<Self, ContractError> {
        let value = Self(DecryptProviderResponseKindV1::CancelledPreparedRecipient {
            schema: DECRYPT_PROVIDER_RESPONSE_SCHEMA_V1.to_string(),
            audit_request_id: *audit_request_id.digest().as_bytes(),
            prepared_recipient_handle: OpaqueHandleV1::new(prepared_recipient_handle)?,
        });
        value.validate()?;
        Ok(value)
    }

    pub fn new_prepared_recipient_already_absent(
        audit_request_id: RuntimeReleaseAuditIdV1,
        prepared_recipient_handle: [u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1],
    ) -> Result<Self, ContractError> {
        let value = Self(
            DecryptProviderResponseKindV1::PreparedRecipientAlreadyAbsent {
                schema: DECRYPT_PROVIDER_RESPONSE_SCHEMA_V1.to_string(),
                audit_request_id: *audit_request_id.digest().as_bytes(),
                prepared_recipient_handle: OpaqueHandleV1::new(prepared_recipient_handle)?,
            },
        );
        value.validate()?;
        Ok(value)
    }

    pub fn new_closed_viewer_session(
        audit_request_id: RuntimeReleaseAuditIdV1,
        viewer_session_handle: [u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1],
    ) -> Result<Self, ContractError> {
        let value = Self(DecryptProviderResponseKindV1::ClosedViewerSession {
            schema: DECRYPT_PROVIDER_RESPONSE_SCHEMA_V1.to_string(),
            audit_request_id: *audit_request_id.digest().as_bytes(),
            viewer_session_handle: OpaqueHandleV1::new(viewer_session_handle)?,
        });
        value.validate()?;
        Ok(value)
    }

    pub fn new_viewer_session_already_absent(
        audit_request_id: RuntimeReleaseAuditIdV1,
        viewer_session_handle: [u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1],
    ) -> Result<Self, ContractError> {
        let value = Self(DecryptProviderResponseKindV1::ViewerSessionAlreadyAbsent {
            schema: DECRYPT_PROVIDER_RESPONSE_SCHEMA_V1.to_string(),
            audit_request_id: *audit_request_id.digest().as_bytes(),
            viewer_session_handle: OpaqueHandleV1::new(viewer_session_handle)?,
        });
        value.validate()?;
        Ok(value)
    }

    pub fn new_viewer_object_chunk(
        audit_request_id: RuntimeReleaseAuditIdV1,
        plaintext: Vec<u8>,
    ) -> Result<Self, ContractError> {
        let value = Self(DecryptProviderResponseKindV1::ViewerObjectChunk {
            schema: DECRYPT_PROVIDER_RESPONSE_SCHEMA_V1.to_string(),
            audit_request_id: *audit_request_id.digest().as_bytes(),
            plaintext: ObjectPlaintextChunkBlobV1::new(plaintext)?,
        });
        value.validate()?;
        Ok(value)
    }

    /// Plan B T3.1: one sealed part of a V2 session.
    pub fn new_viewer_sealed_part(
        audit_request_id: RuntimeReleaseAuditIdV1,
        viewer_session_handle: [u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1],
        sealed_part: Vec<u8>,
    ) -> Result<Self, ContractError> {
        let value = Self(DecryptProviderResponseKindV1::ViewerSealedPart {
            schema: DECRYPT_PROVIDER_RESPONSE_SCHEMA_V1.to_string(),
            audit_request_id: *audit_request_id.digest().as_bytes(),
            viewer_session_handle: OpaqueHandleV1::new(viewer_session_handle)?,
            sealed_part: SealedViewerPartBlobV1::new(sealed_part)?,
        });
        value.validate()?;
        Ok(value)
    }

    pub fn sealed_part(&self) -> Result<&[u8], ContractError> {
        match &self.0 {
            DecryptProviderResponseKindV1::ViewerSealedPart { sealed_part, .. } => {
                Ok(sealed_part.as_slice())
            }
            _ => Err(ContractError::InvalidField("sealed_part")),
        }
    }

    pub fn plaintext(&self) -> Result<&[u8], ContractError> {
        match &self.0 {
            DecryptProviderResponseKindV1::ViewerObjectChunk { plaintext, .. } => {
                Ok(plaintext.as_slice())
            }
            _ => Err(ContractError::InvalidField("plaintext")),
        }
    }

    pub fn new_failure(
        audit_request_id: RuntimeReleaseAuditIdV1,
        code: ProviderFailureCodeV1,
    ) -> Result<Self, ContractError> {
        let value = Self(DecryptProviderResponseKindV1::Failure {
            schema: DECRYPT_PROVIDER_RESPONSE_SCHEMA_V1.to_string(),
            audit_request_id: *audit_request_id.digest().as_bytes(),
            code,
        });
        value.validate()?;
        Ok(value)
    }

    pub fn audit_request_id(&self) -> Result<RuntimeReleaseAuditIdV1, ContractError> {
        match &self.0 {
            DecryptProviderResponseKindV1::PreparedRecipient {
                audit_request_id, ..
            }
            | DecryptProviderResponseKindV1::ViewerSessionOpened {
                audit_request_id, ..
            }
            | DecryptProviderResponseKindV1::ViewerMediaPart {
                audit_request_id, ..
            }
            | DecryptProviderResponseKindV1::CancelledPreparedRecipient {
                audit_request_id, ..
            }
            | DecryptProviderResponseKindV1::PreparedRecipientAlreadyAbsent {
                audit_request_id,
                ..
            }
            | DecryptProviderResponseKindV1::ClosedViewerSession {
                audit_request_id, ..
            }
            | DecryptProviderResponseKindV1::ViewerSessionAlreadyAbsent {
                audit_request_id, ..
            }
            | DecryptProviderResponseKindV1::ViewerObjectChunk {
                audit_request_id, ..
            }
            | DecryptProviderResponseKindV1::ViewerSealedPart {
                audit_request_id, ..
            }
            | DecryptProviderResponseKindV1::Failure {
                audit_request_id, ..
            } => RuntimeReleaseAuditIdV1::new(elastos_protected_content_contracts::Digest32::new(
                *audit_request_id,
            )),
        }
    }

    pub fn prepared_recipient_handle(
        &self,
    ) -> Result<&[u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1], ContractError> {
        match &self.0 {
            DecryptProviderResponseKindV1::PreparedRecipient {
                prepared_recipient_handle,
                ..
            }
            | DecryptProviderResponseKindV1::CancelledPreparedRecipient {
                prepared_recipient_handle,
                ..
            }
            | DecryptProviderResponseKindV1::PreparedRecipientAlreadyAbsent {
                prepared_recipient_handle,
                ..
            } => Ok(prepared_recipient_handle.as_bytes()),
            _ => Err(ContractError::InvalidField("prepared_recipient_handle")),
        }
    }

    pub fn recipient_public_key(&self) -> Result<RecipientPublicKeyBytesV1, ContractError> {
        match &self.0 {
            DecryptProviderResponseKindV1::PreparedRecipient {
                recipient_public_key,
                ..
            } => {
                let bytes: [u8;
                    elastos_protected_content_contracts::PQ_HYBRID_WRAP_PUBLIC_KEY_BYTES] =
                    recipient_public_key
                        .as_slice()
                        .try_into()
                        .map_err(|_| ContractError::InvalidField("recipient_public_key"))?;
                RecipientPublicKeyBytesV1::new(bytes)
            }
            _ => Err(ContractError::InvalidField("recipient_public_key")),
        }
    }

    pub fn recipient_identity(&self) -> Result<RecipientKeyIdentityV1, ContractError> {
        match &self.0 {
            DecryptProviderResponseKindV1::PreparedRecipient {
                recipient_identity, ..
            } => recipient_identity.decode(),
            _ => Err(ContractError::InvalidField("recipient_identity")),
        }
    }

    pub fn viewer_session_handle(
        &self,
    ) -> Result<&[u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1], ContractError> {
        match &self.0 {
            DecryptProviderResponseKindV1::ViewerSessionOpened {
                viewer_session_handle,
                ..
            }
            | DecryptProviderResponseKindV1::ViewerMediaPart {
                viewer_session_handle,
                ..
            }
            | DecryptProviderResponseKindV1::ClosedViewerSession {
                viewer_session_handle,
                ..
            }
            | DecryptProviderResponseKindV1::ViewerSessionAlreadyAbsent {
                viewer_session_handle,
                ..
            }
            | DecryptProviderResponseKindV1::ViewerSealedPart {
                viewer_session_handle,
                ..
            } => Ok(viewer_session_handle.as_bytes()),
            _ => Err(ContractError::InvalidField("viewer_session_handle")),
        }
    }

    pub fn failure_code(&self) -> Result<ProviderFailureCodeV1, ContractError> {
        match self.0 {
            DecryptProviderResponseKindV1::Failure { code, .. } => Ok(code),
            _ => Err(ContractError::InvalidField("provider_failure_code")),
        }
    }

    pub fn viewer_media_part_selector(&self) -> Result<&ViewerMediaPartSelectorV1, ContractError> {
        match &self.0 {
            DecryptProviderResponseKindV1::ViewerMediaPart { part_selector, .. } => {
                Ok(part_selector)
            }
            _ => Err(ContractError::InvalidField("part_selector")),
        }
    }

    pub fn clear_media_part(&self) -> Result<&[u8], ContractError> {
        match &self.0 {
            DecryptProviderResponseKindV1::ViewerMediaPart {
                clear_media_part, ..
            } => Ok(clear_media_part.as_slice()),
            _ => Err(ContractError::InvalidField("clear_media_part")),
        }
    }

    pub fn to_json_vec(&self) -> Result<Vec<u8>, serde_json::Error> {
        encode_json(self)
    }

    pub fn from_json_slice(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        decode_json(bytes)
    }

    fn validate(&self) -> Result<(), ContractError> {
        match &self.0 {
            DecryptProviderResponseKindV1::PreparedRecipient { schema, .. } => {
                validate_schema(
                    schema,
                    DECRYPT_PROVIDER_RESPONSE_SCHEMA_V1,
                    "decrypt_provider_response.schema",
                )?;
                let recipient_public_key = self.recipient_public_key()?;
                let recipient_identity = self.recipient_identity()?;
                if !recipient_identity.matches_public_key(recipient_public_key.as_bytes()) {
                    return Err(ContractError::InvalidField("recipient_identity"));
                }
                self.audit_request_id()?;
                self.prepared_recipient_handle()?;
                Ok(())
            }
            DecryptProviderResponseKindV1::ViewerSessionOpened { schema, .. }
            | DecryptProviderResponseKindV1::ClosedViewerSession { schema, .. }
            | DecryptProviderResponseKindV1::ViewerSessionAlreadyAbsent { schema, .. } => {
                validate_schema(
                    schema,
                    DECRYPT_PROVIDER_RESPONSE_SCHEMA_V1,
                    "decrypt_provider_response.schema",
                )?;
                self.audit_request_id()?;
                self.viewer_session_handle()?;
                Ok(())
            }
            DecryptProviderResponseKindV1::ViewerMediaPart { schema, .. } => {
                validate_schema(
                    schema,
                    DECRYPT_PROVIDER_RESPONSE_SCHEMA_V1,
                    "decrypt_provider_response.schema",
                )?;
                self.audit_request_id()?;
                self.viewer_session_handle()?;
                let _ = self.viewer_media_part_selector()?;
                let _ = self.clear_media_part()?;
                Ok(())
            }
            DecryptProviderResponseKindV1::CancelledPreparedRecipient { schema, .. }
            | DecryptProviderResponseKindV1::PreparedRecipientAlreadyAbsent { schema, .. } => {
                validate_schema(
                    schema,
                    DECRYPT_PROVIDER_RESPONSE_SCHEMA_V1,
                    "decrypt_provider_response.schema",
                )?;
                self.audit_request_id()?;
                self.prepared_recipient_handle()?;
                Ok(())
            }
            DecryptProviderResponseKindV1::ViewerObjectChunk { schema, .. } => {
                validate_schema(
                    schema,
                    DECRYPT_PROVIDER_RESPONSE_SCHEMA_V1,
                    "decrypt_provider_response.schema",
                )?;
                self.audit_request_id()?;
                let _ = self.plaintext()?;
                Ok(())
            }
            DecryptProviderResponseKindV1::ViewerSealedPart { schema, .. } => {
                validate_schema(
                    schema,
                    DECRYPT_PROVIDER_RESPONSE_SCHEMA_V1,
                    "decrypt_provider_response.schema",
                )?;
                self.audit_request_id()?;
                self.viewer_session_handle()?;
                let _ = self.sealed_part()?;
                Ok(())
            }
            DecryptProviderResponseKindV1::Failure { schema, .. } => {
                validate_schema(
                    schema,
                    DECRYPT_PROVIDER_RESPONSE_SCHEMA_V1,
                    "decrypt_provider_response.schema",
                )?;
                self.audit_request_id()?;
                let _ = self.failure_code()?;
                Ok(())
            }
        }
    }
}

impl Serialize for DecryptProviderResponseV1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for DecryptProviderResponseV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let inner = DecryptProviderResponseKindV1::deserialize(deserializer)?;
        let value = Self(inner);
        value.validate().map_err(D::Error::custom)?;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        test_support::{
            custody_envelope_for_encrypted_content, custody_envelope_for_media,
            custody_envelope_for_seed, digest, make_signed_node_contribution,
            make_signed_runtime_release_operation,
            make_signed_runtime_release_operation_for_envelope_and_seed,
            make_signed_terminal_receipt, media_components, media_identity, recipient_identity,
            recipient_public_key, runtime_operation_issuer_for_seed,
        },
        ChunkedPayloadObjectIdentityV1, DecryptProviderRequestOpV1, DecryptProviderRequestV1,
        DecryptProviderResponseStatusV1, DecryptProviderResponseV1, ProviderFailureCodeV1,
        ValidatedDecryptProviderRequestV1, ViewerMediaPartSelectorV1,
        MAX_OBJECT_FRAMED_CHUNK_BYTES_V1, MAX_OBJECT_FRAMED_HEADER_BYTES_V1,
        MAX_OBJECT_PLAINTEXT_CHUNK_BYTES_V1, MAX_PROVIDER_FRAME_BYTES_V1,
        MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1, MAX_VIEWER_MEDIA_PART_BYTES_V1,
    };
    use elastos_protected_content_contracts::{
        CanonicalContract, EncryptedContentIdentityV1, RuntimeReleaseAuditIdV1,
        SignedRuntimeReleaseOperationV1,
    };

    fn handle(seed: u8) -> [u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1] {
        let mut bytes = [0u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1];
        bytes[0] = seed.max(1);
        bytes[31] = seed ^ 0x5a;
        bytes
    }

    fn decode_request(
        bytes: &[u8],
    ) -> Result<ValidatedDecryptProviderRequestV1, serde_json::Error> {
        ValidatedDecryptProviderRequestV1::decode_and_validate_at(
            bytes,
            runtime_operation_issuer_for_seed(0x42),
            crate::test_support::NOW + 10,
        )
    }

    fn open_fixture(
        seed: u8,
    ) -> (
        crate::CencFmp4MediaIdentityV1,
        Vec<u8>,
        Vec<Vec<u8>>,
        elastos_protected_content_contracts::CustodyEnvelopeV1,
        SignedRuntimeReleaseOperationV1,
    ) {
        let media_identity = media_identity(seed);
        let (init_segment, encrypted_segments, _, _) = media_components(seed);
        let custody_envelope = custody_envelope_for_media(seed);
        let operation =
            make_signed_runtime_release_operation_for_envelope_and_seed(0x42, &custody_envelope);
        (
            media_identity,
            init_segment,
            encrypted_segments,
            custody_envelope,
            operation,
        )
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    #[test]
    fn v1_media_wire_bytes_are_pinned() {
        let (media_identity, init_segment, encrypted_segments, custody_envelope, operation) =
            open_fixture(0x11);
        let contributions = vec![
            make_signed_node_contribution(&operation, 1),
            make_signed_node_contribution(&operation, 2),
        ];
        let terminal = make_signed_terminal_receipt(&operation, &contributions, 0x61);
        let open_request = DecryptProviderRequestV1::new_open_viewer_session(
            handle(0x21),
            &operation,
            terminal.statement().issuer(),
            custody_envelope.manifest().content_key_commitment(),
            &media_identity,
            &init_segment,
            &contributions,
            &terminal,
        )
        .unwrap();
        let audit = operation.statement().audit_request_id();
        let init_read = DecryptProviderRequestV1::new_read_viewer_media_part(
            audit,
            handle(0x41),
            ViewerMediaPartSelectorV1::init(),
        )
        .unwrap();
        let segment_read = DecryptProviderRequestV1::new_read_viewer_media_part(
            audit,
            handle(0x41),
            ViewerMediaPartSelectorV1::segment(1, vec![1, 2, 3]).unwrap(),
        )
        .unwrap();
        let part_response = DecryptProviderResponseV1::new_viewer_media_part(
            audit,
            handle(0x41),
            ViewerMediaPartSelectorV1::segment(1, vec![1, 2, 3]).unwrap(),
            vec![0x10, 0x11],
        )
        .unwrap();
        let opened_response =
            DecryptProviderResponseV1::new_viewer_session_opened(audit, handle(0x41)).unwrap();

        let audit_json = "[211,211,211,211,211,211,211,211,211,211,211,211,211,211,211,211,211,211,211,211,211,211,211,211,211,211,211,211,211,211,211,211]";
        let handle_json = "410000000000000000000000000000000000000000000000000000000000001b";
        // Recorded on the unmodified base: a v1 caller must keep these exact bytes.
        assert_eq!(
            sha256_hex(&open_request.to_json_vec().unwrap()),
            "70e656fd1c84c24112dbc3e455a1e29aaa6517850d3386fe26b5507d919d1345"
        );
        assert_eq!(
            String::from_utf8(init_read.to_json_vec().unwrap()).unwrap(),
            format!(
                r#"{{"op":"read_viewer_media_part","schema":"elastos.protected-content.decrypt-provider.request/v1","audit_request_id":{audit_json},"viewer_session_handle":"{handle_json}","part_selector":{{"part":"init"}}}}"#
            )
        );
        assert_eq!(
            String::from_utf8(segment_read.to_json_vec().unwrap()).unwrap(),
            format!(
                r#"{{"op":"read_viewer_media_part","schema":"elastos.protected-content.decrypt-provider.request/v1","audit_request_id":{audit_json},"viewer_session_handle":"{handle_json}","part_selector":{{"part":"segment","segment_index":1,"encrypted_segment":[1,2,3]}}}}"#
            )
        );
        assert_eq!(
            String::from_utf8(part_response.to_json_vec().unwrap()).unwrap(),
            format!(
                r#"{{"status":"viewer_media_part","schema":"elastos.protected-content.decrypt-provider.response/v1","audit_request_id":{audit_json},"viewer_session_handle":"{handle_json}","part_selector":{{"part":"segment","segment_index":1,"encrypted_segment":[1,2,3]}},"clear_media_part":[16,17]}}"#
            )
        );
        assert_eq!(
            String::from_utf8(opened_response.to_json_vec().unwrap()).unwrap(),
            format!(
                r#"{{"status":"viewer_session_opened","schema":"elastos.protected-content.decrypt-provider.response/v1","audit_request_id":{audit_json},"viewer_session_handle":"{handle_json}"}}"#
            )
        );
        let _ = encrypted_segments;
    }

    fn proof_entry(seed: u8) -> elastos_protected_content_contracts::Digest32 {
        crate::test_support::digest(seed)
    }

    #[test]
    fn selector_v2_round_trips_and_an_empty_proof_is_present() {
        let init = ViewerMediaPartSelectorV1::init_v2(1).unwrap();
        assert_eq!(
            serde_json::to_string(&init).unwrap(),
            r#"{"part":"init","rendition_index":1}"#
        );
        assert_eq!(init.rendition_index(), Some(1));
        let back: ViewerMediaPartSelectorV1 =
            serde_json::from_slice(&serde_json::to_vec(&init).unwrap()).unwrap();
        assert_eq!(back, init);

        let proof = vec![proof_entry(1), proof_entry(2)];
        let segment =
            ViewerMediaPartSelectorV1::segment_v2(1, 4, vec![9, 9], proof.clone()).unwrap();
        let back: ViewerMediaPartSelectorV1 =
            serde_json::from_slice(&serde_json::to_vec(&segment).unwrap()).unwrap();
        assert_eq!(back, segment);
        assert_eq!(back.segment_index(), Some(4));
        assert_eq!(back.rendition_index(), Some(1));
        assert_eq!(back.segment_proof(), Some(proof));

        let single = ViewerMediaPartSelectorV1::segment_v2(0, 0, vec![9], vec![]).unwrap();
        let json = serde_json::to_string(&single).unwrap();
        assert!(json.contains(r#""segment_proof":[]"#), "{json}");
        let back: ViewerMediaPartSelectorV1 = serde_json::from_str(&json).unwrap();
        assert_eq!(back.segment_proof(), Some(vec![]));
        assert_ne!(
            back,
            ViewerMediaPartSelectorV1::segment(0, vec![9]).unwrap()
        );
    }

    #[test]
    fn selector_v2_refuses_inconsistent_or_oversized_fields() {
        let segment = |extra: &str| {
            format!(r#"{{"part":"segment","segment_index":0,"encrypted_segment":[1]{extra}}}"#)
        };
        let proof33 = vec![vec![0u8; 32]; 33];
        let bad_entry = vec![vec![0u8; 31]];
        for json in [
            segment(r#","rendition_index":0"#),
            segment(r#","segment_proof":[]"#),
            segment(&format!(
                r#","rendition_index":0,"segment_proof":{}"#,
                serde_json::to_string(&proof33).unwrap()
            )),
            segment(r#","rendition_index":2,"segment_proof":[]"#),
            segment(&format!(
                r#","rendition_index":0,"segment_proof":{}"#,
                serde_json::to_string(&bad_entry).unwrap()
            )),
            r#"{"part":"init","rendition_index":2}"#.to_string(),
            r#"{"part":"init","segment_proof":[]}"#.to_string(),
        ] {
            assert!(
                serde_json::from_str::<ViewerMediaPartSelectorV1>(&json).is_err(),
                "{json}"
            );
        }
        assert!(ViewerMediaPartSelectorV1::init_v2(2).is_err());
        assert!(ViewerMediaPartSelectorV1::segment_v2(2, 0, vec![1], vec![]).is_err());
        assert!(
            ViewerMediaPartSelectorV1::segment_v2(0, 0, vec![1], vec![proof_entry(1); 33]).is_err()
        );
    }

    #[test]
    fn selector_v1_has_no_v2_fields() {
        for selector in [
            ViewerMediaPartSelectorV1::init(),
            ViewerMediaPartSelectorV1::segment(3, vec![1]).unwrap(),
        ] {
            assert_eq!(selector.rendition_index(), None);
            assert_eq!(selector.segment_proof(), None);
        }
    }

    use crate::media::v2_tests::{protect, protected_init_without_elastos, A, KID, TIMESCALE, V};
    use crate::{CencDashMediaIdentityV2, CencDashRenditionBytesV2};
    use elastos_protected_content_contracts::ContentAccessIdV1;

    struct DashOpen {
        head: CencDashMediaIdentityV2,
        inits: Vec<Vec<u8>>,
        segments: Vec<Vec<u8>>,
        custody_envelope: elastos_protected_content_contracts::CustodyEnvelopeV1,
        operation: SignedRuntimeReleaseOperationV1,
    }

    fn dash_open_with(video_init: Vec<u8>, audio_init: Vec<u8>, seed: u8) -> DashOpen {
        let video = protect(V, &[]);
        let audio = protect(A, &[]);
        let video_segments = vec![video.segment.clone()];
        let audio_segments = vec![audio.segment.clone()];
        let head = CencDashMediaIdentityV2::new_from_bytes(
            ContentAccessIdV1::new(KID).unwrap(),
            &[
                CencDashRenditionBytesV2 {
                    kind: V,
                    timescale: TIMESCALE,
                    init_segment: &video_init,
                    segments: &video_segments,
                },
                CencDashRenditionBytesV2 {
                    kind: A,
                    timescale: TIMESCALE,
                    init_segment: &audio_init,
                    segments: &audio_segments,
                },
            ],
        )
        .unwrap();
        let custody_envelope =
            custody_envelope_for_encrypted_content(head.encrypted_content().clone(), seed);
        let operation =
            make_signed_runtime_release_operation_for_envelope_and_seed(0x42, &custody_envelope);
        DashOpen {
            head,
            inits: vec![video_init, audio_init],
            segments: vec![video.segment, audio.segment],
            custody_envelope,
            operation,
        }
    }

    fn dash_open(seed: u8) -> DashOpen {
        dash_open_with(protect(V, &[]).init, protect(A, &[]).init, seed)
    }

    fn dash_open_request(
        fixture: &DashOpen,
        head: &CencDashMediaIdentityV2,
        inits: &[Vec<u8>],
    ) -> DecryptProviderRequestV1 {
        let contributions = vec![
            make_signed_node_contribution(&fixture.operation, 1),
            make_signed_node_contribution(&fixture.operation, 2),
        ];
        let terminal = make_signed_terminal_receipt(&fixture.operation, &contributions, 0x61);
        DecryptProviderRequestV1::new_open_viewer_session_v2(
            handle(0x21),
            &fixture.operation,
            terminal.statement().issuer(),
            fixture.custody_envelope.manifest().content_key_commitment(),
            head,
            inits,
            &contributions,
            &terminal,
        )
        .unwrap()
    }

    #[test]
    fn open_v2_round_trips_with_head_sessions_and_inits() {
        let fixture = dash_open(0x11);
        let request = dash_open_request(&fixture, &fixture.head, &fixture.inits);
        let json = request.to_json_vec().unwrap();
        let text = String::from_utf8(json.clone()).unwrap();
        assert!(text.contains("media_identity_v2") && text.contains("protected_init_segments"));
        assert!(!text.contains("\"media_identity\""));
        assert_eq!(
            DecryptProviderRequestV1::decode_wire(&json).unwrap(),
            request
        );
        let validated = decode_request(&json).unwrap();
        assert_eq!(validated.media_identity_v2().unwrap(), &fixture.head);
        let sessions = validated.media_dash_sessions().unwrap();
        assert_eq!(sessions.len(), 2);
        assert_eq!(sessions[0].kind(), V);
        assert_eq!(sessions[1].kind(), A);
        assert_eq!(
            validated.protected_init_segments().unwrap(),
            vec![fixture.inits[0].as_slice(), fixture.inits[1].as_slice()]
        );
        assert!(validated.media_session_layout().is_err());
        assert!(validated.protected_init_segment().is_err());
        assert!(validated.object_identity().is_err());
    }

    #[test]
    fn open_v2_is_exclusive_with_the_other_content_shapes() {
        let fixture = dash_open(0x11);
        let v2 = serde_json::from_slice::<serde_json::Value>(
            &dash_open_request(&fixture, &fixture.head, &fixture.inits)
                .to_json_vec()
                .unwrap(),
        )
        .unwrap();

        let (media_identity, init_segment, _, custody_envelope, operation) = open_fixture(0x11);
        let contributions = vec![
            make_signed_node_contribution(&operation, 1),
            make_signed_node_contribution(&operation, 2),
        ];
        let terminal = make_signed_terminal_receipt(&operation, &contributions, 0x61);
        let v1 = serde_json::from_slice::<serde_json::Value>(
            &DecryptProviderRequestV1::new_open_viewer_session(
                handle(0x21),
                &operation,
                terminal.statement().issuer(),
                custody_envelope.manifest().content_key_commitment(),
                &media_identity,
                &init_segment,
                &contributions,
                &terminal,
            )
            .unwrap()
            .to_json_vec()
            .unwrap(),
        )
        .unwrap();
        let (object_identity, framed_header, object_envelope, object_operation) =
            object_open_fixture(0x71);
        let object_contributions = vec![
            make_signed_node_contribution(&object_operation, 1),
            make_signed_node_contribution(&object_operation, 2),
        ];
        let object_terminal =
            make_signed_terminal_receipt(&object_operation, &object_contributions, 0x61);
        let object = serde_json::from_slice::<serde_json::Value>(
            &DecryptProviderRequestV1::new_open_viewer_session_for_object(
                handle(0x21),
                &object_operation,
                object_terminal.statement().issuer(),
                object_envelope.manifest().content_key_commitment(),
                &object_identity,
                &framed_header,
                &object_contributions,
                &object_terminal,
            )
            .unwrap()
            .to_json_vec()
            .unwrap(),
        )
        .unwrap();

        let refuses = |value: &serde_json::Value| {
            DecryptProviderRequestV1::decode_wire(&serde_json::to_vec(value).unwrap()).is_err()
        };
        let mut both_media = v2.clone();
        for key in ["media_identity", "protected_init_segment"] {
            both_media[key] = v1[key].clone();
        }
        assert!(refuses(&both_media));
        let mut head_only = v2.clone();
        head_only
            .as_object_mut()
            .unwrap()
            .remove("protected_init_segments");
        assert!(refuses(&head_only));
        let mut inits_only = v2.clone();
        inits_only
            .as_object_mut()
            .unwrap()
            .remove("media_identity_v2");
        assert!(refuses(&inits_only));
        let mut three_inits = v2.clone();
        let first = three_inits["protected_init_segments"][0].clone();
        three_inits["protected_init_segments"]
            .as_array_mut()
            .unwrap()
            .push(first);
        assert!(refuses(&three_inits));
        let mut with_object = v2.clone();
        for key in ["object_identity", "framed_header"] {
            with_object[key] = object[key].clone();
        }
        assert!(refuses(&with_object));
        assert!(!refuses(&v2));
    }

    #[test]
    fn open_v2_binding_refusals() {
        let fixture = dash_open(0x11);
        let open = |request: &DecryptProviderRequestV1| {
            decode_request(&request.to_json_vec().unwrap())
                .err()
                .map(|error| error.to_string())
        };

        let video = protect(V, &[]);
        let audio = protect(A, &[]);
        let longer = [video.segment.clone(), video.segment.clone()];
        let other_head = CencDashMediaIdentityV2::new_from_bytes(
            ContentAccessIdV1::new(KID).unwrap(),
            &[
                CencDashRenditionBytesV2 {
                    kind: V,
                    timescale: TIMESCALE,
                    init_segment: &video.init,
                    segments: &longer,
                },
                CencDashRenditionBytesV2 {
                    kind: A,
                    timescale: TIMESCALE,
                    init_segment: &audio.init,
                    segments: std::slice::from_ref(&audio.segment),
                },
            ],
        )
        .unwrap();
        assert_ne!(
            other_head.encrypted_content(),
            fixture.head.encrypted_content()
        );
        let other_release = dash_open_request(&fixture, &other_head, &fixture.inits);
        // A head whose encrypted content is not the one the release is bound to.
        let message = open(&other_release).expect("a foreign head must be refused");
        assert!(message.contains("media_identity_v2"), "{message}");

        let one_init = dash_open_request(&fixture, &fixture.head, &fixture.inits[..1]);
        let message = open(&one_init).expect("one init for two renditions must be refused");
        assert!(message.contains("protected_init_segments"), "{message}");

        let mut flipped = fixture.inits.clone();
        flipped[0][0] ^= 0x01;
        let message = open(&dash_open_request(&fixture, &fixture.head, &flipped))
            .expect("a changed init must be refused");
        assert!(message.contains("protected_init_segments"), "{message}");

        let stripped = dash_open_with(
            protected_init_without_elastos(V),
            protect(A, &[]).init,
            0x13,
        );
        let message = open(&dash_open_request(
            &stripped,
            &stripped.head,
            &stripped.inits,
        ))
        .expect("an init without the Elastos header must be refused");
        assert!(message.contains("protected_init_segments"), "{message}");
    }

    #[test]
    fn v2_part_requests_and_responses_stay_within_the_frame_limit() {
        let fixture = dash_open(0x11);
        let audit = fixture.operation.statement().audit_request_id();
        let big = vec![0x41u8; MAX_VIEWER_MEDIA_PART_BYTES_V1];
        let proof = vec![proof_entry(0xff); 32];
        let v1_request = DecryptProviderRequestV1::new_read_viewer_media_part(
            audit,
            handle(0x41),
            ViewerMediaPartSelectorV1::segment(7, big.clone()).unwrap(),
        )
        .unwrap();
        let v2_selector = ViewerMediaPartSelectorV1::segment_v2(1, 7, big.clone(), proof).unwrap();
        let v2_request = DecryptProviderRequestV1::new_read_viewer_media_part(
            audit,
            handle(0x41),
            v2_selector.clone(),
        )
        .unwrap();
        let v1_len = v1_request.to_json_vec().unwrap().len();
        let v2_len = v2_request.to_json_vec().unwrap().len();
        assert!(v2_len <= MAX_PROVIDER_FRAME_BYTES_V1);
        // 32 digests of 32 bytes at most 4 JSON bytes each, plus the field names.
        assert!(v2_len - v1_len <= 5 * 1024, "{}", v2_len - v1_len);
        let response = DecryptProviderResponseV1::new_viewer_media_part(
            audit,
            handle(0x41),
            v2_selector,
            vec![0x42u8; MAX_VIEWER_MEDIA_PART_BYTES_V1],
        )
        .unwrap();
        assert!(response.to_json_vec().unwrap().len() <= MAX_PROVIDER_FRAME_BYTES_V1);
        let _ = fixture.segments;
    }

    #[test]
    fn decrypt_prepare_request_round_trips() {
        let operation = make_signed_runtime_release_operation();
        let request = DecryptProviderRequestV1::new_prepare_recipient(
            operation.statement().release_request().binding(),
            operation.statement().audit_request_id(),
            operation.statement().release_request().action(),
            operation.statement().runtime_operation_issuer(),
            operation.statement().issued_at(),
            operation.statement().expires_at(),
        )
        .unwrap();
        let decoded =
            DecryptProviderRequestV1::decode_wire(&request.to_json_vec().unwrap()).unwrap();
        assert_eq!(decoded, request);
        let validated = decode_request(&request.to_json_vec().unwrap()).unwrap();
        assert_eq!(validated.op(), request.op());
        assert_eq!(
            validated.audit_request_id(),
            operation.statement().audit_request_id()
        );

        assert!(ValidatedDecryptProviderRequestV1::decode_and_validate_at(
            &request.to_json_vec().unwrap(),
            runtime_operation_issuer_for_seed(0x42),
            crate::test_support::NOW + 1,
        )
        .is_err());
        assert!(ValidatedDecryptProviderRequestV1::decode_and_validate_at(
            &request.to_json_vec().unwrap(),
            runtime_operation_issuer_for_seed(0x42),
            crate::test_support::NOW + 41,
        )
        .is_err());

        let mut injected_now =
            serde_json::from_slice::<serde_json::Value>(&request.to_json_vec().unwrap()).unwrap();
        injected_now["now_unix_ms"] = serde_json::json!(crate::test_support::NOW + 10);
        assert!(ValidatedDecryptProviderRequestV1::decode_and_validate_at(
            &serde_json::to_vec(&injected_now).unwrap(),
            runtime_operation_issuer_for_seed(0x42),
            crate::test_support::NOW + 10,
        )
        .is_err());

        assert!(ValidatedDecryptProviderRequestV1::decode_and_validate_at(
            &request.to_json_vec().unwrap(),
            runtime_operation_issuer_for_seed(0x43),
            crate::test_support::NOW + 10,
        )
        .is_err());
    }

    #[test]
    fn decrypt_open_request_round_trips_without_envelope_and_rejects_wrong_bindings() {
        let (media_identity, init_segment, _, custody_envelope, operation) = open_fixture(0x11);
        let contributions = vec![
            make_signed_node_contribution(&operation, 1),
            make_signed_node_contribution(&operation, 2),
        ];
        let terminal = make_signed_terminal_receipt(&operation, &contributions, 0x61);
        let request = DecryptProviderRequestV1::new_open_viewer_session(
            handle(0x21),
            &operation,
            terminal.statement().issuer(),
            custody_envelope.manifest().content_key_commitment(),
            &media_identity,
            &init_segment,
            &contributions,
            &terminal,
        )
        .unwrap();
        let request_json = request.to_json_vec().unwrap();
        let request_text = String::from_utf8(request_json.clone()).unwrap();
        assert!(!request_text.contains("custody_envelope"));
        assert!(!request_text.contains("stored_share"));
        assert!(!request_text.contains("sealed_share"));
        let stored_share_json = serde_json::to_string(
            &custody_envelope.stored_shares()[0]
                .canonical_bytes()
                .unwrap(),
        )
        .unwrap();
        assert!(!request_text.contains(&stored_share_json));
        let decoded = DecryptProviderRequestV1::decode_wire(&request_json).unwrap();
        assert_eq!(decoded, request);
        let validated = decode_request(&request.to_json_vec().unwrap()).unwrap();
        assert_eq!(validated.op(), request.op());
        assert_eq!(
            validated.audit_request_id(),
            operation.statement().audit_request_id()
        );
        assert_eq!(
            validated.content_key_commitment().unwrap(),
            custody_envelope.manifest().content_key_commitment()
        );
        assert!(ValidatedDecryptProviderRequestV1::decode_and_validate_at(
            &request.to_json_vec().unwrap(),
            runtime_operation_issuer_for_seed(0x42),
            crate::test_support::NOW.saturating_sub(10),
        )
        .is_err());
        assert!(ValidatedDecryptProviderRequestV1::decode_and_validate_at(
            &request.to_json_vec().unwrap(),
            runtime_operation_issuer_for_seed(0x42),
            crate::test_support::NOW + 41,
        )
        .is_err());

        let other_operation = make_signed_runtime_release_operation_for_envelope_and_seed(
            0x52,
            &custody_envelope_for_seed(0x52),
        );
        let wrong_contributions = DecryptProviderRequestV1::new_open_viewer_session(
            handle(0x21),
            &operation,
            terminal.statement().issuer(),
            custody_envelope.manifest().content_key_commitment(),
            &media_identity,
            &init_segment,
            &[
                make_signed_node_contribution(&other_operation, 1),
                make_signed_node_contribution(&other_operation, 2),
            ],
            &terminal,
        )
        .unwrap();
        assert!(ValidatedDecryptProviderRequestV1::decode_and_validate_at(
            &wrong_contributions.to_json_vec().unwrap(),
            runtime_operation_issuer_for_seed(0x42),
            crate::test_support::NOW + 10,
        )
        .is_err());

        assert!(ValidatedDecryptProviderRequestV1::decode_and_validate_at(
            &request.to_json_vec().unwrap(),
            runtime_operation_issuer_for_seed(0x43),
            crate::test_support::NOW + 10,
        )
        .is_err());

        let wrong_media_identity = crate::test_support::media_identity(0x21);
        let wrong_media = DecryptProviderRequestV1::new_open_viewer_session(
            handle(0x21),
            &operation,
            terminal.statement().issuer(),
            custody_envelope.manifest().content_key_commitment(),
            &wrong_media_identity,
            &init_segment,
            &contributions,
            &terminal,
        )
        .unwrap();
        assert!(ValidatedDecryptProviderRequestV1::decode_and_validate_at(
            &wrong_media.to_json_vec().unwrap(),
            runtime_operation_issuer_for_seed(0x42),
            crate::test_support::NOW + 10,
        )
        .is_err());

        let mut wrong_init = init_segment.clone();
        wrong_init[0] ^= 0x01;
        let wrong_init_request = DecryptProviderRequestV1::new_open_viewer_session(
            handle(0x21),
            &operation,
            terminal.statement().issuer(),
            custody_envelope.manifest().content_key_commitment(),
            &media_identity,
            &wrong_init,
            &contributions,
            &terminal,
        )
        .unwrap();
        assert!(ValidatedDecryptProviderRequestV1::decode_and_validate_at(
            &wrong_init_request.to_json_vec().unwrap(),
            runtime_operation_issuer_for_seed(0x42),
            crate::test_support::NOW + 10,
        )
        .is_err());
    }

    #[test]
    fn decrypt_open_request_rejects_required_plus_one_duplicate_and_trailing_bytes() {
        let (media_identity, init_segment, _, custody_envelope, operation) = open_fixture(0x11);
        let contributions = vec![
            make_signed_node_contribution(&operation, 1),
            make_signed_node_contribution(&operation, 2),
        ];
        let terminal = make_signed_terminal_receipt(&operation, &contributions, 0x61);
        let extra_contribution = DecryptProviderRequestV1::new_open_viewer_session(
            handle(0x21),
            &operation,
            terminal.statement().issuer(),
            custody_envelope.manifest().content_key_commitment(),
            &media_identity,
            &init_segment,
            &[
                contributions[0].clone(),
                contributions[1].clone(),
                make_signed_node_contribution(&operation, 3),
            ],
            &terminal,
        )
        .unwrap();
        assert!(ValidatedDecryptProviderRequestV1::decode_and_validate_at(
            &extra_contribution.to_json_vec().unwrap(),
            runtime_operation_issuer_for_seed(0x42),
            crate::test_support::NOW + 10,
        )
        .is_err());

        let duplicate_contribution = DecryptProviderRequestV1::new_open_viewer_session(
            handle(0x21),
            &operation,
            terminal.statement().issuer(),
            custody_envelope.manifest().content_key_commitment(),
            &media_identity,
            &init_segment,
            &[contributions[0].clone(), contributions[0].clone()],
            &terminal,
        )
        .unwrap();
        assert!(ValidatedDecryptProviderRequestV1::decode_and_validate_at(
            &duplicate_contribution.to_json_vec().unwrap(),
            runtime_operation_issuer_for_seed(0x42),
            crate::test_support::NOW + 10,
        )
        .is_err());

        let mut trailing = DecryptProviderRequestV1::new_cancel_prepared_recipient(
            operation.statement().audit_request_id(),
            handle(0x21),
        )
        .unwrap()
        .to_json_vec()
        .unwrap();
        trailing.extend_from_slice(br#"{"extra":true}"#);
        assert!(ValidatedDecryptProviderRequestV1::decode_and_validate_at(
            &trailing,
            runtime_operation_issuer_for_seed(0x42),
            crate::test_support::NOW + 10,
        )
        .is_err());
    }

    #[test]
    fn decrypt_response_round_trips_and_redacts_handles() {
        let audit_id = RuntimeReleaseAuditIdV1::new(crate::test_support::digest(0x91)).unwrap();
        let response = DecryptProviderResponseV1::new_prepared_recipient(
            audit_id,
            handle(0x21),
            recipient_public_key(0x30),
            &recipient_identity(0x30),
        )
        .unwrap();
        let decoded =
            DecryptProviderResponseV1::from_json_slice(&response.to_json_vec().unwrap()).unwrap();
        assert_eq!(decoded, response);

        let debug = format!("{response:?}");
        assert!(!debug.contains("215b"));
        assert!(debug.contains("[redacted]"));
    }

    #[test]
    fn decrypt_read_viewer_media_part_contract_is_strict_and_bounded() {
        let (media_identity, init_segment, encrypted_segments, custody_envelope, operation) =
            open_fixture(0x11);
        let contributions = vec![
            make_signed_node_contribution(&operation, 1),
            make_signed_node_contribution(&operation, 2),
        ];
        let terminal = make_signed_terminal_receipt(&operation, &contributions, 0x61);
        let open_request = DecryptProviderRequestV1::new_open_viewer_session(
            handle(0x21),
            &operation,
            terminal.statement().issuer(),
            custody_envelope.manifest().content_key_commitment(),
            &media_identity,
            &init_segment,
            &contributions,
            &terminal,
        )
        .unwrap();
        let open_validated = decode_request(&open_request.to_json_vec().unwrap()).unwrap();
        assert_eq!(
            open_validated
                .media_session_layout()
                .unwrap()
                .media_identity(),
            &media_identity
        );
        assert_eq!(
            open_validated.protected_init_segment().unwrap(),
            init_segment.as_slice()
        );

        let init_request = DecryptProviderRequestV1::new_read_viewer_media_part(
            operation.statement().audit_request_id(),
            handle(0x41),
            ViewerMediaPartSelectorV1::init(),
        )
        .unwrap();
        let init_json =
            serde_json::from_slice::<serde_json::Value>(&init_request.to_json_vec().unwrap())
                .unwrap();
        assert_eq!(init_json["part_selector"]["part"], "init");
        assert!(init_json["part_selector"]
            .get("encrypted_segment")
            .is_none());
        let validated_init = decode_request(&init_request.to_json_vec().unwrap()).unwrap();
        assert_eq!(
            validated_init.op(),
            DecryptProviderRequestOpV1::ReadViewerMediaPart
        );
        assert!(validated_init
            .viewer_media_part_selector()
            .unwrap()
            .is_init());

        let segment_request = DecryptProviderRequestV1::new_read_viewer_media_part(
            operation.statement().audit_request_id(),
            handle(0x41),
            ViewerMediaPartSelectorV1::segment(1, encrypted_segments[1].clone()).unwrap(),
        )
        .unwrap();
        let validated_segment = decode_request(&segment_request.to_json_vec().unwrap()).unwrap();
        assert_eq!(
            validated_segment
                .viewer_media_part_selector()
                .unwrap()
                .segment_index(),
            Some(1)
        );
        assert_eq!(
            validated_segment
                .viewer_media_part_selector()
                .unwrap()
                .encrypted_segment()
                .unwrap(),
            encrypted_segments[1].as_slice()
        );

        let response = DecryptProviderResponseV1::new_viewer_media_part(
            operation.statement().audit_request_id(),
            handle(0x41),
            ViewerMediaPartSelectorV1::segment(1, encrypted_segments[1].clone()).unwrap(),
            vec![0x10, 0x11, 0x12],
        )
        .unwrap();
        let decoded =
            DecryptProviderResponseV1::from_json_slice(&response.to_json_vec().unwrap()).unwrap();
        assert_eq!(
            decoded.status(),
            DecryptProviderResponseStatusV1::ViewerMediaPart
        );
        assert_eq!(
            decoded
                .viewer_media_part_selector()
                .unwrap()
                .segment_index(),
            Some(1)
        );
        assert_eq!(decoded.clear_media_part().unwrap(), &[0x10, 0x11, 0x12]);

        let mut wrong_shape =
            serde_json::from_slice::<serde_json::Value>(&init_request.to_json_vec().unwrap())
                .unwrap();
        wrong_shape["part_selector"]["encrypted_segment"] = serde_json::json!([1, 2, 3]);
        assert!(decode_request(&serde_json::to_vec(&wrong_shape).unwrap()).is_err());

        let mut missing_segment =
            serde_json::from_slice::<serde_json::Value>(&segment_request.to_json_vec().unwrap())
                .unwrap();
        missing_segment["part_selector"]
            .as_object_mut()
            .unwrap()
            .remove("encrypted_segment");
        assert!(decode_request(&serde_json::to_vec(&missing_segment).unwrap()).is_err());

        let mut oversized =
            serde_json::from_slice::<serde_json::Value>(&segment_request.to_json_vec().unwrap())
                .unwrap();
        oversized["part_selector"]["encrypted_segment"] =
            serde_json::json!(vec![7u8; MAX_VIEWER_MEDIA_PART_BYTES_V1 + 1]);
        assert!(decode_request(&serde_json::to_vec(&oversized).unwrap()).is_err());

        let mut out_of_range =
            serde_json::from_slice::<serde_json::Value>(&segment_request.to_json_vec().unwrap())
                .unwrap();
        out_of_range["part_selector"]["segment_index"] = serde_json::json!(u64::from(u32::MAX) + 1);
        assert!(decode_request(&serde_json::to_vec(&out_of_range).unwrap()).is_err());

        let mut trailing = segment_request.to_json_vec().unwrap();
        trailing.extend_from_slice(br#"{"extra":true}"#);
        assert!(decode_request(&trailing).is_err());

        let debug = format!("{response:?}");
        for forbidden in ["play_url", "route", "credential", "share", "cek"] {
            assert!(!debug.contains(forbidden));
        }
        assert!(debug.contains("[redacted]"));
    }

    #[test]
    fn decrypt_lifecycle_round_trips_with_exact_binding() {
        let audit_id = RuntimeReleaseAuditIdV1::new(crate::test_support::digest(0x91)).unwrap();
        let (media_identity, init_segment, encrypted_segments, custody_envelope, operation) =
            open_fixture(0x11);
        let contributions = vec![
            make_signed_node_contribution(&operation, 1),
            make_signed_node_contribution(&operation, 2),
        ];
        let terminal = make_signed_terminal_receipt(&operation, &contributions, 0x61);
        let prepared = handle(0x21);
        let viewer = handle(0x31);

        let requests = [
            DecryptProviderRequestV1::new_prepare_recipient(
                operation.statement().release_request().binding(),
                audit_id,
                operation.statement().release_request().action(),
                operation.statement().runtime_operation_issuer(),
                operation.statement().issued_at(),
                operation.statement().expires_at(),
            )
            .unwrap(),
            DecryptProviderRequestV1::new_open_viewer_session(
                prepared,
                &operation,
                terminal.statement().issuer(),
                custody_envelope.manifest().content_key_commitment(),
                &media_identity,
                &init_segment,
                &contributions,
                &terminal,
            )
            .unwrap(),
            DecryptProviderRequestV1::new_read_viewer_media_part(
                audit_id,
                viewer,
                ViewerMediaPartSelectorV1::segment(1, encrypted_segments[1].clone()).unwrap(),
            )
            .unwrap(),
            DecryptProviderRequestV1::new_cancel_prepared_recipient(audit_id, prepared).unwrap(),
            DecryptProviderRequestV1::new_close_viewer_session(audit_id, viewer).unwrap(),
        ];
        for request in requests {
            let decoded =
                DecryptProviderRequestV1::decode_wire(&request.to_json_vec().unwrap()).unwrap();
            assert_eq!(decoded, request);
            assert_eq!(
                ValidatedDecryptProviderRequestV1::decode_and_validate_at(
                    &request.to_json_vec().unwrap(),
                    runtime_operation_issuer_for_seed(0x42),
                    crate::test_support::NOW + 10,
                )
                .unwrap()
                .op(),
                request.op()
            );
        }

        let responses = [
            DecryptProviderResponseV1::new_prepared_recipient(
                audit_id,
                prepared,
                recipient_public_key(0x30),
                &recipient_identity(0x30),
            )
            .unwrap(),
            DecryptProviderResponseV1::new_viewer_session_opened(audit_id, viewer).unwrap(),
            DecryptProviderResponseV1::new_viewer_media_part(
                audit_id,
                viewer,
                ViewerMediaPartSelectorV1::segment(1, encrypted_segments[1].clone()).unwrap(),
                vec![0x41, 0x42, 0x43],
            )
            .unwrap(),
            DecryptProviderResponseV1::new_cancelled_prepared_recipient(audit_id, prepared)
                .unwrap(),
            DecryptProviderResponseV1::new_prepared_recipient_already_absent(audit_id, prepared)
                .unwrap(),
            DecryptProviderResponseV1::new_closed_viewer_session(audit_id, viewer).unwrap(),
            DecryptProviderResponseV1::new_viewer_session_already_absent(audit_id, viewer).unwrap(),
        ];
        for response in responses {
            let decoded =
                DecryptProviderResponseV1::from_json_slice(&response.to_json_vec().unwrap())
                    .unwrap();
            assert_eq!(decoded, response);
        }
    }

    #[test]
    fn decrypt_response_terminal_statuses_and_failure_are_typed() {
        let audit_id = RuntimeReleaseAuditIdV1::new(crate::test_support::digest(0x91)).unwrap();
        let opened =
            DecryptProviderResponseV1::new_viewer_session_opened(audit_id, handle(0x31)).unwrap();
        assert_eq!(
            opened.status(),
            DecryptProviderResponseStatusV1::ViewerSessionOpened
        );
        let media = DecryptProviderResponseV1::new_viewer_media_part(
            audit_id,
            handle(0x31),
            ViewerMediaPartSelectorV1::init(),
            vec![0x41],
        )
        .unwrap();
        assert_eq!(
            media.status(),
            DecryptProviderResponseStatusV1::ViewerMediaPart
        );
        let closed =
            DecryptProviderResponseV1::new_closed_viewer_session(audit_id, handle(0x31)).unwrap();
        assert_eq!(
            closed.status(),
            DecryptProviderResponseStatusV1::ClosedViewerSession
        );
        let absent =
            DecryptProviderResponseV1::new_viewer_session_already_absent(audit_id, handle(0x31))
                .unwrap();
        assert_eq!(
            absent.status(),
            DecryptProviderResponseStatusV1::ViewerSessionAlreadyAbsent
        );
        let failure =
            DecryptProviderResponseV1::new_failure(audit_id, ProviderFailureCodeV1::NotConfigured)
                .unwrap();
        assert_eq!(failure.status(), DecryptProviderResponseStatusV1::Failure);
        assert_eq!(
            failure.failure_code().unwrap(),
            ProviderFailureCodeV1::NotConfigured
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

    fn object_open_fixture(
        seed: u8,
    ) -> (
        ChunkedPayloadObjectIdentityV1,
        Vec<u8>,
        elastos_protected_content_contracts::CustodyEnvelopeV1,
        SignedRuntimeReleaseOperationV1,
    ) {
        let object_identity = object_identity_for(seed, 4096);
        let framed_header = vec![seed; 64];
        let custody_envelope = custody_envelope_for_encrypted_content(
            object_identity.encrypted_content().clone(),
            seed,
        );
        let operation =
            make_signed_runtime_release_operation_for_envelope_and_seed(0x42, &custody_envelope);
        (object_identity, framed_header, custody_envelope, operation)
    }

    #[test]
    fn decrypt_open_request_for_object_round_trips_and_enforces_exactly_one_content() {
        let (object_identity, framed_header, custody_envelope, operation) =
            object_open_fixture(0x71);
        let contributions = vec![
            make_signed_node_contribution(&operation, 1),
            make_signed_node_contribution(&operation, 2),
        ];
        let terminal = make_signed_terminal_receipt(&operation, &contributions, 0x61);
        let request = DecryptProviderRequestV1::new_open_viewer_session_for_object(
            handle(0x21),
            &operation,
            terminal.statement().issuer(),
            custody_envelope.manifest().content_key_commitment(),
            &object_identity,
            &framed_header,
            &contributions,
            &terminal,
        )
        .unwrap();
        let request_json = request.to_json_vec().unwrap();
        let request_text = String::from_utf8(request_json.clone()).unwrap();
        assert!(!request_text.contains("media_identity"));
        assert!(!request_text.contains("protected_init_segment"));

        let decoded = DecryptProviderRequestV1::decode_wire(&request_json).unwrap();
        assert_eq!(decoded, request);
        let validated = decode_request(&request_json).unwrap();
        assert_eq!(
            validated.op(),
            DecryptProviderRequestOpV1::OpenViewerSession
        );
        assert_eq!(validated.object_identity().unwrap(), &object_identity);
        assert_eq!(validated.framed_header().unwrap(), framed_header.as_slice());
        assert!(validated.media_session_layout().is_err());
        assert!(validated.protected_init_segment().is_err());

        // Both media and object content present: rejected.
        let media_identity = crate::test_support::media_identity(0x11);
        let (init_segment, _, _, _) = media_components(0x11);
        let mut both = serde_json::from_slice::<serde_json::Value>(&request_json).unwrap();
        both["media_identity"] = serde_json::json!(media_identity.canonical_bytes().unwrap());
        both["protected_init_segment"] = serde_json::json!(init_segment);
        assert!(decode_request(&serde_json::to_vec(&both).unwrap()).is_err());

        // Neither media nor object content present: rejected.
        let mut neither = serde_json::from_slice::<serde_json::Value>(&request_json).unwrap();
        neither.as_object_mut().unwrap().remove("object_identity");
        neither.as_object_mut().unwrap().remove("framed_header");
        assert!(decode_request(&serde_json::to_vec(&neither).unwrap()).is_err());

        // framed_header length must match the identity's declared framed_header_bytes.
        let mut wrong_header_len =
            serde_json::from_slice::<serde_json::Value>(&request_json).unwrap();
        wrong_header_len["framed_header"] = serde_json::json!(vec![0x11u8; 63]);
        assert!(decode_request(&serde_json::to_vec(&wrong_header_len).unwrap()).is_err());

        // framed_header exceeding the CanonicalBlob bound is rejected structurally.
        let mut oversized_header =
            serde_json::from_slice::<serde_json::Value>(&request_json).unwrap();
        oversized_header["framed_header"] =
            serde_json::json!(vec![0x11u8; MAX_OBJECT_FRAMED_HEADER_BYTES_V1 + 1]);
        assert!(decode_request(&serde_json::to_vec(&oversized_header).unwrap()).is_err());

        // object_identity not bound to the operation's encrypted content: rejected.
        let wrong_object_identity = object_identity_for(0x72, 4096);
        let wrong_object_request = DecryptProviderRequestV1::new_open_viewer_session_for_object(
            handle(0x21),
            &operation,
            terminal.statement().issuer(),
            custody_envelope.manifest().content_key_commitment(),
            &wrong_object_identity,
            &framed_header,
            &contributions,
            &terminal,
        )
        .unwrap();
        assert!(decode_request(&wrong_object_request.to_json_vec().unwrap()).is_err());

        let mut unknown = serde_json::from_slice::<serde_json::Value>(&request_json).unwrap();
        unknown["unexpected"] = serde_json::json!(true);
        assert!(decode_request(&serde_json::to_vec(&unknown).unwrap()).is_err());
    }

    #[test]
    fn decrypt_read_viewer_object_chunk_round_trips_rejects_unknown_field_and_oversize_blobs() {
        let audit_id = RuntimeReleaseAuditIdV1::new(digest(0x91)).unwrap();
        let request = DecryptProviderRequestV1::new_read_viewer_object_chunk(
            audit_id,
            handle(0x41),
            3,
            b"framed-chunk",
        )
        .unwrap();
        let request_json = request.to_json_vec().unwrap();
        let decoded = DecryptProviderRequestV1::decode_wire(&request_json).unwrap();
        assert_eq!(decoded, request);
        let validated = decode_request(&request_json).unwrap();
        assert_eq!(
            validated.op(),
            DecryptProviderRequestOpV1::ReadViewerObjectChunk
        );
        assert_eq!(validated.chunk_index().unwrap(), 3);
        assert_eq!(validated.framed_chunk().unwrap(), b"framed-chunk");
        assert_eq!(validated.session_handle().unwrap(), &handle(0x41));

        assert!(DecryptProviderRequestV1::new_read_viewer_object_chunk(
            audit_id,
            handle(0x41),
            3,
            &vec![0u8; MAX_OBJECT_FRAMED_CHUNK_BYTES_V1 + 1],
        )
        .is_err());

        let mut unknown = serde_json::from_slice::<serde_json::Value>(&request_json).unwrap();
        unknown["unexpected"] = serde_json::json!(true);
        assert!(decode_request(&serde_json::to_vec(&unknown).unwrap()).is_err());

        let mut trailing = request_json.clone();
        trailing.extend_from_slice(br#"{"extra":true}"#);
        assert!(decode_request(&trailing).is_err());

        let response =
            DecryptProviderResponseV1::new_viewer_object_chunk(audit_id, b"clear-chunk".to_vec())
                .unwrap();
        let decoded_response =
            DecryptProviderResponseV1::from_json_slice(&response.to_json_vec().unwrap()).unwrap();
        assert_eq!(decoded_response, response);
        assert_eq!(
            decoded_response.status(),
            DecryptProviderResponseStatusV1::ViewerObjectChunk
        );
        assert_eq!(decoded_response.plaintext().unwrap(), b"clear-chunk");
        assert_eq!(decoded_response.audit_request_id().unwrap(), audit_id);

        assert!(DecryptProviderResponseV1::new_viewer_object_chunk(
            audit_id,
            vec![0u8; MAX_OBJECT_PLAINTEXT_CHUNK_BYTES_V1 + 1],
        )
        .is_err());

        let mut unknown_response =
            serde_json::from_slice::<serde_json::Value>(&response.to_json_vec().unwrap()).unwrap();
        unknown_response["unexpected"] = serde_json::json!(true);
        assert!(DecryptProviderResponseV1::from_json_slice(
            &serde_json::to_vec(&unknown_response).unwrap()
        )
        .is_err());
    }

    #[test]
    fn maximum_object_chunk_requests_and_responses_stay_within_provider_frame_limit() {
        let audit_id = RuntimeReleaseAuditIdV1::new(digest(0x91)).unwrap();

        let chunk_request = DecryptProviderRequestV1::new_read_viewer_object_chunk(
            audit_id,
            handle(0x41),
            u32::MAX,
            &vec![0x77; MAX_OBJECT_FRAMED_CHUNK_BYTES_V1],
        )
        .unwrap();
        let chunk_request_json = chunk_request.to_json_vec().unwrap();
        assert!(chunk_request_json.len() <= MAX_PROVIDER_FRAME_BYTES_V1);

        let chunk_response = DecryptProviderResponseV1::new_viewer_object_chunk(
            audit_id,
            vec![0x88; MAX_OBJECT_PLAINTEXT_CHUNK_BYTES_V1],
        )
        .unwrap();
        let chunk_response_json = chunk_response.to_json_vec().unwrap();
        assert!(chunk_response_json.len() <= MAX_PROVIDER_FRAME_BYTES_V1);
    }

    // Plan B T3.1: V2 ops validate under the issuer they declare, through
    // their own entry; V1 ops keep the trusted issuer.

    #[test]
    fn v2_ops_validate_only_through_the_declared_entry() {
        use elastos_protected_content_contracts::{
            RightsActionV1, MAX_RECIPIENT_KEY_AUTHORIZATION_LIFETIME_SECS,
        };
        let now = crate::test_support::NOW + 10;
        let (_, _, _, _, operation) = open_fixture(0x11);
        let binding = operation.statement().release_request().binding().clone();
        let audit = RuntimeReleaseAuditIdV1::new(digest(0xb1)).unwrap();
        let declared = runtime_operation_issuer_for_seed(0x77);
        let v2 = DecryptProviderRequestV1::new_prepare_recipient_v2(
            &binding,
            audit,
            RightsActionV1::View,
            declared,
            now + 200,
        )
        .unwrap();
        assert_eq!(v2.op(), DecryptProviderRequestOpV1::PrepareRecipientV2);
        let bytes = v2.to_json_vec().unwrap();
        // The trusted entry refuses a V2 op, even for its own issuer.
        assert!(
            ValidatedDecryptProviderRequestV1::decode_and_validate_at(&bytes, declared, now)
                .is_err()
        );
        let validated =
            ValidatedDecryptProviderRequestV1::decode_and_validate_declared_at(&bytes, now)
                .unwrap();
        assert_eq!(
            validated.op(),
            DecryptProviderRequestOpV1::PrepareRecipientV2
        );
        assert_eq!(validated.runtime_operation_issuer().unwrap(), declared);
        assert_eq!(validated.expires_at().unwrap(), now + 200);
        // The declared entry refuses a V1 op.
        let v1 = DecryptProviderRequestV1::new_prepare_recipient(
            &binding,
            audit,
            RightsActionV1::View,
            runtime_operation_issuer_for_seed(0x42),
            now - 5,
            now + 20,
        )
        .unwrap();
        assert!(
            ValidatedDecryptProviderRequestV1::decode_and_validate_declared_at(
                &v1.to_json_vec().unwrap(),
                now
            )
            .is_err()
        );
        // A V2 prepare lives at most as long as a V1 recipient authorization,
        // and not at all once expired.
        for expires_at in [now + MAX_RECIPIENT_KEY_AUTHORIZATION_LIFETIME_SECS + 1, now] {
            let request = DecryptProviderRequestV1::new_prepare_recipient_v2(
                &binding,
                audit,
                RightsActionV1::View,
                declared,
                expires_at,
            )
            .unwrap();
            assert!(
                ValidatedDecryptProviderRequestV1::decode_and_validate_declared_at(
                    &request.to_json_vec().unwrap(),
                    now
                )
                .is_err()
            );
        }
    }

    #[test]
    fn sealed_read_requests_carry_their_session_id() {
        let now = crate::test_support::NOW + 10;
        let audit = RuntimeReleaseAuditIdV1::new(digest(0xb2)).unwrap();
        let media = DecryptProviderRequestV1::new_read_viewer_media_part_sealed(
            audit,
            handle(0x41),
            ViewerMediaPartSelectorV1::init(),
            [0x5a; 16],
        )
        .unwrap();
        let validated = ValidatedDecryptProviderRequestV1::decode_and_validate_declared_at(
            &media.to_json_vec().unwrap(),
            now,
        )
        .unwrap();
        assert_eq!(
            validated.op(),
            DecryptProviderRequestOpV1::ReadViewerMediaPartSealed
        );
        assert_eq!(validated.session_id().unwrap(), [0x5a; 16]);
        assert_eq!(validated.viewer_session_handle().unwrap(), &handle(0x41));
        assert!(validated.viewer_media_part_selector().unwrap().is_init());

        let chunk = DecryptProviderRequestV1::new_read_viewer_object_chunk_sealed(
            audit,
            handle(0x41),
            3,
            &[1, 2, 3],
            [0x5b; 16],
        )
        .unwrap();
        let bytes = chunk.to_json_vec().unwrap();
        let validated =
            ValidatedDecryptProviderRequestV1::decode_and_validate_declared_at(&bytes, now)
                .unwrap();
        assert_eq!(
            validated.op(),
            DecryptProviderRequestOpV1::ReadViewerObjectChunkSealed
        );
        assert_eq!(validated.session_id().unwrap(), [0x5b; 16]);
        assert_eq!(validated.chunk_index().unwrap(), 3);
        assert_eq!(validated.framed_chunk().unwrap(), &[1, 2, 3]);
        // A sealed read is a V2 op.
        assert!(ValidatedDecryptProviderRequestV1::decode_and_validate_at(
            &bytes,
            runtime_operation_issuer_for_seed(0x42),
            now
        )
        .is_err());
    }

    #[test]
    fn sealed_part_response_is_bounded_by_the_seal_overhead() {
        use crate::MAX_SEALED_VIEWER_PART_BYTES_V1;
        assert_eq!(
            MAX_SEALED_VIEWER_PART_BYTES_V1,
            MAX_VIEWER_MEDIA_PART_BYTES_V1
                + elastos_protected_content_contracts::X_WING_DRAFT06_CIPHERTEXT_BYTES
                + 12
                + 16
        );
        let audit = RuntimeReleaseAuditIdV1::new(digest(0xb3)).unwrap();
        let at_cap = DecryptProviderResponseV1::new_viewer_sealed_part(
            audit,
            handle(0x41),
            vec![0x5c; MAX_SEALED_VIEWER_PART_BYTES_V1],
        )
        .unwrap();
        assert_eq!(
            at_cap.status(),
            DecryptProviderResponseStatusV1::ViewerSealedPart
        );
        let json = at_cap.to_json_vec().unwrap();
        assert!(json.len() <= MAX_PROVIDER_FRAME_BYTES_V1);
        assert_eq!(
            DecryptProviderResponseV1::from_json_slice(&json).unwrap(),
            at_cap
        );
        assert!(DecryptProviderResponseV1::new_viewer_sealed_part(
            audit,
            handle(0x41),
            vec![0x5c; MAX_SEALED_VIEWER_PART_BYTES_V1 + 1],
        )
        .is_err());
    }
}
