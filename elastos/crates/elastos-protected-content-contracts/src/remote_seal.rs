//! Signed admission for a remote encryption session. The transport binds the
//! session to the authenticated opening peer and the host enforces its trust
//! and concurrency limits before accepting any file bytes.

use ed25519_dalek::Signature;

use crate::canonical::{validate_ascii_identifier, CanonicalBody, Decoder, Encoder};
use crate::identity::validate_ed25519_public_key;
use crate::rights::{validate_active, validate_time_window};
use crate::{
    CanonicalContract, ContentAccessIdV1, ContractError, CustodyEpochIdentityV1,
    CustodyEpochIssuerKeyV1, Digest32, KeyEnvelopeIdentityV1, NodePublicKey, PoolContractError,
    PoolDidV1, PoolEpochBundleV1, RecipientPublicKeyBytesV1, RightsError,
    RuntimeOperationIssuerKeyV1, SignedPoolDescriptorAnyV1, VerifiedPoolDescriptorV1,
    MAX_RUNTIME_CUSTODY_PROVISIONING_LIFETIME_SECS,
};

pub const SEAL_SESSION_GRACE_SECS: u64 = 600;
pub const SEAL_PIECE_MAX_CLEAR_BYTES: usize = 512 * 1024;
pub const SEAL_PIECE_OVERHEAD_BYTES: usize = crate::X_WING_DRAFT06_CIPHERTEXT_BYTES + 12 + 16;
pub const SEAL_OBJECT_CHUNK_CLEAR_BYTES: u64 = 1024 * 1024;
pub const MAX_REMOTE_SHARE_ADMISSION_BYTES_V1: usize = 64 * 1024;
const MAX_RENDITIONS: usize = 2;
pub const SEAL_DASH_MAX_SEGMENTS_PER_RENDITION: usize = 512;
const MAX_MEDIA_PART_BYTES: u32 = 2 * 1024 * 1024;
const MAX_OBJECT_BYTES: u64 = 200 * 1024 * 1024;
const MAX_CONTENT_TYPE_BYTES: usize = 255;
const MAX_SEAL_DID_BYTES: usize = 256;
const MAX_SEAL_CID_BYTES: usize = 128;
const MAX_SEAL_PATH_BYTES: usize = 256;
const MAX_SEAL_FILES: usize = MAX_RENDITIONS * (SEAL_DASH_MAX_SEGMENTS_PER_RENDITION + 1) + 6;
const MAX_SEAL_CONTENT_IDENTITY_BYTES: usize = 4 * 1024;
const MAX_SEAL_AVAILABILITY_BYTES: usize = 24 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClearRenditionV1 {
    pub kind: u8,
    pub init_len: u32,
    pub segment_lengths: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClearLayoutV1 {
    DashV2 { renditions: Vec<ClearRenditionV1> },
    Object { content_type: String, length: u64 },
}

impl ClearLayoutV1 {
    fn byte_len(&self) -> Result<u64, ContractError> {
        match self {
            Self::Object {
                content_type,
                length,
            } => {
                validate_ascii_identifier(content_type, "content_type", MAX_CONTENT_TYPE_BYTES)?;
                if !(1..=MAX_OBJECT_BYTES).contains(length) {
                    return Err(ContractError::InvalidField("object_length"));
                }
                Ok(*length)
            }
            Self::DashV2 { renditions } => {
                if !(1..=MAX_RENDITIONS).contains(&renditions.len())
                    || renditions
                        .windows(2)
                        .any(|pair| pair[0].kind >= pair[1].kind)
                {
                    return Err(ContractError::InvalidField("renditions"));
                }
                let mut size = 0;
                for rendition in renditions {
                    if !matches!(rendition.kind, 1 | 2)
                        || !(1..=SEAL_DASH_MAX_SEGMENTS_PER_RENDITION)
                            .contains(&rendition.segment_lengths.len())
                    {
                        return Err(ContractError::InvalidField("rendition"));
                    }
                    for len in
                        std::iter::once(&rendition.init_len).chain(&rendition.segment_lengths)
                    {
                        if !(1..=MAX_MEDIA_PART_BYTES).contains(len) {
                            return Err(ContractError::InvalidField("media_part_length"));
                        }
                        size += u64::from(*len);
                    }
                }
                Ok(size)
            }
        }
    }

    fn encode(&self, encoder: &mut Encoder) -> Result<(), ContractError> {
        match self {
            Self::DashV2 { renditions } => {
                encoder.u8(1);
                encoder.u8(renditions.len() as u8);
                for rendition in renditions {
                    encoder.u8(rendition.kind);
                    encoder.u32(rendition.init_len);
                    encoder.u16(rendition.segment_lengths.len() as u16);
                    for length in &rendition.segment_lengths {
                        encoder.u32(*length);
                    }
                }
            }
            Self::Object {
                content_type,
                length,
            } => {
                encoder.u8(2);
                encoder.string(content_type)?;
                encoder.u64(*length);
            }
        }
        Ok(())
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, ContractError> {
        match decoder.u8()? {
            1 => {
                let count = usize::from(decoder.u8()?);
                if !(1..=MAX_RENDITIONS).contains(&count) {
                    return Err(ContractError::InvalidField("renditions"));
                }
                let mut renditions = Vec::with_capacity(count);
                for _ in 0..count {
                    let kind = decoder.u8()?;
                    let init_len = decoder.u32()?;
                    let count = usize::from(decoder.u16()?);
                    if !(1..=SEAL_DASH_MAX_SEGMENTS_PER_RENDITION).contains(&count) {
                        return Err(ContractError::InvalidField("segment_lengths"));
                    }
                    let segment_lengths = (0..count)
                        .map(|_| decoder.u32())
                        .collect::<Result<Vec<_>, _>>()?;
                    renditions.push(ClearRenditionV1 {
                        kind,
                        init_len,
                        segment_lengths,
                    });
                }
                Ok(Self::DashV2 { renditions })
            }
            2 => Ok(Self::Object {
                content_type: decoder.string("content_type", MAX_CONTENT_TYPE_BYTES)?,
                length: decoder.u64()?,
            }),
            _ => Err(ContractError::InvalidField("clear_layout")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintRequestV1 {
    pub pool: PoolDidV1,
    pub epoch: CustodyEpochIdentityV1,
    pub minter_issuer: RuntimeOperationIssuerKeyV1,
    pub content_access_id: ContentAccessIdV1,
    pub clear_layout: ClearLayoutV1,
    pub request_nonce: [u8; 16],
    pub issued_at: u64,
    pub expires_at: u64,
}

impl CanonicalBody for MintRequestV1 {
    const DOMAIN: &'static str = "elastos.protected-content.mint-request-statement/v1";

    fn validate(&self) -> Result<(), ContractError> {
        self.epoch.canonical_bytes()?;
        self.clear_layout.byte_len()?;
        if self.request_nonce == [0; 16] {
            return Err(ContractError::InvalidField("mint_request.nonce"));
        }
        validate_time_window(
            self.issued_at,
            self.expires_at,
            SEAL_SESSION_GRACE_SECS,
            "mint_request.window",
        )
    }

    fn encode_fields(&self, encoder: &mut Encoder) -> Result<(), ContractError> {
        encoder.fixed(self.pool.issuer().as_bytes());
        encoder.nested(&self.epoch)?;
        encoder.fixed(self.minter_issuer.as_bytes());
        encoder.fixed(self.content_access_id.as_bytes());
        self.clear_layout.encode(encoder)?;
        encoder.u64(self.clear_layout.byte_len()?);
        encoder.fixed(&self.request_nonce);
        encoder.u64(self.issued_at);
        encoder.u64(self.expires_at);
        Ok(())
    }

    fn decode_fields(decoder: &mut Decoder<'_>) -> Result<Self, ContractError> {
        let pool = PoolDidV1::from_issuer(CustodyEpochIssuerKeyV1::new(decoder.fixed()?)?);
        let epoch = decoder.nested("mint_request.epoch")?;
        let minter_issuer = RuntimeOperationIssuerKeyV1::new(decoder.fixed()?)?;
        let content_access_id = ContentAccessIdV1::new(decoder.fixed()?)?;
        let clear_layout = ClearLayoutV1::decode(decoder)?;
        if decoder.u64()? != clear_layout.byte_len()? {
            return Err(ContractError::InvalidField(
                "mint_request.total_clear_bytes",
            ));
        }
        Ok(Self {
            pool,
            epoch,
            minter_issuer,
            content_access_id,
            clear_layout,
            request_nonce: decoder.fixed()?,
            issued_at: decoder.u64()?,
            expires_at: decoder.u64()?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedMintRequestV1 {
    request: MintRequestV1,
    runtime_signature: [u8; 64],
}

impl SignedMintRequestV1 {
    /// The encoded request fields. Use `verify_for_sealer` before trusting them.
    pub fn statement(&self) -> &MintRequestV1 {
        &self.request
    }

    pub fn new(request: MintRequestV1, runtime_signature: [u8; 64]) -> Result<Self, ContractError> {
        CanonicalBody::validate(&request)?;
        Ok(Self {
            request,
            runtime_signature,
        })
    }

    pub fn verify_for_sealer(
        &self,
        descriptor: &SignedPoolDescriptorAnyV1,
        sealer: NodePublicKey,
        now: u64,
    ) -> Result<&MintRequestV1, PoolContractError> {
        let request = &self.request;
        let key = validate_ed25519_public_key(*request.minter_issuer.as_bytes(), "minter_issuer")
            .map_err(|_| PoolContractError::Signature)?;
        key.verify_strict(
            &request.canonical_bytes()?,
            &Signature::from_bytes(&self.runtime_signature),
        )
        .map_err(|_| PoolContractError::Signature)?;
        require_active_seal_window(request.issued_at, request.expires_at, now)?;

        let verified = descriptor.verify(now)?;
        verified.admits_new_release()?;
        if verified.pool() != &request.pool {
            return Err(PoolContractError::IssuerMismatch);
        }
        if !verified
            .mint_policy()
            .admitted_minters
            .contains(&request.minter_issuer)
        {
            return Err(ContractError::InvalidField("mint_request.minter_admission").into());
        }
        let bundle = descriptor
            .epochs()
            .iter()
            .find(|epoch| {
                epoch
                    .epoch_identity()
                    .is_ok_and(|identity| identity == request.epoch)
            })
            .ok_or(PoolContractError::EpochMismatch)?;
        bundle.validate_for_provisioning(request.pool.issuer(), now)?;
        require_epoch_sealer(&verified, bundle, sealer)?;
        Ok(request)
    }
}

fn require_epoch_sealer(
    descriptor: &VerifiedPoolDescriptorV1,
    bundle: &PoolEpochBundleV1,
    sealer: NodePublicKey,
) -> Result<(), PoolContractError> {
    if !bundle
        .signed_epoch()
        .statement()
        .nodes()
        .iter()
        .any(|node| node.node_public_key() == sealer)
    {
        return Err(PoolContractError::NotMember);
    }
    if !descriptor
        .member(sealer)
        .ok_or(PoolContractError::NotMember)?
        .roles()
        .seal
    {
        return Err(PoolContractError::RoleMissing);
    }
    Ok(())
}

fn require_active_seal_window(
    issued_at: u64,
    expires_at: u64,
    now: u64,
) -> Result<(), PoolContractError> {
    validate_active(issued_at, expires_at, now).map_err(|error| match error {
        RightsError::NotYetValid => PoolContractError::NotYetValid,
        _ => PoolContractError::Expired,
    })
}

/// The selected node signs this before the minter uploads any file bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealSessionAttestationV1 {
    pub pool: PoolDidV1,
    pub epoch: CustodyEpochIdentityV1,
    pub sealer_node_public_key: NodePublicKey,
    pub seal_session_id: [u8; 16],
    pub descriptor_digest: Digest32,
    pub seal_session_public_key: RecipientPublicKeyBytesV1,
    pub mint_request_hash: Digest32,
    pub issued_at: u64,
    pub expires_at: u64,
}

impl CanonicalBody for SealSessionAttestationV1 {
    const DOMAIN: &'static str = "elastos.protected-content.seal-session-attestation-statement/v1";

    fn validate(&self) -> Result<(), ContractError> {
        self.epoch.canonical_bytes()?;
        if self.seal_session_id == [0; 16] {
            return Err(ContractError::InvalidField(
                "seal_session_attestation.session_id",
            ));
        }
        validate_time_window(
            self.issued_at,
            self.expires_at,
            SEAL_SESSION_GRACE_SECS,
            "seal_session_attestation.window",
        )
    }

    fn encode_fields(&self, encoder: &mut Encoder) -> Result<(), ContractError> {
        encoder.fixed(self.pool.issuer().as_bytes());
        encoder.nested(&self.epoch)?;
        encoder.fixed(self.sealer_node_public_key.as_bytes());
        encoder.fixed(&self.seal_session_id);
        encoder.fixed(self.descriptor_digest.as_bytes());
        encoder.fixed(self.seal_session_public_key.as_bytes());
        encoder.fixed(self.mint_request_hash.as_bytes());
        encoder.u64(self.issued_at);
        encoder.u64(self.expires_at);
        Ok(())
    }

    fn decode_fields(decoder: &mut Decoder<'_>) -> Result<Self, ContractError> {
        Ok(Self {
            pool: PoolDidV1::from_issuer(CustodyEpochIssuerKeyV1::new(decoder.fixed()?)?),
            epoch: decoder.nested("seal_session_attestation.epoch")?,
            sealer_node_public_key: NodePublicKey::new(decoder.fixed()?)?,
            seal_session_id: decoder.fixed()?,
            descriptor_digest: Digest32::new(decoder.fixed()?),
            seal_session_public_key: RecipientPublicKeyBytesV1::new(decoder.fixed()?)?,
            mint_request_hash: Digest32::new(decoder.fixed()?),
            issued_at: decoder.u64()?,
            expires_at: decoder.u64()?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedSealSessionAttestationV1 {
    statement: SealSessionAttestationV1,
    node_signature: [u8; 64],
}

impl SignedSealSessionAttestationV1 {
    pub const fn statement(&self) -> &SealSessionAttestationV1 {
        &self.statement
    }

    pub const fn sealer_node_public_key(&self) -> NodePublicKey {
        self.statement.sealer_node_public_key
    }

    pub const fn session_id(&self) -> [u8; 16] {
        self.statement.seal_session_id
    }

    pub fn new(
        statement: SealSessionAttestationV1,
        node_signature: [u8; 64],
    ) -> Result<Self, ContractError> {
        CanonicalBody::validate(&statement)?;
        Ok(Self {
            statement,
            node_signature,
        })
    }

    /// The caller supplies the key of the selected node from the verified
    /// route, never a key supplied by the unauthenticated reply itself.
    pub fn verify_for_upload(
        &self,
        signed_request: &SignedMintRequestV1,
        descriptor: &SignedPoolDescriptorAnyV1,
        expected_sealer: NodePublicKey,
        expected_session_id: [u8; 16],
        now: u64,
    ) -> Result<&RecipientPublicKeyBytesV1, PoolContractError> {
        let statement = &self.statement;
        let request = signed_request.verify_for_sealer(descriptor, expected_sealer, now)?;
        if statement.sealer_node_public_key != expected_sealer
            || statement.seal_session_id != expected_session_id
            || statement.descriptor_digest != descriptor.canonical_hash()?
            || statement.pool != request.pool
            || statement.epoch != request.epoch
            || statement.mint_request_hash != signed_request.canonical_hash()?
        {
            return Err(ContractError::InvalidField("seal_session_attestation.binding").into());
        }
        if statement.issued_at < request.issued_at
            || statement.expires_at > request.expires_at.min(descriptor.expires_at())
        {
            return Err(ContractError::InvalidField("seal_session_attestation.window").into());
        }
        require_active_seal_window(statement.issued_at, statement.expires_at, now)?;
        let key =
            validate_ed25519_public_key(*expected_sealer.as_bytes(), "sealer_node_public_key")
                .map_err(|_| PoolContractError::Signature)?;
        key.verify_strict(
            &statement.canonical_bytes()?,
            &Signature::from_bytes(&self.node_signature),
        )
        .map_err(|_| PoolContractError::Signature)?;
        Ok(&statement.seal_session_public_key)
    }
}

impl CanonicalBody for SignedSealSessionAttestationV1 {
    const DOMAIN: &'static str = "elastos.protected-content.seal-session-attestation/v1";

    fn validate(&self) -> Result<(), ContractError> {
        CanonicalBody::validate(&self.statement)
    }

    fn encode_fields(&self, encoder: &mut Encoder) -> Result<(), ContractError> {
        encoder.nested(&self.statement)?;
        encoder.fixed(&self.node_signature);
        Ok(())
    }

    fn decode_fields(decoder: &mut Decoder<'_>) -> Result<Self, ContractError> {
        Self::new(
            decoder.nested("seal_session_attestation")?,
            decoder.fixed()?,
        )
    }
}

impl CanonicalBody for SignedMintRequestV1 {
    const DOMAIN: &'static str = "elastos.protected-content.mint-request/v1";

    fn validate(&self) -> Result<(), ContractError> {
        CanonicalBody::validate(&self.request)
    }

    fn encode_fields(&self, encoder: &mut Encoder) -> Result<(), ContractError> {
        encoder.nested(&self.request)?;
        encoder.fixed(&self.runtime_signature);
        Ok(())
    }

    fn decode_fields(decoder: &mut Decoder<'_>) -> Result<Self, ContractError> {
        Self::new(decoder.nested("mint_request")?, decoder.fixed()?)
    }
}

/// Admission for one verified encrypted asset. Each node's provisioning
/// statement still binds its own share record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolProvisioningAuthorizationV1 {
    pub pool: PoolDidV1,
    pub epoch: CustodyEpochIdentityV1,
    pub sealer_node_public_key: NodePublicKey,
    pub sealer_runtime_issuer: RuntimeOperationIssuerKeyV1,
    pub key_envelope: KeyEnvelopeIdentityV1,
    pub content_access_id: ContentAccessIdV1,
    pub mint_request_hash: Digest32,
    pub issued_at: u64,
    pub expires_at: u64,
}

impl CanonicalBody for PoolProvisioningAuthorizationV1 {
    const DOMAIN: &'static str =
        "elastos.protected-content.pool-provisioning-authorization-statement/v1";

    fn validate(&self) -> Result<(), ContractError> {
        self.key_envelope.canonical_bytes()?;
        if self.epoch != self.key_envelope.custody_epoch() {
            return Err(ContractError::InvalidField(
                "pool_provisioning_authorization.epoch",
            ));
        }
        validate_time_window(
            self.issued_at,
            self.expires_at,
            MAX_RUNTIME_CUSTODY_PROVISIONING_LIFETIME_SECS,
            "pool_provisioning_authorization.window",
        )
    }

    fn encode_fields(&self, encoder: &mut Encoder) -> Result<(), ContractError> {
        encoder.fixed(self.pool.issuer().as_bytes());
        encoder.nested(&self.epoch)?;
        encoder.fixed(self.sealer_node_public_key.as_bytes());
        encoder.fixed(self.sealer_runtime_issuer.as_bytes());
        encoder.nested(&self.key_envelope)?;
        encoder.fixed(self.content_access_id.as_bytes());
        encoder.fixed(self.mint_request_hash.as_bytes());
        encoder.u64(self.issued_at);
        encoder.u64(self.expires_at);
        Ok(())
    }

    fn decode_fields(decoder: &mut Decoder<'_>) -> Result<Self, ContractError> {
        Ok(Self {
            pool: PoolDidV1::from_issuer(CustodyEpochIssuerKeyV1::new(decoder.fixed()?)?),
            epoch: decoder.nested("pool_provisioning_authorization.epoch")?,
            sealer_node_public_key: NodePublicKey::new(decoder.fixed()?)?,
            sealer_runtime_issuer: RuntimeOperationIssuerKeyV1::new(decoder.fixed()?)?,
            key_envelope: decoder.nested("pool_provisioning_authorization.key_envelope")?,
            content_access_id: ContentAccessIdV1::new(decoder.fixed()?)?,
            mint_request_hash: Digest32::new(decoder.fixed()?),
            issued_at: decoder.u64()?,
            expires_at: decoder.u64()?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedPoolProvisioningAuthorizationV1 {
    statement: PoolProvisioningAuthorizationV1,
    node_signature: [u8; 64],
}

impl SignedPoolProvisioningAuthorizationV1 {
    pub fn statement(&self) -> &PoolProvisioningAuthorizationV1 {
        &self.statement
    }

    pub fn new(
        statement: PoolProvisioningAuthorizationV1,
        node_signature: [u8; 64],
    ) -> Result<Self, ContractError> {
        CanonicalBody::validate(&statement)?;
        Ok(Self {
            statement,
            node_signature,
        })
    }

    /// Bind the share authorization to the minter's original signed request.
    /// A correctly signed sealer response for a different request or KID
    /// cannot authorize a write to this asset's slot.
    pub fn verify_for_mint_request(
        &self,
        descriptor: &SignedPoolDescriptorAnyV1,
        request: &SignedMintRequestV1,
        expected_envelope: &KeyEnvelopeIdentityV1,
        now: u64,
    ) -> Result<
        (
            &PoolProvisioningAuthorizationV1,
            RuntimeOperationIssuerKeyV1,
        ),
        PoolContractError,
    > {
        let statement = self.verify_for_provisioning(descriptor, expected_envelope, now)?;
        let minter =
            request.verify_for_sealer(descriptor, statement.sealer_node_public_key, now)?;
        if statement.mint_request_hash != request.canonical_hash()?
            || statement.content_access_id != minter.content_access_id
            || statement.pool != minter.pool
            || statement.epoch != minter.epoch
            || statement.issued_at < minter.issued_at
            || statement.expires_at > minter.expires_at.min(descriptor.expires_at())
        {
            return Err(ContractError::InvalidField(
                "pool_provisioning_authorization.mint_request",
            )
            .into());
        }
        Ok((statement, minter.minter_issuer))
    }

    fn verify_for_provisioning(
        &self,
        descriptor: &SignedPoolDescriptorAnyV1,
        expected_envelope: &KeyEnvelopeIdentityV1,
        now: u64,
    ) -> Result<&PoolProvisioningAuthorizationV1, PoolContractError> {
        let statement = &self.statement;
        if &statement.key_envelope != expected_envelope {
            return Err(ContractError::InvalidField(
                "pool_provisioning_authorization.key_envelope",
            )
            .into());
        }
        require_active_seal_window(statement.issued_at, statement.expires_at, now)?;
        let verified = descriptor.verify(now)?;
        verified.admits_new_release()?;
        if verified.pool() != &statement.pool {
            return Err(PoolContractError::IssuerMismatch);
        }
        let bundle = verified.epoch_for_provisioning(expected_envelope, now)?;
        bundle
            .signed_epoch()
            .verify_against_key_envelope(expected_envelope)
            .map_err(|_| {
                ContractError::InvalidField("pool_provisioning_authorization.key_envelope")
            })?;
        let sealer = statement.sealer_node_public_key;
        require_epoch_sealer(&verified, bundle, sealer)?;
        let key = validate_ed25519_public_key(*sealer.as_bytes(), "sealer_node_public_key")
            .map_err(|_| PoolContractError::Signature)?;
        key.verify_strict(
            &statement.canonical_bytes()?,
            &Signature::from_bytes(&self.node_signature),
        )
        .map_err(|_| PoolContractError::Signature)?;
        Ok(statement)
    }
}

impl CanonicalBody for SignedPoolProvisioningAuthorizationV1 {
    const DOMAIN: &'static str = "elastos.protected-content.pool-provisioning-authorization/v1";

    fn validate(&self) -> Result<(), ContractError> {
        CanonicalBody::validate(&self.statement)
    }

    fn encode_fields(&self, encoder: &mut Encoder) -> Result<(), ContractError> {
        encoder.nested(&self.statement)?;
        encoder.fixed(&self.node_signature);
        Ok(())
    }

    fn decode_fields(decoder: &mut Decoder<'_>) -> Result<Self, ContractError> {
        Self::new(
            decoder.nested("pool_provisioning_authorization")?,
            decoder.fixed()?,
        )
    }
}

/// Retained evidence for the remote share's original admission. Keeping the
/// signed descriptor allows reload to verify membership at the accepted time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteShareAdmissionV1 {
    pub descriptor: SignedPoolDescriptorAnyV1,
    pub request: SignedMintRequestV1,
    pub authorization: SignedPoolProvisioningAuthorizationV1,
}

impl CanonicalBody for RemoteShareAdmissionV1 {
    const DOMAIN: &'static str = "elastos.protected-content.remote-share-admission/v1";

    fn validate(&self) -> Result<(), ContractError> {
        Ok(())
    }

    fn encode_fields(&self, encoder: &mut Encoder) -> Result<(), ContractError> {
        encoder.nested(&self.descriptor)?;
        encoder.nested(&self.request)?;
        encoder.nested(&self.authorization)?;
        Ok(())
    }

    fn decode_fields(decoder: &mut Decoder<'_>) -> Result<Self, ContractError> {
        Ok(Self {
            descriptor: decoder.nested("remote_share_admission.descriptor")?,
            request: decoder.nested("remote_share_admission.request")?,
            authorization: decoder.nested("remote_share_admission.authorization")?,
        })
    }
}

/// What a sealer returns after staging and provisioning one encrypted item.
/// The media and availability layers decode and verify their own evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealCompletedV1 {
    pub pool: PoolDidV1,
    pub epoch: CustodyEpochIdentityV1,
    pub descriptor_digest: Digest32,
    pub sealer_node_public_key: NodePublicKey,
    pub sealer_device_did: String,
    pub content_publisher_did: String,
    pub mint_request_hash: Digest32,
    pub content_access_id: ContentAccessIdV1,
    pub key_envelope: KeyEnvelopeIdentityV1,
    pub content_identity: Vec<u8>,
    pub content_key_commitment: Digest32,
    pub package_cid: String,
    /// Strictly sorted by relative path, with one entry per path.
    pub file_cids: Vec<(String, String)>,
    pub availability_receipt: Vec<u8>,
    pub completed_at: u64,
}

impl CanonicalBody for SealCompletedV1 {
    const DOMAIN: &'static str = "elastos.protected-content.seal-completed-statement/v1";

    fn validate(&self) -> Result<(), ContractError> {
        self.key_envelope.canonical_bytes()?;
        if self.epoch != self.key_envelope.custody_epoch() {
            return Err(ContractError::InvalidField("seal_completed.epoch"));
        }
        validate_ascii_identifier(
            &self.sealer_device_did,
            "seal_completed.peer",
            MAX_SEAL_DID_BYTES,
        )?;
        validate_ascii_identifier(
            &self.content_publisher_did,
            "seal_completed.publisher",
            MAX_SEAL_DID_BYTES,
        )?;
        validate_ascii_identifier(
            &self.package_cid,
            "seal_completed.package",
            MAX_SEAL_CID_BYTES,
        )?;
        if self.content_identity.is_empty()
            || self.content_identity.len() > MAX_SEAL_CONTENT_IDENTITY_BYTES
        {
            return Err(ContractError::InvalidField(
                "seal_completed.content_identity",
            ));
        }
        if self.availability_receipt.is_empty()
            || self.availability_receipt.len() > MAX_SEAL_AVAILABILITY_BYTES
        {
            return Err(ContractError::InvalidField("seal_completed.availability"));
        }
        if self.file_cids.is_empty() || self.file_cids.len() > MAX_SEAL_FILES {
            return Err(ContractError::InvalidField("seal_completed.files"));
        }
        for (path, cid) in &self.file_cids {
            validate_ascii_identifier(path, "seal_completed.file_path", MAX_SEAL_PATH_BYTES)?;
            if path.contains('\\') || path.split('/').any(|part| matches!(part, "" | "." | "..")) {
                return Err(ContractError::InvalidField("seal_completed.file_path"));
            }
            validate_ascii_identifier(cid, "seal_completed.file_cid", MAX_SEAL_CID_BYTES)?;
        }
        if self
            .file_cids
            .windows(2)
            .any(|files| files[0].0 >= files[1].0)
        {
            return Err(ContractError::InvalidField("seal_completed.file_order"));
        }
        Ok(())
    }

    fn encode_fields(&self, encoder: &mut Encoder) -> Result<(), ContractError> {
        encoder.fixed(self.pool.issuer().as_bytes());
        encoder.nested(&self.epoch)?;
        encoder.fixed(self.descriptor_digest.as_bytes());
        encoder.fixed(self.sealer_node_public_key.as_bytes());
        encoder.string(&self.sealer_device_did)?;
        encoder.string(&self.content_publisher_did)?;
        encoder.fixed(self.mint_request_hash.as_bytes());
        encoder.fixed(self.content_access_id.as_bytes());
        encoder.nested(&self.key_envelope)?;
        encoder.bytes(&self.content_identity)?;
        encoder.fixed(self.content_key_commitment.as_bytes());
        encoder.string(&self.package_cid)?;
        encoder.u16(self.file_cids.len() as u16);
        for (path, cid) in &self.file_cids {
            encoder.string(path)?;
            encoder.string(cid)?;
        }
        encoder.bytes(&self.availability_receipt)?;
        encoder.u64(self.completed_at);
        Ok(())
    }

    fn decode_fields(decoder: &mut Decoder<'_>) -> Result<Self, ContractError> {
        let pool = PoolDidV1::from_issuer(CustodyEpochIssuerKeyV1::new(decoder.fixed()?)?);
        let epoch = decoder.nested("seal_completed.epoch")?;
        let descriptor_digest = Digest32::new(decoder.fixed()?);
        let sealer_node_public_key = NodePublicKey::new(decoder.fixed()?)?;
        let sealer_device_did = decoder.string("seal_completed.peer", MAX_SEAL_DID_BYTES)?;
        let content_publisher_did =
            decoder.string("seal_completed.publisher", MAX_SEAL_DID_BYTES)?;
        let mint_request_hash = Digest32::new(decoder.fixed()?);
        let content_access_id = ContentAccessIdV1::new(decoder.fixed()?)?;
        let key_envelope = decoder.nested("seal_completed.key_envelope")?;
        let content_identity = decoder.bytes(
            "seal_completed.content_identity",
            MAX_SEAL_CONTENT_IDENTITY_BYTES,
        )?;
        let content_key_commitment = Digest32::new(decoder.fixed()?);
        let package_cid = decoder.string("seal_completed.package", MAX_SEAL_CID_BYTES)?;
        let files = usize::from(decoder.u16()?);
        if files == 0 || files > MAX_SEAL_FILES {
            return Err(ContractError::InvalidField("seal_completed.files"));
        }
        let mut file_cids = Vec::with_capacity(files);
        for _ in 0..files {
            file_cids.push((
                decoder.string("seal_completed.file_path", MAX_SEAL_PATH_BYTES)?,
                decoder.string("seal_completed.file_cid", MAX_SEAL_CID_BYTES)?,
            ));
        }
        Ok(Self {
            pool,
            epoch,
            descriptor_digest,
            sealer_node_public_key,
            sealer_device_did,
            content_publisher_did,
            mint_request_hash,
            content_access_id,
            key_envelope,
            content_identity,
            content_key_commitment,
            package_cid,
            file_cids,
            availability_receipt: decoder
                .bytes("seal_completed.availability", MAX_SEAL_AVAILABILITY_BYTES)?,
            completed_at: decoder.u64()?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedSealCompletedV1 {
    statement: SealCompletedV1,
    node_signature: [u8; 64],
}

impl SignedSealCompletedV1 {
    pub fn new(statement: SealCompletedV1, signature: [u8; 64]) -> Result<Self, ContractError> {
        CanonicalBody::validate(&statement)?;
        Ok(Self {
            statement,
            node_signature: signature,
        })
    }

    /// Authenticate archived evidence against the exact signed descriptor and
    /// independently resolved asset. No timestamp in this receipt can grant
    /// current authority or substitute for an availability or chain check.
    pub fn verify_historical(
        &self,
        descriptor: &SignedPoolDescriptorAnyV1,
        expected_envelope: &KeyEnvelopeIdentityV1,
        expected_content_access_id: ContentAccessIdV1,
    ) -> Result<&SealCompletedV1, PoolContractError> {
        let SignedPoolDescriptorAnyV1::V3(v3) = descriptor else {
            return Err(PoolContractError::TrustRequired);
        };
        let statement = &self.statement;
        if &statement.key_envelope != expected_envelope
            || statement.content_access_id != expected_content_access_id
            || &statement.pool != descriptor.pool()
            || statement.descriptor_digest != descriptor.canonical_hash()?
        {
            return Err(ContractError::InvalidField("seal_completed.binding").into());
        }
        let verified = v3.verify_historical()?;
        verified.admits_new_release()?;
        let bundle = verified
            .epoch_for(expected_envelope)
            .ok_or(PoolContractError::EpochMismatch)?;
        bundle
            .signed_epoch()
            .verify_against_key_envelope(expected_envelope)
            .map_err(|_| PoolContractError::EpochMismatch)?;
        let sealer = statement.sealer_node_public_key;
        require_epoch_sealer(&verified, bundle, sealer)?;
        if descriptor.member_peer_did(sealer) != Some(statement.sealer_device_did.as_str()) {
            return Err(ContractError::InvalidField("seal_completed.peer").into());
        }
        let key = validate_ed25519_public_key(*sealer.as_bytes(), "seal_completed_node")
            .map_err(|_| PoolContractError::Signature)?;
        key.verify_strict(
            &statement.canonical_bytes()?,
            &Signature::from_bytes(&self.node_signature),
        )
        .map_err(|_| PoolContractError::Signature)?;
        Ok(statement)
    }

    /// Fresh completion must still match the original request and the chosen
    /// sealer, with admission checked at the caller's own clock.
    pub fn verify_for_request_at<'request>(
        &self,
        descriptor: &SignedPoolDescriptorAnyV1,
        request: &'request SignedMintRequestV1,
        expected_sealer: NodePublicKey,
        now: u64,
    ) -> Result<(&SealCompletedV1, &'request ClearLayoutV1), PoolContractError> {
        request.verify_for_sealer(descriptor, expected_sealer, now)?;
        self.verify_for_recorded_request(descriptor, request, expected_sealer)
    }

    /// Recheck the identity of a completion already admitted during upload.
    /// This permits archival replay and grants no current dispatch authority.
    pub fn verify_for_recorded_request<'request>(
        &self,
        descriptor: &SignedPoolDescriptorAnyV1,
        request: &'request SignedMintRequestV1,
        expected_sealer: NodePublicKey,
    ) -> Result<(&SealCompletedV1, &'request ClearLayoutV1), PoolContractError> {
        let mint = request.statement();
        let statement = self.verify_historical(
            descriptor,
            &self.statement.key_envelope,
            mint.content_access_id,
        )?;
        if statement.mint_request_hash != request.canonical_hash()?
            || statement.sealer_node_public_key != expected_sealer
            || statement.pool != mint.pool
            || statement.epoch != mint.epoch
        {
            return Err(ContractError::InvalidField("seal_completed.mint_request").into());
        }
        Ok((statement, &mint.clear_layout))
    }
}

impl CanonicalBody for SignedSealCompletedV1 {
    const DOMAIN: &'static str = "elastos.protected-content.seal-completed/v1";

    fn validate(&self) -> Result<(), ContractError> {
        CanonicalBody::validate(&self.statement)
    }

    fn encode_fields(&self, encoder: &mut Encoder) -> Result<(), ContractError> {
        // A full DASH file table may exceed the canonical nested-blob limit.
        self.statement.encode_fields(encoder)?;
        encoder.fixed(&self.node_signature);
        Ok(())
    }

    fn decode_fields(decoder: &mut Decoder<'_>) -> Result<Self, ContractError> {
        Self::new(SealCompletedV1::decode_fields(decoder)?, decoder.fixed()?)
    }
}

/// The position within the signed clear layout. DASH rendition numbers are
/// the signed kinds (1 for video and 2 for audio).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ClearPartIndexV1 {
    DashInit { rendition: u8 },
    DashSegment { rendition: u8, index: u32 },
    ObjectChunk { index: u32 },
}

impl ClearLayoutV1 {
    /// Ordered parts and their signed plaintext lengths.
    pub fn parts(&self) -> Result<Vec<(ClearPartIndexV1, u64)>, ContractError> {
        self.byte_len()?;
        Ok(match self {
            Self::Object { length, .. } => (0..length.div_ceil(SEAL_OBJECT_CHUNK_CLEAR_BYTES))
                .map(|index| {
                    let bytes = (length - index * SEAL_OBJECT_CHUNK_CLEAR_BYTES)
                        .min(SEAL_OBJECT_CHUNK_CLEAR_BYTES);
                    (
                        ClearPartIndexV1::ObjectChunk {
                            index: index as u32,
                        },
                        bytes,
                    )
                })
                .collect(),
            Self::DashV2 { renditions } => {
                let mut parts = Vec::new();
                parts.extend(renditions.iter().map(|entry| {
                    (
                        ClearPartIndexV1::DashInit {
                            rendition: entry.kind,
                        },
                        u64::from(entry.init_len),
                    )
                }));
                for entry in renditions {
                    parts.extend(
                        entry
                            .segment_lengths
                            .iter()
                            .enumerate()
                            .map(|(index, size)| {
                                (
                                    ClearPartIndexV1::DashSegment {
                                        rendition: entry.kind,
                                        index: index as u32,
                                    },
                                    u64::from(*size),
                                )
                            }),
                    );
                }
                parts
            }
        })
    }

    /// Zero-based order of the complete clear parts in this upload.
    pub fn part_position(&self, part: ClearPartIndexV1) -> Option<u64> {
        match (self, part) {
            (Self::Object { length, .. }, ClearPartIndexV1::ObjectChunk { index }) => {
                let index = u64::from(index);
                (index < length.div_ceil(SEAL_OBJECT_CHUNK_CLEAR_BYTES)).then_some(index)
            }
            (Self::DashV2 { renditions }, ClearPartIndexV1::DashInit { rendition }) => renditions
                .iter()
                .position(|entry| entry.kind == rendition)
                .map(|index| index as u64),
            (Self::DashV2 { renditions }, ClearPartIndexV1::DashSegment { rendition, index }) => {
                let mut position = renditions.len() as u64;
                for entry in renditions {
                    let count = entry.segment_lengths.len() as u64;
                    if entry.kind == rendition {
                        return (u64::from(index) < count).then_some(position + u64::from(index));
                    }
                    position += count;
                }
                None
            }
            _ => None,
        }
    }
}

/// Authenticated data for one encrypted upload piece. The receiver checks
/// its signed request, expected part, and exact next piece before accepting it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MintPieceAadV1 {
    pub mint_request_hash: Digest32,
    pub part: ClearPartIndexV1,
    pub piece: u16,
    pub piece_count: u16,
}

impl CanonicalBody for MintPieceAadV1 {
    const DOMAIN: &'static str = "elastos.protected-content.mint-piece-aad/v1";

    fn validate(&self) -> Result<(), ContractError> {
        let valid_part = match self.part {
            ClearPartIndexV1::DashInit { rendition } => matches!(rendition, 1 | 2),
            ClearPartIndexV1::DashSegment { rendition, index } => {
                matches!(rendition, 1 | 2)
                    && (index as usize) < SEAL_DASH_MAX_SEGMENTS_PER_RENDITION
            }
            ClearPartIndexV1::ObjectChunk { .. } => true,
        };
        if !valid_part {
            return Err(ContractError::InvalidField("mint_piece.part"));
        }
        let maximum_pieces = (MAX_MEDIA_PART_BYTES as usize) / SEAL_PIECE_MAX_CLEAR_BYTES;
        if self.piece >= self.piece_count || usize::from(self.piece_count) > maximum_pieces {
            return Err(ContractError::InvalidField("mint_piece.piece"));
        }
        Ok(())
    }

    fn encode_fields(&self, encoder: &mut Encoder) -> Result<(), ContractError> {
        encoder.fixed(self.mint_request_hash.as_bytes());
        match self.part {
            ClearPartIndexV1::DashInit { rendition } => {
                encoder.u8(1);
                encoder.u8(rendition);
            }
            ClearPartIndexV1::DashSegment { rendition, index } => {
                encoder.u8(2);
                encoder.u8(rendition);
                encoder.u32(index);
            }
            ClearPartIndexV1::ObjectChunk { index } => {
                encoder.u8(3);
                encoder.u32(index);
            }
        }
        encoder.u16(self.piece);
        encoder.u16(self.piece_count);
        Ok(())
    }

    fn decode_fields(decoder: &mut Decoder<'_>) -> Result<Self, ContractError> {
        let mint_request_hash = Digest32::new(decoder.fixed()?);
        let part = match decoder.u8()? {
            1 => ClearPartIndexV1::DashInit {
                rendition: decoder.u8()?,
            },
            2 => ClearPartIndexV1::DashSegment {
                rendition: decoder.u8()?,
                index: decoder.u32()?,
            },
            3 => ClearPartIndexV1::ObjectChunk {
                index: decoder.u32()?,
            },
            _ => return Err(ContractError::InvalidField("mint_piece.part")),
        };
        Ok(Self {
            mint_request_hash,
            part,
            piece: decoder.u16()?,
            piece_count: decoder.u16()?,
        })
    }
}
