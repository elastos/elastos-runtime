//! Encrypt authenticated remote DASH uploads inside the Protect provider.

use std::collections::BTreeMap;

use elastos_protected_content_contracts::{
    ClearLayoutV1, ClearPartIndexV1, CustodyEnvelopeV1, Digest32, MintPieceAadV1, NodePublicKey,
    SealSessionAttestationV1, SignedMintRequestV1, SignedPoolDescriptorAnyV1,
};
use elastos_protected_content_custody::{
    protect_validated_clear_fmp4_init_to_cenc_v2, protect_validated_clear_fmp4_segment_to_cenc_v2,
    ContentEncryptionKeyV1, CustodyError, RemoteSealUploadV1,
};
use elastos_protected_content_provider_contracts::{
    CencDashIdentityBuilderV2, CencDashMediaIdentityV2, CencDashRenditionDeclV2, CencLayoutProfile,
    CencMediaSuite, CustodyProtectionHeader, ValidatedClearFmp4MediaSessionLayoutV1,
    MAX_PROTECT_MEDIA_PART_BYTES_V1,
};

use super::{allocate_sample_ivs, random_bytes};

pub struct RemoteDashSealerV1 {
    upload: RemoteSealUploadV1,
    encryptor: DashEncryptor,
}

struct DashEncryptor {
    header: CustodyProtectionHeader,
    declared_segment_counts: BTreeMap<u8, u32>,
    renditions: BTreeMap<u8, DashRendition>,
    builder: Option<CencDashIdentityBuilderV2>,
    key: ContentEncryptionKeyV1,
    iv_prefix: [u8; 4],
    next_iv: u32,
}

struct DashRendition {
    layout: ValidatedClearFmp4MediaSessionLayoutV1,
    declaration: CencDashRenditionDeclV2,
    next_decode_time: u64,
}

impl RemoteDashSealerV1 {
    pub fn open(
        request: &SignedMintRequestV1,
        descriptor: &SignedPoolDescriptorAnyV1,
        local_node: NodePublicKey,
        now: u64,
    ) -> Result<Self, CustodyError> {
        let upload = RemoteSealUploadV1::open(request, descriptor, local_node, now)?;
        let statement = request.statement();
        let ClearLayoutV1::DashV2 { renditions } = &statement.clear_layout else {
            return Err(CustodyError::BindingMismatch("remote_dash_layout"));
        };
        let epoch = descriptor
            .epochs()
            .iter()
            .find(|bundle| {
                bundle
                    .epoch_identity()
                    .is_ok_and(|epoch| epoch == statement.epoch)
            })
            .ok_or(CustodyError::BindingMismatch("remote_dash_epoch"))?;
        let header = CustodyProtectionHeader::new(
            statement.content_access_id,
            &epoch.signed_pool().pool_identity()?,
            &statement.epoch,
            &epoch
                .signed_committee_authorization()
                .authorization_identity()?,
            CencMediaSuite::DashV2,
        );
        Ok(Self {
            upload,
            encryptor: DashEncryptor {
                header,
                declared_segment_counts: renditions
                    .iter()
                    .map(|entry| (entry.kind, entry.segment_lengths.len() as u32))
                    .collect(),
                renditions: BTreeMap::new(),
                builder: None,
                key: ContentEncryptionKeyV1::generate()?,
                iv_prefix: random_bytes().map_err(|_| CustodyError::RandomnessUnavailable)?,
                next_iv: 0,
            },
        })
    }

    pub fn attestation_statement(&self) -> Result<SealSessionAttestationV1, CustodyError> {
        self.upload.attestation_statement()
    }

    pub fn resume_upload(&mut self, now: u64) -> Result<Option<ClearPartIndexV1>, CustodyError> {
        self.upload.resume_upload(now)
    }

    /// Deliver only protected parts to the sink. The shared upload state
    /// acknowledges a part only after this sink succeeds.
    pub fn stage_piece(
        &mut self,
        aad: &MintPieceAadV1,
        part_hash: Digest32,
        sealed: &[u8],
        now: u64,
        stage_protected: impl FnOnce(ClearPartIndexV1, &[u8]) -> Result<(), CustodyError>,
    ) -> Result<Option<ClearPartIndexV1>, CustodyError> {
        let encryptor = &mut self.encryptor;
        let kid = self.upload.content_access_id();
        self.upload
            .stage_piece(aad, part_hash, sealed, now, |part, clear| {
                let protected = match part {
                    ClearPartIndexV1::DashInit { rendition } => {
                        encryptor.protect_init(kid, rendition, clear)?
                    }
                    ClearPartIndexV1::DashSegment { rendition, .. } => {
                        encryptor.protect_segment(rendition, clear)?
                    }
                    ClearPartIndexV1::ObjectChunk { .. } => {
                        return Err(CustodyError::BindingMismatch("remote_dash_layout"))
                    }
                };
                if protected.len() > MAX_PROTECT_MEDIA_PART_BYTES_V1 {
                    return Err(CustodyError::BindingMismatch(
                        "remote_dash_protected_part_length",
                    ));
                }
                stage_protected(part, &protected)
            })
    }

    /// Accept the identity rebuilt from the Runtime's encrypted staging.
    /// A failed readback leaves the upload available for another check and
    /// produces no custody shares.
    pub fn check_staged_content(
        &self,
        staged: &CencDashMediaIdentityV2,
        now: u64,
    ) -> Result<(), CustodyError> {
        self.upload.check_ready_to_finish(now)?;
        let head = self
            .encryptor
            .builder
            .as_ref()
            .ok_or(CustodyError::BindingMismatch("remote_dash_layout"))?
            .clone()
            .finish()?;
        if head != *staged {
            return Err(CustodyError::BindingMismatch(
                "remote_dash_staged_ciphertext",
            ));
        }
        Ok(())
    }

    pub fn finish(
        self,
        staged: &CencDashMediaIdentityV2,
        now: u64,
    ) -> Result<CustodyEnvelopeV1, CustodyError> {
        self.check_staged_content(staged, now)?;
        self.upload
            .provision(staged.encrypted_content(), &self.encryptor.key, now)
    }
}

impl DashEncryptor {
    fn protect_init(
        &mut self,
        kid: elastos_protected_content_contracts::ContentAccessIdV1,
        code: u8,
        clear: &[u8],
    ) -> Result<Vec<u8>, CustodyError> {
        let layout =
            ValidatedClearFmp4MediaSessionLayoutV1::new_with_profile(clear, CencLayoutProfile::V2)?;
        let rendition = layout
            .rendition()
            .ok_or(CustodyError::BindingMismatch("remote_dash_layout"))?;
        let count = *self
            .declared_segment_counts
            .get(&code)
            .filter(|_| rendition.kind().code() == code)
            .ok_or(CustodyError::BindingMismatch("remote_dash_rendition"))?;
        let protected =
            protect_validated_clear_fmp4_init_to_cenc_v2(&layout, clear, &self.header, &[])?;
        let declaration = CencDashRenditionDeclV2::from_init(
            rendition.kind(),
            rendition.timescale(),
            &protected,
            count,
        );
        self.renditions.insert(
            code,
            DashRendition {
                layout,
                declaration,
                next_decode_time: 0,
            },
        );
        if self.renditions.len() == self.declared_segment_counts.len() {
            self.builder = Some(CencDashIdentityBuilderV2::new(
                kid,
                self.renditions
                    .values()
                    .map(|rendition| rendition.declaration.clone())
                    .collect(),
            )?);
        }
        Ok(protected)
    }

    fn protect_segment(&mut self, code: u8, clear: &[u8]) -> Result<Vec<u8>, CustodyError> {
        let rendition = self
            .renditions
            .get_mut(&code)
            .ok_or(CustodyError::BindingMismatch("remote_dash_rendition"))?;
        let part = rendition.layout.validate_segment(clear)?;
        let timeline = part
            .timeline()
            .filter(|timeline| {
                timeline.decode_time == rendition.next_decode_time && timeline.duration > 0
            })
            .ok_or(CustodyError::BindingMismatch("remote_dash_timeline"))?;
        let next = timeline
            .decode_time
            .checked_add(timeline.duration)
            .ok_or(CustodyError::BindingMismatch("remote_dash_timeline"))?;
        let ivs = allocate_sample_ivs(self.iv_prefix, &mut self.next_iv, part.samples().len())
            .map_err(|_| CustodyError::BindingMismatch("remote_dash_iv_range"))?;
        let protected = protect_validated_clear_fmp4_segment_to_cenc_v2(
            &rendition.layout,
            &part,
            clear,
            &self.key,
            &ivs,
        )?;
        self.builder
            .as_mut()
            .ok_or(CustodyError::BindingMismatch("remote_dash_layout"))?
            .push_segment(&protected)?;
        rendition.next_decode_time = next;
        Ok(protected)
    }
}
