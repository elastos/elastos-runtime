//! Authenticated ingress shared by remote object and DASH protection.

use elastos_protected_content_contracts::{
    validate_custody_epoch_against_pool_at, CanonicalContract, ClearPartIndexV1, ContentAccessIdV1,
    CustodyEnvelopeV1, Digest32, EncryptedContentIdentityV1, MintPieceAadV1, NodePublicKey,
    PoolDidV1, PoolEpochBundleV1, SealSessionAttestationV1, SignedMintRequestV1,
    SignedPoolDescriptorAnyV1, SEAL_PIECE_MAX_CLEAR_BYTES,
};
use sha2::{Digest as _, Sha256};
use zeroize::{Zeroize as _, Zeroizing};

use crate::{
    open_mint_piece_v1, provision_custody_envelope, ContentEncryptionKeyV1, CustodyError,
    SealSessionSecretKeyV1,
};

/// One signed upload inside the protect provider. The caller admits the
/// authenticated peer and supplies a sink that encrypts and stages each part.
pub struct RemoteSealUploadV1 {
    request_hash: Digest32,
    descriptor_digest: Digest32,
    content_access_id: ContentAccessIdV1,
    pool: PoolDidV1,
    epoch: PoolEpochBundleV1,
    sealer: NodePublicKey,
    opened_at: u64,
    expires_at: u64,
    upload_key: SealSessionSecretKeyV1,
    parts: Vec<(ClearPartIndexV1, u64)>,
    next_part: usize,
    next_piece: u16,
    pending_hash: Option<Digest32>,
    pending: Zeroizing<Vec<u8>>,
    staging_failed: bool,
}

impl RemoteSealUploadV1 {
    pub fn open(
        signed: &SignedMintRequestV1,
        descriptor: &SignedPoolDescriptorAnyV1,
        sealer: NodePublicKey,
        now: u64,
    ) -> Result<Self, CustodyError> {
        let request = signed
            .verify_for_sealer(descriptor, sealer, now)
            .map_err(|_| CustodyError::BindingMismatch("remote_mint_request"))?;
        let epoch = descriptor
            .epochs()
            .iter()
            .find(|bundle| {
                bundle
                    .epoch_identity()
                    .is_ok_and(|identity| identity == request.epoch)
            })
            .ok_or(CustodyError::BindingMismatch("remote_mint_epoch"))?;
        Ok(Self {
            request_hash: signed.canonical_hash()?,
            descriptor_digest: descriptor.canonical_hash()?,
            content_access_id: request.content_access_id,
            pool: request.pool,
            epoch: epoch.clone(),
            sealer,
            opened_at: now,
            expires_at: request.expires_at.min(descriptor.expires_at()),
            upload_key: SealSessionSecretKeyV1::generate()?,
            parts: request.clear_layout.parts()?,
            next_part: 0,
            next_piece: 0,
            pending_hash: None,
            pending: Zeroizing::new(Vec::new()),
            staging_failed: false,
        })
    }

    pub const fn request_hash(&self) -> Digest32 {
        self.request_hash
    }

    pub const fn content_access_id(&self) -> ContentAccessIdV1 {
        self.content_access_id
    }

    pub fn attestation_statement(&self) -> Result<SealSessionAttestationV1, CustodyError> {
        let upload_key = self.upload_key.public_key()?;
        let mut hash = Sha256::new();
        hash.update(b"elastos.protected-content.remote-seal-session/v1\0");
        hash.update(upload_key.as_bytes());
        hash.update(self.request_hash.as_bytes());
        let mut seal_session_id: [u8; 16] = hash.finalize()[..16].try_into().expect("fixed digest");
        if seal_session_id == [0; 16] {
            seal_session_id[0] = 1;
        }
        Ok(SealSessionAttestationV1 {
            pool: self.pool,
            epoch: self.epoch.epoch_identity()?,
            sealer_node_public_key: self.sealer,
            seal_session_id,
            descriptor_digest: self.descriptor_digest,
            seal_session_public_key: upload_key,
            mint_request_hash: self.request_hash,
            issued_at: self.opened_at,
            expires_at: self.expires_at,
        })
    }

    pub fn resume_upload(&mut self, now: u64) -> Result<Option<ClearPartIndexV1>, CustodyError> {
        self.check_active(now)?;
        self.clear_pending();
        Ok(self.last_staged_part())
    }

    pub fn stage_piece(
        &mut self,
        aad: &MintPieceAadV1,
        part_hash: Digest32,
        sealed: &[u8],
        now: u64,
        stage_clear_part: impl FnOnce(ClearPartIndexV1, &[u8]) -> Result<(), CustodyError>,
    ) -> Result<Option<ClearPartIndexV1>, CustodyError> {
        self.check_active(now)?;
        let &(part, size) = self
            .parts
            .get(self.next_part)
            .ok_or(CustodyError::BindingMismatch("remote_upload_session"))?;
        let size = size as usize;
        let piece_count = size.div_ceil(SEAL_PIECE_MAX_CLEAR_BYTES) as u16;
        let expected = MintPieceAadV1 {
            mint_request_hash: self.request_hash,
            part,
            piece: self.next_piece,
            piece_count,
        };
        if *aad != expected || self.pending_hash.is_some_and(|hash| hash != part_hash) {
            return Err(CustodyError::BindingMismatch("remote_upload_piece"));
        }
        let clear = open_mint_piece_v1(&self.upload_key, aad, sealed)?;
        let expected_len = (size - self.pending.len()).min(SEAL_PIECE_MAX_CLEAR_BYTES);
        if clear.len() != expected_len {
            return Err(CustodyError::BindingMismatch("remote_upload_piece_length"));
        }
        if self.next_piece + 1 < piece_count {
            if self.pending.is_empty() {
                self.pending.reserve_exact(size);
            }
            self.pending.extend_from_slice(&clear);
            self.pending_hash = Some(part_hash);
            self.next_piece += 1;
            return Ok(self.last_staged_part());
        }
        let mut digest = Sha256::new();
        digest.update(&*self.pending);
        digest.update(&*clear);
        if Digest32::new(digest.finalize().into()) != part_hash {
            return Err(CustodyError::BindingMismatch("remote_upload_part_hash"));
        }
        self.staging_failed = true;
        let result = if self.pending.is_empty() {
            stage_clear_part(part, &clear)
        } else {
            self.pending.extend_from_slice(&clear);
            stage_clear_part(part, &self.pending)
        };
        self.clear_pending();
        result?;
        self.staging_failed = false;
        self.next_part += 1;
        Ok(self.last_staged_part())
    }

    pub fn check_ready_to_finish(&self, now: u64) -> Result<(), CustodyError> {
        self.check_active(now)?;
        if self.next_part != self.parts.len() {
            return Err(CustodyError::BindingMismatch("remote_upload_session"));
        }
        Ok(())
    }

    /// After independent ciphertext verification, seal the key exclusively
    /// to the exact committee fixed by the signed upload.
    pub fn provision(
        &self,
        encrypted_content: &EncryptedContentIdentityV1,
        key: &ContentEncryptionKeyV1,
        now: u64,
    ) -> Result<CustodyEnvelopeV1, CustodyError> {
        self.check_ready_to_finish(now)?;
        let authorization = self.epoch.signed_committee_authorization();
        let committee = validate_custody_epoch_against_pool_at(
            self.pool.issuer(),
            authorization.authorization_identity()?,
            self.epoch.signed_pool(),
            self.epoch.signed_epoch(),
            authorization,
            now,
        )
        .map_err(|_| CustodyError::BindingMismatch("remote_mint_epoch"))?;
        provision_custody_envelope(encrypted_content.clone(), key, &committee)
    }

    fn last_staged_part(&self) -> Option<ClearPartIndexV1> {
        self.next_part
            .checked_sub(1)
            .map(|index| self.parts[index].0)
    }

    fn check_active(&self, now: u64) -> Result<(), CustodyError> {
        if self.staging_failed || now >= self.expires_at {
            Err(CustodyError::BindingMismatch("remote_upload_session"))
        } else {
            Ok(())
        }
    }

    fn clear_pending(&mut self) {
        self.pending.zeroize();
        self.next_piece = 0;
        self.pending_hash = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seal_mint_piece_v1;
    use crate::test_support::{xwing_public_key_from_seed, NOW};
    use ed25519_dalek::Signer as _;
    use elastos_protected_content_contracts::test_fixtures::{
        node_public_key, pool_bundle, pool_descriptor_signed_by, pool_did, runtime_issuer,
        signing_key, POOL_AUTHORITY_SEED,
    };
    use elastos_protected_content_contracts::{ClearLayoutV1, ClearRenditionV1, MintRequestV1};

    #[test]
    fn dash_upload_stages_both_inits_before_any_segment_and_never_acks_failed_staging() {
        let bundle = pool_bundle(xwing_public_key_from_seed, NOW);
        let descriptor = pool_descriptor_signed_by(&bundle, 1, NOW, POOL_AUTHORITY_SEED).into();
        let statement = MintRequestV1 {
            pool: pool_did(),
            epoch: bundle.epoch_identity().unwrap(),
            minter_issuer: runtime_issuer(POOL_AUTHORITY_SEED),
            content_access_id: ContentAccessIdV1::new([0x11; 16]).unwrap(),
            clear_layout: ClearLayoutV1::DashV2 {
                renditions: vec![
                    ClearRenditionV1 {
                        kind: 1,
                        init_len: 3,
                        segment_lengths: vec![4],
                    },
                    ClearRenditionV1 {
                        kind: 2,
                        init_len: 5,
                        segment_lengths: vec![6],
                    },
                ],
            },
            request_nonce: [0x41; 16],
            issued_at: NOW,
            expires_at: NOW + 60,
        };
        let signature =
            signing_key(POOL_AUTHORITY_SEED).sign(&statement.canonical_bytes().unwrap());
        let request = SignedMintRequestV1::new(statement, signature.to_bytes()).unwrap();
        let mut upload =
            RemoteSealUploadV1::open(&request, &descriptor, node_public_key(1), NOW).unwrap();
        let public = upload
            .attestation_statement()
            .unwrap()
            .seal_session_public_key;
        let piece = |part, bytes: &[u8]| {
            let aad = MintPieceAadV1 {
                mint_request_hash: request.canonical_hash().unwrap(),
                part,
                piece: 0,
                piece_count: 1,
            };
            let sealed = seal_mint_piece_v1(&public, &aad, bytes).unwrap();
            (aad, Digest32::new(Sha256::digest(bytes).into()), sealed)
        };
        let stage_failure =
            |_: ClearPartIndexV1, _: &[u8]| panic!("unexpected part reached staging");
        let (aad, digest, sealed) = piece(
            ClearPartIndexV1::DashSegment {
                rendition: 1,
                index: 0,
            },
            b"1234",
        );
        assert!(upload
            .stage_piece(&aad, digest, &sealed, NOW, stage_failure)
            .is_err());
        assert_eq!(upload.resume_upload(NOW).unwrap(), None);
        for (part, bytes) in [
            (
                ClearPartIndexV1::DashInit { rendition: 1 },
                b"abc".as_slice(),
            ),
            (
                ClearPartIndexV1::DashInit { rendition: 2 },
                b"12345".as_slice(),
            ),
            (
                ClearPartIndexV1::DashSegment {
                    rendition: 1,
                    index: 0,
                },
                b"1234".as_slice(),
            ),
        ] {
            let (aad, digest, sealed) = piece(part, bytes);
            let ack = upload
                .stage_piece(&aad, digest, &sealed, NOW, |staged, clear| {
                    assert_eq!(staged, part);
                    assert_eq!(clear, bytes);
                    Ok(())
                })
                .unwrap();
            assert_eq!(ack, Some(part));
        }
        assert!(upload.check_ready_to_finish(NOW).is_err());
        let (aad, digest, sealed) = piece(
            ClearPartIndexV1::DashSegment {
                rendition: 2,
                index: 0,
            },
            b"123456",
        );
        assert!(matches!(
            upload.stage_piece(&aad, digest, &sealed, NOW, |_, _| Err(
                CustodyError::PayloadIo
            )),
            Err(CustodyError::PayloadIo)
        ));
        assert!(upload.resume_upload(NOW).is_err());
        assert!(upload.check_ready_to_finish(NOW).is_err());
    }
}
