//! Provider-private object encryption driven by a signed remote upload.

use elastos_protected_content_contracts::{
    ClearLayoutV1, ClearPartIndexV1, ContentAccessIdV1, CustodyEnvelopeV1, Digest32,
    EncryptedContentIdentityV1, MintPieceAadV1, NodePublicKey, SealSessionAttestationV1,
    SignedMintRequestV1, SignedPoolDescriptorAnyV1, SEAL_OBJECT_CHUNK_CLEAR_BYTES,
};

use crate::{CustodyError, PayloadSealerV1, RemoteSealUploadV1, PAYLOAD_PLAINTEXT_CHUNK_BYTES_V1};

const _: () = assert!(SEAL_OBJECT_CHUNK_CLEAR_BYTES == PAYLOAD_PLAINTEXT_CHUNK_BYTES_V1 as u64);

/// One object session, owned by the protect provider. The host and minter
/// are admitted before opening it. Clear bytes stay in the provider.
pub struct RemoteObjectSealerV1 {
    upload: RemoteSealUploadV1,
    object: PayloadSealerV1,
}

/// Verified staging and the shares encrypted to the signed committee.
pub struct RemoteSealedObjectV1 {
    pub request_hash: Digest32,
    pub content_access_id: ContentAccessIdV1,
    pub custody_envelope: CustodyEnvelopeV1,
}

impl RemoteObjectSealerV1 {
    pub fn open(
        signed: &SignedMintRequestV1,
        descriptor: &SignedPoolDescriptorAnyV1,
        sealer: NodePublicKey,
        now: u64,
    ) -> Result<(Self, Vec<u8>), CustodyError> {
        let upload = RemoteSealUploadV1::open(signed, descriptor, sealer, now)?;
        let ClearLayoutV1::Object {
            content_type,
            length,
        } = &signed.statement().clear_layout
        else {
            return Err(CustodyError::BindingMismatch("remote_object_layout"));
        };
        let (object, header) = PayloadSealerV1::open(content_type, *length)?;
        Ok((Self { upload, object }, header))
    }

    pub fn attestation_statement(&self) -> Result<SealSessionAttestationV1, CustodyError> {
        self.upload.attestation_statement()
    }

    pub fn resume_upload(&mut self, now: u64) -> Result<Option<ClearPartIndexV1>, CustodyError> {
        self.upload.resume_upload(now).map_err(object_upload_error)
    }

    /// Acknowledge a completed chunk only after its frame is staged.
    pub fn stage_piece(
        &mut self,
        aad: &MintPieceAadV1,
        part_hash: Digest32,
        sealed: &[u8],
        now: u64,
        stage_frame: impl FnOnce(&[u8]) -> Result<(), CustodyError>,
    ) -> Result<Option<ClearPartIndexV1>, CustodyError> {
        let object = &mut self.object;
        self.upload
            .stage_piece(aad, part_hash, sealed, now, |part, clear| {
                let ClearPartIndexV1::ObjectChunk { index } = part else {
                    return Err(CustodyError::BindingMismatch("remote_object_layout"));
                };
                let frame = object.seal_chunk(index, clear)?;
                stage_frame(&frame)
            })
            .map_err(object_upload_error)
    }

    /// Compare independently staged ciphertext before creating any shares.
    pub fn finish(
        self,
        staged: &EncryptedContentIdentityV1,
        now: u64,
    ) -> Result<RemoteSealedObjectV1, CustodyError> {
        self.check_ready_to_finish(now)?;
        let object = self.object.finish_unprovisioned()?;
        if object.encrypted_content_identity() != staged {
            return Err(CustodyError::BindingMismatch(
                "remote_object_staged_ciphertext",
            ));
        }
        let custody_envelope = self.upload.provision(staged, object.content_key(), now)?;
        Ok(RemoteSealedObjectV1 {
            request_hash: self.upload.request_hash(),
            content_access_id: self.upload.content_access_id(),
            custody_envelope,
        })
    }

    pub fn check_ready_to_finish(&self, now: u64) -> Result<(), CustodyError> {
        self.upload
            .check_ready_to_finish(now)
            .map_err(object_upload_error)
    }

    /// Verify an independent readback without consuming a completed upload.
    pub fn check_staged_content(
        &self,
        staged: &EncryptedContentIdentityV1,
        now: u64,
    ) -> Result<(), CustodyError> {
        self.check_ready_to_finish(now)?;
        if self.object.completed_encrypted_identity()? != *staged {
            return Err(CustodyError::BindingMismatch(
                "remote_object_staged_ciphertext",
            ));
        }
        Ok(())
    }
}

fn object_upload_error(error: CustodyError) -> CustodyError {
    match error {
        CustodyError::BindingMismatch("remote_upload_session") => {
            CustodyError::BindingMismatch("remote_object_session")
        }
        CustodyError::BindingMismatch("remote_upload_piece") => {
            CustodyError::BindingMismatch("remote_object_piece")
        }
        CustodyError::BindingMismatch("remote_upload_piece_length") => {
            CustodyError::BindingMismatch("remote_object_piece_length")
        }
        CustodyError::BindingMismatch("remote_upload_part_hash") => {
            CustodyError::BindingMismatch("remote_object_part_hash")
        }
        CustodyError::BindingMismatch("remote_mint_epoch") => {
            CustodyError::BindingMismatch("remote_object_epoch")
        }
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{xwing_public_key_from_seed, NOW};
    use crate::{
        seal_mint_piece_v1, ContentEncryptionKeyV1, PayloadChunkDecrypterV1, SealSessionSecretKeyV1,
    };
    use ed25519_dalek::Signer as _;
    use elastos_protected_content_contracts::test_fixtures::{
        node_public_key, pool_bundle, pool_descriptor_signed_by, pool_did, runtime_issuer,
        signing_key, CUSTODY_KEY_SEED_BASE, POOL_AUTHORITY_SEED,
    };
    use elastos_protected_content_contracts::{CanonicalContract, SEAL_PIECE_MAX_CLEAR_BYTES};
    use elastos_protected_content_contracts::{
        MintRequestV1, SignedSealSessionAttestationV1, STORED_SHARE_HPKE_INFO_V1,
    };
    use sha2::{Digest as _, Sha256};
    use zeroize::Zeroizing;

    // Only the fixture owns the committee's private keys. Reconstruct from
    // the actual encrypted outputs to verify what finalization returned.
    fn recover_fixture_key(envelope: &CustodyEnvelopeV1) -> ContentEncryptionKeyV1 {
        let manifest = envelope.manifest();
        let mut clear_shares = Zeroizing::new(Vec::new());
        for node in manifest
            .nodes()
            .iter()
            .take(usize::from(manifest.threshold().required()))
        {
            let key = node.node_public_key();
            let seed = (1..=3).find(|seed| node_public_key(*seed) == key).unwrap();
            let share = crate::share_wrap::open_share(
                envelope.stored_share_for_node(key).unwrap(),
                &[CUSTODY_KEY_SEED_BASE + seed; 32],
                STORED_SHARE_HPKE_INFO_V1,
                &manifest.stored_share_aad_bytes_for_node(key).unwrap(),
            )
            .unwrap();
            let mut indexed = Vec::with_capacity(share.len() + 1);
            indexed.push(node.share_coordinate().get());
            indexed.extend_from_slice(share.as_slice());
            clear_shares.push(indexed);
        }
        let reconstructed = Zeroizing::new(vsss_rs::Gf256::combine_bytes(&*clear_shares).unwrap());
        ContentEncryptionKeyV1::from_guarded_bytes(Zeroizing::new(
            reconstructed.as_slice().try_into().unwrap(),
        ))
    }

    #[test]
    fn isolated_remote_pdf_uses_the_signed_asset_and_a_distinct_content_key() {
        let mut pdf = vec![b' '; SEAL_PIECE_MAX_CLEAR_BYTES + 4096];
        pdf[..9].copy_from_slice(b"%PDF-1.7\n");
        let len = pdf.len();
        pdf[len - 5..].copy_from_slice(b"%%EOF");
        let bundle = pool_bundle(xwing_public_key_from_seed, NOW);
        let descriptor = pool_descriptor_signed_by(&bundle, 1, NOW, POOL_AUTHORITY_SEED).into();
        let request = |seed| {
            let request = MintRequestV1 {
                pool: pool_did(),
                epoch: bundle.epoch_identity().unwrap(),
                minter_issuer: runtime_issuer(POOL_AUTHORITY_SEED),
                content_access_id: ContentAccessIdV1::new([seed; 16]).unwrap(),
                clear_layout: ClearLayoutV1::Object {
                    content_type: "application/pdf".into(),
                    length: len as u64,
                },
                request_nonce: [seed; 16],
                issued_at: NOW,
                expires_at: NOW + 60,
            };
            let signature = signing_key(POOL_AUTHORITY_SEED)
                .sign(&request.canonical_bytes().unwrap())
                .to_bytes();
            SignedMintRequestV1::new(request, signature).unwrap()
        };

        let encrypt = |request: SignedMintRequestV1, seed, tamper_staging, fail_write| {
            let (mut session, header) =
                RemoteObjectSealerV1::open(&request, &descriptor, node_public_key(1), NOW).unwrap();
            let statement = session.attestation_statement().unwrap();
            let session_id = statement.seal_session_id;
            let signature = signing_key(1)
                .sign(&statement.canonical_bytes().unwrap())
                .to_bytes();
            let attestation =
                SignedSealSessionAttestationV1::new(statement.clone(), signature).unwrap();
            let encoded = attestation.canonical_bytes().unwrap();
            let attestation =
                SignedSealSessionAttestationV1::from_canonical_bytes(&encoded).unwrap();
            let public = attestation
                .verify_for_upload(&request, &descriptor, node_public_key(1), session_id, NOW)
                .unwrap();
            assert!(attestation
                .verify_for_upload(&request, &descriptor, node_public_key(2), session_id, NOW)
                .is_err());
            let mut wrong = statement;
            wrong.seal_session_public_key = SealSessionSecretKeyV1::generate()
                .unwrap()
                .public_key()
                .unwrap();
            let wrong = SignedSealSessionAttestationV1::new(wrong, signature).unwrap();
            assert!(wrong
                .verify_for_upload(&request, &descriptor, node_public_key(1), session_id, NOW)
                .is_err());
            let mut aad = MintPieceAadV1 {
                mint_request_hash: request.canonical_hash().unwrap(),
                part: ClearPartIndexV1::ObjectChunk { index: 0 },
                piece: 0,
                piece_count: 2,
            };
            let digest = Digest32::new(Sha256::digest(&pdf).into());
            let first =
                seal_mint_piece_v1(public, &aad, &pdf[..SEAL_PIECE_MAX_CLEAR_BYTES]).unwrap();
            let next = MintPieceAadV1 { piece: 1, ..aad };
            let last =
                seal_mint_piece_v1(public, &next, &pdf[SEAL_PIECE_MAX_CLEAR_BYTES..]).unwrap();
            assert!(session
                .stage_piece(&next, digest, &last, NOW, |_| panic!(
                    "out-of-order chunk reached staging"
                ))
                .is_err());
            assert_eq!(
                session
                    .stage_piece(&aad, digest, &first, NOW, |_| panic!(
                        "partial chunk staged"
                    ))
                    .unwrap(),
                None
            );
            assert!(session
                .stage_piece(&aad, digest, &first, NOW, |_| panic!(
                    "a repeated partial chunk reached staging"
                ))
                .is_err());
            // A lost reply for a partial chunk makes the sender replay the
            // entire chunk. Resume clears only that uncommitted progress.
            assert_eq!(session.resume_upload(NOW).unwrap(), None);
            assert_eq!(
                session
                    .stage_piece(&aad, digest, &first, NOW, |_| panic!(
                        "partial chunk staged"
                    ))
                    .unwrap(),
                None
            );
            aad.piece = 1;
            assert!(session
                .stage_piece(&aad, Digest32::new([0; 32]), &last, NOW, |_| panic!(
                    "wrong digest reached staging"
                ))
                .is_err());
            assert!(session
                .stage_piece(&aad, digest, &last, NOW + 60, |_| panic!(
                    "expired chunk reached staging"
                ))
                .is_err());
            let mut staged = header.clone();
            let ack = session.stage_piece(&aad, digest, &last, NOW, |frame| {
                if fail_write {
                    return Err(CustodyError::PayloadIo);
                }
                staged.extend_from_slice(frame);
                Ok(())
            });
            if fail_write {
                assert!(matches!(ack, Err(CustodyError::PayloadIo)));
                assert!(session.resume_upload(NOW).is_err());
                let identity = EncryptedContentIdentityV1::new(Digest32::new([1; 32]), 1).unwrap();
                return session.finish(&identity, NOW).map(|_| unreachable!());
            }
            assert_eq!(ack.unwrap(), Some(aad.part));
            assert_eq!(session.resume_upload(NOW).unwrap(), Some(aad.part));
            let cipher = staged[header.len()..].to_vec();
            if tamper_staging {
                staged[0] ^= 1;
            }
            let identity = EncryptedContentIdentityV1::new(
                Digest32::new(Sha256::digest(&staged).into()),
                staged.len() as u64,
            )
            .unwrap();
            let finished = session.finish(&identity, NOW)?;
            assert_eq!(
                finished.content_access_id,
                ContentAccessIdV1::new([seed; 16]).unwrap()
            );
            assert_eq!(finished.request_hash, request.canonical_hash().unwrap());
            let envelope = &finished.custody_envelope;
            assert_eq!(
                envelope.manifest().custody_epoch(),
                bundle.epoch_identity().unwrap()
            );
            assert_eq!(envelope.stored_shares().len(), 3);
            let key = recover_fixture_key(envelope);
            let decipher = PayloadChunkDecrypterV1::new(&header, &key).unwrap();
            assert_eq!(decipher.decrypt_chunk(0, &cipher).unwrap().as_slice(), pdf);
            Ok((header, key))
        };

        let (first_header, first) = encrypt(request(0x41), 0x41, false, false).unwrap();
        let (other_header, other) = encrypt(request(0x42), 0x42, false, false).unwrap();
        assert_ne!(first.commitment(), other.commitment());
        assert!(matches!(
            encrypt(request(0x43), 0x43, true, false),
            Err(CustodyError::BindingMismatch(
                "remote_object_staged_ciphertext"
            ))
        ));
        assert!(matches!(
            encrypt(request(0x44), 0x44, false, true),
            Err(CustodyError::BindingMismatch("remote_object_session"))
        ));
        assert!(matches!(
            PayloadChunkDecrypterV1::new(&first_header, &other),
            Err(CustodyError::ContentKeyCommitmentMismatch)
        ));
        assert!(matches!(
            PayloadChunkDecrypterV1::new(&other_header, &first),
            Err(CustodyError::ContentKeyCommitmentMismatch)
        ));
    }
}
