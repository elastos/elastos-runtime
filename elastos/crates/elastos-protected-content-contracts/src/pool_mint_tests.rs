//! Plan B POOL-MINT: the minting Home's signed share statement.

use ed25519_dalek::Signer as _;
use hex::encode;
use sha2::{Digest as _, Sha256};

use crate::test_fixtures::{
    key_envelope_for, node_public_key, pool_bundle, pool_descriptor_signed_by, pool_did,
    pool_mint_share, runtime_issuer, signing_key, POOL_AUTHORITY_SEED,
};
use crate::test_support::{digest, xwing_public_key_bytes, NOW};
use crate::{
    CanonicalContract, ClearLayoutV1, ClearRenditionV1, ContentAccessIdV1, ContractError,
    EncryptedContentIdentityV1, KeyEnvelopeIdentityV1, MintRequestV1, PoolContractError,
    PoolMintShareStatementV1, PoolProvisioningAuthorizationV1, SealCompletedV1,
    SignedMintRequestV1, SignedPoolDescriptorAnyV1, SignedPoolDescriptorV3, SignedPoolMintShareV1,
    SignedPoolProvisioningAuthorizationV1, SignedSealCompletedV1, SEAL_SESSION_GRACE_SECS,
};

const MINTER: u8 = 0x44;

#[test]
fn remote_dash_upload_starts_both_renditions_before_their_segments() {
    use crate::ClearPartIndexV1::{DashInit, DashSegment};

    let layout = ClearLayoutV1::DashV2 {
        renditions: vec![
            ClearRenditionV1 {
                kind: 1,
                init_len: 10,
                segment_lengths: vec![11, 12],
            },
            ClearRenditionV1 {
                kind: 2,
                init_len: 20,
                segment_lengths: vec![21],
            },
        ],
    };
    let ordered = layout.parts().unwrap();
    assert_eq!(
        ordered,
        vec![
            (DashInit { rendition: 1 }, 10),
            (DashInit { rendition: 2 }, 20),
            (
                DashSegment {
                    rendition: 1,
                    index: 0
                },
                11
            ),
            (
                DashSegment {
                    rendition: 1,
                    index: 1
                },
                12
            ),
            (
                DashSegment {
                    rendition: 2,
                    index: 0
                },
                21
            ),
        ]
    );
    for (index, (part, _)) in ordered.into_iter().enumerate() {
        assert_eq!(layout.part_position(part), Some(index as u64));
    }
    assert_eq!(
        layout.part_position(DashSegment {
            rendition: 2,
            index: 1
        }),
        None
    );
}

fn kid(seed: u8) -> ContentAccessIdV1 {
    ContentAccessIdV1::new([seed; 16]).unwrap()
}

fn envelope(seed: u8) -> KeyEnvelopeIdentityV1 {
    key_envelope_for(
        &pool_bundle(xwing_public_key_bytes, NOW),
        &EncryptedContentIdentityV1::new(digest(seed), 4096).unwrap(),
    )
}

fn share() -> SignedPoolMintShareV1 {
    pool_mint_share(pool_did(), &envelope(0x11), kid(0x41), MINTER)
}

#[test]
fn remote_seal_request_binds_admission_asset_group_and_expiry() {
    let epoch = pool_bundle(xwing_public_key_bytes, NOW);
    let descriptor = pool_descriptor_signed_by(&epoch, 1, NOW, POOL_AUTHORITY_SEED).into();
    let request = MintRequestV1 {
        pool: pool_did(),
        epoch: epoch.epoch_identity().unwrap(),
        minter_issuer: runtime_issuer(POOL_AUTHORITY_SEED),
        content_access_id: kid(0x41),
        clear_layout: ClearLayoutV1::Object {
            content_type: "application/pdf".into(),
            length: 4096,
        },
        request_nonce: [0x31; 16],
        issued_at: NOW,
        expires_at: NOW + SEAL_SESSION_GRACE_SECS,
    };
    let sign = |request: &MintRequestV1, seed| {
        signing_key(seed)
            .sign(&request.canonical_bytes().unwrap())
            .to_bytes()
    };
    let signature = sign(&request, POOL_AUTHORITY_SEED);
    let signed = SignedMintRequestV1::new(request.clone(), signature).unwrap();
    let sealer = node_public_key(1);
    let bytes = signed.canonical_bytes().unwrap();
    assert_eq!(
        sha256_hex(&bytes),
        "b78332cfdc904721a3c4a5ec067b4c32abda07054b8531332f577a9a713943d3",
        "canonical remote seal request vector"
    );
    let decoded = SignedMintRequestV1::from_canonical_bytes(&bytes).unwrap();
    assert_eq!(decoded, signed);
    assert_eq!(
        decoded.verify_for_sealer(&descriptor, sealer, NOW),
        Ok(&request)
    );
    assert_eq!(
        decoded.verify_for_sealer(&descriptor, sealer, request.expires_at),
        Err(PoolContractError::Expired)
    );
    assert_eq!(
        decoded.verify_for_sealer(&descriptor, node_public_key(9), NOW),
        Err(PoolContractError::NotMember)
    );

    let changed_asset = MintRequestV1 {
        content_access_id: kid(0x42),
        ..request.clone()
    };
    let mismatched = SignedMintRequestV1::new(changed_asset, signature).unwrap();
    assert_eq!(
        mismatched.verify_for_sealer(&descriptor, sealer, NOW),
        Err(PoolContractError::Signature)
    );

    let foreign_minter = MintRequestV1 {
        minter_issuer: runtime_issuer(MINTER),
        ..request.clone()
    };
    let unadmitted =
        SignedMintRequestV1::new(foreign_minter.clone(), sign(&foreign_minter, MINTER)).unwrap();
    assert_eq!(
        unadmitted.verify_for_sealer(&descriptor, sealer, NOW),
        Err(ContractError::InvalidField("mint_request.minter_admission").into())
    );

    let other_epoch = pool_bundle(|seed| xwing_public_key_bytes(seed + 8), NOW);
    let changed_group = MintRequestV1 {
        epoch: other_epoch.epoch_identity().unwrap(),
        ..request.clone()
    };
    let mismatched = SignedMintRequestV1::new(
        changed_group.clone(),
        sign(&changed_group, POOL_AUTHORITY_SEED),
    )
    .unwrap();
    assert_eq!(
        mismatched.verify_for_sealer(&descriptor, sealer, NOW),
        Err(PoolContractError::EpochMismatch)
    );

    let invalid_layout = MintRequestV1 {
        clear_layout: ClearLayoutV1::DashV2 {
            renditions: vec![ClearRenditionV1 {
                kind: 1,
                init_len: 1,
                segment_lengths: vec![0],
            }],
        },
        ..request
    };
    assert_eq!(
        invalid_layout.canonical_bytes(),
        Err(ContractError::InvalidField("media_part_length"))
    );
}

fn sha256_hex(bytes: &[u8]) -> String {
    encode(Sha256::digest(bytes))
}

#[test]
fn remote_provisioning_authorization_binds_one_envelope_and_asset() {
    let epoch = pool_bundle(xwing_public_key_bytes, NOW);
    let descriptor = pool_descriptor_signed_by(&epoch, 1, NOW, POOL_AUTHORITY_SEED).into();
    let request = MintRequestV1 {
        pool: pool_did(),
        epoch: epoch.epoch_identity().unwrap(),
        minter_issuer: runtime_issuer(POOL_AUTHORITY_SEED),
        content_access_id: kid(0x41),
        clear_layout: ClearLayoutV1::Object {
            content_type: "application/pdf".into(),
            length: 4096,
        },
        request_nonce: [0x31; 16],
        issued_at: NOW,
        expires_at: NOW + SEAL_SESSION_GRACE_SECS,
    };
    let request_signature = signing_key(POOL_AUTHORITY_SEED)
        .sign(&request.canonical_bytes().unwrap())
        .to_bytes();
    let request = SignedMintRequestV1::new(request, request_signature).unwrap();
    let statement = PoolProvisioningAuthorizationV1 {
        pool: pool_did(),
        epoch: epoch.epoch_identity().unwrap(),
        sealer_node_public_key: node_public_key(1),
        sealer_runtime_issuer: runtime_issuer(0x55),
        key_envelope: envelope(0x11),
        content_access_id: kid(0x41),
        mint_request_hash: request.canonical_hash().unwrap(),
        issued_at: NOW,
        expires_at: NOW + 60,
    };
    let signature = signing_key(1)
        .sign(&statement.canonical_bytes().unwrap())
        .to_bytes();
    let signed = SignedPoolProvisioningAuthorizationV1::new(statement.clone(), signature).unwrap();
    let decoded = SignedPoolProvisioningAuthorizationV1::from_canonical_bytes(
        &signed.canonical_bytes().unwrap(),
    )
    .unwrap();
    assert_eq!(
        decoded.verify_for_mint_request(&descriptor, &request, &statement.key_envelope, NOW),
        Ok((&statement, runtime_issuer(POOL_AUTHORITY_SEED)))
    );
    assert_eq!(
        decoded.verify_for_mint_request(&descriptor, &request, &envelope(0x12), NOW),
        Err(ContractError::InvalidField("pool_provisioning_authorization.key_envelope").into())
    );
    assert_eq!(
        decoded.verify_for_mint_request(&descriptor, &request, &statement.key_envelope, NOW + 60),
        Err(PoolContractError::Expired)
    );

    let changed_asset = PoolProvisioningAuthorizationV1 {
        content_access_id: kid(0x42),
        ..statement.clone()
    };
    let tampered =
        SignedPoolProvisioningAuthorizationV1::new(changed_asset.clone(), signature).unwrap();
    assert_eq!(
        tampered.verify_for_mint_request(&descriptor, &request, &statement.key_envelope, NOW),
        Err(PoolContractError::Signature)
    );
    let wrong_asset_signature = signing_key(1)
        .sign(&changed_asset.canonical_bytes().unwrap())
        .to_bytes();
    let wrong_asset =
        SignedPoolProvisioningAuthorizationV1::new(changed_asset, wrong_asset_signature).unwrap();
    assert_eq!(
        wrong_asset.verify_for_mint_request(&descriptor, &request, &statement.key_envelope, NOW),
        Err(ContractError::InvalidField("pool_provisioning_authorization.mint_request").into())
    );
    let too_long = PoolProvisioningAuthorizationV1 {
        expires_at: NOW + 61,
        ..statement
    };
    assert!(SignedPoolProvisioningAuthorizationV1::new(too_long, signature).is_err());
}

#[test]
fn remote_completion_retains_exact_descriptor_and_asset_across_expiry() {
    let bundle = pool_bundle(xwing_public_key_bytes, NOW);
    let v3 = pool_descriptor_signed_by(&bundle, 1, NOW, POOL_AUTHORITY_SEED);
    let descriptor = SignedPoolDescriptorAnyV1::from(v3.clone());
    let mint = MintRequestV1 {
        pool: pool_did(),
        epoch: bundle.epoch_identity().unwrap(),
        minter_issuer: runtime_issuer(POOL_AUTHORITY_SEED),
        content_access_id: kid(0x41),
        clear_layout: ClearLayoutV1::Object {
            content_type: "application/pdf".into(),
            length: 4080,
        },
        request_nonce: [0x31; 16],
        issued_at: NOW,
        expires_at: NOW + 60,
    };
    let signature = signing_key(POOL_AUTHORITY_SEED)
        .sign(&mint.canonical_bytes().unwrap())
        .to_bytes();
    let clear_layout = mint.clear_layout.clone();
    let mint = SignedMintRequestV1::new(mint, signature).unwrap();
    let statement = SealCompletedV1 {
        pool: pool_did(),
        epoch: bundle.epoch_identity().unwrap(),
        descriptor_digest: descriptor.canonical_hash().unwrap(),
        sealer_node_public_key: node_public_key(1),
        sealer_device_did: descriptor
            .member_peer_did(node_public_key(1))
            .unwrap()
            .into(),
        content_publisher_did: "did:key:zPublisher".into(),
        mint_request_hash: mint.canonical_hash().unwrap(),
        content_access_id: kid(0x41),
        key_envelope: envelope(0x11),
        content_identity: vec![1, 2, 3],
        content_key_commitment: digest(0x36),
        package_cid: "bafypackagefixture".into(),
        file_cids: vec![("asset.epc".into(), "bafyfilefixture".into())],
        availability_receipt: vec![4, 5, 6],
        completed_at: NOW + 1,
    };
    let sign = |statement: SealCompletedV1, seed| {
        let signature = signing_key(seed)
            .sign(&statement.canonical_bytes().unwrap())
            .to_bytes();
        SignedSealCompletedV1::new(statement, signature).unwrap()
    };
    let signed = sign(statement.clone(), 1);
    let decoded =
        SignedSealCompletedV1::from_canonical_bytes(&signed.canonical_bytes().unwrap()).unwrap();
    assert_eq!(decoded, signed);
    assert_eq!(
        decoded.verify_for_request_at(&descriptor, &mint, node_public_key(1), NOW + 2),
        Ok((&statement, &clear_layout))
    );
    let expired = descriptor.expires_at() + 1;
    assert_eq!(
        descriptor.verify(expired).unwrap_err(),
        PoolContractError::Expired
    );
    assert_eq!(
        decoded.verify_for_request_at(&descriptor, &mint, node_public_key(1), expired),
        Err(PoolContractError::Expired)
    );
    assert_eq!(
        decoded.verify_historical(&descriptor, &statement.key_envelope, kid(0x41)),
        Ok(&statement)
    );
    assert!(decoded
        .verify_historical(&descriptor, &statement.key_envelope, kid(0x42))
        .is_err());
    assert!(decoded
        .verify_historical(&descriptor, &envelope(0x12), kid(0x41))
        .is_err());
    let successor = pool_descriptor_signed_by(&bundle, 2, NOW, POOL_AUTHORITY_SEED).into();
    assert!(decoded
        .verify_historical(&successor, &statement.key_envelope, kid(0x41))
        .is_err());
    let descriptor_with_wrong_signature: SignedPoolDescriptorAnyV1 = SignedPoolDescriptorV3::new(
        v3.statement().clone(),
        signing_key(9)
            .sign(&v3.statement().canonical_bytes().unwrap())
            .to_bytes()
            .to_vec(),
    )
    .unwrap()
    .into();
    let forged = sign(
        SealCompletedV1 {
            descriptor_digest: descriptor_with_wrong_signature.canonical_hash().unwrap(),
            ..statement.clone()
        },
        1,
    );
    assert_eq!(
        forged.verify_historical(
            &descriptor_with_wrong_signature,
            &statement.key_envelope,
            kid(0x41)
        ),
        Err(PoolContractError::Signature)
    );
    assert_eq!(
        sign(statement.clone(), 9).verify_historical(
            &descriptor,
            &statement.key_envelope,
            kid(0x41)
        ),
        Err(PoolContractError::Signature)
    );
    let signed_for_another_request = sign(
        SealCompletedV1 {
            mint_request_hash: digest(0x88),
            ..statement
        },
        1,
    );
    assert_eq!(
        signed_for_another_request.verify_for_request_at(
            &descriptor,
            &mint,
            node_public_key(1),
            NOW + 2
        ),
        Err(ContractError::InvalidField("seal_completed.mint_request").into())
    );
}

#[test]
fn pool_mint_share_round_trips_under_its_own_domains() {
    let signed = share();
    let bytes = signed.canonical_bytes().unwrap();
    assert!(bytes.starts_with(b"elastos.protected-content.pool-mint-share/v1\0"));
    assert_eq!(
        SignedPoolMintShareV1::from_canonical_bytes(&bytes).unwrap(),
        signed
    );
    let statement = signed.statement().canonical_bytes().unwrap();
    assert!(statement.starts_with(b"elastos.protected-content.pool-mint-share-statement/v1\0"));
    assert_eq!(
        PoolMintShareStatementV1::from_canonical_bytes(&statement).unwrap(),
        *signed.statement()
    );
    assert_eq!(signed.statement().epoch(), envelope(0x11).custody_epoch());
    assert_eq!(
        signed.verify_signature().unwrap().minter_runtime_issuer(),
        runtime_issuer(MINTER)
    );
}

/// KATs (append-only): the fixture statement, its signed form and the
/// minter's Ed25519 signature.
#[test]
fn pool_mint_share_known_answers() {
    let signed = share();
    let statement = signed.statement().canonical_bytes().unwrap();
    let bytes = signed.canonical_bytes().unwrap();
    assert_eq!(
        (statement.len(), sha256_hex(&statement)),
        (KAT_STATEMENT_LEN, KAT_STATEMENT_SHA256.to_string())
    );
    assert_eq!(
        (bytes.len(), sha256_hex(&bytes)),
        (KAT_SIGNED_LEN, KAT_SIGNED_SHA256.to_string())
    );
    assert_eq!(encode(signed.runtime_signature()), KAT_SIGNATURE);
}

const KAT_STATEMENT_LEN: usize = 715;
const KAT_STATEMENT_SHA256: &str =
    "6570b86f986849e9ad1bcc6a9ccf1b7bf423d65f24ea7d966141cf98a35a1c2d";
const KAT_SIGNED_LEN: usize = 828;
const KAT_SIGNED_SHA256: &str = "2e33a1500f1de081fa5c7938be85184c7385f591af55b56de3ba47c7d667dfbf";
const KAT_SIGNATURE: &str =
    "7713c666207abe37b098af3b8d082f699841789da47803935e81bbe36ed55482fb9ba3884f367caebbbc0a0deb4db25f378404496bfd5c82d73e0fb0ddf6e400";

#[test]
fn guard_pool_mint_share_with_a_tampered_signature_is_refused() {
    let signed = share();
    let mut signature = signed.runtime_signature().to_vec();
    signature[0] ^= 1;
    let tampered = SignedPoolMintShareV1::new(signed.statement().clone(), signature).unwrap();
    assert_eq!(
        tampered.verify_signature(),
        Err(PoolContractError::Signature)
    );
    // Signed by another key than the statement's minter.
    let other = pool_mint_share(pool_did(), &envelope(0x11), kid(0x41), 0x45);
    let forged = SignedPoolMintShareV1::new(
        signed.statement().clone(),
        other.runtime_signature().to_vec(),
    )
    .unwrap();
    assert_eq!(forged.verify_signature(), Err(PoolContractError::Signature));
}

#[test]
fn guard_pool_mint_share_for_another_item_is_refused() {
    let signed = share();
    assert!(signed.verify_for_item(&envelope(0x11), kid(0x41)).is_ok());
    assert!(matches!(
        signed.verify_for_item(&envelope(0x12), kid(0x41)),
        Err(PoolContractError::Contract(ContractError::InvalidField(_)))
    ));
    assert!(matches!(
        signed.verify_for_item(&envelope(0x11), kid(0x42)),
        Err(PoolContractError::Contract(ContractError::InvalidField(_)))
    ));
}
