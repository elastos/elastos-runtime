//! Plan B T4.6: availability evidence and the pool-node owner-state root.

use elastos_protected_content_contracts::test_fixtures::{node_public_key, pool_did, signing_key};
use elastos_protected_content_contracts::{
    CustodyEpochIdentityV1, CustodyEpochIssuerKeyV1, Digest32, PoolDidV1,
};
use sha2::{Digest as _, Sha256};

use crate::{
    pool_node_owner_state_root, RuntimeAvailabilityBinding, RuntimeAvailabilityEvidenceV1,
    RuntimeVerifiedContentFetchV1, RuntimeVerifiedContentIdentityRootV1,
};

fn object_root() -> RuntimeVerifiedContentIdentityRootV1 {
    RuntimeVerifiedContentIdentityRootV1::Object(Digest32::new([0x7e; 32]))
}

fn fetch() -> RuntimeVerifiedContentFetchV1 {
    let identity = crate::test_object::object_identity(0x21);
    RuntimeVerifiedContentFetchV1::new(
        "bafy-item",
        "content:item",
        2_000_000_000,
        identity.encrypted_content().clone(),
        object_root(),
    )
    .unwrap()
}

#[test]
fn verified_fetch_is_evidence_without_a_receipt() {
    let identity = crate::test_object::object_identity(0x21);
    let evidence = RuntimeAvailabilityEvidenceV1::VerifiedFetch(fetch());
    assert_eq!(evidence.kind(), "verified_fetch");
    assert_eq!(evidence.receipt_digest(), None);
    assert!(evidence.as_receipt().is_none());
    assert_eq!(evidence.observed_replicas(), 0);
    assert_eq!(evidence.content_cid(), "bafy-item");
    assert_eq!(evidence.object_identity(), "content:item");
    assert_eq!(evidence.checked_at(), 2_000_000_000);
    // It binds an open exactly as a receipt does: content and identity root.
    assert_eq!(
        evidence.bound_encrypted_content(),
        identity.encrypted_content()
    );
    assert_eq!(evidence.bound_content_identity_root(), object_root());

    // A fetch with no time, an empty name or a zero root is refused.
    let encrypted = identity.encrypted_content().clone();
    for (cid, checked_at, root) in [
        ("bafy-item", 0, object_root()),
        ("", 1, object_root()),
        (
            "bafy-item",
            1,
            RuntimeVerifiedContentIdentityRootV1::Object(Digest32::new([0; 32])),
        ),
    ] {
        assert!(RuntimeVerifiedContentFetchV1::new(
            cid,
            "content:item",
            checked_at,
            encrypted.clone(),
            root
        )
        .is_err());
    }
}

#[test]
fn pool_node_owner_state_root_binds_pool_epoch_and_node() {
    let epoch = CustodyEpochIdentityV1::new(Digest32::new([0x11; 32]), 512).unwrap();
    let other_epoch = CustodyEpochIdentityV1::new(Digest32::new([0x12; 32]), 512).unwrap();
    let other_pool = PoolDidV1::from_issuer(
        CustodyEpochIssuerKeyV1::new(signing_key(0x72).verifying_key().to_bytes()).unwrap(),
    );
    let root = pool_node_owner_state_root(&pool_did(), epoch, node_public_key(1));

    let mut hasher = Sha256::new();
    hasher.update(b"elastos.protected-content.pool-node-root/v1");
    hasher.update(pool_did().issuer().as_bytes());
    hasher.update(epoch.epoch_sha256().as_bytes());
    hasher.update(512u32.to_be_bytes());
    hasher.update(node_public_key(1).as_bytes());
    assert_eq!(root, Digest32::new(hasher.finalize().into()));

    assert_ne!(
        root,
        pool_node_owner_state_root(&other_pool, epoch, node_public_key(1))
    );
    assert_ne!(
        root,
        pool_node_owner_state_root(&pool_did(), other_epoch, node_public_key(1))
    );
    assert_ne!(
        root,
        pool_node_owner_state_root(&pool_did(), epoch, node_public_key(2))
    );
    assert_ne!(root, Digest32::new([0; 32]));
}
