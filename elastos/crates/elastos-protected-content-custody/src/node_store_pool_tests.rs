//! Plan B POOL-MINT: a share a Home that uses the pool provisioned keeps its
//! signed share statement, reloads under the minter's issuer and KID, and
//! releases only for that KID (ADV-02). The slot (minting Home, KID) is
//! written once (C6, ADV-16).

use std::path::Path;

use ed25519_dalek::Signer as _;
use elastos_protected_content_contracts::test_fixtures::{
    pool_bundle, pool_did, pool_mint_share, pool_provisioning_record, runtime_custody_provisioning,
    runtime_issuer, signed_node_rights_decision, signing_key,
};
use elastos_protected_content_contracts::{
    CanonicalContract, ContentAccessIdV1, CustodyEnvelopeV1, CustodyNodeProvisioningRecordV1,
    RightsDecisionV1, RuntimeCustodyProvisioningIdV1, RuntimeCustodyProvisioningStatementV1,
    SignedPoolMintShareV1, SignedRuntimeCustodyProvisioningV1,
};

use crate::replay_store::DurableReplayClaimStoreV1;
use crate::test_support::{
    digest, node_public_key, pool_node_custody_secret, pool_release_test, PoolReleaseTestV1, NOW,
};
use crate::{CustodyError, NodeLocalShareStoreErrorV1, NodeLocalShareStoreV1};

const OWNER: u8 = 0x7a;
const MINTER: u8 = 0x44;

fn temp_root() -> tempfile::TempDir {
    let temp = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    temp
}

fn store(root: &Path) -> NodeLocalShareStoreV1 {
    NodeLocalShareStoreV1::new(node_public_key(1), root.join("shares"))
}

fn record(envelope: &CustodyEnvelopeV1) -> CustodyNodeProvisioningRecordV1 {
    CustodyNodeProvisioningRecordV1::new(
        envelope.key_envelope_identity().unwrap(),
        envelope.manifest().clone(),
        node_public_key(1),
        envelope
            .stored_share_for_node(node_public_key(1))
            .unwrap()
            .clone(),
    )
    .unwrap()
}

fn item_kid(test: &PoolReleaseTestV1) -> ContentAccessIdV1 {
    test.fixture
        .authenticated()
        .statement()
        .policy_body()
        .content_access_id()
}

fn mint_share_of(
    record: &CustodyNodeProvisioningRecordV1,
    kid: ContentAccessIdV1,
    minter: u8,
) -> SignedPoolMintShareV1 {
    pool_mint_share(pool_did(), record.key_envelope_identity(), kid, minter)
}

/// The minter's share statement for `record` (the statement has no clock).
fn share_for(
    record: &CustodyNodeProvisioningRecordV1,
    kid: ContentAccessIdV1,
    _issued_at: u64,
) -> SignedPoolMintShareV1 {
    mint_share_of(record, kid, MINTER)
}

/// A structurally valid share of another item of the fixture pool, for the
/// slot and cap rules (its sealed share is filler; it is never opened).
fn other_item(seed: u8) -> CustodyNodeProvisioningRecordV1 {
    pool_provisioning_record(
        &pool_bundle(crate::test_support::xwing_public_key_from_seed, NOW),
        &elastos_protected_content_contracts::EncryptedContentIdentityV1::new(digest(seed), 4096)
            .unwrap(),
        1,
    )
}

fn provision(
    store: &NodeLocalShareStoreV1,
    record: &CustodyNodeProvisioningRecordV1,
    statement: &SignedRuntimeCustodyProvisioningV1,
    share: &SignedPoolMintShareV1,
    now: u64,
) -> Result<crate::PoolProvisionedNodeShareV1, crate::NodeShareProvisionErrorV1> {
    store.provision_pool_node_share_classified(
        record,
        statement,
        share,
        &pool_node_custody_secret(1),
        now,
    )
}

fn claim(
    test: &PoolReleaseTestV1,
    share: &crate::NodeLocalStoredShareV1,
    temp: &tempfile::TempDir,
) -> Result<usize, CustodyError> {
    let operation = test.fixture.authenticated();
    let decision = signed_node_rights_decision(&operation, 1, RightsDecisionV1::Allowed, NOW);
    let mut replay = DurableReplayClaimStoreV1::new(node_public_key(1), temp.path().join("replay"));
    replay
        .claim_or_replay_pool_contributions(
            operation,
            &decision,
            share,
            &crate::test_support::node_signing_key(1),
            &pool_node_custody_secret(1),
            NOW + 5,
            NOW + 30,
            NOW + 6,
        )
        .map(|contributions| contributions.len())
}

#[test]
fn minter_issued_entry_reloads_with_its_own_issuer_and_kid() {
    let temp = temp_root();
    let test = pool_release_test(vec![(9, 1)], 1, 0x43);
    let record = record(&test.envelope);
    let statement = runtime_custody_provisioning(&record, MINTER, 0xf1, NOW);
    let share = share_for(&record, item_kid(&test), NOW);
    let first = provision(&store(temp.path()), &record, &statement, &share, NOW + 1).unwrap();
    assert!(!first.already_stored());
    // A restart: a new store over the same folder. The root's own issuer
    // (the owner) is passed and ignored for this entry; no window, no term.
    let loaded = store(temp.path())
        .load_node_share(
            record.key_envelope_identity(),
            runtime_issuer(OWNER),
            &pool_node_custody_secret(1),
        )
        .unwrap();
    assert_eq!(
        loaded.node_share().bound_content_access_id(),
        Some(item_kid(&test))
    );
    assert_eq!(loaded.receipt(), first.provisioned().receipt());
}

#[test]
fn v1_entry_still_loads_with_the_root_issuer() {
    let temp = temp_root();
    let test = pool_release_test(vec![(9, 1)], 1, 0x43);
    let record = record(&test.envelope);
    let statement = runtime_custody_provisioning(&record, OWNER, 0xf1, NOW);
    store(temp.path())
        .provision_node_share(
            &record,
            &statement,
            runtime_issuer(OWNER),
            &pool_node_custody_secret(1),
            NOW + 1,
        )
        .unwrap();
    let loaded = store(temp.path())
        .load_node_share(
            record.key_envelope_identity(),
            runtime_issuer(OWNER),
            &pool_node_custody_secret(1),
        )
        .unwrap();
    assert_eq!(loaded.node_share().bound_content_access_id(), None);
    assert!(store(temp.path())
        .load_node_share(
            record.key_envelope_identity(),
            runtime_issuer(MINTER),
            &pool_node_custody_secret(1),
        )
        .is_err());
}

#[test]
fn guard_tampered_stored_share_statement_fails_load() {
    let temp = temp_root();
    let test = pool_release_test(vec![(9, 1)], 1, 0x43);
    let record = record(&test.envelope);
    let statement = runtime_custody_provisioning(&record, MINTER, 0xf1, NOW);
    let share = share_for(&record, item_kid(&test), NOW);
    provision(&store(temp.path()), &record, &statement, &share, NOW + 1).unwrap();
    let shares = temp.path().join("shares");
    let file = std::fs::read_dir(&shares)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            !path
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .ends_with(".lock")
        })
        .unwrap();
    let mut bytes = std::fs::read(&file).unwrap();
    // Flip one byte of the stored share statement's signature and re-seal the
    // integrity digest, so only the signature check can catch it.
    let share_bytes = share.canonical_bytes().unwrap();
    let at = bytes
        .windows(share_bytes.len())
        .position(|window| window == share_bytes.as_slice())
        .unwrap();
    let flip = at + share_bytes.len() - 1;
    bytes[flip] ^= 1;
    let payload_len = bytes.len() - 32;
    let digest = crate::node_store::test_integrity_digest(&bytes[..payload_len]);
    bytes[payload_len..].copy_from_slice(&digest);
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    std::fs::write(&file, &bytes).unwrap();
    assert!(store(temp.path())
        .load_node_share(
            record.key_envelope_identity(),
            runtime_issuer(OWNER),
            &pool_node_custody_secret(1),
        )
        .is_err());
}

#[test]
fn guard_pool_release_naming_another_kid_is_refused() {
    let temp = temp_root();
    let test = pool_release_test(vec![(9, 1)], 1, 0x43);
    let record = record(&test.envelope);
    let statement = runtime_custody_provisioning(&record, MINTER, 0xf1, NOW);
    // The share is bound to another KID than the one the release names.
    let other = ContentAccessIdV1::new([0x99; 16]).unwrap();
    assert_ne!(other, item_kid(&test));
    let stored = provision(
        &store(temp.path()),
        &record,
        &statement,
        &share_for(&record, other, NOW),
        NOW + 1,
    )
    .unwrap();
    assert!(matches!(
        claim(&test, stored.provisioned().node_share(), &temp),
        Err(CustodyError::BindingMismatch("content_access_id"))
    ));
}

#[test]
fn pool_release_with_the_bound_kid_is_accepted() {
    let temp = temp_root();
    let test = pool_release_test(vec![(9, 1)], 1, 0x43);
    let record = record(&test.envelope);
    let statement = runtime_custody_provisioning(&record, MINTER, 0xf1, NOW);
    let stored = provision(
        &store(temp.path()),
        &record,
        &statement,
        &share_for(&record, item_kid(&test), NOW),
        NOW + 1,
    )
    .unwrap();
    assert_eq!(
        claim(&test, stored.provisioned().node_share(), &temp).unwrap(),
        1
    );
}

#[test]
fn identical_duplicate_share_is_already_stored() {
    let temp = temp_root();
    let test = pool_release_test(vec![(9, 1)], 1, 0x43);
    let record = record(&test.envelope);
    let statement = runtime_custody_provisioning(&record, MINTER, 0xf1, NOW);
    let share = share_for(&record, item_kid(&test), NOW);
    let first = provision(&store(temp.path()), &record, &statement, &share, NOW + 1).unwrap();
    let again = provision(&store(temp.path()), &record, &statement, &share, NOW + 2).unwrap();
    assert!(again.already_stored());
    assert_eq!(again.provisioned().receipt(), first.provisioned().receipt());
}

#[test]
fn lost_reply_retry_after_60_s_is_already_stored_without_replacing_the_record() {
    let temp = temp_root();
    let test = pool_release_test(vec![(9, 1)], 1, 0x43);
    let record = record(&test.envelope);
    let first_statement = runtime_custody_provisioning(&record, MINTER, 0xf1, NOW);
    let first = provision(
        &store(temp.path()),
        &record,
        &first_statement,
        &share_for(&record, item_kid(&test), NOW),
        NOW + 1,
    )
    .unwrap();
    // The reply was lost; 90 s later the minter retries with a fresh
    // share statement and a fresh runtime statement.
    let later = NOW + 90;
    let fresh_statement = runtime_custody_provisioning(&record, MINTER, 0xf1, later);
    let retry = provision(
        &store(temp.path()),
        &record,
        &fresh_statement,
        &share_for(&record, item_kid(&test), later),
        later + 1,
    )
    .unwrap();
    assert!(retry.already_stored());
    // The stored entry is the first one, unchanged.
    assert_eq!(retry.provisioned().receipt(), first.provisioned().receipt());
    // An expired statement is refused before the store, even for a duplicate.
    assert!(provision(
        &store(temp.path()),
        &record,
        &first_statement,
        &share_for(&record, item_kid(&test), later),
        later + 1,
    )
    .unwrap_err()
    .proves_not_stored());
}

#[test]
fn guard_retry_with_another_kid_is_refused() {
    let temp = temp_root();
    let test = pool_release_test(vec![(9, 1)], 1, 0x43);
    let record = record(&test.envelope);
    let statement = runtime_custody_provisioning(&record, MINTER, 0xf1, NOW);
    provision(
        &store(temp.path()),
        &record,
        &statement,
        &share_for(&record, item_kid(&test), NOW),
        NOW + 1,
    )
    .unwrap();
    let error = provision(
        &store(temp.path()),
        &record,
        &statement,
        &share_for(&record, ContentAccessIdV1::new([0x99; 16]).unwrap(), NOW),
        NOW + 2,
    )
    .unwrap_err();
    assert!(error.proves_not_stored());
    assert!(matches!(
        error.into_cause(),
        CustodyError::NodeShareStore(NodeLocalShareStoreErrorV1::Conflict)
    ));
}

#[test]
fn guard_different_record_for_an_occupied_slot_is_refused() {
    let temp = temp_root();
    let test = pool_release_test(vec![(9, 1)], 1, 0x43);
    let record = record(&test.envelope);
    let statement = runtime_custody_provisioning(&record, MINTER, 0xf1, NOW);
    provision(
        &store(temp.path()),
        &record,
        &statement,
        &share_for(&record, item_kid(&test), NOW),
        NOW + 1,
    )
    .unwrap();
    // Same key envelope and node (the slot), another sealed share.
    let other = CustodyNodeProvisioningRecordV1::new(
        record.key_envelope_identity().clone(),
        record.manifest().clone(),
        node_public_key(1),
        record.sealed_share().tamper_envelope(),
    )
    .unwrap();
    let other_statement = runtime_custody_provisioning(&other, MINTER, 0xf2, NOW);
    let error = provision(
        &store(temp.path()),
        &other,
        &other_statement,
        &share_for(&other, item_kid(&test), NOW),
        NOW + 2,
    )
    .unwrap_err();
    assert!(error.proves_not_stored());
}

#[test]
fn v1_occupied_slot_is_never_replaced_by_a_pool_share() {
    let temp = temp_root();
    let test = pool_release_test(vec![(9, 1)], 1, 0x43);
    let record = record(&test.envelope);
    store(temp.path())
        .provision_node_share(
            &record,
            &runtime_custody_provisioning(&record, OWNER, 0xf1, NOW),
            runtime_issuer(OWNER),
            &pool_node_custody_secret(1),
            NOW + 1,
        )
        .unwrap();
    let error = provision(
        &store(temp.path()),
        &record,
        &runtime_custody_provisioning(&record, MINTER, 0xf1, NOW),
        &share_for(&record, item_kid(&test), NOW),
        NOW + 2,
    )
    .unwrap_err();
    assert!(error.proves_not_stored());
}

#[test]
fn v1_duplicate_still_needs_identical_signed_bytes() {
    let temp = temp_root();
    let test = pool_release_test(vec![(9, 1)], 1, 0x43);
    let record = record(&test.envelope);
    let first = runtime_custody_provisioning(&record, OWNER, 0xf1, NOW);
    let shares = store(temp.path());
    shares
        .provision_node_share(
            &record,
            &first,
            runtime_issuer(OWNER),
            &pool_node_custody_secret(1),
            NOW + 1,
        )
        .unwrap();
    // A fresh statement for the same record: V1 keeps its exact-bytes rule.
    let statement = RuntimeCustodyProvisioningStatementV1::new(
        runtime_issuer(OWNER),
        record.record_identity().unwrap(),
        RuntimeCustodyProvisioningIdV1::new(digest(0xf1)).unwrap(),
        NOW + 2,
        NOW + 62,
    )
    .unwrap();
    let fresh = SignedRuntimeCustodyProvisioningV1::new(
        statement.clone(),
        signing_key(OWNER)
            .sign(&statement.canonical_bytes().unwrap())
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(shares
        .provision_node_share(
            &record,
            &fresh,
            runtime_issuer(OWNER),
            &pool_node_custody_secret(1),
            NOW + 3
        )
        .is_err());
}

#[test]
fn guard_second_write_to_the_same_slot_is_refused() {
    // The slot is (minting Home, KID): the same minter and KID for another
    // item is a second write to it.
    let temp = temp_root();
    let kid = ContentAccessIdV1::new([0x61; 16]).unwrap();
    let first = other_item(0x31);
    provision(
        &store(temp.path()),
        &first,
        &runtime_custody_provisioning(&first, MINTER, 0xf1, NOW),
        &mint_share_of(&first, kid, MINTER),
        NOW + 1,
    )
    .unwrap();
    assert!(store(temp.path())
        .pool_slot_held(runtime_issuer(MINTER), kid)
        .unwrap());
    let second = other_item(0x32);
    let error = provision(
        &store(temp.path()),
        &second,
        &runtime_custody_provisioning(&second, MINTER, 0xf2, NOW),
        &mint_share_of(&second, kid, MINTER),
        NOW + 2,
    )
    .unwrap_err();
    assert!(error.proves_not_stored());
    assert!(matches!(
        error.into_cause(),
        CustodyError::NodeShareStore(NodeLocalShareStoreErrorV1::Conflict)
    ));
}

/// PM-F1: B first, then A, for the same KID: each Home's KID is its own
/// slot, and each share loads for its own item.
#[test]
fn b_then_a_for_the_same_kid_each_take_their_own_slot() {
    let temp = temp_root();
    let kid = ContentAccessIdV1::new([0x62; 16]).unwrap();
    let home_b = 0x46;
    let item_b = other_item(0x33);
    let item_a = other_item(0x34);
    provision(
        &store(temp.path()),
        &item_b,
        &runtime_custody_provisioning(&item_b, home_b, 0xf1, NOW),
        &mint_share_of(&item_b, kid, home_b),
        NOW + 1,
    )
    .unwrap();
    provision(
        &store(temp.path()),
        &item_a,
        &runtime_custody_provisioning(&item_a, MINTER, 0xf2, NOW),
        &mint_share_of(&item_a, kid, MINTER),
        NOW + 2,
    )
    .unwrap();
    for item in [&item_a, &item_b] {
        let loaded = store(temp.path())
            .load_node_share(
                item.key_envelope_identity(),
                runtime_issuer(OWNER),
                &pool_node_custody_secret(1),
            )
            .unwrap();
        assert_eq!(loaded.node_share().bound_content_access_id(), Some(kid));
        assert_eq!(
            loaded.node_share().key_envelope_identity(),
            item.key_envelope_identity()
        );
    }
}

/// PM-F1: B submits A's exact occupied record under its own statement.
#[test]
fn guard_home_b_cannot_take_home_a_record() {
    let temp = temp_root();
    let kid = ContentAccessIdV1::new([0x63; 16]).unwrap();
    let item_a = other_item(0x35);
    provision(
        &store(temp.path()),
        &item_a,
        &runtime_custody_provisioning(&item_a, MINTER, 0xf1, NOW),
        &mint_share_of(&item_a, kid, MINTER),
        NOW + 1,
    )
    .unwrap();
    let home_b = 0x46;
    for kid_b in [kid, ContentAccessIdV1::new([0x64; 16]).unwrap()] {
        let error = provision(
            &store(temp.path()),
            &item_a,
            &runtime_custody_provisioning(&item_a, home_b, 0xf2, NOW),
            &mint_share_of(&item_a, kid_b, home_b),
            NOW + 2,
        )
        .unwrap_err();
        assert!(error.proves_not_stored());
    }
}
