//! Plan B POOL-MINT: a Home mints into the pool it uses.
//!
//! The pool choice and the no-pool refusal, the pool committee as the mint
//! composition (pool-bound bindings, descriptor routes), a resume on the
//! recorded pool, and the item's pool path carried by its signed share
//! statement so every Home rebuilds the same `mint_id`.

use std::path::Path;
use std::sync::Arc;

use base64::Engine as _;
use elastos_protected_content_contracts::test_fixtures::{
    key_envelope_for, node_public_key, pool_bundle, pool_bundle_signed_by, pool_descriptor_routed,
    pool_did, pool_mint_share, POOL_AUTHORITY_SEED,
};
use elastos_protected_content_contracts::{
    CanonicalContract, ContentAccessIdV1, Digest32, EncryptedContentIdentityV1,
    KeyEnvelopeIdentityV1, PoolEpochBundleV1, SignedPoolDescriptorAnyV1, SignedPoolMintShareV1,
    PQ_HYBRID_WRAP_PUBLIC_KEY_BYTES,
};
use elastos_runtime::provider::{
    ProviderCarrierRoute, ProviderInvocationTransport, ProviderRegistry,
};

use super::*;

const MINTER: u8 = 0x44;

fn xwing(seed: u8) -> [u8; PQ_HYBRID_WRAP_PUBLIC_KEY_BYTES] {
    use x_wing::kem::Decapsulator as _;
    use x_wing::KeyExport as _;
    let secret = x_wing::DecapsulationKey::from([seed; x_wing::DECAPSULATION_KEY_SIZE]);
    secret.encapsulation_key().to_bytes().into()
}

fn home() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().join("home");
    std::fs::create_dir_all(&data_dir).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&data_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    elastos_identity::load_or_create_did(&data_dir).unwrap();
    (dir, data_dir)
}

async fn keep_known(data_dir: &Path, descriptor: &SignedPoolDescriptorAnyV1, now: u64) {
    let write = crate::custody_consent::lock_custody_writes().await;
    crate::custody_pool_resolver::keep_known_pool_for_test(
        &write,
        data_dir,
        "elastos-pool:test",
        descriptor,
        now,
    )
    .unwrap();
}

/// A member's canonical peer DID: the did:key of its node key.
fn member_did(seed: u8) -> String {
    crate::carrier::public_key_to_did(&iroh::SecretKey::from_bytes(&[0x90 + seed; 32]).public())
        .unwrap()
}

/// A descriptor whose member routes are canonical peer DIDs.
fn routed(
    bundle: &PoolEpochBundleV1,
    sequence: u64,
    now: u64,
    authority_seed: u8,
) -> SignedPoolDescriptorAnyV1 {
    pool_descriptor_routed(bundle, sequence, now, authority_seed, &member_did).into()
}

fn registry() -> Arc<ProviderRegistry> {
    Arc::new(ProviderRegistry::new())
}

fn message(result: anyhow::Result<RuntimeCustodyMintPool>) -> String {
    match result {
        Ok(_) => "ok".to_string(),
        Err(error) => error.to_string(),
    }
}

#[test]
fn no_pool_answers_the_no_pool_message_before_any_media_work() {
    let (_dir, data_dir) = home();
    assert_eq!(
        message(load_runtime_custody_mint_pool(
            &data_dir,
            registry(),
            None,
            None
        )),
        RUNTIME_CUSTODY_MINT_NO_POOL_MESSAGE
    );
    assert_eq!(
        RUNTIME_CUSTODY_MINT_NO_POOL_MESSAGE,
        "This Home can't mint yet: create a custody pool or add one under Pools this Home uses."
    );
    // A pool this Home does not use is the same refusal.
    let did = pool_did().to_did_key().unwrap();
    assert_eq!(
        message(load_runtime_custody_mint_pool(
            &data_dir,
            registry(),
            Some(&did),
            None
        )),
        RUNTIME_CUSTODY_MINT_NO_POOL_MESSAGE
    );
}

#[tokio::test]
async fn a_home_that_only_uses_the_pool_mints_into_it_over_descriptor_routes() {
    let (_dir, data_dir) = home();
    let now = crate::auth::now_ts();
    let bundle = pool_bundle(xwing, now);
    // The pool's owner admitted nobody: using the pool is enough.
    let descriptor = routed(&bundle, 2, now, POOL_AUTHORITY_SEED);
    keep_known(&data_dir, &descriptor, now).await;
    for requested in [None, Some(pool_did().to_did_key().unwrap())] {
        let pool =
            load_runtime_custody_mint_pool(&data_dir, registry(), requested.as_deref(), None)
                .unwrap();
        assert_eq!(pool.used.as_ref(), Some(&descriptor));
        let epoch = bundle.epoch_identity().unwrap();
        for node in &pool.composition.nodes {
            let seed = [1u8, 2, 3]
                .into_iter()
                .find(|seed| node_public_key(*seed) == node.node_public_key)
                .expect("a committee node of the fixture pool");
            assert_eq!(
                node.owner_state_root,
                elastos_protected_content_runtime::pool_node_owner_state_root(
                    &pool_did(),
                    epoch,
                    node_public_key(seed)
                )
            );
            match &node.adapter.transport {
                ProviderInvocationTransport::Carrier(ProviderCarrierRoute::PeerDid {
                    peer_did,
                    ..
                }) => assert_eq!(peer_did, &member_did(seed)),
                _ => panic!("a remote pool node is reached by its peer DID"),
            }
        }
        let configured = pool.composition.configured_nodes().unwrap();
        assert!(resolve_runtime_mint_selected_nodes(
            pool.composition.expected_policy_authority,
            pool.composition.expected_authorization_identity,
            &pool.composition.signed_pool,
            &pool.composition.signed_epoch,
            &pool.composition.signed_committee_authorization,
            now,
            &configured,
        )
        .is_ok());
    }
}

#[tokio::test]
async fn two_used_pools_need_a_choice() {
    let (_dir, data_dir) = home();
    let now = crate::auth::now_ts();
    let first = routed(&pool_bundle(xwing, now), 1, now, POOL_AUTHORITY_SEED);
    let other = pool_bundle_signed_by(xwing, now, None, None, 0x73);
    let second = routed(&other, 1, now, 0x73);
    keep_known(&data_dir, &first, now).await;
    keep_known(&data_dir, &second, now).await;
    assert_eq!(
        message(load_runtime_custody_mint_pool(
            &data_dir,
            registry(),
            None,
            None
        )),
        RUNTIME_CUSTODY_MINT_POOL_CHOICE_MESSAGE
    );
    let did = second.pool().to_did_key().unwrap();
    let chosen = load_runtime_custody_mint_pool(&data_dir, registry(), Some(&did), None).unwrap();
    assert_eq!(chosen.used.as_ref(), Some(&second));
}

/// S7I-F1: a resumed mint uses the pool its journal recorded, with no
/// reselection and no fallback, even after the pool was removed from the
/// pools this Home uses.
#[cfg(unix)]
#[tokio::test]
async fn resume_after_the_used_pool_is_removed_still_finishes_on_the_recorded_pool() {
    let (_dir, data_dir) = home();
    let now = crate::auth::now_ts();
    let descriptor = routed(&pool_bundle(xwing, now), 1, now, POOL_AUTHORITY_SEED);
    keep_known(&data_dir, &descriptor, now).await;
    let input = tests::library_publish_test_input(&data_dir, "person:local:pool-mint-resume");
    let source = (
        input.principal_id.as_str(),
        input.object_uri.as_str(),
        input.source_storage.as_str(),
    );
    let pool = load_runtime_custody_mint_pool(&data_dir, registry(), None, Some(source)).unwrap();
    assert_eq!(pool.used.as_ref(), Some(&descriptor));
    let configured = pool.composition.configured_nodes().unwrap();
    let selected = resolve_runtime_mint_selected_nodes(
        pool.composition.expected_policy_authority,
        pool.composition.expected_authorization_identity,
        &pool.composition.signed_pool,
        &pool.composition.signed_epoch,
        &pool.composition.signed_committee_authorization,
        now,
        &configured,
    )
    .unwrap();
    let intent = load_or_persist_runtime_mint_intent(
        &runtime_mint_journal(&data_dir),
        &pool.composition,
        &input,
        selected.iter().map(|node| node.binding().clone()).collect(),
    )
    .unwrap();
    // The pool is removed from "Pools this Home uses", and another is added.
    std::fs::remove_file(
        protected_content_root(&data_dir).join(crate::custody_pool_resolver::KNOWN_POOLS_FILE),
    )
    .unwrap();
    let other = routed(
        &pool_bundle_signed_by(xwing, now, None, None, 0x73),
        1,
        now,
        0x73,
    );
    keep_known(&data_dir, &other, now).await;
    let other_did = other.pool().to_did_key().unwrap();
    for requested in [None, Some(other_did.as_str())] {
        let resumed =
            load_runtime_custody_mint_pool(&data_dir, registry(), requested, Some(source)).unwrap();
        assert_eq!(resumed.used.as_ref(), Some(&descriptor));
        assert_eq!(
            resumed.composition.signed_epoch.epoch_identity().unwrap(),
            intent.custody_epoch()
        );
    }
}

// ---------------------------------------------------------------------------
// S7I-F2: the item's pool path travels with it, signed.
// ---------------------------------------------------------------------------

fn envelope(seed: u8) -> KeyEnvelopeIdentityV1 {
    key_envelope_for(
        &pool_bundle(xwing, crate::auth::now_ts()),
        &EncryptedContentIdentityV1::new(Digest32::new([seed; 32]), 4096).unwrap(),
    )
}

fn kid() -> ContentAccessIdV1 {
    ContentAccessIdV1::new([0x41; 16]).unwrap()
}

fn b64(value: &impl CanonicalContract) -> String {
    base64::engine::general_purpose::STANDARD.encode(value.canonical_bytes().unwrap())
}

#[test]
fn a_pool_minted_listing_is_pool_bound_on_every_home() {
    let share = pool_mint_share(pool_did(), &envelope(0x11), kid(), MINTER);
    assert!(verify_pool_mint_share(Some(&b64(&share)), &envelope(0x11), kid()).unwrap());
    assert!(!verify_pool_mint_share(None, &envelope(0x11), kid()).unwrap());
    // The owner (who holds the ciphertext) and a third Home take one path.
    for holds in [true, false] {
        assert_eq!(
            draft_node_bindings_for(ItemMintPath::Pool, holds),
            DraftNodeBindings::PoolBound
        );
    }
}

#[test]
fn guard_a_tampered_or_swapped_pool_mint_share_is_refused() {
    let share = pool_mint_share(pool_did(), &envelope(0x11), kid(), MINTER);
    let mut signature = share.runtime_signature().to_vec();
    signature[3] ^= 1;
    let tampered = SignedPoolMintShareV1::new(share.statement().clone(), signature).unwrap();
    assert!(verify_pool_mint_share(Some(&b64(&tampered)), &envelope(0x11), kid()).is_err());
    // Another item's statement, or another KID.
    assert!(verify_pool_mint_share(Some(&b64(&share)), &envelope(0x12), kid()).is_err());
    assert!(verify_pool_mint_share(
        Some(&b64(&share)),
        &envelope(0x11),
        ContentAccessIdV1::new([0x42; 16]).unwrap()
    )
    .is_err());
}

/// Adoption by the owner or a third Home reads the item's pool path from its
/// shared document, so both rebuild the creator's `mint_id`.
#[test]
fn adoption_reads_the_pool_path_from_the_shared_document() {
    let share = b64(&pool_mint_share(pool_did(), &envelope(0x11), kid(), MINTER));
    let protection = crate::protected_content_elacity_metadata::runtime_custody_protection(
        2,
        3,
        crate::protected_content_elacity_metadata::ProtectedContentIdentities {
            rights_policy: "cG9saWN5",
            key_envelope: "ZW52ZWxvcGU=",
            content_key_commitment: "Y29tbWl0bWVudA==",
            content_identity: "aWRlbnRpdHk=",
            pool_mint_share: Some(&share),
        },
    );
    assert_eq!(protection["pool_mint_share_base64"], share.as_str());
    let without = crate::protected_content_elacity_metadata::runtime_custody_protection(
        2,
        3,
        crate::protected_content_elacity_metadata::ProtectedContentIdentities {
            rights_policy: "cG9saWN5",
            key_envelope: "ZW52ZWxvcGU=",
            content_key_commitment: "Y29tbWl0bWVudA==",
            content_identity: "aWRlbnRpdHk=",
            pool_mint_share: None,
        },
    );
    assert!(without.get("pool_mint_share_base64").is_none());
}

#[tokio::test]
async fn creator_lists_this_homes_pool_and_the_pools_it_uses() {
    let (_dir, data_dir) = home();
    let now = crate::auth::now_ts();
    let first = routed(&pool_bundle(xwing, now), 1, now, POOL_AUTHORITY_SEED);
    let second = routed(
        &pool_bundle_signed_by(xwing, now, None, None, 0x73),
        1,
        now,
        0x73,
    );
    keep_known(&data_dir, &first, now).await;
    keep_known(&data_dir, &second, now).await;
    let choices = runtime_custody_mint_pool_choices(&data_dir);
    assert_eq!(choices.len(), 2, "{choices:?}");
    for pool in [&first, &second] {
        let did = pool.pool().to_did_key().unwrap();
        let choice = choices
            .iter()
            .find(|choice| choice["pool_did"] == did.as_str())
            .unwrap();
        assert!(choice["label"].as_str().unwrap().starts_with("Pool "));
        assert!(choice.get("admitted").is_none());
    }
}

// ---------------------------------------------------------------------------
// The host storage maximum (Anders #388): one WCI-set total per host, across
// all its pools, whichever Home mints. No per-creator quota.
// ---------------------------------------------------------------------------

fn plant_share_bytes(data_dir: &Path, root: &str, name: &str, bytes: usize) {
    let store = custody_provider::node_share_store_dir(&custody_root_dir(data_dir, root));
    std::fs::create_dir_all(&store).unwrap();
    std::fs::write(store.join(name), vec![0u8; bytes]).unwrap();
}

#[test]
fn guard_a_wci_host_without_a_storage_maximum_refuses_shares() {
    let (_dir, data_dir) = home();
    // Fail closed: no record, and a WCI record without a maximum.
    for _ in 0..2 {
        let refusal = host_storage_refusal(&data_dir, 1).expect("refused");
        assert_eq!(refusal["code"], crate::host_trust::HOST_STORAGE_MAX_UNSET);
        assert!(refusal["message"]
            .as_str()
            .unwrap()
            .contains("--max-storage-bytes"));
        crate::host_trust::write_host_trust(
            &data_dir,
            crate::host_trust::HostTrustModeV1::WciOperated,
            None,
        )
        .unwrap();
    }
}

#[test]
fn guard_a_share_past_the_host_storage_maximum_is_refused_with_storage_full() {
    let (_dir, data_dir) = home();
    crate::host_trust::write_host_trust(
        &data_dir,
        crate::host_trust::HostTrustModeV1::WciOperated,
        Some(100),
    )
    .unwrap();
    // Shares of two pools count toward one host total.
    plant_share_bytes(&data_dir, "inactive", "a", 40);
    plant_share_bytes(&data_dir, &format!("pools/{}", "ab".repeat(32)), "b", 40);
    assert_eq!(host_custody_storage_bytes(&data_dir).unwrap(), 80);
    assert_eq!(host_storage_refusal(&data_dir, 20), None);
    let refusal = host_storage_refusal(&data_dir, 21).expect("refused");
    assert_eq!(refusal["code"], crate::host_trust::HOST_STORAGE_FULL);
    // Both refusals prove nothing was stored, so a mint closes cleanly.
    for code in [
        crate::host_trust::HOST_STORAGE_FULL,
        crate::host_trust::HOST_STORAGE_MAX_UNSET,
    ] {
        assert!(CUSTODY_EFFECT_FREE_REFUSAL_CODES.contains(&code));
    }
}

fn host_with_storage_maximum(max: u64) -> (tempfile::TempDir, std::path::PathBuf) {
    let (dir, data_dir) = home();
    crate::host_trust::write_host_trust(
        &data_dir,
        crate::host_trust::HostTrustModeV1::WciOperated,
        Some(max),
    )
    .unwrap();
    (dir, data_dir)
}

/// PM-F2: the maximum check and the write it allows are one step under the
/// host-wide lock. Two writes that each fit alone but not together: one is
/// stored, the other is refused with `storage_full`.
#[tokio::test]
async fn guard_two_concurrent_share_writes_that_only_fit_alone_store_one() {
    let (_dir, data_dir) = host_with_storage_maximum(100);
    plant_share_bytes(&data_dir, "inactive", "held", 40);
    let write = |name: &'static str| {
        let data_dir = data_dir.clone();
        guarded_host_share_write(
            data_dir.clone(),
            40,
            || false,
            move || async move {
                // The provider answers after a pause: without the lock, the
                // other write is checked inside it.
                tokio::task::yield_now().await;
                plant_share_bytes(&data_dir, "inactive", name, 40);
                Ok(json!({ "status": "ok" }))
            },
        )
    };
    let (first, second) = tokio::join!(write("first"), write("second"));
    let mut answers = [first.unwrap(), second.unwrap()].map(|answer| {
        answer["code"]
            .as_str()
            .unwrap_or(answer["status"].as_str().unwrap())
            .to_string()
    });
    answers.sort();
    assert_eq!(answers, ["ok", crate::host_trust::HOST_STORAGE_FULL]);
    assert_eq!(host_custody_storage_bytes(&data_dir).unwrap(), 80);
}

/// PM-F2: the write runs in its own task, in the caller's dispatch fence, so
/// the provider dispatch it makes is still fenced.
#[tokio::test]
async fn a_host_share_write_keeps_the_callers_dispatch_fence() {
    let (_dir, data_dir) = host_with_storage_maximum(100);
    let fence = elastos_runtime::provider::dispatch::DispatchFence::new(|| Ok(()));
    let fenced = fence
        .scope(guarded_host_share_write(
            data_dir,
            1,
            || false,
            || async {
                Ok(json!({
                    "fenced": elastos_runtime::provider::dispatch::DispatchFence::current()
                        .is_some(),
                }))
            },
        ))
        .await
        .unwrap();
    assert_eq!(fenced["fenced"], true);
}

/// PM-F3: a stopped pool's retained shares still count toward the host
/// maximum when another pool provisions.
#[test]
fn guard_a_stopped_pools_retained_shares_still_count() {
    let (_dir, data_dir) = host_with_storage_maximum(100);
    let stopped = format!("pools/{}", "ab".repeat(32));
    plant_share_bytes(&data_dir, &stopped, "retained", 70);
    // Stopping keeps the root as a tombstone (custody_pool_setup).
    std::fs::rename(
        custody_root_dir(&data_dir, &stopped),
        custody_root_dir(&data_dir, &format!("{stopped}.stopped-1700000000")),
    )
    .unwrap();
    plant_share_bytes(&data_dir, &format!("pools/{}", "cd".repeat(32)), "a", 10);
    assert_eq!(host_custody_storage_bytes(&data_dir).unwrap(), 80);
    assert_eq!(host_storage_refusal(&data_dir, 20), None);
    let refusal = host_storage_refusal(&data_dir, 21).expect("refused");
    assert_eq!(refusal["code"], crate::host_trust::HOST_STORAGE_FULL);
}

/// PM-F4: an exact retry (the reply was lost) fills no new slot, so it is not
/// charged: at a full maximum the stored receipt still comes back. A new slot
/// at the same maximum is refused before it is sent.
#[tokio::test]
async fn an_exact_retry_at_a_full_host_maximum_gets_its_stored_receipt_back() {
    let (_dir, data_dir) = host_with_storage_maximum(100);
    plant_share_bytes(&data_dir, "inactive", "stored", 100);
    let receipt = json!({ "status": "ok", "data": { "receipt": "stored" } });
    let stored = receipt.clone();
    let retried = guarded_host_share_write(data_dir.clone(), 40, || true, || async { Ok(stored) })
        .await
        .unwrap();
    assert_eq!(retried, receipt);
    let new = guarded_host_share_write(
        data_dir.clone(),
        40,
        || false,
        || async { panic!("a refused share is never sent") },
    )
    .await
    .unwrap();
    assert_eq!(new["code"], crate::host_trust::HOST_STORAGE_FULL);
}

/// PM-F5: a recorded mint settles on its original pool and epoch after the
/// descriptor and the term expired: no freshness check, no reselection. A
/// new mint into the expired pool is refused.
#[cfg(unix)]
#[tokio::test]
async fn a_recorded_mint_settles_on_its_pool_after_the_descriptor_and_term_expired() {
    let (_dir, data_dir) = home();
    let now = crate::auth::now_ts();
    let then = now - 3 * 86_400;
    let descriptor = routed(&pool_bundle(xwing, then), 1, then, POOL_AUTHORITY_SEED);
    keep_known(&data_dir, &descriptor, then).await;
    let input = tests::library_publish_test_input(&data_dir, "person:local:pool-mint-expired");
    let source = (
        input.principal_id.as_str(),
        input.object_uri.as_str(),
        input.source_storage.as_str(),
    );
    // The attempt was recorded and its intent written while the pool was
    // fresh.
    let started = RuntimeCustodyMintPool {
        composition: runtime_custody_composition_for_pool(
            &data_dir,
            registry(),
            &descriptor,
            None,
            then,
        )
        .unwrap(),
        used: Some(descriptor.clone()),
        recorded: false,
    };
    record_runtime_mint_attempt_pool(&data_dir, source, Some(&descriptor)).unwrap();
    let configured = started.composition.configured_nodes().unwrap();
    let selected = started.selected_nodes(&configured, then).unwrap();
    let intent = load_or_persist_runtime_mint_intent(
        &runtime_mint_journal(&data_dir),
        &started.composition,
        &input,
        selected.iter().map(|node| node.binding().clone()).collect(),
    )
    .unwrap();
    // Now the descriptor and the term are past: no new mint goes into it.
    assert_eq!(
        message(load_runtime_custody_mint_pool(
            &data_dir,
            registry(),
            None,
            None
        )),
        RUNTIME_CUSTODY_MINT_NO_POOL_MESSAGE
    );
    let resumed =
        load_runtime_custody_mint_pool(&data_dir, registry(), None, Some(source)).unwrap();
    assert!(resumed.recorded);
    assert_eq!(resumed.used.as_ref(), Some(&descriptor));
    assert_eq!(
        resumed.composition.signed_epoch.epoch_identity().unwrap(),
        intent.custody_epoch()
    );
    let configured = resumed.composition.configured_nodes().unwrap();
    let settled = resumed.selected_nodes(&configured, now).unwrap();
    assert_eq!(
        settled
            .iter()
            .map(|node| node.binding().clone())
            .collect::<Vec<_>>(),
        selected
            .iter()
            .map(|node| node.binding().clone())
            .collect::<Vec<_>>()
    );
}
