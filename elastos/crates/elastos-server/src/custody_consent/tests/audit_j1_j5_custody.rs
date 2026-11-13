//! AUDIT-REPRO J1/J5 (coll-journey-audit-20261117.md J5-1,
//! J5-2, J5-4, J5-5, J5-6, J5-7, J5-8; journey-audit-20261117.md F7): red
//! tests only, no fix. Each asserts the behaviour the finding says is
//! missing, through the production functions the journey runs.

use super::*;

/// J5-1: a Stop that fails after its `pools/<hex>` root was set aside keeps
/// the served-pools entry (so the API could stop it again), but the root
/// moved with the node card inside it, so Custody lists no serving node and
/// offers no Stop button. Nothing in the delivery pass finishes it.
/// Trigger: Kubo cannot report a kept copy's pin state (Kubo down).
#[tokio::test]
async fn audit_j5_1_a_stop_that_fails_after_its_root_is_set_aside_stays_offered_or_finishes() {
    let now = crate::auth::now_ts();
    let (node, _olivia, oscar) = two_pools(now).await;
    let root = pool_root_of(&oscar);
    let root_dir = crate::protected_content_runtime::custody_root_dir(&node.data_dir, &root);
    assert!(
        crate::protected_content_config::custody_node_descriptor_path_for(&node.data_dir, &root)
            .starts_with(&root_dir),
        "precondition: a pools/<hex> root keeps its node card inside the root"
    );
    let hex = oscar
        .pool_fingerprint()
        .strip_prefix("sha256:")
        .unwrap()
        .to_string();
    assert!(
        crate::custody_pool_setup::summary(&node.data_dir, None, None, None)
            .await
            .serving
            .iter()
            .any(|serving| serving.pool_fingerprint == hex),
        "precondition: Custody offers Stop for Oscar's pool"
    );
    // One copy kept for Oscar's pool, whose pin state Kubo cannot report.
    let cid = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi".to_string();
    record_member_copy(
        &node.data_dir,
        MemberCopyV1 {
            cid: cid.clone(),
            owner_did: oscar.did(),
            pool_fingerprint: oscar.pool_fingerprint(),
            bytes: 10,
            borrowed: false,
        },
    )
    .unwrap();
    let ipfs = Arc::new(MemberIpfs::default());
    *ipfs.pin_status_fails.lock().unwrap() = Some(cid);
    let registry = Arc::new(ProviderRegistry::new());
    registry
        .register_sub_provider("ipfs", ipfs.clone())
        .await
        .unwrap();

    let write = lock_custody_writes().await;
    let stopped = crate::custody_pool_setup::stop_serving_pool(
        &write,
        &node.data_dir,
        Some(&registry),
        &hex,
        now,
    )
    .await;
    drop(write);
    assert!(stopped.is_err(), "precondition: the Stop fails");
    assert!(!root_dir.exists(), "precondition: the root was set aside");
    // A later delivery pass (the only periodic custody step) runs.
    node.handler.before_delivery_pass(now + 1);

    let entry_kept = served_pools(&node.data_dir)
        .unwrap()
        .entries
        .contains_key(&oscar.pool_fingerprint());
    let offered = crate::custody_pool_setup::summary(&node.data_dir, None, None, None)
        .await
        .serving
        .iter()
        .any(|serving| serving.pool_fingerprint == hex);
    assert!(
        !entry_kept || offered,
        "J5-1: after a failed Stop the pool's entry is kept (entry_kept={entry_kept}) \
         but Custody lists no serving node for it (offered={offered}): no Stop button, \
         and nothing finished the Stop"
    );
}

/// J5-2: Stop serving tells the pool owner nothing. The owner keeps the
/// node in its descriptor and committee.
#[tokio::test]
async fn audit_j5_2_stopping_a_pool_tells_its_owner() {
    let now = crate::auth::now_ts();
    let olivia = Owner::new("Olivia", now);
    let node = serving(&olivia, now, 0x21).await;
    assert!(node.outbox.keys().is_empty());

    stop_serving(&node, &olivia, now).await;

    let queued = node.outbox.keys();
    assert!(
        !queued.is_empty(),
        "J5-2: the member stopped serving Olivia's pool and queued no message to her: {queued:?}"
    );
}

/// J5-4: the Approved decision the node kept for the stopped pool is queued
/// to the owner again by the next delivery pass after a restart.
#[tokio::test]
async fn audit_j5_4_a_stopped_pools_approval_is_not_queued_again_after_restart() {
    let now = crate::auth::now_ts();
    let olivia = Owner::new("Olivia", now);
    let node = serving(&olivia, now, 0x22).await;
    stop_serving(&node, &olivia, now).await;
    // A restart: the outbox is empty, the records are on disk.
    node.outbox.clear();

    node.handler.before_delivery_pass(now + 1);

    let approvals: Vec<String> = node
        .outbox
        .decisions()
        .into_iter()
        .filter(|decision| decision.outcome == CustodyNodeDecisionOutcome::Approved)
        .map(|decision| decision.request_id)
        .collect();
    assert!(
        approvals.is_empty(),
        "J5-4: the stopped pool's approval {approvals:?} is sent to its owner again"
    );
}

/// J5-5: the shares of a stopped pool's set-aside root stay charged to the
/// host storage maximum for ever: a Stop 400 days ago still counts.
#[tokio::test]
async fn audit_j5_5_a_set_aside_root_is_released_after_its_retention() {
    let now = crate::auth::now_ts();
    let (node, _olivia, oscar) = two_pools(now).await;
    let root = pool_root_of(&oscar);
    let store = custody_provider::node_share_store_dir(
        &crate::protected_content_runtime::custody_root_dir(&node.data_dir, &root),
    );
    std::fs::create_dir_all(&store).unwrap();
    std::fs::write(store.join("retained"), vec![0u8; 1000]).unwrap();
    assert_eq!(
        crate::protected_content_runtime::host_custody_storage_bytes(&node.data_dir).unwrap(),
        1000
    );

    stop_serving(&node, &oscar, now - 400 * DAY).await;
    node.handler.before_delivery_pass(now);

    let charged =
        crate::protected_content_runtime::host_custody_storage_bytes(&node.data_dir).unwrap();
    assert!(
        charged < 1000,
        "J5-5: a root set aside 400 days ago is still charged {charged} bytes; nothing releases it"
    );
}

/// J5-6: a copy record whose pin is gone (a kill between the record's
/// reservation and the pin, or a pin another owner dropped) is kept and
/// charged: no reconcile drops or repairs it.
#[tokio::test]
async fn audit_j5_6_a_copy_record_whose_pin_is_gone_is_reconciled() {
    let item = ListedItem::new("film");
    let fixture = CopyFixture::new(0x2a, &[&item], AMPLE).await;
    assert_eq!(
        fixture.keep(&item.listing.cid).await,
        Ok(crate::carrier::MemberCopyOutcome::Kept)
    );
    let charged_before = member_copies_bytes(&fixture.member.data_dir).unwrap();
    // The payload's pin is gone; its record stays.
    fixture
        .ipfs
        .pinned
        .lock()
        .unwrap()
        .remove(&item.content.cid);
    assert_eq!(
        crate::carrier::local_cid_pinned(&fixture.registry, &item.content.cid).await,
        Some(false),
        "precondition: the pin is proven absent"
    );

    // STAB-49: the start's reconcile pass. The delivery pass has no
    // provider registry to read pin states with, so the sheet's boot pass
    // is the trigger (STAB-IMPL WP-C: trigger changed, assertion unchanged).
    crate::custody_consent::reconcile_member_copy_pins(&fixture.registry, &fixture.member.data_dir)
        .await;

    let still_recorded = fixture.recorded().contains(&item.content.cid);
    let charged_after = member_copies_bytes(&fixture.member.data_dir).unwrap();
    assert!(
        !still_recorded,
        "J5-6: the copy record of an unpinned CID is kept and charged \
         ({charged_after} of {charged_before} bytes still charged)"
    );
}

/// J5-7: a copy's staging folder a kill left behind is never removed, and
/// the host storage account does not count it.
#[tokio::test]
async fn audit_j5_7_boot_removes_stale_member_copy_staging() {
    let now = crate::auth::now_ts();
    let olivia = Owner::new("Olivia", now);
    let node = serving(&olivia, now, 0x23).await;
    let staging = protected_content_root(&node.data_dir)
        .join("member-copies")
        .join("staging-killed");
    std::fs::create_dir_all(&staging).unwrap();
    std::fs::write(staging.join("object.epc1"), vec![0u8; 4096]).unwrap();

    // The start's custody step, and a delivery pass. STAB-50: the staging
    // cleanup runs at start before Carrier (server_infra), not in `resume`
    // (STAB-IMPL WP-C: trigger added, assertion unchanged).
    crate::custody_pool_setup::remove_stale_member_copy_staging(&node.data_dir);
    crate::custody_consent::resume(&node.data_dir, node.outbox.as_ref(), now).unwrap();
    node.handler.before_delivery_pass(now + 1);

    let counted =
        crate::protected_content_runtime::host_custody_storage_bytes(&node.data_dir).unwrap();
    assert!(
        !staging.exists() || counted >= 4096,
        "J5-7: a stale copy staging folder stays on disk ({} bytes) and is uncounted \
         (host storage counts {counted})",
        4096
    );
}

/// J5-8: a Stop holds the host share-write lock across its whole
/// withdrawal. A share write that arrives while the first copy is being
/// unpinned waits until every copy of the pool is unpinned.
#[tokio::test]
async fn audit_j5_8_a_stop_does_not_hold_share_writes_for_its_whole_withdrawal() {
    let item = ListedItem::new("film");
    let fixture = Arc::new(CopyFixture::new(0x2c, &[&item], AMPLE).await);
    assert_eq!(
        fixture.keep(&item.listing.cid).await,
        Ok(crate::carrier::MemberCopyOutcome::Kept)
    );
    let copies = member_copies(&fixture.member.data_dir).unwrap();
    assert_eq!(copies.len(), 3, "precondition: three copies kept");
    let first = copies[0].cid.clone();
    let gate = Gate::new(&first, "unpin");
    *fixture.ipfs.gate.lock().unwrap() = Some(gate.clone());

    let stopping = tokio::spawn({
        let fixture = Arc::clone(&fixture);
        async move { fixture.stop().await }
    });
    gate.reached.notified().await;
    // A share write (a pool mint's share, another pool's copy) arrives now.
    let writer = tokio::spawn({
        let fixture = Arc::clone(&fixture);
        async move {
            let _write = crate::protected_content_runtime::lock_host_share_writes().await;
            fixture.ipfs.pinned()
        }
    });
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    gate.release();
    stopping.await.unwrap().unwrap();

    let pinned_when_the_write_ran = writer.await.unwrap();
    let others_left: Vec<String> = item
        .cids()
        .into_iter()
        .filter(|cid| *cid != first && pinned_when_the_write_ran.contains(cid))
        .collect();
    assert!(
        !others_left.is_empty(),
        "J5-8: the share write ran only after the whole withdrawal: pinned then = \
         {pinned_when_the_write_ran:?}"
    );
}

/// STAB-51: another publication can acquire the host lock between two
/// withdrawn copies. Each next-copy step must see the owner it records.
#[tokio::test]
async fn stab_51_a_publication_between_copy_withdrawals_keeps_its_pin() {
    let item = ListedItem::new("film");
    let fixture = CopyFixture::new(0x2d, &[&item], AMPLE).await;
    fixture.keep(&item.listing.cid).await.unwrap();
    let copies = member_copies(&fixture.member.data_dir).unwrap();
    assert_eq!(copies.len(), 3);
    let published_cid = copies[1].cid.clone();
    let data_dir = &fixture.member.data_dir;
    let pool_key = fixture.owner.pool_fingerprint();

    // Run the same per-copy step as Stop, then let a Library publish run
    // in the interval where Stop has released HOST_SHARE_WRITES.
    assert!(
        withdraw_next_member_copy(data_dir, Some(&fixture.registry), &pool_key,)
            .await
            .unwrap()
    );
    assert!(fixture.ipfs.pinned().contains(&published_cid));
    let library = Arc::new(ProviderRegistry::new());
    library
        .register_sub_provider(
            "content",
            Arc::new(HeldPublishContent {
                ipfs: fixture.ipfs.clone(),
                cid: published_cid.clone(),
                gate: StdMutex::new(None),
            }),
        )
        .await
        .unwrap();
    let principal = "did:key:z6MkBetweenCopyWithdrawals";
    let uri = format!(
        "{}/Documents/film.bin",
        crate::auth::principal_localhost_root(principal)
    );
    let written = Box::pin(crate::library::handle_object_provider_runtime_request(
        data_dir,
        library.clone(),
        &serde_json::json!({
            "op": "write",
            "principal_id": principal,
            "uri": uri,
            "data": base64::engine::general_purpose::STANDARD.encode(b"film"),
        }),
    ))
    .await;
    assert_eq!(written["status"], "ok", "{written}");
    let published = Box::pin(crate::library::handle_object_provider_runtime_request(
        data_dir,
        library,
        &serde_json::json!({"op": "publish", "principal_id": principal, "uri": uri}),
    ))
    .await;
    assert_eq!(published["status"], "ok", "{published}");
    assert!(crate::library::published_cids(data_dir)
        .unwrap()
        .contains(&published_cid));

    while withdraw_next_member_copy(data_dir, Some(&fixture.registry), &pool_key)
        .await
        .unwrap()
    {}

    assert!(fixture.recorded().is_empty());
    assert_eq!(
        fixture.ipfs.pinned(),
        BTreeSet::from([published_cid]),
        "a publication committed between copies keeps its pin after Stop"
    );
}

/// journey-audit F7, adapted per D3 (STAB-42): a Home that mints into a pool
/// it does not own targets the pool's owner for a copy, and the owner keeps
/// copies of its own pool's mints (its own pool counts as served for copy
/// admission, `own_copy_pool`), so the owner is a copy holder.
#[tokio::test]
async fn audit_j1_f7b_a_pool_listing_is_placed_only_on_members_that_can_keep_it() {
    use elastos_protected_content_contracts::test_fixtures::{
        pool_descriptor_routed, POOL_AUTHORITY_SEED,
    };
    let now = crate::auth::now_ts();
    let minter = node(now);
    let (_, own) = elastos_identity::load_existing_did(&minter.data_dir).unwrap();
    // The pool owner's Home: its device key is the descriptor's Runtime owner.
    let owner_home = crate::carrier::public_key_to_did(
        &iroh::SecretKey::from_bytes(&[POOL_AUTHORITY_SEED; 32]).public(),
    )
    .unwrap();
    let third =
        crate::carrier::public_key_to_did(&iroh::SecretKey::from_bytes(&[0xb3; 32]).public())
            .unwrap();
    let bundle = elastos_protected_content_contracts::test_fixtures::pool_bundle(copy_xwing, now);
    let route = |seed: u8| match seed {
        1 => own.clone(),
        2 => owner_home.clone(),
        _ => third.clone(),
    };
    let descriptor: elastos_protected_content_contracts::SignedPoolDescriptorAnyV1 =
        pool_descriptor_routed(&bundle, 1, now, POOL_AUTHORITY_SEED, &route).into();
    assert!(
        descriptor.verify(now).is_ok(),
        "precondition: the descriptor verifies"
    );
    let write = lock_custody_writes().await;
    crate::custody_pool_resolver::keep_known_pool_for_test(
        &write,
        &minter.data_dir,
        "elastos-pool:test",
        &descriptor,
        now,
    )
    .unwrap();
    drop(write);
    let pool = bundle.signed_pool().pool_identity().unwrap();

    let holders = crate::custody_pool_descriptor::pool_copy_holders(&minter.data_dir, pool, now);

    assert!(
        holders.contains(&owner_home) && holders.contains(&third) && !holders.contains(&own),
        "F7 (D3): the minter asks the owner {owner_home} and the other member to keep a \
         copy, never itself: {holders:?}"
    );
}

/// J1-F9 (STAB-IMPL WP-B proof): the owner's copy fails part-way (it does
/// not serve the payload), after the member imported the listing folder.
/// The replica `ensure` must not then fall back to a plain pin of that
/// folder: such a pin has no copy record, so it is neither charged to the
/// host storage maximum nor withdrawn by Stop.
#[tokio::test]
async fn audit_j1_f9_a_failed_owner_copy_leaves_no_pin_outside_copy_accounting() {
    let item = ListedItem::new("film");
    let fixture = CopyFixture::new(0x2e, &[&item], AMPLE).await;
    fixture
        .folders
        .files
        .lock()
        .unwrap()
        .retain(|(cid, _), _| *cid != item.content.cid);

    let answer = fixture.owner_asks_to_keep(&item.listing.cid).await;

    let recorded = fixture.recorded();
    let unaccounted: Vec<String> = fixture
        .ipfs
        .pinned()
        .into_iter()
        .filter(|cid| !recorded.contains(cid))
        .collect();
    assert!(
        unaccounted.is_empty(),
        "J1-F9: a failed owner copy left {unaccounted:?} pinned with no copy record \
         (recorded {recorded:?}); the ensure answered ok={} status={}",
        answer["ok"],
        answer["result"]["data"]["availability"]["status"]
    );
}
