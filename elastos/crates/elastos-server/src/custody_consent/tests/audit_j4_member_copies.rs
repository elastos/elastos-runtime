//! AUDIT-REPRO J4 (coll-journey-audit-20261117.md J4-F3(b), J4-F4, J4-F6;
//! journey-audit A2-F1, A2-F6): red tests only, no fix. Each runs the
//! MEMBER-COPIES fixture: a real owner Home on Carrier and a member serving
//! its pool with its own content plane.

use super::*;

#[tokio::test]
async fn stab_r1_f1_substituted_metadata_cannot_add_an_unrelated_private_copy() {
    let item = ListedItem::new("film");
    let private = ListedItem::new("private");
    let fixture = Arc::new(CopyFixture::new(0x91, &[&item, &private], AMPLE).await);
    fixture
        .ipfs
        .pinned
        .lock()
        .unwrap()
        .insert(private.content.cid.clone());
    let reader = stranger();
    assert!(fixture
        .peer_reads(&reader, &private.content.cid)
        .await
        .is_err());
    let gate = Gate::new(&item.metadata.cid, "pin");
    *fixture.ipfs.gate.lock().unwrap() = Some(gate.clone());
    let keep = tokio::spawn({
        let fixture = fixture.clone();
        let cid = item.listing.cid.clone();
        async move { fixture.keep(&cid).await }
    });
    gate.reached.notified().await;
    // The imported metadata already passed its manifest/CID checks. The
    // requester substitutes only its later, unproved response.
    fixture.folders.files.lock().unwrap().insert(
        (
            item.metadata.cid.clone(),
            crate::library::METADATA_DOCUMENT_PATH.to_string(),
        ),
        serde_json::to_vec(
            &serde_json::json!({"image": format!("ipfs://{}", private.content.cid)}),
        )
        .unwrap(),
    );
    gate.release();
    let outcome = keep.await.unwrap();
    assert_eq!(outcome, Ok(crate::carrier::MemberCopyOutcome::Kept));
    assert!(
        !fixture.recorded().contains(&private.content.cid),
        "the requester substituted a CID outside the verified metadata"
    );
    assert!(fixture
        .peer_reads(&reader, &private.content.cid)
        .await
        .is_err());
}

#[tokio::test]
async fn stab_r1_f5_both_pools_servers_can_read_a_shared_copy_without_a_limit() {
    let item = ListedItem::new("film");
    let fixture = CopyFixture::new(0x93, &[&item], AMPLE).await;
    fixture.keep(&item.listing.cid).await.unwrap();
    let now = crate::auth::now_ts();
    let second = Owner::new("Oscar", now);
    fixture.member.installs_provider_for(&second.issuer(), 0xa7);
    assert_eq!(fixture.member.receive(&second, 3, now), Ok(()));
    fixture.member.approve(3, now).await.unwrap();
    let descriptor = elastos_protected_content_contracts::test_fixtures::pool_descriptor(
        &served_custody_pool(),
        2,
        elastos_protected_content_contracts::RuntimeOperationIssuerKeyV1::new(
            second.device.verifying_key().to_bytes(),
        )
        .unwrap(),
        *COPY_POOL_AT,
    );
    assert!(
        descriptor.verify(now).is_ok(),
        "second pool descriptor must be current"
    );
    update_served_pools(&fixture.member.data_dir, |pools| {
        use elastos_protected_content_contracts::CanonicalContract as _;
        pools
            .entries
            .get_mut(&second.pool_fingerprint())
            .unwrap()
            .descriptor = Some(
            base64::engine::general_purpose::STANDARD.encode(descriptor.canonical_bytes().unwrap()),
        );
        Ok(())
    })
    .unwrap();
    assert_eq!(
        crate::custody_pool_descriptor::served_descriptors(&fixture.member.data_dir, now)
            .unwrap()
            .len(),
        2,
        "both served descriptors must verify at the current time"
    );
    record_member_copy(
        &fixture.member.data_dir,
        MemberCopyV1 {
            cid: item.content.cid.clone(),
            owner_did: second.did(),
            pool_fingerprint: second.pool_fingerprint(),
            bytes: 100,
            borrowed: true,
        },
    )
    .unwrap();
    let second_peer =
        iroh::PublicKey::from_bytes(&second.device.verifying_key().to_bytes()).unwrap();
    let mut limited = Vec::new();
    for peer in [fixture.owner_endpoint(), second_peer] {
        for read in 1..=241 {
            if let Err(answer) = fixture.peer_reads(&peer, &item.content.cid).await {
                limited.push((
                    crate::carrier::public_key_to_did(&peer).unwrap(),
                    read,
                    answer,
                ));
                break;
            }
        }
    }
    assert!(
        limited.is_empty(),
        "both active pools serve the shared CID: {limited:?}"
    );
    let outsider = stranger();
    for _ in 0..240 {
        assert!(fixture
            .peer_reads(&outsider, &item.content.cid)
            .await
            .is_ok());
    }
    assert_eq!(
        fixture
            .peer_reads(&outsider, &item.content.cid)
            .await
            .unwrap_err()["code"],
        "rate_limited"
    );
}

#[tokio::test]
async fn stab_r1_f5_an_owner_without_a_verified_descriptor_keeps_the_read_limit() {
    let item = ListedItem::new("film");
    let fixture = CopyFixture::new(0x97, &[&item], AMPLE).await;
    fixture.keep(&item.listing.cid).await.unwrap();
    update_served_pools(&fixture.member.data_dir, |pools| {
        pools
            .entries
            .get_mut(&fixture.owner.pool_fingerprint())
            .unwrap()
            .descriptor = Some(base64::engine::general_purpose::STANDARD.encode(b"{}"));
        Ok(())
    })
    .unwrap();
    let owner = fixture.owner_endpoint();
    for _ in 0..240 {
        assert!(fixture.peer_reads(&owner, &item.content.cid).await.is_ok());
    }
    assert_eq!(
        fixture
            .peer_reads(&owner, &item.content.cid)
            .await
            .unwrap_err()["code"],
        "rate_limited",
        "an invalid descriptor gives its owner no current-pool exemption"
    );
}

#[tokio::test]
async fn stab_r1_f6_a_delayed_keep_announcement_cannot_resurrect_a_stopped_copy() {
    let item = ListedItem::new("film");
    let fixture = Arc::new(CopyFixture::new(0x95, &[&item], AMPLE).await);
    fixture.keep(&item.listing.cid).await.unwrap();
    let gate = Gate::new(&item.content.cid, "announce");
    let delayed = tokio::spawn({
        let (fixture, gate, cid) = (fixture.clone(), gate.clone(), item.content.cid.clone());
        async move {
            Gate::pass(&StdMutex::new(Some(gate)), &cid, "announce").await;
            crate::carrier::tests::announce_member_copy_for_test(
                &fixture.registry,
                &fixture.member.data_dir,
                &cid,
            )
            .await;
        }
    });
    gate.reached.notified().await;
    fixture.stop().await.unwrap();
    assert!(fixture.recorded().is_empty());
    gate.release();
    delayed.await.unwrap();
    let announcements = std::fs::read_to_string(
        fixture
            .member
            .data_dir
            .join("ElastOS/SystemServices/Content/local-holder-announcements.json"),
    )
    .unwrap();
    assert!(
        !announcements.contains(&item.content.cid),
        "a delayed keep completion recreated a withdrawn announcement: {announcements}"
    );
}

/// The Carrier read refusals a reader takes as final for this holder
/// (`carrier::CARRIER_READ_REFUSALS`).
const FINAL_READ_REFUSALS: [&str; 3] = [
    crate::carrier::CARRIER_PEER_REFUSED,
    crate::carrier::CARRIER_CONTENT_TOO_LARGE,
    crate::carrier::CARRIER_CONTENT_NOT_FOUND,
];

/// J4-F3(b): a member that kept the copies records no local-holder
/// announcement for them, so it never announces itself as a holder (nor
/// after a restart, which re-announces only that record).
#[tokio::test]
async fn audit_j4_f3b_a_member_announces_the_copies_it_keeps() {
    let item = ListedItem::new("film");
    let fixture = CopyFixture::new(0xf1, &[&item], AMPLE).await;
    assert_eq!(
        fixture.keep(&item.listing.cid).await.unwrap(),
        crate::carrier::MemberCopyOutcome::Kept
    );
    assert_eq!(fixture.recorded(), item.cids(), "the member keeps the set");
    let path = fixture
        .member
        .data_dir
        .join("ElastOS/SystemServices/Content/local-holder-announcements.json");
    let announced = std::fs::read_to_string(&path).unwrap_or_default();
    let unannounced: Vec<String> = item
        .cids()
        .into_iter()
        .filter(|cid| !announced.contains(cid.as_str()))
        .collect();
    assert!(
        unannounced.is_empty(),
        "J4-F3(b): the member keeps {:?} but announces none of {unannounced:?} \
         (local holder announcements: {})",
        fixture.recorded(),
        if announced.is_empty() {
            "no file".to_string()
        } else {
            announced
        }
    );
}

/// ADV-19 (D3-A): a member announces the copies it keeps only through its
/// Carrier holder records; no protected CID is provided on the public
/// IPFS/DHT store.
#[tokio::test]
async fn guard_a_member_copy_announcement_never_reaches_the_public_dht() {
    let item = ListedItem::new("film");
    let fixture = CopyFixture::new(0xf9, &[&item], AMPLE).await;
    assert_eq!(
        fixture.keep(&item.listing.cid).await.unwrap(),
        crate::carrier::MemberCopyOutcome::Kept
    );
    // The announce is spawned; let it run.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let public: Vec<(String, String)> = fixture
        .ipfs
        .ops
        .lock()
        .unwrap()
        .iter()
        .filter(|(op, _)| op.contains("provide") || op.contains("publish"))
        .cloned()
        .collect();
    assert!(
        public.is_empty(),
        "ADV-19: a kept copy reached the public store: {public:?}"
    );
    let announced = std::fs::read_to_string(
        fixture
            .member
            .data_dir
            .join("ElastOS/SystemServices/Content/local-holder-announcements.json"),
    )
    .unwrap();
    let announced: serde_json::Value = serde_json::from_str(&announced).unwrap();
    let holders = announced["holders"].as_array().unwrap();
    assert!(!holders.is_empty());
    for holder in holders {
        assert_eq!(holder["policy"], "carrier_replica", "{holder}");
    }
}

/// ADV-19 (D3-A): the copies the owner keeps of its own pool's mints
/// (STAB-42) are member copy records like a served pool's, so they count
/// against its host storage maximum.
#[tokio::test]
async fn guard_the_owners_own_kept_copies_count_against_its_host_storage_maximum() {
    let fixture = CopyFixture::new(0xfb, &[], Some(1_000)).await;
    assert!(
        crate::protected_content_runtime::host_storage_refusal(&fixture.member.data_dir, 1)
            .is_none(),
        "precondition: room for one byte"
    );
    record_member_copy(
        &fixture.member.data_dir,
        MemberCopyV1 {
            cid: "bafyownpoolcopy".to_string(),
            owner_did: elastos_identity::load_existing_did(&fixture.member.data_dir)
                .unwrap()
                .1,
            pool_fingerprint: "sha256:own-pool".to_string(),
            bytes: 1_000,
            borrowed: false,
        },
    )
    .unwrap();
    assert!(
        crate::protected_content_runtime::host_storage_refusal(&fixture.member.data_dir, 1)
            .is_some(),
        "ADV-19: the owner's own kept copy is not charged to its host storage maximum"
    );
}

/// J4-F4: one buyer's playback reads a kept DASH payload file by file from
/// this member (2 s segments: a 5-minute video and audio item is ~300 files).
/// The creator Home is offline, so the member is the holder. D7 (STAB-12):
/// the buyer's Adopt checks the manifest only (STAB-32) and its playback is
/// served part by part by the pool's server, a Home of the copy's pool, here
/// the pool's owner; those reads are not rate-limited.
#[tokio::test]
async fn audit_j4_f4_one_buyer_reading_a_kept_dash_payload_is_not_rate_limited() {
    let item = ListedItem::new("film");
    let fixture = CopyFixture::new(0xf3, &[&item], AMPLE).await;
    fixture.keep(&item.listing.cid).await.unwrap();
    let pool_server = fixture.owner_endpoint();
    let mut limited_at = None;
    for read in 1..=300 {
        if let Err(answer) = fixture.peer_reads(&pool_server, &item.content.cid).await {
            limited_at = Some((read, answer));
            break;
        }
    }
    assert!(
        limited_at.is_none(),
        "J4-F4: one buyer's file reads of a kept payload are refused at {limited_at:?}"
    );
}

/// STAB-12 (D7): a Home outside the copy's pool keeps the read rate of 240
/// reads per 60 s.
#[tokio::test]
async fn stab_12_a_home_outside_the_copys_pool_is_still_rate_limited() {
    let item = ListedItem::new("film");
    let fixture = CopyFixture::new(0xf4, &[&item], AMPLE).await;
    fixture.keep(&item.listing.cid).await.unwrap();
    let reader = stranger();
    for read in 1..=240 {
        assert_eq!(
            fixture.peer_reads(&reader, &item.content.cid).await,
            Ok(()),
            "read {read} is within the rate"
        );
    }
    let answer = fixture.peer_reads(&reader, &item.content.cid).await;
    assert_eq!(
        answer
            .as_ref()
            .err()
            .and_then(|answer| answer["code"].as_str()),
        Some("rate_limited"),
        "the 241st read by a non-member is limited: {answer:?}"
    );
}

/// A2-F6: the read limit is keyed by the Carrier peer that reads, which in
/// pool playback is the session server, here the pool's own owner Home.
#[tokio::test]
async fn audit_a2_f6_a_member_of_the_copys_pool_is_not_rate_limited() {
    let item = ListedItem::new("film");
    let fixture = CopyFixture::new(0xf5, &[&item], AMPLE).await;
    fixture.keep(&item.listing.cid).await.unwrap();
    let owner = fixture.owner_endpoint();
    let mut limited_at = None;
    for read in 1..=241 {
        if let Err(answer) = fixture.peer_reads(&owner, &item.content.cid).await {
            limited_at = Some((read, answer));
            break;
        }
    }
    assert!(
        limited_at.is_none(),
        "A2-F6: the pool's own Home reading the copy is refused at {limited_at:?}"
    );
}

/// J4-F6: the member keeps and pins the copy, then its pin state cannot be
/// read for a moment (Kubo busy). The read must not be refused finally.
#[tokio::test]
async fn audit_j4_f6_an_unknown_pin_state_is_not_a_refusal() {
    let item = ListedItem::new("film");
    let fixture = CopyFixture::new(0xf7, &[&item], AMPLE).await;
    fixture.keep(&item.listing.cid).await.unwrap();
    let reader = stranger();
    assert_eq!(fixture.peer_reads(&reader, &item.content.cid).await, Ok(()));
    *fixture.ipfs.pin_status_fails.lock().unwrap() = Some(item.content.cid.clone());

    let answer = fixture.peer_reads(&reader, &item.content.cid).await;
    let code = answer
        .as_ref()
        .err()
        .and_then(|answer| answer["code"].as_str())
        .unwrap_or_default()
        .to_string();
    assert!(
        !FINAL_READ_REFUSALS.contains(&code.as_str()),
        "J4-F6: a pin state that cannot be read now answers the final refusal {answer:?}"
    );
}

/// A2-F1: the members are asked for a listing's copies once, by the publish.
/// Nothing asks them again: the restart re-announces with one replica and
/// no targets, and the repair scheduler is off by default. (Source-shape
/// test; the live state on demo Homes 5 and 6 is in audit-repro-j4.md.)
#[test]
fn audit_a2_f1_members_are_asked_again_after_the_mint() {
    const LIBRARY: &str = include_str!("../../library.rs");
    const CARRIER: &str = include_str!("../../carrier.rs");
    const SERVER_INFRA: &str = include_str!("../../server_infra.rs");
    const CUSTODY_CONSENT: &str = include_str!("../../custody_consent.rs");
    const RUNTIME: &str = concat!(
        include_str!("../../protected_content_runtime.rs"),
        include_str!("../../protected_content_runtime/custody.rs"),
        include_str!("../../protected_content_runtime/creator.rs"),
        include_str!("../../protected_content_runtime/library_publish.rs"),
        include_str!("../../protected_content_runtime/listing.rs"),
        include_str!("../../protected_content_runtime/viewer.rs"),
    );
    const PROXY: &str = concat!(
        include_str!("../../api/gateway_provider_proxy.rs"),
        include_str!("../../api/gateway_provider_proxy/library_transfer.rs"),
        include_str!("../../api/gateway_provider_proxy/creator_publish.rs"),
        include_str!("../../api/gateway_provider_proxy/custody_buy.rs"),
    );
    let call = "place_runtime_custody_listing_copies(";
    let callers: Vec<(&str, usize)> = [
        ("library.rs", LIBRARY),
        ("carrier.rs", CARRIER),
        ("server_infra.rs", SERVER_INFRA),
        ("custody_consent.rs", CUSTODY_CONSENT),
        ("protected_content_runtime.rs", RUNTIME),
        // Minus its own definition.
        ("api/gateway_provider_proxy.rs", PROXY),
    ]
    .into_iter()
    .map(|(name, source)| {
        let count =
            source.matches(call).count() - usize::from(name == "api/gateway_provider_proxy.rs");
        (name, count)
    })
    .filter(|(_, count)| *count > 0)
    .collect();
    // STAB-07 (D3): the delivery pass places the copies again until every
    // member confirms; the restart's re-announce stays a local-holder ensure.
    let pass = &CUSTODY_CONSENT[CUSTODY_CONSENT.find("fn before_delivery_pass(").unwrap()..];
    let pass = &pass[..pass.find("\n    }\n").unwrap()];
    assert!(pass.contains("spawn_listing_copy_placement("));
    assert!(pass.contains("LISTING_COPY_REPLACE_INTERVAL_SECS"));
    assert!(
        callers.iter().map(|(_, count)| count).sum::<usize>() > 1,
        "A2-F1: members are asked for copies only by {callers:?} (the publish); the \
         restart ensure has max_replicas 1 and no placement targets"
    );
}
