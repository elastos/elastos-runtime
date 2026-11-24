//! AUDIT-REPRO J2/J3 (red, no fix): Runtime-side findings of the 2026-11-17
//! journey audits. Each test fails on d848c1e77 for exactly the finding's
//! reason; nothing here changes production code.

use super::*;

use super::super::{
    list_runtime_custody_listings, non_holder_check, persist_runtime_custody_viewer_record,
    runtime_custody_listing_chain_index, runtime_custody_listing_summary, NonHolderCheck,
    PortableVerifyMode, RuntimeCustodyOpenPendingInput, RuntimeCustodyOpenProgress,
    RuntimeCustodyPoolSessionRenewalRequired, RuntimeCustodyViewerRecord,
};

fn audit_data_dir() -> (tempfile::TempDir, PathBuf) {
    let temp = safe_ancestor_tempdir();
    let data_dir = temp.path().join("home");
    owner_only_dir(&data_dir);
    owner_only_dir(&data_dir.join("protected-content"));
    (temp, data_dir)
}

/// J3-F10 (D6): a pool read with no part before the session's end answers a
/// typed transient code (the Player re-asks it within seconds), distinct
/// from the session's end, and the library error envelope carries it.
#[test]
fn audit_j3_f10_a_dropped_pool_read_answers_the_typed_transient_code() {
    use super::super::RuntimeCustodyPoolReadUnavailable;
    let error = RuntimeCustodyPoolReadUnavailable::error();
    assert!(RuntimeCustodyPoolReadUnavailable::is(&error));
    assert!(!RuntimeCustodyPoolSessionRenewalRequired::is(&error));
    assert_eq!(
        RuntimeCustodyPoolReadUnavailable::CODE,
        "pool_read_unavailable"
    );
    let read = concat!(
        include_str!("../../protected_content_runtime.rs"),
        include_str!("../../protected_content_runtime/custody.rs"),
        include_str!("../../protected_content_runtime/creator.rs"),
        include_str!("../../protected_content_runtime/library_publish.rs"),
        include_str!("../../protected_content_runtime/listing.rs"),
        include_str!("../../protected_content_runtime/viewer.rs"),
    );
    let start = read
        .find("async fn read_runtime_custody_pool_part(")
        .unwrap();
    assert!(read[start..].contains("return Err(RuntimeCustodyPoolReadUnavailable::error())"));
    assert!(
        include_str!("../../library.rs").contains("RuntimeCustodyPoolReadUnavailable::is(error)")
    );
}

// ---------------------------------------------------------------------------
// J3-F1: session renewal mid-playback
// ---------------------------------------------------------------------------

/// The Player reopens at rights expiry and asks the same part on the new
/// handle (player.js:948-953, pinned green by
/// `renewal_required_reopens_and_resumes_at_the_same_position`). The reopen
/// builds its record exactly as `open_runtime_custody_pool_viewer` does:
/// `from_open_pending` (next part 0) then `from_pool_opened` (a clone), and
/// the read checks `require_media_dash_part` against it before anything is
/// fetched (`read_runtime_custody_pool_part`).
#[test]
fn audit_j3_f1_a_renewed_viewer_reads_on_from_the_part_that_met_the_end() {
    let (head, _, _) = fake_dash_package(&[DASH_VIDEO, DASH_AUDIO], &[3, 3]);
    // The old session read both inits and segment 0 of each rendition
    // (parts 0..=3) and met the rights expiry at video segment 1.
    let mut old = dash_test_record();
    old.next_media_part_index = 4;
    assert_eq!(
        old.require_media_dash_part(&head, Some(1)).unwrap(),
        (0, Some(1)),
        "precondition: the old session's next part is video segment 1"
    );

    let principal_id = "person:local:dash-record";
    let profile_did = derived_device_key_for_seed(0x66).1;
    let mint_id = digest(0x77);
    let binding = super::super::derive_runtime_custody_session_binding(
        principal_id,
        &profile_did,
        TEST_VIEWER_EXECUTABLE_ACTOR,
        TEST_VIEWER_LAUNCH_ID,
        "proof:dash",
        "runtime-session:dash",
        "grant:dash",
        mint_id,
    )
    .unwrap();
    let now = crate::auth::now_ts();
    let pending = RuntimeCustodyViewerRecord::from_open_pending(RuntimeCustodyOpenPendingInput {
        principal_id,
        profile_did: &profile_did,
        mint_id,
        content_id: "content-id",
        runtime_session_binding: binding,
        audit_request_id: digest(0x92),
        viewer_session_handle: opaque_handle(0x22),
        expires_at: now + 290,
        now,
    })
    .unwrap();
    let mut renewed = RuntimeCustodyViewerRecord::from_pool_opened(
        &pending,
        &crate::protected_content_pool_open::PoolOpened {
            handle: opaque_handle(0x22),
            expires_at: now + 290,
            sessions: crate::protected_content_pool_open::PoolViewerSessions::new(&[], &[]),
            read_ahead_segments: 6,
        },
        now,
    );
    let read_on = renewed.require_media_dash_part(&head, Some(1));
    assert!(
        read_on.is_ok(),
        "the renewed viewer must read on at video segment 1 (where the old one ended); \
         it starts at part {} and refuses: {:#}",
        renewed.next_media_part_index,
        read_on.unwrap_err()
    );
}

// ---------------------------------------------------------------------------
// J3-F2: a pool read after a Runtime restart
// ---------------------------------------------------------------------------

/// A Runtime restart loses the in-memory delivery secret
/// (`PoolDeliveryKeys::global()`), while the Active pool record stays on
/// disk. Before its expiry the read settles the record and answers "session
/// is unavailable", not `pool_session_renewal_required`, so the Player never
/// reopens (it reopens only on the typed code: player.test.mjs "an early read
/// error is not a reopen", "a browser clock past the expiry never reopens
/// without the Runtime's typed answer"), and every Retry reads a record that
/// is gone.
#[cfg(unix)]
#[tokio::test]
async fn audit_j3_f2_a_pool_read_after_restart_answers_renewal_required() {
    let viewer = dash_viewer(
        media_dash_components(&[DASH_VIDEO, DASH_AUDIO], &[2, 2]),
        "audit-j3-f2",
    )
    .await;
    // An Active pool viewer whose secret this process does not hold.
    let mut record = viewer.record();
    record.pool = Some(crate::protected_content_pool_open::PoolViewerSessions::new(
        &[],
        &[],
    ));
    persist_runtime_custody_viewer_record(
        viewer.data_dir(),
        &viewer.principal_id,
        viewer.mint_id(),
        &record,
    )
    .unwrap();
    assert!(
        !record.is_expired(crate::auth::now_ts()),
        "precondition: before the session's end"
    );
    let error = viewer.read(None, None).await.unwrap_err();
    assert!(
        RuntimeCustodyPoolSessionRenewalRequired::is(&error),
        "a pool viewer that lost its secret must answer the renewal code the Player reopens on; \
         it answered: {error:#}"
    );
}

// ---------------------------------------------------------------------------
// J3-F9: a second launch while a viewer is live
// ---------------------------------------------------------------------------

/// A reload of the Player (a new launch, so a new session binding) while the
/// earlier viewer is Active and unexpired is refused with the final
/// `denied` progress (protected_content_runtime.rs:13846-13851), which the
/// Player shows with nothing to press, for up to the session's remaining
/// life.
#[cfg(unix)]
#[tokio::test]
async fn audit_j3_f9_a_second_launch_during_a_live_viewer_is_not_final() {
    let viewer = dash_viewer(
        media_dash_components(&[DASH_VIDEO, DASH_AUDIO], &[2, 2]),
        "audit-j3-f9",
    )
    .await;
    let open = |launch_id: &str| {
        super::super::open_runtime_custody_viewer(
            viewer.data_dir(),
            viewer.harness.base.registry.clone(),
            super::super::RuntimeCustodyViewerOpenInput {
                principal_id: viewer.principal_id.clone(),
                mint_id: hex::encode(viewer.mint_id().as_bytes()),
                executable_actor: TEST_VIEWER_EXECUTABLE_ACTOR.to_string(),
                launch_id: Some(launch_id.to_string()),
                proof_binding_id: Some(viewer.proof_binding_id.clone()),
                session_id: Some("runtime-session:alpha".to_string()),
                grant_id: Some("grant:alpha".to_string()),
            },
        )
    };
    // Control: the same launch gets its live session back, so every input
    // but the launch is right and the refusal below is the binding branch.
    open(TEST_VIEWER_LAUNCH_ID)
        .await
        .expect("precondition: the first launch reopens its live session");
    let error = super::super::open_runtime_custody_viewer(
        viewer.data_dir(),
        viewer.harness.base.registry.clone(),
        super::super::RuntimeCustodyViewerOpenInput {
            principal_id: viewer.principal_id.clone(),
            mint_id: hex::encode(viewer.mint_id().as_bytes()),
            executable_actor: TEST_VIEWER_EXECUTABLE_ACTOR.to_string(),
            launch_id: Some(TEST_VIEWER_LAUNCH_ID_B.to_string()),
            proof_binding_id: Some(viewer.proof_binding_id.clone()),
            session_id: Some("runtime-session:alpha".to_string()),
            grant_id: Some("grant:alpha".to_string()),
        },
    )
    .await
    .unwrap_err();
    let progress = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<RuntimeCustodyOpenProgress>())
        .unwrap_or_else(|| panic!("the open answers typed progress: {error:#}"));
    assert!(
        progress.resumable(),
        "a second launch while the first viewer is live must be resumable (open elsewhere / take over), \
         not the final {}: {error:#}",
        progress.stage_label()
    );
}

// ---------------------------------------------------------------------------
// J3-F5: the fresh availability check while the Wallet is asked
// ---------------------------------------------------------------------------

/// Every open, and every 2 s poll of a pending approval, re-runs
/// `verify_fresh_runtime_custody_availability` (protected_content_runtime.rs
/// :13873, before the pending release is resumed). Its failure carries no
/// `RuntimeCustodyOpenProgress` (:13529-13536), so the Player's resume loop
/// (player.js:1096) stops polling. Fixture as
/// `runtime_custody_viewer_expired_old_binding_allows_cleanup_before_fresh_open`,
/// with the content plane unreachable instead of the composition removed.
#[cfg(unix)]
#[tokio::test]
async fn audit_j3_f5_a_fresh_availability_failure_keeps_the_open_resumable() {
    let harness = runtime_custody_prebuy_availability_harness(
        0x61,
        ContentAvailabilityTestConfig::accepted_now(),
    )
    .await;
    let principal_id = "person:local:audit-j3-f5";
    let (proof_binding_id, _) =
        install_profile_authority_keeping_device_key(&harness.data_dir, principal_id);
    let current_profile_did = load_profile_did_for_test(&harness.data_dir, principal_id);
    let mint = runtime_mint_journal(&harness.data_dir)
        .load(harness.mint_id)
        .unwrap();
    persist_runtime_custody_purchase_for_mint(
        &harness.data_dir,
        &mint,
        principal_id,
        &current_profile_did,
        crate::auth::now_ts(),
    );
    // The content plane cannot be reached for now: no content provider
    // answers the fresh check's reads (a transient fetch failure).
    let registry = Arc::new(ProviderRegistry::new());
    let error = super::super::open_runtime_custody_viewer(
        &harness.data_dir,
        registry,
        super::super::RuntimeCustodyViewerOpenInput {
            principal_id: principal_id.to_string(),
            mint_id: hex::encode(harness.mint_id.as_bytes()),
            executable_actor: TEST_VIEWER_EXECUTABLE_ACTOR.to_string(),
            launch_id: Some(TEST_VIEWER_LAUNCH_ID.to_string()),
            proof_binding_id: Some(proof_binding_id),
            session_id: Some("runtime-session:beta".to_string()),
            grant_id: Some("grant:alpha".to_string()),
        },
    )
    .await
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains(RUNTIME_CUSTODY_AVAILABILITY_UNAVAILABLE_MESSAGE),
        "precondition: the fresh availability check failed: {error:#}"
    );
    let progress = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<RuntimeCustodyOpenProgress>());
    assert!(
        progress.is_some_and(RuntimeCustodyOpenProgress::resumable),
        "a fresh-check failure must stay resumable so a Player polling a pending approval keeps polling; \
         it carries {:?}: {error:#}",
        progress.map(RuntimeCustodyOpenProgress::stage_label)
    );
}

// ---------------------------------------------------------------------------
// J2-F3: the shelf row names no ledger
// ---------------------------------------------------------------------------

/// `list_runtime_custody` names the token but not its ledger
/// (`runtime_custody_listing_summary`), so the page cannot key the chain's
/// access watch (`ledger|tokenId`) on a local card, and an Imported listing
/// with no purchase stays `available` = Buy for a channel subscriber.
#[test]
fn audit_j2_f3_a_shelf_row_names_its_ledger() {
    let (_temp, data_dir) = audit_data_dir();
    let record = runtime_custody_listing_record_for_test(
        digest(0x31),
        "person:local:audit-j2-f3-creator",
        "Film",
        NOW,
    );
    let summary =
        runtime_custody_listing_summary(&data_dir, "person:local:audit-j2-f3-viewer", &record)
            .unwrap();
    assert_eq!(
        summary["access_state"], "available",
        "precondition: no purchase on this Home: {summary}"
    );
    assert_eq!(
        summary.get("ledger").and_then(Value::as_str),
        Some(record.package.ledger.as_str()),
        "the shelf row must name its ledger: {summary}"
    );
}

// ---------------------------------------------------------------------------
// J2-F6: one unreadable record breaks the join and the shelf
// ---------------------------------------------------------------------------

/// `runtime_custody_listing_chain_index` skips a bad listing but `?`s the
/// purchase read (protected_content_runtime.rs:13226), and so does the shelf
/// (`runtime_custody_listing_summary`). One unreadable purchase file then
/// empties the catalog join (`mark_held_market_catalog_items` logs and uses
/// an empty Vec) and fails the whole shelf.
#[test]
fn audit_j2_f6_one_unreadable_purchase_does_not_hide_every_held_item() {
    let (_temp, data_dir) = audit_data_dir();
    let viewer = "person:local:audit-j2-f6-viewer";
    for (seed, token) in [(0x41u8, "0x1"), (0x42u8, "0x2")] {
        let mut record = runtime_custody_listing_record_for_test(
            digest(seed),
            "person:local:audit-j2-f6-creator",
            "Film",
            NOW,
        );
        record.package.token_id = token.to_string();
        restate_published_digest(&mut record);
        super::super::persist_runtime_custody_listing(&data_dir, &record).unwrap();
    }
    let broken = runtime_purchase_path(&data_dir, viewer, digest(0x42));
    // Every directory Runtime itself would create is owner-only.
    let mut dirs: Vec<&Path> = broken
        .ancestors()
        .skip(1)
        .take_while(|dir| *dir != data_dir.as_path())
        .collect();
    dirs.reverse();
    for dir in dirs {
        owner_only_dir(dir);
    }
    write_owner_only_bytes(&broken, b"{ not a purchase").unwrap();

    let index = runtime_custody_listing_chain_index(&data_dir, viewer);
    assert!(
        index.as_ref().is_ok_and(|index| !index.is_empty()),
        "one unreadable purchase must not empty the catalog join: {:?}",
        index.map(|index| index.len())
    );
    let shelf = list_runtime_custody_listings(&data_dir, viewer);
    assert!(
        shelf.is_ok(),
        "one unreadable purchase must not fail the whole shelf: {:?}",
        shelf.err()
    );
}

// ---------------------------------------------------------------------------
// Independent audit F4: Adopt fetches every file before the first Open
// ---------------------------------------------------------------------------

/// The first Open of a channel item on a Home that does not hold it adopts a
/// Granted listing (`download_owned_copy` -> `adopt_runtime_granted_listing`
/// -> `build_adopted_runtime_listing`, `PortableVerifyMode::Adopt`), and
/// Adopt is `FullFetch`: every file is fetched and hashed before the Player
/// starts (`adopted_listing_on_non_holder_verifies_by_fetch`, green, asserts
/// every file was fetched). An Open is `ManifestOnly`; the staging pool
/// server verifies each part it serves (T3.4).
#[test]
fn audit_f4_an_adoption_checks_the_manifest_without_fetching_every_file() {
    assert_eq!(
        non_holder_check(PortableVerifyMode::Adopt).unwrap(),
        NonHolderCheck::ManifestOnly,
        "an adoption before the first Open must not fetch the whole item"
    );
}

// ---------------------------------------------------------------------------
// J2-F10: the catalog join past the shelf's row bound
// ---------------------------------------------------------------------------

/// The shelf answers at most 128 rows and keeps the smallest mint ids
/// (`select_runtime_custody_listing_paths`). The catalog join read through
/// the same selection, so on a Home with more listings a creator's own new
/// item (a random, here the largest, mint id) fell out of the join, and
/// Explore offered the creator Buy on it.
#[test]
fn audit_j2_f10_the_catalog_join_keeps_a_creators_item_past_the_shelf_bound() {
    let (_temp, data_dir) = audit_data_dir();
    let creator = "person:local:audit-j2-f10-creator";
    for index in 0..=128u16 {
        let mut bytes = [0u8; 32];
        bytes[..2].copy_from_slice(&index.to_be_bytes());
        let mut record = runtime_custody_listing_record_for_test(
            Digest32::new(bytes),
            "person:local:audit-j2-f10-other",
            "Film",
            NOW,
        );
        record.package.token_id = format!("0x{:x}", u32::from(index) + 2);
        restate_published_digest(&mut record);
        super::super::persist_runtime_custody_listing(&data_dir, &record).unwrap();
    }
    let own_mint = digest(0xff);
    let mut own = runtime_custody_listing_record_for_test(own_mint, creator, "Mine", NOW);
    own.package.token_id = "0x1".to_string();
    restate_published_digest(&mut own);
    super::super::persist_runtime_custody_listing(&data_dir, &own).unwrap();

    let index = runtime_custody_listing_chain_index(&data_dir, creator).unwrap();
    let mine = index
        .iter()
        .find(|entry| entry.mint_id == hex::encode(own_mint.as_bytes()));
    assert_eq!(
        mine.map(|entry| entry.access_state.as_str()),
        Some("creator"),
        "the creator's own item must stay in the catalog join past the shelf bound ({} joined)",
        index.len()
    );
    // The shelf keeps its row bound.
    let shelf = list_runtime_custody_listings(&data_dir, creator).unwrap();
    assert_eq!(shelf["truncated"], true);
}
