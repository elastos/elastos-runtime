//! AUDIT-REPRO J1 (coll-journey-audit-20261117.md J1-F1, J1-F4, J1-F8;
//! journey-audit-20261117.md F3): red tests only, no fix. The creator's
//! publish and its recovery, through the Library routes and the creator
//! tail the gateway runs.

use super::*;

/// The content plane of `creator_listing_is_served_to_peers_when_its_members_are_asked_to_copy_it`,
/// except that a placement `ensure` (one naming placement targets: the
/// pool's members asked to keep a copy) never answers, as a member busy
/// pulling a large item, or unreachable for its 360 s Carrier wait, does.
struct SlowPlacementProbe {
    inner: std::sync::Arc<TwoRuntimeContentProvider>,
    placements: std::sync::atomic::AtomicUsize,
}

#[async_trait::async_trait]
impl Provider for SlowPlacementProbe {
    async fn handle(&self, request: ResourceRequest) -> Result<ResourceResponse, ProviderError> {
        self.inner.handle(request).await
    }

    fn schemes(&self) -> Vec<&'static str> {
        self.inner.schemes()
    }

    fn name(&self) -> &'static str {
        "slow-placement-probe"
    }

    async fn send_raw(&self, request: &Value) -> Result<Value, ProviderError> {
        let asks_for_copies = request["availability_requirements"]
            .get("placement_targets")
            .is_some();
        if request["op"] == "ensure" && asks_for_copies {
            self.placements
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            std::future::pending::<()>().await;
        }
        if request["op"] == "ensure" {
            return Ok(json!({ "status": "ok", "data": {} }));
        }
        self.inner.send_raw(request).await
    }
}

/// J1-F1 / journey-audit F3: the publish answers only once every member
/// asked to keep a copy has answered. A member that does not answer holds
/// the creator's publish (and its source lock) for as long as it takes.
#[tokio::test]
async fn audit_j1_f1_creator_publish_answers_before_member_copy_placement_settles() {
    let _guard = protected_content_gateway_mock_test_guard().lock().await;
    reset_mock_chain_raw_requests();
    reset_mock_protected_content_chain_mode();
    reset_mock_protected_content_purchase_fixture();
    set_mock_protected_content_purchase_native();

    let runtime_a = tempfile::tempdir().unwrap();
    enable_protected_content(runtime_a.path());
    crate::protected_content_runtime::tests::write_device_key(runtime_a.path(), 0x5b);
    let probe = std::sync::Arc::new(SlowPlacementProbe {
        inner: TwoRuntimeContentProvider::new(
            0x5b,
            std::sync::Arc::new(std::sync::Mutex::new(BTreeMap::new())),
        ),
        placements: std::sync::atomic::AtomicUsize::new(0),
    });
    // The listing's pool has one other member.
    crate::api::gateway::gateway_provider_proxy::test_seams::set_listing_copy_holders(
        runtime_a.path(),
        vec!["did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".to_string()],
    );
    let (state_a, wallet_a) = wallet_chain_test_state_with_observer(runtime_a.path()).await;
    let registry_a = state_a.provider_registry.as_ref().unwrap().clone();
    registry_a
        .register_sub_provider("content", probe.clone())
        .await
        .unwrap();
    registry_a
        .register_sub_provider(
            "object",
            std::sync::Arc::new(crate::library::ObjectProvider::new(
                runtime_a.path().to_path_buf(),
                std::sync::Arc::downgrade(&registry_a),
            )),
        )
        .await
        .unwrap();
    let _process_fixture = crate::protected_content_runtime::tests::register_runtime_custody_process_providers_for_test_registry(
        runtime_a.path(),
        &registry_a,
    )
    .await;
    crate::protected_content_runtime::tests::register_runtime_custody_mock_media_provider_for_test_registry(
        runtime_a.path(),
        &registry_a,
    )
    .await;
    let creator = passkey_authority_with_profile_role_credential(
        runtime_a.path(),
        "audit-j1-creator",
        crate::auth::RuntimePrincipalRole::Admin,
        "gateway-test-passkey-audit-j1-creator",
    );
    let creator_token = app_token_for_authority(runtime_a.path(), LIBRARY_CAPSULE_ID, &creator);
    let creator_account = wallet_a
        .provider
        .seed_managed_evm_account_for_principal_with_index(&creator.principal_id, 1)
        .await;
    set_mock_wallet_transaction_default(
        &wallet_a.provider,
        &creator.principal_id,
        "eip155:8453",
        &creator_account,
        10,
    )
    .await;
    let app_a = gateway_router(state_a);
    let creator_uri = format!(
        "{}/Documents/audit-j1-placement.mp4",
        crate::auth::principal_localhost_root(&creator.principal_id)
    );
    write_library_bytes(&app_a, &creator_token, &creator_uri, b"media").await;
    let publish_body = json!({
        "uri": creator_uri,
        "protection": {
            "mode": "runtime_custody",
            "channel": "0x0000000000000000000000000000000000000022",
            "copies": "0x1",
            "price": MOCK_PROTECTED_CONTENT_LISTING_AMOUNT,
        },
    });
    let _ = post_library(
        app_a.clone(),
        &creator_token,
        "publish",
        publish_body.clone(),
    )
    .await;
    let _ = wallet_a
        .provider
        .complete_latest_transaction_approval()
        .await;

    let answered = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        post_library(app_a.clone(), &creator_token, "publish", publish_body),
    )
    .await;

    let placements = probe.placements.load(std::sync::atomic::Ordering::SeqCst);
    assert!(
        answered.is_ok(),
        "J1-F1: the creator's publish had not answered after 30 s: it waits inline on the \
         member copy placement ({placements} placement ensure(s) outstanding)"
    );
}

/// J1-F4: a crash after the creator tail persisted the listing and before
/// the Library wrote its publication leaves a listed mint that is not
/// served (no publication) and is not offered to finish: the mint counts as
/// finished once its listing file exists.
#[tokio::test]
async fn audit_j1_f4_a_listed_mint_without_its_library_publication_is_offered_to_finish() {
    let _guard = protected_content_gateway_mock_test_guard().lock().await;
    let fx = CreatorRecoveryFixture::new().await;
    fx.registry
        .register_sub_provider(
            "object",
            Arc::new(crate::library::ObjectProvider::new(
                fx.dir.path().to_path_buf(),
                Arc::downgrade(&fx.registry),
            )),
        )
        .await
        .unwrap();
    let app = gateway_router(fx.state.clone());
    let creator_token = app_token_for_authority(fx.dir.path(), CREATOR_CAPSULE_ID, &fx.authority);
    let root = crate::auth::principal_localhost_root(&fx.authority.principal_id);
    let input = fx.input("crashed.mp4", 0x9c);
    let (status, _, upload) =
        put_library_upload(app.clone(), &creator_token, &input.object_uri, b"media").await;
    assert_eq!(status, StatusCode::OK, "{upload}");
    let facts = seed_completed_runtime_custody_mint(fx.dir.path(), &input);
    // Approved, mined, settled; the listing publish fails once, and Resume
    // persists the listing. The creator tail never writes the Library's
    // publication: that is the Library publish's next step (library.rs),
    // which a crash here never reaches.
    assert!(fx.tail(&input, &facts).await.is_err());
    fx.wallet_provider
        .provider
        .complete_latest_transaction_approval()
        .await;
    set_mock_runtime_listing_publish_failure(true);
    assert!(fx.tail(&input, &facts).await.is_err());
    set_mock_runtime_listing_publish_failure(false);
    fx.resume(&input, &facts).await.unwrap();
    let listing = crate::protected_content_runtime::load_runtime_custody_listing(
        fx.dir.path(),
        facts.mint_id,
    )
    .unwrap()
    .expect("precondition: the listing is persisted");
    let crate::protected_content_runtime::RuntimeCustodyListingOrigin::LocalCreator {
        listing_uri,
        ..
    } = &listing.origin
    else {
        panic!("precondition: a local creator listing");
    };
    let listing_cid = listing_uri.strip_prefix("elastos://").unwrap();
    assert!(
        crate::library::published_cid_audience(fx.dir.path(), listing_cid).is_none(),
        "precondition: the listing folder is not served to peers"
    );

    let (status, answer) = post_library(
        app.clone(),
        &creator_token,
        "unfinished_protections",
        json!({ "uri": format!("{root}/Creator") }),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(answer["status"], "ok", "{answer}");
    let offered = answer["data"]["unfinished"]
        .as_array()
        .unwrap()
        .iter()
        .any(|entry| {
            entry["uri"] == input.object_uri.as_str() && entry["stage"] == "listing_not_assembled"
        });
    assert!(
        offered,
        "J1-F4: a mint whose listing is saved but whose Library publication is missing \
         (not served to peers) is not offered to finish: {}",
        answer["data"]
    );
}

/// STAB-01 / D1 (the sheet's "S1 progress" item): the progress a reload
/// reads from the journal said "Publish metadata" was active through the
/// Wallet, chain and finality waits. An approval is raised only after the
/// publication, so once the wallet effect exists the stage is done.
#[tokio::test]
async fn stab_s1_progress_says_publish_metadata_is_done_once_the_approval_is_raised() {
    let _guard = protected_content_gateway_mock_test_guard().lock().await;
    let fx = CreatorRecoveryFixture::new().await;
    let input = fx.input("progress.mp4", 0x9e);
    let facts = seed_completed_runtime_custody_mint(fx.dir.path(), &input);
    let public_metadata = |entry: &serde_json::Value| -> String {
        entry["progress"]["stages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|stage| stage["id"] == "public_metadata")
            .expect("the progress carries the public_metadata stage")["state"]
            .as_str()
            .unwrap()
            .to_string()
    };
    async fn unfinished(
        fx: &CreatorRecoveryFixture,
        input: &crate::protected_content_runtime::RuntimeCustodyLibraryPublishInput,
    ) -> serde_json::Value {
        match fx.unfinished(input).await {
            crate::api::gateway::RuntimeCustodyUnfinishedMintOutcome::Unfinished(entry) => entry,
            other => panic!("the mint is offered on reload: {other:?}"),
        }
    }

    // The Wallet wait: the approval is raised, so the metadata is published.
    assert_eq!(
        fx.tail(&input, &facts).await.unwrap_err().to_string(),
        RECOVERY_PENDING_MESSAGE
    );
    let entry = unfinished(&fx, &input).await;
    assert_eq!(
        public_metadata(&entry),
        "done",
        "S1 progress: through the Wallet wait a reload paints Publish metadata as {} ({})",
        public_metadata(&entry),
        entry["progress"]
    );

    // The finality wait: mined, the receipt not yet readable.
    fx.wallet_provider
        .provider
        .complete_latest_transaction_approval()
        .await;
    set_mock_protected_content_chain_receipt_error();
    let _ = fx.tail(&input, &facts).await.unwrap_err();
    reset_mock_protected_content_chain_mode();
    let entry = unfinished(&fx, &input).await;
    assert_eq!(entry["stage"], "transaction_mined", "{entry}");
    assert_eq!(
        public_metadata(&entry),
        "done",
        "S1 progress: through the finality wait a reload paints Publish metadata as {} ({})",
        public_metadata(&entry),
        entry["progress"]
    );
}

/// J1-F8 (STAB-34, fixed under D5): a transient chain read failure after the
/// mint transaction was mined answered "unavailable", not the pending state
/// Creator polls on, so the page stopped with no action. (Reloading Creator
/// does offer Resume: that part of the finding does not hold, and is checked
/// first here.)
#[tokio::test]
async fn audit_j1_f8_a_transient_receipt_read_after_mining_stays_pending() {
    let _guard = protected_content_gateway_mock_test_guard().lock().await;
    let fx = CreatorRecoveryFixture::new().await;
    let input = fx.input("mined.mp4", 0x9d);
    let facts = seed_completed_runtime_custody_mint(fx.dir.path(), &input);
    assert_eq!(
        fx.tail(&input, &facts).await.unwrap_err().to_string(),
        RECOVERY_PENDING_MESSAGE
    );
    fx.wallet_provider
        .provider
        .complete_latest_transaction_approval()
        .await;

    // Mined; the chain provider's receipt read fails transiently.
    set_mock_protected_content_chain_receipt_error();
    let error = fx.tail(&input, &facts).await.unwrap_err().to_string();
    reset_mock_protected_content_chain_mode();

    // A reload's unfinished list offers Resume at the mined stage.
    match fx.unfinished(&input).await {
        crate::api::gateway::RuntimeCustodyUnfinishedMintOutcome::Unfinished(entry) => {
            assert_eq!(entry["stage"], "transaction_mined", "{entry}");
            assert_eq!(entry["resume"], "recorded_terms", "{entry}");
        }
        other => panic!("a mined mint is offered on reload: {other:?}"),
    }
    assert_eq!(
        error, RECOVERY_PENDING_MESSAGE,
        "J1-F8: a transient receipt read after mining ends the open page's publish as \
         `{error}`, which Creator does not poll and offers no action for"
    );
}
