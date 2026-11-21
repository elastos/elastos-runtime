use super::*;

#[cfg(unix)]
#[tokio::test]
async fn runtime_custody_listings_project_public_summary_and_access_state() {
    let harness = runtime_custody_prebuy_availability_harness(
        0x61,
        ContentAvailabilityTestConfig::accepted(),
    )
    .await;
    let mint = runtime_mint_journal(&harness.data_dir)
        .load(harness.mint_id)
        .unwrap();
    let buyer_principal_id = "person:local:buyer";
    install_profile_authority_keeping_device_key(&harness.data_dir, buyer_principal_id);
    let buyer_profile_did = load_profile_did_for_test(&harness.data_dir, buyer_principal_id);
    persist_runtime_custody_purchase_for_mint(
        &harness.data_dir,
        &mint,
        buyer_principal_id,
        &buyer_profile_did,
        crate::auth::now_ts(),
    );

    let creator_view =
        super::super::list_runtime_custody_listings(&harness.data_dir, "person:local:creator")
            .unwrap();
    assert_eq!(
        creator_view["schema"],
        super::super::RUNTIME_CUSTODY_LISTINGS_RESPONSE_SCHEMA_V1
    );
    assert_eq!(creator_view["truncated"], false);
    let creator_listing = creator_view["listings"][0].as_object().unwrap();
    assert_eq!(
        creator_listing.keys().cloned().collect::<Vec<_>>(),
        vec![
            "access_state",
            "availability",
            "codecs",
            "display_name",
            "mime_type",
            "mint_id",
            "pay_token",
            "price",
            "published_at",
            "quantity",
            "schema",
            "seller_address",
            "token_id",
        ]
    );
    assert_eq!(creator_listing["display_name"], "protected-video.mp4");
    assert_eq!(creator_listing["mime_type"], MEDIA_MIME_TYPE_V1);
    assert_eq!(creator_listing["codecs"], MEDIA_CODECS_V1);
    assert_eq!(creator_listing["quantity"], "0x2");
    assert_eq!(creator_listing["price"], "0x5");
    let expected_availability = json!({
        "schema": super::super::RUNTIME_CUSTODY_LISTING_AVAILABILITY_SCHEMA_V1,
        "status": "last_verified_receipt",
        "checked_at": NOW,
        "required_replicas": 3,
        "observed_replicas": 3,
        "receipt_digest": hex::encode([0x67; 32]),
        "recheck_before_buy": true,
        "recheck_before_open": true,
    });
    assert_eq!(creator_listing["availability"], expected_availability);
    assert_eq!(creator_listing["access_state"], "creator");

    let buyer_view =
        super::super::list_runtime_custody_listings(&harness.data_dir, buyer_principal_id).unwrap();
    assert_eq!(buyer_view["listings"][0]["access_state"], "purchased");
    assert_eq!(
        buyer_view["listings"][0]["availability"],
        expected_availability
    );

    let other_view =
        super::super::list_runtime_custody_listings(&harness.data_dir, "person:local:other")
            .unwrap();
    assert_eq!(other_view["listings"][0]["access_state"], "available");
    assert_eq!(
        other_view["listings"][0]["availability"],
        expected_availability
    );
    for hidden in [
        "publisher_principal_id",
        "content_id",
        "cid",
        "metadata_cid",
        "token_uri",
        "chain_namespace",
        "network",
        "ledger",
        "operative",
        "payment_processor",
    ] {
        assert!(
            creator_view["listings"][0].get(hidden).is_none(),
            "{hidden}"
        );
    }
}

#[cfg(unix)]
#[test]
fn runtime_custody_listing_selection_is_stable_and_truncated_by_mint_filename() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    owner_only_dir(&data_dir.join("protected-content"));
    let listings_root = data_dir.join(super::super::RUNTIME_LISTING_ROOT);
    owner_only_dir(&listings_root);

    for index in (0..(super::super::MAX_RUNTIME_CUSTODY_LISTINGS + 3)).rev() {
        let mint_id = Digest32::new([u8::try_from(index + 1).unwrap(); 32]);
        let path = super::super::runtime_listing_path(&data_dir, mint_id);
        write_owner_only_bytes(&path, b"{}").unwrap();
    }

    let (first_paths, first_truncated) =
        super::super::select_runtime_custody_listing_paths(&listings_root).unwrap();
    let (second_paths, second_truncated) =
        super::super::select_runtime_custody_listing_paths(&listings_root).unwrap();
    assert!(first_truncated);
    assert!(second_truncated);
    assert_eq!(first_paths, second_paths);
    assert_eq!(
        first_paths.len(),
        super::super::MAX_RUNTIME_CUSTODY_LISTINGS
    );
    let selected = first_paths
        .iter()
        .map(|path| path.file_name().unwrap().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    let expected = (0..super::super::MAX_RUNTIME_CUSTODY_LISTINGS)
        .map(|index| {
            format!(
                "{}.json",
                hex::encode([u8::try_from(index + 1).unwrap(); 32])
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(selected, expected);
}

#[cfg(unix)]
#[test]
fn runtime_custody_listings_reject_malformed_record() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    owner_only_dir(&data_dir.join("protected-content"));

    let mint_id = digest(0x90);
    let mut invalid = serde_json::to_value(runtime_custody_listing_record_for_test(
        mint_id,
        "person:local:creator",
        "Valid name",
        123,
    ))
    .unwrap();
    invalid["display_name"] = Value::String(String::new());
    write_owner_only_bytes(
        &super::super::runtime_listing_path(&data_dir, mint_id),
        &serde_json::to_vec(&invalid).unwrap(),
    )
    .unwrap();

    let error = super::super::list_runtime_custody_listings(&data_dir, "person:local:creator")
        .expect_err("expected malformed record rejection");
    assert_eq!(error.to_string(), "Runtime custody listing is invalid");
}

#[tokio::test]
async fn runtime_custody_prebuy_availability_refetches_fresh_exact_receipt_without_publish() {
    let now = crate::auth::now_ts();
    let harness = runtime_custody_prebuy_availability_harness(
        0x61,
        ContentAvailabilityTestConfig {
            checked_at: now,
            ..ContentAvailabilityTestConfig::accepted()
        },
    )
    .await;
    let listing = super::super::load_runtime_custody_listing(&harness.data_dir, harness.mint_id)
        .unwrap()
        .unwrap();
    let (_, verified) = super::super::verify_fresh_runtime_custody_availability(
        &harness.data_dir,
        &harness.registry,
        &listing,
        harness.mint_id,
        now,
    )
    .await
    .unwrap();
    assert_eq!(verified.content_cid(), ContentAvailabilityTestProvider::CID);
    assert_eq!(verified.required_replicas(), 3);
    assert_eq!(verified.observed_replicas(), 3);

    let requests = harness.content_provider.requests().await;
    // A fresh observation: `ensure` under the exact listing bindings, then
    // the receipt it produced, never a republish.
    let ensure = requests
        .iter()
        .find(|request| request.get("op").and_then(Value::as_str) == Some("ensure"))
        .expect("prebuy verification must ensure the CID again");
    assert_eq!(
        ensure["availability_policy"],
        super::super::PROTECTED_CONTENT_REPLICATION_POLICY
    );
    assert_eq!(ensure["availability_requirements"]["min_replicas"], 3);
    assert_eq!(
        ensure["availability_requirements"]["require_live_multi_peer_proof"],
        true
    );
    assert_eq!(ensure["object_did"], listing.package.content_id);
    assert_eq!(
        ensure["publisher_did"],
        listing.package.publisher_profile_did
    );
    let ensure_index = requests
        .iter()
        .position(|request| request.get("op").and_then(Value::as_str) == Some("ensure"))
        .unwrap();
    let status_index = requests
        .iter()
        .position(|request| request.get("op").and_then(Value::as_str) == Some("status"))
        .expect("receipt is read after ensure");
    assert!(ensure_index < status_index);
    assert!(requests
        .iter()
        .any(|request| request.get("op").and_then(Value::as_str) == Some("fetch")));
    assert!(requests.iter().all(|request| matches!(
        request.get("op").and_then(Value::as_str),
        Some("ensure" | "status" | "fetch")
    )));
    assert!(!requests
        .iter()
        .any(|request| request.get("op").and_then(Value::as_str) == Some("publish")));
}

#[tokio::test]
async fn runtime_custody_prebuy_availability_rejects_stale_receipt() {
    let now = crate::auth::now_ts();
    let harness = runtime_custody_prebuy_availability_harness(
        0x61,
        ContentAvailabilityTestConfig {
            checked_at: now - super::super::PROTECTED_CONTENT_AVAILABILITY_MAX_AGE_SECS - 1,
            ..ContentAvailabilityTestConfig::accepted()
        },
    )
    .await;
    let listing = super::super::load_runtime_custody_listing(&harness.data_dir, harness.mint_id)
        .unwrap()
        .unwrap();
    assert!(super::super::verify_fresh_runtime_custody_availability(
        &harness.data_dir,
        &harness.registry,
        &listing,
        harness.mint_id,
        now,
    )
    .await
    .is_err());
}

#[tokio::test]
async fn runtime_custody_prebuy_availability_rejects_wrong_receipt_binding_or_manifest() {
    let now = crate::auth::now_ts();
    let cases = [
        ContentAvailabilityTestConfig {
            receipt_object_identity: Some("did:key:wrong#content".to_string()),
            ..ContentAvailabilityTestConfig::accepted_at(now)
        },
        ContentAvailabilityTestConfig {
            receipt_publisher_did: Some("did:key:wrong#publisher".to_string()),
            ..ContentAvailabilityTestConfig::accepted_at(now)
        },
        ContentAvailabilityTestConfig {
            policy: "wrong-policy".to_string(),
            ..ContentAvailabilityTestConfig::accepted_at(now)
        },
        ContentAvailabilityTestConfig {
            replicas: 2,
            ..ContentAvailabilityTestConfig::accepted_at(now)
        },
        ContentAvailabilityTestConfig {
            live_multi_peer_proof: None,
            ..ContentAvailabilityTestConfig::accepted_at(now)
        },
        ContentAvailabilityTestConfig {
            live_multi_peer_proof: Some(false),
            ..ContentAvailabilityTestConfig::accepted_at(now)
        },
        ContentAvailabilityTestConfig {
            malformed_receipt: true,
            ..ContentAvailabilityTestConfig::accepted_at(now)
        },
        ContentAvailabilityTestConfig {
            mutate_manifest_extra_file: true,
            ..ContentAvailabilityTestConfig::accepted_at(now)
        },
    ];
    for config in cases {
        let harness = runtime_custody_prebuy_availability_harness(0x61, config).await;
        let listing =
            super::super::load_runtime_custody_listing(&harness.data_dir, harness.mint_id)
                .unwrap()
                .unwrap();
        assert!(super::super::verify_fresh_runtime_custody_availability(
            &harness.data_dir,
            &harness.registry,
            &listing,
            harness.mint_id,
            now,
        )
        .await
        .is_err());
    }

    let wrong_signer = runtime_custody_prebuy_availability_harness(
        0x62,
        ContentAvailabilityTestConfig::accepted_at(now),
    )
    .await;
    let listing =
        super::super::load_runtime_custody_listing(&wrong_signer.data_dir, wrong_signer.mint_id)
            .unwrap()
            .unwrap();
    assert!(super::super::verify_fresh_runtime_custody_availability(
        &wrong_signer.data_dir,
        &wrong_signer.registry,
        &listing,
        wrong_signer.mint_id,
        now,
    )
    .await
    .is_err());
}

#[tokio::test]
async fn runtime_custody_prebuy_availability_rejects_missing_listing_and_wrong_mint_before_provider_use(
) {
    let missing_listing = runtime_custody_prebuy_availability_harness(
        0x61,
        ContentAvailabilityTestConfig::accepted(),
    )
    .await;
    fs::remove_file(super::super::runtime_listing_path(
        &missing_listing.data_dir,
        missing_listing.mint_id,
    ))
    .unwrap();
    assert!(super::super::load_runtime_custody_listing(
        &missing_listing.data_dir,
        missing_listing.mint_id,
    )
    .unwrap()
    .is_none());
    assert!(missing_listing.content_provider.requests().await.is_empty());

    let wrong_mint = runtime_custody_prebuy_availability_harness(
        0x61,
        ContentAvailabilityTestConfig::accepted(),
    )
    .await;
    let listing =
        super::super::load_runtime_custody_listing(&wrong_mint.data_dir, wrong_mint.mint_id)
            .unwrap()
            .unwrap();
    assert!(super::super::verify_fresh_runtime_custody_availability(
        &wrong_mint.data_dir,
        &wrong_mint.registry,
        &listing,
        digest(0x33),
        NOW,
    )
    .await
    .is_err());
    assert!(wrong_mint.content_provider.requests().await.is_empty());
}

#[cfg(unix)]
#[tokio::test]
async fn runtime_custody_viewer_open_rejects_missing_or_tampered_listing_before_effects() {
    for tamper in [false, true] {
        let harness = runtime_custody_prebuy_availability_harness(
            0x61,
            ContentAvailabilityTestConfig::accepted(),
        )
        .await;
        let principal_id = "person:local:runtime-custody-viewer-listing-tamper";
        let (proof_binding_id, _) =
            install_profile_authority_keeping_device_key(&harness.data_dir, principal_id);
        let profile_did = load_profile_did_for_test(&harness.data_dir, principal_id);
        let mint = runtime_mint_journal(&harness.data_dir)
            .load(harness.mint_id)
            .unwrap();
        persist_runtime_custody_purchase_for_mint(
            &harness.data_dir,
            &mint,
            principal_id,
            &profile_did,
            crate::auth::now_ts(),
        );
        let effects = RecordingProvider::new(
            "unused",
            ok_provider_response(serde_json::json!({"schema":"unused"})),
        );
        harness
            .registry
            .register_sub_provider("wallet", effects.clone())
            .await
            .unwrap();
        harness
            .registry
            .register_runtime_provider_target(
                PROTECTED_CONTENT_DECRYPT_PROVIDER_ID,
                effects.clone(),
            )
            .await
            .unwrap();
        if tamper {
            let mut listing =
                super::super::load_runtime_custody_listing(&harness.data_dir, harness.mint_id)
                    .unwrap()
                    .unwrap();
            listing.package.price = "0x6".to_string();
            super::super::persist_runtime_custody_listing(&harness.data_dir, &listing).unwrap();
        } else {
            fs::remove_file(super::super::runtime_listing_path(
                &harness.data_dir,
                harness.mint_id,
            ))
            .unwrap();
        }
        let error = super::super::open_runtime_custody_viewer(
            &harness.data_dir,
            harness.registry.clone(),
            super::super::RuntimeCustodyViewerOpenInput {
                principal_id: principal_id.to_string(),
                mint_id: hex::encode(harness.mint_id.as_bytes()),
                launch_id: Some(TEST_VIEWER_LAUNCH_ID.to_string()),
                proof_binding_id: Some(proof_binding_id),
                session_id: Some("runtime-session:alpha".to_string()),
                grant_id: Some("grant:alpha".to_string()),
            },
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("Runtime custody"));
        assert!(harness.content_provider.requests().await.is_empty());
        assert!(effects.requests().await.is_empty());
    }
}
