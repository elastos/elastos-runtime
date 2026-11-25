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
        // The same list lives in `capsules/marketplace/browser/src/listing.js`
        // as LISTING_KEYS. The shelf parses these exactly, so a field added
        // here and forgotten there is refused in front of a person.
        vec![
            "access_state",
            "availability",
            "chain_namespace",
            "codecs",
            "content_kind",
            "display_name",
            "ledger",
            "listing_uri",
            "metadata_cid",
            "mime_type",
            "mint_id",
            "pay_token",
            "price",
            "published_at",
            "purchase_in_flight",
            "quantity",
            "schema",
            "seller_address",
            "token_id",
        ]
    );
    assert_eq!(creator_listing["display_name"], "protected-video.mp4");
    assert!(
        creator_listing["listing_uri"]
            .as_str()
            .is_some_and(|uri| uri.starts_with("elastos://")),
        "a listing names the address a creator passes on"
    );
    assert_eq!(
        creator_listing["purchase_in_flight"], false,
        "nobody is part way through buying this"
    );
    assert_eq!(creator_listing["mime_type"], MEDIA_MIME_TYPE_V1);
    assert_eq!(creator_listing["codecs"], MEDIA_CODECS_V1);
    assert_eq!(creator_listing["quantity"], "0x2");
    assert_eq!(creator_listing["price"], "0x5");
    let expected_availability = json!({
        "schema": super::super::RUNTIME_CUSTODY_LISTING_AVAILABILITY_SCHEMA_V1,
        "status": "last_verified_receipt",
        "checked_at": NOW,
        "required_replicas": super::super::PROTECTED_CONTENT_ACCEPTED_REPLICA_FLOOR,
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
    // `metadata_cid` used to be on this list and is deliberately off it now.
    //
    // It is not private: the mint writes `ipfs://<metadata_cid>/metadata.json`
    // as the media token's URI, so it is on chain for anyone to read, and the
    // document it names is published for marketplaces to fetch. Withholding it
    // from this Home's own shelf bought nothing and cost the shelf its titles
    // and covers, which live in that document.
    //
    // `token_uri` stays hidden even so: the bare CID is what a surface needs
    // to ask this Home's `/ipfs/` route for, and a URI is a second spelling of
    // the same fact that a consumer would have to parse to use.
    for hidden in [
        "publisher_principal_id",
        "content_id",
        "cid",
        "token_uri",
        // STAB-27 (J2-F3): `chain_namespace` and `ledger` are on the shelf
        // now, so a local card keys the chain's access watch; both are the
        // token's own public chain address.
        "network",
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

    let (first_paths, first_truncated) = super::super::select_runtime_custody_listing_paths(
        &listings_root,
        super::super::MAX_RUNTIME_CUSTODY_LISTINGS,
    )
    .unwrap();
    let (second_paths, second_truncated) = super::super::select_runtime_custody_listing_paths(
        &listings_root,
        super::super::MAX_RUNTIME_CUSTODY_LISTINGS,
    )
    .unwrap();
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
    // A holder still proves availability by a receipt (Plan B T4.6).
    let verified = verified.as_receipt().cloned().expect("a holder's receipt");
    assert_eq!(verified.content_cid(), ContentAvailabilityTestProvider::CID);
    // A listing verified with three copies stays valid under the one-copy rule.
    assert_eq!(
        verified.required_replicas(),
        super::super::PROTECTED_CONTENT_ACCEPTED_REPLICA_FLOOR
    );
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
    assert_eq!(
        ensure["availability_requirements"]["min_replicas"],
        super::super::PROTECTED_CONTENT_ACCEPTED_REPLICA_FLOOR
    );
    assert_eq!(
        ensure["availability_requirements"]["require_live_multi_peer_proof"],
        false
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
/// Every purchase written before minted copies existed spells the acquiring
/// transaction `buy_stage` and carries no `acquisition`. Those records are on
/// real disks, so they must keep loading, and must keep reading as bought --
/// the field was renamed because a minted copy records its mint there, not
/// because the old records meant anything different.
#[test]
fn a_purchase_written_before_minted_copies_still_loads_as_bought() {
    let legacy = serde_json::json!({
        "schema": super::super::RUNTIME_PURCHASE_SCHEMA_V1,
        "principal_id": "person:local:legacy-buyer",
        "profile_did": "did:key:z6MklegacybuyerprofiledidZZZZZZZZZZZZZZZZZZZZZZZZ",
        "mint_id": "11".repeat(32),
        "content_id": "22".repeat(16),
        "cid": "bafylegacycontent",
        "listing_sha256": format!("sha256:{}", "33".repeat(32)),
        "seller_address": "0x0000000000000000000000000000000000000011",
        "chain_namespace": "eip155:8453",
        "network": "base-mainnet",
        "ledger": "0x0000000000000000000000000000000000000022",
        "token_id": "0x77",
        "operative": "0x00000000000000000000000000000000000000dd",
        "price": "0x5",
        "pay_token": "0x0000000000000000000000000000000000000000",
        "availability_receipt_digest": format!("sha256:{}", "44".repeat(32)),
        "account_id": "wallet-account-legacy",
        "address": "0x00000000000000000000000000000000000000ee",
        "buy_stage": {
            "stage": "buy",
            "effect_id": "runtime-effect:11111111111111111111111111111111",
            "approval_request_id": "wallet-request:11111111111111111111111111111111",
            "request_sha256": format!("sha256:{}", "ac".repeat(32)),
            "chain_namespace": "eip155:8453",
            "network": "base-mainnet",
            "to": "0x2222222222222222222222222222222222222222",
            "value": "0x1",
            "data": "0x1234",
        },
        "progress": { "state": "pending" },
        "created_at": 1_700_000_000u64,
        "updated_at": 1_700_000_000u64,
    });
    let decoded: super::super::RuntimeCustodyPurchaseRecord =
        serde_json::from_value(legacy).expect("a legacy purchase record must still decode");
    assert_eq!(
        decoded.acquisition,
        super::super::RuntimeCustodyAcquisitionV1::Bought
    );
    assert_eq!(decoded.acquisition_stage.stage, "buy");
    assert_eq!(decoded.acquisition_stage.value, "0x1");
}

/// A granted copy is recorded only where no record exists, decided under
/// the purchase lock: a purchase under way -- or any record -- that lands
/// first is never overwritten.
#[test]
fn create_runtime_custody_purchase_if_absent_never_overwrites_a_record() {
    let dir = tempfile::tempdir().unwrap();
    owner_only_dir(dir.path());
    let (principal, mint_id, pending) = sample_purchase_record();
    assert!(super::super::create_runtime_custody_purchase_if_absent(dir.path(), &pending).unwrap());
    let mut granted = pending.clone();
    granted.acquisition = super::super::RuntimeCustodyAcquisitionV1::Granted;
    granted.account_id = "wallet-account-granted".to_string();
    assert!(
        !super::super::create_runtime_custody_purchase_if_absent(dir.path(), &granted).unwrap()
    );
    assert_eq!(
        load_runtime_custody_purchase(dir.path(), &principal, mint_id)
            .unwrap()
            .unwrap(),
        pending
    );
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
                executable_actor: TEST_VIEWER_EXECUTABLE_ACTOR.to_string(),
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

#[test]
fn remote_listing_proof_has_its_own_size_bound() {
    let record =
        runtime_custody_listing_record_for_test(digest(0x65), "person:local:creator", "Film", NOW);
    let mut package = record.package;
    let legacy_limit = super::super::MAX_RUNTIME_PORTABLE_LISTING_BYTES as usize;
    let remote_limit = super::super::MAX_RUNTIME_REMOTE_PORTABLE_LISTING_BYTES as usize;
    let synthetic = vec![0; remote_limit + 1];
    assert!(package
        .check_encoded_listing_size(&synthetic[..legacy_limit])
        .is_ok());
    assert!(package
        .check_encoded_listing_size(&synthetic[..legacy_limit + 1])
        .is_err());
    package.schema = super::super::RUNTIME_PORTABLE_LISTING_SCHEMA_V3.into();
    assert!(package
        .check_encoded_listing_size(&synthetic[..remote_limit])
        .is_ok());
    assert!(package.check_encoded_listing_size(&synthetic).is_err());
}

#[test]
fn real_pre_object_widening_listing_still_decodes_and_reserializes_byte_identically() {
    let record: super::super::RuntimeCustodyListingRecord =
        serde_json::from_slice(REAL_PRE_OBJECT_WIDENING_LISTING_JSON)
            .expect("a real pre-widening listing file must still deserialize");
    record
        .validate()
        .expect("a real pre-widening listing file must still validate");
    assert_eq!(
        hex::encode(sha2::Sha256::digest(
            serde_json::to_vec(&record.package).unwrap()
        )),
        REAL_PRE_OBJECT_WIDENING_PACKAGE_SHA256,
        "a media listing package must re-serialize to the exact bytes its stored digest commits to"
    );
    assert_eq!(
        serde_json::to_vec(&record).unwrap(),
        REAL_PRE_OBJECT_WIDENING_LISTING_JSON,
        "the whole record must round-trip to the exact on-disk bytes"
    );
    let decoded = record.package.decode_and_validate().unwrap();
    let media = match &decoded.content_identity {
        RuntimeContentIdentityV1::Media(media) => media,
        RuntimeContentIdentityV1::Object(_) | RuntimeContentIdentityV1::MediaDash(_) => {
            panic!("the real corpus listing is a media listing")
        }
    };
    assert_eq!(media.mime_type(), "video/mp4");
    assert_eq!(media.codecs(), "avc1.640028");
    assert_eq!(media.encrypted_segments().len(), 3);
}

/// A receipt check asks for a live proof from another peer exactly when its
/// own requirement asks for another copy. The same `local_pinned` receipt,
/// with no live proof, passes the re-check built at the floor and is refused by
/// a check that asks for two copies. With two copies on the receipt, that
/// refusal comes from the missing proof, not from the count.
#[tokio::test]
async fn receipt_check_asks_for_live_proof_only_when_its_requirement_needs_another_copy() {
    for replicas_on_receipt in [1, 2] {
        let (directory, media) = protected_content_directory(0x41);
        let provider = ContentAvailabilityTestProvider::new(
            0x61,
            ContentAvailabilityTestConfig {
                status: "local_pinned".to_string(),
                replicas: replicas_on_receipt,
                live_multi_peer_proof: Some(false),
                ..ContentAvailabilityTestConfig::accepted()
            },
        );
        let signer_did = provider.signer_did();
        let requirement_for = |minimum_replicas: u32| {
            RuntimeContentAvailabilityRequirement::new(
                signer_did.clone(),
                "did:key:z6Mkhq7f4c4QAEgwRByrEsmGu3RJRYvpP5UGcWvqBjGW4YRe#content",
                "did:key:z6Mkhq7f4c4QAEgwRByrEsmGu3RJRYvpP5UGcWvqBjGW4YRe#publisher",
                super::super::PROTECTED_CONTENT_REPLICATION_POLICY,
                minimum_replicas,
                super::super::PROTECTED_CONTENT_AVAILABILITY_MAX_AGE_SECS,
                super::super::PROTECTED_CONTENT_AVAILABILITY_MAX_FUTURE_SKEW_SECS,
            )
            .unwrap()
        };
        let recheck = requirement_for(super::super::PROTECTED_CONTENT_ACCEPTED_REPLICA_FLOOR);
        let two_copies = requirement_for(2);
        let registry = ProviderRegistry::new();
        registry
            .register_sub_provider("content", provider)
            .await
            .unwrap();

        let verified = publish_and_verify_v1_protected_content_for_test(
            &registry,
            directory.path(),
            &media,
            &recheck,
            || NOW,
        )
        .await
        .unwrap_or_else(|error| {
            panic!("{replicas_on_receipt} local_pinned copies pass the floor check: {error:#}")
        });
        let content_cid = verified.content_cid().to_string();
        let receipt = super::super::fetch_content_availability_receipt(&registry, &content_cid)
            .await
            .unwrap();
        let manifest = crate::content::fetch_content_object_manifest(&registry, &content_cid)
            .await
            .unwrap();
        let check = |requirement: &RuntimeContentAvailabilityRequirement| {
            super::super::verify_protected_content_receipt(
                &content_cid,
                &manifest,
                &receipt,
                &media,
                requirement,
                NOW,
                super::super::RuntimeManifestPublisherBinding::Exact,
            )
        };
        assert!(
            check(&recheck).is_ok(),
            "{replicas_on_receipt} local_pinned copies pass the re-check at the floor"
        );
        assert!(
            check(&two_copies).is_err(),
            "{replicas_on_receipt} local_pinned copies without a live proof fail a two-copy check"
        );
    }
}

/// A listing verified with one copy keeps validating, and its re-check asks
/// for one copy, whatever the new-mint target is: these paths read the
/// accepted floor only. The count is a literal so that a raised target which
/// leaked into validation fails here.
#[test]
fn listing_with_one_replica_stays_valid_when_target_rises() {
    const ONE_COPY: u32 = 1;
    let mut record: super::super::RuntimeCustodyListingRecord =
        serde_json::from_slice(REAL_PRE_OBJECT_WIDENING_LISTING_JSON).unwrap();
    record.availability.observed_replicas = ONE_COPY;
    record
        .validate()
        .expect("a listing verified with one copy stays valid");
    assert_eq!(
        super::super::runtime_custody_listing_availability(&record)["required_replicas"],
        ONE_COPY
    );
    record.availability.observed_replicas = 0;
    assert!(
        record.validate().is_err(),
        "a listing with no verified copy is refused"
    );

    // The re-check before a buy or an open asks for the floor.
    let recheck = RuntimeContentAvailabilityRequirement::new(
        derived_device_key_for_seed(0x61).1,
        "did:key:z6Mkhq7f4c4QAEgwRByrEsmGu3RJRYvpP5UGcWvqBjGW4YRe#content",
        "did:key:z6Mkhq7f4c4QAEgwRByrEsmGu3RJRYvpP5UGcWvqBjGW4YRe#publisher",
        super::super::PROTECTED_CONTENT_REPLICATION_POLICY,
        super::super::PROTECTED_CONTENT_ACCEPTED_REPLICA_FLOOR,
        super::super::PROTECTED_CONTENT_AVAILABILITY_MAX_AGE_SECS,
        super::super::PROTECTED_CONTENT_AVAILABILITY_MAX_FUTURE_SKEW_SECS,
    )
    .unwrap();
    assert_eq!(recheck.minimum_replicas(), ONE_COPY);
    super::super::validate_protected_content_availability_requirement(&recheck)
        .expect("a one-copy re-check requirement is accepted");
}

#[test]
fn object_listing_package_decodes_as_an_object_and_omits_the_media_identity_field() {
    let (object_identity, package) = object_listing_package_for_test(0x71);
    let bytes = serde_json::to_vec(&package).unwrap();
    let text = String::from_utf8(bytes.clone()).unwrap();
    assert!(
        !text.contains("media_identity_base64"),
        "an object package must not carry a media identity field at all"
    );
    assert!(text.contains("\"content_identity_base64\":"));
    assert_eq!(
        serde_json::from_slice::<super::super::RuntimePortableListingPackage>(&bytes).unwrap(),
        package,
        "an object package must round-trip through the durable JSON form"
    );
    let decoded = package.decode_and_validate().unwrap();
    match &decoded.content_identity {
        RuntimeContentIdentityV1::Object(object) => assert_eq!(object, &object_identity),
        RuntimeContentIdentityV1::Media(_) | RuntimeContentIdentityV1::MediaDash(_) => {
            panic!("an object package must decode as an object")
        }
    }
    assert_eq!(decoded.content_identity.content_type(), "application/pdf");
    assert_eq!(
        super::super::runtime_portable_content_codecs(&decoded.content_identity),
        "",
        "an object declares no codecs"
    );
}

/// A listing says what kind of item it is, and both kinds publish one shape.
///
/// `runtime_custody_listings_project_public_summary_and_access_state` carries
/// the canonical key list for a media row; the same list lives in
/// `capsules/marketplace/browser/src/listing.js` as LISTING_KEYS, and the
/// Marketplace parser refuses any row that does not match it exactly. That is
/// the pair that had drifted: the producer gained an availability
/// `receipt_digest` and the consumer did not, so every protected row was
/// refused in front of a person for twenty-four days.
///
/// What that test does not cover is an object. This one does, and it holds the
/// two kinds to one shape rather than repeating the list.
#[test]
fn listing_summary_names_the_kind_and_publishes_one_shape_for_both() {
    fn sorted_keys(value: &serde_json::Value) -> Vec<String> {
        let mut keys = value
            .as_object()
            .expect("a summary is an object")
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        keys.sort();
        keys
    }

    let temp = tempfile::tempdir().unwrap();
    let media = runtime_custody_listing_record_for_test(
        Digest32::new([0x7a; 32]),
        "person:local:creator",
        "clip.mp4",
        NOW,
    );
    let media_summary =
        super::super::runtime_custody_listing_summary(temp.path(), "person:local:buyer", &media)
            .unwrap();
    assert_eq!(media_summary["content_kind"], "media");
    assert_eq!(media_summary["access_state"], "available");

    let (_, package) = object_listing_package_for_test(0x7b);
    let object = super::super::RuntimeCustodyListingRecord {
        origin: super::super::RuntimeCustodyListingOrigin::LocalCreator {
            principal_id: "person:local:creator".to_string(),
            listing_uri: format!("elastos://{}", ContentAvailabilityTestProvider::CID),
            package_sha256: hex::encode(sha2::Sha256::digest(
                serde_json::to_vec(&package).unwrap(),
            )),
        },
        package,
        ..media
    };
    // Read as the creator who listed it, which is the other access state the
    // shelf renders and the one that never offers a Buy control.
    let object_summary =
        super::super::runtime_custody_listing_summary(temp.path(), "person:local:creator", &object)
            .unwrap();
    assert_eq!(
        sorted_keys(&object_summary),
        sorted_keys(&media_summary),
        "a shelf parses one row shape, whatever kind the item is"
    );
    assert_eq!(
        sorted_keys(&object_summary["availability"]),
        sorted_keys(&media_summary["availability"])
    );
    assert_eq!(object_summary["content_kind"], "object");
    assert_eq!(object_summary["mime_type"], "application/pdf");
    assert_eq!(
        object_summary["codecs"], "",
        "an object declares no codecs, and the shelf accepts that as its answer"
    );
    assert_eq!(
        object_summary["access_state"], "creator",
        "the creator of a listing is never offered their own item to buy"
    );
    marketplace_listing_consumer_for_test(&json!({
        "schema":"elastos.library.runtime-custody-listings/v1","truncated":false,
        "listings":[media_summary,object_summary]
    }));
}

/// D11: making `mint_transaction_hash` and `published_at` optional moves no
/// byte of any package that carries them. `package_sha256` and the listing CID
/// are computed over exactly these bytes, so the digests below were taken from
/// the fixtures BEFORE the fields became optional and must never change.
#[test]
fn existing_package_bytes_are_unchanged() {
    let media = runtime_custody_listing_record_for_test(
        Digest32::new([0x73; 32]),
        "person:local:media-listing",
        "media-listing",
        NOW,
    )
    .package;
    let (_, object) = object_listing_package_for_test(0x72);
    for (label, package, expected) in [
        (
            "media",
            &media,
            "3409cf54dd74fa9ce8fa1b5490eea33fc0498f3b2589c08b37b46af2f73210e2",
        ),
        (
            "object",
            &object,
            "806eef996d9f047985977766c9ddb8ee9b7a88f4b267c1cb90c37fabe9470182",
        ),
    ] {
        let bytes = serde_json::to_vec(package).unwrap();
        assert_eq!(
            hex::encode(sha2::Sha256::digest(&bytes)),
            expected,
            "{label} package bytes moved"
        );
        let round_trip: super::super::RuntimePortableListingPackage =
            serde_json::from_slice(&bytes).unwrap();
        assert_eq!(serde_json::to_vec(&round_trip).unwrap(), bytes);
    }
}

#[test]
fn shared_read_dataset_reads_only_metadata_json() {
    let media_package = media_listing_package_for_shared_test();
    let media_document =
        shared_metadata_from_producer(&SharedIdentities::of_package(&media_package, "video/mp4"));
    let dataset = crate::protected_content_market::shared_read_dataset(&media_document)
        .unwrap()
        .expect("an ElastOS mint's shared document is adoptable");
    assert_eq!(dataset.kid, media_package.content_access_id);
    assert_eq!(dataset.content_cid, ContentAvailabilityTestProvider::CID);
    assert_eq!(dataset.mime_type, "video/mp4");
    assert_eq!(dataset.name, "shared-proof.mp4");
    assert_eq!(
        dataset.rights_policy_identity_base64,
        media_package.rights_policy_identity_base64
    );
    assert_eq!(
        dataset.key_envelope_identity_base64,
        media_package.key_envelope_identity_base64
    );
    assert_eq!(
        dataset.content_key_commitment_base64,
        media_package.content_key_commitment_base64
    );
    assert_eq!(
        dataset.content_identity,
        media_package
            .decode_and_validate()
            .unwrap()
            .content_identity
    );
    assert_eq!(
        dataset.publisher_identity,
        format!(
            "did:pkh:eip155:8453:{}",
            SHARED_PUBLISHER.to_ascii_lowercase()
        )
    );
    // The identity maps back onto exactly the package's own field pair.
    assert_eq!(
        super::super::runtime_portable_identity_fields(&dataset.content_identity).unwrap(),
        (media_package.media_identity_base64.clone(), None)
    );

    let (object_identity, object_package) = object_listing_package_for_test(0x75);
    let object_document = shared_metadata_from_producer(&SharedIdentities::of_package(
        &object_package,
        "application/pdf",
    ));
    let dataset = crate::protected_content_market::shared_read_dataset(&object_document)
        .unwrap()
        .unwrap();
    assert_eq!(
        dataset.content_identity,
        RuntimeContentIdentityV1::Object(object_identity)
    );
    assert_eq!(
        super::super::runtime_portable_identity_fields(&dataset.content_identity).unwrap(),
        (None, object_package.content_identity_base64.clone())
    );

    // A bare-hex KID (what ela.city writes) is the same KID (R9); a document
    // whose KIDs disagree names none.
    let mut bare = media_document.clone();
    bare["kid"] = json!(media_package.content_access_id.trim_start_matches("0x"));
    assert_eq!(
        crate::protected_content_market::shared_read_dataset(&bare)
            .unwrap()
            .unwrap()
            .kid,
        media_package.content_access_id
    );
    let mut split = media_document;
    split["properties"]["kid"] = json!(format!("0x{}", "ab".repeat(16)));
    assert!(crate::protected_content_market::shared_read_dataset(&split).is_err());
}

#[test]
fn adopted_source_provenance_preserves_old_bytes_and_local_package_identity() {
    let mut record = adopted_listing_record_for_test();
    record.validate().unwrap();
    let old_bytes = serde_json::to_vec(&record).unwrap();
    assert!(!String::from_utf8_lossy(&old_bytes).contains("source_listing"));
    let decoded: super::super::RuntimeCustodyListingRecord =
        serde_json::from_slice(&old_bytes).unwrap();
    assert_eq!(serde_json::to_vec(&decoded).unwrap(), old_bytes);
    let old_digest = record.portable_package_digest();
    let source_uri = format!("elastos://{}", record.package.content_cid);
    let source = super::super::RuntimeSourceListing {
        listing_uri: source_uri.clone(),
        package_sha256: "ab".repeat(32),
    };
    let super::super::RuntimeCustodyListingOrigin::Asset { source_listing, .. } =
        &mut record.origin
    else {
        unreachable!()
    };
    *source_listing = Some(source.clone());
    record.validate().unwrap();
    assert_eq!(
        serde_json::to_vec(&record).unwrap(),
        old_bytes,
        "even Some provenance must not change the closed legacy listing JSON"
    );
    assert_eq!(
        record.portable_package_digest(),
        old_digest,
        "public provenance is not the local purchase digest"
    );
    assert_eq!(record.origin.listing_uri(), Some(source_uri.as_str()));
    for malformed in [
        super::super::RuntimeSourceListing {
            listing_uri: "https://example.invalid/private".to_string(),
            ..source.clone()
        },
        super::super::RuntimeSourceListing {
            package_sha256: "AB".repeat(32),
            ..source.clone()
        },
        super::super::RuntimeSourceListing {
            package_sha256: "ab".repeat(31),
            ..source
        },
    ] {
        let mut refused = record.clone();
        let super::super::RuntimeCustodyListingOrigin::Asset { source_listing, .. } =
            &mut refused.origin
        else {
            unreachable!()
        };
        *source_listing = Some(malformed);
        assert!(refused.validate().is_err());
    }
}

/// A granted listing is an adopted one on zero terms nobody offered: it
/// states nothing else, and travels nowhere.
#[test]
fn granted_origin_requires_zero_terms_and_names_no_listing_link() {
    let granted = granted_listing_record_for_test();
    granted.validate().expect("a granted record validates");
    assert!(granted.origin.is_granted());
    assert_eq!(granted.origin.listing_uri(), None);
    assert_eq!(
        serde_json::to_value(&granted.origin).unwrap(),
        json!({
            "kind": "granted",
            "asset_uri": format!("elastos://{}", granted.package.metadata_cid),
        })
    );
    assert_eq!(
        granted.portable_package_digest(),
        format!(
            "sha256:{}",
            hex::encode(sha2::Sha256::digest(
                serde_json::to_vec(&granted.package).unwrap()
            ))
        )
    );
    let refused = |label: &str, change: &dyn Fn(&mut super::super::RuntimeCustodyListingRecord)| {
        let mut record = granted_listing_record_for_test();
        change(&mut record);
        assert!(record.validate().is_err(), "{label}");
    };
    refused("a granted record names a price", &|record| {
        record.package.price = "0x1".to_string();
    });
    refused("a granted record names another seller", &|record| {
        record.package.seller_address = SHARED_PUBLISHER.to_ascii_lowercase();
    });
    refused("a granted record names a pay token", &|record| {
        record.package.pay_token = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913".to_string();
    });
    refused("a granted record names a processor", &|record| {
        record.package.payment_processor =
            Some("0x833589fcd6edb6e08f4c7c32d4f71b54bda02913".to_string());
    });
    refused("a granted record names two copies", &|record| {
        record.package.quantity = "0x2".to_string();
    });
    refused("a granted record states a mint hash", &|record| {
        record.package.mint_transaction_hash = Some(format!("0x{}", hex::encode([0x68; 32])));
    });

    // Acquisition and progress spell themselves `granted`, and every other
    // acquisition keeps its spelling.
    assert_eq!(
        serde_json::to_value(super::super::RuntimeCustodyAcquisitionV1::Granted).unwrap(),
        json!("granted")
    );
    assert_eq!(
        super::super::RuntimeCustodyAcquisitionV1::Granted.wire_value(),
        "granted"
    );
    for (acquisition, wire) in [
        (super::super::RuntimeCustodyAcquisitionV1::Bought, "bought"),
        (super::super::RuntimeCustodyAcquisitionV1::Minted, "minted"),
        (super::super::RuntimeCustodyAcquisitionV1::Market, "market"),
    ] {
        assert_eq!(serde_json::to_value(acquisition).unwrap(), json!(wire));
    }
}

#[test]
fn asset_origin_requires_absent_mint_hash_and_a_pkh_publisher() {
    let adopted = adopted_listing_record_for_test();
    adopted.validate().expect("an adopted record validates");
    let bytes = serde_json::to_string(&adopted.package).unwrap();
    assert!(!bytes.contains("mint_transaction_hash") && !bytes.contains("published_at"));
    assert_eq!(
        adopted.portable_package_digest(),
        format!(
            "sha256:{}",
            hex::encode(sha2::Sha256::digest(
                serde_json::to_vec(&adopted.package).unwrap()
            ))
        )
    );

    let refused = |label: &str, change: &dyn Fn(&mut super::super::RuntimeCustodyListingRecord)| {
        let mut record = adopted_listing_record_for_test();
        change(&mut record);
        assert!(record.validate().is_err(), "{label}");
    };
    refused("an adopted record states a mint hash", &|record| {
        record.package.mint_transaction_hash = Some(format!("0x{}", hex::encode([0x68; 32])));
    });
    refused("an adopted record states a publication time", &|record| {
        record.package.published_at = Some(NOW);
    });
    refused("an adopted record names a did:key publisher", &|record| {
        record.package.publisher_profile_did = derived_device_key_for_seed(0x66).1;
    });
    refused(
        "an adopted record names another chain's publisher",
        &|record| {
            record.package.publisher_profile_did =
                format!("did:pkh:eip155:1:{}", SHARED_PUBLISHER.to_ascii_lowercase());
        },
    );
    refused(
        "an adopted record names a mixed-case publisher",
        &|record| {
            record.package.publisher_profile_did =
                format!("did:pkh:eip155:8453:{SHARED_PUBLISHER}");
        },
    );
    refused("an adopted record names another folder", &|record| {
        record.origin = super::super::RuntimeCustodyListingOrigin::Asset {
            asset_uri: "elastos://QmcKGaG3CsCw93bc5JgDehrQTM7h1LMF1BQQiLXCvPvfz2".to_string(),
            source_listing: None,
        };
    });

    // The converse: every published origin keeps requiring both facts and a
    // `did:key` publisher.
    for origin in ["local_creator", "imported"] {
        let published = || {
            let mut record = runtime_custody_listing_record_for_test(
                Digest32::new([0x77; 32]),
                "person:local:published",
                "published",
                NOW,
            );
            if origin == "imported" {
                record.origin = super::super::RuntimeCustodyListingOrigin::Imported {
                    listing_uri: record.origin.listing_uri().unwrap().to_string(),
                    package_sha256: String::new(),
                };
                restate_published_digest(&mut record);
            }
            record
        };
        published()
            .validate()
            .expect("the control record validates");
        for (label, change) in [
            (
                "no mint hash",
                Box::new(|record: &mut super::super::RuntimeCustodyListingRecord| {
                    record.package.mint_transaction_hash = None;
                }) as Box<dyn Fn(&mut super::super::RuntimeCustodyListingRecord)>,
            ),
            (
                "no publication time",
                Box::new(|record: &mut super::super::RuntimeCustodyListingRecord| {
                    record.package.published_at = None;
                }),
            ),
            (
                "a did:pkh publisher",
                Box::new(|record: &mut super::super::RuntimeCustodyListingRecord| {
                    record.package.publisher_profile_did = format!(
                        "did:pkh:eip155:8453:{}",
                        SHARED_PUBLISHER.to_ascii_lowercase()
                    );
                }),
            ),
        ] {
            let mut record = published();
            change(&mut record);
            restate_published_digest(&mut record);
            assert!(record.validate().is_err(), "{origin} with {label}");
        }
    }
}

/// DASH v2: the codecs a head's listing declares are exactly the head's own
/// pinned codecs, comma-joined in rendition order, for every kind set.
#[test]
fn a_dash_head_declares_its_own_pinned_codecs_in_a_listing() {
    use elastos_protected_content_provider_contracts::{
        CencDashMediaIdentityV2, CencDashRenditionBytesV2, CencDashRenditionKindV2,
    };
    let segments = vec![vec![1u8, 2, 3], vec![4u8, 5, 6]];
    for kinds in [
        vec![
            CencDashRenditionKindV2::Video,
            CencDashRenditionKindV2::Audio,
        ],
        vec![CencDashRenditionKindV2::Video],
        vec![CencDashRenditionKindV2::Audio],
    ] {
        let renditions = kinds
            .iter()
            .map(|kind| CencDashRenditionBytesV2 {
                kind: *kind,
                timescale: 90_000,
                init_segment: b"init",
                segments: &segments,
            })
            .collect::<Vec<_>>();
        let head = CencDashMediaIdentityV2::new_from_bytes(
            ContentAccessIdV1::new([0x07; 16]).unwrap(),
            &renditions,
        )
        .unwrap();
        let joined = head
            .renditions()
            .iter()
            .map(|rendition| rendition.codecs())
            .collect::<Vec<_>>()
            .join(",");
        let identity = RuntimeContentIdentityV1::MediaDash(head);
        assert_eq!(
            super::super::runtime_portable_content_codecs(&identity),
            joined
        );
        assert_eq!(
            super::super::runtime_custody_content_kind(&identity),
            "media"
        );
        assert_eq!(
            super::super::expected_runtime_custody_viewer_capsule(&identity),
            super::super::ELACITY_PLAYER_CAPSULE_ID
        );
    }
}

#[test]
fn dash_listing_package_carries_the_head_in_the_object_field() {
    let components = media_dash_components(&[DASH_VIDEO, DASH_AUDIO], &[2, 2]);
    let (draft, package) = dash_listing_package_for_test(&components);
    assert!(package.media_identity_base64.is_none());
    let encoded = package.content_identity_base64.clone().unwrap();
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(&encoded)
        .unwrap();
    assert_eq!(bytes[0], 0x03, "the kind byte of a v2 head");
    let text = String::from_utf8(serde_json::to_vec(&package).unwrap()).unwrap();
    assert!(!text.contains("media_identity_base64"));
    assert_eq!(
        serde_json::from_slice::<super::super::RuntimePortableListingPackage>(text.as_bytes())
            .unwrap(),
        package
    );
    let decoded = package.decode_and_validate().unwrap();
    match &decoded.content_identity {
        RuntimeContentIdentityV1::MediaDash(head) => assert_eq!(head, &components.head),
        _ => panic!("a v2 package must decode as a head"),
    }
    assert_eq!(&decoded.content_identity, draft.content_identity());

    // A kind-prefixed v1 media identity is still refused in that field.
    let media = RuntimeContentIdentityV1::Media(media_identity(0x41));
    let mut forged = package.clone();
    forged.content_identity_base64 =
        Some(base64::engine::general_purpose::STANDARD.encode(media.canonical_bytes().unwrap()));
    assert!(forged.decode_and_validate().is_err());
    // And a head in the v1 field fails as v1 bytes.
    let mut forged = package;
    forged.content_identity_base64 = None;
    forged.media_identity_base64 = Some(encoded);
    assert!(forged.decode_and_validate().is_err());
}

#[test]
fn shared_dataset_identity_decodes_a_head_and_still_decodes_v1_media() {
    let components = media_dash_components(&[DASH_VIDEO], &[2]);
    let identity = RuntimeContentIdentityV1::MediaDash(components.head.clone());
    let encoded =
        base64::engine::general_purpose::STANDARD.encode(identity.canonical_bytes().unwrap());
    assert_eq!(
        super::super::decode_runtime_shared_content_identity(&encoded).unwrap(),
        identity
    );
    let media = media_identity(0x41);
    let bare = media.canonical_bytes().unwrap();
    assert!(
        !(0x01..=0x03).contains(&bare[0]),
        "bare v1 media bytes must not collide with a kind byte"
    );
    assert_eq!(
        super::super::decode_runtime_shared_content_identity(
            &base64::engine::general_purpose::STANDARD.encode(&bare)
        )
        .unwrap(),
        RuntimeContentIdentityV1::Media(media.clone())
    );
    // A kind-prefixed media identity is refused.
    let prefixed = RuntimeContentIdentityV1::Media(media)
        .canonical_bytes()
        .unwrap();
    assert!(super::super::decode_runtime_shared_content_identity(
        &base64::engine::general_purpose::STANDARD.encode(prefixed)
    )
    .is_err());
}

#[cfg(unix)]
#[tokio::test]
async fn dash_availability_rebuilds_the_head_draft_from_the_manifest_alone() {
    let now = crate::auth::now_ts();
    let components = media_dash_components(&[DASH_VIDEO, DASH_AUDIO], &[2, 2]);
    let harness = runtime_custody_media_dash_availability_harness(
        components,
        ContentAvailabilityTestConfig {
            checked_at: now,
            ..ContentAvailabilityTestConfig::accepted()
        },
    )
    .await;
    let listing =
        super::super::load_runtime_custody_listing(&harness.base.data_dir, harness.base.mint_id)
            .unwrap()
            .unwrap();
    let (draft, verified) = super::super::verify_fresh_runtime_custody_availability(
        &harness.base.data_dir,
        &harness.base.registry,
        &listing,
        harness.base.mint_id,
        now,
    )
    .await
    .unwrap();
    let verified = verified.as_receipt().cloned().expect("a holder's receipt");
    assert_eq!(draft.mint_id(), harness.base.mint_id);
    assert_eq!(
        draft.content_identity(),
        &RuntimeContentIdentityV1::MediaDash(harness.components.head.clone())
    );
    assert_eq!(
        verified.content_identity_root(),
        elastos_protected_content_runtime::RuntimeVerifiedContentIdentityRootV1::for_media_dash(
            &harness.components.head
        )
    );
    // Ruling D1: the manifest is enough; no segment is fetched.
    let paths = harness.base.content_provider.fetched_paths().await;
    assert!(!paths.is_empty());
    assert!(
        paths.iter().all(|path| !path.contains("/seg-")),
        "{paths:?}"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn dash_availability_is_unavailable_when_a_published_segment_disagrees() {
    let now = crate::auth::now_ts();
    let components = media_dash_components(&[DASH_VIDEO, DASH_AUDIO], &[2, 2]);
    let harness = runtime_custody_media_dash_availability_harness(
        components,
        ContentAvailabilityTestConfig {
            checked_at: now,
            ..ContentAvailabilityTestConfig::accepted()
        },
    )
    .await;
    harness
        .base
        .content_provider
        .tamper_published_manifest(|manifest| {
            let at = manifest
                .files
                .iter()
                .position(|f| f.path == dash_segment_file(DASH_AUDIO, 1))
                .unwrap();
            manifest.files[at].sha256 = hex::encode(sha2::Sha256::digest(b"other"));
            reseal(manifest);
        })
        .await;
    let listing =
        super::super::load_runtime_custody_listing(&harness.base.data_dir, harness.base.mint_id)
            .unwrap()
            .unwrap();
    let error = super::super::verify_fresh_runtime_custody_availability(
        &harness.base.data_dir,
        &harness.base.registry,
        &listing,
        harness.base.mint_id,
        now,
    )
    .await
    .unwrap_err();
    assert_eq!(
        error.to_string(),
        RUNTIME_CUSTODY_AVAILABILITY_UNAVAILABLE_MESSAGE
    );
}
