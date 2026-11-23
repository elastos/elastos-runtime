use super::*;

#[cfg(unix)]
#[tokio::test]
async fn runtime_media_preparation_reuses_exact_settled_output_and_rejects_source_changes() {
    let temp = tempfile::tempdir().unwrap();
    let (data_dir, staging_root) = setup_media_preparation_root(temp.path());
    let input = media_preparation_source_input(temp.path(), "person:local:media-retry");
    let provider = Arc::new(TestMediaPreparationProvider {
        staging_root: staging_root.clone(),
        requests: Mutex::new(Vec::new()),
        response: TestMediaPreparationResponse::prepared_video(),
    });
    let registry = Arc::new(ProviderRegistry::new());
    registry
        .register_runtime_provider_target(MEDIA_PROVIDER_ID, provider.clone())
        .await
        .unwrap();

    let first = prepare_runtime_custody_library_source(&data_dir, registry.as_ref(), &input)
        .await
        .expect("first preparation must settle");
    assert!(matches!(first, RuntimeLibraryMediaPreparation::Prepared(_)));
    let second = prepare_runtime_custody_library_source(&data_dir, registry.as_ref(), &input)
        .await
        .expect("exact retry must reuse prepared output");
    assert!(matches!(
        second,
        RuntimeLibraryMediaPreparation::Prepared(_)
    ));
    assert_eq!(provider.requests.lock().await.len(), 1);

    let operation_id = provider.requests.lock().await[0].clone();
    fs::remove_file(
        staging_root
            .join(operation_id)
            .join("prepared/video/segments/00000001.m4s"),
    )
    .unwrap();
    let corrupt = prepare_runtime_custody_library_source(&data_dir, registry.as_ref(), &input)
        .await
        .expect_err("corrupt settled output must fail closed without redispatch");
    assert_eq!(
        attempt_conflict_reason(&corrupt),
        RuntimeCustodyAttemptConflictReason::SourceChanged
    );
    assert_eq!(provider.requests.lock().await.len(), 1);

    fs::write(&input.source_file_path, b"changed source media").unwrap();
    let error = prepare_runtime_custody_library_source(&data_dir, registry.as_ref(), &input)
        .await
        .expect_err("changed source must conflict with durable authority");
    assert!(error
        .to_string()
        .contains("conflicts with existing authority"));
    assert_eq!(
        attempt_conflict_reason(&error),
        RuntimeCustodyAttemptConflictReason::SourceChanged
    );
    assert_eq!(provider.requests.lock().await.len(), 1);

    // Start over: the changed file is prepared as a new attempt, under an
    // operation of its own.
    start_over_for_test(
        &data_dir,
        &input.principal_id,
        &input.object_uri,
        &input.source_storage,
    );
    let _ = prepare_runtime_custody_library_source(&data_dir, registry.as_ref(), &input).await;
    let requests = provider.requests.lock().await;
    assert_eq!(requests.len(), 2);
    assert_ne!(requests[1], requests[0]);
}

#[cfg(unix)]
#[tokio::test]
async fn media_preparation_accepts_audio_pair() {
    let temp = tempfile::tempdir().unwrap();
    let (data_dir, staging_root) = setup_media_preparation_root(temp.path());
    let input = media_preparation_source_input(temp.path(), "person:local:media-audio");
    let provider = Arc::new(TestMediaPreparationProvider {
        staging_root,
        requests: Mutex::new(Vec::new()),
        response: TestMediaPreparationResponse::prepared_audio(),
    });
    let registry = Arc::new(ProviderRegistry::new());
    registry
        .register_runtime_provider_target(MEDIA_PROVIDER_ID, provider.clone())
        .await
        .unwrap();

    let prepared = prepare_runtime_custody_library_source(&data_dir, registry.as_ref(), &input)
        .await
        .expect("an audio rendition must settle");
    let RuntimeLibraryMediaPreparation::Prepared(prepared) = prepared else {
        panic!("expected a prepared audio rendition");
    };
    assert_eq!(prepared.input.media.renditions.len(), 1);
    assert_eq!(prepared.input.media.renditions[0].kind, DASH_AUDIO);
    assert_eq!(provider.requests.lock().await.len(), 1);
}

#[cfg(unix)]
#[tokio::test]
async fn media_preparation_rejects_unknown_pair() {
    // Only the pairs the media path can actually play are accepted; anything
    // else fails closed rather than reaching a listing no viewer can open.
    let temp = tempfile::tempdir().unwrap();
    let (data_dir, staging_root) = setup_media_preparation_root(temp.path());
    for (index, (kind, mime_type, codecs)) in [
        (DASH_AUDIO, "audio/webm", "opus"),
        // Each half of an allowed pair is still rejected when it is crossed
        // with the other rendition's half.
        (DASH_AUDIO, "audio/mp4", "avc1.640028"),
        (DASH_VIDEO, "video/mp4", "mp4a.40.2"),
    ]
    .into_iter()
    .enumerate()
    {
        // A fresh principal per pair: a rejected attempt settles as failed and
        // that record is terminal for its own source.
        let input = media_preparation_source_input(
            temp.path(),
            &format!("person:local:media-unknown-pair-{index}"),
        );
        let provider = Arc::new(TestMediaPreparationProvider {
            staging_root: staging_root.clone(),
            requests: Mutex::new(Vec::new()),
            response: TestMediaPreparationResponse::Prepared(Box::leak(Box::new([
                TestPreparedRendition {
                    kind,
                    mime_type,
                    codecs,
                    segments: 2,
                },
            ]))),
        });
        let registry = Arc::new(ProviderRegistry::new());
        registry
            .register_runtime_provider_target(MEDIA_PROVIDER_ID, provider.clone())
            .await
            .unwrap();
        let error = prepare_runtime_custody_library_source(&data_dir, registry.as_ref(), &input)
            .await
            .expect_err("an unlisted rendition pair must fail closed");
        assert!(
            error.to_string().contains("output is invalid"),
            "{mime_type} {codecs}: {error}"
        );
    }
}

#[cfg(unix)]
#[tokio::test]
async fn media_preparation_resume_matches_audio_receipt() {
    // A crash between the provider settling and the listing completing leaves
    // a record that binds the receipt digest but not the rendition pair, so
    // resuming has to rediscover which allowed pair produced that digest.
    let temp = tempfile::tempdir().unwrap();
    let (data_dir, staging_root) = setup_media_preparation_root(temp.path());
    let input = media_preparation_source_input(temp.path(), "person:local:media-audio-resume");
    let provider = Arc::new(TestMediaPreparationProvider {
        staging_root,
        requests: Mutex::new(Vec::new()),
        response: TestMediaPreparationResponse::prepared_audio(),
    });
    let registry = Arc::new(ProviderRegistry::new());
    registry
        .register_runtime_provider_target(MEDIA_PROVIDER_ID, provider.clone())
        .await
        .unwrap();

    let first = prepare_runtime_custody_library_source(&data_dir, registry.as_ref(), &input)
        .await
        .expect("first audio preparation must settle");
    assert!(matches!(first, RuntimeLibraryMediaPreparation::Prepared(_)));

    let resumed = prepare_runtime_custody_library_source(&data_dir, registry.as_ref(), &input)
        .await
        .expect("a settled audio preparation must resume from its receipt");
    let RuntimeLibraryMediaPreparation::Prepared(resumed) = resumed else {
        panic!("expected the resumed audio rendition");
    };
    assert_eq!(resumed.input.media.renditions.len(), 1);
    assert_eq!(resumed.input.media.renditions[0].kind, DASH_AUDIO);
    assert_eq!(provider.requests.lock().await.len(), 1);
}

#[cfg(unix)]
#[tokio::test]
async fn runtime_media_preparation_unknown_settlement_never_redispatches() {
    let temp = tempfile::tempdir().unwrap();
    let (data_dir, staging_root) = setup_media_preparation_root(temp.path());
    let input = media_preparation_source_input(temp.path(), "person:local:media-unknown");
    let request_id = RuntimeMintIntent::request_id_for_source(
        &input.principal_id,
        &input.object_uri,
        &input.source_storage,
    )
    .unwrap();
    let provider = Arc::new(TestMediaPreparationProvider {
        staging_root,
        requests: Mutex::new(Vec::new()),
        response: TestMediaPreparationResponse::UnknownSettlement,
    });
    let registry = Arc::new(ProviderRegistry::new());
    registry
        .register_runtime_provider_target(MEDIA_PROVIDER_ID, provider.clone())
        .await
        .unwrap();

    for _ in 0..2 {
        let error = prepare_runtime_custody_library_source(&data_dir, registry.as_ref(), &input)
            .await
            .expect_err("unknown settlement must require reconciliation");
        assert!(error.to_string().contains("settlement reconciliation"));
    }
    assert_eq!(provider.requests.lock().await.len(), 1);
    assert_eq!(
        runtime_mint_journal(&data_dir)
            .load_media_preparation(request_id)
            .unwrap()
            .state(),
        RuntimeMediaPreparationState::EffectPending
    );
}

#[cfg(unix)]
#[tokio::test]
async fn runtime_media_preparation_settled_failure_is_terminal_and_cleans_staging() {
    let temp = tempfile::tempdir().unwrap();
    let (data_dir, staging_root) = setup_media_preparation_root(temp.path());
    let input = media_preparation_source_input(temp.path(), "person:local:media-failed");
    let request_id = RuntimeMintIntent::request_id_for_source(
        &input.principal_id,
        &input.object_uri,
        &input.source_storage,
    )
    .unwrap();
    let provider = Arc::new(TestMediaPreparationProvider {
        staging_root: staging_root.clone(),
        requests: Mutex::new(Vec::new()),
        response: TestMediaPreparationResponse::SettledFailure,
    });
    let registry = Arc::new(ProviderRegistry::new());
    registry
        .register_runtime_provider_target(MEDIA_PROVIDER_ID, provider.clone())
        .await
        .unwrap();

    for _ in 0..2 {
        let error = prepare_runtime_custody_library_source(&data_dir, registry.as_ref(), &input)
            .await
            .expect_err("settled provider failure must remain terminal");
        assert!(error.to_string().contains("media preparation failed"));
    }
    assert_eq!(provider.requests.lock().await.len(), 1);
    assert_eq!(
        runtime_mint_journal(&data_dir)
            .load_media_preparation(request_id)
            .unwrap()
            .state(),
        RuntimeMediaPreparationState::Failed
    );
    assert!(fs::read_dir(staging_root).unwrap().next().is_none());
}

#[tokio::test]
async fn runtime_custody_library_publish_fails_closed_without_composition() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    fs::create_dir_all(&data_dir).unwrap();
    let error = publish_runtime_custody_library_object(
        &data_dir,
        Arc::new(ProviderRegistry::new()),
        library_publish_test_input(
            &data_dir,
            "person:local:runtime-custody-missing-composition",
        ),
    )
    .await
    .expect_err("missing composition must fail closed");
    // Plan B S7-lite T7.6: no own pool and no admitting pool.
    assert_eq!(
        error.to_string(),
        super::super::RUNTIME_CUSTODY_MINT_NO_POOL_MESSAGE
    );
    assert!(!data_dir.join("protected-content/runtime-mint").exists());
}

#[cfg(unix)]
#[tokio::test]
async fn runtime_custody_library_publish_fails_closed_without_protect_provider() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    write_device_key(&data_dir, 0x21);
    let _ = write_library_publish_test_composition(&data_dir);
    let input =
        library_publish_test_input(&data_dir, "person:local:runtime-custody-missing-protect");
    let request_id = library_publish_request_id(&input);
    let error =
        publish_runtime_custody_library_object(&data_dir, Arc::new(ProviderRegistry::new()), input)
            .await
            .expect_err("missing protect provider must fail closed");
    assert!(
        error
            .to_string()
            .contains("Runtime custody protect provider is unavailable"),
        "{error}"
    );
    let intent = runtime_mint_journal(&data_dir)
        .load_intent(request_id)
        .unwrap();
    assert_eq!(intent.protect_state_label(), "not_started");
    assert!(!intent.provider_effect_started());
}

#[cfg(unix)]
#[tokio::test]
async fn runtime_custody_library_publish_fails_closed_without_chain_policy() {
    let protect_binary = required_test_binary_path(TEST_PROTECT_PROVIDER_BIN_ENV);
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    write_device_key(&data_dir, 0x21);
    let _ = write_library_publish_test_composition(&data_dir);
    let registry = Arc::new(ProviderRegistry::new());
    register_protect_provider(&registry, &protect_binary)
        .await
        .unwrap();
    let input =
        library_publish_test_input(&data_dir, "person:local:runtime-custody-missing-policy");
    let request_id = library_publish_request_id(&input);
    let error = publish_runtime_custody_library_object(&data_dir, registry.clone(), input)
        .await
        .expect_err("missing chain policy must fail closed");
    assert!(
        error
            .to_string()
            .contains("Runtime custody rights policy is unavailable"),
        "{error}"
    );
    let intent = runtime_mint_journal(&data_dir)
        .load_intent(request_id)
        .unwrap();
    assert!(intent.protect_terminal_before_draft());
    assert_eq!(intent.protect_terminal_settlement_label(), Some("closed"));

    registry
        .unregister_runtime_provider_target(PROTECT_PROVIDER_ID)
        .await
        .unwrap();
    let replay = publish_runtime_custody_library_object(
        &data_dir,
        registry,
        library_publish_test_input(&data_dir, "person:local:runtime-custody-missing-policy"),
    )
    .await
    .expect_err("settled-before-draft retry must remain terminal");
    assert!(
        replay
            .to_string()
            .contains(RUNTIME_CUSTODY_MINT_TERMINAL_ABORT_MESSAGE),
        "{replay}"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn runtime_custody_library_publish_adopts_completed_mint_after_lost_completion_mark() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    write_device_key(&data_dir, 0x21);
    let input = library_publish_test_input(
        &data_dir,
        "person:local:runtime-custody-lost-completion-mark",
    );
    let request_id = library_publish_request_id(&input);
    let expected_mint_id = seed_settled_runtime_custody_mint_record(&data_dir, &input, true);

    // No providers registered: adoption must resolve from the journal alone.
    let facts =
        publish_runtime_custody_library_object(&data_dir, Arc::new(ProviderRegistry::new()), input)
            .await
            .expect(
                "a crash after completed mint work must adopt the record, not brick the source",
            );
    assert_eq!(facts.mint_id, expected_mint_id);

    let intent = runtime_mint_journal(&data_dir)
        .load_intent(request_id)
        .unwrap();
    assert_eq!(intent.completed_mint_id(), Some(expected_mint_id));

    let replay = publish_runtime_custody_library_object(
        &data_dir,
        Arc::new(ProviderRegistry::new()),
        library_publish_test_input(
            &data_dir,
            "person:local:runtime-custody-lost-completion-mark",
        ),
    )
    .await
    .expect("an adopted completion must replay as completed facts");
    assert_eq!(replay.mint_id, expected_mint_id);
}

#[cfg(unix)]
#[tokio::test]
async fn runtime_custody_library_publish_retries_exactly_when_protect_never_dispatches() {
    let protect_binary = required_test_binary_path(TEST_PROTECT_PROVIDER_BIN_ENV);
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    write_device_key(&data_dir, 0x21);
    let (epoch, _composition_now) = write_library_publish_test_composition(&data_dir);
    let registry = Arc::new(ProviderRegistry::new());
    let input = pre_dispatch_retry_publish_input(&data_dir);
    let request_id = library_publish_request_id(&input);
    let first = publish_runtime_custody_library_object(&data_dir, registry.clone(), input)
        .await
        .expect_err("missing protect provider must fail closed");
    assert!(
        first
            .to_string()
            .contains("Runtime custody protect provider is unavailable"),
        "{first}"
    );

    let first_intent = runtime_mint_journal(&data_dir)
        .load_intent(request_id)
        .unwrap();
    assert_eq!(first_intent.protect_state_label(), "not_started");
    let expected_access_id = first_intent.content_access_id();

    register_protect_provider(&registry, &protect_binary)
        .await
        .unwrap();
    registry
        .register_runtime_provider_target(
            CUSTODY_PROVIDER_ID,
            Arc::new(LibraryMintCustodyProvider {
                expected_issuer: derived_device_runtime_issuer(0x21),
                nodes: epoch
                    .statement()
                    .nodes()
                    .iter()
                    .map(|node| node.node_public_key())
                    .collect(),
            }),
        )
        .await
        .unwrap();
    registry
        .set_carrier_invoker(Arc::new(LoopbackCustodyCarrierInvoker {
            registry: Arc::downgrade(&registry),
        }))
        .await;
    registry
        .register_sub_provider(CHAIN_PROVIDER_ID, Arc::new(LibraryMintChainPolicyProvider))
        .await
        .unwrap();
    install_profile_authority_keeping_device_key(
        &data_dir,
        "person:local:runtime-custody-pre-dispatch-retry",
    );
    let (device_key, _) = derived_device_key_for_seed(0x21);
    let content = ContentAvailabilityTestProvider::with_signing_key(
        device_key,
        ContentAvailabilityTestConfig {
            checked_at: crate::auth::now_ts(),
            ..ContentAvailabilityTestConfig::accepted()
        },
    );
    registry
        .register_sub_provider("content", content)
        .await
        .unwrap();

    let published = publish_runtime_custody_library_object(
        &data_dir,
        registry.clone(),
        pre_dispatch_retry_publish_input(&data_dir),
    )
    .await
    .expect("exact retry must reuse the persisted intent");
    assert!(published.content_id.starts_with("content:"));

    let reloaded = runtime_mint_journal(&data_dir)
        .load_intent(request_id)
        .unwrap();
    assert_eq!(reloaded.content_access_id(), expected_access_id);
    assert_eq!(reloaded.completed_mint_id(), Some(published.mint_id));

    registry
        .unregister_runtime_provider_target(PROTECT_PROVIDER_ID)
        .await
        .unwrap();
    registry
        .unregister_runtime_provider_target(CUSTODY_PROVIDER_ID)
        .await
        .unwrap();
    registry
        .unregister_sub_provider(CHAIN_PROVIDER_ID)
        .await
        .unwrap();
    registry.unregister_sub_provider("content").await.unwrap();

    let media_provider_root = data_dir.join("protected-content/media-provider");
    owner_only_dir(&media_provider_root);
    owner_only_dir(&media_provider_root.join("staging"));
    // The principal's root is recovery-activated (protected) by the profile
    // authority above, so the source object must be stored as a protected
    // principal-root envelope like a real Library write; the replay is keyed
    // on the plaintext digest.
    let retry_principal = "person:local:runtime-custody-pre-dispatch-retry";
    let retry_localhost_root = crate::auth::principal_localhost_root(retry_principal);
    let retry_object_uri = format!("{retry_localhost_root}/Documents/media");
    let source_file_path =
        elastos_common::localhost::rooted_localhost_fs_path(&data_dir, &retry_object_uri).unwrap();
    let mut source_ancestors: Vec<PathBuf> = source_file_path
        .ancestors()
        .skip(1)
        .take_while(|dir| dir.starts_with(&data_dir) && *dir != data_dir)
        .map(Path::to_path_buf)
        .collect();
    source_ancestors.reverse();
    for dir in source_ancestors {
        owner_only_dir(&dir);
    }
    crate::auth::write_protected_principal_root_object(
        &data_dir,
        retry_principal,
        &retry_localhost_root,
        &retry_object_uri,
        &source_file_path,
        b"completed source media",
    )
    .unwrap();
    let source = RuntimeCustodyLibrarySourceInput {
        listing: None,
        object_uri: retry_object_uri.clone(),
        principal_id: retry_principal.to_string(),
        source_file_path: source_file_path.clone(),
        wallet_account_id: "wallet-account-1".to_string(),
        wallet_account_address: "0x1111111111111111111111111111111111111111".to_string(),
        creator_mint_source_digest: digest(0x71),
        copies: "0x1".to_string(),
        price: "5".to_string(),
        channel: "0x0000000000000000000000000000000000000022".to_string(),
        pay_token: String::new(),
        source_storage: "plain_localhost_root".to_string(),
        pool_did: None,
    };
    let preparation = RuntimeMediaPreparationRecord::new(
        &source.principal_id,
        &source.object_uri,
        &source.source_storage,
        runtime_media_source_digest(b"completed source media"),
        MEDIA_PROVIDER_ID,
        source.wallet_account_id.clone(),
        source.wallet_account_address.clone(),
        source.creator_mint_source_digest,
    )
    .unwrap();
    let preparation_receipt = digest(0xd1);
    let journal = runtime_mint_journal(&data_dir);
    journal.persist_media_preparation(&preparation).unwrap();
    journal
        .mark_media_preparation_effect_started(preparation.request_id())
        .unwrap();
    journal
        .mark_media_preparation_prepared(preparation.request_id(), preparation_receipt)
        .unwrap();
    journal
        .mark_media_preparation_consumed(
            preparation.request_id(),
            preparation_receipt,
            published.mint_id,
        )
        .unwrap();
    let (source_replay, source_replay_input) =
        publish_runtime_custody_library_source(&data_dir, registry.clone(), source)
            .await
            .expect("consumed media preparation must replay without provider dispatch");
    assert_eq!(source_replay.mint_id, published.mint_id);
    assert!(source_replay_input.media.renditions.is_empty());

    let replay = publish_runtime_custody_library_object(
        &data_dir,
        registry,
        pre_dispatch_retry_publish_input(&data_dir),
    )
    .await
    .expect("completed mint replay must remain idempotent without providers");
    assert_eq!(replay.content_cid, published.content_cid);
    assert_eq!(replay.content_id, published.content_id);
    assert_eq!(replay.mint_id, published.mint_id);
}

#[cfg(unix)]
#[tokio::test]
async fn runtime_custody_library_publish_rejects_creator_account_switch_before_protect_effects() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    write_device_key(&data_dir, 0x21);
    write_library_publish_test_composition(&data_dir);
    let registry = Arc::new(ProviderRegistry::new());
    let input = library_publish_test_input(
        &data_dir,
        "person:local:runtime-custody-creator-account-switch",
    );
    let request_id = library_publish_request_id(&input);
    let first = publish_runtime_custody_library_object(&data_dir, registry.clone(), input.clone())
        .await
        .expect_err("missing protect provider must fail closed");
    assert!(
        first
            .to_string()
            .contains("Runtime custody protect provider is unavailable"),
        "{first}"
    );

    let mut switched = input;
    switched.wallet_account_id = "wallet-account-2".to_string();
    switched.wallet_account_address = "0x2222222222222222222222222222222222222222".to_string();
    let second =
        publish_runtime_custody_library_object(&data_dir, registry.clone(), switched.clone())
            .await
            .expect_err("creator account drift must fail closed");
    assert!(
        second
            .to_string()
            .contains("Runtime custody mint intent conflicts with existing authority"),
        "{second}"
    );
    assert_eq!(
        attempt_conflict_reason(&second),
        RuntimeCustodyAttemptConflictReason::AuthorityChanged
    );

    let intent = runtime_mint_journal(&data_dir)
        .load_intent(request_id)
        .unwrap();
    assert_eq!(intent.creator_wallet_account_id(), "wallet-account-1");
    assert_eq!(
        intent.creator_wallet_address(),
        "0x1111111111111111111111111111111111111111"
    );
    assert_eq!(intent.protect_state_label(), "not_started");

    // Never a dead end: Start over sets the attempt aside, and the switched
    // account then starts a new attempt instead of meeting the old one.
    start_over_for_test(
        &data_dir,
        &switched.principal_id,
        &switched.object_uri,
        &switched.source_storage,
    );
    let third = publish_runtime_custody_library_object(&data_dir, registry, switched)
        .await
        .expect_err("still no protect provider");
    assert!(
        third
            .to_string()
            .contains("Runtime custody protect provider is unavailable"),
        "{third}"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn runtime_custody_library_publish_rejects_creator_source_drift_during_open_request_pending()
{
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    write_device_key(&data_dir, 0x21);
    write_library_publish_test_composition(&data_dir);
    let protect = SequencedProvider::new(
        PROTECT_PROVIDER_ID,
        vec![Err(ProviderError::Provider(
            "simulated protect bridge failure".to_string(),
        ))],
    );
    let registry = Arc::new(ProviderRegistry::new());
    registry
        .register_runtime_provider_target(PROTECT_PROVIDER_ID, protect.clone())
        .await
        .unwrap();
    let input = library_publish_test_input(&data_dir, "person:local:runtime-custody-source-drift");
    let request_id = library_publish_request_id(&input);
    let first = publish_runtime_custody_library_object(&data_dir, registry.clone(), input.clone())
        .await
        .expect_err("ambiguous protect dispatch must fail closed");
    assert!(
        first
            .to_string()
            .contains("Runtime custody protect provider is unavailable"),
        "{first}"
    );
    let pending = runtime_mint_journal(&data_dir)
        .load_intent(request_id)
        .unwrap();
    assert_eq!(pending.protect_state_label(), "open_request_pending");

    let mut drifted = input.clone();
    drifted.creator_mint_source_digest = digest(0x72);
    let second = publish_runtime_custody_library_object(&data_dir, registry.clone(), drifted)
        .await
        .expect_err("creator source drift must fail closed");
    assert!(
        second
            .to_string()
            .contains("Runtime custody mint intent conflicts with existing authority"),
        "{second}"
    );
    assert_eq!(
        attempt_conflict_reason(&second),
        RuntimeCustodyAttemptConflictReason::AuthorityChanged
    );

    let reloaded = runtime_mint_journal(&data_dir)
        .load_intent(request_id)
        .unwrap();
    assert_eq!(reloaded.protect_state_label(), "open_request_pending");
    let requests = protect.requests().await;
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0]["op"], "open_protection_session");

    // The exact retry cannot replay a dispatch whose outcome is unknown, and
    // says so as data.
    let third = publish_runtime_custody_library_object(&data_dir, registry.clone(), input.clone())
        .await
        .expect_err("an uncertain dispatch must fail closed");
    assert_eq!(
        attempt_conflict_reason(&third),
        RuntimeCustodyAttemptConflictReason::DispatchUncertain
    );
    assert_eq!(
        runtime_mint_journal(&data_dir)
            .load_intent(request_id)
            .unwrap()
            .protect_state_label(),
        "open_request_pending"
    );

    // Start over leaves that attempt where it is, aside, and the next publish
    // opens a session of its own under a new identity.
    start_over_for_test(
        &data_dir,
        &input.principal_id,
        &input.object_uri,
        &input.source_storage,
    );
    let dispatched = protect.requests().await.len();
    let _ = publish_runtime_custody_library_object(&data_dir, registry, input).await;
    let requests = protect.requests().await;
    assert_eq!(requests.len(), dispatched + 1);
    assert_eq!(requests[dispatched]["op"], "open_protection_session");
    assert_ne!(requests[dispatched], requests[0]);
}

#[cfg(unix)]
#[tokio::test]
async fn runtime_custody_library_publish_settles_cancelled_session_before_failing() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    write_device_key(&data_dir, 0x21);
    let _ = write_library_publish_test_composition(&data_dir);
    let handle = [0x31; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1];
    let protect = SequencedProvider::new(
        PROTECT_PROVIDER_ID,
        vec![
            Ok(ok_typed_protect_provider_response(
                ProtectProviderResponseV1::new_opened_v2(
                    handle,
                    &[
                        b"placeholder-protected-init".to_vec(),
                        b"placeholder-protected-init".to_vec(),
                    ],
                )
                .unwrap(),
            )),
            Ok(ok_typed_protect_provider_response(
                ProtectProviderResponseV1::new_failure(ProviderFailureCodeV1::BackendUnavailable)
                    .unwrap(),
            )),
            Ok(ok_typed_protect_provider_response(
                ProtectProviderResponseV1::new_cancelled(handle).unwrap(),
            )),
        ],
    );
    let registry = Arc::new(ProviderRegistry::new());
    registry
        .register_runtime_provider_target(PROTECT_PROVIDER_ID, protect.clone())
        .await
        .unwrap();
    let input =
        library_publish_test_input(&data_dir, "person:local:runtime-custody-cancel-settlement");
    let request_id = library_publish_request_id(&input);
    let first = publish_runtime_custody_library_object(&data_dir, registry.clone(), input)
        .await
        .expect_err("protect segment failure must fail closed");
    assert!(
        first
            .to_string()
            .contains("Runtime custody protect provider is unavailable"),
        "{first}"
    );
    let settled = runtime_mint_journal(&data_dir)
        .load_intent(request_id)
        .unwrap();
    assert!(settled.protect_terminal_before_draft());
    assert_eq!(
        settled.protect_terminal_settlement_label(),
        Some("cancelled")
    );

    let second = publish_runtime_custody_library_object(
        &data_dir,
        registry,
        library_publish_test_input(&data_dir, "person:local:runtime-custody-cancel-settlement"),
    )
    .await
    .expect_err("acted intent must not redispatch after cancel settlement");
    assert!(
        second
            .to_string()
            .contains(RUNTIME_CUSTODY_MINT_TERMINAL_ABORT_MESSAGE),
        "{second}"
    );
    let requests = protect.requests().await;
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[2]["op"], "cancel_protection_session");
}

#[cfg(unix)]
#[tokio::test]
async fn runtime_media_preparation_stages_plaintext_from_a_protected_principal_root() {
    // Once recovery is activated the principal root is encrypted: the source
    // object on disk is an `elastos.principal-root.object/v1` envelope, not
    // the media bytes. The Runtime must stage the decrypted plaintext for the
    // media provider (a raw copy would hand ffprobe ciphertext).
    let temp = tempfile::tempdir().unwrap();
    let (data_dir, staging_root) = setup_media_preparation_root(temp.path());
    let principal_id = "person:local:media-protected-root";
    let mut input = media_preparation_source_input(temp.path(), principal_id);
    let localhost_root = crate::auth::principal_localhost_root(principal_id);
    let source_path =
        elastos_common::localhost::rooted_localhost_fs_path(&data_dir, &input.object_uri).unwrap();
    // Protected writes require an owner-only ancestry under the data dir.
    let mut ancestors: Vec<PathBuf> = source_path
        .ancestors()
        .skip(1)
        .take_while(|dir| dir.starts_with(&data_dir) && *dir != data_dir)
        .map(Path::to_path_buf)
        .collect();
    ancestors.reverse();
    for dir in ancestors {
        owner_only_dir(&dir);
    }
    input.source_file_path = source_path.clone();
    crate::auth::store_test_principal_root_protection(&data_dir, principal_id);
    let plaintext = b"protected source media".to_vec();
    crate::auth::write_protected_principal_root_object(
        &data_dir,
        principal_id,
        &localhost_root,
        &input.object_uri,
        &source_path,
        &plaintext,
    )
    .unwrap();
    let stored = fs::read(&source_path).unwrap();
    assert_ne!(stored, plaintext);
    assert!(stored.starts_with(b"{"));

    let provider = Arc::new(TestMediaPreparationProvider {
        staging_root: staging_root.clone(),
        requests: Mutex::new(Vec::new()),
        response: TestMediaPreparationResponse::prepared_video(),
    });
    let registry = Arc::new(ProviderRegistry::new());
    registry
        .register_runtime_provider_target(MEDIA_PROVIDER_ID, provider.clone())
        .await
        .unwrap();
    let prepared = prepare_runtime_custody_library_source(&data_dir, registry.as_ref(), &input)
        .await
        .expect("protected source must prepare");
    assert!(matches!(
        prepared,
        RuntimeLibraryMediaPreparation::Prepared(_)
    ));
    let operation_id = provider.requests.lock().await[0].clone();
    assert_eq!(
        fs::read(staging_root.join(operation_id).join("input.bin")).unwrap(),
        plaintext
    );
}

#[cfg(unix)]
#[test]
fn prepared_v2_loader_reads_video_audio_video_only_and_audio_only() {
    for (renditions, declared) in [
        (
            vec![(DASH_VIDEO, 3), (DASH_AUDIO, 3)],
            vec![
                (TEST_VIDEO_DECL.0, TEST_VIDEO_DECL.1, TEST_VIDEO_DECL.2, 3),
                (TEST_AUDIO_DECL.0, TEST_AUDIO_DECL.1, TEST_AUDIO_DECL.2, 3),
            ],
        ),
        (
            vec![(DASH_VIDEO, 4)],
            vec![(TEST_VIDEO_DECL.0, TEST_VIDEO_DECL.1, TEST_VIDEO_DECL.2, 4)],
        ),
        (
            vec![(DASH_AUDIO, 2)],
            vec![(TEST_AUDIO_DECL.0, TEST_AUDIO_DECL.1, TEST_AUDIO_DECL.2, 2)],
        ),
    ] {
        let (_temp, root) = prepared_root_for_test(&renditions);
        let media = super::super::load_validated_runtime_prepared_media_v2(
            &root,
            &prepared_output_for_test(&declared),
        )
        .unwrap();
        assert_eq!(media.renditions.len(), renditions.len());
        let mut clear_bytes = 0u64;
        for (loaded, (kind, count)) in media.renditions.iter().zip(&renditions) {
            assert_eq!(loaded.kind, *kind);
            assert_eq!(loaded.segment_count as usize, *count);
            let init = media_dash_fixture::init(*kind, 1);
            assert_eq!(loaded.clear_init_segment, init);
            clear_bytes += init.len() as u64
                + media_dash_fixture::clear_segments(*kind, *count)
                    .iter()
                    .map(|segment| segment.len() as u64)
                    .sum::<u64>();
        }
        assert_eq!(media.clear_bytes(), clear_bytes);
        assert_eq!(
            media.preparation_receipt(),
            independent_preparation_receipt(&renditions)
        );
        // A resume needs no declaration and gets the same value.
        let resumed = super::super::load_settled_runtime_prepared_media_v2(
            &root,
            media.preparation_receipt(),
        )
        .unwrap();
        assert_eq!(resumed.preparation_receipt(), media.preparation_receipt());
        assert!(super::super::load_settled_runtime_prepared_media_v2(&root, digest(0x01)).is_err());
    }
}

#[cfg(unix)]
#[test]
fn prepared_v2_loader_refuses_every_deviation_and_accepts_the_part_rule() {
    const RULE: usize = 2 * 1024 * 1024 - 64 * 1024;
    let video_audio = [(DASH_VIDEO, 3), (DASH_AUDIO, 3)];
    let declared_video_audio = vec![
        (TEST_VIDEO_DECL.0, TEST_VIDEO_DECL.1, TEST_VIDEO_DECL.2, 3),
        (TEST_AUDIO_DECL.0, TEST_AUDIO_DECL.1, TEST_AUDIO_DECL.2, 3),
    ];
    let load = |root: &Path, declared: &[(&str, &str, &str, usize)]| {
        super::super::load_validated_runtime_prepared_media_v2(
            root,
            &prepared_output_for_test(declared),
        )
    };
    let invalid = |result: anyhow::Result<super::super::RuntimePreparedMediaV2>, label: &str| {
        let error = result
            .err()
            .unwrap_or_else(|| panic!("{label}: must be refused"));
        assert_eq!(
            error.to_string(),
            "Runtime custody media preparation output is invalid",
            "{label}"
        );
    };

    // The declaration itself.
    let (_temp, root) = prepared_root_for_test(&video_audio);
    let mut v1 = prepared_output_for_test(&declared_video_audio);
    v1.schema = "elastos.media-provider.prepared-media/v1".to_string();
    invalid(
        super::super::load_validated_runtime_prepared_media_v2(&root, &v1),
        "a v1 schema",
    );
    assert!(
        serde_json::from_value::<super::super::RuntimePreparedMediaProviderOutputV2>(json!({
            "schema": "elastos.media-provider.prepared-media/v2",
            "renditions": [],
            "mime_type": "video/mp4",
        }))
        .is_err()
    );
    assert!(
        serde_json::from_value::<super::super::RuntimePreparedMediaProviderOutputV2>(json!({
            "schema": "elastos.media-provider.prepared-media/v1",
            "mime_type": "video/mp4",
            "codecs": "avc1.640028",
        }))
        .is_err()
    );
    invalid(
        load(
            &root,
            &[("video", "video/mp4", "mp4a.40.2", 3), audio_decl(3)],
        ),
        "a wrong pair",
    );
    invalid(
        load(
            &root,
            &[audio_decl(3), ("video", "video/mp4", "avc1.640028", 3)],
        ),
        "audio before video",
    );
    invalid(load(&root, &[]), "no rendition");
    invalid(
        load(
            &root,
            &[
                ("video", "video/mp4", "avc1.640028", 3),
                ("video", "video/mp4", "avc1.640028", 3),
            ],
        ),
        "a duplicate rendition",
    );
    invalid(
        load(
            &root,
            &[("video", "video/mp4", "avc1.640028", 2), audio_decl(3)],
        ),
        "a declared count different from the files",
    );

    // The tree.
    let mutate = |renditions: &[(CencDashRenditionKindV2, usize)],
                  declared: &[(&str, &str, &str, usize)],
                  label: &str,
                  change: &dyn Fn(&Path)| {
        let (_temp, root) = prepared_root_for_test(renditions);
        change(&root);
        invalid(load(&root, declared), label);
    };
    mutate(&video_audio, &declared_video_audio, "a name gap", &|root| {
        fs::rename(
            root.join("prepared/video/segments/00000002.m4s"),
            root.join("prepared/video/segments/00000003.m4s"),
        )
        .unwrap();
    });
    mutate(
        &video_audio,
        &declared_video_audio,
        "an extra file in prepared/",
        &|root| {
            write_private_file(&root.join("prepared/manifest.mpd"), b"x");
        },
    );
    mutate(
        &video_audio,
        &declared_video_audio,
        "an extra file in a rendition",
        &|root| {
            write_private_file(&root.join("prepared/audio/extra"), b"x");
        },
    );
    mutate(
        &video_audio,
        &declared_video_audio,
        "an extra file in segments",
        &|root| {
            write_private_file(&root.join("prepared/audio/segments/notes.txt"), b"x");
        },
    );
    mutate(
        &video_audio,
        &declared_video_audio,
        "a rendition missing its init",
        &|root| {
            fs::remove_file(root.join("prepared/video/init.mp4")).unwrap();
        },
    );
    mutate(
        &video_audio,
        &declared_video_audio,
        "a symlinked segment",
        &|root| {
            let target = root.join("prepared/video/segments/00000001.m4s");
            let copy = root.join("elsewhere.m4s");
            fs::rename(&target, &copy).unwrap();
            std::os::unix::fs::symlink(&copy, &target).unwrap();
        },
    );
    mutate(
        &video_audio,
        &declared_video_audio,
        "a world-readable segments directory",
        &|root| {
            fs::set_permissions(
                root.join("prepared/video/segments"),
                fs::Permissions::from_mode(0o755),
            )
            .unwrap();
        },
    );
    mutate(
        &video_audio,
        &declared_video_audio,
        "a v1-shaped output",
        &|root| {
            write_private_file(&root.join("prepared/init.mp4"), b"init");
        },
    );
    // An init of the other kind, and a two-track init.
    mutate(
        &video_audio,
        &declared_video_audio,
        "an init of the wrong kind",
        &|root| {
            write_private_file(
                &root.join("prepared/video/init.mp4"),
                &media_dash_fixture::init(DASH_AUDIO, 1),
            );
        },
    );
    mutate(
        &video_audio,
        &declared_video_audio,
        "a two-track init",
        &|root| {
            write_private_file(
                &root.join("prepared/video/init.mp4"),
                &clear_media_components(0x41).0,
            );
        },
    );
    // Timelines: not starting at zero, a gap, and samples not at the mdat data.
    mutate(
        &video_audio,
        &declared_video_audio,
        "a first segment not at zero",
        &|root| {
            write_private_file(
                &root.join("prepared/video/segments/00000000.m4s"),
                &media_dash_fixture::clear_segment(
                    1,
                    1_024,
                    &[media_dash_fixture::video_sample(300)],
                ),
            );
        },
    );
    mutate(
        &video_audio,
        &declared_video_audio,
        "a gap in the timeline",
        &|root| {
            write_private_file(
                &root.join("prepared/audio/segments/00000001.m4s"),
                &media_dash_fixture::clear_segment(
                    1,
                    5_000,
                    &[media_dash_fixture::audio_sample(1, 120)],
                ),
            );
        },
    );
    mutate(
        &video_audio,
        &declared_video_audio,
        "samples not at the mdat data",
        &|root| {
            let path = root.join("prepared/video/segments/00000001.m4s");
            let mut segment = fs::read(&path).unwrap();
            // data_offset + 1 and one more mdat byte: the first sample no longer
            // starts at the mdat payload.
            let trun = segment
                .windows(4)
                .position(|window| window == b"trun")
                .unwrap()
                - 4;
            let offset = u32::from_be_bytes(segment[trun + 16..trun + 20].try_into().unwrap()) + 1;
            segment[trun + 16..trun + 20].copy_from_slice(&offset.to_be_bytes());
            let moof = u32::from_be_bytes(segment[0..4].try_into().unwrap()) as usize;
            let size = u32::from_be_bytes(segment[moof..moof + 4].try_into().unwrap()) + 1;
            segment[moof..moof + 4].copy_from_slice(&size.to_be_bytes());
            segment.push(0);
            write_private_file(&path, &segment);
        },
    );
    // Skew: the head allows the rendition counts to differ by at most one.
    let skewed = [(DASH_VIDEO, 4), (DASH_AUDIO, 2)];
    let (_temp, root) = prepared_root_for_test(&skewed);
    invalid(
        load(
            &root,
            &[("video", "video/mp4", "avc1.640028", 4), audio_decl(2)],
        ),
        "a skew of two",
    );
    let off_by_one = [(DASH_VIDEO, 3), (DASH_AUDIO, 2)];
    let (_temp, root) = prepared_root_for_test(&off_by_one);
    load(
        &root,
        &[("video", "video/mp4", "avc1.640028", 3), audio_decl(2)],
    )
    .expect("a skew of one is allowed");

    // The part rule: a part exactly at 2 MiB - 64 KiB loads, one byte more does not.
    let (_temp, root) = prepared_root_for_test(&[(DASH_VIDEO, 2)]);
    write_private_file(&root.join("prepared/video/segments/00000001.m4s"), &{
        let mut segment = video_segment_of_len(RULE);
        // The second segment follows the first on the timeline.
        let tfdt = segment
            .windows(4)
            .position(|window| window == b"tfdt")
            .unwrap();
        segment[tfdt + 8..tfdt + 16].copy_from_slice(&1_024u64.to_be_bytes());
        segment
    });
    load(&root, &[("video", "video/mp4", "avc1.640028", 2)])
        .expect("a part at the rule is accepted");
    let (_temp, root) = prepared_root_for_test(&[(DASH_VIDEO, 2)]);
    write_private_file(&root.join("prepared/video/segments/00000001.m4s"), &{
        let mut segment = video_segment_of_len(RULE + 1);
        let tfdt = segment
            .windows(4)
            .position(|window| window == b"tfdt")
            .unwrap();
        segment[tfdt + 8..tfdt + 16].copy_from_slice(&1_024u64.to_be_bytes());
        segment
    });
    invalid(
        load(&root, &[("video", "video/mp4", "avc1.640028", 2)]),
        "a part one byte over the rule",
    );
}

#[cfg(unix)]
#[tokio::test]
async fn prepared_v2_resume_gives_the_same_receipt_and_refuses_changed_files() {
    let temp = tempfile::tempdir().unwrap();
    let (data_dir, staging_root) = setup_media_preparation_root(temp.path());
    let input = media_preparation_source_input(temp.path(), "person:local:media-v2-resume");
    let provider = Arc::new(TestMediaPreparationProvider {
        staging_root: staging_root.clone(),
        requests: Mutex::new(Vec::new()),
        response: TestMediaPreparationResponse::prepared_video_audio(),
    });
    let registry = Arc::new(ProviderRegistry::new());
    registry
        .register_runtime_provider_target(MEDIA_PROVIDER_ID, provider.clone())
        .await
        .unwrap();
    let RuntimeLibraryMediaPreparation::Prepared(first) =
        prepare_runtime_custody_library_source(&data_dir, registry.as_ref(), &input)
            .await
            .unwrap()
    else {
        panic!("expected a prepared media");
    };
    let RuntimeLibraryMediaPreparation::Prepared(second) =
        prepare_runtime_custody_library_source(&data_dir, registry.as_ref(), &input)
            .await
            .unwrap()
    else {
        panic!("expected the same prepared media");
    };
    assert_eq!(first.output_receipt_digest, second.output_receipt_digest);
    assert_eq!(
        first.input.media.preparation_receipt(),
        second.input.media.preparation_receipt()
    );
    assert_eq!(
        first.output_receipt_digest,
        independent_preparation_receipt(&[(DASH_VIDEO, 2), (DASH_AUDIO, 2)])
    );
    assert_eq!(provider.requests.lock().await.len(), 1);

    // One byte of a settled part changed on disk: refused, never redispatched.
    let operation_id = provider.requests.lock().await[0].clone();
    let part = staging_root
        .join(operation_id)
        .join("prepared/audio/segments/00000001.m4s");
    let mut bytes = fs::read(&part).unwrap();
    *bytes.last_mut().unwrap() ^= 0x01;
    write_private_file(&part, &bytes);
    let error = prepare_runtime_custody_library_source(&data_dir, registry.as_ref(), &input)
        .await
        .expect_err("a changed part must be refused");
    assert_eq!(
        attempt_conflict_reason(&error),
        RuntimeCustodyAttemptConflictReason::SourceChanged,
        "{error}"
    );
    assert_eq!(provider.requests.lock().await.len(), 1);
}

#[cfg(unix)]
#[tokio::test]
async fn prepared_v2_resume_refuses_a_v1_shaped_output_until_the_attempt_is_set_aside() {
    let temp = tempfile::tempdir().unwrap();
    let (data_dir, staging_root) = setup_media_preparation_root(temp.path());
    let input = media_preparation_source_input(temp.path(), "person:local:media-v1-upgrade");
    let provider = Arc::new(TestMediaPreparationProvider {
        staging_root: staging_root.clone(),
        requests: Mutex::new(Vec::new()),
        response: TestMediaPreparationResponse::prepared_video_audio(),
    });
    let registry = Arc::new(ProviderRegistry::new());
    registry
        .register_runtime_provider_target(MEDIA_PROVIDER_ID, provider.clone())
        .await
        .unwrap();
    prepare_runtime_custody_library_source(&data_dir, registry.as_ref(), &input)
        .await
        .unwrap();
    // What the v1 writer left behind: one rendition directly in prepared/.
    let operation_root = staging_root.join(provider.requests.lock().await[0].clone());
    fs::remove_dir_all(operation_root.join("prepared")).unwrap();
    owner_only_dir(&operation_root.join("prepared/segments"));
    write_private_file(&operation_root.join("prepared/init.mp4"), b"v1 init");
    write_private_file(
        &operation_root.join("prepared/segments/00000000.m4s"),
        b"v1 segment",
    );

    // Refused every time, never redispatched: a Prepared record cannot move to
    // Failed, so the way out is the creator's existing set-aside.
    for _ in 0..2 {
        let error = prepare_runtime_custody_library_source(&data_dir, registry.as_ref(), &input)
            .await
            .expect_err("a v1-shaped output cannot be a v2 package");
        // Answered as data, so Creator offers Start over.
        assert_eq!(
            attempt_conflict_reason(&error),
            RuntimeCustodyAttemptConflictReason::AuthorityChanged,
            "{error}"
        );
    }
    assert_eq!(provider.requests.lock().await.len(), 1);

    start_over_for_test(
        &data_dir,
        &input.principal_id,
        &input.object_uri,
        &input.source_storage,
    );
    let RuntimeLibraryMediaPreparation::Prepared(fresh) =
        prepare_runtime_custody_library_source(&data_dir, registry.as_ref(), &input)
            .await
            .unwrap()
    else {
        panic!("expected a v2 preparation");
    };
    assert_eq!(fresh.input.media.renditions.len(), 2);
    assert_eq!(provider.requests.lock().await.len(), 2);
}

#[cfg(unix)]
#[tokio::test]
async fn dash_publish_twin_verifies_every_published_file_and_binds_the_head_root() {
    let components = media_dash_components(&[DASH_VIDEO, DASH_AUDIO], &[3, 3]);
    let requirement_for = |provider: &Arc<ContentAvailabilityTestProvider>| {
        availability_requirement(provider.signer_did())
    };
    // A good publish: the evidence carries the v2 head's root.
    let provider =
        ContentAvailabilityTestProvider::new(0x61, ContentAvailabilityTestConfig::accepted());
    let registry = ProviderRegistry::new();
    registry
        .register_sub_provider("content", provider.clone())
        .await
        .unwrap();
    let directory = stage_dash_package(&components, b"<MPD/>");
    let evidence = super::super::publish_and_verify_protected_content_dash_availability(
        &registry,
        directory.path(),
        &components.head,
        &requirement_for(&provider),
        || NOW,
    )
    .await
    .expect("a good package publishes");
    assert_eq!(
        evidence.content_identity_root(),
        elastos_protected_content_runtime::RuntimeVerifiedContentIdentityRootV1::for_media_dash(
            &components.head
        )
    );
    assert_eq!(
        evidence.encrypted_content(),
        components.head.encrypted_content()
    );

    // A published segment that changed after publish fails its file check.
    let tampered = ContentAvailabilityTestProvider::new(
        0x61,
        ContentAvailabilityTestConfig {
            mutate_fetch_path: Some(dash_segment_file(DASH_AUDIO, 2)),
            ..ContentAvailabilityTestConfig::accepted()
        },
    );
    let registry = ProviderRegistry::new();
    registry
        .register_sub_provider("content", tampered.clone())
        .await
        .unwrap();
    assert!(
        super::super::publish_and_verify_protected_content_dash_availability(
            &registry,
            directory.path(),
            &components.head,
            &requirement_for(&tampered),
            || NOW,
        )
        .await
        .is_err(),
        "a changed published segment"
    );

    // A staging directory that does not match its head is refused before the
    // content plane sees anything.
    let wrong =
        ContentAvailabilityTestProvider::new(0x61, ContentAvailabilityTestConfig::accepted());
    let registry = ProviderRegistry::new();
    registry
        .register_sub_provider("content", wrong.clone())
        .await
        .unwrap();
    let extra = stage_dash_package(&components, b"<MPD/>");
    fs::write(extra.path().join("protected-content/v2/extra.bin"), b"x").unwrap();
    assert!(
        super::super::publish_and_verify_protected_content_dash_availability(
            &registry,
            extra.path(),
            &components.head,
            &requirement_for(&wrong),
            || NOW,
        )
        .await
        .is_err()
    );
    assert!(wrong.requests().await.is_empty());
}
