use super::*;

#[tokio::test]
async fn protected_content_publish_sends_exact_three_replica_live_requirement() {
    let (directory, media) = protected_content_directory(0x41);
    let provider =
        ContentAvailabilityTestProvider::new(0x61, ContentAvailabilityTestConfig::accepted());
    let requirement = availability_requirement(provider.signer_did());
    let registry = ProviderRegistry::new();
    registry
        .register_sub_provider("content", provider.clone())
        .await
        .unwrap();

    super::super::publish_and_verify_protected_content_availability(
        &registry,
        directory.path(),
        &media,
        &requirement,
        || NOW,
    )
    .await
    .unwrap();

    let requests = provider.requests().await;
    let publish = requests
        .iter()
        .find(|request| request.get("op").and_then(Value::as_str) == Some("publish"))
        .unwrap();
    assert_eq!(
        publish.get("availability_requirements"),
        Some(&json!({
            "min_replicas": 3,
            "require_live_multi_peer_proof": true,
        }))
    );
    assert!(publish["availability_requirements"]
        .get("max_replicas")
        .is_none());
}

#[tokio::test]
async fn protected_content_publish_rejects_mismatched_policy_or_count_before_provider_use() {
    for (policy, minimum_replicas) in [("wrong-policy", 3), ("protected-content-replication/v1", 2)]
    {
        let (directory, media) = protected_content_directory(0x41);
        let provider =
            ContentAvailabilityTestProvider::new(0x61, ContentAvailabilityTestConfig::accepted());
        let requirement = RuntimeContentAvailabilityRequirement::new(
            provider.signer_did(),
            "did:key:z6Mkhq7f4c4QAEgwRByrEsmGu3RJRYvpP5UGcWvqBjGW4YRe#content",
            "did:key:z6Mkhq7f4c4QAEgwRByrEsmGu3RJRYvpP5UGcWvqBjGW4YRe#publisher",
            policy,
            minimum_replicas,
            60,
            5,
        )
        .unwrap();
        let registry = ProviderRegistry::new();
        registry
            .register_sub_provider("content", provider.clone())
            .await
            .unwrap();

        super::super::publish_and_verify_protected_content_availability(
            &registry,
            directory.path(),
            &media,
            &requirement,
            || NOW,
        )
        .await
        .expect_err("mismatched protected availability requirement must fail closed");

        assert!(provider.requests().await.is_empty());
    }
}

#[cfg(unix)]
#[tokio::test]
async fn runtime_media_preparation_reuses_exact_settled_output_and_rejects_source_changes() {
    let temp = tempfile::tempdir().unwrap();
    let (data_dir, staging_root) = setup_media_preparation_root(temp.path());
    let input = media_preparation_source_input(temp.path(), "person:local:media-retry");
    let provider = Arc::new(TestMediaPreparationProvider {
        staging_root: staging_root.clone(),
        requests: Mutex::new(Vec::new()),
        response: TestMediaPreparationResponse::Prepared,
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
            .join("prepared/segments/00000001.m4s"),
    )
    .unwrap();
    let corrupt = prepare_runtime_custody_library_source(&data_dir, registry.as_ref(), &input)
        .await
        .expect_err("corrupt settled output must fail closed without redispatch");
    assert!(corrupt.to_string().contains("output is invalid"));
    assert_eq!(provider.requests.lock().await.len(), 1);

    fs::write(&input.source_file_path, b"changed source media").unwrap();
    let error = prepare_runtime_custody_library_source(&data_dir, registry.as_ref(), &input)
        .await
        .expect_err("changed source must conflict with durable authority");
    assert!(error
        .to_string()
        .contains("conflicts with existing authority"));
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
    let (clear_init_segment, clear_segments) = clear_media_components(0x41);
    let error = publish_runtime_custody_library_object(
        &data_dir,
        Arc::new(ProviderRegistry::new()),
        RuntimeCustodyLibraryPublishInput {
            object_uri: "localhost://Users/test/Documents/media".to_string(),
            principal_id: "person:local:runtime-custody-missing-composition".to_string(),
            mime_type: MEDIA_MIME_TYPE_V1.to_string(),
            codecs: MEDIA_CODECS_V1.to_string(),
            wallet_account_id: "wallet-account-1".to_string(),
            wallet_account_address: "0x1111111111111111111111111111111111111111".to_string(),
            creator_mint_source_digest: digest(0x71),
            copies: "0x1".to_string(),
            price: "0x5".to_string(),
            clear_init_segment,
            clear_segments,
            source_storage: "plain_localhost_root".to_string(),
        },
    )
    .await
    .expect_err("missing composition must fail closed");
    assert_eq!(
        error.to_string(),
        RUNTIME_CUSTODY_COMPOSITION_MISSING_MESSAGE
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
    let input = library_publish_test_input("person:local:runtime-custody-missing-protect");
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
    let input = library_publish_test_input("person:local:runtime-custody-missing-policy");
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
        library_publish_test_input("person:local:runtime-custody-missing-policy"),
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
    let input = library_publish_test_input("person:local:runtime-custody-lost-completion-mark");
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
        library_publish_test_input("person:local:runtime-custody-lost-completion-mark"),
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
    let input = pre_dispatch_retry_publish_input();
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
        pre_dispatch_retry_publish_input(),
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
        object_uri: retry_object_uri.clone(),
        principal_id: retry_principal.to_string(),
        source_file_path: source_file_path.clone(),
        wallet_account_id: "wallet-account-1".to_string(),
        wallet_account_address: "0x1111111111111111111111111111111111111111".to_string(),
        creator_mint_source_digest: digest(0x71),
        copies: "0x1".to_string(),
        price: "0x5".to_string(),
        source_storage: "plain_localhost_root".to_string(),
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
    assert!(source_replay_input.clear_init_segment.is_empty());
    assert!(source_replay_input.clear_segments.is_empty());

    let replay = publish_runtime_custody_library_object(
        &data_dir,
        registry,
        pre_dispatch_retry_publish_input(),
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
    let input = library_publish_test_input("person:local:runtime-custody-creator-account-switch");
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
    let second = publish_runtime_custody_library_object(&data_dir, registry, switched)
        .await
        .expect_err("creator account drift must fail closed");
    assert!(
        second
            .to_string()
            .contains("Runtime custody mint intent conflicts with existing authority"),
        "{second}"
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
    let input = library_publish_test_input("person:local:runtime-custody-source-drift");
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

    let mut drifted = input;
    drifted.creator_mint_source_digest = digest(0x72);
    let second = publish_runtime_custody_library_object(&data_dir, registry, drifted)
        .await
        .expect_err("creator source drift must fail closed");
    assert!(
        second
            .to_string()
            .contains("Runtime custody mint intent conflicts with existing authority"),
        "{second}"
    );

    let reloaded = runtime_mint_journal(&data_dir)
        .load_intent(request_id)
        .unwrap();
    assert_eq!(reloaded.protect_state_label(), "open_request_pending");
    let requests = protect.requests().await;
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0]["op"], "open_protection_session");
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
                ProtectProviderResponseV1::new_opened(handle, b"placeholder-protected-init")
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
    let input = library_publish_test_input("person:local:runtime-custody-cancel-settlement");
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
        library_publish_test_input("person:local:runtime-custody-cancel-settlement"),
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
        response: TestMediaPreparationResponse::Prepared,
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
