use super::*;

#[cfg(unix)]
#[test]
fn profile_authorized_runtime_release_assembly_is_exact_and_side_effect_free() {
    let directory = tempfile::tempdir().unwrap();
    let principal_id = "person:local:protected-content-release";
    let (proof_binding_id, localhost_root, profile) =
        install_profile_authority_for_release_test(directory.path(), principal_id);
    let input = release_operation_assembly_input(profile);
    let profile_path = crate::collaboration_profile_authority::profile_authority_path(
        directory.path(),
        &localhost_root,
    )
    .unwrap();
    let profile_before = fs::read(&profile_path).unwrap();
    let profile_bundle = crate::auth::read_principal_root_object(
        directory.path(),
        principal_id,
        &localhost_root,
        &crate::collaboration_profile_authority::profile_authority_object_uri(&localhost_root),
        &profile_path,
    )
    .unwrap();
    let profile_signing_seed_hex = serde_json::from_slice::<Value>(&profile_bundle)
        .unwrap()
        .get("profile_signing_seed_hex")
        .and_then(Value::as_str)
        .unwrap()
        .to_owned();
    let device_before = fs::read(directory.path().join("identity/device.key")).unwrap();

    let operation = super::super::assemble_protected_content_runtime_release_operation(
        directory.path(),
        principal_id,
        &localhost_root,
        &proof_binding_id,
        input.clone(),
        NOW + 3,
    )
    .unwrap();
    let (device_key, _) = elastos_identity::derive_did(&[0x42; 32]);
    let expected_issuer =
        RuntimeOperationIssuerKeyV1::new(device_key.verifying_key().to_bytes()).unwrap();
    assert_eq!(
        operation.statement().runtime_operation_issuer(),
        expected_issuer
    );
    let verified = operation.verify(expected_issuer, NOW + 3);
    assert!(verified.is_ok(), "{verified:?}");
    let duplicate = super::super::assemble_protected_content_runtime_release_operation(
        directory.path(),
        principal_id,
        &localhost_root,
        &proof_binding_id,
        input,
        NOW + 3,
    )
    .unwrap();
    assert_eq!(
        operation.canonical_bytes().unwrap(),
        duplicate.canonical_bytes().unwrap()
    );
    assert_eq!(profile_before, fs::read(profile_path).unwrap());
    assert_eq!(
        device_before,
        fs::read(directory.path().join("identity/device.key")).unwrap()
    );
    assert!(!directory
        .path()
        .join("protected-content/runtime-release")
        .exists());
    let debug = format!("{operation:?}");
    assert!(!debug.contains("profile_signing_seed_hex"));
    assert!(!debug.contains(&profile_signing_seed_hex));
    assert!(!operation
        .canonical_bytes()
        .unwrap()
        .windows(profile_signing_seed_hex.len())
        .any(|window| window == profile_signing_seed_hex.as_bytes()));
    assert!(!debug.contains(&hex::encode([0x42; 32])));

    assert!(
        super::super::assemble_protected_content_runtime_release_operation(
            directory.path(),
            principal_id,
            &localhost_root,
            "proof:passkey:missing-protected-content-release",
            release_operation_assembly_input(profile),
            NOW + 3,
        )
        .is_err()
    );

    let foreign_proof = store_profile_signing_passkey(
        directory.path(),
        "person:local:foreign-protected-content-release",
        "credential-foreign-protected-content",
    );
    assert!(
        super::super::assemble_protected_content_runtime_release_operation(
            directory.path(),
            principal_id,
            &localhost_root,
            &foreign_proof,
            release_operation_assembly_input(profile),
            NOW + 3,
        )
        .is_err()
    );
    crate::auth::revoke_passkey_binding(directory.path(), &proof_binding_id, NOW + 4).unwrap();
    assert!(
        super::super::assemble_protected_content_runtime_release_operation(
            directory.path(),
            principal_id,
            &localhost_root,
            &proof_binding_id,
            release_operation_assembly_input(profile),
            NOW + 4,
        )
        .is_err()
    );
}

#[cfg(unix)]
#[test]
fn profile_authorized_runtime_release_assembly_fails_without_required_authority() {
    let unprotected = tempfile::tempdir().unwrap();
    let unprotected_principal = "person:local:unprotected-profile-release";
    owner_only_dir(unprotected.path());
    write_device_key(unprotected.path(), 0x42);
    let unprotected_proof = store_profile_signing_passkey(
        unprotected.path(),
        unprotected_principal,
        "credential-unprotected-profile",
    );
    let other_profile = ProfileIdentityV1::from_public_key_bytes(
        SigningKey::from_bytes(&[0x26; 32])
            .verifying_key()
            .to_bytes(),
    )
    .unwrap();
    let error = super::super::assemble_protected_content_runtime_release_operation(
        unprotected.path(),
        unprotected_principal,
        &crate::auth::principal_localhost_root(unprotected_principal),
        &unprotected_proof,
        release_operation_assembly_input(other_profile),
        NOW + 3,
    )
    .unwrap_err();
    assert!(error
        .to_string()
        .contains("protected principal root is required"));

    let missing_profile = tempfile::tempdir().unwrap();
    let missing_profile_principal = "person:local:missing-profile-release";
    owner_only_dir(missing_profile.path());
    write_device_key(missing_profile.path(), 0x42);
    let missing_profile_proof = store_profile_signing_passkey(
        missing_profile.path(),
        missing_profile_principal,
        "credential-missing-profile",
    );
    crate::auth::store_test_principal_root_protection(
        missing_profile.path(),
        missing_profile_principal,
    );
    assert!(
        super::super::assemble_protected_content_runtime_release_operation(
            missing_profile.path(),
            missing_profile_principal,
            &crate::auth::principal_localhost_root(missing_profile_principal),
            &missing_profile_proof,
            release_operation_assembly_input(other_profile),
            NOW + 3,
        )
        .is_err()
    );

    let missing_device = tempfile::tempdir().unwrap();
    let missing_device_principal = "person:local:missing-device-release";
    let (proof_binding_id, localhost_root, profile) =
        install_profile_authority_for_release_test(missing_device.path(), missing_device_principal);
    fs::remove_file(missing_device.path().join("identity/device.key")).unwrap();
    assert!(
        super::super::assemble_protected_content_runtime_release_operation(
            missing_device.path(),
            missing_device_principal,
            &localhost_root,
            &proof_binding_id,
            release_operation_assembly_input(profile),
            NOW + 3,
        )
        .is_err()
    );

    let mismatch = tempfile::tempdir().unwrap();
    let mismatch_principal = "person:local:mismatched-profile-release";
    let (proof_binding_id, localhost_root, _) =
        install_profile_authority_for_release_test(mismatch.path(), mismatch_principal);
    assert!(
        super::super::assemble_protected_content_runtime_release_operation(
            mismatch.path(),
            mismatch_principal,
            &localhost_root,
            &proof_binding_id,
            release_operation_assembly_input(other_profile),
            NOW + 3,
        )
        .is_err()
    );
}

#[cfg(unix)]
#[test]
fn runtime_custody_viewer_record_load_rejects_oversized_serialized_state() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    let viewer_path = super::super::runtime_viewer_path(
        &data_dir,
        "person:local:oversized-viewer-record",
        digest(0x61),
    );
    write_owner_only_bytes(&viewer_path, &vec![b'x'; (64 * 1024) + 1]).unwrap();

    let error = super::super::load_runtime_custody_viewer_record(
        &data_dir,
        "person:local:oversized-viewer-record",
        digest(0x61),
    )
    .err()
    .expect("expected oversized viewer record rejection");
    assert!(error
        .to_string()
        .contains("Runtime custody viewer session is unavailable"));
}

#[cfg(unix)]
#[test]
fn runtime_custody_viewer_record_persist_rejects_oversized_serialized_state() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    let mut record = super::super::RuntimeCustodyViewerRecord::from_active_session(
        "person:local:oversized-viewer-record",
        "did:key:z6MkoD3Yk6TBGj1jiL1pDkV8JrjT4bQmQGq7nD5x7WQy3mYQ",
        digest(0x62),
        "content:1234",
        RuntimeSessionBindingV1::new(digest(0x63)).unwrap(),
        &RuntimeViewerSession::from_persisted_parts(
            digest(0x64),
            opaque_handle(0x65),
            media_identity(0x66).encrypted_content().clone(),
            RightsActionV1::View,
            crate::auth::now_ts() + 60,
        )
        .unwrap(),
        crate::auth::now_ts(),
    )
    .unwrap();
    record.content_id = format!("content:{}", "a".repeat((64 * 1024) + 1));

    let error = super::super::persist_runtime_custody_viewer_record(
        &data_dir,
        "person:local:oversized-viewer-record",
        digest(0x62),
        &record,
    )
    .expect_err("expected oversized viewer record rejection");
    assert!(error
        .to_string()
        .contains("Runtime custody viewer session is unavailable"));
}

#[tokio::test]
async fn decrypt_registry_adapter_dispatches_prepare_recipient_exactly_once() {
    let registry = Arc::new(ProviderRegistry::new());
    let decrypt = RecordingProvider::new(
        "decrypt",
        ok_provider_response(
            serde_json::to_value(
                DecryptProviderResponseV1::new_prepared_recipient(
                    RuntimeReleaseAuditIdV1::new(digest(0x91)).unwrap(),
                    opaque_handle(0x21),
                    recipient_public_key(0x30),
                    &recipient_identity(0x30),
                )
                .unwrap(),
            )
            .unwrap(),
        ),
    );
    let drm = RecordingProvider::new("drm", json!({"status": "ok", "data": {"echo": "drm"}}));
    registry
        .register_runtime_provider_target(PROTECTED_CONTENT_DECRYPT_PROVIDER_ID, decrypt.clone())
        .await
        .unwrap();
    registry
        .register_sub_provider("drm", drm.clone())
        .await
        .unwrap();
    let adapter = RuntimeDecryptRegistryAdapter::new(registry.clone());
    let request = decrypt_prepare_request();
    let expected_request = serde_json::to_value(&request).unwrap();

    let response = RuntimeDecryptProvider::prepare_recipient(&adapter, &request)
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        DecryptProviderResponseStatusV1::PreparedRecipient
    );
    assert_eq!(
        response.audit_request_id().unwrap(),
        RuntimeReleaseAuditIdV1::new(digest(0x91)).unwrap()
    );
    let requests = decrypt.requests().await;
    assert_eq!(requests.len(), 1);
    assert_exact_runtime_decrypt_invocation(&requests[0], "prepare_recipient", &expected_request);
    assert!(drm.requests().await.is_empty());
}

#[tokio::test]
async fn decrypt_registry_adapter_dispatches_open_viewer_session_exactly_once() {
    let registry = Arc::new(ProviderRegistry::new());
    let (request, audit_id, handle, _init_segment, _segments) = decrypt_open_fixture();
    let decrypt = RecordingProvider::new(
        "decrypt",
        ok_provider_response(
            serde_json::to_value(
                DecryptProviderResponseV1::new_viewer_session_opened(audit_id, handle).unwrap(),
            )
            .unwrap(),
        ),
    );
    let key = RecordingProvider::new("key", json!({"status": "ok", "data": {"echo": "key"}}));
    registry
        .register_runtime_provider_target(PROTECTED_CONTENT_DECRYPT_PROVIDER_ID, decrypt.clone())
        .await
        .unwrap();
    registry
        .register_sub_provider("key", key.clone())
        .await
        .unwrap();
    let adapter = RuntimeDecryptRegistryAdapter::new(registry.clone());
    let expected_request = serde_json::to_value(&request).unwrap();

    let response = RuntimeDecryptProvider::open_viewer_session(&adapter, &request)
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        DecryptProviderResponseStatusV1::ViewerSessionOpened
    );
    assert_eq!(response.audit_request_id().unwrap(), audit_id);
    assert_eq!(response.viewer_session_handle().unwrap(), &handle);
    let requests = decrypt.requests().await;
    assert_eq!(requests.len(), 1);
    assert_exact_runtime_decrypt_invocation(&requests[0], "open_viewer_session", &expected_request);
    assert!(key.requests().await.is_empty());
}

#[tokio::test]
async fn decrypt_registry_adapter_dispatches_read_cancel_and_close_exactly_once() {
    let registry = Arc::new(ProviderRegistry::new());
    let (_open_request, audit_id, handle, _init_segment, encrypted_segments) =
        decrypt_open_fixture();
    let read_request = DecryptProviderRequestV1::new_read_viewer_media_part(
        audit_id,
        handle,
        ViewerMediaPartSelectorV1::segment(1, encrypted_segments[1].clone()).unwrap(),
    )
    .unwrap();
    let cancel_request =
        DecryptProviderRequestV1::new_cancel_prepared_recipient(audit_id, handle).unwrap();
    let close_request =
        DecryptProviderRequestV1::new_close_viewer_session(audit_id, handle).unwrap();
    let adapter = RuntimeDecryptRegistryAdapter::new(registry.clone());

    let read_provider = RecordingProvider::new(
        "decrypt",
        ok_provider_response(
            serde_json::to_value(
                DecryptProviderResponseV1::new_viewer_media_part(
                    audit_id,
                    handle,
                    ViewerMediaPartSelectorV1::segment(1, encrypted_segments[1].clone()).unwrap(),
                    vec![0x10, 0x11, 0x12],
                )
                .unwrap(),
            )
            .unwrap(),
        ),
    );
    registry
        .register_runtime_provider_target(
            PROTECTED_CONTENT_DECRYPT_PROVIDER_ID,
            read_provider.clone(),
        )
        .await
        .unwrap();
    let read_expected = serde_json::to_value(&read_request).unwrap();
    let read_response = RuntimeDecryptProvider::read_viewer_media_part(&adapter, &read_request)
        .await
        .unwrap();
    assert_eq!(
        read_response.status(),
        DecryptProviderResponseStatusV1::ViewerMediaPart
    );
    assert_eq!(read_provider.requests().await.len(), 1);
    assert_exact_runtime_decrypt_invocation(
        &read_provider.requests().await[0],
        "read_viewer_media_part",
        &read_expected,
    );
    registry
        .unregister_runtime_provider_target(PROTECTED_CONTENT_DECRYPT_PROVIDER_ID)
        .await
        .unwrap();

    let cancel_provider = RecordingProvider::new(
        "decrypt",
        ok_provider_response(
            serde_json::to_value(
                DecryptProviderResponseV1::new_cancelled_prepared_recipient(audit_id, handle)
                    .unwrap(),
            )
            .unwrap(),
        ),
    );
    registry
        .register_runtime_provider_target(
            PROTECTED_CONTENT_DECRYPT_PROVIDER_ID,
            cancel_provider.clone(),
        )
        .await
        .unwrap();
    let cancel_expected = serde_json::to_value(&cancel_request).unwrap();
    let cancel_response =
        RuntimeDecryptProvider::cancel_prepared_recipient(&adapter, &cancel_request)
            .await
            .unwrap();
    assert_eq!(
        cancel_response.status(),
        DecryptProviderResponseStatusV1::CancelledPreparedRecipient
    );
    assert_exact_runtime_decrypt_invocation(
        &cancel_provider.requests().await[0],
        "cancel_prepared_recipient",
        &cancel_expected,
    );
    registry
        .unregister_runtime_provider_target(PROTECTED_CONTENT_DECRYPT_PROVIDER_ID)
        .await
        .unwrap();

    let close_provider = RecordingProvider::new(
        "decrypt",
        ok_provider_response(
            serde_json::to_value(
                DecryptProviderResponseV1::new_closed_viewer_session(audit_id, handle).unwrap(),
            )
            .unwrap(),
        ),
    );
    registry
        .register_runtime_provider_target(
            PROTECTED_CONTENT_DECRYPT_PROVIDER_ID,
            close_provider.clone(),
        )
        .await
        .unwrap();
    let close_expected = serde_json::to_value(&close_request).unwrap();
    let close_response = RuntimeDecryptProvider::close_viewer_session(&adapter, &close_request)
        .await
        .unwrap();
    assert_eq!(
        close_response.status(),
        DecryptProviderResponseStatusV1::ClosedViewerSession
    );
    assert_exact_runtime_decrypt_invocation(
        &close_provider.requests().await[0],
        "close_viewer_session",
        &close_expected,
    );
}

#[tokio::test]
async fn decrypt_registry_adapter_fails_closed_on_provider_status_and_data_errors() {
    let request = decrypt_prepare_request();

    for response in [
        json!({"status": "error", "code": "invalid_request"}),
        json!({"data": {}}),
        json!({"status": "weird", "data": {}}),
        json!({"status": "ok", "data": {"status": "prepared_recipient"}}),
    ] {
        let registry = Arc::new(ProviderRegistry::new());
        let decrypt = RecordingProvider::new("decrypt", response);
        registry
            .register_runtime_provider_target(PROTECTED_CONTENT_DECRYPT_PROVIDER_ID, decrypt)
            .await
            .unwrap();
        let adapter = RuntimeDecryptRegistryAdapter::new(registry);
        assert_eq!(
            RuntimeDecryptProvider::prepare_recipient(&adapter, &request).await,
            Err(RuntimeProviderCallError::NoExactResult)
        );
    }
}

#[tokio::test]
async fn decrypt_registry_adapter_fails_closed_without_registered_decrypt_provider() {
    let registry = Arc::new(ProviderRegistry::new());
    let provisional =
        RecordingProvider::new("drm", json!({"status": "ok", "data": {"echo": "drm"}}));
    registry
        .register_sub_provider("drm", provisional.clone())
        .await
        .unwrap();
    let adapter = RuntimeDecryptRegistryAdapter::new(registry);
    let request = decrypt_prepare_request();
    assert_eq!(
        RuntimeDecryptProvider::prepare_recipient(&adapter, &request).await,
        Err(RuntimeProviderCallError::NoExactResult)
    );
    assert!(provisional.requests().await.is_empty());
}

#[cfg(unix)]
#[tokio::test]
async fn runtime_custody_release_wallet_pends_on_managed_approval_and_resumes_exact_request() {
    let harness = runtime_custody_prebuy_availability_harness(
        0x61,
        ContentAvailabilityTestConfig::accepted(),
    )
    .await;
    let principal_id = "person:local:runtime-custody-managed-release";
    let mint = runtime_mint_journal(&harness.data_dir)
        .load(harness.mint_id)
        .unwrap();
    install_profile_authority_keeping_device_key(&harness.data_dir, principal_id);
    let current_profile_did = load_profile_did_for_test(&harness.data_dir, principal_id);
    let purchase = persist_runtime_custody_purchase_for_mint(
        &harness.data_dir,
        &mint,
        principal_id,
        &current_profile_did,
        crate::auth::now_ts(),
    );
    let buy = super::super::reconstructed_buy_receipt(
        mint.draft(),
        mint.content_availability().unwrap(),
        &purchase,
        &current_profile_did,
    )
    .unwrap();
    let wallet = Arc::new(ManagedReleaseWalletProvider::new());
    let registry = Arc::new(ProviderRegistry::new());
    registry
        .register_sub_provider("wallet", wallet.clone())
        .await
        .unwrap();
    let session = super::super::derive_runtime_custody_session_binding(
        principal_id,
        &current_profile_did,
        TEST_VIEWER_LAUNCH_ID,
        "proof:alpha",
        "runtime-session:alpha",
        "grant:alpha",
        mint.draft().mint_id(),
    )
    .unwrap();
    let invocation = || super::super::RuntimeReleaseWalletInvocation {
        principal_id,
        account_id: &purchase.account_id,
        proof_binding_id: "proof:alpha",
        session_id: "runtime-session:alpha",
        grant_id: "grant:alpha",
        mint_id: mint.draft().mint_id(),
        runtime_session_binding: session,
    };
    let now = crate::auth::now_ts();
    let recipient = recipient_identity(0x30);

    // First shot: the managed account holds the request as a pending approval.
    let (request_bytes, approval_request_id) = match super::super::invoke_runtime_release_wallet(
        registry.as_ref(),
        &buy,
        &recipient,
        invocation(),
        None,
        now,
    )
    .await
    .unwrap()
    {
        super::super::RuntimeReleaseWalletOutcome::PendingApproval {
            request_bytes,
            approval_request_id,
        } => (request_bytes, approval_request_id),
        super::super::RuntimeReleaseWalletOutcome::Signed { .. } => {
            panic!("expected pending approval")
        }
    };
    let decoded = WalletProviderRequestV2::decode_at(&request_bytes, now).unwrap();
    assert_eq!(approval_request_id, decoded.request_id);

    // Replaying the exact request before approval stays pending on the SAME
    // wallet request (no second approval is raised).
    match super::super::invoke_runtime_release_wallet(
        registry.as_ref(),
        &buy,
        &recipient,
        invocation(),
        Some(&request_bytes),
        now,
    )
    .await
    .unwrap()
    {
        super::super::RuntimeReleaseWalletOutcome::PendingApproval {
            request_bytes: replayed,
            approval_request_id: replayed_id,
        } => {
            assert_eq!(replayed, request_bytes);
            assert_eq!(replayed_id, approval_request_id);
        }
        super::super::RuntimeReleaseWalletOutcome::Signed { .. } => {
            panic!("expected pending approval")
        }
    }

    // A replay bound to a different recipient identity is refused: the
    // persisted request must belong to the prepared recipient being resumed.
    let foreign = super::super::invoke_runtime_release_wallet(
        registry.as_ref(),
        &buy,
        &recipient_identity(0x31),
        invocation(),
        Some(&request_bytes),
        now,
    )
    .await;
    assert_eq!(
        foreign.unwrap_err().to_string(),
        super::super::RUNTIME_CUSTODY_RELEASE_APPROVAL_UNAVAILABLE_MESSAGE
    );

    // Approved: the exact replay yields the signed rights for the SAME
    // request, decoded out of the Wallet's approval envelope.
    wallet.approve(&approval_request_id);
    let (signed_request_bytes, response_bytes, signed_rights) = signed_release_wallet_outcome(
        super::super::invoke_runtime_release_wallet(
            registry.as_ref(),
            &buy,
            &recipient,
            invocation(),
            Some(&request_bytes),
            now,
        )
        .await
        .unwrap(),
    );
    assert_eq!(signed_request_bytes, request_bytes);
    assert_eq!(signed_rights.request().recipient(), &recipient);
    assert_eq!(
        signed_rights.request().binding(),
        &buy.binding_for_session(session).unwrap()
    );
    super::super::wallet_signed_rights_from_bytes(&signed_request_bytes, &response_bytes).unwrap();
    assert_eq!(
        wallet.seen_request_ids(),
        vec![approval_request_id.clone(); 3],
        "every shot replayed the identical wallet request"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn runtime_custody_release_wallet_uses_fresh_binding_per_session() {
    let harness = runtime_custody_prebuy_availability_harness(
        0x61,
        ContentAvailabilityTestConfig::accepted(),
    )
    .await;
    let principal_id = "person:local:runtime-custody-profile-check";
    let mint = runtime_mint_journal(&harness.data_dir)
        .load(harness.mint_id)
        .unwrap();
    let (_proof_binding_id, _profile_identity) =
        install_profile_authority_keeping_device_key(&harness.data_dir, principal_id);
    let current_profile_did = load_profile_did_for_test(&harness.data_dir, principal_id);
    let purchase = persist_runtime_custody_purchase_for_mint(
        &harness.data_dir,
        &mint,
        principal_id,
        &current_profile_did,
        crate::auth::now_ts(),
    );
    let buy = super::super::reconstructed_buy_receipt(
        mint.draft(),
        mint.content_availability().unwrap(),
        &purchase,
        &current_profile_did,
    )
    .unwrap();
    let registry = Arc::new(ProviderRegistry::new());
    registry
        .register_sub_provider("wallet", Arc::new(LibraryReleaseWalletProvider))
        .await
        .unwrap();
    let session_a = super::super::derive_runtime_custody_session_binding(
        principal_id,
        &current_profile_did,
        TEST_VIEWER_LAUNCH_ID,
        "proof:alpha",
        "runtime-session:alpha",
        "grant:alpha",
        mint.draft().mint_id(),
    )
    .unwrap();
    let session_b = super::super::derive_runtime_custody_session_binding(
        principal_id,
        &current_profile_did,
        TEST_VIEWER_LAUNCH_ID,
        "proof:alpha",
        "runtime-session:beta",
        "grant:alpha",
        mint.draft().mint_id(),
    )
    .unwrap();
    let launch_b = super::super::derive_runtime_custody_session_binding(
        principal_id,
        &current_profile_did,
        TEST_VIEWER_LAUNCH_ID_B,
        "proof:alpha",
        "runtime-session:alpha",
        "grant:alpha",
        mint.draft().mint_id(),
    )
    .unwrap();
    assert_ne!(session_a, session_b);
    assert_ne!(session_a, launch_b);
    let now = crate::auth::now_ts();
    let (request_a, response_a, signed_a) = super::super::invoke_runtime_release_wallet(
        registry.as_ref(),
        &buy,
        &recipient_identity(0x30),
        super::super::RuntimeReleaseWalletInvocation {
            principal_id,
            account_id: &purchase.account_id,
            proof_binding_id: "proof:alpha",
            session_id: "runtime-session:alpha",
            grant_id: "grant:alpha",
            mint_id: mint.draft().mint_id(),
            runtime_session_binding: session_a,
        },
        None,
        now,
    )
    .await
    .map(signed_release_wallet_outcome)
    .unwrap();
    let expected_a = buy.binding_for_session(session_a).unwrap();
    assert_eq!(signed_a.request().binding(), &expected_a);
    let decoded_request_a = WalletProviderRequestV2::decode_at(&request_a, now).unwrap();
    WalletProviderResponseV2::decode_for_request(&response_a, &decoded_request_a).unwrap();
    let request_a_hex = match &decoded_request_a.operation {
        WalletProviderOperationV2::RequestProtectedContentRightsSignature {
            canonical_rights_request_hex,
            ..
        } => canonical_rights_request_hex.clone(),
        other => panic!("unexpected wallet request: {other:?}"),
    };
    let request_a_binding =
        RightsRequestV1::from_canonical_bytes(&hex::decode(request_a_hex).unwrap()).unwrap();
    assert_eq!(request_a_binding.binding(), &expected_a);

    let (request_b, _response_b, signed_b) = super::super::invoke_runtime_release_wallet(
        registry.as_ref(),
        &buy,
        &recipient_identity(0x30),
        super::super::RuntimeReleaseWalletInvocation {
            principal_id,
            account_id: &purchase.account_id,
            proof_binding_id: "proof:alpha",
            session_id: "runtime-session:beta",
            grant_id: "grant:alpha",
            mint_id: mint.draft().mint_id(),
            runtime_session_binding: session_b,
        },
        None,
        now,
    )
    .await
    .map(signed_release_wallet_outcome)
    .unwrap();
    let expected_b = buy.binding_for_session(session_b).unwrap();
    assert_eq!(signed_b.request().binding(), &expected_b);
    assert_ne!(expected_a, expected_b);
    let decoded_request_b = WalletProviderRequestV2::decode_at(&request_b, now).unwrap();
    let request_b_hex = match &decoded_request_b.operation {
        WalletProviderOperationV2::RequestProtectedContentRightsSignature {
            canonical_rights_request_hex,
            ..
        } => canonical_rights_request_hex.clone(),
        other => panic!("unexpected wallet request: {other:?}"),
    };
    let request_b_binding =
        RightsRequestV1::from_canonical_bytes(&hex::decode(request_b_hex).unwrap()).unwrap();
    assert_eq!(request_b_binding.binding(), &expected_b);
}

#[cfg(unix)]
#[tokio::test]
async fn runtime_custody_viewer_open_replays_exact_active_session_without_provider_effects() {
    let harness = runtime_custody_prebuy_availability_harness(
        0x61,
        ContentAvailabilityTestConfig::accepted(),
    )
    .await;
    let principal_id = "person:local:runtime-custody-viewer-replay";
    let (proof_binding_id, _) =
        install_profile_authority_keeping_device_key(&harness.data_dir, principal_id);
    let current_profile_did = load_profile_did_for_test(&harness.data_dir, principal_id);
    let mint = runtime_mint_journal(&harness.data_dir)
        .load(harness.mint_id)
        .unwrap();
    let purchase = persist_runtime_custody_purchase_for_mint(
        &harness.data_dir,
        &mint,
        principal_id,
        &current_profile_did,
        crate::auth::now_ts(),
    );
    let session = persist_runtime_custody_active_viewer_for_purchase(
        &harness.data_dir,
        &mint,
        &purchase,
        &proof_binding_id,
        "runtime-session:alpha",
        "grant:alpha",
        opaque_handle(0x21),
        crate::auth::now_ts() + 60,
    );
    make_runtime_custody_listing_imported_without_creator_mint(
        &harness.data_dir,
        mint.draft().mint_id(),
    );
    let open = super::super::open_runtime_custody_viewer(
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
    .unwrap();
    assert_eq!(
        open["viewer_session_handle"].as_str().unwrap(),
        hex::encode(session.viewer_session_handle())
    );
    assert_eq!(open["expires_at"].as_u64(), Some(session.expires_at()));
    assert_eq!(open["mime_type"], MEDIA_MIME_TYPE_V1);
    assert_eq!(open["codecs"], MEDIA_CODECS_V1);
    assert_eq!(open["has_init_segment"], true);
    assert_eq!(
        open["segment_count"].as_u64(),
        Some(u64::try_from(mint.draft().media_identity().encrypted_segments().len()).unwrap())
    );
    let open_keys = open
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        open_keys,
        std::collections::BTreeSet::from([
            "codecs",
            "expires_at",
            "has_init_segment",
            "mime_type",
            "mint_id",
            "schema",
            "segment_count",
            "viewer_session_handle",
        ])
    );
    assert!(harness.content_provider.requests().await.is_empty());
}

#[cfg(unix)]
#[tokio::test]
async fn runtime_custody_viewer_open_rejects_substituted_session_without_provider_effects() {
    let harness = runtime_custody_prebuy_availability_harness(
        0x61,
        ContentAvailabilityTestConfig::accepted(),
    )
    .await;
    let principal_id = "person:local:runtime-custody-viewer-replay";
    let (proof_binding_id, _) =
        install_profile_authority_keeping_device_key(&harness.data_dir, principal_id);
    let current_profile_did = load_profile_did_for_test(&harness.data_dir, principal_id);
    let mint = runtime_mint_journal(&harness.data_dir)
        .load(harness.mint_id)
        .unwrap();
    let purchase = persist_runtime_custody_purchase_for_mint(
        &harness.data_dir,
        &mint,
        principal_id,
        &current_profile_did,
        crate::auth::now_ts(),
    );
    persist_runtime_custody_active_viewer_for_purchase(
        &harness.data_dir,
        &mint,
        &purchase,
        &proof_binding_id,
        "runtime-session:alpha",
        "grant:alpha",
        opaque_handle(0x21),
        crate::auth::now_ts() + 60,
    );
    let err = super::super::open_runtime_custody_viewer(
        &harness.data_dir,
        harness.registry.clone(),
        super::super::RuntimeCustodyViewerOpenInput {
            principal_id: principal_id.to_string(),
            mint_id: hex::encode(harness.mint_id.as_bytes()),
            launch_id: Some(TEST_VIEWER_LAUNCH_ID.to_string()),
            proof_binding_id: Some(proof_binding_id),
            session_id: Some("runtime-session:beta".to_string()),
            grant_id: Some("grant:alpha".to_string()),
        },
    )
    .await
    .unwrap_err();
    assert!(err
        .to_string()
        .contains(RUNTIME_CUSTODY_OPEN_DENIED_MESSAGE));
    assert!(harness.content_provider.requests().await.is_empty());
}

#[cfg(unix)]
#[tokio::test]
async fn runtime_custody_viewer_open_rejects_missing_live_availability_before_new_effects() {
    let harness = runtime_custody_prebuy_availability_harness(
        0x61,
        ContentAvailabilityTestConfig {
            live_multi_peer_proof: None,
            ..ContentAvailabilityTestConfig::accepted_now()
        },
    )
    .await;
    let principal_id = "person:local:runtime-custody-viewer-missing-live-availability";
    write_device_key(&harness.data_dir, 0x21);
    let (_epoch, _composition_now) = write_library_publish_test_composition(&harness.data_dir);
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
    let decrypt = PrepareOnlyCleanupDecryptProvider::new();
    harness
        .registry
        .register_runtime_provider_target(PROTECTED_CONTENT_DECRYPT_PROVIDER_ID, decrypt.clone())
        .await
        .unwrap();
    let wallet = RecordingProvider::new("wallet", ok_provider_response(json!({})));
    harness
        .registry
        .register_sub_provider("wallet", wallet.clone())
        .await
        .unwrap();

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

    assert!(error
        .to_string()
        .contains("Runtime custody content availability is unavailable"));
    assert!(super::super::load_runtime_custody_viewer_record(
        &harness.data_dir,
        principal_id,
        mint.draft().mint_id(),
    )
    .unwrap()
    .is_none());
    assert!(decrypt.requests().await.is_empty());
    assert!(wallet.requests().await.is_empty());
    assert!(harness
        .content_provider
        .requests()
        .await
        .iter()
        .any(|request| request.get("op").and_then(Value::as_str) == Some("status")));
}

#[cfg(unix)]
#[tokio::test]
async fn runtime_custody_viewer_read_close_and_replay_settle_exactly() {
    let harness = runtime_custody_prebuy_availability_harness(
        0x61,
        ContentAvailabilityTestConfig::accepted(),
    )
    .await;
    let principal_id = "person:local:runtime-custody-viewer-read-close";
    let (proof_binding_id, _) =
        install_profile_authority_keeping_device_key(&harness.data_dir, principal_id);
    let current_profile_did = load_profile_did_for_test(&harness.data_dir, principal_id);
    let mint = runtime_mint_journal(&harness.data_dir)
        .load(harness.mint_id)
        .unwrap();
    let purchase = persist_runtime_custody_purchase_for_mint(
        &harness.data_dir,
        &mint,
        principal_id,
        &current_profile_did,
        crate::auth::now_ts(),
    );
    let session = persist_runtime_custody_active_viewer_for_purchase(
        &harness.data_dir,
        &mint,
        &purchase,
        &proof_binding_id,
        "runtime-session:alpha",
        "grant:alpha",
        opaque_handle(0x21),
        crate::auth::now_ts() + 60,
    );
    make_runtime_custody_listing_imported_without_creator_mint(
        &harness.data_dir,
        mint.draft().mint_id(),
    );
    let registry = Arc::new(ProviderRegistry::new());
    let read_request = DecryptProviderRequestV1::new_read_viewer_media_part(
        RuntimeReleaseAuditIdV1::new(session.audit_request_id()).unwrap(),
        *session.viewer_session_handle(),
        ViewerMediaPartSelectorV1::init(),
    )
    .unwrap();
    let read_provider = RecordingProvider::new(
        "decrypt",
        ok_provider_response(
            serde_json::to_value(
                DecryptProviderResponseV1::new_viewer_media_part(
                    RuntimeReleaseAuditIdV1::new(session.audit_request_id()).unwrap(),
                    *session.viewer_session_handle(),
                    ViewerMediaPartSelectorV1::init(),
                    vec![0x10, 0x11, 0x12],
                )
                .unwrap(),
            )
            .unwrap(),
        ),
    );
    registry
        .register_runtime_provider_target(
            PROTECTED_CONTENT_DECRYPT_PROVIDER_ID,
            read_provider.clone(),
        )
        .await
        .unwrap();
    let early_segment = super::super::read_runtime_custody_viewer(
        &harness.data_dir,
        registry.clone(),
        principal_id,
        &hex::encode(harness.mint_id.as_bytes()),
        &hex::encode(session.viewer_session_handle()),
        Some(TEST_VIEWER_LAUNCH_ID),
        Some(&proof_binding_id),
        Some("runtime-session:alpha"),
        Some("grant:alpha"),
        Some(0),
    )
    .await
    .unwrap_err();
    assert_eq!(
        early_segment.to_string(),
        "Runtime custody viewer media part is invalid"
    );
    assert!(read_provider.requests().await.is_empty());
    let read = super::super::read_runtime_custody_viewer(
        &harness.data_dir,
        registry.clone(),
        principal_id,
        &hex::encode(harness.mint_id.as_bytes()),
        &hex::encode(session.viewer_session_handle()),
        Some(TEST_VIEWER_LAUNCH_ID),
        Some(&proof_binding_id),
        Some("runtime-session:alpha"),
        Some("grant:alpha"),
        None,
    )
    .await
    .unwrap();
    assert_eq!(
        base64::engine::general_purpose::STANDARD
            .decode(read["data"].as_str().unwrap())
            .unwrap(),
        vec![0x10, 0x11, 0x12]
    );
    assert_eq!(read_provider.requests().await.len(), 1);
    assert_exact_runtime_decrypt_invocation(
        &read_provider.requests().await[0],
        "read_viewer_media_part",
        &serde_json::to_value(&read_request).unwrap(),
    );
    let repeated_init = super::super::read_runtime_custody_viewer(
        &harness.data_dir,
        registry.clone(),
        principal_id,
        &hex::encode(harness.mint_id.as_bytes()),
        &hex::encode(session.viewer_session_handle()),
        Some(TEST_VIEWER_LAUNCH_ID),
        Some(&proof_binding_id),
        Some("runtime-session:alpha"),
        Some("grant:alpha"),
        None,
    )
    .await
    .unwrap_err();
    assert_eq!(
        repeated_init.to_string(),
        "Runtime custody viewer media part is invalid"
    );
    assert_eq!(read_provider.requests().await.len(), 1);

    registry
        .unregister_runtime_provider_target(PROTECTED_CONTENT_DECRYPT_PROVIDER_ID)
        .await
        .unwrap();
    let close_provider = RecordingProvider::new(
        "decrypt",
        ok_provider_response(
            serde_json::to_value(
                DecryptProviderResponseV1::new_closed_viewer_session(
                    RuntimeReleaseAuditIdV1::new(session.audit_request_id()).unwrap(),
                    *session.viewer_session_handle(),
                )
                .unwrap(),
            )
            .unwrap(),
        ),
    );
    registry
        .register_runtime_provider_target(
            PROTECTED_CONTENT_DECRYPT_PROVIDER_ID,
            close_provider.clone(),
        )
        .await
        .unwrap();
    let close = super::super::close_runtime_custody_viewer(
        &harness.data_dir,
        registry.clone(),
        principal_id,
        &hex::encode(harness.mint_id.as_bytes()),
        &hex::encode(session.viewer_session_handle()),
        Some(TEST_VIEWER_LAUNCH_ID),
        Some(&proof_binding_id),
        Some("runtime-session:alpha"),
        Some("grant:alpha"),
    )
    .await
    .unwrap();
    assert_eq!(close["close_result"], "closed");
    let record = super::super::load_runtime_custody_viewer_record(
        &harness.data_dir,
        principal_id,
        mint.draft().mint_id(),
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        record.lifecycle_status,
        super::super::RuntimeCustodyViewerLifecycleStatus::Closed
    );
    let closed_record_bytes = fs::read(super::super::runtime_viewer_path(
        &harness.data_dir,
        principal_id,
        mint.draft().mint_id(),
    ))
    .unwrap();
    registry
        .unregister_runtime_provider_target(PROTECTED_CONTENT_DECRYPT_PROVIDER_ID)
        .await
        .unwrap();

    let replay = super::super::close_runtime_custody_viewer(
        &harness.data_dir,
        registry.clone(),
        principal_id,
        &hex::encode(harness.mint_id.as_bytes()),
        &hex::encode(session.viewer_session_handle()),
        Some(TEST_VIEWER_LAUNCH_ID),
        Some(&proof_binding_id),
        Some("runtime-session:alpha"),
        Some("grant:alpha"),
    )
    .await
    .unwrap();
    assert_eq!(replay["close_result"], "already_absent");
    let record_bytes = fs::read(super::super::runtime_viewer_path(
        &harness.data_dir,
        principal_id,
        mint.draft().mint_id(),
    ))
    .unwrap();
    assert_eq!(record_bytes, closed_record_bytes);
    let replay_record: super::super::RuntimeCustodyViewerRecord =
        serde_json::from_slice(&record_bytes).unwrap();
    assert_eq!(
        replay_record.lifecycle_status,
        super::super::RuntimeCustodyViewerLifecycleStatus::Closed
    );
    let record_json = String::from_utf8(record_bytes).unwrap();
    assert!(!record_json.contains("proof:alpha"));
    assert!(!record_json.contains("runtime-session:alpha"));
    assert!(!record_json.contains("grant:alpha"));
    assert!(!record_json.contains("http://"));
    assert!(!record_json.contains("encrypted_content_base64"));
    assert!(!record_json.contains("\"action\""));
    assert!(!record_json.contains("\"clear_media_part\""));
}

#[cfg(unix)]
#[tokio::test]
async fn runtime_custody_viewer_open_read_and_close_reject_wrong_principal_without_provider_effects(
) {
    let harness = runtime_custody_prebuy_availability_harness(
        0x61,
        ContentAvailabilityTestConfig::accepted(),
    )
    .await;
    let principal_id = "person:local:runtime-custody-viewer-close-owner";
    let wrong_principal_id = "person:local:runtime-custody-viewer-close-other";
    let (proof_binding_id, _) =
        install_profile_authority_keeping_device_key(&harness.data_dir, principal_id);
    let current_profile_did = load_profile_did_for_test(&harness.data_dir, principal_id);
    let mint = runtime_mint_journal(&harness.data_dir)
        .load(harness.mint_id)
        .unwrap();
    let purchase = persist_runtime_custody_purchase_for_mint(
        &harness.data_dir,
        &mint,
        principal_id,
        &current_profile_did,
        crate::auth::now_ts(),
    );
    let session = persist_runtime_custody_active_viewer_for_purchase(
        &harness.data_dir,
        &mint,
        &purchase,
        &proof_binding_id,
        "runtime-session:alpha",
        "grant:alpha",
        opaque_handle(0x29),
        crate::auth::now_ts() + 60,
    );
    make_runtime_custody_listing_imported_without_creator_mint(
        &harness.data_dir,
        mint.draft().mint_id(),
    );
    let record_path =
        super::super::runtime_viewer_path(&harness.data_dir, principal_id, mint.draft().mint_id());
    let before = fs::read(&record_path).unwrap();
    let registry = Arc::new(ProviderRegistry::new());
    let decrypt_provider = RecordingProvider::new(
        "decrypt",
        ok_provider_response(serde_json::json!({"schema":"unused"})),
    );
    registry
        .register_runtime_provider_target(
            PROTECTED_CONTENT_DECRYPT_PROVIDER_ID,
            decrypt_provider.clone(),
        )
        .await
        .unwrap();

    let open_error = super::super::open_runtime_custody_viewer(
        &harness.data_dir,
        registry.clone(),
        super::super::RuntimeCustodyViewerOpenInput {
            principal_id: wrong_principal_id.to_string(),
            mint_id: hex::encode(harness.mint_id.as_bytes()),
            launch_id: Some(TEST_VIEWER_LAUNCH_ID.to_string()),
            proof_binding_id: Some(proof_binding_id.clone()),
            session_id: Some("runtime-session:alpha".to_string()),
            grant_id: Some("grant:alpha".to_string()),
        },
    )
    .await
    .expect_err("expected wrong-principal open rejection");
    assert!(open_error
        .to_string()
        .contains(RUNTIME_CUSTODY_OPEN_DENIED_MESSAGE));

    let read_error = super::super::read_runtime_custody_viewer(
        &harness.data_dir,
        registry.clone(),
        wrong_principal_id,
        &hex::encode(harness.mint_id.as_bytes()),
        &hex::encode(session.viewer_session_handle()),
        Some(TEST_VIEWER_LAUNCH_ID),
        Some(&proof_binding_id),
        Some("runtime-session:alpha"),
        Some("grant:alpha"),
        None,
    )
    .await
    .expect_err("expected wrong-principal read rejection");
    assert!(read_error
        .to_string()
        .contains("Runtime custody viewer session is unavailable"));

    let error = super::super::close_runtime_custody_viewer(
        &harness.data_dir,
        registry,
        wrong_principal_id,
        &hex::encode(harness.mint_id.as_bytes()),
        &hex::encode(session.viewer_session_handle()),
        Some(TEST_VIEWER_LAUNCH_ID),
        Some(&proof_binding_id),
        Some("runtime-session:alpha"),
        Some("grant:alpha"),
    )
    .await
    .expect_err("expected wrong-principal close rejection");
    assert!(error
        .to_string()
        .contains("Runtime custody viewer session is unavailable"));
    assert!(decrypt_provider.requests().await.is_empty());
    assert_eq!(fs::read(&record_path).unwrap(), before);
}

#[cfg(unix)]
#[tokio::test]
async fn runtime_custody_viewer_close_retains_cleanup_pending_until_exact_settlement() {
    let harness = runtime_custody_prebuy_availability_harness(
        0x61,
        ContentAvailabilityTestConfig::accepted(),
    )
    .await;
    let principal_id = "person:local:runtime-custody-viewer-close-reconcile";
    let (proof_binding_id, _) =
        install_profile_authority_keeping_device_key(&harness.data_dir, principal_id);
    let current_profile_did = load_profile_did_for_test(&harness.data_dir, principal_id);
    let mint = runtime_mint_journal(&harness.data_dir)
        .load(harness.mint_id)
        .unwrap();
    let purchase = persist_runtime_custody_purchase_for_mint(
        &harness.data_dir,
        &mint,
        principal_id,
        &current_profile_did,
        crate::auth::now_ts(),
    );
    let session = persist_runtime_custody_active_viewer_for_purchase(
        &harness.data_dir,
        &mint,
        &purchase,
        &proof_binding_id,
        "runtime-session:alpha",
        "grant:alpha",
        opaque_handle(0x21),
        crate::auth::now_ts() + 60,
    );
    make_runtime_custody_listing_imported_without_creator_mint(
        &harness.data_dir,
        mint.draft().mint_id(),
    );
    let registry = Arc::new(ProviderRegistry::new());
    let close_request = DecryptProviderRequestV1::new_close_viewer_session(
        RuntimeReleaseAuditIdV1::new(session.audit_request_id()).unwrap(),
        *session.viewer_session_handle(),
    )
    .unwrap();
    let pending_provider = SequencedProvider::new(
        "decrypt",
        vec![Err(ProviderError::Provider("timeout".to_string()))],
    );
    registry
        .register_runtime_provider_target(
            PROTECTED_CONTENT_DECRYPT_PROVIDER_ID,
            pending_provider.clone(),
        )
        .await
        .unwrap();
    let err = super::super::close_runtime_custody_viewer(
        &harness.data_dir,
        registry.clone(),
        principal_id,
        &hex::encode(harness.mint_id.as_bytes()),
        &hex::encode(session.viewer_session_handle()),
        Some(TEST_VIEWER_LAUNCH_ID),
        Some(&proof_binding_id),
        Some("runtime-session:alpha"),
        Some("grant:alpha"),
    )
    .await
    .unwrap_err();
    assert!(err
        .to_string()
        .contains(RUNTIME_CUSTODY_DECRYPT_UNAVAILABLE_MESSAGE));
    let pending = super::super::load_runtime_custody_viewer_record(
        &harness.data_dir,
        principal_id,
        mint.draft().mint_id(),
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        pending.lifecycle_status,
        super::super::RuntimeCustodyViewerLifecycleStatus::CleanupPending
    );
    assert_eq!(pending_provider.requests().await.len(), 1);
    assert_exact_runtime_decrypt_invocation(
        &pending_provider.requests().await[0],
        "close_viewer_session",
        &serde_json::to_value(&close_request).unwrap(),
    );

    registry
        .unregister_runtime_provider_target(PROTECTED_CONTENT_DECRYPT_PROVIDER_ID)
        .await
        .unwrap();
    let absent_provider = RecordingProvider::new(
        "decrypt",
        ok_provider_response(
            serde_json::to_value(
                DecryptProviderResponseV1::new_viewer_session_already_absent(
                    RuntimeReleaseAuditIdV1::new(session.audit_request_id()).unwrap(),
                    *session.viewer_session_handle(),
                )
                .unwrap(),
            )
            .unwrap(),
        ),
    );
    registry
        .register_runtime_provider_target(
            PROTECTED_CONTENT_DECRYPT_PROVIDER_ID,
            absent_provider.clone(),
        )
        .await
        .unwrap();
    super::super::reconcile_runtime_custody_viewers_after_decrypt_registration(
        &harness.data_dir,
        registry.clone(),
    )
    .await
    .unwrap();
    let settled = super::super::load_runtime_custody_viewer_record(
        &harness.data_dir,
        principal_id,
        mint.draft().mint_id(),
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        settled.lifecycle_status,
        super::super::RuntimeCustodyViewerLifecycleStatus::AlreadyAbsent
    );
    assert_eq!(absent_provider.requests().await.len(), 1);
    assert_exact_runtime_decrypt_invocation(
        &absent_provider.requests().await[0],
        "close_viewer_session",
        &serde_json::to_value(&close_request).unwrap(),
    );
    assert!(!harness
        .data_dir
        .join(super::super::RUNTIME_MINT_JOURNAL_ROOT)
        .exists());
}

#[cfg(unix)]
#[tokio::test]
async fn runtime_custody_open_pending_reconciliation_settles_no_dispatch_with_exact_close_and_cancel(
) {
    let harness = runtime_custody_prebuy_availability_harness(
        0x61,
        ContentAvailabilityTestConfig::accepted(),
    )
    .await;
    let principal_id = "person:local:runtime-custody-open-pending-no-dispatch";
    let (proof_binding_id, _) =
        install_profile_authority_keeping_device_key(&harness.data_dir, principal_id);
    let current_profile_did = load_profile_did_for_test(&harness.data_dir, principal_id);
    let mint = runtime_mint_journal(&harness.data_dir)
        .load(harness.mint_id)
        .unwrap();
    let purchase = persist_runtime_custody_purchase_for_mint(
        &harness.data_dir,
        &mint,
        principal_id,
        &current_profile_did,
        crate::auth::now_ts(),
    );
    let record = persist_runtime_custody_open_pending_viewer_for_purchase(
        &harness.data_dir,
        &mint,
        &purchase,
        &proof_binding_id,
        "runtime-session:alpha",
        "grant:alpha",
        opaque_handle(0x51),
        crate::auth::now_ts() + 60,
    );
    let audit_request_id = RuntimeReleaseAuditIdV1::new(digest(0x91)).unwrap();
    let close_request =
        DecryptProviderRequestV1::new_close_viewer_session(audit_request_id, opaque_handle(0x51))
            .unwrap();
    let cancel_request = DecryptProviderRequestV1::new_cancel_prepared_recipient(
        audit_request_id,
        opaque_handle(0x51),
    )
    .unwrap();
    let registry = Arc::new(ProviderRegistry::new());
    let decrypt = SequencedProvider::new(
        "decrypt",
        vec![
            Ok(ok_provider_response(
                serde_json::to_value(
                    DecryptProviderResponseV1::new_viewer_session_already_absent(
                        audit_request_id,
                        opaque_handle(0x51),
                    )
                    .unwrap(),
                )
                .unwrap(),
            )),
            Ok(ok_provider_response(
                serde_json::to_value(
                    DecryptProviderResponseV1::new_cancelled_prepared_recipient(
                        audit_request_id,
                        opaque_handle(0x51),
                    )
                    .unwrap(),
                )
                .unwrap(),
            )),
        ],
    );
    registry
        .register_runtime_provider_target(PROTECTED_CONTENT_DECRYPT_PROVIDER_ID, decrypt.clone())
        .await
        .unwrap();

    let listing =
        super::super::load_runtime_custody_listing(&harness.data_dir, mint.draft().mint_id())
            .unwrap()
            .unwrap();
    let settled = super::super::settle_runtime_custody_viewer_cleanup(
        &harness.data_dir,
        registry,
        &listing,
        principal_id,
        mint.draft().mint_id(),
        record,
    )
    .await
    .unwrap();

    assert_eq!(
        settled.lifecycle_status,
        super::super::RuntimeCustodyViewerLifecycleStatus::AlreadyAbsent
    );
    let requests = decrypt.requests().await;
    assert_eq!(requests.len(), 2);
    assert_exact_runtime_decrypt_invocation(
        &requests[0],
        "close_viewer_session",
        &serde_json::to_value(&close_request).unwrap(),
    );
    assert_exact_runtime_decrypt_invocation(
        &requests[1],
        "cancel_prepared_recipient",
        &serde_json::to_value(&cancel_request).unwrap(),
    );
    let persisted = super::super::load_runtime_custody_viewer_record(
        &harness.data_dir,
        principal_id,
        mint.draft().mint_id(),
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        persisted.lifecycle_status,
        super::super::RuntimeCustodyViewerLifecycleStatus::AlreadyAbsent
    );
    assert!(harness.content_provider.requests().await.is_empty());
}

#[cfg(unix)]
#[tokio::test]
async fn runtime_custody_open_pending_reconciliation_settles_response_loss_with_exact_close_and_cancel(
) {
    let harness = runtime_custody_prebuy_availability_harness(
        0x61,
        ContentAvailabilityTestConfig::accepted(),
    )
    .await;
    let principal_id = "person:local:runtime-custody-open-pending-response-loss";
    let (proof_binding_id, _) =
        install_profile_authority_keeping_device_key(&harness.data_dir, principal_id);
    let current_profile_did = load_profile_did_for_test(&harness.data_dir, principal_id);
    let mint = runtime_mint_journal(&harness.data_dir)
        .load(harness.mint_id)
        .unwrap();
    let purchase = persist_runtime_custody_purchase_for_mint(
        &harness.data_dir,
        &mint,
        principal_id,
        &current_profile_did,
        crate::auth::now_ts(),
    );
    let record = persist_runtime_custody_open_pending_viewer_for_purchase(
        &harness.data_dir,
        &mint,
        &purchase,
        &proof_binding_id,
        "runtime-session:alpha",
        "grant:alpha",
        opaque_handle(0x52),
        crate::auth::now_ts() + 60,
    );
    let audit_request_id = RuntimeReleaseAuditIdV1::new(digest(0x91)).unwrap();
    let close_request =
        DecryptProviderRequestV1::new_close_viewer_session(audit_request_id, opaque_handle(0x52))
            .unwrap();
    let cancel_request = DecryptProviderRequestV1::new_cancel_prepared_recipient(
        audit_request_id,
        opaque_handle(0x52),
    )
    .unwrap();
    let registry = Arc::new(ProviderRegistry::new());
    let decrypt = SequencedProvider::new(
        "decrypt",
        vec![
            Ok(ok_provider_response(
                serde_json::to_value(
                    DecryptProviderResponseV1::new_closed_viewer_session(
                        audit_request_id,
                        opaque_handle(0x52),
                    )
                    .unwrap(),
                )
                .unwrap(),
            )),
            Ok(ok_provider_response(
                serde_json::to_value(
                    DecryptProviderResponseV1::new_prepared_recipient_already_absent(
                        audit_request_id,
                        opaque_handle(0x52),
                    )
                    .unwrap(),
                )
                .unwrap(),
            )),
        ],
    );
    registry
        .register_runtime_provider_target(PROTECTED_CONTENT_DECRYPT_PROVIDER_ID, decrypt.clone())
        .await
        .unwrap();

    let listing =
        super::super::load_runtime_custody_listing(&harness.data_dir, mint.draft().mint_id())
            .unwrap()
            .unwrap();
    let settled = super::super::settle_runtime_custody_viewer_cleanup(
        &harness.data_dir,
        registry,
        &listing,
        principal_id,
        mint.draft().mint_id(),
        record,
    )
    .await
    .unwrap();

    assert_eq!(
        settled.lifecycle_status,
        super::super::RuntimeCustodyViewerLifecycleStatus::Closed
    );
    let requests = decrypt.requests().await;
    assert_eq!(requests.len(), 2);
    assert_exact_runtime_decrypt_invocation(
        &requests[0],
        "close_viewer_session",
        &serde_json::to_value(&close_request).unwrap(),
    );
    assert_exact_runtime_decrypt_invocation(
        &requests[1],
        "cancel_prepared_recipient",
        &serde_json::to_value(&cancel_request).unwrap(),
    );
    let persisted = super::super::load_runtime_custody_viewer_record(
        &harness.data_dir,
        principal_id,
        mint.draft().mint_id(),
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        persisted.lifecycle_status,
        super::super::RuntimeCustodyViewerLifecycleStatus::Closed
    );
    assert!(harness.content_provider.requests().await.is_empty());
}

#[cfg(unix)]
#[tokio::test]
async fn runtime_custody_open_pending_survives_active_write_failure_and_failed_cleanup() {
    let harness = runtime_custody_prebuy_availability_harness(
        0x61,
        ContentAvailabilityTestConfig::accepted(),
    )
    .await;
    let principal_id = "person:local:runtime-custody-open-pending-write-failure";
    let (proof_binding_id, _) =
        install_profile_authority_keeping_device_key(&harness.data_dir, principal_id);
    let current_profile_did = load_profile_did_for_test(&harness.data_dir, principal_id);
    let mint = runtime_mint_journal(&harness.data_dir)
        .load(harness.mint_id)
        .unwrap();
    let purchase = persist_runtime_custody_purchase_for_mint(
        &harness.data_dir,
        &mint,
        principal_id,
        &current_profile_did,
        crate::auth::now_ts(),
    );
    let open_pending = persist_runtime_custody_open_pending_viewer_for_purchase(
        &harness.data_dir,
        &mint,
        &purchase,
        &proof_binding_id,
        "runtime-session:alpha",
        "grant:alpha",
        opaque_handle(0x53),
        crate::auth::now_ts() + 60,
    );
    let before = fs::read(super::super::runtime_viewer_path(
        &harness.data_dir,
        principal_id,
        mint.draft().mint_id(),
    ))
    .unwrap();
    let active = super::super::RuntimeCustodyViewerRecord::from_active_session(
        principal_id,
        &current_profile_did,
        mint.draft().mint_id(),
        &purchase.content_id,
        super::super::derive_runtime_custody_session_binding(
            principal_id,
            &current_profile_did,
            TEST_VIEWER_LAUNCH_ID,
            &proof_binding_id,
            "runtime-session:alpha",
            "grant:alpha",
            mint.draft().mint_id(),
        )
        .unwrap(),
        &RuntimeViewerSession::from_persisted_parts(
            digest(0x91),
            opaque_handle(0x53),
            mint.draft().encrypted_content().clone(),
            RightsActionV1::View,
            crate::auth::now_ts() + 60,
        )
        .unwrap(),
        crate::auth::now_ts(),
    )
    .unwrap();
    let viewers_dir =
        super::super::runtime_viewer_path(&harness.data_dir, principal_id, mint.draft().mint_id())
            .parent()
            .unwrap()
            .to_path_buf();
    fs::set_permissions(&viewers_dir, fs::Permissions::from_mode(0o500)).unwrap();
    let persist_error = super::super::persist_runtime_custody_viewer_record(
        &harness.data_dir,
        principal_id,
        mint.draft().mint_id(),
        &active,
    )
    .expect_err("expected active viewer persist failure");
    let _ = persist_error;
    let registry = Arc::new(ProviderRegistry::new());
    let decrypt = SequencedProvider::new(
        "decrypt",
        vec![Err(ProviderError::Provider("timeout".to_string()))],
    );
    registry
        .register_runtime_provider_target(PROTECTED_CONTENT_DECRYPT_PROVIDER_ID, decrypt)
        .await
        .unwrap();
    let listing =
        super::super::load_runtime_custody_listing(&harness.data_dir, mint.draft().mint_id())
            .unwrap()
            .unwrap();
    let cleanup_error = super::super::settle_runtime_custody_viewer_cleanup(
        &harness.data_dir,
        registry,
        &listing,
        principal_id,
        mint.draft().mint_id(),
        open_pending,
    )
    .await
    .err()
    .expect("expected cleanup failure");
    fs::set_permissions(&viewers_dir, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(cleanup_error
        .to_string()
        .contains(RUNTIME_CUSTODY_DECRYPT_UNAVAILABLE_MESSAGE));
    assert_eq!(
        fs::read(super::super::runtime_viewer_path(
            &harness.data_dir,
            principal_id,
            mint.draft().mint_id(),
        ))
        .unwrap(),
        before
    );
}

#[cfg(unix)]
#[tokio::test]
async fn runtime_custody_viewer_expiry_reconciles_exact_cleanup_before_read() {
    let harness = runtime_custody_prebuy_availability_harness(
        0x61,
        ContentAvailabilityTestConfig::accepted(),
    )
    .await;
    let principal_id = "person:local:runtime-custody-viewer-expiry";
    let (proof_binding_id, _) =
        install_profile_authority_keeping_device_key(&harness.data_dir, principal_id);
    let current_profile_did = load_profile_did_for_test(&harness.data_dir, principal_id);
    let mint = runtime_mint_journal(&harness.data_dir)
        .load(harness.mint_id)
        .unwrap();
    let purchase = persist_runtime_custody_purchase_for_mint(
        &harness.data_dir,
        &mint,
        principal_id,
        &current_profile_did,
        crate::auth::now_ts(),
    );
    let session = persist_runtime_custody_active_viewer_for_purchase(
        &harness.data_dir,
        &mint,
        &purchase,
        &proof_binding_id,
        "runtime-session:alpha",
        "grant:alpha",
        opaque_handle(0x21),
        crate::auth::now_ts().saturating_sub(1),
    );
    let registry = Arc::new(ProviderRegistry::new());
    let close_request = DecryptProviderRequestV1::new_close_viewer_session(
        RuntimeReleaseAuditIdV1::new(session.audit_request_id()).unwrap(),
        *session.viewer_session_handle(),
    )
    .unwrap();
    let close_provider = RecordingProvider::new(
        "decrypt",
        ok_provider_response(
            serde_json::to_value(
                DecryptProviderResponseV1::new_viewer_session_already_absent(
                    RuntimeReleaseAuditIdV1::new(session.audit_request_id()).unwrap(),
                    *session.viewer_session_handle(),
                )
                .unwrap(),
            )
            .unwrap(),
        ),
    );
    registry
        .register_runtime_provider_target(
            PROTECTED_CONTENT_DECRYPT_PROVIDER_ID,
            close_provider.clone(),
        )
        .await
        .unwrap();
    let err = super::super::read_runtime_custody_viewer(
        &harness.data_dir,
        registry.clone(),
        principal_id,
        &hex::encode(harness.mint_id.as_bytes()),
        &hex::encode(session.viewer_session_handle()),
        Some(TEST_VIEWER_LAUNCH_ID),
        Some(&proof_binding_id),
        Some("runtime-session:alpha"),
        Some("grant:alpha"),
        None,
    )
    .await
    .unwrap_err();
    assert!(err
        .to_string()
        .contains("Runtime custody viewer session is unavailable"));
    assert_eq!(close_provider.requests().await.len(), 1);
    assert_exact_runtime_decrypt_invocation(
        &close_provider.requests().await[0],
        "close_viewer_session",
        &serde_json::to_value(&close_request).unwrap(),
    );
    let record = super::super::load_runtime_custody_viewer_record(
        &harness.data_dir,
        principal_id,
        mint.draft().mint_id(),
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        record.lifecycle_status,
        super::super::RuntimeCustodyViewerLifecycleStatus::AlreadyAbsent
    );
    assert!(harness.content_provider.requests().await.is_empty());
}

#[cfg(unix)]
#[tokio::test]
async fn runtime_custody_viewer_restart_reconciliation_settles_old_active_record_before_replay() {
    let harness = runtime_custody_prebuy_availability_harness(
        0x61,
        ContentAvailabilityTestConfig::accepted(),
    )
    .await;
    let principal_id = "person:local:runtime-custody-viewer-restart-reconcile";
    let (proof_binding_id, _) =
        install_profile_authority_keeping_device_key(&harness.data_dir, principal_id);
    let current_profile_did = load_profile_did_for_test(&harness.data_dir, principal_id);
    let mint = runtime_mint_journal(&harness.data_dir)
        .load(harness.mint_id)
        .unwrap();
    let purchase = persist_runtime_custody_purchase_for_mint(
        &harness.data_dir,
        &mint,
        principal_id,
        &current_profile_did,
        crate::auth::now_ts(),
    );
    let session = persist_runtime_custody_active_viewer_for_purchase(
        &harness.data_dir,
        &mint,
        &purchase,
        &proof_binding_id,
        "runtime-session:alpha",
        "grant:alpha",
        opaque_handle(0x31),
        crate::auth::now_ts() + 60,
    );
    make_runtime_custody_listing_imported_without_creator_mint(
        &harness.data_dir,
        mint.draft().mint_id(),
    );
    let registry = Arc::new(ProviderRegistry::new());
    let close_request = DecryptProviderRequestV1::new_close_viewer_session(
        RuntimeReleaseAuditIdV1::new(session.audit_request_id()).unwrap(),
        *session.viewer_session_handle(),
    )
    .unwrap();
    let close_provider = RecordingProvider::new(
        "decrypt",
        ok_provider_response(
            serde_json::to_value(
                DecryptProviderResponseV1::new_viewer_session_already_absent(
                    RuntimeReleaseAuditIdV1::new(session.audit_request_id()).unwrap(),
                    *session.viewer_session_handle(),
                )
                .unwrap(),
            )
            .unwrap(),
        ),
    );
    registry
        .register_runtime_provider_target(
            PROTECTED_CONTENT_DECRYPT_PROVIDER_ID,
            close_provider.clone(),
        )
        .await
        .unwrap();

    super::super::reconcile_runtime_custody_viewers_after_decrypt_registration(
        &harness.data_dir,
        registry.clone(),
    )
    .await
    .unwrap();

    assert_eq!(close_provider.requests().await.len(), 1);
    assert_exact_runtime_decrypt_invocation(
        &close_provider.requests().await[0],
        "close_viewer_session",
        &serde_json::to_value(&close_request).unwrap(),
    );
    let record = super::super::load_runtime_custody_viewer_record(
        &harness.data_dir,
        principal_id,
        mint.draft().mint_id(),
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        record.lifecycle_status,
        super::super::RuntimeCustodyViewerLifecycleStatus::AlreadyAbsent
    );
}

#[cfg(unix)]
#[tokio::test]
async fn runtime_custody_viewer_read_and_close_reject_substituted_session_without_provider_effects()
{
    let harness = runtime_custody_prebuy_availability_harness(
        0x61,
        ContentAvailabilityTestConfig::accepted(),
    )
    .await;
    let principal_id = "person:local:runtime-custody-viewer-substituted-binding";
    let (proof_binding_id, _) =
        install_profile_authority_keeping_device_key(&harness.data_dir, principal_id);
    let current_profile_did = load_profile_did_for_test(&harness.data_dir, principal_id);
    let mint = runtime_mint_journal(&harness.data_dir)
        .load(harness.mint_id)
        .unwrap();
    let purchase = persist_runtime_custody_purchase_for_mint(
        &harness.data_dir,
        &mint,
        principal_id,
        &current_profile_did,
        crate::auth::now_ts(),
    );
    let session = persist_runtime_custody_active_viewer_for_purchase(
        &harness.data_dir,
        &mint,
        &purchase,
        &proof_binding_id,
        "runtime-session:alpha",
        "grant:alpha",
        opaque_handle(0x2a),
        crate::auth::now_ts() + 60,
    );
    let record_path =
        super::super::runtime_viewer_path(&harness.data_dir, principal_id, mint.draft().mint_id());
    let before = fs::read(&record_path).unwrap();
    let registry = Arc::new(ProviderRegistry::new());
    let decrypt_provider = RecordingProvider::new(
        "decrypt",
        ok_provider_response(serde_json::json!({"schema":"unused"})),
    );
    registry
        .register_runtime_provider_target(
            PROTECTED_CONTENT_DECRYPT_PROVIDER_ID,
            decrypt_provider.clone(),
        )
        .await
        .unwrap();

    let read_error = super::super::read_runtime_custody_viewer(
        &harness.data_dir,
        registry.clone(),
        principal_id,
        &hex::encode(harness.mint_id.as_bytes()),
        &hex::encode(session.viewer_session_handle()),
        Some(TEST_VIEWER_LAUNCH_ID),
        Some(&proof_binding_id),
        Some("runtime-session:beta"),
        Some("grant:alpha"),
        None,
    )
    .await
    .unwrap_err();
    assert!(read_error
        .to_string()
        .contains("Runtime custody viewer session is unavailable"));

    let close_error = super::super::close_runtime_custody_viewer(
        &harness.data_dir,
        registry,
        principal_id,
        &hex::encode(harness.mint_id.as_bytes()),
        &hex::encode(session.viewer_session_handle()),
        Some(TEST_VIEWER_LAUNCH_ID),
        Some(&proof_binding_id),
        Some("runtime-session:beta"),
        Some("grant:alpha"),
    )
    .await
    .unwrap_err();
    assert!(close_error
        .to_string()
        .contains("Runtime custody viewer session is unavailable"));
    assert!(decrypt_provider.requests().await.is_empty());
    assert_eq!(fs::read(&record_path).unwrap(), before);
}

#[cfg(unix)]
#[tokio::test]
async fn runtime_custody_viewer_read_and_close_reject_malformed_binding_without_provider_effects() {
    let harness = runtime_custody_prebuy_availability_harness(
        0x61,
        ContentAvailabilityTestConfig::accepted(),
    )
    .await;
    let principal_id = "person:local:runtime-custody-viewer-malformed-binding";
    let (proof_binding_id, _) =
        install_profile_authority_keeping_device_key(&harness.data_dir, principal_id);
    let current_profile_did = load_profile_did_for_test(&harness.data_dir, principal_id);
    let mint = runtime_mint_journal(&harness.data_dir)
        .load(harness.mint_id)
        .unwrap();
    let purchase = persist_runtime_custody_purchase_for_mint(
        &harness.data_dir,
        &mint,
        principal_id,
        &current_profile_did,
        crate::auth::now_ts(),
    );
    let session = persist_runtime_custody_active_viewer_for_purchase(
        &harness.data_dir,
        &mint,
        &purchase,
        &proof_binding_id,
        "runtime-session:alpha",
        "grant:alpha",
        opaque_handle(0x2b),
        crate::auth::now_ts() + 60,
    );
    let record_path =
        super::super::runtime_viewer_path(&harness.data_dir, principal_id, mint.draft().mint_id());
    let before = fs::read(&record_path).unwrap();
    let registry = Arc::new(ProviderRegistry::new());
    let decrypt_provider = RecordingProvider::new(
        "decrypt",
        ok_provider_response(serde_json::json!({"schema":"unused"})),
    );
    registry
        .register_runtime_provider_target(
            PROTECTED_CONTENT_DECRYPT_PROVIDER_ID,
            decrypt_provider.clone(),
        )
        .await
        .unwrap();

    let read_error = super::super::read_runtime_custody_viewer(
        &harness.data_dir,
        registry.clone(),
        principal_id,
        &hex::encode(harness.mint_id.as_bytes()),
        &hex::encode(session.viewer_session_handle()),
        Some(TEST_VIEWER_LAUNCH_ID),
        Some(&proof_binding_id),
        Some(""),
        Some("grant:alpha"),
        None,
    )
    .await
    .unwrap_err();
    assert_eq!(
        read_error.to_string(),
        "Runtime custody viewer session is unavailable"
    );

    let close_error = super::super::close_runtime_custody_viewer(
        &harness.data_dir,
        registry.clone(),
        principal_id,
        &hex::encode(harness.mint_id.as_bytes()),
        &hex::encode(session.viewer_session_handle()),
        Some(TEST_VIEWER_LAUNCH_ID),
        Some(&proof_binding_id),
        Some("runtime-session:alpha"),
        Some(""),
    )
    .await
    .unwrap_err();
    assert_eq!(
        close_error.to_string(),
        "Runtime custody viewer session is unavailable"
    );

    assert!(decrypt_provider.requests().await.is_empty());
    assert_eq!(fs::read(&record_path).unwrap(), before);
}

#[cfg(unix)]
#[tokio::test]
async fn runtime_custody_viewer_restart_reconciliation_settles_open_pending_record() {
    let harness = runtime_custody_prebuy_availability_harness(
        0x61,
        ContentAvailabilityTestConfig::accepted(),
    )
    .await;
    let principal_id = "person:local:runtime-custody-viewer-restart-open-pending";
    let (proof_binding_id, _) =
        install_profile_authority_keeping_device_key(&harness.data_dir, principal_id);
    let current_profile_did = load_profile_did_for_test(&harness.data_dir, principal_id);
    let mint = runtime_mint_journal(&harness.data_dir)
        .load(harness.mint_id)
        .unwrap();
    let purchase = persist_runtime_custody_purchase_for_mint(
        &harness.data_dir,
        &mint,
        principal_id,
        &current_profile_did,
        crate::auth::now_ts(),
    );
    persist_runtime_custody_open_pending_viewer_for_purchase(
        &harness.data_dir,
        &mint,
        &purchase,
        &proof_binding_id,
        "runtime-session:alpha",
        "grant:alpha",
        opaque_handle(0x33),
        crate::auth::now_ts() + 60,
    );
    let audit_request_id = RuntimeReleaseAuditIdV1::new(digest(0x91)).unwrap();
    let close_request =
        DecryptProviderRequestV1::new_close_viewer_session(audit_request_id, opaque_handle(0x33))
            .unwrap();
    let cancel_request = DecryptProviderRequestV1::new_cancel_prepared_recipient(
        audit_request_id,
        opaque_handle(0x33),
    )
    .unwrap();
    let registry = Arc::new(ProviderRegistry::new());
    let decrypt = SequencedProvider::new(
        "decrypt",
        vec![
            Ok(ok_provider_response(
                serde_json::to_value(
                    DecryptProviderResponseV1::new_viewer_session_already_absent(
                        audit_request_id,
                        opaque_handle(0x33),
                    )
                    .unwrap(),
                )
                .unwrap(),
            )),
            Ok(ok_provider_response(
                serde_json::to_value(
                    DecryptProviderResponseV1::new_cancelled_prepared_recipient(
                        audit_request_id,
                        opaque_handle(0x33),
                    )
                    .unwrap(),
                )
                .unwrap(),
            )),
        ],
    );
    registry
        .register_runtime_provider_target(PROTECTED_CONTENT_DECRYPT_PROVIDER_ID, decrypt.clone())
        .await
        .unwrap();

    super::super::reconcile_runtime_custody_viewers_after_decrypt_registration(
        &harness.data_dir,
        registry,
    )
    .await
    .unwrap();

    let requests = decrypt.requests().await;
    assert_eq!(requests.len(), 2);
    assert_exact_runtime_decrypt_invocation(
        &requests[0],
        "close_viewer_session",
        &serde_json::to_value(&close_request).unwrap(),
    );
    assert_exact_runtime_decrypt_invocation(
        &requests[1],
        "cancel_prepared_recipient",
        &serde_json::to_value(&cancel_request).unwrap(),
    );
    let record = super::super::load_runtime_custody_viewer_record(
        &harness.data_dir,
        principal_id,
        mint.draft().mint_id(),
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        record.lifecycle_status,
        super::super::RuntimeCustodyViewerLifecycleStatus::AlreadyAbsent
    );
}

#[cfg(unix)]
#[tokio::test]
async fn runtime_custody_viewer_restart_reconciliation_settles_cleanup_pending_record() {
    let harness = runtime_custody_prebuy_availability_harness(
        0x61,
        ContentAvailabilityTestConfig::accepted(),
    )
    .await;
    let principal_id = "person:local:runtime-custody-viewer-restart-cleanup-pending";
    let (proof_binding_id, _) =
        install_profile_authority_keeping_device_key(&harness.data_dir, principal_id);
    let current_profile_did = load_profile_did_for_test(&harness.data_dir, principal_id);
    let mint = runtime_mint_journal(&harness.data_dir)
        .load(harness.mint_id)
        .unwrap();
    let purchase = persist_runtime_custody_purchase_for_mint(
        &harness.data_dir,
        &mint,
        principal_id,
        &current_profile_did,
        crate::auth::now_ts(),
    );
    let session = persist_runtime_custody_active_viewer_for_purchase(
        &harness.data_dir,
        &mint,
        &purchase,
        &proof_binding_id,
        "runtime-session:alpha",
        "grant:alpha",
        opaque_handle(0x34),
        crate::auth::now_ts() + 60,
    );
    let mut record = super::super::load_runtime_custody_viewer_record(
        &harness.data_dir,
        principal_id,
        mint.draft().mint_id(),
    )
    .unwrap()
    .unwrap();
    record.mark_cleanup_pending(crate::auth::now_ts());
    super::super::persist_runtime_custody_viewer_record(
        &harness.data_dir,
        principal_id,
        mint.draft().mint_id(),
        &record,
    )
    .unwrap();
    let close_request = DecryptProviderRequestV1::new_close_viewer_session(
        RuntimeReleaseAuditIdV1::new(session.audit_request_id()).unwrap(),
        *session.viewer_session_handle(),
    )
    .unwrap();
    let registry = Arc::new(ProviderRegistry::new());
    let close_provider = RecordingProvider::new(
        "decrypt",
        ok_provider_response(
            serde_json::to_value(
                DecryptProviderResponseV1::new_viewer_session_already_absent(
                    RuntimeReleaseAuditIdV1::new(session.audit_request_id()).unwrap(),
                    *session.viewer_session_handle(),
                )
                .unwrap(),
            )
            .unwrap(),
        ),
    );
    registry
        .register_runtime_provider_target(
            PROTECTED_CONTENT_DECRYPT_PROVIDER_ID,
            close_provider.clone(),
        )
        .await
        .unwrap();

    super::super::reconcile_runtime_custody_viewers_after_decrypt_registration(
        &harness.data_dir,
        registry,
    )
    .await
    .unwrap();

    assert_eq!(close_provider.requests().await.len(), 1);
    assert_exact_runtime_decrypt_invocation(
        &close_provider.requests().await[0],
        "close_viewer_session",
        &serde_json::to_value(&close_request).unwrap(),
    );
    let settled = super::super::load_runtime_custody_viewer_record(
        &harness.data_dir,
        principal_id,
        mint.draft().mint_id(),
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        settled.lifecycle_status,
        super::super::RuntimeCustodyViewerLifecycleStatus::AlreadyAbsent
    );
}

#[cfg(unix)]
#[tokio::test]
async fn runtime_custody_viewer_expired_old_binding_allows_cleanup_before_fresh_open() {
    let harness = runtime_custody_prebuy_availability_harness(
        0x61,
        ContentAvailabilityTestConfig::accepted_now(),
    )
    .await;
    let principal_id = "person:local:runtime-custody-viewer-expired-old-binding";
    // The prebuy harness writes a custody composition; this scenario proves
    // the expired-binding cleanup runs and the FRESH open then fails closed
    // at the first missing prerequisite. Availability verification is the
    // first gate that requires the composition, so removing it makes the
    // fresh open fail closed there.
    fs::remove_file(custody_composition_config_path(&harness.data_dir)).unwrap();
    let (proof_binding_id, _) =
        install_profile_authority_keeping_device_key(&harness.data_dir, principal_id);
    let current_profile_did = load_profile_did_for_test(&harness.data_dir, principal_id);
    let mint = runtime_mint_journal(&harness.data_dir)
        .load(harness.mint_id)
        .unwrap();
    let purchase = persist_runtime_custody_purchase_for_mint(
        &harness.data_dir,
        &mint,
        principal_id,
        &current_profile_did,
        crate::auth::now_ts(),
    );
    let session = persist_runtime_custody_active_viewer_for_purchase(
        &harness.data_dir,
        &mint,
        &purchase,
        &proof_binding_id,
        "runtime-session:alpha",
        "grant:alpha",
        opaque_handle(0x35),
        crate::auth::now_ts().saturating_sub(1),
    );
    let close_request = DecryptProviderRequestV1::new_close_viewer_session(
        RuntimeReleaseAuditIdV1::new(session.audit_request_id()).unwrap(),
        *session.viewer_session_handle(),
    )
    .unwrap();
    let registry = Arc::new(ProviderRegistry::new());
    let close_provider = RecordingProvider::new(
        "decrypt",
        ok_provider_response(
            serde_json::to_value(
                DecryptProviderResponseV1::new_viewer_session_already_absent(
                    RuntimeReleaseAuditIdV1::new(session.audit_request_id()).unwrap(),
                    *session.viewer_session_handle(),
                )
                .unwrap(),
            )
            .unwrap(),
        ),
    );
    registry
        .register_runtime_provider_target(
            PROTECTED_CONTENT_DECRYPT_PROVIDER_ID,
            close_provider.clone(),
        )
        .await
        .unwrap();
    registry
        .register_sub_provider("content", harness.content_provider.clone())
        .await
        .unwrap();

    let error = super::super::open_runtime_custody_viewer(
        &harness.data_dir,
        registry.clone(),
        super::super::RuntimeCustodyViewerOpenInput {
            principal_id: principal_id.to_string(),
            mint_id: hex::encode(harness.mint_id.as_bytes()),
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
        "{error}"
    );
    assert_eq!(close_provider.requests().await.len(), 1);
    assert_exact_runtime_decrypt_invocation(
        &close_provider.requests().await[0],
        "close_viewer_session",
        &serde_json::to_value(&close_request).unwrap(),
    );
    let record = super::super::load_runtime_custody_viewer_record(
        &harness.data_dir,
        principal_id,
        mint.draft().mint_id(),
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        record.lifecycle_status,
        super::super::RuntimeCustodyViewerLifecycleStatus::AlreadyAbsent
    );
}

#[cfg(unix)]
#[tokio::test]
async fn runtime_custody_viewer_reconciliation_ignores_terminal_histories_beyond_unresolved_limit()
{
    let harness = runtime_custody_prebuy_availability_harness(
        0x61,
        ContentAvailabilityTestConfig::accepted(),
    )
    .await;
    let mint = runtime_mint_journal(&harness.data_dir)
        .load(harness.mint_id)
        .unwrap();
    let profile_did = derived_device_key_for_seed(0x41).1;
    for index in 0..300usize {
        let principal_id = format!("person:local:runtime-custody-viewer-terminal-{index}");
        let purchase = persist_runtime_custody_purchase_for_mint(
            &harness.data_dir,
            &mint,
            &principal_id,
            &profile_did,
            crate::auth::now_ts(),
        );
        let session = RuntimeViewerSession::from_persisted_parts(
            Digest32::new([u8::try_from((index % 250) + 1).unwrap(); 32]),
            [u8::try_from((index % 250) + 1).unwrap(); MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1],
            mint.draft().encrypted_content().clone(),
            RightsActionV1::View,
            crate::auth::now_ts() + 60,
        )
        .unwrap();
        let mut record = super::super::RuntimeCustodyViewerRecord::from_active_session(
            &principal_id,
            &profile_did,
            mint.draft().mint_id(),
            &purchase.content_id,
            RuntimeSessionBindingV1::new(Digest32::new(
                [u8::try_from((index % 250) + 1).unwrap(); 32],
            ))
            .unwrap(),
            &session,
            crate::auth::now_ts(),
        )
        .unwrap();
        record.mark_terminal(
            elastos_protected_content_runtime::RuntimeViewerSessionCloseResult::Closed,
            crate::auth::now_ts(),
        );
        super::super::persist_runtime_custody_viewer_record(
            &harness.data_dir,
            &principal_id,
            mint.draft().mint_id(),
            &record,
        )
        .unwrap();
    }
    let principal_id = "person:local:runtime-custody-viewer-unresolved";
    let (proof_binding_id, _) =
        install_profile_authority_keeping_device_key(&harness.data_dir, principal_id);
    let purchase = persist_runtime_custody_purchase_for_mint(
        &harness.data_dir,
        &mint,
        principal_id,
        &load_profile_did_for_test(&harness.data_dir, principal_id),
        crate::auth::now_ts(),
    );
    persist_runtime_custody_open_pending_viewer_for_purchase(
        &harness.data_dir,
        &mint,
        &purchase,
        &proof_binding_id,
        "runtime-session:alpha",
        "grant:alpha",
        opaque_handle(0x36),
        crate::auth::now_ts() + 60,
    );
    let registry = Arc::new(ProviderRegistry::new());
    let decrypt = SequencedProvider::new(
        "decrypt",
        vec![
            Ok(ok_provider_response(
                serde_json::to_value(
                    DecryptProviderResponseV1::new_viewer_session_already_absent(
                        RuntimeReleaseAuditIdV1::new(digest(0x91)).unwrap(),
                        opaque_handle(0x36),
                    )
                    .unwrap(),
                )
                .unwrap(),
            )),
            Ok(ok_provider_response(
                serde_json::to_value(
                    DecryptProviderResponseV1::new_cancelled_prepared_recipient(
                        RuntimeReleaseAuditIdV1::new(digest(0x91)).unwrap(),
                        opaque_handle(0x36),
                    )
                    .unwrap(),
                )
                .unwrap(),
            )),
        ],
    );
    registry
        .register_runtime_provider_target(PROTECTED_CONTENT_DECRYPT_PROVIDER_ID, decrypt)
        .await
        .unwrap();

    super::super::reconcile_runtime_custody_viewers_after_decrypt_registration(
        &harness.data_dir,
        registry,
    )
    .await
    .unwrap();

    let record = super::super::load_runtime_custody_viewer_record(
        &harness.data_dir,
        principal_id,
        mint.draft().mint_id(),
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        record.lifecycle_status,
        super::super::RuntimeCustodyViewerLifecycleStatus::AlreadyAbsent
    );
}

#[cfg(unix)]
#[tokio::test]
async fn runtime_custody_viewer_restart_reconciliation_rejects_invalid_active_record() {
    let harness = runtime_custody_prebuy_availability_harness(
        0x61,
        ContentAvailabilityTestConfig::accepted(),
    )
    .await;
    let principal_id = "person:local:runtime-custody-viewer-restart-invalid";
    let (proof_binding_id, _) =
        install_profile_authority_keeping_device_key(&harness.data_dir, principal_id);
    let current_profile_did = load_profile_did_for_test(&harness.data_dir, principal_id);
    let mint = runtime_mint_journal(&harness.data_dir)
        .load(harness.mint_id)
        .unwrap();
    let purchase = persist_runtime_custody_purchase_for_mint(
        &harness.data_dir,
        &mint,
        principal_id,
        &current_profile_did,
        crate::auth::now_ts(),
    );
    persist_runtime_custody_active_viewer_for_purchase(
        &harness.data_dir,
        &mint,
        &purchase,
        &proof_binding_id,
        "runtime-session:alpha",
        "grant:alpha",
        opaque_handle(0x32),
        crate::auth::now_ts() + 60,
    );
    let mut record = super::super::load_runtime_custody_viewer_record(
        &harness.data_dir,
        principal_id,
        mint.draft().mint_id(),
    )
    .unwrap()
    .unwrap();
    record.viewer_session_handle = hex::encode([0u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1]);
    super::super::persist_runtime_custody_viewer_record(
        &harness.data_dir,
        principal_id,
        mint.draft().mint_id(),
        &record,
    )
    .unwrap();

    let error = super::super::reconcile_runtime_custody_viewers_after_decrypt_registration(
        &harness.data_dir,
        Arc::new(ProviderRegistry::new()),
    )
    .await
    .expect_err("expected invalid active record rejection");
    assert!(error.to_string().contains("invalid"));
}

/// The boot hook must delegate to the restart reconciliation once decrypt
/// registration succeeds; the per-lifecycle settlement semantics are covered
/// by the `runtime_custody_viewer_restart_reconciliation_*` tests.
#[cfg(unix)]
#[tokio::test]
async fn runtime_custody_viewer_decrypt_boot_settles_open_pending_record_after_registration() {
    let harness = runtime_custody_prebuy_availability_harness(
        0x61,
        ContentAvailabilityTestConfig::accepted(),
    )
    .await;
    let principal_id = "person:local:runtime-custody-viewer-decrypt-boot";
    let (proof_binding_id, _) =
        install_profile_authority_keeping_device_key(&harness.data_dir, principal_id);
    let mint = runtime_mint_journal(&harness.data_dir)
        .load(harness.mint_id)
        .unwrap();
    let purchase = persist_runtime_custody_purchase_for_mint(
        &harness.data_dir,
        &mint,
        principal_id,
        &load_profile_did_for_test(&harness.data_dir, principal_id),
        crate::auth::now_ts(),
    );
    persist_runtime_custody_open_pending_viewer_for_purchase(
        &harness.data_dir,
        &mint,
        &purchase,
        &proof_binding_id,
        "runtime-session:alpha",
        "grant:alpha",
        opaque_handle(0x36),
        crate::auth::now_ts() + 60,
    );
    let registry = Arc::new(ProviderRegistry::new());
    let decrypt = SequencedProvider::new(
        "decrypt",
        vec![
            Ok(ok_provider_response(
                serde_json::to_value(
                    DecryptProviderResponseV1::new_viewer_session_already_absent(
                        RuntimeReleaseAuditIdV1::new(digest(0x91)).unwrap(),
                        opaque_handle(0x36),
                    )
                    .unwrap(),
                )
                .unwrap(),
            )),
            Ok(ok_provider_response(
                serde_json::to_value(
                    DecryptProviderResponseV1::new_cancelled_prepared_recipient(
                        RuntimeReleaseAuditIdV1::new(digest(0x91)).unwrap(),
                        opaque_handle(0x36),
                    )
                    .unwrap(),
                )
                .unwrap(),
            )),
        ],
    );
    registry
        .register_runtime_provider_target(PROTECTED_CONTENT_DECRYPT_PROVIDER_ID, decrypt)
        .await
        .unwrap();

    super::super::reconcile_runtime_custody_viewers_after_decrypt_boot(&harness.data_dir, registry)
        .await;

    let record = super::super::load_runtime_custody_viewer_record(
        &harness.data_dir,
        principal_id,
        mint.draft().mint_id(),
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        record.lifecycle_status,
        super::super::RuntimeCustodyViewerLifecycleStatus::AlreadyAbsent
    );
}

/// The boot hook swallows the reconcile's hard failure into a warning so boot
/// keeps serving; the underlying `Err` path is proven by
/// `runtime_custody_viewer_restart_reconciliation_rejects_invalid_active_record`.
#[cfg(unix)]
#[tokio::test]
async fn runtime_custody_viewer_decrypt_boot_keeps_serving_when_reconciliation_fails_closed() {
    let harness = runtime_custody_prebuy_availability_harness(
        0x61,
        ContentAvailabilityTestConfig::accepted(),
    )
    .await;
    let principal_id = "person:local:runtime-custody-viewer-decrypt-boot-invalid";
    let (proof_binding_id, _) =
        install_profile_authority_keeping_device_key(&harness.data_dir, principal_id);
    let current_profile_did = load_profile_did_for_test(&harness.data_dir, principal_id);
    let mint = runtime_mint_journal(&harness.data_dir)
        .load(harness.mint_id)
        .unwrap();
    let purchase = persist_runtime_custody_purchase_for_mint(
        &harness.data_dir,
        &mint,
        principal_id,
        &current_profile_did,
        crate::auth::now_ts(),
    );
    persist_runtime_custody_active_viewer_for_purchase(
        &harness.data_dir,
        &mint,
        &purchase,
        &proof_binding_id,
        "runtime-session:alpha",
        "grant:alpha",
        opaque_handle(0x32),
        crate::auth::now_ts() + 60,
    );
    let mut record = super::super::load_runtime_custody_viewer_record(
        &harness.data_dir,
        principal_id,
        mint.draft().mint_id(),
    )
    .unwrap()
    .unwrap();
    record.viewer_session_handle = hex::encode([0u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1]);
    super::super::persist_runtime_custody_viewer_record(
        &harness.data_dir,
        principal_id,
        mint.draft().mint_id(),
        &record,
    )
    .unwrap();

    super::super::reconcile_runtime_custody_viewers_after_decrypt_boot(
        &harness.data_dir,
        Arc::new(ProviderRegistry::new()),
    )
    .await;

    let persisted = super::super::load_runtime_custody_viewer_record(
        &harness.data_dir,
        principal_id,
        mint.draft().mint_id(),
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        persisted.lifecycle_status,
        super::super::RuntimeCustodyViewerLifecycleStatus::Active
    );
}

#[cfg(unix)]
#[tokio::test]
async fn runtime_custody_viewer_lifecycle_guard_serializes_same_key_and_leaves_other_keys_independent(
) {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    let first_entered = Arc::new(Notify::new());
    let same_key_attempted = Arc::new(Notify::new());
    let other_key_entered = Arc::new(Notify::new());
    let release_first = Arc::new(Notify::new());
    let same_key_acquired = Arc::new(AtomicBool::new(false));
    let other_key_acquired = Arc::new(AtomicBool::new(false));

    let first_entered_task = first_entered.clone();
    let release_first_task = release_first.clone();
    let first_data_dir = data_dir.clone();
    let first = tokio::spawn(async move {
        let _guard = super::super::acquire_runtime_custody_viewer_lifecycle_guard(
            &first_data_dir,
            "principal-a",
            digest(0x41),
        )
        .await;
        first_entered_task.notify_one();
        release_first_task.notified().await;
    });

    first_entered.notified().await;

    let same_key_flag = same_key_acquired.clone();
    let same_key_attempted_task = same_key_attempted.clone();
    let same_key_data_dir = data_dir.clone();
    let same_key = tokio::spawn(async move {
        same_key_attempted_task.notify_one();
        let _guard = super::super::acquire_runtime_custody_viewer_lifecycle_guard(
            &same_key_data_dir,
            "principal-a",
            digest(0x41),
        )
        .await;
        same_key_flag.store(true, Ordering::SeqCst);
    });

    let other_key_flag = other_key_acquired.clone();
    let other_key_entered_task = other_key_entered.clone();
    let other_key_data_dir = data_dir.clone();
    let other_key = tokio::spawn(async move {
        let _guard = super::super::acquire_runtime_custody_viewer_lifecycle_guard(
            &other_key_data_dir,
            "principal-b",
            digest(0x42),
        )
        .await;
        other_key_flag.store(true, Ordering::SeqCst);
        other_key_entered_task.notify_one();
    });

    same_key_attempted.notified().await;
    other_key_entered.notified().await;
    assert!(!same_key_acquired.load(Ordering::SeqCst));
    assert!(other_key_acquired.load(Ordering::SeqCst));

    release_first.notify_one();
    first.await.unwrap();
    same_key.await.unwrap();
    other_key.await.unwrap();
    assert!(same_key_acquired.load(Ordering::SeqCst));
}

#[cfg(unix)]
#[tokio::test]
async fn runtime_custody_library_open_after_purchase_fails_closed_without_profile() {
    let harness = runtime_custody_prebuy_availability_harness(
        0x61,
        ContentAvailabilityTestConfig::accepted(),
    )
    .await;
    let principal_id = "person:local:runtime-custody-open-missing-profile";
    let mint = runtime_mint_journal(&harness.data_dir)
        .load(harness.mint_id)
        .unwrap();
    persist_runtime_custody_purchase_for_mint(
        &harness.data_dir,
        &mint,
        principal_id,
        &derived_device_key_for_seed(0x27).1,
        crate::auth::now_ts(),
    );
    let open = super::super::open_runtime_custody_viewer(
        &harness.data_dir,
        harness.registry.clone(),
        super::super::RuntimeCustodyViewerOpenInput {
            principal_id: principal_id.to_string(),
            mint_id: hex::encode(harness.mint_id.as_bytes()),
            launch_id: Some(TEST_VIEWER_LAUNCH_ID.to_string()),
            proof_binding_id: Some("proof:alpha".to_string()),
            session_id: Some("runtime-session:alpha".to_string()),
            grant_id: Some("grant:alpha".to_string()),
        },
    )
    .await
    .unwrap_err();
    assert!(
        open.to_string()
            .contains(RUNTIME_CUSTODY_RELEASE_APPROVAL_UNAVAILABLE_MESSAGE),
        "{open}"
    );
    assert!(harness.content_provider.requests().await.is_empty());
    assert!(super::super::load_runtime_custody_viewer_record(
        &harness.data_dir,
        principal_id,
        mint.draft().mint_id()
    )
    .unwrap()
    .is_none());
}

#[cfg(unix)]
#[tokio::test]
async fn runtime_custody_library_open_after_purchase_rejects_mismatched_purchased_profile() {
    let harness = runtime_custody_prebuy_availability_harness(
        0x61,
        ContentAvailabilityTestConfig::accepted(),
    )
    .await;
    let principal_id = "person:local:runtime-custody-open-profile-mismatch";
    let (proof_binding_id, _) =
        install_profile_authority_keeping_device_key(&harness.data_dir, principal_id);
    let other_principal = "person:local:runtime-custody-open-profile-other";
    let (_other_proof_binding_id, _) =
        install_profile_authority_keeping_device_key(&harness.data_dir, other_principal);
    let other_profile_did = load_profile_did_for_test(&harness.data_dir, other_principal);
    let mint = runtime_mint_journal(&harness.data_dir)
        .load(harness.mint_id)
        .unwrap();
    persist_runtime_custody_purchase_for_mint(
        &harness.data_dir,
        &mint,
        principal_id,
        &other_profile_did,
        crate::auth::now_ts(),
    );
    let open = super::super::open_runtime_custody_viewer(
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
    assert!(
        open.to_string()
            .contains(RUNTIME_CUSTODY_OPEN_DENIED_MESSAGE),
        "{open}"
    );
    assert!(harness.content_provider.requests().await.is_empty());
    assert!(super::super::load_runtime_custody_viewer_record(
        &harness.data_dir,
        principal_id,
        mint.draft().mint_id()
    )
    .unwrap()
    .is_none());
}

#[cfg(unix)]
#[tokio::test]
async fn runtime_custody_library_open_after_buy_fails_closed_without_decrypt() {
    let harness = runtime_custody_prebuy_availability_harness(
        0x61,
        ContentAvailabilityTestConfig::accepted_now(),
    )
    .await;
    let principal_id = "person:local:runtime-custody-open-no-decrypt";
    write_device_key(&harness.data_dir, 0x61);
    let (_epoch, _composition_now) = write_library_publish_test_composition(&harness.data_dir);
    let (proof_binding_id, _) =
        install_profile_authority_keeping_device_key(&harness.data_dir, principal_id);
    let mint = runtime_mint_journal(&harness.data_dir)
        .load(harness.mint_id)
        .unwrap();
    let profile_did = load_profile_did_for_test(&harness.data_dir, principal_id);
    persist_runtime_custody_purchase_for_mint(
        &harness.data_dir,
        &mint,
        principal_id,
        &profile_did,
        crate::auth::now_ts(),
    );
    let open = super::super::open_runtime_custody_viewer(
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
    assert!(
        open.to_string()
            .contains(RUNTIME_CUSTODY_DECRYPT_UNAVAILABLE_MESSAGE),
        "{open}"
    );
    assert!(super::super::load_runtime_custody_viewer_record(
        &harness.data_dir,
        principal_id,
        mint.draft().mint_id()
    )
    .unwrap()
    .is_none());
}

#[cfg(unix)]
#[tokio::test]
async fn runtime_custody_library_open_after_buy_fails_closed_without_launch_token() {
    let harness = runtime_custody_prebuy_availability_harness(
        0x61,
        ContentAvailabilityTestConfig::accepted(),
    )
    .await;
    let principal_id = "person:local:runtime-custody-open-no-launch-token";
    write_device_key(&harness.data_dir, 0x21);
    let (_epoch, _composition_now) = write_library_publish_test_composition(&harness.data_dir);
    let (_proof_binding_id, _) =
        install_profile_authority_keeping_device_key(&harness.data_dir, principal_id);
    let mint = runtime_mint_journal(&harness.data_dir)
        .load(harness.mint_id)
        .unwrap();
    let decrypt = PrepareOnlyCleanupDecryptProvider::new();
    harness
        .registry
        .register_runtime_provider_target(PROTECTED_CONTENT_DECRYPT_PROVIDER_ID, decrypt.clone())
        .await
        .unwrap();
    let profile_did = load_profile_did_for_test(&harness.data_dir, principal_id);
    persist_runtime_custody_purchase_for_mint(
        &harness.data_dir,
        &mint,
        principal_id,
        &profile_did,
        crate::auth::now_ts(),
    );
    let open = super::super::open_runtime_custody_viewer(
        &harness.data_dir,
        harness.registry.clone(),
        super::super::RuntimeCustodyViewerOpenInput {
            principal_id: principal_id.to_string(),
            mint_id: hex::encode(harness.mint_id.as_bytes()),
            launch_id: Some(TEST_VIEWER_LAUNCH_ID.to_string()),
            proof_binding_id: None,
            session_id: None,
            grant_id: None,
        },
    )
    .await
    .unwrap_err();
    assert!(
        open.to_string()
            .contains(RUNTIME_CUSTODY_RELEASE_APPROVAL_UNAVAILABLE_MESSAGE),
        "{open}"
    );
    assert!(decrypt.requests().await.is_empty());
    assert!(super::super::load_runtime_custody_viewer_record(
        &harness.data_dir,
        principal_id,
        mint.draft().mint_id()
    )
    .unwrap()
    .is_none());
}

#[cfg(unix)]
#[tokio::test]
async fn runtime_custody_library_open_after_buy_fails_closed_without_release_wallet() {
    let harness = runtime_custody_prebuy_availability_harness(
        0x61,
        ContentAvailabilityTestConfig::accepted_now(),
    )
    .await;
    let principal_id = "person:local:runtime-custody-open-no-release-wallet";
    write_device_key(&harness.data_dir, 0x61);
    let (_epoch, _composition_now) = write_library_publish_test_composition(&harness.data_dir);
    let (proof_binding_id, _) =
        install_profile_authority_keeping_device_key(&harness.data_dir, principal_id);
    let mint = runtime_mint_journal(&harness.data_dir)
        .load(harness.mint_id)
        .unwrap();
    let decrypt = PrepareOnlyCleanupDecryptProvider::with_expected_issuer_seed(0x61);
    harness
        .registry
        .register_runtime_provider_target(PROTECTED_CONTENT_DECRYPT_PROVIDER_ID, decrypt.clone())
        .await
        .unwrap();
    let profile_did = load_profile_did_for_test(&harness.data_dir, principal_id);
    persist_runtime_custody_purchase_for_mint(
        &harness.data_dir,
        &mint,
        principal_id,
        &profile_did,
        crate::auth::now_ts(),
    );
    let open = super::super::open_runtime_custody_viewer(
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
    assert!(
        open.to_string()
            .contains(RUNTIME_CUSTODY_RELEASE_APPROVAL_UNAVAILABLE_MESSAGE),
        "{open}"
    );
    let record = super::super::load_runtime_custody_viewer_record(
        &harness.data_dir,
        principal_id,
        mint.draft().mint_id(),
    )
    .unwrap()
    .expect("expected durable viewer cleanup record");
    let requests = decrypt.requests().await;
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[0]["op"], "prepare_recipient");
    assert_eq!(requests[1]["op"], "close_viewer_session");
    assert_eq!(requests[2]["op"], "cancel_prepared_recipient");
    assert_eq!(
        requests[1]["viewer_session_handle"].as_str(),
        requests[2]["prepared_recipient_handle"].as_str()
    );
    assert_eq!(
        record.lifecycle_status,
        super::super::RuntimeCustodyViewerLifecycleStatus::AlreadyAbsent
    );
}
