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

/// A release operation that ran out of time is replaced from the same Wallet
/// signature: the rebuilt operation is a different, later operation over the
/// same signed rights request, recipient and audit ID.
#[cfg(unix)]
#[test]
fn viewer_release_operation_is_rebuilt_later_from_the_same_wallet_signature() {
    let directory = tempfile::tempdir().unwrap();
    let principal_id = "person:local:protected-content-release-rebuild";
    let (proof_binding_id, _, profile) =
        install_profile_authority_for_release_test(directory.path(), principal_id);
    let assembly = release_operation_assembly_input(profile);
    let (device_key, _) = elastos_identity::derive_did(&[0x42; 32]);
    let runtime_issuer =
        RuntimeOperationIssuerKeyV1::new(device_key.verifying_key().to_bytes()).unwrap();
    let prepared =
        elastos_protected_content_runtime::RuntimePreparedRecipient::from_persisted_parts(
            assembly.audit_request_id.digest(),
            [0x5a; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1],
            assembly.rights_request.request().binding().clone(),
            RightsActionV1::View,
            runtime_issuer,
            NOW + 290,
            assembly.recipient_public_key,
            assembly.recipient_identity.clone(),
        )
        .unwrap();
    let policy = super::super::ResolvedRuntimeRightsPolicy {
        identity: assembly.policy_body.policy_identity().unwrap(),
        body: assembly.policy_body.clone(),
    };
    let input = super::super::RuntimeViewerReleaseOperationInput {
        data_dir: directory.path(),
        principal_id,
        proof_binding_id: &proof_binding_id,
        signed_rights: &assembly.rights_request,
        prepared: &prepared,
        policy: &policy,
        custody_epoch: &assembly.custody_epoch,
        audit_request_id: assembly.audit_request_id,
    };

    let first = super::super::runtime_viewer_release_operation_at(&input, NOW + 10).unwrap();
    let rebuilt = super::super::runtime_viewer_release_operation_at(&input, NOW + 100).unwrap();

    assert!(first.verify(runtime_issuer, NOW + 10).is_ok());
    // The first operation has ended by then; the rebuilt one is live.
    assert!(first.verify(runtime_issuer, NOW + 100).is_err());
    assert!(rebuilt.verify(runtime_issuer, NOW + 100).is_ok());
    assert_ne!(
        first.statement().canonical_hash().unwrap(),
        rebuilt.statement().canonical_hash().unwrap()
    );
    assert_eq!(
        first.statement().rights_request(),
        rebuilt.statement().rights_request()
    );
    assert_eq!(
        rebuilt.statement().audit_request_id(),
        assembly.audit_request_id
    );
    assert!(rebuilt.statement().expires_at() > first.statement().expires_at());
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
    let drm = RecordingProvider::new(
        "library",
        json!({"status": "ok", "data": {"echo": "unrelated-capsule-provider"}}),
    );
    registry
        .register_runtime_provider_target(PROTECTED_CONTENT_DECRYPT_PROVIDER_ID, decrypt.clone())
        .await
        .unwrap();
    registry
        .register_sub_provider("library", drm.clone())
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
    let key = RecordingProvider::new(
        "library",
        json!({"status": "ok", "data": {"echo": "unrelated-capsule-provider"}}),
    );
    registry
        .register_runtime_provider_target(PROTECTED_CONTENT_DECRYPT_PROVIDER_ID, decrypt.clone())
        .await
        .unwrap();
    registry
        .register_sub_provider("library", key.clone())
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
async fn decrypt_registry_adapter_fails_closed_without_registered_decrypt_target() {
    let registry = Arc::new(ProviderRegistry::new());
    let unrelated = RecordingProvider::new(
        "library",
        json!({"status": "ok", "data": {"echo": "unrelated-capsule-provider"}}),
    );
    registry
        .register_sub_provider("library", unrelated.clone())
        .await
        .unwrap();
    let adapter = RuntimeDecryptRegistryAdapter::new(registry);
    let request = decrypt_prepare_request();
    assert_eq!(
        RuntimeDecryptProvider::prepare_recipient(&adapter, &request).await,
        Err(RuntimeProviderCallError::NoExactResult)
    );
    assert!(unrelated.requests().await.is_empty());
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
        &elastos_protected_content_runtime::RuntimeAvailabilityEvidenceV1::from(
            mint.content_availability().unwrap().clone(),
        ),
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
        TEST_VIEWER_EXECUTABLE_ACTOR,
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
            external_signer,
            connector_id,
        } => {
            // Read from the approval record rather than assumed, so a viewer
            // can say whose turn it is.
            assert!(!external_signer);
            assert_eq!(connector_id, None);
            (request_bytes, approval_request_id)
        }
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
            ..
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

    // Confirmed, but the signature has not come back yet. This is the state an
    // external wallet sits in between the person pressing Confirm and the
    // connector posting the signature, and the Wallet answers it with
    // `requires_approval: false` and no signed result, because that flag is
    // `status == Pending` alone. Reading the flag by itself made the release
    // treat a state that was about to succeed as a finished approval carrying
    // no signature, and fail closed. A viewer polling every two seconds lands
    // in this gap reliably, so a person saw their own approval become an error.
    wallet.confirm_awaiting_signature(&approval_request_id);
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
            ..
        } => {
            // Still the same approval and the same request: the release waits
            // rather than raising a second one.
            assert_eq!(replayed, request_bytes);
            assert_eq!(replayed_id, approval_request_id);
        }
        super::super::RuntimeReleaseWalletOutcome::Signed { .. } => {
            panic!("a confirmed approval whose signature has not arrived is not signed")
        }
    }

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
        // Four shots now: pending, pending replay, the confirmed-but-unsigned
        // gap, and the signed replay. All four carry the same request id,
        // which is the point -- a wait never raises a second approval.
        vec![approval_request_id.clone(); 4],
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
        &elastos_protected_content_runtime::RuntimeAvailabilityEvidenceV1::from(
            mint.content_availability().unwrap().clone(),
        ),
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
        TEST_VIEWER_EXECUTABLE_ACTOR,
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
        TEST_VIEWER_EXECUTABLE_ACTOR,
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
        TEST_VIEWER_EXECUTABLE_ACTOR,
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
            executable_actor: TEST_VIEWER_EXECUTABLE_ACTOR.to_string(),
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
    assert_eq!(
        open["content_kind"],
        super::super::RUNTIME_CUSTODY_VIEWER_CONTENT_KIND_MEDIA
    );
    assert_eq!(open["mime_type"], MEDIA_MIME_TYPE_V1);
    assert_eq!(open["codecs"], MEDIA_CODECS_V1);
    assert_eq!(open["has_init_segment"], true);
    assert_eq!(
        open["segment_count"].as_u64(),
        Some(
            u64::try_from(
                mint.draft()
                    .media_identity()
                    .unwrap()
                    .encrypted_segments()
                    .len()
            )
            .unwrap()
        )
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
            "content_kind",
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
    // D6 (STAB-40): a new launch binding of the same principal takes over
    // the live viewer instead of the final denial it used to get.
    let result = super::super::open_runtime_custody_viewer(
        &harness.data_dir,
        harness.registry.clone(),
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
    .await;
    if let Err(err) = result {
        assert!(
            !err.to_string()
                .contains(RUNTIME_CUSTODY_OPEN_DENIED_MESSAGE),
            "a same-principal relaunch is not denied: {err:#}"
        );
    }
    let old = super::super::load_runtime_custody_viewer_record(
        &harness.data_dir,
        principal_id,
        mint.draft().mint_id(),
    )
    .unwrap();
    assert!(
        old.as_ref()
            .is_none_or(
                |record| record.viewer_session_handle != hex::encode(opaque_handle(0x21))
                    || record.lifecycle_status
                        != super::super::RuntimeCustodyViewerLifecycleStatus::Active
            ),
        "the old viewer was taken over"
    );
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
            executable_actor: TEST_VIEWER_EXECUTABLE_ACTOR.to_string(),
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
    let read = super::super::read_runtime_custody_viewer(
        &harness.data_dir,
        registry.clone(),
        principal_id,
        &hex::encode(harness.mint_id.as_bytes()),
        &hex::encode(session.viewer_session_handle()),
        TEST_VIEWER_EXECUTABLE_ACTOR,
        Some(TEST_VIEWER_LAUNCH_ID),
        Some(&proof_binding_id),
        Some("runtime-session:alpha"),
        Some("grant:alpha"),
        None,
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
        TEST_VIEWER_EXECUTABLE_ACTOR,
        Some(TEST_VIEWER_LAUNCH_ID),
        Some(&proof_binding_id),
        Some("runtime-session:alpha"),
        Some("grant:alpha"),
        None,
        None,
    )
    .await
    .unwrap_err();
    assert_eq!(
        repeated_init.to_string(),
        "Runtime custody viewer media part is invalid"
    );
    assert_eq!(read_provider.requests().await.len(), 1);
    // D6 (STAB-05, STAB-39): only a session's first read places it; after
    // the init, a read that skips segment 0 is refused before the provider.
    let skipped_segment = super::super::read_runtime_custody_viewer(
        &harness.data_dir,
        registry.clone(),
        principal_id,
        &hex::encode(harness.mint_id.as_bytes()),
        &hex::encode(session.viewer_session_handle()),
        TEST_VIEWER_EXECUTABLE_ACTOR,
        Some(TEST_VIEWER_LAUNCH_ID),
        Some(&proof_binding_id),
        Some("runtime-session:alpha"),
        Some("grant:alpha"),
        Some(1),
        None,
    )
    .await
    .unwrap_err();
    assert_eq!(
        skipped_segment.to_string(),
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
        TEST_VIEWER_EXECUTABLE_ACTOR,
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
        TEST_VIEWER_EXECUTABLE_ACTOR,
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
            executable_actor: TEST_VIEWER_EXECUTABLE_ACTOR.to_string(),
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
        TEST_VIEWER_EXECUTABLE_ACTOR,
        Some(TEST_VIEWER_LAUNCH_ID),
        Some(&proof_binding_id),
        Some("runtime-session:alpha"),
        Some("grant:alpha"),
        None,
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
        TEST_VIEWER_EXECUTABLE_ACTOR,
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
        TEST_VIEWER_EXECUTABLE_ACTOR,
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
            TEST_VIEWER_EXECUTABLE_ACTOR,
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
        TEST_VIEWER_EXECUTABLE_ACTOR,
        Some(TEST_VIEWER_LAUNCH_ID),
        Some(&proof_binding_id),
        Some("runtime-session:alpha"),
        Some("grant:alpha"),
        None,
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
        TEST_VIEWER_EXECUTABLE_ACTOR,
        Some(TEST_VIEWER_LAUNCH_ID),
        Some(&proof_binding_id),
        Some("runtime-session:beta"),
        Some("grant:alpha"),
        None,
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
        TEST_VIEWER_EXECUTABLE_ACTOR,
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
        TEST_VIEWER_EXECUTABLE_ACTOR,
        Some(TEST_VIEWER_LAUNCH_ID),
        Some(&proof_binding_id),
        Some(""),
        Some("grant:alpha"),
        None,
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
        TEST_VIEWER_EXECUTABLE_ACTOR,
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
            executable_actor: TEST_VIEWER_EXECUTABLE_ACTOR.to_string(),
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
            executable_actor: TEST_VIEWER_EXECUTABLE_ACTOR.to_string(),
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
            executable_actor: TEST_VIEWER_EXECUTABLE_ACTOR.to_string(),
            launch_id: Some(TEST_VIEWER_LAUNCH_ID.to_string()),
            proof_binding_id: Some(proof_binding_id),
            session_id: Some("runtime-session:alpha".to_string()),
            grant_id: Some("grant:alpha".to_string()),
        },
    )
    .await
    .unwrap_err();
    // Plan B T4.4 route matrix (S4-A1): a holder without a ready decrypt
    // target is no local holder, so with no resolvable pool the open is
    // refused before the Wallet: the pool cannot be reached (T4.7 words).
    assert!(
        open.to_string()
            .contains(super::super::RUNTIME_CUSTODY_ELSEWHERE_MESSAGE),
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
            executable_actor: TEST_VIEWER_EXECUTABLE_ACTOR.to_string(),
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
            executable_actor: TEST_VIEWER_EXECUTABLE_ACTOR.to_string(),
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

    // An open that never reaches a signature must not fetch the same content
    // twice.
    //
    // `open_runtime_custody_viewer` runs top to bottom on every call, and a
    // viewer re-issues the identical open every couple of seconds while a
    // person reads their wallet prompt. The viewer session's own fetch used to
    // sit before the wallet was asked, on top of the fetch the freshness check
    // already performs, so the content was pulled and re-hashed twice before
    // the prompt appeared and twice again on every poll of the wait.
    //
    // The session's fetch now sits after the signature. This test fails at the
    // wallet, which is the step it moved behind, so a repeated path here means
    // the ordering has regressed. The freshness check's own fetches remain and
    // are the dominant pre-prompt cost; they are not what this pins.
    let fetched: Vec<String> = harness
        .content_provider
        .requests()
        .await
        .iter()
        .filter(|request| request["op"] == "fetch")
        .map(|request| request["path"].as_str().unwrap_or("?").to_string())
        .collect();
    let mut unique = fetched.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(
        fetched.len(),
        unique.len(),
        "an open that fails at the wallet fetched the same content twice: {fetched:?}"
    );
}

/// Session binding v3 admits two viewer capsules, so admission alone no longer
/// says which one may open a given mint. `open_runtime_custody_viewer` is the
/// SOLE place kind <-> viewer is enforced (the gateway proxy deliberately does
/// not, to avoid creating a mint-journal directory per `open_viewer` call), so
/// a reader launch opening a media mint must be denied here — before any
/// decrypt-provider effect.
#[cfg(unix)]
#[tokio::test]
async fn runtime_custody_library_open_denies_a_reader_actor_on_a_media_mint() {
    let harness = runtime_custody_prebuy_availability_harness(
        0x61,
        ContentAvailabilityTestConfig::accepted_now(),
    )
    .await;
    let principal_id = "person:local:runtime-custody-open-cross-kind-viewer";
    write_device_key(&harness.data_dir, 0x61);
    let (_epoch, _composition_now) = write_library_publish_test_composition(&harness.data_dir);
    let (proof_binding_id, _) =
        install_profile_authority_keeping_device_key(&harness.data_dir, principal_id);
    let mint = runtime_mint_journal(&harness.data_dir)
        .load(harness.mint_id)
        .unwrap();
    assert!(
        mint.draft().media_identity().is_some(),
        "this fixture must be a media mint for the cross-kind case to mean anything"
    );
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
            executable_actor: TEST_VIEWER_READER_EXECUTABLE_ACTOR.to_string(),
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
    assert!(
        decrypt.requests().await.is_empty(),
        "a cross-kind open must be denied before any decrypt-provider effect"
    );
    assert!(super::super::load_runtime_custody_viewer_record(
        &harness.data_dir,
        principal_id,
        mint.draft().mint_id()
    )
    .unwrap()
    .is_none());
}

/// Seals a real multi-chunk EPC1 object with the custody crate's own sealer,
/// then requires the Runtime's framed-header and framed-chunk slicers to
/// recover the sealer's exact bytes for EVERY chunk — including the short
/// final one. This is what makes it safe for the Runtime to slice a chunk out
/// of a published `object.epc1` instead of re-deriving the framing arithmetic:
/// the ranges come from the custody crate's `framed_chunk_ranges_v1`, and this
/// test pins them against the sealer that produced the file.
#[test]
fn object_framed_chunk_slicing_recovers_every_sealed_chunk() {
    const CHUNK_BYTES: usize = 1_048_576;
    let chunks = [
        (0u32..CHUNK_BYTES as u32)
            .map(|value| value as u8)
            .collect::<Vec<u8>>(),
        vec![0xa5u8; CHUNK_BYTES],
        vec![0x5au8; 4096],
    ];
    let plaintext_bytes: u64 = chunks.iter().map(|chunk| chunk.len() as u64).sum();
    let (mut sealer, framed_header) = elastos_protected_content_custody::PayloadSealerV1::open(
        "application/pdf",
        plaintext_bytes,
    )
    .unwrap();
    let framed_chunks: Vec<Vec<u8>> = chunks
        .iter()
        .enumerate()
        .map(|(index, chunk)| {
            sealer
                .seal_chunk(u32::try_from(index).unwrap(), chunk)
                .unwrap()
        })
        .collect();
    let mut framed = framed_header.clone();
    for chunk in &framed_chunks {
        framed.extend_from_slice(chunk);
    }
    let object_identity = ChunkedPayloadObjectIdentityV1::new(
        EncryptedContentIdentityV1::new(
            Digest32::new(sha2::Sha256::digest(&framed).into()),
            framed.len() as u64,
        )
        .unwrap(),
        "application/pdf",
        plaintext_bytes,
        u32::try_from(framed_header.len()).unwrap(),
    )
    .unwrap();

    assert_eq!(object_identity.chunk_count(), 3);
    assert_eq!(
        super::super::runtime_custody_object_framed_header(&framed, &object_identity).unwrap(),
        framed_header
    );
    for (index, expected) in framed_chunks.iter().enumerate() {
        assert_eq!(
            &super::super::runtime_custody_object_framed_chunk(
                &framed,
                &object_identity,
                u32::try_from(index).unwrap()
            )
            .unwrap(),
            expected,
            "framed chunk {index} must be recovered byte-for-byte"
        );
    }
    // Out-of-range chunk indices fail closed rather than slicing garbage.
    assert!(
        super::super::runtime_custody_object_framed_chunk(&framed, &object_identity, 3).is_err()
    );
    assert!(
        super::super::runtime_custody_object_framed_chunk(&framed, &object_identity, u32::MAX)
            .is_err()
    );
    // A truncated file cannot yield a chunk either.
    let truncated = framed[..framed.len() - 1].to_vec();
    assert!(
        super::super::runtime_custody_object_framed_chunk(&truncated, &object_identity, 2).is_err()
    );
}

/// Object chunk admission must bound the request by the object's own chunk
/// count, not only by the in-order counter. Without the ceiling an EXHAUSTED
/// session (`next_media_part_index == chunk_count`) passes the ordering check
/// for `chunk_index == chunk_count` and is only refused after the whole framed
/// object has been fetched and re-hashed — media bounds `segment_index`
/// against `encrypted_segments().len()` before it fetches anything, and the
/// object path must fail just as early.
#[test]
fn object_chunk_admission_bounds_the_request_by_the_chunk_count() {
    const CHUNK_COUNT: u32 = 2;
    let binding = super::super::derive_runtime_custody_session_binding(
        "person:local:object-reader",
        "did:key:zObjectReader",
        super::super::ELACITY_READER_CAPSULE_ID,
        TEST_VIEWER_LAUNCH_ID,
        "proof:object",
        "runtime-session:object",
        "grant:object",
        digest(0x31),
    )
    .unwrap();
    let mut record = super::super::RuntimeCustodyViewerRecord::from_open_pending(
        super::super::RuntimeCustodyOpenPendingInput {
            principal_id: "person:local:object-reader",
            profile_did: "did:key:zObjectReader",
            mint_id: digest(0x31),
            content_id: "content:object",
            runtime_session_binding: binding,
            audit_request_id: digest(0x32),
            viewer_session_handle: [0x33; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1],
            expires_at: NOW + 600,
            now: NOW,
        },
    )
    .unwrap();

    // Fresh session: chunk 0 is admitted, every other index is not.
    record.require_object_chunk_index(0, CHUNK_COUNT).unwrap();
    assert!(record.require_object_chunk_index(1, CHUNK_COUNT).is_err());
    assert!(
        record
            .require_object_chunk_index(CHUNK_COUNT, CHUNK_COUNT)
            .is_err(),
        "a chunk index at the ceiling must be refused even on a fresh session"
    );

    record.mark_media_part_read(NOW).unwrap();
    record.mark_media_part_read(NOW).unwrap();

    // Exhausted session: the counter now equals the chunk count, so ONLY the
    // ceiling can refuse `chunk_index == chunk_count`.
    assert!(
        record
            .require_object_chunk_index(CHUNK_COUNT, CHUNK_COUNT)
            .is_err(),
        "an exhausted session must refuse the one-past-the-end chunk before any content fetch"
    );
    assert!(record
        .require_object_chunk_index(u32::MAX, CHUNK_COUNT)
        .is_err());
    // A previously released chunk is still refused by the ordering rule.
    assert!(record.require_object_chunk_index(0, CHUNK_COUNT).is_err());
}

/// The kind a listing announces and the viewer the open path admits are two
/// readings of one decision. They are separate functions, so this holds them
/// to the same answer for both variants; a third spelling of either word would
/// let a shelf offer an item to a viewer Runtime will refuse.
#[test]
fn a_listing_announces_the_kind_the_open_path_enforces() {
    let media = RuntimeContentIdentityV1::Media(
        mint_draft_for_composition_journal_test()
            .media_identity()
            .unwrap()
            .clone(),
    );
    assert_eq!(
        super::super::runtime_custody_content_kind(&media),
        super::super::RUNTIME_CUSTODY_VIEWER_CONTENT_KIND_MEDIA
    );
    assert_eq!(
        super::super::expected_runtime_custody_viewer_capsule(&media),
        super::super::ELACITY_PLAYER_CAPSULE_ID
    );

    let (object_identity, _) = object_listing_package_for_test(0x7c);
    let object = RuntimeContentIdentityV1::Object(object_identity);
    assert_eq!(
        super::super::runtime_custody_content_kind(&object),
        super::super::RUNTIME_CUSTODY_VIEWER_CONTENT_KIND_OBJECT
    );
    assert_eq!(
        super::super::expected_runtime_custody_viewer_capsule(&object),
        super::super::ELACITY_READER_CAPSULE_ID
    );
}

/// A copy whose grant is at the head but not yet at the finalized block is
/// inside the finality lag: custody would refuse it as unbound, so the open
/// answers `finalizing` before any Wallet request or custody call is made.
#[tokio::test]
async fn open_finality_progress_reports_finalizing_when_only_the_head_has_the_grant() {
    let now = 10_000;
    let (progress, requests) = finality_progress_with(
        vec![
            Ok(finality_unbound_answer()),
            Ok(finality_access_answer(&finality_request("latest"), true)),
        ],
        now - 120,
        now,
    )
    .await;
    let progress = progress.expect("a copy inside the finality lag is finalizing");
    let answer = progress.as_json();
    assert_eq!(answer["stage"], "finalizing");
    assert_eq!(answer["resumable"], true);
    assert_eq!(answer["awaits_person"], false);
    assert_eq!(
        answer["ready_at"],
        json!(now - 120 + super::super::RUNTIME_CUSTODY_EXPECTED_FINALITY_LAG_SECS)
    );
    assert_eq!(requests.len(), 2);
    assert_eq!(
        requests[0]["op"],
        "resolve_protected_content_purchase_access"
    );
    assert_eq!(requests[0]["block"], "finalized");
    assert_eq!(requests[0]["network"], "base-mainnet");
    assert_eq!(requests[0]["wallet"], FINALITY_WALLET);
    assert_eq!(requests[1]["block"], "latest");
}

/// The estimate never names a moment already past: a lag longer than usual
/// still reads as "any moment now", not as a time that went by.
#[tokio::test]
async fn open_finality_progress_never_estimates_a_ready_time_in_the_past() {
    let now = 10_000;
    let confirmed_at = now - super::super::RUNTIME_CUSTODY_EXPECTED_FINALITY_LAG_SECS - 300;
    let (progress, _) = finality_progress_with(
        vec![
            Ok(finality_unbound_answer()),
            Ok(finality_access_answer(&finality_request("latest"), true)),
        ],
        confirmed_at,
        now,
    )
    .await;
    let answer = progress.expect("still finalizing").as_json();
    assert!(answer["ready_at"].as_u64().unwrap() > now);
}

#[test]
fn dash_part_map_walks_the_fixed_interleave() {
    use super::super::runtime_media_dash_part as part;
    let walk = |counts: &[u32]| -> Vec<(u8, Option<u32>)> {
        (0..)
            .map_while(|index| part(counts, index))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        walk(&[3, 3]),
        vec![
            (0, None),
            (1, None),
            (0, Some(0)),
            (1, Some(0)),
            (0, Some(1)),
            (1, Some(1)),
            (0, Some(2)),
            (1, Some(2)),
        ]
    );
    assert_eq!(part(&[3, 3], 8), None);
    // Video one segment longer: the extra video segment closes the walk.
    assert_eq!(walk(&[3, 2]).last(), Some(&(0, Some(2))));
    assert_eq!(walk(&[3, 2]).len(), 2 + 5);
    // Audio one segment longer.
    assert_eq!(walk(&[2, 3]).last(), Some(&(1, Some(2))));
    assert_eq!(walk(&[2, 3]).len(), 2 + 5);
    assert_eq!(
        walk(&[4]),
        vec![
            (0, None),
            (0, Some(0)),
            (0, Some(1)),
            (0, Some(2)),
            (0, Some(3))
        ]
    );
    for counts in [&[3u32, 3][..], &[3, 2], &[2, 3], &[4], &[1], &[1, 1]] {
        assert_eq!(
            Some(walk(counts).len() as u32),
            super::super::runtime_media_dash_part_count(counts),
            "{counts:?}"
        );
    }
    assert_eq!(
        super::super::runtime_media_dash_part_count(&[u32::MAX, 1]),
        None,
        "a count past u32 has no part count"
    );
    assert_eq!(super::super::runtime_media_dash_part(&[], 0), None);
}

#[test]
fn dash_open_answer_has_exactly_the_player_keys() {
    let handle = opaque_handle(0x21);
    for (kinds, counts, names) in [
        (
            vec![DASH_VIDEO, DASH_AUDIO],
            vec![3usize, 2],
            vec!["video", "audio"],
        ),
        (vec![DASH_AUDIO], vec![2], vec!["audio"]),
    ] {
        let (head, _, _) = fake_dash_package(&kinds, &counts);
        let answer = super::super::runtime_custody_viewer_media_dash_public_response(
            &head,
            digest(0x77),
            &handle,
            1234,
        )
        .unwrap();
        let keys = answer
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            keys,
            std::collections::BTreeSet::from([
                "content_kind",
                "expires_at",
                "mint_id",
                "renditions",
                "schema",
                "viewer_session_handle",
            ])
        );
        assert_eq!(
            answer["schema"],
            "elastos.library.runtime-custody-viewer/v2"
        );
        assert_eq!(answer["content_kind"], "media");
        assert_eq!(answer["expires_at"], 1234);
        assert_eq!(answer["mint_id"], hex::encode(digest(0x77).as_bytes()));
        assert_eq!(answer["viewer_session_handle"], hex::encode(handle));
        let renditions = answer["renditions"].as_array().unwrap();
        assert_eq!(renditions.len(), names.len());
        for (index, rendition) in renditions.iter().enumerate() {
            assert_eq!(
                rendition
                    .as_object()
                    .unwrap()
                    .keys()
                    .map(String::as_str)
                    .collect::<std::collections::BTreeSet<_>>(),
                std::collections::BTreeSet::from([
                    "codecs",
                    "mime_type",
                    "rendition",
                    "segment_count"
                ])
            );
            assert_eq!(rendition["rendition"], names[index]);
            assert_eq!(rendition["mime_type"], head.renditions()[index].mime_type());
            assert_eq!(rendition["codecs"], head.renditions()[index].codecs());
            assert_eq!(rendition["segment_count"], counts[index]);
        }
    }
}

#[cfg(unix)]
#[tokio::test]
async fn dash_open_replays_an_active_session_with_the_v2_answer_and_no_provider_effects() {
    let viewer = dash_viewer(
        media_dash_components(&[DASH_VIDEO, DASH_AUDIO], &[2, 2]),
        "replay",
    )
    .await;
    let open = super::super::open_runtime_custody_viewer(
        viewer.data_dir(),
        viewer.harness.base.registry.clone(),
        super::super::RuntimeCustodyViewerOpenInput {
            principal_id: viewer.principal_id.clone(),
            mint_id: hex::encode(viewer.mint_id().as_bytes()),
            executable_actor: TEST_VIEWER_EXECUTABLE_ACTOR.to_string(),
            launch_id: Some(TEST_VIEWER_LAUNCH_ID.to_string()),
            proof_binding_id: Some(viewer.proof_binding_id.clone()),
            session_id: Some("runtime-session:alpha".to_string()),
            grant_id: Some("grant:alpha".to_string()),
        },
    )
    .await
    .unwrap();
    assert_eq!(
        open,
        super::super::runtime_custody_viewer_media_dash_public_response(
            &viewer.harness.components.head,
            viewer.mint_id(),
            viewer.session.viewer_session_handle(),
            viewer.session.expires_at(),
        )
        .unwrap()
    );
    assert_eq!(open["schema"], "elastos.library.runtime-custody-viewer/v2");
    assert!(viewer
        .harness
        .base
        .content_provider
        .requests()
        .await
        .is_empty());
}

#[cfg(unix)]
#[tokio::test]
async fn dash_open_fetches_the_manifest_and_inits_but_no_segment() {
    let components = media_dash_components(&[DASH_VIDEO, DASH_AUDIO], &[3, 3]);
    let harness = runtime_custody_media_dash_availability_harness(
        components,
        ContentAvailabilityTestConfig::accepted_now(),
    )
    .await;
    let head = harness.components.head.clone();
    let (inits, leaves) = super::super::fetch_runtime_custody_open_media_dash(
        harness.base.registry.as_ref(),
        ContentAvailabilityTestProvider::CID,
        &head,
    )
    .await
    .unwrap();
    assert_eq!(inits, harness.components.protected_inits);
    assert_eq!(leaves, dash_all_leaves(&harness.components));
    assert_eq!(
        harness.base.content_provider.fetched_paths().await,
        vec![
            crate::content::CONTENT_OBJECT_MANIFEST_PATH.to_string(),
            dash_init_path(DASH_VIDEO),
            dash_init_path(DASH_AUDIO),
        ],
        "an open reads the manifest and each init, never a segment"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn dash_open_refuses_a_flipped_published_init() {
    let components = media_dash_components(&[DASH_VIDEO, DASH_AUDIO], &[2, 2]);
    let harness = runtime_custody_media_dash_availability_harness(
        components,
        ContentAvailabilityTestConfig {
            mutate_fetch_path: Some(dash_init_path(DASH_AUDIO)),
            ..ContentAvailabilityTestConfig::accepted_now()
        },
    )
    .await;
    let error = super::super::fetch_runtime_custody_open_media_dash(
        harness.base.registry.as_ref(),
        ContentAvailabilityTestProvider::CID,
        &harness.components.head,
    )
    .await
    .unwrap_err();
    assert_eq!(
        error.to_string(),
        RUNTIME_CUSTODY_AVAILABILITY_UNAVAILABLE_MESSAGE
    );
}

#[cfg(unix)]
#[tokio::test]
async fn dash_open_refuses_a_published_manifest_that_disagrees_with_the_head() {
    let components = media_dash_components(&[DASH_VIDEO], &[2]);
    let harness = runtime_custody_media_dash_availability_harness(
        components,
        ContentAvailabilityTestConfig::accepted_now(),
    )
    .await;
    harness
        .base
        .content_provider
        .tamper_published_manifest(|manifest| {
            let at = manifest
                .files
                .iter()
                .position(|f| f.path == dash_segment_file(DASH_VIDEO, 1))
                .unwrap();
            manifest.files[at].sha256 = hex::encode(sha2::Sha256::digest(b"other"));
            reseal(manifest);
        })
        .await;
    assert!(super::super::fetch_runtime_custody_open_media_dash(
        harness.base.registry.as_ref(),
        ContentAvailabilityTestProvider::CID,
        &harness.components.head,
    )
    .await
    .is_err());
}

#[cfg(unix)]
#[tokio::test]
async fn dash_staged_leaves_give_the_expected_proofs() {
    let viewer = dash_viewer(
        media_dash_components(&[DASH_VIDEO, DASH_AUDIO], &[3, 3]),
        "stage",
    )
    .await;
    viewer.stage_leaves();
    let leaves = dash_all_leaves(&viewer.harness.components);
    for (rendition, set) in leaves.iter().enumerate() {
        for index in 0..set.len() {
            let proof = super::super::runtime_custody_media_dash_proof(
                viewer.data_dir(),
                &viewer.principal_id,
                viewer.mint_id(),
                &viewer.harness.components.head,
                rendition as u8,
                index as u32,
                viewer.harness.base.registry.as_ref(),
                ContentAvailabilityTestProvider::CID,
            )
            .await
            .unwrap();
            assert_eq!(proof, dash_proof(set, index));
        }
    }
    assert!(
        viewer
            .harness
            .base
            .content_provider
            .fetched_paths()
            .await
            .is_empty(),
        "staged leaves are served without touching the content plane"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = fs::metadata(viewer.leaves_path())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0, "owner-only");
    }
}

#[cfg(unix)]
#[tokio::test]
async fn dash_read_falls_back_to_the_manifest_when_nothing_usable_is_staged() {
    for variant in ["deleted", "other-root"] {
        let viewer = dash_viewer(
            media_dash_components(&[DASH_VIDEO, DASH_AUDIO], &[2, 2]),
            variant,
        )
        .await;
        match variant {
            "deleted" => {}
            _ => {
                let other = media_dash_components(&[DASH_VIDEO, DASH_AUDIO], &[2, 2]);
                super::super::stage_runtime_custody_media_dash_leaves(
                    viewer.data_dir(),
                    &viewer.principal_id,
                    viewer.mint_id(),
                    &other.head,
                    &dash_all_leaves(&other),
                )
                .unwrap();
                assert_ne!(
                    other.head.media_manifest_root(),
                    viewer.harness.components.head.media_manifest_root()
                );
            }
        }
        assert!(!viewer.leaves_path().exists() || variant == "other-root");
        let reads = viewer.expected_reads();
        let decrypt = viewer.register_decrypt(&reads).await;
        for (selector, clear) in reads.iter().take(3) {
            let answer = viewer.read(selector.segment_index(), None).await.unwrap();
            assert_eq!(&decoded_part(&answer), clear, "{variant}");
        }
        viewer.assert_decrypt_requests(&decrypt.requests().await, &reads[..3]);
        assert_eq!(
            viewer.harness.base.content_provider.fetched_paths().await,
            vec![
                dash_segment_file(DASH_VIDEO, 0),
                crate::content::CONTENT_OBJECT_MANIFEST_PATH.to_string(),
            ],
            "{variant}: the segment, then one manifest fetch for its proof"
        );
    }
}

#[cfg(unix)]
#[tokio::test]
async fn dash_viewer_record_bound_is_the_part_count() {
    let viewer = dash_viewer(
        media_dash_components(&[DASH_VIDEO, DASH_AUDIO], &[2, 2]),
        "bound",
    )
    .await;
    let path = super::super::runtime_viewer_path(
        viewer.data_dir(),
        &viewer.principal_id,
        viewer.mint_id(),
    );
    let validate = |next: u32| {
        let mut record = viewer.record();
        record.next_media_part_index = next;
        super::super::validate_runtime_custody_viewer_record_identity(
            viewer.data_dir(),
            &path,
            &record,
        )
    };
    // 2 inits + 4 segments: a record at the total loads, one past it does not.
    assert!(validate(0).is_ok());
    assert!(validate(6).is_ok());
    assert!(validate(7).is_err());
}

#[cfg(unix)]
#[tokio::test]
async fn dash_close_removes_the_staged_leaves() {
    let viewer = dash_viewer(media_dash_components(&[DASH_VIDEO], &[2]), "close").await;
    viewer.stage_leaves();
    assert!(viewer.leaves_path().exists());
    let close_provider = RecordingProvider::new(
        "decrypt",
        ok_provider_response(
            serde_json::to_value(
                DecryptProviderResponseV1::new_closed_viewer_session(
                    RuntimeReleaseAuditIdV1::new(viewer.session.audit_request_id()).unwrap(),
                    *viewer.session.viewer_session_handle(),
                )
                .unwrap(),
            )
            .unwrap(),
        ),
    );
    viewer
        .harness
        .base
        .registry
        .register_runtime_provider_target(PROTECTED_CONTENT_DECRYPT_PROVIDER_ID, close_provider)
        .await
        .unwrap();
    let close = super::super::close_runtime_custody_viewer(
        viewer.data_dir(),
        viewer.harness.base.registry.clone(),
        &viewer.principal_id,
        &hex::encode(viewer.mint_id().as_bytes()),
        &hex::encode(viewer.session.viewer_session_handle()),
        TEST_VIEWER_EXECUTABLE_ACTOR,
        Some(TEST_VIEWER_LAUNCH_ID),
        Some(&viewer.proof_binding_id),
        Some("runtime-session:alpha"),
        Some("grant:alpha"),
    )
    .await
    .unwrap();
    assert_eq!(close["close_result"], "closed");
    assert!(!viewer.leaves_path().exists());
}

#[cfg(unix)]
#[tokio::test]
async fn dash_open_denies_a_reader_actor_on_a_media_mint() {
    let components = media_dash_components(&[DASH_VIDEO, DASH_AUDIO], &[2, 2]);
    let harness = runtime_custody_media_dash_availability_harness(
        components,
        ContentAvailabilityTestConfig::accepted_now(),
    )
    .await;
    let principal_id = "person:local:dash-cross-kind-viewer";
    let (proof_binding_id, _) =
        install_profile_authority_keeping_device_key(&harness.base.data_dir, principal_id);
    let mint = runtime_mint_journal(&harness.base.data_dir)
        .load(harness.base.mint_id)
        .unwrap();
    let decrypt = PrepareOnlyCleanupDecryptProvider::with_expected_issuer_seed(0x61);
    harness
        .base
        .registry
        .register_runtime_provider_target(PROTECTED_CONTENT_DECRYPT_PROVIDER_ID, decrypt.clone())
        .await
        .unwrap();
    let profile_did = load_profile_did_for_test(&harness.base.data_dir, principal_id);
    persist_runtime_custody_purchase_for_mint(
        &harness.base.data_dir,
        &mint,
        principal_id,
        &profile_did,
        crate::auth::now_ts(),
    );
    let open = super::super::open_runtime_custody_viewer(
        &harness.base.data_dir,
        harness.base.registry.clone(),
        super::super::RuntimeCustodyViewerOpenInput {
            principal_id: principal_id.to_string(),
            mint_id: hex::encode(harness.base.mint_id.as_bytes()),
            executable_actor: TEST_VIEWER_READER_EXECUTABLE_ACTOR.to_string(),
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
    assert!(decrypt.requests().await.is_empty());
    assert!(harness.base.content_provider.requests().await.is_empty());
}

#[cfg(unix)]
#[tokio::test]
async fn object_read_fallback_restages_once() {
    let fixture = object_mint_fixture("person:local:object-restage", 80 * 1024 * 1024, None).await;
    let facts = publish_runtime_custody_library_object_content(
        &fixture.harness.data_dir,
        fixture.harness.registry.clone(),
        fixture.input.clone(),
    )
    .await
    .unwrap();
    let persisted = runtime_mint_journal(&fixture.harness.data_dir)
        .load(facts.mint_id)
        .unwrap();
    let RuntimeContentIdentityV1::Object(identity) = persisted.draft().content_identity() else {
        panic!("the draft must carry an object identity");
    };
    let identity = identity.clone();
    let principal = &fixture.input.principal_id;
    let mint_id = facts.mint_id;
    let staged = runtime_viewer_object_path(&fixture.harness.data_dir, principal, mint_id);
    assert!(!staged.exists());
    let fetches_before = object_epc1_fetches(&fixture.harness).await;

    let chunk_70 = runtime_custody_object_chunk_for_read(
        &fixture.harness.data_dir,
        fixture.harness.registry.as_ref(),
        principal,
        mint_id,
        ContentAvailabilityTestProvider::CID,
        &identity,
        70,
    )
    .await
    .unwrap();
    let chunk_71 = runtime_custody_object_chunk_for_read(
        &fixture.harness.data_dir,
        fixture.harness.registry.as_ref(),
        principal,
        mint_id,
        ContentAvailabilityTestProvider::CID,
        &identity,
        71,
    )
    .await
    .unwrap();

    assert_eq!(
        object_epc1_fetches(&fixture.harness).await - fetches_before,
        1
    );
    assert_eq!(
        fs::metadata(&staged).unwrap().len(),
        identity.encrypted_content().ciphertext_bytes()
    );
    let header = fs::read(&staged).unwrap()[..identity.framed_header_bytes() as usize].to_vec();
    let decrypter = PayloadChunkDecrypterV1::new(&header, fixture.sealed.content_key()).unwrap();
    let mib = 1_048_576;
    assert_eq!(
        decrypter.decrypt_chunk(70, &chunk_70).unwrap().as_slice(),
        &fixture.plaintext[70 * mib..71 * mib]
    );
    assert_eq!(
        decrypter.decrypt_chunk(71, &chunk_71).unwrap().as_slice(),
        &fixture.plaintext[71 * mib..72 * mib]
    );
}

#[test]
fn every_viewer_reply_matches_the_shared_viewer_contract() {
    use elastos_protected_content_provider_contracts::CencDashRenditionKindV2 as Kind;

    let contract: Value = serde_json::from_str(VIEWER_CONTRACT).unwrap();
    let mint_id = digest(0x77);
    let handle = opaque_handle(0x21);
    let handle_hex = hex::encode(handle);
    let object = RuntimeContentIdentityV1::Object(test_object_identity(&[0x5a; 4160]));
    let media = RuntimeContentIdentityV1::Media(media_identity(0x31));
    let (head, _, _) = fake_dash_package(&[Kind::Video, Kind::Audio], &[3, 2]);
    let dash = RuntimeContentIdentityV1::MediaDash(head);
    let opened = crate::protected_content_pool_open::PoolOpened {
        handle,
        expires_at: 1234,
        sessions: crate::protected_content_pool_open::PoolViewerSessions::new(&[], &[]),
        read_ahead_segments: 6,
    };
    let open = |identity: &RuntimeContentIdentityV1| {
        super::super::runtime_custody_viewer_response_for(identity, mint_id, &handle, 1234).unwrap()
    };
    let pool_open = |identity: &RuntimeContentIdentityV1| {
        super::super::runtime_custody_pool_viewer_response(identity, mint_id, &opened).unwrap()
    };
    let built = [
        ("open", "object", open(&object)),
        ("open", "object from the pool", pool_open(&object)),
        ("open", "media v1", open(&media)),
        ("open", "media v1 from the pool", pool_open(&media)),
        ("open", "dash v2", open(&dash)),
        ("open", "dash v2 from the pool", pool_open(&dash)),
        (
            "part",
            "object chunk",
            super::super::runtime_custody_viewer_object_part_response(
                mint_id,
                &handle_hex,
                0,
                b"hello",
            ),
        ),
        (
            "part",
            "media part",
            super::super::runtime_custody_viewer_media_part_response(mint_id, &handle_hex, b"init"),
        ),
    ];
    for section in ["open", "part"] {
        let entries = contract[section].as_array().unwrap();
        let mut names = entries
            .iter()
            .map(|entry| entry["name"].as_str().unwrap())
            .collect::<Vec<_>>();
        let mut covered = built
            .iter()
            .filter(|(of, _, _)| *of == section)
            .map(|(_, name, _)| *name)
            .collect::<Vec<_>>();
        names.sort_unstable();
        covered.sort_unstable();
        assert_eq!(names, covered, "every {section} entry has its builder");
    }
    for (section, name, reply) in &built {
        let entry = contract[*section]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["name"] == *name)
            .unwrap();
        assert_eq!(
            viewer_reply_shape(reply),
            viewer_reply_shape(&entry["reply"]),
            "{section} {name}: Runtime and the viewer contract differ"
        );
    }
}

/// OPEN-LOOP OP2 (a): while the acquisition is not final, polling the open
/// answers the resumable `finalizing` stage and raises no approval request:
/// no recipient is prepared and no viewer record is written, both of which
/// come before any Wallet call.
#[cfg(unix)]
#[tokio::test]
async fn polling_an_open_while_the_copy_awaits_finality_raises_no_approval_request() {
    let harness = runtime_custody_prebuy_availability_harness(
        0x61,
        ContentAvailabilityTestConfig::accepted_now(),
    )
    .await;
    let principal_id = "person:local:runtime-custody-open-awaits-finality";
    write_device_key(&harness.data_dir, 0x61);
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
    // Confirmed two hours ago and still not final.
    persist_runtime_custody_purchase_for_mint(
        &harness.data_dir,
        &mint,
        principal_id,
        &profile_did,
        crate::auth::now_ts() - 2 * super::super::RUNTIME_CUSTODY_FINALITY_WATCH_SECS,
    );
    let latest = json!({
        "request_id": format!(
            "open-finality:{}:latest",
            hex::encode(harness.mint_id.as_bytes())
        ),
        "content_access_id": super::super::runtime_content_access_id_hex(mint.draft().content_access_id()),
    });
    const POLLS: usize = 3;
    let chain = SequencedProvider::new(
        CHAIN_PROVIDER_ID,
        (0..POLLS)
            .flat_map(|_| {
                [
                    Ok(finality_unbound_answer()),
                    Ok(finality_access_answer(&latest, true)),
                ]
            })
            .collect(),
    );
    harness
        .registry
        .register_sub_provider(CHAIN_PROVIDER_ID, chain.clone())
        .await
        .unwrap();
    for _ in 0..POLLS {
        let error = super::super::open_runtime_custody_viewer(
            &harness.data_dir,
            harness.registry.clone(),
            super::super::RuntimeCustodyViewerOpenInput {
                principal_id: principal_id.to_string(),
                mint_id: hex::encode(harness.mint_id.as_bytes()),
                executable_actor: TEST_VIEWER_EXECUTABLE_ACTOR.to_string(),
                launch_id: Some(TEST_VIEWER_LAUNCH_ID.to_string()),
                proof_binding_id: Some(proof_binding_id.clone()),
                session_id: Some("runtime-session:alpha".to_string()),
                grant_id: Some("grant:alpha".to_string()),
            },
        )
        .await
        .unwrap_err();
        let progress = error
            .downcast_ref::<super::super::RuntimeCustodyOpenProgress>()
            .unwrap_or_else(|| panic!("a typed wait: {error:#}"));
        assert_eq!(progress.as_json()["stage"], "finalizing", "{error:#}");
        assert_eq!(progress.as_json()["resumable"], true);
    }
    assert_eq!(chain.requests().await.len(), 2 * POLLS);
    assert!(
        decrypt.requests().await.is_empty(),
        "nothing before the Wallet ran"
    );
    assert!(super::super::load_runtime_custody_viewer_record(
        &harness.data_dir,
        principal_id,
        mint.draft().mint_id()
    )
    .unwrap()
    .is_none());
}
