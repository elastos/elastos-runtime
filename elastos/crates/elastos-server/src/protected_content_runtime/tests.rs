mod creator;
mod custody;
mod format_fixtures;
mod library_publish;
mod listing;
mod support;
mod viewer;

pub(crate) use support::*;

use std::collections::{BTreeMap, VecDeque};
use std::env;
#[cfg(unix)]
use std::ffi::CString;
use std::fs;
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};

use base64::Engine as _;
use custody_provider::{
    parse_and_verify_provisioning_output, ProvisionedCustodyProviderPublicKeys,
};
use ed25519_dalek::{Signer as _, SigningKey};
use elastos_protected_content_custody::provision_custody_envelope;
use elastos_protected_content_rights::{
    chain_rights_evidence_request, CHAIN_PROVIDER_ID, CHAIN_RIGHTS_EVIDENCE_OP,
};
use elastos_protected_content_runtime::{
    bind_buy, cancel_prepared_recipient, close_viewer_session, open_viewer_session,
    prepare_recipient, read_viewer_media_part, resolve_runtime_mint_selected_nodes,
    PersistedRuntimeMint, RuntimeContentAvailabilityRequirement, RuntimeCustodyProvider,
    RuntimeDecryptProvider, RuntimeMediaPreparationRecord, RuntimeMediaPreparationState,
    RuntimeMintCoordinator, RuntimeMintCoordinatorOutcome, RuntimeMintDraft, RuntimeMintIntent,
    RuntimeMintJournal, RuntimeMintNodeBinding, RuntimeMintNodeReceipt, RuntimeMintSelectedNode,
    RuntimeOpenError, RuntimeOpenViewerSessionInput, RuntimeProtectedContentPurchaseIntent,
    RuntimeProviderCallError, RuntimePurchaseEffectAuthority, RuntimeReleaseCoordinator,
    RuntimeReleaseCoordinatorOutcome, RuntimeReleaseJournal, RuntimeReleaseTerminalResult,
    RuntimeRightsProvider, RuntimeSelectedProvider, RuntimeVerifiedPurchaseEffect,
    RuntimeViewerSession,
};
use elastos_runtime::provider::{
    bridge::ProviderConfig, CapsuleProvider, Provider, ProviderBridge, ProviderCarrierInvoker,
    ProviderCarrierRoute, ProviderError, ProviderInvocation, ProviderInvocationTransport,
    ProviderRegistry, ProviderTransfer, ResourceRequest, ResourceResponse,
};
use elastos_wallet_contract::{
    ProtectedContentRightsSignatureResultV1, ValidatedChainOutcomeBindingV1,
    VerifiedWalletInvocationContext, WalletProviderOperationV2, WalletProviderRequestV2,
    WalletProviderResponseV2, WalletResultV2,
};
use k256::ecdsa::SigningKey as WalletSigningKey;
use serde_json::{json, Value};
use sha2::Digest as _;
use sha3::Keccak256;
#[cfg(unix)]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Mutex, Notify};
use x_wing::kem::{Decapsulator as _, KeyExport as _};
use x_wing::TryKeyInit as _;

use super::{
    invoke_json_provider, list_unresolved_runtime_releases, load_or_persist_runtime_mint_intent,
    load_runtime_custody_composition, load_runtime_custody_composition_config,
    load_runtime_media_provider_bridge_config,
    load_runtime_protected_content_chain_provider_config, prepare_runtime_custody_library_source,
    prepare_runtime_media_provider_prerequisite, publish_runtime_custody_library_object,
    publish_runtime_custody_library_source, register_inactive_custody_provider,
    register_inactive_custody_runtime_provider_target, register_protect_provider,
    register_protected_content_decrypt_provider, resolve_runtime_rights_policy,
    runtime_media_source_digest, runtime_mint_journal, runtime_protected_content_id,
    runtime_purchase_path, unresolved_release_audit_records, write_owner_only_bytes,
    InactiveCustodyProvider, InactiveCustodyProviderParts, MediaToolsTrust,
    RuntimeCustodyComposition, RuntimeCustodyCompositionConfigFile,
    RuntimeCustodyLibraryPublishInput, RuntimeCustodyLibrarySourceInput,
    RuntimeCustodyPurchaseAccessEvidenceRecord, RuntimeCustodyPurchaseProgress,
    RuntimeCustodyPurchaseRecord, RuntimeCustodyPurchaseStageRecord, RuntimeCustodyRegistryAdapter,
    RuntimeCustodyRouteBindingConfig, RuntimeCustodyRouteTransportConfig,
    RuntimeCustodyTerminalPurchaseRecord, RuntimeDecryptRegistryAdapter,
    RuntimeLibraryMediaPreparation, SignedMediaToolDigests,
    CHAIN_PROTECTED_CONTENT_POLICY_SCHEMA_V1, CUSTODY_COMPOSITION_SCHEMA_V1, CUSTODY_PROVIDER_ID,
    CUSTODY_PROVIDER_OPERATIONS, MAX_CHAIN_PROVIDER_CONFIG_BYTES, MEDIA_PROVIDER_CONFIG_SCHEMA_V1,
    MEDIA_PROVIDER_ID, MEDIA_PROVIDER_MAX_INPUT_BYTES_V1, MEDIA_PROVIDER_TIMEOUT_MS_V1,
    PROTECTED_CONTENT_CHAIN_PROVIDER_CONFIG_SCHEMA_V1, PROTECTED_CONTENT_DECRYPT_PROVIDER_ID,
    PROTECTED_CONTENT_DECRYPT_PROVIDER_OPERATIONS, PROTECTED_CONTENT_PROVIDER_STATUS_TIMEOUT,
    PROTECT_PROVIDER_ID, PROTECT_PROVIDER_OPERATIONS, PROTECT_PROVIDER_PROCESS_ID,
    RUNTIME_CUSTODY_AVAILABILITY_UNAVAILABLE_MESSAGE, RUNTIME_CUSTODY_COMPOSITION_MISSING_MESSAGE,
    RUNTIME_CUSTODY_DECRYPT_UNAVAILABLE_MESSAGE,
    RUNTIME_CUSTODY_MINT_RECONCILIATION_REQUIRED_MESSAGE,
    RUNTIME_CUSTODY_MINT_TERMINAL_ABORT_MESSAGE, RUNTIME_CUSTODY_OPEN_DENIED_MESSAGE,
    RUNTIME_CUSTODY_RELEASE_APPROVAL_UNAVAILABLE_MESSAGE, RUNTIME_PROVIDER_ID,
    RUNTIME_PURCHASE_SCHEMA_V1,
};
use elastos_protected_content_contracts::{
    CanonicalContract, ContentAccessIdV1, CustodyApprovedSuitesV1,
    CustodyCommitteeAuthorizationIdentityV1, CustodyCommitteeAuthorizationStatementV1,
    CustodyEnvelopeManifestV1, CustodyEnvelopeV1, CustodyEpochIssuerKeyV1, CustodyEpochStatementV1,
    CustodyNodeProvisioningRecordIdentityV1, CustodyNodeProvisioningRecordV1,
    CustodyPoolFailureDomainIdV1, CustodyPoolIdentityV1, CustodyPoolMemberStateV1,
    CustodyPoolMemberV1, CustodyPoolOperatorIdV1, CustodyPoolStatementV1, Digest32,
    EncryptedContentIdentityV1, EvmContractAddressV1, EvmFunctionSelectorV1, EvmRightsMethodAbiV1,
    KeyReleaseOutcomeV1, KeyReleaseRequestV1, NodeContributionRefV1, NodeContributionStatementV1,
    NodeCustodyPublicKeyV1, NodePublicKey, PqHybridSealedShareV1, ProfileIdentityV1,
    ProtectedContentBindingV1, RecipientKeyAuthorizationStatementV1, RecipientKeyIdentityV1,
    RecipientPublicKeyBytesV1, RecipientSealedContributionV1, ReplayNonce16, RightsActionV1,
    RightsDecisionV1, RightsEvaluationEvidenceRequestV1, RightsEvaluationEvidenceV1,
    RightsObservationFinalityV1, RightsPolicyBodyV1, RightsRequestV1,
    RuntimeCustodyProvisioningIdV1, RuntimeCustodyProvisioningStatementV1,
    RuntimeOperationIssuerKeyV1, RuntimeReleaseAuditIdV1, RuntimeReleaseOperationStatementV1,
    RuntimeSessionBindingV1, ShareCoordinateV1, SignedCustodyCommitteeAuthorizationV1,
    SignedCustodyEpochV1, SignedCustodyPoolV1, SignedNodeContributionV1,
    SignedNodeRightsDecisionV1, SignedRecipientKeyAuthorizationV1,
    SignedRuntimeCustodyProvisioningV1, SignedRuntimeReleaseOperationV1, SignedTerminalReceiptV1,
    TerminalReceiptIssuerKey, TerminalReceiptStatementV1, ThresholdV1, ValidatedCustodyCommitteeV1,
    WalletAddress, WalletSignedRightsRequestV1, CUSTODY_X_WING_AES256GCM_SUITE_ID_V1,
    MAX_RIGHTS_EVIDENCE_LIFETIME_SECS, PQ_HYBRID_SEALED_SHARE_ENVELOPE_BYTES,
    X_WING_DRAFT06_CIPHERTEXT_BYTES,
};
use elastos_protected_content_provider_contracts::{
    CencFmp4MediaIdentityV1, CustodyProviderRequestV1, CustodyProviderResponseV1,
    DecryptProviderRequestV1, DecryptProviderResponseStatusV1, DecryptProviderResponseV1,
    ProtectProviderRequestV1, ProtectProviderResponseStatusV1, ProtectProviderResponseV1,
    ProtectionSessionNodeV1, ProviderFailureCodeV1, RightsProviderRequestV1,
    RightsProviderResponseV1, ValidatedClearFmp4MediaSessionLayoutV1,
    ValidatedCustodyProviderRequestV1, ValidatedDecryptProviderRequestV1,
    ValidatedRightsProviderRequestV1, ViewerMediaPartSelectorV1,
    CUSTODY_PROVIDER_REQUEST_SCHEMA_V1, CUSTODY_PROVIDER_RESPONSE_SCHEMA_V1,
    DECRYPT_PROVIDER_REQUEST_SCHEMA_V1, DECRYPT_PROVIDER_RESPONSE_SCHEMA_V1,
    MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1, PROTECT_PROVIDER_REQUEST_SCHEMA_V1,
    PROTECT_PROVIDER_RESPONSE_SCHEMA_V1,
};

#[tokio::test]
async fn protected_content_availability_publishes_status_refetches_and_verifies_exact_media() {
    let evidence =
        publish_protected_content_for_test(ContentAvailabilityTestConfig::accepted(), None, None)
            .await
            .unwrap();
    assert_eq!(
        evidence.object_identity(),
        "did:key:z6Mkhq7f4c4QAEgwRByrEsmGu3RJRYvpP5UGcWvqBjGW4YRe#content"
    );
    assert_eq!(
        evidence.publisher_identity(),
        "did:key:z6Mkhq7f4c4QAEgwRByrEsmGu3RJRYvpP5UGcWvqBjGW4YRe#publisher"
    );
    assert_eq!(evidence.required_replicas(), 3);
    assert_eq!(evidence.observed_replicas(), 3);
    let debug = format!("{evidence:?}");
    assert!(!debug.contains("init.mp4"));
    assert!(!debug.contains("segments/"));
}

#[tokio::test]
async fn protected_content_availability_rejects_wrong_signed_receipt_or_refetched_object() {
    let wrong_signer =
        ContentAvailabilityTestProvider::new(0x62, ContentAvailabilityTestConfig::accepted())
            .signer_did();
    assert!(publish_protected_content_for_test(
        ContentAvailabilityTestConfig::accepted(),
        Some(wrong_signer),
        None,
    )
    .await
    .is_err());
    for config in [
        ContentAvailabilityTestConfig {
            receipt_object_identity: Some("did:key:wrong#content".to_string()),
            ..ContentAvailabilityTestConfig::accepted()
        },
        ContentAvailabilityTestConfig {
            receipt_publisher_did: Some("did:key:wrong#publisher".to_string()),
            ..ContentAvailabilityTestConfig::accepted()
        },
        ContentAvailabilityTestConfig {
            policy: "wrong-policy".to_string(),
            ..ContentAvailabilityTestConfig::accepted()
        },
        ContentAvailabilityTestConfig {
            status: "local_pinned".to_string(),
            ..ContentAvailabilityTestConfig::accepted()
        },
        ContentAvailabilityTestConfig {
            replicas: 2,
            ..ContentAvailabilityTestConfig::accepted()
        },
        ContentAvailabilityTestConfig {
            live_multi_peer_proof: None,
            ..ContentAvailabilityTestConfig::accepted()
        },
        ContentAvailabilityTestConfig {
            live_multi_peer_proof: Some(false),
            ..ContentAvailabilityTestConfig::accepted()
        },
        ContentAvailabilityTestConfig {
            malformed_receipt: true,
            ..ContentAvailabilityTestConfig::accepted()
        },
        ContentAvailabilityTestConfig {
            checked_at: NOW - 61,
            ..ContentAvailabilityTestConfig::accepted()
        },
        ContentAvailabilityTestConfig {
            checked_at: NOW + 6,
            ..ContentAvailabilityTestConfig::accepted()
        },
        ContentAvailabilityTestConfig {
            receipt_cid: Some(
                "bafybeibwzif2r5tn7z7cq4f5a2mmepmab4s4m5a2hqu5v4f4uzkd3t2u7m".to_string(),
            ),
            ..ContentAvailabilityTestConfig::accepted()
        },
        ContentAvailabilityTestConfig {
            mutate_fetch_path: Some("protected-content/v1/identity.bin".to_string()),
            ..ContentAvailabilityTestConfig::accepted()
        },
        ContentAvailabilityTestConfig {
            mutate_manifest_extra_file: true,
            ..ContentAvailabilityTestConfig::accepted()
        },
    ] {
        assert!(publish_protected_content_for_test(config, None, None)
            .await
            .is_err());
    }
}

#[tokio::test]
async fn protected_content_availability_rejects_descriptor_layout_and_extra_source_files() {
    for mutate_directory in [
        mutate_protected_content_descriptor as fn(&Path),
        mutate_protected_content_segment,
        add_extra_protected_content_file,
    ] {
        assert!(publish_protected_content_for_test(
            ContentAvailabilityTestConfig::accepted(),
            None,
            Some(mutate_directory),
        )
        .await
        .is_err());
    }
}

#[tokio::test]
async fn protected_content_availability_rejects_fixed_layout_names_indices_sizes_and_digests() {
    for mutate_directory in [
        remove_protected_content_descriptor as fn(&Path),
        rename_protected_content_descriptor,
        remove_protected_content_init,
        rename_protected_content_init,
        remove_protected_content_segment,
        rename_protected_content_segment,
        reorder_protected_content_segments,
        add_protected_content_segment_index_alias,
        truncate_protected_content_descriptor,
        mutate_protected_content_init,
        truncate_protected_content_init,
        mutate_protected_content_segment,
        truncate_protected_content_segment,
    ] {
        assert!(publish_protected_content_for_test(
            ContentAvailabilityTestConfig::accepted(),
            None,
            Some(mutate_directory),
        )
        .await
        .is_err());
    }
}

// These fixtures represent frozen support files from a different Runtime release.
#[cfg(unix)]
mod provider_status_compatibility {
    use super::*;

    type StatusCheck = fn(&Value) -> anyhow::Result<()>;

    fn cases() -> [(Value, StatusCheck, &'static str); 4] {
        [
            (
                ProtectedStartupProvider::Protect.status(),
                super::super::require_protect_provider_status,
                "protect provider",
            ),
            (
                ProtectedStartupProvider::Custody.status(),
                super::super::require_inactive_custody_provider_status,
                "inactive custody provider",
            ),
            (
                protected_content_decrypt_provider_status(),
                super::super::require_protected_content_decrypt_provider_status,
                "protected-content decrypt provider",
            ),
            (
                json!({
                    "status": "ok",
                    "data": {
                        "provider": "media-provider",
                        "protocol_version": "elastos.media-provider/v1",
                        "version": "0.7.2-alpha.5",
                        "configured": true,
                        "supported_operations": ["status", "prepare"],
                    }
                }),
                super::super::require_media_provider_status,
                "media-provider",
            ),
        ]
    }

    #[test]
    fn accepts_another_release_with_the_same_protocol() {
        for (mut status, check, label) in cases() {
            for version in ["0.7.2-alpha.5", "0.7.2-alpha.6", "0.1.0-dev"] {
                status["data"]["version"] = json!(version);
                check(&status).unwrap_or_else(|error| panic!("{label}: {error}"));
            }
        }
    }

    #[test]
    fn refuses_incompatible_protocol_with_a_plain_message() {
        for (status, check, label) in cases() {
            let fields: &[&str] = if label == "media-provider" {
                &["protocol_version"]
            } else {
                &["request_schema", "response_schema"]
            };
            for field in fields {
                let mut incompatible = status.clone();
                incompatible["data"][field] = json!("incompatible/v2");
                let message = check(&incompatible).unwrap_err().to_string();
                let expected = if label == "media-provider" {
                    format!("{label} status has an unsupported protocol version")
                } else {
                    format!("{label} status has unsupported protocol schemas")
                };
                assert_eq!(message, expected);
            }
        }
    }

    #[test]
    fn refuses_missing_or_garbled_status() {
        for (status, check, label) in cases() {
            for version in [Value::Null, json!(42), json!(""), json!("garbled")] {
                let mut invalid = status.clone();
                invalid["data"]["version"] = version;
                assert!(check(&invalid).is_err(), "{label}");
            }
            for field in status["data"].as_object().unwrap().keys() {
                let mut missing = status.clone();
                missing["data"].as_object_mut().unwrap().remove(field);
                assert!(check(&missing).is_err(), "{label}: {field}");
            }
            assert!(check(&json!({"status": "ok"})).is_err(), "{label}");
            assert!(
                check(&json!({"status": "error", "data": status["data"]})).is_err(),
                "{label}"
            );
        }
    }
}

#[cfg(unix)]
#[tokio::test]
async fn protected_provider_startup_rejects_status_mismatches_and_reaps_child() {
    for provider in ProtectedStartupProvider::ALL {
        for (case, status) in protected_startup_status_mismatches(provider) {
            let temp = tempfile::tempdir().unwrap();
            let case_root = temp.path().join(case);
            fs::create_dir_all(&case_root).unwrap();
            let data_dir = case_root.join("data");
            provider.prepare_private_config(&data_dir);
            let (binary, pid_file, request_log) = write_mock_protected_startup_provider(
                &case_root,
                provider.name(),
                &status.to_string(),
            );
            let registry = Arc::new(ProviderRegistry::new());

            provider
                .register(&registry, &binary, &data_dir)
                .await
                .expect_err("mismatched provider status must fail closed");

            assert!(
                !process_is_running(read_pid(&pid_file)),
                "{provider:?} {case}"
            );
            let requests = fs::read_to_string(request_log).unwrap();
            assert!(requests.contains(r#""op":"status""#), "{provider:?} {case}");
            assert!(
                requests.contains(r#""op":"shutdown""#),
                "{provider:?} {case}"
            );
            assert!(
                !registry
                    .has_ready_runtime_provider_target(provider.target())
                    .await
            );
        }
    }
}

#[cfg(unix)]
#[tokio::test]
async fn protected_provider_startup_rejects_invalid_status_and_reaps_child() {
    for provider in ProtectedStartupProvider::ALL {
        for (case, status) in [
            ("malformed-json", "not-json"),
            ("missing-data", r#"{"status":"ok"}"#),
            (
                "error",
                r#"{"status":"error","code":"not_ready","message":"not ready"}"#,
            ),
        ] {
            let temp = tempfile::tempdir().unwrap();
            let case_root = temp.path().join(case);
            fs::create_dir_all(&case_root).unwrap();
            let data_dir = case_root.join("data");
            provider.prepare_private_config(&data_dir);
            let (binary, pid_file, request_log) =
                write_mock_protected_startup_provider(&case_root, provider.name(), status);
            let registry = Arc::new(ProviderRegistry::new());

            provider
                .register(&registry, &binary, &data_dir)
                .await
                .expect_err("invalid provider status must fail closed");

            assert!(
                !process_is_running(read_pid(&pid_file)),
                "{provider:?} {case}"
            );
            let requests = fs::read_to_string(request_log).unwrap();
            assert!(requests.contains(r#""op":"status""#), "{provider:?} {case}");
            assert!(
                requests.contains(r#""op":"shutdown""#),
                "{provider:?} {case}"
            );
            assert!(
                !registry
                    .has_ready_runtime_provider_target(provider.target())
                    .await
            );
        }
    }
}

#[cfg(unix)]
#[tokio::test]
async fn protected_provider_duplicate_unregister_and_restart_settle_exact_processes() {
    for provider in ProtectedStartupProvider::ALL {
        let temp = tempfile::tempdir().unwrap();
        let data_dir = temp.path().join("data");
        provider.prepare_private_config(&data_dir);
        let (binary, pid_file, request_log) = write_mock_protected_startup_provider(
            temp.path(),
            provider.name(),
            &provider.status().to_string(),
        );
        let registry = Arc::new(ProviderRegistry::new());

        provider
            .register(&registry, &binary, &data_dir)
            .await
            .unwrap();
        let first_pid = read_pid(&pid_file);
        assert!(process_is_running(first_pid), "{provider:?}");
        assert!(
            registry
                .has_ready_runtime_provider_target(provider.target())
                .await
        );

        let duplicate = provider
            .register(&registry, &binary, &data_dir)
            .await
            .unwrap_err();
        assert!(duplicate.to_string().contains("already registered"));
        let pids = read_pids(&pid_file);
        assert_eq!(pids.len(), 2, "{provider:?}");
        let rejected_pid = pids[1];
        assert!(process_is_running(first_pid), "{provider:?}");
        assert!(!process_is_running(rejected_pid), "{provider:?}");

        registry
            .unregister_runtime_provider_target(provider.target())
            .await
            .unwrap();
        assert!(!process_is_running(first_pid), "{provider:?}");

        provider
            .register(&registry, &binary, &data_dir)
            .await
            .unwrap();
        let replacement_pid = read_pid(&pid_file);
        assert_ne!(replacement_pid, first_pid);
        assert_ne!(replacement_pid, rejected_pid);
        assert!(process_is_running(replacement_pid), "{provider:?}");
        registry
            .unregister_runtime_provider_target(provider.target())
            .await
            .unwrap();
        assert!(!process_is_running(replacement_pid), "{provider:?}");
        assert_eq!(
            fs::read_to_string(request_log)
                .unwrap()
                .matches(r#""op":"shutdown""#)
                .count(),
            3,
            "{provider:?}"
        );
    }
}

#[cfg(unix)]
#[tokio::test]
async fn protected_provider_startup_keeps_primary_error_with_shutdown_failure_context() {
    let temp = tempfile::tempdir().unwrap();
    let provider = ProtectedStartupProvider::Protect;
    let data_dir = temp.path().join("data");
    provider.prepare_private_config(&data_dir);
    let mut status = provider.status();
    status["data"]["provider"] = json!("wrong-provider");
    let (binary, pid_file, request_log) = write_mock_protected_startup_provider_with_shutdown(
        temp.path(),
        provider.name(),
        &status.to_string(),
        r#"{"status":"error","code":"shutdown_failed","message":"denied"}"#,
    );
    let registry = Arc::new(ProviderRegistry::new());

    let error = provider
        .register(&registry, &binary, &data_dir)
        .await
        .unwrap_err()
        .to_string();

    let primary = error.find("unsupported identity").unwrap();
    let cleanup = error.find("shutdown/reap also failed").unwrap();
    assert!(primary < cleanup, "{error}");
    assert!(!process_is_running(read_pid(&pid_file)));
    assert!(fs::read_to_string(request_log)
        .unwrap()
        .contains(r#""op":"shutdown""#));
}

#[cfg(unix)]
#[test]
fn write_owner_only_bytes_creates_owner_only_atomic_runtime_storage() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    let path = data_dir.join("protected-content/runtime-open/demo/viewers/state.json");
    write_owner_only_bytes(&path, b"{\"state\":\"active\"}").unwrap();

    assert_eq!(fs::read(&path).unwrap(), b"{\"state\":\"active\"}");
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(path.parent().unwrap().parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
}

#[cfg(unix)]
#[test]
fn write_owner_only_bytes_failed_replace_preserves_previous_runtime_storage_record() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    let path = data_dir.join("protected-content/runtime-open/demo/viewers/state.json");
    write_owner_only_bytes(&path, b"{\"state\":\"closed\"}").unwrap();

    let parent = path.parent().unwrap();
    fs::set_permissions(parent, fs::Permissions::from_mode(0o500)).unwrap();
    let error = write_owner_only_bytes(&path, b"{\"state\":\"active\"}")
        .expect_err("expected atomic write failure");
    assert!(
        error.to_string().contains("Permission denied") || error.to_string().contains("storage")
    );
    assert_eq!(fs::read(&path).unwrap(), b"{\"state\":\"closed\"}");
    let entries = fs::read_dir(parent)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(entries, vec!["state.json".to_string()]);
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn unresolved_release_scan_is_empty_without_creating_state() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    std::fs::create_dir(&data_dir).unwrap();
    assert!(list_unresolved_runtime_releases(&data_dir)
        .unwrap()
        .is_empty());
    assert!(unresolved_release_audit_records(&data_dir)
        .unwrap()
        .is_empty());
    assert!(!data_dir.join("protected-content").exists());
}

#[tokio::test]
async fn runtime_rights_adapter_invokes_chain_not_the_provisional_rights_route() {
    let registry = Arc::new(ProviderRegistry::new());
    let chain = RecordingProvider::new(
        "chain",
        json!({
            "status": "ok",
            "data": {
                "schema": "elastos.chain.protected-content-rights-evidence/v1"
            }
        }),
    );
    let rights = RecordingProvider::new(
        "rights",
        json!({"status": "ok", "data": {"echo": "rights"}}),
    );
    registry
        .register_sub_provider("rights", rights.clone())
        .await
        .unwrap();
    registry
        .register_sub_provider("chain", chain.clone())
        .await
        .unwrap();

    let data = invoke_json_provider(
        registry.as_ref(),
        CHAIN_PROVIDER_ID,
        CHAIN_RIGHTS_EVIDENCE_OP,
        json!({
            "op": CHAIN_RIGHTS_EVIDENCE_OP,
            "signed_runtime_release_operation": "0xab"
        }),
    )
    .await
    .unwrap();
    assert_eq!(
        data["schema"],
        "elastos.chain.protected-content-rights-evidence/v1"
    );

    let chain_requests = chain.requests().await;
    let rights_requests = rights.requests().await;
    assert_eq!(chain_requests.len(), 1);
    assert!(rights_requests.is_empty());
    assert_eq!(chain_requests[0]["op"], CHAIN_RIGHTS_EVIDENCE_OP);
    assert_eq!(
        chain_requests[0]["_runtime_invocation"]["source"],
        RUNTIME_PROVIDER_ID
    );
    assert_eq!(
        chain_requests[0]["_runtime_invocation"]["target"],
        CHAIN_PROVIDER_ID
    );
    assert_eq!(
        chain_requests[0]["_runtime_invocation"]["carrier"],
        Value::Null
    );
    assert_eq!(
        chain_requests[0]["_runtime_invocation"]["transport"],
        "runtime-local-provider-plane"
    );
    assert!(chain_requests[0].get("network").is_none());
    assert!(chain_requests[0].get("rpc_url").is_none());
    assert!(chain_requests[0].get("host").is_none());
    assert!(chain_requests[0].get("has_access").is_none());

    let mut schemes = registry.sub_provider_schemes().await;
    schemes.sort();
    assert_eq!(schemes, vec!["chain".to_string(), "rights".to_string()]);
}

#[tokio::test]
async fn runtime_rights_adapter_fails_closed_without_chain_and_does_not_call_rights() {
    let registry = Arc::new(ProviderRegistry::new());
    let rights = RecordingProvider::new(
        "rights",
        json!({"status": "ok", "data": {"echo": "rights"}}),
    );
    registry
        .register_sub_provider("rights", rights.clone())
        .await
        .unwrap();
    let err = invoke_json_provider(
        registry.as_ref(),
        CHAIN_PROVIDER_ID,
        CHAIN_RIGHTS_EVIDENCE_OP,
        json!({
            "op": CHAIN_RIGHTS_EVIDENCE_OP,
            "signed_runtime_release_operation": "0xab"
        }),
    )
    .await
    .unwrap_err();
    assert!(err.contains("invocation failed"));
    assert!(rights.requests().await.is_empty());
    let mut schemes = registry.sub_provider_schemes().await;
    schemes.sort();
    assert_eq!(schemes, vec!["rights".to_string()]);
}

#[test]
fn runtime_protected_content_id_is_exact_lowercase_domain_hash_and_changes_for_mutations() {
    let identity = EncryptedContentIdentityV1::new(digest(0x41), 2048).unwrap();
    let derived = runtime_protected_content_id(&identity).unwrap();
    let expected = format!(
        "content:{}",
        hex::encode(identity.canonical_hash().unwrap().as_bytes())
    );
    assert_eq!(derived, expected);
    assert!(derived.starts_with("content:"));
    assert_eq!(derived.len(), "content:".len() + 64);
    assert!(derived["content:".len()..]
        .bytes()
        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')));

    let changed_digest = EncryptedContentIdentityV1::new(digest(0x42), 2048).unwrap();
    let changed_len = EncryptedContentIdentityV1::new(digest(0x41), 2049).unwrap();
    assert_ne!(
        runtime_protected_content_id(&changed_digest).unwrap(),
        derived
    );
    assert_ne!(runtime_protected_content_id(&changed_len).unwrap(), derived);
}
