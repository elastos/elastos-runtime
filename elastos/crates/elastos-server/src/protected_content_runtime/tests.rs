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
use elastos_protected_content_custody::{
    provision_custody_envelope, PayloadChunkDecrypterV1, PayloadSealerV1,
    UnprovisionedSealedPayloadV1,
};
use elastos_protected_content_provider_contracts::{
    ATTEST_REMOTE_SEAL_UPLOAD_OP, AUTHORIZE_REMOTE_SEAL_SHARE_OP, MAX_OBJECT_FRAMED_CHUNK_BYTES_V1,
    SIGN_REMOTE_SEAL_COMPLETION_OP,
};
use elastos_protected_content_rights::{
    chain_rights_evidence_request, CHAIN_PROVIDER_ID, CHAIN_RIGHTS_EVIDENCE_OP,
};
use elastos_protected_content_runtime::{
    bind_buy, cancel_prepared_recipient, close_viewer_session, open_viewer_session,
    prepare_recipient, read_viewer_media_part, resolve_runtime_mint_selected_nodes,
    PersistedRuntimeMint, RuntimeContentAvailabilityRequirement, RuntimeContentIdentityV1,
    RuntimeCustodyProvider, RuntimeDecryptProvider, RuntimeMediaPreparationRecord,
    RuntimeMediaPreparationState, RuntimeMintCoordinator, RuntimeMintCoordinatorOutcome,
    RuntimeMintDraft, RuntimeMintIntent, RuntimeMintJournal, RuntimeMintNodeBinding,
    RuntimeMintNodeReceipt, RuntimeMintSelectedNode, RuntimeOpenError, RuntimeOpenViewerContentV1,
    RuntimeOpenViewerSessionInput, RuntimeProtectedContentPurchaseIntent, RuntimeProviderCallError,
    RuntimePurchaseEffectAuthority, RuntimeReleaseCoordinator, RuntimeReleaseCoordinatorOutcome,
    RuntimeReleaseJournal, RuntimeReleaseTerminalResult, RuntimeRightsProvider,
    RuntimeSelectedProvider, RuntimeVerifiedPurchaseEffect, RuntimeViewerSession,
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
    load_runtime_custody_purchase, load_runtime_media_provider_bridge_config,
    load_runtime_prepared_media_v2, load_runtime_protected_content_chain_provider_config,
    object_protected_content_files, persist_runtime_custody_purchase,
    prepare_runtime_custody_library_source, prepare_runtime_media_provider_prerequisite,
    protected_content_object_manifest_bytes, publish_runtime_custody_library_object,
    publish_runtime_custody_library_object_content, publish_runtime_custody_library_source,
    read_runtime_object_source, register_custody_host_provider, register_custody_provider,
    register_custody_runtime_provider_target, register_protect_provider,
    register_protected_content_decrypt_provider, resolve_runtime_rights_policy,
    runtime_custody_object_chunk_for_read, runtime_media_source_digest, runtime_media_staging_root,
    runtime_mint_journal, runtime_protected_content_id, runtime_purchase_lock_path,
    runtime_purchase_lock_test_overlap_detected, runtime_purchase_path, runtime_viewer_object_path,
    sha256_file, unresolved_release_audit_records, verify_protected_content_object_directory,
    write_owner_only_bytes, InactiveCustodyProvider, InactiveCustodyProviderParts, MediaToolsTrust,
    ObjectFramedStagingSink, RuntimeCustodyAttemptConflict, RuntimeCustodyAttemptConflictReason,
    RuntimeCustodyComposition, RuntimeCustodyCompositionConfigFile,
    RuntimeCustodyConfirmedPurchaseStage, RuntimeCustodyLibraryPublishInput,
    RuntimeCustodyLibraryPublishObjectInput, RuntimeCustodyLibrarySourceInput,
    RuntimeCustodyPurchaseAccessEvidenceRecord, RuntimeCustodyPurchaseProgress,
    RuntimeCustodyPurchaseRecord, RuntimeCustodyPurchaseStageRecord, RuntimeCustodyRegistryAdapter,
    RuntimeCustodyRouteBindingConfig, RuntimeCustodyRouteTransportConfig,
    RuntimeCustodyTerminalPurchaseRecord, RuntimeDecryptRegistryAdapter,
    RuntimeLibraryMediaPreparation, SignedMediaToolDigests,
    CHAIN_PROTECTED_CONTENT_POLICY_SCHEMA_V1, CUSTODY_COMPOSITION_SCHEMA_V1, CUSTODY_PROVIDER_ID,
    CUSTODY_PROVIDER_OPERATIONS, MAX_CHAIN_PROVIDER_CONFIG_BYTES, MEDIA_PROVIDER_CONFIG_SCHEMA_V1,
    MEDIA_PROVIDER_ID, MEDIA_PROVIDER_MAX_INPUT_BYTES_V1, MEDIA_PROVIDER_TIMEOUT_MS_V1,
    PROTECTED_CONTENT_CHAIN_PROVIDER_CONFIG_SCHEMA_V1, PROTECTED_CONTENT_DECRYPT_PROVIDER_ID,
    PROTECTED_CONTENT_DECRYPT_PROVIDER_OPERATIONS, PROTECTED_CONTENT_OBJECT_EPC1_PATH,
    PROTECTED_CONTENT_OBJECT_MANIFEST_PATH, PROTECTED_CONTENT_PROVIDER_STATUS_TIMEOUT,
    PROTECT_PROVIDER_ID, PROTECT_PROVIDER_OPERATIONS, PROTECT_PROVIDER_PROCESS_ID,
    RUNTIME_CUSTODY_AVAILABILITY_UNAVAILABLE_MESSAGE, RUNTIME_CUSTODY_DECRYPT_UNAVAILABLE_MESSAGE,
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
    CencDashRenditionKindV2, CencFmp4MediaIdentityV1, CencMediaSuite,
    ChunkedPayloadObjectIdentityV1, CustodyProtectionHeader, CustodyProviderRequestV1,
    CustodyProviderResponseV1, DecryptProviderRequestV1, DecryptProviderResponseStatusV1,
    DecryptProviderResponseV1, ProtectProviderRequestV1, ProtectProviderResponseStatusV1,
    ProtectProviderResponseV1, ProtectionSessionNodeV1, ProviderFailureCodeV1,
    RightsProviderRequestV1, RightsProviderResponseV1, ValidatedClearFmp4MediaSessionLayoutV1,
    ValidatedCustodyProviderRequestV1, ValidatedDecryptProviderRequestV1,
    ValidatedRightsProviderRequestV1, ViewerMediaPartSelectorV1,
    CUSTODY_PROVIDER_REQUEST_SCHEMA_V1, CUSTODY_PROVIDER_RESPONSE_SCHEMA_V1,
    DECRYPT_PROVIDER_REQUEST_SCHEMA_V1, DECRYPT_PROVIDER_RESPONSE_SCHEMA_V1,
    MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1, PROTECTION, PROTECT_PROVIDER_REQUEST_SCHEMA_V1,
    PROTECT_PROVIDER_RESPONSE_SCHEMA_V1,
};

#[tokio::test]
async fn protected_content_publish_sends_the_exact_one_copy_requirement() {
    let (directory, media) = protected_content_directory(0x41);
    let provider =
        ContentAvailabilityTestProvider::new(0x61, ContentAvailabilityTestConfig::accepted());
    let requirement = availability_requirement(provider.signer_did());
    let registry = ProviderRegistry::new();
    registry
        .register_sub_provider("content", provider.clone())
        .await
        .unwrap();

    publish_and_verify_v1_protected_content_for_test(
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
            "min_replicas": 1,
            "require_live_multi_peer_proof": false,
        }))
    );
    assert!(publish["availability_requirements"]
        .get("max_replicas")
        .is_none());
}

#[tokio::test]
async fn protected_content_publish_rejects_mismatched_policy_or_count_before_provider_use() {
    for (policy, minimum_replicas) in [("wrong-policy", 1), ("wrong-policy", 3)] {
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

        publish_and_verify_v1_protected_content_for_test(
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

/// The creator's Home holds the one required copy: its verified pin is the
/// availability proof, whether or not Carrier announced it to a peer.
#[tokio::test]
async fn protected_content_availability_accepts_the_creator_homes_one_verified_copy() {
    for status in ["local_pinned", "carrier_announced", "network_available"] {
        let config = ContentAvailabilityTestConfig {
            status: status.to_string(),
            replicas: 1,
            live_multi_peer_proof: Some(false),
            ..ContentAvailabilityTestConfig::accepted()
        };
        assert!(
            publish_protected_content_for_test(config, None, None)
                .await
                .is_ok(),
            "{status}"
        );
    }
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
            status: "repair_needed".to_string(),
            ..ContentAvailabilityTestConfig::accepted()
        },
        ContentAvailabilityTestConfig {
            replicas: 0,
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
                super::super::require_custody_provider_status,
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

/// A ledger record written before `confirmed_approval` existed serialized
/// `Pending` with only `confirmed_buy` (both already `skip_serializing_if`,
/// so an unset field was omitted, not written as `null`). Such a record must
/// still deserialize with the new field defaulting to `None`, a record with
/// neither stage confirmed must serialize identically regardless of Runtime
/// version, and a record carrying the pre-upgrade `confirmed_buy` alone must
/// keep deserializing once `confirmed_approval` is added alongside it.
#[test]
fn runtime_custody_purchase_progress_pending_stays_compatible_across_confirmed_approval() {
    // Oldest possible shape: neither field ever existed on disk.
    let bare_pending = json!({ "state": "pending" });
    assert_eq!(
        serde_json::from_value::<RuntimeCustodyPurchaseProgress>(bare_pending.clone()).unwrap(),
        RuntimeCustodyPurchaseProgress::Pending {
            confirmed_approval: None,
            confirmed_buy: None,
        }
    );
    // ... and a record with neither stage confirmed still serializes to
    // exactly that shape today, so a no-op resave never rewrites bytes an
    // operator or diff tool would see as changed.
    assert_eq!(
        serde_json::to_value(RuntimeCustodyPurchaseProgress::Pending {
            confirmed_approval: None,
            confirmed_buy: None,
        })
        .unwrap(),
        bare_pending
    );

    // Pre-upgrade shape: only `confirmed_buy` was ever recorded.
    let confirmed_buy = sample_confirmed_purchase_stage();
    let pre_upgrade_json = json!({
        "state": "pending",
        "confirmed_buy": serde_json::to_value(&confirmed_buy).unwrap(),
    });
    let deserialized: RuntimeCustodyPurchaseProgress = serde_json::from_value(
        pre_upgrade_json.clone(),
    )
    .expect("a Pending record written before confirmed_approval existed must still deserialize");
    assert_eq!(
        deserialized,
        RuntimeCustodyPurchaseProgress::Pending {
            confirmed_approval: None,
            confirmed_buy: Some(confirmed_buy.clone()),
        }
    );
    assert_eq!(
        serde_json::to_value(&deserialized).unwrap(),
        pre_upgrade_json,
        "a pre-upgrade record with only confirmed_buy set must round-trip byte-identically"
    );

    // Once populated, both stages round-trip and remain independently legible.
    let confirmed_approval = sample_confirmed_purchase_stage();
    let both_confirmed = RuntimeCustodyPurchaseProgress::Pending {
        confirmed_approval: Some(confirmed_approval.clone()),
        confirmed_buy: Some(confirmed_buy.clone()),
    };
    let round_tripped: RuntimeCustodyPurchaseProgress =
        serde_json::from_value(serde_json::to_value(&both_confirmed).unwrap()).unwrap();
    assert_eq!(round_tripped, both_confirmed);
}

#[cfg(unix)]
#[test]
fn load_runtime_custody_purchase_refuses_symlinked_record() {
    let dir = tempfile::tempdir().unwrap();
    owner_only_dir(dir.path());
    let (principal, mint_id, record) = sample_purchase_record();
    persist_runtime_custody_purchase(dir.path(), &record).unwrap();
    let path = runtime_purchase_path(dir.path(), &principal, mint_id);
    let real = path.with_extension("real");
    std::fs::rename(&path, &real).unwrap();
    std::os::unix::fs::symlink(&real, &path).unwrap();
    assert!(load_runtime_custody_purchase(dir.path(), &principal, mint_id).is_err());
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
async fn runtime_rights_adapter_invokes_chain_not_any_capsule_sub_provider() {
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
        "library",
        json!({"status": "ok", "data": {"echo": "unrelated-capsule-provider"}}),
    );
    registry
        .register_sub_provider("library", rights.clone())
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
    assert_eq!(schemes, vec!["chain".to_string(), "library".to_string()]);
}

// Plan B T1.7 (L10, L15): the custody wrapper admits ops from the custody
// surface and rate-limits releases in two stages.

/// Plan B POOL-MINT (trusted binding): a share for a pool this Home does not
/// serve, under an attacker's self-signed descriptor naming this node's key,
/// never reaches the provider: this Home holds no root for that pool.
#[cfg(unix)]
#[tokio::test]
async fn guard_pool_provisioning_for_a_pool_this_home_does_not_serve_is_refused_before_the_provider(
) {
    use crate::custody_surface::OP_CUSTODY_PROVISION_POOL_NODE_SHARE;
    use elastos_protected_content_contracts::test_fixtures::{
        pool_bundle, pool_descriptor_signed_by, pool_mint_share, pool_provisioning_record,
        runtime_custody_provisioning,
    };
    use elastos_protected_content_contracts::{
        ContentAccessIdV1, Digest32, EncryptedContentIdentityV1, PoolDidV1,
        SignedPoolDescriptorAnyV1,
    };
    fn xwing(
        seed: u8,
    ) -> [u8; elastos_protected_content_contracts::PQ_HYBRID_WRAP_PUBLIC_KEY_BYTES] {
        use x_wing::kem::Decapsulator as _;
        use x_wing::KeyExport as _;
        let secret = x_wing::DecapsulationKey::from([seed; x_wing::DECAPSULATION_KEY_SIZE]);
        secret.encapsulation_key().to_bytes().into()
    }
    let now = crate::auth::now_ts();
    let bundle = pool_bundle(xwing, now);
    let content = EncryptedContentIdentityV1::new(Digest32::new([0x11; 32]), 4096).unwrap();
    let record = pool_provisioning_record(&bundle, &content, 1);
    let attacker: SignedPoolDescriptorAnyV1 =
        pool_descriptor_signed_by(&bundle, 1, now, 0x66).into();
    let pool: PoolDidV1 = *attacker.pool();
    let request = elastos_protected_content_provider_contracts::PoolCustodyRequestV1::new_provision_pool_node_share(
        &record,
        &runtime_custody_provisioning(&record, 0x66, 0xf1, now),
        &pool_mint_share(
            pool,
            record.key_envelope_identity(),
            ContentAccessIdV1::new([0x41; 16]).unwrap(),
            0x66,
        ),
        &attacker,
    )
    .unwrap();
    let wrapper = ScriptedCustodyWrapper::start().await;
    let response = wrapper
        .send(
            serde_json::from_slice(&request.to_json_vec().unwrap()).unwrap(),
            custody_carrier_envelope(OP_CUSTODY_PROVISION_POOL_NODE_SHARE, 0x66),
        )
        .await
        .unwrap();
    assert_eq!(response["code"], "provisioning_refused", "{response}");
    assert_eq!(
        wrapper.forwarded_count(OP_CUSTODY_PROVISION_POOL_NODE_SHARE),
        0
    );
}

#[cfg(unix)]
#[tokio::test]
async fn sign_pool_statement_over_carrier_is_refused() {
    use crate::custody_surface::{
        OP_CUSTODY_RELEASE_POOL_CONTRIBUTION, OP_CUSTODY_SIGN_POOL_STATEMENT,
    };
    let wrapper = ScriptedCustodyWrapper::start().await;
    let statement = json!({"op": OP_CUSTODY_SIGN_POOL_STATEMENT});

    let error = wrapper
        .send(
            statement.clone(),
            custody_carrier_envelope(OP_CUSTODY_SIGN_POOL_STATEMENT, 0x61),
        )
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("op is local to the Runtime"),
        "{error}"
    );
    assert!(wrapper.forwarded().is_empty());

    for op in [
        ATTEST_REMOTE_SEAL_UPLOAD_OP,
        AUTHORIZE_REMOTE_SEAL_SHARE_OP,
        SIGN_REMOTE_SEAL_COMPLETION_OP,
    ] {
        let error = wrapper
            .send(json!({"op": op}), custody_carrier_envelope(op, 0x61))
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("op is local to the Runtime"),
            "{error}"
        );
    }
    assert!(wrapper.forwarded().is_empty());

    // The Runtime itself may ask its node for the signature.
    let signed = wrapper
        .send(
            statement,
            custody_local_envelope(OP_CUSTODY_SIGN_POOL_STATEMENT),
        )
        .await
        .unwrap();
    assert_eq!(signed["status"], "ok");
    // A pool release is a Carrier op.
    let released = wrapper
        .send(
            json!({"op": OP_CUSTODY_RELEASE_POOL_CONTRIBUTION}),
            custody_carrier_envelope(OP_CUSTODY_RELEASE_POOL_CONTRIBUTION, 0x61),
        )
        .await
        .unwrap();
    assert_eq!(released["status"], "ok");
    let forwarded = wrapper.forwarded();
    assert_eq!(forwarded.len(), 2);
    assert_eq!(forwarded[0]["op"], OP_CUSTODY_SIGN_POOL_STATEMENT);
    assert_eq!(forwarded[1]["op"], OP_CUSTODY_RELEASE_POOL_CONTRIBUTION);
    assert!(forwarded
        .iter()
        .all(|frame| frame.get("_runtime_invocation").is_none()));
}

#[cfg(unix)]
#[tokio::test]
async fn burst_from_one_endpoint_returns_rate_limited() {
    use crate::custody_surface::{
        OP_CUSTODY_RELEASE_CONTRIBUTION, OP_CUSTODY_RELEASE_POOL_CONTRIBUTION,
    };
    let wrapper = ScriptedCustodyWrapper::start().await;
    for index in 0..endpoint_budget() {
        let op = if index % 2 == 0 {
            OP_CUSTODY_RELEASE_CONTRIBUTION
        } else {
            OP_CUSTODY_RELEASE_POOL_CONTRIBUTION
        };
        let response = wrapper
            .send(json!({"op": op}), custody_carrier_envelope(op, 0x61))
            .await
            .unwrap();
        assert_eq!(response["status"], "ok", "call {index}");
    }
    let refused = wrapper
        .send(
            json!({"op": OP_CUSTODY_RELEASE_CONTRIBUTION}),
            custody_carrier_envelope(OP_CUSTODY_RELEASE_CONTRIBUTION, 0x61),
        )
        .await
        .unwrap();
    assert_rate_limited(&refused);
    // The refused call never reached the capsule.
    assert_eq!(wrapper.forwarded().len(), endpoint_budget());

    // Another endpoint has its own budget.
    let other = wrapper
        .send(
            json!({"op": OP_CUSTODY_RELEASE_CONTRIBUTION}),
            custody_carrier_envelope(OP_CUSTODY_RELEASE_CONTRIBUTION, 0x62),
        )
        .await
        .unwrap();
    assert_eq!(other["status"], "ok");
}

#[cfg(unix)]
#[tokio::test]
async fn endpoint_budget_counts_at_entry() {
    use crate::custody_surface::OP_CUSTODY_EVALUATE;
    let wrapper = ScriptedCustodyWrapper::start().await;
    wrapper.refuse_prepare("rights_denied");
    let request = custody_evaluate_request();
    for index in 0..endpoint_budget() {
        let error = wrapper
            .send(
                request.clone(),
                custody_carrier_envelope(OP_CUSTODY_EVALUATE, 0x63),
            )
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("rights_denied"),
            "call {index}: {error}"
        );
    }
    // Every refused prepare spent the endpoint's budget: the next call stops
    // at entry, before the capsule.
    let refused = wrapper
        .send(request, custody_carrier_envelope(OP_CUSTODY_EVALUATE, 0x63))
        .await
        .unwrap();
    assert_rate_limited(&refused);
    assert_eq!(
        wrapper.forwarded_count("prepare_evidence"),
        endpoint_budget()
    );
    assert_eq!(wrapper.forwarded_count("settle_evidence"), 0);
    assert_eq!(wrapper.chain_reads().await, 0);
}

#[cfg(unix)]
#[tokio::test]
async fn wallet_and_kid_budgets_count_only_after_prepare_accepts() {
    use crate::custody_surface::OP_CUSTODY_EVALUATE;
    let wrapper = ScriptedCustodyWrapper::start().await;
    let request = custody_evaluate_request();
    // Each call comes from its own endpoint, so only the rights budgets bind.
    let mut endpoint = 0x10_u8;
    let mut next_envelope = || {
        endpoint += 1;
        custody_carrier_envelope(OP_CUSTODY_EVALUATE, endpoint)
    };

    wrapper.refuse_prepare("rights_denied");
    let refused_prepares = wallet_budget() + 5;
    for _ in 0..refused_prepares {
        wrapper
            .send(request.clone(), next_envelope())
            .await
            .unwrap_err();
    }
    assert_eq!(wrapper.chain_reads().await, 0);

    // The refused prepares spent nothing of the wallet's budget.
    wrapper.accept_prepare();
    for index in 0..wallet_budget() {
        let response = wrapper
            .send(request.clone(), next_envelope())
            .await
            .unwrap();
        assert_eq!(response["status"], "ok", "call {index}: {response}");
    }
    assert_eq!(wrapper.chain_reads().await, wallet_budget());

    // The wallet's budget is spent after an accepted prepare and before the
    // chain read.
    let refused = wrapper.send(request, next_envelope()).await.unwrap();
    assert_rate_limited(&refused);
    assert_eq!(wrapper.chain_reads().await, wallet_budget());
    assert_eq!(
        wrapper.forwarded_count("prepare_evidence"),
        refused_prepares + wallet_budget() + 1
    );
    assert_eq!(wrapper.forwarded_count("settle_evidence"), wallet_budget());
}

#[cfg(unix)]
#[tokio::test]
async fn local_plane_calls_share_one_bucket() {
    use crate::custody_surface::{
        OP_CUSTODY_EVALUATE, OP_CUSTODY_RELEASE_CONTRIBUTION, OP_CUSTODY_RELEASE_POOL_CONTRIBUTION,
        OP_CUSTODY_SIGN_POOL_STATEMENT,
    };
    let wrapper = ScriptedCustodyWrapper::start().await;
    // A statement signature is not a release and spends no budget.
    for _ in 0..5 {
        let response = wrapper
            .send(
                json!({"op": OP_CUSTODY_SIGN_POOL_STATEMENT}),
                custody_local_envelope(OP_CUSTODY_SIGN_POOL_STATEMENT),
            )
            .await
            .unwrap();
        assert_eq!(response["status"], "ok");
    }
    // Releases from every local caller share the key `runtime-local`.
    wrapper.refuse_prepare("rights_denied");
    let evaluate = custody_evaluate_request();
    for index in 0..endpoint_budget() {
        let result = match index % 3 {
            0 => {
                wrapper
                    .send(
                        json!({"op": OP_CUSTODY_RELEASE_CONTRIBUTION}),
                        custody_local_envelope(OP_CUSTODY_RELEASE_CONTRIBUTION),
                    )
                    .await
            }
            1 => {
                wrapper
                    .send(
                        json!({"op": OP_CUSTODY_RELEASE_POOL_CONTRIBUTION}),
                        custody_local_envelope(OP_CUSTODY_RELEASE_POOL_CONTRIBUTION),
                    )
                    .await
            }
            _ => {
                wrapper
                    .send(
                        evaluate.clone(),
                        custody_local_envelope(OP_CUSTODY_EVALUATE),
                    )
                    .await
            }
        };
        if let Ok(response) = result {
            assert_ne!(response["code"], "rate_limited", "call {index}");
        }
    }
    let refused = wrapper
        .send(
            json!({"op": OP_CUSTODY_RELEASE_POOL_CONTRIBUTION}),
            custody_local_envelope(OP_CUSTODY_RELEASE_POOL_CONTRIBUTION),
        )
        .await
        .unwrap();
    assert_rate_limited(&refused);
    // A Carrier endpoint keeps its own budget.
    let carrier = wrapper
        .send(
            json!({"op": OP_CUSTODY_RELEASE_CONTRIBUTION}),
            custody_carrier_envelope(OP_CUSTODY_RELEASE_CONTRIBUTION, 0x64),
        )
        .await
        .unwrap();
    assert_eq!(carrier["status"], "ok");
}

#[cfg(unix)]
#[tokio::test]
async fn v2_evaluate_runs_no_chain_read_for_unknown_envelope() {
    use crate::custody_surface::OP_CUSTODY_EVALUATE;
    // The capsule refuses `prepare_evidence` for an item it holds no share
    // of (T1.5 `guard_unknown_envelope_refused_before_chain_request`). The frame
    // carries a real V2 operation.
    let request = custody_v2_evaluate_request();
    let bytes: Vec<u8> =
        serde_json::from_value(request["signed_runtime_release_operation"].clone()).unwrap();
    assert!(matches!(
        elastos_protected_content_contracts::RuntimeReleaseOperationAnyV1::from_canonical_bytes(
            &bytes
        )
        .unwrap(),
        elastos_protected_content_contracts::RuntimeReleaseOperationAnyV1::V2(_)
    ));
    let wrapper = ScriptedCustodyWrapper::start().await;
    wrapper.refuse_prepare("unknown_envelope");
    let error = wrapper
        .send(request, custody_local_envelope(OP_CUSTODY_EVALUATE))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("unknown_envelope"), "{error}");
    assert_eq!(wrapper.chain_reads().await, 0);
    assert_eq!(wrapper.forwarded_count("prepare_evidence"), 1);
    assert_eq!(wrapper.forwarded_count("settle_evidence"), 0);
}

#[cfg(unix)]
#[tokio::test]
async fn carrier_status_lists_only_carrier_ops() {
    use crate::custody_surface::{
        OP_CUSTODY_EVALUATE, OP_CUSTODY_PROVISION_NODE_SHARE, OP_CUSTODY_PROVISION_POOL_NODE_SHARE,
        OP_CUSTODY_RELEASE_CONTRIBUTION, OP_CUSTODY_RELEASE_POOL_CONTRIBUTION,
        OP_CUSTODY_SIGN_POOL_STATEMENT, OP_CUSTODY_STATUS,
    };
    let wrapper = ScriptedCustodyWrapper::start().await;
    let carrier = wrapper
        .send(
            json!({"op": OP_CUSTODY_STATUS}),
            custody_carrier_envelope(OP_CUSTODY_STATUS, 0x64),
        )
        .await
        .unwrap();
    assert_eq!(
        carrier["data"]["supported_operations"],
        json!([
            OP_CUSTODY_STATUS,
            OP_CUSTODY_PROVISION_NODE_SHARE,
            OP_CUSTODY_RELEASE_CONTRIBUTION,
            OP_CUSTODY_EVALUATE,
            OP_CUSTODY_RELEASE_POOL_CONTRIBUTION,
            OP_CUSTODY_PROVISION_POOL_NODE_SHARE,
        ])
    );
    // A local caller keeps the Runtime-local op too.
    let local = wrapper
        .send(
            json!({"op": OP_CUSTODY_STATUS}),
            custody_local_envelope(OP_CUSTODY_STATUS),
        )
        .await
        .unwrap();
    assert_eq!(
        local["data"]["supported_operations"],
        json!([
            OP_CUSTODY_STATUS,
            OP_CUSTODY_PROVISION_NODE_SHARE,
            OP_CUSTODY_RELEASE_CONTRIBUTION,
            OP_CUSTODY_EVALUATE,
            OP_CUSTODY_RELEASE_POOL_CONTRIBUTION,
            OP_CUSTODY_SIGN_POOL_STATEMENT,
            OP_CUSTODY_PROVISION_POOL_NODE_SHARE,
        ])
    );
}

/// PM-F2 (b): a new V1 share takes new bytes, so a full host maximum refuses
/// it before the provider, as it refuses a pool share.
#[cfg(unix)]
#[tokio::test]
async fn guard_a_new_v1_share_at_a_full_host_maximum_is_refused_with_storage_full() {
    let host = HostShareWriteFixture::start(Some(u64::MAX)).await;
    let stored = host
        .provider
        .send_raw(&host.v1_share_request(0x11))
        .await
        .unwrap();
    assert_eq!(stored["status"], "ok", "{stored}");
    let used = host.used_bytes();
    host.set_storage_maximum(Some(used));

    let refused = host
        .provider
        .send_raw(&host.v1_share_request(0x12))
        .await
        .unwrap();
    assert_eq!(
        refused["code"],
        crate::host_trust::HOST_STORAGE_FULL,
        "{refused}"
    );
    assert_eq!(host.used_bytes(), used);
}

/// PM-F2 (b): a WCI host without a storage maximum refuses V1 shares too
/// (fail closed): no V1 exemption.
#[cfg(unix)]
#[tokio::test]
async fn guard_a_new_v1_share_without_a_host_maximum_is_refused_with_storage_max_unset() {
    let host = HostShareWriteFixture::start(None).await;
    let refused = host
        .provider
        .send_raw(&host.v1_share_request(0x11))
        .await
        .unwrap();
    assert_eq!(
        refused["code"],
        crate::host_trust::HOST_STORAGE_MAX_UNSET,
        "{refused}"
    );
    assert_eq!(host.used_bytes(), 0);
}

/// PM-F2 (b): an exact V1 retry fills no new slot, so it is not charged: at
/// a full maximum the stored receipt still comes back.
#[cfg(unix)]
#[tokio::test]
async fn a_v1_exact_retry_at_a_full_host_maximum_gets_its_stored_receipt_back() {
    let host = HostShareWriteFixture::start(Some(u64::MAX)).await;
    let request = host.v1_share_request(0x11);
    let stored = host.provider.send_raw(&request).await.unwrap();
    assert_eq!(stored["status"], "ok", "{stored}");
    let used = host.used_bytes();
    host.set_storage_maximum(Some(used));

    let retried = host.provider.send_raw(&request).await.unwrap();
    assert_eq!(retried, stored);
    assert_eq!(host.used_bytes(), used);
}

#[tokio::test]
async fn runtime_rights_adapter_fails_closed_without_chain_and_does_not_call_rights() {
    let registry = Arc::new(ProviderRegistry::new());
    let rights = RecordingProvider::new(
        "library",
        json!({"status": "ok", "data": {"echo": "unrelated-capsule-provider"}}),
    );
    registry
        .register_sub_provider("library", rights.clone())
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
    assert_eq!(schemes, vec!["library".to_string()]);
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

/// A NEW protect output must carry the protection header. The box ships in a
/// public media file and a client reading the artifacts directly routes on it, so
/// a provider that omits it never reaches publish. (Absence stays legal on the
/// READ path - `media_structure_admits_only_a_well_formed_elacity_pssh_in_moov`
/// pins that an init segment without one still validates.)
#[cfg(unix)]
#[tokio::test]
async fn runtime_custody_library_publish_rejects_a_protect_output_with_no_protection_header() {
    let error = library_publish_error_with_steered_protection_header(
        "person:local:runtime-custody-missing-protection-header",
        |_, _, protected_init| replace_protection_header(&protected_init, &[]),
    )
    .await;
    assert!(
        error.contains("Runtime custody protect output is invalid"),
        "{error}"
    );
}

/// The header must name THIS session's custody quorum. A structurally perfect box
/// that points a future client at some other pool is refused, in every rendition.
#[cfg(unix)]
#[tokio::test]
async fn runtime_custody_library_publish_rejects_a_protection_header_naming_another_pool() {
    let error = library_publish_error_with_steered_protection_header(
        "person:local:runtime-custody-foreign-protection-pool",
        |intent, _, protected_init| {
            let foreign_pool = CustodyPoolIdentityV1::new(Digest32::new([0xee; 32]), 512).unwrap();
            assert_ne!(foreign_pool, intent.custody_pool());
            let foreign_header = CustodyProtectionHeader::new(
                intent.content_access_id(),
                &foreign_pool,
                &intent.custody_epoch(),
                &intent.custody_committee_authorization(),
                CencMediaSuite::DashV2,
            );
            replace_protection_header(
                &protected_init,
                &PROTECTION.encode_custody(&foreign_header).unwrap(),
            )
        },
    )
    .await;
    assert!(
        error.contains("Runtime custody protect output is invalid"),
        "{error}"
    );
}

/// One item has one custody binding: inits whose headers differ only in the
/// epoch they name are refused, even though each is well formed on its own.
#[cfg(unix)]
#[tokio::test]
async fn runtime_custody_library_publish_rejects_inits_whose_headers_differ_only_in_epoch() {
    let error = library_publish_error_with_steered_protection_header(
        "person:local:runtime-custody-split-protection-epoch",
        |intent, position, protected_init| {
            if position == 0 {
                return protected_init;
            }
            let other_epoch = elastos_protected_content_contracts::CustodyEpochIdentityV1::new(
                Digest32::new([0xdd; 32]),
                512,
            )
            .unwrap();
            assert_ne!(other_epoch, intent.custody_epoch());
            let header = CustodyProtectionHeader::new(
                intent.content_access_id(),
                &intent.custody_pool(),
                &other_epoch,
                &intent.custody_committee_authorization(),
                CencMediaSuite::DashV2,
            );
            replace_protection_header(
                &protected_init,
                &PROTECTION.encode_custody(&header).unwrap(),
            )
        },
    )
    .await;
    assert!(
        error.contains("Runtime custody protect output is invalid"),
        "{error}"
    );
}

/// A new mint is produced only by the active encoder: an init whose (otherwise
/// honest) header sits in a box of a retired, decode-only system is refused.
#[cfg(unix)]
#[tokio::test]
async fn runtime_custody_library_publish_rejects_a_header_written_by_a_retired_system() {
    let error = library_publish_error_with_steered_protection_header(
        "person:local:runtime-custody-retired-system",
        |_, _, protected_init| {
            let retired = PROTECTION
                .registry()
                .systems()
                .iter()
                .find(|system| system.is_custody() && !system.can_encode())
                .expect("a decode-only custody system is registered")
                .id;
            let (start, _, _) = elastos_protection_box_span(&protected_init);
            let mut steered = protected_init;
            steered[start + 12..start + 28].copy_from_slice(retired.as_bytes());
            steered
        },
    )
    .await;
    assert!(
        error.contains("Runtime custody protect output is invalid"),
        "{error}"
    );
}

#[cfg(unix)]
#[test]
fn object_source_above_the_old_cap_is_read() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    let principal_id = "person:local:object-source";
    let object_uri = format!(
        "{}/Documents/large.bin",
        crate::auth::principal_localhost_root(principal_id)
    );
    let source = temp.path().join("large.bin");
    let length = 64 * 1024 * 1024 + 1;
    fs::write(&source, vec![0x7au8; length]).unwrap();
    fs::set_permissions(&source, fs::Permissions::from_mode(0o600)).unwrap();
    let bytes = read_runtime_object_source(&data_dir, principal_id, &object_uri, &source).unwrap();
    assert_eq!(bytes.len(), length);

    let empty = temp.path().join("empty.bin");
    fs::write(&empty, b"").unwrap();
    fs::set_permissions(&empty, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(read_runtime_object_source(&data_dir, principal_id, &object_uri, &empty).is_err());
}

#[test]
fn listing_package_requires_exactly_one_identity_field_of_the_matching_kind() {
    let (_, object_package) = object_listing_package_for_test(0x72);
    let media_package = runtime_custody_listing_record_for_test(
        Digest32::new([0x73; 32]),
        "person:local:media-listing",
        "media-listing",
        NOW,
    )
    .package;
    media_package
        .decode_and_validate()
        .expect("the media control package must still decode");
    object_package
        .decode_and_validate()
        .expect("the object control package must still decode");

    let mut both = object_package.clone();
    both.media_identity_base64 = media_package.media_identity_base64.clone();
    assert!(
        both.decode_and_validate().is_err(),
        "a package carrying both identity fields must fail closed"
    );

    let mut neither = object_package.clone();
    neither.content_identity_base64 = None;
    assert!(
        neither.decode_and_validate().is_err(),
        "a package carrying no identity field must fail closed"
    );

    // A media identity smuggled into the object field is a cross-kind
    // encoding: media has exactly one canonical home, `media_identity_base64`.
    let media_identity = match media_package
        .decode_and_validate()
        .unwrap()
        .content_identity
    {
        RuntimeContentIdentityV1::Media(media) => media,
        RuntimeContentIdentityV1::Object(_) | RuntimeContentIdentityV1::MediaDash(_) => {
            panic!("the control package is media")
        }
    };
    let mut smuggled = media_package.clone();
    smuggled.media_identity_base64 = None;
    smuggled.content_identity_base64 = Some(
        base64::engine::general_purpose::STANDARD.encode(
            RuntimeContentIdentityV1::Media(media_identity)
                .canonical_bytes()
                .unwrap(),
        ),
    );
    assert!(
        smuggled.decode_and_validate().is_err(),
        "a media identity carried under content_identity_base64 must fail closed"
    );

    // An unknown kind discriminant is corrupt, never a default.
    let mut unknown_kind = object_package.clone();
    let mut raw = base64::engine::general_purpose::STANDARD
        .decode(object_package.content_identity_base64.as_deref().unwrap())
        .unwrap();
    raw[0] = 0x03;
    unknown_kind.content_identity_base64 =
        Some(base64::engine::general_purpose::STANDARD.encode(raw));
    assert!(
        unknown_kind.decode_and_validate().is_err(),
        "an unknown content-identity kind byte must fail closed"
    );
}

/// Widening the typed layer must not change a single message the
/// string-returning callers have always produced.
#[test]
fn classified_failures_format_exactly_as_before() {
    assert_eq!(
        super::ProviderInvocationFailure::NotCompleted {
            detail: "boom".to_string(),
        }
        .into_message("custody", "provision_node_share"),
        "custody provider provision_node_share invocation failed: boom"
    );
    assert_eq!(
        super::ProviderInvocationFailure::Refused {
            code: "rights_denied".to_string(),
            message: "no".to_string(),
        }
        .into_message("custody", "provision_node_share"),
        "custody provider provision_node_share rejected the request: rights_denied: no"
    );
    assert_eq!(
        super::ProviderInvocationFailure::MalformedResponse {
            detail: "custody provider provision_node_share response is missing data".to_string(),
        }
        .into_message("custody", "provision_node_share"),
        "custody provider provision_node_share response is missing data"
    );
}

// --- Read after a buy: the shared read dataset and adopted listings -------

#[test]
fn shared_read_dataset_is_none_without_an_elastos_protection() {
    // What an ela.city (Lit) mint writes: no `asset`, a bare-hex `kid`, and
    // the protection named only in `media.protectionType`.
    let lit = json!({
        "name": "Tradingviewww",
        "media": {
            "uri": "ipfs://QmPczy2mXWn2eVeN4e7wsScLEaKgbrEu2BUBGrniNAThFN",
            "contentType": "video",
            "protectionType": ["cenc:lit-aes-gcm-v3"],
        },
        "properties": { "publisher": SHARED_PUBLISHER },
        "kid": "facabcf1ea699570a8409db83779ae5c",
    });
    assert!(crate::protected_content_market::shared_read_dataset(&lit)
        .unwrap()
        .is_none());

    // An ElastOS entry that cannot be adopted is ours, not foreign (R12).
    let media_package = media_listing_package_for_shared_test();
    let document =
        shared_metadata_from_producer(&SharedIdentities::of_package(&media_package, "video/mp4"));
    let mut v0 = document.clone();
    v0["asset"]["protections"][0] = json!({
        "protectionType": "cenc:elastos-pq-hybrid-threshold-v0",
        "algorithm": "x",
        "shares": [],
    });
    assert!(crate::protected_content_market::shared_read_dataset(&v0).is_err());
    let mut missing = document;
    missing["asset"]["protections"][0]
        .as_object_mut()
        .unwrap()
        .remove("key_envelope_identity_base64");
    assert!(crate::protected_content_market::shared_read_dataset(&missing).is_err());
}

#[test]
fn shared_read_dataset_refuses_a_kind_prefixed_media_identity() {
    let media_package = media_listing_package_for_shared_test();
    let media = match media_package
        .decode_and_validate()
        .unwrap()
        .content_identity
    {
        RuntimeContentIdentityV1::Media(media) => media,
        RuntimeContentIdentityV1::Object(_) | RuntimeContentIdentityV1::MediaDash(_) => {
            panic!("the control package is media")
        }
    };
    let mut identities = SharedIdentities::of_package(&media_package, "video/mp4");
    identities.content_identity = base64::engine::general_purpose::STANDARD.encode(
        RuntimeContentIdentityV1::Media(media)
            .canonical_bytes()
            .unwrap(),
    );
    let document = shared_metadata_from_producer(&identities);
    assert!(
        crate::protected_content_market::shared_read_dataset(&document).is_err(),
        "a media identity has exactly one encoding: the bare one"
    );
}

#[tokio::test]
async fn open_finality_progress_is_silent_once_the_grant_is_finalized() {
    let now = 10_000;
    let (progress, requests) = finality_progress_with(
        vec![Ok(finality_access_answer(
            &finality_request("finalized"),
            true,
        ))],
        now - 120,
        now,
    )
    .await;
    assert!(progress.is_none());
    assert_eq!(requests.len(), 1);
}

/// OPEN-LOOP OP2 (a): finality is read before any Wallet request however
/// long ago the copy confirmed; a copy still waiting for it answers
/// `finalizing` rather than a prompt that cannot lead to a release.
#[tokio::test]
async fn open_finality_progress_reads_the_chain_however_long_ago_the_copy_confirmed() {
    let now = 100_000;
    let (progress, requests) = finality_progress_with(
        vec![
            Ok(finality_unbound_answer()),
            Ok(finality_access_answer(&finality_request("latest"), true)),
        ],
        now - super::RUNTIME_CUSTODY_FINALITY_WATCH_SECS - 1,
        now,
    )
    .await;
    assert_eq!(
        progress.expect("still finalizing").as_json()["stage"],
        "finalizing"
    );
    assert_eq!(requests.len(), 2);
}

/// No grant at the head either: that is not a finality wait, and the open
/// goes on to let custody give its own answer.
#[tokio::test]
async fn open_finality_progress_is_silent_when_the_head_has_no_grant_either() {
    let now = 10_000;
    let (progress, requests) = finality_progress_with(
        vec![
            Ok(finality_access_answer(
                &finality_request("finalized"),
                false,
            )),
            Ok(finality_access_answer(&finality_request("latest"), false)),
        ],
        now - 120,
        now,
    )
    .await;
    assert!(progress.is_none());
    assert_eq!(requests.len(), 2);
}

/// A chain read that fails adds no new way for an open to fail: the open
/// carries on exactly as it did before this check existed.
#[tokio::test]
async fn open_finality_progress_is_silent_when_the_chain_cannot_answer() {
    let now = 10_000;
    let (progress, requests) = finality_progress_with(
        vec![Err(ProviderError::Provider("rpc unavailable".to_string()))],
        now - 120,
        now,
    )
    .await;
    assert!(progress.is_none());
    assert_eq!(requests.len(), 1);
}

/// The archive directory's date, at the edges the civil-date arithmetic has to
/// get right: the epoch, a leap day, a year's last day, and a plain day.
#[test]
fn archive_dates_are_civil_utc_dates() {
    for (secs, stamp) in [
        (0, "19700101"),
        (951_782_400, "20000229"),
        (1_735_689_599, "20241231"),
        (1_793_275_200, "20261029"),
    ] {
        assert_eq!(super::utc_date_stamp(secs), stamp, "{secs}");
    }
}

// ---------------------------------------------------------------------------
// DASH v2 read side (T8b)
// ---------------------------------------------------------------------------

/// Compact clear-fMP4 builders and the real CENC protection of a v2 package,
/// shared with T10. The builders are copied from the custody crate's own v2
/// test media (`protect.rs`), which cannot be imported across crates; the
/// protection goes through the custody crate's public protect functions, so
/// the ciphertext and the pssh in every init are real.
pub(crate) mod media_dash_fixture {
    use elastos_protected_content_contracts::{
        ContentAccessIdV1, CustodyCommitteeAuthorizationIdentityV1, CustodyEpochIdentityV1,
        CustodyPoolIdentityV1, Digest32,
    };
    use elastos_protected_content_custody::{
        protect_validated_clear_fmp4_init_to_cenc_v2,
        protect_validated_clear_fmp4_segment_to_cenc_v2, ContentEncryptionKeyV1,
    };
    use elastos_protected_content_provider_contracts::{
        CencDashMediaIdentityV2, CencDashRenditionBytesV2, CencDashRenditionKindV2,
        CencLayoutProfile, CencMediaSuite, CustodyProtectionHeader,
        ValidatedClearFmp4MediaSessionLayoutV1,
    };

    pub(crate) const V: CencDashRenditionKindV2 = CencDashRenditionKindV2::Video;
    pub(crate) const A: CencDashRenditionKindV2 = CencDashRenditionKindV2::Audio;
    const TIMESCALE: u32 = 15360;
    const DEFAULT_DURATION: u32 = 512;
    const TFHD_FLAGS_BENTO4: u32 = 0x02002a;
    const TRUN_FLAGS_OFFSET_SIZE: u32 = 0x000201;
    const IV_PREFIX: [u8; 4] = [0x11; 4];

    pub(crate) fn bx(box_type: &[u8; 4], content: &[u8]) -> Vec<u8> {
        let mut out = ((8 + content.len()) as u32).to_be_bytes().to_vec();
        out.extend_from_slice(box_type);
        out.extend_from_slice(content);
        out
    }

    fn fbx(box_type: &[u8; 4], version: u8, flags: u32, payload: &[u8]) -> Vec<u8> {
        let mut content = vec![version];
        content.extend_from_slice(&flags.to_be_bytes()[1..]);
        content.extend_from_slice(payload);
        bx(box_type, &content)
    }

    /// A one-track clear init: `avc1` (640x360, `avcC` NAL length 4) or `mp4a`.
    pub(crate) fn init(kind: CencDashRenditionKindV2, track_id: u32) -> Vec<u8> {
        let mut tkhd = vec![0u8; 12];
        tkhd[8..12].copy_from_slice(&track_id.to_be_bytes());
        let mut mdhd = vec![0u8; 20];
        mdhd[8..12].copy_from_slice(&TIMESCALE.to_be_bytes());
        let (handler, entry_type, entry) = match kind {
            V => {
                let mut entry = vec![0u8; 78];
                entry[24..26].copy_from_slice(&640u16.to_be_bytes());
                entry[26..28].copy_from_slice(&360u16.to_be_bytes());
                entry.extend_from_slice(&bx(b"avcC", &[1, 0x64, 0, 0x1f, 0xff, 0xe0, 0]));
                (b"vide", b"avc1", entry)
            }
            A => {
                let mut entry = vec![0u8; 28];
                entry[16..18].copy_from_slice(&2u16.to_be_bytes());
                entry[24..28].copy_from_slice(&(48_000u32 << 16).to_be_bytes());
                (b"soun", b"mp4a", entry)
            }
        };
        let mut hdlr = vec![0u8; 4];
        hdlr.extend_from_slice(handler);
        hdlr.extend_from_slice(&[0u8; 13]);
        let mut stsd = vec![0, 0, 0, 0, 0, 0, 0, 1];
        stsd.extend_from_slice(&bx(entry_type, &entry));
        let minf = bx(b"minf", &bx(b"stbl", &bx(b"stsd", &stsd)));
        let mdia = bx(
            b"mdia",
            &[fbx(b"mdhd", 0, 0, &mdhd), fbx(b"hdlr", 0, 0, &hdlr), minf].concat(),
        );
        let trak = bx(b"trak", &[fbx(b"tkhd", 0, 0, &tkhd), mdia].concat());
        let mut trex = track_id.to_be_bytes().to_vec();
        trex.extend_from_slice(&[0u8; 16]);
        let moov = bx(
            b"moov",
            &[
                bx(b"mvhd", &[0u8; 4]),
                trak,
                bx(b"mvex", &fbx(b"trex", 0, 0, &trex)),
            ]
            .concat(),
        );
        [bx(b"ftyp", b"iso6\0\0\0\0iso6dash"), moov].concat()
    }

    /// A length-prefixed (4 bytes) NAL unit of `len` bytes, header byte included.
    pub(crate) fn nal(nal_type: u8, len: usize) -> Vec<u8> {
        let mut out = (len as u32).to_be_bytes().to_vec();
        out.push(0x60 | nal_type);
        out.extend((1..len).map(|index| (index * 7 + 3) as u8));
        out
    }

    /// `moof(mfhd, traf(tfhd tfdt trun))` + `mdat(samples)` with Bento4's `tfhd`.
    pub(crate) fn clear_segment(track_id: u32, decode_time: u64, samples: &[Vec<u8>]) -> Vec<u8> {
        let mut tfhd = track_id.to_be_bytes().to_vec();
        tfhd.extend_from_slice(&1u32.to_be_bytes());
        tfhd.extend_from_slice(&DEFAULT_DURATION.to_be_bytes());
        tfhd.extend_from_slice(&0u32.to_be_bytes());
        let mut trun = (samples.len() as u32).to_be_bytes().to_vec();
        trun.extend_from_slice(&0i32.to_be_bytes());
        for sample in samples {
            trun.extend_from_slice(&(sample.len() as u32).to_be_bytes());
        }
        let tfhd = fbx(b"tfhd", 0, TFHD_FLAGS_BENTO4, &tfhd);
        let tfdt = fbx(b"tfdt", 1, 0, &decode_time.to_be_bytes());
        let trun = fbx(b"trun", 0, TRUN_FLAGS_OFFSET_SIZE, &trun);
        let trun_off = 8 + 16 + 8 + tfhd.len() + tfdt.len();
        let traf = bx(b"traf", &[tfhd, tfdt, trun].concat());
        let mut moof = bx(
            b"moof",
            &[fbx(b"mfhd", 0, 0, &1u32.to_be_bytes()), traf].concat(),
        );
        let data_offset = (moof.len() + 8) as i32;
        moof[trun_off + 16..trun_off + 20].copy_from_slice(&data_offset.to_be_bytes());
        [moof, bx(b"mdat", &samples.concat())].concat()
    }

    /// A video sample: SEI, one IDR/P slice of `slice_len` bytes, a short slice.
    pub(crate) fn video_sample(slice_len: usize) -> Vec<u8> {
        [nal(6, 30), nal(5, slice_len), nal(1, 100)].concat()
    }

    pub(crate) fn audio_sample(seed: u8, len: usize) -> Vec<u8> {
        (0..len)
            .map(|index| seed.wrapping_add(index as u8))
            .collect()
    }

    pub(crate) fn clear_segments(kind: CencDashRenditionKindV2, count: usize) -> Vec<Vec<u8>> {
        (0..count)
            .map(|index| {
                let samples = match kind {
                    V => vec![video_sample(300 + index), video_sample(200)],
                    A => vec![audio_sample(1, 120), audio_sample(9, 121)],
                };
                clear_segment(1, 1_024 * index as u64, &samples)
            })
            .collect()
    }

    /// Everything one v2 package is made of, before it is laid out in files.
    pub(crate) struct MediaDashComponents {
        pub(crate) kinds: Vec<CencDashRenditionKindV2>,
        pub(crate) protected_inits: Vec<Vec<u8>>,
        pub(crate) protected_segments: Vec<Vec<Vec<u8>>>,
        pub(crate) head: CencDashMediaIdentityV2,
    }

    /// Protects `segments_per_rendition[r]` clear segments of `kinds[r]` under a
    /// fresh content key, one IV counter across the whole media, with a pssh in
    /// each init that names the given custody epoch, and builds the head.
    pub(crate) fn protected_media_dash_components(
        seed: u8,
        kinds: &[CencDashRenditionKindV2],
        segments_per_rendition: &[usize],
        custody_epoch: &CustodyEpochIdentityV1,
    ) -> MediaDashComponents {
        assert_eq!(kinds.len(), segments_per_rendition.len());
        let kid = ContentAccessIdV1::new([seed; 16]).unwrap();
        let header = CustodyProtectionHeader::new(
            kid,
            &CustodyPoolIdentityV1::new(Digest32::new([seed ^ 0x34; 32]), 512).unwrap(),
            custody_epoch,
            &CustodyCommitteeAuthorizationIdentityV1::new(Digest32::new([seed ^ 0x35; 32]), 512)
                .unwrap(),
            CencMediaSuite::DashV2,
        );
        protect_media_dash_clear(
            kid,
            &header,
            &clear_media_dash(kinds, segments_per_rendition),
            &|_, init| init,
        )
    }

    /// The clear media of `kinds[r]` with `segments_per_rendition[r]` segments:
    /// per rendition its init and its segments.
    #[allow(clippy::type_complexity)]
    pub(crate) fn clear_media_dash(
        kinds: &[CencDashRenditionKindV2],
        segments_per_rendition: &[usize],
    ) -> Vec<(CencDashRenditionKindV2, Vec<u8>, Vec<Vec<u8>>)> {
        kinds
            .iter()
            .zip(segments_per_rendition)
            .map(|(kind, count)| (*kind, init(*kind, 1), clear_segments(*kind, *count)))
            .collect()
    }

    /// Protects clear media the way the protect provider does: each init is
    /// rewritten under `header` (then handed to `steer_init`, which a test uses
    /// to tamper with the init a provider returns), each segment is encrypted
    /// under one fresh key with one IV counter across the whole media, and the
    /// head is built over what results.
    #[allow(clippy::type_complexity)]
    pub(crate) fn protect_media_dash_clear(
        kid: ContentAccessIdV1,
        header: &CustodyProtectionHeader,
        clear: &[(CencDashRenditionKindV2, Vec<u8>, Vec<Vec<u8>>)],
        steer_init: &dyn Fn(usize, Vec<u8>) -> Vec<u8>,
    ) -> MediaDashComponents {
        let cek = ContentEncryptionKeyV1::generate().unwrap();
        let mut counter = 0u32;
        let mut inits = Vec::new();
        let mut protected_all = Vec::new();
        let mut timescales = Vec::new();
        for (position, (_, clear_init, clear_segments)) in clear.iter().enumerate() {
            let session = ValidatedClearFmp4MediaSessionLayoutV1::new_with_profile(
                clear_init,
                CencLayoutProfile::V2,
            )
            .unwrap();
            inits.push(steer_init(
                position,
                protect_validated_clear_fmp4_init_to_cenc_v2(&session, clear_init, header, &[])
                    .unwrap(),
            ));
            timescales.push(session.rendition().unwrap().timescale());
            let mut protected = Vec::new();
            for segment in clear_segments {
                let layout = session.validate_segment(segment).unwrap();
                let ivs: Vec<[u8; 8]> = layout
                    .samples()
                    .iter()
                    .map(|_| {
                        counter += 1;
                        let mut iv = [0u8; 8];
                        iv[..4].copy_from_slice(&IV_PREFIX);
                        iv[4..].copy_from_slice(&counter.to_be_bytes());
                        iv
                    })
                    .collect();
                protected.push(
                    protect_validated_clear_fmp4_segment_to_cenc_v2(
                        &session, &layout, segment, &cek, &ivs,
                    )
                    .unwrap(),
                );
            }
            protected_all.push(protected);
        }
        let bytes: Vec<CencDashRenditionBytesV2<'_>> = clear
            .iter()
            .enumerate()
            .map(|(index, (kind, _, _))| CencDashRenditionBytesV2 {
                kind: *kind,
                timescale: timescales[index],
                init_segment: &inits[index],
                segments: &protected_all[index],
            })
            .collect();
        let head = CencDashMediaIdentityV2::new_from_bytes(kid, &bytes).unwrap();
        MediaDashComponents {
            kinds: clear.iter().map(|(kind, _, _)| *kind).collect(),
            protected_inits: inits,
            protected_segments: protected_all,
            head,
        }
    }
}

use media_dash_fixture::{MediaDashComponents, A as DASH_AUDIO, V as DASH_VIDEO};

#[test]
fn require_media_dash_part_enforces_the_interleave() {
    let (head, _, _) = fake_dash_package(&[DASH_VIDEO, DASH_AUDIO], &[3, 3]);
    let mut record = dash_test_record();
    // Part 0 is the video init: no index, rendition 0.
    assert_eq!(
        record.require_media_dash_part(&head, None).unwrap(),
        (0, None)
    );
    // D6 lets a fresh viewer start at a later media part. Once the first
    // init has been released, the remaining parts keep the exact interleave.
    record.mark_media_part_read(crate::auth::now_ts()).unwrap();
    assert!(record.require_media_dash_part(&head, Some(0)).is_err());
    // Part 1 is the audio init.
    record.next_media_part_index = 1;
    assert_eq!(
        record.require_media_dash_part(&head, None).unwrap(),
        (1, None)
    );
    // Part 2 is video segment 0: asking for segment 1, or for an init, is refused.
    record.next_media_part_index = 2;
    assert_eq!(
        record.require_media_dash_part(&head, Some(0)).unwrap(),
        (0, Some(0))
    );
    assert!(record.require_media_dash_part(&head, Some(1)).is_err());
    assert!(record.require_media_dash_part(&head, None).is_err());
    // Part 3 is audio segment 0.
    record.next_media_part_index = 3;
    assert_eq!(
        record.require_media_dash_part(&head, Some(0)).unwrap(),
        (1, Some(0))
    );
    // Past the last part (2 inits + 6 segments) nothing is valid.
    record.next_media_part_index = 8;
    for segment_index in [None, Some(0), Some(2), Some(3)] {
        let error = record
            .require_media_dash_part(&head, segment_index)
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "Runtime custody viewer media part is invalid"
        );
    }
}

#[cfg(unix)]
#[tokio::test]
async fn dash_read_walks_the_interleave_with_a_proof_per_segment() {
    let viewer = dash_viewer(
        media_dash_components(&[DASH_VIDEO, DASH_AUDIO], &[3, 3]),
        "walk",
    )
    .await;
    viewer.stage_leaves();
    let reads = viewer.expected_reads();
    assert_eq!(reads.len(), 2 + 6);
    let decrypt = viewer.register_decrypt(&reads).await;
    for (index, (selector, clear)) in reads.iter().enumerate() {
        let segment_index = selector.segment_index();
        let answer = viewer.read(segment_index, None).await.unwrap();
        assert_eq!(&decoded_part(&answer), clear, "part {index}");
    }
    viewer.assert_decrypt_requests(&decrypt.requests().await, &reads);
    // Staged leaves: only the six segments were fetched, never the manifest.
    let expected_paths: Vec<String> = (0..3)
        .flat_map(|index| {
            [
                dash_segment_file(DASH_VIDEO, index),
                dash_segment_file(DASH_AUDIO, index),
            ]
        })
        .collect();
    assert_eq!(
        viewer.harness.base.content_provider.fetched_paths().await,
        expected_paths
    );
    assert_eq!(viewer.record().next_media_part_index, 8);
    // The walk is over.
    assert!(viewer.read(None, None).await.is_err());
    assert!(viewer.read(Some(3), None).await.is_err());
}

#[cfg(unix)]
#[tokio::test]
async fn dash_read_interleaves_unequal_counts() {
    let viewer = dash_viewer(
        media_dash_components(&[DASH_VIDEO, DASH_AUDIO], &[3, 2]),
        "unequal",
    )
    .await;
    viewer.stage_leaves();
    let reads = viewer.expected_reads();
    assert_eq!(reads.len(), 2 + 5);
    let decrypt = viewer.register_decrypt(&reads).await;
    for (selector, clear) in &reads {
        let answer = viewer.read(selector.segment_index(), None).await.unwrap();
        assert_eq!(&decoded_part(&answer), clear);
    }
    viewer.assert_decrypt_requests(&decrypt.requests().await, &reads);
}

#[cfg(unix)]
#[tokio::test]
async fn dash_read_refuses_out_of_order_requests_before_any_fetch() {
    let viewer = dash_viewer(
        media_dash_components(&[DASH_VIDEO, DASH_AUDIO], &[3, 3]),
        "order",
    )
    .await;
    viewer.stage_leaves();
    let reads = viewer.expected_reads();
    let decrypt = viewer.register_decrypt(&reads).await;
    // At part 0 (nothing read yet; D6 lets the first read place the
    // session): a segment past the end, and a chunk, are refused.
    assert_eq!(
        viewer.read(Some(3), None).await.unwrap_err().to_string(),
        "Runtime custody viewer media part is invalid"
    );
    assert_eq!(
        viewer.read(None, Some(0)).await.unwrap_err().to_string(),
        "Runtime custody viewer session is unavailable"
    );
    // At part 2 (video segment 0): segment 1 is refused, and so is an init.
    viewer.set_next_part(2);
    for segment_index in [Some(1), None] {
        assert_eq!(
            viewer
                .read(segment_index, None)
                .await
                .unwrap_err()
                .to_string(),
            "Runtime custody viewer media part is invalid"
        );
    }
    // Past the last part.
    viewer.set_next_part(8);
    assert_eq!(
        viewer.read(Some(3), None).await.unwrap_err().to_string(),
        "Runtime custody viewer media part is invalid"
    );
    assert_eq!(viewer.record().next_media_part_index, 8);
    assert!(viewer
        .harness
        .base
        .content_provider
        .requests()
        .await
        .is_empty());
    assert!(decrypt.requests().await.is_empty());
}

#[cfg(unix)]
#[tokio::test]
async fn dash_read_sends_an_empty_proof_for_a_one_segment_rendition() {
    let viewer = dash_viewer(media_dash_components(&[DASH_VIDEO], &[1]), "single").await;
    viewer.stage_leaves();
    let reads = viewer.expected_reads();
    assert_eq!(reads.len(), 2);
    let decrypt = viewer.register_decrypt(&reads).await;
    for (selector, clear) in &reads {
        let answer = viewer.read(selector.segment_index(), None).await.unwrap();
        assert_eq!(&decoded_part(&answer), clear);
    }
    let recorded = decrypt.requests().await;
    viewer.assert_decrypt_requests(&recorded, &reads);
    assert!(
        serde_json::to_string(&recorded[1])
            .unwrap()
            .contains("\"segment_proof\":[]"),
        "{}",
        recorded[1]
    );
}

// ---------------------------------------------------------------------------
// DASH v2 mint (T10)
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[tokio::test]
async fn media_dash_mint_holds_one_clear_part_at_a_time() {
    let harness = library_mint_harness(
        "person:local:dash-mint-bounded",
        &[(DASH_VIDEO, 8), (DASH_AUDIO, 8)],
    )
    .await;
    let (_, components, envelope) = harness.honest_protect();
    let mut script = media_dash_protect_script(TEST_PROTECT_HANDLE, &components, &envelope);
    script.push(closed_protect_response());
    let protect = harness.register_protect(script).await;

    harness.publish().await.expect("the mint must publish");

    // At the k-th protect request exactly k + 1 parts have been read: each part
    // is read, handed to the provider and dropped before the next is read.
    assert_eq!(
        protect.reads_at_segment_requests().await,
        (1..=16).collect::<Vec<usize>>()
    );
}

#[cfg(unix)]
#[tokio::test]
async fn media_dash_mint_fails_closed_on_every_deviant_protect_output() {
    type Tamper = fn(
        &mut Vec<Result<Value, ProviderError>>,
        &media_dash_fixture::MediaDashComponents,
        &CustodyEnvelopeV1,
    );
    fn typed(response: ProtectProviderResponseV1) -> Result<Value, ProviderError> {
        Ok(ok_typed_protect_provider_response(response))
    }
    let cases: [(&str, &str, Tamper); 5] = [
        (
            "the finalized head differs from the local head",
            "Runtime custody protect output is invalid",
            |script, components, envelope| {
                // The same ciphertext under a head that declares another
                // timescale: a different head, and a coherent answer.
                let renditions: Vec<_> = components
                    .kinds
                    .iter()
                    .enumerate()
                    .map(|(index, kind)| {
                        elastos_protected_content_provider_contracts::CencDashRenditionBytesV2 {
                            kind: *kind,
                            timescale: 15_361,
                            init_segment: &components.protected_inits[index],
                            segments: &components.protected_segments[index],
                        }
                    })
                    .collect();
                let skewed =
                    elastos_protected_content_provider_contracts::CencDashMediaIdentityV2::new_from_bytes(
                        components.head.default_kid(),
                        &renditions,
                    )
                    .unwrap();
                assert_ne!(skewed, components.head);
                let last = script.len() - 1;
                script[last] = typed(
                    ProtectProviderResponseV1::new_finalized_v2(
                        TEST_PROTECT_HANDLE,
                        &skewed,
                        envelope,
                    )
                    .unwrap(),
                );
            },
        ),
        (
            "an envelope over other encrypted content",
            "Runtime custody protect output is invalid",
            |script, _components, envelope| {
                // The typed constructor refuses to pair a head with an
                // envelope for other content, so the answer is spliced as a
                // provider that did not use it would send it.
                let other = media_dash_components(&[DASH_VIDEO], &[1]);
                let foreign = CustodyEnvelopeV1::new(
                    CustodyEnvelopeManifestV1::new(
                        other.head.encrypted_content().clone(),
                        envelope.manifest().custody_pool(),
                        envelope.manifest().custody_epoch(),
                        envelope.manifest().custody_committee_authorization(),
                        envelope.manifest().threshold(),
                        envelope.manifest().content_key_commitment(),
                        envelope.manifest().nodes().to_vec(),
                    )
                    .unwrap(),
                    envelope.stored_shares().to_vec(),
                )
                .unwrap();
                let last = script.len() - 1;
                let mut spliced = script[last].as_ref().ok().unwrap().clone();
                let foreign_answer = ok_typed_protect_provider_response(
                    ProtectProviderResponseV1::new_finalized_v2(
                        TEST_PROTECT_HANDLE,
                        &other.head,
                        &foreign,
                    )
                    .unwrap(),
                );
                spliced["data"]["custody_envelope"] =
                    foreign_answer["data"]["custody_envelope"].clone();
                script[last] = Ok(spliced);
            },
        ),
        (
            "a wrong echoed segment index",
            "Runtime custody protect provider is unavailable",
            |script, components, _| {
                script[2] = typed(
                    ProtectProviderResponseV1::new_segment_protected(
                        TEST_PROTECT_HANDLE,
                        5,
                        &components.protected_segments[0][1],
                    )
                    .unwrap(),
                );
                // The mint stops at the bad answer and settles the session.
                script.truncate(3);
            },
        ),
        (
            "one protected init for two renditions",
            "Runtime custody protect output is invalid",
            |script, components, _| {
                script[0] = typed(
                    ProtectProviderResponseV1::new_opened_v2(
                        TEST_PROTECT_HANDLE,
                        &components.protected_inits[..1],
                    )
                    .unwrap(),
                );
                script.truncate(1);
            },
        ),
        (
            "an empty protected segment",
            "Runtime custody protect output is invalid",
            |script, _, _| {
                // A segment answer with no bytes cannot be a protected segment.
                script[1] = typed(
                    ProtectProviderResponseV1::new_failure(
                        ProviderFailureCodeV1::BackendUnavailable,
                    )
                    .unwrap(),
                );
                script.truncate(2);
            },
        ),
    ];
    for (index, (label, message, tamper)) in cases.into_iter().enumerate() {
        let harness = library_mint_harness(
            &format!("person:local:dash-mint-deviant-{index}"),
            &[(DASH_VIDEO, 2), (DASH_AUDIO, 2)],
        )
        .await;
        let (intent, components, envelope) = harness.honest_protect();
        let mut script = media_dash_protect_script(TEST_PROTECT_HANDLE, &components, &envelope);
        tamper(&mut script, &components, &envelope);
        script.push(cancelled_protect_response());
        let protect = harness.register_protect(script).await;

        let error = harness
            .publish()
            .await
            .err()
            .unwrap_or_else(|| panic!("{label}: must be refused"));

        // The provider-side failure of a segment surfaces as "unavailable";
        // anything wrong in a well-formed answer as "invalid".
        let expected = if label == "an empty protected segment" {
            "Runtime custody protect provider is unavailable"
        } else {
            message
        };
        assert!(error.to_string().contains(expected), "{label}: {error}");
        assert_refused_before_any_draft(&harness, &intent, &protect.requests().await);
    }
}

// ── #388 A1: the custody roles on an everyday host ──────────────────

/// Plan B T4.6: adopted listings on a Home that does not hold the item.
/// Unix only, like the composition journal fixture it uses.
#[cfg(unix)]
mod plan_b_non_holder {
    use super::*;
    use crate::protected_content_runtime as pcr;
    use elastos_protected_content_contracts::test_fixtures::{
        key_envelope_for, node_public_key as fixture_node_key, pool_bundle, pool_descriptor_with,
        pool_did, runtime_issuer,
    };
    use elastos_protected_content_contracts::{RightsSubjectSourceV1, ServePolicyV1};
    use elastos_protected_content_runtime::{
        pool_node_owner_state_root, resolve_pool_from_candidates, AcceptAnyPool, PoolResolveError,
        RuntimeAvailabilityEvidenceV1, RuntimeContentIdentityV1,
    };

    fn xwing(
        seed: u8,
    ) -> [u8; elastos_protected_content_contracts::PQ_HYBRID_WRAP_PUBLIC_KEY_BYTES] {
        use x_wing::kem::Decapsulator as _;
        use x_wing::KeyExport as _;
        let secret = x_wing::DecapsulationKey::from([seed; x_wing::DECAPSULATION_KEY_SIZE]);
        secret.encapsulation_key().to_bytes().into()
    }

    /// A media item published on the fake content plane, and its provider.
    async fn published_media() -> (
        tempfile::TempDir,
        Arc<ProviderRegistry>,
        Arc<ContentAvailabilityTestProvider>,
        RuntimeContentIdentityV1,
        String,
    ) {
        let (directory, media) = protected_content_directory(0x41);
        let provider =
            ContentAvailabilityTestProvider::new(0x61, ContentAvailabilityTestConfig::accepted());
        let requirement = availability_requirement(provider.signer_did());
        let registry = Arc::new(ProviderRegistry::new());
        registry
            .register_sub_provider("content", provider.clone())
            .await
            .unwrap();
        publish_and_verify_v1_protected_content_for_test(
            registry.as_ref(),
            directory.path(),
            &media,
            &requirement,
            || NOW,
        )
        .await
        .unwrap();
        let identity = RuntimeContentIdentityV1::Media(media);
        let content_id = pcr::runtime_protected_content_id(identity.encrypted_content()).unwrap();
        (directory, registry, provider, identity, content_id)
    }

    async fn ops_since(provider: &ContentAvailabilityTestProvider, from: usize) -> Vec<Value> {
        provider.requests.lock().await[from..].to_vec()
    }

    /// D7-A: an adoption, like an open, checks the manifest only; the pool
    /// server checks each part against the manifest's verified leaf before
    /// serving it (`custody_pool_service::tests::guard_a_tampered_part_is_refused_before_serving`).
    /// This replaces the S4-U2 full fetch (`adopted_listing_on_non_holder_verifies_by_fetch`,
    /// `adopted_listing_with_tampered_file_is_refused`).
    #[tokio::test]
    async fn adopted_listing_on_non_holder_checks_the_manifest_only() {
        let (_dir, registry, provider, identity, content_id) = published_media().await;
        let before = provider.requests.lock().await.len();
        let evidence = pcr::verify_non_holder_content(
            registry.as_ref(),
            ContentAvailabilityTestProvider::CID,
            &content_id,
            &identity,
            None,
            pcr::non_holder_check(pcr::PortableVerifyMode::Adopt).unwrap(),
            NOW,
        )
        .await
        .unwrap();
        assert_eq!(
            evidence.kind(),
            RuntimeAvailabilityEvidenceV1::VERIFIED_FETCH
        );
        assert_eq!(evidence.content_cid(), ContentAvailabilityTestProvider::CID);
        assert_eq!(evidence.object_identity(), content_id);
        // The manifest only; nothing was ensured or pinned here.
        let ops = ops_since(&provider, before).await;
        assert_eq!(ops.len(), 1, "{ops:?}");
        assert_eq!(ops[0]["op"], "fetch");
        assert_eq!(ops[0]["path"], crate::content::CONTENT_OBJECT_MANIFEST_PATH);
    }

    #[tokio::test]
    async fn open_on_non_holder_checks_the_manifest_only() {
        let (_dir, registry, provider, identity, content_id) = published_media().await;
        // A changed file is the staging pool server's to refuse (T3.4); the
        // open's check reads the manifest only.
        {
            let mut files = provider.files.lock().await;
            let segment = files
                .keys()
                .find(|path| path.contains("segment"))
                .cloned()
                .expect("a published segment");
            files.get_mut(&segment).unwrap()[0] ^= 0x01;
        }
        let before = provider.requests.lock().await.len();
        let evidence = pcr::verify_non_holder_content(
            registry.as_ref(),
            ContentAvailabilityTestProvider::CID,
            &content_id,
            &identity,
            None,
            pcr::NonHolderCheck::ManifestOnly,
            NOW,
        )
        .await
        .unwrap();
        assert_eq!(
            evidence.kind(),
            RuntimeAvailabilityEvidenceV1::VERIFIED_FETCH
        );
        let ops = ops_since(&provider, before).await;
        assert_eq!(ops.len(), 1, "{ops:?}");
        assert_eq!(ops[0]["path"], crate::content::CONTENT_OBJECT_MANIFEST_PATH);
        assert_eq!(
            pcr::non_holder_check(pcr::PortableVerifyMode::Open).unwrap(),
            pcr::NonHolderCheck::ManifestOnly
        );
        assert_eq!(
            pcr::non_holder_check(pcr::PortableVerifyMode::Adopt).unwrap(),
            pcr::NonHolderCheck::ManifestOnly
        );
    }

    /// D2-A (STAB-02): an import resolves the item's pool like an adoption
    /// (own, served or known descriptor) and is refused only when that
    /// resolution fails. Replaces `imported_listing_on_non_holder_is_unresolved`
    /// (S4-Q14).
    #[test]
    fn import_policy_on_non_holder_uses_the_same_manifest_check_as_adoption() {
        assert_eq!(
            pcr::non_holder_check(pcr::PortableVerifyMode::Import).unwrap(),
            pcr::non_holder_check(pcr::PortableVerifyMode::Adopt).unwrap()
        );
        // The refusal an unresolved pool still answers (T4.7).
        let error = pcr::RuntimeCustodyUnresolved::error();
        assert!(pcr::RuntimeCustodyElsewhere::is(&error));
        assert_eq!(pcr::RuntimeCustodyUnresolved::CODE, "custody_unresolved");
    }

    /// D2-A guard (ADV-19): the item's pool comes ONLY from a verified pool
    /// descriptor this Home keeps. A pasted Share link's package carries a
    /// key envelope that names a pool; when no descriptor here verifies that
    /// pool, the import is `custody_unresolved`, however well formed the
    /// envelope is, and no part of the item is fetched or bound.
    #[test]
    fn guard_import_with_a_forged_pool_reference_is_refused_unresolved() {
        // This Home keeps one verified descriptor: `known`.
        let known = pool_bundle(xwing, NOW);
        let descriptor = pool_descriptor_with(
            &known,
            1,
            ServePolicyV1::DEFAULT,
            None,
            runtime_issuer(0x43),
            NOW,
        );
        // The pasted package names another pool over the same node keys,
        // signed by an authority this Home never verified.
        let forged_bundle =
            elastos_protected_content_contracts::test_fixtures::pool_bundle_signed_by(
                xwing, NOW, None, None, 0x72,
            );
        let framed = vec![0x5a; 4096 + 64];
        let object = test_object_identity(&framed);
        let forged = key_envelope_for(&forged_bundle, object.encrypted_content());
        let genuine = key_envelope_for(&known, object.encrypted_content());
        assert_ne!(forged.custody_pool(), genuine.custody_pool());
        // The import goes through the same resolution as an adoption ...
        assert_eq!(
            pcr::non_holder_check(pcr::PortableVerifyMode::Import).unwrap(),
            pcr::NonHolderCheck::ManifestOnly
        );
        // ... which admits the genuine envelope and refuses the forged one.
        let candidates = || vec![("known", descriptor.clone().into())];
        assert!(
            resolve_pool_from_candidates(candidates(), &AcceptAnyPool, &genuine, &[], NOW).is_ok()
        );
        assert_eq!(
            resolve_pool_from_candidates(candidates(), &AcceptAnyPool, &forged, &[], NOW)
                .map(|resolved| resolved.source),
            Err(PoolResolveError::Unresolved)
        );
        // No descriptor at all: the same refusal, never a pool taken from the package.
        assert_eq!(
            resolve_pool_from_candidates(Vec::new(), &AcceptAnyPool, &forged, &[], NOW)
                .map(|resolved| resolved.source),
            Err(PoolResolveError::Unresolved)
        );
    }

    #[tokio::test]
    async fn item_of_unknown_pool_is_unresolved() {
        let dir = crate::protected_content_config::tests::safe_ancestor_tempdir();
        let data_dir = dir.path().join("home");
        crate::protected_content_config::tests::owner_only_dir(&data_dir);
        let draft = mint_draft_for_composition_journal_test();
        assert_eq!(
            pcr::runtime_custody_pool_for_key_envelope_cached(&data_dir, draft.key_envelope(), NOW),
            Err(PoolResolveError::Unresolved)
        );
        assert_eq!(
            pcr::runtime_custody_pool_for_key_envelope(
                &data_dir,
                Arc::new(ProviderRegistry::new()),
                draft.key_envelope(),
                NOW,
            )
            .await,
            Err(PoolResolveError::Unresolved)
        );
    }

    #[test]
    fn draft_rebuild_uses_pool_bound_node_bindings() {
        let bundle = pool_bundle(xwing, NOW);
        let descriptor = pool_descriptor_with(
            &bundle,
            1,
            ServePolicyV1::DEFAULT,
            None,
            runtime_issuer(0x43),
            NOW,
        );
        let framed = vec![0x5a; 4096 + 64];
        let object = test_object_identity(&framed);
        let key_envelope = key_envelope_for(&bundle, object.encrypted_content());
        let resolved = resolve_pool_from_candidates(
            vec![("known", descriptor.into())],
            &AcceptAnyPool,
            &key_envelope,
            &[],
            NOW,
        )
        .unwrap();
        let bindings = pcr::pool_bound_node_bindings(&resolved).unwrap();
        let epoch = bundle.epoch_identity().unwrap();
        assert_eq!(bindings.len(), 3);
        // The epoch orders its nodes by key, so each binding is found by key.
        for seed in 1u8..=3 {
            let binding = bindings
                .iter()
                .find(|binding| binding.node_public_key() == fixture_node_key(seed))
                .expect("a binding per epoch node");
            // Operator and failure domain come from the epoch committee.
            assert_eq!(binding.operator_id().as_bytes(), &[0xa0 + seed; 32]);
            assert_eq!(binding.failure_domain_id().as_bytes(), &[0xc0 + seed; 32]);
            assert_eq!(
                binding.owner_state_root(),
                pool_node_owner_state_root(&pool_did(), epoch, fixture_node_key(seed))
            );
        }
        // The draft accepts them: their node set is the key envelope's.
        let policy = elastos_protected_content_contracts::RightsPolicyBodyV1::new(
            object.encrypted_content().clone(),
            ContentAccessIdV1::new([0x44; 16]).unwrap(),
            RightsActionV1::View,
            RightsSubjectSourceV1::WalletAddress,
            11155111,
            EvmContractAddressV1::new([0x11; 20]).unwrap(),
            EvmFunctionSelectorV1::new([0x12, 0x34, 0x56, 0x78]).unwrap(),
            EvmRightsMethodAbiV1::HasAccessByContentIdAddressBytes16,
            RightsObservationFinalityV1::finalized(),
        )
        .unwrap();
        RuntimeMintDraft::new_from_identity(
            RuntimeContentIdentityV1::Object(object),
            ContentAccessIdV1::new([0x44; 16]).unwrap(),
            key_envelope.clone(),
            policy.policy_identity().unwrap(),
            Digest32::new([0xcc; 32]),
            key_envelope.threshold(),
            bindings,
        )
        .unwrap();
    }

    #[test]
    fn listing_record_without_kind_reads_as_receipt() {
        let summary: pcr::RuntimeCustodyListingAvailabilitySummary =
            serde_json::from_value(json!({
                "checked_at": NOW,
                "observed_replicas": 3,
                "receipt_digest": hex::encode([0x67; 32]),
            }))
            .unwrap();
        assert_eq!(summary.kind, "receipt");
        assert!(!summary.is_verified_fetch());
        assert_eq!(
            summary.purchase_digest(),
            format!("sha256:{}", hex::encode([0x67; 32]))
        );
        // A record written with a kind keeps it.
        let fetched = pcr::RuntimeCustodyListingAvailabilitySummary {
            kind: "verified_fetch".to_string(),
            checked_at: NOW,
            observed_replicas: 0,
            receipt_digest: String::new(),
        };
        let round_trip: pcr::RuntimeCustodyListingAvailabilitySummary =
            serde_json::from_value(serde_json::to_value(&fetched).unwrap()).unwrap();
        assert_eq!(round_trip, fetched);
        assert_eq!(
            fetched.purchase_digest(),
            pcr::RUNTIME_PURCHASE_VERIFIED_FETCH_DIGEST
        );
    }

    #[test]
    fn holder_listing_still_needs_receipt() {
        // A creator's or imported listing (a holder's) must carry a receipt;
        // only an adopted listing may record a verified fetch.
        let mut record = runtime_custody_listing_record_for_test(
            Digest32::new([0x31; 32]),
            "principal:alpha",
            "Item",
            NOW,
        );
        record.validate().unwrap();
        record.availability = pcr::RuntimeCustodyListingAvailabilitySummary {
            kind: "verified_fetch".to_string(),
            checked_at: NOW,
            observed_replicas: 0,
            receipt_digest: String::new(),
        };
        assert!(record.validate().is_err());
        record.availability.kind = "teapot".to_string();
        assert!(record.validate().is_err());
        // A holder rebuilds with its composition bindings.
        assert_eq!(
            pcr::draft_node_bindings_for(pcr::ItemMintPath::Composition, true),
            pcr::DraftNodeBindings::Composition
        );
    }

    #[test]
    fn owner_listing_keeps_its_mint_id() {
        // The owner holds its item, so it keeps the composition path that
        // rebuilt its `mint_id` before T4.6; only a non-holder is pool-bound.
        assert_eq!(
            pcr::draft_node_bindings_for(pcr::ItemMintPath::Composition, true),
            pcr::DraftNodeBindings::Composition
        );
        assert_eq!(
            pcr::draft_node_bindings_for(pcr::ItemMintPath::Composition, false),
            pcr::DraftNodeBindings::PoolBound
        );
        let source = concat!(
            include_str!("../protected_content_runtime.rs"),
            include_str!("../protected_content_runtime/custody.rs"),
            include_str!("../protected_content_runtime/creator.rs"),
            include_str!("../protected_content_runtime/library_publish.rs"),
            include_str!("../protected_content_runtime/listing.rs"),
            include_str!("../protected_content_runtime/viewer.rs"),
        );
        let rebuild = &source[source
            .find("async fn rebuild_runtime_portable_content(")
            .unwrap()..];
        let rebuild = &rebuild[..rebuild.find("\n}\n").unwrap()];
        // The holder branch is the composition verifiers, which compare the
        // rebuilt `mint_id` with the package's (`verify_runtime_portable_content`).
        assert!(rebuild.contains("verify_runtime_portable_media("));
        assert!(rebuild.contains("verify_runtime_portable_media_dash("));
        assert!(rebuild.contains("verify_runtime_portable_object("));
    }

    #[test]
    fn every_binding_site_uses_the_one_choice_function() {
        let source = concat!(
            include_str!("../protected_content_runtime.rs"),
            include_str!("../protected_content_runtime/custody.rs"),
            include_str!("../protected_content_runtime/creator.rs"),
            include_str!("../protected_content_runtime/library_publish.rs"),
            include_str!("../protected_content_runtime/listing.rs"),
            include_str!("../protected_content_runtime/viewer.rs"),
        );
        let body = |name: &str| {
            let start = source
                .find(name)
                .unwrap_or_else(|| panic!("{name} is declared"));
            let rest = &source[start..];
            rest[..rest.find("\n}\n").unwrap()].to_string()
        };
        // The rebuild asks the choice function before anything else, and the
        // pool-bound branch builds its draft from the pool's committee.
        let rebuild = body("async fn rebuild_runtime_portable_content(");
        // Plan B S7-lite: the item's path is the package's (`Pool` when it
        // carries a pool mint's admission), and the one choice decides.
        assert!(rebuild.contains("draft_node_bindings_for(item, holds)"));
        assert!(rebuild.contains("ItemMintPath::Pool"));
        let non_holder = body("async fn rebuild_non_holder_portable_content(");
        assert!(non_holder.contains("pool_bound_node_bindings(&resolved)"));
        // Every verifier reaches the bindings only through the rebuild: the
        // per-kind composition verifiers have no other caller.
        for verifier in [
            "verify_runtime_portable_media(",
            "verify_runtime_portable_media_dash(",
            "verify_runtime_portable_object(",
        ] {
            assert_eq!(
                source.matches(verifier).count(),
                2,
                "{verifier} is declared once and called once, from the rebuild"
            );
        }
        assert_eq!(
            source.matches("rebuild_runtime_portable_content(").count(),
            4,
            "declared, called by strict verification, import compatibility and adoption"
        );
    }
}

// Plan B T2.1: the Runtime starts one custody provider with every root.

// ---------------------------------------------------------------------------
// OPEN-LOOP F3: one viewer reply contract for Runtime, Reader and Player
// ---------------------------------------------------------------------------

// AUDIT-REPRO J2/J3 (red tests, no fix).
mod audit_j2_j3_runtime;

// AUDIT-REPRO J1 (red tests, no fix).
mod audit_j1_custody_refusal;
mod creator;
mod custody;
mod format_fixtures;
mod library_publish;
mod listing;
mod support;
mod viewer;

pub(crate) use support::*;
